//! The gateway's own description of a pending change request.
//!
//! An approval card leads with this description: a title that names the
//! action and its target, the specific changes, and what approval does. The
//! requester's reason and the exact captured parameters follow it. The
//! description is computed from current gateway state each time the card
//! renders, so it states what approval would do now.
//!
//! Card text follows the writing rules in `docs/agents/dashboard-ui.md`: name
//! the object, show only what changes, state the outcome in one sentence, and
//! keep identifiers with the exact parameters.

use std::sync::Arc;

use waygate_catalog::tool_reviews::ToolReview;
use waygate_changeset::ChangeRequest;
use waygate_oidc::Principal;

use crate::contract_summary::{self, ContractSummary};
use crate::state::AdminState;
use crate::tool_reviews::ToolReviewParams;

/// Changes listed on a card before the rest are left to the linked evidence.
/// Flagged changes are listed even beyond this limit.
const CARD_CHANGES: usize = 8;

/// One fact in a change list.
pub(crate) struct DescribedChange {
    pub text: String,
    /// Why the change can widen what the target does or receives.
    pub flag: Option<String>,
}

/// Linked evidence that holds every detail the card leaves out.
pub(crate) struct EvidenceLink {
    pub label: &'static str,
    /// Tenant-relative dashboard path.
    pub path: String,
}

pub(crate) struct ChangeDescription {
    /// Starts with a verb and names the target.
    pub title: String,
    /// Flagged changes first.
    pub changes: Vec<DescribedChange>,
    /// What the change list cannot show, in one sentence.
    pub note: Option<String>,
    /// What approval does, in one sentence.
    pub outcome: Option<String>,
    pub evidence: Option<EvidenceLink>,
    /// Why approval is unavailable now. Denial remains available.
    pub blocked: Option<String>,
    /// When the change runs, for a request that needs more than one
    /// approval.
    pub quorum: Option<String>,
    /// The title and changes state every captured intent parameter, and the
    /// gateway checked every captured identity against current state. Only
    /// then do the exact parameters start collapsed; they always remain in the
    /// page. Freshness witnesses such as a manifest hash are enforced by the
    /// executor.
    pub covers_params: bool,
}

impl ChangeDescription {
    /// An action without a target description keeps its generic title and
    /// outcome, and its captured parameters open.
    fn undescribed(action_type: &str) -> Self {
        let text = crate::change_outcome::action_text(action_type);
        Self {
            title: text
                .as_ref()
                .map_or_else(|| action_type.to_owned(), |text| text.title.to_owned()),
            changes: Vec::new(),
            note: None,
            outcome: text.map(|text| text.outcome.to_owned()),
            evidence: None,
            blocked: None,
            quorum: None,
            covers_params: false,
        }
    }

    /// The approval confirmation: the title as a question, what approval
    /// does, and when a multi-approver change runs.
    pub(crate) fn confirmation(&self) -> String {
        [
            Some(format!("{}?", self.title)),
            self.outcome.clone(),
            self.quorum.clone(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
    }
}

/// Describe one pending change from current gateway state, as `viewer`
/// would approve it.
pub(crate) async fn describe(
    state: &Arc<AdminState>,
    viewer: Option<&Principal>,
    change: &ChangeRequest,
) -> ChangeDescription {
    let mut description = match change.action_type.as_str() {
        "tool_contract.approve" => tool_contract(state, change, true).await,
        "tool_contract.reject" => tool_contract(state, change, false).await,
        other => ChangeDescription::undescribed(other),
    };
    if description.blocked.is_none() {
        description.blocked = stale_target(state, viewer, change).await;
    }
    description.quorum = quorum(change.required_approvals);
    description
}

fn quorum(required_approvals: i32) -> Option<String> {
    (required_approvals > 1).then(|| {
        format!(
            "The change runs once {required_approvals} different administrators approve it. \
             Each approval is recorded until then."
        )
    })
}

/// Why approval would fail the freshness check that runs before execution:
/// the action's target, as captured at proposal, no longer matches current
/// state. Approval re-runs the same capture, so the card can say so first.
async fn stale_target(
    state: &Arc<AdminState>,
    viewer: Option<&Principal>,
    change: &ChangeRequest,
) -> Option<String> {
    let proposed = change.target_etag.as_deref()?;
    let viewer = viewer?;
    let executor = crate::change_executor::registry().get(&change.action_type)?;
    match executor
        .capture_etag(state, &change.tenant_id, viewer, &change.params)
        .await
    {
        Ok(Some(current)) if current == proposed => None,
        Ok(_) => Some(
            "The target changed after this request, so approval would fail. A new request \
             against the current state is needed."
                .to_owned(),
        ),
        Err(crate::change_executor::ExecError::Precondition(reason)) => Some(format!(
            "The target changed after this request, so approval would fail: {reason}"
        )),
        Err(error) => Some(format!(
            "The target cannot be checked, so approval would fail: {}",
            error.message()
        )),
    }
}

async fn tool_contract(
    state: &AdminState,
    change: &ChangeRequest,
    accept: bool,
) -> ChangeDescription {
    let Ok(params) = serde_json::from_value::<ToolReviewParams>(change.params.clone()) else {
        return ChangeDescription::undescribed(&change.action_type);
    };
    let target = format!("{} · {}", params.server, params.tool);
    let mut description = ChangeDescription {
        title: if accept {
            format!("Accept the new definition of {target}")
        } else {
            format!("Keep {target} blocked")
        },
        changes: Vec::new(),
        note: None,
        outcome: Some(if accept {
            format!(
                "Agents can discover and call {} with this definition, subject to access \
                 policies. A later definition change is held for review when the gateway's drift \
                 settings require it.",
                params.tool
            )
        } else {
            format!(
                "{} stays hidden and its calls stay blocked until a later decision.",
                params.tool
            )
        }),
        evidence: Some(EvidenceLink {
            label: "Full comparison",
            path: crate::dashboard_tool_reviews::review_url(&params.server, &params.tool),
        }),
        blocked: None,
        quorum: None,
        covers_params: true,
    };
    let manifest = state
        .upstreams
        .manifests()
        .into_iter()
        .find(|manifest| manifest.name == params.server);
    let (risk, risk_blocks) = risk_effect(manifest.as_ref(), &params, accept);
    description.changes.extend(risk);
    let review = match current_review(state, &change.tenant_id, &params).await {
        Ok(review) => review,
        Err(reason) => {
            description.blocked = Some(reason.to_owned());
            description.covers_params = false;
            return description;
        }
    };
    if let Some(reason) = decision_unavailable(&review, &params, accept).or(risk_blocks) {
        description.blocked = Some(reason.to_owned());
        return description;
    }
    if let Some(reversal) = kept_blocked_reversal(&review, accept) {
        description.changes.insert(0, reversal);
    }
    if review.approved_hash.is_empty() {
        description.note =
            Some("This is the tool's first definition, so there is nothing to compare.".into());
    } else if review.approved_contract.is_null() {
        description.note = Some(
            "The accepted definition was not kept, so only the new definition can be shown.".into(),
        );
    } else if review.observed_contract.is_null() {
        description.note = Some(
            "The new definition exceeds the review storage limit, so it cannot be compared.".into(),
        );
    } else {
        let (changes, note) = card_changes(contract_summary::summarize(
            &review.approved_contract,
            &review.observed_contract,
        ));
        description.changes.extend(changes);
        description.note = note;
    }
    description
}

/// What the request's risk classification does. Approval applies it only
/// when it creates the first classification of a tool on a server that
/// classifies tools by their annotations, and that approval requires one.
/// Elsewhere the decision cores ignore it, and the card says so.
fn risk_effect(
    manifest: Option<&waygate_upstream::UpstreamManifest>,
    params: &ToolReviewParams,
    accept: bool,
) -> (Option<DescribedChange>, Option<&'static str>) {
    let classifies_first = accept
        && manifest.is_some_and(|manifest| {
            matches!(
                manifest.classification_mode,
                waygate_upstream::ClassificationMode::McpAnnotations
            ) && !manifest.tools.iter().any(|tool| tool.name == params.tool)
        });
    match (params.risk, classifies_first) {
        (Some(risk), true) => (
            Some(DescribedChange {
                text: format!("Sets the gateway risk classification to {}", risk.as_str()),
                flag: None,
            }),
            None,
        ),
        (Some(risk), false) => (
            Some(DescribedChange {
                text: format!(
                    "The requested risk classification ({}) is not used; the tool's \
                     classification does not change",
                    risk.as_str()
                ),
                flag: None,
            }),
            None,
        ),
        (None, true) => (
            None,
            Some(
                "Approving this tool's first definition needs a gateway risk classification, \
                 and this request has none.",
            ),
        ),
        (None, false) => (None, None),
    }
}

const REVIEW_UNAVAILABLE: &str =
    "Tool review storage is unavailable, so the change cannot be shown.";

async fn current_review(
    state: &AdminState,
    tenant: &str,
    params: &ToolReviewParams,
) -> Result<ToolReview, &'static str> {
    let store = crate::tool_reviews::store(state).map_err(|_| REVIEW_UNAVAILABLE)?;
    match store.get(tenant, &params.server, &params.tool).await {
        Ok(Some(review)) => Ok(review),
        Ok(None) => Err("This tool has no review to decide."),
        Err(error) => {
            tracing::warn!(
                error = %error,
                server = %params.server,
                tool = %params.tool,
                "approval card could not read the tool review"
            );
            Err(REVIEW_UNAVAILABLE)
        }
    }
}

/// Why the captured decision can no longer be made. The decision cores
/// enforce the same conditions; the card states them before the
/// administrator acts.
fn decision_unavailable(
    review: &ToolReview,
    params: &ToolReviewParams,
    accept: bool,
) -> Option<&'static str> {
    if review.generation != params.generation || review.observed_hash != params.observed_hash {
        return Some(
            "The tool definition changed after this request. Review the current definition on \
             the full comparison.",
        );
    }
    if !review.quarantined {
        return Some("This definition is already accepted.");
    }
    if accept && review.observed_contract.is_null() {
        return Some(
            "The new definition exceeds the review storage limit and cannot be reviewed. Reduce \
             it upstream and refresh.",
        );
    }
    if !accept && review.decided_at.is_some() {
        return Some("This definition is already kept blocked.");
    }
    None
}

/// Accepting a definition an administrator kept blocked reverses that
/// decision; the card says so before the definition's own changes.
fn kept_blocked_reversal(review: &ToolReview, accept: bool) -> Option<DescribedChange> {
    let decided_at = review.decided_at.filter(|_| accept && review.quarantined)?;
    Some(DescribedChange {
        text: "Reverses the decision to keep this definition blocked".to_owned(),
        flag: Some(format!(
            "An administrator kept it blocked on {}.",
            waygate_core::fmt::format_ts_abs(decided_at)
        )),
    })
}

/// Order a contract summary for a card: every flagged change first, then
/// unflagged changes up to the card limit. The note counts what the card
/// leaves to the full comparison.
fn card_changes(summary: ContractSummary) -> (Vec<DescribedChange>, Option<String>) {
    let ContractSummary {
        changes,
        unlisted,
        flagged,
    } = summary;
    if changes.is_empty() && unlisted == 0 {
        return (
            Vec::new(),
            Some(
                "The definitions differ outside the summarized fields. The full comparison shows \
                 both."
                    .into(),
            ),
        );
    }
    let (listed_flagged, plain): (Vec<_>, Vec<_>) = changes
        .into_iter()
        .partition(|change| change.flag.is_some());
    let unlisted_flagged = flagged.saturating_sub(listed_flagged.len());
    let shown_plain = plain
        .len()
        .min(CARD_CHANGES.saturating_sub(listed_flagged.len()));
    let omitted = plain.len() - shown_plain + unlisted;
    let changes = listed_flagged
        .into_iter()
        .chain(plain.into_iter().take(shown_plain))
        .map(|change| DescribedChange {
            text: change.text,
            flag: change.flag,
        })
        .collect();
    let note = match (omitted, unlisted_flagged) {
        (0, _) => None,
        (1, 0) => Some("1 more change is on the full comparison.".to_owned()),
        (1, _) => Some("1 more flagged change is on the full comparison.".to_owned()),
        (n, 0) => Some(format!("{n} more changes are on the full comparison.")),
        (n, f) => Some(format!(
            "{n} more changes, {f} of them flagged, are on the full comparison."
        )),
    };
    (changes, note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::OffsetDateTime;

    fn review(quarantined: bool, decided: bool) -> ToolReview {
        ToolReview {
            tool_id: uuid::Uuid::nil(),
            tenant_id: "default".into(),
            server: "docs".into(),
            tool: "search".into(),
            approved_hash: "a".into(),
            approved_contract: json!({"description": "Search."}),
            observed_hash: "b".into(),
            observed_contract: json!({"description": "Search all."}),
            generation: 2,
            quarantined,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            decided_at: decided.then_some(OffsetDateTime::UNIX_EPOCH),
        }
    }

    fn params(generation: i64, observed_hash: &str) -> ToolReviewParams {
        ToolReviewParams {
            server: "docs".into(),
            tool: "search".into(),
            generation,
            observed_hash: observed_hash.into(),
            manifest_hash: String::new(),
            risk: None,
        }
    }

    #[test]
    fn a_stale_or_decided_review_blocks_only_the_decisions_it_prevents() {
        let pending = review(true, false);
        assert_eq!(decision_unavailable(&pending, &params(2, "b"), true), None);
        assert_eq!(decision_unavailable(&pending, &params(2, "b"), false), None);
        for stale in [params(1, "b"), params(2, "c")] {
            assert!(decision_unavailable(&pending, &stale, true)
                .unwrap()
                .contains("changed after this request"));
        }
        assert_eq!(
            decision_unavailable(&review(false, true), &params(2, "b"), true),
            Some("This definition is already accepted.")
        );
        let kept_blocked = review(true, true);
        assert_eq!(
            decision_unavailable(&kept_blocked, &params(2, "b"), true),
            None
        );
        assert_eq!(
            decision_unavailable(&kept_blocked, &params(2, "b"), false),
            Some("This definition is already kept blocked.")
        );
        let mut oversized = review(true, false);
        oversized.observed_contract = serde_json::Value::Null;
        assert!(decision_unavailable(&oversized, &params(2, "b"), true)
            .unwrap()
            .contains("storage limit"));
        assert_eq!(
            decision_unavailable(&oversized, &params(2, "b"), false),
            None
        );
    }

    fn change(text: &str, flagged: bool) -> contract_summary::ContractChange {
        contract_summary::ContractChange {
            text: text.into(),
            flag: flagged.then(|| "widens input".into()),
        }
    }

    fn manifest(annotations: bool) -> waygate_upstream::UpstreamManifest {
        let mut manifest = waygate_upstream::parse_manifest_set(
            "- name: docs\n  transport: http\n  trust: internal\n  url: https://docs.example/mcp\n  tools:\n    - name: search\n      risk: low\n",
        )
        .unwrap()
        .remove("docs")
        .unwrap();
        if annotations {
            manifest.classification_mode = waygate_upstream::ClassificationMode::McpAnnotations;
        }
        manifest
    }

    #[test]
    fn accepting_a_kept_blocked_definition_names_the_reversal() {
        let reversal = kept_blocked_reversal(&review(true, true), true).unwrap();
        assert_eq!(
            reversal.text,
            "Reverses the decision to keep this definition blocked"
        );
        assert!(reversal
            .flag
            .unwrap()
            .starts_with("An administrator kept it blocked on"));
        assert!(kept_blocked_reversal(&review(true, false), true).is_none());
        assert!(kept_blocked_reversal(&review(true, true), false).is_none());
        assert!(kept_blocked_reversal(&review(false, true), true).is_none());
    }

    #[test]
    fn risk_is_described_as_applied_only_where_approval_applies_it() {
        let annotations = manifest(true);
        let classified = manifest(false);
        let mut first = params(1, "b");
        first.tool = "fetch".into();
        first.risk = Some(waygate_core::RiskTier::High);
        let (change, blocks) = risk_effect(Some(&annotations), &first, true);
        assert_eq!(
            change.unwrap().text,
            "Sets the gateway risk classification to high"
        );
        assert_eq!(blocks, None);
        // Rejection, a manifest-classified server, and an unconfigured server
        // all ignore the requested value.
        for (manifest, accept) in [
            (Some(&annotations), false),
            (Some(&classified), true),
            (None, true),
        ] {
            let (change, blocks) = risk_effect(manifest, &first, accept);
            assert!(change.unwrap().text.contains("(high) is not used"));
            assert_eq!(blocks, None);
        }
        // An already classified tool keeps its classification.
        let mut search = params(1, "b");
        search.risk = Some(waygate_core::RiskTier::Low);
        let (change, _) = risk_effect(Some(&annotations), &search, true);
        assert!(change.unwrap().text.contains("(low) is not used"));
        search.risk = None;
        let (change, blocks) = risk_effect(Some(&annotations), &search, true);
        assert!(change.is_none() && blocks.is_none());
        // A first annotation classification cannot be approved without one.
        first.risk = None;
        let (change, blocks) = risk_effect(Some(&annotations), &first, true);
        assert!(change.is_none());
        assert!(blocks
            .unwrap()
            .contains("needs a gateway risk classification"));
    }

    #[test]
    fn confirmation_asks_with_the_title_and_states_the_outcome_and_quorum() {
        let mut description = ChangeDescription::undescribed("rate_limit.delete");
        assert_eq!(description.title, "Delete a rate limit");
        assert!(!description.covers_params);
        assert_eq!(
            description.confirmation(),
            format!(
                "Delete a rate limit? {}",
                crate::change_outcome::action_text("rate_limit.delete")
                    .unwrap()
                    .outcome
            )
        );
        description.quorum = quorum(2);
        assert!(description
            .confirmation()
            .ends_with("The change runs once 2 different administrators approve it. Each approval is recorded until then."));
        assert_eq!(quorum(1), None);
        let unknown = ChangeDescription::undescribed("not.registered");
        assert_eq!(unknown.title, "not.registered");
        assert_eq!(unknown.confirmation(), "not.registered?");
    }

    #[test]
    fn card_changes_list_flagged_changes_first_and_count_the_rest() {
        let mut changes: Vec<_> = (0..10)
            .map(|i| change(&format!("plain {i}"), false))
            .collect();
        changes.insert(5, change("flagged", true));
        let (listed, note) = card_changes(ContractSummary {
            changes,
            unlisted: 0,
            flagged: 1,
        });
        assert_eq!(listed.len(), CARD_CHANGES);
        assert_eq!(listed[0].text, "flagged");
        assert!(listed[0].flag.is_some());
        assert_eq!(listed[1].text, "plain 0");
        assert_eq!(
            note.as_deref(),
            Some("3 more changes are on the full comparison.")
        );
    }

    #[test]
    fn card_changes_never_drop_a_listed_flag_and_name_unlisted_flags() {
        let changes: Vec<_> = (0..CARD_CHANGES + 2)
            .map(|i| change(&format!("flagged {i}"), true))
            .chain([change("plain", false)])
            .collect();
        let (listed, note) = card_changes(ContractSummary {
            changes,
            unlisted: 3,
            flagged: CARD_CHANGES + 4,
        });
        assert_eq!(listed.len(), CARD_CHANGES + 2);
        assert!(listed.iter().all(|change| change.flag.is_some()));
        assert_eq!(
            note.as_deref(),
            Some("4 more changes, 2 of them flagged, are on the full comparison.")
        );
    }

    #[test]
    fn card_changes_explain_a_difference_the_summary_does_not_list() {
        let (listed, note) = card_changes(ContractSummary::default());
        assert!(listed.is_empty());
        assert!(note.unwrap().contains("outside the summarized fields"));
        let (listed, note) = card_changes(ContractSummary {
            changes: vec![change("Description changed", false)],
            unlisted: 0,
            flagged: 0,
        });
        assert_eq!(listed.len(), 1);
        assert_eq!(note, None);
    }
}
