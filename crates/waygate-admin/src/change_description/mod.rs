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

use std::fmt::Display;
use std::sync::Arc;

use serde_json::Value;
use waygate_changeset::ChangeRequest;
use waygate_oidc::Principal;

use crate::state::AdminState;

/// A name or value in quotes, with invisible characters, tabs, and line
/// breaks revealed, since card text collapses whitespace. Values are never
/// shortened: a description states each parameter completely.
pub(crate) fn quoted(text: &str) -> String {
    let revealed = crate::review_diff::reveal(text)
        .replace('\t', "[U+0009]")
        .replace('\n', "[U+000A]");
    format!("“{revealed}”")
}

mod access;
mod agents;
mod api_keys;
mod audit;
mod catalog;
mod peers;
mod rate_limits;
mod rbac;
mod tools;

/// One fact in a change list.
#[derive(Debug)]
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

    /// A described action: the given title naming its target, the action's
    /// outcome, and parameters that start collapsed only when every captured
    /// key is one the description states or checks.
    fn titled(action_type: &str, title: String, params: &Value, stated: &[&str]) -> Self {
        let mut description = Self::undescribed(action_type);
        description.title = title;
        description.covers_params = only_keys(params, stated);
        description
    }

    /// Approval is unavailable for `reason`; denial remains available.
    fn blocked(mut self, reason: impl Into<String>) -> Self {
        self.blocked = Some(reason.into());
        self
    }

    /// What the change list cannot show.
    fn noted(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Current state could not be read, so the card cannot state what
    /// changes; the exact parameters stay open.
    fn cannot_read(mut self, what: &str) -> Self {
        self.covers_params = false;
        self.noted(unreadable(what))
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

/// The current target of a change, or the description to show instead.
enum Lookup<T> {
    Found(T),
    Fallback(ChangeDescription),
}

impl<T> Lookup<T> {
    /// A missing target blocks approval, since execution would fail. An
    /// unconfigured or failing store leaves the generic description with its
    /// parameters open, so a store outage never blocks a decision.
    fn from_read<E: Display>(action: &str, what: &str, read: Option<Result<Option<T>, E>>) -> Self {
        match read {
            Some(Ok(Some(target))) => Self::Found(target),
            Some(Ok(None)) => {
                Self::Fallback(ChangeDescription::undescribed(action).blocked(gone(what)))
            }
            Some(Err(error)) => {
                tracing::warn!(error = %error, target = what, "approval card could not read the target");
                Self::Fallback(ChangeDescription::undescribed(action).noted(unreadable(what)))
            }
            None => Self::Fallback(ChangeDescription::undescribed(action).noted(unreadable(what))),
        }
    }
}

/// The found target, or return the fallback description.
macro_rules! found {
    ($lookup:expr) => {
        match $lookup {
            Lookup::Found(target) => target,
            Lookup::Fallback(description) => return description,
        }
    };
}
use found;

/// Whether every top-level captured parameter is one the description states
/// or checks.
fn only_keys(params: &Value, stated: &[&str]) -> bool {
    params
        .as_object()
        .is_some_and(|map| map.keys().all(|key| stated.contains(&key.as_str())))
}

/// One fact in a change list.
fn change(text: impl Into<String>) -> DescribedChange {
    DescribedChange {
        text: text.into(),
        flag: None,
    }
}

/// One changed value, as `label: current → proposed`.
fn field_change(label: &str, current: impl Display, proposed: impl Display) -> DescribedChange {
    change(format!("{label}: {current} → {proposed}"))
}

/// A captured string parameter.
fn param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

/// A captured identifier parameter.
fn param_id(params: &Value, key: &str) -> Option<uuid::Uuid> {
    param(params, key).and_then(|id| id.parse().ok())
}

/// A captured list of strings, in order; absent means empty.
fn param_list(params: &Value, key: &str) -> Vec<String> {
    params
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// What a list replacement adds and removes, quoted, in the order given.
/// Unchanged entries are left out.
fn list_changes(label: &str, current: &[String], proposed: &[String]) -> Vec<DescribedChange> {
    let added: Vec<String> = proposed
        .iter()
        .filter(|value| !current.contains(value))
        .map(|value| quoted(value))
        .collect();
    let removed: Vec<String> = current
        .iter()
        .filter(|value| !proposed.contains(value))
        .map(|value| quoted(value))
        .collect();
    let mut changes = Vec::new();
    if !added.is_empty() {
        changes.push(change(format!("{label} added: {}", added.join(", "))));
    }
    if !removed.is_empty() {
        changes.push(change(format!("{label} removed: {}", removed.join(", "))));
    }
    changes
}

/// A list shown whole, or `none` when it is empty.
fn quoted_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values
            .iter()
            .map(|value| quoted(value))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Reason shown when the target of a captured change no longer exists.
fn gone(what: &str) -> String {
    format!("The {what} no longer exists.")
}

/// Note shown when current state cannot be read.
fn unreadable(what: &str) -> String {
    format!("The current {what} cannot be read, so the change cannot be shown.")
}

/// The module that describes an action's target.
enum Family {
    Tools,
    RateLimits,
    Rbac,
    ApiKeys,
    Peers,
    Agents,
    Audit,
    Access,
    Catalog,
}

/// Each described action, named exactly so a newly registered action is
/// never assumed to be described.
fn family(action: &str) -> Option<Family> {
    Some(match action {
        "tool_contract.approve" | "tool_contract.reject" => Family::Tools,
        "rate_limit.create" | "rate_limit.update" | "rate_limit.delete" => Family::RateLimits,
        "rbac.role.create"
        | "rbac.role.update"
        | "rbac.role.delete"
        | "rbac.assignment.grant"
        | "rbac.assignment.grant_privileged"
        | "rbac.assignment.revoke"
        | "rbac.assignment.revoke_privileged"
        | "rbac.group_mapping.grant"
        | "rbac.group_mapping.grant_privileged"
        | "rbac.group_mapping.revoke"
        | "rbac.group_mapping.revoke_privileged" => Family::Rbac,
        "api_key.mint"
        | "api_key.revoke"
        | "api_key.update_grants"
        | "api_key_profile.create"
        | "api_key_profile.delete" => Family::ApiKeys,
        "peer.create" | "peer.update" | "peer.delete" => Family::Peers,
        "agent_config.create" | "agent_config.update" | "agent_config.delete" => Family::Agents,
        "tenant.update"
        | "audit.retention.set"
        | "audit.retention.clear"
        | "audit.routing.set"
        | "audit.routing.clear" => Family::Audit,
        "oauth_consent.revoke"
        | "upstream_session.revoke"
        | "break_glass.mint"
        | "break_glass.revoke" => Family::Access,
        "group.create_local"
        | "group.delete_local"
        | "scope.create_local"
        | "scope.delete_local"
        | "inspection_rule.delete"
        | "skill.approve"
        | "skill.reject"
        | "skill.quarantine"
        | "upstream.reconnect"
        | "upstream.refresh_catalog"
        | "upstream.quarantine.clear"
        | "catalog.server.unquarantine"
        | "config.reload" => Family::Catalog,
        _ => return None,
    })
}

/// Actions whose cards show the generic title and outcome with their exact
/// parameters open. Policy and server-set changes show their effect preview
/// in place of a target description.
#[cfg(test)]
const UNDESCRIBED: &[&str] = &[
    "manifest.publish",
    "manifest.remove_servers",
    "manifest.rollback",
    "manifest.stage_and_publish",
    "manifest.upsert_servers",
    "policy.publish",
    "policy.rollback",
    "policy.upsert_fragment",
];

/// Describe one pending change from current gateway state, as `viewer`
/// would approve it.
pub(crate) async fn describe(
    state: &Arc<AdminState>,
    viewer: Option<&Principal>,
    change: &ChangeRequest,
) -> ChangeDescription {
    let action = change.action_type.as_str();
    let mut description = match family(action) {
        Some(Family::Tools) => {
            tools::tool_contract(state, change, action == "tool_contract.approve").await
        }
        Some(Family::RateLimits) => rate_limits::describe(state, change).await,
        Some(Family::Rbac) => rbac::describe(state, change).await,
        Some(Family::ApiKeys) => api_keys::describe(state, change).await,
        Some(Family::Peers) => peers::describe(state, change).await,
        Some(Family::Agents) => agents::describe(state, change).await,
        Some(Family::Audit) => audit::describe(state, change).await,
        Some(Family::Access) => access::describe(state, change).await,
        Some(Family::Catalog) => catalog::describe(state, change).await,
        None => ChangeDescription::undescribed(action),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_values_are_complete_and_reveal_invisible_characters() {
        let long = format!("{}-end", "a".repeat(200));
        assert_eq!(quoted(&long), format!("“{long}”"));
        assert_eq!(quoted("a\u{200B}b"), "“a[U+200B]b”");
        assert_eq!(quoted("ops\tadmins\n"), "“ops[U+0009]admins[U+000A]”");
        assert_ne!(quoted("ops admins"), quoted("ops\tadmins"));
    }

    /// Every described action declares exactly the parameters its schema
    /// accepts, so a new or renamed parameter fails here until the card
    /// states it, checks it, or keeps the parameters open for it. At render
    /// time, any captured key outside the stated set keeps them open.
    #[test]
    fn described_actions_declare_exactly_their_schema_parameters() {
        let tables = [
            tools::DECLARED,
            rate_limits::DECLARED,
            rbac::DECLARED,
            api_keys::DECLARED,
            peers::DECLARED,
            agents::DECLARED,
            audit::DECLARED,
            access::DECLARED,
            catalog::DECLARED,
        ];
        let registry = crate::change_executor::registry();
        for action in registry.action_types() {
            if family(action).is_none() {
                continue;
            }
            let declared: std::collections::BTreeSet<&str> = tables
                .iter()
                .flat_map(|table| table.iter())
                .filter(|(declared, _)| *declared == action)
                .flat_map(|(_, keys)| keys.iter().copied())
                .collect();
            let schema = registry
                .params_schema(action)
                .expect("registered action has a schema");
            let accepted: std::collections::BTreeSet<&str> = schema["properties"]
                .as_object()
                .map(|properties| properties.keys().map(String::as_str).collect())
                .unwrap_or_default();
            assert_eq!(
                declared, accepted,
                "{action}: the card's declared parameters must match its schema"
            );
        }
    }

    #[test]
    fn every_action_is_described_or_recorded_as_open() {
        let registered = crate::change_executor::registry().action_types();
        for action in &registered {
            assert!(
                family(action).is_some() != UNDESCRIBED.contains(action),
                "{action} must be described or listed in UNDESCRIBED, not both"
            );
        }
        for action in UNDESCRIBED {
            assert!(
                registered.contains(action),
                "{action} is listed in UNDESCRIBED but not registered"
            );
        }
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
}
