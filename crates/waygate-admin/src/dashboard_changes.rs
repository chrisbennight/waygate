//! Change-request review queue — `/admin/t/{tenant}/changes` (HITL).
//!
//! The operator-facing twin of the `change_requests` REST surface: a human
//! sees pending change requests an agent proposed (`mcp:propose`) and
//! clicks **Approve** (which runs the captured intent server-side via the
//! executor) or **Deny** (with a reason returned to the maker). Three
//! lifecycle sections, each fetched with a precise
//! [`waygate_changeset::ChangeRequestLifecycle`] predicate so the store's
//! cap applies per-bucket:
//!
//! 1. **Pending** — `status = 'pending' AND expires_at > now()`. The queue
//!    that needs a human; each row carries Approve + Deny forms.
//! 2. **Expired** — `status = 'pending' AND expires_at <= now()`. Lapsed
//!    without a decision; read-only.
//! 3. **Decided** — terminal history (`approved` / `executing` / `executed`
//!    / `failed` / `denied` / `expired`), most recent first, capped.
//!
//! Approve/Deny reuse the REST surface's
//! [`crate::change_requests::approve_and_execute_core`] /
//! [`crate::change_requests::deny_core`] so the HTML and JSON paths can't
//! drift — same configured-quorum enforcement, single-use execution claim, audit, and
//! fail-loud execution. Gated by `mcp:admin` (the checker scope) + CSRF,
//! exactly like the equivalent REST endpoints (`require_admin`).

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_changeset::{
    ChangeRequest, ChangeRequestLifecycle, ChangeRequestStatus, ChangeRequestSummary,
};
use waygate_oidc::{AuthMethod, Principal, Scope, Session};

use crate::auth::CsrfToken;
use crate::change_requests::{approve_and_execute_core, deny_core};
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// Cap on rendered decided-history rows. The REST surface
/// (`GET /api/v1/admin/change_requests?lifecycle=decided`) is the full
/// source.
const HISTORY_LIMIT: usize = 50;
/// Pending rows render their complete params. Eight maximum-sized agent-config
/// proposals keep one approval page near the original aggregate render bound;
/// one extra row is fetched only to determine whether a next page exists.
pub(crate) const PENDING_PARAMS_PAGE_SIZE: u32 = 8;
const PENDING_FETCH_LIMIT: u32 = PENDING_PARAMS_PAGE_SIZE + 1;
/// Expired/decided store fetch window; those rows do not render params.
const BUCKET_LIMIT: u32 = 200;
/// Max policy-change effect previews computed per `/changes` render. Each
/// preview runs a bounded (≤[`crate::policy_bundles`]'s 500-row) decision
/// replay, so this caps the per-render cost: a maker holding `mcp:propose`
/// can't make the approver's queue render arbitrarily expensive by queuing many
/// policy changes. Realistic pending counts sit far below this; legacy overflow
/// rows show captured params only, while mandatory-preview actions remain
/// unapprovable until a focused render computes their effect.
pub(crate) const POLICY_PREVIEW_CAP: usize = 25;

#[derive(Template)]
#[template(path = "changes.html")]
struct ChangesPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the change-request store is unwired (dev / no DB).
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin`. The page
    /// renders an "insufficient scope" card and SKIPS the data — mirrors
    /// the `require_admin` gate on the REST decision endpoints so a
    /// non-admin SSO session can't read proposed-change detail by
    /// browsing instead of curling.
    insufficient_scope: bool,
    pending: Vec<ChangeRow>,
    pending_prev_rel: Option<String>,
    pending_next_rel: Option<String>,
    expired: Vec<ChangeRow>,
    decided: Vec<ChangeRow>,
    decided_truncated: bool,
    /// Per-bucket "failed to load" flags so a store error reads as an
    /// error, not an empty section.
    expired_load_error: bool,
    decided_load_error: bool,
    /// Page-level banner — set only when the load-bearing Pending bucket
    /// failed.
    error: Option<String>,
    /// PRG channel: an approve/deny failure is carried back here.
    ch_error: Option<String>,
}

struct ChangeRow {
    id: Uuid,
    /// Relative URLs for the per-row decision forms (rendered only on
    /// Pending rows). Precomputed because askama can't `format!` inline.
    approve_rel: String,
    deny_rel: String,
    action_type: String,
    requested_by: String,
    justification: String,
    /// Pretty-rendered captured params — the maker's exact proposed intent,
    /// shown to the human approver. Review is only meaningful if the approver
    /// sees WHAT they are authorizing, not just `action_type` + a maker-written
    /// `justification`. Empty `{}` when there are no params.
    params_pretty: String,
    binding_code: String,
    /// CIBA-style display status: `authorization_pending` for a live
    /// pending row, else the literal terminal status.
    status: String,
    approver: Option<String>,
    denied_reason: Option<String>,
    /// One-line outcome detail: the execution result (executed) or the
    /// error (failed); `None` otherwise.
    outcome: Option<String>,
    /// Outcome-first receipt for an executed server-manifest change. Publication
    /// is the durable mutation; fleet activation is a separately observed state.
    /// Non-manifest outcomes continue to use `outcome`.
    manifest_execution: Option<ManifestExecutionOutcomeView>,
    created_at_abs: String,
    expires_at_abs: String,
    /// Frozen approval bar shown before the action controls.
    approval_requirement: ApprovalRequirementView,
    /// Policy-aware preview for a pending publish, rollback, or fragment-upsert
    /// change — compile status, attached-test results, and the computed
    /// blast radius — so the approver reviews the EFFECT, not just the raw
    /// `bundle_id` / `version` in `params_pretty`. `None` for non-policy
    /// actions, and for decided/expired rows (the change already ran — its
    /// `outcome` is shown instead). Rendered ABOVE `params_pretty`, which
    /// always stays in full.
    policy_preview: Option<PolicyChangePreviewView>,
    /// Server-review parity: the manifest analogue of `policy_preview` for a
    /// pending `manifest.publish` / `manifest.rollback` change — the blast-radius
    /// of the candidate's `risk`/`pii`/`side_effects` reclassification replayed
    /// against the live policy. `None` for non-manifest actions and for
    /// decided/expired rows. Mutually exclusive with `policy_preview` (a row is
    /// one or the other).
    manifest_preview: Option<ManifestChangePreviewView>,
    /// The approver must explicitly confirm that they reviewed the computed
    /// effect before the approval form can be submitted.
    effect_preview_acknowledgement_required: bool,
    /// The effect preview is missing or found a fail-closed condition, so the
    /// dashboard keeps Deny available but does not offer approval.
    approval_blocked: bool,
}

struct ManifestExecutionOutcomeView {
    publication: String,
    activation_label: &'static str,
    activation: String,
    activation_tone: &'static str,
}

/// Human-readable projection of the frozen approval requirement. Every
/// approval surface renders this before the decision controls so the checker
/// can see the role, factor, and timing conditions the server will enforce.
pub(crate) struct ApprovalRequirementView {
    pub(crate) summary: String,
    pub(crate) step_up_required: bool,
    pub(crate) cooldown_until_abs: Option<String>,
}

pub(crate) fn approval_requirement_view(c: &ChangeRequest) -> ApprovalRequirementView {
    approval_requirement_view_fields(
        c.required_approvals,
        &c.eligible_role,
        &c.required_factors,
        c.cooldown_seconds,
        c.created_at,
    )
}

fn approval_requirement_view_fields(
    required_approvals: i32,
    eligible_role: &str,
    required_factors: &[String],
    cooldown_seconds: Option<i32>,
    created_at: OffsetDateTime,
) -> ApprovalRequirementView {
    let approval_word = if required_approvals == 1 {
        "approval"
    } else {
        "distinct approvals"
    };
    let factors = if required_factors.is_empty() {
        "dashboard session".to_owned()
    } else {
        required_factors.join(" + ")
    };
    let cooldown_until_abs = cooldown_seconds
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| created_at.checked_add(time::Duration::seconds(i64::from(seconds))))
        .map(format_ts_abs);
    ApprovalRequirementView {
        summary: format!(
            "{} {} · role {} · {}",
            required_approvals, approval_word, eligible_role, factors
        ),
        step_up_required: !required_factors.is_empty(),
        cooldown_until_abs,
    }
}

/// Template projection of a [`crate::change_policy_preview::PolicyChangePreview`]
/// for the approval review. Holds the domain reports directly (their fields are
/// public) so the template renders the same test/impact shapes the policy-bundles
/// pane does, plus a flattened compile state the template can switch on.
pub(crate) struct PolicyChangePreviewView {
    /// Human-legible action ("Publish draft as v3" / "Roll back to v2").
    pub(crate) kind_label: String,
    /// `"ok"` (parses), `"error"` (won't compile — can't land), or `"unknown"`
    /// (content couldn't be loaded; see `note`).
    pub(crate) compile_state: &'static str,
    /// The parse error when `compile_state == "error"`.
    pub(crate) compile_error: Option<String>,
    /// Attached-test report (publish only, when the draft carries tests).
    pub(crate) tests: Option<crate::policy_tests::PolicyTestReport>,
    /// Blast-radius replay against the proposed content.
    pub(crate) impact: Option<crate::impact::ImpactReport>,
    /// Why a piece is absent (missing draft, unwired store, malformed params).
    pub(crate) note: Option<String>,
    /// "Will not execute" reason — set when the executor would refuse this change
    /// (non-draft publish target, draft rollback target, malformed tests). The
    /// template renders it as a prominent banner so the approver doesn't approve
    /// an effect that can't actually happen.
    pub(crate) blocked: Option<String>,
}

impl PolicyChangePreviewView {
    pub(crate) fn from_preview(p: crate::change_policy_preview::PolicyChangePreview) -> Self {
        use crate::change_policy_preview::{CompileStatus, PolicyChangeKind};
        let kind_label = match p.kind {
            PolicyChangeKind::Publish { version } if version > 0 => {
                format!("Publish draft as v{version}")
            }
            PolicyChangeKind::Publish { .. } => "Publish draft".to_owned(),
            PolicyChangeKind::Rollback { version } if version > 0 => {
                format!("Roll back to v{version}")
            }
            PolicyChangeKind::Rollback { .. } => "Roll back".to_owned(),
            PolicyChangeKind::UpsertFragment {
                policy_id: Some(policy_id),
            } => format!("Upsert and publish policy @id={policy_id}"),
            PolicyChangeKind::UpsertFragment { .. } => {
                "Upsert and publish policy fragment".to_owned()
            }
        };
        let (compile_state, compile_error) = match p.compile {
            CompileStatus::Ok => ("ok", None),
            CompileStatus::Error(e) => ("error", Some(e)),
            CompileStatus::Unknown => ("unknown", None),
        };
        Self {
            kind_label,
            compile_state,
            compile_error,
            tests: p.tests,
            impact: p.impact,
            note: p.note,
            blocked: p.blocked,
        }
    }
}

/// Template projection of a
/// [`crate::manifest_change_preview::ManifestChangePreview`] for the approval
/// review — the manifest analogue of [`PolicyChangePreviewView`]. No
/// `compile_state`/`tests`: a manifest's validity (does it parse?) is carried
/// inside the report's own `error`, and there is no attached-test gate.
pub(crate) struct ManifestChangePreviewView {
    /// Human-legible action ("Publish manifest draft as v3" / "Roll back to v2").
    pub(crate) kind_label: String,
    /// Blast-radius replay of the candidate's classification change.
    pub(crate) impact: Option<crate::manifest_impact::ManifestImpactReport>,
    /// Outcome-first projection across configured capability, post-publication
    /// availability, and the operator work that remains. This is deliberately
    /// separate from historical decision replay: newly added tools can have a
    /// large service impact while there are no reclassified tools to replay.
    pub(crate) effective: Option<ManifestEffectiveImpactView>,
    /// Plain-language applicability of the historical replay report.
    pub(crate) replay_summary: Option<String>,
    /// Plain-language result of applying candidate tool facts to a bounded set
    /// of distinct recent caller contexts.
    pub(crate) prospective_summary: Option<String>,
    /// Whether per-target prospective verdict totals are available.
    pub(crate) show_prospective_details: bool,
    /// Whether the replay accounting table is meaningful for this candidate.
    pub(crate) show_replay_details: bool,
    /// Why a piece is absent (missing bundle, unwired store, malformed params).
    pub(crate) note: Option<String>,
    /// Why approval is unavailable: an execution precondition failed or a
    /// mandatory part of the current effect preview could not be computed.
    /// Rendered as a prominent banner.
    pub(crate) blocked: Option<String>,
}

impl ManifestChangePreviewView {
    pub(crate) fn from_preview(p: crate::manifest_change_preview::ManifestChangePreview) -> Self {
        use crate::manifest_change_preview::ManifestChangeKind;
        let blocked = p.mandatory_approval_blocker();
        let kind_label = match p.kind {
            ManifestChangeKind::Publish { version } if version > 0 => {
                format!("Publish manifest draft as v{version}")
            }
            ManifestChangeKind::Publish { .. } => "Publish manifest draft".to_owned(),
            ManifestChangeKind::Rollback { version } if version > 0 => {
                format!("Roll back manifests to v{version}")
            }
            ManifestChangeKind::Rollback { .. } => "Roll back manifests".to_owned(),
            ManifestChangeKind::StageAndPublish => "Publish manifest set".to_owned(),
            ManifestChangeKind::UpsertServers => "Upsert manifest servers".to_owned(),
            ManifestChangeKind::RemoveServers => "Remove manifest servers".to_owned(),
        };
        let replay_summary = p.impact.as_ref().map(replay_summary).or_else(|| {
            p.effective.as_ref().map(|_| {
                "Historical authorization replay is unavailable for this preview.".to_owned()
            })
        });
        let prospective_summary = p.impact.as_ref().map(prospective_summary).or_else(|| {
            p.effective.as_ref().map(|_| {
                "Prospective authorization sampling is unavailable for this preview.".to_owned()
            })
        });
        Self {
            kind_label,
            effective: p.effective.map(ManifestEffectiveImpactView::from_impact),
            replay_summary,
            prospective_summary,
            show_prospective_details: p
                .impact
                .as_ref()
                .is_some_and(show_manifest_prospective_details),
            show_replay_details: p.impact.as_ref().is_some_and(show_manifest_replay_details),
            impact: p.impact,
            note: p.note,
            blocked,
        }
    }
}

/// Human-language projection of the domain-level effective manifest impact.
/// Keeping this conversion server-side makes both approval surfaces render the
/// same conclusion without teaching Askama templates domain-enum logic.
pub(crate) struct ManifestEffectiveImpactView {
    pub(crate) outcome: String,
    pub(crate) outcome_tone: &'static str,
    pub(crate) tool_delta: String,
    pub(crate) resource_delta: String,
    pub(crate) added_tool_posture: Option<String>,
    pub(crate) approval_posture: Option<String>,
    pub(crate) servers: Vec<ManifestServerImpactView>,
    pub(crate) follow_ups: Vec<String>,
    pub(crate) fleet_note: Option<&'static str>,
}

pub(crate) struct ManifestServerImpactView {
    pub(crate) server: String,
    pub(crate) outcome: String,
    pub(crate) barriers: Vec<String>,
}

impl ManifestEffectiveImpactView {
    fn from_impact(impact: crate::manifest_effect::ManifestEffectiveImpact) -> Self {
        use crate::manifest_effect::ActivationReadiness;

        let outcome_tone = match impact.activation_readiness {
            ActivationReadiness::BlockedAfterChange => "blocked",
            ActivationReadiness::Unknown | ActivationReadiness::RuntimeContingent => "attention",
            ActivationReadiness::ExpectedAvailable => "settled",
            ActivationReadiness::Removed
            | ActivationReadiness::Mixed
            | ActivationReadiness::NoRuntimeChange => "neutral",
        };
        let outcome = effective_outcome(&impact);
        let tool_delta = format!(
            "{} added · {} removed · {} reclassified",
            impact.tools.added, impact.tools.removed, impact.tools.reclassified
        );
        let resource_delta = format!(
            "{} resource prefixes added · {} removed · {} reclassified",
            impact.resources.added, impact.resources.removed, impact.resources.reclassified
        );
        let approval_posture = match (
            impact.tools.approval_relaxed_servers,
            impact.tools.approval_tightened_servers,
            impact.tools.approval_relaxed_manifest_tools,
            impact.tools.approval_tightened_manifest_tools,
        ) {
            (0, 0, _, _) => None,
            (servers, 0, tools, _) => Some(format!(
                "Ordinary annotation/catalog approval is suppressed for every runtime tool on {servers} existing server{}, including {tools} manifest-declared tool{}; Cedar policy remains authoritative.",
                if servers == 1 { "" } else { "s" },
                if tools == 1 { "" } else { "s" }
            )),
            (0, servers, _, tools) => Some(format!(
                "Ordinary annotation/catalog approval is restored for every runtime tool on {servers} existing server{}, including {tools} manifest-declared tool{}; Cedar policy remains authoritative.",
                if servers == 1 { "" } else { "s" },
                if tools == 1 { "" } else { "s" }
            )),
            (relaxed, tightened, relaxed_tools, tightened_tools) => Some(format!(
                "Ordinary approval is suppressed on {relaxed} server(s) ({relaxed_tools} manifest-declared tools) and restored on {tightened} ({tightened_tools} tools); Cedar policy remains authoritative."
            )),
        };
        let mut posture = Vec::new();
        if impact.tools.added_side_effecting > 0 {
            let count = impact.tools.added_side_effecting;
            posture.push(format!(
                "{count} added tool{} may have side effects",
                if count == 1 { "" } else { "s" }
            ));
        }
        if impact.tools.added_pii > 0 {
            let count = impact.tools.added_pii;
            posture.push(format!(
                "{count} added tool{} {} PII",
                if count == 1 { "" } else { "s" },
                if count == 1 { "handles" } else { "handle" }
            ));
        }
        if impact.tools.added_high_risk > 0 {
            let count = impact.tools.added_high_risk;
            posture.push(format!(
                "{count} added tool{} {} high risk",
                if count == 1 { "" } else { "s" },
                if count == 1 { "is" } else { "are" }
            ));
        }
        if impact.resources.added_high_risk > 0 {
            let count = impact.resources.added_high_risk;
            posture.push(format!(
                "{count} added resource prefix{} {} high risk",
                if count == 1 { "" } else { "es" },
                if count == 1 { "is" } else { "are" }
            ));
        }
        let servers = impact
            .servers
            .into_iter()
            .map(|server| ManifestServerImpactView {
                outcome: server_outcome(server.manifest_change, server.readiness),
                barriers: server
                    .barriers
                    .into_iter()
                    .map(availability_barrier)
                    .collect(),
                server: server.server,
            })
            .collect();
        let follow_ups = impact
            .follow_up_actions
            .into_iter()
            .map(follow_up_summary)
            .collect();
        Self {
            outcome,
            outcome_tone,
            tool_delta,
            resource_delta,
            added_tool_posture: (!posture.is_empty()).then(|| posture.join("; ")),
            approval_posture,
            servers,
            follow_ups,
            fleet_note: impact.fleet_activation_asynchronous.then_some(
                "If this change executes, publication and fleet activation are separate: activation converges asynchronously across the gateway fleet.",
            ),
        }
    }
}

fn effective_outcome(impact: &crate::manifest_effect::ManifestEffectiveImpact) -> String {
    use crate::manifest_effect::{ActivationReadiness, CapabilityChange};

    let capability = match impact.capability_change {
        CapabilityChange::Expands => "Expands the configured capability surface".to_owned(),
        CapabilityChange::Restricts => "Restricts the configured capability surface".to_owned(),
        CapabilityChange::Changes => "Changes the configured capability surface".to_owned(),
        CapabilityChange::ConfigurationOnly => {
            "Changes server configuration without changing the tool list".to_owned()
        }
        CapabilityChange::None => "Makes no configured capability change".to_owned(),
    };
    let availability = match impact.activation_readiness {
        ActivationReadiness::BlockedAfterChange => {
            "but at least one changed server will remain unavailable after publication"
        }
        ActivationReadiness::RuntimeContingent => {
            "and availability depends on a successful runtime connection"
        }
        ActivationReadiness::ExpectedAvailable => {
            "and the changed servers are expected to become available"
        }
        ActivationReadiness::Removed => "and removes the affected servers from service",
        ActivationReadiness::Mixed => "with mixed post-publication availability",
        ActivationReadiness::Unknown => "but post-publication availability cannot be confirmed",
        ActivationReadiness::NoRuntimeChange => "with no runtime activation change",
    };
    format!("{capability}, {availability}.")
}

fn server_outcome(
    change: crate::manifest_effect::ManifestServerChange,
    readiness: crate::manifest_effect::ActivationReadiness,
) -> String {
    use crate::manifest_effect::{ActivationReadiness, ManifestServerChange};
    let change = match change {
        ManifestServerChange::Added => "Added to the manifest",
        ManifestServerChange::Removed => "Removed from the manifest",
        ManifestServerChange::Updated => "Configuration updated",
    };
    let state = match readiness {
        ActivationReadiness::ExpectedAvailable => "expected to be available",
        ActivationReadiness::RuntimeContingent => "connection must still succeed",
        ActivationReadiness::BlockedAfterChange => "remains unavailable",
        ActivationReadiness::Removed => "will be drained from service",
        ActivationReadiness::Mixed => "has mixed runtime outcomes",
        ActivationReadiness::Unknown => "availability is unknown",
        ActivationReadiness::NoRuntimeChange => "no runtime change",
    };
    format!("{change}; {state}.")
}

fn availability_barrier(barrier: crate::manifest_effect::AvailabilityBarrier) -> String {
    use crate::manifest_effect::{AvailabilityBarrier, CatalogLifecycle};
    match barrier {
        AvailabilityBarrier::CatalogLifecycle { status } => match status {
            CatalogLifecycle::Missing => "No catalog record exists yet.",
            CatalogLifecycle::Proposed => "Catalog review is still pending.",
            CatalogLifecycle::Approved => "Catalog promotion to live is still pending.",
            CatalogLifecycle::Live => "The catalog record is live.",
            CatalogLifecycle::Quarantined => "Catalog status remains quarantined.",
            CatalogLifecycle::Retired => "Catalog status remains retired.",
            CatalogLifecycle::Unavailable => "Catalog state could not be read.",
        }
        .to_owned(),
        AvailabilityBarrier::CatalogStateUnavailable => {
            "Catalog state could not be read.".to_owned()
        }
        AvailabilityBarrier::DriftQuarantine { tools } => plural_count(
            tools,
            "1 tool remains drift-quarantined.",
            &format!("{tools} tools remain drift-quarantined."),
        ),
        AvailabilityBarrier::RestartRequired => {
            "Resource ownership and connection shape changed together; restart the gateway to apply this server safely.".to_owned()
        }
    }
}

fn follow_up_summary(action: crate::manifest_effect::FollowUpAction) -> String {
    use crate::manifest_effect::FollowUpKind;
    match action.kind {
        FollowUpKind::PromoteCatalogServer => {
            format!("Complete governed catalog recovery for {}.", action.server)
        }
        FollowUpKind::ClearDriftQuarantine => format!(
            "Review observed contracts, then clear the drift quarantine for {}.",
            action.server
        ),
        FollowUpKind::VerifyConnection => {
            format!("Verify {} connects after publication.", action.server)
        }
        FollowUpKind::RestartGateway => {
            format!("Restart the gateway to apply {} safely.", action.server)
        }
        FollowUpKind::VerifyFleetConvergence => {
            format!(
                "Verify {} converges across the gateway fleet.",
                action.server
            )
        }
    }
}

fn plural_count(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        singular.to_owned()
    } else {
        plural.to_owned()
    }
}

fn replay_summary(report: &crate::manifest_impact::ManifestImpactReport) -> String {
    use crate::manifest_impact::ManifestReplayApplicability;
    match report.replay_applicability {
        ManifestReplayApplicability::Replayed => {
            if report.changed == 0 {
                format!(
                    "Recent authorization replay found no changed decisions across {} replayed call{}.",
                    report.replayed,
                    if report.replayed == 1 { "" } else { "s" }
                )
            } else {
                format!(
                    "Recent authorization replay found {} decision{} that would change.",
                    report.changed,
                    if report.changed == 1 { "" } else { "s" }
                )
            }
        }
        ManifestReplayApplicability::NoReclassifiedTools => {
            if report.tools_added > 0
                || report.tools_removed > 0
                || report.resources_added > 0
                || report.resources_removed > 0
            {
                "Not applicable: this candidate changes capability membership, but does not reclassify an existing tool or resource prefix.".to_owned()
            } else {
                "Not applicable: this candidate does not reclassify an existing tool or resource prefix."
                    .to_owned()
            }
        }
        ManifestReplayApplicability::NoMatchingHistory => {
            "No matching history: existing tools or resource prefixes are reclassified, but no recent captured decision used them.".to_owned()
        }
        ManifestReplayApplicability::NoReplayableHistory => {
            "No replayable history: matching decisions did not retain the inputs needed for comparison.".to_owned()
        }
        ManifestReplayApplicability::Unavailable => {
            "Historical authorization replay is unavailable for this preview.".to_owned()
        }
        ManifestReplayApplicability::LedgerOnlyNoActivation => {
            "Not applicable: this tenant-local ledger change does not activate the gateway-wide manifest."
                .to_owned()
        }
    }
}

fn prospective_summary(report: &crate::manifest_impact::ManifestImpactReport) -> String {
    use crate::manifest_impact::ManifestProspectiveApplicability;
    let sample = &report.prospective_access;
    match sample.applicability {
        ManifestProspectiveApplicability::Evaluated => format!(
            "Across {} distinct recent caller context{} and {} added or reclassified access target{}, the preview produced {} allow, {} deny, {} step-up, and {} approval-required verdicts.{}",
            sample.caller_contexts_considered,
            if sample.caller_contexts_considered == 1 { "" } else { "s" },
            sample.targets_considered,
            if sample.targets_considered == 1 { "" } else { "s" },
            sample.allow,
            sample.deny,
            sample.step_up,
            sample.approval_required,
            if sample.indeterminate == 0 {
                String::new()
            } else {
                format!(" {} context-target pair(s) were indeterminate.", sample.indeterminate)
            }
        ),
        ManifestProspectiveApplicability::NoCandidateTools => {
            "Not applicable: no manifest-declared added or reclassified access targets are available for prospective evaluation.".to_owned()
        }
        ManifestProspectiveApplicability::NoConcreteResourceHistory => {
            "No prospective resource sample: changed URI prefixes had no exact resource URI in the recent audit window, and the preview does not invent one.".to_owned()
        }
        ManifestProspectiveApplicability::NoRecentCallerContexts => {
            "No prospective caller sample: no recent reconstructable caller contexts were available. This is not evidence that the candidate tools are inaccessible.".to_owned()
        }
        ManifestProspectiveApplicability::Unavailable => {
            "Prospective authorization sampling is unavailable for this preview.".to_owned()
        }
        ManifestProspectiveApplicability::LedgerOnlyNoActivation => {
            "Not applicable: this tenant-local ledger change does not activate the gateway-wide manifest.".to_owned()
        }
    }
}

fn show_manifest_prospective_details(
    report: &crate::manifest_impact::ManifestImpactReport,
) -> bool {
    matches!(
        report.prospective_access.applicability,
        crate::manifest_impact::ManifestProspectiveApplicability::Evaluated
    )
}

fn show_manifest_replay_details(report: &crate::manifest_impact::ManifestImpactReport) -> bool {
    matches!(
        report.replay_applicability,
        crate::manifest_impact::ManifestReplayApplicability::Replayed
            | crate::manifest_impact::ManifestReplayApplicability::NoMatchingHistory
            | crate::manifest_impact::ManifestReplayApplicability::NoReplayableHistory
    )
}

/// The effect preview for ONE pending change request — at most one of the two
/// is `Some` (a change is a policy change, a manifest change, or neither).
/// Shared by EVERY approval surface so an approver always sees the blast-radius
/// before approving, regardless of which queue they act from.
pub(crate) struct PendingPreviews {
    pub policy: Option<PolicyChangePreviewView>,
    pub manifest: Option<ManifestChangePreviewView>,
}

/// Compute the policy-or-manifest effect preview for a pending change,
/// decrementing the caller's shared `previews_left` budget when a preview is
/// produced. Returns `(None, None)` past the budget or for a non-previewable
/// action. `policy_change_preview` returns `Some` only for `policy.*` and
/// `manifest_change_preview` only for `manifest.*`, so the two are mutually
/// exclusive. This is the single enrichment both `/changes` (the dedicated
/// queue) and `/decisions` (the unified inbox) call — neither approval surface
/// may show a manifest/policy change with only raw params, or the review gate
/// would be open on the other surface.
pub(crate) async fn preview_pending_change(
    state: &AdminState,
    tenant_id: &str,
    action_type: &str,
    params: &serde_json::Value,
    target_etag: Option<&str>,
    previews_left: &mut usize,
) -> PendingPreviews {
    if *previews_left == 0 {
        // This action's impact preview is mandatory, not best-effort. A busy
        // queue may exhaust the bounded replay budget, but it must never turn
        // the overflow row into a blind approval path. Render an explicit
        // blocked card; a focused reload after earlier rows are decided will
        // compute the exact preview.
        if action_type == "policy.upsert_fragment" {
            return PendingPreviews {
                policy: Some(PolicyChangePreviewView {
                    kind_label: "Upsert and publish policy fragment".to_owned(),
                    compile_state: "unknown",
                    compile_error: None,
                    tests: None,
                    impact: None,
                    note: Some(
                        "the bounded preview budget was exhausted before this row".to_owned(),
                    ),
                    blocked: Some(
                        "the mandatory impact preview has not run, so approval is unavailable"
                            .to_owned(),
                    ),
                }),
                manifest: None,
            };
        }
        return PendingPreviews {
            policy: None,
            manifest: None,
        };
    }
    let policy = crate::change_policy_preview::policy_change_preview(
        state,
        tenant_id,
        action_type,
        params,
        target_etag,
    )
    .await
    .map(PolicyChangePreviewView::from_preview);
    if policy.is_some() {
        *previews_left -= 1;
        return PendingPreviews {
            policy,
            manifest: None,
        };
    }
    let manifest = crate::manifest_change_preview::manifest_change_preview_for_request(
        state,
        tenant_id,
        action_type,
        params,
        target_etag,
        // The dashboard queues render no observed-contracts section, so no
        // observer is offered and none is computed.
        None,
    )
    .await
    .map(ManifestChangePreviewView::from_preview);
    if manifest.is_some() {
        *previews_left -= 1;
    }
    PendingPreviews {
        policy: None,
        manifest,
    }
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/changes", get(changes_page))
        .route("/changes/{id}/approve", post(approve_change))
        .route("/changes/{id}/deny", post(deny_change))
}

#[derive(Debug, Default, Deserialize)]
struct ChangesQuery {
    /// PRG channel for an approve/deny failure message.
    #[serde(default)]
    ch_error: Option<String>,
    /// Offset within the pending bucket. Pending params are paged because each
    /// row is rendered completely for the approver.
    #[serde(default)]
    pending_offset: u32,
    /// Select one tenant-scoped pending request for an approval deep link.
    /// This keeps the target visible even when newer requests push it beyond
    /// the bounded pending page.
    #[serde(default)]
    pending_id: Option<Uuid>,
}

async fn changes_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<ChangesQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.hitl.change_requests.enabled();

    let load = if insufficient_scope {
        LoadResult::default()
    } else {
        load_changes(&state, &read_tenant, q.pending_offset, q.pending_id).await
    };

    let page = ChangesPage {
        chrome: PageChrome::build(
            &state,
            "Change requests",
            "/changes",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        pending: load.pending,
        pending_prev_rel: load.pending_prev_rel,
        pending_next_rel: load.pending_next_rel,
        expired: load.expired,
        decided: load.decided,
        decided_truncated: load.decided_truncated,
        expired_load_error: load.expired_load_error,
        decided_load_error: load.decided_load_error,
        error: load.error,
        ch_error: q.ch_error,
    };
    render(&page)
}

/// Approve form body. A visible approval form carries the preview
/// acknowledgement; the shared core requires it only for policy-fragment
/// changes and ignores it for all other actions.
#[derive(Deserialize)]
struct ApproveForm {
    #[serde(default)]
    csrf: String,
    #[serde(default, alias = "policy_preview_acknowledged")]
    effect_preview_acknowledged: bool,
}

/// Deny form body — CSRF + the required reason returned to the maker.
#[derive(Deserialize)]
struct DenyForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    reason: String,
}

async fn approve_change(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    session: Option<Extension<Session>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<ApproveForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let id = match parse_id(&params, &tenant_ctx) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    let session = session.as_ref().map(|Extension(s)| s);
    match approve_and_execute_core(
        &state,
        principal,
        id,
        session,
        form.effect_preview_acknowledged,
    )
    .await
    {
        Ok(cr) => redirect_ok(
            tenant_ctx,
            &format!("Change {} is now {}.", short(id), cr.status.as_db_str()),
        ),
        Err(e) => redirect_with_error(tenant_ctx, &decision_err_message(&e)),
    }
}

async fn deny_change(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<DenyForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let id = match parse_id(&params, &tenant_ctx) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    if form.reason.trim().is_empty() {
        return redirect_with_error(tenant_ctx, "A reason is required to deny a change.");
    }
    match deny_core(&state, principal, id, &form.reason).await {
        Ok(_) => redirect_ok(tenant_ctx, &format!("Denied change {}.", short(id))),
        Err(e) => redirect_with_error(tenant_ctx, &decision_err_message(&e)),
    }
}

/// Shared admin-gate + CSRF for the decision handlers. Returns
/// `(principal, tenant_ctx)` or the boxed error `Response`.
#[allow(clippy::type_complexity)]
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<Extension<TenantContext>>,
    form_csrf: &str,
) -> Result<(&'a Principal, Option<TenantContext>), Box<Response>> {
    let principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(principal) {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "Change-request decisions require mcp:admin",
            )
                .into_response(),
        ));
    }
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form_csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, form_csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "csrf mismatch").into_response(),
        ));
    }
    // `principal_has_dashboard_admin` already rejected `None`.
    let principal = principal.expect("admin gate guarantees a principal");
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c)))
}

fn parse_id(
    params: &HashMap<String, String>,
    tenant_ctx: &Option<TenantContext>,
) -> Result<Uuid, Box<Response>> {
    let Some(id) = params.get("id") else {
        return Err(Box::new(redirect_with_error(
            tenant_ctx.clone(),
            "Missing change id.",
        )));
    };
    Uuid::parse_str(id.trim()).map_err(|_| {
        Box::new(redirect_with_error(
            tenant_ctx.clone(),
            "Invalid change id.",
        ))
    })
}

fn short(id: Uuid) -> String {
    id.to_string().chars().take(8).collect()
}

fn redirect_ok(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    // The success message rides the same PRG channel; the page renders it
    // as an info banner. Keeps a single redirect target.
    let url = format!(
        "{}?ch_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/changes"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?ch_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/changes"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Operator-safe decision message. The conflict / forbidden / bad-request
/// details are safe to surface (they explain WHY the decision was
/// refused); store/internal errors collapse to a generic line.
pub(crate) fn decision_err_message(e: &ApiError) -> String {
    match e {
        ApiError::ServiceUnavailable(d) => (*d).to_owned(),
        ApiError::NotFound(d) => (*d).to_owned(),
        ApiError::Forbidden(d) => (*d).to_owned(),
        ApiError::ForbiddenDyn(d) => d.clone(),
        ApiError::Conflict(d) => d.clone(),
        ApiError::BadRequest(d) => d.clone(),
        ApiError::UnprocessableEntity(d) => d.clone(),
        _ => "Failed to act on the change — see gateway logs for details.".to_owned(),
    }
}

/// Authorization gate for the change-review page + decisions. OAuth /
/// API-key principal carrying `mcp:admin`; peer assertions refused (same
/// defense-in-depth as `require_admin_extension`).
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

enum FleetActivationObservation {
    StoreUnavailable,
    LoadFailed,
    Available(Vec<waygate_manifest_store::ReplicaHeartbeat>),
}

fn is_manifest_execution_action(action_type: &str) -> bool {
    matches!(
        action_type,
        "manifest.publish"
            | "manifest.rollback"
            | "manifest.stage_and_publish"
            | "manifest.upsert_servers"
            | "manifest.remove_servers"
    )
}

fn receipt_i32(receipt: Option<&serde_json::Value>, field: &str) -> Option<i32> {
    receipt?
        .get(field)?
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
}

fn manifest_publication_summary(action_type: &str, receipt: Option<&serde_json::Value>) -> String {
    let version = receipt_i32(receipt, "version").or_else(|| receipt_i32(receipt, "new_version"));
    match (
        version,
        (action_type == "manifest.rollback")
            .then(|| receipt_i32(receipt, "rolled_back_to_version"))
            .flatten(),
    ) {
        (Some(version), Some(target)) => {
            format!("Published manifest v{version} from rollback target v{target}.")
        }
        (Some(version), None) => format!("Published manifest v{version}."),
        (None, _) => "Manifest publication completed.".to_owned(),
    }
}

fn manifest_execution_outcome(
    tenant: &str,
    action_type: &str,
    status: ChangeRequestStatus,
    receipt: Option<&serde_json::Value>,
    fleet: Option<&FleetActivationObservation>,
    now: OffsetDateTime,
) -> Option<ManifestExecutionOutcomeView> {
    if status != ChangeRequestStatus::Executed || !is_manifest_execution_action(action_type) {
        return None;
    }

    let publication = manifest_publication_summary(action_type, receipt);
    if tenant != waygate_core::TenantId::DEFAULT {
        return Some(ManifestExecutionOutcomeView {
            publication,
            activation_label: "not applicable",
            activation: "Runtime upstreams currently load only the default tenant; this publication updated the tenant ledger only."
                .to_owned(),
            activation_tone: "neutral",
        });
    }

    let Some(activation_hash) = receipt
        .and_then(|value| value.get("activation_hash"))
        .and_then(serde_json::Value::as_str)
    else {
        return Some(ManifestExecutionOutcomeView {
            publication,
            activation_label: "unavailable",
            activation: "This historical receipt predates activation fingerprints, so fleet convergence cannot be verified from it."
                .to_owned(),
            activation_tone: "neutral",
        });
    };
    let expected_version =
        receipt_i32(receipt, "version").or_else(|| receipt_i32(receipt, "new_version"));

    let Some(fleet) = fleet else {
        return Some(ManifestExecutionOutcomeView {
            publication,
            activation_label: "unavailable",
            activation: "Fleet verification evidence was not loaded.".to_owned(),
            activation_tone: "neutral",
        });
    };
    let heartbeats = match fleet {
        FleetActivationObservation::StoreUnavailable => {
            return Some(ManifestExecutionOutcomeView {
                publication,
                activation_label: "unavailable",
                activation:
                    "The manifest store is not configured, so replica heartbeats are unavailable."
                        .to_owned(),
                activation_tone: "neutral",
            });
        }
        FleetActivationObservation::LoadFailed => {
            return Some(ManifestExecutionOutcomeView {
                publication,
                activation_label: "unavailable",
                activation: "Replica heartbeats could not be loaded; publication remains recorded, but activation is unverified."
                    .to_owned(),
                activation_tone: "neutral",
            });
        }
        FleetActivationObservation::Available(heartbeats) => heartbeats,
    };
    if heartbeats.is_empty() {
        return Some(ManifestExecutionOutcomeView {
            publication,
            activation_label: "awaiting evidence",
            activation: "No replicas have reported this activation yet.".to_owned(),
            activation_tone: "warn",
        });
    }

    let mut fresh_count = 0;
    let mut stale_count = 0;
    let mut matching = 0;
    for heartbeat in heartbeats {
        if crate::dashboard_server_manifests::fleet_replica_is_stale(heartbeat.updated_at, now) {
            stale_count += 1;
        } else {
            fresh_count += 1;
            if heartbeat.content_hash == activation_hash && heartbeat.version == expected_version {
                matching += 1;
            }
        }
    }
    let (activation_label, activation, activation_tone) = if fresh_count == 0 {
        (
            "not verified",
            format!("No fresh replica heartbeats; {stale_count} observed replica(s) are stale."),
            "warn",
        )
    } else if matching == fresh_count && stale_count == 0 {
        (
            "verified",
            format!("All {fresh_count} fresh observed replica(s) loaded this version."),
            "ok",
        )
    } else if matching == fresh_count {
        (
            "partially verified",
            format!(
                "All {fresh_count} fresh observed replica(s) match; {stale_count} stale replica(s) remain unverified."
            ),
            "warn",
        )
    } else {
        let stale_suffix = if stale_count == 0 {
            String::new()
        } else {
            format!("; {stale_count} stale replica(s) also remain unverified")
        };
        (
            "pending",
            format!(
                "{matching} of {fresh_count} fresh observed replica(s) loaded this version{stale_suffix}."
            ),
            "warn",
        )
    };
    Some(ManifestExecutionOutcomeView {
        publication,
        activation_label,
        activation,
        activation_tone,
    })
}

async fn load_fleet_activation_observation(
    state: &AdminState,
    tenant: &str,
    decided: &[ChangeRequestSummary],
) -> Option<FleetActivationObservation> {
    let needs_fleet = tenant == waygate_core::TenantId::DEFAULT
        && decided.iter().any(|change| {
            change.status == ChangeRequestStatus::Executed
                && is_manifest_execution_action(&change.action_type)
                && change
                    .execution_result
                    .as_ref()
                    .and_then(|receipt| receipt.get("activation_hash"))
                    .is_some()
        });
    if !needs_fleet {
        return None;
    }
    let Some(store) = state.servers.manifest_store.get() else {
        return Some(FleetActivationObservation::StoreUnavailable);
    };
    match store.list_replica_heartbeats(tenant).await {
        Ok(heartbeats) => Some(FleetActivationObservation::Available(heartbeats)),
        Err(error) => {
            tracing::error!(error = %error, tenant = %tenant, "changes page: fleet activation verification failed");
            Some(FleetActivationObservation::LoadFailed)
        }
    }
}

#[derive(Default)]
struct LoadResult {
    pending: Vec<ChangeRow>,
    pending_prev_rel: Option<String>,
    pending_next_rel: Option<String>,
    expired: Vec<ChangeRow>,
    decided: Vec<ChangeRow>,
    decided_truncated: bool,
    expired_load_error: bool,
    decided_load_error: bool,
    error: Option<String>,
}

async fn load_changes(
    state: &Arc<AdminState>,
    tenant: &str,
    pending_offset: u32,
    pending_id: Option<Uuid>,
) -> LoadResult {
    let Some(store) = state.hitl.change_requests.get() else {
        // No change-request store wired — nothing to load. (changes_page also
        // surfaces this via `store_configured`.)
        return LoadResult::default();
    };
    let focused_pending = if let Some(id) = pending_id {
        match store.get(tenant, id).await {
            Ok(Some(row))
                if row.effective_status(OffsetDateTime::now_utc())
                    == ChangeRequestStatus::Pending =>
            {
                Some(row)
            }
            Ok(_) => None,
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, change_request_id = %id, "changes page: focused pending request failed");
                return LoadResult {
                    error: Some(
                        "Failed to load change requests — see gateway logs for details.".to_owned(),
                    ),
                    ..LoadResult::default()
                };
            }
        }
    } else {
        None
    };
    let (pending, pending_prev_rel, pending_next_rel) = if let Some(row) = focused_pending {
        (vec![row], None, None)
    } else {
        let mut rows = match store
            .list(
                tenant,
                Some(ChangeRequestLifecycle::Pending),
                PENDING_FETCH_LIMIT,
                pending_offset,
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, "changes page: pending list failed");
                return LoadResult {
                    error: Some(
                        "Failed to load change requests — see gateway logs for details.".to_owned(),
                    ),
                    ..LoadResult::default()
                };
            }
        };
        let pending_has_more = rows.len() > PENDING_PARAMS_PAGE_SIZE as usize;
        rows.truncate(PENDING_PARAMS_PAGE_SIZE as usize);
        let (previous, next) = pending_page_links(pending_offset, pending_has_more);
        (rows, previous, next)
    };
    let (expired, expired_load_error) = match store
        .list_summaries(
            tenant,
            Some(ChangeRequestLifecycle::Expired),
            BUCKET_LIMIT,
            0,
        )
        .await
    {
        Ok(rows) => (rows, false),
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "changes page: expired list failed");
            (Vec::new(), true)
        }
    };
    let (mut decided, decided_load_error) = match store
        .list_summaries(
            tenant,
            Some(ChangeRequestLifecycle::Decided),
            BUCKET_LIMIT,
            0,
        )
        .await
    {
        Ok(rows) => (rows, false),
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "changes page: decided list failed");
            (Vec::new(), true)
        }
    };
    let decided_truncated = decided.len() > HISTORY_LIMIT;
    if decided_truncated {
        decided.truncate(HISTORY_LIMIT);
    }
    let fleet_activation = load_fleet_activation_observation(state, tenant, &decided).await;
    let activation_observed_at = OffsetDateTime::now_utc();

    // Enrich each pending previewable policy action with its effect preview
    // (compile / attached-tests / blast-radius), tenant-scoped to the
    // change's OWN tenant (== the executor's resolved tenant). Decided/expired
    // rows skip it — that change already ran, so its `outcome` is shown instead
    // of a fresh preview. Legacy bundle previews degrade best-effort; actions
    // with a mandatory effect preview render a blocked card when it cannot run.
    let mut pending_rows = Vec::with_capacity(pending.len());
    let mut previews_left = POLICY_PREVIEW_CAP;
    for c in pending {
        // Only a policy change consumes a preview slot; a non-policy change
        // returns None cheaply (a bare action-type match) and costs nothing, so
        // it never burns the cap. Past the cap, legacy preview actions show
        // captured params only; mandatory-preview actions fail closed.
        // Enrich with the effect preview (policy or manifest, mutually
        // exclusive), drawing from the shared `previews_left` budget so a queue
        // full of either kind can't run an unbounded number of ≤500-row replays.
        // The same helper enriches the /decisions inbox, so mandatory-preview
        // actions cannot become blind approval paths on either surface.
        let previews = preview_pending_change(
            state,
            &c.tenant_id,
            &c.action_type,
            &c.params,
            c.target_etag.as_deref(),
            &mut previews_left,
        )
        .await;
        let effect_preview_acknowledgement_required =
            crate::change_requests::requires_effect_preview_acknowledgement(&c.action_type);
        let preview_available = previews.policy.is_some() || previews.manifest.is_some();
        let approval_blocked = (effect_preview_acknowledgement_required && !preview_available)
            || previews
                .policy
                .as_ref()
                .is_some_and(|preview| preview.blocked.is_some())
            || previews
                .manifest
                .as_ref()
                .is_some_and(|preview| preview.blocked.is_some());
        let mut row = change_row(c, true);
        row.policy_preview = previews.policy;
        row.manifest_preview = previews.manifest;
        row.effect_preview_acknowledgement_required = effect_preview_acknowledgement_required;
        row.approval_blocked = approval_blocked;
        pending_rows.push(row);
    }

    LoadResult {
        pending: pending_rows,
        pending_prev_rel,
        pending_next_rel,
        expired: expired.into_iter().map(|c| change_row(c, false)).collect(),
        decided: decided
            .into_iter()
            .map(|c| {
                let manifest_execution = manifest_execution_outcome(
                    tenant,
                    &c.action_type,
                    c.status,
                    c.execution_result.as_ref(),
                    fleet_activation.as_ref(),
                    activation_observed_at,
                );
                let mut row = change_row(c, false);
                row.manifest_execution = manifest_execution;
                row
            })
            .collect(),
        decided_truncated,
        expired_load_error,
        decided_load_error,
        error: None,
    }
}

fn pending_page_links(offset: u32, has_more: bool) -> (Option<String>, Option<String>) {
    let previous = (offset > 0).then(|| {
        format!(
            "/changes?pending_offset={}",
            offset.saturating_sub(PENDING_PARAMS_PAGE_SIZE)
        )
    });
    let next = has_more.then(|| {
        format!(
            "/changes?pending_offset={}",
            offset.saturating_add(PENDING_PARAMS_PAGE_SIZE)
        )
    });
    (previous, next)
}

struct ChangeRowSource {
    id: Uuid,
    params: Option<serde_json::Value>,
    action_type: String,
    requested_by: String,
    justification: String,
    binding_code: String,
    required_approvals: i32,
    eligible_role: String,
    required_factors: Vec<String>,
    cooldown_seconds: Option<i32>,
    status: ChangeRequestStatus,
    approver_sub: Option<String>,
    denied_reason: Option<String>,
    execution_result_preview: Option<String>,
    error_message: Option<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl From<ChangeRequest> for ChangeRowSource {
    fn from(c: ChangeRequest) -> Self {
        Self {
            id: c.id,
            params: Some(c.params),
            action_type: c.action_type,
            requested_by: c.requested_by,
            justification: c.justification,
            binding_code: c.binding_code,
            required_approvals: c.required_approvals,
            eligible_role: c.eligible_role,
            required_factors: c.required_factors,
            cooldown_seconds: c.cooldown_seconds,
            status: c.status,
            approver_sub: c.approver_sub,
            denied_reason: c.denied_reason,
            execution_result_preview: c
                .execution_result
                .as_ref()
                .map(|value| truncate(&value.to_string(), 200)),
            error_message: c.error_message,
            created_at: c.created_at,
            expires_at: c.expires_at,
        }
    }
}

impl From<ChangeRequestSummary> for ChangeRowSource {
    fn from(c: ChangeRequestSummary) -> Self {
        Self {
            id: c.id,
            params: None,
            action_type: c.action_type,
            requested_by: c.requested_by,
            justification: c.justification,
            binding_code: c.binding_code,
            required_approvals: c.required_approvals,
            eligible_role: c.eligible_role,
            required_factors: c.required_factors,
            cooldown_seconds: c.cooldown_seconds,
            status: c.status,
            approver_sub: c.approver_sub,
            denied_reason: c.denied_reason,
            execution_result_preview: c.execution_result_preview,
            error_message: c.error_message,
            created_at: c.created_at,
            expires_at: c.expires_at,
        }
    }
}

fn change_row(c: impl Into<ChangeRowSource>, pending: bool) -> ChangeRow {
    let c = c.into();
    let approval_requirement = approval_requirement_view_fields(
        c.required_approvals,
        &c.eligible_role,
        &c.required_factors,
        c.cooldown_seconds,
        c.created_at,
    );
    let now = OffsetDateTime::now_utc();
    let effective_status = if c.status == ChangeRequestStatus::Pending && now >= c.expires_at {
        ChangeRequestStatus::Expired
    } else {
        c.status
    };
    let status = if pending {
        "authorization_pending".to_owned()
    } else {
        effective_status.as_db_str().to_owned()
    };
    let outcome = match effective_status {
        ChangeRequestStatus::Executed => c.execution_result_preview.clone(),
        ChangeRequestStatus::Failed => c.error_message.clone(),
        _ => None,
    };
    ChangeRow {
        approve_rel: format!("/changes/{}/approve", c.id),
        deny_rel: format!("/changes/{}/deny", c.id),
        id: c.id,
        params_pretty: c.params.as_ref().map(render_params).unwrap_or_default(),
        action_type: c.action_type,
        requested_by: c.requested_by,
        justification: c.justification,
        binding_code: c.binding_code,
        status,
        approver: c.approver_sub,
        denied_reason: c.denied_reason,
        outcome,
        manifest_execution: None,
        created_at_abs: format_ts_abs(c.created_at),
        expires_at_abs: format_ts_abs(c.expires_at),
        approval_requirement,
        // Set by the caller (`load_changes`) for pending policy/manifest
        // changes; pure mapping leaves them None.
        policy_preview: None,
        manifest_preview: None,
        effect_preview_acknowledgement_required: false,
        approval_blocked: false,
    }
}

/// Pretty-render captured change-request params for the human approver. The
/// approval review is only meaningful if the approver sees the EXACT, COMPLETE
/// intent they're authorizing — not just `action_type` + a maker-written
/// `justification`: a maker could propose one subject / scope / TTL while
/// writing a benign justification.
///
/// The full params are rendered, NEVER truncated: a hidden field is precisely
/// the blind-approval hole this closes, and there is no admin-reachable
/// endpoint that re-serves the captured params as a fallback (the status poll
/// omits them and is maker-gated). The review well bounds the
/// *visual* size with a scrollbar (`max-height` + `overflow: auto` in
/// `.params-review__pre`); the complete params stay in the DOM for the reviewer
/// to scroll through.
pub(crate) fn render_params(params: &serde_json::Value) -> String {
    serde_json::to_string_pretty(params).unwrap_or_else(|_| params.to_string())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_receipt() -> serde_json::Value {
        serde_json::json!({
            "version": 7,
            "content_hash": "ledger-hash",
            "activation_hash": "activation-hash"
        })
    }

    fn heartbeat(
        replica_id: &str,
        version: i32,
        content_hash: &str,
        updated_at: OffsetDateTime,
    ) -> waygate_manifest_store::ReplicaHeartbeat {
        waygate_manifest_store::ReplicaHeartbeat {
            replica_id: replica_id.to_owned(),
            tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
            version: Some(version),
            content_hash: content_hash.to_owned(),
            updated_at,
        }
    }

    #[test]
    fn manifest_execution_is_verified_only_when_every_observed_replica_is_fresh_and_matching() {
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let receipt = manifest_receipt();
        let fleet = FleetActivationObservation::Available(vec![
            heartbeat("a", 7, "activation-hash", now),
            heartbeat("b", 7, "activation-hash", now),
        ]);
        let outcome = manifest_execution_outcome(
            "default",
            "manifest.upsert_servers",
            ChangeRequestStatus::Executed,
            Some(&receipt),
            Some(&fleet),
            now,
        )
        .expect("manifest outcome");
        assert_eq!(outcome.activation_label, "verified");
        assert_eq!(outcome.activation_tone, "ok");
        assert!(outcome.activation.contains("All 2 fresh observed"));
    }

    #[test]
    fn stale_replica_keeps_manifest_activation_partial() {
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let receipt = manifest_receipt();
        let fleet = FleetActivationObservation::Available(vec![
            heartbeat("fresh", 7, "activation-hash", now),
            heartbeat(
                "stale",
                7,
                "activation-hash",
                now - time::Duration::minutes(2),
            ),
        ]);
        let outcome = manifest_execution_outcome(
            "default",
            "manifest.publish",
            ChangeRequestStatus::Executed,
            Some(&receipt),
            Some(&fleet),
            now,
        )
        .expect("manifest outcome");
        assert_eq!(outcome.activation_label, "partially verified");
        assert!(outcome
            .activation
            .contains("1 stale replica(s) remain unverified"));
    }

    #[test]
    fn tenant_ledger_publication_never_claims_gateway_fleet_activation() {
        let receipt = serde_json::json!({"version": 3, "content_hash": "ledger-hash"});
        let outcome = manifest_execution_outcome(
            "tenant-b",
            "manifest.rollback",
            ChangeRequestStatus::Executed,
            Some(&receipt),
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("manifest outcome");
        assert_eq!(outcome.activation_label, "not applicable");
        assert!(outcome.activation.contains("tenant ledger only"));
    }

    #[test]
    fn pending_page_preserves_the_original_aggregate_params_bound() {
        let previous_aggregate =
            BUCKET_LIMIT as usize * crate::change_requests::DEFAULT_MAX_PROPOSE_PARAMS_BYTES;
        let maximum_page = PENDING_PARAMS_PAGE_SIZE as usize
            * crate::change_requests::DOCUMENT_MAX_PROPOSE_PARAMS_BYTES;
        assert!(
            maximum_page <= previous_aggregate,
            "maximum pending page must not exceed the original bounded render"
        );
    }

    #[test]
    fn pending_page_links_advance_without_hiding_rows() {
        assert_eq!(
            pending_page_links(0, true),
            (None, Some("/changes?pending_offset=8".to_owned()))
        );
        assert_eq!(
            pending_page_links(8, true),
            (
                Some("/changes?pending_offset=0".to_owned()),
                Some("/changes?pending_offset=16".to_owned())
            )
        );
        assert_eq!(
            pending_page_links(16, false),
            (Some("/changes?pending_offset=8".to_owned()), None)
        );
    }

    fn principal_with(scopes: Vec<&str>, method: AuthMethod) -> Principal {
        Principal {
            sub: "tester".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: scopes.into_iter().map(String::from).collect(),
            tenant: waygate_core::TenantId::default(),
            auth_method: method,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn admin_gate_blocks_propose_only() {
        // The maker scope (mcp:propose) is NOT the checker scope — a maker
        // session must not reach the review queue.
        let p = principal_with(vec!["mcp:read", "mcp:propose"], AuthMethod::Oauth);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn admin_gate_blocks_peer_assertion_even_with_admin() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn short_id_is_eight_chars() {
        let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        assert_eq!(short(id).len(), 8);
    }

    #[test]
    fn truncate_caps_long_strings() {
        assert_eq!(truncate("abc", 10), "abc");
        let long = "x".repeat(300);
        let t = truncate(&long, 200);
        assert_eq!(t.chars().count(), 201); // 200 + ellipsis
        assert!(t.ends_with('…'));
    }

    #[test]
    fn render_params_pretty_prints_small_payloads() {
        let out = render_params(&serde_json::json!({ "scopes": ["mcp:read"], "sub": "alice" }));
        // Multi-line pretty JSON the reviewer can scan; the values are present.
        assert!(out.contains("\"scopes\""));
        assert!(out.contains("\"mcp:read\""));
        assert!(out.contains("\"alice\""));
        assert!(out.contains('\n'), "pretty JSON should be multi-line");
    }

    #[test]
    fn render_params_never_truncates() {
        // A large payload renders in FULL — never clipped. A hidden field is the
        // exact blind-approval hole this surface closes, and there's no
        // admin-reachable fallback that re-serves the params.
        // The visual size is bounded by CSS (scrollable well), not by dropping
        // bytes — so both the first AND last field are present.
        let big = serde_json::json!({
            "first": "alpha",
            "blob": "y".repeat(20_000),
            "last": "omega-tail-field",
        });
        let out = render_params(&big);
        assert!(out.contains("\"first\"") && out.contains("alpha"));
        assert!(out.contains("\"last\"") && out.contains("omega-tail-field"));
        assert!(
            out.chars().count() >= 20_000,
            "the full payload must be rendered, not truncated",
        );
        assert!(!out.contains("truncated"));
    }

    #[test]
    fn approval_requirement_view_exposes_protected_conditions() {
        let change = ChangeRequest {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            requested_by: "maker".into(),
            client_id: None,
            action_type: "role.membership.add".into(),
            params: serde_json::json!({}),
            preview: None,
            target_etag: None,
            justification: "grant operator access".into(),
            binding_code: "AMBER-OTTER-01".into(),
            required_approvals: 2,
            eligible_role: "security-admins".into(),
            required_factors: vec!["mfa".into(), "passkey".into()],
            cooldown_seconds: Some(60),
            status: ChangeRequestStatus::Pending,
            approver_sub: None,
            denied_reason: None,
            execution_result: None,
            error_message: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(10),
            decided_at: None,
            executed_at: None,
        };

        let view = approval_requirement_view(&change);
        assert_eq!(
            view.summary,
            "2 distinct approvals · role security-admins · mfa + passkey"
        );
        assert!(view.step_up_required);
        assert!(view.cooldown_until_abs.is_some());
    }

    // ---- PolicyChangePreviewView projection -------------------------

    use crate::change_policy_preview::{CompileStatus, PolicyChangeKind, PolicyChangePreview};

    #[test]
    fn from_preview_publish_label_and_compile_ok() {
        let v = PolicyChangePreviewView::from_preview(PolicyChangePreview {
            kind: PolicyChangeKind::Publish { version: 3 },
            compile: CompileStatus::Ok,
            tests: None,
            impact: None,
            note: None,
            blocked: None,
        });
        assert_eq!(v.kind_label, "Publish draft as v3");
        assert_eq!(v.compile_state, "ok");
        assert!(v.compile_error.is_none());
        assert!(v.note.is_none());
        assert!(v.blocked.is_none());
    }

    #[test]
    fn from_preview_rollback_label_and_compile_error_carries_message() {
        let v = PolicyChangePreviewView::from_preview(PolicyChangePreview {
            kind: PolicyChangeKind::Rollback { version: 2 },
            compile: CompileStatus::Error("parse boom".into()),
            tests: None,
            impact: None,
            note: Some("heads up".into()),
            blocked: Some("version 2 is a draft, not a published version".into()),
        });
        assert_eq!(v.kind_label, "Roll back to v2");
        assert_eq!(v.compile_state, "error");
        assert_eq!(v.compile_error.as_deref(), Some("parse boom"));
        // note + blocked pass through verbatim.
        assert_eq!(v.note.as_deref(), Some("heads up"));
        assert_eq!(
            v.blocked.as_deref(),
            Some("version 2 is a draft, not a published version")
        );
    }

    #[test]
    fn from_preview_unknown_compile_uses_degraded_labels() {
        // version 0 ⇒ the version couldn't be resolved (degraded) ⇒ the bare
        // "Publish draft" / "Roll back" label, and compile reads "unknown".
        let pub0 = PolicyChangePreviewView::from_preview(PolicyChangePreview {
            kind: PolicyChangeKind::Publish { version: 0 },
            compile: CompileStatus::Unknown,
            tests: None,
            impact: None,
            note: Some("x".into()),
            blocked: None,
        });
        assert_eq!(pub0.kind_label, "Publish draft");
        assert_eq!(pub0.compile_state, "unknown");
        assert!(pub0.compile_error.is_none());

        let rb0 = PolicyChangePreviewView::from_preview(PolicyChangePreview {
            kind: PolicyChangeKind::Rollback { version: 0 },
            compile: CompileStatus::Unknown,
            tests: None,
            impact: None,
            note: None,
            blocked: None,
        });
        assert_eq!(rb0.kind_label, "Roll back");
    }

    // ---- ManifestChangePreviewView projection ----------------------------

    use crate::manifest_change_preview::{ManifestChangeKind, ManifestChangePreview};
    use crate::manifest_effect::{
        ActivationReadiness, AvailabilityBarrier, CapabilityChange, CatalogLifecycle,
        FollowUpAction, FollowUpKind, ManifestEffectiveImpact, ManifestServerChange,
        ResourceCapabilitySummary, RuntimeEffect, ServerEffectiveImpact, ToolCapabilitySummary,
    };
    use crate::manifest_impact::{
        ManifestImpactReport, ManifestProspectiveAccessReport, ManifestProspectiveAccessTarget,
        ManifestProspectiveApplicability, ManifestProspectiveTargetApplicability,
    };

    fn sample_prospective_report() -> ManifestProspectiveAccessReport {
        ManifestProspectiveAccessReport {
            applicability: ManifestProspectiveApplicability::Evaluated,
            caller_contexts_considered: 2,
            caller_contexts_omitted: 0,
            targets_considered: 1,
            targets_omitted: 0,
            evaluations: 2,
            allow: 1,
            deny: 1,
            step_up: 0,
            approval_required: 0,
            indeterminate: 0,
            targets: vec![ManifestProspectiveAccessTarget {
                server: "bank".to_owned(),
                tool: "new_tool".to_owned(),
                operation: Some("read".to_owned()),
                applicability: ManifestProspectiveTargetApplicability::Evaluated,
                allow: 1,
                deny: 1,
                step_up: 0,
                approval_required: 0,
                indeterminate: 0,
            }],
            resource_targets: Vec::new(),
        }
    }

    fn sample_manifest_report(changed: usize) -> ManifestImpactReport {
        ManifestImpactReport {
            error: None,
            tools_changed: 1,
            tools_added: 0,
            tools_removed: 0,
            resources_changed: 0,
            resources_added: 0,
            resources_removed: 0,
            approval_mode_changes: Vec::new(),
            prospective_access: sample_prospective_report(),
            replay_applicability: crate::manifest_impact::ManifestReplayApplicability::Replayed,
            considered: 5,
            affected: 1,
            replayed: 1,
            unchanged: 1 - changed.min(1),
            changed,
            not_replayable: 0,
            deltas: Vec::new(),
            samples: Vec::new(),
        }
    }

    fn quarantined_addition_effect() -> ManifestEffectiveImpact {
        ManifestEffectiveImpact {
            capability_change: CapabilityChange::Expands,
            activation_readiness: ActivationReadiness::BlockedAfterChange,
            tools: ToolCapabilitySummary {
                added: 10,
                removed: 0,
                reclassified: 0,
                added_side_effecting: 4,
                added_pii: 0,
                added_high_risk: 0,
                approval_relaxed_manifest_tools: 0,
                approval_tightened_manifest_tools: 0,
                approval_relaxed_servers: 0,
                approval_tightened_servers: 0,
            },
            resources: ResourceCapabilitySummary {
                added: 0,
                removed: 0,
                reclassified: 0,
                added_high_risk: 0,
            },
            servers: vec![ServerEffectiveImpact {
                server: "grounded-docs".to_owned(),
                manifest_change: ManifestServerChange::Added,
                runtime_effect: RuntimeEffect::RegisterAndConnect,
                connected_before: None,
                catalog_before: CatalogLifecycle::Quarantined,
                catalog_after: CatalogLifecycle::Quarantined,
                drift_quarantined_before: 0,
                drift_quarantined_after_at_least: 0,
                readiness: ActivationReadiness::BlockedAfterChange,
                barriers: vec![AvailabilityBarrier::CatalogLifecycle {
                    status: CatalogLifecycle::Quarantined,
                }],
            }],
            follow_up_actions: vec![
                FollowUpAction {
                    server: "grounded-docs".to_owned(),
                    kind: FollowUpKind::PromoteCatalogServer,
                },
                FollowUpAction {
                    server: "grounded-docs".to_owned(),
                    kind: FollowUpKind::VerifyConnection,
                },
                FollowUpAction {
                    server: "grounded-docs".to_owned(),
                    kind: FollowUpKind::VerifyFleetConvergence,
                },
            ],
            fleet_activation_asynchronous: true,
        }
    }

    #[test]
    fn manifest_from_preview_blocks_an_incomplete_effect() {
        let v = ManifestChangePreviewView::from_preview(ManifestChangePreview {
            kind: ManifestChangeKind::Publish { version: 3 },
            impact: Some(sample_manifest_report(1)),
            effective: None,
            note: None,
            blocked: None,
            observed: Vec::new(),
        });
        assert_eq!(v.kind_label, "Publish manifest draft as v3");
        assert_eq!(v.impact.as_ref().map(|im| im.changed), Some(1));
        assert!(v.note.is_none());
        assert!(v
            .blocked
            .as_deref()
            .is_some_and(|reason| reason.contains("effective service-impact")));
    }

    #[test]
    fn ledger_only_manifest_effect_reports_no_fleet_activation() {
        let impact = crate::manifest_impact::ManifestImpactReport::ledger_only(
            "- name: tenant-local\n  transport: http\n  url: http://tenant-local/mcp\n",
        );
        assert!(replay_summary(&impact).contains("does not activate"));

        let effect = ManifestEffectiveImpactView::from_impact(
            crate::manifest_effect::ManifestEffectiveImpact::ledger_only(),
        );
        assert!(effect.outcome.contains("no runtime activation change"));
        assert!(effect.fleet_note.is_none());
    }

    #[test]
    fn manifest_effective_view_leads_with_blocked_service_outcome() {
        let mut report = sample_manifest_report(0);
        report.tools_changed = 0;
        report.tools_added = 10;
        report.replay_applicability =
            crate::manifest_impact::ManifestReplayApplicability::NoReclassifiedTools;
        report.considered = 0;
        report.affected = 0;
        report.replayed = 0;
        report.unchanged = 0;
        let v = ManifestChangePreviewView::from_preview(ManifestChangePreview {
            kind: ManifestChangeKind::UpsertServers,
            impact: Some(report),
            effective: Some(quarantined_addition_effect()),
            note: None,
            blocked: None,
            observed: Vec::new(),
        });

        assert!(v.blocked.is_none(), "the complete effect may be approved");
        let effect = v.effective.expect("effective impact view");
        assert_eq!(effect.outcome_tone, "blocked");
        assert!(effect
            .outcome
            .contains("Expands the configured capability surface"));
        assert!(effect.outcome.contains("remain unavailable"));
        assert_eq!(effect.tool_delta, "10 added · 0 removed · 0 reclassified");
        assert_eq!(
            effect.added_tool_posture.as_deref(),
            Some("4 added tools may have side effects")
        );
        assert_eq!(
            effect.servers[0].barriers,
            vec!["Catalog status remains quarantined."]
        );
        assert!(
            effect
                .follow_ups
                .iter()
                .any(|action| action.contains("governed catalog recovery")),
            "catalog recovery must be explicit"
        );
        assert!(
            effect
                .follow_ups
                .iter()
                .any(|action| action.contains("connects after publication")),
            "connection verification remains necessary after catalog recovery"
        );
        assert!(
            effect
                .follow_ups
                .iter()
                .any(|action| action.contains("gateway fleet")),
            "fleet convergence must remain distinct from publication"
        );
        assert_eq!(
            v.replay_summary.as_deref(),
            Some(
                "Not applicable: this candidate changes capability membership, but does not reclassify an existing tool or resource prefix."
            )
        );
        assert!(
            !v.show_replay_details,
            "zero reclassified tools must not render replay accounting as a no-impact status"
        );
        assert!(
            v.prospective_summary
                .as_deref()
                .is_some_and(|summary| summary.contains("1 allow") && summary.contains("1 deny")),
            "the approval view must summarize candidate access, not only historical replay"
        );
        assert!(v.show_prospective_details);
    }

    #[test]
    fn manifest_effective_view_warns_when_ordinary_approval_is_suppressed() {
        let mut impact = quarantined_addition_effect();
        impact.tools.approval_relaxed_manifest_tools = 2;
        impact.tools.approval_relaxed_servers = 1;
        let view = ManifestEffectiveImpactView::from_impact(impact);

        assert!(view.approval_posture.as_deref().is_some_and(|text| text
            .contains("every runtime tool on 1 existing server")
            && text.contains("2 manifest-declared tools")
            && text.contains("Cedar policy remains authoritative")));
    }

    #[test]
    fn manifest_effective_view_describes_removal_as_service_restriction() {
        let effect = ManifestEffectiveImpactView::from_impact(ManifestEffectiveImpact {
            capability_change: CapabilityChange::Restricts,
            activation_readiness: ActivationReadiness::Removed,
            tools: ToolCapabilitySummary {
                added: 0,
                removed: 3,
                reclassified: 0,
                added_side_effecting: 0,
                added_pii: 0,
                added_high_risk: 0,
                approval_relaxed_manifest_tools: 0,
                approval_tightened_manifest_tools: 0,
                approval_relaxed_servers: 0,
                approval_tightened_servers: 0,
            },
            resources: ResourceCapabilitySummary {
                added: 0,
                removed: 0,
                reclassified: 0,
                added_high_risk: 0,
            },
            servers: vec![ServerEffectiveImpact {
                server: "legacy-docs".to_owned(),
                manifest_change: ManifestServerChange::Removed,
                runtime_effect: RuntimeEffect::DrainAndRemove,
                connected_before: Some(true),
                catalog_before: CatalogLifecycle::Live,
                catalog_after: CatalogLifecycle::Retired,
                drift_quarantined_before: 0,
                drift_quarantined_after_at_least: 0,
                readiness: ActivationReadiness::Removed,
                barriers: Vec::new(),
            }],
            follow_up_actions: vec![FollowUpAction {
                server: "legacy-docs".to_owned(),
                kind: FollowUpKind::VerifyFleetConvergence,
            }],
            fleet_activation_asynchronous: true,
        });

        assert!(effect
            .outcome
            .contains("Restricts the configured capability surface"));
        assert!(effect
            .outcome
            .contains("removes the affected servers from service"));
        assert_eq!(effect.outcome_tone, "neutral");
        assert!(
            effect
                .follow_ups
                .iter()
                .all(|action| !action.contains("catalog recovery")),
            "removal must not invent a catalog recovery action"
        );
    }

    #[test]
    fn manifest_from_preview_rollback_label_and_blocked_note_passthrough() {
        let v = ManifestChangePreviewView::from_preview(ManifestChangePreview {
            kind: ManifestChangeKind::Rollback { version: 2 },
            impact: None,
            effective: None,
            note: Some("heads up".into()),
            blocked: Some("target is no longer a draft".into()),
            observed: Vec::new(),
        });
        assert_eq!(v.kind_label, "Roll back manifests to v2");
        assert!(v.impact.is_none());
        // note + blocked pass through verbatim.
        assert_eq!(v.note.as_deref(), Some("heads up"));
        assert_eq!(v.blocked.as_deref(), Some("target is no longer a draft"));
    }

    #[test]
    fn manifest_from_preview_unknown_version_uses_degraded_labels() {
        // version 0 ⇒ the version couldn't be resolved (degraded) ⇒ the bare
        // "Publish manifest draft" / "Roll back manifests" label.
        let pub0 = ManifestChangePreviewView::from_preview(ManifestChangePreview {
            kind: ManifestChangeKind::Publish { version: 0 },
            impact: None,
            effective: None,
            note: Some("x".into()),
            blocked: None,
            observed: Vec::new(),
        });
        assert_eq!(pub0.kind_label, "Publish manifest draft");

        let rb0 = ManifestChangePreviewView::from_preview(ManifestChangePreview {
            kind: ManifestChangeKind::Rollback { version: 0 },
            impact: None,
            effective: None,
            note: None,
            blocked: None,
            observed: Vec::new(),
        });
        assert_eq!(rb0.kind_label, "Roll back manifests");
    }

    // ---- shared preview_pending_change enrichment (used by BOTH the
    //      /changes queue and the /decisions inbox) ----

    async fn no_store_state() -> Arc<AdminState> {
        let pool = Arc::new(
            waygate_upstream::pool::UpstreamPool::connect(std::collections::BTreeMap::new()).await,
        );
        let evidence: waygate_mcp::audit::SharedEvidence =
            Arc::new(waygate_mcp::audit::InMemorySink::default());
        Arc::new(AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        ))
    }

    #[tokio::test]
    async fn preview_pending_change_routes_policy_vs_manifest_and_spends_budget() {
        let state = no_store_state().await;
        let mut budget = 25usize;

        // A manifest action populates the manifest slot (degraded note here, since
        // no store is wired) and NOT the policy slot, and spends one budget unit.
        let m = preview_pending_change(
            &state,
            "default",
            "manifest.publish",
            &serde_json::json!({ "bundle_id": uuid::Uuid::now_v7().to_string() }),
            None,
            &mut budget,
        )
        .await;
        assert!(
            m.policy.is_none() && m.manifest.is_some(),
            "manifest.* → manifest slot only"
        );
        assert_eq!(budget, 24, "a produced preview spends one budget unit");

        // A policy action populates the policy slot only.
        let p = preview_pending_change(
            &state,
            "default",
            "policy.publish",
            &serde_json::json!({ "bundle_id": uuid::Uuid::now_v7().to_string() }),
            None,
            &mut budget,
        )
        .await;
        assert!(
            p.policy.is_some() && p.manifest.is_none(),
            "policy.* → policy slot only"
        );
        assert_eq!(budget, 23);

        // A non-previewable action produces neither and spends nothing.
        let n = preview_pending_change(
            &state,
            "default",
            "rate_limit.update",
            &serde_json::json!({ "id": "x" }),
            None,
            &mut budget,
        )
        .await;
        assert!(n.policy.is_none() && n.manifest.is_none());
        assert_eq!(budget, 23, "a non-previewable action costs no budget");
    }

    #[tokio::test]
    async fn preview_pending_change_exhausted_budget_yields_nothing() {
        // At budget 0 the helper short-circuits — a queue full of changes can't
        // run an unbounded number of ≤500-row replays (the cap holds on BOTH
        // approval surfaces, since they share this helper).
        let state = no_store_state().await;
        let mut budget = 0usize;
        let r = preview_pending_change(
            &state,
            "default",
            "manifest.publish",
            &serde_json::json!({ "bundle_id": uuid::Uuid::now_v7().to_string() }),
            None,
            &mut budget,
        )
        .await;
        assert!(r.policy.is_none() && r.manifest.is_none());
        assert_eq!(budget, 0);
    }

    #[tokio::test]
    async fn mandatory_policy_preview_exhaustion_is_blocked_not_blind() {
        let state = no_store_state().await;
        let mut budget = 0usize;
        let result = preview_pending_change(
            &state,
            "default",
            "policy.upsert_fragment",
            &serde_json::json!({
                "statement": "@id(\"example-security\") permit(principal, action, resource);"
            }),
            Some("captured-base"),
            &mut budget,
        )
        .await;
        let preview = result
            .policy
            .expect("mandatory action keeps a blocked card");
        assert!(preview.blocked.is_some());
        assert!(preview.impact.is_none());
        assert_eq!(budget, 0);
    }
}
