//! Exact decision replay / impact analysis.
//!
//! Given a CANDIDATE policy draft, this module replays the tenant's recent
//! RECORDED authorization decisions against it and reports which would CHANGE
//! (allow→deny, deny→allow, →step-up, …) — so an operator sees the BLAST
//! RADIUS of a policy edit BEFORE publishing.
//!
//! ## Why this is possible
//!
//! Migration 0062 added the four authorization-decision INPUTS a Cedar decision
//! branched on (`req_scopes` = `principal.scopes`, `auth_method` =
//! `principal.auth_method`, `req_roles` = `principal.roles`, `side_effects` =
//! `resource.side_effects`) onto the decision row in `audit_log`. With those
//! plus the principal / resource fields already on the row, a recorded
//! decision is reconstructable into the same `(Principal, Action,
//! ResourceSpec)` triple the live gate evaluated when the row has no additional
//! uncaptured context — so re-running it under a candidate engine is a faithful
//! replay, not an approximation.
//!
//! ## What is (and isn't) replayed
//!
//! - **Replayable row** ⇔ `auth_method.is_some()` AND the row is a supported
//!   invocation decision (tool call, resource read, or skill list/read; NULL
//!   category counted as invocation per migration 0006) AND it carried no SCIM
//!   enrichment (`scim_active.is_none()`, see below).
//!   `auth_method.is_some()` is the single migration-0062-captured
//!   predicate that is true ONLY for principal-bearing authorization-decision
//!   rows recorded after migration 0062 — it excludes legacy NULL rows
//!   (pre-0062) AND no-principal/gate-skipped rows (deliberately left
//!   without the captured inputs).
//! - **`llm_completion` (model) decisions are NOT replayed.** The simulator has
//!   no model / completion resource shape, so a model decision cannot be
//!   reconstructed into a faithful resource entity. We never force a model
//!   into a different resource shape; those rows are counted as
//!   `not_replayable` (reported separately as "model decisions"), never
//!   silently mis-replayed.
//! - **SCIM-enriched decisions are NOT replayed.** The live Cedar entity
//!   exposes `scim_user_name`, `scim_external_id`, and a flattened `scim_attrs`
//!   record to policies (`waygate-authz/src/cedar.rs`), but the audit row
//!   captures only `scim_active` + `scim_groups` (migration 0022) — the other
//!   three were never persisted. A principal that went through SCIM enrichment
//!   (`scim_active.is_some()`) therefore can't be exactly reconstructed for a
//!   policy gating on the un-captured attrs, so those rows are counted
//!   `not_replayable` rather than replayed against placeholders. Rows with NO
//!   SCIM build an identical `scim_present == false` entity on both paths and
//!   replay faithfully. (Capturing the remaining SCIM attrs to make these rows
//!   exactly replayable is a deferred follow-up, like migration 0062 did for
//!   the other inputs.)
//! - **Nested decisions are NOT replayed.** Invocation hierarchy is persisted,
//!   but the gateway-stamped authorization channel is not. A hierarchy can
//!   refer to current direct-authority execution or an older restricted
//!   execution, so historical replay excludes it rather than guessing a channel.
//! - **Non-decision outcomes** (anything other than success / execution_error
//!   / denied / step_up_required) are counted `not_replayable` too — there's no
//!   recorded verdict to compare against.
//!
//! ## Read-only
//!
//! Replay NEVER writes anything: it is a pure read of the tenant's recent
//! decisions plus an in-memory eval against an ephemeral candidate engine. No
//! publish, no audit mutation, no disk write.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use waygate_authz::{CedarEngine, Decision};
pub(crate) use waygate_core::fmt::format_ts_rfc3339;
use waygate_core::{RiskTier, TenantId};
use waygate_storage::AuditRow;

use crate::policies::{
    SimulateAction, SimulateAuthMethod, SimulatePrincipal, SimulateRequest, SimulateResource,
};

/// The audit category for decisions [`reconstruct_simulate_request`] can
/// faithfully represent. A NULL category counts as `invocation` (migration
/// 0006), so a legacy-but-0062-stamped invocation row may still be replayable.
/// `llm_completion` rows are deliberately excluded (see module docs) because
/// there is no model resource shape in the simulator.
const INVOCATION_CATEGORY: &str = "invocation";

/// Tool calls share the invocation category with native resource and skill
/// decisions, each of which carries a different Cedar action and resource
/// shape.
const CALL_TOOL_ACTION: &str = "CallTool";
const READ_RESOURCE_ACTION: &str = "ReadResource";
const LIST_SKILLS_ACTION: &str = "ListSkills";
const FETCH_SKILL_RESOURCE_ACTION: &str = "FetchSkillResource";
const READ_SKILL_ACTION: &str = "ReadSkill";

#[derive(Deserialize)]
struct SkillAuditTarget {
    source_origin: String,
    artifact_digest: String,
    #[serde(default)]
    source_tree_digest: Option<String>,
    #[serde(default)]
    skill_uri: Option<String>,
    #[serde(default)]
    resource_uri: Option<String>,
    #[serde(default)]
    revision_digest: Option<String>,
    #[serde(default)]
    resource_digest: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    source_object: Option<String>,
}

/// The recorded verdict of an authorization decision, in the same
/// allow / deny / step_up vocabulary the candidate engine produces (and the
/// simulator's `SimulateResponse::decision` uses). Derived from the stored
/// `outcome` string by [`recorded_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDecision {
    Allow,
    Deny,
    StepUp,
    ApprovalRequired,
}

impl ReplayDecision {
    /// The wire string, matching the simulator's decision vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::StepUp => "step_up",
            Self::ApprovalRequired => "approval_required",
        }
    }

    /// Map an engine [`Decision`] (the candidate's verdict) into this shared
    /// vocabulary so a candidate verdict can be compared to a recorded one.
    /// `pub(crate)` so the manifest impact-preview (`crate::manifest_impact`)
    /// can reuse the same engine→verdict mapping it does here.
    pub(crate) fn from_engine(d: Decision) -> Self {
        match d {
            Decision::Allow => Self::Allow,
            Decision::Deny => Self::Deny,
            Decision::StepUpRequired => Self::StepUp,
            Decision::ApprovalRequired => Self::ApprovalRequired,
        }
    }
}

/// Map a stored `outcome` string to the authz verdict it represents, or `None`
/// for outcomes that aren't authorization decisions we replay.
///
/// - `success` / `execution_error` → the gate ALLOWED it (execution_error =
///   allowed by the gate, then failed downstream during dispatch).
/// - `denied` → deny.
/// - `step_up_required` → step_up.
///
/// Anything else (an outcome the gate never produces for a decision row) →
/// `None`, so the caller counts the row as not-replayable rather than guessing
/// a verdict.
pub fn recorded_decision(row: &AuditRow) -> Option<ReplayDecision> {
    let reason = row.reason.as_deref().unwrap_or_default();
    let skill_action = matches!(
        row.action.as_str(),
        LIST_SKILLS_ACTION | FETCH_SKILL_RESOURCE_ACTION | READ_SKILL_ACTION
    );
    if skill_action && reason == waygate_core::SKILL_PROFILE_REFUSAL_REASON {
        return None;
    }
    if skill_action && reason.starts_with(waygate_core::SKILL_POST_AUTHORIZATION_REFUSAL_PREFIX) {
        return Some(ReplayDecision::Allow);
    }
    match row.outcome.as_str() {
        // A policy-gated effect that dispatched consumed a grant Cedar's
        // ApprovalRequired verdict demanded — the recorded POLICY verdict
        // is approval_required, which the unchanged bundle reproduces.
        "success" | "execution_error" if reason.starts_with("policy-gated effect") => {
            Some(ReplayDecision::ApprovalRequired)
        }
        "success" | "execution_error" => Some(ReplayDecision::Allow),
        // A Cedar-demanded grant was missing: the recorded policy verdict
        // is approval_required.
        "denied" if reason.starts_with("approval required by policy") => {
            Some(ReplayDecision::ApprovalRequired)
        }
        // A catalog-flag-only refusal: Cedar allowed the call and the
        // per-tool flag (not policy) refused it. The recorded POLICY
        // verdict is allow — mapping it to Deny or ApprovalRequired would
        // fabricate a transition under an unchanged bundle. (Rows written
        // before the authority label existed are all of this class: the
        // Cedar approval verdict did not exist yet.)
        "denied" if reason.starts_with("approval required") => {
            if row.action == CALL_TOOL_ACTION {
                Some(ReplayDecision::Allow)
            } else {
                // Native resource reads have no catalog-flag approval stage.
                // This refusal shape is emitted only for Cedar's actual
                // ApprovalRequired verdict.
                Some(ReplayDecision::ApprovalRequired)
            }
        }
        "denied" => Some(ReplayDecision::Deny),
        "step_up_required" => Some(ReplayDecision::StepUp),
        _ => None,
    }
}

/// Parse a stored `auth_method` string into the simulator's
/// [`SimulateAuthMethod`]. Every method the gateway authenticates a principal
/// with — `oauth`, `api_key`, `peer_assertion` — has a faithful simulator
/// variant, so the reconstructed verdict reflects a policy that branches on
/// `principal.auth_method` exactly as the live decision did. An *unknown*
/// string (a future method this build predates) falls back to the enum default
/// (`Oauth`); in practice `reconstruct_simulate_request` never reaches this path
/// for such rows, since the audit pipeline only stamps the three known values,
/// but the default keeps the function total without coercing a *known* method
/// to the wrong one.
fn parse_auth_method(s: &str) -> SimulateAuthMethod {
    match s {
        "api_key" => SimulateAuthMethod::ApiKey,
        "peer_assertion" => SimulateAuthMethod::PeerAssertion,
        // "oauth" and any unknown/future value → the default.
        _ => SimulateAuthMethod::Oauth,
    }
}

/// Whether `row` is a tool-call decision row replay can reconstruct. NULL
/// category counts as `invocation` (migration 0006). Pulled out so the
/// replay-eligible predicate (`category` + `auth_method.is_some()`) lives in
/// one place.
fn is_invocation(row: &AuditRow) -> bool {
    row.category.as_deref().unwrap_or(INVOCATION_CATEGORY) == INVOCATION_CATEGORY
}

/// Reconstruct the [`SimulateRequest`] the live gate evaluated for a recorded
/// decision row, or `None` when the row is NOT replayable.
///
/// Returns `None` when:
/// - `auth_method.is_none()` — a legacy (pre-0062) NULL row or a
///   no-principal / gate-skipped row left without the migration-0062
///   captured inputs.
/// - the row isn't an invocation decision (`category != "invocation"`, e.g. an
///   `llm_completion` model decision) — the simulator has no resource shape for
///   it (see module docs).
/// - a tool-call row carries no `tool`, or a skill row has no valid structured
///   target — the action/resource pair cannot be reconstructed faithfully.
/// - the row carried SCIM enrichment (`scim_active.is_some()`). The live Cedar
///   entity exposes `scim_user_name`, `scim_external_id`, and a flattened
///   `scim_attrs` record to policies (`waygate-authz/src/cedar.rs`), but the
///   audit row captures only `scim_active` + `scim_groups` (migration 0022) —
///   the other three were never persisted. A candidate gating on an
///   un-captured SCIM attr would replay against placeholders, so such rows are
///   EXCLUDED (per "faithful or excluded"), never coerced. A row with NO SCIM
///   (`scim_active.is_none()`) builds an identical `scim_present == false`
///   entity on both the live and replay paths, so it IS faithful.
/// - the row carries an invocation hierarchy. The audit row does not capture
///   the authorization channel, and nested client and skill executions use
///   different channels, so neither can be reconstructed faithfully.
///
/// Pure field mapping (no I/O). `risk_level` parses via [`RiskTier::parse`],
/// defaulting to `Low` for an absent / unknown value (the same default the
/// simulator's `SimulateAction::CallTool` / `SimulateResource::Tool` use). The
/// reconstructed request stamps the principal's TENANT from the converter's
/// default; the caller ([`compute_impact`]) overrides it to the row's tenant
/// before evaluating, exactly like the live simulator and the publish gate.
pub fn reconstruct_simulate_request(row: &AuditRow) -> Option<SimulateRequest> {
    // The capture predicate: a replayable row is principal-bearing and
    // carries the captured `auth_method`. This is the single check that
    // excludes both legacy NULL rows and no-principal rows.
    let auth_method_str = row.auth_method.as_deref()?;
    // Only invocation decisions are representable; a model (`llm_completion`)
    // decision has no simulator resource shape.
    if !is_invocation(row) {
        return None;
    }
    if row.invocation_hierarchy.is_some() {
        return None;
    }
    if !matches!(
        row.action.as_str(),
        CALL_TOOL_ACTION
            | READ_RESOURCE_ACTION
            | LIST_SKILLS_ACTION
            | FETCH_SKILL_RESOURCE_ACTION
            | READ_SKILL_ACTION
    ) {
        return None;
    }
    let sub = row.principal_sub.clone()?;

    let risk = row
        .risk_level
        .as_deref()
        .and_then(RiskTier::parse)
        .unwrap_or(RiskTier::Low);

    // SCIM fidelity guard (see the doc comment): the audit row captures only
    // scim_active + scim_groups, but the live gate also exposes scim_user_name,
    // scim_external_id, and a flattened scim_attrs record to policies. A row that
    // went through SCIM enrichment therefore can't be faithfully reconstructed —
    // exclude it rather than replay against placeholder SCIM facts. Rows with no
    // SCIM build an identical scim_present == false entity on both paths, so they
    // are faithful and fall through to a `scim: None` principal below.
    if row.scim_active.is_some() {
        return None;
    }

    let (action, resource) = match row.action.as_str() {
        READ_RESOURCE_ACTION => {
            let server = row.server.clone()?;
            let uri = row.target.clone()?;
            (
                SimulateAction::ReadResource { uri: uri.clone() },
                SimulateResource::McpResource { server, uri, risk },
            )
        }
        LIST_SKILLS_ACTION | FETCH_SKILL_RESOURCE_ACTION | READ_SKILL_ACTION => {
            let target: SkillAuditTarget = serde_json::from_str(row.target.as_deref()?).ok()?;
            let action = match row.action.as_str() {
                LIST_SKILLS_ACTION => SimulateAction::ListSkills,
                FETCH_SKILL_RESOURCE_ACTION => SimulateAction::FetchSkillResource {
                    uri: target.resource_uri.clone()?,
                },
                READ_SKILL_ACTION => SimulateAction::ReadSkill {
                    uri: target.resource_uri.clone()?,
                },
                _ => unreachable!("skill action matched above"),
            };
            (
                action,
                SimulateResource::Skill {
                    source_origin: target.source_origin,
                    artifact_digest: target.artifact_digest,
                    source_tree_digest: target.source_tree_digest,
                    skill_uri: target.skill_uri,
                    resource_uri: target.resource_uri,
                    revision_digest: target.revision_digest,
                    content_digest: target.resource_digest,
                    source_path: target.source_path,
                    source_object: target.source_object,
                },
            )
        }
        CALL_TOOL_ACTION => {
            // A tool-call decision always named the tool; without it there is
            // no action/resource pair to reconstruct.
            let tool = row.tool.clone()?;
            (
                SimulateAction::CallTool {
                    name: tool.clone(),
                    risk,
                },
                SimulateResource::Tool {
                    server: row.server.clone().unwrap_or_default(),
                    name: tool,
                    risk,
                    side_effects: row.side_effects.unwrap_or(false),
                    pii: row.pii.unwrap_or(false),
                    operation: row.operation.clone(),
                },
            )
        }
        _ => return None,
    };

    Some(SimulateRequest {
        principal: SimulatePrincipal {
            sub,
            email: row.principal_email.clone(),
            groups: row.principal_groups.clone(),
            // Default the issuer to the captured one, or the converter's
            // "simulation" default when absent — issuer rarely gates a policy
            // but is reconstructed faithfully when present.
            issuer: row
                .issuer
                .clone()
                .unwrap_or_else(|| "simulation".to_owned()),
            scopes: row.req_scopes.clone(),
            auth_method: parse_auth_method(auth_method_str),
            // Always None here: a SCIM-enriched row (scim_active.is_some()) was
            // excluded above, so a row that reaches this point had no SCIM and
            // its faithful entity carries scim_present == false.
            scim: None,
            roles: row.req_roles.clone(),
        },
        action,
        resource,
        // Hierarchy-bearing rows were excluded above because their channel was
        // not captured. Every remaining replayable row is a direct invocation.
        // `approval_present` stays false because a granted state was expressed
        // through the claim, not Cedar context.
        context: crate::policies::SimulateContext {
            channel: crate::policies::SimulateChannel::Direct,
            approval_present: false,
        },
    })
}

/// One transition bucket in the impact report: how many replayed decisions
/// moved `from` → `to` under the candidate. Only CHANGED transitions are
/// surfaced (`from != to`).
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ImpactDelta {
    /// The recorded verdict (`allow` / `deny` / `step_up`).
    pub from: String,
    /// The candidate's verdict (`allow` / `deny` / `step_up`).
    pub to: String,
    pub count: usize,
}

/// One changed-decision example for the operator: a recorded decision whose
/// verdict the candidate would flip. A bounded number are carried so the
/// operator can eyeball *which* calls are affected, not just the counts.
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ImpactSample {
    /// The recorded verdict (`allow` / `deny` / `step_up`).
    pub recorded: String,
    /// The candidate's verdict (`allow` / `deny` / `step_up`).
    pub candidate: String,
    /// The acting principal (sub), for operator context.
    pub principal: String,
    /// `server.tool` of the affected call.
    pub server_tool: String,
    /// The decision's timestamp (RFC3339), so the operator can find the row.
    pub ts: String,
    /// The policy ids the RECORDED decision fired (the candidate's fired set may
    /// differ; this is the historical context).
    pub policy_ids: Vec<String>,
}

/// The blast-radius report for replaying a tenant's recent decisions against a
/// candidate draft.
///
/// `replayed + not_replayable == considered` (the rows fetched). `unchanged +
/// changed == replayed`. When the candidate doesn't parse, `error` is set and
/// NO row is evaluated — `replayed`, `unchanged`, `changed` are 0 and `deltas`
/// / `samples` are empty — but `considered` and `not_replayable` still reflect
/// the rows fetched (the invariant holds: `0 + considered == considered`).
/// `considered` is never zeroed away when there was a non-empty fetch, so it
/// can't claim "0 considered" against 500 real rows; the UI renders only the
/// `error` in this case, never the counts.
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ImpactReport {
    /// Replay terminated early because the candidate does not parse as Cedar.
    /// `Some(detail)` ⇒ nothing was evaluated: `replayed` / `unchanged` /
    /// `changed` are 0 and `deltas` / `samples` empty, while `considered` and
    /// `not_replayable` still count the rows that were fetched. Surfaced so a
    /// broken draft reads as an error, not "0 changes".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Total recorded decisions considered (the rows fetched for the tenant).
    pub considered: usize,
    /// Of `considered`, how many were replayable (had the captured inputs and a
    /// representable shape) and were evaluated against the candidate.
    pub replayed: usize,
    /// Of `replayed`, how many produced the SAME verdict under the candidate.
    pub unchanged: usize,
    /// Of `replayed`, how many produced a DIFFERENT verdict under the candidate.
    pub changed: usize,
    /// Of `considered`, how many could NOT be replayed (legacy rows without the
    /// captured inputs, model `llm_completion` decisions, SCIM-enriched rows
    /// whose full SCIM facts weren't captured, or non-decision outcomes).
    /// Surfaced so the operator knows the sample isn't the full history.
    pub not_replayable: usize,
    /// Per-transition counts for the changed decisions (allow→deny, deny→allow,
    /// →step_up, …), sorted for a stable render.
    pub deltas: Vec<ImpactDelta>,
    /// A bounded set of changed-decision examples for the operator.
    pub samples: Vec<ImpactSample>,
}

/// How many changed-decision examples to carry in [`ImpactReport::samples`].
/// Bounded so a candidate that flips thousands of decisions doesn't produce a
/// multi-megabyte report; the counts (`changed`, `deltas`) still reflect every
/// flip.
const MAX_SAMPLES: usize = 25;

/// Replay `rows` (the tenant's recent recorded decisions) against
/// `candidate_content` and report the blast radius.
///
/// The candidate is parsed ONCE into an ephemeral [`CedarEngine`]; if it
/// doesn't parse, an error report is returned (NEVER a panic). For each
/// replayable row the recorded decision is reconstructed and re-evaluated under
/// `tenant` (the rows are already tenant-scoped to the caller; the principal's
/// tenant is overridden to `tenant` so a per-tenant policy is judged in the
/// right authorization context, exactly like the live simulator and publish
/// gate). Evaluation is STRICT ([`CedarEngine::evaluate_strict`], like the
/// publish gate): a candidate broken at EVAL time surfaces as an error
/// (counted as not-replayable for that row) rather than silently
/// mis-replaying against a degraded result.
pub fn compute_impact(
    candidate_content: &str,
    tenant: &TenantId,
    rows: &[AuditRow],
) -> ImpactReport {
    let considered = rows.len();

    let engine = match CedarEngine::from_source(candidate_content) {
        Ok(e) => e,
        Err(e) => {
            // Broken candidate: don't evaluate anything — surface the parse
            // error so the operator sees it's broken, not "0 changes".
            return ImpactReport {
                error: Some(format!("candidate policy does not parse as Cedar: {e}")),
                considered,
                replayed: 0,
                unchanged: 0,
                changed: 0,
                not_replayable: considered,
                deltas: Vec::new(),
                samples: Vec::new(),
            };
        }
    };

    let mut replayed = 0usize;
    let mut unchanged = 0usize;
    let mut changed = 0usize;
    let mut not_replayable = 0usize;
    // (from, to) -> count, keyed by the wire strings for a stable, sorted order.
    let mut delta_counts: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
    let mut samples: Vec<ImpactSample> = Vec::new();

    for row in rows {
        // A row is replayable only if BOTH the recorded verdict and the
        // reconstructed request are derivable. Either being absent ⇒
        // not-replayable (legacy row, model decision, or non-decision outcome).
        let (Some(recorded), Some(req)) =
            (recorded_decision(row), reconstruct_simulate_request(row))
        else {
            not_replayable += 1;
            continue;
        };

        // Tenant-scope the evaluation to the row's tenant (the rows are
        // already scoped to the caller), and carry the reconstructed runtime
        // context reconstructed above.
        let facts = crate::policies::simulate_request_to_facts(req, tenant.clone());

        // STRICT eval (like the publish gate): a candidate that errors at
        // EVAL time (undefined attribute, type mismatch) must SURFACE, not be
        // silently evaluated against a degraded result. Treat a per-row
        // evaluator error as not-replayable for THAT row rather than guessing a
        // verdict — the candidate's parse already succeeded, so this is a
        // request-shaped eval failure, not a broken-draft signal for the whole
        // report.
        let candidate = match engine.evaluate_facts_strict(&facts) {
            Ok(r) => ReplayDecision::from_engine(r.decision),
            Err(_) => {
                not_replayable += 1;
                continue;
            }
        };

        replayed += 1;
        if candidate == recorded {
            unchanged += 1;
        } else {
            changed += 1;
            *delta_counts
                .entry((recorded.as_str(), candidate.as_str()))
                .or_insert(0) += 1;
            if samples.len() < MAX_SAMPLES {
                samples.push(ImpactSample {
                    recorded: recorded.as_str().to_owned(),
                    candidate: candidate.as_str().to_owned(),
                    principal: row
                        .principal_sub
                        .clone()
                        .or_else(|| row.principal_email.clone())
                        .unwrap_or_default(),
                    server_tool: format_access_target(row),
                    ts: format_ts_rfc3339(row.ts),
                    policy_ids: row.policy_ids.clone(),
                });
            }
        }
    }

    let deltas = delta_counts
        .into_iter()
        .map(|((from, to), count)| ImpactDelta {
            from: from.to_owned(),
            to: to.to_owned(),
            count,
        })
        .collect();

    ImpactReport {
        error: None,
        considered,
        replayed,
        unchanged,
        changed,
        not_replayable,
        deltas,
        samples,
    }
}

/// Human-readable access target for a replay sample. Tool calls use
/// `server.tool`; native reads use `server.resources/read (URI)`.
pub(crate) fn format_access_target(row: &AuditRow) -> String {
    let server = row.server.as_deref().unwrap_or("–");
    if row.action == "ReadResource" {
        return match row.target.as_deref() {
            Some(uri) => format!("{server}.resources/read ({uri})"),
            None => format!("{server}.resources/read"),
        };
    }
    match row.tool.as_deref() {
        Some(tool) => format!("{server}.{tool}"),
        None => server.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// A draft that permits everything — every replayed request allows.
    const PERMIT_ALL: &str = "@id(\"permit-all\")\npermit(principal, action, resource);";

    /// A draft that permits everything but FORBIDS high-risk tool calls. Mirrors
    /// the proven `resource.risk == "high"` shape used elsewhere; a `CallTool`
    /// always carries a `Tool` resource with a `risk` attribute.
    const FORBID_HIGH: &str = "@id(\"baseline\")\n\
         permit(principal, action, resource);\n\
         @id(\"forbid-high\")\n\
         forbid(principal, action == Action::\"CallTool\", resource)\n\
         when { resource.risk == \"high\" };";

    /// A fully-populated, replayable tool-call decision row.
    fn replayable_row(outcome: &str, risk: &str) -> AuditRow {
        AuditRow {
            operation: None,
            id: Uuid::now_v7(),
            ts: time::OffsetDateTime::UNIX_EPOCH,
            category: Some("invocation".into()),
            tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
            action: "CallTool".into(),
            outcome: outcome.into(),
            principal_sub: Some("alice@example.com".into()),
            principal_email: Some("alice@example.com".into()),
            principal_groups: vec!["mcp-users".into()],
            issuer: Some("https://auth.example.com".into()),
            server: Some("bank".into()),
            tool: Some("wire_money".into()),
            risk_level: Some(risk.into()),
            pii: Some(false),
            policy_ids: vec!["baseline".into()],
            reason: None,
            trace_id: None,
            latency_ms: Some(12),
            scim_active: None,
            scim_groups: Vec::new(),
            target: None,
            req_scopes: vec!["mcp:invoke".into()],
            // The capture marker: this is what makes a row replayable.
            auth_method: Some("oauth".into()),
            req_roles: vec![],
            side_effects: Some(true),
            invocation_hierarchy: None,
        }
    }

    /// A legacy row (pre-0062): no `auth_method`, so NOT replayable even though
    /// it's a decision-shaped invocation row.
    fn legacy_row(outcome: &str) -> AuditRow {
        let mut r = replayable_row(outcome, "low");
        r.auth_method = None;
        r.req_scopes = Vec::new();
        r.req_roles = Vec::new();
        r.side_effects = None;
        r
    }

    /// A model (`llm_completion`) decision: capture-stamped (`auth_method` set)
    /// but NOT representable as a `Tool`, so excluded from replay.
    fn model_row(outcome: &str) -> AuditRow {
        let mut r = replayable_row(outcome, "low");
        r.category = Some("llm_completion".into());
        r.tool = None;
        r.server = Some("openai".into());
        r
    }

    #[test]
    fn recorded_decision_maps_outcomes() {
        let row = |outcome: &str| replayable_row(outcome, "low");
        assert_eq!(
            recorded_decision(&row("success")),
            Some(ReplayDecision::Allow)
        );
        assert_eq!(
            recorded_decision(&row("execution_error")),
            Some(ReplayDecision::Allow),
            "execution_error = allowed by the gate, then failed downstream",
        );
        assert_eq!(
            recorded_decision(&row("denied")),
            Some(ReplayDecision::Deny)
        );
        // A POLICY-gated refusal replays as approval_required — the verdict
        // the unchanged bundle reproduces.
        let mut policy_refusal = row("denied");
        policy_refusal.reason = Some("approval required by policy: no matching grant".to_owned());
        assert_eq!(
            recorded_decision(&policy_refusal),
            Some(ReplayDecision::ApprovalRequired)
        );
        // A catalog-flag-only refusal (including every pre-label historical
        // row): Cedar allowed; the flag refused. The policy verdict is allow.
        let mut flag_refusal = row("denied");
        flag_refusal.reason = Some("approval required: no matching grant".to_owned());
        assert_eq!(
            recorded_decision(&flag_refusal),
            Some(ReplayDecision::Allow)
        );
        let mut resource_refusal = row("denied");
        resource_refusal.action = "ReadResource".to_owned();
        resource_refusal.tool = None;
        resource_refusal.target = Some("bank://statements/2026-08".to_owned());
        resource_refusal.reason = Some("approval required: operator grant".to_owned());
        assert_eq!(
            recorded_decision(&resource_refusal),
            Some(ReplayDecision::ApprovalRequired),
            "native reads must not inherit the tool-only catalog-flag exception",
        );
        // A dispatched policy-gated effect: the grant satisfied Cedar's
        // approval_required verdict, which the unchanged bundle reproduces.
        let mut policy_success = row("success");
        policy_success.reason = Some("policy-gated effect: approval grant consumed".to_owned());
        assert_eq!(
            recorded_decision(&policy_success),
            Some(ReplayDecision::ApprovalRequired)
        );
        assert_eq!(
            recorded_decision(&row("step_up_required")),
            Some(ReplayDecision::StepUp),
        );
        // A non-decision outcome has no verdict to replay.
        assert_eq!(recorded_decision(&row("queued")), None);
        assert_eq!(recorded_decision(&row("")), None);
    }

    #[test]
    fn parse_auth_method_maps_every_known_method_faithfully() {
        assert!(matches!(
            parse_auth_method("api_key"),
            SimulateAuthMethod::ApiKey
        ));
        assert!(matches!(
            parse_auth_method("oauth"),
            SimulateAuthMethod::Oauth
        ));
        // peer_assertion has its own simulator variant — it must NOT coerce to
        // oauth, or a policy that branches on auth_method would replay wrong.
        assert!(matches!(
            parse_auth_method("peer_assertion"),
            SimulateAuthMethod::PeerAssertion
        ));
        // Only a genuinely unknown/future value falls back to the default.
        assert!(matches!(
            parse_auth_method("nonsense"),
            SimulateAuthMethod::Oauth
        ));
    }

    #[test]
    fn reconstruct_preserves_peer_assertion_auth_method() {
        // A peer-asserted (Tier-C federation) decision must reconstruct with the
        // peer auth_method, not coerce to oauth — a policy gating on
        // `principal.auth_method == "peer_assertion"` would otherwise replay the
        // wrong verdict and under/over-count the blast radius.
        let mut row = replayable_row("success", "low");
        row.auth_method = Some("peer_assertion".into());
        let req = reconstruct_simulate_request(&row).expect("peer-asserted row is replayable");
        assert!(matches!(
            req.principal.auth_method,
            SimulateAuthMethod::PeerAssertion
        ));
    }

    #[test]
    fn reconstruct_none_for_legacy_row() {
        // No auth_method ⇒ not replayable, even though the row is a decision.
        assert!(reconstruct_simulate_request(&legacy_row("denied")).is_none());
    }

    #[test]
    fn reconstruct_none_for_model_decision() {
        // A model decision (llm_completion) has no simulator resource shape.
        assert!(reconstruct_simulate_request(&model_row("success")).is_none());
    }

    #[test]
    fn reconstructs_resource_read_as_its_native_action_and_entity() {
        let mut row = replayable_row("success", "low");
        row.action = "ReadResource".into();
        row.tool = None;
        row.target = Some("printable://design/product-v1".into());
        let request = reconstruct_simulate_request(&row).expect("resource read is replayable");
        assert!(matches!(
            request.action,
            SimulateAction::ReadResource { ref uri }
                if uri == "printable://design/product-v1"
        ));
        assert!(matches!(
            request.resource,
            SimulateResource::McpResource { ref server, ref uri, risk }
                if server == "bank"
                    && uri == "printable://design/product-v1"
                    && risk == RiskTier::Low
        ));
    }

    #[test]
    fn reconstructs_skill_list_from_structured_audit_target() {
        let mut row = replayable_row("success", "low");
        row.action = LIST_SKILLS_ACTION.into();
        row.tool = None;
        row.server = Some("gateway-skills".into());
        row.target = Some(
            serde_json::json!({
                "source_origin": "git+https://git.example/api/v1/example/skills",
                "artifact_digest": format!("sha256:{}", "a".repeat(64)),
                "source_tree_digest": format!("git-sha1:{}", "e".repeat(40)),
            })
            .to_string(),
        );

        let request = reconstruct_simulate_request(&row).expect("skill list is replayable");
        assert!(matches!(request.action, SimulateAction::ListSkills));
        assert!(matches!(
            request.resource,
            SimulateResource::Skill {
                ref source_origin,
                ref artifact_digest,
                ref source_tree_digest,
                skill_uri: None,
                resource_uri: None,
                revision_digest: None,
                content_digest: None,
                source_path: None,
                source_object: None,
            } if source_origin == "git+https://git.example/api/v1/example/skills"
                && artifact_digest == &format!("sha256:{}", "a".repeat(64))
                && source_tree_digest.as_deref()
                    == Some(format!("git-sha1:{}", "e".repeat(40)).as_str())
        ));
    }

    #[test]
    fn reconstructs_skill_read_from_structured_audit_target() {
        let mut row = replayable_row("denied", "low");
        row.action = READ_SKILL_ACTION.into();
        row.tool = None;
        row.server = Some("gateway-skills".into());
        row.target = Some(
            serde_json::json!({
                "source_origin": "git+https://git.example/api/v1/example/skills",
                "artifact_digest": format!("sha256:{}", "a".repeat(64)),
                "source_tree_digest": format!("git-sha1:{}", "e".repeat(40)),
                "skill_uri": "skill://catalog/demo/SKILL.md",
                "revision_digest": format!("sha256:{}", "b".repeat(64)),
                "resource_uri": "skill://catalog/demo/scripts/check.js",
                "resource_digest": format!("sha256:{}", "c".repeat(64)),
                "source_path": "plugins/demo/scripts/check.js",
                "source_object": format!("git-sha1:{}", "d".repeat(40)),
            })
            .to_string(),
        );

        let request = reconstruct_simulate_request(&row).expect("skill read is replayable");
        assert!(matches!(
            request.action,
            SimulateAction::ReadSkill { ref uri }
                if uri == "skill://catalog/demo/scripts/check.js"
        ));
        assert!(matches!(
            request.resource,
            SimulateResource::Skill {
                ref source_origin,
                ref artifact_digest,
                ref source_tree_digest,
                ref skill_uri,
                ref resource_uri,
                ref revision_digest,
                ref content_digest,
                ref source_path,
                ref source_object,
            } if source_origin == "git+https://git.example/api/v1/example/skills"
                && artifact_digest == &format!("sha256:{}", "a".repeat(64))
                && source_tree_digest.as_deref()
                    == Some(format!("git-sha1:{}", "e".repeat(40)).as_str())
                && skill_uri.as_deref() == Some("skill://catalog/demo/SKILL.md")
                && resource_uri.as_deref()
                    == Some("skill://catalog/demo/scripts/check.js")
                && revision_digest.as_deref()
                    == Some(format!("sha256:{}", "b".repeat(64)).as_str())
                && content_digest.as_deref()
                    == Some(format!("sha256:{}", "c".repeat(64)).as_str())
                && source_path.as_deref() == Some("plugins/demo/scripts/check.js")
                && source_object.as_deref()
                    == Some(format!("git-sha1:{}", "d".repeat(40)).as_str())
        ));
    }

    #[test]
    fn reconstructs_skill_fetch_without_claiming_a_content_digest() {
        let mut row = replayable_row("denied", "low");
        row.action = FETCH_SKILL_RESOURCE_ACTION.into();
        row.tool = None;
        row.server = Some("gateway-skills".into());
        row.target = Some(
            serde_json::json!({
                "source_origin": "git+https://git.example/api/v1/example/skills",
                "artifact_digest": format!("git-sha1:{}", "a".repeat(40)),
                "skill_uri": "skill://catalog/demo/SKILL.md",
                "revision_digest": format!("sha256:{}", "b".repeat(64)),
                "resource_uri": "skill://catalog/demo/scripts/check.js",
                "source_path": "plugins/demo/scripts/check.js",
                "source_object": format!("git-sha1:{}", "d".repeat(40)),
            })
            .to_string(),
        );

        let request = reconstruct_simulate_request(&row).expect("skill fetch is replayable");
        assert!(matches!(
            request.action,
            SimulateAction::FetchSkillResource { ref uri }
                if uri == "skill://catalog/demo/scripts/check.js"
        ));
        assert!(matches!(
            request.resource,
            SimulateResource::Skill {
                content_digest: None,
                ref source_path,
                ref source_object,
                ..
            } if source_path.as_deref() == Some("plugins/demo/scripts/check.js")
                && source_object.as_deref()
                    == Some(format!("git-sha1:{}", "d".repeat(40)).as_str())
        ));
    }

    #[test]
    fn skill_replay_distinguishes_pre_policy_and_post_allow_refusals() {
        let skill_target = serde_json::json!({
            "source_origin": "git+https://git.example/api/v1/example/skills",
            "artifact_digest": format!("sha256:{}", "a".repeat(64)),
            "skill_uri": "skill://catalog/demo/SKILL.md",
            "revision_digest": format!("sha256:{}", "b".repeat(64)),
            "resource_uri": "skill://catalog/demo/SKILL.md",
            "resource_digest": format!("sha256:{}", "c".repeat(64)),
        })
        .to_string();

        let mut profile_refusal = replayable_row("denied", "low");
        profile_refusal.action = READ_SKILL_ACTION.into();
        profile_refusal.tool = None;
        profile_refusal.server = Some("gateway-skills".into());
        profile_refusal.target = Some(skill_target.clone());
        profile_refusal.reason = Some(waygate_core::SKILL_PROFILE_REFUSAL_REASON.into());

        let mut post_allow_refusal = profile_refusal.clone();
        post_allow_refusal.reason = Some(format!(
            "{}origin collision",
            waygate_core::SKILL_POST_AUTHORIZATION_REFUSAL_PREFIX
        ));

        assert_eq!(recorded_decision(&profile_refusal), None);
        assert_eq!(
            recorded_decision(&post_allow_refusal),
            Some(ReplayDecision::Allow)
        );

        let report = compute_impact(
            PERMIT_ALL,
            &TenantId::default_id(),
            &[profile_refusal, post_allow_refusal],
        );
        assert_eq!(report.considered, 2);
        assert_eq!(report.replayed, 1);
        assert_eq!(report.not_replayable, 1);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.changed, 0);
    }

    #[test]
    fn reconstruct_none_for_scim_enriched_row() {
        // A row that went through SCIM enrichment (scim_active.is_some()) carries
        // only scim_active + scim_groups in the audit row, but the live gate also
        // exposes scim_user_name / scim_external_id / scim_attrs to policies. We
        // can't faithfully reconstruct those, so the row is NOT replayable —
        // excluded, never coerced to placeholder SCIM facts.
        let mut row = replayable_row("success", "low");
        row.scim_active = Some(true);
        row.scim_groups = vec!["scim-admins".to_owned()];
        assert!(
            reconstruct_simulate_request(&row).is_none(),
            "a SCIM-enriched row must be excluded, not replayed against placeholders",
        );

        // A SCIM-INACTIVE row still carried SCIM facts (user_name/external_id may
        // have been set) — scim_active.is_some() is the guard, regardless of the
        // bool value.
        let mut inactive = replayable_row("success", "low");
        inactive.scim_active = Some(false);
        assert!(reconstruct_simulate_request(&inactive).is_none());
    }

    #[test]
    fn compute_impact_counts_scim_rows_as_not_replayable() {
        let tenant = TenantId::default_id();
        // One plain replayable flip + one SCIM-enriched row. The SCIM row must be
        // COUNTED not-replayable, never evaluated against placeholder facts.
        let mut scim = replayable_row("success", "high");
        scim.scim_active = Some(true);
        let rows = vec![replayable_row("success", "high"), scim];
        let report = compute_impact(FORBID_HIGH, &tenant, &rows);
        assert_eq!(report.considered, 2);
        assert_eq!(report.replayed, 1, "only the non-SCIM row replays");
        assert_eq!(report.changed, 1);
        assert_eq!(
            report.not_replayable, 1,
            "the SCIM-enriched row is excluded"
        );
    }

    #[test]
    fn reconstruct_some_round_trips_the_captured_fields() {
        let row = replayable_row("denied", "high");
        let req = reconstruct_simulate_request(&row).expect("populated row is replayable");
        // Principal fields come straight off the captured row.
        assert_eq!(req.principal.sub, "alice@example.com");
        assert_eq!(req.principal.scopes, vec!["mcp:invoke".to_owned()]);
        assert!(matches!(
            req.principal.auth_method,
            SimulateAuthMethod::Oauth
        ));
        assert_eq!(req.principal.groups, vec!["mcp-users".to_owned()]);
        // Action: CallTool with the parsed risk.
        match req.action {
            SimulateAction::CallTool { ref name, risk } => {
                assert_eq!(name, "wire_money");
                assert_eq!(risk, RiskTier::High);
            }
            _ => panic!("expected CallTool action"),
        }
        // Resource: Tool with server / side_effects / risk reconstructed.
        match req.resource {
            SimulateResource::Tool {
                ref server,
                ref name,
                risk,
                side_effects,
                pii,
                ref operation,
            } => {
                assert_eq!(
                    operation.as_deref(),
                    None,
                    "a row with no recorded operation replays without the attribute"
                );
                assert_eq!(server, "bank");
                assert_eq!(name, "wire_money");
                assert_eq!(risk, RiskTier::High);
                assert!(side_effects, "side_effects captured by migration 0062");
                assert!(!pii);
            }
            _ => panic!("expected Tool resource"),
        }
    }

    #[test]
    fn compute_impact_buckets_a_flip_as_allow_to_deny() {
        let tenant = TenantId::default_id();
        // A recorded ALLOW of a high-risk call; the candidate FORBIDS high-risk
        // calls ⇒ this decision flips allow→deny.
        let rows = vec![replayable_row("success", "high")];
        let report = compute_impact(FORBID_HIGH, &tenant, &rows);
        assert!(report.error.is_none());
        assert_eq!(report.considered, 1);
        assert_eq!(report.replayed, 1);
        assert_eq!(report.changed, 1);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.not_replayable, 0);
        assert_eq!(report.deltas.len(), 1);
        assert_eq!(report.deltas[0].from, "allow");
        assert_eq!(report.deltas[0].to, "deny");
        assert_eq!(report.deltas[0].count, 1);
        // The flip is surfaced as a sample naming the call.
        assert_eq!(report.samples.len(), 1);
        assert_eq!(report.samples[0].recorded, "allow");
        assert_eq!(report.samples[0].candidate, "deny");
        assert_eq!(report.samples[0].server_tool, "bank.wire_money");
    }

    /// Hierarchy does not identify the authorization channel. Exclude nested
    /// rows rather than guessing which channel a historical execution used.
    #[test]
    fn compute_impact_excludes_hierarchy_rows_without_a_captured_channel() {
        const PERMIT_PLUS_CODEMODE_OVERLAY: &str = "@id(\"permit-all\")\n\
             permit(principal, action, resource);\n\
             @id(\"codemode-mutation-approval\")\n\
             forbid(principal, action == Action::\"CallTool\", resource)\n\
             when { context.channel == \"codemode\" &&\n\
                    resource.side_effects &&\n\
                    !context.approval_present };";
        let tenant = TenantId::default_id();
        let mut codemode_row = replayable_row("success", "low");
        codemode_row.invocation_hierarchy = Some(waygate_core::InvocationHierarchy {
            parent_execution_id: Uuid::now_v7(),
            step: std::num::NonZeroU32::new(1).unwrap(),
            call_id: Uuid::now_v7(),
            attempt: std::num::NonZeroU32::new(1).unwrap(),
        });
        let rows = vec![codemode_row, replayable_row("success", "low")];
        let report = compute_impact(PERMIT_PLUS_CODEMODE_OVERLAY, &tenant, &rows);
        assert!(report.error.is_none());
        assert_eq!(report.replayed, 1);
        assert_eq!(report.changed, 0);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.not_replayable, 1);
        assert!(report.deltas.is_empty());
    }

    /// A tool call refused at the grant gate (recorded `denied` /
    /// "approval required: …") replays as approval_required against the
    /// UNCHANGED overlay bundle — the impact report must count it
    /// unchanged, never fabricate a deny→approval_required transition.
    #[test]
    fn approval_refusals_replay_unchanged_against_the_same_overlay() {
        const PERMIT_PLUS_APPROVAL_OVERLAY: &str = "@id(\"permit-all\")\n\
             permit(principal, action, resource);\n\
             @id(\"codemode-mutation-approval\")\n\
             forbid(principal, action == Action::\"CallTool\", resource)\n\
             when { resource.side_effects &&\n\
                    !context.approval_present };";
        let tenant = TenantId::default_id();
        let mut refusal = replayable_row("denied", "low");
        refusal.reason = Some("approval required by policy: no matching grant".to_owned());
        let report = compute_impact(PERMIT_PLUS_APPROVAL_OVERLAY, &tenant, &[refusal]);
        assert!(report.error.is_none());
        assert_eq!(report.replayed, 1);
        assert_eq!(report.unchanged, 1, "same bundle ⇒ no transition");
        assert_eq!(report.changed, 0);
    }

    #[test]
    fn resource_approval_refusal_replays_unchanged_against_the_same_overlay() {
        const RESOURCE_APPROVAL_OVERLAY: &str = "@id(\"permit-all\")\n\
             permit(principal, action, resource);\n\
             @id(\"resource-approval\")\n\
             forbid(principal, action == Action::\"ReadResource\", resource)\n\
             when { !context.approval_present };";
        let tenant = TenantId::default_id();
        let mut refusal = replayable_row("denied", "low");
        refusal.action = "ReadResource".to_owned();
        refusal.tool = None;
        refusal.target = Some("bank://statements/2026-08".to_owned());
        refusal.reason = Some("approval required: operator grant".to_owned());

        let report = compute_impact(RESOURCE_APPROVAL_OVERLAY, &tenant, &[refusal]);
        assert!(report.error.is_none());
        assert_eq!(report.replayed, 1);
        assert_eq!(report.unchanged, 1, "same bundle must not fabricate a flip");
        assert_eq!(report.changed, 0);
    }

    #[test]
    fn compute_impact_counts_unchanged_decisions() {
        let tenant = TenantId::default_id();
        // A recorded ALLOW that the permit-all candidate also allows ⇒ unchanged.
        let rows = vec![replayable_row("success", "low")];
        let report = compute_impact(PERMIT_ALL, &tenant, &rows);
        assert_eq!(report.replayed, 1);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.changed, 0);
        assert!(report.deltas.is_empty());
        assert!(report.samples.is_empty());
    }

    #[test]
    fn compute_impact_excludes_non_replayable_rows_without_evaluating_them() {
        let tenant = TenantId::default_id();
        // One replayable flip + a legacy row + a model row. The non-replayable
        // rows must be COUNTED, not evaluated.
        let rows = vec![
            replayable_row("success", "high"), // flips allow→deny under FORBID_HIGH
            legacy_row("denied"),              // no auth_method ⇒ not replayable
            model_row("success"),              // llm_completion ⇒ not replayable
        ];
        let report = compute_impact(FORBID_HIGH, &tenant, &rows);
        assert_eq!(report.considered, 3);
        assert_eq!(
            report.replayed, 1,
            "only the populated tool-call row replays"
        );
        assert_eq!(report.changed, 1);
        assert_eq!(report.not_replayable, 2, "legacy + model rows excluded");
    }

    #[test]
    fn compute_impact_non_decision_outcome_is_not_replayable() {
        let tenant = TenantId::default_id();
        // A capture-stamped invocation row whose outcome isn't a decision verdict.
        let rows = vec![replayable_row("queued", "low")];
        let report = compute_impact(PERMIT_ALL, &tenant, &rows);
        assert_eq!(report.replayed, 0);
        assert_eq!(report.not_replayable, 1);
    }

    #[test]
    fn compute_impact_broken_candidate_is_an_error_report_not_a_panic() {
        let tenant = TenantId::default_id();
        let rows = vec![replayable_row("success", "low")];
        let report = compute_impact("this is not valid cedar {{{", &tenant, &rows);
        assert!(
            report.error.is_some(),
            "a non-parsing candidate must surface as an error, not 0 changes",
        );
        // Nothing is evaluated against a broken engine.
        assert_eq!(report.replayed, 0);
        assert_eq!(report.changed, 0);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.considered, 1);
        assert_eq!(report.not_replayable, 1);
    }

    #[test]
    fn compute_impact_evaluates_under_the_passed_tenant() {
        // A candidate that forbids the call ONLY for tenant "acme". The SAME
        // recorded allow must therefore be UNCHANGED under `default` (permitted)
        // and CHANGED (allow→deny) under `acme` (forbidden) — proving the replay
        // honours the passed tenant, not the converter's default stamp.
        const TENANT_FORBID: &str = "permit(principal, action, resource);\n\
            forbid(principal, action, resource) when { principal.tenant == \"acme\" };";
        let rows = vec![replayable_row("success", "low")];

        let under_default = compute_impact(TENANT_FORBID, &TenantId::default_id(), &rows);
        assert_eq!(under_default.changed, 0, "permitted under default tenant");
        assert_eq!(under_default.unchanged, 1);

        let acme = TenantId::parse("acme").expect("valid tenant id");
        let under_acme = compute_impact(TENANT_FORBID, &acme, &rows);
        assert_eq!(under_acme.changed, 1, "forbidden under acme tenant");
        assert_eq!(under_acme.deltas[0].from, "allow");
        assert_eq!(under_acme.deltas[0].to, "deny");
    }

    /// Replay has to reproduce the entity the live gate evaluated, including
    /// the operation. A policy branching on `resource.operation` would
    /// otherwise be reported as a decision change it never made.
    #[test]
    fn reconstruct_carries_a_recorded_operation() {
        let mut row = replayable_row("denied", "high");
        row.operation = Some("secrets.reveal".to_owned());

        let req = reconstruct_simulate_request(&row).expect("row is replayable");
        match req.resource {
            SimulateResource::Tool { ref operation, .. } => assert_eq!(
                operation.as_deref(),
                Some("secrets.reveal"),
                "the operation the row recorded must reach the replayed resource"
            ),
            other => panic!("expected a tool resource, got {other:?}"),
        }
    }
}
