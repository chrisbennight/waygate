//! Server-manifest classification impact-preview (server-config review parity).
//!
//! The policy impact-preview ([`crate::impact`]) answers "if I publish this
//! POLICY draft, which recorded decisions flip?" by holding the resource facts
//! fixed and varying the engine. This module answers the mirror question for
//! the OTHER half of the authz inputs: "if I publish this SERVER-MANIFEST draft
//! — changing a tool/operation classification, a declared resource URI
//! prefix's risk, or the server-wide ordinary approval posture — which access
//! controls move?", by holding the live POLICY fixed and varying the manifest.
//! Approval-mode changes are surfaced explicitly rather than folded into Cedar
//! replay because annotation/catalog approval is a separate invocation gate.
//!
//! ## Why it can't reuse the policy replay verbatim
//!
//! A tool or selected operation's classification reaches Cedar as the `Tool`
//! entity's `risk` / `side_effects` / `pii` attributes
//! (`waygate-authz/src/cedar.rs`), and the `audit_log` row CAPTURES those values
//! and the selected operation AT DECISION TIME (migrations 0005, 0062). So a
//! row already carries the classification that was live when the call happened
//! — replaying it as-is would re-judge the OLD classification. To preview a
//! classification change we must OVERRIDE the row's captured classification
//! before re-evaluating.
//!
//! ## Isolated-baseline semantics
//!
//! For each affected row we evaluate TWICE under the SAME live policy engine:
//!
//! - **baseline** = the row re-judged with the *active manifest's* current
//!   classification for that tool, and
//! - **candidate** = the row re-judged with the *draft's* classification.
//!
//! The baseline is the ACTIVE MANIFEST's value, **not the row's recorded
//! value**: a row recorded weeks ago may carry a classification that an
//! intervening publish already changed, and attributing that already-live drift
//! to *this* edit would mislead the operator. Anchoring both evals to the
//! active-vs-candidate diff isolates exactly the effect of the proposed change.
//! The row contributes only the *identity* of the call (principal, server,
//! tool, scopes, auth method, roles) — its recorded outcome and classification
//! are not used as the verdict to compare against.
//!
//! Because Cedar's `Tool` entity exposes only `risk` / `side_effects` / `pii`
//! (plus the identity attrs) from a manifest, a tool whose classification is
//! UNCHANGED produces a byte-identical entity in both evals and therefore never
//! flips. We filter the replay set to the changed `(server, tool)` pairs — this
//! loses no flips, it is sound, not merely an optimization. Removed tools have
//! no candidate to evaluate. Added tools have no historical baseline, so a
//! separate bounded prospective sample applies their candidate facts to
//! distinct recent caller contexts instead. The evidence types stay separate:
//! prospective access is not an observed decision change.
//!
//! ## Read-only
//!
//! Like the policy preview, this NEVER writes anything: a pure read of the
//! tenant's recent decisions plus an in-memory re-eval against the live policy
//! snapshot. No publish, no audit mutation, no disk write.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use utoipa::ToSchema;

use waygate_authz::CedarEngine;
use waygate_core::{RiskTier, TenantId};
use waygate_storage::AuditRow;
use waygate_upstream::{
    parse_manifest_set, serialize_manifest_set, ApprovalMode, ClassificationMode,
    ToolClassification,
};

use crate::error::{ApiError, ApiResult};
use crate::impact::{
    format_access_target, format_ts_rfc3339, reconstruct_simulate_request, ImpactDelta,
    ImpactSample, ReplayDecision,
};
use crate::policies::{SimulateAction, SimulateRequest, SimulateResource};
use crate::state::AdminState;

/// How many recent decisions to fetch for a manifest replay. Mirrors
/// `policy_bundles::IMPACT_REPLAY_LIMIT` so the two previews scan the same
/// window of history.
const MANIFEST_REPLAY_LIMIT: i64 = 500;

/// How many changed-decision examples to carry in
/// [`ManifestImpactReport::samples`]. Bounded so a reclassification that flips
/// thousands of calls doesn't produce a multi-megabyte report; the counts still
/// reflect every flip. Mirrors `impact::MAX_SAMPLES`.
const MAX_SAMPLES: usize = 25;

/// Bound both axes of the prospective matrix so approval-page work remains
/// predictable. At most 500 context-target pairs are considered.
const PROSPECTIVE_CONTEXT_LIMIT: usize = 20;
const PROSPECTIVE_TARGET_LIMIT: usize = 25;

/// The classification delta between the active manifest set and a candidate
/// draft, keyed by `(server, tool)`.
///
/// `changed` carries BOTH the active (old) and candidate (new)
/// [`ToolClassification`] for every tool whose classification differs, so the
/// replay core needs no further manifest lookup. `added` / `removed` are tools
/// present in only one side — they have no historical decisions to replay and
/// are surfaced as structural counts.
#[derive(Debug, Clone, Default)]
pub struct ClassificationDiff {
    /// `(server, tool)` -> (active/old classification, candidate/new classification).
    pub changed: BTreeMap<(String, String), (ToolClassification, ToolClassification)>,
    /// `(server, tool)` present in the candidate but not the active set.
    pub added: Vec<(String, String)>,
    /// `(server, tool)` present in the active set but not the candidate.
    pub removed: Vec<(String, String)>,
    /// Complete candidate lookup used by prospective evaluation. Callers
    /// should otherwise reason through the explicit diff buckets above.
    pub(crate) candidate: BTreeMap<(String, String), ToolClassification>,
    /// Active tools whose policy flags derive from reviewed live annotations
    /// rather than from the manifest's legacy flag fields.
    active_annotation_native: BTreeSet<(String, String)>,
    /// Candidate tools whose policy flags require reviewed live annotations.
    candidate_annotation_native: BTreeSet<(String, String)>,
    /// `(server, URI prefix)` -> (active risk, candidate risk).
    pub resource_changed: BTreeMap<(String, String), (RiskTier, RiskTier)>,
    /// Declared resource URI spaces present only in the candidate.
    pub resource_added: Vec<(String, String)>,
    /// Declared resource URI spaces present only in the active set.
    pub resource_removed: Vec<(String, String)>,
    /// Complete candidate resource routing/risk lookup.
    resource_candidate: BTreeMap<(String, String), RiskTier>,
    /// Existing servers whose ordinary approval posture changes.
    approval_modes_changed: BTreeMap<String, (ApprovalMode, ApprovalMode)>,
}

struct ClassificationProjection {
    tools: BTreeMap<(String, String), ToolClassification>,
    annotation_native: BTreeSet<(String, String)>,
    resources: BTreeMap<(String, String), RiskTier>,
    approval_modes: BTreeMap<String, ApprovalMode>,
}

fn classification_projection(
    content: &str,
) -> Result<ClassificationProjection, waygate_upstream::UpstreamError> {
    let set = parse_manifest_set(content)?;
    let mut tools = BTreeMap::new();
    let mut annotation_native = BTreeSet::new();
    let mut resources = BTreeMap::new();
    let mut approval_modes = BTreeMap::new();
    for (server, manifest) in set {
        approval_modes.insert(server.clone(), manifest.approval_mode);
        let derives_flags_from_annotations = matches!(
            manifest.classification_mode,
            ClassificationMode::McpAnnotations
        );
        for mut classification in manifest.tools {
            let key = (server.clone(), classification.name.clone());
            if derives_flags_from_annotations {
                annotation_native.insert(key.clone());
                // Other manifest impact summaries keep a conservative posture
                // when reviewed live annotations are not part of their input.
                classification.side_effects = true;
                classification.pii = true;
            }
            tools.insert(key, classification);
        }
        for resource in manifest.resources {
            resources.insert((server.clone(), resource.uri_prefix), resource.risk);
        }
    }
    Ok(ClassificationProjection {
        tools,
        annotation_native,
        resources,
        approval_modes,
    })
}

/// Build a `(server, tool) -> ToolClassification` map from a manifest-set YAML
/// string. The server name is the manifest set's key (== `manifest.name`).
pub(crate) fn classification_map(
    content: &str,
) -> Result<BTreeMap<(String, String), ToolClassification>, waygate_upstream::UpstreamError> {
    classification_projection(content).map(|projection| projection.tools)
}

/// Diff a candidate manifest set against the active one. `Err(detail)` when
/// EITHER side fails to parse (surfaced as [`ManifestImpactReport::error`] so a
/// broken draft reads as an error, not "0 changes").
pub fn diff_classifications(active: &str, candidate: &str) -> Result<ClassificationDiff, String> {
    let active_projection = classification_projection(active)
        .map_err(|e| format!("active manifest set does not parse: {e}"))?;
    let candidate_projection = classification_projection(candidate)
        .map_err(|e| format!("candidate manifest set does not parse: {e}"))?;
    let active_map = &active_projection.tools;
    let candidate_map = &candidate_projection.tools;

    let mut changed = BTreeMap::new();
    let mut added = Vec::new();
    for (key, cand_tc) in candidate_map {
        match active_map.get(key) {
            Some(active_tc)
                if active_tc != cand_tc
                    || active_projection.annotation_native.contains(key)
                        != candidate_projection.annotation_native.contains(key) =>
            {
                changed.insert(key.clone(), (active_tc.clone(), cand_tc.clone()));
            }
            Some(_) => {} // unchanged classification
            None => added.push(key.clone()),
        }
    }
    let mut removed: Vec<(String, String)> = active_map
        .keys()
        .filter(|k| !candidate_map.contains_key(*k))
        .cloned()
        .collect();
    added.sort();
    removed.sort();

    let mut resource_changed = BTreeMap::new();
    let mut resource_added = Vec::new();
    for (key, candidate_risk) in &candidate_projection.resources {
        match active_projection.resources.get(key) {
            Some(active_risk) if active_risk != candidate_risk => {
                resource_changed.insert(key.clone(), (*active_risk, *candidate_risk));
            }
            Some(_) => {}
            None => resource_added.push(key.clone()),
        }
    }
    let mut resource_removed = active_projection
        .resources
        .keys()
        .filter(|key| !candidate_projection.resources.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    resource_added.sort();
    resource_removed.sort();

    let approval_modes_changed = candidate_projection
        .approval_modes
        .iter()
        .filter_map(|(server, candidate_mode)| {
            let active_mode = active_projection.approval_modes.get(server)?;
            (active_mode != candidate_mode)
                .then(|| (server.clone(), (*active_mode, *candidate_mode)))
        })
        .collect();

    Ok(ClassificationDiff {
        changed,
        added,
        removed,
        candidate: candidate_projection.tools,
        active_annotation_native: active_projection.annotation_native,
        candidate_annotation_native: candidate_projection.annotation_native,
        resource_changed,
        resource_added,
        resource_removed,
        resource_candidate: candidate_projection.resources,
        approval_modes_changed,
    })
}

/// Override a reconstructed request's tool classification in place — on BOTH
/// the `CallTool` action's `risk` and the `Tool` resource's `risk` /
/// `side_effects` / `pii`. The Cedar entity attributes come from the resource
/// side; patching the action's `risk` too keeps the request internally
/// consistent (a step-up path that reads the action risk sees the same value).
fn effective_classification(
    c: &ToolClassification,
    operation: Option<&str>,
) -> (RiskTier, bool, bool) {
    if c.discriminator.is_some() {
        if let Some(classification) = operation
            .and_then(|operation| c.operations.iter().find(|entry| entry.value == operation))
        {
            return (
                classification.risk,
                classification.side_effects,
                classification.pii,
            );
        }
    }
    (c.risk, c.side_effects, c.pii)
}

fn apply_classification(req: &mut SimulateRequest, c: &ToolClassification) {
    let operation = match &req.resource {
        SimulateResource::Tool { operation, .. } => operation.as_deref(),
        SimulateResource::Server { .. }
        | SimulateResource::McpResource { .. }
        | SimulateResource::Skill { .. } => None,
    };
    let (effective_risk, effective_side_effects, effective_pii) =
        effective_classification(c, operation);
    if let SimulateAction::CallTool { risk, .. } = &mut req.action {
        *risk = effective_risk;
    }
    if let SimulateResource::Tool {
        risk,
        side_effects,
        pii,
        ..
    } = &mut req.resource
    {
        *risk = effective_risk;
        *side_effects = effective_side_effects;
        *pii = effective_pii;
    }
}

fn apply_resource_risk(req: &mut SimulateRequest, risk: RiskTier) {
    if let SimulateResource::McpResource {
        risk: request_risk, ..
    } = &mut req.resource
    {
        *request_risk = risk;
    }
}

/// Re-judge `req` under `engine` with `c`'s classification applied, scoped to
/// `tenant`. `None` on a request-time evaluation error (treated as
/// not-replayable for that row, exactly like the policy replay).
fn decide(
    engine: &CedarEngine,
    tenant: &TenantId,
    req: &SimulateRequest,
    c: &ToolClassification,
) -> Option<ReplayDecision> {
    let mut patched = req.clone();
    apply_classification(&mut patched, c);
    // Tenant-scope the evaluation to the row's tenant (the rows are already
    // scoped to the caller) and carry the reconstructed runtime context.
    let facts = crate::policies::simulate_request_to_facts(patched, tenant.clone());
    match engine.evaluate_facts_strict(&facts) {
        Ok(r) => Some(ReplayDecision::from_engine(r.decision)),
        Err(_) => None,
    }
}

fn decide_resource(
    engine: &CedarEngine,
    tenant: &TenantId,
    req: &SimulateRequest,
    risk: RiskTier,
) -> Option<ReplayDecision> {
    let mut patched = req.clone();
    apply_resource_risk(&mut patched, risk);
    let facts = crate::policies::simulate_request_to_facts(patched, tenant.clone());
    engine
        .evaluate_facts_strict(&facts)
        .ok()
        .map(|result| ReplayDecision::from_engine(result.decision))
}

/// A server-wide change to the sources that can require ordinary per-call
/// approval. Cedar remains authoritative in both modes.
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ManifestApprovalModeChange {
    pub server: String,
    pub from: String,
    pub to: String,
    /// Manifest-declared tools whose ordinary approval posture changes.
    pub tools_affected: usize,
    /// `true` for `per_call -> policy_only`, which suppresses annotation and
    /// catalog approval requirements and therefore expands callable posture.
    pub relaxes_ordinary_approval: bool,
}

/// The blast-radius report for publishing a server-manifest classification
/// change.
///
/// Accounting over the fetched window:
/// `affected == replayed + not_replayable` (rows touching a changed tool),
/// `unchanged + changed == replayed`. Rows whose `(server, tool)` is NOT in the
/// changed set are out of scope and counted only in `considered`.
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ManifestImpactReport {
    /// The candidate (or active) manifest set does not parse. `Some(detail)` ⇒
    /// nothing was evaluated and all counts except `considered` are 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Tools whose classification differs between active and candidate.
    pub tools_changed: usize,
    /// Tools present in the candidate but not the active set (no replay history).
    pub tools_added: usize,
    /// Tools present in the active set but not the candidate (no candidate eval).
    pub tools_removed: usize,
    /// Declared resource URI prefixes whose risk differs.
    pub resources_changed: usize,
    /// Declared resource URI prefixes present only in the candidate.
    pub resources_added: usize,
    /// Declared resource URI prefixes present only in the active set.
    pub resources_removed: usize,
    /// Explicit server-wide approval-posture changes. These are not Cedar
    /// reclassifications, so they are surfaced separately from replay counts.
    pub approval_mode_changes: Vec<ManifestApprovalModeChange>,
    /// Bounded evaluation of added and reclassified candidate access targets
    /// against distinct recent caller contexts. Each target is either the
    /// tool-level fallback or one declared operation. This is prospective
    /// evidence, not a claim that those exact calls occurred historically.
    pub prospective_access: ManifestProspectiveAccessReport,
    /// Whether historical replay produced evidence for this candidate. This
    /// prevents a zero-row replay from being presented as proof of no impact.
    pub replay_applicability: ManifestReplayApplicability,
    /// Total recorded decisions considered (the rows fetched for the tenant).
    pub considered: usize,
    /// Of `considered`, how many called a tool whose classification changed —
    /// the only rows that can possibly flip.
    pub affected: usize,
    /// Of `affected`, how many were reconstructable and evaluated (twice).
    pub replayed: usize,
    /// Of `replayed`, how many produced the SAME verdict under the new
    /// classification.
    pub unchanged: usize,
    /// Of `replayed`, how many FLIPPED under the new classification.
    pub changed: usize,
    /// Of `affected`, how many could NOT be replayed (legacy rows without the
    /// captured inputs, SCIM-enriched rows, or a request-time eval error).
    pub not_replayable: usize,
    /// Per-transition counts for the flips (allow→deny, deny→allow, →step_up, …).
    pub deltas: Vec<ImpactDelta>,
    /// A bounded set of flipped-decision examples. The sample's `recorded` field
    /// carries the BASELINE (active-classification) verdict, `candidate` the new
    /// one — there is no single "recorded" outcome here, the baseline is
    /// recomputed under the live policy (see module docs).
    pub samples: Vec<ImpactSample>,
}

/// Why prospective Cedar evaluation did or did not produce access evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestProspectiveApplicability {
    /// At least one candidate access target was evaluated for at least one
    /// recent caller context.
    Evaluated,
    /// No added/reclassified tool or resource prefix exists to evaluate. The
    /// historical wire name is retained for API compatibility.
    NoCandidateTools,
    /// Resource prefixes changed, but the bounded history contains no exact
    /// resource URI under those prefixes. The preview refuses to invent one.
    NoConcreteResourceHistory,
    /// Candidate tools exist, but recent audit rows contained no faithfully
    /// reconstructable caller context.
    NoRecentCallerContexts,
    /// Parsing or another prerequisite failed.
    Unavailable,
    /// The tenant-local ledger mutation does not activate the gateway-wide
    /// manifest.
    LedgerOnlyNoActivation,
}

/// Whether one candidate access target has enough facts for a trustworthy
/// prospective Cedar verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestProspectiveTargetApplicability {
    /// All runtime authorization facts are represented by the manifest.
    Evaluated,
    /// Side-effect and sensitivity facts derive from reviewed live MCP
    /// annotations, which the manifest draft does not contain.
    RuntimeAnnotationFactsUnavailable,
    /// A tool-level fallback can retain any admissible undeclared operation
    /// value as a Cedar attribute, so one finite verdict cannot represent it.
    UndeclaredOperationValueUnbounded,
}

/// Prospective Cedar verdict totals for one candidate access target across the
/// sampled caller contexts.
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ManifestProspectiveAccessTarget {
    pub server: String,
    pub tool: String,
    /// A declared operation refinement. `None` is the tool-level fallback that
    /// applies when no operation entry matches at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    pub applicability: ManifestProspectiveTargetApplicability,
    pub allow: usize,
    pub deny: usize,
    pub step_up: usize,
    pub approval_required: usize,
    /// Context-target pairs that could not produce a trustworthy verdict.
    pub indeterminate: usize,
}

/// Prospective Cedar verdict totals for one exact, previously observed
/// resource URI that falls under an added or reclassified candidate prefix.
/// Exact URIs come from the bounded audit window; the preview never invents a
/// representative URI for an open-ended prefix.
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ManifestProspectiveResourceAccessTarget {
    pub server: String,
    pub uri: String,
    #[schemars(with = "String")]
    pub risk: RiskTier,
    pub allow: usize,
    pub deny: usize,
    pub step_up: usize,
    pub approval_required: usize,
    pub indeterminate: usize,
}

impl ManifestProspectiveResourceAccessTarget {
    fn new(server: String, uri: String, risk: RiskTier) -> Self {
        Self {
            server,
            uri,
            risk,
            allow: 0,
            deny: 0,
            step_up: 0,
            approval_required: 0,
            indeterminate: 0,
        }
    }
}

impl ManifestProspectiveAccessTarget {
    fn new(
        server: &str,
        tool: &str,
        operation: Option<String>,
        applicability: ManifestProspectiveTargetApplicability,
    ) -> Self {
        Self {
            server: server.to_owned(),
            tool: tool.to_owned(),
            operation,
            applicability,
            allow: 0,
            deny: 0,
            step_up: 0,
            approval_required: 0,
            indeterminate: 0,
        }
    }
}

/// Bounded prospective access evidence for candidate capabilities.
#[derive(Debug, Clone, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ManifestProspectiveAccessReport {
    pub applicability: ManifestProspectiveApplicability,
    /// Distinct recent principal + runtime-channel contexts evaluated.
    pub caller_contexts_considered: usize,
    /// Additional distinct contexts omitted by the fixed preview bound.
    pub caller_contexts_omitted: usize,
    /// Tool-level fallbacks plus declared operation refinements considered.
    pub targets_considered: usize,
    /// Additional candidate access targets omitted by the fixed preview bound.
    pub targets_omitted: usize,
    pub evaluations: usize,
    pub allow: usize,
    pub deny: usize,
    pub step_up: usize,
    pub approval_required: usize,
    pub indeterminate: usize,
    pub targets: Vec<ManifestProspectiveAccessTarget>,
    /// Exact observed resource URIs evaluated under candidate prefix risks.
    pub resource_targets: Vec<ManifestProspectiveResourceAccessTarget>,
}

impl ManifestProspectiveAccessReport {
    fn unavailable(applicability: ManifestProspectiveApplicability) -> Self {
        Self {
            applicability,
            caller_contexts_considered: 0,
            caller_contexts_omitted: 0,
            targets_considered: 0,
            targets_omitted: 0,
            evaluations: 0,
            allow: 0,
            deny: 0,
            step_up: 0,
            approval_required: 0,
            indeterminate: 0,
            targets: Vec::new(),
            resource_targets: Vec::new(),
        }
    }
}

/// Why a manifest classification replay did or did not produce comparative
/// authorization evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestReplayApplicability {
    /// At least one affected decision was reconstructed and evaluated.
    Replayed,
    /// The candidate has no reclassified existing tool or resource prefix.
    /// The historical wire name is retained for API compatibility.
    NoReclassifiedTools,
    /// Classifications changed, but the bounded decision window contains no
    /// call to those tools.
    NoMatchingHistory,
    /// Matching rows exist, but none carried enough captured input for a
    /// faithful replay.
    NoReplayableHistory,
    /// Parsing or another replay prerequisite failed.
    Unavailable,
    /// The tenant-local ledger mutation does not activate the gateway-wide
    /// manifest, so there is no live authorization effect to replay.
    LedgerOnlyNoActivation,
}

impl ManifestImpactReport {
    /// An error report: nothing evaluated, only `considered` reflects the fetch.
    /// `pub(crate)` so the editor preview surface can render a panel error when
    /// the replay dependency (engine / audit / on-disk set) is unavailable.
    pub(crate) fn error(detail: String, considered: usize) -> Self {
        ManifestImpactReport {
            error: Some(detail),
            tools_changed: 0,
            tools_added: 0,
            tools_removed: 0,
            resources_changed: 0,
            resources_added: 0,
            resources_removed: 0,
            approval_mode_changes: Vec::new(),
            prospective_access: ManifestProspectiveAccessReport::unavailable(
                ManifestProspectiveApplicability::Unavailable,
            ),
            replay_applicability: ManifestReplayApplicability::Unavailable,
            considered,
            affected: 0,
            replayed: 0,
            unchanged: 0,
            changed: 0,
            not_replayable: 0,
            deltas: Vec::new(),
            samples: Vec::new(),
        }
    }

    pub(crate) fn ledger_only(candidate_content: &str) -> Self {
        if let Err(error) = parse_manifest_set(candidate_content) {
            return Self::error(format!("candidate manifest set does not parse: {error}"), 0);
        }
        ManifestImpactReport {
            error: None,
            tools_changed: 0,
            tools_added: 0,
            tools_removed: 0,
            resources_changed: 0,
            resources_added: 0,
            resources_removed: 0,
            approval_mode_changes: Vec::new(),
            prospective_access: ManifestProspectiveAccessReport::unavailable(
                ManifestProspectiveApplicability::LedgerOnlyNoActivation,
            ),
            replay_applicability: ManifestReplayApplicability::LedgerOnlyNoActivation,
            considered: 0,
            affected: 0,
            replayed: 0,
            unchanged: 0,
            changed: 0,
            not_replayable: 0,
            deltas: Vec::new(),
            samples: Vec::new(),
        }
    }
}

/// Build a stable identity for a faithfully reconstructed caller context.
/// Cedar treats groups/scopes/roles as sets; sorting before serialization
/// prevents equivalent rows with a different capture order from consuming
/// multiple slots in the bounded sample.
fn caller_context_key(req: &SimulateRequest) -> Option<String> {
    let mut principal = req.principal.clone();
    principal.groups.sort();
    principal.groups.dedup();
    principal.scopes.sort();
    principal.scopes.dedup();
    principal.roles.sort();
    principal.roles.dedup();
    serde_json::to_string(&(principal, req.context.clone())).ok()
}

fn evaluate_candidate_target(
    engine: &CedarEngine,
    tenant: &TenantId,
    context: &SimulateRequest,
    target: &ManifestProspectiveAccessTarget,
    classification: &ToolClassification,
) -> Option<ReplayDecision> {
    let (risk, side_effects, pii) =
        effective_classification(classification, target.operation.as_deref());
    let mut request = context.clone();
    request.action = SimulateAction::CallTool {
        name: target.tool.clone(),
        risk,
    };
    request.resource = SimulateResource::Tool {
        server: target.server.clone(),
        name: target.tool.clone(),
        risk,
        side_effects,
        pii,
        operation: target.operation.clone(),
    };
    let facts = crate::policies::simulate_request_to_facts(request, tenant.clone());
    engine
        .evaluate_facts_strict(&facts)
        .ok()
        .map(|result| ReplayDecision::from_engine(result.decision))
}

fn evaluate_candidate_resource_target(
    engine: &CedarEngine,
    tenant: &TenantId,
    context: &SimulateRequest,
    target: &ManifestProspectiveResourceAccessTarget,
) -> Option<ReplayDecision> {
    let mut request = context.clone();
    request.action = SimulateAction::ReadResource {
        uri: target.uri.clone(),
    };
    request.resource = SimulateResource::McpResource {
        server: target.server.clone(),
        uri: target.uri.clone(),
        risk: target.risk,
    };
    let facts = crate::policies::simulate_request_to_facts(request, tenant.clone());
    engine
        .evaluate_facts_strict(&facts)
        .ok()
        .map(|result| ReplayDecision::from_engine(result.decision))
}

fn compute_prospective_access(
    engine: &CedarEngine,
    tenant: &TenantId,
    diff: &ClassificationDiff,
    rows: &[AuditRow],
) -> ManifestProspectiveAccessReport {
    let candidate_keys: Vec<_> = diff
        .added
        .iter()
        .chain(diff.changed.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let candidate_resource_claims = diff
        .resource_added
        .iter()
        .chain(diff.resource_changed.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    if candidate_keys.is_empty() && candidate_resource_claims.is_empty() {
        return ManifestProspectiveAccessReport::unavailable(
            ManifestProspectiveApplicability::NoCandidateTools,
        );
    }

    // Give every candidate tool its conservative fallback before spending the
    // remaining target budget on operation refinements. One operation-rich
    // tool therefore cannot hide every later tool from the preview.
    let target_applicability =
        |server: &str, tool: &str, classification: &ToolClassification, fallback: bool| {
            if diff
                .candidate_annotation_native
                .contains(&(server.to_owned(), tool.to_owned()))
            {
                ManifestProspectiveTargetApplicability::RuntimeAnnotationFactsUnavailable
            } else if fallback && classification.discriminator.is_some() {
                // The live resolver retains admissible discriminator strings even
                // when no operation entry names them. Their tool-level risk facts
                // are known, but Cedar may branch on the retained string, so a
                // synthetic `operation: None` verdict would not cover the category.
                ManifestProspectiveTargetApplicability::UndeclaredOperationValueUnbounded
            } else {
                ManifestProspectiveTargetApplicability::Evaluated
            }
        };
    let mut candidate_targets = candidate_keys
        .iter()
        .filter_map(|(server, tool)| {
            let classification = diff.candidate.get(&(server.clone(), tool.clone()))?;
            Some(ManifestProspectiveAccessTarget::new(
                server,
                tool,
                None,
                target_applicability(server, tool, classification, true),
            ))
        })
        .collect::<Vec<_>>();
    for (server, tool) in &candidate_keys {
        let Some(classification) = diff.candidate.get(&(server.clone(), tool.clone())) else {
            continue;
        };
        let mut operations = classification.operations.iter().collect::<Vec<_>>();
        operations.sort_by(|left, right| left.value.cmp(&right.value));
        for operation in operations {
            candidate_targets.push(ManifestProspectiveAccessTarget::new(
                server,
                tool,
                Some(operation.value.clone()),
                target_applicability(server, tool, classification, false),
            ));
        }
    }

    let mut resource_targets = BTreeMap::new();
    for row in rows {
        if row.action != "ReadResource" {
            continue;
        }
        let Some(uri) = row.target.as_deref() else {
            continue;
        };
        // The row's server is the owner at capture time. Match the exact
        // observed URI against the candidate prefix instead so an ownership
        // move is previewed under its new server. Candidate prefix ownership
        // is set-wide non-overlapping, so this still selects at most one owner.
        let Some((server, risk)) = candidate_resource_claims.iter().find_map(|claim| {
            if uri.starts_with(&claim.1) {
                diff.resource_candidate
                    .get(claim)
                    .copied()
                    .map(|risk| (claim.0.as_str(), risk))
            } else {
                None
            }
        }) else {
            continue;
        };
        resource_targets
            .entry((server.to_owned(), uri.to_owned()))
            .or_insert_with(|| {
                ManifestProspectiveResourceAccessTarget::new(
                    server.to_owned(),
                    uri.to_owned(),
                    risk,
                )
            });
    }
    let resource_targets = resource_targets.into_values().collect::<Vec<_>>();

    if candidate_targets.is_empty() && resource_targets.is_empty() {
        return ManifestProspectiveAccessReport::unavailable(
            ManifestProspectiveApplicability::NoConcreteResourceHistory,
        );
    }

    let mut seen = BTreeSet::new();
    let mut contexts = Vec::new();
    let mut caller_contexts_omitted = 0usize;
    for row in rows {
        let Some(request) = reconstruct_simulate_request(row) else {
            continue;
        };
        let Some(key) = caller_context_key(&request) else {
            continue;
        };
        if !seen.insert(key) {
            continue;
        }
        if contexts.len() < PROSPECTIVE_CONTEXT_LIMIT {
            contexts.push(request);
        } else {
            caller_contexts_omitted += 1;
        }
    }
    if contexts.is_empty() {
        let mut report = ManifestProspectiveAccessReport::unavailable(
            ManifestProspectiveApplicability::NoRecentCallerContexts,
        );
        report.targets_omitted = candidate_targets
            .len()
            .saturating_add(resource_targets.len())
            .saturating_sub(PROSPECTIVE_TARGET_LIMIT);
        return report;
    }

    // Share the fixed target budget between tool and resource evidence. When
    // both exist, reserve roughly half for each before using spare capacity.
    let mut tool_take = if resource_targets.is_empty() {
        candidate_targets.len().min(PROSPECTIVE_TARGET_LIMIT)
    } else {
        candidate_targets.len().min(PROSPECTIVE_TARGET_LIMIT / 2)
    };
    let resource_take = resource_targets
        .len()
        .min(PROSPECTIVE_TARGET_LIMIT.saturating_sub(tool_take));
    tool_take += candidate_targets
        .len()
        .saturating_sub(tool_take)
        .min(PROSPECTIVE_TARGET_LIMIT.saturating_sub(tool_take + resource_take));
    let targets_considered = tool_take + resource_take;
    let total_targets = candidate_targets.len() + resource_targets.len();

    let mut report = ManifestProspectiveAccessReport {
        applicability: ManifestProspectiveApplicability::Evaluated,
        caller_contexts_considered: contexts.len(),
        caller_contexts_omitted,
        targets_considered,
        targets_omitted: total_targets.saturating_sub(targets_considered),
        evaluations: 0,
        allow: 0,
        deny: 0,
        step_up: 0,
        approval_required: 0,
        indeterminate: 0,
        targets: Vec::new(),
        resource_targets: Vec::new(),
    };

    for mut target_report in candidate_targets.into_iter().take(tool_take) {
        let Some(classification) = diff
            .candidate
            .get(&(target_report.server.clone(), target_report.tool.clone()))
        else {
            continue;
        };
        for context in &contexts {
            report.evaluations += 1;
            if matches!(
                target_report.applicability,
                ManifestProspectiveTargetApplicability::RuntimeAnnotationFactsUnavailable
                    | ManifestProspectiveTargetApplicability::UndeclaredOperationValueUnbounded
            ) {
                report.indeterminate += 1;
                target_report.indeterminate += 1;
                continue;
            }
            match evaluate_candidate_target(engine, tenant, context, &target_report, classification)
            {
                Some(ReplayDecision::Allow) => {
                    report.allow += 1;
                    target_report.allow += 1;
                }
                Some(ReplayDecision::Deny) => {
                    report.deny += 1;
                    target_report.deny += 1;
                }
                Some(ReplayDecision::StepUp) => {
                    report.step_up += 1;
                    target_report.step_up += 1;
                }
                Some(ReplayDecision::ApprovalRequired) => {
                    report.approval_required += 1;
                    target_report.approval_required += 1;
                }
                None => {
                    report.indeterminate += 1;
                    target_report.indeterminate += 1;
                }
            }
        }
        report.targets.push(target_report);
    }
    for mut target_report in resource_targets.into_iter().take(resource_take) {
        for context in &contexts {
            report.evaluations += 1;
            match evaluate_candidate_resource_target(engine, tenant, context, &target_report) {
                Some(ReplayDecision::Allow) => {
                    report.allow += 1;
                    target_report.allow += 1;
                }
                Some(ReplayDecision::Deny) => {
                    report.deny += 1;
                    target_report.deny += 1;
                }
                Some(ReplayDecision::StepUp) => {
                    report.step_up += 1;
                    target_report.step_up += 1;
                }
                Some(ReplayDecision::ApprovalRequired) => {
                    report.approval_required += 1;
                    target_report.approval_required += 1;
                }
                None => {
                    report.indeterminate += 1;
                    target_report.indeterminate += 1;
                }
            }
        }
        report.resource_targets.push(target_report);
    }
    report
}

/// Replay `rows` against a precomputed classification `diff`, under the live
/// policy `engine`, and report the blast radius. Pure (no I/O); the engine is
/// pinned by the caller.
pub fn compute_manifest_impact(
    engine: &CedarEngine,
    tenant: &TenantId,
    diff: &ClassificationDiff,
    rows: &[AuditRow],
) -> ManifestImpactReport {
    let considered = rows.len();
    let prospective_access = compute_prospective_access(engine, tenant, diff, rows);
    let mut affected = 0usize;
    let mut replayed = 0usize;
    let mut unchanged = 0usize;
    let mut changed = 0usize;
    let mut not_replayable = 0usize;
    // (from, to) -> count, keyed by the wire strings for a stable, sorted order.
    let mut delta_counts: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
    let mut samples: Vec<ImpactSample> = Vec::new();

    for row in rows {
        enum ChangedClassification<'a> {
            Tool {
                key: (String, String),
                old: &'a ToolClassification,
                new: &'a ToolClassification,
            },
            Resource {
                old: RiskTier,
                new: RiskTier,
            },
        }

        let changed_classification = if row.action == "ReadResource" {
            let (Some(server), Some(uri)) = (row.server.as_deref(), row.target.as_deref()) else {
                continue;
            };
            diff.resource_changed
                .iter()
                .find_map(|((owner, prefix), risks)| {
                    (owner == server && uri.starts_with(prefix)).then_some(
                        ChangedClassification::Resource {
                            old: risks.0,
                            new: risks.1,
                        },
                    )
                })
        } else {
            let (Some(server), Some(tool)) = (row.server.as_deref(), row.tool.as_deref()) else {
                continue;
            };
            let key = (server.to_owned(), tool.to_owned());
            diff.changed
                .get(&key)
                .map(|(old, new)| ChangedClassification::Tool { key, old, new })
        };
        let Some(changed_classification) = changed_classification else {
            continue;
        };
        affected += 1;

        if let ChangedClassification::Tool { key, old, new } = &changed_classification {
            if diff.active_annotation_native.contains(key)
                || diff.candidate_annotation_native.contains(key)
            {
                // Annotation-native side-effect and sensitivity facts come
                // from the reviewed live descriptor, not this manifest.
                not_replayable += 1;
                continue;
            }
            if row.operation.is_none()
                && (old.discriminator.is_some() || new.discriminator.is_some())
            {
                // Null predates operation capture and also represents a current
                // call without a selected operation. Those cases cannot be
                // distinguished without the original arguments.
                not_replayable += 1;
                continue;
            }
        }

        // Reconstruct the call identity (principal/action/resource); the
        // captured classification is overwritten in both evals below.
        let Some(req) = reconstruct_simulate_request(row) else {
            not_replayable += 1;
            continue;
        };

        let decisions = match changed_classification {
            ChangedClassification::Tool { old, new, .. } => {
                // The row retains the selected operation, not the original
                // arguments. A changed discriminator cannot be replayed.
                if old.discriminator != new.discriminator {
                    None
                } else {
                    decide(engine, tenant, &req, old).zip(decide(engine, tenant, &req, new))
                }
            }
            ChangedClassification::Resource { old, new } => {
                decide_resource(engine, tenant, &req, old)
                    .zip(decide_resource(engine, tenant, &req, new))
            }
        };
        let Some((baseline, candidate)) = decisions else {
            not_replayable += 1;
            continue;
        };

        replayed += 1;
        if baseline == candidate {
            unchanged += 1;
        } else {
            changed += 1;
            *delta_counts
                .entry((baseline.as_str(), candidate.as_str()))
                .or_insert(0) += 1;
            if samples.len() < MAX_SAMPLES {
                samples.push(ImpactSample {
                    recorded: baseline.as_str().to_owned(),
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

    let replay_applicability = if diff.changed.is_empty() && diff.resource_changed.is_empty() {
        ManifestReplayApplicability::NoReclassifiedTools
    } else if affected == 0 {
        ManifestReplayApplicability::NoMatchingHistory
    } else if replayed == 0 {
        ManifestReplayApplicability::NoReplayableHistory
    } else {
        ManifestReplayApplicability::Replayed
    };

    let approval_mode_changes = diff
        .approval_modes_changed
        .iter()
        .map(|(server, (from, to))| ManifestApprovalModeChange {
            server: server.clone(),
            from: approval_mode_name(*from).to_owned(),
            to: approval_mode_name(*to).to_owned(),
            tools_affected: diff
                .candidate
                .keys()
                .filter(|(candidate_server, _)| candidate_server == server)
                .count(),
            relaxes_ordinary_approval: matches!(
                (from, to),
                (ApprovalMode::PerCall, ApprovalMode::PolicyOnly)
            ),
        })
        .collect();

    ManifestImpactReport {
        error: None,
        tools_changed: diff.changed.len(),
        tools_added: diff.added.len(),
        tools_removed: diff.removed.len(),
        resources_changed: diff.resource_changed.len(),
        resources_added: diff.resource_added.len(),
        resources_removed: diff.resource_removed.len(),
        approval_mode_changes,
        prospective_access,
        replay_applicability,
        considered,
        affected,
        replayed,
        unchanged,
        changed,
        not_replayable,
        deltas,
        samples,
    }
}

const fn approval_mode_name(mode: ApprovalMode) -> &'static str {
    match mode {
        ApprovalMode::PerCall => "per_call",
        ApprovalMode::PolicyOnly => "policy_only",
    }
}

/// Convenience: diff the two manifest contents, then replay. A parse failure on
/// either side becomes an [`ManifestImpactReport::error`] (nothing evaluated).
pub fn compute_manifest_impact_from_content(
    engine: &CedarEngine,
    tenant: &TenantId,
    active_content: &str,
    candidate_content: &str,
    rows: &[AuditRow],
) -> ManifestImpactReport {
    match diff_classifications(active_content, candidate_content) {
        Ok(diff) => compute_manifest_impact(engine, tenant, &diff, rows),
        Err(detail) => ManifestImpactReport::error(detail, rows.len()),
    }
}

/// The active manifest set the gateway is ENFORCING, as canonical YAML — read
/// from the on-disk `servers_dir` (the file-as-truth source the runtime loads
/// via `load_manifests` / `resolve_manifests`), **not** the ledger.
///
/// The ledger only FOLLOWS disk (`server_manifest_pointer.updated_by =
/// filesystem-*`), so baselining from `manifest_store.active_bundle` would let
/// an out-of-band `servers/*.yaml` edit, or a stale / empty ledger, make the
/// preview diff the candidate against the WRONG baseline and under-report a real
/// `risk` / `pii` / `side_effects` change. This mirrors the
/// dashboard's own render + stale-edit base
/// ([`AdminState::read_manifest_set_from_disk`]) so preview, render, and the
/// write-path guard all agree on "what is currently live."
///
/// A wired-but-unreadable `servers_dir` is a HARD error (fail-loud — never a
/// silent empty baseline that would report "no affected decisions" for a real
/// change). `None` `servers_dir` (tests / dev with no on-disk set) → empty
/// active set, so every candidate tool reads as `added`.
pub(crate) fn active_manifest_snapshot(state: &AdminState) -> ApiResult<(String, Option<String>)> {
    match state.read_manifest_set_from_disk() {
        Some(Ok((set, hash))) => serialize_manifest_set(&set)
            .map(|content| (content, Some(hash)))
            .map_err(|e| ApiError::Internal(format!("serialize active manifest set: {e}"))),
        Some(Err(e)) => Err(ApiError::Internal(format!(
            "active manifest set unreadable on disk: {e}"
        ))),
        None => Ok(("[]".to_owned(), None)),
    }
}

pub(crate) fn active_manifest_content(state: &AdminState) -> ApiResult<String> {
    active_manifest_snapshot(state).map(|(content, _hash)| content)
}

/// Read-only shared core behind the editor preview and the HITL change
/// queue: pin the live policy engine, read the active (on-disk) manifest
/// as the baseline, fetch the tenant's recent decisions, and compute the report.
///
/// `tenant` is the SECURITY boundary — the bundle/change's OWN tenant, never a
/// viewer's — so a replay can't read another tenant's audit history (identical
/// to `policy_bundles::replay_recent_decisions`). 503 when the policy engine or
/// audit store is unwired; the manifest baseline comes from disk, not the store
/// (see [`active_manifest_content`]). The on-disk manifest set and the policy
/// engine are both global (one served set, one engine) exactly as the live gate
/// sees them; only the audit rows and the eval's `principal.tenant` are
/// tenant-scoped.
///
/// `pub` (rather than `pub(crate)`) so its in-crate callers — the editor
/// preview route and the change-queue preview — can consume it.
pub async fn replay_manifest_impact(
    state: &AdminState,
    tenant: &TenantId,
    candidate_content: &str,
) -> ApiResult<ManifestImpactReport> {
    // Baseline = what the gateway is ENFORCING right now: the on-disk active
    // manifest set (file-as-truth), not the ledger (which only follows disk).
    let active_content = active_manifest_content(state)?;
    replay_manifest_impact_against(state, tenant, &active_content, candidate_content).await
}

/// Replay against an already-read active manifest snapshot. The approval
/// preview uses this form so classification evidence and the effective-state
/// projection share one filesystem baseline.
pub(crate) async fn replay_manifest_impact_against(
    state: &AdminState,
    tenant: &TenantId,
    active_content: &str,
    candidate_content: &str,
) -> ApiResult<ManifestImpactReport> {
    let engine = state
        .policy
        .cedar
        .require()?
        // Pin ONE snapshot for the whole replay so a mid-replay SIGHUP can't
        // judge different rows under different policy sets.
        .snapshot_for_tenant(tenant.as_str());
    let reader = state.observability.audit.require()?;

    let query = crate::audit::decision_store_query(tenant.as_str(), None, None, None, None);
    let rows = reader
        .query_events(&query, MANIFEST_REPLAY_LIMIT, None)
        .await
        .map_err(|e| ApiError::Internal(format!("audit query: {e}")))?;

    Ok(compute_manifest_impact_from_content(
        engine.as_ref(),
        tenant,
        active_content,
        candidate_content,
        &rows,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use uuid::Uuid;

    /// The live policy under test: a baseline permit, narrowed by a high-risk
    /// forbid and an api_key+pii forbid — the two classification dimensions a
    /// manifest edit can move a decision across.
    const POLICY: &str = "@id(\"baseline\")\n\
         permit(principal, action, resource);\n\
         @id(\"forbid-high\")\n\
         forbid(principal, action == Action::\"CallTool\", resource)\n\
         when { resource.risk == \"high\" };\n\
         @id(\"forbid-pii-apikey\")\n\
         forbid(principal, action == Action::\"CallTool\", resource)\n\
         when { resource.pii && principal.auth_method == \"api_key\" };\n\
         @id(\"forbid-high-resource\")\n\
         forbid(principal, action == Action::\"ReadResource\", resource)\n\
         when { resource.risk == \"high\" };";

    /// Active manifest set: `bank` with three tools + a `gone_tool` that the
    /// candidate drops.
    const ACTIVE: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: pii_tool
      risk: low
      side_effects: false
      pii: false
    - name: risk_tool
      risk: low
    - name: steady_tool
      risk: low
    - name: gone_tool
      risk: low
";

    /// Candidate: pii_tool flips pii→true, risk_tool flips risk→high,
    /// steady_tool unchanged, gone_tool removed, new_tool added.
    const CANDIDATE: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: pii_tool
      risk: low
      side_effects: false
      pii: true
    - name: risk_tool
      risk: high
    - name: steady_tool
      risk: low
    - name: new_tool
      risk: low
";

    fn engine() -> CedarEngine {
        CedarEngine::from_source(POLICY).expect("test policy parses")
    }

    /// A fully-populated, replayable tool-call row for `bank.<tool>`.
    fn tool_row(tool: &str, auth_method: &str) -> AuditRow {
        AuditRow {
            operation: None,
            id: Uuid::now_v7(),
            ts: time::OffsetDateTime::UNIX_EPOCH,
            category: Some("invocation".into()),
            tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
            action: "CallTool".into(),
            outcome: "success".into(),
            principal_sub: Some("alice@example.com".into()),
            principal_email: Some("alice@example.com".into()),
            principal_groups: vec!["mcp-users".into()],
            issuer: Some("https://auth.example.com".into()),
            server: Some("bank".into()),
            tool: Some(tool.into()),
            // The recorded classification — DELIBERATELY divergent from the
            // active manifest in places, to prove the baseline comes from the
            // active manifest, not this captured value.
            risk_level: Some("low".into()),
            pii: Some(false),
            policy_ids: vec!["baseline".into()],
            reason: None,
            trace_id: None,
            latency_ms: Some(12),
            scim_active: None,
            scim_groups: Vec::new(),
            target: None,
            req_scopes: vec!["mcp:invoke".into()],
            auth_method: Some(auth_method.into()),
            req_roles: vec![],
            side_effects: Some(false),
            invocation_hierarchy: None,
        }
    }

    fn resource_row(uri: &str, auth_method: &str) -> AuditRow {
        let mut row = tool_row("resources/read", auth_method);
        row.action = "ReadResource".into();
        row.tool = None;
        row.target = Some(uri.to_owned());
        row
    }

    #[test]
    fn resource_risk_change_replays_native_read_and_samples_exact_uri() {
        const ACTIVE_RESOURCES: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  resources:
    - uri_prefix: bank://statements/
      risk: low
";
        const CANDIDATE_RESOURCES: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  resources:
    - uri_prefix: bank://statements/
      risk: high
";
        let diff = diff_classifications(ACTIVE_RESOURCES, CANDIDATE_RESOURCES).unwrap();
        let rows = vec![resource_row("bank://statements/2026-08", "oauth")];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);

        assert_eq!(report.tools_changed, 0);
        assert_eq!(report.resources_changed, 1);
        assert_eq!(report.affected, 1);
        assert_eq!(report.replayed, 1);
        assert_eq!(report.changed, 1);
        assert_eq!(report.deltas[0].from, "allow");
        assert_eq!(report.deltas[0].to, "deny");
        assert_eq!(
            report.samples[0].server_tool,
            "bank.resources/read (bank://statements/2026-08)"
        );
        assert_eq!(report.prospective_access.resource_targets.len(), 1);
        let target = &report.prospective_access.resource_targets[0];
        assert_eq!(target.uri, "bank://statements/2026-08");
        assert_eq!(target.risk, RiskTier::High);
        assert_eq!(target.deny, 1);
    }

    #[test]
    fn resource_prefix_preview_does_not_invent_a_concrete_uri() {
        const CANDIDATE_RESOURCES: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  resources:
    - uri_prefix: bank://statements/
      risk: high
";
        let diff = diff_classifications("[]", CANDIDATE_RESOURCES).unwrap();
        let report = compute_manifest_impact(
            &engine(),
            &TenantId::default_id(),
            &diff,
            &[tool_row("unrelated", "oauth")],
        );

        assert_eq!(report.resources_added, 1);
        assert!(report.prospective_access.resource_targets.is_empty());
        assert_eq!(
            report.prospective_access.applicability,
            ManifestProspectiveApplicability::NoConcreteResourceHistory
        );
    }

    #[test]
    fn resource_owner_move_reuses_exact_uri_under_candidate_owner() {
        const ACTIVE_RESOURCES: &str = "\
- name: archive
  transport: http
  url: http://archive.local
  resources:
    - uri_prefix: bank://statements/
      risk: low
";
        const CANDIDATE_RESOURCES: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  resources:
    - uri_prefix: bank://statements/
      risk: high
";
        let diff = diff_classifications(ACTIVE_RESOURCES, CANDIDATE_RESOURCES).unwrap();
        let mut row = resource_row("bank://statements/2026-08", "oauth");
        row.server = Some("archive".into());

        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &[row]);

        assert_eq!(report.prospective_access.resource_targets.len(), 1);
        let target = &report.prospective_access.resource_targets[0];
        assert_eq!(target.server, "bank");
        assert_eq!(target.uri, "bank://statements/2026-08");
        assert_eq!(target.risk, RiskTier::High);
    }

    #[test]
    fn diff_classifications_buckets_changed_added_removed() {
        let diff = diff_classifications(ACTIVE, CANDIDATE).expect("both parse");
        let changed: Vec<_> = diff.changed.keys().cloned().collect();
        assert_eq!(
            changed,
            vec![
                ("bank".to_owned(), "pii_tool".to_owned()),
                ("bank".to_owned(), "risk_tool".to_owned()),
            ],
            "only the reclassified tools are in `changed`",
        );
        // steady_tool is unchanged → absent from all three buckets.
        assert!(!diff
            .changed
            .contains_key(&("bank".to_owned(), "steady_tool".to_owned())));
        assert_eq!(diff.added, vec![("bank".to_owned(), "new_tool".to_owned())]);
        assert_eq!(
            diff.removed,
            vec![("bank".to_owned(), "gone_tool".to_owned())]
        );
        // The changed entries carry both old and new classification.
        let (old_pii, new_pii) = &diff.changed[&("bank".to_owned(), "pii_tool".to_owned())];
        assert!(!old_pii.pii && new_pii.pii);
    }

    #[test]
    fn approval_mode_relaxation_is_reported_even_without_cedar_reclassification() {
        let active = "\
- name: docs
  transport: http
  url: http://docs.local
  tools:
    - name: publish
      risk: low
";
        let candidate = active.replace("  tools:\n", "  approval_mode: policy_only\n  tools:\n");

        let diff = diff_classifications(active, &candidate).expect("valid manifests");
        assert!(diff.changed.is_empty(), "Cedar facts did not change");
        assert_eq!(diff.approval_modes_changed.len(), 1);

        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &[]);
        assert_eq!(report.approval_mode_changes.len(), 1);
        let change = &report.approval_mode_changes[0];
        assert_eq!(change.server, "docs");
        assert_eq!(change.from, "per_call");
        assert_eq!(change.to, "policy_only");
        assert_eq!(change.tools_affected, 1);
        assert!(change.relaxes_ordinary_approval);
    }

    #[test]
    fn annotation_mode_cutover_does_not_invent_runtime_claim_facts() {
        const ACTIVE_MANIFEST: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: read
      risk: low
";
        const ANNOTATION_CANDIDATE: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  classification_mode: mcp_annotations
  tools:
    - name: read
      risk: low
      approved_behavior_hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      discriminator: operation
      operations:
        - value: list
          risk: low
";
        let diff = diff_classifications(ACTIVE_MANIFEST, ANNOTATION_CANDIDATE).unwrap();
        let (active, candidate) = &diff.changed[&("bank".to_owned(), "read".to_owned())];
        assert!(!active.side_effects);
        assert!(!active.pii);
        assert!(candidate.side_effects);
        assert!(candidate.pii);

        let report = compute_manifest_impact(
            &engine(),
            &TenantId::default_id(),
            &diff,
            &[tool_row("read", "api_key")],
        );
        assert_eq!(report.affected, 1);
        assert_eq!(report.replayed, 0);
        assert_eq!(report.not_replayable, 1);
        assert_eq!(report.changed, 0);
        assert_eq!(report.prospective_access.targets_considered, 2);
        assert_eq!(report.prospective_access.evaluations, 2);
        assert_eq!(report.prospective_access.indeterminate, 2);
        assert!(report.prospective_access.targets.iter().all(|target| {
            target.applicability
                == ManifestProspectiveTargetApplicability::RuntimeAnnotationFactsUnavailable
                && target.indeterminate == 1
        }));
    }

    #[test]
    fn flip_via_pii_for_api_key_caller() {
        // An api_key caller of pii_tool: baseline (pii:false) allows, candidate
        // (pii:true) is forbidden ⇒ allow→deny.
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let rows = vec![tool_row("pii_tool", "api_key")];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        assert_eq!(report.tools_changed, 2);
        assert_eq!(report.considered, 1);
        assert_eq!(report.affected, 1);
        assert_eq!(report.replayed, 1);
        assert_eq!(report.changed, 1);
        assert_eq!(report.unchanged, 0);
        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::Replayed
        );
        assert_eq!(report.deltas.len(), 1);
        assert_eq!(report.deltas[0].from, "allow");
        assert_eq!(report.deltas[0].to, "deny");
        assert_eq!(report.samples[0].server_tool, "bank.pii_tool");
        assert_eq!(report.samples[0].recorded, "allow");
        assert_eq!(report.samples[0].candidate, "deny");
    }

    #[test]
    fn pii_flip_does_not_affect_oauth_caller() {
        // The pii forbid only fires for api_key; an oauth caller of pii_tool is
        // allowed under both classifications ⇒ replayed but unchanged.
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let rows = vec![tool_row("pii_tool", "oauth")];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        assert_eq!(report.affected, 1);
        assert_eq!(report.replayed, 1);
        assert_eq!(report.changed, 0);
        assert_eq!(report.unchanged, 1);
    }

    #[test]
    fn flip_via_risk_low_to_high() {
        // risk_tool low→high: the high-risk forbid fires under the candidate ⇒
        // allow→deny, regardless of auth method.
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let rows = vec![tool_row("risk_tool", "oauth")];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        assert_eq!(report.affected, 1);
        assert_eq!(report.changed, 1);
        assert_eq!(report.deltas[0].from, "allow");
        assert_eq!(report.deltas[0].to, "deny");
        assert_eq!(report.samples[0].server_tool, "bank.risk_tool");
    }

    #[test]
    fn unchanged_tool_is_not_affected() {
        // steady_tool's classification didn't change → out of scope: not
        // counted in `affected`/`replayed`, never evaluated.
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let rows = vec![tool_row("steady_tool", "api_key")];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        assert_eq!(report.considered, 1);
        assert_eq!(report.affected, 0, "steady_tool is not in the changed set");
        assert_eq!(report.replayed, 0);
        assert_eq!(report.changed, 0);
        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::NoMatchingHistory
        );
    }

    #[test]
    fn baseline_comes_from_active_manifest_not_recorded_value() {
        // The row RECORDS risk_level=high, but the ACTIVE manifest classifies
        // risk_tool as low and the candidate also leaves it low. If the baseline
        // used the recorded value the row would look unchanged for the wrong
        // reason; here we prove scope/baseline derive from the manifest diff:
        // with active==candidate for risk_tool, it is simply NOT in the changed
        // set, so the row is unaffected even though it recorded `high`.
        const ACTIVE_LOW: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: risk_tool
      risk: low
";
        const CANDIDATE_LOW: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: risk_tool
      risk: low
";
        let diff = diff_classifications(ACTIVE_LOW, CANDIDATE_LOW).unwrap();
        let mut row = tool_row("risk_tool", "oauth");
        row.risk_level = Some("high".into()); // recorded high, but manifest says low
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &[row]);
        assert_eq!(report.tools_changed, 0);
        assert_eq!(
            report.affected, 0,
            "scope is driven by the active/candidate diff, not the row's recorded class",
        );
    }

    #[test]
    fn added_tool_is_prospective_while_removed_tool_stays_structural() {
        // Rows for new_tool (no active baseline) and gone_tool (no candidate)
        // are not in `changed`, so they never count as historical replay.
        // The added tool is still prospectively evaluated for the caller.
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let rows = vec![
            tool_row("new_tool", "oauth"),
            tool_row("gone_tool", "oauth"),
        ];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        assert_eq!(report.tools_added, 1);
        assert_eq!(report.tools_removed, 1);
        assert_eq!(report.affected, 0);
        assert_eq!(report.replayed, 0);
        assert_eq!(report.changed, 0);
        assert_eq!(
            report.prospective_access.applicability,
            ManifestProspectiveApplicability::Evaluated
        );
        assert_eq!(report.prospective_access.targets_considered, 3);
        assert_eq!(report.prospective_access.caller_contexts_considered, 1);
    }

    #[test]
    fn added_tool_gets_prospective_access_without_historical_baseline() {
        const ADDED_PII: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: sensitive_search
      risk: low
      pii: true
";
        let diff = diff_classifications("[]", ADDED_PII).unwrap();
        let rows = vec![
            tool_row("some_old_tool", "oauth"),
            tool_row("some_old_tool", "api_key"),
        ];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);

        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::NoReclassifiedTools
        );
        assert_eq!(
            report.prospective_access.applicability,
            ManifestProspectiveApplicability::Evaluated
        );
        assert_eq!(report.prospective_access.caller_contexts_considered, 2);
        assert_eq!(report.prospective_access.evaluations, 2);
        assert_eq!(report.prospective_access.allow, 1);
        assert_eq!(report.prospective_access.deny, 1);
    }

    #[test]
    fn reclassified_tool_gets_prospective_access_without_matching_call_history() {
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let report = compute_manifest_impact(
            &engine(),
            &TenantId::default_id(),
            &diff,
            &[tool_row("steady_tool", "oauth")],
        );

        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::NoMatchingHistory
        );
        let risk_tool = report
            .prospective_access
            .targets
            .iter()
            .find(|target| target.tool == "risk_tool" && target.operation.is_none())
            .expect("reclassified tool is sampled");
        assert_eq!(risk_tool.deny, 1);
    }

    #[test]
    fn operation_only_change_uses_operation_facts_in_replay_and_prospective_sample() {
        const OPERATION_POLICY: &str = "@id(\"baseline\")\n\
             permit(principal, action, resource);\n\
             @id(\"forbid-sensitive-read\")\n\
             forbid(principal, action == Action::\"CallTool\", resource)\n\
             when { resource has operation && resource.operation == \"read\" && resource.pii };";
        const ACTIVE_OPERATION: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: executor
      risk: low
      pii: true
      discriminator: operation
      operations:
        - value: read
          risk: low
          pii: false
";
        const CANDIDATE_OPERATION: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: executor
      risk: low
      pii: true
      discriminator: operation
      operations:
        - value: read
          risk: low
          pii: true
";
        let engine = CedarEngine::from_source(OPERATION_POLICY).expect("test policy parses");
        let diff = diff_classifications(ACTIVE_OPERATION, CANDIDATE_OPERATION).unwrap();
        let mut row = tool_row("executor", "oauth");
        row.operation = Some("read".to_owned());

        let report = compute_manifest_impact(&engine, &TenantId::default_id(), &diff, &[row]);

        assert_eq!(report.tools_changed, 1);
        assert_eq!(
            report.changed, 1,
            "operation-only reclassification flips replay"
        );
        assert_eq!(report.deltas[0].from, "allow");
        assert_eq!(report.deltas[0].to, "deny");
        assert_eq!(report.prospective_access.targets_considered, 2);
        let fallback = report
            .prospective_access
            .targets
            .iter()
            .find(|target| target.operation.is_none())
            .expect("tool-level fallback is sampled");
        assert_eq!(
            fallback.applicability,
            ManifestProspectiveTargetApplicability::UndeclaredOperationValueUnbounded
        );
        assert_eq!(
            fallback.indeterminate, 1,
            "undeclared operation strings can change Cedar's fallback verdict"
        );
        let read = report
            .prospective_access
            .targets
            .iter()
            .find(|target| target.operation.as_deref() == Some("read"))
            .expect("declared operation is sampled");
        assert_eq!(read.deny, 1, "operation target carries its value and facts");
    }

    #[test]
    fn discriminator_change_is_not_presented_as_faithful_historical_replay() {
        const ACTIVE_DISCRIMINATOR: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: executor
      risk: low
      discriminator: operation
      operations:
        - value: read
          risk: low
";
        const CANDIDATE_DISCRIMINATOR: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: executor
      risk: low
      discriminator: action
      operations:
        - value: read
          risk: low
";
        let diff = diff_classifications(ACTIVE_DISCRIMINATOR, CANDIDATE_DISCRIMINATOR).unwrap();
        let mut row = tool_row("executor", "oauth");
        row.operation = Some("read".to_owned());

        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &[row]);

        assert_eq!(report.affected, 1);
        assert_eq!(report.replayed, 0);
        assert_eq!(report.not_replayable, 1);
        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::NoReplayableHistory
        );
    }

    #[test]
    fn null_operation_is_not_replayed_for_an_operation_aware_tool() {
        const ACTIVE_OPERATION: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: executor
      risk: low
      discriminator: operation
      operations:
        - value: read
          risk: low
";
        const CANDIDATE_OPERATION: &str = "\
- name: bank
  transport: http
  url: http://bank.local
  tools:
    - name: executor
      risk: high
      discriminator: operation
      operations:
        - value: read
          risk: high
";
        let diff = diff_classifications(ACTIVE_OPERATION, CANDIDATE_OPERATION).unwrap();
        let row = tool_row("executor", "oauth");

        let report = compute_manifest_impact(
            &engine(),
            &TenantId::default_id(),
            &diff,
            std::slice::from_ref(&row),
        );

        assert_eq!(report.affected, 1);
        assert_eq!(report.replayed, 0);
        assert_eq!(report.not_replayable, 1);
        assert_eq!(report.changed, 0);
    }

    #[test]
    fn prospective_evaluation_errors_are_indeterminate_not_access_verdicts() {
        let broken_at_runtime = CedarEngine::from_source(
            r#"forbid(principal, action == Action::"CallTool", resource)
               when { principal.no_such_attr == "x" };"#,
        )
        .expect("policy parses; the missing attribute errors only at evaluation");
        let diff = diff_classifications("[]", CANDIDATE).unwrap();
        let report = compute_manifest_impact(
            &broken_at_runtime,
            &TenantId::default_id(),
            &diff,
            &[tool_row("old_tool", "oauth")],
        );

        assert_eq!(report.prospective_access.evaluations, 4);
        assert_eq!(report.prospective_access.indeterminate, 4);
        assert_eq!(report.prospective_access.allow, 0);
        assert_eq!(report.prospective_access.deny, 0);
    }

    #[test]
    fn prospective_sample_deduplicates_and_bounds_both_axes() {
        let mut candidate =
            String::from("- name: bank\n  transport: http\n  url: http://bank.local\n  tools:\n");
        for index in 0..(PROSPECTIVE_TARGET_LIMIT + 2) {
            candidate.push_str(&format!("    - name: tool_{index}\n      risk: low\n"));
        }
        let diff = diff_classifications("[]", &candidate).unwrap();
        let mut rows = Vec::new();
        for index in 0..(PROSPECTIVE_CONTEXT_LIMIT + 2) {
            let mut row = tool_row("old_tool", "oauth");
            row.principal_sub = Some(format!("caller-{index}"));
            rows.push(row);
        }
        // Equivalent to caller-0 after set normalization; it must not consume
        // an additional slot or increment the omitted count.
        let mut duplicate = rows[0].clone();
        duplicate.principal_groups = vec!["mcp-users".into(), "mcp-users".into()];
        rows.push(duplicate);

        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        let sample = report.prospective_access;
        assert_eq!(sample.caller_contexts_considered, PROSPECTIVE_CONTEXT_LIMIT);
        assert_eq!(sample.caller_contexts_omitted, 2);
        assert_eq!(sample.targets_considered, PROSPECTIVE_TARGET_LIMIT);
        assert_eq!(sample.targets_omitted, 2);
        assert_eq!(
            sample.evaluations,
            PROSPECTIVE_CONTEXT_LIMIT * PROSPECTIVE_TARGET_LIMIT
        );
    }

    #[test]
    fn affected_unreplayable_rows_count_not_replayable() {
        // A legacy row (no auth_method) and a SCIM-enriched row, both calling a
        // CHANGED tool: in scope (affected) but not reconstructable ⇒
        // not_replayable, never evaluated.
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let mut legacy = tool_row("risk_tool", "oauth");
        legacy.auth_method = None;
        let mut scim = tool_row("pii_tool", "api_key");
        scim.scim_active = Some(true);
        let rows = vec![legacy, scim];
        let report = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        assert_eq!(report.affected, 2);
        assert_eq!(report.replayed, 0);
        assert_eq!(report.not_replayable, 2);
        assert_eq!(report.changed, 0);
        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::NoReplayableHistory
        );
    }

    #[test]
    fn unparseable_candidate_is_an_error_report() {
        let rows = vec![tool_row("pii_tool", "api_key")];
        let report = compute_manifest_impact_from_content(
            &engine(),
            &TenantId::default_id(),
            ACTIVE,
            "this is not valid manifest yaml {{{",
            &rows,
        );
        assert!(
            report.error.is_some(),
            "a broken draft must surface as error"
        );
        assert_eq!(report.considered, 1);
        assert_eq!(report.affected, 0);
        assert_eq!(report.replayed, 0);
        assert_eq!(report.changed, 0);
        assert_eq!(report.tools_changed, 0);
        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::Unavailable
        );
    }

    #[test]
    fn added_tools_are_explicitly_outside_comparative_replay() {
        let report = compute_manifest_impact_from_content(
            &engine(),
            &TenantId::default_id(),
            "[]",
            CANDIDATE,
            &[],
        );
        assert_eq!(report.tools_added, 4);
        assert_eq!(report.tools_changed, 0);
        assert_eq!(
            report.replay_applicability,
            ManifestReplayApplicability::NoReclassifiedTools
        );
        assert_eq!(
            report.prospective_access.applicability,
            ManifestProspectiveApplicability::NoRecentCallerContexts
        );
    }

    #[test]
    fn from_content_matches_precomputed_diff() {
        // The convenience wrapper agrees with diff-then-compute.
        let rows = vec![
            tool_row("pii_tool", "api_key"),
            tool_row("risk_tool", "oauth"),
        ];
        let via_content = compute_manifest_impact_from_content(
            &engine(),
            &TenantId::default_id(),
            ACTIVE,
            CANDIDATE,
            &rows,
        );
        let diff = diff_classifications(ACTIVE, CANDIDATE).unwrap();
        let via_diff = compute_manifest_impact(&engine(), &TenantId::default_id(), &diff, &rows);
        assert_eq!(via_content.changed, via_diff.changed);
        assert_eq!(via_content.affected, 2);
        assert_eq!(via_content.changed, 2, "both api_key-pii and risk flips");
    }

    // --- active_manifest_content: the on-disk (file-as-truth) baseline source ---

    /// An `AdminState` with no stores wired and an optional `servers_dir`, for
    /// exercising the on-disk baseline read in isolation (no cedar/audit needed).
    async fn state_with_servers_dir(dir: Option<std::path::PathBuf>) -> AdminState {
        let pool = Arc::new(
            waygate_upstream::pool::UpstreamPool::connect(std::collections::BTreeMap::new()).await,
        );
        let evidence: waygate_mcp::audit::SharedEvidence =
            Arc::new(waygate_mcp::audit::InMemorySink::default());
        let state = AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        );
        match dir {
            Some(d) => state.with_servers_dir(d),
            None => state,
        }
    }

    /// Write a manifest-set YAML to a fresh unique tmpdir (one file per manifest,
    /// the canonical on-disk layout the gateway loads). The caller removes it.
    fn write_servers_dir(content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mitest-servers-{}", Uuid::new_v4()));
        let set = waygate_upstream::parse_manifest_set(content).unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &set).unwrap();
        dir
    }

    #[tokio::test]
    async fn baseline_reads_from_on_disk_servers_dir_not_the_ledger() {
        // With NO manifest_store wired, the baseline still resolves — from
        // the on-disk servers_dir — and drives the diff. Proves the active
        // set comes from disk (what the gateway enforces), not the ledger.
        let dir = write_servers_dir(ACTIVE);
        let state = state_with_servers_dir(Some(dir.clone())).await;

        let active = active_manifest_content(&state).expect("disk read succeeds");
        // The on-disk content diffs against the candidate exactly like ACTIVE.
        let diff = diff_classifications(&active, CANDIDATE).unwrap();
        let changed: Vec<_> = diff.changed.keys().cloned().collect();
        assert_eq!(
            changed,
            vec![
                ("bank".to_owned(), "pii_tool".to_owned()),
                ("bank".to_owned(), "risk_tool".to_owned()),
            ],
        );
        assert_eq!(diff.added, vec![("bank".to_owned(), "new_tool".to_owned())]);
        assert_eq!(
            diff.removed,
            vec![("bank".to_owned(), "gone_tool".to_owned())]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn baseline_empty_when_no_servers_dir() {
        // tests/dev with no on-disk set: empty active baseline (every candidate
        // tool reads as added), never an error.
        let state = state_with_servers_dir(None).await;
        let active =
            active_manifest_content(&state).expect("no servers_dir → empty baseline, not error");
        let diff = diff_classifications(&active, CANDIDATE).unwrap();
        assert!(diff.changed.is_empty());
        assert!(diff.removed.is_empty());
        // All four candidate tools are "added" against an empty baseline.
        assert_eq!(diff.added.len(), 4);
    }

    #[tokio::test]
    async fn baseline_fails_loud_on_unreadable_servers_dir() {
        // A wired-but-missing servers_dir must be a HARD error, NOT a silent
        // empty baseline — an empty baseline would report "no affected decisions"
        // for a real classification change.
        let missing = std::env::temp_dir().join(format!("mitest-missing-{}", Uuid::new_v4()));
        // Deliberately do NOT create it.
        let state = state_with_servers_dir(Some(missing)).await;
        assert!(
            active_manifest_content(&state).is_err(),
            "an unreadable wired servers_dir must fail loud, not produce an empty baseline",
        );
    }
}
