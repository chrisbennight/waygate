//! `/api/v1/policies` — Cedar policy inspection + simulation.
//!
//! `GET /policies` returns the loaded policy set so the dashboard can render
//! it (and so operators can confirm the file-on-disk matches what the engine
//! actually parsed).
//!
//! `POST /policies/simulate` runs a hypothetical authorization request
//! through the live engine without touching the request path — useful for
//! answering "why was I denied?" questions and for policy-author testing.
//! It's gated by `mcp:observe` (the read-only observability scope; `mcp:admin`
//! satisfies it too): the decision + policy-id/reason trace is read-grade
//! diagnostic data — the same tier as the MCP
//! `gateway-observe.simulate_authorization` tool — and the simulation is
//! tenant-scoped to the caller. `GET /policies` (the full policy dump) stays
//! `mcp:admin`.

use std::sync::Arc;

use axum::extract::State;
use axum::middleware;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use waygate_authz::{
    Action as AuthzAction, AuthzEngine, AuthzResult, Decision, PolicySnapshot, ResourceSpec,
    SkillSpec, ToolSpec,
};
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;

use crate::error::{ApiErrorBody, ApiResult};
use crate::scope::{require_admin, require_observe};
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    // `GET /policies` (the full policy dump) stays operator-only. The simulator
    // is the read-only "would X be allowed?" diagnostic — the same tier as the
    // MCP `gateway-observe.simulate_authorization` tool — so it's gated on
    // `mcp:observe` (with `mcp:admin` satisfying it). Design decision: the
    // decision + policy-id/reason trace is read-grade, and the simulation is
    // tenant-scoped to the caller (see `simulate`). Two layered sub-routers
    // because the two paths now carry different scope gates.
    let policies = Router::new()
        .route("/api/v1/policies", get(list_policies))
        .layer(middleware::from_fn(require_admin));
    let sim = Router::new()
        .route("/api/v1/policies/simulate", post(simulate))
        .layer(middleware::from_fn(require_observe));
    policies.merge(sim).with_state(state)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PoliciesResponse {
    pub policies: Vec<PolicySnapshot>,
}

#[utoipa::path(
    get,
    path = "/api/v1/policies",
    tag = "policies",
    responses(
        (status = 200, description = "Loaded Cedar policies (empty when no engine is configured)", body = PoliciesResponse),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_policies(
    State(state): State<Arc<AdminState>>,
    Extension(caller): Extension<Principal>,
) -> ApiResult<Json<PoliciesResponse>> {
    let policies = match state.policy.cedar.get() {
        Some(engine) => engine.list_policies_for_tenant(caller.tenant.as_str()),
        None => Vec::new(),
    };
    Ok(Json(PoliciesResponse { policies }))
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulateRequest {
    pub principal: SimulatePrincipal,
    pub action: SimulateAction,
    pub resource: SimulateResource,
    /// Simulated runtime context. Defaults to a direct-channel call with no
    /// approval grant — the shape every pre-existing simulation evaluated.
    #[serde(default)]
    pub context: SimulateContext,
}

/// Runtime-context inputs for the simulator, mirroring the request context
/// the live gate stamps on every `CallTool` evaluation: the originating
/// channel and whether a live per-call approval grant covers the call. Lets
/// operators and policy tests exercise approval overlays such as
/// `35-codemode-approval.cedar` before shipping them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SimulateContext {
    #[serde(default)]
    pub channel: SimulateChannel,
    /// Treat a live approval grant as present. The engine's own approval
    /// inference already reports `approval_required` when a grant would
    /// flip a deny, so this is only needed to pin the granted-state allow.
    #[serde(default)]
    pub approval_present: bool,
}

/// Wire vocabulary matches Cedar's `context.channel` strings exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum SimulateChannel {
    #[default]
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "codemode")]
    CodeMode,
}

impl SimulateChannel {
    fn as_fact(self) -> waygate_core::InvocationChannelFact {
        match self {
            SimulateChannel::Direct => waygate_core::InvocationChannelFact::Direct,
            SimulateChannel::CodeMode => waygate_core::InvocationChannelFact::CodeMode,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulatePrincipal {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Simulated principal's auth method — `"oauth"` (default) or
    /// `"api_key"`. Lets the simulator exercise policies that branch
    /// on `principal.auth_method`, like the default PII forbid in
    /// `crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar`.
    #[serde(default)]
    pub auth_method: SimulateAuthMethod,
    /// Optional SCIM-attribute inputs so the simulator can
    /// exercise the SCIM default policies
    /// (`crates/waygate-authz/tests/fixtures/policies/16-scim-active.cedar`) and
    /// any tenant-side policy that references
    /// `principal.scim_*`. `None` ⇒ simulated principal carries
    /// `scim: None`; supplying the block flags the principal as
    /// SCIM-enriched.
    #[serde(default)]
    pub scim: Option<SimulateScim>,
    /// RBAC role names so the simulator can exercise policies
    /// that gate on `principal.roles.contains("tenant_admin")`.
    /// In production these come from the chained RBAC enricher
    /// (which unions direct assignments + SCIM group→role
    /// mappings); the simulator takes the resolved set directly
    /// so operators can validate role-gated policies before
    /// granting an actual assignment. Empty default keeps
    /// non-RBAC simulations unaffected.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// SCIM inputs for the policy simulator. Mirrors the subset of
/// `waygate_oidc::ScimPrincipalAttrs` policies actually gate on
/// (active flag + group display names); `external_id` /
/// `user_name` / raw `attrs` are left out to keep the form
/// surface narrow.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulateScim {
    pub active: bool,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SimulateAuthMethod {
    #[default]
    Oauth,
    ApiKey,
    /// Federated peer assertion (Tier-C). Mirrors
    /// [`waygate_oidc::AuthMethod::PeerAssertion`] so the simulator's decision
    /// replay can reconstruct a peer-asserted decision faithfully (a policy may
    /// gate on `principal.auth_method == "peer_assertion"`), rather than
    /// coercing it to `oauth` and replaying the wrong verdict.
    PeerAssertion,
}

impl From<SimulateAuthMethod> for waygate_oidc::AuthMethod {
    fn from(v: SimulateAuthMethod) -> Self {
        match v {
            SimulateAuthMethod::Oauth => waygate_oidc::AuthMethod::Oauth,
            SimulateAuthMethod::ApiKey => waygate_oidc::AuthMethod::ApiKey,
            SimulateAuthMethod::PeerAssertion => waygate_oidc::AuthMethod::PeerAssertion,
        }
    }
}

fn default_issuer() -> String {
    "simulation".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SimulateAction {
    ListTools,
    SearchTools,
    CallTool {
        name: String,
        #[serde(default = "default_risk")]
        risk: RiskTier,
    },
    ReadResource {
        uri: String,
    },
    ListSkills,
    FetchSkillResource {
        uri: String,
    },
    ReadSkill {
        uri: String,
    },
    AdminManagePolicies,
    AdminManageServers,
    AdminViewTelemetry,
    /// EMA cross-app grant (ID-JAG mint). Acts on a `Server` resource;
    /// `crates/waygate-authz/tests/fixtures/policies/40-cross-app-access.cedar` gates it on SCIM membership.
    GrantCrossAppAccess,
}

fn default_risk() -> RiskTier {
    RiskTier::Low
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SimulateResource {
    Server {
        name: String,
    },
    Tool {
        server: String,
        name: String,
        #[serde(default = "default_risk")]
        risk: RiskTier,
        #[serde(default)]
        side_effects: bool,
        /// Whether the tool surfaces PII. Propagates to the Cedar `Tool`
        /// entity's `pii` attribute so the simulator can exercise the
        /// runtime PII-aware default policies. Defaults to `false` so
        /// existing API requests without the field keep working.
        #[serde(default)]
        pii: bool,
        /// The operation the call selected, for a tool carrying many behind one
        /// name. Defaults to absent so an existing request simulates exactly as
        /// it did, and decision replay sets it from the audited row so a policy
        /// branching on `resource.operation` is not reported as a change.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation: Option<String>,
    },
    McpResource {
        server: String,
        uri: String,
        #[serde(default = "default_risk")]
        risk: RiskTier,
    },
    Skill {
        source_origin: String,
        artifact_digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_tree_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        skill_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revision_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_object: Option<String>,
    },
}

/// One fired policy in a simulation trace, joined to its layer/description
/// metadata so the UI (and any API client) can explain *why* a decision was
/// reached, not just *which* opaque ids matched.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, schemars::JsonSchema)]
pub struct SimTraceEntry {
    /// Stable policy id (the `@id` annotation).
    pub policy_id: String,
    /// Human display name of the policy's `@layer` (e.g. "Step-up overlay").
    pub layer: String,
    /// `permit` or `forbid`.
    pub effect: String,
    /// The policy's `@description`, or empty.
    pub description: String,
    /// The policy's `@reason`, or empty.
    pub reason: String,
    /// True for the single policy that decided the outcome — the winning forbid
    /// overlay on a deny, the most-specific permit on an allow.
    pub determinative: bool,
}

#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
pub struct SimulateResponse {
    /// `allow`, `deny`, or `step_up`.
    pub decision: String,
    pub reasons: Vec<String>,
    pub policy_ids: Vec<String>,
    /// The single policy that decided the outcome (deep-link target for the
    /// dashboard). `None` for a default deny — nothing matched, the floor
    /// denied it.
    #[serde(default)]
    pub determinative_policy_id: Option<String>,
    /// When `decision == "step_up"`, the scope the caller must re-authorize
    /// with before the action would be allowed. `None` otherwise.
    #[serde(default)]
    pub required_scope: Option<String>,
    /// The fired policies, joined to layer/description/reason metadata and
    /// ordered by evaluation layer — the structured "why" of the decision.
    #[serde(default)]
    pub trace: Vec<SimTraceEntry>,
}

#[utoipa::path(
    post,
    path = "/api/v1/policies/simulate",
    tag = "policies",
    request_body = SimulateRequest,
    responses(
        (status = 200, description = "Decision with diagnostic reasons + matched policy IDs", body = SimulateResponse),
        (status = 503, description = "No Cedar engine configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:observe", body = ApiErrorBody),
    ),
)]
async fn simulate(
    State(state): State<Arc<AdminState>>,
    Extension(caller): Extension<Principal>,
    Json(req): Json<SimulateRequest>,
) -> ApiResult<Json<SimulateResponse>> {
    let engine = state.policy.cedar.require()?;

    // Tenant-scope the simulation to the caller. The shared converter stamps
    // `TenantId::default()` (it predates a per-tenant simulate caller), but a
    // non-default tenant must evaluate against its OWN tenant policies — Cedar
    // can branch on `principal.tenant`, so a default-tenant stamp would return
    // the wrong allow/deny/step-up for any other tenant.
    let facts = simulate_request_to_facts(req, caller.tenant.clone());
    let required_scope = facts.action.required_scope.clone();
    // Pin ONE engine snapshot for both the decision and the trace metadata: a
    // SIGHUP reload between `evaluate` and `list_policies` would otherwise join
    // the fired policy_ids to a *different* policy set. The CedarEngine trait
    // impl is still fail-closed (→ Deny with diagnostics).
    let snap = engine.snapshot_for_tenant(caller.tenant.as_str());
    let result: AuthzResult = AuthzEngine::evaluate_facts(snap.as_ref(), &facts);
    Ok(Json(authz_result_to_response(
        result,
        &snap.list_policies(),
        required_scope,
    )))
}

/// [`simulate_request_to_inputs`] plus everything the tuple form cannot
/// carry: the tenant stamp and the simulated runtime context (channel /
/// approval presence), returned as the engine-ready [`Facts`](waygate_core::Facts)
/// every admin evaluation surface — the live simulator, attached policy
/// tests, bundle preview, and decision-impact replay — evaluates over. One
/// builder keeps those surfaces faithful to the live gate's fact model.
pub fn simulate_request_to_facts(
    req: SimulateRequest,
    tenant: waygate_core::TenantId,
) -> waygate_core::Facts {
    let context = req.context.clone();
    let (mut principal, action, resource) = simulate_request_to_inputs(req);
    principal.tenant = tenant;
    let mut facts = waygate_authz::simulation_facts(&principal, &action, &resource);
    facts.context.channel = context.channel.as_fact();
    facts.context.approval_present = context.approval_present;
    facts
}

/// Reusable mapping from `SimulateRequest` (the wire shape) to the
/// `(Principal, Action, ResourceSpec)` triple every Cedar evaluator
/// expects. Extracted so `/api/v1/policy_bundles/preview_simulate`
/// can evaluate a candidate bundle against the same shape without
/// duplicating the ~80 lines of field plumbing.
///
/// Synthesised principal carries `tenant = TenantId::default()` and
/// `raw_token = None` exactly like the live simulator — preview eval
/// runs in the same fake-identity envelope.
pub fn simulate_request_to_inputs(req: SimulateRequest) -> (Principal, AuthzAction, ResourceSpec) {
    let principal = Principal {
        sub: req.principal.sub,
        email: req.principal.email,
        groups: req.principal.groups,
        issuer: req.principal.issuer,
        scopes: req.principal.scopes,
        tenant: waygate_core::TenantId::default(),
        auth_method: req.principal.auth_method.into(),
        raw_token: None,
        // Lift simulator SCIM input into the synthesised
        // principal so the simulator exercises
        // `principal.scim_*` policies the same way a real
        // enriched principal would.
        scim: req
            .principal
            .scim
            .map(|s| waygate_oidc::ScimPrincipalAttrs {
                user_id: "simulation".into(),
                user_name: "simulation".into(),
                external_id: None,
                active: s.active,
                attrs: serde_json::Value::Null,
                groups: s
                    .groups
                    .into_iter()
                    .map(|g| waygate_oidc::ScimGroupRef {
                        id: "simulation".into(),
                        display_name: g,
                    })
                    .collect(),
            }),
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
        // Lift simulator role input into the synthesised
        // principal so the simulator exercises
        // `principal.roles` policies the same way a real
        // RBAC-enriched principal would. Empty default keeps
        // non-RBAC simulations unaffected.
        roles: req.principal.roles,
    };
    let action = match req.action {
        SimulateAction::ListTools => AuthzAction::ListTools,
        SimulateAction::SearchTools => AuthzAction::SearchTools,
        SimulateAction::CallTool { name, risk } => AuthzAction::CallTool { name, risk },
        SimulateAction::ReadResource { uri } => AuthzAction::ReadResource { uri },
        SimulateAction::ListSkills => AuthzAction::ListSkills,
        SimulateAction::FetchSkillResource { uri } => AuthzAction::FetchSkillResource { uri },
        SimulateAction::ReadSkill { uri } => AuthzAction::ReadSkill { uri },
        SimulateAction::AdminManagePolicies => AuthzAction::AdminManagePolicies,
        SimulateAction::AdminManageServers => AuthzAction::AdminManageServers,
        SimulateAction::AdminViewTelemetry => AuthzAction::AdminViewTelemetry,
        SimulateAction::GrantCrossAppAccess => AuthzAction::GrantCrossAppAccess,
    };
    let resource = match req.resource {
        SimulateResource::Server { name } => ResourceSpec::Server { name },
        SimulateResource::Tool {
            server,
            name,
            risk,
            side_effects,
            pii,
            operation,
        } => ResourceSpec::Tool(ToolSpec {
            server,
            name,
            risk,
            side_effects,
            pii,
            operation,
        }),
        SimulateResource::McpResource { server, uri, risk } => {
            ResourceSpec::McpResource { server, uri, risk }
        }
        SimulateResource::Skill {
            source_origin,
            artifact_digest,
            source_tree_digest,
            skill_uri,
            resource_uri,
            revision_digest,
            content_digest,
            source_path,
            source_object,
        } => ResourceSpec::Skill(SkillSpec {
            source_origin,
            artifact_digest,
            source_tree_digest,
            skill_uri,
            resource_uri,
            revision_digest,
            content_digest,
            source_path,
            source_object,
        }),
    };
    (principal, action, resource)
}

/// Reusable mapping from the typed `AuthzResult` (plus the engine's policy
/// snapshots and the action's step-up scope) to the wire-shape
/// `SimulateResponse`. Shared by the live simulator and the candidate-bundle
/// preview so both surface the same structured trace.
///
/// `snapshots` should come from the SAME engine that produced `result` (the
/// live `ReloadableCedar` for the simulator, the candidate `CedarEngine` for
/// preview) so the trace's layer/description metadata matches the fired ids.
/// `required_scope` is the action's step-up scope, surfaced only on a step-up
/// decision.
pub fn authz_result_to_response(
    result: AuthzResult,
    snapshots: &[PolicySnapshot],
    required_scope: Option<String>,
) -> SimulateResponse {
    let (trace, determinative_policy_id) = build_trace(&result, snapshots);
    SimulateResponse {
        decision: match result.decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::StepUpRequired => "step_up",
            Decision::ApprovalRequired => "approval_required",
        }
        .to_owned(),
        reasons: result.reasons,
        policy_ids: result.policy_ids,
        determinative_policy_id,
        required_scope: match result.decision {
            Decision::StepUpRequired => required_scope,
            _ => None,
        },
        trace,
    }
}

/// Join the fired `policy_ids` to their layer/description/reason metadata,
/// order them by evaluation layer, and pick the determinative policy. Returns
/// `(trace, determinative_policy_id)`. A default deny (no policy fired) yields
/// an empty trace and `None` — the floor denied it.
pub fn build_trace(
    result: &AuthzResult,
    snapshots: &[PolicySnapshot],
) -> (Vec<SimTraceEntry>, Option<String>) {
    let by_id: std::collections::HashMap<&str, &PolicySnapshot> =
        snapshots.iter().map(|s| (s.id.as_str(), s)).collect();

    let mut ordered: Vec<(u32, SimTraceEntry)> = result
        .policy_ids
        .iter()
        .map(|id| {
            let snap = by_id.get(id.as_str()).copied();
            let layer_id = snap.and_then(|s| s.layer.as_deref()).unwrap_or("ungrouped");
            let (order, title, _) = crate::dashboard::layer_meta(layer_id);
            let entry = SimTraceEntry {
                policy_id: id.clone(),
                layer: title,
                effect: snap.map(|s| s.effect.clone()).unwrap_or_default(),
                description: snap.and_then(|s| s.description.clone()).unwrap_or_default(),
                reason: snap.and_then(|s| s.reason.clone()).unwrap_or_default(),
                determinative: false,
            };
            (order, entry)
        })
        .collect();

    // Stable, evaluation-shaped order: by layer, then policy id.
    ordered.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.policy_id.cmp(&b.1.policy_id))
    });

    // The highest-layer fired policy decides: a forbid overlay wins a deny, the
    // most-specific permit anchors an allow. None when nothing fired.
    let determinative_policy_id = ordered.last().map(|(_, e)| e.policy_id.clone());
    if let Some((_, last)) = ordered.last_mut() {
        last.determinative = true;
    }

    let trace = ordered.into_iter().map(|(_, e)| e).collect();
    (trace, determinative_policy_id)
}

/// The step-up scope simulated inputs would require, mirroring the runtime
/// risk→scope mapping. The authorization bridge derives effective risk from
/// the resource entity for every data-plane action, so this projection must do
/// the same rather than trusting a duplicate action field.
pub fn required_scope_for_simulation(
    action: &AuthzAction,
    resource: &ResourceSpec,
) -> Option<String> {
    let risk = match action {
        AuthzAction::CallTool { .. }
        | AuthzAction::ReadResource { .. }
        | AuthzAction::FetchSkillResource { .. }
        | AuthzAction::ReadSkill { .. } => match resource {
            ResourceSpec::Server { .. } => RiskTier::Low,
            ResourceSpec::Tool(tool) => tool.risk,
            ResourceSpec::McpResource { risk, .. } => *risk,
            ResourceSpec::Skill(_) => RiskTier::Low,
        },
        _ => return None,
    };
    waygate_mcp::authz::required_scope_for(risk).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, effect: &str, layer: &str) -> PolicySnapshot {
        PolicySnapshot {
            id: id.into(),
            effect: effect.into(),
            layer: Some(layer.into()),
            description: Some(format!("desc {id}")),
            tags: Vec::new(),
            reason: Some(format!("reason {id}")),
            source: String::new(),
        }
    }

    fn result(decision: Decision, policy_ids: &[&str]) -> AuthzResult {
        AuthzResult {
            decision,
            reasons: Vec::new(),
            policy_ids: policy_ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn trace_orders_by_layer_and_marks_highest_layer_determinative() {
        // A deny where two forbids fired across layers: the trace must be
        // ordered by evaluation layer (pii before step-up), and the determinative
        // policy must be the highest-layer one (the step-up overlay wins).
        let snaps = vec![
            snap("step-up-x", "forbid", "step-up-overlay"),
            snap("pii-x", "forbid", "pii-overlay"),
        ];
        let r = result(Decision::Deny, &["step-up-x", "pii-x"]);
        let (trace, determinative) = build_trace(&r, &snaps);

        assert_eq!(trace.len(), 2);
        assert_eq!(
            trace[0].policy_id, "pii-x",
            "pii-overlay sorts before step-up"
        );
        assert_eq!(trace[1].policy_id, "step-up-x");
        assert_eq!(trace[0].layer, "PII overlay");
        assert_eq!(trace[1].layer, "Step-up overlay");
        assert!(!trace[0].determinative);
        assert!(
            trace[1].determinative,
            "highest-layer policy is determinative"
        );
        assert_eq!(determinative.as_deref(), Some("step-up-x"));
        // Metadata is joined from the snapshot.
        assert_eq!(trace[1].effect, "forbid");
        assert_eq!(trace[1].reason, "reason step-up-x");
        assert_eq!(trace[1].description, "desc step-up-x");
    }

    #[test]
    fn default_deny_has_empty_trace_and_no_determinative() {
        // No policy fired (Cedar's deny-by-default floor) → nothing to show.
        let (trace, determinative) = build_trace(&result(Decision::Deny, &[]), &[]);
        assert!(trace.is_empty());
        assert_eq!(determinative, None);
    }

    #[test]
    fn unknown_policy_id_still_traced_as_ungrouped() {
        // A fired id absent from the snapshots (shouldn't happen in practice)
        // degrades gracefully to the "Ungrouped" layer rather than panicking.
        let (trace, _) = build_trace(&result(Decision::Allow, &["mystery"]), &[]);
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].layer, "Ungrouped");
        assert_eq!(trace[0].policy_id, "mystery");
    }

    #[test]
    fn required_scope_only_surfaced_on_step_up() {
        let snaps = vec![snap("p", "permit", "baseline")];
        // Allow with a scope supplied → response must NOT carry required_scope.
        let resp = authz_result_to_response(
            result(Decision::Allow, &["p"]),
            &snaps,
            Some("mcp:invoke:high".into()),
        );
        assert_eq!(resp.required_scope, None);
        // Step-up with the same scope → surfaced.
        let resp = authz_result_to_response(
            result(Decision::StepUpRequired, &["p"]),
            &snaps,
            Some("mcp:invoke:high".into()),
        );
        assert_eq!(resp.required_scope.as_deref(), Some("mcp:invoke:high"));
    }

    #[test]
    fn resource_simulation_derives_step_up_scope_from_resource_risk() {
        let action = AuthzAction::ReadResource {
            uri: "bank://statements/2026-08".into(),
        };
        let resource = ResourceSpec::McpResource {
            server: "bank".into(),
            uri: "bank://statements/2026-08".into(),
            risk: RiskTier::High,
        };

        assert_eq!(
            required_scope_for_simulation(&action, &resource).as_deref(),
            Some("mcp:invoke:high"),
        );
    }
}
