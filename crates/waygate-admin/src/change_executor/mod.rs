//! The HITL control-plane action-executor registry.
//!
//! When a human approves a pending change request, the captured intent is
//! executed SERVER-SIDE here (execute-on-approval) — the maker never holds
//! a privileged token, so a compromised/injected maker has nothing to
//! misuse. Each `action_type` maps to an [`ActionExecutor`] that validates
//! its params, performs the side effect against the relevant admin store,
//! and returns a result the change request records. An executor error
//! marks the change `failed` LOUDLY (never tombstoned as done).
//!
//! Registered actions span a secret-minting tier (`api_key.mint`, its own
//! channel for the one-time plaintext) and a standard, non-secret tier —
//! `rate_limit.create` / `.update` / `.delete`, `inspection_rule.delete`, `oauth_consent.revoke`, operational upstream
//! recovery, fleet config reload, and more — each a thin adapter over the
//! same `*_core` the direct control/REST handlers call, so
//! validation, conflict mapping, and the durable audit can't drift between
//! the direct-admin and propose paths. This registry IS the propose
//! allowlist — `change_requests::validate_propose` rejects any
//! `action_type` not registered here, so a maker can only propose actions
//! that can actually execute.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use waygate_changeset::ApprovalRequirement;
use waygate_oidc::Principal;

use crate::audit_retention::{clear_retention_core, set_retention_core};
use crate::audit_routing::{clear_routing_core, set_routing_core};
use crate::break_glass::{mint_token_core, revoke_token_core, MintRequest};
use crate::catalog::{unquarantine_server_if_unchanged_core, CatalogServerUnquarantineParams};
use crate::config_reload::{reload_config_core, ConfigReloadParams};
use crate::federated_peers::{
    create_peer_core, delete_peer_core, update_peer_core, CreatePeerRequest,
};
use crate::inspection_rules::delete_rule_core;
use crate::oauth_consent::revoke_grant_core;
use crate::policy_bundles::{
    merge_policy_fragment_into_live_set, publish_bundle_core, rollback_bundle_core,
    upsert_policy_fragment_core,
};
use crate::rate_limit_policies::{
    create_policy_core, delete_policy_core, update_policy_core, CreatePolicyRequest,
};
use crate::rbac::{
    create_assignment_if_role_version_core, create_group_mapping_if_role_version_core,
    create_role_core, delete_assignment_if_role_version_core,
    delete_group_mapping_if_versions_core, delete_role_core, update_role_core, CreateRoleRequest,
};
use crate::servers::{
    clear_upstream_quarantine_core, reconnect_server_core, refresh_server_catalog_core,
    ClearUpstreamQuarantineParams, ReconnectServerParams, RefreshServerCatalogParams,
};
use crate::state::AdminState;
use crate::tenants::update_tenant_core;
use crate::upstream_sessions::revoke_session_core;
use waygate_core::fmt::format_ts_rfc3339;

/// The role whose members may approve a change by default. Higher-risk
/// actions override [`ActionExecutor::requirement`] to demand a stricter
/// role / approver count / factor set; this is the single-operator bar
/// the rest inherit. Canonical home for the constant the propose path
/// previously hard-coded inline.
pub(crate) const DEFAULT_ELIGIBLE_ROLE: &str = "dashboard-admins";

/// Non-secret proposal witness for a full-set manifest publish or rollback.
/// It binds both the selected ledger target and the live on-disk set that the
/// human's effect preview used as its baseline.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ManifestFullSetWitness {
    pub target_content_hash: String,
    pub live_base_hash: Option<String>,
}

/// Why an execution failed. The approve handler maps these to an HTTP
/// status and stamps the change request `failed` with the message.
#[derive(Debug)]
pub enum ExecError {
    /// A precondition checked at execute time no longer holds
    /// (validate-before-irreversible) — e.g. the target row is gone
    /// between propose and approve.
    Precondition(String),
    /// A store/dependency the executor needs isn't configured.
    Unavailable(&'static str),
    /// The captured params don't match the action's shape (shouldn't
    /// happen post-propose-validation; defensive).
    BadParams(String),
    /// The underlying store returned an error.
    Store(String),
}

/// The executor analogue of [`Capability::require`] (and of
/// `resource_catalog::cap`): the handle, or [`ExecError::Unavailable`]
/// carrying the capability's canonical message — the same string the REST
/// 503 uses, so the two surfaces can't drift.
pub(crate) fn cap<T>(c: &crate::capability::Capability<T>) -> Result<&T, ExecError> {
    c.get().ok_or(ExecError::Unavailable(c.unavailable_msg()))
}

impl ExecError {
    /// Operator-facing message recorded on the failed change request.
    pub fn message(&self) -> String {
        match self {
            Self::Precondition(m) => format!("precondition failed: {m}"),
            Self::Unavailable(m) => format!("dependency unavailable: {m}"),
            Self::BadParams(m) => format!("bad params: {m}"),
            Self::Store(m) => format!("store error: {m}"),
        }
    }
}

/// What an executor produces on success: the JSON `result` recorded on the
/// change request (surfaced to the maker's poll AND the operator's decision
/// view) and, OPTIONALLY, a one-time plaintext `secret` to hand back to the
/// maker (e.g. a freshly minted API key).
///
/// The secret is NEVER part of `result` — `result` carries only a
/// non-sensitive fingerprint (prefix / id) — so it can't leak via the poll,
/// the maker's list, the decision response, the out-of-band notifier, or
/// logs. The plaintext travels the separate encrypted burn-on-read channel
/// (`change_request_secrets` + the `/secret` retrieve route).
#[derive(Debug)]
pub struct ExecOutcome {
    pub result: Value,
    pub secret: Option<Vec<u8>>,
}

impl ExecOutcome {
    /// A result with no secret — the common case.
    pub fn result(result: Value) -> Self {
        Self {
            result,
            secret: None,
        }
    }

    /// A result plus a one-time secret delivered via the burn-on-read
    /// channel. `result` must carry only a non-sensitive fingerprint.
    pub fn with_secret(result: Value, secret: Vec<u8>) -> Self {
        Self {
            result,
            secret: Some(secret),
        }
    }
}

impl From<Value> for ExecOutcome {
    fn from(result: Value) -> Self {
        Self::result(result)
    }
}

/// Re-exported so an executor can declare its uploadable document fields
/// without reaching across to the submission layer that consumes them.
pub use crate::param_files::FileBackedParam;

/// Executes one `action_type`'s captured intent against the live admin
/// stores. Stateless — holds no data; reaches what it needs through
/// `&Arc<AdminState>`.
#[async_trait]
pub trait ActionExecutor: Send + Sync {
    /// The `action_type` key this executor handles (matches the
    /// `change_requests.action_type` and the propose allowlist).
    fn action_type(&self) -> &'static str;

    /// Params fields this action accepts as an uploaded gateway file instead
    /// of inline text. Empty by default: an action opts in only when one of
    /// its fields is a document a maker may reasonably author out of band.
    fn file_params(&self) -> &'static [FileBackedParam] {
        &[]
    }

    /// The approval requirement this action demands, resolved
    /// gateway-side at propose time. NEVER chosen by the maker — a maker
    /// must not be able to weaken its own approval bar, so the
    /// `ProposeRequest` carries no requirement field and `propose_core`
    /// reads it from here instead. Defaults to the single-operator bar
    /// ([`DEFAULT_ELIGIBLE_ROLE`], one approval, no extra factors);
    /// higher-risk actions override to a stricter role / approver count /
    /// factor set.
    fn requirement(&self) -> ApprovalRequirement {
        ApprovalRequirement::single(DEFAULT_ELIGIBLE_ROLE)
    }

    /// Capture an opaque freshness witness of the action's target as it exists
    /// now. Most executors return a content hash of mutable fields. Executors
    /// that bind the witness into a conditional store mutation may instead
    /// return a structured, non-secret version token. `propose_core` stores the
    /// witness on the change request; `approve_and_execute` re-captures it just
    /// before the side effect and refuses when it no longer matches, so an
    /// out-of-band edit during the pending window cannot be silently clobbered.
    ///
    /// Default `Ok(None)`: an action with no mutable target to clobber opts out,
    /// or uses its own store-level compare-and-swap. `None` at propose and
    /// execute always match. Executors that require a witness override
    /// [`Self::requires_target_etag`] so absent or unreadable state fails closed.
    async fn capture_etag(
        &self,
        _state: &Arc<AdminState>,
        _tenant_id: &str,
        _actor: &Principal,
        _params: &Value,
    ) -> Result<Option<String>, ExecError> {
        Ok(None)
    }

    /// Whether a proposal must capture a target witness successfully. Most
    /// legacy actions keep best-effort capture, but operations whose safety
    /// depends on a version-conditional mutation opt in so a missing target or
    /// unreadable store is rejected before the request is queued.
    fn requires_target_etag(&self) -> bool {
        false
    }

    /// Execute with access to the immutable target witness captured on the
    /// change request. The default delegates to [`Self::execute`]; executors
    /// that close the final validation-to-write race inside their store
    /// override this hook and bind the witness into the mutation predicate.
    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        _target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        self.execute(state, tenant_id, actor, params).await
    }

    /// Perform the side effect. Returns an [`ExecOutcome`]: the JSON result
    /// recorded on the change request (and returned to the maker's poll)
    /// plus an optional one-time secret routed through the burn-on-read
    /// channel. Errors mark the change `failed`. Takes `&Arc<AdminState>`
    /// so executors can delegate to the shared `*_core` handlers (which take
    /// `&Arc<AdminState>`).
    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError>;
}

/// `action_type` -> executor. Built once (executors are zero-sized).
pub struct ExecutorRegistry {
    by_type: HashMap<&'static str, Box<dyn ActionExecutor>>,
}

impl ExecutorRegistry {
    fn with_builtins() -> Self {
        let mut by_type: HashMap<&'static str, Box<dyn ActionExecutor>> = HashMap::new();
        for e in builtin_executors() {
            by_type.insert(e.action_type(), e);
        }
        Self { by_type }
    }

    /// The executor for `action_type`, if one is registered.
    pub fn get(&self, action_type: &str) -> Option<&dyn ActionExecutor> {
        self.by_type.get(action_type).map(Box::as_ref)
    }

    /// All registered `action_type` keys, sorted. This IS the propose
    /// allowlist — a maker may only propose actions that can be executed,
    /// so the queue can't fill with intents nothing can ever run.
    pub fn action_types(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.by_type.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Every proposable action paired with the JSON Schema of the params its
    /// executor captures, sorted by `action_type`. The keys MUST equal
    /// [`Self::action_types`] — `action_catalog_keys_match_registry` enforces
    /// it. The `gateway-admin.describe_action` MCP tool serves this so a
    /// maker can construct a valid `propose_change.params` from the wire
    /// surface alone, instead of reading this crate's source.
    pub fn action_catalog(&self) -> Vec<ActionCatalogEntry> {
        let mut v: Vec<ActionCatalogEntry> = action_param_schemas()
            .into_iter()
            .map(|(action_type, params_schema)| ActionCatalogEntry {
                action_type,
                params_schema,
                context: crate::change_context::context_descriptor(action_type),
                file_params: self
                    .get(action_type)
                    .map(|e| e.file_params())
                    .unwrap_or(&[]),
            })
            .collect();
        v.sort_by_key(|e| e.action_type);
        v
    }

    /// The file-backed params `action_type` accepts, or an empty slice for an
    /// unregistered action or one with no out-of-band document field.
    pub fn file_params(&self, action_type: &str) -> &'static [FileBackedParam] {
        self.get(action_type)
            .map(|e| e.file_params())
            .unwrap_or(&[])
    }

    /// The JSON Schema of the params `action_type`'s executor deserializes, or
    /// `None` if the action isn't registered. The same schema
    /// [`Self::action_catalog`] and the `describe_action` MCP tool serve; the
    /// propose path uses it to validate params before queuing a change
    /// (teach-through errors).
    pub fn params_schema(&self, action_type: &str) -> Option<Value> {
        action_param_schemas()
            .into_iter()
            .find(|(at, _)| *at == action_type)
            .map(|(_, schema)| schema)
    }
}

fn builtin_executors() -> Vec<Box<dyn ActionExecutor>> {
    skills::append_executors(local_catalog::append_executors(
        api_key_profiles::append_executors(agent_configs::append_executors(vec![
            Box::new(tool_reviews::ToolContractApproveExecutor),
            Box::new(RateLimitUpdateExecutor),
            Box::new(RateLimitCreateExecutor),
            Box::new(RateLimitDeleteExecutor),
            Box::new(InspectionRuleDeleteExecutor),
            Box::new(OAuthConsentRevokeExecutor),
            Box::new(PeerCreateExecutor),
            Box::new(PeerUpdateExecutor),
            Box::new(PeerDeleteExecutor),
            Box::new(RbacRoleCreateExecutor),
            Box::new(RbacRoleUpdateExecutor),
            Box::new(RbacRoleDeleteExecutor),
            Box::new(RbacAssignmentGrantExecutor(MembershipClass::Ordinary)),
            Box::new(RbacAssignmentGrantExecutor(MembershipClass::Privileged)),
            Box::new(RbacAssignmentRevokeExecutor(MembershipClass::Ordinary)),
            Box::new(RbacAssignmentRevokeExecutor(MembershipClass::Privileged)),
            Box::new(RbacGroupMappingGrantExecutor(MembershipClass::Ordinary)),
            Box::new(RbacGroupMappingGrantExecutor(MembershipClass::Privileged)),
            Box::new(RbacGroupMappingRevokeExecutor(MembershipClass::Ordinary)),
            Box::new(RbacGroupMappingRevokeExecutor(MembershipClass::Privileged)),
            Box::new(TenantUpdateExecutor),
            Box::new(AuditRetentionSetExecutor),
            Box::new(AuditRetentionClearExecutor),
            Box::new(AuditRoutingSetExecutor),
            Box::new(AuditRoutingClearExecutor),
            Box::new(UpstreamSessionRevokeExecutor),
            Box::new(BreakGlassMintExecutor),
            Box::new(BreakGlassRevokeExecutor),
            Box::new(ApiKeyMintExecutor),
            Box::new(ApiKeyRevokeExecutor),
            Box::new(ApiKeyUpdateGrantsExecutor),
            Box::new(PolicyPublishExecutor),
            Box::new(PolicyRollbackExecutor),
            Box::new(PolicyUpsertFragmentExecutor),
            Box::new(ManifestPublishExecutor),
            Box::new(ManifestRollbackExecutor),
            Box::new(ManifestStageAndPublishExecutor),
            Box::new(ManifestUpsertServersExecutor),
            Box::new(ManifestRemoveServersExecutor),
            Box::new(UpstreamReconnectExecutor),
            Box::new(UpstreamRefreshCatalogExecutor),
            Box::new(UpstreamClearQuarantineExecutor),
            Box::new(CatalogServerUnquarantineExecutor),
            Box::new(ConfigReloadExecutor),
        ])),
    ))
}

/// JSON Schema for a captured-params type `T`, as a `serde_json::Value`.
///
/// Derived (schemars) straight from the Rust type the matching executor
/// deserializes in `execute()`, so the advertised params shape can't drift
/// from what the action actually accepts — the single-source-of-truth rule
/// from `docs/agents/mcp-tool-docs.md`.
fn params_schema_of<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("schemars schema serializes to JSON")
}

/// One proposable action and the JSON Schema of the params its executor captures.
#[derive(Debug, Clone)]
pub struct ActionCatalogEntry {
    pub action_type: &'static str,
    pub params_schema: Value,
    /// Optional read-only preparation contract for actions whose safe request
    /// construction depends on current state.
    pub context: Option<crate::change_context::ActionContextDescriptor>,
    /// Params fields that may be submitted as an uploaded gateway file
    /// instead of inline text. Empty for actions with no document field.
    pub file_params: &'static [FileBackedParam],
}

/// Map an [`ApiError`](crate::error::ApiError) from a shared `*_core`
/// handler to an [`ExecError`]. Executors delegate to the same cores the
/// HTTP handlers use; this translates the core's typed error to the
/// execute-on-approval failure taxonomy (so a validation rejection is a
/// clean 422, a missing dependency a 503, etc., rather than an opaque 500).
fn map_core_error(e: crate::error::ApiError) -> ExecError {
    use crate::error::ApiError;
    match e {
        ApiError::ServiceUnavailable(m) => ExecError::Unavailable(m),
        ApiError::BadRequest(m) | ApiError::UnprocessableEntity(m) => ExecError::BadParams(m),
        ApiError::Conflict(m) | ApiError::BadGateway(m) => ExecError::Precondition(m),
        // A target that's gone at execute time (the core returns NotFound /
        // NotFoundDyn — e.g. peer.update on a peer deleted between propose and
        // approve) is a precondition failure, not an internal error. Some
        // cores instead signal not-found via `Ok(None)` / `Ok(false)`, which
        // the executor maps to Precondition directly.
        ApiError::NotFound(m) => ExecError::Precondition(format!("target not found: {m}")),
        ApiError::NotFoundDyn(m) => ExecError::Precondition(format!("target not found: {m}")),
        ApiError::Internal(m) | ApiError::InternalOperatorVisible(m) => ExecError::Store(m),
        // The shared cores reached here only return the variants above; any
        // other is a defensive catch-all (ApiError has no Display to forward).
        _ => ExecError::Store("admin operation failed".into()),
    }
}

/// Scopes a proposed RBAC role may NOT grant. These confer control-plane
/// authority over THIS gateway — operator (`mcp:admin`), maker
/// (`mcp:propose`), and provisioning (`scim:write`) rights — and a role's
/// scopes are merged into every assignee's `Principal.scopes`
/// (`waygate_rbac`), which [`crate::scope`] gates those same surfaces off.
/// Granting any of them through the role-definition propose path would be a
/// privilege escalation: a maker could queue an innocuous-looking
/// `rbac.role.update` that hands `mcp:admin`/`mcp:propose` to every current
/// member. Role-definition changes remain operator-only; assigning an existing
/// privileged role uses the explicit protected membership actions with the explicit protected approval bar. This is exactly the set
/// [`crate::scope`]'s `peer_assertion_permits` forbids a non-operator peer
/// from ever holding. An operator may still grant these via the direct admin
/// API; only the propose path is restricted.
const PRIVILEGED_ROLE_SCOPES: &[&str] = waygate_core::CONTROL_PLANE_SCOPES;

/// Refuse a proposed role whose scopes include any [`PRIVILEGED_ROLE_SCOPES`]
/// entry — checked BEFORE the irreversible `create_role` / `update_role`, so
/// the escalation can never persist even if a human approves the change.
fn reject_privileged_role_scopes(scopes: &[String]) -> Result<(), ExecError> {
    if let Some(bad) = scopes
        .iter()
        .find(|s| PRIVILEGED_ROLE_SCOPES.contains(&s.as_str()))
    {
        return Err(ExecError::BadParams(format!(
            "role scope {bad:?} confers control-plane authority and cannot be granted through \
             the propose path; an operator must grant it via the direct admin API"
        )));
    }
    Ok(())
}

/// Process-wide registry handle.
pub fn registry() -> &'static ExecutorRegistry {
    static REGISTRY: OnceLock<ExecutorRegistry> = OnceLock::new();
    REGISTRY.get_or_init(ExecutorRegistry::with_builtins)
}

/// Validate `params` against `action_type`'s schemars schema, returning a
/// payload-safe message per violation. Empty ⇒ valid (or the action has no /
/// an uncompilable schema — the execute-time `from_value` in each executor
/// stays the final guard). The single source the propose path (first error ⇒
/// `BadRequest`) and [`preview_action`] (all errors) share, so the two can't
/// drift.
pub fn validate_action_params(action_type: &str, params: &Value) -> Vec<String> {
    let Some(schema) = registry().params_schema(action_type) else {
        return Vec::new();
    };
    match jsonschema::validator_for(&schema) {
        Ok(validator) => validator
            .iter_errors(params)
            // Payload-safe: surfaces field NAMES + paths + schema rules, never
            // the offending instance VALUE.
            .map(|e| waygate_mcp::invocation::sanitize_validation_error(&e))
            .collect(),
        // A generated schema that won't compile is OUR bug, not the caller's —
        // log and treat as "no schema-level objection".
        Err(e) => {
            tracing::warn!(action_type, error = %e, "params schema failed to compile; skipping validation");
            Vec::new()
        }
    }
}

/// A read-only dry-run of a `propose_change`: whether `params` satisfy the
/// action's schema (and the violations if not), plus the approval bar the
/// change would demand — without queuing anything. Served by the
/// `gateway-admin.preview_change` MCP tool.
#[derive(Debug, Clone)]
pub struct ActionPreview {
    pub action_type: String,
    pub valid: bool,
    pub errors: Vec<String>,
    pub required_approvals: i32,
    pub eligible_role: String,
    pub factors: Vec<String>,
    pub cooldown_seconds: Option<i32>,
    pub params_schema: Value,
}

/// Build an [`ActionPreview`] for `action_type` + `params`, or `None` when the
/// action isn't registered (the caller teaches the valid set). Pure: no store
/// access and no side effect — exactly what a maker runs before `propose_change`.
pub fn preview_action(action_type: &str, params: &Value) -> Option<ActionPreview> {
    let exec = registry().get(action_type)?;
    let errors = validate_action_params(action_type, params);
    let req = exec.requirement();
    Some(ActionPreview {
        action_type: action_type.to_owned(),
        valid: errors.is_empty(),
        errors,
        required_approvals: req.required_approvals,
        eligible_role: req.eligible_role,
        factors: req.factors,
        cooldown_seconds: req.cooldown_seconds,
        params_schema: registry().params_schema(action_type).unwrap_or(Value::Null),
    })
}

/// Hash an UPDATE target's mutable-field fingerprint into an opaque freshness
/// token (see [`ActionExecutor::capture_etag`]). Reuses the same sha256 helper
/// the policy/manifest ledgers use; `serde_json::Value::to_string` renders the
/// passed object's keys in a stable order, so identical target state always
/// hashes to the same token. The token is one-way — safe to persist on the
/// change request even when a hashed field is sensitive (e.g. a peer's
/// credential-bearing issuer URL), since the raw value can't be recovered from
/// the hash.
fn etag_of(fields: &Value) -> String {
    waygate_policy::content_hash(&fields.to_string())
}

// ---- rate_limit.update ----

// Executor implementations, split per domain. `builtin_executors()` and
// the schema catalog above reference them through these private glob
// imports.
mod agent_configs;
mod api_key_profiles;
mod api_keys;
mod break_glass;
mod bundles;
mod federation;
mod inspection_rules;
mod local_catalog;
mod oauth_sessions;
mod operations;
mod param_schemas;
mod rate_limits;
mod rbac;
mod skills;
mod tenants_audit;
use agent_configs::*;
use api_keys::*;
use break_glass::*;
use bundles::*;
use federation::*;
use inspection_rules::*;
use oauth_sessions::*;
use operations::*;
use param_schemas::action_param_schemas;
use rate_limits::*;
use rbac::*;
use tenants_audit::*;

#[cfg(test)]
mod tests;

mod tool_reviews;
