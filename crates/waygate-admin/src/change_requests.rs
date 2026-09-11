//! `/api/v1/admin/change_requests` — the HITL control-plane change-request
//! surface: the maker proposes + polls, the operator approves /
//! denies, and an approved change executes server-side.
//!
//! CIBA-shaped: `POST` (`mcp:propose`) captures the INTENT of a privileged
//! admin mutation as a `pending` change request and returns the
//! `change_request_id` (the CIBA `auth_req_id` to poll on) plus a
//! `binding_code`. The maker polls `GET .../{id}` until a human decides.
//! `POST .../{id}/approve` and `.../{id}/deny` (`mcp:admin`) are the
//! operator decision surface; approve runs the captured intent through the
//! [`crate::change_executor`] registry (execute-on-approval), recording the
//! row `executed` / `failed`.
//!
//! Gated by `mcp:propose` (the *maker* scope), NOT `mcp:admin`: the whole
//! point is that an automated caller can QUEUE a privileged change
//! without holding admin. Tenant is always the principal's tenant (never
//! a request-supplied value — same lesson as break_glass / oauth_consent),
//! and a maker only ever sees its OWN requests (`requested_by =
//! principal.sub`); the operator's all-tenant review view is the
//! dashboard, gated by `mcp:admin`.
//!
//! The approval REQUIREMENT is resolved by the gateway, never chosen by
//! the maker — a maker must not be able to weaken its own approval bar.
//! The requirement is read per-action from the executor
//! (`ActionExecutor::requirement`), and a `required_approvals > 1` bar is
//! enforced by collecting N distinct eligible-admin approvals
//! (`ChangeRequestStore::record_approval`) before execute. Non-default eligible
//! roles, fresh dashboard authentication factors, and proposal-age cooldowns are
//! enforced at the same approve-time boundary before any state transition.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use waygate_changeset::{
    ChangeRequest, ChangeRequestError, ChangeRequestLifecycle, ChangeRequestStatus,
    ChangeRequestStatusSummary, NewChangeRequest, SharedChangeRequestStore, MAX_LIST_LIMIT,
};
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory, SharedEvidence};
use waygate_oidc::{Principal, Session};

use crate::approval_requirement::{
    enforce_approval_requirement, requirement_enforceable, requirement_fits_ttl,
};
use crate::change_executor::{registry, ExecError};
use crate::change_notify::{ChangeProposedNotification, SharedChangeNotifier};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::param_files::ResolvedParamFile;
use crate::scope::{require_admin, require_propose};
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339;

/// Default change-request TTL (15 minutes) when the body omits one.
const DEFAULT_TTL_SECONDS: u32 = 900;
/// Hard TTL ceiling (24h), mirroring break-glass — a pending change is
/// for a near-term action, not a standing intent.
const MAX_TTL_SECONDS: u32 = 86_400;
/// Default cap on the serialized size of a proposed change's `params`. The
/// review UI renders the COMPLETE params for every pending row (truncating the
/// display would hide fields from the approver), so every row is bounded at the
/// source and the approval surfaces separately bound rows per render.
pub(crate) const DEFAULT_MAX_PROPOSE_PARAMS_BYTES: usize = 16 * 1024;
/// Cap for actions whose params carry an authored DOCUMENT rather than a
/// handful of scalars — a full manifest set, a Cedar statement, an agent's
/// instruction addendum. The default cap is sized for scalars and is far too
/// small for these: a complete agent configuration alone can hold an
/// 8,000-character instruction plus 200 tool ids of 256 characters, and JSON
/// escaping can spend six bytes per character. A real manifest set outgrows
/// 16 KiB well before a deployment is large.
///
/// These actions are also the ones that accept their document as an uploaded
/// file ([`crate::param_files`]); the upload keeps the bytes out of MCP
/// JSON-RPC and model context, and this cap bounds the resolved text that
/// lands in the reviewable row either way.
///
/// The ceiling is a render bound, not a storage one: the review queue shows an
/// approver the complete params of every pending row, so the page size and
/// this cap together bound one rendered page
/// (`pending_page_preserves_the_original_aggregate_params_bound`).
pub(crate) const DOCUMENT_MAX_PROPOSE_PARAMS_BYTES: usize = 384 * 1024;
/// Recommended poll cadence handed back to the maker (CIBA `interval`).
const DEFAULT_POLL_INTERVAL_SECONDS: u32 = 5;

/// The params ceiling for `action_type`. Document-carrying actions get the
/// larger envelope; everything else stays at the scalar default.
pub fn max_propose_params_bytes(action_type: &str) -> usize {
    match action_type {
        "agent_config.create"
        | "agent_config.update"
        | "manifest.stage_and_publish"
        | "manifest.upsert_servers"
        | "policy.upsert_fragment" => DOCUMENT_MAX_PROPOSE_PARAMS_BYTES,
        _ => DEFAULT_MAX_PROPOSE_PARAMS_BYTES,
    }
}

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/change_requests",
            get(list_requests).post(propose_request),
        )
        .route(
            "/api/v1/admin/change_requests/{id}",
            get(get_request_status),
        )
        .route(
            "/api/v1/admin/change_requests/{id}/secret",
            get(get_request_secret),
        )
        .layer(middleware::from_fn(require_propose))
        .with_state(state)
}

/// The operator decision surface (`/approve`, `/deny`), gated by
/// `mcp:admin` — separate from the maker `router` (gated by `mcp:propose`)
/// because approve/deny is a checker action, not a maker one.
pub fn admin_router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/change_requests/{id}/approve",
            post(approve_request),
        )
        .route(
            "/api/v1/admin/change_requests/{id}/deny",
            post(deny_request),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProposeRequest {
    /// Registry key for the action, e.g. `api_key.mint`.
    pub action_type: String,
    /// The captured intent the executor replays on approval. Its shape is
    /// specific to each `action_type` and is validated against the action's
    /// JSON Schema at propose time (see [`validate_propose`]).
    #[schema(value_type = Object)]
    pub params: Value,
    /// Why this change is needed. Required, non-empty — surfaced to the
    /// human approver and audited.
    pub justification: String,
    /// TTL in seconds; defaults to 900 (15m), capped at 86400 (24h).
    #[serde(default)]
    pub ttl_seconds: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ProposeResponse {
    /// The change-request id == the CIBA `auth_req_id` to poll on.
    pub change_request_id: Uuid,
    /// Literal stored status at creation (`pending`).
    pub status: String,
    /// CIBA `binding_message` short code — confirm it matches on the
    /// approval page before approving.
    pub binding_code: String,
    /// Seconds until the request expires unapproved.
    pub expires_in: i64,
    /// Recommended seconds between status polls.
    pub interval: u32,
    /// Where a human approves this (the dashboard review page).
    pub approval_url: String,
    /// Poll this for the decision.
    pub poll_url: String,
}

#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
pub struct StatusResponse {
    pub change_request_id: Uuid,
    /// CIBA-style poll status: `authorization_pending` | `approved` |
    /// `denied` | `expired` | `executing` | `executed` | `failed`.
    pub status: String,
    pub binding_code: String,
    pub action_type: String,
    pub expires_at: String,
    pub interval: u32,
    /// The human who decided, once decided.
    pub approver: Option<String>,
    /// Present when `status = denied` — returned to the maker so it can
    /// adjust and re-propose.
    pub denied_reason: Option<String>,
    /// The executor's result JSON when `status = executed`. The list endpoint
    /// omits an oversized outcome to keep polling bounded; fetch the individual
    /// request status for the complete result.
    #[schema(value_type = Object)]
    pub execution_result: Option<Value>,
    /// The failure message when `status = failed`.
    pub error_message: Option<String>,
    pub approval_url: String,
}

#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
pub struct ListResponse {
    pub requests: Vec<StatusResponse>,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListQuery {
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    /// Optional lifecycle bucket: `pending` | `expired` | `decided`.
    #[serde(default)]
    pub lifecycle: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/change_requests",
    tag = "change_requests",
    request_body = ProposeRequest,
    responses(
        (status = 201, description = "Change request captured (pending)", body = ProposeResponse),
        (status = 400, description = "Validation failed", body = ApiErrorBody),
        (status = 503, description = "Change-request store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:propose", body = ApiErrorBody),
    ),
)]
async fn propose_request(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Json(mut req): Json<ProposeRequest>,
) -> ApiResult<(StatusCode, Json<ProposeResponse>)> {
    let store = require_store(&state)?;
    // Turn any uploaded document into inline text FIRST, so every step below —
    // the freshness witness, schema validation, the stored row, the approver's
    // render — reads the resolved params and never a file reference.
    let files = resolve_submission_files(&state, &req.action_type, &mut req.params, &actor).await?;
    // Capture the target's freshness token NOW (before the propose), so
    // execute-on-approval can detect an out-of-band edit during the pending
    // window. Computed here (the REST surface has `AdminState`); the built-in
    // MCP propose path computes it the same way via `capture_target_etag`.
    let target_etag = capture_target_etag(&state, &req.action_type, &actor, &req.params).await?;
    let resp = propose_core(
        store,
        &state.evidence,
        &state.public_url,
        state.hitl.change_notifier.as_ref(),
        &actor,
        req,
        SubmissionContext { target_etag, files },
    )
    .await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

/// What a submission surface established about a proposal before it is stored.
///
/// Both members are produced by the caller — which holds `AdminState` and can
/// therefore reach the target stores and the file plane — and are consumed only
/// by [`propose_core`], which holds neither.
#[derive(Default)]
pub struct SubmissionContext {
    /// The target's freshness witness, captured just before the propose so
    /// execute-on-approval can refuse a stale write. `None` for actions that
    /// opt out of the guard.
    pub target_etag: Option<String>,
    /// Provenance of every document read out of the file plane into `params`.
    /// Empty for an entirely inline submission.
    pub files: Vec<ResolvedParamFile>,
}

/// Resolve `action_type`'s uploaded-document params into inline text, bounded
/// by that action's params ceiling.
///
/// Shared by every submission surface — the REST propose handler and the
/// `propose_change` / `preview_change` tools — so a candidate that previews
/// clean submits identically and no surface can skip the resolution.
pub async fn resolve_submission_files(
    state: &Arc<AdminState>,
    action_type: &str,
    params: &mut Value,
    actor: &Principal,
) -> Result<Vec<ResolvedParamFile>, ApiError> {
    crate::param_files::resolve_param_files(
        state,
        action_type,
        params,
        actor,
        max_propose_params_bytes(action_type),
    )
    .await
}

/// Capture the freshness token of `action_type`'s target as it exists NOW, via
/// the action's executor's [`crate::change_executor::ActionExecutor::capture_etag`].
/// Stored on the change request at propose so [`execute_approved`] can
/// refuse a stale approved write that would clobber an out-of-band edit made
/// during the pending window. Shared by BOTH propose entry points — the REST
/// handler and the built-in MCP tool (`waygate_server::mcp_builtin`) — so the
/// freshness guard applies no matter how a maker proposed.
///
/// Best-effort for legacy actions: returns `Ok(None)` (no baseline, change
/// simply isn't freshness-guarded) when the action opts out, its target is
/// absent, or a capture error occurs. Actions that declare
/// `requires_target_etag()` fail closed instead: missing/stale targets and
/// store failures are returned before the proposal is queued because their
/// version-conditional mutation cannot execute safely without the witness.
/// (Param SHAPE is a
/// separate concern — [`validate_propose`] now checks it against the action's
/// schema at propose; format/parse issues the schema treats as annotations,
/// e.g. a non-UUID string, are still deferred to the executor at execute time.)
/// Degrading to `None` is no worse than pre-B2 (the change just isn't guarded)
/// and the executor still validates params + handles a missing target at
/// execute. The execute-time recheck in [`execute_approved`] stays STRICT — a
/// capture error there fails closed — so only the propose-time baseline is
/// best-effort.
pub async fn capture_target_etag(
    state: &Arc<AdminState>,
    action_type: &str,
    actor: &Principal,
    params: &serde_json::Value,
) -> Result<Option<String>, ApiError> {
    let Some(exec) = registry().get(action_type) else {
        return Ok(None);
    };
    match exec
        .capture_etag(state, actor.tenant.as_str(), actor, params)
        .await
    {
        Ok(Some(etag)) => Ok(Some(etag)),
        Ok(None) if exec.requires_target_etag() => Err(ApiError::BadRequest(format!(
            "action {action_type:?} requires an existing target whose current version can be captured"
        ))),
        Ok(None) => Ok(None),
        Err(e) => {
            if exec.requires_target_etag() {
                return Err(capture_error_to_api(&e));
            }
            tracing::debug!(
                action_type = %action_type,
                error = %e.message(),
                "change-request: target freshness capture skipped at propose (no baseline)",
            );
            Ok(None)
        }
    }
}

/// Shared propose path used by the REST handler AND the built-in MCP tool
/// surface ([`crate::mcp_builtin`]). Validate → insert `pending` →
/// fail-closed audit → out-of-band notify → build the CIBA response (binding
/// code + approval + poll URLs). Takes the minimal pieces (store / evidence /
/// public_url / notifier) rather than `&AdminState` so the MCP composition
/// root can build it before `AdminState` exists, sharing one store Arc (and
/// one notifier) with the REST surface.
pub async fn propose_core(
    store: &SharedChangeRequestStore,
    evidence: &SharedEvidence,
    public_url: &str,
    notifier: Option<&SharedChangeNotifier>,
    actor: &Principal,
    req: ProposeRequest,
    submission: SubmissionContext,
) -> Result<ProposeResponse, ApiError> {
    validate_propose(&req)?;

    let ttl = req.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(ttl as i64);
    // The requirement is gateway-resolved from the action's executor,
    // never maker-chosen (a maker must not be able to weaken its own
    // approval bar — the `ProposeRequest` carries no requirement field).
    // `validate_propose` above already rejected an unregistered
    // `action_type`, so the lookup is present; the `ok_or_else` is a
    // defensive backstop rather than an expected path.
    let requirement = registry()
        .get(&req.action_type)
        .map(|e| e.requirement())
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "unknown or non-executable action_type {:?}",
                req.action_type
            ))
        })?;
    // Fail closed: refuse to queue a change whose declared approval bar
    // exceeds what the approve path can enforce today. Distinct counts,
    // eligible roles, authentication factors, and proposal-age cooldowns are
    // enforceable; break-glass-backed approval still lacks a claim surface.
    // A registered built-in executor reaching this is a build-time invariant
    // violation, not a maker error, so log it loudly and 500 rather than
    // under-enforce.
    if !requirement_enforceable(&requirement) {
        tracing::error!(
            action_type = %req.action_type,
            required_approvals = requirement.required_approvals,
            eligible_role = %requirement.eligible_role,
            factors = ?requirement.factors,
            "change-request: executor declared an approval requirement this build \
             cannot enforce; refusing propose (fail closed)",
        );
        return Err(ApiError::Internal(format!(
            "action {:?} declares an approval requirement this build cannot \
             enforce; refusing to queue an under-enforced change",
            req.action_type
        )));
    }
    if !requirement_fits_ttl(&requirement, ttl) {
        return Err(ApiError::BadRequest(format!(
            "ttl_seconds ({ttl}) must be greater than the action's cooldown_seconds ({})",
            requirement.cooldown_seconds.unwrap_or_default()
        )));
    }
    let new = NewChangeRequest {
        tenant_id: actor.tenant.as_str().to_owned(),
        requested_by: actor.sub.clone(),
        client_id: None,
        action_type: req.action_type.clone(),
        params: req.params.clone(),
        preview: None,
        // The target's freshness token captured by the caller (via
        // `capture_target_etag`) just before this propose. `execute_approved`
        // re-captures and refuses if it changed in the pending window, so an
        // approved stale write can't clobber an out-of-band edit. `None` for
        // actions that opt out of the guard (the default) and for legacy
        // best-effort capture; witness-required actions were rejected before
        // this point if their target was absent or unreadable.
        target_etag: submission.target_etag,
        justification: req.justification.clone(),
        requirement,
        expires_at,
    };
    let cr = store.propose(new).await.map_err(map_store_err)?;

    // The propose ceremony is an AdminMutation (a maker queued a
    // control-plane change), even though no privileged side effect has
    // run. record_required (fail-closed) so a missing audit row fails the
    // call rather than leaving an unattributed queued change.
    //
    // This insert-then-audit is NOT atomic — if the evidence write fails,
    // a `pending` row already exists and the caller gets 500. This
    // deliberately matches the break-glass mint posture (the row exists
    // but the caller sees the failure and investigates the audit infra
    // before trusting the system); the single shared-transaction
    // contract is tracked in issue #151. The blast radius here is
    // bounded: an un-audited row is only `pending` — it does nothing
    // until a human approves it, and approval/execution emit their own
    // audit rows, so an audit-less propose can't silently drive a
    // privileged side effect.
    evidence
        .record_required(
            AuditEvent::new("ChangeRequestPropose", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(Some(actor))
                .with_target(cr.action_type.clone())
                .with_reason(format!(
                    "proposed change id={} action={} tenant={} binding={} justification={:?}{}",
                    cr.id,
                    cr.action_type,
                    cr.tenant_id,
                    cr.binding_code,
                    cr.justification,
                    describe_resolved_files(&submission.files),
                )),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                change_request_id = %cr.id,
                "change-request: propose audit failed AFTER insert; returning error",
            );
            ApiError::Internal(format!("change-request propose audit failed: {e}"))
        })?;

    // Out-of-band heads-up for an operator away from the dashboard.
    // Fired only AFTER the propose is durably stored and audited, so a
    // notification always corresponds to a real, attributable pending change.
    // Fire-and-forget + best-effort by contract (the impl spawns any I/O and
    // swallows errors) — it never blocks or fails the propose; the change
    // still sits in the dashboard review queue if delivery fails. Carries an
    // operator-safe summary + a deep link only — no params, no justification.
    if let Some(notifier) = notifier {
        notifier.notify_change_proposed(ChangeProposedNotification {
            tenant_id: cr.tenant_id.clone(),
            change_request_id: cr.id,
            action_type: cr.action_type.clone(),
            requested_by: cr.requested_by.clone(),
            binding_code: cr.binding_code.clone(),
            expires_at: cr.expires_at,
            approval_url: approval_url(public_url, cr.id),
        });
    }

    Ok(ProposeResponse {
        change_request_id: cr.id,
        status: cr.status.as_db_str().to_owned(),
        binding_code: cr.binding_code.clone(),
        expires_in: (cr.expires_at - OffsetDateTime::now_utc())
            .whole_seconds()
            .max(0),
        interval: DEFAULT_POLL_INTERVAL_SECONDS,
        approval_url: approval_url(public_url, cr.id),
        poll_url: poll_url(public_url, cr.id),
    })
}

/// Unwrap the change-request store or 503. Shared by the REST handlers.
fn require_store(state: &Arc<AdminState>) -> Result<&SharedChangeRequestStore, ApiError> {
    state.hitl.change_requests.require()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/change_requests/{id}",
    tag = "change_requests",
    params(("id" = Uuid, Path, description = "Change request id (the CIBA auth_req_id)")),
    responses(
        (status = 200, description = "Change request status", body = StatusResponse),
        (status = 404, description = "Not found, or not the caller's own request", body = ApiErrorBody),
        (status = 503, description = "Change-request store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:propose", body = ApiErrorBody),
    ),
)]
async fn get_request_status(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<StatusResponse>> {
    let store = require_store(&state)?;
    Ok(Json(
        status_core(store, &state.public_url, &actor, id).await?,
    ))
}

/// Shared poll path used by the REST handler AND the built-in MCP tool. A
/// maker only ever sees its OWN request; a request belonging to another
/// maker (or a non-existent id) is a 404, never 403, so the endpoint can't
/// be used to probe another maker's change ids.
pub async fn status_core(
    store: &SharedChangeRequestStore,
    public_url: &str,
    actor: &Principal,
    id: Uuid,
) -> Result<StatusResponse, ApiError> {
    let cr = store
        .get(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
        .filter(|cr| cr.requested_by == actor.sub)
        .ok_or(ApiError::NotFound("change request not found"))?;
    Ok(status_response(public_url, &cr))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/change_requests",
    tag = "change_requests",
    params(ListQuery),
    responses(
        (status = 200, description = "The caller's own change requests", body = ListResponse),
        (status = 400, description = "Invalid lifecycle filter", body = ApiErrorBody),
        (status = 503, description = "Change-request store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:propose", body = ApiErrorBody),
    ),
)]
async fn list_requests(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<ListResponse>> {
    let store = require_store(&state)?;
    Ok(Json(
        list_core(
            store,
            &state.public_url,
            &actor,
            q.limit,
            q.offset,
            q.lifecycle.as_deref(),
        )
        .await?,
    ))
}

/// Shared list path used by the REST handler AND the built-in MCP tool. A
/// maker sees only its OWN requests, and the `requested_by` filter is pushed
/// into the store so pagination is over the maker's own rows — not a
/// tenant-wide page then filtered (which could omit the maker's older rows
/// behind other makers' and leak coarse presence/order of other makers
/// through offset).
pub async fn list_core(
    store: &SharedChangeRequestStore,
    public_url: &str,
    actor: &Principal,
    limit: u32,
    offset: u32,
    lifecycle: Option<&str>,
) -> Result<ListResponse, ApiError> {
    let lifecycle = match lifecycle {
        None => None,
        Some(s) => Some(parse_lifecycle(s)?),
    };
    let effective_limit = limit.min(MAX_LIST_LIMIT);
    let rows = store
        .list_for_requester(
            actor.tenant.as_str(),
            &actor.sub,
            lifecycle,
            effective_limit,
            offset,
        )
        .await
        .map_err(map_store_err)?;
    let requests = rows
        .into_iter()
        .map(|cr| status_response_summary(public_url, &cr))
        .collect();
    Ok(ListResponse {
        requests,
        limit: effective_limit,
        offset,
    })
}

fn validate_propose(req: &ProposeRequest) -> Result<(), ApiError> {
    if req.action_type.trim().is_empty() {
        return Err(ApiError::BadRequest("action_type must be non-empty".into()));
    }
    // The propose allowlist IS the executor registry — a maker may only
    // propose actions that can actually be executed, so the queue
    // can't fill with intents nothing can ever run.
    if registry().get(&req.action_type).is_none() {
        return Err(ApiError::BadRequest(format!(
            "unknown or non-executable action_type {:?}; proposable actions: {}",
            req.action_type,
            registry().action_types().join(", "),
        )));
    }
    if req.justification.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "justification must be non-empty".into(),
        ));
    }
    // Bound each row at the source so the review UI can render the COMPLETE
    // params without truncation. The approval surfaces separately paginate to
    // preserve the aggregate render bound.
    if let Some(error) = validate_propose_params_size(&req.action_type, &req.params) {
        return Err(ApiError::BadRequest(error));
    }
    // Teach-through-errors: validate `params` against the action's
    // schemars schema BEFORE the change is queued (validate-before-irreversible),
    // so a malformed params object is refused early with a field-level message
    // and a pointer to the schema, instead of deserialising-and-failing only at
    // execute time. The execute-time `from_value` in each executor stays the
    // final guard (it also catches `format`-level issues this check — which
    // treats `format` as an annotation — does not, e.g. a non-UUID string).
    // Single-sourced with the `gateway-admin.preview_change` tool:
    // `validate_action_params` runs the action's schemars schema and returns a
    // payload-safe message per violation (field names/paths/rules, never the
    // offending instance VALUE; an uncompilable schema is logged there and
    // treated as no-objection). The FIRST violation
    // refuses the propose with a pointer to `describe_action`.
    if let Some(detail) =
        crate::change_executor::validate_action_params(&req.action_type, &req.params)
            .into_iter()
            .next()
    {
        return Err(ApiError::BadRequest(format!(
            "params do not match the schema for action {:?}: {detail}. Call the \
             `gateway-admin.describe_action` tool (action_type {:?}) for the exact \
             params shape.",
            req.action_type, req.action_type,
        )));
    }
    if let Some(ttl) = req.ttl_seconds {
        if ttl == 0 {
            return Err(ApiError::BadRequest("ttl_seconds must be > 0".into()));
        }
        if ttl > MAX_TTL_SECONDS {
            return Err(ApiError::BadRequest("ttl_seconds exceeds 24h cap".into()));
        }
    }
    Ok(())
}

/// Append the provenance of any document read out of the file plane to the
/// propose audit reason.
///
/// The change request itself stores only the resolved text, so this entry is
/// the sole durable link from the reviewed document back to the upload that
/// produced it. Only the URI, digest, and byte count travel — the bytes are
/// already in the change request, and the audit log is not a second copy.
fn describe_resolved_files(files: &[ResolvedParamFile]) -> String {
    if files.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = files
        .iter()
        .map(|f| {
            format!(
                "{}=<{} sha256={} bytes={}>",
                f.pointer.trim_start_matches('/'),
                f.uri,
                f.sha256,
                f.size
            )
        })
        .collect();
    format!(" uploaded={}", parts.join(","))
}

/// Return the proposal-row size violation for `params`, if any.
///
/// The MCP preview path shares this exact check with proposal creation so a
/// candidate reported as valid will fit in the review queue and render in full
/// for the approver.
pub fn validate_propose_params_size(action_type: &str, params: &Value) -> Option<String> {
    let params_bytes = serde_json::to_vec(params).map(|v| v.len()).unwrap_or(0);
    let max_params_bytes = max_propose_params_bytes(action_type);
    (params_bytes > max_params_bytes).then(|| {
        format!(
            "params too large ({params_bytes} bytes); the cap is {max_params_bytes} bytes \
             (the review UI renders the full params for the approver, so they're bounded at propose)"
        )
    })
}

fn parse_lifecycle(s: &str) -> Result<ChangeRequestLifecycle, ApiError> {
    match s {
        "pending" => Ok(ChangeRequestLifecycle::Pending),
        "expired" => Ok(ChangeRequestLifecycle::Expired),
        "decided" => Ok(ChangeRequestLifecycle::Decided),
        other => Err(ApiError::BadRequest(format!(
            "unknown lifecycle {other:?}; use pending|expired|decided"
        ))),
    }
}

/// Map the stored status to the CIBA-style poll status. A `pending` row
/// past its expiry reads as `expired` even before any sweep flips the
/// physical column (`ChangeRequest::effective_status`).
fn ciba_status(cr: &ChangeRequest, now: OffsetDateTime) -> &'static str {
    status_name(cr.effective_status(now))
}

fn status_name(status: ChangeRequestStatus) -> &'static str {
    match status {
        ChangeRequestStatus::Pending => "authorization_pending",
        ChangeRequestStatus::Approved => "approved",
        ChangeRequestStatus::Executing => "executing",
        ChangeRequestStatus::Executed => "executed",
        ChangeRequestStatus::Failed => "failed",
        ChangeRequestStatus::Denied => "denied",
        ChangeRequestStatus::Expired => "expired",
    }
}

fn status_response_summary(public_url: &str, cr: &ChangeRequestStatusSummary) -> StatusResponse {
    StatusResponse {
        change_request_id: cr.id,
        status: status_name(cr.effective_status(OffsetDateTime::now_utc())).to_owned(),
        binding_code: cr.binding_code.clone(),
        action_type: cr.action_type.clone(),
        expires_at: format_ts_rfc3339(cr.expires_at),
        interval: DEFAULT_POLL_INTERVAL_SECONDS,
        approver: cr.approver_sub.clone(),
        denied_reason: cr.denied_reason.clone(),
        execution_result: cr.execution_result.clone(),
        error_message: cr.error_message.clone(),
        approval_url: approval_url(public_url, cr.id),
    }
}

fn status_response(public_url: &str, cr: &ChangeRequest) -> StatusResponse {
    StatusResponse {
        change_request_id: cr.id,
        status: ciba_status(cr, OffsetDateTime::now_utc()).to_owned(),
        binding_code: cr.binding_code.clone(),
        action_type: cr.action_type.clone(),
        expires_at: format_ts_rfc3339(cr.expires_at),
        interval: DEFAULT_POLL_INTERVAL_SECONDS,
        approver: cr.approver_sub.clone(),
        denied_reason: cr.denied_reason.clone(),
        execution_result: cr.execution_result.clone(),
        error_message: cr.error_message.clone(),
        approval_url: approval_url(public_url, cr.id),
    }
}

fn approval_url(public_url: &str, id: Uuid) -> String {
    // Select the tenant-scoped pending row before scrolling to its anchor, so
    // newer requests cannot push the requested review outside the bounded
    // pending page. There is deliberately no per-id GET route; the dashboard
    // query remains behind the same operator authorization as the queue.
    format!(
        "{}/admin/changes?pending_id={}#change-{}",
        public_url.trim_end_matches('/'),
        id,
        id
    )
}

fn poll_url(public_url: &str, id: Uuid) -> String {
    format!(
        "{}/api/v1/admin/change_requests/{}",
        public_url.trim_end_matches('/'),
        id
    )
}

fn map_store_err(e: ChangeRequestError) -> ApiError {
    match e {
        ChangeRequestError::Database(_) => ApiError::Internal(format!("change-request store: {e}")),
        // Validation variants — the handler validates first, but map
        // these to 400 as a backstop rather than leaking a 500.
        ChangeRequestError::EmptyJustification
        | ChangeRequestError::EmptyActionType
        | ChangeRequestError::InvalidApprovalCount(_)
        | ChangeRequestError::InvalidCooldown(_)
        | ChangeRequestError::EmptyEligibleRole
        | ChangeRequestError::UnknownFactor(_) => ApiError::BadRequest(e.to_string()),
    }
}

// ---- Decision surface (approve / deny) — operator, mcp:admin ----

/// Body for `POST /api/v1/admin/change_requests/{id}/deny`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DenyRequest {
    /// Why the change was refused. Required, non-empty — returned to the
    /// maker so it can adjust, and audited.
    pub reason: String,
}

/// Response to approve/deny — the change's status after the decision plus,
/// for an executed approve, the execution outcome (execute-on-approval).
#[derive(Debug, Serialize, ToSchema)]
pub struct DecisionResponse {
    pub change_request_id: Uuid,
    /// Status after the decision: `executed` / `failed` (approve that ran),
    /// `denied` (deny), or — for a partial multi-approver approval that
    /// hasn't yet reached quorum — still `pending` (the recorded approval
    /// counts, but more distinct approvers are needed before it executes).
    pub status: String,
    pub action_type: String,
    pub approver: Option<String>,
    pub denied_reason: Option<String>,
    /// The executor's result JSON when `status = executed`.
    #[schema(value_type = Object)]
    pub execution_result: Option<Value>,
    /// The failure message when `status = failed`.
    pub error_message: Option<String>,
}

/// Optional approval acknowledgement. Manifest changes and
/// `policy.upsert_fragment` require an explicit
/// `effect_preview_acknowledged: true` after the operator reviews the computed
/// effect. Other actions ignore the field. The former policy-specific field
/// name remains accepted for existing API clients.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ApproveRequest {
    /// Must be `true` for manifest changes and `policy.upsert_fragment` after
    /// reviewing the current effect preview. Ignored for other actions.
    #[serde(default, alias = "policy_preview_acknowledged")]
    pub effect_preview_acknowledged: bool,
}

/// Whether approval of this action consumes an explicit, current effect-preview
/// acknowledgement. Kept shared so the API guard and both dashboard surfaces
/// describe the same set of governed actions.
pub(crate) fn requires_effect_preview_acknowledgement(action_type: &str) -> bool {
    matches!(
        action_type,
        "policy.upsert_fragment"
            | "manifest.publish"
            | "manifest.rollback"
            | "manifest.stage_and_publish"
            | "manifest.upsert_servers"
            | "manifest.remove_servers"
    )
}

impl DecisionResponse {
    fn from_cr(cr: &ChangeRequest) -> Self {
        Self {
            change_request_id: cr.id,
            status: cr.status.as_db_str().to_owned(),
            action_type: cr.action_type.clone(),
            approver: cr.approver_sub.clone(),
            denied_reason: cr.denied_reason.clone(),
            execution_result: cr.execution_result.clone(),
            error_message: cr.error_message.clone(),
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/change_requests/{id}/approve",
    tag = "change_requests",
    params(("id" = Uuid, Path, description = "Change request id")),
    request_body = ApproveRequest,
    responses(
        (status = 200, description = "Decision recorded. For a single-approver change (or the approval that completes an M-of-N quorum): executed (or recorded failed). For a partial M-of-N approval: still `pending`, awaiting more distinct approvers — body status reflects which.", body = DecisionResponse),
        (status = 404, description = "Not found", body = ApiErrorBody),
        (status = 403, description = "Missing eligible role, missing fresh dashboard authentication assurance, or lacks mcp:admin", body = ApiErrorBody),
        (status = 409, description = "Not approvable (cooldown active, already decided, expired, or mandatory effect preview not acknowledged/available/successful)", body = ApiErrorBody),
        (status = 422, description = "Execution rejected the captured params", body = ApiErrorBody),
        (status = 503, description = "Store/dependency not configured", body = ApiErrorBody),
    ),
)]
async fn approve_request(
    State(state): State<Arc<AdminState>>,
    Extension(approver): Extension<Principal>,
    session: Option<Extension<Session>>,
    Path(id): Path<Uuid>,
    body: Option<Json<ApproveRequest>>,
) -> ApiResult<Json<DecisionResponse>> {
    let session = session.as_ref().map(|Extension(s)| s);
    let preview_acknowledged = body
        .as_ref()
        .is_some_and(|Json(body)| body.effect_preview_acknowledged);
    let outcome =
        approve_and_execute_core(&state, &approver, id, session, preview_acknowledged).await?;
    Ok(Json(DecisionResponse::from_cr(&outcome)))
}

/// Shared approve+execute path used by the REST handler AND the dashboard
/// form. Single-approver: atomic approve (or resume of a stranded
/// `approved` row), approve audit, execute-on-approval — returns the
/// terminal change request (`executed` / `failed`). Multi-approver
/// (`required_approvals > 1`): records one distinct approval and executes
/// only once the quorum is met; a partial approval returns the still-
/// `pending` change without executing. Every path enforces the frozen
/// eligible-role, session-factor, proposal-age cooldown, and mandatory effect
/// preview bar before an approval-state write.
pub(crate) async fn approve_and_execute_core(
    state: &Arc<AdminState>,
    approver: &Principal,
    id: Uuid,
    session: Option<&Session>,
    effect_preview_acknowledged: bool,
) -> Result<ChangeRequest, ApiError> {
    let store = state.hitl.change_requests.require()?;
    let tenant = approver.tenant.as_str();
    let existing = store
        .get(tenant, id)
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::NotFound("change request not found"))?;
    let now = OffsetDateTime::now_utc();
    let effective_status = existing.effective_status(now);
    if !matches!(
        effective_status,
        ChangeRequestStatus::Pending | ChangeRequestStatus::Approved
    ) {
        return Err(approve_refusal(&existing));
    }
    enforce_approval_requirement(&existing, approver, session, now)?;
    enforce_mandatory_effect_preview(state, &existing, effect_preview_acknowledged).await?;
    let approved = match effective_status {
        ChangeRequestStatus::Pending if existing.required_approvals > 1 => {
            // Multi-approver (M-of-N): collect distinct eligible approvals;
            // execute only once the quorum is met. Separation is enforced by
            // authorization rather than identity inequality: a propose-only
            // maker cannot reach this mcp:admin boundary, while an eligible
            // admin proposer counts toward the configured quorum.
            let progress = store
                .record_approval(tenant, id, &approver.sub)
                .await
                .map_err(map_store_err)?;
            // Audit only a REAL state change — never a no-op. A repeat
            // approval by the same approver, or one against a since-decided
            // change, records nothing (`recorded == false`); emitting a
            // success "approval recorded" audit for it would be a misleading
            // ledger entry. The quorum-completing approval gets its own
            // message.
            match progress.approved {
                // Quorum met — audit the completion, then execute.
                Some(cr) => {
                    record_mutation(
                        state,
                        "ChangeRequestApprove",
                        AuditOutcome::Success,
                        approver,
                        format!(
                            "approval {}/{} completed the quorum for change id={} action={} requested_by={}",
                            progress.collected,
                            progress.required,
                            existing.id,
                            existing.action_type,
                            existing.requested_by
                        ),
                        existing.action_type.clone(),
                    )
                    .await?;
                    cr
                }
                // Quorum not yet met. Audit any approval COUNTED toward the
                // live quorum — newly recorded OR a retry/duplicate of an
                // already-counted one — so a quorum-counting approval is
                // never left without a ChangeRequestApprove row even if a
                // post-commit audit failed on a prior attempt and the
                // approver retried. A non-counted no-op
                // (maker / decided / expired) is genuinely nothing and isn't
                // audited; the wording only claims a NEW approval when
                // `recorded`. Then re-read the row so the response reflects
                // its CURRENT state rather than the pre-record snapshot —
                // e.g. a concurrently denied/expired change surfaces as
                // decided, not a stale `pending`.
                None => {
                    if progress.counted {
                        let detail = if progress.recorded {
                            format!(
                                "recorded approval {}/{} for change id={} action={} requested_by={}",
                                progress.collected,
                                progress.required,
                                existing.id,
                                existing.action_type,
                                existing.requested_by
                            )
                        } else {
                            format!(
                                "approval by {} already counted toward {}/{} for change id={} action={} (no new approval recorded)",
                                approver.sub,
                                progress.collected,
                                progress.required,
                                existing.id,
                                existing.action_type
                            )
                        };
                        record_mutation(
                            state,
                            "ChangeRequestApprove",
                            AuditOutcome::Success,
                            approver,
                            detail,
                            existing.action_type.clone(),
                        )
                        .await?;
                    }
                    return store
                        .get(tenant, id)
                        .await
                        .map_err(map_store_err)?
                        .ok_or(ApiError::NotFound("change request not found"));
                }
            }
        }
        ChangeRequestStatus::Pending => {
            // Single-approver fast path — the count=1 guard lives in the
            // store UPDATE. An eligible admin proposer may satisfy it; a
            // propose-only maker cannot reach this approval boundary.
            let approved = match store
                .try_approve(tenant, id, &approver.sub)
                .await
                .map_err(map_store_err)?
            {
                Some(cr) => cr,
                None => return Err(approve_refusal(&existing)),
            };
            record_mutation(
                state,
                "ChangeRequestApprove",
                AuditOutcome::Success,
                approver,
                format!(
                    "approved change id={} action={} requested_by={}",
                    approved.id, approved.action_type, approved.requested_by
                ),
                approved.action_type.clone(),
            )
            .await?;
            approved
        }
        ChangeRequestStatus::Approved => {
            // Resume a row already `approved` but not yet executed. Emit
            // ChangeRequestApprove BEFORE execute so the side effect is
            // always preceded by a durable approve audit even when the
            // original approval's audit is what failed. record_required is
            // fail-closed, so execution proceeds only once this lands.
            record_mutation(
                state,
                "ChangeRequestApprove",
                AuditOutcome::Success,
                approver,
                format!(
                    "resumed approval of change id={} action={} \
                     originally approved_by={:?} (execution not yet recorded)",
                    existing.id, existing.action_type, existing.approver_sub
                ),
                existing.action_type.clone(),
            )
            .await?;
            existing
        }
        // Terminal/effectively-expired states returned above before protected
        // approval requirements were evaluated.
        _ => unreachable!("effective approval status was checked above"),
    };
    // The proposal-age cooldown was satisfied before the approval write. Run
    // the captured intent server-side, then record executed / failed.
    execute_approved(state, approver, &approved).await
}

/// Require governed effects to be acknowledged and successfully recomputed
/// before any approval state is consumed. The request's own tenant and captured
/// params are the inputs, so this is the same effect the review queues render.
/// Execution repeats its fail-closed checks to cover dependency or live-state
/// changes after this read-only boundary.
async fn enforce_mandatory_effect_preview(
    state: &AdminState,
    change: &ChangeRequest,
    acknowledged: bool,
) -> Result<(), ApiError> {
    if !requires_effect_preview_acknowledgement(&change.action_type) {
        return Ok(());
    }
    if !acknowledged {
        return Err(ApiError::Conflict(
            "approval requires explicit acknowledgement of the computed effect preview".to_owned(),
        ));
    }
    if change.action_type == "policy.upsert_fragment" {
        let preview = crate::change_policy_preview::policy_change_preview(
            state,
            &change.tenant_id,
            &change.action_type,
            &change.params,
            change.target_etag.as_deref(),
        )
        .await
        .ok_or_else(|| {
            ApiError::Conflict(
                "the mandatory policy effect preview could not be constructed".to_owned(),
            )
        })?;
        if let Some(reason) = preview.mandatory_approval_blocker() {
            return Err(ApiError::Conflict(reason));
        }
        return Ok(());
    }

    let preview = crate::manifest_change_preview::manifest_change_preview_for_request(
        state,
        &change.tenant_id,
        &change.action_type,
        &change.params,
        change.target_etag.as_deref(),
        None,
    )
    .await
    .ok_or_else(|| {
        ApiError::Conflict(
            "the mandatory manifest effect preview could not be constructed".to_owned(),
        )
    })?;
    if let Some(reason) = preview.mandatory_approval_blocker() {
        return Err(ApiError::Conflict(reason));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/change_requests/{id}/deny",
    tag = "change_requests",
    params(("id" = Uuid, Path, description = "Change request id")),
    request_body = DenyRequest,
    responses(
        (status = 200, description = "Denied", body = DecisionResponse),
        (status = 400, description = "Empty reason", body = ApiErrorBody),
        (status = 404, description = "Not found", body = ApiErrorBody),
        (status = 409, description = "Not deniable (already decided / expired)", body = ApiErrorBody),
        (status = 503, description = "Store not configured", body = ApiErrorBody),
    ),
)]
async fn deny_request(
    State(state): State<Arc<AdminState>>,
    Extension(approver): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<DenyRequest>,
) -> ApiResult<Json<DecisionResponse>> {
    let denied = deny_core(&state, &approver, id, &body.reason).await?;
    Ok(Json(DecisionResponse::from_cr(&denied)))
}

/// Shared deny path used by the REST handler AND the dashboard form.
pub(crate) async fn deny_core(
    state: &Arc<AdminState>,
    approver: &Principal,
    id: Uuid,
    reason: &str,
) -> Result<ChangeRequest, ApiError> {
    if reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason must be non-empty".into()));
    }
    let store = state.hitl.change_requests.require()?;
    let tenant = approver.tenant.as_str();
    let existing = store
        .get(tenant, id)
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::NotFound("change request not found"))?;
    let denied = match store
        .try_deny(tenant, id, &approver.sub, reason)
        .await
        .map_err(map_store_err)?
    {
        Some(cr) => cr,
        None => return Err(deny_refusal(&existing)),
    };
    record_mutation(
        state,
        "ChangeRequestDeny",
        AuditOutcome::Success,
        approver,
        format!(
            "denied change id={} action={} reason={:?}",
            denied.id, denied.action_type, denied.denied_reason
        ),
        denied.action_type.clone(),
    )
    .await?;
    Ok(denied)
}

/// Run an approved change's captured intent server-side, then record the
/// outcome. The execution claim (`approved -> executing`) is single-use,
/// and a failed execution lands the row in `failed` LOUDLY (never
/// tombstoned as done) before the error is surfaced to the caller.
async fn execute_approved(
    state: &Arc<AdminState>,
    approver: &Principal,
    approved: &ChangeRequest,
) -> Result<ChangeRequest, ApiError> {
    let store = state.hitl.change_requests.require()?;
    let tenant = approver.tenant.as_str();
    let claimed = store
        .try_begin_execution(tenant, approved.id)
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::Conflict(
            "change request is already executing or executed".into(),
        ))?;

    let Some(executor) = registry().get(&claimed.action_type) else {
        // Propose only admits registered actions, so this is defensive —
        // but fail the row loudly rather than stranding it `executing`.
        let msg = format!(
            "no executor registered for action {:?}",
            claimed.action_type
        );
        mark_failed_audited(state, approver, &claimed, &msg).await?;
        return Err(ApiError::Internal(msg));
    };

    // Freshness guard: if a target etag was captured at propose, re-
    // capture it NOW and refuse if the target changed during the pending
    // window. The update cores do an unconditional `UPDATE … WHERE id`, so an
    // approved stale field set would silently clobber whatever an operator
    // edited in the meantime; failing closed forces a re-propose against the
    // current state. Actions that opt out captured `None` and skip this. The
    // recheck runs AFTER the `executing` claim and BEFORE the side effect, so
    // nothing is clobbered. Executors whose correctness depends on closing the
    // remaining recheck-to-write window bind this same immutable witness into
    // their store mutation through `execute_with_target_etag`; the default
    // executor hook preserves the existing recheck for unconditional update
    // cores. A capture error (can't read the target) also fails closed.
    if let Some(proposed) = claimed.target_etag.as_deref() {
        match executor
            .capture_etag(state, tenant, approver, &claimed.params)
            .await
        {
            Ok(Some(current)) if current == proposed => { /* fresh — proceed */ }
            Ok(_) => {
                let msg = "target changed since this change was proposed; re-propose against \
                           the current state";
                mark_failed_audited(state, approver, &claimed, msg).await?;
                return Err(ApiError::Conflict(msg.into()));
            }
            Err(e) => {
                let msg = format!(
                    "could not verify target freshness before execute: {}",
                    e.message()
                );
                mark_failed_audited(state, approver, &claimed, &msg).await?;
                return Err(exec_error_to_api(&e));
            }
        }
    }

    match executor
        .execute_with_target_etag(
            state,
            tenant,
            approver,
            &claimed.params,
            claimed.target_etag.as_deref(),
        )
        .await
    {
        Ok(outcome) => {
            // Secret-producing actions (e.g. api_key.mint) hand back a
            // one-time plaintext secret. Encrypt + store it BEFORE marking
            // executed so a poll that observes `executed` can always
            // retrieve it via the burn-on-read channel. If delivery fails
            // the side effect has ALREADY run (the key is minted), so we
            // fail the row LOUDLY with the result fingerprint rather than
            // tombstone a half-done change as executed — the operator uses
            // the fingerprint to locate and revoke the orphaned artifact.
            if let Some(secret) = &outcome.secret {
                if let Err(msg) = store_execution_secret(state, &claimed, secret).await {
                    let detail = format!(
                        "side effect completed but secret delivery failed: {msg}; \
                         result={}",
                        outcome.result
                    );
                    mark_failed_audited(state, approver, &claimed, &detail).await?;
                    return Err(ApiError::Internal(format!(
                        "change {} ran its side effect but secret delivery failed: {msg}",
                        claimed.id
                    )));
                }
            }
            let done = store
                .mark_executed(tenant, claimed.id, outcome.result)
                .await
                .map_err(map_store_err)?
                .ok_or(ApiError::Internal(
                    "change request left the `executing` state unexpectedly".into(),
                ))?;
            // The side effect and the `executed` row are already committed
            // here, so a record_required failure leaves an audit gap (the
            // caller gets 500 and investigates). This is the same
            // fail-closed post-commit-audit posture the break-glass /
            // propose paths and the other admin mutation handlers use; the
            // atomic shared-transaction contract (executor store +
            // change_requests row + evidence in one tx) is tracked in
            // issue #151.
            //
            // For an M-of-N change, the per-approval `ChangeRequestApprove`
            // audits are also post-commit,
            // so a counting partial approval whose audit failed would only be
            // re-attributed on a same-approver retry. Naming EVERY distinct
            // approver from the ledger in this fail-closed execute audit closes
            // that gap at the point it matters: no M-of-N change can reach
            // `executed` without a durable audit attributing every approver who
            // counted toward its quorum. (Single-approver changes are already
            // fully attributed by `approver`.) A `list_approvers` read failure
            // fails the audit loud — same posture as any record_required error.
            let attribution = if done.required_approvals > 1 {
                let approvers = store
                    .list_approvers(tenant, done.id)
                    .await
                    .map_err(map_store_err)?;
                format!(" approvers=[{}]", approvers.join(","))
            } else {
                String::new()
            };
            record_mutation(
                state,
                "ChangeRequestExecute",
                AuditOutcome::Success,
                approver,
                format!(
                    "executed change id={} action={}{}",
                    done.id, done.action_type, attribution
                ),
                done.action_type.clone(),
            )
            .await?;
            Ok(done)
        }
        Err(e) => {
            mark_failed_audited(state, approver, &claimed, &e.message()).await?;
            Err(exec_error_to_api(&e))
        }
    }
}

/// Encrypt an executor-produced secret under the configured change-secret
/// keyring and persist it for single-use burn-on-read. Returns a short
/// reason string on failure (the caller marks the change `failed` with it).
/// The plaintext is NEVER logged.
async fn store_execution_secret(
    state: &Arc<AdminState>,
    claimed: &ChangeRequest,
    secret: &[u8],
) -> Result<(), String> {
    let crypto = state.hitl.change_secret_crypto.get().ok_or_else(|| {
        state
            .hitl
            .change_secret_crypto
            .unavailable_msg()
            .to_string()
    })?;
    let ciphertext = crypto
        .encrypt(secret)
        .map_err(|e| format!("encrypt failed: {e}"))?;
    let store = state
        .hitl
        .change_requests
        .get()
        .ok_or_else(|| "change-request store not configured".to_string())?;
    store
        .store_secret(
            &claimed.tenant_id,
            claimed.id,
            &ciphertext,
            crypto.active_id(),
        )
        .await
        .map_err(|e| format!("persist secret failed: {e}"))?;
    Ok(())
}

/// The one-time secret a maker retrieves after a secret-producing change
/// executes (e.g. a freshly minted `mcpgw_…` API key).
#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
pub struct SecretResponse {
    /// The plaintext secret. Shown ONCE — a second retrieve returns 409.
    /// Never logged and returned with `no-store` cache headers.
    pub secret: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/change_requests/{id}/secret",
    tag = "change_requests",
    params(("id" = Uuid, Path, description = "Change request id")),
    responses(
        (status = 200, description = "The one-time secret (shown once)", body = SecretResponse),
        (status = 404, description = "Not found, or not the caller's own request", body = ApiErrorBody),
        (status = 409, description = "Not yet executed, already retrieved, or no secret for this change", body = ApiErrorBody),
        (status = 503, description = "Secret channel not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:propose", body = ApiErrorBody),
    ),
)]
async fn get_request_secret(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let body = retrieve_secret_core(&state, &actor, id).await?;
    let mut resp = Json(body).into_response();
    // "shown once": never cache the secret (mirror the api-key reveal page).
    crate::api_keys::no_store(&mut resp);
    Ok(resp)
}

/// Single-use, maker-only retrieval of an executor-produced secret. A maker
/// sees only its OWN change (404 — never 403 — for another maker's id, the
/// same idiom as [`status_core`], so the endpoint can't probe foreign ids),
/// and only after the change `executed`. The burn is atomic
/// ([`ChangeRequestStore::try_burn_secret`](waygate_changeset::ChangeRequestStore::try_burn_secret)),
/// so a second retrieve — or a race — gets a 409. The plaintext is decrypted
/// just-in-time, returned once, and never logged.
pub async fn retrieve_secret_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    id: Uuid,
) -> Result<SecretResponse, ApiError> {
    let store = require_store(state)?;
    let cr = store
        .get(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
        .filter(|cr| cr.requested_by == actor.sub)
        .ok_or(ApiError::NotFound("change request not found"))?;
    if cr.effective_status(OffsetDateTime::now_utc()) != ChangeRequestStatus::Executed {
        return Err(ApiError::Conflict(
            "secret is only available after the change has executed".into(),
        ));
    }
    let crypto = state.hitl.change_secret_crypto.require()?;
    // Decrypt-BEFORE-burn: produce the plaintext from a read-only peek
    // FIRST, so an operator key/config mistake (the stored key_id no
    // longer in the keyring, etc.) returns an error with `retrieved_at`
    // still NULL — the secret stays retrievable after the key is fixed,
    // instead of being burned-and-lost on the failed attempt.
    let Some(stored) = store
        .get_secret(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
    else {
        return Err(ApiError::Conflict(
            "this change produced no retrievable secret".into(),
        ));
    };
    let plaintext = crypto
        .decrypt(&stored.key_id, &stored.ciphertext)
        .map_err(|e| {
            tracing::error!(
                error = %e,
                change_request_id = %id,
                "change-request: secret decrypt failed (key/config mismatch?) — \
                 NOT burning, secret stays retrievable",
            );
            ApiError::Internal("secret decrypt failed".into())
        })?;
    let secret = String::from_utf8(plaintext)
        .map_err(|_| ApiError::Internal("stored secret is not valid UTF-8".into()))?;
    // Only NOW claim the single-use burn — the plaintext is in hand, so the
    // irreversible stamp can't strand a recoverable secret. The atomic
    // `retrieved_at IS NULL` UPDATE is what enforces single delivery: under a
    // concurrent double-read both decrypt, but only the burn winner returns
    // the secret; the loser gets 409.
    if store
        .try_burn_secret(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
        .is_none()
    {
        return Err(ApiError::Conflict("secret already retrieved".into()));
    }
    // Best-effort audit (NOT fail-closed like mint/propose): the burn above
    // is irreversible, so failing the call after it would lose the secret the
    // maker just claimed. The side effect (e.g. the mint) is already
    // fail-closed-audited at execute time; this is the supplementary
    // "secret retrieved" event — fingerprint only, NEVER the secret.
    state
        .evidence
        .record_best_effort(
            AuditEvent::new("ChangeRequestSecretRetrieve", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(Some(actor))
                .with_target(cr.action_type.clone())
                .with_reason(format!(
                    "retrieved one-time secret for change id={} action={}",
                    cr.id, cr.action_type
                )),
        )
        .await;
    Ok(SecretResponse { secret })
}

/// Mark a claimed (`executing`) change `failed` with `msg` and emit the
/// `ExecutionError` audit. Shared by the no-executor and executor-error
/// paths so the row is always durably `failed` before the caller sees an
/// error.
async fn mark_failed_audited(
    state: &Arc<AdminState>,
    approver: &Principal,
    claimed: &ChangeRequest,
    msg: &str,
) -> Result<(), ApiError> {
    let store = state.hitl.change_requests.require()?;
    store
        .mark_failed(approver.tenant.as_str(), claimed.id, msg)
        .await
        .map_err(map_store_err)?;
    record_mutation(
        state,
        "ChangeRequestExecute",
        AuditOutcome::ExecutionError,
        approver,
        format!(
            "execution FAILED change id={} action={}: {}",
            claimed.id, claimed.action_type, msg
        ),
        claimed.action_type.clone(),
    )
    .await
}

fn approve_refusal(existing: &ChangeRequest) -> ApiError {
    let status = existing.effective_status(OffsetDateTime::now_utc());
    if status != ChangeRequestStatus::Pending {
        return ApiError::Conflict(format!(
            "change request is {} — not pending",
            status.as_db_str()
        ));
    }
    // Multi-approver (required_approvals > 1) is handled by the
    // record_approval path in approve_and_execute_core, never here, so there
    // is no "multi-approval not supported" refusal anymore.
    ApiError::Conflict("change request is no longer approvable".into())
}

fn deny_refusal(existing: &ChangeRequest) -> ApiError {
    if existing.effective_status(OffsetDateTime::now_utc()) != ChangeRequestStatus::Pending {
        ApiError::Conflict(format!(
            "change request is {} — not pending",
            existing.status.as_db_str()
        ))
    } else {
        ApiError::Conflict("change request is no longer deniable".into())
    }
}

fn exec_error_to_api(e: &ExecError) -> ApiError {
    match e {
        ExecError::Precondition(m) => {
            ApiError::Conflict(format!("execution precondition failed: {m}"))
        }
        ExecError::Unavailable(m) => ApiError::ServiceUnavailable(m),
        ExecError::BadParams(m) => {
            ApiError::UnprocessableEntity(format!("execution rejected: {m}"))
        }
        ExecError::Store(m) => ApiError::Internal(format!("execution store error: {m}")),
    }
}

fn capture_error_to_api(e: &ExecError) -> ApiError {
    match e {
        ExecError::Precondition(m) | ExecError::BadParams(m) => {
            ApiError::BadRequest(format!("proposal target rejected: {m}"))
        }
        ExecError::Unavailable(m) => ApiError::ServiceUnavailable(m),
        ExecError::Store(m) => {
            tracing::warn!(error = %m, "change-request: required target capture failed");
            ApiError::Internal("could not read the proposal target".into())
        }
    }
}

async fn record_mutation(
    state: &Arc<AdminState>,
    action: &'static str,
    outcome: AuditOutcome,
    actor: &Principal,
    reason: String,
    // The change's `action_type` (e.g. "api_key.mint"), recorded as the
    // structured `target` column so the overview "What changed" feed and the
    // activity views can name WHAT the ceremony acted on
    // ("ChangeRequestPropose · api_key.mint · <maker>") rather than only WHO.
    target: String,
) -> Result<(), ApiError> {
    state
        .evidence
        .record_required(
            AuditEvent::new(action, outcome)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(Some(actor))
                .with_reason(reason)
                .with_target(target),
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(error = %e, action, "change-request decision audit failed");
            ApiError::Internal(format!("change-request {action} audit failed: {e}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_preview_acknowledgement_covers_every_manifest_mutation() {
        for action in [
            "manifest.publish",
            "manifest.rollback",
            "manifest.stage_and_publish",
            "manifest.upsert_servers",
            "manifest.remove_servers",
            "policy.upsert_fragment",
        ] {
            assert!(
                requires_effect_preview_acknowledgement(action),
                "{action} must require acknowledgement"
            );
        }
        assert!(!requires_effect_preview_acknowledgement("policy.publish"));
        assert!(!requires_effect_preview_acknowledgement("api_key.mint"));
    }

    #[test]
    fn approve_request_accepts_the_legacy_policy_acknowledgement_name() {
        let request: ApproveRequest = serde_json::from_value(serde_json::json!({
            "policy_preview_acknowledged": true
        }))
        .expect("legacy approval body");
        assert!(request.effect_preview_acknowledged);
    }

    #[test]
    fn registry_action_types_are_lowercase_dotted() {
        let types = registry().action_types();
        assert!(!types.is_empty(), "the propose allowlist must be non-empty");
        for a in types {
            assert!(a.contains('.'), "{a} should be a `domain.verb` key");
            assert!(
                a.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "{a} should be lowercase dotted"
            );
        }
    }

    #[test]
    fn validate_propose_rejects_unknown_action() {
        let req = ProposeRequest {
            action_type: "api_key.delete_everything".into(),
            params: serde_json::json!({}),
            justification: "x".into(),
            ttl_seconds: None,
        };
        assert!(matches!(
            validate_propose(&req),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_propose_rejects_empty_justification_and_bad_ttl() {
        let base = || ProposeRequest {
            action_type: "rate_limit.update".into(),
            // Valid params for rate_limit.update so this test isolates the
            // justification / ttl checks now that propose also validates params
            // against the action's schema.
            params: serde_json::json!({
                "policy_id": "00000000-0000-0000-0000-000000000000",
                "bucket_capacity": 10,
            }),
            justification: "ok".into(),
            ttl_seconds: None,
        };
        let mut empty = base();
        empty.justification = "  ".into();
        assert!(matches!(
            validate_propose(&empty),
            Err(ApiError::BadRequest(_))
        ));

        let mut zero_ttl = base();
        zero_ttl.ttl_seconds = Some(0);
        assert!(matches!(
            validate_propose(&zero_ttl),
            Err(ApiError::BadRequest(_))
        ));

        let mut huge_ttl = base();
        huge_ttl.ttl_seconds = Some(MAX_TTL_SECONDS + 1);
        assert!(matches!(
            validate_propose(&huge_ttl),
            Err(ApiError::BadRequest(_))
        ));

        assert!(validate_propose(&base()).is_ok());
    }

    #[test]
    fn validate_propose_rejects_oversized_params() {
        // The review UI renders COMPLETE params (never truncated), so every row
        // is bounded at the source; the queue separately bounds rows per page.
        // A normal payload passes, while an oversized row is refused before it
        // can bloat the review UI.
        let base = || ProposeRequest {
            action_type: "rate_limit.update".into(),
            params: serde_json::json!({ "policy_id": "x", "bucket_capacity": 5 }),
            justification: "ok".into(),
            ttl_seconds: None,
        };
        assert!(validate_propose(&base()).is_ok());

        let mut huge = base();
        huge.params = serde_json::json!({ "blob": "z".repeat(DEFAULT_MAX_PROPOSE_PARAMS_BYTES) });
        assert!(
            matches!(validate_propose(&huge), Err(ApiError::BadRequest(_))),
            "params over the size cap must be refused at propose",
        );
    }

    #[test]
    fn validate_propose_accepts_the_largest_valid_agent_config() {
        // A database-persistable control character takes the maximum six bytes
        // when JSON escaped. This proves the larger action-specific envelope
        // covers the actual validator ceiling, not just typical ASCII input.
        let maximally_escaped = "\u{0001}";
        let config = serde_json::json!({
            "name": maximally_escaped.repeat(64),
            "kind": "classification",
            "model_alias": maximally_escaped.repeat(128),
            "instructions": maximally_escaped.repeat(8_000),
            "allowed_tools": vec![maximally_escaped.repeat(256); 200],
            "max_steps": 100,
            "max_tool_calls": 500,
            "token_budget": i32::MAX,
            "enabled": true,
        });
        let parsed: crate::agent_configs::AgentConfigInput =
            serde_json::from_value(config.clone()).expect("maximum config deserializes");
        crate::agent_configs::validate(&parsed).expect("maximum config passes shared validation");

        for (action_type, params) in [
            ("agent_config.create", config.clone()),
            (
                "agent_config.update",
                serde_json::json!({
                    "agent_id": "00000000-0000-0000-0000-000000000000",
                    "config": config,
                }),
            ),
        ] {
            let serialized_len = serde_json::to_vec(&params).unwrap().len();
            assert!(
                serialized_len > DEFAULT_MAX_PROPOSE_PARAMS_BYTES,
                "fixture must exercise the action-specific envelope"
            );
            assert!(
                serialized_len <= DOCUMENT_MAX_PROPOSE_PARAMS_BYTES,
                "validator ceiling must fit the bounded proposal envelope"
            );
            let request = ProposeRequest {
                action_type: action_type.into(),
                params,
                justification: "review the complete agent configuration".into(),
                ttl_seconds: None,
            };
            validate_propose(&request)
                .unwrap_or_else(|error| panic!("{action_type} maximum config rejected: {error:?}"));
        }
    }

    #[test]
    fn every_document_carrying_action_gets_the_larger_params_envelope() {
        // An action that accepts an uploaded document but is still bounded by
        // the scalar default would refuse the very submissions the upload path
        // exists to carry: the file would read successfully and the proposal
        // would then be rejected for size. The two declarations are made in
        // different files, so tie them together here.
        let reg = crate::change_executor::registry();
        let mut document_actions = 0;
        for action_type in reg.action_types() {
            if reg.file_params(action_type).is_empty() {
                continue;
            }
            document_actions += 1;
            assert_eq!(
                max_propose_params_bytes(action_type),
                DOCUMENT_MAX_PROPOSE_PARAMS_BYTES,
                "{action_type} accepts an uploaded document, so it needs the document envelope",
            );
        }
        assert!(document_actions > 0, "no action accepts an upload");
    }

    #[test]
    fn a_full_manifest_set_no_longer_hits_the_scalar_params_ceiling() {
        // The concrete regression: a real manifest set outgrew the scalar
        // default and could not be proposed at all, by upload or inline.
        let content = "- name: example-messages\n  transport: http\n".repeat(1_000);
        let params = serde_json::json!({ "base_hash": "h", "content": content });
        let serialized_len = serde_json::to_vec(&params).unwrap().len();
        assert!(
            serialized_len > DEFAULT_MAX_PROPOSE_PARAMS_BYTES,
            "fixture must exceed the scalar default to exercise the envelope",
        );
        assert!(
            validate_propose_params_size("manifest.stage_and_publish", &params).is_none(),
            "a manifest set of this size must fit the document envelope",
        );
        // The envelope is per-action, not a global relaxation: an action that
        // carries scalars is still held to the smaller bound.
        assert!(
            validate_propose_params_size("manifest.rollback", &params).is_some(),
            "a scalar action must keep the tighter ceiling",
        );
    }

    #[test]
    fn validate_propose_rejects_params_missing_required_field() {
        // rate_limit.update requires `policy_id`; omitting it is refused at
        // propose (not deferred to execute), with a message that names the
        // field and points the maker at the discovery tool instead of guessing.
        let req = ProposeRequest {
            action_type: "rate_limit.update".into(),
            params: serde_json::json!({ "bucket_capacity": 10 }),
            justification: "raise the cap".into(),
            ttl_seconds: None,
        };
        match validate_propose(&req) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("policy_id"), "names the missing field: {msg}");
                assert!(
                    msg.contains("describe_action"),
                    "points at the discovery tool: {msg}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_propose_rejects_params_wrong_type() {
        // bucket_capacity is an integer; a string value is refused at propose.
        let req = ProposeRequest {
            action_type: "rate_limit.update".into(),
            params: serde_json::json!({
                "policy_id": "00000000-0000-0000-0000-000000000000",
                "bucket_capacity": "lots",
            }),
            justification: "raise the cap".into(),
            ttl_seconds: None,
        };
        assert!(matches!(
            validate_propose(&req),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_propose_accepts_well_formed_params() {
        let req = ProposeRequest {
            action_type: "rate_limit.update".into(),
            params: serde_json::json!({
                "policy_id": "00000000-0000-0000-0000-000000000000",
                "bucket_capacity": 10,
                "refill_per_second": 2.5,
            }),
            justification: "raise the cap".into(),
            ttl_seconds: None,
        };
        assert!(validate_propose(&req).is_ok());
    }

    #[test]
    fn parse_lifecycle_maps_known_and_rejects_unknown() {
        assert_eq!(
            parse_lifecycle("pending").unwrap(),
            ChangeRequestLifecycle::Pending
        );
        assert_eq!(
            parse_lifecycle("decided").unwrap(),
            ChangeRequestLifecycle::Decided
        );
        assert!(parse_lifecycle("bogus").is_err());
    }

    #[derive(Default)]
    struct RecordingNotifier {
        last: std::sync::Mutex<Option<ChangeProposedNotification>>,
    }

    impl crate::change_notify::ChangeRequestNotifier for RecordingNotifier {
        fn notify_change_proposed(&self, payload: ChangeProposedNotification) {
            *self.last.lock().unwrap() = Some(payload);
        }
    }

    fn maker(sub: &str) -> Principal {
        Principal {
            sub: sub.into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: vec!["mcp:propose".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[tokio::test]
    async fn propose_core_fires_notifier_with_operator_safe_summary_only() {
        let store: SharedChangeRequestStore =
            Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
        let evidence: SharedEvidence = Arc::new(waygate_mcp::audit::InMemorySink::default());
        let notifier = Arc::new(RecordingNotifier::default());
        let shared: SharedChangeNotifier = notifier.clone();

        let req = ProposeRequest {
            action_type: "rate_limit.update".into(),
            // Valid params for the action (propose validates against the
            // action's schema) with the leak sentinel riding an extra
            // field — schemars schemas don't
            // forbid additional properties, so this still passes validation while
            // carrying a value the notifier payload must never echo.
            params: serde_json::json!({
                "policy_id": "00000000-0000-0000-0000-000000000000",
                "bucket_capacity": 10,
                "secret_param": "do-not-leak",
            }),
            justification: "sensitive context that must stay behind the dashboard".into(),
            ttl_seconds: None,
        };
        let resp = propose_core(
            &store,
            &evidence,
            "https://gw.example",
            Some(&shared),
            &maker("agent-1"),
            req,
            SubmissionContext::default(),
        )
        .await
        .expect("propose");

        let got = notifier
            .last
            .lock()
            .unwrap()
            .clone()
            .expect("notifier must fire on a successful propose");
        // Carries the operator-safe summary + deep link, matching the response.
        assert_eq!(got.change_request_id, resp.change_request_id);
        assert_eq!(got.action_type, "rate_limit.update");
        assert_eq!(got.requested_by, "agent-1");
        assert_eq!(got.binding_code, resp.binding_code);
        assert_eq!(got.approval_url, resp.approval_url);
        // The sensitive params/justification must NOT appear in ANY field of
        // the notification — the human clicks through to the authenticated
        // dashboard for detail. (The payload struct has no such field, so this
        // can only regress if someone widens it.)
        for field in [
            &got.tenant_id,
            &got.action_type,
            &got.requested_by,
            &got.binding_code,
            &got.approval_url,
        ] {
            assert!(!field.contains("do-not-leak"), "params leaked: {field}");
            assert!(
                !field.contains("sensitive context"),
                "justification leaked: {field}"
            );
        }
    }

    #[tokio::test]
    async fn propose_core_with_no_notifier_still_succeeds() {
        let store: SharedChangeRequestStore =
            Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
        let evidence: SharedEvidence = Arc::new(waygate_mcp::audit::InMemorySink::default());
        let resp = propose_core(
            &store,
            &evidence,
            "https://gw.example",
            None,
            &maker("agent-1"),
            ProposeRequest {
                action_type: "rate_limit.update".into(),
                params: serde_json::json!({
                    "policy_id": "00000000-0000-0000-0000-000000000000",
                    "bucket_capacity": 10,
                }),
                justification: "ok".into(),
                ttl_seconds: None,
            },
            SubmissionContext::default(),
        )
        .await
        .expect("propose without a notifier must still succeed");
        assert_eq!(resp.status, "pending");
    }
}
