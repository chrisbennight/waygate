//! `/api/v1/admin/approval_grants` — operator surface for the HITL
//! (human-in-the-loop) approval grants the per-call gate
//! [`waygate_mcp::DefaultInvocationService::check_approval`]
//! consumes.
//!
//! Operators see "approval required" responses on the caller side
//! and resolve them here:
//!
//! - `POST   /api/v1/admin/approval_grants` — mint one. The body
//!   names the principal, the qualified `<server>.<tool>`, the
//!   call arguments (or pre-computed argument_hash), an expiry,
//!   and an optional reason. The handler resolves the
//!   `<server>.<tool>` to a catalog `tool_id` + `server_id` and
//!   combines the current behavior hash with the canonical argument
//!   digest so an approval is tightly bound to both the reviewed tool
//!   version and the call shape the admin vetted.
//! - `GET    /api/v1/admin/approval_grants?principal_sub=&tool=` —
//!   list live (or, with `include_consumed=true`, historical)
//!   grants for the caller's tenant.
//! - `DELETE /api/v1/admin/approval_grants/{id}` — revoke a grant
//!   (sets `consumed_at = now()` so the next `find_grant` /
//!   `claim_grant` excludes it). Closes ANY grant that is still
//!   `consumed_at IS NULL` — this includes an expired-but-unconsumed
//!   row, since the store keys only on `consumed_at`, not
//!   `expires_at`. 404 covers both "no such grant" and "already
//!   consumed/revoked" so an attacker probing IDs can't distinguish
//!   them.
//!
//! All three are gated by `mcp:admin`. The catalog store is the
//! durability boundary (`waygate_catalog::CatalogStore`); when no
//! catalog is wired the endpoints 503 (matches the existing
//! `/api/v1/catalog/*` pattern).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{middleware, Extension, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use waygate_catalog::{
    GrantExecutionBinding, GrantFilter, NewApprovalGrant, ResolvedTool, SharedCatalogStore,
};
use waygate_core::TenantId;
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/approval_grants",
            axum::routing::post(create_grant).get(list_grants),
        )
        .route(
            "/api/v1/admin/approval_grants/{id}",
            axum::routing::delete(revoke_grant),
        )
        .route(
            "/api/v1/admin/codemode/approval_requests",
            axum::routing::get(list_codemode_approval_requests),
        )
        .route(
            "/api/v1/admin/codemode/approval_requests/{id}/approve",
            axum::routing::post(approve_codemode_request),
        )
        .route(
            "/api/v1/admin/codemode/approval_requests/{id}/deny",
            axum::routing::post(deny_codemode_request),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

/// Minimum / maximum grant lifetime. Hard caps so an operator
/// can't mint a perpetual approval (which would defeat the
/// by-request HITL model) or a sub-second grant (which would
/// race the caller's retry).
const MIN_EXPIRES_IN: Duration = Duration::from_secs(60);
const MAX_EXPIRES_IN: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 7 days
const DEFAULT_EXPIRES_IN: Duration = Duration::from_secs(15 * 60); // 15 minutes

// `deny_unknown_fields`: silently accepting an unrecognized field
// would let an operator script send a field the server no longer
// honors (e.g. a stale `client_id`) and have its grant minted as
// any-client instead of the intended client-scoped binding, with no
// indication anything went wrong. Strict serde rejection turns that
// into a clean 400 the caller can act on — and applies the same
// protection to any future field this struct removes or renames.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateGrantRequest {
    /// The end-user whose call this approval will satisfy. Matched
    /// against `Principal.sub` at dispatch time.
    pub principal_sub: String,
    /// Issuer that minted the requester's `sub`. Matched exactly against
    /// `Principal.issuer` at dispatch time — two issuers may mint the same
    /// `sub` for different people, so a grant without the right issuer
    /// must not satisfy the call. Take it from the `HitlApprovalNeeded`
    /// notification.
    pub principal_issuer: String,
    /// Qualified tool name (`<server>.<tool>`). Resolved against
    /// the catalog so the grant binds to the catalog's
    /// `tool_id` + `server_id` rather than the (possibly
    /// reassignable) string name.
    pub tool: String,
    /// One of `arguments` / `argument_hash` is required. When
    /// `arguments` is set the handler computes the canonical
    /// argument digest server-side so the operator and the caller
    /// can't disagree on canonicalization. When `argument_hash` is
    /// set, it is that same raw canonical argument digest (advanced
    /// flow; useful for an approval-needed event). The gateway
    /// combines either form with the current approved behavior hash
    /// before storage, so a later tool-version change cannot reuse
    /// the grant.
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    #[serde(default)]
    pub argument_hash: Option<String>,
    /// Reviewed behavior hash of the tool version the approver reviewed. It
    /// binds the human decision to that exact contract: if the tool's approved
    /// behavior changed between review and this POST, minting refuses (409)
    /// rather than silently authorizing the new, unreviewed version. Operators
    /// take it from the `HitlApprovalNeeded` notification or the tool's catalog
    /// entry.
    pub behavior_hash: String,
    /// Lifetime in seconds. Capped to
    /// `[MIN_EXPIRES_IN, MAX_EXPIRES_IN]`. Defaults to 15 minutes
    /// when omitted — long enough for a caller to retry after
    /// seeing the `approval_required` response, short enough that a
    /// stale grant doesn't sit around.
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
    /// Optional human-readable reason ("ticket #4242: approved by
    /// security review"). Recorded verbatim.
    #[serde(default)]
    pub reason: Option<String>,
    // `client_id` scoping is intentionally absent from this request
    // shape: the per-call HITL gate currently has no
    // `Principal.client_id` to supply, so any client-scoped grant
    // minted today couldn't be claimed — `(client_id IS NULL OR
    // client_id = $5)` with $5=NULL reduces to `client_id IS NULL`.
    // The field will re-appear alongside the lookup-side wiring so
    // they ship symmetrically.
}

/// JSON shape returned to admin callers. Mirrors `ApprovalGrant`
/// but uses ISO-8601 string timestamps for stable serialization.
#[derive(Debug, Serialize, ToSchema)]
pub struct GrantView {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_sub: String,
    /// Issuer that minted the requester's `sub`; absent only on
    /// pre-upgrade grants, which no claim can match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub server_id: Uuid,
    pub tool_id: Uuid,
    /// Stored approval-binding digest covering behavior version and arguments.
    pub argument_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_binding: Option<GrantExecutionBindingView>,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<String>,
    pub approver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GrantExecutionBindingView {
    pub execution_id: Uuid,
    pub source_digest: String,
    pub call_id: Uuid,
}

impl From<waygate_catalog::ApprovalGrant> for GrantView {
    fn from(g: waygate_catalog::ApprovalGrant) -> Self {
        GrantView {
            id: g.id,
            tenant_id: g.tenant_id,
            principal_sub: g.principal_sub,
            principal_issuer: g.principal_issuer,
            client_id: g.client_id,
            server_id: g.server_id,
            tool_id: g.tool_id,
            argument_hash: g.argument_hash,
            execution_binding: g
                .execution_binding
                .map(|binding| GrantExecutionBindingView {
                    execution_id: binding.execution_id,
                    source_digest: binding.source_digest,
                    call_id: binding.call_id,
                }),
            expires_at: format_ts_rfc3339(g.expires_at),
            consumed_at: g.consumed_at.map(format_ts_rfc3339),
            approver: g.approver,
            reason: g.reason,
            created_at: format_ts_rfc3339(g.created_at),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GrantListResponse {
    pub grants: Vec<GrantView>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeModeApprovalRequestView {
    pub connector: String,
    pub operation: String,
    pub argument_hash: String,
    pub arguments_preview: serde_json::Value,
    pub risk: String,
    pub source_digest: String,
    pub call_id: Uuid,
    pub step: u32,
    pub contract: serde_json::Value,
    pub prior_effects: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PendingCodeModeApprovalView {
    pub execution_id: Uuid,
    pub principal_sub: String,
    /// Issuer that minted the requester's `sub`; absent on pre-upgrade
    /// executions, which cannot be approved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_issuer: Option<String>,
    pub submitted_at: String,
    pub updated_at: String,
    pub request: CodeModeApprovalRequestView,
    /// Canonical digest of the durable request as reviewed. An approval must
    /// echo it, binding the decision to this exact request rather than to
    /// whichever request is pending for the execution when the POST lands.
    pub request_digest: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PendingCodeModeApprovalList {
    pub approvals: Vec<PendingCodeModeApprovalView>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeModeApprovalDecision {
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
    /// The `request_digest` from the pending-approval listing. Required to
    /// approve: it proves which exact request the administrator reviewed, so
    /// a request that changed underneath refuses the stale decision. Denial
    /// verifies it only when supplied — refusing whatever is pending confers
    /// no authority.
    #[serde(default)]
    pub request_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListGrantsQuery {
    #[serde(default)]
    pub principal_sub: Option<String>,
    /// Qualified tool name `<server>.<tool>` to filter by. Resolved
    /// to a catalog `tool_id` server-side; unknown tools yield
    /// empty results (a tighter 404 would leak existence of a
    /// catalog row).
    #[serde(default)]
    pub tool: Option<String>,
    /// Include consumed / expired rows. Defaults to false — the
    /// operator's "pending approvals" view.
    #[serde(default)]
    pub include_consumed: bool,
}

fn catalog_store(state: &AdminState) -> ApiResult<&SharedCatalogStore> {
    state.servers.catalog.require()
}

fn caller_tenant(principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| TenantId::DEFAULT.to_owned())
}

fn grant_lifetime(seconds: Option<u64>) -> (Duration, OffsetDateTime) {
    let lifetime = seconds
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_EXPIRES_IN)
        .max(MIN_EXPIRES_IN)
        .min(MAX_EXPIRES_IN);
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(lifetime.as_secs() as i64);
    (lifetime, expires_at)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/approval_grants",
    tag = "approval_grants",
    request_body = CreateGrantRequest,
    responses(
        (status = 201, description = "Grant minted", body = GrantView),
        (status = 400, description = "Bad request (missing args, bad tool format, …)", body = ApiErrorBody),
        (status = 404, description = "Tool not Live in caller's catalog", body = ApiErrorBody),
        (status = 409, description = "Self-approval (separation of duty), or reviewed behavior_hash no longer matches the tool's approved behavior", body = ApiErrorBody),
        (status = 503, description = "Catalog store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn create_grant(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<CreateGrantRequest>,
) -> ApiResult<(StatusCode, Json<GrantView>)> {
    let catalog = catalog_store(&state)?;
    let p = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(p);
    // Approver is the calling admin's sub; matches the existing
    // catalog-approval pattern.
    let approver = p.map(|p| p.sub.as_str()).unwrap_or("dev@local").to_owned();
    let approver_issuer = p.map(|p| p.issuer.as_str()).unwrap_or("dev@local");

    // Separation of duty: an approver may not grant a call for their own
    // principal. For any approval-required tool this is the human/second-party
    // gate — a self-mint would let one `mcp:admin` principal authorize its own
    // approval-required call. Requiring a DIFFERENT principal to approve
    // enforces that gate structurally, independent of the caller's auth method.
    // The comparison is the full identity (issuer + sub): two issuers may
    // mint the same `sub` for different people, and a bare-sub comparison
    // would wrongly block that legitimate cross-issuer approval while
    // catching nothing extra.
    if approver == body.principal_sub && approver_issuer == body.principal_issuer {
        return Err(ApiError::Conflict(
            "an approver may not grant a call for their own principal".to_owned(),
        ));
    }

    // Argument binding: exactly one of `arguments` / `argument_hash`
    // must be present. Both-set is rejected as `400` so an operator
    // can't accidentally bind to a stale pre-computed hash that
    // disagrees with the passed-through args.
    let raw_argument_hash = match (&body.arguments, &body.argument_hash) {
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "specify exactly one of `arguments` / `argument_hash`, not both".into(),
            ));
        }
        (None, None) => {
            return Err(ApiError::BadRequest(
                "must specify either `arguments` or `argument_hash`".into(),
            ));
        }
        (Some(args), None) => match args {
            // `null` is treated as "no arguments" — matches the
            // pool-side `argument_hash(None)` semantics so an
            // empty-args grant covers an empty-args call.
            serde_json::Value::Null => waygate_catalog::argument_hash(None),
            serde_json::Value::Object(map) => waygate_catalog::argument_hash(Some(map)),
            _ => {
                return Err(ApiError::BadRequest(
                    "`arguments` must be a JSON object or null".into(),
                ));
            }
        },
        (None, Some(h)) => {
            if h.trim().is_empty() {
                return Err(ApiError::BadRequest(
                    "`argument_hash` must be non-empty".into(),
                ));
            }
            h.clone()
        }
    };

    // Tool resolution: must be a `<server>.<tool>` qualified name
    // that's Live in the caller's tenant catalog. Quarantined /
    // PendingApproval / NotFound all refuse — minting a grant for
    // a tool the gateway wouldn't dispatch anyway is dead code.
    let (server_id, tool_id, tool_behavior_hash) =
        match catalog.resolve_tool(&tenant, &body.tool).await {
            Ok(ResolvedTool::Live(def)) => (def.server_id, def.tool_id, def.schema_hash),
            Ok(ResolvedTool::Quarantined { .. })
            | Ok(ResolvedTool::PendingApproval { .. })
            | Ok(ResolvedTool::NotFound) => {
                return Err(ApiError::NotFound("tool not Live in catalog"));
            }
            Err(e) => {
                return Err(ApiError::Internal(format!("catalog resolve_tool: {e}")));
            }
        };

    // Bind the grant to the contract the approver reviewed, not to whichever
    // version is Live when this POST lands. If the tool's approved behavior
    // changed since review, refuse so a human decision never authorizes an
    // unreviewed version.
    if body.behavior_hash != tool_behavior_hash {
        return Err(ApiError::Conflict(
            "tool behavior changed since review; re-review the tool and retry with its current behavior_hash".to_owned(),
        ));
    }
    let argument_hash =
        waygate_catalog::approval_binding_hash(&tool_behavior_hash, &raw_argument_hash);

    // Lifetime: clamped to [MIN, MAX]; default 15 minutes.
    let (expires_in_secs, expires_at) = grant_lifetime(body.expires_in_seconds);

    let new_grant = NewApprovalGrant {
        tenant_id: &tenant,
        principal_sub: body.principal_sub.as_str(),
        principal_issuer: body.principal_issuer.as_str(),
        // Always None until `Principal.client_id` is available to
        // the per-call gate. See `CreateGrantRequest`.
        client_id: None,
        server_id,
        tool_id,
        argument_hash: argument_hash.as_str(),
        execution_binding: None,
        expires_at,
        approver: approver.as_str(),
        reason: body.reason.as_deref(),
    };
    let grant = catalog
        .create_grant(new_grant)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog create_grant: {e}")))?;
    tracing::info!(
        tenant = %tenant,
        approver = %approver,
        principal_sub = %grant.principal_sub,
        tool = %body.tool,
        grant_id = %grant.id,
        expires_in_secs = expires_in_secs.as_secs(),
        "HITL approval grant minted",
    );
    Ok((StatusCode::CREATED, Json(GrantView::from(grant))))
}

fn codemode_request(
    execution: &waygate_codemode::Execution,
) -> ApiResult<(CodeModeApprovalRequestView, String)> {
    if execution.status != waygate_codemode::ExecutionStatus::WaitingForApproval
        || execution
            .execution_profile
            .get("name")
            .and_then(serde_json::Value::as_str)
            != Some("approval_bound_mutation")
    {
        return Err(ApiError::Conflict(
            "Code Mode execution is not waiting for a mutation decision".to_owned(),
        ));
    }
    let request = execution
        .resume_context
        .as_ref()
        .and_then(|context| context.get("approval"))
        .cloned()
        .ok_or_else(|| {
            ApiError::Internal("Code Mode approval request is missing its durable preview".into())
        })?;
    // Digest the durable JSON exactly as stored (canonicalized), before any
    // deserialization can reshape it: this is the identity an approval echoes.
    let digest = waygate_catalog::argument_hash(request.as_object());
    let request: CodeModeApprovalRequestView =
        serde_json::from_value(request).map_err(|error| {
            ApiError::Internal(format!(
                "Code Mode approval request has an incompatible shape: {error}"
            ))
        })?;
    if request.source_digest != execution.source_digest {
        return Err(ApiError::Conflict(
            "Code Mode approval source digest no longer matches the execution".to_owned(),
        ));
    }
    Ok((request, digest))
}

/// Refuse a decision that names a different request than the one currently
/// pending: an administrator's approval must not transfer to a request they
/// never reviewed.
fn verify_reviewed_digest(reviewed: &str, current: &str) -> ApiResult<()> {
    if reviewed != current {
        return Err(ApiError::Conflict(
            "the pending Code Mode request changed after it was reviewed; list the approval \
             requests again and review the current request"
                .to_owned(),
        ));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/codemode/approval_requests",
    tag = "approval_grants",
    responses(
        (status = 200, description = "Pending Code Mode mutation decisions", body = PendingCodeModeApprovalList),
        (status = 503, description = "Code Mode execution store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_codemode_approval_requests(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<PendingCodeModeApprovalList>> {
    let store = state.hitl.codemode_executions.require()?;
    let tenant = caller_tenant(principal.as_ref().map(|Extension(p)| p));
    let executions = store
        .list_waiting_approvals(&tenant, 100)
        .await
        .map_err(|error| {
            ApiError::Internal(format!("list Code Mode approval requests: {error}"))
        })?;
    let approvals = executions
        .into_iter()
        .map(|execution| {
            let (request, request_digest) = codemode_request(&execution)?;
            Ok(PendingCodeModeApprovalView {
                execution_id: execution.id,
                principal_issuer: execution.principal_issuer.clone(),
                principal_sub: execution.principal_sub,
                submitted_at: format_ts_rfc3339(execution.submitted_at),
                updated_at: format_ts_rfc3339(execution.updated_at),
                request,
                request_digest,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(PendingCodeModeApprovalList { approvals }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/codemode/approval_requests/{id}/approve",
    tag = "approval_grants",
    request_body = CodeModeApprovalDecision,
    params(("id" = Uuid, Path, description = "Code Mode execution id")),
    responses(
        (status = 201, description = "Execution-bound grant minted", body = GrantView),
        (status = 400, description = "Decision does not echo the reviewed request_digest", body = ApiErrorBody),
        (status = 404, description = "Execution or live governed tool unavailable", body = ApiErrorBody),
        (status = 409, description = "Execution is no longer waiting or request drifted", body = ApiErrorBody),
        (status = 503, description = "Required store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn approve_codemode_request(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Path(id): Path<Uuid>,
    Json(body): Json<CodeModeApprovalDecision>,
) -> ApiResult<(StatusCode, Json<GrantView>)> {
    let execution_store = state.hitl.codemode_executions.require()?;
    let catalog = catalog_store(&state)?;
    let p = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(p);
    let approver = p.map(|p| p.sub.as_str()).unwrap_or("dev@local");
    let execution = execution_store
        .get(&tenant, id)
        .await
        .map_err(|error| ApiError::Internal(format!("get Code Mode approval request: {error}")))?
        .ok_or(ApiError::NotFound("Code Mode approval request"))?;
    // Separation of duty (see the direct-grant path): the approver may not
    // authorize a mutation their own principal proposed. This is the
    // human/second-party gate for approval-required mutations, enforced
    // structurally by requiring a different principal.
    // Full-identity comparison, and a fail-closed requirement that the
    // execution row RECORDED its owner's issuer: a pre-upgrade row has no
    // trustworthy requester identity to bind a grant to.
    let Some(requester_issuer) = execution.principal_issuer.clone() else {
        return Err(ApiError::Conflict(
            "this execution predates issuer-scoped ownership and records no requester \
             issuer; it cannot be approved — re-run the execution"
                .to_owned(),
        ));
    };
    let approver_issuer = p.map(|p| p.issuer.as_str()).unwrap_or("dev@local");
    if approver == execution.principal_sub && approver_issuer == requester_issuer {
        return Err(ApiError::Conflict(
            "an approver may not authorize a mutation proposed by their own principal".to_owned(),
        ));
    }
    let (request, current_digest) = codemode_request(&execution)?;
    let reviewed_digest = body.request_digest.as_deref().ok_or_else(|| {
        ApiError::BadRequest(
            "approval requires the `request_digest` returned by the pending-approval listing"
                .to_owned(),
        )
    })?;
    verify_reviewed_digest(reviewed_digest, &current_digest)?;
    let authority = request
        .contract
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| ApiError::Conflict("approval contract authority is missing".to_owned()))?;
    if authority
        .get("authority")
        .and_then(serde_json::Value::as_str)
        != Some("catalog")
    {
        return Err(ApiError::Conflict(
            "approval contract is not catalog-authoritative".to_owned(),
        ));
    }
    let tool_id = authority
        .get("tool_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| ApiError::Conflict("approval contract tool id is invalid".to_owned()))?;
    // The behavior version the operator actually reviewed, carried on the
    // durable request. The grant binds to THIS hash, and the live tool must
    // still be on it — otherwise a version change between listing and
    // approval would mint a grant for a contract the operator never saw
    // (and the durable snapshot check would then reject it as unusable).
    let reviewed_behavior_hash = authority
        .get("catalog_schema_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ApiError::Conflict("approval contract behavior hash is missing".to_owned())
        })?;
    let tool = catalog
        .resolve_live_tool_id(&tenant, tool_id)
        .await
        .map_err(|error| ApiError::Internal(format!("resolve Code Mode approval tool: {error}")))?
        .ok_or(ApiError::NotFound("live Code Mode approval tool"))?;
    if tool.schema_hash != reviewed_behavior_hash {
        return Err(ApiError::Conflict(
            "the governed tool version changed after this request was reviewed; \
             list the approval requests again and review the current version"
                .to_owned(),
        ));
    }
    // The pending waiting_for_approval request is itself the authority that
    // approval was demanded (the dispatch pipeline paused on a Cedar
    // ApprovalRequired verdict or the former Code Mode approval overlay). The
    // catalog `requires_approval` flag is therefore NOT re-checked here — a
    // policy-gated tool with the flag off must still be approvable — but the
    // reviewed behavior generation (checked above) and the reviewed tool
    // identity must still hold. Effectfulness is re-checked only for
    // manifest-mode tools, whose catalog `side_effects` flag is authoritative;
    // annotation-native rows keep that legacy flag forced-false and derive
    // effectfulness from the reviewed annotations at dispatch, so re-reading it
    // here would reject every annotation-native side-effecting mutation. For
    // those the pause that produced this pending request — a read-only call
    // never reaches waiting_for_approval — is itself the effectfulness decision.
    let manifest_effectfulness_regressed =
        tool.classification_mode != "mcp_annotations" && !tool.side_effects;
    if tool.server_name != request.connector
        || tool.tool_name != request.operation
        || manifest_effectfulness_regressed
    {
        return Err(ApiError::Conflict(
            "governed tool no longer matches the pending mutation".to_owned(),
        ));
    }
    // Bind the grant to the reviewed contract generation, exactly as the
    // direct-grant path and the invocation lookup do: the stored digest
    // combines the tool's approved behavior hash with the canonical argument
    // hash, so a reviewed tool-version change invalidates the grant.
    let approval_binding =
        waygate_catalog::approval_binding_hash(reviewed_behavior_hash, &request.argument_hash);
    let (lifetime, expires_at) = grant_lifetime(body.expires_in_seconds);
    let grant = catalog
        .create_grant(NewApprovalGrant {
            tenant_id: &tenant,
            principal_sub: &execution.principal_sub,
            principal_issuer: &requester_issuer,
            client_id: None,
            server_id: tool.server_id,
            tool_id,
            argument_hash: &approval_binding,
            execution_binding: Some(GrantExecutionBinding {
                execution_id: execution.id,
                source_digest: &request.source_digest,
                call_id: request.call_id,
            }),
            expires_at,
            approver,
            reason: body.reason.as_deref(),
        })
        .await
        .map_err(|error| {
            ApiError::Internal(format!("create Code Mode execution-bound grant: {error}"))
        })?;
    // The digest was verified against a snapshot, and a concurrent
    // writer may have replaced the pending request while the grant
    // was being minted. Re-read the execution and revoke the mint if the
    // reviewed request is no longer the pending one — combined with
    // revoke-on-replace in the broker, a bound grant survives only while the
    // exact request it authorizes stays current.
    let still_current = execution_store
        .get(&tenant, id)
        .await
        .map_err(|error| {
            ApiError::Internal(format!("confirm Code Mode approval request: {error}"))
        })?
        .as_ref()
        .map(codemode_request)
        .and_then(Result::ok)
        .is_some_and(|(_, digest)| digest == current_digest);
    if !still_current {
        if let Err(error) = catalog.revoke_grant(&tenant, grant.id).await {
            return Err(ApiError::Internal(format!(
                "revoke superseded Code Mode grant {}: {error}",
                grant.id
            )));
        }
        return Err(ApiError::Conflict(
            "the pending Code Mode request changed while the approval was being recorded; the \
             minted grant was revoked — list the approval requests again"
                .to_owned(),
        ));
    }
    tracing::info!(
        tenant,
        %approver,
        execution_id = %execution.id,
        grant_id = %grant.id,
        connector = %request.connector,
        operation = %request.operation,
        expires_in_secs = lifetime.as_secs(),
        "Code Mode mutation approval grant minted"
    );
    Ok((StatusCode::CREATED, Json(GrantView::from(grant))))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/codemode/approval_requests/{id}/deny",
    tag = "approval_grants",
    request_body = CodeModeApprovalDecision,
    params(("id" = Uuid, Path, description = "Code Mode execution id")),
    responses(
        (status = 204, description = "Mutation denied"),
        (status = 404, description = "Pending request unavailable", body = ApiErrorBody),
        (status = 503, description = "Code Mode execution store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn deny_codemode_request(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Path(id): Path<Uuid>,
    Json(body): Json<CodeModeApprovalDecision>,
) -> ApiResult<StatusCode> {
    let store = state.hitl.codemode_executions.require()?;
    let p = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(p);
    let approver = p.map(|p| p.sub.as_str()).unwrap_or("dev@local");
    // Optional review binding: refusing whatever is pending confers no
    // authority, so denial works without a digest — but when the caller names
    // the request it reviewed, a swapped request is surfaced instead of
    // silently denying a different one.
    if let Some(reviewed_digest) = body.request_digest.as_deref() {
        let execution = store
            .get(&tenant, id)
            .await
            .map_err(|error| {
                ApiError::Internal(format!("get Code Mode approval request: {error}"))
            })?
            .ok_or(ApiError::NotFound("Code Mode approval request"))?;
        let (_, current_digest) = codemode_request(&execution)?;
        verify_reviewed_digest(reviewed_digest, &current_digest)?;
    }
    let denied = store
        .deny_waiting_approval(&tenant, id, approver, body.reason.as_deref())
        .await
        .map_err(|error| ApiError::Internal(format!("deny Code Mode approval request: {error}")))?;
    if !denied {
        return Err(ApiError::NotFound("pending Code Mode approval request"));
    }
    tracing::info!(
        tenant,
        %approver,
        execution_id = %id,
        "Code Mode mutation denied"
    );
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/approval_grants",
    tag = "approval_grants",
    params(
        ("principal_sub" = Option<String>, Query, description = "Filter by principal"),
        ("tool" = Option<String>, Query, description = "Filter by qualified <server>.<tool>"),
        ("include_consumed" = Option<bool>, Query, description = "Include consumed/expired"),
    ),
    responses(
        (status = 200, description = "Matching grants in this tenant", body = GrantListResponse),
        (status = 503, description = "Catalog store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_grants(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Query(q): Query<ListGrantsQuery>,
) -> ApiResult<Json<GrantListResponse>> {
    let catalog = catalog_store(&state)?;
    let p = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(p);
    // Tool filter: when the operator passes ?tool=example-messages.send,
    // resolve it once to a tool_id rather than asking the store
    // for string-name matching. Unknown / non-Live → return an
    // empty list (not a 404; a 404 would let an outsider probe
    // for catalog presence).
    let tool_id = if let Some(tool) = q.tool.as_deref() {
        match catalog.resolve_tool(&tenant, tool).await {
            Ok(ResolvedTool::Live(def)) => Some(def.tool_id),
            Ok(_) => return Ok(Json(GrantListResponse { grants: vec![] })),
            Err(e) => {
                return Err(ApiError::Internal(format!("catalog resolve_tool: {e}")));
            }
        }
    } else {
        None
    };
    let filter = GrantFilter {
        principal_sub: q.principal_sub.as_deref(),
        tool_id,
        server_id: None,
        include_consumed: q.include_consumed,
        lifecycle: None,
    };
    let grants = catalog
        .list_grants(&tenant, filter)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog list_grants: {e}")))?;
    Ok(Json(GrantListResponse {
        grants: grants.into_iter().map(GrantView::from).collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/approval_grants/{id}",
    tag = "approval_grants",
    params(("id" = String, Path, description = "Grant UUID")),
    responses(
        (status = 204, description = "Grant revoked (any unconsumed grant — including an expired-but-unconsumed one)"),
        (status = 404, description = "Nothing to revoke in caller's tenant: no such grant, or already consumed/revoked (consumed counts as 404)", body = ApiErrorBody),
        (status = 503, description = "Catalog store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn revoke_grant(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<Uuid>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<StatusCode> {
    let p = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(p);
    if revoke_grant_core(&state, &tenant, p, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("approval grant"))
    }
}

/// Shared revoke path: store-check → `revoke_grant` (sets
/// `consumed_at = now()`) → loud `tracing` line. Both the REST
/// `revoke_grant` handler and the dashboard's per-row revoke form call
/// this. `revoke_grant` closes any grant whose `consumed_at IS NULL`
/// (the store does NOT additionally check `expires_at`), so an
/// expired-but-unconsumed grant is still closeable here — returning
/// `true`. `false` means there was nothing to close: the grant is
/// already consumed/revoked, or absent from this tenant.
///
/// No durable `record_required` audit: approval-grant lifecycle events
/// are tracing-only today (see the module doc on `dashboard_approvals`);
/// promoting them to the Evidence stream is a separate cross-cutting
/// decision, so this preserves the existing best-effort posture rather
/// than introducing a one-off fail-closed path here.
pub(crate) async fn revoke_grant_core(
    state: &Arc<AdminState>,
    tenant: &str,
    actor: Option<&Principal>,
    id: Uuid,
) -> ApiResult<bool> {
    let catalog = catalog_store(state)?;
    let revoked = catalog
        .revoke_grant(tenant, id)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog revoke_grant: {e}")))?;
    if revoked {
        tracing::info!(
            tenant = %tenant,
            actor = %actor.map(|p| p.sub.as_str()).unwrap_or("dev@local"),
            grant_id = %id,
            "HITL approval grant revoked",
        );
    }
    Ok(revoked)
}
