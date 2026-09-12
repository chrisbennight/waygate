//! `/api/v1/catalog/*` — read-only views of the governed catalog.
//!
//! The governed catalog is the Postgres-backed registry of upstream
//! MCP servers and their tools (servers, tool versions, risk
//! classifications, approvals, drift events). It is the durable
//! registry populated through governed configuration changes. These two
//! endpoints expose the operator-facing read surface over it:
//!
//! - `GET /api/v1/catalog/servers` — the live upstream servers
//!   visible to the caller's tenant (own-tenant rows plus rows
//!   marked globally visible).
//! - `GET /api/v1/catalog/drift_events` — recent schema-drift
//!   observations (an upstream's live tool schema diverging from
//!   the catalog's approved version), newest first.
//!
//! and two mutating transitions that change a server's lifecycle
//! status (writing an audit row to `catalog_approvals` for each):
//!
//! - `POST /api/v1/catalog/servers/{id}/approve` — promote a
//!   server to `live` so its tools become dispatchable.
//! - `POST /api/v1/catalog/servers/{id}/quarantine` — pull a
//!   server out of dispatch (status `quarantined`).
//!
//! All four are gated by `mcp:admin`.

use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{middleware, Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use waygate_catalog::{
    CatalogServerStatus, CatalogServerStatusChange, CatalogServerSummary,
    CatalogServerTransitionTarget, DriftEvent, SharedCatalogStore,
};
use waygate_core::TenantId;
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/catalog/servers", axum::routing::get(list_servers))
        .route(
            "/api/v1/catalog/drift_events",
            axum::routing::get(list_drift_events),
        )
        .route(
            "/api/v1/catalog/servers/{id}/approve",
            axum::routing::post(approve_server),
        )
        .route(
            "/api/v1/catalog/servers/{id}/quarantine",
            axum::routing::post(quarantine_server),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

/// Resolve the tenant whose catalog view to serve: the caller's
/// own tenant, or the default tenant when the request arrived
/// without a principal (auth-disabled dev mode).
fn caller_tenant(principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| TenantId::DEFAULT.to_owned())
}

fn catalog_store(state: &AdminState) -> ApiResult<&SharedCatalogStore> {
    state.servers.catalog.require()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServerListResponse {
    pub servers: Vec<CatalogServerSummary>,
}

#[utoipa::path(
    get,
    path = "/api/v1/catalog/servers",
    tag = "catalog",
    responses(
        (status = 200, description = "Live catalog servers visible to the caller's tenant", body = ServerListResponse),
        (status = 503, description = "Catalog store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Catalog query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_servers(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<ServerListResponse>> {
    let catalog = catalog_store(&state)?;
    let tenant = caller_tenant(principal.as_ref().map(|Extension(p)| p));
    let servers = catalog
        .approved_servers(&tenant)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog servers: {e}")))?;
    Ok(Json(ServerListResponse { servers }))
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct DriftQuery {
    /// Max rows to return. Hard-capped at 500 by the store.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Only events at or after this RFC 3339 timestamp. Absent ⇒
    /// the last 7 days.
    #[serde(default)]
    pub since: Option<String>,
}

// Deliberate override of waygate_core::page::DEFAULT_LIST_LIMIT (50):
// the catalog list is the primary browse surface and pages at 100.
fn default_limit() -> u32 {
    100
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DriftListResponse {
    pub events: Vec<DriftEvent>,
}

#[utoipa::path(
    get,
    path = "/api/v1/catalog/drift_events",
    tag = "catalog",
    params(DriftQuery),
    responses(
        (status = 200, description = "Recent drift events for the caller's tenant, newest first", body = DriftListResponse),
        (status = 400, description = "Malformed `since` timestamp", body = ApiErrorBody),
        (status = 503, description = "Catalog store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Catalog query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_drift_events(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<DriftQuery>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<DriftListResponse>> {
    let catalog = catalog_store(&state)?;
    let tenant = caller_tenant(principal.as_ref().map(|Extension(p)| p));
    let since = match q.since.as_deref() {
        Some(s) => time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map_err(|e| ApiError::BadRequest(format!("invalid `since` timestamp: {e}")))?,
        None => time::OffsetDateTime::now_utc() - time::Duration::days(7),
    };
    let events = catalog
        .list_drift_events(&tenant, since, q.limit)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog drift events: {e}")))?;
    Ok(Json(DriftListResponse { events }))
}

/// Optional `{ "reason": "..." }` body for direct approve or immediate
/// quarantine — recorded verbatim on the `catalog_approvals`
/// audit row so a reviewer can see *why* a server was promoted or
/// pulled. Body is optional; an empty/absent body records no reason.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct StatusChangeBody {
    #[serde(default)]
    pub reason: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/catalog/servers/{id}/approve",
    tag = "catalog",
    params(("id" = String, Path, description = "Catalog server UUID")),
    request_body = StatusChangeBody,
    responses(
        (status = 204, description = "Server promoted to live"),
        (status = 409, description = "Server changed during approval, is quarantined and requires catalog.server.unquarantine, or the configured two-approver rule rejects the actor", body = ApiErrorBody),
        (status = 404, description = "No such server in the caller's tenant", body = ApiErrorBody),
        (status = 503, description = "Catalog store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn approve_server(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<Uuid>,
    principal: Option<Extension<Principal>>,
    body: Option<Json<StatusChangeBody>>,
) -> ApiResult<StatusCode> {
    approve_server_if_not_quarantined(&state, id, principal, body).await
}

/// Direct approval retains its legacy transitions except for durable
/// quarantine recovery. A quarantined row must travel through the
/// `catalog.server.unquarantine` change request so a maker cannot bypass HITL
/// by calling this older REST endpoint directly.
async fn approve_server_if_not_quarantined(
    state: &AdminState,
    server_id: Uuid,
    principal: Option<Extension<Principal>>,
    body: Option<Json<StatusChangeBody>>,
) -> ApiResult<StatusCode> {
    let catalog = catalog_store(state)?;
    let p = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(p);
    let actor = p.map(|p| p.sub.as_str()).unwrap_or("dev@local");
    let target = catalog
        .server_transition_target(&tenant, server_id)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog server transition target: {e}")))?
        .ok_or(ApiError::NotFound("catalog server"))?;

    if target.status == CatalogServerStatus::Quarantined {
        return Err(ApiError::Conflict(
            "quarantined servers must be restored through a catalog.server.unquarantine change request"
                .into(),
        ));
    }

    // The legacy two-approver rule remains on direct promotion. Quarantine
    // stays single-actor for incident response; unquarantine has the change
    // request's own proposer/approver separation.
    if state.hitl.require_two_approvals {
        let prior = catalog
            .last_approve_actor(&tenant, server_id)
            .await
            .map_err(|e| ApiError::Internal(format!("catalog last_approve_actor: {e}")))?;
        if let Some(prior_actor) = prior {
            if prior_actor == actor {
                return Err(ApiError::Conflict(format!(
                    "two-approver rule: `{actor}` was also the most recent approver \
                     of this server; a different admin must approve",
                )));
            }
        }
    }

    let reason = body.as_ref().and_then(|Json(b)| b.reason.as_deref());
    let updated = catalog
        .transition_server_status_if_unchanged(CatalogServerStatusChange {
            target: &target,
            new_status: CatalogServerStatus::Live,
            actor,
            reason,
        })
        .await
        .map_err(|e| ApiError::Internal(format!("catalog approve server: {e}")))?;
    if updated {
        state.upstreams.tool_catalog_epoch().mark_changed();
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Conflict(
            "catalog server changed during approval; reload and retry".into(),
        ))
    }
}

/// Captured intent for the governed durable-catalog recovery action.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CatalogServerUnquarantineParams {
    /// Immutable catalog server id from `gateway-observe.read_resource`.
    pub server_id: Uuid,
    /// Reviewed server name; execution rejects an id/name mismatch.
    pub expected_name: String,
    /// Operator-readable justification recorded on the lifecycle audit row.
    #[schemars(length(min = 1, max = 500), regex(pattern = r"\S"))]
    pub reason: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CatalogServerUnquarantineResponse {
    pub server_id: Uuid,
    pub server: String,
    pub previous_status: String,
    pub status: String,
}

/// Apply an already-reviewed `quarantined -> live` transition against the
/// exact row version captured by the proposal. The catalog store binds all
/// predicates into the update and records its lifecycle audit atomically.
pub async fn unquarantine_server_if_unchanged_core(
    state: &AdminState,
    tenant_id: &str,
    actor: &Principal,
    params: &CatalogServerUnquarantineParams,
    target: &CatalogServerTransitionTarget,
) -> ApiResult<CatalogServerUnquarantineResponse> {
    if params.reason.trim().is_empty() || params.reason.chars().count() > 500 {
        return Err(ApiError::BadRequest(
            "reason must be 1..=500 characters and contain non-whitespace".into(),
        ));
    }
    if target.tenant_id != tenant_id
        || target.id != params.server_id
        || target.name != params.expected_name
    {
        return Err(ApiError::Conflict(
            "catalog server identity no longer matches the reviewed proposal".into(),
        ));
    }
    if target.status != CatalogServerStatus::Quarantined {
        return Err(ApiError::Conflict(format!(
            "catalog server `{}` is `{}`, not `quarantined`",
            target.name,
            target.status.as_str(),
        )));
    }

    let catalog = catalog_store(state)?;
    let updated = catalog
        .transition_server_status_if_unchanged(CatalogServerStatusChange {
            target,
            new_status: CatalogServerStatus::Live,
            actor: &actor.sub,
            reason: Some(params.reason.trim()),
        })
        .await
        .map_err(|e| ApiError::Internal(format!("catalog unquarantine server: {e}")))?;
    if !updated {
        return Err(ApiError::Conflict(
            "catalog server changed since proposal; inspect and re-propose".into(),
        ));
    }

    state.upstreams.tool_catalog_epoch().mark_changed();

    Ok(CatalogServerUnquarantineResponse {
        server_id: target.id,
        server: target.name.clone(),
        previous_status: CatalogServerStatus::Quarantined.as_str().into(),
        status: CatalogServerStatus::Live.as_str().into(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/catalog/servers/{id}/quarantine",
    tag = "catalog",
    params(("id" = String, Path, description = "Catalog server UUID")),
    request_body = StatusChangeBody,
    responses(
        (status = 204, description = "Server quarantined (removed from dispatch)"),
        (status = 404, description = "No such server in the caller's tenant", body = ApiErrorBody),
        (status = 503, description = "Catalog store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn quarantine_server(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<Uuid>,
    principal: Option<Extension<Principal>>,
    body: Option<Json<StatusChangeBody>>,
) -> ApiResult<StatusCode> {
    set_status(
        &state,
        id,
        CatalogServerStatus::Quarantined,
        principal,
        body,
    )
    .await
}

/// Immediate-quarantine core: resolve the catalog store, caller tenant, and
/// actor; call `set_server_status`; then map the outcome to 204 (updated) or
/// 404 (no such server in this tenant).
async fn set_status(
    state: &AdminState,
    server_id: Uuid,
    new_status: CatalogServerStatus,
    principal: Option<Extension<Principal>>,
    body: Option<Json<StatusChangeBody>>,
) -> ApiResult<StatusCode> {
    let catalog = catalog_store(state)?;
    let p = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(p);
    // Actor for the audit row: the acting principal's sub, or a
    // sentinel for the auth-disabled dev path (no principal).
    let actor = p.map(|p| p.sub.as_str()).unwrap_or("dev@local");
    let reason = body.as_ref().and_then(|Json(b)| b.reason.as_deref());
    let updated = catalog
        .set_server_status(&tenant, server_id, new_status, actor, reason)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog set_server_status: {e}")))?;
    if updated {
        state.upstreams.tool_catalog_epoch().mark_changed();
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("catalog server"))
    }
}

// ---- dashboard surface (session + CSRF; reuses the REST lifecycle cores) ---

/// Form body for the dashboard catalog lifecycle actions.
#[derive(Debug, Deserialize)]
pub(crate) struct CatalogActionForm {
    /// Defaulted so a missing csrf hits the handler's own check (→ 403)
    /// rather than a 422 deserialize error.
    #[serde(default)]
    pub(crate) csrf: String,
    pub(crate) id: String,
}

/// Admin gate + CSRF + id-parse shared by the dashboard catalog actions.
/// Returns the parsed server id, or an `ApiError` the caller renders.
pub(crate) fn catalog_action_guard(
    user: &Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    form: &CatalogActionForm,
) -> Result<Uuid, ApiError> {
    crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p))?;
    // Dev mode injects a CsrfToken; require a match when one is present.
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form.csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, &form.csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return Err(ApiError::Forbidden("csrf mismatch"));
    }
    Uuid::parse_str(form.id.trim()).map_err(|_| ApiError::BadRequest("invalid server id".into()))
}

fn catalog_redirect(tenant_ctx: Option<Extension<TenantContext>>) -> Response {
    let ctx = tenant_ctx.map(|Extension(c)| c);
    Redirect::to(&tenant_ctx::nav_url(ctx.as_ref(), "/catalog")).into_response()
}

/// `POST /catalog/approve` — promote a catalog server to Live. Admin-gated +
/// CSRF; the legacy two-approver promotion rule is enforced exactly as the REST
/// path. Quarantined rows are rejected here; other legacy transitions retain
/// their prior behavior.
pub(crate) async fn catalog_approve_dashboard(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<CatalogActionForm>,
) -> Response {
    let id = match catalog_action_guard(&user, &csrf, &form) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match approve_server_if_not_quarantined(&state, id, user, None).await {
        Ok(_) => catalog_redirect(tenant_ctx),
        Err(e) => e.into_response(),
    }
}

/// `POST /catalog/quarantine` — quarantine a server (single-actor, so an
/// operator can always pull a misbehaving server from dispatch fast).
/// Admin-gated + CSRF.
pub(crate) async fn catalog_quarantine_dashboard(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<CatalogActionForm>,
) -> Response {
    let id = match catalog_action_guard(&user, &csrf, &form) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match set_status(&state, id, CatalogServerStatus::Quarantined, user, None).await {
        Ok(_) => catalog_redirect(tenant_ctx),
        Err(e) => e.into_response(),
    }
}
