//! `/api/v1/audit/routing` — per-tenant evidence routing CRUD.
//!
//! Backs the `tenant_evidence_routing` table (migration
//! 0016). The recorder reads this table inside its
//! `record_required` transaction to decide which exporters
//! get an outbox row for each event — see
//! `waygate_storage::routing` for the resolution semantics.
//!
//! - `GET /api/v1/audit/routing` — list every routing row,
//!   optionally scoped to one tenant via `?tenant_id=`.
//! - `PUT /api/v1/audit/routing` — upsert by
//!   `(tenant_id, exporter_name)`. Body carries
//!   `enabled` + `config` (free-form JSON; each exporter
//!   interprets its own schema).
//! - `DELETE /api/v1/audit/routing?tenant_id=&exporter_name=`
//!   — remove one row. 404 when the row doesn't exist (so
//!   operators can tell "I removed nothing" from "I removed
//!   the row I wanted").
//!
//! Mounted under the same `/api/v1/audit` namespace as the
//! list + verify endpoints; gated by `mcp:admin`
//! middleware-scoped (no `/admin/` URL prefix, consistent
//! with the rest of the admin surface).

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get, put};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use utoipa::ToSchema;

use waygate_core::TenantId;
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;
use waygate_storage::RoutingRow;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/audit/routing", get(list_routing))
        .route("/api/v1/audit/routing", put(upsert_routing))
        .route("/api/v1/audit/routing", delete(delete_routing))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoutingRowView {
    pub tenant_id: String,
    pub exporter_name: String,
    pub enabled: bool,
    pub config: JsonValue,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<RoutingRow> for RoutingRowView {
    fn from(r: RoutingRow) -> Self {
        Self {
            tenant_id: r.tenant_id,
            exporter_name: r.exporter_name,
            enabled: r.enabled,
            config: r.config,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoutingListResponse {
    pub rows: Vec<RoutingRowView>,
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListRoutingQuery {
    /// Optional tenant scope. Omit to list every tenant's
    /// rows.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/audit/routing",
    tag = "audit",
    params(ListRoutingQuery),
    responses(
        (status = 200, description = "Routing rows; empty list when no rows exist", body = RoutingListResponse),
        (status = 503, description = "Audit store not configured", body = ApiErrorBody),
        (status = 500, description = "Routing query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_routing(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<ListRoutingQuery>,
) -> ApiResult<Json<RoutingListResponse>> {
    let store = state.observability.routing.require()?;
    let rows = store
        .list(q.tenant_id.as_deref())
        .await
        .map_err(|e| ApiError::Internal(format!("routing list: {e}")))?;
    Ok(Json(RoutingListResponse {
        rows: rows.into_iter().map(RoutingRowView::from).collect(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertRoutingBody {
    pub tenant_id: String,
    pub exporter_name: String,
    pub enabled: bool,
    /// Exporter-specific config. Free-form JSON; each
    /// exporter (OCSF / Syslog / S3 / webhook) interprets
    /// its own schema. Defaults to `{}` if omitted.
    #[serde(default = "default_config")]
    pub config: JsonValue,
}

fn default_config() -> JsonValue {
    JsonValue::Object(serde_json::Map::new())
}

#[utoipa::path(
    put,
    path = "/api/v1/audit/routing",
    tag = "audit",
    request_body = UpsertRoutingBody,
    responses(
        (status = 200, description = "Routing row inserted or updated", body = RoutingRowView),
        (status = 400, description = "Empty tenant_id or exporter_name", body = ApiErrorBody),
        (status = 503, description = "Audit store not configured", body = ApiErrorBody),
        (status = 500, description = "Upsert failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn upsert_routing(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<UpsertRoutingBody>,
) -> ApiResult<Json<RoutingRowView>> {
    let actor = principal.as_ref().map(|Extension(p)| p);
    Ok(Json(
        set_routing_core(
            &state,
            &body.tenant_id,
            &body.exporter_name,
            body.enabled,
            &body.config,
            actor,
        )
        .await?,
    ))
}

/// Shared routing-upsert path: validate → `store.upsert` → fail-closed
/// `record_required` AdminMutation stamped to the TARGET tenant's chain. Both
/// the REST `upsert_routing` handler (tenant from the body) and the
/// `audit.routing.set` propose executor (tenant = the change request's, i.e.
/// the maker's own) call this, so validation and the compliance-critical audit
/// can't drift between the direct-admin and propose paths.
///
/// Routing mutations MUST be chain-covered — an admin
/// must not be able to silently reroute or disable a tenant's evidence — so
/// this `record_required`s to the TARGET tenant's chain (`with_tenant`)
/// and is fail-closed: the row already committed via `store.upsert`,
/// so an audit-write failure surfaces a "retry to record the audit" 500.
pub(crate) async fn set_routing_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    exporter_name: &str,
    enabled: bool,
    config: &JsonValue,
    actor: Option<&Principal>,
) -> ApiResult<RoutingRowView> {
    if tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }
    if exporter_name.trim().is_empty() {
        return Err(ApiError::BadRequest("exporter_name is required".to_owned()));
    }
    let target_tenant = TenantId::parse(tenant_id.to_owned())
        .map_err(|e| ApiError::BadRequest(format!("invalid tenant_id: {e}")))?;
    let store = state.observability.routing.require()?;
    let row = store
        .upsert(tenant_id, exporter_name, enabled, config)
        .await
        .map_err(|e| ApiError::Internal(format!("routing upsert: {e}")))?;
    state
        .evidence
        .record_required(
            AuditEvent::new("audit_routing.upsert", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_tenant(target_tenant)
                .with_reason(format!(
                    "routing upsert tenant={tenant_id} exporter={exporter_name} enabled={enabled}"
                )),
        )
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "routing upsert AUDIT FAILED (row was changed; retry to record audit): {e}"
            ))
        })?;
    Ok(RoutingRowView::from(row))
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct DeleteRoutingQuery {
    pub tenant_id: String,
    pub exporter_name: String,
}

#[utoipa::path(
    delete,
    path = "/api/v1/audit/routing",
    tag = "audit",
    params(DeleteRoutingQuery),
    responses(
        (status = 204, description = "Row deleted"),
        (status = 400, description = "Empty tenant_id or exporter_name", body = ApiErrorBody),
        (status = 404, description = "No such routing row", body = ApiErrorBody),
        (status = 503, description = "Audit store not configured", body = ApiErrorBody),
        (status = 500, description = "Delete failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_routing(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Query(q): Query<DeleteRoutingQuery>,
) -> ApiResult<StatusCode> {
    let actor = principal.as_ref().map(|Extension(p)| p);
    if clear_routing_core(&state, &q.tenant_id, &q.exporter_name, actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("no such routing row"))
    }
}

/// Shared routing-delete path: validate → `store.delete` → on actual removal,
/// fail-closed `record_required` AdminMutation stamped to the TARGET tenant's
/// chain. Returns whether a row was removed (the REST handler maps `false` →
/// 404; the `audit.routing.clear` propose executor treats both outcomes as
/// success — clearing an absent route is idempotent).
///
/// Deleting the last routing row for a tenant resumes the
/// configured-targets fallback — a material compliance change — so removal is
/// chain-covered (`with_tenant`, fail-closed). The 404 path records nothing
/// because nothing changed.
pub(crate) async fn clear_routing_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    exporter_name: &str,
    actor: Option<&Principal>,
) -> ApiResult<bool> {
    if tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }
    if exporter_name.trim().is_empty() {
        return Err(ApiError::BadRequest("exporter_name is required".to_owned()));
    }
    let target_tenant = TenantId::parse(tenant_id.to_owned())
        .map_err(|e| ApiError::BadRequest(format!("invalid tenant_id: {e}")))?;
    let store = state.observability.routing.require()?;
    let removed = store
        .delete(tenant_id, exporter_name)
        .await
        .map_err(|e| ApiError::Internal(format!("routing delete: {e}")))?;
    if removed {
        state
            .evidence
            .record_required(
                AuditEvent::new("audit_routing.delete", AuditOutcome::Success)
                    .with_category(EvidenceCategory::AdminMutation)
                    .with_principal(actor)
                    .with_tenant(target_tenant)
                    .with_reason(format!(
                        "routing delete tenant={tenant_id} exporter={exporter_name}"
                    )),
            )
            .await
            .map_err(|e| {
                ApiError::Internal(format!(
                    "routing delete AUDIT FAILED (row was removed; retry to record audit): {e}"
                ))
            })?;
    }
    Ok(removed)
}
