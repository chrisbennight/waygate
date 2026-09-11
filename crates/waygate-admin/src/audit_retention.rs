//! # SCOPE: POLICY CRUD ONLY. Enforcement lives in `audit_sweep.rs` /
//! `waygate_storage::sweep`.
//!
//! This module's handlers store and return policy rows; nothing here
//! DELETEs from `audit_log`. The `audit_log` append-only trigger is
//! untouched by this module.
//!
//! ---
//!
//! `/api/v1/audit/retention` — per-tenant per-category audit_log
//! retention POLICY CRUD.
//!
//! Backs the `evidence_retention_policy` table (migration 0017).
//! Operators configure intended retention windows here.
//! **Enforcement** (the sweep that DELETEs old rows) runs automatically
//! via `waygate_storage::run_retention_scheduler`'s periodic tick, and can
//! be force-run on demand via `audit_sweep.rs` (`POST /api/v1/audit/sweep`).
//! Both paths resolve the effective policy from this table and delete
//! through the migration-0018 SECURITY DEFINER wrapper
//! (`audit_log_sweep_delete()`), with its own role separation.
//!
//! Mounted under the same `/api/v1/audit` namespace as list /
//! verify / routing; same `require_admin` middleware-scoped
//! auth (no `/admin/` URL prefix).
//!
//! Mutating handlers (PUT, DELETE) emit `AdminMutation` audit
//! events on success — same pattern as `audit_routing.rs`,
//! same threat model: an authorized admin tightening retention
//! from 365 days to 1 day can silently wipe a tenant's compliance
//! window within a single sweep tick, so the audit trail has to
//! record who made the call. Auditing the policy change preserves
//! the historical record so the next sweep doesn't catch operators
//! off-guard.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get, put};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use waygate_core::TenantId;
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;
use waygate_storage::RetentionPolicy;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/audit/retention", get(list_retention))
        .route("/api/v1/audit/retention", put(upsert_retention))
        .route("/api/v1/audit/retention", delete(delete_retention))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetentionPolicyView {
    pub tenant_id: String,
    pub category: String,
    pub delete_after_days: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<RetentionPolicy> for RetentionPolicyView {
    fn from(p: RetentionPolicy) -> Self {
        Self {
            tenant_id: p.tenant_id,
            category: p.category,
            delete_after_days: p.delete_after_days,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetentionListResponse {
    pub policies: Vec<RetentionPolicyView>,
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListRetentionQuery {
    /// Optional tenant scope. Omit to list policies for every
    /// tenant.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/audit/retention",
    tag = "audit",
    params(ListRetentionQuery),
    responses(
        (status = 200, description = "Retention policies; empty list when none configured", body = RetentionListResponse),
        (status = 503, description = "Retention store not configured", body = ApiErrorBody),
        (status = 500, description = "Retention query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_retention(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<ListRetentionQuery>,
) -> ApiResult<Json<RetentionListResponse>> {
    let store = state.observability.retention.require()?;
    let rows = store
        .list(q.tenant_id.as_deref())
        .await
        .map_err(|e| ApiError::Internal(format!("retention list: {e}")))?;
    Ok(Json(RetentionListResponse {
        policies: rows.into_iter().map(RetentionPolicyView::from).collect(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertRetentionBody {
    pub tenant_id: String,
    /// Either an `EvidenceCategory.as_str()` value (`"invocation"`,
    /// `"admin_mutation"`, etc.) or the literal `"*"` wildcard.
    /// A concrete category matches `audit_log.category` directly. The `"*"`
    /// policy applies to every category that has no explicit policy for the
    /// same tenant. Both `POST /api/v1/audit/sweep` and the periodic scheduler
    /// enforce this most-specific-policy-wins rule.
    pub category: String,
    /// Intended window: the enforcement sweep deletes rows older than this
    /// many days, whether triggered by the periodic scheduler or an
    /// on-demand `POST /api/v1/audit/sweep` call. Must be > 0 — 0 would
    /// mean "delete everything in this category immediately" which is
    /// almost certainly a typo; the migration's CHECK constraint also
    /// rejects it.
    pub delete_after_days: i32,
}

#[utoipa::path(
    put,
    path = "/api/v1/audit/retention",
    tag = "audit",
    request_body = UpsertRetentionBody,
    responses(
        (status = 200, description = "Policy inserted or updated", body = RetentionPolicyView),
        (status = 400, description = "Empty tenant_id/category or invalid delete_after_days", body = ApiErrorBody),
        (status = 503, description = "Retention store not configured", body = ApiErrorBody),
        (status = 500, description = "Upsert failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn upsert_retention(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<UpsertRetentionBody>,
) -> ApiResult<Json<RetentionPolicyView>> {
    let actor = principal.as_ref().map(|Extension(p)| p);
    Ok(Json(
        set_retention_core(
            &state,
            &body.tenant_id,
            &body.category,
            body.delete_after_days,
            actor,
        )
        .await?,
    ))
}

/// Shared retention-upsert path: validate → `store.upsert` → fail-closed
/// `record_required` AdminMutation stamped to the TARGET tenant's chain. Both
/// the REST `upsert_retention` handler (tenant from the body) and the
/// `audit.retention.set` propose executor (tenant = the change request's, i.e.
/// the maker's own) call this, so validation and the compliance-critical audit
/// can't drift between the direct-admin and propose paths.
///
/// `TenantId::parse(tenant_id)` lets the audit event stamp the
/// TARGET tenant's chain (not the actor's), so per-tenant chain verification
/// sees the policy change. `record_required` lands the
/// AdminMutation in the tamper chain; fail-closed — the policy already
/// committed via `store.upsert`, so an audit-write failure surfaces a clear
/// "retry to record the audit" 500 rather than a silent compliance gap.
pub(crate) async fn set_retention_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    category: &str,
    delete_after_days: i32,
    actor: Option<&Principal>,
) -> ApiResult<RetentionPolicyView> {
    if tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }
    if category.trim().is_empty() {
        return Err(ApiError::BadRequest("category is required".to_owned()));
    }
    validate_delete_after_days(delete_after_days)?;
    let target_tenant = TenantId::parse(tenant_id.to_owned())
        .map_err(|e| ApiError::BadRequest(format!("invalid tenant_id: {e}")))?;
    let store = state.observability.retention.require()?;
    let row = store
        .upsert(tenant_id, category, delete_after_days)
        .await
        .map_err(|e| ApiError::Internal(format!("retention upsert: {e}")))?;
    state
        .evidence
        .record_required(
            AuditEvent::new("audit_retention.upsert", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_tenant(target_tenant)
                .with_reason(format!(
                    "retention upsert tenant={tenant_id} category={category} delete_after_days={delete_after_days}"
                )),
        )
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "retention upsert AUDIT FAILED (policy was changed; retry to record audit): {e}"
            ))
        })?;
    Ok(RetentionPolicyView::from(row))
}

fn validate_delete_after_days(delete_after_days: i32) -> ApiResult<()> {
    if delete_after_days <= 0 {
        return Err(ApiError::BadRequest(
            "delete_after_days must be > 0".to_owned(),
        ));
    }
    if waygate_storage::retention_cutoff(OffsetDateTime::now_utc(), delete_after_days).is_none() {
        return Err(ApiError::BadRequest(
            "delete_after_days exceeds the supported timestamp range".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct DeleteRetentionQuery {
    pub tenant_id: String,
    pub category: String,
}

#[utoipa::path(
    delete,
    path = "/api/v1/audit/retention",
    tag = "audit",
    params(DeleteRetentionQuery),
    responses(
        (status = 204, description = "Policy deleted"),
        (status = 400, description = "Empty tenant_id or category", body = ApiErrorBody),
        (status = 404, description = "No such policy", body = ApiErrorBody),
        (status = 503, description = "Retention store not configured", body = ApiErrorBody),
        (status = 500, description = "Delete failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_retention(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Query(q): Query<DeleteRetentionQuery>,
) -> ApiResult<StatusCode> {
    let actor = principal.as_ref().map(|Extension(p)| p);
    if clear_retention_core(&state, &q.tenant_id, &q.category, actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("no such retention policy"))
    }
}

/// Shared retention-clear path (the delete-side twin of [`set_retention_core`]):
/// validate → `store.delete` → fail-closed `record_required` AdminMutation
/// stamped to the TARGET tenant's chain, ONLY when a row was actually removed
/// (a no-op clear of an absent policy changes nothing, so it isn't audited).
/// Returns whether a row was removed. Both the REST `delete_retention` handler
/// and the `audit.retention.clear` propose executor call this.
pub(crate) async fn clear_retention_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    category: &str,
    actor: Option<&Principal>,
) -> ApiResult<bool> {
    if tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }
    if category.trim().is_empty() {
        return Err(ApiError::BadRequest("category is required".to_owned()));
    }
    let target_tenant = TenantId::parse(tenant_id.to_owned())
        .map_err(|e| ApiError::BadRequest(format!("invalid tenant_id: {e}")))?;
    let store = state.observability.retention.require()?;
    let removed = store
        .delete(tenant_id, category)
        .await
        .map_err(|e| ApiError::Internal(format!("retention delete: {e}")))?;
    if removed {
        state
            .evidence
            .record_required(
                AuditEvent::new("audit_retention.delete", AuditOutcome::Success)
                    .with_category(EvidenceCategory::AdminMutation)
                    .with_principal(actor)
                    .with_tenant(target_tenant)
                    .with_reason(format!(
                        "retention delete tenant={tenant_id} category={category}"
                    )),
            )
            .await
            .map_err(|e| {
                ApiError::Internal(format!(
                    "retention delete AUDIT FAILED (policy was removed; retry to record audit): {e}"
                ))
            })?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_days_must_be_positive_and_representable() {
        assert!(validate_delete_after_days(30).is_ok());

        let non_positive = validate_delete_after_days(0).expect_err("zero must be rejected");
        assert!(matches!(non_positive, ApiError::BadRequest(_)));

        let unrepresentable = validate_delete_after_days(i32::MAX)
            .expect_err("an unrepresentable cutoff must be rejected");
        match unrepresentable {
            ApiError::BadRequest(detail) => {
                assert!(detail.contains("exceeds the supported timestamp range"));
            }
            other => panic!("expected bad request, got {other:?}"),
        }
    }
}
