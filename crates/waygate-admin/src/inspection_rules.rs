//! Tenant-scoped read/delete access to stored custom inspection rules.
//! These records are not enforced. Every endpoint requires `mcp:admin`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_dashboard_stores::inspection_rules::{
    InspectionRule, InspectorKind, RuleError, RuleFilter, MAX_LIST_LIMIT,
};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/admin/inspection_rules", get(list_rules))
        .route(
            "/api/v1/admin/inspection_rules/{id}",
            get(get_rule).delete(delete_rule),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

// --- DTOs --------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleListResponse {
    pub rules: Vec<RuleView>,
    /// Echoed page size after `MAX_LIST_LIMIT` clamp.
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    /// Optional inspector kind filter.
    #[serde(default)]
    pub inspector: Option<String>,
    /// Optional exact-name filter (within the tenant +
    /// inspector scope).
    #[serde(default)]
    pub name: Option<String>,
    /// `true` ⇒ only enabled rows, `false` ⇒ only
    /// disabled. Unset ⇒ both.
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

// --- Handlers ----------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/inspection_rules",
    tag = "inspection_rules",
    params(ListQuery),
    responses(
        (status = 200, description = "Rules in the caller's tenant", body = RuleListResponse),
        (status = 503, description = "Rules store not configured", body = ApiErrorBody),
        (status = 500, description = "Rules query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_rules(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<RuleListResponse>> {
    let store = state.policy.inspection_rules.require()?;
    let tenant_id = actor.tenant.as_str();
    let effective_limit = q.limit.min(MAX_LIST_LIMIT);
    // An unknown inspector name leaves the filter unset.
    let inspector = q.inspector.as_deref().and_then(InspectorKind::parse);
    let filter = RuleFilter {
        inspector,
        name: q.name.as_deref(),
        enabled: q.enabled,
    };
    let rules = store
        .list(tenant_id, filter, effective_limit, q.offset)
        .await
        .map_err(map_store_err)?;
    Ok(Json(RuleListResponse {
        rules: rules.into_iter().map(RuleView::from).collect(),
        limit: effective_limit,
        offset: q.offset,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/inspection_rules/{id}",
    tag = "inspection_rules",
    params(("id" = Uuid, Path, description = "Rule UUID")),
    responses(
        (status = 200, description = "Rule detail", body = RuleView),
        (status = 404, description = "Rule not found in this tenant", body = ApiErrorBody),
        (status = 503, description = "Rules store not configured", body = ApiErrorBody),
        (status = 500, description = "Rules query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn get_rule(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<RuleView>> {
    let store = state.policy.inspection_rules.require()?;
    let rule = store
        .get(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::NotFound("inspection rule"))?;
    Ok(Json(RuleView::from(rule)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/inspection_rules/{id}",
    tag = "inspection_rules",
    params(("id" = Uuid, Path, description = "Rule UUID")),
    responses(
        (status = 204, description = "Rule deleted"),
        (status = 404, description = "Rule not found in this tenant", body = ApiErrorBody),
        (status = 503, description = "Rules store not configured", body = ApiErrorBody),
        (status = 500, description = "Rules store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn delete_rule(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if delete_rule_core(&state, &actor, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("inspection rule"))
    }
}

/// Shared delete path: store-check → `delete` → fail-closed audit.
/// `Ok(false)` ⇒ no such rule in this tenant (REST → 404, dashboard →
/// "no longer exists" banner).
pub(crate) async fn delete_rule_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    id: Uuid,
) -> ApiResult<bool> {
    let store = state.policy.inspection_rules.require()?;
    let removed = store
        .delete(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?;
    if removed {
        // Durable AdminMutation evidence BEFORE the 204 lands so an
        // audit reader pivots on the evidence row, not the (now-gone)
        // inspection_rules row. Only the id remains
        // (the row was hard-deleted); the audit chain fills in the
        // prior shape if needed.
        crate::admin_mutation::record_admin_mutation(
            state,
            "inspection_rules",
            "GET /api/v1/admin/inspection_rules",
            actor.tenant.as_str(),
            Some(actor),
            "InspectionRuleDeleted",
            format!("deleted rule id={id}"),
        )
        .await?;
    }
    Ok(removed)
}

fn map_store_err(e: RuleError) -> ApiError {
    match e {
        RuleError::DuplicateName => ApiError::Conflict(
            "rule with the same (tenant, inspector, name) already exists".to_owned(),
        ),
        RuleError::Database(_) => ApiError::Internal(format!("inspection rules store: {e}")),
    }
}

/// Stored configuration retained for inspection and deletion, not enforcement.
#[derive(Debug, Serialize, ToSchema)]
pub struct RuleView {
    #[serde(flatten)]
    pub rule: InspectionRule,
    pub enforcement: RuleEnforcement,
}

#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleEnforcement {
    NotEnforced,
}

impl From<InspectionRule> for RuleView {
    fn from(rule: InspectionRule) -> Self {
        Self {
            rule,
            enforcement: RuleEnforcement::NotEnforced,
        }
    }
}
