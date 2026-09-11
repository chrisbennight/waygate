//! `/api/v1/admin/inspection_rules` — per-tenant
//! response-inspector rule overrides.
//!
//! Operators page, create, update, and delete custom
//! inspector rules layered on top of the built-in PII /
//! secrets / poisoning rulesets. Every
//! endpoint is behind `mcp:admin` and tenant-scoped via
//! `principal.tenant` (NOT via anything in the request) —
//! same shape as `oauth_consent`, `break_glass`, `tasks`.
//!
//! ## Slice 1 scope
//!
//! Admin CRUD only. Rows are inert at the runtime layer
//! until a runtime consumer wires the inspector that reads
//! from `inspection_rules` on each invoke (or via a cached
//! refresh worker). Until then, this surface lets
//! operators seed rules ahead of the flip.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_dashboard_stores::inspection_rules::{
    InspectionRule, InspectorKind, NewInspectionRule, RuleError, RuleFilter, RuleUpdate,
    MAX_LIST_LIMIT,
};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/inspection_rules",
            get(list_rules).post(create_rule),
        )
        .route(
            "/api/v1/admin/inspection_rules/{id}",
            get(get_rule).patch(update_rule).delete(delete_rule),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

// --- DTOs --------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema, schemars::JsonSchema)]
pub struct CreateRuleRequest {
    pub inspector: InspectorKind,
    /// Operator-friendly label; unique within
    /// (tenant, inspector). 1–128 chars.
    pub name: String,
    /// Inspector-specific rule body. Shape is opaque to
    /// this slice's storage — the runtime consumer
    /// validates per inspector kind.
    pub config: Value,
    /// Optional `applies_to` selector. Defaults to `{}`
    /// (any tool, any principal).
    #[serde(default)]
    pub applies_to: Option<Value>,
    /// Defaults to `true` (rule is active immediately).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub config: Option<Value>,
    pub applies_to: Option<Value>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleListResponse {
    pub rules: Vec<InspectionRule>,
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

const NAME_MIN: usize = 1;
const NAME_MAX: usize = 128;

fn validate_name(name: &str) -> Result<(), ApiError> {
    let len = name.chars().count();
    if !(NAME_MIN..=NAME_MAX).contains(&len) {
        return Err(ApiError::BadRequest(format!(
            "name length must be between {NAME_MIN} and {NAME_MAX} chars",
        )));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/inspection_rules",
    tag = "inspection_rules",
    request_body = CreateRuleRequest,
    responses(
        (status = 201, description = "Rule created", body = InspectionRule),
        (status = 400, description = "Invalid rule fields", body = ApiErrorBody),
        (status = 409, description = "Duplicate (tenant, inspector, name)", body = ApiErrorBody),
        (status = 503, description = "Rules store not configured", body = ApiErrorBody),
        (status = 500, description = "Rules store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn create_rule(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Json(body): Json<CreateRuleRequest>,
) -> ApiResult<(StatusCode, Json<InspectionRule>)> {
    let applies_to = body
        .applies_to
        .unwrap_or_else(|| Value::Object(Default::default()));
    let rule = create_rule_core(
        &state,
        &actor,
        body.inspector,
        &body.name,
        &body.config,
        &applies_to,
        body.enabled,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

/// Shared create path: store-check → validate name → `insert` →
/// fail-closed audit. Both the REST `create_rule` handler and the
/// dashboard composer call this so validation, the
/// (tenant, inspector, name) uniqueness conflict, and the durable
/// AdminMutation evidence can't drift between the HTML and JSON
/// surfaces. Tenant comes from `actor.tenant` (never the request).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_rule_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    inspector: InspectorKind,
    name: &str,
    config: &Value,
    applies_to: &Value,
    enabled: bool,
) -> ApiResult<InspectionRule> {
    let store = state.policy.inspection_rules.require()?;
    validate_name(name)?;
    let rule = store
        .insert(NewInspectionRule {
            tenant_id: actor.tenant.as_str(),
            inspector,
            name,
            config,
            applies_to,
            enabled,
        })
        .await
        .map_err(map_store_err)?;
    // Durable AdminMutation evidence BEFORE responding so a tampered
    // chain pivots on this row, not just the (mutable)
    // inspection_rules row.
    crate::admin_mutation::record_admin_mutation(
        state,
        "inspection_rules",
        "GET /api/v1/admin/inspection_rules",
        actor.tenant.as_str(),
        Some(actor),
        "InspectionRuleCreated",
        format!(
            "created rule id={} inspector={} name={}",
            rule.id,
            rule.inspector.as_str(),
            rule.name
        ),
    )
    .await?;
    Ok(rule)
}

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
    // Unknown inspector string ⇒ no filter (silently
    // dropped — same posture as the tasks.rs status
    // filter).
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
        rules,
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
        (status = 200, description = "Rule detail", body = InspectionRule),
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
) -> ApiResult<Json<InspectionRule>> {
    let store = state.policy.inspection_rules.require()?;
    let rule = store
        .get(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::NotFound("inspection rule"))?;
    Ok(Json(rule))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/inspection_rules/{id}",
    tag = "inspection_rules",
    params(("id" = Uuid, Path, description = "Rule UUID")),
    request_body = UpdateRuleRequest,
    responses(
        (status = 200, description = "Rule updated", body = InspectionRule),
        (status = 400, description = "Invalid rule fields", body = ApiErrorBody),
        (status = 404, description = "Rule not found in this tenant", body = ApiErrorBody),
        (status = 409, description = "Rename collides with existing (tenant, inspector, name)", body = ApiErrorBody),
        (status = 503, description = "Rules store not configured", body = ApiErrorBody),
        (status = 500, description = "Rules store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn update_rule(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateRuleRequest>,
) -> ApiResult<Json<InspectionRule>> {
    let rule = update_rule_core(
        &state,
        &actor,
        id,
        body.name.as_deref(),
        body.config.as_ref(),
        body.applies_to.as_ref(),
        body.enabled,
    )
    .await?
    .ok_or(ApiError::NotFound("inspection rule"))?;
    Ok(Json(rule))
}

/// Shared update path: store-check → validate name → `update` →
/// fail-closed audit. `Ok(None)` ⇒ no such rule in this tenant. Both
/// surfaces call this; the REST handler maps `None` to a 404, the
/// dashboard to a "no longer exists" banner.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_rule_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    id: Uuid,
    name: Option<&str>,
    config: Option<&Value>,
    applies_to: Option<&Value>,
    enabled: Option<bool>,
) -> ApiResult<Option<InspectionRule>> {
    let store = state.policy.inspection_rules.require()?;
    if let Some(n) = name {
        validate_name(n)?;
    }
    let updated = store
        .update(
            actor.tenant.as_str(),
            id,
            RuleUpdate {
                name,
                config,
                applies_to,
                enabled,
            },
        )
        .await
        .map_err(map_store_err)?;
    let Some(rule) = updated else {
        return Ok(None);
    };
    // Durable AdminMutation audit on update. The reason carries the
    // post-update enabled state so operators can pivot on
    // enable/disable flips without joining to the rule row (which
    // may have been further updated since).
    crate::admin_mutation::record_admin_mutation(
        state,
        "inspection_rules",
        "GET /api/v1/admin/inspection_rules",
        actor.tenant.as_str(),
        Some(actor),
        "InspectionRuleUpdated",
        format!(
            "updated rule id={} inspector={} name={} enabled={}",
            rule.id,
            rule.inspector.as_str(),
            rule.name,
            rule.enabled,
        ),
    )
    .await?;
    Ok(Some(rule))
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
