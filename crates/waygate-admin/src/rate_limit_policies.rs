//! `/api/v1/admin/rate_limit_policies/*` — admin CRUD for the
//! per-tenant rate-limit policies.
//!
//! Endpoints (all mcp:admin-gated):
//!
//! - `GET    /api/v1/admin/rate_limit_policies`        — list
//! - `POST   /api/v1/admin/rate_limit_policies`        — create
//! - `GET    /api/v1/admin/rate_limit_policies/{id}`   — read
//! - `PATCH  /api/v1/admin/rate_limit_policies/{id}`   — update (capacity / refill only)
//! - `DELETE /api/v1/admin/rate_limit_policies/{id}`   — delete
//!
//! ## Tenant scoping
//!
//! Per-tenant: each operator only sees + modifies their own
//! tenant's policies (read from `principal.tenant`). The store
//! filters `WHERE tenant_id = $1` on every query so the admin
//! API can't accidentally cross-read.
//!
//! ## Audit posture
//!
//! Same fail-closed `record_required` discipline as RBAC and
//! tenants: mutation failures → HTTP 500. Cascade
//! invalidation is unnecessary here because the QuotaService
//! reads rows directly per-call (no cache layer to flush) —
//! changes take effect on the next invocation immediately.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_oidc::Principal;
use waygate_quota::{QuotaAction, QuotaScope, RateLimitPolicy, RateLimitStoreError};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/rate_limit_policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/api/v1/admin/rate_limit_policies/{id}",
            get(get_policy).patch(update_policy).delete(delete_policy),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportedQuotaScope {
    Tenant,
    Principal,
    Server,
    Tool,
}

#[derive(Debug, Deserialize, ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportedQuotaAction {
    Call,
    SideEffectingCall,
    Discovery,
}

fn deserialize_scope<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<QuotaScope, D::Error> {
    Ok(match SupportedQuotaScope::deserialize(deserializer)? {
        SupportedQuotaScope::Tenant => QuotaScope::Tenant,
        SupportedQuotaScope::Principal => QuotaScope::Principal,
        SupportedQuotaScope::Server => QuotaScope::Server,
        SupportedQuotaScope::Tool => QuotaScope::Tool,
    })
}

fn deserialize_action<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<QuotaAction, D::Error> {
    Ok(match SupportedQuotaAction::deserialize(deserializer)? {
        SupportedQuotaAction::Call => QuotaAction::Call,
        SupportedQuotaAction::SideEffectingCall => QuotaAction::SideEffectingCall,
        SupportedQuotaAction::Discovery => QuotaAction::Discovery,
    })
}

#[derive(Debug, Deserialize, ToSchema, schemars::JsonSchema)]
pub struct CreatePolicyRequest {
    pub name: String,
    #[serde(deserialize_with = "deserialize_scope")]
    #[schema(value_type = SupportedQuotaScope)]
    #[schemars(with = "SupportedQuotaScope")]
    pub scope: QuotaScope,
    /// Required for every scope EXCEPT `tenant`. Validated at
    /// the HTTP boundary so the operator gets a 400 with a clear
    /// "scope_value required for scope=X" message rather than a
    /// raw 23514 CHECK violation surfacing as 400 with a
    /// Postgres error string.
    #[serde(default)]
    pub scope_value: Option<String>,
    pub bucket_capacity: i32,
    pub refill_per_second: f64,
    #[serde(deserialize_with = "deserialize_action")]
    #[schema(value_type = SupportedQuotaAction)]
    #[schemars(with = "SupportedQuotaAction")]
    pub action: QuotaAction,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    /// `None` ⇒ leave bucket_capacity unchanged.
    #[serde(default)]
    pub bucket_capacity: Option<i32>,
    /// `None` ⇒ leave refill_per_second unchanged.
    #[serde(default)]
    pub refill_per_second: Option<f64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyListResponse {
    pub items: Vec<PolicyView>,
}

/// View shape returned by the API. Mirrors `RateLimitPolicy`
/// but with a `ToSchema` derive that utoipa can register
/// without dragging `time::OffsetDateTime`'s native shape into
/// the OpenAPI surface — we serialise timestamps as RFC 3339
/// strings.
#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub scope: QuotaScope,
    pub scope_value: Option<String>,
    pub bucket_capacity: i32,
    pub refill_per_second: f64,
    pub action: QuotaAction,
    /// Present when this policy is unsupported and does not protect calls.
    pub inactive_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<RateLimitPolicy> for PolicyView {
    fn from(p: RateLimitPolicy) -> Self {
        Self {
            inactive_reason: p.inactive_reason().map(str::to_owned),
            id: p.id.to_string(),
            tenant_id: p.tenant_id,
            name: p.name,
            scope: p.scope,
            scope_value: p.scope_value,
            bucket_capacity: p.bucket_capacity,
            refill_per_second: p.refill_per_second,
            action: p.action,
            created_at: format_ts_rfc3339(p.created_at),
            updated_at: format_ts_rfc3339(p.updated_at),
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/rate_limit_policies",
    tag = "rate_limit_policies",
    responses(
        (status = 200, description = "Every rate-limit policy in the calling principal's tenant", body = PolicyListResponse),
        (status = 503, description = "Rate-limit store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_policies(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
) -> ApiResult<Json<PolicyListResponse>> {
    let store = state.policy.rate_limit_policies.require()?;
    let items = store
        .list(principal.tenant.as_str())
        .await
        .map_err(map_store_err)?
        .into_iter()
        .map(PolicyView::from)
        .collect();
    Ok(Json(PolicyListResponse { items }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/rate_limit_policies",
    tag = "rate_limit_policies",
    request_body = CreatePolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyView),
        (status = 400, description = "Invalid input (bad scope_value shape, non-positive capacity/refill)", body = ApiErrorBody),
        (status = 409, description = "A policy already exists for this (scope, scope_value, action)", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "Rate-limit store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn create_policy(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<CreatePolicyRequest>,
) -> Response {
    match create_policy_core(&state, principal.tenant.as_str(), &principal, &req).await {
        Ok(p) => (StatusCode::CREATED, Json(PolicyView::from(p))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared create path: store-check → validate → `store.create` →
/// fail-closed audit. Both the REST `create_policy` handler and the
/// dashboard's inline composer call this so the HTML and JSON surfaces
/// can't drift on validation or the uniqueness conflict mapping.
pub(crate) async fn create_policy_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    req: &CreatePolicyRequest,
) -> Result<RateLimitPolicy, ApiError> {
    let store = state.policy.rate_limit_policies.require()?;
    validate_create(req)?;
    let p = store
        .create(
            tenant_id,
            &req.name,
            req.scope,
            req.scope_value.as_deref(),
            req.bucket_capacity,
            req.refill_per_second,
            req.action,
        )
        .await
        .map_err(map_store_err)?;
    crate::admin_mutation::record_admin_mutation(
        state,
        "rate_limit_policies",
        "GET /api/v1/admin/rate_limit_policies",
        tenant_id,
        Some(actor),
        "rate_limit_policies.create",
        format!(
            "policy id={} name={} scope={} scope_value={:?} \
             capacity={} refill={} action={}",
            p.id,
            p.name,
            p.scope.as_str(),
            p.scope_value,
            p.bucket_capacity,
            p.refill_per_second,
            p.action.as_str(),
        ),
    )
    .await?;
    Ok(p)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/rate_limit_policies/{id}",
    tag = "rate_limit_policies",
    params(("id" = String, Path, description = "Policy id (UUID)")),
    responses(
        (status = 200, description = "Policy", body = PolicyView),
        (status = 404, description = "Policy not found in this tenant", body = ApiErrorBody),
        (status = 503, description = "Rate-limit store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn get_policy(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Json<PolicyView>> {
    let store = state.policy.rate_limit_policies.require()?;
    let uuid = parse_uuid(&id)?;
    match store
        .get(principal.tenant.as_str(), uuid)
        .await
        .map_err(map_store_err)?
    {
        Some(p) => Ok(Json(PolicyView::from(p))),
        None => Err(ApiError::NotFoundDyn(format!(
            "rate_limit_policy {id} in tenant `{}`",
            principal.tenant.as_str()
        ))),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/rate_limit_policies/{id}",
    tag = "rate_limit_policies",
    params(("id" = String, Path, description = "Policy id (UUID)")),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "Updated policy", body = PolicyView),
        (status = 400, description = "Invalid input (non-positive capacity/refill)", body = ApiErrorBody),
        (status = 404, description = "Policy not found in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "Rate-limit store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn update_policy(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Response {
    let tenant_id = principal.tenant.as_str();
    match update_policy_core(
        &state,
        tenant_id,
        &principal,
        &id,
        req.bucket_capacity,
        req.refill_per_second,
    )
    .await
    {
        Ok(Some(p)) => Json(PolicyView::from(p)).into_response(),
        Ok(None) => {
            ApiError::NotFoundDyn(format!("rate_limit_policy {id} in tenant `{tenant_id}`"))
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Shared update path: store-check → parse uuid → validate →
/// `store.update` → fail-closed audit. `id` is taken as `&str` (parsed
/// inside) so the 503-before-400 ordering is preserved on both
/// surfaces. `Ok(None)` ⇒ no such policy in this tenant. Only
/// `bucket_capacity` / `refill_per_second` are mutable (the
/// (scope, scope_value, action) tuple is the identity).
pub(crate) async fn update_policy_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    id: &str,
    bucket_capacity: Option<i32>,
    refill_per_second: Option<f64>,
) -> Result<Option<RateLimitPolicy>, ApiError> {
    let store = state.policy.rate_limit_policies.require()?;
    let uuid = parse_uuid(id)?;
    let req = UpdatePolicyRequest {
        bucket_capacity,
        refill_per_second,
    };
    validate_update(&req)?;
    if let Some(policy) = store.get(tenant_id, uuid).await.map_err(map_store_err)? {
        if let Some(reason) = policy.inactive_reason() {
            return Err(ApiError::BadRequest(reason.into()));
        }
    }
    match store
        .update(tenant_id, uuid, bucket_capacity, refill_per_second)
        .await
        .map_err(map_store_err)?
    {
        Some(p) => {
            crate::admin_mutation::record_admin_mutation(
                state,
                "rate_limit_policies",
                "GET /api/v1/admin/rate_limit_policies",
                tenant_id,
                Some(actor),
                "rate_limit_policies.update",
                format!(
                    "policy id={} capacity={} refill={}",
                    p.id, p.bucket_capacity, p.refill_per_second
                ),
            )
            .await?;
            Ok(Some(p))
        }
        None => Ok(None),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/rate_limit_policies/{id}",
    tag = "rate_limit_policies",
    params(("id" = String, Path, description = "Policy id (UUID)")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Policy not found in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "Rate-limit store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_policy(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    let tenant_id = principal.tenant.as_str();
    match delete_policy_core(&state, tenant_id, &principal, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            ApiError::NotFoundDyn(format!("rate_limit_policy {id} in tenant `{tenant_id}`"))
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Shared delete path: store-check → parse uuid → prefetch (for the
/// audit reason) → `store.delete` → fail-closed audit. `id` is `&str`
/// (parsed inside) to preserve 503-before-400 ordering. `Ok(false)` ⇒
/// no such policy in this tenant.
pub(crate) async fn delete_policy_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    id: &str,
) -> Result<bool, ApiError> {
    let store = state.policy.rate_limit_policies.require()?;
    let uuid = parse_uuid(id)?;
    // Prefetch so the audit row records the policy's identity before the
    // delete blows it away. Mirrors the RBAC and tenants delete handlers.
    let pre = store.get(tenant_id, uuid).await.ok().flatten();
    if store.delete(tenant_id, uuid).await.map_err(map_store_err)? {
        let reason = match pre.as_ref() {
            Some(p) => format!(
                "policy id={} name={} scope={} action={}",
                p.id,
                p.name,
                p.scope.as_str(),
                p.action.as_str(),
            ),
            None => format!("policy id={id} (prefetch failed)"),
        };
        crate::admin_mutation::record_admin_mutation(
            state,
            "rate_limit_policies",
            "GET /api/v1/admin/rate_limit_policies",
            tenant_id,
            Some(actor),
            "rate_limit_policies.delete",
            reason,
        )
        .await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ---- helpers --------------------------------------------------

fn parse_uuid(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|e| ApiError::BadRequest(format!("invalid policy id: {e}")))
}

fn validate_create(req: &CreatePolicyRequest) -> Result<(), ApiError> {
    if req.scope == QuotaScope::Client || req.action == QuotaAction::CostBearing {
        return Err(ApiError::BadRequest(
            "Client scope and cost_bearing action are not enforced and cannot be configured."
                .into(),
        ));
    }
    if req.name.is_empty() || req.name.len() > 128 {
        return Err(ApiError::BadRequest(
            "`name` must be non-empty and ≤128 chars".into(),
        ));
    }
    if req.bucket_capacity <= 0 {
        return Err(ApiError::BadRequest("`bucket_capacity` must be > 0".into()));
    }
    if !req.refill_per_second.is_finite() || req.refill_per_second <= 0.0 {
        return Err(ApiError::BadRequest(
            "`refill_per_second` must be > 0 (finite)".into(),
        ));
    }
    // Enforce the scope/scope_value pairing at the HTTP boundary so
    // the operator gets a clear 400 rather than a raw SQL CHECK
    // message. Mirrors the migration's
    // `rate_limit_policies_scope_value_shape` CHECK.
    match (req.scope, req.scope_value.as_deref()) {
        (QuotaScope::Tenant, Some(_)) => Err(ApiError::BadRequest(
            "`scope_value` must be omitted when scope=tenant (the policy's tenant_id is the bucket key)".into(),
        )),
        (QuotaScope::Tenant, None) => Ok(()),
        (_, None) | (_, Some("")) => Err(ApiError::BadRequest(format!(
            "`scope_value` is required for scope={}",
            req.scope.as_str(),
        ))),
        (_, Some(_)) => Ok(()),
    }
}

fn validate_update(req: &UpdatePolicyRequest) -> Result<(), ApiError> {
    if let Some(c) = req.bucket_capacity {
        if c <= 0 {
            return Err(ApiError::BadRequest("`bucket_capacity` must be > 0".into()));
        }
    }
    if let Some(r) = req.refill_per_second {
        if !r.is_finite() || r <= 0.0 {
            return Err(ApiError::BadRequest(
                "`refill_per_second` must be > 0 (finite)".into(),
            ));
        }
    }
    Ok(())
}

fn map_store_err(e: RateLimitStoreError) -> ApiError {
    match e {
        RateLimitStoreError::Conflict => ApiError::Conflict(
            "a policy already exists for this (scope, scope_value, action) — \
             DELETE the existing one to replace its config"
                .into(),
        ),
        RateLimitStoreError::InvalidShape(msg) => ApiError::BadRequest(msg),
        RateLimitStoreError::Sqlx(e) => {
            tracing::error!(error = %e, "rate_limit_policies store error");
            ApiError::Internal("rate_limit_policies store error".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(scope: QuotaScope, scope_value: Option<&str>) -> CreatePolicyRequest {
        CreatePolicyRequest {
            name: "n".into(),
            scope,
            scope_value: scope_value.map(str::to_owned),
            bucket_capacity: 10,
            refill_per_second: 1.0,
            action: QuotaAction::Call,
        }
    }

    #[test]
    fn unsupported_policies_are_rejected_by_input_and_core_validation() {
        let base = serde_json::json!({"name":"quota", "scope":"tenant", "bucket_capacity":10, "refill_per_second":1.0, "action":"call"});
        assert!(serde_json::from_value::<CreatePolicyRequest>(base.clone()).is_ok());
        for (field, value) in [("scope", "client"), ("action", "cost_bearing")] {
            let mut input = base.clone();
            input[field] = value.into();
            assert!(serde_json::from_value::<CreatePolicyRequest>(input).is_err());
        }
        assert!(validate_create(&req(QuotaScope::Client, Some("client-id"))).is_err());
        let mut unsupported = req(QuotaScope::Tenant, None);
        unsupported.action = QuotaAction::CostBearing;
        assert!(validate_create(&unsupported).is_err());
    }

    #[test]
    fn creation_schema_only_offers_supported_controls() {
        let schema = serde_json::to_value(schemars::schema_for!(CreatePolicyRequest)).unwrap();
        let definitions = &schema["$defs"];
        assert_eq!(
            definitions["SupportedQuotaScope"]["enum"],
            serde_json::json!(["tenant", "principal", "server", "tool"])
        );
        assert_eq!(
            definitions["SupportedQuotaAction"]["enum"],
            serde_json::json!(["call", "side_effecting_call", "discovery"])
        );
    }

    #[test]
    fn openapi_creation_schema_only_offers_supported_controls() {
        use utoipa::OpenApi;
        let document = serde_json::to_value(crate::openapi::ApiDoc::openapi()).unwrap();
        let schemas = &document["components"]["schemas"];
        let properties = &schemas["CreatePolicyRequest"]["properties"];
        for (field, expected) in [
            (
                "scope",
                serde_json::json!(["tenant", "principal", "server", "tool"]),
            ),
            (
                "action",
                serde_json::json!(["call", "side_effecting_call", "discovery"]),
            ),
        ] {
            let reference = properties[field]["$ref"].as_str().expect("enum reference");
            let schema = document
                .pointer(reference.strip_prefix('#').unwrap())
                .expect("referenced enum must exist in OpenAPI components");
            assert_eq!(schema["enum"], expected);
        }
    }

    #[test]
    fn tenant_scope_rejects_scope_value() {
        let r = req(QuotaScope::Tenant, Some("acme"));
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
    }

    #[test]
    fn tenant_scope_accepts_none() {
        let r = req(QuotaScope::Tenant, None);
        assert!(validate_create(&r).is_ok());
    }

    #[test]
    fn non_tenant_scopes_require_scope_value() {
        for scope in [QuotaScope::Principal, QuotaScope::Server, QuotaScope::Tool] {
            assert!(
                matches!(
                    validate_create(&req(scope, None)),
                    Err(ApiError::BadRequest(_))
                ),
                "scope={scope:?} should require scope_value",
            );
            assert!(
                matches!(
                    validate_create(&req(scope, Some(""))),
                    Err(ApiError::BadRequest(_))
                ),
                "scope={scope:?} should reject empty scope_value",
            );
            assert!(
                validate_create(&req(scope, Some("foo"))).is_ok(),
                "scope={scope:?} should accept non-empty scope_value",
            );
        }
    }

    #[test]
    fn rejects_non_positive_capacity_and_refill() {
        let mut r = req(QuotaScope::Tenant, None);
        r.bucket_capacity = 0;
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.bucket_capacity = 10;
        r.refill_per_second = 0.0;
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.refill_per_second = f64::NAN;
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.refill_per_second = f64::INFINITY;
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
    }

    #[test]
    fn rejects_empty_or_oversized_name() {
        let mut r = req(QuotaScope::Tenant, None);
        r.name = "".into();
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.name = "x".repeat(129);
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.name = "x".repeat(128);
        assert!(validate_create(&r).is_ok());
    }

    #[test]
    fn update_validates_capacity_and_refill_when_present() {
        assert!(validate_update(&UpdatePolicyRequest {
            bucket_capacity: Some(0),
            refill_per_second: None,
        })
        .is_err());
        assert!(validate_update(&UpdatePolicyRequest {
            bucket_capacity: None,
            refill_per_second: Some(-1.0),
        })
        .is_err());
        assert!(validate_update(&UpdatePolicyRequest {
            bucket_capacity: None,
            refill_per_second: None,
        })
        .is_ok());
        assert!(validate_update(&UpdatePolicyRequest {
            bucket_capacity: Some(1),
            refill_per_second: Some(0.5),
        })
        .is_ok());
    }

    #[test]
    fn map_store_err_conflict_to_409() {
        assert!(matches!(
            map_store_err(RateLimitStoreError::Conflict),
            ApiError::Conflict(_)
        ));
    }

    #[test]
    fn map_store_err_invalid_shape_to_400() {
        assert!(matches!(
            map_store_err(RateLimitStoreError::InvalidShape("x".into())),
            ApiError::BadRequest(_)
        ));
    }
}
