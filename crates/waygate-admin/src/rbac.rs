//! `/api/v1/admin/rbac/*` — RBAC admin REST CRUD.
//!
//! Companion to `waygate_rbac::PgRbacStore`.
//! Endpoints:
//!
//! - `GET    /api/v1/admin/rbac/roles`                              — list
//! - `POST   /api/v1/admin/rbac/roles`                              — create
//! - `GET    /api/v1/admin/rbac/roles/{id}`                         — read
//! - `PUT    /api/v1/admin/rbac/roles/{id}`                         — update
//! - `DELETE /api/v1/admin/rbac/roles/{id}`                         — delete
//! - `GET    /api/v1/admin/rbac/assignments`                        — list (optional `role_id`, `subject_sub` query)
//! - `POST   /api/v1/admin/rbac/assignments`                        — create
//! - `DELETE /api/v1/admin/rbac/assignments/{id}`                   — delete
//! - `GET    /api/v1/admin/rbac/group-mappings`                     — list (optional `role_id`, `group_id` query)
//! - `POST   /api/v1/admin/rbac/group-mappings`                     — create
//! - `DELETE /api/v1/admin/rbac/group-mappings/{group_id}/{role_id}` — delete
//!
//! All gated by `mcp:admin` scope. Every mutating handler emits an
//! `AdminMutation` evidence event via `record_required` — RBAC
//! changes are compliance-significant (granting an admin role is a
//! security event), so we fail-closed on audit-sink failures to
//! match the existing `AdminMutation` discipline.
//!
//! Tenant isolation: every handler scopes by `principal.tenant`.
//! Cross-tenant reads/writes are structurally impossible.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_oidc::Principal;
use waygate_rbac::{GroupRoleMapping, RbacError, Role, RoleAssignment};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/rbac/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/api/v1/admin/rbac/roles/{id}",
            get(get_role).put(update_role).delete(delete_role),
        )
        .route(
            "/api/v1/admin/rbac/assignments",
            get(list_assignments).post(create_assignment),
        )
        .route(
            "/api/v1/admin/rbac/assignments/{id}",
            delete(delete_assignment),
        )
        .route(
            "/api/v1/admin/rbac/group-mappings",
            get(list_group_mappings).post(create_group_mapping),
        )
        .route(
            "/api/v1/admin/rbac/group-mappings/{group_id}/{role_id}",
            delete(delete_group_mapping),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

// ---- Roles ---------------------------------------------------

#[derive(Debug, Deserialize, ToSchema, schemars::JsonSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// utoipa's `ToSchema` derive doesn't
/// gracefully handle generic wrappers, so each list endpoint
/// uses its own concrete shape rather than a single generic
/// `ListResponse<T>`. Same JSON shape on the wire (`{ items:
/// [...] }`); per-type structs keep the generated OpenAPI clean.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleListResponse {
    pub items: Vec<Role>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AssignmentListResponse {
    pub items: Vec<RoleAssignment>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupMappingListResponse {
    pub items: Vec<GroupRoleMapping>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/rbac/roles",
    tag = "rbac",
    responses(
        (status = 200, description = "Roles for the caller's tenant, alphabetised by name", body = RoleListResponse),
        (status = 503, description = "RBAC store not configured (no Postgres pool)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_roles(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
) -> ApiResult<Json<RoleListResponse>> {
    let store = state.identity.rbac.require()?;
    let items = store
        .list_roles(principal.tenant.as_str())
        .await
        .map_err(map_rbac_err)?;
    Ok(Json(RoleListResponse { items }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/rbac/roles",
    tag = "rbac",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = Role),
        (status = 400, description = "Invalid input (empty name, oversized name, empty scope entry)", body = ApiErrorBody),
        (status = 409, description = "Role name already exists in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed (mutation committed; verify via GET /roles)", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn create_role(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<CreateRoleRequest>,
) -> Response {
    match create_role_core(
        &state,
        principal.tenant.as_str(),
        Some(&principal),
        &req.name,
        req.description.as_deref(),
        &req.scopes,
    )
    .await
    {
        Ok(role) => (StatusCode::CREATED, Json(role)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared create-role path: store-check → `validate_role_input` →
/// `store.create_role` → resolver-cache invalidate → fail-closed
/// `AdminMutation` audit. Both the REST `create_role` handler and the
/// dashboard's in-page form call this, so the JSON and HTML surfaces
/// can't drift. Cache invalidate runs BEFORE the audit write so a
/// revoked/granted role is never served stale even if the
/// audit-of-record subsequently fails.
pub(crate) async fn create_role_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    name: &str,
    description: Option<&str>,
    scopes: &[String],
) -> Result<Role, ApiError> {
    let store = state.identity.rbac.require()?;
    validate_role_input(name, scopes)?;
    let role = store
        .create_role(tenant_id, name, description, scopes)
        .await
        .map_err(map_rbac_err)?;
    invalidate_rbac_cache(state);
    crate::admin_mutation::record_admin_mutation(
        state,
        "rbac",
        "GET /api/v1/admin/rbac/roles",
        tenant_id,
        actor,
        "rbac.create_role",
        format!(
            "role id={} name={} scopes=[{}]",
            role.id,
            role.name,
            role.scopes.join(",")
        ),
    )
    .await?;
    Ok(role)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/rbac/roles/{id}",
    tag = "rbac",
    params(("id" = Uuid, Path, description = "Role id")),
    responses(
        (status = 200, description = "Role", body = Role),
        (status = 404, description = "Role not found in this tenant", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn get_role(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Role>> {
    let store = state.identity.rbac.require()?;
    match store
        .get_role(principal.tenant.as_str(), id)
        .await
        .map_err(map_rbac_err)?
    {
        Some(r) => Ok(Json(r)),
        None => Err(ApiError::NotFoundDyn(format!("role {id}"))),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/rbac/roles/{id}",
    tag = "rbac",
    params(("id" = Uuid, Path, description = "Role id")),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Updated role", body = Role),
        (status = 400, description = "Invalid input", body = ApiErrorBody),
        (status = 404, description = "Role not found in this tenant", body = ApiErrorBody),
        (status = 409, description = "New name collides with another role in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn update_role(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRoleRequest>,
) -> Response {
    match update_role_core(
        &state,
        principal.tenant.as_str(),
        Some(&principal),
        id,
        &req.name,
        req.description.as_deref(),
        &req.scopes,
    )
    .await
    {
        Ok(Some(role)) => Json(role).into_response(),
        Ok(None) => ApiError::NotFoundDyn(format!("role {id}")).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared update-role path: store-check → validate → `store.update_role`
/// → cache invalidate → fail-closed audit. `Ok(None)` = role not found in
/// this tenant. Both the REST `update_role` handler and the dashboard's
/// edit form call this.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_role_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
    name: &str,
    description: Option<&str>,
    scopes: &[String],
) -> Result<Option<Role>, ApiError> {
    let store = state.identity.rbac.require()?;
    validate_role_input(name, scopes)?;
    let Some(role) = store
        .update_role(tenant_id, id, name, description, scopes)
        .await
        .map_err(map_rbac_err)?
    else {
        return Ok(None);
    };
    invalidate_rbac_cache(state);
    crate::admin_mutation::record_admin_mutation(
        state,
        "rbac",
        "GET /api/v1/admin/rbac/roles",
        tenant_id,
        actor,
        "rbac.update_role",
        format!(
            "role id={} name={} scopes=[{}]",
            role.id,
            role.name,
            role.scopes.join(",")
        ),
    )
    .await?;
    Ok(Some(role))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/rbac/roles/{id}",
    tag = "rbac",
    params(("id" = Uuid, Path, description = "Role id")),
    responses(
        (status = 204, description = "Deleted; assignments + mappings cascaded by FK"),
        (status = 404, description = "Role not found in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_role(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    match delete_role_core(&state, principal.tenant.as_str(), Some(&principal), id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => ApiError::NotFoundDyn(format!("role {id}")).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared delete-role path: store-check → prefetch (for the audit
/// reason) → `store.delete_role` (assignments + mappings cascade by FK)
/// → cache invalidate → fail-closed audit. Both the REST `delete_role`
/// handler and the dashboard's per-row delete form call this. `Ok(false)`
/// = no such role in this tenant.
///
/// A successful delete with a failed prefetch still audits (with
/// just the id) — never a silent unaudited delete.
pub(crate) async fn delete_role_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
) -> Result<bool, ApiError> {
    let store = state.identity.rbac.require()?;
    let pre = store.get_role(tenant_id, id).await.ok().flatten();
    if !store
        .delete_role(tenant_id, id)
        .await
        .map_err(map_rbac_err)?
    {
        return Ok(false);
    }
    let reason = match pre.as_ref() {
        Some(role) => format!(
            "role id={} name={} scopes=[{}]",
            role.id,
            role.name,
            role.scopes.join(",")
        ),
        None => format!("role id={id} (prefetch failed — name/scopes unknown)"),
    };
    invalidate_rbac_cache(state);
    crate::admin_mutation::record_admin_mutation(
        state,
        "rbac",
        "GET /api/v1/admin/rbac/roles",
        tenant_id,
        actor,
        "rbac.delete_role",
        reason,
    )
    .await?;
    Ok(true)
}

// ---- Assignments ---------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAssignmentRequest {
    pub role_id: Uuid,
    pub subject_sub: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct AssignmentListQuery {
    #[serde(default)]
    pub role_id: Option<Uuid>,
    #[serde(default)]
    pub subject_sub: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/rbac/assignments",
    tag = "rbac",
    params(
        ("role_id" = Option<Uuid>, Query, description = "Filter by role id"),
        ("subject_sub" = Option<String>, Query, description = "Filter by JWT subject sub"),
    ),
    responses(
        (status = 200, description = "Assignments for the caller's tenant", body = AssignmentListResponse),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_assignments(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Query(q): Query<AssignmentListQuery>,
) -> ApiResult<Json<AssignmentListResponse>> {
    let store = state.identity.rbac.require()?;
    let items = store
        .list_assignments(
            principal.tenant.as_str(),
            q.role_id,
            q.subject_sub.as_deref(),
        )
        .await
        .map_err(map_rbac_err)?;
    Ok(Json(AssignmentListResponse { items }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/rbac/assignments",
    tag = "rbac",
    request_body = CreateAssignmentRequest,
    responses(
        (status = 201, description = "Assignment created", body = RoleAssignment),
        (status = 400, description = "Invalid input (empty subject_sub)", body = ApiErrorBody),
        (status = 409, description = "Assignment already exists for this (role, subject)", body = ApiErrorBody),
        (status = 422, description = "role_id does not exist in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn create_assignment(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<CreateAssignmentRequest>,
) -> Response {
    match create_assignment_core(
        &state,
        principal.tenant.as_str(),
        Some(&principal),
        req.role_id,
        &req.subject_sub,
    )
    .await
    {
        Ok(a) => (StatusCode::CREATED, Json(a)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared create-assignment path: store-check → non-empty
/// `subject_sub` → `store.create_assignment` → cache invalidate →
/// fail-closed audit. Both the REST handler and the dashboard form call
/// this. (`InvalidReference` from the store → 422 when `role_id` doesn't
/// exist in the tenant.)
pub(crate) async fn create_assignment_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    role_id: Uuid,
    subject_sub: &str,
) -> Result<RoleAssignment, ApiError> {
    let store = state.identity.rbac.require()?;
    if subject_sub.is_empty() {
        return Err(ApiError::BadRequest(
            "`subject_sub` must be non-empty".into(),
        ));
    }
    let a = store
        .create_assignment(tenant_id, role_id, subject_sub)
        .await
        .map_err(map_rbac_err)?;
    finish_create_assignment(state, tenant_id, actor, a).await
}

/// Governed create-assignment path. The role-version predicate and assignment
/// insert are one store operation, closing the window where an operator could
/// change the role after review but before the grant. `Ok(None)` means the
/// reviewed role version is no longer current.
pub(crate) async fn create_assignment_if_role_version_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    role_id: Uuid,
    subject_sub: &str,
    expected_role_updated_at: OffsetDateTime,
) -> Result<Option<RoleAssignment>, ApiError> {
    let store = state.identity.rbac.require()?;
    if subject_sub.is_empty() {
        return Err(ApiError::BadRequest(
            "`subject_sub` must be non-empty".into(),
        ));
    }
    let Some(a) = store
        .create_assignment_if_role_version(
            tenant_id,
            role_id,
            subject_sub,
            expected_role_updated_at,
        )
        .await
        .map_err(map_rbac_err)?
    else {
        return Ok(None);
    };
    Ok(Some(
        finish_create_assignment(state, tenant_id, actor, a).await?,
    ))
}

async fn finish_create_assignment(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    a: RoleAssignment,
) -> Result<RoleAssignment, ApiError> {
    invalidate_rbac_cache(state);
    crate::admin_mutation::record_admin_mutation(
        state,
        "rbac",
        "GET /api/v1/admin/rbac/roles",
        tenant_id,
        actor,
        "rbac.create_assignment",
        format!(
            "assignment id={} role_id={} subject_sub={}",
            a.id, a.role_id, a.subject_sub
        ),
    )
    .await?;
    Ok(a)
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/rbac/assignments/{id}",
    tag = "rbac",
    params(("id" = Uuid, Path, description = "Assignment id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Assignment not found in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_assignment(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    match delete_assignment_core(&state, principal.tenant.as_str(), Some(&principal), id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => ApiError::NotFoundDyn(format!("assignment {id}")).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared delete-assignment path: store-check → prefetch (the audit
/// reason must answer "which subject lost which role?") →
/// `store.delete_assignment` → cache invalidate → fail-closed audit.
/// Both the REST handler and the dashboard form call this.
/// `Ok(false)` = not found in this tenant.
pub(crate) async fn delete_assignment_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
) -> Result<bool, ApiError> {
    let store = state.identity.rbac.require()?;
    let pre = store.get_assignment(tenant_id, id).await.ok().flatten();
    if !store
        .delete_assignment(tenant_id, id)
        .await
        .map_err(map_rbac_err)?
    {
        return Ok(false);
    }
    let reason = match pre.as_ref() {
        Some(a) => format!(
            "assignment id={} role_id={} subject_sub={}",
            a.id, a.role_id, a.subject_sub
        ),
        None => format!("assignment id={id} (prefetch failed — role_id/subject_sub unknown)"),
    };
    finish_delete_assignment(state, tenant_id, actor, reason).await?;
    Ok(true)
}

/// Governed delete-assignment path. The assignment identity, role identity,
/// and reviewed role version are checked by the same statement that deletes
/// the row. `Ok(None)` means any part of that witness is stale.
pub(crate) async fn delete_assignment_if_role_version_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
    expected_role_id: Uuid,
    expected_role_updated_at: OffsetDateTime,
) -> Result<Option<RoleAssignment>, ApiError> {
    let store = state.identity.rbac.require()?;
    let Some(deleted) = store
        .delete_assignment_if_role_version(
            tenant_id,
            id,
            expected_role_id,
            expected_role_updated_at,
        )
        .await
        .map_err(map_rbac_err)?
    else {
        return Ok(None);
    };
    let reason = format!(
        "assignment id={} role_id={} subject_sub={}",
        deleted.id, deleted.role_id, deleted.subject_sub
    );
    finish_delete_assignment(state, tenant_id, actor, reason).await?;
    Ok(Some(deleted))
}

async fn finish_delete_assignment(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    reason: String,
) -> Result<(), ApiError> {
    invalidate_rbac_cache(state);
    crate::admin_mutation::record_admin_mutation(
        state,
        "rbac",
        "GET /api/v1/admin/rbac/roles",
        tenant_id,
        actor,
        "rbac.delete_assignment",
        reason,
    )
    .await?;
    Ok(())
}

// ---- Group mappings ------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateGroupMappingRequest {
    pub group_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Debug, Deserialize, Default)]
pub struct GroupMappingListQuery {
    #[serde(default)]
    pub role_id: Option<Uuid>,
    #[serde(default)]
    pub group_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/rbac/group-mappings",
    tag = "rbac",
    params(
        ("role_id" = Option<Uuid>, Query, description = "Filter by role id"),
        ("group_id" = Option<Uuid>, Query, description = "Filter by SCIM group id"),
    ),
    responses(
        (status = 200, description = "Group→role mappings for the caller's tenant", body = GroupMappingListResponse),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_group_mappings(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Query(q): Query<GroupMappingListQuery>,
) -> ApiResult<Json<GroupMappingListResponse>> {
    let store = state.identity.rbac.require()?;
    let items = store
        .list_group_mappings(principal.tenant.as_str(), q.role_id, q.group_id)
        .await
        .map_err(map_rbac_err)?;
    Ok(Json(GroupMappingListResponse { items }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/rbac/group-mappings",
    tag = "rbac",
    request_body = CreateGroupMappingRequest,
    responses(
        (status = 201, description = "Mapping created", body = GroupRoleMapping),
        (status = 409, description = "Mapping already exists for this (group, role)", body = ApiErrorBody),
        (status = 422, description = "group_id or role_id does not exist in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn create_group_mapping(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<CreateGroupMappingRequest>,
) -> Response {
    match create_group_mapping_core(
        &state,
        principal.tenant.as_str(),
        Some(&principal),
        req.group_id,
        req.role_id,
    )
    .await
    {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared create-group-mapping path: store-check →
/// `store.create_group_mapping` → cache invalidate → fail-closed audit.
/// Both the REST handler and the dashboard form call this.
/// (`InvalidReference` → 422 when group_id or role_id doesn't exist.)
pub(crate) async fn create_group_mapping_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    group_id: Uuid,
    role_id: Uuid,
) -> Result<GroupRoleMapping, ApiError> {
    let store = state.identity.rbac.require()?;
    let m = store
        .create_group_mapping(tenant_id, group_id, role_id)
        .await
        .map_err(map_rbac_err)?;
    finish_create_group_mapping(state, tenant_id, actor, m).await
}

/// Governed create-group-mapping path. Parent existence and the reviewed role
/// version are checked atomically with the insert. `Ok(None)` means a parent
/// vanished or the role changed.
pub(crate) async fn create_group_mapping_if_role_version_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    group_id: Uuid,
    role_id: Uuid,
    expected_role_updated_at: OffsetDateTime,
) -> Result<Option<GroupRoleMapping>, ApiError> {
    let store = state.identity.rbac.require()?;
    let Some(mapping) = store
        .create_group_mapping_if_role_version(
            tenant_id,
            group_id,
            role_id,
            expected_role_updated_at,
        )
        .await
        .map_err(map_rbac_err)?
    else {
        return Ok(None);
    };
    Ok(Some(
        finish_create_group_mapping(state, tenant_id, actor, mapping).await?,
    ))
}

async fn finish_create_group_mapping(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    m: GroupRoleMapping,
) -> Result<GroupRoleMapping, ApiError> {
    invalidate_rbac_cache(state);
    crate::admin_mutation::record_admin_mutation(
        state,
        "rbac",
        "GET /api/v1/admin/rbac/roles",
        tenant_id,
        actor,
        "rbac.create_group_mapping",
        format!("mapping group_id={} role_id={}", m.group_id, m.role_id),
    )
    .await?;
    Ok(m)
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/rbac/group-mappings/{group_id}/{role_id}",
    tag = "rbac",
    params(
        ("group_id" = Uuid, Path, description = "SCIM group id"),
        ("role_id" = Uuid, Path, description = "Role id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Mapping not found in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "RBAC store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_group_mapping(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path((group_id, role_id)): Path<(Uuid, Uuid)>,
) -> Response {
    match delete_group_mapping_core(
        &state,
        principal.tenant.as_str(),
        Some(&principal),
        group_id,
        role_id,
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            ApiError::NotFoundDyn(format!("mapping group_id={group_id} role_id={role_id}"))
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Shared delete-group-mapping path: store-check →
/// `store.delete_group_mapping` → cache invalidate → fail-closed audit.
/// Both the REST handler and the dashboard form call this. `Ok(false)` =
/// no such (group, role) mapping in this tenant.
pub(crate) async fn delete_group_mapping_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    group_id: Uuid,
    role_id: Uuid,
) -> Result<bool, ApiError> {
    let store = state.identity.rbac.require()?;
    if !store
        .delete_group_mapping(tenant_id, group_id, role_id)
        .await
        .map_err(map_rbac_err)?
    {
        return Ok(false);
    }
    finish_delete_group_mapping(state, tenant_id, actor, group_id, role_id).await?;
    Ok(true)
}

/// Governed delete-group-mapping path. The role version and mapping generation
/// are checked in the delete statement so a stale approval cannot remove a
/// replacement mapping. `Ok(None)` means the witness no longer matches.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn delete_group_mapping_if_versions_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    group_id: Uuid,
    role_id: Uuid,
    expected_mapping_created_at: OffsetDateTime,
    expected_role_updated_at: OffsetDateTime,
) -> Result<Option<GroupRoleMapping>, ApiError> {
    let store = state.identity.rbac.require()?;
    let Some(deleted) = store
        .delete_group_mapping_if_versions(
            tenant_id,
            group_id,
            role_id,
            expected_mapping_created_at,
            expected_role_updated_at,
        )
        .await
        .map_err(map_rbac_err)?
    else {
        return Ok(None);
    };
    finish_delete_group_mapping(state, tenant_id, actor, group_id, role_id).await?;
    Ok(Some(deleted))
}

async fn finish_delete_group_mapping(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    group_id: Uuid,
    role_id: Uuid,
) -> Result<(), ApiError> {
    invalidate_rbac_cache(state);
    crate::admin_mutation::record_admin_mutation(
        state,
        "rbac",
        "GET /api/v1/admin/rbac/roles",
        tenant_id,
        actor,
        "rbac.delete_group_mapping",
        format!("mapping group_id={group_id} role_id={role_id}"),
    )
    .await?;
    Ok(())
}

// ---- helpers --------------------------------------------------

/// Drop the bearer-time RBAC resolver cache after a successful admin
/// mutation so the next request sees the change immediately, not
/// after the 60s TTL. No-op when the enricher isn't wired (dev mode /
/// no DB).
///
/// Called BETWEEN the successful store mutation and the audit-row
/// write, not after the audit. The mutation has already committed at
/// this point; stale cache must be dropped even when the
/// audit-of-record subsequently fails (the operator still gets the
/// active grant/revoke, just with a 500 response signalling the
/// audit gap — see `admin_mutation::record_admin_mutation`). If we
/// waited for audit success first, an audit-sink hiccup would leave a
/// revoked role still cached for up to 60s.
pub(crate) fn invalidate_rbac_cache(state: &Arc<AdminState>) {
    if let Some(enricher) = state.identity.rbac_enricher.as_ref() {
        enricher.invalidate_all();
    }
}

fn validate_role_input(name: &str, scopes: &[String]) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::BadRequest("`name` must be non-empty".into()));
    }
    if name.len() > 256 {
        return Err(ApiError::BadRequest("`name` must be ≤256 chars".into()));
    }
    for s in scopes {
        if s.is_empty() {
            return Err(ApiError::BadRequest(
                "`scopes` entries must be non-empty strings".into(),
            ));
        }
    }
    Ok(())
}

fn map_rbac_err(e: RbacError) -> ApiError {
    match e {
        RbacError::Conflict(msg) => ApiError::Conflict(msg),
        RbacError::InvalidReference(msg) => ApiError::UnprocessableEntity(msg),
        RbacError::Sqlx(e) => {
            tracing::error!(error = %e, "RBAC store error");
            ApiError::Internal("RBAC store error".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_role_input_rejects_empty_name() {
        assert!(matches!(
            validate_role_input("", &[]),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_role_input_rejects_oversized_name() {
        let huge = "x".repeat(257);
        assert!(matches!(
            validate_role_input(&huge, &[]),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_role_input_rejects_empty_scope_entry() {
        let scopes = vec!["mcp:read".to_owned(), "".to_owned()];
        assert!(matches!(
            validate_role_input("ok", &scopes),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_role_input_accepts_minimum() {
        assert!(validate_role_input("ok", &[]).is_ok());
        assert!(validate_role_input("ok", &["mcp:read".into()]).is_ok());
    }

    /// `map_rbac_err` must distinguish Conflict
    /// (409) from InvalidReference (422) from Sqlx (500) so the
    /// admin UI can differentiate "name collides with another role"
    /// from "you referenced a role/group that doesn't exist in this
    /// tenant" from "the database is on fire."
    #[test]
    fn map_rbac_err_routes_conflict_to_409() {
        let err = map_rbac_err(RbacError::Conflict("dup".into()));
        assert!(matches!(err, ApiError::Conflict(_)));
    }

    #[test]
    fn map_rbac_err_routes_invalid_reference_to_422() {
        let err = map_rbac_err(RbacError::InvalidReference("missing".into()));
        assert!(matches!(err, ApiError::UnprocessableEntity(_)));
    }
}
