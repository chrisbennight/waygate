//! `/api/v1/admin/tasks` — read-only admin surface for
//! the `task_states` table.
//!
//! Operators paging the table see every task the
//! gateway has tracked in their tenant: who started it,
//! which tool it ran against, its lifecycle status, the
//! result URL when present. Both endpoints are behind
//! `mcp:admin` and tenant-scope via `principal.tenant`
//! (NOT via anything in the request) — same shape as
//! `oauth_consent` and `break_glass`.
//!
//! ## Read-only on purpose
//!
//! This surface ships persistence + read API only. There's
//! no admin "cancel this task" endpoint here because:
//!
//! 1. The wire shape for cancellation is part of the
//!    Tasks spec the gateway is waiting on.
//! 2. A "cancel" verb without a write-through into the
//!    upstream worker would just flip a DB column while
//!    the upstream call keeps running — confusing for
//!    operators.
//!
//! Both arrive once `InvocationService` write-through
//! lands.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_dashboard_stores::tasks::{
    Task, TaskError, TaskListFilter, TaskStatus, MAX_LIST_LIMIT,
};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/admin/tasks", get(list_tasks))
        .route("/api/v1/admin/tasks/{id}", get(get_task))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    /// Optional principal `sub` filter — defaults to "all
    /// users in this tenant" so an operator scanning
    /// "what's in flight" doesn't have to know a sub up
    /// front.
    #[serde(default)]
    pub principal_sub: Option<String>,
    /// Optional snake-case TaskStatus filter
    /// (`pending` / `running` / `succeeded` / `failed` /
    /// `cancelled` / `resumable`). Unknown values are
    /// silently dropped from the filter (= "no status
    /// filter") rather than returning 400 — a typo in
    /// the URL shouldn't 4xx; it just widens the result
    /// set.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct TaskListResponse {
    pub tasks: Vec<Task>,
    /// Echoed page size after MAX_LIST_LIMIT clamp.
    /// Paging by `offset += response.limit` is safe even
    /// when the request asked for `limit=1000`.
    pub limit: u32,
    pub offset: u32,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tasks",
    tag = "tasks",
    params(ListQuery),
    responses(
        (status = 200, description = "Tasks in the caller's tenant", body = TaskListResponse),
        (status = 503, description = "Tasks store not configured", body = ApiErrorBody),
        (status = 500, description = "Tasks query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_tasks(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<TaskListResponse>> {
    let store = state.dashboard.tasks.require()?;
    let tenant_id = actor.tenant.as_str();
    let effective_limit = q.limit.min(MAX_LIST_LIMIT);
    let filter = TaskListFilter {
        principal_sub: q.principal_sub.as_deref(),
        status: q.status.as_deref().and_then(TaskStatus::parse),
    };
    let tasks = store
        .list(tenant_id, filter, effective_limit, q.offset)
        .await
        .map_err(map_store_err)?;
    Ok(Json(TaskListResponse {
        tasks,
        limit: effective_limit,
        offset: q.offset,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tasks/{id}",
    tag = "tasks",
    params(("id" = Uuid, Path, description = "Task UUID")),
    responses(
        (status = 200, description = "Task detail", body = Task),
        (status = 404, description = "Task not found in this tenant", body = ApiErrorBody),
        (status = 503, description = "Tasks store not configured", body = ApiErrorBody),
        (status = 500, description = "Tasks query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn get_task(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Task>> {
    let store = state.dashboard.tasks.require()?;
    let task = store
        .get(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::NotFound("task not found in this tenant"))?;
    Ok(Json(task))
}

fn map_store_err(e: TaskError) -> ApiError {
    ApiError::Internal(format!("tasks store: {e}"))
}
