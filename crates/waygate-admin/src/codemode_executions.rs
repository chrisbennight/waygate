//! `/api/v1/admin/codemode/executions` — operator visibility into
//! in-flight Code Mode executions, plus tenant-scoped cancellation.
//!
//! Projects the Code Mode execution journal for operators who need to see
//! what is running and for whom. The caller-facing `codemode.executions`
//! tool is owner-scoped by
//! construction. Both endpoints are behind `mcp:admin` and tenant-scoped
//! via `principal.tenant` (NOT via anything in the request), the same
//! shape as the approval-request surface beside them.
//!
//! Metadata only, deliberately: identity, ownership, state, claim
//! liveness, and age. Results, checkpoints, source, and snapshots are
//! governed content whose retention is an explicit information-flow
//! decision; an observability view must not become a way around it.
//!
//! Cancellation is the one intervention, made deliberately: it reuses the
//! journal's cancellation-request semantics (an unclaimed row terminalizes
//! as `cancelled_by_operator`; a live claim keeps its lease and the runner
//! observes the request), records the operator's subject in the journal
//! event, and emits a fail-closed `AdminMutation` evidence row.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::middleware;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_codemode::OperatorInFlightExecution;
use waygate_core::fmt::format_ts_rfc3339;
use waygate_core::page::MAX_LIST_LIMIT;
use waygate_oidc::Principal;

use crate::admin_mutation::record_admin_mutation;
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/admin/codemode/executions", get(list_executions))
        .route(
            "/api/v1/admin/codemode/executions/{id}/cancel",
            post(cancel_execution),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    /// Optional principal `sub` filter — defaults to "all principals in
    /// this tenant" so an operator scanning "what is holding capacity"
    /// doesn't have to know a sub up front.
    #[serde(default)]
    pub principal_sub: Option<String>,
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

/// One in-flight execution, as an operator sees it: identity, ownership,
/// state, claim liveness, and age — never program content.
#[derive(Debug, serde::Serialize, ToSchema)]
pub struct OperatorExecutionView {
    pub id: Uuid,
    pub principal_sub: String,
    /// Absent only on rows recorded before issuers were stored.
    pub principal_issuer: Option<String>,
    /// Journal lifecycle status (`submitted`, `running`,
    /// `waiting_for_resume`, …).
    pub status: String,
    pub cancellation_requested: bool,
    /// Whether a worker currently holds a live (unexpired) claim.
    pub claimed: bool,
    pub claim_expires_at: Option<String>,
    pub submitted_at: String,
    pub updated_at: String,
    pub retention_until: String,
}

impl From<OperatorInFlightExecution> for OperatorExecutionView {
    fn from(execution: OperatorInFlightExecution) -> Self {
        Self {
            id: execution.id,
            principal_sub: execution.principal_sub,
            principal_issuer: execution.principal_issuer,
            status: execution.status.as_str().to_owned(),
            cancellation_requested: execution.cancellation_requested,
            claimed: execution.claimed,
            claim_expires_at: execution.claim_expires_at.map(format_ts_rfc3339),
            submitted_at: format_ts_rfc3339(execution.submitted_at),
            updated_at: format_ts_rfc3339(execution.updated_at),
            retention_until: format_ts_rfc3339(execution.retention_until),
        }
    }
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct OperatorExecutionList {
    pub executions: Vec<OperatorExecutionView>,
    /// Echoed page size after the `MAX_LIST_LIMIT` clamp, so paging by
    /// `offset += response.limit` is safe whatever the request asked for.
    pub limit: u32,
    pub offset: u32,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/codemode/executions",
    tag = "codemode_executions",
    params(ListQuery),
    responses(
        (status = 200, description = "In-flight Code Mode executions in the caller's tenant, newest submission first", body = OperatorExecutionList),
        (status = 503, description = "Code Mode execution store not configured", body = ApiErrorBody),
        (status = 500, description = "Execution journal query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_executions(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<OperatorExecutionList>> {
    let store = state.hitl.codemode_executions.require()?;
    let effective_limit = q.limit.min(MAX_LIST_LIMIT);
    let executions = store
        .list_in_flight_for_operator(
            actor.tenant.as_str(),
            q.principal_sub.as_deref(),
            u16::try_from(effective_limit).unwrap_or(u16::MAX),
            q.offset,
        )
        .await
        .map_err(|error| {
            ApiError::Internal(format!("list in-flight Code Mode executions: {error}"))
        })?;
    Ok(Json(OperatorExecutionList {
        executions: executions.into_iter().map(Into::into).collect(),
        limit: effective_limit,
        offset: q.offset,
    }))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct CancelExecutionResponse {
    pub execution_id: Uuid,
    /// The status after the request: `cancelled` when nothing held a live
    /// claim, unchanged (e.g. `running`) when a worker holds the lease and
    /// will observe the request, or an already-terminal status when the
    /// execution had finished before the operator acted.
    pub status: String,
    pub cancellation_requested: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/codemode/executions/{id}/cancel",
    tag = "codemode_executions",
    params(("id" = Uuid, Path, description = "Execution UUID")),
    responses(
        (status = 200, description = "Cancellation recorded (or the execution was already terminal)", body = CancelExecutionResponse),
        (status = 404, description = "No such execution in this tenant", body = ApiErrorBody),
        (status = 503, description = "Code Mode execution store not configured", body = ApiErrorBody),
        (status = 500, description = "Cancellation failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn cancel_execution(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CancelExecutionResponse>> {
    let store = state.hitl.codemode_executions.require()?;
    let tenant = actor.tenant.clone();
    let execution = store
        .request_cancellation_for_operator(tenant.as_str(), id, &actor.sub)
        .await
        .map_err(|error| ApiError::Internal(format!("cancel Code Mode execution: {error}")))?
        .ok_or(ApiError::NotFound(
            "Code Mode execution not found in this tenant",
        ))?;
    record_admin_mutation(
        &state,
        "codemode_executions",
        "GET /api/v1/admin/codemode/executions",
        tenant.as_str(),
        Some(&actor),
        "codemode_executions.cancel",
        format!(
            "requested cancellation of Code Mode execution {id} (status after request: {})",
            execution.status.as_str()
        ),
    )
    .await?;
    Ok(Json(CancelExecutionResponse {
        execution_id: execution.id,
        status: execution.status.as_str().to_owned(),
        cancellation_requested: execution.cancellation_requested_at.is_some(),
    }))
}
