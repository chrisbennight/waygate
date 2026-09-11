//! `/api/v1/audit` — paginated recent audit events.
//!
//! Cursor-based pagination on the UUIDv7 primary key: pass `after_id=<uuid>`
//! of the last row you saw to get the next page. We chose this over offset
//! pagination because the audit table grows monotonically and operators
//! commonly tail it while new rows are being inserted — offset pagination
//! would skip rows when the table shifts under the scroll.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_oidc::Principal;
// Aliased: this module already defines its own cursor-only `AuditQuery` (the
// `/api/v1/audit` query string). The store's filter struct is distinct.
use waygate_storage::{AuditQuery as StoreAuditQuery, AuditRow};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

/// The audit categories that represent authorization DECISIONS — what the
/// Decision Log (`/api/v1/audit/decisions`) surfaces. Tool calls audit as
/// `invocation`; model/LLM calls audit as `llm_completion` (both authorize
/// through the same Cedar gate and both record fired policy ids, so the
/// policy-id reverse lookup must cover both). Every other category
/// (`admin_mutation`, `oauth_event`, `retention_sweep`, …) is NOT a decision
/// and must never appear in the Decision Log list OR detail. A NULL category
/// counts as `invocation` (migration 0006), i.e. a decision. Single source of
/// truth shared by `list_decisions` (the query filter), `get_decision`
/// (the detail-row guard), and the dashboard Decision Log pane
/// (`dashboard_decisions_log`), all of which reach it through
/// [`decision_store_query`] / [`is_decision_row`] rather than re-listing the
/// classes.
pub(crate) const DECISION_CATEGORIES: [&str; 2] = ["invocation", "llm_completion"];

/// Build the storage-layer `AuditQuery` that defines "a Decision Log row":
/// authorization decisions (categories = [`DECISION_CATEGORIES`]) for one
/// tenant, with the fail-closed `pre_call` pre-dispatch evidence rows excluded
/// (`reason_ne = "pre_call"`), plus the optional facets a caller filters on.
///
/// SINGLE SOURCE OF TRUTH. Both the REST endpoint ([`list_decisions`]) and the
/// server-rendered dashboard pane (`dashboard_decisions_log`) call this so
/// "what is a decision query" lives in exactly one place — the category set,
/// the `pre_call` exclusion, and (critically) the tenant scope can never drift
/// between the two surfaces. `tenant` is always the *caller's* tenant: it is a
/// SECURITY boundary, not a pivotable facet, so neither surface may read
/// another tenant's audit history.
pub(crate) fn decision_store_query(
    tenant: &str,
    policy_id: Option<String>,
    outcome: Option<String>,
    server: Option<String>,
    principal: Option<String>,
) -> StoreAuditQuery {
    StoreAuditQuery {
        // SECURITY: tenant-scope to the caller, exactly like the Activity feed,
        // so a decision query can never read another tenant's audit history.
        tenant_id: Some(tenant.to_owned()),
        // Constrain to authorization DECISIONS so an unfiltered request never
        // returns non-decision rows (admin_mutation / oauth_event /
        // retention_sweep). Both tool-call (`invocation`) and model
        // (`llm_completion`) decisions are included — they authorize through
        // the same Cedar gate and both record fired policy ids, so the
        // policy-id reverse lookup must surface both — a reverse lookup that
        // only covered `invocation` would silently miss policy activity on
        // the model call itself.
        categories: DECISION_CATEGORIES
            .iter()
            .map(|c| (*c).to_owned())
            .collect(),
        server,
        outcome,
        principal_substr: principal,
        policy_id,
        // Drop the fail-closed pre-dispatch evidence rows (reason='pre_call'):
        // each pairs with a later outcome row carrying the same policy_ids, so
        // without this the reverse lookup would show a duplicate `success`
        // decision (or a pre-dispatch success beside a later execution_error)
        // for a side-effecting call under GATEWAY_AUDIT_MODE=fail_closed.
        // Mirrors the top-tools aggregate's exclusion.
        reason_ne: Some("pre_call".to_owned()),
        ..Default::default()
    }
}

/// Whether an audit row is a Decision Log row — the `/decisions/{id}` detail
/// endpoint's in-memory mirror of the `list_decisions` query's structural
/// filters, so detail never serves a row the list deliberately omits (an admin
/// who learns a row id could otherwise read through detail what the list
/// hides). Two conditions, both kept in lockstep with the `StoreAuditQuery`
/// that `list_decisions` builds: the category must be a decision class
/// (`DECISION_CATEGORIES`; a NULL category counts as `invocation` per migration
/// 0006), and the reason must not be `pre_call` (the list drops the fail-closed
/// pre-dispatch evidence rows via `reason_ne='pre_call'`, so detail must too).
fn is_decision_row(row: &AuditRow) -> bool {
    let category = row.category.as_deref().unwrap_or("invocation");
    DECISION_CATEGORIES.contains(&category) && row.reason.as_deref() != Some("pre_call")
}

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/audit", get(list_audit))
        // The Decision Log — filtered authorization decisions
        // (incl. the `policy_id` reverse lookup) + per-decision detail.
        .route("/api/v1/audit/decisions", get(list_decisions))
        .route("/api/v1/audit/decisions/{id}", get(get_decision))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct AuditQuery {
    #[serde(default = "waygate_core::page::default_list_limit_i64")]
    pub limit: i64,
    #[serde(default)]
    pub after_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditListResponse {
    pub events: Vec<AuditRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/audit",
    tag = "audit",
    params(AuditQuery),
    responses(
        (status = 200, description = "Recent audit events, newest first", body = AuditListResponse),
        (status = 503, description = "Audit store not configured", body = ApiErrorBody),
        (status = 500, description = "Audit query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_audit(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<AuditListResponse>> {
    let reader = state.observability.audit.require()?;

    let events = reader
        .recent_events(q.limit, q.after_id)
        .await
        .map_err(|e| ApiError::Internal(format!("audit query: {e}")))?;

    // Give the client the cursor for the next page (the last row's id), if
    // and only if we filled the requested limit — otherwise there's nothing
    // more to fetch.
    let next_after_id =
        if events.len() as i64 >= q.limit.clamp(1, waygate_core::page::MAX_LIST_LIMIT as i64) {
            events.last().map(|r| r.id)
        } else {
            None
        };
    Ok(Json(AuditListResponse {
        events,
        next_after_id,
    }))
}

/// Filters for the Decision Log (`GET /api/v1/audit/decisions`). All optional;
/// an empty query returns the tenant's recent decisions newest-first.
#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct DecisionQuery {
    /// Reverse lookup: only decisions whose fired-policy set includes this
    /// stable policy `@id` (powers "decisions that matched this policy").
    #[serde(default)]
    pub policy_id: Option<String>,
    /// Exact match on the stored `outcome` string — lower/snake-case, NOT the
    /// PascalCase enum names: `success`, `denied`, `step_up_required`,
    /// `execution_error`. The query uses exact equality, so a PascalCase value
    /// like `Denied` returns an empty result set.
    #[serde(default)]
    pub outcome: Option<String>,
    /// Exact match on `server`.
    #[serde(default)]
    pub server: Option<String>,
    /// Case-sensitive substring match on principal sub/email.
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default = "waygate_core::page::default_list_limit_i64")]
    pub limit: i64,
    #[serde(default)]
    pub after_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/audit/decisions",
    tag = "audit",
    params(DecisionQuery),
    responses(
        (status = 200, description = "Authorization decisions for the caller's tenant, newest first", body = AuditListResponse),
        (status = 503, description = "Audit store not configured", body = ApiErrorBody),
        (status = 500, description = "Audit query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_decisions(
    State(state): State<Arc<AdminState>>,
    Extension(caller): Extension<Principal>,
    Query(q): Query<DecisionQuery>,
) -> ApiResult<Json<AuditListResponse>> {
    let reader = state.observability.audit.require()?;

    // SINGLE SOURCE OF TRUTH for the decision filter (tenant scope + decision
    // categories + `pre_call` exclusion + the optional facets) — the dashboard
    // Decision Log pane builds its query through the same constructor.
    let query = decision_store_query(
        caller.tenant.as_str(),
        q.policy_id,
        q.outcome,
        q.server,
        q.principal,
    );
    let events = reader
        .query_events(&query, q.limit, q.after_id)
        .await
        .map_err(|e| ApiError::Internal(format!("audit query: {e}")))?;
    let next_after_id =
        if events.len() as i64 >= q.limit.clamp(1, waygate_core::page::MAX_LIST_LIMIT as i64) {
            events.last().map(|r| r.id)
        } else {
            None
        };
    Ok(Json(AuditListResponse {
        events,
        next_after_id,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/audit/decisions/{id}",
    tag = "audit",
    params(("id" = Uuid, Path, description = "Audit event id")),
    responses(
        (status = 200, description = "One authorization decision", body = AuditRow),
        (status = 404, description = "No such decision in the caller's tenant", body = ApiErrorBody),
        (status = 503, description = "Audit store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn get_decision(
    State(state): State<Arc<AdminState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AuditRow>> {
    let reader = state.observability.audit.require()?;

    let row = reader
        .fetch_event(id)
        .await
        .map_err(|e| ApiError::Internal(format!("audit query: {e}")))?
        .ok_or(ApiError::NotFound("decision not found"))?;
    // SECURITY: a caller may only read decisions in their own tenant. Return
    // 404 (not 403) so the endpoint doesn't confirm the existence of an
    // other-tenant row.
    if row.tenant_id != caller.tenant.as_str() {
        return Err(ApiError::NotFound("decision not found"));
    }
    // CONTRACT: this is the Decision Log's detail endpoint, so it must only
    // return a row the list would show. `fetch_event` resolves ANY audit row by
    // id, so without this guard a same-tenant admin who learns an id for a
    // non-decision row (`admin_mutation` / `oauth_event` / …) or a
    // fail-closed `pre_call` evidence row the list omits could
    // read it through detail. `is_decision_row` mirrors `list_decisions`'
    // category + reason filters. 404 — same opacity as the tenant check.
    if !is_decision_row(&row) {
        return Err(ApiError::NotFound("decision not found"));
    }
    Ok(Json(row))
}
