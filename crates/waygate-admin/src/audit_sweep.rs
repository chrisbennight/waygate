//! `POST /api/v1/audit/sweep` — run one retention sweep
//! cycle on demand against a `(tenant_id, category)`.
//!
//! Backs the [`waygate_storage::run_retention_sweep`] primitive
//! shipped here. Composes with the retention policy store: when the
//! request body omits `cutoff`, the handler
//! resolves the effective `delete_after_days` from
//! `evidence_retention_policy` (most-specific match wins, per
//! `waygate_storage::resolve_policy`) and computes
//! `cutoff = now - delete_after_days`. An explicit `cutoff` is
//! accepted too — useful for operators force-running a sweep
//! ahead of a policy change and for testing.
//!
//! On success, the handler returns a [`SweepReportView`]
//! (markers written + rows deleted), and records an
//! `AdminMutation` audit event stamped to the TARGET tenant's
//! chain. The markers the sweep wrote are themselves
//! chain-bearing `RetentionSweep` audit rows — the
//! `AdminMutation` event captures the operator action that
//! triggered the sweep separately, so the target tenant's
//! verifier sees both "operator ran a sweep" and "these rows
//! were retired."
//!
//! Same `require_admin` middleware as the other `/api/v1/audit`
//! handlers. DB-level authorisation is gated by the role-based
//! SECURITY DEFINER `audit_log_sweep_delete()` wrapper (owned by
//! `audit_log_sweep_role`, with EXECUTE granted only to runtime roles).
//! Migration 0074 restricts authorization to the exact marker rows written by
//! the current bounded transaction. Full closure
//! of the "INSERT-capable adversary forges a chain-consistent
//! marker" case requires role-separating the recorder; that's
//! a follow-up.

use std::sync::Arc;

use axum::extract::State;
use axum::middleware;
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use waygate_core::TenantId;
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;
use waygate_storage::{RetentionPolicy, SweepReport};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/audit/sweep", post(run_sweep))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RunSweepBody {
    pub tenant_id: String,
    /// A specific `EvidenceCategory.as_str()` value
    /// (`"invocation"`, `"admin_mutation"`, etc.). MUST NOT
    /// be the `"*"` wildcard — wildcards are POLICY-resolution
    /// concepts (`waygate_storage::resolve_policy`), not a concrete category
    /// accepted by this endpoint. MUST NOT be
    /// `"retention_sweep"` — deleting prior marker rows
    /// would destroy chain bridges the verifier needs.
    /// To sweep multiple categories, the admin runs this
    /// endpoint once per category.
    pub category: String,
    /// Optional explicit cutoff timestamp. When omitted, the
    /// handler resolves the effective policy from
    /// `evidence_retention_policy` and computes
    /// `now - delete_after_days`. The policy lookup respects
    /// the wildcard fallback — a `(tenant, "*")` policy row
    /// applies when no `(tenant, <category>)` exists. 400
    /// when omitted AND no policy matches.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub cutoff: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SweepReportView {
    pub tenant_id: String,
    pub category: String,
    #[serde(with = "time::serde::rfc3339")]
    pub cutoff: OffsetDateTime,
    pub markers_written: usize,
    pub rows_deleted: u64,
    /// True means this request filled the bounded transaction batch and the
    /// same sweep should be called again to prove the scope is drained.
    pub batch_limit_reached: bool,
}

impl From<SweepReport> for SweepReportView {
    fn from(r: SweepReport) -> Self {
        Self {
            tenant_id: r.tenant_id,
            category: r.category,
            cutoff: r.cutoff,
            markers_written: r.markers_written,
            rows_deleted: r.rows_deleted,
            batch_limit_reached: r.batch_limit_reached,
        }
    }
}

fn map_sweep_error(error: waygate_storage::SweepError) -> ApiError {
    match error {
        waygate_storage::SweepError::PolicyChanged { .. } => ApiError::Conflict(format!(
            "{error}; retry so the cutoff is resolved from the current policy"
        )),
        other => ApiError::Internal(format!("retention sweep: {other}")),
    }
}

fn cutoff_from_policy(policy: &RetentionPolicy) -> ApiResult<OffsetDateTime> {
    waygate_storage::retention_cutoff(OffsetDateTime::now_utc(), policy.delete_after_days)
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "retention policy for tenant={} category={} has delete_after_days={} outside the supported timestamp range; update the policy or pass an explicit cutoff",
                policy.tenant_id, policy.category, policy.delete_after_days,
            ))
        })
}

#[utoipa::path(
    post,
    path = "/api/v1/audit/sweep",
    tag = "audit",
    request_body = RunSweepBody,
    responses(
        (status = 200, description = "Sweep ran to completion (possibly a no-op)", body = SweepReportView),
        (status = 400, description = "Invalid body (empty tenant_id/category, malformed tenant_id, or no policy + no explicit cutoff)", body = ApiErrorBody),
        (status = 409, description = "The retention policy changed before deletion; retry against the current policy", body = ApiErrorBody),
        (status = 503, description = "Sweep runner or retention store not configured", body = ApiErrorBody),
        (status = 500, description = "Sweep failed; transaction rolled back", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn run_sweep(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<RunSweepBody>,
) -> ApiResult<Json<SweepReportView>> {
    if body.tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }
    if body.category.trim().is_empty() {
        return Err(ApiError::BadRequest("category is required".to_owned()));
    }
    // Reject the
    // wildcard at the boundary. Wildcard policy enforcement is scheduler-owned;
    // this endpoint runs one explicitly named category per operator request.
    if body.category == "*" {
        return Err(ApiError::BadRequest(
            "category '*' is not a row matcher; pass a specific category — wildcards apply only to retention policy lookup, not to which rows the sweep targets".to_owned(),
        ));
    }
    // Refuse the
    // marker category at the boundary. The sweep's storage
    // layer also refuses (defense in depth via
    // `SweepError::ForbiddenCategory`), but rejecting at the
    // boundary gives the operator a clear 400 instead of a
    // 500-shaped "internal error" wrapping.
    if body.category == waygate_storage::FORBIDDEN_SWEEP_CATEGORY {
        return Err(ApiError::BadRequest(format!(
            "category '{}' must not be swept: deleting prior markers would destroy the chain bridges the verifier depends on for older retention gaps",
            body.category
        )));
    }
    // Validate tenant_id format up front; the audit event also
    // needs a parsed TenantId for `with_tenant` (matches the
    // pattern in `audit_retention.rs`).
    let target_tenant = TenantId::parse(body.tenant_id.clone())
        .map_err(|e| ApiError::BadRequest(format!("invalid tenant_id: {e}")))?;

    let sweeper = state.observability.sweeper.require()?;

    // Resolve the cutoff. Explicit body value wins; otherwise
    // look up the policy and compute `now - delete_after_days`.
    let (cutoff, expected_policy) = match body.cutoff {
        Some(c) => (c, None),
        None => {
            let store = state
                .observability
                .retention
                .get()
                .ok_or(ApiError::ServiceUnavailable(
                    "retention store not configured (cannot resolve cutoff without explicit value)",
                ))?;
            // Fetch every policy for this tenant; split into
            // explicit-category rows and the wildcard row, then
            // `resolve_policy` picks the most-specific match.
            let all = store
                .list(Some(&body.tenant_id))
                .await
                .map_err(|e| ApiError::Internal(format!("retention list: {e}")))?;
            let wildcard = all.iter().find(|p| p.category == "*");
            let explicit: Vec<&waygate_storage::RetentionPolicy> =
                all.iter().filter(|p| p.category != "*").collect();
            let policy = waygate_storage::resolve_policy(&explicit, wildcard, &body.category)
                .ok_or_else(|| {
                    ApiError::BadRequest(format!(
                        "no retention policy for tenant={} category={}; pass an explicit `cutoff` to force",
                        body.tenant_id, body.category
                    ))
                })?;
            let cutoff = cutoff_from_policy(policy)?;
            (cutoff, Some(policy.clone()))
        }
    };

    let report = match expected_policy.as_ref() {
        Some(policy) => {
            sweeper
                .sweep_if_policy_current(&body.tenant_id, &body.category, cutoff, policy)
                .await
        }
        None => sweeper.sweep(&body.tenant_id, &body.category, cutoff).await,
    }
    .map_err(map_sweep_error)?;

    // AdminMutation events for
    // compliance-significant actions land in the chain via
    // record_required. `with_tenant(target_tenant)` stamps the
    // event to the TARGET tenant's chain so verifying that
    // tenant sees the operator action against it.
    let actor = principal.as_ref().map(|Extension(p)| p);
    state
        .evidence
        .record_required(
            AuditEvent::new("audit_sweep.run", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_tenant(target_tenant)
                .with_reason(format!(
                    "sweep tenant={} category={} cutoff={} markers={} deleted={} batch_limit_reached={}",
                    report.tenant_id,
                    report.category,
                    report.cutoff,
                    report.markers_written,
                    report.rows_deleted,
                    report.batch_limit_reached,
                )),
        )
        .await
        .map_err(|e| {
            ApiError::Internal(format!(
                "sweep ran (markers_written={}, rows_deleted={}) but AUDIT FAILED; retry to record the operator action: {}",
                report.markers_written, report.rows_deleted, e
            ))
        })?;

    Ok(Json(SweepReportView::from(report)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_change_maps_to_retryable_conflict() {
        let error = map_sweep_error(waygate_storage::SweepError::PolicyChanged {
            tenant_id: "acme".to_owned(),
            scope: "invocation".to_owned(),
        });

        match error {
            ApiError::Conflict(detail) => {
                assert!(detail.contains("policy changed"));
                assert!(detail.contains("retry"));
            }
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[test]
    fn unrepresentable_policy_cutoff_is_a_bad_request() {
        let now = OffsetDateTime::now_utc();
        let policy = RetentionPolicy {
            tenant_id: "acme".to_owned(),
            category: "invocation".to_owned(),
            delete_after_days: i32::MAX,
            created_at: now,
            updated_at: now,
        };

        let error = cutoff_from_policy(&policy).expect_err("cutoff must be rejected");
        match error {
            ApiError::BadRequest(detail) => {
                assert!(detail.contains("outside the supported timestamp range"));
                assert!(detail.contains("update the policy"));
            }
            other => panic!("expected bad request, got {other:?}"),
        }
    }
}
