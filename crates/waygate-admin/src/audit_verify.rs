//! `GET /api/v1/audit/verify` — walk a tenant's required-write
//! tamper-evidence hash chain and report whether every
//! chain-bearing row still rehashes to its stored `row_hash`
//! and links to its prior row's `row_hash`.
//!
//! Mounted under the same `/api/v1/audit` namespace as the
//! existing list endpoint; both use the codebase's
//! middleware-scoped auth (`require_admin` here) rather than a
//! URL `/admin/` prefix.
//!
//! The verifier reads chain-bearing rows from the durable
//! `audit_log` table. `record_required` writes this chain at
//! insert time; successfully persisted `record_best_effort` events have
//! null hashes and are outside this report. This handler is
//! the read-side counterpart that lets an operator (or a
//! periodic SOC2 / NIST-AI-RMF evidence check) prove the
//! required-write chain is intact.
//!
//! `tenant_id` is required — each tenant has its own chain
//! (one `pg_advisory_xact_lock(hashtext(tenant))` per tenant
//! at insert time), and a per-tenant report is the unit
//! operators reason about.
//!
//! `from` / `to` narrow by `ts`. The walk is still
//! `ORDER BY chain_seq ASC` (the authoritative chain order),
//! and when the window starts mid-chain the adapter looks up
//! the prior row's `row_hash` so the first row's `prev_hash`
//! check is correct. See
//! [`waygate_storage::AuditReader::verify_chain`].
//!
//! `limit` caps the walk size. Default 1000; storage adapter
//! clamps to 10,000.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::middleware;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

use waygate_storage::ChainVerifyReport;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/audit/verify", get(verify_chain))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct VerifyChainQuery {
    /// Tenant whose chain to verify. Required — each tenant
    /// has its own chain.
    pub tenant_id: String,
    /// Lower bound on `ts`. RFC 3339. Optional. Translated
    /// internally to a `chain_seq` range (via MIN/MAX over
    /// rows matching the ts predicate) so the chain walk
    /// never skips interior rows whose ts falls outside the
    /// window — `ts` is caller-assigned and can be
    /// out-of-order with `chain_seq` (see migration 0015
    /// round-1 lesson).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    /// Upper bound on `ts`. RFC 3339. Optional. Same
    /// translation as `from`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
    /// Strict-after pagination cursor: walk only rows
    /// whose `chain_seq > after_chain_seq`. Pass back
    /// `next_after_chain_seq` from a prior `incomplete`
    /// report to continue — the field names are
    /// symmetric so the handoff is a copy. Using `>=` here
    /// (instead of strict `>`) would reselect the "last walked"
    /// row and block pagination on chains longer than the cap.
    /// `>` ensures progress: a returned cursor of N means
    /// the next page starts at chain_seq > N, so row N
    /// (already walked) is not re-emitted.
    #[serde(default)]
    pub after_chain_seq: Option<i64>,
    /// Cap on the number of rows walked. Default 1000;
    /// the storage adapter clamps to 10,000. When the cap
    /// is hit, status is `incomplete` and
    /// `next_after_chain_seq` is set.
    #[serde(default = "default_limit")]
    pub limit: i64,
}

// Deliberate override of waygate_core::page::DEFAULT_LIST_LIMIT (50):
// chain verification batches big on purpose — it reads rows, not pages.
fn default_limit() -> i64 {
    1000
}

#[utoipa::path(
    get,
    path = "/api/v1/audit/verify",
    tag = "audit",
    params(VerifyChainQuery),
    responses(
        (status = 200, description = "Chain verification report (status=ok/mismatch/empty/incomplete). `empty` means no chain-bearing rows matched, not that the audit log is empty or fully chain covered. `incomplete` means the walk hit `limit` with no mismatch found; paginate with `next_after_chain_seq`.", body = ChainVerifyReport),
        (status = 400, description = "Missing tenant_id or malformed ts", body = ApiErrorBody),
        (status = 503, description = "Audit store not configured", body = ApiErrorBody),
        (status = 500, description = "Verification query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn verify_chain(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<VerifyChainQuery>,
) -> ApiResult<Json<ChainVerifyReport>> {
    if q.tenant_id.trim().is_empty() {
        return Err(ApiError::BadRequest("tenant_id is required".to_owned()));
    }
    let reader = state.observability.audit.require()?;

    let report = reader
        .verify_chain(&q.tenant_id, q.from, q.to, q.after_chain_seq, q.limit)
        .await
        .map_err(|e| ApiError::Internal(format!("chain verification: {e}")))?;
    Ok(Json(report))
}
