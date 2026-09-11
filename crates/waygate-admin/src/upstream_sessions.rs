//! `/api/v1/admin/upstream_sessions` — list + revoke Tier-A durable
//! upstream sessions.
//!
//! The list endpoint returns ciphertext-free metadata
//! (`sub`, `upstream_issuer`, `access_expires_at`, `refreshed_at`,
//! `created_at`) so an operator can pivot "which users have live
//! upstream sessions, when did they last refresh, when do they
//! expire" without ever serving the encrypted bearer envelope over
//! the read surface. The revoke endpoint delegates to
//! [`UpstreamSessionStore::revoke`] (unconditional — the operator
//! intent is "burn this session right now"); the per-call read
//! path will then fail closed via `tier_a_required: true` until the
//! user re-completes `/oauth/callback`.
//!
//! Both endpoints sit behind `mcp:admin` so a `mcp:read` API key
//! can't fingerprint user-IdP linkage by enumerating the table.
//! Revoke emits an `AdminMutation` evidence event so "who revoked
//! whose session" is auditable from the same `audit_log` table the
//! rest of the gateway writes to.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use waygate_as::sessions::{SessionMetadata, SessionStoreError, MAX_LIST_LIMIT};
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339 as format_ts;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/admin/upstream_sessions", get(list_sessions))
        .route(
            "/api/v1/admin/upstream_sessions/{sub}/{upstream_issuer}",
            delete(revoke_session),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionRow {
    pub sub: String,
    pub upstream_issuer: String,
    /// Id of the `UpstreamCrypto` keyring entry that produced this
    /// row's ciphertext. Operators page the list during a rotation
    /// to confirm every row has advanced to the current active id
    /// before retiring the previous key from the
    /// `GATEWAY_UPSTREAM_TOKEN_KEY_<id>` env-var family. Never
    /// secret material — just the public id string.
    pub key_id: String,
    /// RFC 3339 wall-clock time the upstream access token expires.
    pub access_expires_at: String,
    pub refreshed_at: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionRow>,
    /// The actually-applied page size (after the store's hard cap
    /// at `waygate_core::page::MAX_LIST_LIMIT` is enforced). An
    /// operator script paging by `offset += response.limit` is
    /// guaranteed not to skip rows: echoing the request's raw limit
    /// instead could exceed the cap and cause the script to advance
    /// past the truncated page.
    pub limit: u32,
    pub offset: u32,
}

impl From<SessionMetadata> for SessionRow {
    fn from(m: SessionMetadata) -> Self {
        Self {
            sub: m.sub,
            upstream_issuer: m.upstream_issuer,
            key_id: m.key_id,
            access_expires_at: format_ts(m.access_expires_at),
            refreshed_at: format_ts(m.refreshed_at),
            created_at: format_ts(m.created_at),
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/upstream_sessions",
    tag = "upstream_sessions",
    params(ListQuery),
    responses(
        (status = 200, description = "Durable upstream sessions, metadata only", body = SessionListResponse),
        (status = 503, description = "Tier-A session store not configured", body = ApiErrorBody),
        (status = 500, description = "Session query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_sessions(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<SessionListResponse>> {
    let store = state.identity.upstream_sessions.require()?;
    // Clamp the request limit to the store's hard cap BEFORE the
    // SQL query so the echoed `limit` reflects what the gateway
    // actually applied: a client asking for limit=1000 would
    // otherwise get a 500-row page with an echoed `limit: 1000`,
    // and paging by `offset += limit` would skip 500 rows per page.
    let effective_limit = q.limit.min(MAX_LIST_LIMIT);
    let rows = store
        .list_all(effective_limit, q.offset)
        .await
        .map_err(map_store_err)?;
    Ok(Json(SessionListResponse {
        sessions: rows.into_iter().map(SessionRow::from).collect(),
        limit: effective_limit,
        offset: q.offset,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/upstream_sessions/{sub}/{upstream_issuer}",
    tag = "upstream_sessions",
    params(
        ("sub" = String, Path, description = "User subject (matches `Principal.sub`)"),
        ("upstream_issuer" = String, Path, description = "Upstream IdP issuer URL (URL-encoded)"),
    ),
    responses(
        (status = 204, description = "Session revoked (or already absent)"),
        (status = 503, description = "Tier-A session store not configured", body = ApiErrorBody),
        (status = 500, description = "Revoke failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn revoke_session(
    State(state): State<Arc<AdminState>>,
    Path((sub, upstream_issuer)): Path<(String, String)>,
    actor: Option<Extension<Principal>>,
) -> ApiResult<StatusCode> {
    let actor_ref = actor.as_ref().map(|Extension(p)| p);
    revoke_session_core(&state, actor_ref, &sub, &upstream_issuer).await?;
    // 204 either way — admin intent is idempotent ("burn this session"); an
    // already-absent row is a no-op success.
    Ok(StatusCode::NO_CONTENT)
}

/// Shared revoke path: store-check → unconditional revoke → fail-closed
/// `AdminMutation` audit. Both the REST `revoke_session` handler and the
/// `upstream_session.revoke` propose executor call this, so the direct-admin
/// and propose paths can't drift on the store call or the audit. Returns
/// whether a row was actually removed (revoke is idempotent — an already-absent
/// session returns `false` but is not an error).
///
/// The audit is fail-closed `record_required` (matching `oauth_consent.revoke`
/// and the other admin-mutation cores): a session revoke is security-relevant,
/// so its AdminMutation row must not be silently dropped on a sink failure. The
/// revoke has already committed when the audit runs, so a sink failure surfaces
/// a 500 ("verify via GET") rather than reporting an audited success; revoke is
/// idempotent, so the caller's retry is safe.
pub(crate) async fn revoke_session_core(
    state: &Arc<AdminState>,
    actor: Option<&Principal>,
    sub: &str,
    upstream_issuer: &str,
) -> Result<bool, ApiError> {
    let store = state.identity.upstream_sessions.require()?;
    let removed = store
        .revoke(sub, upstream_issuer)
        .await
        .map_err(map_store_err)?;
    tracing::info!(
        target = %sub,
        upstream_issuer = %upstream_issuer,
        removed,
        "admin revoked upstream session",
    );
    state
        .evidence
        .record_required(
            AuditEvent::new("upstream_session.revoke", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_reason(format!(
                    "revoked tier-a session sub={sub} upstream_issuer={upstream_issuer} removed={removed}"
                )),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "upstream_session.revoke evidence record_required failed; revoke already committed",
            );
            ApiError::InternalOperatorVisible(
                "upstream session revoke committed but audit-of-record failed to persist; \
                 verify via GET /api/v1/admin/upstream_sessions"
                    .into(),
            )
        })?;
    Ok(removed)
}

fn map_store_err(e: SessionStoreError) -> ApiError {
    ApiError::Internal(format!("upstream session store: {e}"))
}
