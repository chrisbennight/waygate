//! `/api/v1/admin/break_glass` — mint, list, and revoke
//! break-glass override tokens.
//!
//! Every endpoint is behind `mcp:admin` and scopes by
//! `principal.tenant` (NOT by anything in the request).
//! Same lesson as oauth_consent: tenant onboarding grants
//! `mcp:admin` to per-tenant admins, so trusting a
//! request-supplied tenant id would let a tenant A admin
//! mint tokens that attack tenant B.
//!
//! Mint requires a non-empty `reason` and a `scope_pattern`
//! that's either a literal `server.tool` FQN or a
//! `server.*` wildcard. Empty pattern is refused — that
//! would silently match every tool. Non-empty
//! `requires_amr` is also refused for now (`Principal`
//! doesn't carry an `amr` field yet, and minting a
//! "requires MFA" token the runtime can't enforce is the
//! exact "operator believes a security control is on
//! while it isn't" footgun this PR is trying to avoid).
//!
//! Revoke is a HARD delete (matching the schema's "no
//! revoked_at column" decision) — the AdminMutation
//! evidence on the revoke ceremony is what an audit
//! reader pivots on, not a soft tombstone.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_authz::{BreakGlassError, BreakGlassToken, NewBreakGlassToken, MAX_LIST_LIMIT};
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/break_glass",
            get(list_tokens).post(mint_token),
        )
        .route("/api/v1/admin/break_glass/{token_id}", delete(revoke_token))
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, schemars::JsonSchema)]
pub struct MintRequest {
    /// Principal `sub` the token authorizes. Required —
    /// minting a "for whoever" token would defeat the
    /// per-principal scoping.
    pub issued_to: String,
    /// Free-text justification recorded on the token and
    /// surfaced in every override-event audit row.
    /// Required + non-empty (`""` is refused).
    pub reason: String,
    /// `server.tool` literal FQN or `server.*` wildcard.
    /// Empty is refused.
    pub scope_pattern: String,
    /// AMR values the principal MUST present at
    /// use-time. Non-empty values are refused here because
    /// `Principal` doesn't carry an `amr` field yet —
    /// minting a "requires MFA" token the runtime can't
    /// enforce is the exact "operator believes a control is
    /// on while it isn't" footgun this endpoint avoids. This
    /// restriction lifts once `Principal.amr` lands.
    #[serde(default)]
    pub requires_amr: Vec<String>,
    /// TTL in seconds from now. Capped at 86400 (24h)
    /// by the admin handler — break-glass is for an
    /// incident, not a standing override; a longer TTL
    /// should be implemented as a Cedar policy change
    /// instead.
    pub ttl_seconds: u32,
}

const MAX_TTL_SECONDS: u32 = 86_400;

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenRow {
    pub id: Uuid,
    pub tenant_id: String,
    pub issued_to: String,
    pub issued_by: String,
    pub reason: String,
    pub scope_pattern: String,
    pub requires_amr: Vec<String>,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenListResponse {
    pub tokens: Vec<TokenRow>,
    pub limit: u32,
    pub offset: u32,
}

impl From<BreakGlassToken> for TokenRow {
    fn from(t: BreakGlassToken) -> Self {
        Self {
            id: t.id,
            tenant_id: t.tenant_id,
            issued_to: t.issued_to,
            issued_by: t.issued_by,
            reason: t.reason,
            scope_pattern: t.scope_pattern,
            requires_amr: t.requires_amr,
            expires_at: format_ts_rfc3339(t.expires_at),
            used_at: t.used_at.map(format_ts_rfc3339),
            created_at: format_ts_rfc3339(t.created_at),
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/break_glass",
    tag = "break_glass",
    request_body = MintRequest,
    responses(
        (status = 201, description = "Token minted", body = TokenRow),
        (status = 400, description = "Validation failed", body = ApiErrorBody),
        (status = 503, description = "Break-glass store not configured", body = ApiErrorBody),
        (status = 500, description = "Mint failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn mint_token(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Json(req): Json<MintRequest>,
) -> ApiResult<(StatusCode, Json<TokenRow>)> {
    let token = mint_token_core(&state, actor.tenant.as_str(), Some(&actor), &req).await?;
    Ok((StatusCode::CREATED, Json(TokenRow::from(token))))
}

/// Shared mint path: store-check → `validate_mint_request` →
/// `store.mint` → loud `tracing::warn` → fail-closed `AdminMutation`
/// audit. Both the REST `mint_token` handler and the dashboard's
/// in-page mint form call this, so the JSON and HTML surfaces can't
/// drift on validation, the store call, or the audit. `issued_by` is
/// the actor's `sub`.
pub(crate) async fn mint_token_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    req: &MintRequest,
) -> Result<BreakGlassToken, ApiError> {
    let store = state.policy.break_glass.require()?;
    validate_mint_request(req)?;

    let issued_by = actor.map(|p| p.sub.as_str()).unwrap_or("unknown");
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(req.ttl_seconds as i64);
    let token = store
        .mint(NewBreakGlassToken {
            tenant_id,
            issued_to: &req.issued_to,
            issued_by,
            reason: &req.reason,
            scope_pattern: &req.scope_pattern,
            requires_amr: &req.requires_amr,
            expires_at,
        })
        .await
        .map_err(map_store_err)?;

    tracing::warn!(
        token_id = %token.id,
        tenant_id = %token.tenant_id,
        issued_to = %token.issued_to,
        issued_by = %token.issued_by,
        scope_pattern = %token.scope_pattern,
        ttl_seconds = req.ttl_seconds,
        reason = %token.reason,
        "break-glass token MINTED",
    );
    // A successful mint MUST NOT create a Cedar-bypass grant without a
    // durable audit row: uses record_required (not record_best_effort)
    // so an evidence write failure surfaces as an error instead of a
    // silent grant. The DB row exists at this point (a `list` would
    // still show it) but the caller gets the failure, so they
    // investigate the audit infra before treating any subsequent
    // break-glass attempt as reliable. Issue #151 tracks the atomic-tx
    // version of this contract.
    state
        .evidence
        .record_required(
            AuditEvent::new("BreakGlassMint", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_reason(format!(
                    "minted break-glass token id={} tenant_id={} issued_to={} \
                     scope_pattern={} ttl_seconds={} mint_reason={:?}",
                    token.id,
                    token.tenant_id,
                    token.issued_to,
                    token.scope_pattern,
                    req.ttl_seconds,
                    token.reason,
                )),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                token_id = %token.id,
                "break-glass: record_required failed AFTER mint; returning error",
            );
            ApiError::Internal(format!("break-glass mint audit failed: {e}"))
        })?;

    Ok(token)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/break_glass",
    tag = "break_glass",
    params(ListQuery),
    responses(
        (status = 200, description = "Break-glass tokens for the caller's tenant", body = TokenListResponse),
        (status = 503, description = "Break-glass store not configured", body = ApiErrorBody),
        (status = 500, description = "List failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_tokens(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<TokenListResponse>> {
    let store = state.policy.break_glass.require()?;
    let effective_limit = q.limit.min(MAX_LIST_LIMIT);
    let tokens = store
        // REST list keeps the legacy unfiltered shape (lifecycle = None).
        // The documented `?include_used` / lifecycle filtering on the
        // public surface is a separate change; for now the dashboard is
        // the only caller using the precise lifecycle predicate.
        .list(actor.tenant.as_str(), None, effective_limit, q.offset)
        .await
        .map_err(map_store_err)?;
    Ok(Json(TokenListResponse {
        tokens: tokens.into_iter().map(TokenRow::from).collect(),
        limit: effective_limit,
        offset: q.offset,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/break_glass/{token_id}",
    tag = "break_glass",
    params(("token_id" = Uuid, Path, description = "Token UUID to revoke")),
    responses(
        (status = 204, description = "Token revoked (or already absent — idempotent)"),
        (status = 503, description = "Break-glass store not configured", body = ApiErrorBody),
        (status = 500, description = "Revoke failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn revoke_token(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(token_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    revoke_token_core(&state, actor.tenant.as_str(), Some(&actor), token_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Shared revoke path: store-check → HARD delete → loud
/// `tracing::warn` → fail-closed `AdminMutation` audit (migration
/// 0029 has no `revoked_at`; the audit IS the revocation record).
/// Both the REST `revoke_token` handler and the dashboard's per-row
/// revoke form call this. Returns whether a row was actually removed
/// (revoke is idempotent — absent token still audits + succeeds).
pub(crate) async fn revoke_token_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    token_id: Uuid,
) -> Result<bool, ApiError> {
    let store = state.policy.break_glass.require()?;
    let removed = store
        .delete(tenant_id, token_id)
        .await
        .map_err(map_store_err)?;
    tracing::warn!(
        token_id = %token_id,
        tenant_id = %tenant_id,
        actor = actor.map(|p| p.sub.as_str()).unwrap_or("unknown"),
        removed,
        "break-glass token REVOKED",
    );
    // A successful 204 MUST NOT remove a Cedar-bypass grant
    // without a durable audit row. Migration 0029's "no
    // revoked_at; audit captures revocation" decision means the
    // audit IS the revocation record — drop it and you've lost
    // the only "this was revoked at time T by actor A" evidence.
    // Uses record_required (not record_best_effort) so an
    // evidence write failure surfaces as 500; same reasoning as
    // the mint path above (the row is already deleted, but the
    // caller doesn't see 204 confirming the operation, so they
    // investigate the audit infra). Issue #151 tracks the
    // atomic-tx version.
    state
        .evidence
        .record_required(
            AuditEvent::new("BreakGlassRevoke", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_reason(format!(
                    "revoked break-glass token id={token_id} tenant_id={tenant_id} removed={removed}"
                )),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                token_id = %token_id,
                "break-glass: record_required failed AFTER revoke; returning error",
            );
            ApiError::Internal(format!("break-glass revoke audit failed: {e}"))
        })?;
    Ok(removed)
}

fn validate_mint_request(req: &MintRequest) -> Result<(), ApiError> {
    if req.issued_to.trim().is_empty() {
        return Err(ApiError::BadRequest("issued_to must be non-empty".into()));
    }
    if req.reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason must be non-empty".into()));
    }
    if req.scope_pattern.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "scope_pattern must be non-empty (empty would silently match every tool)".into(),
        ));
    }
    // Validate the documented shape at admin time, not just at
    // runtime. The runtime helper
    // (`waygate_authz::scope_pattern_matches`) refuses
    // anything that isn't an exact `server.tool` FQN or
    // a `server.*` wildcard, so a malformed pattern
    // would silently match nothing — a token the
    // operator believes is usable that the gate would
    // never apply. Fail loud at mint so the operator
    // sees the typo before the incident.
    if !is_valid_scope_pattern(&req.scope_pattern) {
        return Err(ApiError::BadRequest(
            "scope_pattern must be either an exact `server.tool` FQN (one dot, no wildcards) \
             or a `server.*` wildcard (server name + `.*` suffix); reject everything else \
             so a typo doesn't mint a token that silently never matches"
                .into(),
        ));
    }
    if req.ttl_seconds == 0 {
        return Err(ApiError::BadRequest("ttl_seconds must be > 0".into()));
    }
    if req.ttl_seconds > MAX_TTL_SECONDS {
        return Err(ApiError::BadRequest(
            "ttl_seconds exceeds 24h cap — break-glass is for an incident, not a standing override"
                .into(),
        ));
    }
    // Non-empty requires_amr is refused — see the module doc +
    // MintRequest.requires_amr doc. Lifts once
    // `Principal.amr` lands.
    if !req.requires_amr.is_empty() {
        return Err(ApiError::BadRequest(
            "requires_amr is not enforceable yet (Principal lacks an `amr` field); \
             leave empty until AMR plumbing lands"
                .into(),
        ));
    }
    Ok(())
}

fn map_store_err(e: BreakGlassError) -> ApiError {
    ApiError::Internal(format!("break-glass store: {e}"))
}

/// Enforce the documented `server.tool` or `server.*` shape
/// at mint time. The runtime matcher already accepts only
/// these shapes — this gate makes a typo loud at mint
/// instead of silent at use.
///
/// Rules:
/// - Exact: `<server>.<tool>` where both halves are
///   non-empty and contain only alphanumeric / `-` / `_`
///   (the same character class MCP tool names use). One
///   dot only.
/// - Wildcard: `<server>.*` where `<server>` is a valid
///   identifier per the above. The literal `.*` is the
///   only wildcard form accepted.
fn is_valid_scope_pattern(p: &str) -> bool {
    // Empty caught by the prior validator; defensive.
    if p.is_empty() {
        return false;
    }
    // Wildcard form.
    if let Some(server) = p.strip_suffix(".*") {
        return !server.is_empty() && is_valid_identifier(server);
    }
    // Exact form: exactly one `.`, non-empty both sides,
    // both sides valid identifiers.
    let parts: Vec<&str> = p.split('.').collect();
    if parts.len() != 2 {
        return false;
    }
    let (server, tool) = (parts[0], parts[1]);
    !server.is_empty()
        && !tool.is_empty()
        && is_valid_identifier(server)
        && is_valid_identifier(tool)
}

fn is_valid_identifier(s: &str) -> bool {
    // Alphanumeric + `-` + `_`. Matches the character
    // class used elsewhere for MCP names; deliberately
    // does NOT allow `.` (would let `server.sub.tool`
    // sneak past).
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_pattern_accepts_exact_fqn() {
        assert!(is_valid_scope_pattern("billing.charge"));
        assert!(is_valid_scope_pattern("svc_a.refund-customer"));
        assert!(is_valid_scope_pattern("example-memory.recall"));
    }

    #[test]
    fn scope_pattern_accepts_wildcard() {
        assert!(is_valid_scope_pattern("billing.*"));
        assert!(is_valid_scope_pattern("svc_a.*"));
    }

    #[test]
    fn scope_pattern_rejects_malformed() {
        // Missing dot.
        assert!(!is_valid_scope_pattern("billing"));
        // Empty halves.
        assert!(!is_valid_scope_pattern(".charge"));
        assert!(!is_valid_scope_pattern("billing."));
        assert!(!is_valid_scope_pattern("."));
        // Too many dots (would sneak nested namespaces).
        assert!(!is_valid_scope_pattern("billing.charge.extra"));
        // Wildcard in wrong position / partial.
        assert!(!is_valid_scope_pattern("*.charge"));
        assert!(!is_valid_scope_pattern("billing.char*"));
        assert!(!is_valid_scope_pattern("billing.*.extra"));
        // Forbidden characters.
        assert!(!is_valid_scope_pattern("billing.charge!"));
        assert!(!is_valid_scope_pattern("bill ing.charge"));
        // Empty wildcard server.
        assert!(!is_valid_scope_pattern(".*"));
    }
}
