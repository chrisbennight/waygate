//! `/api/v1/admin/oauth_consent` — list + revoke OAuth
//! consent grants.
//!
//! Read surface returns the full grant view (id, scopes,
//! granted_at, expires_at, revoked_at). No secret material
//! — consent grants don't hold tokens, just the audit fact
//! of "this client got authorized to act on behalf of this
//! user." Both endpoints sit behind `mcp:admin` to keep
//! `mcp:read` API keys from fingerprinting principal /
//! client relationships.
//!
//! ## Tenant scoping
//!
//! Scope is per-tenant (security-critical) — every query and
//! revoke targets `principal.tenant.as_str()`, NOT a tenant id
//! supplied by the request. Tenant onboarding grants `mcp:admin`
//! to per-tenant admins, so trusting a request-supplied
//! `tenant_id` would let an admin from tenant A list or
//! revoke tenant B's grants by passing the other tenant
//! in the URL. Same discipline as the per-tenant
//! `rate_limit_policies` admin surface — cross-tenant
//! ("super-admin") surfaces would route differently.
//!
//! Revoke is a SOFT delete (sets `revoked_at = now()`)
//! rather than a hard delete so the audit trail survives.
//! Idempotent: revoking an already-revoked or absent grant
//! returns 204 with `removed=false` in the audit reason.
//! A gateway-wide `require_explicit_consent` flag already
//! turns revocation into a hard gate ("user must re-consent
//! next authorize flow") when enabled; per-tenant granularity
//! is not yet wired, so absent that flag revocation is an
//! audit kill switch + a UI signal.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_as::consent::{ConsentGrant, ConsentStoreError, MAX_LIST_LIMIT};
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339 as format_ts;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/admin/oauth_consent", get(list_grants))
        // Tenant id is taken from `principal.tenant`, NOT
        // the path. Path carries only what isn't
        // authority-bound: principal_sub + client_id.
        .route(
            "/api/v1/admin/oauth_consent/{principal_sub}/{client_id}",
            delete(revoke_grant),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    /// Optional principal `sub` filter. When present,
    /// return only grants for that user (the dashboard
    /// "show this user's connected clients" view); absent
    /// returns every grant in the caller's tenant. The
    /// tenant itself is NOT a query parameter — it's
    /// resolved from `principal.tenant`: a client-supplied
    /// tenant id would let a tenant A admin enumerate
    /// tenant B's grants.
    #[serde(default)]
    pub principal_sub: Option<String>,
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GrantRow {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_sub: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub granted_at: String,
    /// RFC 3339 wall-clock expiry. `null` ⇒ no expiry; the
    /// grant lives until an admin revokes it.
    pub expires_at: Option<String>,
    /// RFC 3339 wall-clock time the grant was soft-revoked.
    /// `null` ⇒ grant is still active. When the gateway-wide
    /// `require_explicit_consent` flag is on, a non-null
    /// `revoked_at` means "no covering grant" at the
    /// callback gate; otherwise it's an audit + UI signal.
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GrantListResponse {
    pub grants: Vec<GrantRow>,
    /// Echoed page size after the store's hard cap at
    /// [`MAX_LIST_LIMIT`] is applied. Paging by
    /// `offset += limit` is safe — see the same discipline
    /// on `upstream_sessions::SessionListResponse`.
    pub limit: u32,
    pub offset: u32,
}

impl From<ConsentGrant> for GrantRow {
    fn from(g: ConsentGrant) -> Self {
        Self {
            id: g.id,
            tenant_id: g.tenant_id,
            principal_sub: g.principal_sub,
            client_id: g.client_id,
            scopes: g.scopes,
            granted_at: format_ts(g.granted_at),
            expires_at: g.expires_at.map(format_ts),
            revoked_at: g.revoked_at.map(format_ts),
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/oauth_consent",
    tag = "oauth_consent",
    params(ListQuery),
    responses(
        (status = 200, description = "OAuth consent grants for the caller's tenant", body = GrantListResponse),
        (status = 503, description = "Consent store not configured", body = ApiErrorBody),
        (status = 500, description = "Consent store query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_grants(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<GrantListResponse>> {
    let store = state.identity.consent.require()?;
    // Tenant from principal, never from query.
    // `require_admin` already gated mcp:admin; we still
    // must scope reads to the caller's tenant because
    // mcp:admin is granted per-tenant by onboarding.
    let tenant_id = principal.tenant.as_str();
    // Same MAX_LIST_LIMIT discipline as upstream_sessions:
    // clamp HERE so the echoed limit matches what the
    // query actually applied. A caller paging by
    // `offset += response.limit` is then guaranteed not to
    // skip rows even when they asked for limit=1000.
    let effective_limit = q.limit.min(MAX_LIST_LIMIT);
    let rows = store
        .list(
            tenant_id,
            q.principal_sub.as_deref(),
            effective_limit,
            q.offset,
        )
        .await
        .map_err(map_store_err)?;
    Ok(Json(GrantListResponse {
        grants: rows.into_iter().map(GrantRow::from).collect(),
        limit: effective_limit,
        offset: q.offset,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/oauth_consent/{principal_sub}/{client_id}",
    tag = "oauth_consent",
    params(
        ("principal_sub" = String, Path, description = "OIDC subject (matches Principal.sub)"),
        ("client_id" = String, Path, description = "CIMD client URL (URL-encoded)"),
    ),
    responses(
        (status = 204, description = "Grant revoked (or already absent / already revoked — idempotent)"),
        (status = 503, description = "Consent store not configured", body = ApiErrorBody),
        (status = 500, description = "Revoke failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn revoke_grant(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path((principal_sub, client_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    revoke_grant_core(
        &state,
        actor.tenant.as_str(),
        Some(&actor),
        &principal_sub,
        &client_id,
    )
    .await?;
    // 204 either way — admin intent is idempotent ("ensure this grant is
    // revoked"). An already-revoked or absent row is a no-op success.
    Ok(StatusCode::NO_CONTENT)
}

/// Shared revoke path: store-check → tenant-scoped conditional revoke →
/// fail-closed `AdminMutation` audit (`record_required`; see the call site
/// for why a revoke's audit-of-record must not be dropped). Both the REST
/// `revoke_grant` handler and the dashboard's per-row revoke form call this,
/// so the JSON and HTML surfaces can't drift. Returns whether a row was
/// actually flipped (revoke is idempotent — an absent / already-revoked
/// grant returns `false` but is not an error).
///
/// `tenant_id` MUST be the actor's own tenant, never request-supplied:
/// a tenant-A admin revoking a tenant-B grant hits the store with
/// their own tenant_id, matches no rows, and gets a `false` no-op —
/// they cannot affect another tenant's data.
pub(crate) async fn revoke_grant_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    principal_sub: &str,
    client_id: &str,
) -> Result<bool, ApiError> {
    let store = state.identity.consent.require()?;
    let removed = store
        .revoke(tenant_id, principal_sub, client_id)
        .await
        .map_err(map_store_err)?;
    tracing::info!(
        tenant_id = %tenant_id,
        principal_sub = %principal_sub,
        client_id = %client_id,
        removed,
        "admin revoked oauth consent grant",
    );
    // Fail-closed audit-of-record. A consent revoke is a
    // security-relevant mutation, so its AdminMutation row must not be
    // silently dropped on a sink failure — this matches the fail-closed
    // `record_required` posture every other admin-mutation core uses
    // (rate_limit_policies, inspection_rules) and the executors that reuse
    // them. The soft-delete has already committed, so a sink failure surfaces
    // a 500 ("verify via GET") rather than tombstoning the revoke as audited;
    // revoke is idempotent, so the caller's retry is safe. (The grant row's
    // own `revoked_at` is the durable record of the revoke itself; this is the
    // supplementary AdminMutation event the operator audits against.)
    state
        .evidence
        .record_required(
            AuditEvent::new("oauth_consent.revoke", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_reason(format!(
                    "revoked oauth consent tenant_id={tenant_id} principal_sub={principal_sub} \
                     client_id={client_id} removed={removed}"
                )),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "oauth_consent.revoke evidence record_required failed; revoke already committed",
            );
            ApiError::InternalOperatorVisible(
                "oauth consent revoke committed but audit-of-record failed to persist; \
                 verify via GET /api/v1/admin/oauth_consent"
                    .into(),
            )
        })?;
    Ok(removed)
}

fn map_store_err(e: ConsentStoreError) -> ApiError {
    ApiError::Internal(format!("consent store: {e}"))
}
