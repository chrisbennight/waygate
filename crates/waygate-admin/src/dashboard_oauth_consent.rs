//! OAuth-consent page — `/admin/t/{tenant}/oauth_consent`.
//!
//! Read-only operator view of the per-tenant `oauth_consent`
//! grants from the consent flow. Each row is a
//! `(principal_sub, client_id)` tuple with the
//! scopes the user approved at authorize-time, plus
//! `granted_at` / `expires_at` / `revoked_at` timestamps.
//!
//! Active grants are rendered green; expired and revoked are
//! muted with chips. Active rows carry an admin-gated, CSRF-
//! protected inline Revoke button that reuses the REST
//! path's `revoke_grant_core`; the equivalent
//! `DELETE /api/v1/admin/oauth_consent/{sub}/{client}` remains
//! available in parallel.
//!
//! ## "Three-tier kill" — partial today
//!
//! A complete three-tier kill offers three operator-facing
//! kill actuators: per-grant, per-principal, per-client.
//! Today the store + REST expose only the per-grant single
//! revoke (`crates/waygate-as/src/consent.rs::ConsentStore::revoke`).
//! Per-principal / per-client bulk revoke needs a new store
//! method (`revoke_all_for_principal` / `revoke_all_for_client`)
//! and matching REST endpoints; that's enough surface to
//! warrant its own change. The per-grant single revoke is wired
//! inline on the page; the two bulk kills remain unimplemented.
//!
//! ## What's NOT here (deferred)
//!
//! - **Bulk revoke** (per-principal / per-client). The per-grant
//!   inline Revoke button is wired; the two bulk kills still
//!   need new store methods + REST endpoints.
//! - **Scope diff vs request-time** when the grant scopes
//!   don't cover the current /authorize ask. The gate already
//!   re-prompts the user via the consent screen; the dashboard
//!   doesn't need to duplicate that logic.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant` — same posture every other
//! dashboard page takes today. Cross-tenant operator access
//! is out of scope for this page.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin` middleware
//! (`crates/waygate-admin/src/oauth_consent.rs`). A dashboard
//! session without `mcp:admin` (or a peer-asserted principal)
//! sees the insufficient-scope card; the store fetch is
//! skipped entirely so no consent data — including
//! `principal_sub` (PII) and the user's granted scope set —
//! enters the rendered HTML.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_as::consent::{ConsentGrant, SharedConsentStore};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::oauth_consent::revoke_grant_core;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// Per-fetch row cap. The store clamps at 500; we use 200
/// here so a tenant with thousands of grants doesn't blow up
/// the rendered table while still surfacing enough rows for
/// per-principal triage. Truncation flag in the template
/// nudges toward the REST surface for the full list.
const FETCH_LIMIT: u32 = 200;

#[derive(Template)]
#[template(path = "oauth_consent.html")]
struct OauthConsentPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the consent store is unwired (dev mode /
    /// no DB / consent flow not enabled). Template
    /// renders the "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). Template renders the
    /// insufficient-scope card and SKIPS the store fetch so
    /// no grant data enters the rendered HTML.
    insufficient_scope: bool,
    /// Grants for the principal's tenant, capped at
    /// [`FETCH_LIMIT`]. Sorted by `(principal_sub,
    /// client_id)` (store-side) so per-principal rows cluster
    /// for triage.
    grants: Vec<GrantRow>,
    /// `true` when the fetch hit [`FETCH_LIMIT`]; the
    /// template renders a "showing first N" hint nudging
    /// toward the REST surface.
    truncated: bool,
    /// Store-error fallback. When `list` fails, populate
    /// with a short operator message and render an error
    /// card. Single fetch → single banner.
    error: Option<String>,
    /// `Some(msg)` when a revoke submission failed, threaded back via
    /// the `?oc_error=` PRG query param and rendered above the table.
    oc_error: Option<String>,
}

struct GrantRow {
    id: Uuid,
    principal_sub: String,
    client_id: String,
    /// Pre-joined scope list. Avoids askama having to
    /// .join() inside the loop.
    scopes_label: String,
    granted_at_abs: String,
    /// `None` rendered as "never" in the template.
    expires_at_abs: Option<String>,
    /// Drives the chip + row color. One of:
    /// `"active"`, `"expired"`, `"revoked"`. Computed once
    /// at row-build time so the template doesn't have to
    /// re-derive from the timestamps.
    status: &'static str,
    /// RFC-3339-ish `revoked_at` stamp when `status ==
    /// "revoked"`; `None` for active / expired rows. The
    /// template shows this in the hover-title of the chip
    /// for forensics.
    revoked_at_abs: Option<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/oauth_consent", get(oauth_consent_page))
        .route("/oauth_consent/revoke", post(revoke))
}

/// `?oc_error=` PRG channel — a revoke failure is carried back here and
/// rendered above the table.
#[derive(serde::Deserialize)]
struct OauthConsentQuery {
    #[serde(default)]
    oc_error: Option<String>,
}

async fn oauth_consent_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<OauthConsentQuery>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.identity.consent.enabled();

    let (grants, truncated, error) = if insufficient_scope {
        // Skip the store read entirely — no consent data
        // leaks into the rendered HTML.
        (Vec::new(), false, None)
    } else {
        match state.identity.consent.get() {
            Some(store) => load_grants(store, &read_tenant).await,
            None => (Vec::new(), false, None),
        }
    };

    let page = OauthConsentPage {
        chrome: PageChrome::build(
            &state,
            "OAuth consent",
            "/oauth_consent",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        grants,
        truncated,
        error,
        oc_error: q.oc_error,
    };
    render(&page)
}

/// Revoke form body. Carries the grant's `(principal_sub, client_id)`
/// as hidden fields rather than path segments — `client_id` is a CIMD
/// client URL, awkward to embed in a path. The tenant is taken from the
/// principal, never the form.
#[derive(serde::Deserialize)]
struct RevokeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    principal_sub: String,
    #[serde(default)]
    client_id: String,
}

/// `POST /oauth_consent/revoke` — admin-gated + CSRF, then reuses the
/// REST path's [`revoke_grant_core`] (tenant-scoped conditional revoke +
/// fail-closed `record_required` audit) and PRG-redirects to the consent
/// page. Idempotent: an already-revoked / absent grant still succeeds. On
/// failure (store error, or audit-of-record persistence failure) it
/// redirects with an `?oc_error=` message.
async fn revoke(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<RevokeForm>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let principal = user.as_ref().map(|Extension(p)| p);
    // Stricter gate (refuses peer-asserted principals), mirroring the
    // page's own read gate.
    if !principal_has_dashboard_admin(principal) {
        return (
            StatusCode::FORBIDDEN,
            "oauth consent revoke requires mcp:admin",
        )
            .into_response();
    }
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form.csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, &form.csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let tenant = principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);

    if form.principal_sub.is_empty() || form.client_id.is_empty() {
        return redirect_with_error(tenant_ctx.as_ref(), "Missing grant identifiers.");
    }
    match revoke_grant_core(
        &state,
        tenant,
        principal,
        &form.principal_sub,
        &form.client_id,
    )
    .await
    {
        Ok(_) => Redirect::to(&crate::tenant_ctx::nav_url(
            tenant_ctx.as_ref(),
            "/oauth_consent",
        ))
        .into_response(),
        Err(e) => redirect_with_error(tenant_ctx.as_ref(), &oc_err_message(&e)),
    }
}

/// PRG redirect back to the consent page with an error in `?oc_error=`.
fn redirect_with_error(tenant_ctx: Option<&TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?oc_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx, "/oauth_consent"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Operator-safe revoke-failure message. Validation / unavailable detail
/// is safe; anything else collapses to a generic line.
fn oc_err_message(e: &ApiError) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::BadGateway(d)
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) => (*d).to_owned(),
        _ => "Failed to revoke consent grant — see gateway logs for details.".to_owned(),
    }
}

/// Authorization gate for the oauth-consent dashboard page.
/// Refuses peer assertions even when scopes appear to match
/// — same defense-in-depth posture as the rest of the
/// dashboard's mcp:admin gates.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

async fn load_grants(
    store: &SharedConsentStore,
    tenant: &str,
) -> (Vec<GrantRow>, bool, Option<String>) {
    // Single fetch — the store's `list` returns the
    // tenant-scoped slice ordered by (principal_sub,
    // client_id) so triage by principal works out of the
    // box. principal_sub = None means "every user".
    match store.list(tenant, None, FETCH_LIMIT, 0).await {
        Ok(rows) => {
            let truncated = rows.len() as u32 >= FETCH_LIMIT;
            let now = OffsetDateTime::now_utc();
            let grants: Vec<GrantRow> = rows.into_iter().map(|g| grant_row(g, now)).collect();
            (grants, truncated, None)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                "oauth_consent page: list failed",
            );
            (
                Vec::new(),
                false,
                Some(
                    "Failed to load OAuth consent grants — see gateway logs for details."
                        .to_owned(),
                ),
            )
        }
    }
}

fn grant_row(g: ConsentGrant, now: OffsetDateTime) -> GrantRow {
    let (status, revoked_at_abs) = if g.revoked_at.is_some() {
        ("revoked", g.revoked_at.map(format_ts_abs))
    } else if matches!(g.expires_at, Some(exp) if exp <= now) {
        ("expired", None)
    } else {
        ("active", None)
    };
    GrantRow {
        id: g.id,
        principal_sub: g.principal_sub,
        client_id: g.client_id,
        scopes_label: g.scopes.join(" "),
        granted_at_abs: format_ts_abs(g.granted_at),
        expires_at_abs: g.expires_at.map(format_ts_abs),
        status,
        revoked_at_abs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal_with(scopes: Vec<&str>, method: AuthMethod) -> Principal {
        Principal {
            sub: "tester".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: scopes.into_iter().map(String::from).collect(),
            tenant: waygate_core::TenantId::default(),
            auth_method: method,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn oauth_consent_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn oauth_consent_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn oauth_consent_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn oauth_consent_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    fn grant(id_byte: u8, expires_unix: Option<i64>, revoked_unix: Option<i64>) -> ConsentGrant {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        ConsentGrant {
            id: Uuid::from_bytes([id_byte; 16]),
            tenant_id: "default".into(),
            principal_sub: "alice".into(),
            client_id: "claude-code".into(),
            scopes: vec!["openid".into(), "profile".into()],
            granted_at: now,
            expires_at: expires_unix.map(|t| OffsetDateTime::from_unix_timestamp(t).unwrap()),
            revoked_at: revoked_unix.map(|t| OffsetDateTime::from_unix_timestamp(t).unwrap()),
        }
    }

    #[test]
    fn grant_row_marks_revoked_when_revoked_at_set() {
        // revoked_at wins over expires_at — a revoked grant
        // that was also past its expires_at should still show
        // "revoked" because the operator's audit trail is the
        // revocation ceremony, not the natural expiry.
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_500).unwrap();
        let row = grant_row(grant(1, Some(1_700_000_100), Some(1_700_000_300)), now);
        assert_eq!(row.status, "revoked");
        assert!(row.revoked_at_abs.is_some(), "revoked_at_abs must populate");
    }

    #[test]
    fn grant_row_marks_expired_when_unrevoked_past_expiry() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_500).unwrap();
        let row = grant_row(grant(1, Some(1_700_000_100), None), now);
        assert_eq!(row.status, "expired");
        assert!(
            row.revoked_at_abs.is_none(),
            "expired row carries no revoke stamp"
        );
    }

    #[test]
    fn grant_row_marks_active_when_no_expiry_or_revoke() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_500).unwrap();
        let row = grant_row(grant(1, None, None), now);
        assert_eq!(row.status, "active");
    }

    #[test]
    fn grant_row_marks_active_when_future_expiry_and_not_revoked() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
        let row = grant_row(grant(1, Some(1_700_000_500), None), now);
        assert_eq!(row.status, "active");
    }
}
