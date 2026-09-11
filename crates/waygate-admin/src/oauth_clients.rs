//! The body of the `/admin/sessions` page: live OAuth session inventory
//! with chain-revoke. (Split onto its own page from the API-keys page;
//! previously a sibling section there.)
//!
//! Where API keys are operator-minted long-lived bearers, OAuth sessions
//! are user-driven (CIMD login → refresh-token chain). This panel exposes:
//!
//! * A row per live `(client_id, sub)` pair, with email/groups/scopes,
//!   the chain count, and a 7-day usage figure pulled from the audit log
//!   (counts tool-call events authored by that sub).
//! * A "revoke session" button that chain-revokes every live refresh
//!   token for the pair (the existing `OauthStore::revoke_chain` revokes
//!   from one seed token; this revokes the whole `(client_id, sub)`
//!   tuple in one shot — the same identity logged in from two browsers
//!   gets both chains killed together).
//!
//! Read-side only on the request hot path — no writes outside the
//! explicit revoke action. Like the API-keys panel, every handler that
//! reads or writes session-level data requires `mcp:admin`.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use waygate_as::store::OauthSession;
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::error::{ApiError, ApiResult};
use crate::scope::require_admin_extension;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::{format_ts_abs, format_ts_rel};

/// Cap on rows the list query returns. The dashboard renders them all on
/// one page; pagination arrives only if a deployment ever needs it.
const LIST_LIMIT: i64 = 200;

/// Sparkline window. Matches the API-keys panel so the two side-by-side
/// "usage in last N days" numbers are directly comparable.
pub const USAGE_WINDOW_DAYS: i64 = 7;

/// Issuer label the API-key validator stamps on its principals (see
/// `waygate_apikeys::ValidatorConfig::issuer_label`'s default). Used as
/// the exclude-issuer filter in the OAuth-session usage query so this
/// panel's number doesn't inflate when the same sub has both an OAuth
/// session and a static API key.
const API_KEY_ISSUER_LABEL: &str = "api-key";

// ---- view-model -----------------------------------------------------------

#[derive(Clone)]
pub struct SessionView {
    pub client_id: String,
    /// Best display name for the client. For CIMD URLs this is the URL
    /// itself; future static-pre-reg client IDs would surface their
    /// human name here.
    pub client_label: String,
    pub sub: String,
    pub email: String,
    pub groups: String,
    pub scopes: String,
    pub chain_count: i64,
    pub oldest_issued_abs: String,
    pub oldest_issued_rel: String,
    pub newest_issued_abs: String,
    pub newest_issued_rel: String,
    /// Tool-call audit events in the last [`USAGE_WINDOW_DAYS`] days
    /// whose `principal_sub` matches this session's `sub`. Approximate:
    /// a user with two simultaneous logins (two `(client_id, sub)` rows)
    /// will see the same usage figure on each row, since the audit log
    /// only carries `sub`, not `client_id`. Acceptable for the
    /// "is this session being used at all?" question the panel answers.
    pub usage_count: i64,
}

#[derive(Template)]
#[template(path = "oauth_clients_section.html")]
pub struct OauthClientsSection {
    pub enabled: bool,
    pub is_admin: bool,
    pub csrf_token: String,
    pub sessions: Vec<SessionView>,
    /// Set when the underlying store query failed. The template renders
    /// an error card instead of the empty-state card so an operator
    /// doesn't mistake "DB unreachable" for "no live sessions".
    pub error: Option<String>,
    /// The step-up re-auth link in the
    /// section template carries a `next=` query param that must
    /// route back to the tenant-prefixed Sessions page when the
    /// parent was loaded under `/admin/t/<tenant>/`. Populated by
    /// [`load_section`].
    pub tenant_ctx: Option<TenantContext>,
}

impl OauthClientsSection {
    pub fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

// ---- loader (called from the /admin/sessions page handler) ----------------

/// Build the section's view-model. Skipped (returns the "disabled" shape)
/// when either the OAuth store is unwired or the caller lacks
/// `mcp:admin`; the calling page handler is responsible for the admin
/// check on the umbrella page, but we re-apply it here too as defence-
/// in-depth.
pub async fn load_section(
    state: &Arc<AdminState>,
    user: Option<&Principal>,
    csrf_token: String,
    tenant_ctx: Option<TenantContext>,
) -> OauthClientsSection {
    let is_admin = user
        .map(|p| p.has_scope(waygate_oidc::Scope::McpAdmin.as_str()))
        .unwrap_or(false);
    let Some(store) = state.identity.oauth.get() else {
        return OauthClientsSection {
            enabled: false,
            is_admin,
            csrf_token,
            sessions: Vec::new(),
            error: None,
            tenant_ctx,
        };
    };
    if !is_admin {
        return OauthClientsSection {
            enabled: true,
            is_admin,
            csrf_token,
            sessions: Vec::new(),
            error: None,
            tenant_ctx,
        };
    }

    let raw = match store.list_active_sessions(LIST_LIMIT).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "oauth_clients: list_active_sessions failed");
            // Surface the failure to the operator instead of an empty
            // list — "DB query failed" and "no live sessions" should
            // not look identical in the UI.
            return OauthClientsSection {
                enabled: true,
                is_admin,
                csrf_token,
                sessions: Vec::new(),
                error: Some("Failed to load OAuth sessions — see gateway logs for details.".into()),
                tenant_ctx,
            };
        }
    };

    // Bulk-load usage counts: one query per distinct sub. Subs repeat
    // across rows when a user has multiple client_ids (e.g. CLI + IDE).
    // Caching keeps the dashboard render to ≤ N_distinct_subs DB hits
    // rather than N_rows.
    //
    // Exclude events with `issuer = "api-key"` from the count: a sub
    // that also has a static API key would otherwise have OAuth-session
    // usage padded by API-key tool calls, since both auth paths share
    // the same `principal_sub` claim. The API-keys panel still surfaces
    // those calls on its own sparkline.
    let mut usage_cache: HashMap<String, i64> = HashMap::new();
    let since = OffsetDateTime::now_utc() - time::Duration::days(USAGE_WINDOW_DAYS);
    if let Some(audit) = state.observability.audit.get() {
        for row in &raw {
            if usage_cache.contains_key(&row.sub) {
                continue;
            }
            let count = audit
                .count_events_by_sub_since(&row.sub, since, Some(API_KEY_ISSUER_LABEL))
                .await
                .unwrap_or(0);
            usage_cache.insert(row.sub.clone(), count);
        }
    }

    let sessions = raw
        .into_iter()
        .map(|s| view_from_row(s, &usage_cache))
        .collect();
    OauthClientsSection {
        enabled: true,
        is_admin,
        csrf_token,
        sessions,
        error: None,
        tenant_ctx,
    }
}

fn view_from_row(s: OauthSession, usage: &HashMap<String, i64>) -> SessionView {
    let usage_count = usage.get(&s.sub).copied().unwrap_or(0);
    let client_label = display_client(&s.client_id);
    SessionView {
        client_id: s.client_id,
        client_label,
        email: s.email.clone().unwrap_or_default(),
        groups: s.groups.join(", "),
        scopes: s.scopes.join(" "),
        chain_count: s.chain_count,
        oldest_issued_abs: format_ts_abs(s.oldest_issued_at),
        oldest_issued_rel: format_ts_rel(s.oldest_issued_at),
        newest_issued_abs: format_ts_abs(s.newest_issued_at),
        newest_issued_rel: format_ts_rel(s.newest_issued_at),
        sub: s.sub,
        usage_count,
    }
}

/// For CIMD `client_id`s (which are HTTPS URLs) the URL itself is a
/// reasonable label. For non-URL client IDs (future pre-reg path) we'd
/// look up a friendly name; today they don't exist, so this is just a
/// pass-through with one small affordance — strip the `https://` scheme
/// so the column is readable.
fn display_client(client_id: &str) -> String {
    client_id
        .strip_prefix("https://")
        .or_else(|| client_id.strip_prefix("http://"))
        .map(str::to_owned)
        .unwrap_or_else(|| client_id.to_owned())
}

// ---- revoke handler -------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub csrf: String,
    /// Full client_id (URL-decoded). Lives in the body because CIMD
    /// client IDs are HTTPS URLs and embedding them in a path requires
    /// double-encoding that's fiddly to get right across both htmx and
    /// axum.
    pub client_id: String,
    /// OIDC subject. Also lives in the body rather than the URL path: the
    /// OIDC `sub` is "a locally unique and never reassigned identifier
    /// within the Issuer for the End-User" (RFC 7519 §4.1.2) which the
    /// spec doesn't constrain to any character set. Authentik in
    /// particular emits UUIDs that don't contain `/` but other IdPs may,
    /// and putting `sub` in the path means a value with `/`, `?`, or `#`
    /// either routes wrong or fails to match the route at all.
    pub sub: String,
}

/// Render-only partial for the htmx swap target after a mutation. The
/// full section template wraps this in `<section>` + the heading; the
/// partial is just what lives inside `<div id="oauth-sessions-section">`.
/// Returning the full section would nest a duplicate heading inside the
/// existing div on `hx-swap="innerHTML"`.
///
/// Carries the same `error: Option<String>` the section template uses so
/// the post-revoke swap surfaces a DB-failure state symmetrically with
/// the page-load path (otherwise a `list_active_sessions` failure after
/// a mutation would degrade to "No live OAuth sessions" silently).
#[derive(Template)]
#[template(path = "oauth_clients_table.html")]
struct OauthClientsRefresh {
    csrf_token: String,
    sessions: Vec<SessionView>,
    error: Option<String>,
    /// Each row's hx-post revoke form
    /// targets `/admin/identities/oauth-sessions/revoke` (or its
    /// tenant-prefixed equivalent), so this fragment needs to know
    /// which one to render. Populated by [`refresh_section`].
    tenant_ctx: Option<TenantContext>,
}

impl OauthClientsRefresh {
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

async fn revoke(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<RevokeForm>,
) -> ApiResult<Response> {
    require_admin_extension(user.as_ref().map(|Extension(p)| p))?;
    require_csrf(csrf.as_ref().map(|Extension(c)| c), &form.csrf)?;
    let store = state.identity.oauth.require()?;
    let revoked = store
        .revoke_by_client_sub(&form.client_id, &form.sub)
        .await
        .map_err(|e| ApiError::Internal(format!("revoke_by_client_sub: {e}")))?;
    tracing::info!(
        action = "oauth_session_revoked",
        oauth.client_id = %form.client_id,
        oauth.sub = %form.sub,
        oauth.revoked_rows = revoked,
        actor = %actor(&user),
        "oauth_clients: session revoked",
    );
    // Durable evidence: pair with the tracing line so the admin
    // Activity feed shows operator-driven OAuth revocations alongside
    // the token-mint events written by `/oauth/token`.
    state
        .evidence
        .record_chained_best_effort(
            waygate_mcp::AuditEvent::new("OAuthSessionRevoked", waygate_mcp::AuditOutcome::Success)
                .with_category(waygate_mcp::EvidenceCategory::OAuthEvent)
                .with_principal(user.as_ref().map(|Extension(p)| p))
                .with_reason(format!(
                    "client_id={} sub={} revoked_rows={} actor={}",
                    form.client_id,
                    form.sub,
                    revoked,
                    actor(&user),
                )),
        )
        .await;
    refresh_section(
        &state,
        user.as_ref().map(|Extension(p)| p),
        csrf,
        tenant_ctx.map(|Extension(c)| c),
    )
    .await
}

async fn refresh_section(
    state: &Arc<AdminState>,
    user: Option<&Principal>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<TenantContext>,
) -> ApiResult<Response> {
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();
    let section = load_section(state, user, csrf_token, tenant_ctx.clone()).await;
    // Render only the table partial — the section's `<section>` +
    // heading are already in the live DOM at the swap target's parent,
    // so re-rendering them would nest a duplicate. `hx-swap="innerHTML"`
    // on the form replaces `#oauth-sessions-section`'s children with this
    // body verbatim. Forward `error` through so a post-mutation list
    // failure renders the same error card as a page-load failure
    // instead of degrading to "No live OAuth sessions".
    let html = OauthClientsRefresh {
        csrf_token: section.csrf_token,
        sessions: section.sessions,
        error: section.error,
        tenant_ctx,
    }
    .render()
    .map_err(|e| ApiError::Internal(format!("render oauth section: {e}")))?;
    Ok(axum::response::Html(html).into_response())
}

// ---- shared helpers -------------------------------------------------------

fn require_csrf(have: Option<&CsrfToken>, submitted: &str) -> Result<(), ApiError> {
    let expected = have
        .ok_or(ApiError::Forbidden("csrf token missing from session"))?
        .0
        .as_str();
    if expected.is_empty() || expected != submitted {
        return Err(ApiError::Forbidden("csrf token mismatch"));
    }
    Ok(())
}

fn actor(user: &Option<Extension<Principal>>) -> String {
    user.as_ref()
        .map(|Extension(p)| p.sub.clone())
        .unwrap_or_else(|| "dashboard".into())
}

// ---- router ---------------------------------------------------------------

pub fn router() -> Router<Arc<AdminState>> {
    // `sub` lives in the form body, not the path — see `RevokeForm::sub`
    // for the OIDC-spec rationale (sub may contain arbitrary characters
    // that don't survive a URL path segment cleanly).
    Router::new().route("/identities/oauth-sessions/revoke", post(revoke))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_client_strips_scheme() {
        assert_eq!(
            display_client("https://cli.example.com/codex.json"),
            "cli.example.com/codex.json",
        );
        assert_eq!(
            display_client("http://localhost:8080/c.json"),
            "localhost:8080/c.json",
        );
        // Non-URL (future pre-reg) — pass through unchanged.
        assert_eq!(display_client("some-static-id"), "some-static-id");
    }
}
