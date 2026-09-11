//! Sessions page — `/admin/t/{tenant}/sessions`.
//!
//! Standalone home for the live OAuth-session inventory that used to be a
//! sibling section on the API-keys page. Renders the shared
//! `oauth_clients_section.html` (and its in-place htmx revoke flow) inside
//! a full dashboard page. The section's view-model, admin gating, and
//! revoke handler all live in [`crate::oauth_clients`]; this module is a
//! thin page wrapper. Read/observe surface only — no request hot-path
//! impact.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::oauth_clients::OauthClientsSection;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "sessions.html")]
struct SessionsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// OAuth-sessions section view-model (built by
    /// `oauth_clients::load_section`). The template rebinds its locals and
    /// includes `oauth_clients_section.html`; the section's `self.nav_url`
    /// and its htmx revoke target (`#oauth-sessions-section`) resolve
    /// against this page struct.
    oauth_section: OauthClientsSection,
}

impl SessionsPage {
    /// Include-context delegate: the shared partial this page includes calls
    /// `self.nav_url(...)`, which must resolve on the page struct too. Pure
    /// forward to [`crate::chrome::PageChrome::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        self.chrome.nav_url(path)
    }
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/sessions", get(sessions_page))
}

async fn sessions_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    // The section loader applies its own `mcp:admin` gate (defence in
    // depth) and the disabled-state shape when the OAuth store is unwired,
    // so this handler stays a thin orchestrator.
    let oauth_section =
        crate::oauth_clients::load_section(&state, user_principal, csrf_token, tenant_ctx.clone())
            .await;

    render(&SessionsPage {
        chrome: PageChrome::build(
            &state,
            "Sessions",
            "/sessions",
            &headers,
            user_principal.map(user_display),
            tenant_ctx,
            String::new(),
        ),
        oauth_section,
    })
}
