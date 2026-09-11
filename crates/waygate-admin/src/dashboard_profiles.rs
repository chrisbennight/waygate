//! Profiles page — `/admin/t/{tenant}/profiles`.
//!
//! Standalone home for the API-key profile registry + inline create/delete
//! forms that used to be a section on the API-keys page. "Minting a key and
//! minting a key profile should be separate" — profiles now get their own
//! page, so the mint form on the API Keys page is just key minting.
//!
//! Renders the shared `api_key_profiles_section.html`; the section's
//! view-model, admin gating, and create/delete handlers all live in
//! [`crate::api_key_profiles_section`]. Those handlers PRG-redirect back
//! here (`?akp_error=<msg>` carries a create/delete failure for the form
//! to render). Authoring surface only — no request hot-path impact.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use waygate_oidc::Principal;

use crate::api_key_profiles_section::ProfilesSection;
use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "profiles.html")]
struct ProfilesPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// API-key profiles section view-model (built by
    /// `api_key_profiles_section::load_section`). The template rebinds its
    /// locals and includes `api_key_profiles_section.html`; the section's
    /// `self.nav_url` resolves against this page struct.
    profiles_section: ProfilesSection,
}

impl ProfilesPage {
    /// Include-context delegate: the shared partial this page includes calls
    /// `self.nav_url(...)`, which must resolve on the page struct too. Pure
    /// forward to [`crate::chrome::PageChrome::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        self.chrome.nav_url(path)
    }
}

/// `?akp_error=` PRG channel: a create/delete-form failure is carried back
/// here by the section's handlers and rendered beside the form.
#[derive(Debug, Default, Deserialize)]
struct ProfilesQuery {
    #[serde(default)]
    akp_error: Option<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/profiles", get(profiles_page))
}

async fn profiles_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<ProfilesQuery>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    // Tenant comes from the principal, NOT tenant_ctx — same rule every
    // other profile path enforces. The section loader applies its own
    // admin gate + disabled-state shape, so this handler stays thin.
    let profiles_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let profiles_section = crate::api_key_profiles_section::load_section(
        &state,
        user_principal,
        &profiles_tenant,
        tenant_ctx.clone(),
        csrf_token,
        q.akp_error,
    )
    .await;

    render(&ProfilesPage {
        chrome: PageChrome::build(
            &state,
            "Profiles",
            "/profiles",
            &headers,
            user_principal.map(user_display),
            tenant_ctx,
            String::new(),
        ),
        profiles_section,
    })
}
