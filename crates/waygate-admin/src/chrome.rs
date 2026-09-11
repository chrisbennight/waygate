//! The shared dashboard page chrome.
//!
//! Every full dashboard page renders through `layout.html`, whose topbar /
//! sidebar / theming consume the same seven values. Before this module, all
//! 38 page structs redeclared those seven fields and 54 copies of `nav_url`
//! existed; the topbar's environment chip was a hardcoded `"dev"` literal at
//! every construction site. [`PageChrome`] is the single copy: page structs
//! embed `chrome: PageChrome`, handlers call [`PageChrome::build`], and
//! templates read `chrome.title`, `chrome.nav`, `chrome.nav_url(...)`, etc.
//!
//! `scripts/check-page-chrome.sh` enforces this in CI: a new `nav:
//! Vec<NavGroup>` field or `fn nav_url` outside this module fails the build.
//!
//! Deliberately NOT here: page-specific state (tables, error strings,
//! `store_configured` cards) and fragment templates that don't extend
//! `layout.html`.

use axum::http::HeaderMap;

use crate::dashboard::{theme_from_cookie, NavGroup};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};

/// The seven values `layout.html`'s topbar / sidebar / theming consume, plus
/// the CSRF token page bodies embed in mutating forms. One per rendered page;
/// built by [`PageChrome::build`] at the top of the handler.
pub struct PageChrome {
    /// Page `<title>` and topbar heading.
    pub title: &'static str,
    /// Topbar environment chip — `SystemInfo::deployment_profile`
    /// (`GATEWAY_DEPLOYMENT_PROFILE`): `"dev"`, `"prod"`, or `"unknown"` in
    /// compositions that don't set it. Was a hardcoded `"dev"` literal at
    /// every page before this module existed.
    pub env: &'static str,
    /// Signed-in principal's display string (email, else sub); `None` on
    /// pages rendered without a principal.
    pub user: Option<String>,
    /// Theme cookie value (`"light"` / `"dark"`), `None` = default.
    pub theme: Option<String>,
    /// Sidebar destinations with the active entry marked, built by
    /// [`crate::dashboard::nav`] from the page's route suffix.
    pub nav: Vec<NavGroup>,
    /// Tenant path prefix context (`/admin/t/{tenant}` URLs); `None` on
    /// legacy non-tenant-scoped URLs.
    pub tenant_ctx: Option<TenantContext>,
    /// Per-session CSRF token pages embed in mutating forms; empty on pages
    /// with no forms (they never render it).
    pub csrf_token: String,
}

impl PageChrome {
    /// Assemble the chrome from what every page handler already has in hand.
    /// `active_suffix` is the page's route suffix (e.g. `"/tenants"`) used to
    /// mark the sidebar's active destination.
    pub(crate) fn build(
        state: &AdminState,
        title: &'static str,
        active_suffix: &str,
        headers: &HeaderMap,
        user: Option<String>,
        tenant_ctx: Option<TenantContext>,
        csrf_token: String,
    ) -> Self {
        Self {
            title,
            env: state.system.deployment_profile,
            user,
            theme: theme_from_cookie(headers),
            nav: crate::dashboard::nav(active_suffix, tenant_ctx.as_ref()),
            tenant_ctx,
            csrf_token,
        }
    }

    /// Tenant-aware URL for a dashboard path — the single copy of what used
    /// to be 54 identical per-page-struct `fn nav_url` impls. Templates call
    /// `chrome.nav_url("/x")`.
    pub fn nav_url(&self, path: &str) -> String {
        tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}
