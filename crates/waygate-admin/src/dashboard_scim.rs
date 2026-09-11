//! Users page — `/admin/t/{tenant}/scim`.
//!
//! Nav tab + page title read "Users"; the route and backend stay
//! SCIM 2.0 (`waygate_scim`), so the module keeps the SCIM name.
//!
//! Read-only operator view of the per-tenant SCIM-provisioned
//! identity directory (`waygate_scim`).
//!
//! 1. **Users** — `scim_users` for the tenant: userName,
//!    external id, active flag, created timestamp. Backed by
//!    `ScimUserStore::list`.
//! 2. **Provisioning log** — the latest SCIM mutations from
//!    `scim_provisioning_log`, rendered as a timeline. Backed by
//!    `ScimProvisioningLogStore`; independent of the user store gate,
//!    so it renders for any sufficient-scope principal whenever the
//!    log store is wired.
//!
//! Groups (SCIM + local) live on the unified **Groups** page
//! (`/groups`); this page no longer renders a Groups section —
//! consolidated into the single Groups view.
//!
//! ## What's NOT here (deferred, intentional)
//!
//! - **Per-row drawer** with full attributes + group membership.
//!   Membership is a per-group `members()` call (an N+1 over
//!   the list), and the raw `attrs` JSON is operator-confidential
//!   IdP payload best shown on demand. Today the full resource
//!   (including `members[]`) is available via the REST surface
//!   (`GET /scim/v2/Users/{id}`, `GET /scim/v2/Groups/{id}`).
//!
//! Same read-only-mutations-go-via-REST posture every other
//! dashboard page holds — SCIM CRUD stays at `/scim/v2/*`.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant`; both `list` calls are strictly
//! per-tenant.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin`. A dashboard session
//! without `mcp:admin` (or a peer-asserted principal) sees the
//! insufficient-scope card; both store fetches are skipped so no
//! IdP-provisioned user names or external ids enter the rendered
//! HTML.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_scim::{ListParams, ScimFilter, ScimUser};

use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// Page size for each section. The store clamps `count` to
/// `[1, 200]`; 200 shows a full first page for a healthy tenant.
/// Deep paging lives on the REST surface (`?startIndex=&count=`).
const SCIM_PAGE_COUNT: i64 = 200;

/// Page size for the provisioning-log section. The
/// store clamps at 100; 50 leaves the page compact while
/// still showing the most recent few minutes of provisioning
/// activity on a healthy tenant.
const PROVISIONING_LOG_PAGE_LIMIT: i64 = 50;

#[derive(Template)]
#[template(path = "scim.html")]
struct ScimPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the SCIM stores are unwired (dev mode / no DB).
    /// Template renders the "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). Template renders the
    /// insufficient-scope card and SKIPS both store fetches.
    insufficient_scope: bool,

    users: Vec<UserRow>,
    /// `true` when the user count exceeded [`SCIM_PAGE_COUNT`];
    /// template renders a "showing first N" hint toward REST.
    users_truncated: bool,
    /// `true` when the user fetch failed (renders a per-section
    /// error card).
    users_load_error: bool,

    /// `true` when the provisioning-log store is wired
    /// on `AdminState`. `false` ⇒ the template hides the
    /// Provisioning-log section; the page falls back to the
    /// list-only shape.
    provisioning_log_configured: bool,
    /// Latest entries for the active tenant, newest
    /// first. Capped at [`PROVISIONING_LOG_PAGE_LIMIT`].
    provisioning_log: Vec<ProvisioningLogRow>,
    /// `true` when the provisioning-log fetch failed;
    /// template renders a per-section error card (same pattern
    /// as users / groups).
    provisioning_log_load_error: bool,
    /// `true` when the latest fetch returned exactly
    /// `PROVISIONING_LOG_PAGE_LIMIT` rows — likely more in the
    /// store. Template surfaces a hint pointing at the
    /// Activity page.
    provisioning_log_truncated: bool,
}

impl ScimPage {}

struct UserRow {
    user_name: String,
    /// `Some(ext)` when the IdP emits an external id; `None`
    /// renders an em-dash.
    external_id: Option<String>,
    active: bool,
    created_at_abs: String,
}

/// One provisioning-log entry as the dashboard
/// timeline renders it. Pre-formatted strings so the askama
/// template stays renderer-only.
struct ProvisioningLogRow {
    ts_abs: String,
    target_kind: &'static str,
    target_display: String,
    action: String,
    /// `success` | `error`. Template renders the matching chip.
    outcome: &'static str,
    /// Operator-friendly actor — email if present, else sub,
    /// else `—`.
    actor: String,
    /// `Some(...)` when `outcome == "error"`; rendered inline
    /// under the row. `None` for success rows.
    error_message: Option<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/scim", get(scim_page))
}

async fn scim_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    // This page is now Users-only (groups moved to /groups); SCIM is
    // configured when the users store is wired (same DB-pool gating).
    let store_configured = state.identity.scim_users.enabled();

    let load = if insufficient_scope {
        LoadResult::default()
    } else {
        load_scim(&state, &read_tenant).await
    };

    let page = ScimPage {
        chrome: PageChrome::build(
            &state,
            "Users",
            "/scim",
            &headers,
            user_display_str,
            tenant_ctx,
            String::new(),
        ),
        store_configured,
        insufficient_scope,
        users: load.users,
        users_truncated: load.users_truncated,
        users_load_error: load.users_load_error,
        provisioning_log_configured: state.identity.scim_provisioning_log.enabled(),
        provisioning_log: load.provisioning_log,
        provisioning_log_load_error: load.provisioning_log_load_error,
        provisioning_log_truncated: load.provisioning_log_truncated,
    };
    render(&page)
}

/// Authorization gate for the SCIM dashboard page. Same shape as
/// `dashboard_catalog::principal_has_dashboard_admin`.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

#[derive(Default)]
struct LoadResult {
    users: Vec<UserRow>,
    users_truncated: bool,
    users_load_error: bool,
    provisioning_log: Vec<ProvisioningLogRow>,
    provisioning_log_load_error: bool,
    provisioning_log_truncated: bool,
}

async fn load_scim(state: &AdminState, tenant: &str) -> LoadResult {
    let mut out = LoadResult::default();
    let params = ListParams {
        start_index: 1,
        count: SCIM_PAGE_COUNT,
    };

    // Two independent per-section fetches; a failure on one renders
    // that section's error card without wiping the other.
    if let Some(store) = state.identity.scim_users.get() {
        match store.list(tenant, ScimFilter::None, params).await {
            Ok(res) => {
                out.users_truncated = res.total_results > res.resources.len() as i64;
                out.users = res.resources.into_iter().map(user_row).collect();
            }
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, "scim page: user list failed");
                out.users_load_error = true;
            }
        }
    }

    if let Some(store) = state.identity.scim_provisioning_log.get() {
        match store.list(tenant, PROVISIONING_LOG_PAGE_LIMIT, None).await {
            Ok(rows) => {
                out.provisioning_log_truncated = rows.len() as i64 >= PROVISIONING_LOG_PAGE_LIMIT;
                out.provisioning_log = rows.into_iter().map(provisioning_row).collect();
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant = %tenant,
                    "scim page: provisioning_log list failed",
                );
                out.provisioning_log_load_error = true;
            }
        }
    }

    out
}

/// Convert a stored entry into the template-ready row.
fn provisioning_row(
    e: waygate_dashboard_stores::scim_provisioning_log::Entry,
) -> ProvisioningLogRow {
    use waygate_dashboard_stores::scim_provisioning_log::{Outcome, TargetKind};
    ProvisioningLogRow {
        ts_abs: format_ts_abs(e.ts),
        target_kind: match e.target_kind {
            TargetKind::User => "user",
            TargetKind::Group => "group",
        },
        target_display: e.target_display,
        action: e.action,
        outcome: match e.outcome {
            Outcome::Success => "success",
            Outcome::Error => "error",
        },
        actor: e
            .actor_email
            .or(e.actor_sub)
            .unwrap_or_else(|| "—".to_string()),
        error_message: e.error_message,
    }
}

fn user_row(u: ScimUser) -> UserRow {
    UserRow {
        user_name: u.user_name,
        external_id: u.external_id,
        active: u.active,
        created_at_abs: format_ts_abs(u.created_at),
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
    fn scim_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn scim_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn scim_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn scim_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }
}
