//! Groups page — `/admin/t/{tenant}/groups`.
//!
//! Read-only operator view of the unified group catalog
//! (`waygate_apikeys::GroupStore` over the `scim_groups` table). One
//! section: every group known to the tenant — IdP-provisioned SCIM
//! groups (`source='scim'`) and operator/api-key `'local'` groups —
//! each annotated with how many SCIM users and live api-keys are
//! members.
//!
//! This unifies the two previously-disconnected notions of "group":
//! the free-text labels typed into the api-key mint form (now backfilled
//! as first-class `local` groups by migration 0066) and the
//! SCIM-provisioned directory. It's a visibility layer only — Cedar
//! still evaluates `principal.groups` as plain strings, so this page is
//! off the request hot path.
//!
//! ## Admin gate
//!
//! Mirrors `dashboard_scopes` / `dashboard_catalog`: a session without
//! `mcp:admin` (or a peer assertion) sees the insufficient-scope card
//! and the store fetch is skipped, so no per-tenant group data enters
//! the rendered HTML.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use serde::Deserialize;
use waygate_apikeys::GroupView;
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_core::fmt::format_ts_abs;

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the group store is unwired (dev / no DB). Template
    /// renders the "store not configured" card.
    store_configured: bool,
    /// `true` when the principal lacks `mcp:admin` (or is a peer
    /// assertion). Template renders the insufficient-scope card and SKIPS
    /// the store fetch.
    insufficient_scope: bool,
    /// Every group visible to the tenant, ordered server-side by source
    /// then name.
    groups: Vec<GroupRow>,
    /// `true` when the store fetch failed. Template renders an error card
    /// instead of the empty state.
    load_error: bool,
    /// Operator-visible error from a failed create, threaded back via the
    /// `?groups_error=` PRG query param.
    error: Option<String>,
}

/// One group row for the table.
struct GroupRow {
    display_name: String,
    /// `'scim'` | `'local'` — straight from the DB.
    source: String,
    /// IdP external id (SCIM groups) — `None` renders an em-dash.
    external_id: Option<String>,
    created_at_abs: String,
    user_member_count: i64,
    key_member_count: i64,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/groups", get(groups_page))
        .route("/groups/create", post(create_group))
}

/// `?groups_error=` PRG banner from a failed create.
#[derive(Debug, Default, Deserialize)]
struct GroupsQuery {
    groups_error: Option<String>,
}

/// Create-form body: register a tenant-local group.
#[derive(Debug, Deserialize)]
struct GroupForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
}

async fn groups_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<GroupsQuery>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.identity.groups.enabled();

    let (groups, load_error) = if insufficient_scope {
        (Vec::new(), false)
    } else {
        match state.identity.groups.get() {
            Some(store) => match store.list_with_usage(&read_tenant).await {
                Ok(rows) => (rows.into_iter().map(group_row).collect(), false),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        tenant = %read_tenant,
                        "groups page: list_with_usage failed",
                    );
                    (Vec::new(), true)
                }
            },
            None => (Vec::new(), false),
        }
    };

    let page = GroupsPage {
        chrome: PageChrome::build(
            &state,
            "Groups",
            "/groups",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope,
        groups,
        load_error,
        error: if insufficient_scope {
            None
        } else {
            q.groups_error
        },
    };
    render(&page)
}

/// Register a tenant-local group from the dashboard create form.
/// Admin-gated + CSRF-checked; audited fail-closed; PRG back to `/groups`.
async fn create_group(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<GroupForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    match crate::identity_catalog::create_local_group_core(&state, tenant, principal, &form.name)
        .await
    {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_err(tenant_ctx, &e.detail()),
    }
}

/// Admin-gate + CSRF check, shared by the create handler. Mirrors
/// `dashboard_rbac::authorize`.
#[allow(clippy::type_complexity)]
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<Extension<TenantContext>>,
    form_csrf: &str,
) -> Result<(Option<&'a Principal>, Option<TenantContext>, &'a str), Box<Response>> {
    let principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(principal) {
        return Err(Box::new(
            (
                axum::http::StatusCode::FORBIDDEN,
                "group changes require mcp:admin",
            )
                .into_response(),
        ));
    }
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form_csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, form_csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return Err(Box::new(
            (axum::http::StatusCode::FORBIDDEN, "csrf mismatch").into_response(),
        ));
    }
    let tenant = principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c), tenant))
}

fn redirect_ok(tenant_ctx: Option<TenantContext>) -> Response {
    Redirect::to(&tenant_ctx::nav_url(tenant_ctx.as_ref(), "/groups")).into_response()
}

fn redirect_err(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?groups_error={}",
        tenant_ctx::nav_url(tenant_ctx.as_ref(), "/groups"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

fn group_row(v: GroupView) -> GroupRow {
    GroupRow {
        display_name: v.display_name,
        source: v.source,
        external_id: v.external_id,
        created_at_abs: format_ts_abs(v.created_at),
        user_member_count: v.user_member_count,
        key_member_count: v.key_member_count,
    }
}

/// Authorization gate for the groups dashboard page. Same shape as
/// `dashboard_scopes::principal_has_dashboard_admin`.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

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
    fn groups_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn groups_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(vec!["mcp:read"], AuthMethod::Oauth);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn groups_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn group_row_carries_source_and_member_counts() {
        let v = GroupView {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            display_name: "mcp-users".into(),
            source: "local".into(),
            external_id: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            user_member_count: 0,
            key_member_count: 4,
            role_mapping_count: 0,
        };
        let row = group_row(v);
        assert_eq!(row.source, "local");
        assert_eq!(row.key_member_count, 4);
        assert_eq!(row.user_member_count, 0);
        assert!(row.external_id.is_none());
    }
}
