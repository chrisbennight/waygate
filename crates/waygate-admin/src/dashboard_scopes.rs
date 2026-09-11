//! Scopes page — `/admin/t/{tenant}/scopes`.
//!
//! Operator view of the scope registry (`waygate_apikeys::ScopeStore`,
//! table `scopes`). Three parts:
//!
//! 1. **Scopes** — every capability scope known to the principal's
//!    tenant: global built-ins (and policy-referenced
//!    scopes) unioned with this tenant's local scopes, each annotated
//!    with its `source` and how many live api-keys / roles reference it.
//! 2. **Add a scope** — admin-gated create form registering a
//!    tenant-local capability scope (minting is catalog-only).
//! 3. **Who has scope X?** — reverse lookup over RBAC: roles whose bundle
//!    contains the scope, plus their direct subjects and mapped SCIM
//!    groups. Needs `state.identity.rbac` (separate from the scope registry); a
//!    "not configured" note renders when the roles store is unwired.
//!
//! This kills the "scopes get created implicitly, can't see what
//! exists" gap: previously a scope was just a string typed into the
//! api-key mint form or baked into the `Scope` enum, with nothing to
//! browse. It is a visibility layer only — Cedar still evaluates
//! `principal.scopes` as plain strings, so this page is off the request
//! hot path.
//!
//! ## Admin gate
//!
//! Mirrors `dashboard_catalog`: a dashboard session without `mcp:admin`
//! (or a peer-asserted principal) sees the insufficient-scope card and
//! the store fetch is skipped entirely, so no per-tenant scope data
//! enters the rendered HTML.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use serde::Deserialize;
use waygate_apikeys::ScopeView;
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_rbac::Role;

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};

#[derive(Template)]
#[template(path = "scopes.html")]
struct ScopesPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the scope store is unwired (dev / no DB). Template
    /// renders the "store not configured" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin` (or is a
    /// peer assertion). Template renders the insufficient-scope card and
    /// SKIPS the store fetch.
    insufficient_scope: bool,
    /// Every scope visible to the tenant, ordered server-side by
    /// source then name.
    scopes: Vec<ScopeRow>,
    /// `true` when the store fetch failed. Template renders an error
    /// card instead of the empty state.
    load_error: bool,
    /// Operator-visible error from a failed create, threaded back via the
    /// `?scopes_error=` PRG query param. `None` ⇒ no banner.
    error: Option<String>,
    /// Current `?scope=` reverse-lookup input, re-populated into the form
    /// after the GET round-trip (same plain-GET re-fill posture the RBAC
    /// page used). `None` ⇒ empty form.
    scope_input: Option<String>,
    /// Result of the "Who has scope X?" reverse lookup over RBAC.
    reverse: ReversePanel,
    /// `true` when the RBAC store is wired. The reverse form renders a
    /// "store not configured" note otherwise (the lookup needs the roles
    /// store, which is independent of the scope registry).
    rbac_configured: bool,
}

/// One scope row for the table.
struct ScopeRow {
    name: String,
    /// `'builtin'` | `'policy'` | `'local'` — straight from the DB.
    source: String,
    /// `true` ⇒ a global scope (built-in / policy-referenced, applies
    /// to every tenant); `false` ⇒ tenant-local.
    is_global: bool,
    description: Option<String>,
    key_refs: i64,
    role_refs: i64,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/scopes", get(scopes_page))
        .route("/scopes/create", post(create_scope))
}

/// Query-string state for the page: the `?scopes_error=` PRG banner from
/// a failed create, plus the `?scope=` "Who has scope X?" reverse-lookup
/// input (moved here from the RBAC page — scopes are the natural home for
/// a scope→holders query).
#[derive(Debug, Default, Deserialize)]
struct ScopesQuery {
    scopes_error: Option<String>,
    /// "Who has scope X?" reverse lookup input. Trimmed to `None` when
    /// blank, so an empty submit renders the form with no result panel.
    #[serde(default)]
    scope: Option<String>,
}

/// Create-form body: register a tenant-local scope.
#[derive(Debug, Deserialize)]
struct ScopeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
}

async fn scopes_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<ScopesQuery>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.identity.scopes.enabled();

    let (scopes, load_error) = if insufficient_scope {
        // Skip the store read entirely — no scope data leaks into the
        // rendered HTML for a non-admin session.
        (Vec::new(), false)
    } else {
        match state.identity.scopes.get() {
            Some(store) => match store.list_with_usage(&read_tenant).await {
                Ok(rows) => (rows.into_iter().map(scope_row).collect(), false),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        tenant = %read_tenant,
                        "scopes page: list_with_usage failed",
                    );
                    (Vec::new(), true)
                }
            },
            None => (Vec::new(), false),
        }
    };

    // "Who has scope X?" reverse lookup. Same gate as the rest of the
    // page body (admin + scope store configured) so the form lives inside
    // the configured-page branch in the template; the lookup itself only
    // needs the RBAC store, surfaced separately via `rbac_configured`.
    let rbac_configured = state.identity.rbac.enabled();
    let scope_input = q.scope.as_ref().and_then(|s| {
        let t = s.trim().to_owned();
        (!t.is_empty()).then_some(t)
    });
    let reverse = if insufficient_scope || !store_configured {
        ReversePanel::not_queried()
    } else {
        match (state.identity.rbac.get(), scope_input.as_deref()) {
            (Some(rbac), Some(scope)) => lookup_reverse(rbac.as_ref(), &read_tenant, scope).await,
            _ => ReversePanel::not_queried(),
        }
    };

    let page = ScopesPage {
        chrome: PageChrome::build(
            &state,
            "Scopes",
            "/scopes",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope,
        scopes,
        load_error,
        // Only surface the banner to admins (a non-admin never sees the form).
        error: if insufficient_scope {
            None
        } else {
            q.scopes_error
        },
        scope_input,
        reverse,
        rbac_configured,
    };
    render(&page)
}

/// Register a tenant-local scope from the dashboard create form.
/// Admin-gated + CSRF-checked; audited fail-closed; PRG back to `/scopes`.
async fn create_scope(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<ScopeForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    match crate::identity_catalog::create_local_scope_core(
        &state,
        tenant,
        principal,
        &form.name,
        Some(&form.description),
    )
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
                "scope changes require mcp:admin",
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
    Redirect::to(&tenant_ctx::nav_url(tenant_ctx.as_ref(), "/scopes")).into_response()
}

fn redirect_err(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?scopes_error={}",
        tenant_ctx::nav_url(tenant_ctx.as_ref(), "/scopes"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

fn scope_row(v: ScopeView) -> ScopeRow {
    ScopeRow {
        name: v.name,
        source: v.source,
        is_global: v.tenant_id.is_none(),
        description: v.description,
        key_refs: v.key_refs,
        role_refs: v.role_refs,
    }
}

/// Result of the "Who has scope X?" reverse lookup (moved here from the
/// RBAC page — scopes are the natural home for a scope→holders query).
/// Flat-struct shape so askama renders each branch off booleans.
#[derive(Default)]
struct ReversePanel {
    queried: bool,
    scope: Option<String>,
    is_error: bool,
    error_message: Option<String>,
    /// `true` when the scope wasn't present in any role's bundle for this
    /// tenant. RBAC wouldn't grant it — though direct JWT / API-key scopes
    /// can still carry it.
    is_no_matches: bool,
    /// `true` when at least one role's bundle contains the scope. `rows`
    /// is non-empty in that case.
    is_found: bool,
    rows: Vec<ReverseRow>,
}

impl ReversePanel {
    fn not_queried() -> Self {
        Self::default()
    }
    fn no_matches(scope: String) -> Self {
        Self {
            queried: true,
            scope: Some(scope),
            is_no_matches: true,
            ..Self::default()
        }
    }
    fn found(scope: String, rows: Vec<ReverseRow>) -> Self {
        Self {
            queried: true,
            scope: Some(scope),
            is_found: true,
            rows,
            ..Self::default()
        }
    }
    fn error(scope: String, message: String) -> Self {
        Self {
            queried: true,
            scope: Some(scope),
            is_error: true,
            error_message: Some(message),
            ..Self::default()
        }
    }
}

struct ReverseRow {
    role: String,
    /// Operator-friendly `subject_sub` strings from direct
    /// `role_assignments`. Empty when the role grants the scope only via
    /// group mappings.
    direct_subjects: Vec<String>,
    /// Group ids the role is bound to. Rendered as `group:<uuid>` (the
    /// string form the dashboard uses elsewhere); member expansion is the
    /// SCIM/Groups page's job.
    via_groups: Vec<String>,
}

/// Walk every role in the tenant, filter to roles whose `scopes` bundle
/// contains the input string, then surface the direct subjects + SCIM
/// groups bound to each matching role. Member expansion of groups is
/// deferred — the Groups page is the canonical group→members view.
async fn lookup_reverse(
    rbac: &dyn waygate_rbac::RbacStore,
    tenant: &str,
    scope: &str,
) -> ReversePanel {
    let roles = match rbac.list_roles(tenant).await {
        Ok(r) => r,
        Err(e) => return ReversePanel::error(scope.to_owned(), format!("list_roles failed: {e}")),
    };
    let matching: Vec<Role> = roles
        .into_iter()
        .filter(|r| r.scopes.iter().any(|s| s == scope))
        .collect();
    if matching.is_empty() {
        return ReversePanel::no_matches(scope.to_owned());
    }

    let mut rows = Vec::with_capacity(matching.len());
    for role in matching {
        // Per-role lookups are bounded (typical tenants have ≪50
        // assignments + ≪10 mappings per role). The two calls run
        // sequentially per role to keep the upper-bound pool load
        // conservative.
        let direct_subjects = match rbac.list_assignments(tenant, Some(role.id), None).await {
            Ok(a) => a.into_iter().map(|a| a.subject_sub).collect(),
            Err(e) => {
                return ReversePanel::error(
                    scope.to_owned(),
                    format!("list_assignments({}) failed: {e}", role.name),
                )
            }
        };
        let via_groups = match rbac.list_group_mappings(tenant, Some(role.id), None).await {
            Ok(m) => m.into_iter().map(|m| m.group_id.to_string()).collect(),
            Err(e) => {
                return ReversePanel::error(
                    scope.to_owned(),
                    format!("list_group_mappings({}) failed: {e}", role.name),
                )
            }
        };
        rows.push(ReverseRow {
            role: role.name,
            direct_subjects,
            via_groups,
        });
    }

    ReversePanel::found(scope.to_owned(), rows)
}

/// Authorization gate for the scopes dashboard page. Same shape as
/// `dashboard_catalog::principal_has_dashboard_admin`.
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
    use time::OffsetDateTime;
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
    fn scopes_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn scopes_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(vec!["mcp:read"], AuthMethod::Oauth);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn scopes_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn scopes_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn scope_row_marks_null_tenant_as_global() {
        let global = ScopeView {
            id: Uuid::nil(),
            tenant_id: None,
            name: "mcp:invoke".into(),
            source: "builtin".into(),
            description: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            key_refs: 3,
            role_refs: 1,
        };
        let row = scope_row(global);
        assert!(
            row.is_global,
            "NULL tenant_id must render as a global scope"
        );
        assert_eq!(row.source, "builtin");
        assert_eq!(row.key_refs, 3);

        let local = ScopeView {
            id: Uuid::nil(),
            tenant_id: Some("default".into()),
            name: "team:payroll".into(),
            source: "local".into(),
            description: Some("payroll team".into()),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            key_refs: 0,
            role_refs: 0,
        };
        let row = scope_row(local);
        assert!(!row.is_global, "a tenant slug must render as tenant-local");
    }
}
