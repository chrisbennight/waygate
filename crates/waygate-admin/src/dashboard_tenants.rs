//! Tenants page — `/admin/t/{tenant}/tenants`.
//!
//! Listing of the canonical `tenants` registry (id, display_name, status,
//! created/updated timestamps) plus an admin-only inline **create** form
//! (`POST /tenants/create`, which reuses the REST composition-root seeding).
//! The remaining mutations (suspend / archive / retire) still live at
//! `/api/v1/admin/tenants/*`; inline edit forms for those are a follow-up.
//!
//! ## Why a separate page
//!
//! Multi-tenancy is live (the canonical registry plus bearer
//! enforcement) but operators had no way to see "which
//! tenants exist on this gateway, and what state are they in" without
//! curling the REST API. The cross-tenant banner presumes the
//! operator already knows the slug they want; this page is the
//! discovery surface that feeds the sidebar selector.
//!
//! ## Tenant scoping
//!
//! Unlike most dashboard pages, this one INTENTIONALLY does not filter
//! by `principal.tenant`. The tenants registry is global (every row is
//! visible to any operator with dashboard access today; cross-tenant
//! role separation is not yet implemented). A `tenant_admin`-scoped
//! operator who shouldn't see other tenants would currently still see
//! them here — that's future role-separation work, not a gap specific
//! to this page.
//!
//! ## Row enrichment (deferred)
//!
//! A 7-day activity count and role/key counts per tenant would round
//! this page out. Those are per-row store fan-outs (audit reader, the
//! api_keys store, the rbac store) and would require a coordinated
//! multi-query loop or a denormalized stats view. Out of scope
//! today; the row drawer redesign in a follow-up earns the right to
//! do them.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use waygate_oidc::Principal;
use waygate_tenants::{Tenant, TenantStatus, TenantStore};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_core::fmt::format_ts_abs;

/// Row cap on the dashboard. Larger deployments would need the REST
/// surface (which already supports pagination); the dashboard view
/// is a discovery surface, not a bulk-operator surface.
const TENANT_LIST_LIMIT: usize = 200;

#[derive(Template)]
#[template(path = "tenants.html")]
struct TenantsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when no tenants registry is wired (dev mode / no DB).
    /// The template renders a feature-disabled card so an operator
    /// doesn't misread the empty list as "no tenants exist."
    store_configured: bool,
    /// Tenants from `state.identity.tenants.list()`, capped at
    /// [`TENANT_LIST_LIMIT`]. Sorted by id (the registry's natural
    /// alphabetical order — see `PgTenantStore::list`).
    tenants: Vec<TenantRow>,
    /// `true` when the registry held more rows than the cap. Template
    /// nudges toward the REST surface for the full list.
    truncated: bool,
    /// Store-error fallback. When `list()` returns an error, populate
    /// this with a short operator message and render an error card
    /// instead of an empty table.
    error: Option<String>,
    /// The principal's home tenant slug. Highlighted in the table so
    /// an operator scanning the list sees "you're acting from this
    /// tenant" at a glance.
    principal_tenant_slug: String,
    /// `true` when the dashboard principal has admin scope — gates the
    /// inline create / edit / delete forms' visibility (the POST
    /// handlers re-check).
    is_admin: bool,
    /// `Some(msg)` when an inline edit / delete submission failed,
    /// threaded back via the `?tenants_error=` PRG query param and
    /// rendered above the table. (Create keeps its raw-error contract —
    /// see `tenants_create`.)
    tenants_error: Option<String>,
}

struct TenantRow {
    id: String,
    display_name: String,
    /// Raw status string from the store — `"active"` or `"suspended"`.
    /// Template drives the chip class from this.
    status: String,
    created_at_abs: String,
    updated_at_abs: String,
    /// `true` when this row's id matches the principal's home tenant.
    /// Template renders a small "you" chip on it.
    is_principal_home: bool,
    /// Relative URLs for the per-row edit / delete form actions; the
    /// template wraps each with `self.nav_url(...)`. Precomputed because
    /// askama can't `format!` the id into the path inline.
    update_rel: String,
    delete_rel: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/tenants", get(tenants_page))
        .route("/tenants/create", post(tenants_create))
        .route("/tenants/{id}/update", post(tenants_update))
        .route("/tenants/{id}/delete", post(tenants_delete))
}

/// Query-string state for the tenants page — only the PRG error channel
/// for the inline edit / delete forms.
#[derive(Debug, Default, Deserialize)]
struct TenantsQuery {
    /// PRG channel: an edit / delete failure is carried back here and
    /// rendered above the table. Passed through verbatim (urlencoded on
    /// the way out).
    #[serde(default)]
    tenants_error: Option<String>,
}

async fn tenants_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<TenantsQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let is_admin = crate::scope::require_admin_extension(user_principal).is_ok();
    let user_display_str = user_principal.map(user_display);

    let principal_tenant_slug = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let store_configured = state.identity.tenants.enabled();
    let (tenants, truncated, error) = match state.identity.tenants.get() {
        Some(store) => load_tenants(store, &principal_tenant_slug).await,
        None => (Vec::new(), false, None),
    };

    let page = TenantsPage {
        chrome: PageChrome::build(
            &state,
            "Tenants",
            "/tenants",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        tenants,
        truncated,
        error,
        principal_tenant_slug,
        is_admin,
        tenants_error: q.tenants_error,
    };
    render(&page)
}

/// Form body for the inline tenant-create form.
#[derive(Debug, Deserialize)]
struct CreateTenantForm {
    /// Defaulted so a missing csrf lands in the handler's own CSRF check
    /// (→ 403) rather than a 422 deserialize error.
    #[serde(default)]
    csrf: String,
    id: String,
    display_name: String,
}

/// `POST /tenants/create` — inline dashboard tenant create + composition-root
/// seeding. Admin-gated + CSRF; reuses the REST orchestration via
/// `crate::tenants::create_and_seed_tenant_dashboard`, then PRG back to the list.
async fn tenants_create(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<CreateTenantForm>,
) -> Response {
    if let Err(e) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    // Dev mode injects a CsrfToken; require a match when one is present.
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form.csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, &form.csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let principal = match user.as_ref() {
        Some(Extension(p)) => p,
        None => return (StatusCode::FORBIDDEN, "admin scope required").into_response(),
    };
    if let Err(e) = crate::tenants::create_and_seed_tenant_dashboard(
        &state,
        form.id.trim(),
        form.display_name.trim(),
        principal,
    )
    .await
    {
        return e.into_response();
    }
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    Redirect::to(&tenant_ctx::nav_url(tenant_ctx.as_ref(), "/tenants")).into_response()
}

/// Form body for the per-row tenant edit: a display-name input + a
/// status `<select>`. An empty `display_name` is treated as "leave
/// unchanged" (PATCH semantics), so the operator can flip status
/// without retyping the name.
#[derive(Debug, Deserialize)]
struct UpdateTenantForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    status: String,
}

/// Form body for the per-row tenant delete — only the CSRF token.
#[derive(Debug, Deserialize)]
struct DeleteTenantForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /tenants/{id}/update` — admin-gated + CSRF, reuses
/// [`crate::tenants::update_tenant_core`] (validate → update →
/// cache-invalidate → audit) and PRG-redirects with a `?tenants_error=`
/// channel.
async fn tenants_update(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<UpdateTenantForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read `id` by name: mounted at both `/tenants/{id}/update` and the
    // 2-capture `/t/{tenant}/...` nest; `Path<String>` 500s on the
    // latter.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing tenant id.");
    };
    let status = match form.status.trim() {
        "" => None,
        "active" => Some(TenantStatus::Active),
        "suspended" => Some(TenantStatus::Suspended),
        other => return redirect_with_error(tenant_ctx, &format!("Unknown status '{other}'.")),
    };
    let trimmed = form.display_name.trim();
    let display_name = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    };
    match crate::tenants::update_tenant_core(&state, id.trim(), display_name, status, principal)
        .await
    {
        Ok(Some(_)) => redirect_ok(tenant_ctx),
        Ok(None) => redirect_with_error(tenant_ctx, "That tenant no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &tenant_err_message(&e, "update")),
    }
}

/// `POST /tenants/{id}/delete` — admin-gated + CSRF, reuses
/// [`crate::tenants::delete_tenant_core`]. That core runs the
/// security-critical onboarding-residue cleanup BEFORE the
/// row delete; routing the dashboard delete through it is what keeps
/// the inline action from reopening the key-resurrection hole.
async fn tenants_delete(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<DeleteTenantForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // By-name `id` — same dual-mount reason as `tenants_update`.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing tenant id.");
    };
    match crate::tenants::delete_tenant_core(&state, id.trim(), principal).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(tenant_ctx, "That tenant no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &tenant_err_message(&e, "delete")),
    }
}

/// Shared admin-gate + CSRF for the tenant edit / delete handlers.
/// Matches the page's existing `tenants_create` gate
/// (`require_admin_extension` + the dev-mode CSRF check) so the three
/// mutations share one posture. Returns `(principal, tenant_ctx)` or the
/// boxed error `Response`.
#[allow(clippy::type_complexity)]
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<Extension<TenantContext>>,
    form_csrf: &str,
) -> Result<(&'a Principal, Option<TenantContext>), Box<Response>> {
    let principal_opt = user.as_ref().map(|Extension(p)| p);
    if let Err(e) = crate::scope::require_admin_extension(principal_opt) {
        return Err(Box::new(e.into_response()));
    }
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form_csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, form_csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "csrf mismatch").into_response(),
        ));
    }
    // require_admin_extension(None) errors above, so principal is Some here.
    let Some(principal) = principal_opt else {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "admin scope required").into_response(),
        ));
    };
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c)))
}

fn redirect_ok(tenant_ctx: Option<TenantContext>) -> Response {
    Redirect::to(&tenant_ctx::nav_url(tenant_ctx.as_ref(), "/tenants")).into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?tenants_error={}",
        tenant_ctx::nav_url(tenant_ctx.as_ref(), "/tenants"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Operator-safe tenant-mutation message, parameterized by verb. The
/// validation / conflict / not-found detail is safe to surface; anything
/// else collapses to a generic line pointing at the logs.
fn tenant_err_message(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::NotFoundDyn(d) => d.clone(),
        ApiError::ServiceUnavailable(d) | ApiError::NotFound(d) => (*d).to_owned(),
        _ => format!("Failed to {verb} tenant — see gateway logs for details."),
    }
}

async fn load_tenants(
    store: &Arc<dyn TenantStore>,
    principal_slug: &str,
) -> (Vec<TenantRow>, bool, Option<String>) {
    let raw = match store.list().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "tenants page: list failed");
            return (
                Vec::new(),
                false,
                Some("Failed to load tenants — see gateway logs for details.".to_owned()),
            );
        }
    };
    // +1 truncation detection: fetch one extra so an exactly-N
    // registry isn't mis-flagged as truncated. The store's `list()`
    // doesn't take a limit today, so we cap after.
    let total = raw.len();
    let truncated = total > TENANT_LIST_LIMIT;
    let rows: Vec<TenantRow> = raw
        .into_iter()
        .take(TENANT_LIST_LIMIT)
        .map(|t| tenant_row(t, principal_slug))
        .collect();
    (rows, truncated, None)
}

fn tenant_row(t: Tenant, principal_slug: &str) -> TenantRow {
    let is_principal_home = t.id == principal_slug;
    TenantRow {
        is_principal_home,
        created_at_abs: format_ts_abs(t.created_at),
        updated_at_abs: format_ts_abs(t.updated_at),
        update_rel: format!("/tenants/{}/update", t.id),
        delete_rel: format!("/tenants/{}/delete", t.id),
        id: t.id,
        display_name: t.display_name,
        status: t.status,
    }
}
