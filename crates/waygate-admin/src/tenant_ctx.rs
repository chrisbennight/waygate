//! `/admin/t/{tenant}/...` URL-scoping foundation.
//!
//! Every NEW dashboard page lives under `/admin/t/{tenant}/...`,
//! and existing pages are mounted at BOTH the legacy un-prefixed paths
//! AND the tenant-prefixed paths (per-page URL migration deferred).
//! This module supplies the shared plumbing:
//!
//! 1. [`TenantContext`] — the view-model every page template gets,
//!    carrying the active tenant slug, the principal's home tenant,
//!    whether the operator is acting cross-tenant (drives the banner),
//!    and the list of tenants visible in the selector.
//! 2. [`tenant_scope_middleware`] — extracts `{tenant}` from the path,
//!    validates the slug (`TenantId::parse`), looks it up against
//!    `state.identity.tenants` when present, and inserts the [`TenantContext`]
//!    into request extensions. Single source of truth; page handlers
//!    just pull the context like they pull `Principal`.
//! 3. [`tenant_switch_get`] — `GET /admin/tenant-switch?tenant_slug=<slug>`
//!    server-side target for the sidebar selector form. Validates and
//!    303s to `/admin/t/<slug>/`. Lets the no-JS `<noscript>` fallback
//!    work without the form-action JS rewriter the early draft used.
//! 4. [`nav_url`] — the shared free function templates call via
//!    `{{ self.nav_url("/foo") }}` to compose `/admin/t/<slug>/foo`
//!    when the page carries a [`TenantContext`] or fall back to
//!    `/admin/foo` when it doesn't. Keeps legacy un-prefixed pages
//!    rendering legacy in-page URLs while tenant-prefixed pages keep
//!    every click inside the prefix.
//!
//! Legacy un-prefixed paths (`/admin/`, `/admin/servers`, …) are not
//! redirected away — they continue to render directly out of the same
//! handler set without the tenant context, so bookmarks and old docs
//! keep working. The post-login callback (`auth::callback_get`) is the
//! only place that nudges operators into the tenant-prefixed shape,
//! and only when no explicit `next=` was set.
//!
//! ## Validation policy
//!
//! - When `state.identity.tenants` is `Some` (Postgres pool present), the
//!   middleware *requires* the slug to exist in the registry. Unknown
//!   slug → 404 with a small HTML page so a typo doesn't silently fall
//!   back to a "looks correct" view. Existence-only check — the
//!   `status` field (active/suspended) is enforced by the upstream
//!   bearer middleware (`PgTenantEnricher`), so a suspended tenant's
//!   principal can't sign in at all and the dashboard layer doesn't
//!   need to re-check.
//! - When `state.identity.tenants` is `None` (dev mode, no DB), we accept any
//!   slug that passes [`TenantId::parse`]. Refusing here would lock
//!   dev paths out of the dashboard entirely.
//!
//! ## Cross-tenant detection
//!
//! `is_cross_tenant = url_tenant != principal.tenant`. Drives the
//! red banner in layout.html. There is *no* role check today
//! (gateway-admin vs tenant-admin role separation is not yet
//! implemented); the banner is purely a visibility cue. Per-page
//! handlers may still
//! refuse cross-tenant access where the underlying store enforces
//! `principal.tenant` (current behavior preserved).

use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use serde::Deserialize;
use waygate_core::html::escape as html_escape;
use waygate_core::TenantId;
use waygate_oidc::Principal;

use crate::state::AdminState;

/// Cap on tenants rendered in the sidebar selector. Operators with
/// 100+ tenants need a search box, not an infinite dropdown — the
/// Cmd-K palette is the real navigation primitive for that scale.
/// Until then, truncate and surface a "showing N of M" footer so
/// operators know to use the palette.
const SELECTOR_TENANT_CAP: usize = 50;

/// View-model handed to every page template via `Extension<TenantContext>`.
///
/// `available_tenants` is empty when `state.identity.tenants` is `None` (dev
/// mode) — the selector renders a static current-tenant chip in that
/// case.
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Tenant slug from the URL `{tenant}` segment.
    pub slug: String,
    /// Human-friendly name from the `tenants` registry
    /// (`display_name` column). `None` *only* when no registry is
    /// wired (dev mode, `state.identity.tenants is None`) — the template
    /// falls back to the slug for display. When the registry IS
    /// wired the middleware 404s any slug it can't find, so this
    /// field is always `Some` on a request that reaches a page
    /// handler. There is no DEFAULT-tenant bypass.
    pub display_name: Option<String>,
    /// `true` when the URL tenant differs from `principal.tenant`.
    /// Drives the cross-tenant red banner in layout.html.
    pub is_cross_tenant: bool,
    /// Principal's "home" tenant — what we redirect to from legacy
    /// un-prefixed paths and what the selector treats as the
    /// principal-default option.
    pub principal_tenant: String,
    /// Options for the sidebar selector (capped at
    /// [`SELECTOR_TENANT_CAP`]). Sorted by slug for stable rendering.
    pub available_tenants: Vec<TenantOption>,
    /// `true` when the on-disk registry holds more tenants than
    /// [`SELECTOR_TENANT_CAP`]; the selector shows a "use palette
    /// to search" hint in that case.
    pub more_tenants_available: bool,
}

impl TenantContext {
    /// Prefix every internal path with `/admin/t/<slug>`. Use this
    /// in handlers that build URLs (auth redirects, hx-* targets
    /// constructed Rust-side). Templates have the slug as a field
    /// and concat directly.
    pub fn url(&self, path: &str) -> String {
        debug_assert!(
            path.starts_with('/'),
            "TenantContext::url paths must be rooted (`/foo`); got `{path}`",
        );
        format!("/admin/t/{}{}", self.slug, path)
    }
}

/// Single row in the sidebar tenant selector.
#[derive(Debug, Clone)]
pub struct TenantOption {
    pub slug: String,
    pub display_name: String,
    /// `true` when this option matches the current URL `{tenant}`.
    /// Templates render it as `aria-current="page"` / highlighted.
    pub active: bool,
}

/// Path-extraction shape for the `{tenant}` axum capture. Wrapped
/// in a typed struct so the `Deserialize` impl rejects empty / wrong
/// shapes at the boundary.
#[derive(Debug, Deserialize)]
pub struct TenantPathParam {
    pub tenant: String,
}

/// Middleware applied to the `/t/{tenant}` sub-tree of the dashboard
/// router. Extracts and validates the slug, optionally looks it up in
/// the registry, builds the selector option list, and injects
/// [`TenantContext`] into request extensions.
pub async fn tenant_scope_middleware(
    State(state): State<Arc<AdminState>>,
    Path(params): Path<TenantPathParam>,
    user: Option<Extension<Principal>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Stage 1: shape check. `TenantId::parse` enforces the
    // lowercase-alphanumeric + dash/underscore + length rules
    // shared with the storage layer; refusing malformed slugs
    // here keeps stack traces out of `tenants` SQL lookups.
    if TenantId::parse(&params.tenant).is_err() {
        return tenant_404("Tenant slug is not a valid identifier.");
    }

    // Stage 2: registry lookup when a registry is wired. Dev paths
    // without a Postgres pool fall through to the "accept any
    // shape-valid slug" branch so the dashboard still loads.
    let display_name = match state.identity.tenants.get() {
        Some(store) => match store.get(&params.tenant).await {
            Ok(Some(t)) => Some(t.display_name),
            Ok(None) => {
                return tenant_404(&format!(
                    "Tenant `{}` does not exist.",
                    html_escape(&params.tenant),
                ));
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant = %params.tenant,
                    "tenant_scope: registry lookup failed",
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    "<p>Tenant registry lookup failed.</p>",
                )
                    .into_response();
            }
        },
        None => None,
    };

    // Stage 3: principal "home" tenant + cross-tenant flag.
    let principal_tenant = user
        .as_ref()
        .map(|Extension(p)| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| TenantId::DEFAULT.to_owned());
    let is_cross_tenant = principal_tenant != params.tenant;

    // Stage 4: build the selector option list. Empty when no
    // registry; otherwise pull every tenant the principal is
    // entitled to see (today: every tenant — gateway-admin role
    // separation is not yet implemented).
    let (available_tenants, more_tenants_available) =
        load_selector_options(&state, &params.tenant).await;

    let ctx = TenantContext {
        slug: params.tenant.clone(),
        display_name,
        is_cross_tenant,
        principal_tenant,
        available_tenants,
        more_tenants_available,
    };
    req.extensions_mut().insert(ctx);
    next.run(req).await
}

/// Pull the tenant list for the sidebar selector, capped at
/// [`SELECTOR_TENANT_CAP`]. Returns `(options, more_available)`
/// where `more_available = true` when the registry held more rows
/// than the cap.
///
/// **Active-tenant invariant**: the returned list is guaranteed to
/// contain a `TenantOption` with
/// `active = true` whenever the active slug exists in the registry,
/// even if it sorts past the cap. The cap is enforced by displacing
/// the LAST row of the first-N slice rather than by silently
/// dropping the active row. Without this, an operator viewing
/// `/admin/t/zebra/` against a registry of 60 alphabetised tenants
/// would see a dropdown of the first 50 with no option `selected`,
/// and the browser would render whatever the first option happened
/// to be — contradicting the "active tenant always visible" goal
/// stated in the PR body.
async fn load_selector_options(
    state: &Arc<AdminState>,
    active_slug: &str,
) -> (Vec<TenantOption>, bool) {
    let Some(store) = state.identity.tenants.get() else {
        return (Vec::new(), false);
    };
    match store.list().await {
        Ok(rows) => {
            let total = rows.len();
            let more = total > SELECTOR_TENANT_CAP;

            // Split the registry into the first-N visible slice and
            // the "active row from the tail" — if the active tenant
            // sorts past the cap, displace the last of the visible
            // slice so the active option is always present.
            let active_row = rows.iter().find(|t| t.id == active_slug).cloned();
            let visible_contains_active = rows
                .iter()
                .take(SELECTOR_TENANT_CAP)
                .any(|t| t.id == active_slug);

            let mut options: Vec<TenantOption> = rows
                .into_iter()
                .take(SELECTOR_TENANT_CAP)
                .map(|t| TenantOption {
                    active: t.id == active_slug,
                    slug: t.id,
                    display_name: t.display_name,
                })
                .collect();

            if !visible_contains_active {
                if let Some(row) = active_row {
                    // Displace the last visible row so the cap is
                    // preserved. Sort order shifts slightly but the
                    // active-visibility invariant takes priority.
                    if options.len() >= SELECTOR_TENANT_CAP {
                        options.pop();
                    }
                    options.push(TenantOption {
                        active: true,
                        slug: row.id,
                        display_name: row.display_name,
                    });
                }
                // If the active slug ISN'T in the registry at all,
                // the middleware will already have 404ed (since
                // `state.identity.tenants.get(slug)` returned None upstream
                // of this call). No fallback needed here — this
                // branch is unreachable on a valid request.
            }

            (options, more)
        }
        Err(e) => {
            // Degrade open — the selector hides itself when the
            // list is empty rather than blocking the page render.
            tracing::error!(error = %e, "tenant_scope: selector list failed");
            (Vec::new(), false)
        }
    }
}

/// Resolve the "home" tenant slug for a principal. Falls back to
/// [`TenantId::DEFAULT`] when no principal is in scope (Disabled
/// dashboard auth + no enricher).
pub fn home_tenant_for(principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| TenantId::DEFAULT.to_owned())
}

/// Build the canonical `/admin/t/<tenant>/` URL the dashboard nav
/// + auth callback both redirect to.
pub fn home_url(tenant: &str) -> String {
    format!("/admin/t/{tenant}/")
}

/// Prefix a rooted dashboard path with `/admin/t/<slug>` when a
/// [`TenantContext`] is in scope, else with the legacy `/admin`
/// prefix. Templates call this via `{{ self.nav_url("/activity") }}`
/// to keep in-page links (overview tiles, "See all activity →",
/// htmx hx-get/hx-post targets, step-up `next=` redirects) inside
/// the active tenant scope.
///
/// **Why a free function**: every layout-extending page template
/// would otherwise need its own `nav_url` method. Templates can call
/// this via a tiny instance-method delegate (`fn nav_url(&self,
/// path: &str) -> String { tenant_ctx::nav_url(self.tenant_ctx.
/// as_ref(), path) }`) which is grep'able and consistent.
///
/// In-page targets fall back to the legacy (un-prefixed) path when no
/// [`TenantContext`] is present, so pages rendered without tenant
/// scoping keep every click inside the legacy URL space.
pub fn nav_url(ctx: Option<&TenantContext>, path: &str) -> String {
    debug_assert!(
        path.starts_with('/'),
        "nav_url paths must be rooted (`/foo`); got `{path}`",
    );
    match ctx {
        Some(c) => c.url(path),
        None => format!("/admin{path}"),
    }
}

/// Query shape for [`tenant_switch_get`]. Single field so the
/// sidebar selector form can post it via a plain `<select name="tenant_slug">`
/// without an inline JS rewriter.
#[derive(Debug, Deserialize)]
pub struct TenantSwitchQuery {
    pub tenant_slug: String,
}

/// `GET /admin/tenant-switch?tenant_slug=<slug>` — server-side tenant
/// switch target.
///
/// Gives the no-JS `<noscript>` sidebar selector fallback the same
/// behaviour as an inline-JS form-action rewrite would — validate,
/// then 303 to the canonical tenant home — without relying on a
/// placeholder route. Templates point the form action at this
/// endpoint directly.
///
/// Validation: the slug must parse as a [`TenantId`] (shape rules
/// shared with the rest of the storage layer). Malformed slug ⇒
/// 303 back to `/admin/` so the session middleware can re-route to
/// the principal's home tenant; we don't render a 4xx here because
/// the operator interacted with a dropdown they didn't author.
/// Registry membership is re-checked by [`tenant_scope_middleware`]
/// on the very next request, so a slug that's well-formed but
/// unknown will still 404 there — defence in depth without a
/// double round-trip on the common case.
pub async fn tenant_switch_get(Query(q): Query<TenantSwitchQuery>) -> Response {
    match TenantId::parse(&q.tenant_slug) {
        Ok(_) => Redirect::to(&home_url(&q.tenant_slug)).into_response(),
        Err(_) => Redirect::to("/admin/").into_response(),
    }
}

/// 404 page rendered when the tenant slug is malformed or unknown.
/// Plain HTML (no askama template) so this works even when the
/// dashboard render path is partially broken.
fn tenant_404(detail: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Tenant not found</title>\
         <style>body{{font-family:system-ui;max-width:40em;margin:4em auto;padding:0 1em;color:#333}}h1{{color:#a00}}</style>\
         <h1>Tenant not found</h1><p>{detail}</p>\
         <p><a href=\"/admin/\">Back to admin home</a></p>",
    );
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_prefixes_rooted_paths() {
        let ctx = TenantContext {
            slug: "acme".into(),
            display_name: Some("Acme".into()),
            is_cross_tenant: false,
            principal_tenant: "acme".into(),
            available_tenants: vec![],
            more_tenants_available: false,
        };
        assert_eq!(ctx.url("/"), "/admin/t/acme/");
        assert_eq!(ctx.url("/servers"), "/admin/t/acme/servers");
        assert_eq!(
            ctx.url("/activity/rows?after_id=abc"),
            "/admin/t/acme/activity/rows?after_id=abc",
        );
    }

    #[test]
    #[should_panic(expected = "TenantContext::url paths must be rooted")]
    fn url_panics_on_unrooted_path() {
        let ctx = TenantContext {
            slug: "acme".into(),
            display_name: None,
            is_cross_tenant: false,
            principal_tenant: "acme".into(),
            available_tenants: vec![],
            more_tenants_available: false,
        };
        let _ = ctx.url("servers"); // missing leading `/`
    }

    #[test]
    fn home_url_uses_canonical_prefix() {
        assert_eq!(home_url("default"), "/admin/t/default/");
        assert_eq!(home_url("acme"), "/admin/t/acme/");
    }

    #[test]
    fn home_tenant_for_falls_back_to_default() {
        assert_eq!(home_tenant_for(None), TenantId::DEFAULT);
    }

    #[test]
    fn html_escape_neutralizes_attack_payload() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        );
    }

    // Regression: the selector list always contains the active option,
    // even when the registry has more
    // tenants than [`SELECTOR_TENANT_CAP`] AND the active slug sorts
    // past the cap. Without this, the browser falls back to rendering
    // the first option as visually selected — a different tenant than
    // the one the operator is actually viewing.
    //
    // We test the displacement directly rather than wiring a fake
    // store: the loader is purely synchronous over a `Vec<Tenant>`
    // after the `store.list()` await, so the invariant is testable as
    // a pure transformation. A future refactor that introduced state
    // into the displacement path would need to switch this to a
    // tokio-test with a fake store — fine.
    use time::OffsetDateTime;
    use waygate_tenants::Tenant;

    fn make_tenant(id: &str) -> Tenant {
        Tenant {
            id: id.to_owned(),
            display_name: id.to_owned(),
            status: "active".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    /// Mirror of the displacement logic inside `load_selector_options`
    /// so the invariant can be tested without standing up a fake store.
    /// If this drifts from the real implementation, the active-tenant
    /// regression above returns silently — keep the two in lock-step.
    fn build_options(rows: Vec<Tenant>, active_slug: &str) -> (Vec<TenantOption>, bool) {
        let total = rows.len();
        let more = total > SELECTOR_TENANT_CAP;
        let active_row = rows.iter().find(|t| t.id == active_slug).cloned();
        let visible_contains_active = rows
            .iter()
            .take(SELECTOR_TENANT_CAP)
            .any(|t| t.id == active_slug);
        let mut options: Vec<TenantOption> = rows
            .into_iter()
            .take(SELECTOR_TENANT_CAP)
            .map(|t| TenantOption {
                active: t.id == active_slug,
                slug: t.id,
                display_name: t.display_name,
            })
            .collect();
        if !visible_contains_active {
            if let Some(row) = active_row {
                if options.len() >= SELECTOR_TENANT_CAP {
                    options.pop();
                }
                options.push(TenantOption {
                    active: true,
                    slug: row.id,
                    display_name: row.display_name,
                });
            }
        }
        (options, more)
    }

    #[test]
    fn selector_displaces_to_keep_active_visible() {
        // 60 alphabetised tenants: t000 .. t059. Active = t055
        // sorts past the cap (50). Without displacement, the
        // selector would not contain t055 and the dropdown would
        // render t000 as visually selected by browser default.
        let rows: Vec<Tenant> = (0..60).map(|i| make_tenant(&format!("t{i:03}"))).collect();
        let (options, more) = build_options(rows, "t055");
        assert_eq!(options.len(), SELECTOR_TENANT_CAP);
        assert!(more, "more_available must signal truncation");
        assert!(
            options.iter().any(|o| o.active && o.slug == "t055"),
            "active tenant t055 must be in the selector despite sorting past the cap",
        );
        // Exactly one option should be marked active.
        let active_count = options.iter().filter(|o| o.active).count();
        assert_eq!(
            active_count, 1,
            "exactly one option should be marked active; got {active_count}",
        );
    }

    #[test]
    fn selector_keeps_active_when_already_visible() {
        // Active sorts within the first N — no displacement needed.
        let rows: Vec<Tenant> = (0..60).map(|i| make_tenant(&format!("t{i:03}"))).collect();
        let (options, more) = build_options(rows, "t012");
        assert_eq!(options.len(), SELECTOR_TENANT_CAP);
        assert!(more);
        assert!(options.iter().any(|o| o.active && o.slug == "t012"));
        // The last visible row (t049) should still be there — no
        // displacement when active is already in the slice.
        assert!(options.iter().any(|o| o.slug == "t049"));
    }

    #[test]
    fn selector_no_truncation_below_cap() {
        // 10 tenants → all visible, no `more_available` flag.
        let rows: Vec<Tenant> = (0..10).map(|i| make_tenant(&format!("t{i}"))).collect();
        let (options, more) = build_options(rows, "t5");
        assert_eq!(options.len(), 10);
        assert!(!more);
        assert!(options.iter().any(|o| o.active && o.slug == "t5"));
    }

    // tenant_switch_get's server-side fallback.
    //
    // Unit-test the validation branch directly: malformed slugs
    // 303 to `/admin/`, well-formed slugs 303 to the canonical
    // tenant home. The full route-level smoke is in
    // tests/dashboard_render/ (chrome.rs).

    #[tokio::test]
    async fn tenant_switch_redirects_valid_slug_to_home_url() {
        let resp = tenant_switch_get(Query(TenantSwitchQuery {
            tenant_slug: "acme".into(),
        }))
        .await;
        let status = resp.status();
        let location = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        assert!(status.is_redirection(), "expected 3xx, got {status}");
        assert_eq!(location, "/admin/t/acme/");
    }

    #[tokio::test]
    async fn tenant_switch_redirects_malformed_slug_to_admin_root() {
        let resp = tenant_switch_get(Query(TenantSwitchQuery {
            tenant_slug: "Has Spaces".into(),
        }))
        .await;
        let status = resp.status();
        let location = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        assert!(status.is_redirection(), "expected 3xx, got {status}");
        assert_eq!(
            location, "/admin/",
            "malformed slug must bounce to admin root, not to a constructed \
             tenant-home URL that would 404",
        );
    }
}
