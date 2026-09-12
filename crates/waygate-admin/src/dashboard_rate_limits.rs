//! Rate-limits page — `/admin/t/{tenant}/rate_limits`.
//!
//! Operator view of the per-tenant `rate_limit_policies` registry
//! from `waygate_quota`, with full inline CRUD. Each row
//! carries: name, scope (`tenant` / `principal` /
//! `server` / `tool`), optional scope_value (the scope's anchor —
//! sub for `principal`, server slug for `server`, etc.), action
//! (`call` / `side_effecting_call` / `discovery`),
//! bucket_capacity, refill_per_second, created_at, updated_at.
//!
//! ## Inline actions
//!
//! Full CRUD: a create composer plus per-row edit and delete. Edit is
//! limited to `bucket_capacity` / `refill_per_second` — the
//! (scope, scope_value, action) tuple is the policy's identity, rotated
//! by delete-then-create. Each mutation is admin-gated + CSRF, PRG via
//! `?rl_error=`, and reuses the REST `*_policy_core` functions so the
//! HTML and JSON surfaces can't drift on validation or the uniqueness
//! conflict. All forms are admin-only by construction — the
//! insufficient-scope gate hides every byte of policy data, so a
//! non-admin never sees the forms either.
//!
//! ## What's NOT here (deferred)
//!
//! - **Small multiples on top-N throttled scopes**. The plan
//!   calls for compact sparkline-style visualizations of which
//!   scope_values are currently bucket-empty. Today the store
//!   exposes only the policy registry, not a top-N counters
//!   helper. Surfacing the bucket-pressure data needs a new
//!   `RateLimitPolicyStore::top_depleted(tenant, n)` (or
//!   similar) backed by `SELECT … FROM rate_limit_counters
//!   ORDER BY tokens_remaining / capacity ASC LIMIT n`.
//! - **Throttling event drill-down**. Linking through to the
//!   audit row that captured a `RateLimited` outcome lands once
//!   the Activity page exposes a per-row drawer.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant` — same posture every other
//! dashboard page takes today. Cross-tenant operator access
//! is out of scope for this page.
//!
//! ## Admin-scope gate
//!
//! Mirrors the REST surface's `require_admin` middleware
//! (`crates/waygate-admin/src/rate_limit_policies.rs`). A
//! dashboard session without `mcp:admin` (or a peer-asserted
//! principal) sees an insufficient-scope card; the store fetch
//! is skipped entirely so no policy data enters the rendered
//! HTML. Same admin-gate shape as other dashboard pages.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use uuid::Uuid;
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_quota::{QuotaAction, QuotaScope, RateLimitPolicy};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::rate_limit_policies::{
    create_policy_core, delete_policy_core, update_policy_core, CreatePolicyRequest,
};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_core::fmt::format_ts_abs;

#[derive(Template)]
#[template(path = "rate_limits.html")]
struct RateLimitsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the rate-limit policy store is unwired (dev
    /// mode / no DB / rate-limiting not enabled). Template
    /// renders the "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin` (or
    /// is a peer assertion). Template renders an "insufficient
    /// scope" card and SKIPS the store read.
    insufficient_scope: bool,
    /// Policies for the principal's tenant. The store returns
    /// the full set (typically <50 per tenant — these are
    /// operator-curated, not auto-generated). No truncation
    /// today; if a tenant ever crosses ~200 policies we'll add
    /// pagination as a follow-up.
    policies: Vec<PolicyRow>,
    /// Store-error fallback. When `list` fails, populate with a
    /// short operator message and render an error card. Single
    /// fetch → single banner, no per-section partial rendering
    /// (this surface only has one section).
    error: Option<String>,
    /// `Some(msg)` when a create / edit / delete submission failed,
    /// threaded back via the `?rl_error=` PRG query param and rendered
    /// above the table.
    rl_error: Option<String>,
}

impl RateLimitsPage {}

struct PolicyRow {
    id: Uuid,
    /// Relative URLs for the per-row edit / delete form actions; the
    /// template wraps each with `self.nav_url(...)`. Precomputed because
    /// askama can't `format!` the id into the path inline.
    update_rel: String,
    delete_rel: String,
    name: String,
    scope: &'static str,
    /// `None` for `scope=tenant` (tenant policies have no
    /// anchor — the policy applies to the whole tenant). Set
    /// for the other four scopes. Template renders an em-dash
    /// for the `None` case.
    scope_value: Option<String>,
    action: &'static str,
    inactive_reason: Option<&'static str>,
    bucket_capacity: i32,
    /// Pre-formatted "X.YY/sec" string so the template doesn't
    /// have to know the f64 precision rules.
    refill_label: String,
    /// Raw refill rate for the edit form's number input (f64 Display:
    /// `10.0` → "10", `2.5` → "2.5"). The display column uses
    /// `refill_label`; the input needs the unadorned value.
    refill_value: f64,
    created_at_abs: String,
    updated_at_abs: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/rate_limits", get(rate_limits_page))
        .route("/rate_limits/create", post(rl_create))
        .route("/rate_limits/{id}/update", post(rl_update))
        .route("/rate_limits/{id}/delete", post(rl_delete))
}

/// Query-string state for the rate-limits page — only the PRG error
/// channel for the create / edit / delete forms.
#[derive(Debug, Default, Deserialize)]
struct RlQuery {
    #[serde(default)]
    rl_error: Option<String>,
}

async fn rate_limits_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<RlQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.policy.rate_limit_policies.enabled();
    let (policies, error) = if insufficient_scope {
        // Skip the store read entirely — no policy data leaks
        // into the rendered HTML.
        (Vec::new(), None)
    } else {
        match state.policy.rate_limit_policies.get() {
            Some(store) => match store.list(&read_tenant).await {
                Ok(rows) => (rows.into_iter().map(policy_row).collect(), None),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        tenant = %read_tenant,
                        "rate_limits page: list failed",
                    );
                    (
                        Vec::new(),
                        Some(
                            "Failed to load rate-limit policies — see gateway logs for details."
                                .to_owned(),
                        ),
                    )
                }
            },
            None => (Vec::new(), None),
        }
    };

    let page = RateLimitsPage {
        chrome: PageChrome::build(
            &state,
            "Rate limits",
            "/rate_limits",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        policies,
        error,
        rl_error: q.rl_error,
    };
    render(&page)
}

// ---- inline create / edit / delete -----------------------------------------

/// Form body for the inline "New policy" composer.
#[derive(Debug, Deserialize)]
struct RlCreateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    scope_value: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    bucket_capacity: String,
    #[serde(default)]
    refill_per_second: String,
}

/// Form body for the per-row edit — only capacity + refill are mutable
/// (the (scope, scope_value, action) tuple is the policy's identity).
/// An empty field means "leave unchanged" (PATCH semantics).
#[derive(Debug, Deserialize)]
struct RlUpdateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    bucket_capacity: String,
    #[serde(default)]
    refill_per_second: String,
}

/// Form body for the per-row delete — only the CSRF token.
#[derive(Debug, Deserialize)]
struct RlDeleteForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /rate_limits/create` — admin-gated + CSRF, parses the form
/// into a [`CreatePolicyRequest`] and reuses [`create_policy_core`]
/// (validate → create → fail-closed audit). PRG via `?rl_error=`.
async fn rl_create(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<RlCreateForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Some(scope) = parse_scope(form.scope.trim()) else {
        return redirect_with_error(tenant_ctx, "Pick a valid scope.");
    };
    let Some(action) = parse_action(form.action.trim()) else {
        return redirect_with_error(tenant_ctx, "Pick a valid action.");
    };
    let Ok(bucket_capacity) = form.bucket_capacity.trim().parse::<i32>() else {
        return redirect_with_error(tenant_ctx, "Capacity must be a whole number.");
    };
    let Ok(refill_per_second) = form.refill_per_second.trim().parse::<f64>() else {
        return redirect_with_error(tenant_ctx, "Refill must be a number.");
    };
    let sv = form.scope_value.trim();
    let scope_value = if sv.is_empty() {
        None
    } else {
        Some(sv.to_owned())
    };
    let req = CreatePolicyRequest {
        name: form.name.trim().to_owned(),
        scope,
        scope_value,
        bucket_capacity,
        refill_per_second,
        action,
    };
    match create_policy_core(&state, tenant, principal, &req).await {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &rl_err_message(&e, "create")),
    }
}

/// `POST /rate_limits/{id}/update` — admin-gated + CSRF, reuses
/// [`update_policy_core`]. Empty capacity/refill ⇒ leave unchanged.
async fn rl_update(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RlUpdateForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read `id` by name from the path captures: this handler is mounted
    // BOTH at `/rate_limits/{id}/update` (1 capture) and, via the
    // `/t/{tenant}` nest, at `/t/{tenant}/rate_limits/{id}/update` (2
    // captures). A `Path<String>` extractor expects exactly one param
    // and 500s on the tenant-scoped mount. A by-name map
    // works on both. (axum 0.8 nesting surfaces all parent+child
    // captures to the inner handler.)
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing policy id.");
    };
    let bucket_capacity = match form.bucket_capacity.trim() {
        "" => None,
        s => match s.parse::<i32>() {
            Ok(c) => Some(c),
            Err(_) => return redirect_with_error(tenant_ctx, "Capacity must be a whole number."),
        },
    };
    let refill_per_second = match form.refill_per_second.trim() {
        "" => None,
        s => match s.parse::<f64>() {
            Ok(r) => Some(r),
            Err(_) => return redirect_with_error(tenant_ctx, "Refill must be a number."),
        },
    };
    match update_policy_core(
        &state,
        tenant,
        principal,
        id.trim(),
        bucket_capacity,
        refill_per_second,
    )
    .await
    {
        Ok(Some(_)) => redirect_ok(tenant_ctx),
        Ok(None) => redirect_with_error(tenant_ctx, "That policy no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &rl_err_message(&e, "update")),
    }
}

/// `POST /rate_limits/{id}/delete` — admin-gated + CSRF, reuses
/// [`delete_policy_core`].
async fn rl_delete(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RlDeleteForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // By-name `id` — same dual-mount reason as `rl_update` above.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing policy id.");
    };
    match delete_policy_core(&state, tenant, principal, id.trim()).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(tenant_ctx, "That policy no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &rl_err_message(&e, "delete")),
    }
}

/// Shared admin-gate + CSRF for the rate-limit mutation handlers. Uses
/// the page's stricter [`principal_has_dashboard_admin`] (refuses
/// peer-asserted principals). Returns `(principal, tenant_ctx, tenant)`
/// — `tenant` is the principal's tenant (per-tenant scoping, same as
/// the REST surface) — or the boxed error `Response`.
#[allow(clippy::type_complexity)]
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<Extension<TenantContext>>,
    form_csrf: &str,
) -> Result<(&'a Principal, Option<TenantContext>, &'a str), Box<Response>> {
    let principal_opt = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(principal_opt) {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "Rate-limit changes require mcp:admin",
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
            (StatusCode::FORBIDDEN, "csrf mismatch").into_response(),
        ));
    }
    // principal_has_dashboard_admin(None) is false, so principal is Some.
    let Some(principal) = principal_opt else {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "admin scope required").into_response(),
        ));
    };
    let tenant = principal.tenant.as_str();
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c), tenant))
}

fn redirect_ok(tenant_ctx: Option<TenantContext>) -> Response {
    Redirect::to(&tenant_ctx::nav_url(tenant_ctx.as_ref(), "/rate_limits")).into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?rl_error={}",
        tenant_ctx::nav_url(tenant_ctx.as_ref(), "/rate_limits"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Parse the scope `<select>` value. Matches [`quota_scope_str`] so the
/// option values round-trip through the same vocabulary the DB stores.
fn parse_scope(s: &str) -> Option<QuotaScope> {
    match s {
        "tenant" => Some(QuotaScope::Tenant),
        "principal" => Some(QuotaScope::Principal),
        "server" => Some(QuotaScope::Server),
        "tool" => Some(QuotaScope::Tool),
        _ => None,
    }
}

/// Parse the action `<select>` value. Matches [`quota_action_str`].
fn parse_action(s: &str) -> Option<QuotaAction> {
    match s {
        "call" => Some(QuotaAction::Call),
        "side_effecting_call" => Some(QuotaAction::SideEffectingCall),
        "discovery" => Some(QuotaAction::Discovery),
        _ => None,
    }
}

/// Operator-safe rate-limit mutation message, parameterized by verb.
/// The validation / conflict / not-found detail is safe to surface;
/// anything else collapses to a generic line pointing at the logs.
fn rl_err_message(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::NotFoundDyn(d)
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) | ApiError::NotFound(d) => (*d).to_owned(),
        _ => format!("Failed to {verb} rate-limit policy — see gateway logs for details."),
    }
}

/// Authorization gate for the rate-limits dashboard page.
/// Same shape as `dashboard_break_glass::principal_has_dashboard_admin`
/// — refuses peer assertions even when scopes appear to
/// match, matching the REST `require_admin` posture.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

fn policy_row(p: RateLimitPolicy) -> PolicyRow {
    PolicyRow {
        inactive_reason: p.inactive_reason(),
        update_rel: format!("/rate_limits/{}/update", p.id),
        delete_rel: format!("/rate_limits/{}/delete", p.id),
        id: p.id,
        name: p.name,
        scope: quota_scope_str(p.scope),
        scope_value: p.scope_value,
        action: quota_action_str(p.action),
        bucket_capacity: p.bucket_capacity,
        refill_label: format_refill(p.refill_per_second),
        refill_value: p.refill_per_second,
        created_at_abs: format_ts_abs(p.created_at),
        updated_at_abs: format_ts_abs(p.updated_at),
    }
}

/// Display string for a [`QuotaScope`]. Matches the DB CHECK
/// constraint literal; rename here without updating the DB
/// would lie to operators about what was stored.
fn quota_scope_str(s: QuotaScope) -> &'static str {
    match s {
        QuotaScope::Tenant => "tenant",
        QuotaScope::Principal => "principal",
        QuotaScope::Client => "client",
        QuotaScope::Server => "server",
        QuotaScope::Tool => "tool",
    }
}

fn quota_action_str(a: QuotaAction) -> &'static str {
    match a {
        QuotaAction::Call => "call",
        QuotaAction::SideEffectingCall => "side_effecting_call",
        QuotaAction::CostBearing => "cost_bearing",
        QuotaAction::Discovery => "discovery",
    }
}

/// Format `refill_per_second` for the operator. Rounds to 2
/// decimal places for typical values (10.00/sec), drops
/// trailing zeros on the fractional part for clean display
/// (1/sec instead of 1.00/sec), and falls back to scientific
/// notation only if the value is so small the rounded form
/// would render as `0.00/sec`.
fn format_refill(r: f64) -> String {
    if r >= 1.0 {
        // Whole-number-friendly: render `10/sec` not `10.00/sec`.
        if (r - r.round()).abs() < 1e-9 {
            format!("{}/sec", r.round() as i64)
        } else {
            format!("{r:.2}/sec")
        }
    } else if r >= 0.005 {
        format!("{r:.2}/sec")
    } else if r > 0.0 {
        // Avoid lying with "0.00/sec" for a sub-centisecond
        // refill — surface scientific notation instead.
        format!("{r:.2e}/sec")
    } else {
        // Zero / negative is invalid but the admin handler
        // rejects on POST. Defensive surface.
        "0/sec".to_owned()
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
    fn unsupported_policy_controls_are_not_accepted_by_forms() {
        assert!(parse_scope("client").is_none());
        assert!(parse_action("cost_bearing").is_none());
        assert_eq!(parse_scope("principal"), Some(QuotaScope::Principal));
        assert_eq!(
            parse_action("side_effecting_call"),
            Some(QuotaAction::SideEffectingCall)
        );
    }

    #[test]
    fn rate_limits_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn rate_limits_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn rate_limits_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn rate_limits_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn format_refill_renders_whole_numbers_without_trailing_zeros() {
        assert_eq!(format_refill(10.0), "10/sec");
        assert_eq!(format_refill(1.0), "1/sec");
    }

    #[test]
    fn format_refill_keeps_two_decimal_places_for_fractional_rates() {
        assert_eq!(format_refill(2.5), "2.50/sec");
        assert_eq!(format_refill(0.25), "0.25/sec");
    }

    #[test]
    fn format_refill_escapes_to_scientific_for_sub_centisecond_rates() {
        // A rate so slow the 2-decimal form would lie ("0.00/sec").
        let label = format_refill(0.0001);
        assert!(
            label.contains("e") || label.contains("E"),
            "expected scientific notation for tiny rate, got {label}",
        );
        assert_ne!(label, "0.00/sec", "must not silently round to 0");
    }

    #[test]
    fn quota_scope_strings_match_db_constraints() {
        // The DB CHECK constraint on rate_limit_policies.scope
        // pins these literals. A rename here without a
        // migration would lie to operators about what was
        // stored.
        assert_eq!(quota_scope_str(QuotaScope::Tenant), "tenant");
        assert_eq!(quota_scope_str(QuotaScope::Principal), "principal");
        assert_eq!(quota_scope_str(QuotaScope::Client), "client");
        assert_eq!(quota_scope_str(QuotaScope::Server), "server");
        assert_eq!(quota_scope_str(QuotaScope::Tool), "tool");
    }

    #[test]
    fn quota_action_strings_match_db_constraints() {
        assert_eq!(quota_action_str(QuotaAction::Call), "call");
        assert_eq!(
            quota_action_str(QuotaAction::SideEffectingCall),
            "side_effecting_call"
        );
        assert_eq!(quota_action_str(QuotaAction::CostBearing), "cost_bearing");
        assert_eq!(quota_action_str(QuotaAction::Discovery), "discovery");
    }
}
