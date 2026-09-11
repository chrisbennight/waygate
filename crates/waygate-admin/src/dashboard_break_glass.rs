//! Break-glass page — `/admin/t/{tenant}/break_glass`.
//!
//! Read-only listing of break-glass override tokens
//! from the `break_glass_tokens` table. Three lifecycle sections,
//! each fetched with a precise [`BreakGlassLifecycle`] predicate so
//! the store's per-call row cap applies WITHIN the bucket rather
//! than across the unfiltered created_at window — an unfiltered
//! single fetch would silently drop old active tokens on a
//! high-churn tenant once newer expired/used rows filled the cap.
//!
//! 1. **Active** — `used_at IS NULL AND expires_at > now()`. The
//!    operator's "what's currently overriding the policy gate"
//!    surface. Red chip on every row.
//! 2. **Expired** — `used_at IS NULL AND expires_at <= now()`.
//!    Tokens that timed out before they were used. Useful for
//!    spotting "this incident never fired the override" patterns.
//! 3. **Recently used** — `used_at IS NOT NULL`, capped at
//!    [`HISTORY_LIMIT`]. The terminal-state list — break-glass is
//!    single-use, so `used_at` is set exactly once per token by
//!    `BreakGlassStore::try_claim`.
//!
//! ## Inline CRUD
//!
//! - **Mint form** — an admin-gated, CSRF-protected composer below the
//!   tables that reuses the REST path's [`mint_token_core`] (validate →
//!   `store.mint` → loud warn → fail-closed audit), so the HTML and JSON
//!   surfaces can't drift. `requires_amr` is intentionally omitted (the
//!   validator refuses non-empty values until Principal carries `amr`).
//! - **Per-row revoke** — Active / Expired rows carry a CSRF-protected
//!   Revoke button reusing [`revoke_token_core`] (hard delete → audit).
//!   Both forms PRG-redirect with a `?bg_error=` channel; both gate on
//!   the stricter [`principal_has_dashboard_admin`] (peer-asserted
//!   principals refused) — REST remains available in parallel.
//!
//! ## What's NOT here (deferred)
//!
//! - **Token-use trace.** Today the page shows `used_at` only.
//!   Linking through to the audit row that captured the override
//!   ceremony is not yet implemented — the audit row's
//!   `break_glass_token_id` reference would land here once the
//!   Activity page exposes a per-row drawer.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant` — same posture every other
//! dashboard page takes today. Cross-tenant operator access is
//! not supported.
//!
//! ## Admin-scope gate
//!
//! Mirrors the REST surface's `require_admin` middleware
//! (`crates/waygate-admin/src/break_glass.rs:53`). A dashboard
//! session without `mcp:admin` (or a peer-asserted principal)
//! sees an insufficient-scope card; the store fetch is skipped
//! entirely so no token data enters the rendered HTML. Same
//! shape the approvals page enforces.
//!
//! ## Overview banner
//!
//! When any active tokens exist, the Overview page renders a red
//! "active break-glass tokens" banner linking here. See
//! `dashboard::overview` + `OverviewPage.active_break_glass`.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use uuid::Uuid;
use waygate_authz::{BreakGlassLifecycle, BreakGlassToken, SharedBreakGlassStore};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::auth::CsrfToken;
use crate::break_glass::{mint_token_core, revoke_token_core, MintRequest};
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// Cap on rendered recently-used rows. Break-glass is single-use;
/// the full historical list is in the catalog (pull via
/// `GET /api/v1/admin/break_glass?limit=...`). The dashboard slice
/// is just a glance — operators investigating a specific incident
/// pivot to the audit log, not this page.
const HISTORY_LIMIT: usize = 50;

/// Per-fetch row cap for the dashboard's lifecycle bucketing.
/// Single fetch + client-side partition (no per-bucket query) is
/// safe here because break-glass tokens are rare by design — a
/// tenant with >200 tokens in any one state is in an incident
/// already and should be looking at the audit log, not this page.
/// Stays well below `waygate_authz::MAX_LIST_LIMIT = 500`.
const FETCH_LIMIT: u32 = 200;

#[derive(Template)]
#[template(path = "break_glass.html")]
struct BreakGlassPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the break-glass store is unwired (dev mode /
    /// no DB / break-glass feature disabled). Template renders
    /// the "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin` (or
    /// is a peer assertion). Template renders an "insufficient
    /// scope" card and SKIPS the store read so no token data
    /// enters the rendered HTML. Mirrors the
    /// `crates/waygate-admin/src/break_glass.rs::router`
    /// `require_admin` layer.
    insufficient_scope: bool,
    /// `used_at IS NULL AND expires_at > now()` — overrides
    /// currently bypassing the policy gate. Operators triage
    /// from this section first.
    active: Vec<TokenRow>,
    /// `used_at IS NULL AND expires_at <= now()` — tokens that
    /// timed out unused. Useful for the "we minted the override
    /// but the incident resolved without it" case.
    expired: Vec<TokenRow>,
    /// `used_at IS NOT NULL` — terminal-state rows. Capped at
    /// [`HISTORY_LIMIT`]. Older rows live in the REST surface
    /// (`GET /api/v1/admin/break_glass?limit=...`) and the
    /// AdminMutation audit category.
    recent_used: Vec<TokenRow>,
    /// `true` when the recent_used slice was capped (more rows
    /// exist past the limit). Template nudges toward the REST
    /// surface for the full history.
    recent_used_truncated: bool,
    /// `true` when the Expired bucket's `list` call failed.
    /// Template renders a per-section "failed to load" card
    /// instead of the "no expired" empty state — same posture
    /// as the approvals page.
    expired_load_error: bool,
    /// Same as [`Self::expired_load_error`] but for the
    /// Recently-used bucket.
    recent_used_load_error: bool,
    /// Page-level error banner — set only when the Active
    /// bucket fetch failed (that's the load-bearing
    /// "currently overriding the gate" section; silently
    /// emptying it during an incident is worse than a banner).
    /// Expired / Used failures live in the per-bucket flags
    /// above and don't wipe the page.
    error: Option<String>,
    /// `Some(msg)` when a mint / revoke submission failed, threaded
    /// back via the `?bg_error=` PRG query param and rendered beside
    /// the mint form.
    bg_error: Option<String>,
}

impl BreakGlassPage {}

struct TokenRow {
    id: Uuid,
    issued_to: String,
    issued_by: String,
    reason: String,
    scope_pattern: String,
    /// Relative URL for the per-row revoke form `action`; the template
    /// wraps it with `self.nav_url(...)`. Precomputed because askama
    /// can't `format!` the id into the path inline.
    revoke_rel: String,
    /// Required AMR values; empty for tokens minted before AMR
    /// enforcement was hooked up. Rendered as a comma-joined
    /// list so the operator can confirm the runtime gate.
    requires_amr: Vec<String>,
    created_at_abs: String,
    expires_at_abs: String,
    /// Set only on the recent_used bucket. `None` on Active /
    /// Expired (the template branches per section).
    used_at_abs: Option<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/break_glass", get(break_glass_page))
        .route("/break_glass/mint", post(mint))
        .route("/break_glass/{token_id}/revoke", post(revoke))
}

/// `?bg_error=` PRG channel — a mint / revoke failure is carried back
/// here and rendered beside the mint form.
#[derive(serde::Deserialize)]
struct BreakGlassQuery {
    #[serde(default)]
    bg_error: Option<String>,
}

async fn break_glass_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<BreakGlassQuery>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    // Mirror the REST gate (crates/waygate-admin/src/break_glass.rs
    // wraps every route in `require_admin`). A non-admin SSO
    // dashboard session must not see active overrides — those are
    // an admin's emergency lever and the issued_to / reason fields
    // are sensitive (they name the principal and incident).
    let insufficient_scope = !principal_has_dashboard_admin(user_principal);

    let store_configured = state.policy.break_glass.enabled();
    let load = if insufficient_scope {
        // Skip the store read entirely — no token data leaks
        // into the rendered HTML.
        LoadResult::default()
    } else {
        match state.policy.break_glass.get() {
            Some(store) => load_tokens(store, &read_tenant).await,
            None => LoadResult::default(),
        }
    };

    let page = BreakGlassPage {
        chrome: PageChrome::build(
            &state,
            "Break-glass",
            "/break_glass",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        active: load.active,
        expired: load.expired,
        recent_used: load.recent_used,
        recent_used_truncated: load.recent_used_truncated,
        expired_load_error: load.expired_load_error,
        recent_used_load_error: load.recent_used_load_error,
        error: load.error,
        bg_error: q.bg_error,
    };
    render(&page)
}

// --- Mint / revoke forms (admin-gated + CSRF; reuse the REST cores) --------

/// Mint form body. `scope_pattern` / `ttl_seconds` are validated by the
/// shared `mint_token_core`; `ttl_seconds` is parsed here so a
/// non-numeric value yields a friendly error rather than a 422. AMR is
/// intentionally absent — the validator refuses a non-empty
/// `requires_amr` until Principal carries an `amr` field.
#[derive(serde::Deserialize)]
struct MintForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    issued_to: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    scope_pattern: String,
    #[serde(default)]
    ttl_seconds: String,
}

/// Revoke form body — only the CSRF token (token id is a path param).
#[derive(serde::Deserialize)]
struct RevokeForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /break_glass/mint` — admin-gated + CSRF, then reuses
/// [`mint_token_core`] (validate → store.mint → loud warn → fail-closed
/// audit) and PRG-redirects to the break-glass page. On error it
/// redirects with a `?bg_error=` message rendered beside the form.
async fn mint(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<MintForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let ttl_seconds = match form.ttl_seconds.trim().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            return redirect_with_error(
                tenant_ctx,
                "TTL (seconds) must be a whole number between 1 and 86400.",
            )
        }
    };
    let req = MintRequest {
        issued_to: form.issued_to.trim().to_owned(),
        reason: form.reason.trim().to_owned(),
        scope_pattern: form.scope_pattern.trim().to_owned(),
        requires_amr: Vec::new(),
        ttl_seconds,
    };
    match mint_token_core(&state, tenant, principal, &req).await {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &bg_err_message(&e, "mint")),
    }
}

/// `POST /break_glass/{token_id}/revoke` — admin-gated + CSRF, reuses
/// [`revoke_token_core`] (hard delete → loud warn → fail-closed audit).
/// Revoke is idempotent; an already-absent token still PRG-succeeds.
async fn revoke(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RevokeForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read `token_id` by name: mounted at both `/break_glass/{token_id}/revoke`
    // and the 2-capture `/t/{tenant}/...` nest; `Path<String>` 500s on the
    // latter, so parse it manually instead.
    let Some(token_id) = params.get("token_id") else {
        return redirect_with_error(tenant_ctx, "Missing token id.");
    };
    let Ok(uuid) = Uuid::parse_str(token_id.trim()) else {
        return redirect_with_error(tenant_ctx, "Invalid token id.");
    };
    match revoke_token_core(&state, tenant, principal, uuid).await {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &bg_err_message(&e, "revoke")),
    }
}

/// Shared admin-gate + CSRF check for the mint / revoke handlers. Uses
/// the page's stricter [`principal_has_dashboard_admin`] (refuses
/// peer-asserted principals) rather than the bare scope check —
/// break-glass mutation is an operator-only ceremony. Returns
/// `(principal, tenant_ctx, tenant)` or the boxed error `Response`.
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
            (StatusCode::FORBIDDEN, "break-glass requires mcp:admin").into_response(),
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
    let tenant = principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c), tenant))
}

fn redirect_ok(tenant_ctx: Option<TenantContext>) -> Response {
    Redirect::to(&crate::tenant_ctx::nav_url(
        tenant_ctx.as_ref(),
        "/break_glass",
    ))
    .into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?bg_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/break_glass"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Operator-safe message for a mint / revoke failure, parameterized by
/// verb. Validation detail (the scope-pattern / TTL / issued_to / AMR
/// rejections) is safe to surface; anything else collapses to a generic
/// line so implementation detail never reaches the browser.
pub(crate) fn bg_err_message(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::BadGateway(d)
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) => (*d).to_owned(),
        _ => format!("Failed to {verb} break-glass token — see gateway logs for details."),
    }
}

/// Authorization gate for the break-glass dashboard page. Returns
/// `true` only for an OAuth/API-key principal carrying the
/// `mcp:admin` scope. Peer-asserted principals are refused even
/// when scopes appear to match — same defense-in-depth posture as
/// [`crate::scope::require_admin_extension`] (federated peers are
/// never operators of this gateway, and a break-glass row is
/// strictly an operator artifact).
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

/// Lifecycle-bucketed page output. Three narrow store fetches
/// (one per lifecycle) so the FETCH_LIMIT cap applies WITHIN
/// each bucket — an active token older than FETCH_LIMIT newer
/// used/expired tokens still appears. Per-bucket failure flags
/// mirror the approvals page: a partial-load error renders
/// a section-specific message rather than masquerading as
/// empty.
#[derive(Default)]
struct LoadResult {
    active: Vec<TokenRow>,
    expired: Vec<TokenRow>,
    recent_used: Vec<TokenRow>,
    recent_used_truncated: bool,
    expired_load_error: bool,
    recent_used_load_error: bool,
    /// Page-level error banner — set only when the Active
    /// fetch failed (that's the "currently overriding the
    /// gate" surface — silently emptying it is the worst-case
    /// UX for an incident-response operator). Expired /
    /// Recently-used failures live in the per-bucket flags
    /// above and don't wipe the page.
    error: Option<String>,
}

async fn load_tokens(store: &SharedBreakGlassStore, tenant: &str) -> LoadResult {
    // A single fetch using `BreakGlassStore::list`'s bare
    // created_at-DESC + LIMIT 200 window would let an active
    // token older than 200 newer used/expired tokens get
    // silently dropped from BOTH the Active section AND the
    // overview banner. Each lifecycle bucket is instead fetched
    // with its own precise BreakGlassLifecycle predicate, so the
    // FETCH_LIMIT cap applies within the bucket rather than
    // across the unfiltered window (the same shape the
    // approvals page uses for its GrantFilter buckets).
    //
    // Per-call `now()`-race is bounded by the Rust-side dedupe
    // below.
    let active_rows = match list_bucket(store, tenant, BreakGlassLifecycle::Active).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                "break_glass page: active list failed",
            );
            return LoadResult {
                error: Some(
                    "Failed to load break-glass tokens — see gateway logs for details.".to_owned(),
                ),
                ..LoadResult::default()
            };
        }
    };
    let (expired_rows, expired_load_error) =
        match list_bucket(store, tenant, BreakGlassLifecycle::Expired).await {
            Ok(rows) => (rows, false),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant = %tenant,
                    "break_glass page: expired list failed",
                );
                (Vec::new(), true)
            }
        };
    let (used_rows, recent_used_load_error) =
        match list_bucket(store, tenant, BreakGlassLifecycle::Used).await {
            Ok(rows) => (rows, false),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant = %tenant,
                    "break_glass page: used list failed",
                );
                (Vec::new(), true)
            }
        };

    // Lifecycle transitions are monotonic (Active → {Expired
    // or Used}; Used is terminal); a row appearing in BOTH
    // Active and a later bucket means it transitioned between
    // queries. The LATER observation is authoritative, so
    // dedupe by evicting from earlier buckets. Same shape as
    // the approvals page's `dedupe_overlapping_lifecycles`.
    let mut active = active_rows;
    let mut expired = expired_rows;
    let used = used_rows;
    dedupe_overlapping_lifecycles(&mut active, &mut expired, &used);

    let recent_used_truncated = used.len() > HISTORY_LIMIT;
    let mut recent_used = used;
    if recent_used_truncated {
        recent_used.truncate(HISTORY_LIMIT);
    }

    LoadResult {
        active: active.into_iter().map(token_row).collect(),
        expired: expired.into_iter().map(token_row).collect(),
        recent_used: recent_used.into_iter().map(token_row).collect(),
        recent_used_truncated,
        expired_load_error,
        recent_used_load_error,
        error: None,
    }
}

/// Fetch a single lifecycle bucket. The store applies its
/// own 200-row cap per call WITHIN the lifecycle predicate —
/// an unfiltered list could otherwise push old active tokens
/// out of view once newer expired/used rows filled the cap.
async fn list_bucket(
    store: &SharedBreakGlassStore,
    tenant: &str,
    lifecycle: BreakGlassLifecycle,
) -> Result<Vec<BreakGlassToken>, waygate_authz::BreakGlassError> {
    store.list(tenant, Some(lifecycle), FETCH_LIMIT, 0).await
}

/// Active break-glass tokens for `tenant`, capped at [`FETCH_LIMIT`].
/// Exposed for the merged Decisions queue; the queue needs the
/// same "currently bypassing the policy gate" set this page's Active
/// section shows. `saturated` (caller-computed via `rows.len() >=
/// FETCH_LIMIT`) tells the queue to nudge toward this page for the rest.
pub(crate) async fn list_active(
    store: &SharedBreakGlassStore,
    tenant: &str,
) -> Result<Vec<BreakGlassToken>, waygate_authz::BreakGlassError> {
    list_bucket(store, tenant, BreakGlassLifecycle::Active).await
}

/// The break-glass active-list cap, exposed so the Decisions queue can
/// detect saturation with the same bound.
pub(crate) const ACTIVE_FETCH_LIMIT: u32 = FETCH_LIMIT;

/// Resolve overlap across the three lifecycle queries. An id
/// appearing in BOTH Active and Expired means the token
/// expired between the two store calls; an id in both Active
/// (or Expired) and Used means a parallel claim landed
/// in-window. Lifecycle is monotonic forward, so the LATER
/// observation wins and we evict the earlier-bucket row.
fn dedupe_overlapping_lifecycles(
    active: &mut Vec<BreakGlassToken>,
    expired: &mut Vec<BreakGlassToken>,
    used: &[BreakGlassToken],
) {
    use std::collections::HashSet;
    let used_ids: HashSet<Uuid> = used.iter().map(|t| t.id).collect();
    let later_than_active: HashSet<Uuid> = expired
        .iter()
        .map(|t| t.id)
        .chain(used_ids.iter().copied())
        .collect();
    active.retain(|t| !later_than_active.contains(&t.id));
    expired.retain(|t| !used_ids.contains(&t.id));
}

fn token_row(t: BreakGlassToken) -> TokenRow {
    TokenRow {
        id: t.id,
        issued_to: t.issued_to,
        issued_by: t.issued_by,
        reason: t.reason,
        scope_pattern: t.scope_pattern,
        revoke_rel: format!("/break_glass/{}/revoke", t.id),
        requires_amr: t.requires_amr,
        created_at_abs: format_ts_abs(t.created_at),
        expires_at_abs: format_ts_abs(t.expires_at),
        used_at_abs: t.used_at.map(format_ts_abs),
    }
}

/// Count active break-glass tokens for `tenant`. Used by the
/// Overview page's red banner. Returns `Some(count)` when the
/// fetch succeeded (0 when nothing is active); returns `None`
/// when the store is unwired OR the fetch failed (the banner
/// silently disappears in those cases — the dashboard's
/// disabled-state / partial-load cards on the `/break_glass`
/// page surface the real problem).
///
/// The fetch is capped at [`FETCH_LIMIT`]; a returned count of
/// `FETCH_LIMIT` is reported as-is and the banner copy reads
/// "{n}+" so an operator on a tenant with a runaway-mint
/// situation isn't lied to about the volume.
pub async fn count_active_for_banner(
    store: Option<&SharedBreakGlassStore>,
    tenant: &str,
) -> Option<usize> {
    // Uses the precise lifecycle predicate rather than fetching
    // the unfiltered created_at-DESC window and filtering
    // client-side, which would silently undercount on a tenant
    // with churn (a true-active token older than the limit's
    // worth of newer used/expired rows would not make it into
    // the result). The lifecycle=Active store predicate
    // guarantees the cap applies WITHIN active rows.
    let store = store?;
    let rows = store
        .list(tenant, Some(BreakGlassLifecycle::Active), FETCH_LIMIT, 0)
        .await
        .ok()?;
    Some(rows.len())
}

/// Returned by [`count_active_for_banner`] consumers to render
/// the truncation-aware banner copy. `saturated` is true when the
/// fetch saturated at [`FETCH_LIMIT`] — the count is a floor in
/// that case.
pub fn active_banner_label(count: usize) -> (usize, bool) {
    let saturated = count >= FETCH_LIMIT as usize;
    (count, saturated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

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
    fn break_glass_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn break_glass_admin_gate_allows_api_key_admin() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::ApiKey);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn break_glass_admin_gate_blocks_oauth_without_admin_scope() {
        // Default dashboard SSO scopes lack mcp:admin — a routine
        // sign-in must not see active override tokens.
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn break_glass_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        // Defense-in-depth: a federated peer is never an operator
        // of THIS gateway. Even if a future validator bug lets
        // mcp:admin slip through, this gate refuses on auth_method.
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn break_glass_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn active_banner_label_marks_saturation_at_fetch_limit() {
        let (n, sat) = active_banner_label(FETCH_LIMIT as usize);
        assert_eq!(n, FETCH_LIMIT as usize);
        assert!(sat, "exactly-limit fetch must be flagged saturated");
    }

    #[test]
    fn active_banner_label_does_not_lie_on_small_counts() {
        let (n, sat) = active_banner_label(3);
        assert_eq!(n, 3);
        assert!(!sat);
    }

    fn token(id_byte: u8, used_unix: Option<i64>, expires_offset_secs: i64) -> BreakGlassToken {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        BreakGlassToken {
            id: Uuid::from_bytes([id_byte; 16]),
            tenant_id: "default".into(),
            issued_to: "alice".into(),
            issued_by: "op".into(),
            reason: "incident".into(),
            scope_pattern: "example-messages.*".into(),
            requires_amr: vec![],
            expires_at: now + time::Duration::seconds(expires_offset_secs),
            used_at: used_unix.map(|u| OffsetDateTime::from_unix_timestamp(u).unwrap()),
            created_at: now,
        }
    }

    #[test]
    fn dedupe_strips_active_id_when_it_also_appears_in_expired() {
        // Token expired in the window between the Active and
        // Expired store calls. Expired observation wins.
        let mut active = vec![token(1, None, -10), token(2, None, 60)];
        let mut expired = vec![token(1, None, -10)];
        let used: Vec<BreakGlassToken> = vec![];
        dedupe_overlapping_lifecycles(&mut active, &mut expired, &used);
        assert_eq!(
            active.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![Uuid::from_bytes([2; 16])]
        );
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn dedupe_strips_active_and_expired_ids_when_used_arrives_later() {
        // Caller claimed the token in the window between
        // Active/Expired and Used. Used is terminal.
        let mut active = vec![token(1, None, 60)];
        let mut expired = vec![token(2, None, -10)];
        let used = vec![
            token(1, Some(1_700_000_001), 60),
            token(2, Some(1_700_000_002), -10),
        ];
        dedupe_overlapping_lifecycles(&mut active, &mut expired, &used);
        assert!(active.is_empty(), "used terminal must evict from active");
        assert!(expired.is_empty(), "used terminal must evict from expired");
    }

    #[test]
    fn dedupe_is_a_noop_when_buckets_are_already_disjoint() {
        let mut active = vec![token(1, None, 60)];
        let mut expired = vec![token(2, None, -10)];
        let used = vec![token(3, Some(1_700_000_001), 60)];
        dedupe_overlapping_lifecycles(&mut active, &mut expired, &used);
        assert_eq!(active.len(), 1);
        assert_eq!(expired.len(), 1);
    }
}
