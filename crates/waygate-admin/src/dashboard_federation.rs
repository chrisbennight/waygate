//! Federation page — `/admin/t/{tenant}/federation`.
//!
//! Surfaces federated-peer state to operators. Without
//! this page the federation runtime is opaque — peers are configured
//! via REST and the JWKS cache lives only in process memory, so an
//! operator triaging "Tier-C dispatch is failing for peer X" has to
//! reach for logs or curl the admin REST surface.
//!
//! ## Page layout (server-rendered)
//!
//! Two stacked sections, no tabs yet (sub-tabs land when the
//! federation surface earns the second-screen treatment):
//!
//! 1. **Peers** — list of `FederatedPeer` rows for the principal's
//!    tenant, capped at [`PEER_LIST_LIMIT`]. Per row: peer name,
//!    issuer, JWKS URL, trust tier chip (full / restricted), and a
//!    cache chip (warm + key count / cold / no cache). For admins
//!    (`mcp:admin`), each row carries an inline Edit form + a Delete
//!    button, and an "Add a federated peer" composer renders below
//!    the table. These reuse the REST `*_peer_core` functions
//!    ([`create_peer_core`] / [`update_peer_core`] / [`delete_peer_core`])
//!    so the HTML and JSON surfaces validate / audit / cache-invalidate
//!    identically. When the registry has no peers the empty state +
//!    open composer take the table's place. The forms are CSRF-protected
//!    and admin-gated server-side; non-admins see the read-only list.
//! 2. **JWKS cache** — short status panel: "cache wired" vs "cache
//!    not wired." Per-peer warm/cold + key count appears in the
//!    Peers table above (we read `PeerJwksCache::get_by_peer_id`
//!    rather than the impl-only generation counter so the page
//!    works against any `SharedPeerJwksCache`).
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant`, NOT `tenant_ctx.slug`. Cross-tenant
//! operator data access is out of scope for this page; the
//! tenant-prefix in the URL is visual scaffolding (URL + selector +
//! banner) and doesn't flip the read scope. A gateway-admin operator on
//! `/admin/t/acme/federation` sees their own tenant's peers and the
//! red cross-tenant banner naming acme — same posture every other
//! dashboard page takes today.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use uuid::Uuid;
use waygate_federation::{FederatedPeer, PeerFilter, SharedPeersStore, TrustTier};
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::federated_peers::{create_peer_core, delete_peer_core, update_peer_core};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// Peers list cap on the dashboard. Larger tenants page via the REST
/// surface; the dashboard summary stops at this many rows and adds a
/// "showing first N" hint when the registry has more.
const PEER_LIST_LIMIT: u32 = 200;

#[derive(Template)]
#[template(path = "federation.html")]
struct FederationPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the federated-peers store is unwired (no DB pool
    /// at boot). Template renders a "feature disabled" card.
    store_configured: bool,
    /// `true` when the in-memory JWKS cache is wired. When `false`
    /// the per-row Cache column shows "cache not configured" so an
    /// operator doesn't misread that as "cache cold."
    cache_configured: bool,
    /// Peers from `state.federation.federated_peers.list(tenant)`. Capped at
    /// [`PEER_LIST_LIMIT`].
    peers: Vec<PeerRow>,
    /// `true` when the registry held more rows than the cap. Template
    /// nudges toward the REST surface for the full list.
    truncated: bool,
    /// Store-error fallback — if `list()` returns an error, populate
    /// this with a short operator message and render an error card
    /// instead of an empty table.
    error: Option<String>,
    /// Caller has `mcp:admin`. The create / edit / delete forms render
    /// only for admins (the mutation handlers re-check server-side).
    is_admin: bool,
    /// `Some(msg)` when a create / edit / delete submission failed,
    /// threaded back via the `?fed_error=` PRG query param and rendered
    /// beside the forms.
    fed_error: Option<String>,
}

impl FederationPage {}

struct PeerRow {
    id: Uuid,
    peer_name: String,
    issuer: String,
    jwks_url: String,
    trust_tier: &'static str,
    /// Relative URLs for the per-row edit / delete form actions; the
    /// template wraps each with `self.nav_url(...)`. Precomputed
    /// because askama can't `format!` the id into the path inline.
    update_rel: String,
    delete_rel: String,
    /// "warm" when `cache.get_by_peer_id(peer)` returns Some (the
    /// refresher has populated this entry at least once), "cold"
    /// when the cache exists but has no entry, "unknown" when no
    /// cache is wired at all (dev mode / test fixtures).
    cache_state: &'static str,
    /// Number of keys in the cached `JwkSet`. 0 when cold/unknown.
    /// Surfaces "refresher fetched the JWKS endpoint but it was
    /// empty" as a distinct state from "no fetch yet."
    cache_key_count: usize,
    created_at_abs: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/federation", get(federation_page))
        .route("/federation/peers/create", post(create))
        .route("/federation/peers/{id}/update", post(update))
        .route("/federation/peers/{id}/delete", post(delete))
}

/// `?fed_error=` PRG channel — a create / edit / delete submission
/// failure is carried back here and rendered beside the forms.
#[derive(serde::Deserialize)]
struct FederationQuery {
    #[serde(default)]
    fed_error: Option<String>,
}

async fn federation_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<FederationQuery>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let is_admin = user_principal
        .map(|p| p.has_scope(waygate_oidc::Scope::McpAdmin.as_str()))
        .unwrap_or(false);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    // Read scope: principal.tenant (see module doc). Falls back to
    // the default tenant when no principal is in scope (Disabled
    // dashboard auth in dev paths).
    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let store_configured = state.federation.federated_peers.enabled();
    let cache_configured = state.federation.federated_peers_cache.is_some();

    let (peers, truncated, error) = match state.federation.federated_peers.get() {
        Some(store) => {
            load_peers(
                store,
                &read_tenant,
                state.federation.federated_peers_cache.as_ref(),
            )
            .await
        }
        None => (Vec::new(), false, None),
    };

    let page = FederationPage {
        chrome: PageChrome::build(
            &state,
            "Federation",
            "/federation",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        cache_configured,
        peers,
        truncated,
        error,
        is_admin,
        fed_error: q.fed_error,
    };
    render(&page)
}

// --- Mutating forms (admin-gated + CSRF; reuse the REST cores) -------------

/// Form body for create / edit. Every field is plain text; `trust_tier`
/// is parsed to the [`TrustTier`] enum in the handler so a bad value
/// yields a friendly error rather than a 422 from the extractor.
#[derive(serde::Deserialize)]
struct PeerForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    peer_name: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    jwks_url: String,
    #[serde(default)]
    trust_tier: String,
}

/// Form body for the per-row delete — only the CSRF token.
#[derive(serde::Deserialize)]
struct DeleteForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /federation/peers/create` — admin-gated + CSRF, then reuses
/// [`create_peer_core`] (validate → store.insert → audit) and
/// PRG-redirects to the federation page. On error it redirects with a
/// `?fed_error=` message rendered beside the form.
async fn create(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<PeerForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Some(trust_tier) = TrustTier::parse(form.trust_tier.trim()) else {
        return redirect_with_error(tenant_ctx, "Trust tier must be `full` or `restricted`.");
    };
    match create_peer_core(
        &state,
        tenant,
        principal,
        &form.peer_name,
        &form.issuer,
        &form.jwks_url,
        trust_tier,
    )
    .await
    {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &fed_err_message(&e, "create")),
    }
}

/// `POST /federation/peers/{id}/update` — admin-gated + CSRF, reuses
/// [`update_peer_core`]. The dashboard edit form submits ALL fields, so
/// every PATCH re-asserts issuer / jwks_url / trust_tier (which
/// re-confirms the JWKS cache on the next tick — the intended
/// full-row-edit semantics).
async fn update(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<PeerForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read `id` by name: this handler is mounted at both
    // `/federation/peers/{id}/update` and (via the `/t/{tenant}` nest)
    // the 2-capture tenant-scoped path. `Path<String>` 500s on the
    // latter; a by-name map works on both.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing peer id.");
    };
    let Ok(uuid) = Uuid::parse_str(id.trim()) else {
        return redirect_with_error(tenant_ctx, "Invalid peer id.");
    };
    let Some(trust_tier) = TrustTier::parse(form.trust_tier.trim()) else {
        return redirect_with_error(tenant_ctx, "Trust tier must be `full` or `restricted`.");
    };
    match update_peer_core(
        &state,
        tenant,
        principal,
        uuid,
        Some(&form.peer_name),
        Some(&form.issuer),
        Some(&form.jwks_url),
        Some(trust_tier),
    )
    .await
    {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &fed_err_message(&e, "update")),
    }
}

/// `POST /federation/peers/{id}/delete` — admin-gated + CSRF, reuses
/// [`delete_peer_core`] (store.delete → JWKS-cache evict → audit).
async fn delete(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<DeleteForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // By-name `id` — same dual-mount reason as `update` above.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing peer id.");
    };
    let Ok(uuid) = Uuid::parse_str(id.trim()) else {
        return redirect_with_error(tenant_ctx, "Invalid peer id.");
    };
    match delete_peer_core(&state, tenant, principal, uuid).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(
            tenant_ctx,
            "That peer no longer exists — it may have already been deleted.",
        ),
        Err(e) => redirect_with_error(tenant_ctx, &fed_err_message(&e, "delete")),
    }
}

/// Shared admin-gate + CSRF check for the three mutating handlers.
/// Returns `(principal, tenant_ctx, tenant_str)` on success, or the
/// error `Response` to short-circuit. Tenant comes from the principal,
/// never `tenant_ctx`.
// The Ok tuple is tiny; the Err is a full axum `Response` (~hundreds of
// bytes), so the Result is boxed on the error side to satisfy clippy's
// `result_large_err`. Callers `return *resp` to short-circuit.
#[allow(clippy::type_complexity)]
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<Extension<TenantContext>>,
    form_csrf: &str,
) -> Result<(Option<&'a Principal>, Option<TenantContext>, &'a str), Box<Response>> {
    let principal = user.as_ref().map(|Extension(p)| p);
    if let Err(e) = crate::scope::require_admin_extension(principal) {
        return Err(Box::new(e.into_response()));
    }
    // Same CSRF contract as the api-key-profiles / activity forms: when
    // a token is injected it must match; when none is injected (CSRF
    // middleware off, e.g. dev) the check passes.
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
        "/federation",
    ))
    .into_response()
}

/// PRG redirect back to the federation page with an error in
/// `?fed_error=` (URL-encoded). The page renders it beside the forms.
fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?fed_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/federation"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Operator-safe message for a peer-mutation failure, parameterized by
/// verb. Validation / conflict / unavailable detail is safe to surface
/// (incl. the userinfo / scheme rejections); anything else collapses to
/// a generic line so implementation detail never reaches the browser.
fn fed_err_message(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::BadGateway(d)
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) => (*d).to_owned(),
        ApiError::NotFound(d) => format!("{d} not found."),
        _ => format!("Failed to {verb} peer — see gateway logs for details."),
    }
}

async fn load_peers(
    store: &SharedPeersStore,
    tenant: &str,
    cache: Option<&waygate_federation::jwks::SharedPeerJwksCache>,
) -> (Vec<PeerRow>, bool, Option<String>) {
    let filter = PeerFilter {
        peer_name: None,
        issuer: None,
        trust_tier: None,
    };
    // Fetch limit+1 to detect "exactly more than the cap" without
    // flagging the boundary case of "exactly the cap" as truncated.
    // We then trim the extra row before rendering so the table
    // still shows at most PEER_LIST_LIMIT.
    let fetch_limit = PEER_LIST_LIMIT.saturating_add(1);
    let mut raw = match store.list(tenant, filter, fetch_limit, 0).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                "federation page: peer list failed",
            );
            return (
                Vec::new(),
                false,
                Some("Failed to load federated peers — see gateway logs for details.".to_owned()),
            );
        }
    };
    let truncated = raw.len() as u32 > PEER_LIST_LIMIT;
    if truncated {
        raw.truncate(PEER_LIST_LIMIT as usize);
    }
    let mut rows: Vec<PeerRow> = Vec::with_capacity(raw.len());
    for p in raw {
        rows.push(peer_row(p, cache).await);
    }
    (rows, truncated, None)
}

async fn peer_row(
    p: FederatedPeer,
    cache: Option<&waygate_federation::jwks::SharedPeerJwksCache>,
) -> PeerRow {
    let (cache_state, cache_key_count) = match cache {
        Some(c) => match c.get_by_peer_id(p.id).await {
            Some(entry) => ("warm", entry.keys.keys.len()),
            None => ("cold", 0),
        },
        None => ("unknown", 0),
    };
    PeerRow {
        id: p.id,
        peer_name: p.peer_name,
        issuer: p.issuer,
        jwks_url: p.jwks_url,
        trust_tier: p.trust_tier.as_str(),
        update_rel: format!("/federation/peers/{}/update", p.id),
        delete_rel: format!("/federation/peers/{}/delete", p.id),
        cache_state,
        cache_key_count,
        created_at_abs: format_ts_abs(p.created_at),
    }
}
