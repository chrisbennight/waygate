//! Approvals page — `/admin/t/{tenant}/approvals`.
//!
//! Listing of HITL approval grants from the catalog
//! `approval_grants` table, with an inline per-row revoke on the
//! Active section (see "Inline actions" below). Three
//! lifecycle sections, each fetched
//! with a precise [`GrantLifecycle`] predicate so the store's
//! 200-row cap applies per-bucket (no crowd-out across sections):
//!
//! 1. **Active** — `consumed_at IS NULL AND expires_at > now()`.
//!    Operators see what's open for the principal to invoke.
//! 2. **Expired** — `consumed_at IS NULL AND expires_at <= now()`.
//!    Grants that timed out before use; useful for spotting
//!    too-short TTLs.
//! 3. **Recently closed** — `consumed_at IS NOT NULL`, ordered by
//!    `consumed_at DESC` at the store layer (so the slice is the
//!    most-recently-CLOSED, not the most-recently-CREATED), then
//!    truncated to [`HISTORY_LIMIT`]. Includes BOTH caller-consumed
//!    and operator-revoked grants — the store's `revoke_grant`
//!    reuses `consumed_at = now()` for revocations, so the schema
//!    can't distinguish the two cases without a future
//!    `revoked_at` column. The template surface labels these as
//!    "closed" rather than "consumed" so a revoked grant doesn't
//!    look caller-used. Older closed rows live in the catalog
//!    itself; pull via
//!    `GET /api/v1/admin/approval_grants?include_consumed=true`.
//!    Approval-grant lifecycle events are NOT yet routed to the
//!    Activity audit stream (the create/revoke handlers emit
//!    `tracing` logs but no durable evidence event), so Activity
//!    will not surface them.
//!
//! ## Inline actions
//!
//! - **Per-row revoke** on the *Active* section. Each live grant gets a
//!   Revoke button that POSTs to `/approvals/{id}/revoke` (admin-gated +
//!   CSRF), reusing the REST surface's
//!   [`crate::approval_grants::revoke_grant_core`] so the HTML and JSON
//!   paths can't drift. The *form* is rendered only on Active rows
//!   (the operator's intended target); the Expired and Closed tables
//!   carry no button. The shared core does NOT itself filter by
//!   lifecycle — it closes any grant with `consumed_at IS NULL`,
//!   including an already-expired one — exactly as the REST
//!   `DELETE /api/v1/admin/approval_grants/{id}` does. That parity is
//!   deliberate: gating expired revokes only on the dashboard path
//!   would reintroduce the HTML/JSON drift the shared core exists to
//!   prevent. So a hand-crafted admin+CSRF POST naming an expired
//!   grant's id WILL close it (harmless — the grant was already
//!   unclaimable via `find_grant`); the UI just never surfaces that
//!   path. The tracing-only audit posture (no Evidence event) is
//!   preserved by the shared core.
//!
//! ## What's NOT here (deferred)
//!
//! - **Live WebSocket subscription** to `/api/v1/admin/approval_grants/subscribe`
//!   for in-progress invocation-blocked notifications. The hub
//!   (`crate::hitl_ws::ApprovalHub`) already exists; the dashboard JS
//!   that subscribes + renders "WAITING" rows is not yet implemented.
//! - **Inline mint form**. POST via REST today; an in-page
//!   "Approve alice for tool X with hash Y" composer is deferred — minting
//!   binds the grant to a canonical `argument_hash` over the exact call
//!   arguments, which needs a dedicated composer rather than a flat
//!   form, so it stays on the REST surface for now.
//! - **Age coding + SLA badges + keyboard shortcuts**. Plan calls for
//!   these on the active section; ship the visibility first, then
//!   layer ergonomics in follow-ups.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant` — same posture every other dashboard
//! page takes today. Cross-tenant operator access is not supported.

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
use waygate_catalog::{ApprovalGrant, GrantFilter, GrantLifecycle, SharedCatalogStore};
use waygate_core::fmt::format_ts_abs;
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::approval_grants::revoke_grant_core;
use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

/// Cap on rendered consumed-history rows. This slice is a "recent
/// activity" glance; the catalog REST surface
/// (`GET /api/v1/admin/approval_grants?include_consumed=true`) is
/// the authoritative full-history source. +1 detection idiom for
/// truncation.
const HISTORY_LIMIT: usize = 50;

#[derive(Template)]
#[template(path = "approvals.html")]
struct ApprovalsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the catalog store is unwired (dev mode / no DB).
    /// Template renders a "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin` (or is
    /// a peer assertion). Template renders an "insufficient scope"
    /// card and SKIPS rendering any grant data. The equivalent REST
    /// endpoint (`/api/v1/admin/approval_grants`) is gated by
    /// `require_admin`; the dashboard view must match so a
    /// non-admin SSO session can't read principal_sub / argument
    /// hashes / etc. by browsing instead of curling.
    insufficient_scope: bool,
    /// Live grants the caller has not yet used — `consumed_at IS NULL`
    /// AND `expires_at > now()`.
    active: Vec<GrantRow>,
    /// Grants the caller didn't use in time — `consumed_at IS NULL`
    /// AND `expires_at <= now()`. Surfaces TTL-too-short patterns.
    expired: Vec<GrantRow>,
    /// Recently-consumed grants, capped at [`HISTORY_LIMIT`]. Most
    /// recent first.
    history: Vec<GrantRow>,
    /// `true` when the consumed-history slice was capped (more rows
    /// exist past the limit). Template nudges toward the catalog
    /// REST surface for the full history (NOT Activity — grant
    /// lifecycle events aren't audited yet).
    history_truncated: bool,
    /// `true` when the Expired bucket's `list_grants` call failed.
    /// Template renders a per-section "failed to load" message
    /// instead of the "no expired grants" empty card: substituting
    /// `Vec::new()` on a per-bucket store failure would make a load
    /// error indistinguishable from a genuinely empty section.
    expired_load_error: bool,
    /// Same as [`Self::expired_load_error`] but for the "closed"
    /// (consumed-or-revoked) bucket — internally still keyed on
    /// `consumed_at IS NOT NULL` because the schema reuses that
    /// column for both caller-consumption and operator-revocation.
    history_load_error: bool,
    /// Store-error fallback for the *Active* bucket. Active is the
    /// "currently waiting callers" surface — if it fails the whole
    /// page renders an error banner rather than three empty
    /// sections, because hiding a "this is broken" signal behind
    /// empty cards is worse than a banner. Set to `None` when
    /// active loaded successfully (even if expired / consumed
    /// failed — those have per-section error flags above).
    error: Option<String>,
    /// `Some(msg)` when a revoke submission failed, threaded back via
    /// the `?appr_error=` PRG query param and rendered above the
    /// Active section.
    appr_error: Option<String>,
}

impl ApprovalsPage {}

struct GrantRow {
    id: Uuid,
    /// Relative URL for the per-row revoke form action; the template
    /// wraps it with `self.nav_url(...)`. Precomputed because askama
    /// can't `format!` the id into the path inline. Rendered only on
    /// Active rows.
    revoke_rel: String,
    principal_sub: String,
    client_id: Option<String>,
    /// Catalog server id — shown alongside `tool_id` because operators
    /// triaging a misfire need to know which upstream the grant binds
    /// to (the catalog mcp_servers join for human-friendly names is a
    /// follow-up; UUIDs serve until then).
    server_id: Uuid,
    tool_id: Uuid,
    argument_hash: String,
    approver: String,
    reason: Option<String>,
    created_at_abs: String,
    expires_at_abs: String,
    consumed_at_abs: Option<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/approvals", get(approvals_page))
        .route("/approvals/{id}/revoke", post(revoke_grant))
}

/// Query-string state for the approvals page. Only carries the PRG
/// error channel — the revoke form is the page's sole mutation.
#[derive(Debug, Default, Deserialize)]
struct ApprovalsQuery {
    /// PRG channel: a revoke failure is carried back here and rendered
    /// above the Active section. Passed through verbatim (it was
    /// urlencoded on the way out).
    #[serde(default)]
    appr_error: Option<String>,
}

async fn approvals_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<ApprovalsQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    // The equivalent REST surface wraps every approval-grant route
    // in `require_admin`. Mirror it here so a dashboard session
    // without mcp:admin can't read
    // principal_sub / approver / argument hashes / etc. by
    // browsing. Peer-asserted principals are refused on the same
    // defense-in-depth grounds as `require_admin_extension`
    // (peers are not operators of THIS gateway).
    let insufficient_scope = !principal_has_dashboard_admin(user_principal);

    let store_configured = state.servers.catalog.enabled();
    let load = if insufficient_scope {
        // Skip the catalog read entirely — no grant data leaks
        // into the rendered HTML.
        LoadResult::default()
    } else {
        match state.servers.catalog.get() {
            Some(store) => load_grants(store, &read_tenant).await,
            None => LoadResult::default(),
        }
    };

    let page = ApprovalsPage {
        chrome: PageChrome::build(
            &state,
            "Approvals",
            "/approvals",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        active: load.active,
        expired: load.expired,
        history: load.history,
        history_truncated: load.history_truncated,
        expired_load_error: load.expired_load_error,
        history_load_error: load.history_load_error,
        error: load.error,
        appr_error: q.appr_error,
    };
    render(&page)
}

/// Form body for the per-row revoke — only the CSRF token.
#[derive(Deserialize)]
struct RevokeForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /approvals/{id}/revoke` — admin-gated + CSRF, reuses
/// [`revoke_grant_core`] and PRG-redirects with a `?appr_error=`
/// channel. The Revoke form is rendered only on Active rows, but the
/// shared core (like the REST `DELETE`) closes any grant that is still
/// `consumed_at IS NULL` — including an expired-but-unconsumed one if a
/// crafted request names it. `Ok(true)` ⇒ a live grant was closed;
/// `Ok(false)` ⇒ nothing to close (already consumed/revoked, or no such
/// grant in this tenant) → the "no longer active" banner.
async fn revoke_grant(
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
    // Read `id` by name: mounted at both `/approvals/{id}/revoke` and the
    // 2-capture `/t/{tenant}/...` nest; `Path<String>` 500s on the latter,
    // so parse it manually instead.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing grant id.");
    };
    let Ok(uuid) = Uuid::parse_str(id.trim()) else {
        return redirect_with_error(tenant_ctx, "Invalid grant id.");
    };
    match revoke_grant_core(&state, tenant, principal, uuid).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(
            tenant_ctx,
            "That grant is no longer active (already closed).",
        ),
        Err(e) => redirect_with_error(tenant_ctx, &appr_err_message(&e)),
    }
}

/// Shared admin-gate + CSRF for the revoke handler. Uses the page's
/// stricter [`principal_has_dashboard_admin`] (refuses peer-asserted
/// principals). Returns `(principal, tenant_ctx, tenant)` or the boxed
/// error `Response`. Same shape as `dashboard_rbac::authorize`.
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
                StatusCode::FORBIDDEN,
                "Approval-grant changes require mcp:admin",
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
    let tenant = principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c), tenant))
}

fn redirect_ok(tenant_ctx: Option<TenantContext>) -> Response {
    Redirect::to(&crate::tenant_ctx::nav_url(
        tenant_ctx.as_ref(),
        "/approvals",
    ))
    .into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?appr_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/approvals"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Operator-safe revoke message. The store-unavailable detail is safe
/// to surface; anything else collapses to a generic line that points at
/// the logs (the tracing line carries the real cause).
fn appr_err_message(e: &ApiError) -> String {
    match e {
        ApiError::ServiceUnavailable(d) => (*d).to_owned(),
        _ => "Failed to revoke grant — see gateway logs for details.".to_owned(),
    }
}

/// Authorization gate for the approvals dashboard page. Returns
/// `true` only for an OAuth/API-key principal carrying the
/// `mcp:admin` scope. Peer-asserted principals are refused even
/// when scopes appear to match — same defense-in-depth posture as
/// [`crate::scope::require_admin_extension`].
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

/// Output of [`load_grants`]. Bucket vectors are always present
/// (empty when missing); per-bucket `*_load_error` flags
/// distinguish "genuinely empty" from "store failed for this
/// bucket" so the template can render a per-section error message
/// instead of the "no grants" empty card.
#[derive(Default)]
struct LoadResult {
    active: Vec<GrantRow>,
    expired: Vec<GrantRow>,
    history: Vec<GrantRow>,
    history_truncated: bool,
    expired_load_error: bool,
    history_load_error: bool,
    /// Page-level error banner — populated ONLY when the Active
    /// bucket failed (the "currently waiting callers" surface is
    /// the load-bearing one). Expired / Consumed failures live in
    /// the per-bucket flags above and don't wipe the page.
    error: Option<String>,
}

async fn load_grants(store: &SharedCatalogStore, tenant: &str) -> LoadResult {
    // Each lifecycle bucket is fetched with the precise
    // `GrantFilter.lifecycle` predicate rather than bucketed
    // client-side on `expires_at`: the store's bare
    // `include_consumed=false` filter resolves to `consumed_at IS
    // NULL AND expires_at > now()` — ACTIVE only — so a single
    // client-filtered query would leave the Expired table
    // permanently empty. Each bucket also gets its own 200-row
    // store window so none can crowd another out of a shared cap;
    // the consumed query orders by `consumed_at DESC` at the SQL
    // layer, so HISTORY_LIMIT surfaces the most-recently-consumed
    // rows.
    //
    // Per-bucket `*_load_error` flags distinguish "bucket loaded
    // empty" from "bucket failed and we substituted empty" —
    // without them, a fetch failure for Expired or Consumed reads
    // as "no grants timed out" instead of "this section failed to
    // load."
    let mut active = match list_bucket(store, tenant, GrantLifecycle::Active).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "approvals page: active list failed");
            return LoadResult {
                error: Some(
                    "Failed to load approval grants — see gateway logs for details.".to_owned(),
                ),
                ..LoadResult::default()
            };
        }
    };
    let (mut expired, expired_load_error) = match list_bucket(
        store,
        tenant,
        GrantLifecycle::Expired,
    )
    .await
    {
        Ok(rows) => (rows, false),
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "approvals page: expired list failed");
            (Vec::new(), true)
        }
    };
    let (mut consumed, history_load_error) = match list_bucket(
        store,
        tenant,
        GrantLifecycle::Consumed,
    )
    .await
    {
        Ok(rows) => (rows, false),
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "approvals page: consumed list failed");
            (Vec::new(), true)
        }
    };

    // The three list_grants calls each evaluate their own SQL
    // `now()`, so a grant whose `expires_at` falls in the window
    // between the Active and Expired queries can appear in BOTH
    // (Active sampled it as not-yet-expired; Expired sampled it as
    // past-expired a moment later). Same for the active→consumed
    // and expired→consumed boundaries. Lifecycle state strictly
    // monotonically advances (active → expired or consumed;
    // consumed is terminal), so the LATER observation is always
    // authoritative; dedupe by dropping ids from earlier buckets
    // when they reappear in a later one.
    dedupe_overlapping_lifecycles(&mut active, &mut expired, &consumed);

    let history_truncated = consumed.len() > HISTORY_LIMIT;
    if history_truncated {
        consumed.truncate(HISTORY_LIMIT);
    }

    LoadResult {
        active: active.into_iter().map(grant_row).collect(),
        expired: expired.into_iter().map(grant_row).collect(),
        history: consumed.into_iter().map(grant_row).collect(),
        history_truncated,
        expired_load_error,
        history_load_error,
        error: None,
    }
}

/// Resolve overlap between the three lifecycle bucket queries: an
/// id present in a later-sampled bucket evicts it from earlier
/// ones. Issued left-to-right (Active → Expired → Consumed), so an
/// id appearing in BOTH Active and Expired means the grant
/// expired between the two queries; an id in both Active and
/// Consumed means the caller consumed it mid-window; etc. The
/// later observation reflects the more-recent ground truth, so
/// the earlier bucket is the one we strip.
fn dedupe_overlapping_lifecycles(
    active: &mut Vec<ApprovalGrant>,
    expired: &mut Vec<ApprovalGrant>,
    consumed: &[ApprovalGrant],
) {
    use std::collections::HashSet;
    let consumed_ids: HashSet<Uuid> = consumed.iter().map(|g| g.id).collect();
    let later_than_active: HashSet<Uuid> = expired
        .iter()
        .map(|g| g.id)
        .chain(consumed_ids.iter().copied())
        .collect();
    active.retain(|g| !later_than_active.contains(&g.id));
    expired.retain(|g| !consumed_ids.contains(&g.id));
}

/// Fetch a single lifecycle bucket. The store applies its own 200-row
/// cap per call; the caller is expected to invoke once per bucket so
/// buckets can't crowd each other out of a shared cap.
async fn list_bucket(
    store: &SharedCatalogStore,
    tenant: &str,
    lifecycle: GrantLifecycle,
) -> Result<Vec<ApprovalGrant>, waygate_catalog::CatalogError> {
    let filter = GrantFilter {
        principal_sub: None,
        tool_id: None,
        server_id: None,
        include_consumed: false,
        lifecycle: Some(lifecycle),
    };
    store.list_grants(tenant, filter).await
}

/// Feeds the overview page's attention queue. Count active HITL
/// approval grants for `tenant`. Returns `Some(count)` when the fetch
/// succeeded (0 when nothing is active); `None` when the store
/// is unwired or the fetch failed (attention queue silently
/// skips the row in that case — the dashboard's own
/// approvals page surfaces the real problem).
///
/// The fetch is capped by the store's per-call window (200
/// rows in PgCatalogStore); a tenant with more active approval
/// grants than that has crossed an incident threshold and the
/// dashboard's approvals page is where the operator should
/// pivot, not the overview tile.
pub async fn count_active_for_attention(
    store: Option<&SharedCatalogStore>,
    tenant: &str,
) -> Option<usize> {
    let store = store?;
    let rows = list_bucket(store, tenant, GrantLifecycle::Active)
        .await
        .ok()?;
    Some(rows.len())
}

/// Feeds the overview page's attention queue. Count expired-unused
/// HITL approval grants for `tenant`. A nonzero count is a
/// "TTL-too-short" signal — admins minted grants that the
/// caller never claimed, suggesting either tighter caller
/// timing requirements or longer grant TTLs. Returns
/// `Some(count)` / `None` with the same semantics as
/// [`count_active_for_attention`].
pub async fn count_expired_unused_for_attention(
    store: Option<&SharedCatalogStore>,
    tenant: &str,
) -> Option<usize> {
    let store = store?;
    let rows = list_bucket(store, tenant, GrantLifecycle::Expired)
        .await
        .ok()?;
    Some(rows.len())
}

fn grant_row(g: ApprovalGrant) -> GrantRow {
    GrantRow {
        revoke_rel: format!("/approvals/{}/revoke", g.id),
        id: g.id,
        principal_sub: g.principal_sub,
        client_id: g.client_id,
        server_id: g.server_id,
        tool_id: g.tool_id,
        argument_hash: g.argument_hash,
        approver: g.approver,
        reason: g.reason,
        created_at_abs: format_ts_abs(g.created_at),
        expires_at_abs: format_ts_abs(g.expires_at),
        consumed_at_abs: g.consumed_at.map(format_ts_abs),
    }
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
    fn dashboard_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn dashboard_admin_gate_allows_api_key_admin() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::ApiKey);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn dashboard_admin_gate_blocks_oauth_without_admin_scope() {
        // The default dashboard SSO scopes (openid/profile/email/
        // groups, mcp:read) lack mcp:admin — a routine SSO sign-in
        // must not see HITL grant data.
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn dashboard_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        // Same defense-in-depth posture as require_admin_extension:
        // a federated peer is never an operator of THIS gateway,
        // even if a future bug in the JWT validator lets mcp:admin
        // slip through.
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn dashboard_admin_gate_blocks_missing_principal() {
        // No principal at all (auth misconfigured) → no data.
        assert!(!principal_has_dashboard_admin(None));
    }

    fn grant(id_byte: u8, consumed: Option<i64>, expires_offset_secs: i64) -> ApprovalGrant {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        ApprovalGrant {
            id: Uuid::from_bytes([id_byte; 16]),
            tenant_id: "default".into(),
            principal_sub: "alice".into(),
            principal_issuer: Some("https://issuer.test".into()),
            client_id: None,
            server_id: Uuid::nil(),
            tool_id: Uuid::nil(),
            argument_hash: "h".into(),
            execution_binding: None,
            expires_at: now + time::Duration::seconds(expires_offset_secs),
            consumed_at: consumed.map(|c| OffsetDateTime::from_unix_timestamp(c).unwrap()),
            approver: "op".into(),
            reason: None,
            created_at: now,
        }
    }

    #[test]
    fn dedupe_strips_active_id_when_it_also_appears_in_expired() {
        // Grant expired in the window between Active and Expired
        // queries — both samples returned the same id. The later
        // observation (Expired) is authoritative.
        let mut active = vec![grant(1, None, -10), grant(2, None, 60)];
        let mut expired = vec![grant(1, None, -10)];
        let consumed: Vec<ApprovalGrant> = vec![];
        dedupe_overlapping_lifecycles(&mut active, &mut expired, &consumed);
        assert_eq!(
            active.iter().map(|g| g.id).collect::<Vec<_>>(),
            vec![Uuid::from_bytes([2; 16])]
        );
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn dedupe_strips_active_and_expired_ids_when_consumed_arrives_later() {
        // Caller consumed a grant after the Active query ran;
        // also a grant expired then was retroactively swept to
        // consumed_at by the grant sweeper. Both buckets had stale
        // observations; Consumed is the terminal state.
        let mut active = vec![grant(1, None, 60)];
        let mut expired = vec![grant(2, None, -10)];
        let consumed = vec![
            grant(1, Some(1_700_000_001), 60),
            grant(2, Some(1_700_000_002), -10),
        ];
        dedupe_overlapping_lifecycles(&mut active, &mut expired, &consumed);
        assert!(
            active.is_empty(),
            "consumed terminal must evict from active"
        );
        assert!(
            expired.is_empty(),
            "consumed terminal must evict from expired"
        );
    }

    #[test]
    fn dedupe_is_a_noop_when_buckets_are_already_disjoint() {
        // Healthy snapshot — no overlap. Dedupe must not touch
        // anything.
        let mut active = vec![grant(1, None, 60)];
        let mut expired = vec![grant(2, None, -10)];
        let consumed = vec![grant(3, Some(1_700_000_001), 60)];
        dedupe_overlapping_lifecycles(&mut active, &mut expired, &consumed);
        assert_eq!(active.len(), 1);
        assert_eq!(expired.len(), 1);
    }
}
