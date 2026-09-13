//! Catalog page — `/admin/t/{tenant}/catalog`.
//!
//! Read-only operator view of the governed catalog
//! (`waygate_catalog::CatalogStore`). Two sections per tenant:
//!
//! 1. **Servers** — currently configured upstreams joined with the
//!    `mcp_servers` registry visible to the principal's tenant. The catalog
//!    side uses `list_servers` so configured non-live lifecycle states remain
//!    visible, while rows retained after manifest removal stay on the audit
//!    and control-plane read surfaces instead of looking operational here.
//!    Each row carries lifecycle status
//!    (proposed / approved / live / quarantined / retired) and
//!    visibility scope. The governance posture is at-a-glance
//!    from the status chip.
//! 2. **Recent drift events** — the last 200 rows from
//!    `catalog_drift_events` for the tenant. Each event names
//!    the tool whose schema_hash drifted from the approved
//!    version, plus a severity chip (info / warn / critical)
//!    that maps to the auto-quarantine decision.
//!
//! ## What's NOT here (deferred)
//!
//! - **SSE drift event stream.** A server-sent event feed
//!   would let a drift event appear on the page in real time.
//!   Today the page renders
//!   the most-recent-N as a static table on load; the SSE
//!   wiring is not yet implemented. The store helper
//!   `list_drift_events` already exists for the snapshot view;
//!   a `subscribe_drift_events` channel on the catalog hub is
//!   the missing piece.
//! - **Inline `retire` control.** Initial approve and immediate quarantine ship
//!   in-page (admin-only, own-tenant rows). A quarantined row instead queues
//!   the governed `catalog.server.unquarantine` change for an eligible admin to
//!   approve. `retire` stays at `POST /api/v1/catalog/servers/{id}/...` for now.
//! - **Tool / version detail drawer.** Per-server drill-down
//!   to the per-tool view with schema diffs is not yet
//!   implemented.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant`. The `list_servers` query combines global +
//! tenant-only visibility across all lifecycle states, then the page retains
//! only names in the active upstream configuration. The live-only
//! `approved_servers` query cannot be used because it would also hide a
//! configured server awaiting approval or recovery. The drift query is
//! strictly per-tenant.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin` middleware
//! (`crates/waygate-admin/src/catalog.rs`). A dashboard session
//! without `mcp:admin` (or a peer-asserted principal) sees
//! the insufficient-scope card; the store fetches are skipped
//! entirely so no catalog data — including the per-tenant
//! server names and the operator-confidential drift hashes —
//! enters the rendered HTML.

use std::collections::BTreeSet;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_catalog::{
    CatalogServerStatus, CatalogServerSummary, DriftEvent, DriftSeverity, SharedCatalogStore,
};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::auth::CsrfToken;
use crate::catalog::{
    catalog_approve_dashboard, catalog_quarantine_dashboard, CatalogServerUnquarantineParams,
};
use crate::change_requests::{
    capture_target_etag, propose_core, ProposeRequest, SubmissionContext,
};
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;
use waygate_mcp::catalog::UpstreamCatalog;

/// Per-fetch row cap for the drift-events table. The store
/// orders by `observed_at DESC` so the slice is the most-
/// recent N. 200 is enough for incident-day triage; the
/// REST surface gives the unbounded paginated list.
const DRIFT_FETCH_LIMIT: u32 = 200;

/// Time-window for the drift fetch. 30 days matches the
/// retention default for high-severity events. The
/// `since` parameter on the store is required (the query
/// uses it as the lower bound on `observed_at DESC`); a
/// 30-day window keeps the table small enough to scan
/// without scrolling on a healthy tenant.
const DRIFT_WINDOW_DAYS: i64 = 30;

#[derive(Template)]
#[template(path = "catalog.html")]
struct CatalogPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the catalog store is unwired (dev mode /
    /// no DB / catalog feature disabled). Template renders the
    /// "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). Template renders the
    /// insufficient-scope card and SKIPS both store fetches.
    insufficient_scope: bool,
    /// Servers visible to the principal's tenant (global +
    /// tenant-only). Ordered server-side by name; no client-
    /// side sort.
    servers: Vec<ServerRow>,
    /// Recent drift events for the tenant. Ordered by
    /// observed_at DESC server-side.
    drift_events: Vec<DriftRow>,
    /// `true` when the drift slice hit [`DRIFT_FETCH_LIMIT`];
    /// template renders a "showing first N" hint nudging
    /// toward the REST surface.
    drift_truncated: bool,
    /// `true` when the Servers fetch failed. Template renders
    /// a section-specific error card instead of the empty
    /// "no servers" state, so a store failure isn't mistaken
    /// for "no servers configured".
    servers_load_error: bool,
    /// Same as [`Self::servers_load_error`] but for the
    /// drift-events section.
    drift_load_error: bool,
}

struct ServerRow {
    id: Uuid,
    name: String,
    transport: String,
    status: &'static str,
    visibility: &'static str,
    /// `true` when this row belongs to the caller's tenant. The store only
    /// mutates own-tenant rows, so a foreign global row's transition would
    /// 404 — render the lifecycle buttons only for mutable rows.
    mutable: bool,
    /// `Some(owner)` when the server row has an owner set,
    /// rendered as a sub-line; `None` renders nothing.
    owner: Option<String>,
}

struct DriftRow {
    id: Uuid,
    tool_id: Uuid,
    /// Pre-truncated to 12 chars + ellipsis for the table
    /// view. Full hash on hover via `title` (set by the
    /// template).
    observed_hash_short: String,
    observed_hash: String,
    /// `Some` when the drift was against a known approved
    /// hash; `None` for the first observation of a never-
    /// before-seen tool (the schema arrived but no version
    /// was ever approved). Rendered as an em-dash for None.
    approved_hash_short: Option<String>,
    approved_hash: Option<String>,
    severity: &'static str,
    observed_at_abs: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/catalog", get(catalog_page))
        .route("/catalog/approve", post(catalog_approve_dashboard))
        .route("/catalog/quarantine", post(catalog_quarantine_dashboard))
        .route(
            "/catalog/unquarantine/propose",
            post(catalog_unquarantine_propose),
        )
}

#[derive(Debug, serde::Deserialize)]
struct CatalogUnquarantineForm {
    #[serde(default)]
    csrf: String,
    id: String,
    expected_name: String,
    reason: String,
}

/// Queue durable catalog recovery through the same change-request core used by
/// `gateway-admin.propose_change`. This route only captures intent; the status
/// transition remains impossible until the captured eligible-admin quorum
/// approves it. In the single-admin default, the proposing admin may supply
/// that approval.
async fn catalog_unquarantine_propose(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(form): Form<CatalogUnquarantineForm>,
) -> Response {
    let guard_form = crate::catalog::CatalogActionForm {
        csrf: form.csrf,
        id: form.id,
    };
    let id = match crate::catalog::catalog_action_guard(&user, &csrf, &guard_form) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let Some(Extension(actor)) = user.as_ref() else {
        return crate::error::ApiError::Forbidden("admin principal required").into_response();
    };
    let expected_name = form.expected_name;
    let reason = form.reason.trim().to_owned();
    let params = CatalogServerUnquarantineParams {
        server_id: id,
        expected_name,
        reason: reason.clone(),
    };
    let params = match serde_json::to_value(params) {
        Ok(params) => params,
        Err(e) => {
            return crate::error::ApiError::Internal(format!("catalog unquarantine params: {e}"))
                .into_response()
        }
    };
    let req = ProposeRequest {
        action_type: "catalog.server.unquarantine".into(),
        params,
        justification: reason,
        ttl_seconds: None,
    };
    let target_etag = match capture_target_etag(&state, &req.action_type, actor, &req.params).await
    {
        Ok(etag) => etag,
        Err(e) => return e.into_response(),
    };
    let store = match state.hitl.change_requests.require() {
        Ok(store) => store,
        Err(e) => return e.into_response(),
    };
    match propose_core(
        store,
        &state.evidence,
        &state.public_url,
        state.hitl.change_notifier.as_ref(),
        actor,
        req,
        // Gateway-constructed params from a typed dashboard form; this action
        // has no document field, so nothing was read out of the file plane.
        SubmissionContext {
            target_etag,
            files: Vec::new(),
        },
    )
    .await
    {
        Ok(response) => axum::response::Redirect::to(&response.approval_url).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn catalog_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
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
    let store_configured = state.servers.catalog.enabled();

    let load = if insufficient_scope {
        // Skip both store reads entirely — no catalog data
        // leaks into the rendered HTML.
        LoadResult::default()
    } else {
        match state.servers.catalog.get() {
            Some(store) => {
                let configured_names: BTreeSet<String> =
                    state.upstreams.list_servers().await.into_iter().collect();
                load_catalog(store, &read_tenant, &configured_names).await
            }
            None => LoadResult::default(),
        }
    };

    let page = CatalogPage {
        chrome: PageChrome::build(
            &state,
            "Catalog",
            "/catalog",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope,
        servers: load.servers,
        drift_events: load.drift_events,
        drift_truncated: load.drift_truncated,
        servers_load_error: load.servers_load_error,
        drift_load_error: load.drift_load_error,
    };
    render(&page)
}

/// Authorization gate for the catalog dashboard page. Same
/// shape as `dashboard_break_glass::principal_has_dashboard_admin`.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

#[derive(Default)]
struct LoadResult {
    servers: Vec<ServerRow>,
    drift_events: Vec<DriftRow>,
    drift_truncated: bool,
    /// Per-section error flags: distinguish "store failed" from
    /// "genuinely empty" so the template renders a per-section
    /// error card rather than the empty state.
    servers_load_error: bool,
    drift_load_error: bool,
}

async fn load_catalog(
    store: &SharedCatalogStore,
    tenant: &str,
    configured_names: &BTreeSet<String>,
) -> LoadResult {
    // Two independent fetches — neither blocks the other.
    // A failure on one renders a per-section error card; the
    // other section keeps its data. The catalog page doesn't
    // have a "load-bearing" section (unlike the approvals page,
    // where an Active-fetch failure wipes the page) — both
    // sections are independently meaningful, so partial-render
    // is the right shape.
    // `list_servers` supplies all lifecycle states, while the configured-name
    // intersection keeps this operational page from presenting retained rows
    // for removed manifests as current servers. `approved_servers` cannot
    // express that distinction because it would also hide a configured
    // quarantine or pending approval.
    let (servers, servers_load_error) = match store.list_servers(tenant).await {
        Ok(rows) => (
            rows.into_iter()
                .filter(|server| configured_names.contains(&server.name))
                .map(|s| server_row(s, tenant))
                .collect(),
            false,
        ),
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                "catalog page: list_servers failed",
            );
            (Vec::new(), true)
        }
    };

    let since = OffsetDateTime::now_utc() - time::Duration::days(DRIFT_WINDOW_DAYS);
    let (drift_events, drift_truncated, drift_load_error) = match store
        .list_drift_events(tenant, since, DRIFT_FETCH_LIMIT)
        .await
    {
        Ok(rows) => {
            let truncated = rows.len() as u32 >= DRIFT_FETCH_LIMIT;
            let mapped: Vec<DriftRow> = rows.into_iter().map(drift_row).collect();
            (mapped, truncated, false)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                "catalog page: list_drift_events failed",
            );
            (Vec::new(), false, true)
        }
    };

    LoadResult {
        servers,
        drift_events,
        drift_truncated,
        servers_load_error,
        drift_load_error,
    }
}

fn server_row(s: CatalogServerSummary, read_tenant: &str) -> ServerRow {
    ServerRow {
        id: s.id,
        name: s.name,
        transport: s.transport,
        status: catalog_server_status_str(s.status),
        visibility: catalog_visibility_str(s.visibility),
        mutable: s.tenant_id == read_tenant,
        owner: s.owner,
    }
}

fn drift_row(d: DriftEvent) -> DriftRow {
    let observed_short = short_hash(&d.observed_hash);
    let approved_short = d.approved_hash.as_deref().map(short_hash);
    DriftRow {
        id: d.id,
        tool_id: d.tool_id,
        observed_hash_short: observed_short,
        observed_hash: d.observed_hash,
        approved_hash_short: approved_short,
        approved_hash: d.approved_hash,
        severity: drift_severity_str(d.severity),
        observed_at_abs: format_ts_abs(d.observed_at),
    }
}

/// Display string for [`CatalogServerStatus`]. Matches the DB
/// CHECK literal; a rename here without a migration would
/// lie to operators about what was stored.
fn catalog_server_status_str(s: CatalogServerStatus) -> &'static str {
    match s {
        CatalogServerStatus::Proposed => "proposed",
        CatalogServerStatus::Approved => "approved",
        CatalogServerStatus::Live => "live",
        CatalogServerStatus::Quarantined => "quarantined",
        CatalogServerStatus::Retired => "retired",
    }
}

fn catalog_visibility_str(v: waygate_catalog::CatalogVisibility) -> &'static str {
    match v {
        waygate_catalog::CatalogVisibility::Global => "global",
        waygate_catalog::CatalogVisibility::TenantOnly => "tenant",
    }
}

fn drift_severity_str(s: DriftSeverity) -> &'static str {
    match s {
        DriftSeverity::Info => "info",
        DriftSeverity::Warn => "warn",
        DriftSeverity::Critical => "critical",
    }
}

/// First 12 hex chars + ellipsis. Schema hashes are typically
/// 64-char hex; the full hash is on hover via the template's
/// `title=` attribute, so the short form is for at-a-glance
/// "did the same drift fire twice in a row?" pattern recognition.
fn short_hash(h: &str) -> String {
    if h.len() <= 12 {
        return h.to_owned();
    }
    format!("{}…", &h[..12])
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
    fn catalog_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn catalog_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn catalog_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn catalog_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn server_status_strings_match_db_constraints() {
        // The DB CHECK constraint on mcp_servers.status pins
        // these literals; a rename without a migration would
        // lie to operators about what was stored.
        assert_eq!(
            catalog_server_status_str(CatalogServerStatus::Proposed),
            "proposed"
        );
        assert_eq!(
            catalog_server_status_str(CatalogServerStatus::Approved),
            "approved"
        );
        assert_eq!(catalog_server_status_str(CatalogServerStatus::Live), "live");
        assert_eq!(
            catalog_server_status_str(CatalogServerStatus::Quarantined),
            "quarantined",
        );
        assert_eq!(
            catalog_server_status_str(CatalogServerStatus::Retired),
            "retired"
        );
    }

    #[test]
    fn drift_severity_strings_match_db_constraints() {
        assert_eq!(drift_severity_str(DriftSeverity::Info), "info");
        assert_eq!(drift_severity_str(DriftSeverity::Warn), "warn");
        assert_eq!(drift_severity_str(DriftSeverity::Critical), "critical");
    }

    #[test]
    fn short_hash_truncates_with_ellipsis_for_long_hashes() {
        let full = "abcdef0123456789abcdef0123456789";
        let short = short_hash(full);
        assert_eq!(short, "abcdef012345…");
        assert!(short.starts_with("abcdef"), "must preserve the prefix");
    }

    #[test]
    fn short_hash_passes_through_short_strings() {
        // A 12-char-or-shorter hash isn't useful in production
        // but the helper shouldn't add the ellipsis if there's
        // nothing to truncate.
        assert_eq!(short_hash("short"), "short");
        assert_eq!(short_hash("abcdef012345"), "abcdef012345");
    }

    #[test]
    fn empty_drift_state_links_to_tool_change_review() {
        let page = CatalogPage {
            chrome: PageChrome {
                title: "Catalog",
                env: "test",
                user: None,
                theme: None,
                nav: Vec::new(),
                tenant_ctx: None,
                csrf_token: String::new(),
            },
            store_configured: true,
            insufficient_scope: false,
            servers: Vec::new(),
            drift_events: Vec::new(),
            drift_truncated: false,
            servers_load_error: false,
            drift_load_error: false,
        };
        let html = page.render().expect("catalog page renders");
        assert!(html.contains("No durable catalog drift events"));
        assert!(html.contains("href=\"/admin/servers/tool-changes\""));
        assert!(html.contains("Review quarantined tool changes"));
        assert!(!html.contains("No drift in the last 30 days"));
    }

    /// Fake catalog store whose `approved_servers` is live-only (mirroring the
    /// real per-call discovery query) but whose `list_servers` returns every
    /// seeded row. Used to prove the page retains configured non-live rows
    /// without surfacing removed history.
    struct LifecycleFake {
        servers: Vec<CatalogServerSummary>,
    }

    #[async_trait::async_trait]
    impl waygate_catalog::CatalogStore for LifecycleFake {
        async fn approved_servers(
            &self,
            _principal_tenant: &str,
        ) -> Result<Vec<CatalogServerSummary>, waygate_catalog::CatalogError> {
            Ok(self
                .servers
                .iter()
                .filter(|s| matches!(s.status, CatalogServerStatus::Live))
                .cloned()
                .collect())
        }
        async fn list_servers(
            &self,
            _principal_tenant: &str,
        ) -> Result<Vec<CatalogServerSummary>, waygate_catalog::CatalogError> {
            Ok(self.servers.clone())
        }
        async fn list_drift_events(
            &self,
            _tenant: &str,
            _since: OffsetDateTime,
            _limit: u32,
        ) -> Result<Vec<DriftEvent>, waygate_catalog::CatalogError> {
            Ok(Vec::new())
        }
        async fn resolve_tool(
            &self,
            _principal_tenant: &str,
            _fq_name: &str,
        ) -> Result<waygate_catalog::ResolvedTool, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn record_drift(
            &self,
            _observation: waygate_catalog::DriftObservation<'_>,
        ) -> Result<(), waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn record_approval(
            &self,
            _action: waygate_catalog::ApprovalAction<'_>,
        ) -> Result<(), waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn set_server_status(
            &self,
            _tenant_id: &str,
            _server_id: Uuid,
            _new_status: CatalogServerStatus,
            _actor: &str,
            _reason: Option<&str>,
        ) -> Result<bool, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn last_approve_actor(
            &self,
            _tenant: &str,
            _id: Uuid,
        ) -> Result<Option<String>, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn find_grant<'a>(
            &self,
            _lookup: waygate_catalog::GrantLookup<'a>,
        ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn claim_grant<'a>(
            &self,
            _lookup: waygate_catalog::GrantLookup<'a>,
        ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn create_grant<'a>(
            &self,
            _grant: waygate_catalog::NewApprovalGrant<'a>,
        ) -> Result<waygate_catalog::ApprovalGrant, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn list_grants<'a>(
            &self,
            _tenant_id: &'a str,
            _filter: waygate_catalog::GrantFilter<'a>,
        ) -> Result<Vec<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn revoke_grant(
            &self,
            _tenant_id: &str,
            _id: Uuid,
        ) -> Result<bool, waygate_catalog::CatalogError> {
            unimplemented!()
        }
        async fn sweep_grants(
            &self,
            _older_than: OffsetDateTime,
        ) -> Result<u64, waygate_catalog::CatalogError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn load_catalog_shows_only_configured_lifecycle_servers() {
        let configured_quarantine = CatalogServerSummary {
            id: "00000000-0000-0000-0000-0000000000a1".parse().unwrap(),
            tenant_id: "default".into(),
            name: "configured-quarantine".into(),
            transport: "http".into(),
            status: CatalogServerStatus::Quarantined,
            visibility: waygate_catalog::CatalogVisibility::TenantOnly,
            owner: None,
        };
        let removed_quarantine = CatalogServerSummary {
            id: "00000000-0000-0000-0000-0000000000a2".parse().unwrap(),
            tenant_id: "default".into(),
            name: "removed-quarantine".into(),
            transport: "http".into(),
            status: CatalogServerStatus::Quarantined,
            visibility: waygate_catalog::CatalogVisibility::TenantOnly,
            owner: None,
        };
        let store: SharedCatalogStore = Arc::new(LifecycleFake {
            servers: vec![configured_quarantine, removed_quarantine],
        });
        let configured_names = BTreeSet::from(["configured-quarantine".to_owned()]);

        let load = load_catalog(&store, "default", &configured_names).await;

        assert!(!load.servers_load_error, "fake never errors");
        assert_eq!(
            load.servers.len(),
            1,
            "removed catalog history must stay out of the operational page",
        );
        assert_eq!(load.servers[0].name, "configured-quarantine");
        assert_eq!(
            load.servers[0].status, "quarantined",
            "a configured non-live status must remain visible and actionable",
        );
    }
}
