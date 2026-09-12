//! Federation, tenants, approvals, break-glass, rate-limits pages — split
//! from the monolithic `dashboard_render.rs`; bodies verbatim, cut at the
//! file's own section markers.

use crate::common::*;
use crate::crud_pages::post_form;

// ---- Federation page --------------------------------------------------------

/// The federation page renders at both legacy and tenant-prefixed
/// mounts and shows the "store not configured" empty state when no
/// federated-peers store is wired (empty_state has no DB).
#[tokio::test]
pub(crate) async fn federation_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/federation", "/t/default/federation"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "federation page failed at {path}");
        assert!(body.contains("Federation"), "page title missing at {path}",);
        assert!(
            body.contains("Federated-peer store not configured"),
            "expected disabled-state copy at {path}",
        );
        // The not-configured card renders the shared empty-state
        // component (centered icon + title + body), not a hand-rolled div.
        assert!(
            body.contains(r#"class="empty-state""#) && body.contains("lucide.svg#alert-triangle"),
            "federation disabled state should use the shared .empty-state component at {path}",
        );
    }
}

/// Sidebar nav surfaces Federation as its own destination under the MCP
/// Gateway section (it moved out of the Common access tabs in the section
/// reorg). On /federation the Federation link is current, it sits under
/// the MCP Gateway header, and the Identities destination is NOT current.
/// Confirms the wiring chain dashboard.rs DESTINATIONS → nav() → layout.html.
#[tokio::test]
pub(crate) async fn federation_page_marks_federation_destination_active_in_sidebar() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/federation").await;
    assert_eq!(status, StatusCode::OK);
    // Federation is its own destination — its sidebar link is current.
    assert!(
        body.contains(r#"href="/admin/federation" aria-current="page""#),
        "Federation nav link missing aria-current on legacy mount",
    );
    // It lives under the MCP Gateway section header.
    assert!(
        body.contains(
            r#"<li class="sidebar__section" role="heading" aria-level="2">MCP Gateway</li>"#
        ),
        "MCP Gateway section header should render in the sidebar",
    );
    // Identities is no longer the active destination on the Federation page.
    assert!(
        !body.contains(r#"href="/admin/identities" aria-current="page""#),
        "Identities destination must not be current on the Federation page",
    );
}

/// Palette catalogue contains Federation (the page was added to
/// PAGES alongside the route).
#[tokio::test]
pub(crate) async fn federation_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=fed").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Federation""#),
        "Federation missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Tier-C peer registry"#),
        "Federation hint missing from palette search result: {body}",
    );
}

// ---- Tenants page ----------------------------------------------------------

/// Tenants page renders at both mounts. empty_state has no tenants
/// store wired → renders the "registry not configured" empty card.
#[tokio::test]
pub(crate) async fn tenants_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/tenants", "/t/default/tenants"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "tenants page failed at {path}");
        assert!(body.contains("Tenants"), "page title missing at {path}");
        // The disabled-state card uses the shared `.empty-state`
        // component, not a local `.empty` class.
        assert!(
            body.contains("empty-state__title") && body.contains("Tenants store not configured"),
            "expected shared empty-state store-not-configured card at {path}",
        );
        assert!(
            !body.contains(r#"class="empty""#),
            "legacy .empty class still rendered at {path}",
        );
    }
}

/// Identity sidebar group force-opens on the tenants page
/// (contains_active behavior), and the Tenants nav link is active.
#[tokio::test]
pub(crate) async fn tenants_page_marks_identity_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/identities" aria-current="page""#),
        "the Identities destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/tenants" aria-current="page""#),
        "Tenants nav link missing aria-current on legacy mount",
    );
}

/// Palette finds Tenants in its catalogue.
#[tokio::test]
pub(crate) async fn tenants_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=ten").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Tenants""#),
        "Tenants missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Canonical tenants registry"#),
        "Tenants hint missing from palette search result: {body}",
    );
}

// ---- Approvals page ---------------------------------------------------------

/// Approvals page renders at both mounts. empty_state has no catalog
/// store → renders the shared `.empty-state` "store not configured"
/// card (not a local `.empty` class, and no raw-curl body).
#[tokio::test]
pub(crate) async fn approvals_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/approvals", "/t/default/approvals"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "approvals page failed at {path}");
        assert!(body.contains("Approvals"), "page title missing at {path}");
        assert!(
            body.contains("empty-state__title") && body.contains("Catalog store not configured"),
            "expected shared empty-state store-not-configured card at {path}",
        );
        // The disabled-state body must not carry the old local
        // `.empty` class or any raw `POST /api/v1/...` curl line.
        assert!(
            !body.contains(r#"class="empty""#),
            "legacy .empty class still rendered at {path}",
        );
    }
}

// ---- Approvals inline revoke ------------------------------------------------

/// Seedable in-memory catalog fake for the approvals page. Only the
/// grant methods carry behaviour (`list_grants` honours the lifecycle
/// predicate the page issues; `revoke_grant` sets `consumed_at`); every
/// other `CatalogStore` method is an inert stub. Mirrors the
/// `GrantFakeCatalog` in `approval_grants_api.rs` but bucketed by
/// lifecycle so the dashboard's three per-bucket queries behave like
/// the real store.
pub(crate) struct ApprovalsFakeCatalog {
    grants: std::sync::Mutex<Vec<waygate_catalog::ApprovalGrant>>,
    servers: Vec<waygate_catalog::CatalogServerSummary>,
}

impl ApprovalsFakeCatalog {
    fn with(grants: Vec<waygate_catalog::ApprovalGrant>) -> Self {
        Self {
            grants: std::sync::Mutex::new(grants),
            servers: Vec::new(),
        }
    }

    fn with_servers(servers: Vec<waygate_catalog::CatalogServerSummary>) -> Self {
        Self {
            grants: std::sync::Mutex::new(Vec::new()),
            servers,
        }
    }
}

#[async_trait]
impl waygate_catalog::CatalogStore for ApprovalsFakeCatalog {
    async fn approved_servers(
        &self,
        _t: &str,
    ) -> Result<Vec<waygate_catalog::CatalogServerSummary>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn list_servers(
        &self,
        _t: &str,
    ) -> Result<Vec<waygate_catalog::CatalogServerSummary>, waygate_catalog::CatalogError> {
        Ok(self.servers.clone())
    }
    async fn server_transition_target(
        &self,
        tenant_id: &str,
        server_id: Uuid,
    ) -> Result<Option<waygate_catalog::CatalogServerTransitionTarget>, waygate_catalog::CatalogError>
    {
        Ok(self
            .servers
            .iter()
            .find(|server| server.tenant_id == tenant_id && server.id == server_id)
            .map(|server| waygate_catalog::CatalogServerTransitionTarget {
                id: server.id,
                tenant_id: server.tenant_id.clone(),
                name: server.name.clone(),
                status: server.status,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
            }))
    }
    async fn resolve_tool(
        &self,
        _t: &str,
        _fq: &str,
    ) -> Result<waygate_catalog::ResolvedTool, waygate_catalog::CatalogError> {
        Ok(waygate_catalog::ResolvedTool::NotFound)
    }
    async fn record_drift(
        &self,
        _o: waygate_catalog::DriftObservation<'_>,
    ) -> Result<(), waygate_catalog::CatalogError> {
        Ok(())
    }
    async fn record_approval(
        &self,
        _a: waygate_catalog::ApprovalAction<'_>,
    ) -> Result<(), waygate_catalog::CatalogError> {
        Ok(())
    }
    async fn list_drift_events(
        &self,
        _t: &str,
        _s: time::OffsetDateTime,
        _l: u32,
    ) -> Result<Vec<waygate_catalog::DriftEvent>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn set_server_status(
        &self,
        _t: &str,
        _id: Uuid,
        _s: waygate_catalog::CatalogServerStatus,
        _a: &str,
        _r: Option<&str>,
    ) -> Result<bool, waygate_catalog::CatalogError> {
        Ok(false)
    }
    async fn last_approve_actor(
        &self,
        _t: &str,
        _id: Uuid,
    ) -> Result<Option<String>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn find_grant<'a>(
        &self,
        _l: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn claim_grant<'a>(
        &self,
        _l: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn create_grant<'a>(
        &self,
        _g: waygate_catalog::NewApprovalGrant<'a>,
    ) -> Result<waygate_catalog::ApprovalGrant, waygate_catalog::CatalogError> {
        unimplemented!("dashboard approvals page never mints")
    }
    async fn list_grants<'a>(
        &self,
        tenant_id: &'a str,
        filter: waygate_catalog::GrantFilter<'a>,
    ) -> Result<Vec<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        let v = self.grants.lock().unwrap();
        let now = time::OffsetDateTime::now_utc();
        Ok(v.iter()
            .filter(|g| g.tenant_id == tenant_id)
            .filter(|g| match filter.lifecycle {
                Some(waygate_catalog::GrantLifecycle::Active) => {
                    g.consumed_at.is_none() && g.expires_at > now
                }
                Some(waygate_catalog::GrantLifecycle::Expired) => {
                    g.consumed_at.is_none() && g.expires_at <= now
                }
                Some(waygate_catalog::GrantLifecycle::Consumed) => g.consumed_at.is_some(),
                None => filter.include_consumed || g.consumed_at.is_none(),
            })
            .cloned()
            .collect())
    }
    async fn revoke_grant(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<bool, waygate_catalog::CatalogError> {
        let mut v = self.grants.lock().unwrap();
        match v
            .iter_mut()
            .find(|g| g.tenant_id == tenant_id && g.id == id && g.consumed_at.is_none())
        {
            Some(g) => {
                g.consumed_at = Some(time::OffsetDateTime::now_utc());
                Ok(true)
            }
            None => Ok(false),
        }
    }
    async fn sweep_grants(
        &self,
        _older_than: time::OffsetDateTime,
    ) -> Result<u64, waygate_catalog::CatalogError> {
        Ok(0)
    }
}

pub(crate) fn active_grant(id: Uuid) -> waygate_catalog::ApprovalGrant {
    waygate_catalog::ApprovalGrant {
        id,
        tenant_id: "default".into(),
        principal_sub: "alice@example.com".into(),
        principal_issuer: Some("https://issuer.test".to_owned()),
        client_id: None,
        server_id: Uuid::from_u128(0xBBBB),
        tool_id: Uuid::from_u128(0xAAAA),
        argument_hash: "deadbeef".into(),
        execution_binding: None,
        // Well in the future so it lands in the Active bucket.
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        consumed_at: None,
        approver: "op@example.com".into(),
        reason: Some("vetted".into()),
        created_at: time::OffsetDateTime::now_utc(),
    }
}

/// An expired-but-unconsumed grant (lands in the Expired bucket; the UI
/// renders no revoke form for it).
pub(crate) fn expired_grant(id: Uuid) -> waygate_catalog::ApprovalGrant {
    waygate_catalog::ApprovalGrant {
        expires_at: time::OffsetDateTime::now_utc() - time::Duration::hours(1),
        ..active_grant(id)
    }
}

/// Build an `AdminState` with `catalog = Some(fake)` and nothing else
/// (mirrors `empty_state()` otherwise). The catalog is the 8th
/// positional arg of `AdminState::new`.
pub(crate) fn state_with_catalog(catalog: waygate_catalog::SharedCatalogStore) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
    state_with_catalog_pool(catalog, pool)
}

fn state_with_catalog_pool(
    catalog: waygate_catalog::SharedCatalogStore,
    pool: Arc<UpstreamPool>,
) -> Arc<AdminState> {
    Arc::new(AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        Some(catalog),
        "http://127.0.0.1:0".into(),
    ))
}

pub(crate) fn state_with_catalog_changes(
    catalog: waygate_catalog::SharedCatalogStore,
    changes: waygate_changeset::SharedChangeRequestStore,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    Arc::new(
        AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            Some(catalog),
            "http://127.0.0.1:0".into(),
        )
        .with_change_request_store(Some(changes)),
    )
}

#[tokio::test]
pub(crate) async fn catalog_quarantined_row_proposes_governed_recovery() {
    let server_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000a1").unwrap();
    let removed_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000a2").unwrap();
    let catalog: waygate_catalog::SharedCatalogStore =
        Arc::new(ApprovalsFakeCatalog::with_servers(vec![
            waygate_catalog::CatalogServerSummary {
                id: server_id,
                tenant_id: "default".into(),
                name: "grounded-docs".into(),
                transport: "http".into(),
                status: waygate_catalog::CatalogServerStatus::Quarantined,
                visibility: waygate_catalog::CatalogVisibility::TenantOnly,
                owner: None,
            },
            waygate_catalog::CatalogServerSummary {
                id: removed_id,
                tenant_id: "default".into(),
                name: "ssh".into(),
                transport: "http".into(),
                status: waygate_catalog::CatalogServerStatus::Quarantined,
                visibility: waygate_catalog::CatalogVisibility::TenantOnly,
                owner: None,
            },
        ]));
    let mut manifest = waygate_test_support::admin::example_messages_manifest();
    manifest.name = "grounded-docs".into();
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        ("grounded-docs".into(), manifest),
    ])));
    let app = dashboard_router(
        state_with_catalog_pool(catalog, pool),
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/t/default/catalog").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/t/default/catalog/unquarantine/propose"),
        "quarantined row must expose the governed proposal action: {body}",
    );
    assert!(
        body.contains("Propose unquarantine")
            && body.contains("name=\"expected_name\" value=\"grounded-docs\"")
            && body.contains("name=\"reason\""),
        "proposal form must bind the reviewed identity and require a reason: {body}",
    );
    assert!(
        !body.contains(&format!("srv-{removed_id}")),
        "removed catalog history must not render as an operational row: {body}",
    );
    assert!(
        !body.contains("/catalog/approve"),
        "quarantined rows must not expose the direct approval bypass: {body}",
    );
}

#[tokio::test]
pub(crate) async fn catalog_unquarantine_form_queues_single_admin_approvable_change() {
    let server_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000a1").unwrap();
    let catalog: waygate_catalog::SharedCatalogStore =
        Arc::new(ApprovalsFakeCatalog::with_servers(vec![
            waygate_catalog::CatalogServerSummary {
                id: server_id,
                tenant_id: "default".into(),
                name: "   ".into(),
                transport: "http".into(),
                status: waygate_catalog::CatalogServerStatus::Quarantined,
                visibility: waygate_catalog::CatalogVisibility::TenantOnly,
                owner: None,
            },
        ]));
    let changes = Arc::new(waygate_changeset::InMemoryChangeRequestStore::new());
    let app = dashboard_router(
        state_with_catalog_changes(catalog, changes.clone()),
        DashboardAuth::Disabled,
    );
    let (status, location) = post_form(
        app,
        "/catalog/unquarantine/propose",
        &format!("csrf=dev-csrf&id={server_id}&expected_name=+++&reason=manifest+validated"),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location.starts_with("http://127.0.0.1:0/admin/changes?pending_id=")
            && location.contains("#change-"),
        "proposal must redirect to the exact approval URL: {location}",
    );
    let pending = changes.list("default", None, 10, 0).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].requested_by, "dev@local");
    assert_eq!(pending[0].required_approvals, 1);
    assert_eq!(pending[0].action_type, "catalog.server.unquarantine");
    assert_eq!(pending[0].params["expected_name"], "   ");
    assert_eq!(
        pending[0].status,
        waygate_changeset::ChangeRequestStatus::Pending
    );
    let witness: waygate_catalog::CatalogServerTransitionTarget = serde_json::from_str(
        pending[0]
            .target_etag
            .as_deref()
            .expect("proposal must freeze a catalog row witness"),
    )
    .unwrap();
    assert_eq!(witness.id, server_id);
    assert_eq!(witness.name, "   ");
    assert_eq!(
        witness.status,
        waygate_catalog::CatalogServerStatus::Quarantined
    );
    let approved = changes
        .try_approve("default", pending[0].id, "dev@local")
        .await
        .unwrap()
        .expect("the dashboard proposer must satisfy the one-admin quorum");
    assert_eq!(approved.approver_sub.as_deref(), Some("dev@local"));
}

/// An active grant renders a per-row Revoke form (admin session via
/// `DashboardAuth::Disabled`), and the page carries NO raw curl
/// instruction (MASTER.md forbids it in empty-state bodies).
#[tokio::test]
pub(crate) async fn approvals_active_grant_renders_revoke_button() {
    let id = Uuid::from_u128(0x1234);
    let catalog: waygate_catalog::SharedCatalogStore =
        Arc::new(ApprovalsFakeCatalog::with(vec![active_grant(id)]));
    let app = dashboard_router(state_with_catalog(catalog), DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/approvals").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(&format!("/approvals/{id}/revoke")),
        "active row must carry a revoke form action",
    );
    assert!(body.contains(">Revoke<"), "Revoke button missing");
    assert!(body.contains("<th>Actions</th>"), "Actions column missing");
    assert!(
        !body.contains("No active grants"),
        "active empty-state should not render when a grant exists",
    );
    assert!(
        !body.contains("POST /api/v1/admin/approval_grants"),
        "raw curl instruction must not appear in the rendered page",
    );
}

/// Revoke happy path: admin + matching CSRF closes the live grant and
/// PRG-redirects back to the page with no error channel; a re-render
/// then shows the Active bucket empty.
#[tokio::test]
pub(crate) async fn approvals_revoke_happy_path_closes_and_redirects() {
    let id = Uuid::from_u128(0x5678);
    let catalog: waygate_catalog::SharedCatalogStore =
        Arc::new(ApprovalsFakeCatalog::with(vec![active_grant(id)]));
    let app = dashboard_router(state_with_catalog(catalog), DashboardAuth::Disabled);

    let (status, loc) = post_form(
        app.clone(),
        &format!("/approvals/{id}/revoke"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "revoke must PRG-redirect");
    assert!(
        loc.contains("approvals"),
        "redirect should return to the page, got {loc}"
    );
    assert!(
        !loc.contains("appr_error"),
        "a successful revoke must not carry an error, got {loc}",
    );

    // The grant is now consumed → the Active bucket is empty on reload.
    let (status, body) = body_of(app, "/approvals").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No active grants"),
        "revoked grant should no longer appear in the Active section",
    );
}

/// Revoke rejects a missing/blank CSRF token with 403 (same posture as
/// the other dashboard mutation handlers).
#[tokio::test]
pub(crate) async fn approvals_revoke_rejects_missing_csrf() {
    let id = Uuid::from_u128(0x9abc);
    let catalog: waygate_catalog::SharedCatalogStore =
        Arc::new(ApprovalsFakeCatalog::with(vec![active_grant(id)]));
    let app = dashboard_router(state_with_catalog(catalog), DashboardAuth::Disabled);
    let (status, _loc) = post_form(app, &format!("/approvals/{id}/revoke"), "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The shared core closes ANY unconsumed grant — including an
/// expired-but-unconsumed one — exactly as the REST `DELETE` does. The UI
/// only renders the form on Active rows, but a crafted admin+CSRF POST
/// naming an expired grant's id still closes it (`Ok(true)` →
/// redirect_ok, no error banner). This pins that REST-parity behaviour
/// so a future "guard expired on the dashboard path" change — which
/// would reintroduce HTML/JSON drift — fails this test instead of
/// silently diverging.
#[tokio::test]
pub(crate) async fn approvals_revoke_closes_expired_grant_matching_rest() {
    let id = Uuid::from_u128(0xdef0);
    let catalog: waygate_catalog::SharedCatalogStore =
        Arc::new(ApprovalsFakeCatalog::with(vec![expired_grant(id)]));
    let app = dashboard_router(state_with_catalog(catalog), DashboardAuth::Disabled);
    let (status, loc) = post_form(app, &format!("/approvals/{id}/revoke"), "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !loc.contains("appr_error"),
        "revoking an expired-unconsumed grant must succeed (Ok(true)), got {loc}",
    );
}

/// With no catalog store the revoke route still authorizes + parses,
/// then the shared core surfaces service-unavailable, which the handler
/// funnels into the `?appr_error=` PRG channel (defensive — without a
/// store no Active row, hence no button, is ever rendered).
#[tokio::test]
pub(crate) async fn approvals_revoke_without_store_redirects_with_error() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, loc) = post_form(
        app,
        "/approvals/00000000-0000-0000-0000-000000000000/revoke",
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("appr_error"),
        "store-unavailable revoke must carry an error banner, got {loc}",
    );
}

/// Traffic sidebar group force-opens on /approvals
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn approvals_page_marks_traffic_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/approvals").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/approvals" aria-current="page""#),
        "the Decisions destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/approvals" aria-current="page""#),
        "Approvals nav link missing aria-current on legacy mount",
    );
}

/// Palette finds Approvals in its catalogue.
#[tokio::test]
pub(crate) async fn approvals_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=appr").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Approvals""#),
        "Approvals missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"HITL approval grants"#),
        "Approvals hint missing from palette search result: {body}",
    );
}

// ---- Break-glass page --------------------------------------------------

/// Break-glass page renders at both mounts. empty_state has no
/// break-glass store → renders the "feature disabled" empty card.
#[tokio::test]
pub(crate) async fn break_glass_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/break_glass", "/t/default/break_glass"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "break-glass page failed at {path}");
        assert!(body.contains("Break-glass"), "page title missing at {path}");
        assert!(
            body.contains("Break-glass store not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// The Decisions destination is current on /break_glass, and the
/// Break-glass tab within it carries aria-current. (The destination's
/// default landing is the merged Queue at /decisions, so the sidebar
/// link points there; Break-glass is a tab under it.)
#[tokio::test]
pub(crate) async fn break_glass_page_marks_decisions_destination_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/break_glass").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/decisions" aria-current="page""#),
        "the Decisions destination link should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/break_glass" aria-current="page""#),
        "Break-glass tab missing aria-current on legacy mount",
    );
}

/// Palette finds Break-glass in its catalogue.
#[tokio::test]
pub(crate) async fn break_glass_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=break").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Break-glass""#),
        "Break-glass missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Emergency override tokens"#),
        "Break-glass hint missing from palette search result: {body}",
    );
}

// ---- Rate-limits page --------------------------------------------------

/// Rate-limits page renders at both mounts. empty_state has no
/// rate_limit_policies store → renders the disabled-state card.
#[tokio::test]
pub(crate) async fn rate_limits_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/rate_limits", "/t/default/rate_limits"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "rate_limits page failed at {path}");
        assert!(body.contains("Rate limits"), "page title missing at {path}");
        // The disabled-state card uses the shared `.empty-state`
        // component, not a local `.rl-empty` class.
        assert!(
            body.contains("empty-state__title") && body.contains("Rate-limit store not configured"),
            "expected shared empty-state store-not-configured card at {path}",
        );
        assert!(
            !body.contains(r#"class="rl-empty""#),
            "legacy .rl-empty class still rendered at {path}",
        );
    }
}

// ---- Rate-limits inline create / edit / delete -----------------------------

/// Seedable in-memory `RateLimitPolicyStore`. `create` conflicts on a
/// duplicate (scope, scope_value, action) per tenant (mirrors the
/// store's unique index); `update` patches only the provided fields;
/// `delete` reports whether a row existed.
pub(crate) struct FakeRlStore {
    policies: std::sync::Mutex<Vec<waygate_quota::RateLimitPolicy>>,
}

impl FakeRlStore {
    fn with(policies: Vec<waygate_quota::RateLimitPolicy>) -> Self {
        Self {
            policies: std::sync::Mutex::new(policies),
        }
    }
}

#[async_trait]
impl waygate_quota::RateLimitPolicyStore for FakeRlStore {
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        scope: waygate_quota::QuotaScope,
        scope_value: Option<&str>,
        bucket_capacity: i32,
        refill_per_second: f64,
        action: waygate_quota::QuotaAction,
    ) -> Result<waygate_quota::RateLimitPolicy, waygate_quota::RateLimitStoreError> {
        let mut v = self.policies.lock().unwrap();
        let sv = scope_value.map(str::to_owned);
        if v.iter().any(|p| {
            p.tenant_id == tenant_id
                && p.scope == scope
                && p.scope_value == sv
                && p.action == action
        }) {
            return Err(waygate_quota::RateLimitStoreError::Conflict);
        }
        let now = OffsetDateTime::now_utc();
        let p = waygate_quota::RateLimitPolicy {
            id: Uuid::now_v7(),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            scope,
            scope_value: sv,
            bucket_capacity,
            refill_per_second,
            action,
            created_at: now,
            updated_at: now,
        };
        v.push(p.clone());
        Ok(p)
    }
    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<waygate_quota::RateLimitPolicy>, waygate_quota::RateLimitStoreError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.tenant_id == tenant_id && p.id == id)
            .cloned())
    }
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<waygate_quota::RateLimitPolicy>, waygate_quota::RateLimitStoreError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.tenant_id == tenant_id)
            .cloned()
            .collect())
    }
    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        bucket_capacity: Option<i32>,
        refill_per_second: Option<f64>,
    ) -> Result<Option<waygate_quota::RateLimitPolicy>, waygate_quota::RateLimitStoreError> {
        let mut v = self.policies.lock().unwrap();
        match v
            .iter_mut()
            .find(|p| p.tenant_id == tenant_id && p.id == id)
        {
            Some(p) => {
                if let Some(c) = bucket_capacity {
                    p.bucket_capacity = c;
                }
                if let Some(r) = refill_per_second {
                    p.refill_per_second = r;
                }
                p.updated_at = OffsetDateTime::now_utc();
                Ok(Some(p.clone()))
            }
            None => Ok(None),
        }
    }
    async fn delete(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<bool, waygate_quota::RateLimitStoreError> {
        let mut v = self.policies.lock().unwrap();
        let before = v.len();
        v.retain(|p| !(p.tenant_id == tenant_id && p.id == id));
        Ok(v.len() < before)
    }
    async fn delete_all_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<u64, waygate_quota::RateLimitStoreError> {
        let mut v = self.policies.lock().unwrap();
        let before = v.len();
        v.retain(|p| p.tenant_id != tenant_id);
        Ok((before - v.len()) as u64)
    }
}

pub(crate) fn rl_fixture(
    id: Uuid,
    scope: waygate_quota::QuotaScope,
    scope_value: Option<&str>,
    action: waygate_quota::QuotaAction,
) -> waygate_quota::RateLimitPolicy {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    waygate_quota::RateLimitPolicy {
        id,
        tenant_id: "default".into(),
        name: "seed-policy".into(),
        scope,
        scope_value: scope_value.map(str::to_owned),
        bucket_capacity: 100,
        refill_per_second: 10.0,
        action,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) async fn state_with_rl_store(
    store: Arc<dyn waygate_quota::RateLimitPolicyStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Rate-limit mutations audit via record_required (fail-closed).
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    Arc::new(
        AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_rate_limit_policy_store(Some(store)),
    )
}

/// Admin session renders the create composer + per-row edit/delete forms.
#[tokio::test]
pub(crate) async fn rate_limits_admin_rows_render_action_forms() {
    let id = Uuid::from_u128(0x1111);
    let store = Arc::new(FakeRlStore::with(vec![rl_fixture(
        id,
        waygate_quota::QuotaScope::Tenant,
        None,
        waygate_quota::QuotaAction::Call,
    )]));
    let app = dashboard_router(state_with_rl_store(store).await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/rate_limits").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/rate_limits/create"),
        "create composer missing"
    );
    assert!(body.contains("<th>Actions</th>"), "Actions column missing");
    assert!(
        body.contains(&format!("/rate_limits/{id}/update")),
        "edit form action missing",
    );
    assert!(
        body.contains(&format!("/rate_limits/{id}/delete")),
        "delete form action missing",
    );
    assert!(
        !body.contains(r#"class="rl-empty""#),
        "legacy .rl-empty class still rendered",
    );
}

/// Create with admin + CSRF persists a policy and PRG-redirects clean.
#[tokio::test]
pub(crate) async fn rate_limits_create_persists_and_redirects() {
    let store = Arc::new(FakeRlStore::with(vec![]));
    let app = dashboard_router(
        state_with_rl_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/rate_limits/create",
        "csrf=dev-csrf&name=per-tenant&scope=tenant&scope_value=&action=call&bucket_capacity=50&refill_per_second=5",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("rl_error"), "create carried an error: {loc}");
    let policies = store.policies.lock().unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].name, "per-tenant");
    assert_eq!(policies[0].bucket_capacity, 50);
    assert_eq!(policies[0].refill_per_second, 5.0);
    assert_eq!(policies[0].scope, waygate_quota::QuotaScope::Tenant);
    assert!(policies[0].scope_value.is_none());
}

/// Create rejects a missing CSRF token with 403.
#[tokio::test]
pub(crate) async fn rate_limits_create_rejects_missing_csrf() {
    let store = Arc::new(FakeRlStore::with(vec![]));
    let app = dashboard_router(state_with_rl_store(store).await, DashboardAuth::Disabled);
    let (status, _loc) = post_form(
        app,
        "/rate_limits/create",
        "name=x&scope=tenant&action=call&bucket_capacity=1&refill_per_second=1",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Create reuses the REST validator: a non-tenant scope without a
/// scope_value is a BadRequest funneled into `?rl_error=`.
#[tokio::test]
pub(crate) async fn rate_limits_create_missing_scope_value_reports_error() {
    let store = Arc::new(FakeRlStore::with(vec![]));
    let app = dashboard_router(
        state_with_rl_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/rate_limits/create",
        "csrf=dev-csrf&name=x&scope=principal&scope_value=&action=call&bucket_capacity=1&refill_per_second=1",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("rl_error"),
        "expected validation error banner: {loc}"
    );
    assert!(
        store.policies.lock().unwrap().is_empty(),
        "invalid policy must not be persisted",
    );
}

/// Edit patches capacity + refill and PRG-redirects clean.
#[tokio::test]
pub(crate) async fn rate_limits_update_persists_and_redirects() {
    let id = Uuid::from_u128(0x2222);
    let store = Arc::new(FakeRlStore::with(vec![rl_fixture(
        id,
        waygate_quota::QuotaScope::Tenant,
        None,
        waygate_quota::QuotaAction::Call,
    )]));
    let app = dashboard_router(
        state_with_rl_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/rate_limits/{id}/update"),
        "csrf=dev-csrf&bucket_capacity=250&refill_per_second=2.5",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("rl_error"), "update carried an error: {loc}");
    let policies = store.policies.lock().unwrap();
    assert_eq!(policies[0].bucket_capacity, 250);
    assert_eq!(policies[0].refill_per_second, 2.5);
}

/// Delete removes the policy and PRG-redirects clean.
#[tokio::test]
pub(crate) async fn rate_limits_delete_removes_and_redirects() {
    let id = Uuid::from_u128(0x3333);
    let store = Arc::new(FakeRlStore::with(vec![rl_fixture(
        id,
        waygate_quota::QuotaScope::Tenant,
        None,
        waygate_quota::QuotaAction::Call,
    )]));
    let app = dashboard_router(
        state_with_rl_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(app, &format!("/rate_limits/{id}/delete"), "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("rl_error"), "delete carried an error: {loc}");
    assert!(
        store.policies.lock().unwrap().is_empty(),
        "policy not deleted"
    );
}

/// Deleting an unknown id is `Ok(false)` → the "no longer exists" banner.
#[tokio::test]
pub(crate) async fn rate_limits_delete_unknown_id_reports_error() {
    let store = Arc::new(FakeRlStore::with(vec![rl_fixture(
        Uuid::from_u128(0x4444),
        waygate_quota::QuotaScope::Tenant,
        None,
        waygate_quota::QuotaAction::Call,
    )]));
    let app = dashboard_router(state_with_rl_store(store).await, DashboardAuth::Disabled);
    let ghost = Uuid::from_u128(0x9999);
    let (status, loc) = post_form(
        app,
        &format!("/rate_limits/{ghost}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("rl_error"),
        "unknown-id delete must carry an error: {loc}"
    );
}

/// Security: the delete confirm must be a STATIC inline-JS string —
/// `p.name` must never be interpolated into it. Askama HTML-escapes the
/// name, but the browser HTML-decodes an attribute value before the JS
/// parser runs, so an escaped quote (`&#x27;`) decodes back to `'` and
/// breaks out of the `confirm('…')` string → stored XSS. The name is
/// only safe in the (plain HTML-attribute) aria-label. This pins the
/// static confirm so a re-introduced `{{ p.name }}` in the onsubmit
/// fails the test.
#[tokio::test]
pub(crate) async fn rate_limits_delete_confirm_is_static_no_name_interpolation() {
    let id = Uuid::from_u128(0x5151);
    let mut p = rl_fixture(
        id,
        waygate_quota::QuotaScope::Tenant,
        None,
        waygate_quota::QuotaAction::Call,
    );
    p.name = "evil'); alert(document.cookie); //".into();
    let store = Arc::new(FakeRlStore::with(vec![p]));
    let app = dashboard_router(state_with_rl_store(store).await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/rate_limits").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("onsubmit=\"return confirm('Delete this rate-limit policy?"),
        "delete confirm must be the static string (no name interpolation into inline JS)",
    );
    // The raw, quote-bearing name must never appear verbatim — askama
    // escapes it wherever it renders (the aria-label). Representation-
    // agnostic (askama may emit `&#x27;` or `&#39;` for the quote).
    assert!(
        !body.contains("evil'); alert(document.cookie)"),
        "the unescaped quote-breakout form must never render",
    );
}

/// The canonical tenant-scoped mount
/// (`/admin/t/{tenant}/rate_limits/{id}/...`) carries TWO path captures
/// (tenant + id) because `page_routes` is nested under `/t/{tenant}`.
/// A handler extracting `Path<String>` (one param) is rejected by axum
/// before its logic runs. This pins that the tenant-scoped edit/delete
/// actually reach the core. Both mounts must work (the create form has
/// no `{id}` so it was never affected).
#[tokio::test]
pub(crate) async fn rate_limits_tenant_scoped_delete_reaches_core() {
    let id = Uuid::from_u128(0x7777);
    let store = Arc::new(FakeRlStore::with(vec![rl_fixture(
        id,
        waygate_quota::QuotaScope::Tenant,
        None,
        waygate_quota::QuotaAction::Call,
    )]));
    let app = dashboard_router(
        state_with_rl_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/t/default/rate_limits/{id}/delete"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "tenant-scoped delete must reach the handler (got {status}, loc {loc})",
    );
    assert!(
        store.policies.lock().unwrap().is_empty(),
        "tenant-scoped delete must actually remove the policy",
    );
}

/// Policy sidebar group force-opens on /rate_limits
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn rate_limits_page_marks_policy_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/rate_limits").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/policies" aria-current="page""#),
        "the Policy destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/rate_limits" aria-current="page""#),
        "Rate limits nav link missing aria-current on legacy mount",
    );
}

/// Palette finds Rate limits in its catalogue.
#[tokio::test]
pub(crate) async fn rate_limits_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=rate").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Rate limits""#),
        "Rate limits missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Per-tenant token-bucket policies"#),
        "Rate limits hint missing from palette search result: {body}",
    );
}

/// Unenforced custom rules are absent from dashboard discovery.
#[tokio::test]
pub(crate) async fn inspection_rules_are_absent_from_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=inspection").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(r#""label":"Inspection rules""#),
        "Unenforced inspection rules appeared in palette search results: {body}",
    );
}

#[tokio::test]
async fn custom_inspection_dashboard_is_not_exposed() {
    for path in ["/inspection_rules", "/t/default/inspection_rules"] {
        let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
        let (status, _) = body_of(app, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    for path in ["/evidence", "/settings"] {
        let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
        let (status, body) = body_of(app, path).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("Inspection rules"));
    }
}
