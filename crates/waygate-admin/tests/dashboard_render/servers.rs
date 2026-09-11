//! Servers page: tabs, reload, config/session/identity — split from the
//! monolithic `dashboard_render.rs`; bodies verbatim, cut at the file's
//! own section markers.

use crate::common::*;

// ---- servers --------------------------------------------------------------

#[tokio::test]
pub(crate) async fn servers_page_lists_manifest() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/servers").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("example-messages"), "server name missing");
    // Disconnected pool → status column should show 'down'.
    assert!(body.contains("down"), "expected 'down' status");
    assert!(
        body.contains(">0 / 1<"),
        "expected zero connected lanes out of one configured lane: {body}"
    );
    assert!(
        body.contains(">0 / 2<"),
        "expected zero published tools and two classifications: {body}"
    );
    // Sidebar active state set correctly.
    assert!(body.contains(r#"href="/admin/servers""#));
}

#[tokio::test]
pub(crate) async fn servers_page_renders_admin_actions() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/servers").await;
    assert_eq!(status, StatusCode::OK);
    // The Reconnect / Clear-quarantine forms live in the per-server config
    // panel, not the table. The servers page exposes the expander that
    // loads that panel; the Reconnect form itself is asserted in
    // `server_config_fragment_renders_overview`.
    assert!(
        body.contains("/admin/servers/config?server=example-messages"),
        "per-server config expander missing"
    );
    // Server name drills down into the filtered Tools console.
    assert!(
        body.contains("/admin/tools?server=example-messages"),
        "drill-down link missing"
    );
    assert!(body.contains("Quarantine"), "quarantine column missing");
}

#[tokio::test]
pub(crate) async fn servers_reconnect_unknown_server_404() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/servers/reconnect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=dev-csrf&server=nope"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
pub(crate) async fn servers_reconnect_known_server_redirects() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/servers/reconnect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=dev-csrf&server=example-messages"))
                .unwrap(),
        )
        .await
        .unwrap();
    // Re-dial fails in tests (the fixture upstream is unreachable) but the
    // handler still PRG-redirects back to the servers page.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("/servers"), "redirect target wrong: {loc}");
}

#[tokio::test]
pub(crate) async fn servers_reconnect_rejects_missing_csrf() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/servers/reconnect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("server=example-messages"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn servers_refresh_catalog_unknown_server_404() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, _) = post_body(app, "/servers/catalog/refresh", "csrf=dev-csrf&server=nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
pub(crate) async fn servers_refresh_catalog_rejects_missing_csrf() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, _) = post_body(app, "/servers/catalog/refresh", "server=example-messages").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn servers_refresh_catalog_renders_a_failed_attempt() {
    let mut manifest = example_messages_manifest();
    manifest.url = Some("http://127.0.0.1:9/mcp".to_owned());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        (manifest.name.clone(), manifest),
    ])));
    let app = dashboard_router(
        Arc::new(base_admin_state_with_pool(pool)),
        DashboardAuth::Disabled,
    );

    let (status, body) = post_body(
        app,
        "/servers/catalog/refresh",
        "csrf=dev-csrf&server=example-messages",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Catalog refresh failed"), "{body}");
    assert!(
        body.contains("No replacement session was installed"),
        "{body}"
    );
}

// ---- Admin "Reload manifests" ----------------------------------------------

/// An `example-messages`-only manifest set identical to `example_messages_manifest()` except
/// `list_contacts` is re-classified Low→High — so a reload against
/// `state_with_manifests()` reports exactly one classification update.
pub(crate) fn bundle_content_with_changed_classification() -> String {
    let mut m = example_messages_manifest();
    for t in m.tools.iter_mut() {
        if t.name == "list_contacts" {
            t.risk = waygate_mcp::protocol::RiskTier::High;
        }
    }
    let mut set = BTreeMap::new();
    set.insert(m.name.clone(), m);
    waygate_upstream::serialize_manifest_set(&set).expect("serialize manifest set")
}

/// `example-messages` with `exchange` set (the base manifest has none) and no other
/// change. A reload must report an identity/tier update — NOT a no-op — even
/// though no classification or connection-shape changed.
pub(crate) fn bundle_content_with_changed_exchange() -> String {
    let mut m = example_messages_manifest();
    m.exchange = Some(waygate_upstream::ExchangeConfig {
        audience: "https://idp/upstream".into(),
        scope: None,
    });
    let mut set = BTreeMap::new();
    set.insert(m.name.clone(), m);
    waygate_upstream::serialize_manifest_set(&set).expect("serialize manifest set")
}

/// A manifest set with a single `transport: stdio` upstream. The dashboard
/// reload must refuse to apply this in the `prod` profile — exactly as
/// boot/SIGHUP keep it inert — rather than partially applying it.
pub(crate) fn bundle_content_with_stdio() -> String {
    let m = UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: "local-stdio".into(),
        transport: Transport::Stdio,
        protocol: Default::default(),
        url: None,
        command: Some(vec!["echo".into()]),
        tools: vec![],
        resources: vec![],
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: None,
    };
    let mut set = BTreeMap::new();
    set.insert(m.name.clone(), m);
    waygate_upstream::serialize_manifest_set(&set).expect("serialize manifest set")
}

/// The unchanged example-messages manifest serialized as a one-server bundle — the
/// seed for the in-memory store in the classifications tests.
pub(crate) fn example_messages_bundle_content() -> String {
    let mut set = BTreeMap::new();
    set.insert("example-messages".to_string(), example_messages_manifest());
    waygate_upstream::serialize_manifest_set(&set).expect("serialize manifest set")
}

/// Write a serialized manifest-set `content` to a fresh temp dir in the
/// per-file form `load_manifests` reads. Leaked (no cleanup) — fine for the
/// short-lived test process. Used to sync a `servers_dir` with a store so
/// the disk-truth render / write / reload paths see the same set the
/// store holds.
pub(crate) fn servers_dir_from_content(content: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("dashtest-servers-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let set = waygate_upstream::parse_manifest_set(content).expect("parse content for servers dir");
    waygate_upstream::write_manifest_set_to_dir(&dir, &set).expect("write servers dir");
    dir
}

/// A state with the example-messages manifest on disk (`servers_dir`) but NO
/// manifest store — exercises the disk-truth no-store gate: the tab finds
/// the server on disk but can't record a ledger snapshot, so editing is
/// read-only with the "needs a DB" note.
pub(crate) async fn state_with_servers_dir_no_store() -> Arc<AdminState> {
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    Arc::new(
        base_admin_state_with_pool(pool)
            .with_servers_dir(servers_dir_from_content(&example_messages_bundle_content())),
    )
}

pub(crate) async fn state_with_manifests_and_store(
    store: Option<waygate_manifest_store::SharedManifestStore>,
) -> Arc<AdminState> {
    // Default to "dev" — non-prod, so the reload prod-stdio gate is inert and
    // the existing reload tests exercise the apply path unchanged.
    state_with_store_and_profile(store, "dev").await
}

pub(crate) async fn state_with_store_and_profile(
    store: Option<waygate_manifest_store::SharedManifestStore>,
    profile: &'static str,
) -> Arc<AdminState> {
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    // The dashboard reads the deployment profile from the frozen-at-boot
    // SystemInfo snapshot; override just that field for the gate test.
    let mut system = waygate_admin::state::SystemInfo::unknown();
    system.deployment_profile = profile;
    // Disk-truth: the render / write / reload paths read the on-disk
    // set, so sync a servers_dir from the store's active bundle to keep disk
    // and the ledger in agreement.
    let servers_dir = match &store {
        Some(s) => s
            .active_bundle(waygate_core::TenantId::DEFAULT)
            .await
            .ok()
            .map(|b| servers_dir_from_content(&b.content)),
        None => None,
    };
    let mut st = base_admin_state_with_pool(pool)
        .with_manifest_store(store)
        .with_system_info(Arc::new(system));
    if let Some(dir) = servers_dir {
        st = st.with_servers_dir(dir);
    }
    Arc::new(st)
}

/// Like [`state_with_store_and_profile`] but also wires a `config_health`
/// signal, pre-set healthy or degraded, and hands the shared handle back
/// to the caller so a reload test can assert the signal transitions: a
/// dashboard reload must update config_health — clear it on success, set
/// it on a refusal.
pub(crate) async fn state_with_health_and_store(
    store: Option<waygate_manifest_store::SharedManifestStore>,
    profile: &'static str,
    start_degraded: bool,
) -> (Arc<AdminState>, waygate_upstream::SharedConfigHealth) {
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let mut system = waygate_admin::state::SystemInfo::unknown();
    system.deployment_profile = profile;
    let servers_dir = match &store {
        Some(s) => s
            .active_bundle(waygate_core::TenantId::DEFAULT)
            .await
            .ok()
            .map(|b| servers_dir_from_content(&b.content)),
        None => None,
    };
    let health: waygate_upstream::SharedConfigHealth =
        Arc::new(waygate_upstream::ConfigHealth::default());
    if start_degraded {
        health.set_degraded("prior SIGHUP refused — serving the previous set");
    } else {
        health.set_healthy("1 upstream(s) loaded from servers/*.yaml");
    }
    let mut st = base_admin_state_with_pool(pool)
        .with_manifest_store(store)
        .with_system_info(Arc::new(system))
        .with_config_health(health.clone());
    if let Some(dir) = servers_dir {
        st = st.with_servers_dir(dir);
    }
    (Arc::new(st), health)
}

pub(crate) async fn post_body(app: axum::Router, uri: &str, form: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
pub(crate) async fn servers_reload_button_gated_on_servers_dir() {
    // Reload reads the on-disk set, so the button is gated on a
    // configured servers_dir, NOT on a manifest store — it renders even
    // without a DB, and is hidden only when there is no servers_dir at all.
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_changed_classification());
    // servers_dir + store ⇒ button shows.
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/servers").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/servers/reload"),
        "reload form missing with a servers_dir configured"
    );
    // The button posts via hx-post, so the page must load htmx — without it
    // the form would submit a default GET and silently no-op.
    assert!(
        body.contains("htmx.min.js"),
        "servers page renders an hx-post button but does not load htmx"
    );

    // servers_dir WITHOUT a store ⇒ button still shows (no DB required).
    let app_nodb = dashboard_router(
        state_with_servers_dir_no_store().await,
        DashboardAuth::Disabled,
    );
    let (_, body_nodb) = body_of(app_nodb, "/servers").await;
    assert!(
        body_nodb.contains("/servers/reload"),
        "reload form must render with a servers_dir even without a manifest store"
    );

    // No servers_dir ⇒ hidden.
    let app2 = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (_, body2) = body_of(app2, "/servers").await;
    assert!(
        !body2.contains("/servers/reload"),
        "reload form must be hidden without a servers_dir"
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_no_servers_dir_returns_guidance() {
    // Reload reads the on-disk set (no DB store required). With no
    // servers_dir there is nothing to apply, so the handler returns
    // guidance rather than silently no-op'ing.
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No servers dir configured"),
        "expected no-servers-dir guidance, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_applies_active_bundle_classification() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_changed_classification());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("ledger v1"),
        "expected applied banner matching ledger v1, got: {body}"
    );
    assert!(
        body.contains("1 classification update"),
        "expected one classification update, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_labels_version_for_noncanonical_published_bundle() {
    // A published bundle whose stored YAML is valid but NOT canonical (here, a
    // leading comment) parses to the same on-disk set, but its raw content_hash
    // differs from the canonical disk hash. The reload version label must still
    // resolve to the bundle's version (v1), not 0 — it compares the bundle's
    // CANONICAL hash to disk, not its raw stored hash. A raw comparison would
    // mislabel a faithfully-published set as v0.
    let canonical = bundle_content_with_changed_classification();
    let noncanonical = format!("# staged out-of-band\n{canonical}");
    // Precondition: the two forms really do hash differently, so the test would
    // fail under the old raw comparison.
    assert_ne!(
        waygate_manifest_store::content_hash(&noncanonical),
        waygate_manifest_store::content_hash(&canonical),
        "the non-canonical form must hash differently or this test proves nothing",
    );
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&noncanonical);
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("ledger v1"),
        "a non-canonical published bundle must still label as ledger v1, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_reconciles_a_stale_turnstile_pointer() {
    // An out-of-band servers/*.yaml edit (or any drift) can leave the
    // turnstile pointer at a stale hash, after which every dashboard save
    // CAS-fails forever. A dashboard Reload must re-sync the pointer to the
    // actual on-disk hash so the operator's next save wins.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    // The pointer is stale — it points at a hash the on-disk set no longer has.
    store.force_pointer("deadbeef-stale-hash");
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );

    let (status, _body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);

    // After reload the pointer must equal the canonical on-disk hash (what the
    // write-path CAS compares against), not the stale value.
    let disk_hash = waygate_manifest_store::content_hash(
        &waygate_upstream::serialize_manifest_set(
            &waygate_upstream::parse_manifest_set(&example_messages_bundle_content()).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        store.current_pointer().as_deref(),
        Some(disk_hash.as_str()),
        "dashboard reload must reconcile the stale pointer to the on-disk hash",
    );
    assert_ne!(
        store.current_pointer().as_deref(),
        Some("deadbeef-stale-hash"),
        "the stale pointer must not survive the reload",
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_reports_identity_only_change_not_noop() {
    // A bundle that changes only `exchange` (or tier flags) is hot-applied
    // but touches no classification / connection shape. It must be reported
    // as an identity/tier update, not "no changes to apply".
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_changed_exchange());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("identity/tier update"),
        "expected an identity/tier update chip, got: {body}"
    );
    assert!(
        !body.contains("no changes to apply"),
        "an exchange-only change must not be reported as a no-op, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_refuses_prod_stdio_bundle() {
    // In the prod profile the dashboard reload must apply the same gate as
    // boot/SIGHUP: a bundle containing a `transport: stdio` upstream is
    // refused (fail-closed) rather than partially applied.
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_stdio());
    let app = dashboard_router(
        state_with_store_and_profile(Some(store), "prod").await,
        DashboardAuth::Disabled,
    );
    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("transport: stdio") && body.contains("refused"),
        "expected a prod-stdio refusal banner, got: {body}"
    );
    // Fail-closed: the apply path must NOT have run.
    assert!(
        !body.contains("Applied"),
        "prod-stdio set must not be applied, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_allows_stdio_bundle_in_dev() {
    // The same stdio bundle is allowed in the dev profile (dev keeps stdio,
    // with only a boot-time warn) — confirms the gate keys on the profile,
    // not merely on the presence of stdio.
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_stdio());
    let app = dashboard_router(
        state_with_store_and_profile(Some(store), "dev").await,
        DashboardAuth::Disabled,
    );
    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    // local-stdio isn't in the running set, so it reports as added /
    // restart-required — the point is it was not refused.
    assert!(
        !body.contains("refused"),
        "dev profile must not refuse a stdio bundle, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_rejects_missing_csrf() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_changed_classification());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, _) = post_body(app, "/servers/reload", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn servers_reload_success_clears_degraded_config_health() {
    // A SIGHUP may have left config_health degraded (broken
    // servers/*.yaml at reload time). A subsequent clean dashboard
    // reload applies the on-disk set and must flip the signal back to
    // healthy, so the Config STALE banner drops without a restart.
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_changed_classification());
    let (state, health) = state_with_health_and_store(Some(store), "dev", true).await;
    assert!(
        !health.snapshot().expect("health set").healthy,
        "precondition: config_health starts degraded",
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, _body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        health.snapshot().expect("health set").healthy,
        "a successful dashboard reload must clear the degraded config-health signal",
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_prod_refusal_marks_config_health_degraded() {
    // A refused reload keeps the previous (safe) set, so the running
    // config no longer matches disk. The signal must go degraded even
    // though the page also shows an inline refusal — otherwise the full
    // Servers page renders healthy after a refusal.
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_stdio());
    let (state, health) = state_with_health_and_store(Some(store), "prod", false).await;
    assert!(
        health.snapshot().expect("health set").healthy,
        "precondition: config_health starts healthy",
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("refused"),
        "expected a refusal banner, got: {body}"
    );
    assert!(
        !health.snapshot().expect("health set").healthy,
        "a prod-safety refusal must mark the config-health signal degraded",
    );
}

#[tokio::test]
pub(crate) async fn servers_reload_coupled_resource_shape_refusal_has_no_follow_on_effects() {
    use waygate_mcp::catalog::UpstreamCatalog as _;

    let mut fresh_manifest = example_messages_manifest();
    fresh_manifest.url = Some("http://127.0.0.1:9/mcp".to_owned());
    fresh_manifest.resources = vec![waygate_upstream::ResourceClassification {
        uri_prefix: "example-messages://attachment/".to_owned(),
        risk: waygate_mcp::protocol::RiskTier::High,
    }];
    let fresh_content = waygate_upstream::serialize_manifest_set(&BTreeMap::from([(
        fresh_manifest.name.clone(),
        fresh_manifest,
    )]))
    .expect("serialize coupled resource/shape edit");

    let store = InMemoryManifestStore::seeded(&fresh_content);
    store.force_pointer("stale-before-refused-reload");
    let shared_store: waygate_manifest_store::SharedManifestStore = store.clone();

    let old_manifest = example_messages_manifest();
    let old_url = old_manifest.url.clone();
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        (old_manifest.name.clone(), old_manifest),
    ])));
    let pool_handle = pool.clone();
    let reconcile_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = reconcile_calls.clone();
    let reconcile: waygate_admin::SharedCatalogReconcile = Arc::new(move |_manifests| {
        let seen = seen.clone();
        Box::pin(async move {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((1, 1))
        })
    });
    let health: waygate_upstream::SharedConfigHealth =
        Arc::new(waygate_upstream::ConfigHealth::default());
    health.set_healthy("precondition");

    let state = base_admin_state_with_pool(pool)
        .with_manifest_store(Some(shared_store))
        .with_catalog_reconcile(Some(reconcile))
        .with_config_health(health.clone())
        .with_servers_dir(servers_dir_from_content(&fresh_content));
    let app = dashboard_router(Arc::new(state), DashboardAuth::Disabled);

    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("refused before mutation"), "{body}");
    assert!(body.contains("Restart the gateway"), "{body}");
    assert_eq!(
        reconcile_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a refused manifest set must not replace the governed catalog",
    );
    assert_eq!(
        store.current_pointer().as_deref(),
        Some("stale-before-refused-reload"),
        "a refused manifest set must not advance the ledger pointer",
    );
    let stored = pool_handle
        .manifests()
        .into_iter()
        .find(|manifest| manifest.name == "example-messages")
        .expect("old example-messages manifest remains live");
    assert_eq!(stored.url, old_url);
    assert!(stored.resources.is_empty());
    assert!(
        !health.snapshot().expect("health set").healthy,
        "the operator surface must remain degraded until restart applies disk truth",
    );
    assert_eq!(
        pool_handle.resource_claims("example-messages").len(),
        0,
        "the refused resource claims must not become routable",
    );
}

#[tokio::test]
pub(crate) async fn servers_page_renders_accordion_and_loads_js() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/servers").await;
    assert_eq!(status, StatusCode::OK);
    // Each row gets an expander wired to the config fragment, plus the
    // hidden detail row and the toggle script.
    assert!(
        body.contains("data-accordion"),
        "expander button missing: {body}"
    );
    assert!(
        body.contains("/servers/config?server=example-messages"),
        "expander does not target the per-server config fragment"
    );
    assert!(
        body.contains("servers_accordion.js"),
        "accordion toggle script not loaded"
    );
    assert!(body.contains("cfg-row-1"), "detail row missing");
}

#[tokio::test]
pub(crate) async fn server_config_fragment_renders_overview() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/servers/config?server=example-messages&tab=overview").await;
    assert_eq!(status, StatusCode::OK);
    // Read-only overview: resolved isolation, identity tier, tool-risk split.
    assert!(body.contains("Overview"), "tab nav missing: {body}");
    assert!(
        body.contains("per_call"),
        "HTTP upstream should resolve to per_call isolation: {body}"
    );
    assert!(
        body.contains("Tier B"),
        "no exchange/tier_c ⇒ Tier B identity: {body}"
    );
    // example_messages_manifest: send_msg=High, list_contacts=Low ⇒ 1 high / 0 / 1 low.
    assert!(
        body.contains("1 high / 0 medium / 1 low"),
        "tool-risk breakdown wrong: {body}"
    );
    // Recovery action relocated into the panel (admin path under Disabled).
    assert!(
        body.contains("/servers/reconnect"),
        "Reconnect action missing from panel: {body}"
    );
    assert!(
        body.contains("/servers/catalog/refresh"),
        "Refresh catalog action missing from panel: {body}"
    );
    assert!(
        body.contains("0 connected / 1 configured"),
        "lane health missing from panel: {body}"
    );
    assert!(
        body.contains("0 published / 2 classified"),
        "published/classified inventory missing from panel: {body}"
    );
}

#[tokio::test]
pub(crate) async fn server_config_fragment_unknown_server_404() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, _) = body_of(app, "/servers/config?server=nope&tab=overview").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
pub(crate) async fn server_config_fragment_unknown_tab_404() {
    // The `?tab=` contract is real: an unimplemented tab is a 404, not a
    // silent fall-through to Overview.
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, _) = body_of(app, "/servers/config?server=example-messages&tab=bogus").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
pub(crate) async fn classifications_tab_editable_with_store() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(
        app,
        "/servers/config?server=example-messages&tab=classifications",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Editable form: posts to the save route, has a risk <select> and the
    // stale-edit base_hash guard, and lists the server's tools.
    assert!(
        body.contains("/servers/config/classifications"),
        "save form missing: {body}"
    );
    assert!(body.contains("risk_0"), "risk select missing");
    assert!(body.contains("base_hash"), "base_hash guard missing");
    assert!(body.contains("send_msg"), "tool row missing");
}

#[tokio::test]
pub(crate) async fn classifications_tab_readonly_without_store() {
    // No manifest store ⇒ degraded read-only with guidance, no editable form.
    let app = dashboard_router(
        state_with_servers_dir_no_store().await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(
        app,
        "/servers/config?server=example-messages&tab=classifications",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No manifest store configured"),
        "degraded note missing: {body}"
    );
    assert!(
        !body.contains("/servers/config/classifications"),
        "read-only tab must not render the save form"
    );
}

#[tokio::test]
pub(crate) async fn classifications_save_publishes_patched_bundle() {
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    // send_msg High→low, list_contacts Low→high; checkboxes omitted ⇒ false.
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}&n=2\
         &name_0=send_msg&risk_0=low&name_1=list_contacts&risk_1=high"
    );
    let (status, body) = post_body(app, "/servers/config/classifications", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Published v2"),
        "expected a published banner, got: {body}"
    );
    // The active bundle now reflects the patched classifications.
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let tools = &set.get("example-messages").unwrap().tools;
    let send = tools.iter().find(|t| t.name == "send_msg").unwrap();
    let list = tools.iter().find(|t| t.name == "list_contacts").unwrap();
    assert_eq!(send.risk, waygate_mcp::protocol::RiskTier::Low);
    assert_eq!(list.risk, waygate_mcp::protocol::RiskTier::High);
}

#[tokio::test]
pub(crate) async fn classifications_save_stale_hash_refused() {
    // A base_hash that doesn't match the active bundle ⇒ refuse (don't clobber
    // a concurrent edit). Fail-closed: nothing is published.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let form = "csrf=dev-csrf&server=example-messages&base_hash=stale&n=2\
                &name_0=send_msg&risk_0=low&name_1=list_contacts&risk_1=high";
    let (status, body) = post_body(app, "/servers/config/classifications", form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("changed since you opened"),
        "expected stale-edit refusal, got: {body}"
    );
    // Active bundle is unchanged (still v1's content; send_msg stays High).
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let send = set
        .get("example-messages")
        .unwrap()
        .tools
        .iter()
        .find(|t| t.name == "send_msg")
        .unwrap();
    assert_eq!(send.risk, waygate_mcp::protocol::RiskTier::High);
}

#[tokio::test]
pub(crate) async fn classifications_save_turnstile_lost_refused() {
    // The cross-replica turnstile. Here the on-disk base MATCHES the
    // form's base_hash, so the in-process stale-edit guard passes — but
    // another replica advanced the turnstile pointer out from under this
    // writer. The PG compare-and-swap must refuse, fail-closed: nothing is
    // published and the live set is unchanged. This is the multi-replica
    // clobber the in-process write lock alone cannot prevent.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    // Simulate replica B having already written: the pointer now holds some
    // other hash, not the on-disk base this request will present.
    store.force_pointer("a-hash-written-by-another-replica");
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    // base_hash == the real on-disk hash, so the disk-hash guard PASSES and we
    // exercise the turnstile CAS rather than the in-process disk check.
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}&n=2\
         &name_0=send_msg&risk_0=low&name_1=list_contacts&risk_1=high"
    );
    let (status, body) = post_body(app, "/servers/config/classifications", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Another replica changed the config"),
        "expected a cross-replica turnstile refusal, got: {body}"
    );
    // Fail-closed: nothing published; send_msg keeps its original High risk.
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let send = set
        .get("example-messages")
        .unwrap()
        .tools
        .iter()
        .find(|t| t.name == "send_msg")
        .unwrap();
    assert_eq!(send.risk, waygate_mcp::protocol::RiskTier::High);
}

#[tokio::test]
pub(crate) async fn classifications_save_rejects_missing_csrf() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, _) = post_body(
        app,
        "/servers/config/classifications",
        "server=example-messages",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn session_tab_editable_with_store() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/servers/config?server=example-messages&tab=session").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/servers/config/session"),
        "session save form missing: {body}"
    );
    assert!(body.contains("sess-isolation"), "isolation select missing");
    assert!(
        body.contains("sess-setup-recovery"),
        "setup-recovery policy select missing"
    );
    assert!(
        body.contains("sess-concurrency"),
        "concurrency input missing"
    );
    assert!(body.contains("base_hash"), "base_hash guard missing");
    // Session is connection-shape: the tab must say a restart is required.
    assert!(body.contains("restart"), "restart-required note missing");
}

#[tokio::test]
pub(crate) async fn session_tab_readonly_without_store() {
    let app = dashboard_router(
        state_with_servers_dir_no_store().await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/servers/config?server=example-messages&tab=session").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No manifest store configured"),
        "degraded note missing: {body}"
    );
    assert!(
        !body.contains("/servers/config/session"),
        "read-only tab must not render the save form"
    );
}

#[tokio::test]
pub(crate) async fn session_save_publishes_concurrency() {
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}&concurrency=1&isolation=&scope=&retry_on_setup_failure=disabled"
    );
    let (status, body) = post_body(app, "/servers/config/session", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Published v2"),
        "expected publish banner: {body}"
    );
    assert!(
        body.contains("restart"),
        "session apply hint must mention restart: {body}"
    );
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let session = set
        .get("example-messages")
        .unwrap()
        .session
        .as_ref()
        .unwrap();
    assert_eq!(session.concurrency, Some(1));
    assert_eq!(session.retry_on_setup_failure, Some(false));
}

#[tokio::test]
pub(crate) async fn session_save_guardrail_reuse_without_shared() {
    // The validate-before-publish step runs the manifest guardrail: HTTP/SSE
    // `isolation: reuse` without `scope: shared` is refused. Nothing published.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}&concurrency=&isolation=reuse&scope=&retry_on_setup_failure="
    );
    let (status, body) = post_body(app, "/servers/config/session", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("session.scope: shared"),
        "expected the reuse-without-shared guardrail, got: {body}"
    );
    // Fail-closed: the active bundle still has no session block.
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    assert!(set.get("example-messages").unwrap().session.is_none());
}

#[tokio::test]
pub(crate) async fn session_save_rejects_missing_csrf() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, _) = post_body(app, "/servers/config/session", "server=example-messages").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn identity_tab_editable_with_store() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/servers/config?server=example-messages&tab=identity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/servers/config/identity"),
        "identity save form missing: {body}"
    );
    assert!(body.contains("exchange_enabled"), "exchange toggle missing");
    assert!(body.contains("id-bearer"), "bearer env input missing");
    assert!(body.contains("id-cert"), "mTLS cert input missing");
    assert!(body.contains("id-peer"), "tier_c_peer input missing");
    assert!(body.contains("base_hash"), "base_hash guard missing");
    assert!(body.contains("restart"), "restart-required note missing");
}

#[tokio::test]
pub(crate) async fn identity_tab_readonly_without_store() {
    let app = dashboard_router(
        state_with_servers_dir_no_store().await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/servers/config?server=example-messages&tab=identity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No manifest store configured"),
        "degraded note missing: {body}"
    );
    assert!(
        !body.contains("/servers/config/identity"),
        "read-only tab must not render the save form"
    );
}

#[tokio::test]
pub(crate) async fn identity_save_publishes_exchange() {
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}\
         &exchange_enabled=on&exchange_audience=https://idp/upstream"
    );
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Published v2"),
        "expected publish banner: {body}"
    );
    assert!(
        body.contains("restart"),
        "identity hint must mention restart"
    );
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let m = set.get("example-messages").unwrap();
    assert_eq!(
        m.exchange.as_ref().unwrap().audience,
        "https://idp/upstream"
    );
}

#[tokio::test]
pub(crate) async fn identity_save_publishes_bearer_env_name_only() {
    // A static bearer alone (no exchange) publishes; we store only the env var
    // NAME, never a token value.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form =
        format!("csrf=dev-csrf&server=example-messages&base_hash={base_hash}&bearer_env=EXAMPLE_MESSAGES_TOKEN");
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Published v2"),
        "expected publish banner: {body}"
    );
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let m = set.get("example-messages").unwrap();
    assert_eq!(
        m.auth.as_ref().unwrap().bearer_env.as_deref(),
        Some("EXAMPLE_MESSAGES_TOKEN")
    );
}

#[tokio::test]
pub(crate) async fn identity_save_preserves_governed_catalog_probe_groups() {
    for (case, bearer_form, expected_bearer) in [
        (
            "replace bearer",
            "&bearer_env=EXAMPLE_MESSAGES_TOKEN_NEW",
            Some("EXAMPLE_MESSAGES_TOKEN_NEW"),
        ),
        ("remove bearer", "", None),
    ] {
        let mut manifest = example_messages_manifest();
        manifest.auth = Some(waygate_upstream::UpstreamAuth {
            bearer_env: Some("EXAMPLE_MESSAGES_TOKEN_OLD".into()),
            catalog_probe_groups: vec!["example-messages-admin".into()],
        });
        let mut set = BTreeMap::new();
        set.insert(manifest.name.clone(), manifest);
        let content = waygate_upstream::serialize_manifest_set(&set).unwrap();
        let store = InMemoryManifestStore::seeded(&content);
        let shared: waygate_manifest_store::SharedManifestStore = store.clone();
        let app = dashboard_router(
            state_with_manifests_and_store(Some(shared)).await,
            DashboardAuth::Disabled,
        );
        let base_hash = waygate_manifest_store::content_hash(&content);
        let form =
            format!("csrf=dev-csrf&server=example-messages&base_hash={base_hash}{bearer_form}");

        let (status, body) = post_body(app, "/servers/config/identity", &form).await;
        assert_eq!(status, StatusCode::OK, "{case}: {body}");
        assert!(body.contains("Published v2"), "{case}: {body}");

        let active = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
        let auth = active["example-messages"]
            .auth
            .as_ref()
            .expect("auth retained");
        assert_eq!(auth.bearer_env.as_deref(), expected_bearer, "{case}");
        assert_eq!(
            auth.catalog_probe_groups,
            ["example-messages-admin"],
            "{case}"
        );
    }
}

#[tokio::test]
pub(crate) async fn identity_save_refuses_exchange_plus_bearer() {
    // Both write Authorization: the exchanged token shadows the static bearer,
    // so the combo is refused by the guardrail. Nothing published.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}\
         &exchange_enabled=on&exchange_audience=https://idp/upstream&bearer_env=EXAMPLE_MESSAGES_TOKEN"
    );
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("mutually exclusive"),
        "expected the exchange/bearer guardrail, got: {body}"
    );
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let m = set.get("example-messages").unwrap();
    assert!(m.exchange.is_none() && m.auth.is_none());
}

#[tokio::test]
pub(crate) async fn identity_save_rejects_pem_value_in_mtls_path() {
    // A pasted PEM/key value in an mTLS path field is rejected, so key material
    // can't be serialized into the bundle as a "path".
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    // URL-encoded "-----BEGIN PRIVATE KEY-----" as the cert "path". gitleaks:allow
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}\
         &mtls_cert=-----BEGIN%20PRIVATE%20KEY-----"
    );
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("must be file PATHS"),
        "expected the mTLS path validation, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn identity_save_refuses_mtls_on_http_url() {
    // example-messages's url is http://; a client cert is only presented over TLS, so
    // valid cert+key paths still refuse (the https guard). Nothing published.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}\
         &mtls_cert=/etc/c.pem&mtls_key=/etc/k.pem"
    );
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("https://"),
        "expected the mTLS-needs-https guard, got: {body}"
    );
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    assert!(set.get("example-messages").unwrap().mtls.is_none());
}

#[tokio::test]
pub(crate) async fn identity_save_guardrail_tier_c_plus_exchange() {
    // The validate-before-publish step runs the mutual-exclusion guardrail:
    // tier_c_peer together with exchange is refused. Nothing published.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}\
         &exchange_enabled=on&exchange_audience=https://idp/upstream\
         &tier_c_peer=11111111-1111-1111-1111-111111111111"
    );
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("mutually exclusive"),
        "expected the tier_c/exchange guardrail, got: {body}"
    );
    // Fail-closed: the active bundle still has no exchange or tier_c_peer.
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    let m = set.get("example-messages").unwrap();
    assert!(m.exchange.is_none() && m.tier_c_peer.is_none());
}

#[tokio::test]
pub(crate) async fn identity_save_rejects_missing_csrf() {
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let app = dashboard_router(
        state_with_manifests_and_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, _) = post_body(app, "/servers/config/identity", "server=example-messages").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn identity_save_refuses_tier_a_required_without_exchange() {
    // The validate-before-publish step runs the new guard: tier_a_required
    // without exchange refuses every call, so it's rejected. Nothing published.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form =
        format!("csrf=dev-csrf&server=example-messages&base_hash={base_hash}&tier_a_required=on");
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("tier_a_required") && body.contains("exchange"),
        "expected the tier_a-requires-exchange guard, got: {body}"
    );
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    assert!(!set.get("example-messages").unwrap().tier_a_required);
}

#[tokio::test]
pub(crate) async fn identity_save_rejects_lowercase_bearer_token() {
    // A lowercase token value (e.g. a GitHub PAT) is env-var-name-shaped under
    // POSIX but not the UPPER_SNAKE_CASE convention, so it's rejected before it
    // can be stored as auth.bearer_env. Nothing published.
    let store = InMemoryManifestStore::seeded(&example_messages_bundle_content());
    let shared: waygate_manifest_store::SharedManifestStore = store.clone();
    let app = dashboard_router(
        state_with_manifests_and_store(Some(shared)).await,
        DashboardAuth::Disabled,
    );
    let base_hash = waygate_manifest_store::content_hash(&example_messages_bundle_content());
    let form = format!(
        "csrf=dev-csrf&server=example-messages&base_hash={base_hash}&bearer_env=ghp_abc123def"
    );
    let (status, body) = post_body(app, "/servers/config/identity", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("UPPER_SNAKE_CASE"),
        "expected the env-var-name validation, got: {body}"
    );
    let set = waygate_upstream::parse_manifest_set(&store.active_content()).unwrap();
    assert!(set.get("example-messages").unwrap().auth.is_none());
}

#[tokio::test]
pub(crate) async fn servers_drilldown_url_encodes_reserved_chars() {
    // UpstreamManifest.name is a free string; the drill-down query value must
    // be percent-encoded so a name with reserved chars doesn't break the
    // Tools link.
    let mut m = example_messages_manifest();
    m.name = "weird%name 42".into();
    let mut manifests = BTreeMap::new();
    manifests.insert(m.name.clone(), m);
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let state = Arc::new(base_admin_state_with_pool(pool));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/servers").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("?server=weird%25name%2042"),
        "drill-down must URL-encode reserved characters"
    );
    // The visible label still shows the raw name.
    assert!(body.contains("weird%name 42"), "raw name label missing");
}

/// A dashboard Reload applies the set to the live pool FIRST and reconciles
/// the governed catalog after — the doorbell/SIGHUP order, which is the
/// legacy baseline: manifest-mode resolution overlays catalog risk
/// unconditionally, so a catalog-first commit would let a still-serving
/// legacy contract authorize under the new (possibly lower) risk.
/// Annotation-mode safety does not depend on this ordering — the resolver's
/// generation binding refuses mixed catalog/manifest states.
#[tokio::test]
pub(crate) async fn servers_reload_reconciles_catalog_after_applying() {
    use waygate_mcp::catalog::UpstreamCatalog as _;
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_changed_classification());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let pool_handle = pool.clone();
    let risk_before = pool_handle
        .tool_facts("example-messages", "list_contacts")
        .risk;

    let seen = calls.clone();
    let observer = pool.clone();
    let reconcile: waygate_admin::SharedCatalogReconcile = Arc::new(move |manifests| {
        let seen = seen.clone();
        let observer = observer.clone();
        Box::pin(async move {
            assert!(
                manifests.contains_key("example-messages"),
                "the reconcile must receive the applied manifest set",
            );
            assert_ne!(
                observer
                    .tool_facts("example-messages", "list_contacts")
                    .risk,
                waygate_mcp::protocol::RiskTier::Low,
                "the pool must already serve the applied set when the reconcile runs",
            );
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((1, manifests.len() as u64))
        })
    });

    let servers_dir = store
        .active_bundle(waygate_core::TenantId::DEFAULT)
        .await
        .ok()
        .map(|b| servers_dir_from_content(&b.content));
    let mut st = base_admin_state_with_pool(pool)
        .with_manifest_store(Some(store))
        .with_catalog_reconcile(Some(reconcile));
    if let Some(dir) = servers_dir {
        st = st.with_servers_dir(dir);
    }
    let app = dashboard_router(Arc::new(st), DashboardAuth::Disabled);

    let (status, _body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::OK, "reload must succeed");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the reconcile must run exactly once, after the pool applied",
    );
    assert_ne!(
        pool_handle
            .tool_facts("example-messages", "list_contacts")
            .risk,
        risk_before,
        "the reload must have applied the changed classification",
    );
}

/// A failing catalog reconcile after an applied reload reports honestly: the
/// pool HAS applied (that mutation cannot be pretended away), the response
/// names the failure, and config health degrades until the reload task's
/// retry converges the catalog.
#[tokio::test]
pub(crate) async fn servers_reload_reports_reconcile_failure_after_applying() {
    use waygate_mcp::catalog::UpstreamCatalog as _;
    let store: waygate_manifest_store::SharedManifestStore =
        InMemoryManifestStore::seeded(&bundle_content_with_changed_classification());
    let reconcile: waygate_admin::SharedCatalogReconcile =
        Arc::new(|_manifests| Box::pin(async { Err("catalog database unavailable".to_string()) }));

    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let pool_handle = pool.clone();
    let risk_before = pool_handle
        .tool_facts("example-messages", "list_contacts")
        .risk;
    let health: waygate_upstream::SharedConfigHealth =
        Arc::new(waygate_upstream::ConfigHealth::default());
    let servers_dir = store
        .active_bundle(waygate_core::TenantId::DEFAULT)
        .await
        .ok()
        .map(|b| servers_dir_from_content(&b.content));
    let mut st = base_admin_state_with_pool(pool)
        .with_manifest_store(Some(store))
        .with_catalog_reconcile(Some(reconcile))
        .with_config_health(health.clone());
    if let Some(dir) = servers_dir {
        st = st.with_servers_dir(dir);
    }
    let app = dashboard_router(Arc::new(st), DashboardAuth::Disabled);

    let (status, body) = post_body(app, "/servers/reload", "csrf=dev-csrf").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the failure renders as a result fragment"
    );
    assert!(
        body.contains("catalog reconcile"),
        "the response must name the reconcile failure: {body}"
    );
    assert_ne!(
        pool_handle
            .tool_facts("example-messages", "list_contacts")
            .risk,
        risk_before,
        "the applied pool reload must be reported truthfully, not rolled back in prose",
    );
    let snapshot = health.snapshot().expect("health set");
    assert!(
        !snapshot.healthy,
        "config health must degrade until the reload task's retry converges the catalog",
    );
}

/// Annotation mode's operator view must show the ENFORCED facts: the legacy
/// `side_effects`/`pii` manifest flags are required-false in this mode while
/// the runtime conservatively forces both facts true until claim enforcement
/// lands — echoing the raw flags would report the opposite of what
/// authorization and audit use. The edit form also offers no legacy
/// checkboxes, so a save writes the required-false values.
#[tokio::test]
pub(crate) async fn classifications_show_enforced_facts_in_annotation_mode() {
    let mut m = example_messages_manifest();
    m.classification_mode = waygate_upstream::ClassificationMode::McpAnnotations;
    for t in &mut m.tools {
        t.side_effects = false;
        t.pii = false;
        t.approved_behavior_hash = Some("a".repeat(64));
    }
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), m);
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let app = dashboard_router(
        Arc::new(base_admin_state_with_pool(pool)),
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(
        app,
        "/servers/config?server=example-messages&tab=classifications",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("annotation mode: conservative"),
        "the view must show the enforced conservative posture: {body}"
    );
    assert!(
        !body.contains("name=\"se_0\""),
        "annotation mode must not offer the legacy side-effects checkbox: {body}"
    );
}
