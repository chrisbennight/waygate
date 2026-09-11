//! End-to-end proof of LIVE RE-DIAL against real streamable-HTTP
//! upstreams. A connection-shape change that keeps the same slot count
//! (here: a `url` change with `concurrency: 1`) is applied by tearing down the
//! old session and re-dialing the new shape in place — no restart.
//!
//! Two tagged mock upstreams, `A` and `B`, each report their own id from
//! `call_tool` and count the calls they serve. Under `isolation: reuse` a call
//! runs on the slot's stored session, so the id a call returns proves WHICH
//! live session the slot currently holds — not merely which url the manifest
//! records. The test connects to `A`, re-dials to `B`, and asserts traffic
//! moves to `B` while `A` stops receiving calls (a clean swap, no leak to the
//! old shape) and the upstream never drops out of `connected`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
    Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::net::TcpListener;

use waygate_mcp::audit::{AuditEvent, EvidenceError, EvidenceRecorder, InMemorySink};
use waygate_mcp::catalog::{ResolvedInvocationTool, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::{AuthMethod, Principal};
use waygate_upstream::pool::QuarantineThreshold;
use waygate_upstream::{
    CatalogFreshnessTrigger, CatalogRefreshOutcome, CatalogRefreshReport, ScheduledCatalogRefresh,
    SessionConfig, SessionIsolation, ToolClassification, Transport, UpstreamManifest, UpstreamPool,
};

/// Mock upstream that tags every `call_tool` with its own id and counts the
/// calls it serves, so a test can prove which live session a call ran on. The
/// `ping` tool's input-schema `properties` are configurable so two mocks can
/// advertise DIFFERENT schemas for the same tool name — exercising the
/// schema-drift detection a live rebuild must run on its freshly-dialed
/// connection.
#[derive(Clone)]
struct TaggedUpstream {
    id: &'static str,
    calls: Arc<AtomicUsize>,
    schema_props: serde_json::Value,
}

#[derive(Clone)]
struct DynamicCatalogUpstream {
    control: Arc<DynamicCatalogControl>,
}

#[derive(Default)]
struct DynamicCatalogControl {
    expanded: AtomicBool,
    reverse_order: AtomicBool,
    changed_schema: AtomicBool,
    operation_schema: AtomicBool,
    expanded_operation_enum: AtomicBool,
    alternate_schema: AtomicBool,
    changed_output_schema: AtomicBool,
    /// Advertise `reddit_search` with an output schema rooted at
    /// `type: "array"` — the shape a `Vec<T>` return produces, and one a
    /// strict MCP client rejects the whole `tools/list` response over.
    array_rooted_output_schema: AtomicBool,
    fail_list: AtomicBool,
    fail_next_lists: AtomicUsize,
    delay_list: AtomicBool,
    block_list: AtomicBool,
    list_release: tokio::sync::Notify,
    blocked_list_started: tokio::sync::Notify,
    paginate: AtomicBool,
    empty_next_cursor: AtomicBool,
    endless_pages: AtomicBool,
    /// SEP-2549 `ttlMs` stamped on the first `tools/list` page (`None` =
    /// no hint, the legacy posture).
    ttl_ms_first_page: std::sync::Mutex<Option<u64>>,
    /// `ttlMs` stamped on cursor-addressed (later) pages.
    ttl_ms_later_pages: std::sync::Mutex<Option<u64>>,
    /// Server-side instant of the first `tools/list` page served, so a
    /// test can prove the reader's freshness anchor precedes it.
    first_list_at: std::sync::Mutex<Option<std::time::Instant>>,
    active_lists: AtomicUsize,
    list_calls: AtomicUsize,
    max_active_lists: AtomicUsize,
}

struct GatedBestEffortSink {
    started: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    inner: InMemorySink,
}

impl GatedBestEffortSink {
    fn new() -> Self {
        Self {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
            inner: InMemorySink::new(),
        }
    }
}

#[async_trait]
impl EvidenceRecorder for GatedBestEffortSink {
    async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
        self.inner.record_required(event).await
    }

    async fn record_chained_best_effort(&self, event: AuditEvent) {
        self.inner.record_chained_best_effort(event).await;
    }

    async fn record_best_effort(&self, event: AuditEvent) {
        self.started.notify_one();
        self.release
            .acquire()
            .await
            .expect("test submission gate remains open")
            .forget();
        self.inner.record_best_effort(event).await;
    }
}

impl ServerHandler for DynamicCatalogUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("dynamic-catalog-upstream", "0.0.0"))
            .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let expanded = self.control.expanded.load(Ordering::SeqCst);
        let changed_schema = self.control.changed_schema.load(Ordering::SeqCst);
        let operation_schema = self.control.operation_schema.load(Ordering::SeqCst);
        let list_call = self.control.list_calls.fetch_add(1, Ordering::SeqCst);
        self.control
            .first_list_at
            .lock()
            .unwrap()
            .get_or_insert_with(std::time::Instant::now);
        if self
            .control
            .fail_next_lists
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(McpError::internal_error(
                "injected one-shot tools/list failure",
                None,
            ));
        }
        let alternate_schema = self.control.alternate_schema.load(Ordering::SeqCst);
        let changed_output_schema = self.control.changed_output_schema.load(Ordering::SeqCst);
        let array_rooted_output_schema = self
            .control
            .array_rooted_output_schema
            .load(Ordering::SeqCst);
        let paginate = self.control.paginate.load(Ordering::SeqCst);
        let empty_next_cursor = self.control.empty_next_cursor.load(Ordering::SeqCst);
        let endless_pages = self.control.endless_pages.load(Ordering::SeqCst);
        let cursor = request.and_then(|request| request.cursor);
        let active = self.control.active_lists.fetch_add(1, Ordering::SeqCst) + 1;
        self.control
            .max_active_lists
            .fetch_max(active, Ordering::SeqCst);
        if self.control.block_list.load(Ordering::SeqCst) {
            self.control.blocked_list_started.notify_one();
            self.control.list_release.notified().await;
        } else if self.control.delay_list.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.control.active_lists.fetch_sub(1, Ordering::SeqCst);
        if self.control.fail_list.load(Ordering::SeqCst) {
            return Err(McpError::internal_error(
                "injected tools/list failure",
                None,
            ));
        }
        let schema_value = if operation_schema {
            let mut operations = vec!["projects.read"];
            if self.control.expanded_operation_enum.load(Ordering::SeqCst) {
                operations.push("certificatePolicies.update");
            }
            serde_json::json!({
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": operations,
                    }
                },
                "required": ["operation"]
            })
        } else if alternate_schema {
            let property = if list_call.is_multiple_of(2) {
                "even_lane"
            } else {
                "odd_lane"
            };
            let mut properties = serde_json::Map::new();
            properties.insert(property.to_owned(), serde_json::json!({"type": "string"}));
            serde_json::json!({
                "type": "object",
                "properties": properties,
            })
        } else if changed_schema {
            serde_json::json!({
                "type": "object",
                "properties": {"changed": {"type": "string"}}
            })
        } else {
            serde_json::json!({"type": "object"})
        };
        let schema = Arc::new(schema_value.as_object().unwrap().clone());
        let mut reddit = Tool::new(
            "reddit_search".to_string(),
            "search reddit".to_string(),
            schema.clone(),
        );
        if changed_output_schema {
            reddit.output_schema = Some(Arc::new(
                serde_json::json!({
                    "type": "object",
                    "properties": {"results": {"type": "array"}}
                })
                .as_object()
                .expect("output schema object")
                .clone(),
            ));
        }
        if array_rooted_output_schema {
            reddit.output_schema = Some(Arc::new(
                serde_json::json!({
                    "type": "array",
                    "items": {"type": "object"}
                })
                .as_object()
                .expect("output schema object")
                .clone(),
            ));
        }
        let twitter = Tool::new(
            "twitter_search".to_string(),
            "search twitter".to_string(),
            schema,
        );
        // Per-page SEP-2549 hint: the cursorless first page and later pages
        // carry independently configurable hints so a test can prove the
        // reader keeps the strictest one.
        let page_ttl = if cursor.is_none() {
            *self.control.ttl_ms_first_page.lock().unwrap()
        } else {
            *self.control.ttl_ms_later_pages.lock().unwrap()
        };
        let stamp = |listed: ListToolsResult| match page_ttl {
            Some(ttl) => listed.with_ttl_ms(ttl),
            None => listed,
        };
        if endless_pages {
            let page = cursor
                .as_deref()
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap_or(0);
            let mut listed = ListToolsResult::with_all_items(vec![reddit]);
            listed.next_cursor = Some((page + 1).to_string());
            return Ok(stamp(listed));
        }
        if paginate {
            return match cursor.as_deref() {
                None => {
                    let mut listed = ListToolsResult::with_all_items(vec![reddit]);
                    listed.next_cursor = Some("twitter-page".to_owned());
                    Ok(stamp(listed))
                }
                Some("twitter-page") => Ok(stamp(ListToolsResult::with_all_items(vec![twitter]))),
                Some(other) => Err(McpError::invalid_params(
                    format!("unexpected cursor `{other}`"),
                    None,
                )),
            };
        }
        if empty_next_cursor {
            return match cursor.as_deref() {
                None => {
                    let mut listed = ListToolsResult::with_all_items(vec![reddit]);
                    listed.next_cursor = Some(String::new());
                    Ok(stamp(listed))
                }
                Some("") => Ok(stamp(ListToolsResult::with_all_items(vec![twitter]))),
                Some(other) => Err(McpError::invalid_params(
                    format!("unexpected cursor `{other}`"),
                    None,
                )),
            };
        }
        let mut tools = vec![reddit];
        if expanded {
            tools.push(twitter);
        }
        if self.control.reverse_order.load(Ordering::SeqCst) {
            tools.reverse();
        }
        Ok(stamp(ListToolsResult::with_all_items(tools)))
    }

    /// Echo the requested tool name so a caller can prove dispatch actually
    /// reached this upstream, not just that the descriptor was listed.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        Ok(CallToolResult::success(vec![Content::text(request.name.to_string())]).into())
    }
}

async fn spawn_dynamic_catalog() -> (std::net::SocketAddr, Arc<DynamicCatalogControl>) {
    let control = Arc::new(DynamicCatalogControl::default());
    let upstream = DynamicCatalogUpstream {
        control: control.clone(),
    };
    let svc = StreamableHttpService::new(
        move || Ok(upstream.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app = axum::Router::new().nest_service("/mcp", svc);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, control)
}

impl ServerHandler for TaggedUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("tagged-upstream", "0.0.0"))
            .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = serde_json::json!({"type": "object", "properties": self.schema_props})
            .as_object()
            .cloned()
            .unwrap();
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "ping".to_string(),
            "identifies the serving upstream".to_string(),
            Arc::new(schema),
        )]))
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CallToolResult::success(vec![Content::text(self.id)]).into())
    }
}

/// Spawn a tagged mock upstream (empty `ping` schema); returns its address and
/// the per-upstream call counter.
async fn spawn_tagged(id: &'static str) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    spawn_tagged_schema(id, serde_json::json!({})).await
}

/// Like [`spawn_tagged`] but with custom `ping` input-schema `properties`, so a
/// test can stand up two upstreams whose same-named tool has a DIFFERENT schema.
async fn spawn_tagged_schema(
    id: &'static str,
    schema_props: serde_json::Value,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let upstream = TaggedUpstream {
        id,
        calls: calls.clone(),
        schema_props,
    };
    let svc = StreamableHttpService::new(
        move || Ok(upstream.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app = axum::Router::new().nest_service("/mcp", svc);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, calls)
}

/// A black-hole listener: accepts TCP connections but never speaks MCP (never
/// reads or responds), so a dial's connect succeeds but the handshake stalls —
/// exercising the per-lane re-dial timeout.
async fn spawn_black_hole() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                // Park the accepted socket open forever without responding.
                Ok((sock, _)) => {
                    tokio::spawn(async move {
                        let _held = sock;
                        std::future::pending::<()>().await;
                    });
                }
                Err(_) => return,
            }
        }
    });
    addr
}

/// `reuse` + `concurrency: 1`: a single slot whose stored session every call
/// runs on — so the id a call returns reflects the slot's LIVE session, which
/// is exactly what a live re-dial swaps.
fn manifest_at(addr: std::net::SocketAddr) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: "mock".into(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some(format!("http://{addr}/mcp")),
        command: None,
        tools: vec![ToolClassification::new("ping", RiskTier::Low, false, false)],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: Some(SessionConfig {
            concurrency: Some(1),
            isolation: Some(SessionIsolation::Reuse),
            scope: None,
            retry_on_setup_failure: None,
        }),
    }
}

fn dynamic_manifest_at(addr: std::net::SocketAddr) -> UpstreamManifest {
    let mut manifest = manifest_at(addr);
    manifest.tools = ["reddit_search", "twitter_search"]
        .into_iter()
        .map(|name| ToolClassification::new(name, RiskTier::Low, false, false))
        .collect();
    manifest
}

fn admin_principal() -> Principal {
    Principal {
        sub: "catalog-operator".into(),
        email: None,
        groups: vec![],
        issuer: "https://auth.example.test/".into(),
        scopes: vec!["mcp:admin".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn refresh_catalog(pool: &UpstreamPool) -> Option<CatalogRefreshReport> {
    refresh_catalog_for(pool, "mock").await
}

async fn refresh_catalog_for(pool: &UpstreamPool, server: &str) -> Option<CatalogRefreshReport> {
    let actor = admin_principal();
    pool.refresh_server_catalog(server, &actor).await
}

async fn call_id(pool: &UpstreamPool) -> String {
    let res = pool
        .call_tool("mock", "ping", None, None, None)
        .await
        .expect("call_tool ping");
    res.content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("ping must return a text id")
}

#[tokio::test]
async fn invocation_snapshot_captures_the_connected_published_input_schema() {
    let schema_properties = serde_json::json!({
        "message": {"type": "string"}
    });
    let (addr, _calls) = spawn_tagged_schema("schema-source", schema_properties.clone()).await;
    let pool =
        UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest_at(addr))])).await;

    let ResolvedInvocationTool::Ready(snapshot) = pool
        .resolve_invocation_tool("default", "mock", "ping")
        .await
    else {
        panic!("connected manifest tool must resolve to an invocation snapshot");
    };

    assert_eq!(
        snapshot.input_schema(),
        Some(&serde_json::json!({
            "type": "object",
            "properties": schema_properties,
        })),
    );
}

#[tokio::test]
async fn forced_catalog_refresh_replaces_a_healthy_session_and_publishes_new_tools() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut map = BTreeMap::new();
    map.insert("mock".into(), dynamic_manifest_at(addr));
    let pool = UpstreamPool::connect(map).await;
    let epoch = pool.tool_catalog_epoch();
    let mut changes = epoch.subscribe();

    let initial = pool.list_tools("mock").await.expect("initial tools/list");
    assert_eq!(
        initial.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>(),
        vec!["reddit_search"]
    );

    control.expanded.store(true, Ordering::SeqCst);
    assert!(pool.reconnect_one("mock").await);
    assert_eq!(
        pool.list_tools("mock")
            .await
            .expect("cached tools after healthy reconnect")
            .len(),
        1,
        "the recovery-only reconnect must leave a healthy session untouched",
    );

    let report = refresh_catalog(&pool).await.expect("known upstream");
    assert_eq!(report.outcome, CatalogRefreshOutcome::Updated);
    assert!(report.session_replaced);
    assert_eq!(report.before_tool_count, 1);
    assert_eq!(report.after_tool_count, 2);
    assert_eq!(report.added, vec!["twitter_search"]);
    assert!(report.removed.is_empty());
    assert!(report.schema_changed.is_empty());
    tokio::time::timeout(Duration::from_secs(1), changes.changed())
        .await
        .expect("changed catalog advances the epoch promptly")
        .expect("catalog epoch sender remains live");
    assert_eq!(epoch.current(), 1);

    let refreshed = pool.list_tools("mock").await.expect("refreshed tools/list");
    assert_eq!(
        refreshed
            .iter()
            .map(|t| t.name.as_ref())
            .collect::<Vec<_>>(),
        vec!["reddit_search", "twitter_search"]
    );

    control.reverse_order.store(true, Ordering::SeqCst);
    let unchanged = refresh_catalog(&pool).await.expect("known upstream");
    assert_eq!(unchanged.outcome, CatalogRefreshOutcome::Unchanged);
    assert!(unchanged.session_replaced);
    assert_eq!(epoch.current(), 1, "an unchanged catalog must not notify");
    assert!(matches!(changes.has_changed(), Ok(false)));
}

#[tokio::test]
async fn live_rebuild_with_reordered_descriptors_stays_notification_silent() {
    let (addr_a, control_a) = spawn_dynamic_catalog().await;
    control_a.expanded.store(true, Ordering::SeqCst);
    let (addr_b, control_b) = spawn_dynamic_catalog().await;
    control_b.expanded.store(true, Ordering::SeqCst);
    control_b.reverse_order.store(true, Ordering::SeqCst);

    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr_a),
    )]))
    .await;
    let epoch = pool.tool_catalog_epoch();

    let mut resized = dynamic_manifest_at(addr_b);
    resized.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    let report = pool
        .reload_manifests(&BTreeMap::from([("mock".to_owned(), resized)]))
        .await;

    assert_eq!(report.redialed, vec!["mock"]);
    assert_eq!(
        epoch.current(),
        0,
        "descriptor order alone must not notify during a rebuild",
    );
}

#[tokio::test]
async fn forced_catalog_refresh_exhausts_paginated_tools_list() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await;

    control.paginate.store(true, Ordering::SeqCst);
    let report = refresh_catalog(&pool).await.expect("known upstream");

    assert_eq!(report.outcome, CatalogRefreshOutcome::Updated);
    assert_eq!(report.added, vec!["twitter_search"]);
    let names: Vec<String> = pool
        .list_tools("mock")
        .await
        .expect("refreshed tools/list")
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert_eq!(names, vec!["reddit_search", "twitter_search"]);
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "twitter", 10)
        .expect("index search")
        .expect("non-empty query");
    assert_eq!(indexed, vec!["twitter_search"]);
}

#[tokio::test]
async fn empty_tools_list_cursor_is_followed_as_an_opaque_value() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control.empty_next_cursor.store(true, Ordering::SeqCst);
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await;

    let names: Vec<String> = pool
        .list_tools("mock")
        .await
        .expect("tools/list")
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert_eq!(names, vec!["reddit_search", "twitter_search"]);
}

#[tokio::test]
async fn distinct_cursor_stream_is_bounded_and_preserves_old_catalog() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await;
    let epoch = pool.tool_catalog_epoch();
    control.endless_pages.store(true, Ordering::SeqCst);

    let report = refresh_catalog(&pool).await.expect("known upstream");

    assert_eq!(report.outcome, CatalogRefreshOutcome::Failed);
    assert!(!report.session_replaced);
    let names: Vec<String> = pool
        .list_tools("mock")
        .await
        .expect("prior tools/list")
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert_eq!(names, vec!["reddit_search"]);
    assert_eq!(epoch.current(), 0, "a failed refresh must not notify");
}

#[tokio::test]
async fn reconnect_bounds_tools_list_with_redial_timeout() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control.block_list.store(true, Ordering::SeqCst);
    let pool = Arc::new(
        UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
            "mock".to_owned(),
            dynamic_manifest_at(addr),
        )]))
        .with_redial_dial_timeout(Duration::from_secs(2)),
    );

    let reconnect_pool = pool.clone();
    let reconnect = tokio::spawn(async move { reconnect_pool.reconnect_one("mock").await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while control.active_lists.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reconnect reached tools/list");
    assert!(!reconnect.await.expect("reconnect task"));
    assert!(!pool.is_connected("mock").await);

    control.block_list.store(false, Ordering::SeqCst);
    control.list_release.notify_one();
    assert!(pool.reconnect_one("mock").await);
    assert!(pool.is_connected("mock").await);
}

#[tokio::test]
async fn output_schema_only_refresh_is_reported_as_updated() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await;
    control.changed_output_schema.store(true, Ordering::SeqCst);

    let report = refresh_catalog(&pool).await.expect("known upstream");

    assert_eq!(report.outcome, CatalogRefreshOutcome::Updated);
    assert_eq!(report.schema_changed, vec!["reddit_search"]);
    let reddit = pool
        .list_tools("mock")
        .await
        .expect("refreshed tools/list")
        .into_iter()
        .find(|tool| tool.name.as_ref() == "reddit_search")
        .expect("reddit tool");
    assert!(reddit.output_schema.is_some());
}

/// A tool whose advertised output schema cannot describe a
/// `structuredContent` object is published WITHOUT that schema, and the
/// rest of the upstream's catalog is unaffected.
///
/// This is the containment contract: a strict MCP client validates the
/// whole `tools/list` response in one pass, so forwarding one malformed
/// schema costs every tool the gateway serves, not just the bad one.
#[tokio::test]
async fn non_object_rooted_output_schema_is_stripped_without_dropping_the_catalog() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    // Publish a second, conforming tool so the test can prove containment:
    // the bad definition must cost only itself.
    control.expanded.store(true, Ordering::SeqCst);
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await;

    let tools = pool.list_tools("mock").await.expect("connected upstream");

    // The offending tool is still advertised and still callable — only the
    // unsatisfiable output contract is gone.
    let reddit = tools
        .iter()
        .find(|tool| tool.name.as_ref() == "reddit_search")
        .expect("offending tool stays in the catalog");
    assert!(
        reddit.output_schema.is_none(),
        "an output schema that is not object-rooted must not be forwarded",
    );
    assert!(
        reddit.input_schema.contains_key("type"),
        "stripping the output schema must leave the input contract intact",
    );
    // Every sibling survives: one bad definition must not cost the catalog.
    assert!(
        tools
            .iter()
            .any(|tool| tool.name.as_ref() == "twitter_search"),
        "sibling tools must be unaffected",
    );

    // Actually DISPATCH it. "Strip, don't drop" is only the right trade if
    // the tool still works, so that has to be exercised rather than inferred
    // from the descriptor: a regression that kept the tool listed but broke
    // dispatch would otherwise leave this test green.
    let called = pool
        .call_tool("mock", "reddit_search", None, None, None)
        .await
        .expect("a tool whose output schema was stripped must still dispatch");
    assert_eq!(
        called
            .content
            .iter()
            .find_map(|c| c.as_text().map(|t| t.text.clone()))
            .as_deref(),
        Some("reddit_search"),
        "the call must reach the upstream, not a stub",
    );

    // And the operator can see it without reading logs.
    let health = pool.health_snapshot().await;
    assert_eq!(health[0].rejected_output_schema_count, 1);
}

/// Wait for an `UpstreamOutputSchemaRejected` row naming `tool`, or fail.
/// Emission is best-effort and (for the boot replay) detached, so the
/// assertion polls rather than reading the sink once.
async fn await_rejected_output_schema_row(sink: &Arc<InMemorySink>, tool: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if sink.snapshot().await.iter().any(|event| {
                event.action == "UpstreamOutputSchemaRejected"
                    && event.tool.as_deref() == Some(tool)
            }) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("no UpstreamOutputSchemaRejected audit row for `{tool}`");
    });
}

/// A refusal has to reach the operator's ERROR log, not just the process
/// log — that is the whole point of surfacing it. Boot dials run before
/// the evidence recorder is chained onto the pool, so attaching the
/// recorder replays them.
#[tokio::test]
async fn boot_refusals_reach_the_audit_log_once_a_recorder_is_attached() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());

    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await
    .with_evidence(sink.clone());

    await_rejected_output_schema_row(&sink, "reddit_search").await;
    let events = sink.snapshot().await;
    let row = events
        .iter()
        .find(|event| event.action == "UpstreamOutputSchemaRejected")
        .expect("rejection row");
    assert_eq!(row.server.as_deref(), Some("mock"));
    assert_eq!(row.outcome.as_str(), "execution_error");
    assert_eq!(row.category.as_str(), "upstream_health");
    assert!(
        row.reason.as_deref().is_some_and(|r| r.contains("array")),
        "the reason must name the root the upstream actually sent",
    );
    // The pool keeps serving; the refusal is a report, not an outage.
    assert!(pool.is_connected("mock").await);
}

/// An upstream that is down at boot and later auto-recovers installs its
/// connections through the reconnect path, not the boot path. That path
/// must report its own refusals — otherwise the tools are stripped and
/// counted while the operator's error log stays silent.
#[tokio::test]
async fn auto_recovery_reports_its_own_refusals() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    // Down at boot: the dial's tools/list fails, so no lane is installed.
    control.fail_list.store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await
    .with_evidence(sink.clone());
    assert!(!pool.is_connected("mock").await, "must start disconnected");
    assert!(
        !sink
            .snapshot()
            .await
            .iter()
            .any(|event| event.action == "UpstreamOutputSchemaRejected"),
        "nothing was dialed yet, so there is nothing to report",
    );

    control.fail_list.store(false, Ordering::SeqCst);
    assert!(pool.reconnect_one("mock").await, "upstream must recover");

    await_rejected_output_schema_row(&sink, "reddit_search").await;
}

/// Stripping happens at the dial, before manifest classification, so a
/// refused schema can belong to a tool the gateway then withholds. Counting
/// it would tell the operator a tool is "published without an output
/// contract" when it is not published at all — overstating the serving
/// inventory on the metric, the Servers chip, and the audit trail.
#[tokio::test]
async fn a_withheld_tool_is_not_counted_as_published_without_a_contract() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "unclassified-mock".to_owned();
    // Drop the classification for the tool the upstream actually serves, so
    // it is withheld from the published view.
    manifest
        .tools
        .retain(|classification| classification.name != "reddit_search");
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let pool =
        UpstreamPool::connect(BTreeMap::from([("unclassified-mock".to_owned(), manifest)])).await;

    assert!(
        pool.list_tools("unclassified-mock")
            .await
            .expect("connected")
            .is_empty(),
        "the unclassified tool must be withheld — otherwise this test proves nothing",
    );
    let health = pool
        .status_snapshot()
        .await
        .into_iter()
        .find(|entry| entry.health.name == "unclassified-mock")
        .expect("known upstream");
    assert_eq!(
        health.health.rejected_output_schema_count, 0,
        "a withheld tool must not be reported as published without an output contract",
    );
    assert_eq!(rejected_gauge("unclassified-mock"), Some(0));
}

/// The mirror of the test above: once the operator classifies that tool, the
/// gateway starts serving it WITHOUT an output contract. That is the fact the
/// error log exists to record, and no dial happens to report it — so the
/// promotion itself has to write the row, or a refusal reaches clients with
/// nothing in the audit trail saying so.
#[tokio::test]
async fn promoting_a_withheld_tool_audits_the_refusal_it_starts_serving() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut unclassified = dynamic_manifest_at(addr);
    unclassified.name = "promoted-mock".to_owned();
    unclassified
        .tools
        .retain(|classification| classification.name != "reddit_search");
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());

    let pool = UpstreamPool::connect(BTreeMap::from([("promoted-mock".to_owned(), unclassified)]))
        .await
        .with_evidence(sink.clone());
    assert!(
        rejection_rows(&sink).await.is_empty(),
        "a withheld tool is not served, so it has nothing to report yet",
    );

    let mut classified = dynamic_manifest_at(addr);
    classified.name = "promoted-mock".to_owned();
    pool.reload_manifests(&BTreeMap::from([("promoted-mock".to_owned(), classified)]))
        .await;

    assert!(
        !pool
            .list_tools("promoted-mock")
            .await
            .expect("connected")
            .is_empty(),
        "the promotion must actually publish the tool — otherwise this proves nothing",
    );
    await_rejected_output_schema_row(&sink, "reddit_search").await;
    assert_eq!(rejected_gauge("promoted-mock"), Some(1));
}

/// An audit row is an event: it says the gateway observed a refusal. Every
/// republication re-derives the same refusal from the same connection, so
/// writing a row per publication would turn one broken upstream tool into an
/// error log that grows on every redial.
#[tokio::test]
async fn republishing_an_unchanged_refusal_does_not_write_a_second_row() {
    let (addr_a, control_a) = spawn_dynamic_catalog().await;
    let (addr_b, control_b) = spawn_dynamic_catalog().await;
    for control in [&control_a, &control_b] {
        control
            .array_rooted_output_schema
            .store(true, Ordering::SeqCst);
    }
    let sink = Arc::new(InMemorySink::new());

    let mut manifest = dynamic_manifest_at(addr_a);
    manifest.name = "republished-mock".to_owned();
    let pool = UpstreamPool::connect(BTreeMap::from([("republished-mock".to_owned(), manifest)]))
        .await
        .with_evidence(sink.clone());
    await_rejected_output_schema_row(&sink, "reddit_search").await;

    // A transport edit redials, so the same refusal is observed and published
    // a second time.
    let mut moved = dynamic_manifest_at(addr_b);
    moved.name = "republished-mock".to_owned();
    let report = pool
        .reload_manifests(&BTreeMap::from([("republished-mock".to_owned(), moved)]))
        .await;
    assert_eq!(report.redialed, vec!["republished-mock"]);

    assert_eq!(
        rejection_rows(&sink).await.len(),
        1,
        "one refusal, observed twice, is still one thing to tell the operator",
    );
    assert_eq!(rejected_gauge("republished-mock"), Some(1));
}

/// A slot-count change REBUILDS the entry rather than redialing it, so the
/// replacement starts with no memory of what the entry it replaces already
/// reported. It inherits drift state for the same reason it must inherit
/// this: the rebuild serves the same broken upstream tools, and re-reporting
/// them would make a resize look like a new fault.
#[tokio::test]
async fn rebuilding_an_entry_for_a_resize_does_not_re_report_its_refusals() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());

    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "resized-mock".to_owned();
    let pool = UpstreamPool::connect(BTreeMap::from([("resized-mock".to_owned(), manifest)]))
        .await
        .with_evidence(sink.clone());
    await_rejected_output_schema_row(&sink, "reddit_search").await;

    let mut resized = dynamic_manifest_at(addr);
    resized.name = "resized-mock".to_owned();
    resized.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    let report = pool
        .reload_manifests(&BTreeMap::from([("resized-mock".to_owned(), resized)]))
        .await;
    assert_eq!(
        report.redialed,
        vec!["resized-mock"],
        "the resize must actually rebuild the entry — otherwise this proves nothing",
    );

    assert_eq!(
        rejection_rows(&sink).await.len(),
        1,
        "a resize republishes the same refusal; it is not a new one",
    );
    assert_eq!(rejected_gauge("resized-mock"), Some(1));
}

/// What the operator has been told is a fact about the UPSTREAM, so it
/// survives whatever happens to the entry serving it and however the detached
/// boot replay interleaves with a rebuild. Issuing the resize without waiting
/// for the replay exercises that; the interleaving itself is not schedulable
/// from a test, which is why the record is keyed by server rather than
/// handed from one entry to the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resize_issued_during_boot_attach_reports_one_refusal() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());

    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "raced-mock".to_owned();
    let pool = UpstreamPool::connect(BTreeMap::from([("raced-mock".to_owned(), manifest)]))
        .await
        .with_evidence(sink.clone());

    // Deliberately NOT awaiting the boot row first, so the resize is issued
    // without waiting for the replay to have run.
    let mut resized = dynamic_manifest_at(addr);
    resized.name = "raced-mock".to_owned();
    resized.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    let report = pool
        .reload_manifests(&BTreeMap::from([("raced-mock".to_owned(), resized)]))
        .await;
    assert_eq!(report.redialed, vec!["raced-mock"]);

    await_rejected_output_schema_row(&sink, "reddit_search").await;
    // Let any replay still in flight finish before counting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        rejection_rows(&sink).await.len(),
        1,
        "the refusal is one fault however the replay and the resize order",
    );
}

/// Removing an upstream ends the window the record describes. A name that
/// comes back is a different arrangement that has told the operator nothing,
/// so its refusal is reported again rather than silenced by what a previous
/// occupant of the name had already reported.
#[tokio::test]
async fn re_adding_a_removed_upstream_reports_its_refusal_again() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());

    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "readded-mock".to_owned();
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "readded-mock".to_owned(),
        manifest.clone(),
    )]))
    .await
    .with_evidence(sink.clone());
    await_rejected_output_schema_row(&sink, "reddit_search").await;

    pool.reload_manifests(&BTreeMap::new()).await;
    assert_eq!(rejected_gauge("readded-mock"), Some(0));

    pool.reload_manifests(&BTreeMap::from([("readded-mock".to_owned(), manifest)]))
        .await;

    assert_eq!(
        rejection_rows(&sink).await.len(),
        2,
        "the re-added upstream is serving a refusal nobody has been told about",
    );
    assert_eq!(rejected_gauge("readded-mock"), Some(1));
}

/// A drift quarantine withholds the tool, so its refusal stops being served
/// and stops being reported. Lifting the quarantine starts serving it again —
/// without an output contract, and with no dial to say so. That is the whole
/// reason the release records rather than only refreshing the gauge.
#[tokio::test]
async fn lifting_a_quarantine_audits_the_refusal_it_resumes_serving() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());

    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "quarantined-mock".to_owned();
    let pool = UpstreamPool::connect(BTreeMap::from([("quarantined-mock".to_owned(), manifest)]))
        .await
        .with_quarantine_threshold(QuarantineThreshold::All)
        .with_evidence(sink.clone());
    await_rejected_output_schema_row(&sink, "reddit_search").await;

    // Drift the INPUT contract and re-dial onto it, so the refused tool is
    // quarantined and withheld. The refusal is no longer served, so it is no
    // longer reported — which is what makes the release below a new event.
    control.changed_schema.store(true, Ordering::SeqCst);
    let mut drifted = dynamic_manifest_at(addr);
    drifted.name = "quarantined-mock".to_owned();
    drifted.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    let report = pool
        .reload_manifests(&BTreeMap::from([("quarantined-mock".to_owned(), drifted)]))
        .await;
    assert_eq!(report.redialed, vec!["quarantined-mock"]);
    assert_eq!(
        pool.quarantined_tools("quarantined-mock").await,
        Some(vec!["reddit_search".to_string()]),
        "drift must quarantine the tool — otherwise this test proves nothing",
    );
    assert_eq!(rejected_gauge("quarantined-mock"), Some(0));

    assert_eq!(pool.clear_quarantine("quarantined-mock").await, Some(1));

    assert_eq!(
        rejection_rows(&sink).await.len(),
        2,
        "the release resumed serving a refusal the operator was not told about",
    );
    assert_eq!(rejected_gauge("quarantined-mock"), Some(1));
}

/// Withholding a refused tool and serving it again is two events, not one
/// repeat. Both halves are recorded by the transitions themselves, so the
/// second serving is reported even though nothing re-sampled in between and
/// the end state matches the start.
#[tokio::test]
async fn withholding_a_refusal_and_serving_it_again_reports_twice() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());

    let classified = |name: &str| {
        let mut m = dynamic_manifest_at(addr);
        m.name = name.to_owned();
        m
    };
    let unclassified = |name: &str| {
        let mut m = classified(name);
        m.tools
            .retain(|classification| classification.name != "reddit_search");
        m
    };

    let pool = UpstreamPool::connect(BTreeMap::from([(
        "toggled-mock".to_owned(),
        classified("toggled-mock"),
    )]))
    .await
    .with_evidence(sink.clone());
    await_rejected_output_schema_row(&sink, "reddit_search").await;

    // Withhold it: the refusal stops being served, so it stops being reported.
    pool.reload_manifests(&BTreeMap::from([(
        "toggled-mock".to_owned(),
        unclassified("toggled-mock"),
    )]))
    .await;
    assert!(
        pool.list_tools("toggled-mock")
            .await
            .expect("connected")
            .is_empty(),
        "the demotion must actually withhold the tool",
    );
    assert_eq!(rejected_gauge("toggled-mock"), Some(0));

    // Serve it again. Nothing about the upstream changed, but clients can
    // reach a tool with no output contract again, and that is a new event.
    pool.reload_manifests(&BTreeMap::from([(
        "toggled-mock".to_owned(),
        classified("toggled-mock"),
    )]))
    .await;

    assert_eq!(
        rejection_rows(&sink).await.len(),
        2,
        "serving the refusal again is its own event, not a repeat of the first",
    );
    assert_eq!(rejected_gauge("toggled-mock"), Some(1));
}

async fn rejection_rows(sink: &Arc<InMemorySink>) -> Vec<AuditEvent> {
    sink.snapshot()
        .await
        .into_iter()
        .filter(|event| event.action == "UpstreamOutputSchemaRejected")
        .collect()
}

/// A partial heal re-dials only the down lanes, so the lanes can hold
/// different catalog generations. When that makes them disagree about a
/// tool's OUTPUT schema, the tool must still be published — withholding the
/// disputed contract, not the tool. Dropping it would mean a malformed
/// upstream schema still costs you the tool, just one heal later.
#[tokio::test]
async fn a_tool_survives_a_partial_heal_that_diverges_its_output_schema() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "heal-mock".to_owned();
    manifest.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    // Boot malformed with the first lane's tools/list failing, so one lane is
    // down and the serving lane holds a STRIPPED descriptor.
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    control.fail_next_lists.store(1, Ordering::SeqCst);
    let pool = UpstreamPool::connect(BTreeMap::from([("heal-mock".to_owned(), manifest)])).await;
    assert_eq!(
        pool.list_tools("heal-mock").await.expect("connected").len(),
        1,
    );

    // The upstream is fixed, then the down lane heals — so one lane holds
    // `None` (stripped) and the other a conforming object root. Only the
    // OUTPUT contract diverges; name and input schema still agree.
    control
        .array_rooted_output_schema
        .store(false, Ordering::SeqCst);
    control.changed_output_schema.store(true, Ordering::SeqCst);
    assert!(pool.reconnect_one("heal-mock").await, "lane must heal");

    let tools = pool.list_tools("heal-mock").await.expect("connected");
    let reddit = tools
        .iter()
        .find(|tool| tool.name.as_ref() == "reddit_search")
        .expect("a tool every lane advertises must not vanish because the lanes disagree about its output contract");
    assert!(
        reddit.output_schema.is_none(),
        "the disputed output contract is withheld, not one lane's version of it",
    );
    // Still dispatchable — withholding the schema must not withhold the tool.
    pool.call_tool("heal-mock", "reddit_search", None, None, None)
        .await
        .expect("the surviving tool must still dispatch");
}

/// Divergence that touches the DISPATCH contract still withholds the tool:
/// only the output schema is allowed to disagree across lanes.
#[tokio::test]
async fn a_tool_whose_input_contract_diverges_is_still_withheld() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "input-mock".to_owned();
    manifest.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    control.fail_next_lists.store(1, Ordering::SeqCst);
    let pool = UpstreamPool::connect(BTreeMap::from([("input-mock".to_owned(), manifest)])).await;

    // `alternate_schema` changes the INPUT schema, so the healed lane's
    // descriptor is not interchangeable with the stale lane's.
    control.alternate_schema.store(true, Ordering::SeqCst);
    assert!(pool.reconnect_one("input-mock").await, "lane must heal");

    assert!(
        pool.list_tools("input-mock")
            .await
            .expect("connected")
            .is_empty(),
        "a lane disagreement about the input contract must still withhold the tool",
    );
}

/// Lanes are allowed to hold different catalog generations: a partial heal
/// re-dials only the down lanes. If the upstream starts advertising a
/// malformed schema in between, only the healed lane carries the refusal —
/// and sampling a single lane could miss it entirely.
///
/// A refusal on ANY live lane has to be reported, because silently
/// under-reporting is the exact failure this surface exists to prevent.
#[tokio::test]
async fn a_refusal_on_any_lane_is_reported_even_when_lanes_diverge() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut manifest = dynamic_manifest_at(addr);
    manifest.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    // Boot against a malformed upstream, failing exactly the first lane's
    // `tools/list`. The pool comes up with lane 0 DOWN and a later lane
    // holding the refusal.
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    control.fail_next_lists.store(1, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest)]))
        .await
        .with_evidence(sink.clone());
    let booted = pool.health_snapshot().await;
    assert_eq!(booted[0].connected_lanes, 1, "one lane must be down");
    assert_eq!(booted[0].rejected_output_schema_count, 1);

    // The upstream is fixed, then the down lane heals. The healed lane is
    // clean and sorts BEFORE the stale lane that still carries the
    // refusal, so reading only the first connected lane would report zero.
    control
        .array_rooted_output_schema
        .store(false, Ordering::SeqCst);
    assert!(pool.reconnect_one("mock").await, "down lane must heal");

    let healed = pool.health_snapshot().await;
    assert_eq!(healed[0].connected_lanes, 2);
    assert_eq!(
        healed[0].rejected_output_schema_count, 1,
        "a refusal still held by a later lane must not be dropped because \
         an earlier lane is clean",
    );
    await_rejected_output_schema_row(&sink, "reddit_search").await;
}

/// Read the `mcp_upstream_rejected_output_schemas` gauge for `server`
/// out of the Prometheus text exposition. `None` when the series has not
/// been published at all.
fn rejected_gauge(server: &str) -> Option<i64> {
    let needle = format!("mcp_upstream_rejected_output_schemas{{server=\"{server}\"}}");
    waygate_telemetry::gather_text()
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .and_then(|rest| rest.trim().parse::<f64>().ok())
        .map(|v| v as i64)
}

/// The metric has to answer "is this upstream broken RIGHT NOW", which
/// means it must fall back to zero once the upstream is fixed. A
/// cumulative counter could not: it would latch at its last value and make
/// `> 0` alert forever after a single bad dial.
#[tokio::test]
async fn the_refusal_gauge_falls_back_to_zero_once_the_upstream_is_fixed() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let mut manifest = dynamic_manifest_at(addr);
    // A distinct server name: the gauge is process-global and other tests
    // in this binary publish their own series.
    manifest.name = "gauge-mock".to_owned();
    let pool = UpstreamPool::connect(BTreeMap::from([("gauge-mock".to_owned(), manifest)]))
        .await
        .with_evidence(Arc::new(InMemorySink::new()));

    tokio::time::timeout(Duration::from_secs(2), async {
        while rejected_gauge("gauge-mock") != Some(1) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the boot publish must set the gauge to the refusal count");

    // Fix the upstream — it now advertises a proper object root — and
    // re-dial. The series must return to zero rather than stay latched
    // at 1.
    control
        .array_rooted_output_schema
        .store(false, Ordering::SeqCst);
    control.changed_output_schema.store(true, Ordering::SeqCst);
    let report = refresh_catalog_for(&pool, "gauge-mock")
        .await
        .expect("known upstream");
    assert_eq!(report.outcome, CatalogRefreshOutcome::Updated);
    assert_eq!(rejected_gauge("gauge-mock"), Some(0));
    assert_eq!(
        pool.health_snapshot().await[0].rejected_output_schema_count,
        0,
        "the gauge and the admin count must agree",
    );
}

/// A removed upstream publishes nothing, so its refusal series must fall
/// to zero. Leaving it latched would keep alerting on a server that no
/// longer exists.
#[tokio::test]
async fn removing_an_upstream_clears_its_refusal_gauge() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control
        .array_rooted_output_schema
        .store(true, Ordering::SeqCst);
    let mut manifest = dynamic_manifest_at(addr);
    manifest.name = "drop-mock".to_owned();
    let pool = UpstreamPool::connect(BTreeMap::from([("drop-mock".to_owned(), manifest)]))
        .await
        .with_evidence(Arc::new(InMemorySink::new()));

    tokio::time::timeout(Duration::from_secs(2), async {
        while rejected_gauge("drop-mock") != Some(1) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("boot publish must set the gauge");

    // Reload to an empty manifest set: the upstream is hot-removed.
    pool.reload_manifests(&BTreeMap::new()).await;

    assert_eq!(
        rejected_gauge("drop-mock"),
        Some(0),
        "a removed upstream must not keep reporting a refusal count",
    );
}

/// The steady state: a conforming upstream is passed through untouched and
/// reports nothing to the operator.
#[tokio::test]
async fn object_rooted_output_schema_is_forwarded_verbatim() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control.changed_output_schema.store(true, Ordering::SeqCst);
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await;

    let tools = pool.list_tools("mock").await.expect("connected upstream");

    let reddit = tools
        .iter()
        .find(|tool| tool.name.as_ref() == "reddit_search")
        .expect("reddit tool");
    assert_eq!(
        reddit.output_schema.as_deref(),
        Some(
            &serde_json::json!({
                "type": "object",
                "properties": {"results": {"type": "array"}}
            })
            .as_object()
            .expect("output schema object")
            .clone()
        ),
        "a conforming output schema must survive byte-for-byte",
    );
    let health = pool.health_snapshot().await;
    assert_eq!(health[0].rejected_output_schema_count, 0);
}

#[tokio::test]
async fn boot_publishes_only_the_catalog_common_to_every_connected_lane() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control.alternate_schema.store(true, Ordering::SeqCst);
    let mut manifest = dynamic_manifest_at(addr);
    manifest.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });

    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest)])).await;

    let health = pool.health_snapshot().await;
    assert_eq!(health[0].connected_lanes, 2);
    assert_eq!(health[0].total_lanes, 2);
    assert_eq!(
        health[0].published_tool_count, 0,
        "boot must not advertise a descriptor that one serving lane contradicts",
    );
    assert!(
        pool.list_tools("mock")
            .await
            .expect("connected upstream")
            .is_empty(),
        "every connected lane must carry the same conservative boot catalog",
    );
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "reddit", 10)
        .expect("index search")
        .expect("non-empty query");
    assert!(
        indexed.is_empty(),
        "search must expose the same conservative boot catalog as tools/list",
    );
}

#[tokio::test]
async fn multi_lane_refresh_publishes_only_exact_catalog_intersection() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut manifest = dynamic_manifest_at(addr);
    manifest.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest)])).await;
    let initial_health = pool.health_snapshot().await;
    assert_eq!(initial_health.len(), 1);
    assert!(initial_health[0].connected);
    assert_eq!(initial_health[0].connected_lanes, 2);
    assert_eq!(initial_health[0].total_lanes, 2);
    assert_eq!(initial_health[0].published_tool_count, 1);
    assert_eq!(initial_health[0].quarantined_tool_count, 0);
    control.alternate_schema.store(true, Ordering::SeqCst);

    let report = refresh_catalog(&pool).await.expect("known upstream");

    assert_eq!(report.outcome, CatalogRefreshOutcome::Updated);
    assert_eq!(report.removed, vec!["reddit_search"]);
    assert!(report.schema_changed.is_empty());
    assert_eq!(report.after_tool_count, 0);
    assert!(pool
        .list_tools("mock")
        .await
        .expect("published inventory")
        .is_empty());
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "reddit", 10)
        .expect("index search")
        .expect("non-empty query");
    assert!(indexed.is_empty());
    let refreshed_health = pool.health_snapshot().await;
    assert!(refreshed_health[0].connected);
    assert_eq!(refreshed_health[0].connected_lanes, 2);
    assert_eq!(refreshed_health[0].total_lanes, 2);
    assert_eq!(refreshed_health[0].published_tool_count, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_snapshots_never_mix_classification_reload_generations() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control.expanded.store(true, Ordering::SeqCst);
    let mut full = dynamic_manifest_at(addr);
    full.session = Some(SessionConfig {
        concurrency: Some(4),
        ..SessionConfig::default()
    });
    let mut reduced = full.clone();
    reduced
        .tools
        .retain(|classification| classification.name == "reddit_search");
    let full_set = BTreeMap::from([("mock".to_owned(), full)]);
    let reduced_set = BTreeMap::from([("mock".to_owned(), reduced)]);
    let pool = Arc::new(UpstreamPool::connect(full_set.clone()).await);

    let writer_pool = pool.clone();
    let writer = async move {
        for iteration in 0..200 {
            let manifests = if iteration % 2 == 0 {
                &reduced_set
            } else {
                &full_set
            };
            writer_pool.reload_manifests(manifests).await;
            tokio::task::yield_now().await;
        }
    };
    let reader = async {
        for _ in 0..800 {
            let statuses = pool.status_snapshot().await;
            let status = &statuses[0];
            assert_eq!(
                status.health.published_tool_count,
                status.manifest.tools.len(),
                "a status snapshot must not pair a manifest classification generation with a different published lane generation",
            );
            assert_eq!(status.health.connected_lanes, 4);
            tokio::task::yield_now().await;
        }
    };

    tokio::join!(writer, reader);
}

#[tokio::test]
async fn healed_lane_preserves_the_published_catalog_intersection() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut manifest = dynamic_manifest_at(addr);
    manifest.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest)])).await;
    control.alternate_schema.store(true, Ordering::SeqCst);
    control.fail_next_lists.store(1, Ordering::SeqCst);

    let refresh = refresh_catalog(&pool).await.expect("known upstream");

    assert!(refresh.session_replaced);
    assert_eq!(refresh.after_tool_count, 1);
    assert!(pool.reconnect_one("mock").await);
    for _ in 0..2 {
        assert!(
            pool.list_tools("mock")
                .await
                .expect("healed serving inventory")
                .is_empty(),
            "every serving lane must expose the exact catalog intersection"
        );
    }
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "reddit", 10)
        .expect("index search")
        .expect("non-empty query");
    assert!(indexed.is_empty());
}

/// A classification-only reload republishes the catalog without re-dialing.
/// When a partial heal has left the lanes on different upstream generations,
/// that republication must retain their common catalog rather than widening
/// discovery to whichever lane happens to publish the search index.
#[tokio::test]
async fn classification_reload_preserves_the_published_catalog_intersection() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut manifest = dynamic_manifest_at(addr);
    manifest.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    control.fail_next_lists.store(1, Ordering::SeqCst);
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest.clone())])).await;

    // Only the healed lane learns about twitter_search. The other serving
    // lane still advertises the original one-tool catalog.
    control.expanded.store(true, Ordering::SeqCst);
    assert!(pool.reconnect_one("mock").await, "down lane must heal");
    assert_eq!(
        pool.list_tools("mock")
            .await
            .expect("serving inventory")
            .len(),
        1,
        "the partial heal must publish only the common lane catalog",
    );

    // Change governance metadata only. This uses the in-place classification
    // publication path and must not promote the new tool from just one lane.
    manifest.tools[0].risk = RiskTier::High;
    let report = pool
        .reload_manifests(&BTreeMap::from([("mock".to_owned(), manifest)]))
        .await;
    assert_eq!(report.classifications_updated, vec!["mock".to_owned()]);
    assert_eq!(
        pool.tool_facts("mock", "reddit_search").risk,
        RiskTier::High
    );

    for _ in 0..2 {
        let tools = pool.list_tools("mock").await.expect("serving inventory");
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            vec!["reddit_search"],
            "every serving lane must retain the exact common catalog",
        );
    }
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "twitter", 10)
        .expect("index search")
        .expect("non-empty query");
    assert!(
        indexed.is_empty(),
        "the retrieval index must not advertise a tool absent from one serving lane",
    );
}

#[tokio::test]
async fn successful_catalog_refresh_awaits_attributed_evidence_submission() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let sink = Arc::new(GatedBestEffortSink::new());
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await
    .with_evidence(sink.clone());
    let actor = admin_principal();
    control.expanded.store(true, Ordering::SeqCst);

    let started = sink.started.notified();
    tokio::pin!(started);
    let mut refresh = Box::pin(pool.refresh_server_catalog("mock", &actor));
    tokio::select! {
        report = &mut refresh => panic!("refresh returned before evidence submission: {report:?}"),
        () = &mut started => {}
    }
    sink.release.add_permits(1);
    let report = refresh.await.expect("known upstream");
    assert_eq!(report.outcome, CatalogRefreshOutcome::Updated);

    let events = sink.inner.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "UpstreamCatalogRefresh");
    assert_eq!(
        events[0]
            .principal
            .as_ref()
            .map(|principal| principal.sub.as_str()),
        Some("catalog-operator")
    );
    assert_eq!(events[0].target.as_deref(), Some("mock"));
}

#[tokio::test]
async fn failed_catalog_refresh_keeps_the_existing_session_and_inventory() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut map = BTreeMap::new();
    map.insert("mock".into(), dynamic_manifest_at(addr));
    let pool = UpstreamPool::connect(map).await;
    assert!(pool.is_connected("mock").await);

    control.fail_list.store(true, Ordering::SeqCst);
    let report = refresh_catalog(&pool).await.expect("known upstream");
    assert_eq!(report.outcome, CatalogRefreshOutcome::Failed);
    assert!(!report.session_replaced);
    assert_eq!(report.before_tool_count, 1);
    assert_eq!(report.after_tool_count, 1);
    assert!(report.added.is_empty());
    assert!(report.removed.is_empty());
    assert!(report.schema_changed.is_empty());
    assert!(
        pool.is_connected("mock").await,
        "a failed refresh must keep the prior healthy session serving"
    );
    assert_eq!(
        pool.list_tools("mock")
            .await
            .expect("old inventory remains available")
            .len(),
        1
    );
}

#[tokio::test]
async fn failed_catalog_refresh_records_the_disconnected_upstreams_latest_error_class() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]));
    let before = pool.health_snapshot().await.remove(0);
    assert_eq!(before.runtime_state.as_str(), "disconnected");
    assert_eq!(before.last_error_class, None);

    control.fail_list.store(true, Ordering::SeqCst);
    let report = refresh_catalog(&pool).await.expect("known upstream");
    assert_eq!(report.outcome, CatalogRefreshOutcome::Failed);

    let after = pool.health_snapshot().await.remove(0);
    assert_eq!(after.runtime_state.as_str(), "disconnected");
    assert_eq!(
        after.last_error_class.map(|class| class.as_str()),
        Some("protocol"),
        "the authoritative snapshot must retain the newest bounded dial failure",
    );
}

#[tokio::test]
async fn concurrent_catalog_refreshes_serialize_session_replacement() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut map = BTreeMap::new();
    map.insert("mock".into(), dynamic_manifest_at(addr));
    let pool = UpstreamPool::connect(map).await;

    control.delay_list.store(true, Ordering::SeqCst);
    let (first, second) = tokio::join!(refresh_catalog(&pool), refresh_catalog(&pool),);
    let first = first.expect("known upstream");
    let second = second.expect("known upstream");
    assert!(first.session_replaced);
    assert!(second.session_replaced);
    assert_eq!(first.outcome, CatalogRefreshOutcome::Unchanged);
    assert_eq!(second.outcome, CatalogRefreshOutcome::Unchanged);
    assert_eq!(
        control.max_active_lists.load(Ordering::SeqCst),
        1,
        "session replacement must serialize so an older catalog cannot commit last",
    );
}

#[tokio::test]
async fn reconnect_and_freshness_refresh_are_single_flight_per_upstream() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let pool = UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]));
    control.delay_list.store(true, Ordering::SeqCst);

    let actor = admin_principal();
    let future_probe = std::time::Instant::now() + Duration::from_secs(86_400);
    let (reconnected, refresh) = tokio::join!(
        pool.reconnect_one("mock"),
        pool.scheduled_catalog_refresh(
            "mock",
            Duration::ZERO,
            Duration::from_secs(60),
            future_probe,
            &actor,
        ),
    );

    assert!(
        reconnected,
        "the reconnect must restore the disconnected entry"
    );
    assert!(matches!(refresh, ScheduledCatalogRefresh::Refreshed { .. }));
    assert_eq!(
        control.max_active_lists.load(Ordering::SeqCst),
        1,
        "reconnect and freshness redials must share one per-upstream flight",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual live concurrency and timing diagnostic; excluded from required CI"]
async fn slow_reconnect_does_not_delay_another_upstream() {
    let (slow_addr, slow_control) = spawn_dynamic_catalog().await;
    let (fast_addr, fast_control) = spawn_dynamic_catalog().await;
    slow_control.block_list.store(true, Ordering::SeqCst);

    let mut slow = dynamic_manifest_at(slow_addr);
    slow.name = "slow".to_owned();
    let mut fast = dynamic_manifest_at(fast_addr);
    fast.name = "fast".to_owned();
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        ("slow".to_owned(), slow),
        ("fast".to_owned(), fast),
    ])));

    let reconnect_pool = pool.clone();
    let reconnect = tokio::spawn(async move {
        reconnect_pool.try_reconnect_disconnected().await;
    });
    slow_control.blocked_list_started.notified().await;

    // Completion while the other upstream remains blocked proves independence;
    // elapsed scheduler time is not part of that contract.
    while fast_control.list_calls.load(Ordering::SeqCst) == 0 || !pool.is_connected("fast").await {
        tokio::task::yield_now().await;
    }
    assert_eq!(slow_control.active_lists.load(Ordering::SeqCst), 1);

    slow_control.block_list.store(false, Ordering::SeqCst);
    slow_control.list_release.notify_one();
    reconnect.await.expect("reconnect task panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_refresh_cannot_publish_after_slot_resize_replaces_its_entry() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let (replacement_addr, replacement_control) = spawn_dynamic_catalog().await;
    replacement_control.expanded.store(true, Ordering::SeqCst);
    let mut map = BTreeMap::new();
    map.insert("mock".into(), dynamic_manifest_at(addr));
    let pool = Arc::new(UpstreamPool::connect(map).await);
    let epoch = pool.tool_catalog_epoch();

    control.block_list.store(true, Ordering::SeqCst);
    let refresh_pool = pool.clone();
    let refresh = tokio::spawn(async move { refresh_catalog(&refresh_pool).await });
    control.blocked_list_started.notified().await;

    // The in-flight refresh captured the old one-tool response and remains
    // blocked on that upstream. A separate, non-delayed upstream lets the
    // slot-count-changing reload publish its replacement entry first.
    let mut resized = dynamic_manifest_at(replacement_addr);
    resized.session = Some(SessionConfig {
        concurrency: Some(2),
        ..SessionConfig::default()
    });
    let resized_set = BTreeMap::from([("mock".to_owned(), resized)]);
    let reload = pool.reload_manifests(&resized_set).await;
    assert_eq!(reload.redialed, vec!["mock"]);
    assert_eq!(
        epoch.current(),
        1,
        "a rebuild with changed descriptors must notify",
    );

    control.block_list.store(false, Ordering::SeqCst);
    control.list_release.notify_one();
    let stale = refresh
        .await
        .expect("refresh task")
        .expect("known upstream");
    assert_eq!(stale.outcome, CatalogRefreshOutcome::Superseded);
    assert!(!stale.session_replaced);
    assert_eq!(
        epoch.current(),
        1,
        "the superseded refresh must not advance beyond the winning rebuild",
    );
    assert_eq!(
        pool.list_tools("mock").await.expect("live inventory").len(),
        2
    );
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "twitter", 10)
        .expect("index search")
        .expect("non-empty query");
    assert_eq!(indexed, vec!["twitter_search"]);
}

async fn failed_catalog_refresh_racing_reload(
    replacement_addr: Option<std::net::SocketAddr>,
) -> CatalogRefreshReport {
    let (addr, control) = spawn_dynamic_catalog().await;
    let pool = Arc::new(
        UpstreamPool::connect(BTreeMap::from([(
            "mock".to_owned(),
            dynamic_manifest_at(addr),
        )]))
        .await,
    );
    control.block_list.store(true, Ordering::SeqCst);
    control.fail_list.store(true, Ordering::SeqCst);

    let refresh_pool = pool.clone();
    let refresh = tokio::spawn(async move { refresh_catalog(&refresh_pool).await });
    control.blocked_list_started.notified().await;

    if let Some(replacement_addr) = replacement_addr {
        let mut replacement = dynamic_manifest_at(replacement_addr);
        replacement.session = Some(SessionConfig {
            concurrency: Some(2),
            ..SessionConfig::default()
        });
        let reload = pool
            .reload_manifests(&BTreeMap::from([("mock".to_owned(), replacement)]))
            .await;
        assert_eq!(reload.redialed, vec!["mock"]);
    } else {
        let reload = pool.reload_manifests(&BTreeMap::new()).await;
        assert_eq!(reload.removed, vec!["mock"]);
    }

    control.block_list.store(false, Ordering::SeqCst);
    control.list_release.notify_one();
    refresh
        .await
        .expect("refresh task")
        .expect("known upstream")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual live concurrency and timing diagnostic; excluded from required CI"]
async fn failed_catalog_refresh_reports_superseded_when_reload_replaces_its_entry() {
    let (replacement_addr, _) = spawn_dynamic_catalog().await;
    let report = failed_catalog_refresh_racing_reload(Some(replacement_addr)).await;

    assert_eq!(report.outcome, CatalogRefreshOutcome::Superseded);
    assert!(!report.session_replaced);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual live concurrency and timing diagnostic; excluded from required CI"]
async fn failed_catalog_refresh_reports_removed_when_reload_removes_its_entry() {
    let report = failed_catalog_refresh_racing_reload(None).await;

    assert_eq!(report.outcome, CatalogRefreshOutcome::Removed);
    assert!(!report.session_replaced);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_catalog_refresh_keeps_search_and_serving_session_consistent() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut map = BTreeMap::new();
    map.insert("mock".into(), dynamic_manifest_at(addr));
    let pool = Arc::new(UpstreamPool::connect(map).await);
    control.expanded.store(true, Ordering::SeqCst);
    control.delay_list.store(true, Ordering::SeqCst);

    let refresh_pool = pool.clone();
    let refresh = tokio::spawn(async move { refresh_catalog(&refresh_pool).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    refresh.abort();
    assert!(refresh
        .await
        .expect_err("refresh must be cancelled")
        .is_cancelled());

    let serving = pool.list_tools("mock").await.expect("serving inventory");
    assert_eq!(serving.len(), 1, "cancelled dial keeps the prior session");
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "twitter", 10)
        .expect("index search")
        .expect("non-empty query");
    assert!(
        indexed.is_empty(),
        "cancelled dial must not publish a catalog its serving session lacks",
    );

    control.delay_list.store(false, Ordering::SeqCst);
    let completed = refresh_catalog(&pool).await.expect("known upstream");
    assert_eq!(completed.outcome, CatalogRefreshOutcome::Updated);
    assert_eq!(
        pool.list_tools("mock")
            .await
            .expect("fresh inventory")
            .len(),
        2
    );
    let indexed = pool
        .search_index()
        .expect("connected pool has an index")
        .search("mock", "twitter", 10)
        .expect("index search")
        .expect("non-empty query");
    assert_eq!(indexed, vec!["twitter_search"]);
}

#[tokio::test]
async fn catalog_refresh_schema_change_emits_drift_evidence() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let mut map = BTreeMap::new();
    map.insert("mock".into(), dynamic_manifest_at(addr));
    let sink = Arc::new(InMemorySink::new());
    let pool = UpstreamPool::connect(map).await.with_evidence(sink.clone());

    control.changed_schema.store(true, Ordering::SeqCst);
    let report = refresh_catalog(&pool).await.expect("known upstream");
    assert_eq!(report.schema_changed, vec!["reddit_search"]);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if sink
                .snapshot()
                .await
                .iter()
                .any(|event| event.action == "ToolDrift")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("behavior drift evidence must be emitted");
}

#[tokio::test]
async fn live_redial_retargets_the_slot_session_to_the_new_url() {
    let (addr_a, calls_a) = spawn_tagged("A").await;
    let (addr_b, calls_b) = spawn_tagged("B").await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map).await;
    assert!(
        pool.is_connected("mock").await,
        "boot dial must connect to A"
    );

    // Baseline: the slot's reused session runs on A.
    assert_eq!(call_id(&pool).await, "A", "pre-redial calls must hit A");
    assert_eq!(calls_a.load(Ordering::SeqCst), 1);

    // Reload with the url pointed at B. Same transport + same `concurrency: 1`
    // ⇒ a stable slot count ⇒ this is a live re-dial, not a restart-required
    // change.
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".into(), manifest_at(addr_b));
    let report = tokio::time::timeout(Duration::from_secs(10), pool.reload_manifests(&fresh))
        .await
        .expect("reload_manifests hung");

    assert_eq!(
        report.redialed,
        vec!["mock".to_string()],
        "a reachable same-slot-count url change must be re-dialed live",
    );
    assert!(
        report.redial_failed.is_empty(),
        "B is reachable, so the re-dial must succeed on its lane",
    );
    assert!(
        pool.is_connected("mock").await,
        "the upstream stays connected across the live re-dial (no downtime)",
    );

    // The slot now holds B's session: a reused call lands on B. (Under `reuse`
    // this can only be "B" if the slot's LIVE session was swapped — not if only
    // the url metadata had been updated.)
    assert_eq!(call_id(&pool).await, "B", "post-redial calls must hit B");

    // A clean swap: A receives no further traffic; B serves the new call.
    assert_eq!(
        calls_a.load(Ordering::SeqCst),
        1,
        "A must stop receiving calls once the slot is re-dialed to B",
    );
    assert!(
        calls_b.load(Ordering::SeqCst) >= 1,
        "B now serves the upstream's calls",
    );

    // The stored manifest advanced to B's url, so a later reconnect dials B.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock still present");
    assert_eq!(
        stored.url,
        Some(format!("http://{addr_b}/mcp")),
        "a successful re-dial advances the stored url to the new target",
    );
}

/// A slot-count-CHANGING shape edit (here `session.concurrency` 1 → 2)
/// can't re-dial the existing slot in place — it is REBUILT live. A fresh entry
/// with the new slot count is dialed against the reachable new target and
/// swapped into the registry under the structural fence; the old entry drains
/// via its `Arc`. NOT restart-required: it lands in `redialed`, traffic moves to
/// the new upstream, and the stored manifest advances to the new concurrency —
/// which the retired `transport_changed` (restart-required) path could never do.
#[tokio::test]
async fn live_rebuild_applies_a_slot_count_change_without_restart() {
    let (addr_a, calls_a) = spawn_tagged("A").await;
    let (addr_b, calls_b) = spawn_tagged("B").await;

    // Boot: one slot on A (concurrency 1).
    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map).await;
    let epoch = pool.tool_catalog_epoch();
    assert!(
        pool.is_connected("mock").await,
        "boot dial must connect to A"
    );
    assert_eq!(call_id(&pool).await, "A", "pre-rebuild calls must hit A");

    // Reload: point at B AND resize concurrency 1 → 2. The slot count changes, so
    // this is a live REBUILD (not an in-place redial). B is reachable, so the
    // rebuild's dial succeeds and the fresh entry replaces the old one.
    let mut resized = manifest_at(addr_b);
    resized.session = Some(SessionConfig {
        concurrency: Some(2),
        isolation: Some(SessionIsolation::Reuse),
        scope: None,
        retry_on_setup_failure: None,
    });
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".into(), resized);
    let report = tokio::time::timeout(Duration::from_secs(10), pool.reload_manifests(&fresh))
        .await
        .expect("reload_manifests hung");

    // Reported as a live re-dial/rebuild — NOT `added` (the name was already
    // live) and NOT restart-required.
    assert_eq!(
        report.redialed,
        vec!["mock".to_string()],
        "a reachable slot-count change is rebuilt live and reported redialed",
    );
    assert!(
        report.added.is_empty(),
        "a rebuild of an already-live entry is not an add",
    );
    assert!(report.redial_failed.is_empty());
    assert_eq!(
        epoch.current(),
        0,
        "a shape-only rebuild with identical descriptors stays quiet",
    );
    assert!(
        !report.requires_restart(),
        "a slot-count change is no longer restart-required — it is rebuilt live",
    );

    // The upstream stays connected across the rebuild and traffic moves to B.
    assert!(
        pool.is_connected("mock").await,
        "the rebuilt entry is connected to B"
    );
    assert_eq!(call_id(&pool).await, "B", "post-rebuild calls run on B");
    assert!(
        calls_b.load(Ordering::SeqCst) >= 1,
        "B now serves the upstream's calls",
    );
    assert_eq!(
        calls_a.load(Ordering::SeqCst),
        1,
        "A stops receiving calls once the entry is rebuilt onto B",
    );

    // The stored manifest advanced to BOTH the new url AND the new concurrency —
    // proof the rebuilt entry (new slot count) replaced the old one. The retired
    // transport_changed path left the manifest on the boot shape; the rebuild
    // advances it.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock still present");
    assert_eq!(
        stored.url,
        Some(format!("http://{addr_b}/mcp")),
        "a successful rebuild advances the stored url to the new target",
    );
    assert_eq!(
        stored.session.as_ref().and_then(|s| s.concurrency),
        Some(2),
        "a successful rebuild advances the stored concurrency to the new slot count",
    );
}

/// A live rebuild dials a FRESH connection, so it must run
/// schema-drift detection on it (against the inherited baseline) before serving
/// traffic — otherwise a resize that lands on an upstream whose tool schema
/// changed would accept the drifted tool without the ToolDrift audit/quarantine a
/// reconnect/redial publish triggers. A and B advertise the SAME tool (`ping`)
/// with DIFFERENT schemas; a resize from A to B must auto-quarantine `ping`.
#[tokio::test]
async fn live_rebuild_quarantines_a_drifted_tool_on_the_new_connection() {
    let (addr_a, _ca) = spawn_tagged_schema("A", serde_json::json!({})).await;
    let (addr_b, _cb) =
        spawn_tagged_schema("B", serde_json::json!({"drifted": {"type": "string"}})).await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    // QuarantineThreshold::All quarantines on ANY drift, regardless of risk tier.
    let pool = UpstreamPool::connect(map)
        .await
        .with_quarantine_threshold(QuarantineThreshold::All);
    assert!(pool.is_connected("mock").await, "boot dial connects to A");
    // The boot seed establishes A's schema as the baseline; nothing quarantined.
    assert_eq!(
        pool.quarantined_tools("mock").await,
        Some(vec![]),
        "no drift at boot — A's schema is the first observation",
    );

    // Resize concurrency 1 → 2 (a rebuild) AND retarget to B, whose `ping` schema
    // differs from A's. The rebuild inherits A's baseline and dials B.
    let mut resized = manifest_at(addr_b);
    resized.session = Some(SessionConfig {
        concurrency: Some(2),
        isolation: Some(SessionIsolation::Reuse),
        scope: None,
        retry_on_setup_failure: None,
    });
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".into(), resized);
    let report = tokio::time::timeout(Duration::from_secs(10), pool.reload_manifests(&fresh))
        .await
        .expect("reload_manifests hung");
    assert_eq!(
        report.redialed,
        vec!["mock".to_string()],
        "the slot-count change is rebuilt live",
    );

    // The drifted `ping` schema on the new (B) connection must be quarantined —
    // the rebuild ran drift detection rather than silently accepting it.
    assert_eq!(
        pool.quarantined_tools("mock").await,
        Some(vec!["ping".to_string()]),
        "a rebuild that lands on a drifted schema must quarantine the tool",
    );
    let health = pool.health_snapshot().await;
    assert!(health[0].connected);
    assert_eq!(health[0].connected_lanes, 2);
    assert_eq!(health[0].published_tool_count, 0);
    assert_eq!(health[0].quarantined_tool_count, 1);
}

/// An OLDER resize reload must not overwrite a
/// NEWER in-place reload's update just because it reaches the structural commit
/// first. P (older, gen 0) resizes `mock` to a reachable B (rebuild succeeds);
/// Q (newer, gen 1) updates `mock` in place (classification → High) and then
/// parks on a black-hole add, so Q commits AFTER P. P's commit must keep Q's
/// newer live entry (its `last_reload_gen` exceeds P's), not replace it with P's
/// stale rebuild — the reconcile generation fence.
#[tokio::test]
async fn older_resize_rebuild_does_not_overwrite_a_newer_in_place_update() {
    let (addr_a, _ca) = spawn_tagged("A").await;
    let (addr_b, _cb) = spawn_tagged("B").await;
    let park = spawn_black_hole().await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map)
        .await
        .with_redial_dial_timeout(Duration::from_millis(300));
    assert!(pool.is_connected("mock").await, "boot dial connects to A");
    assert_eq!(pool.tool_facts("mock", "ping").risk, RiskTier::Low);

    // P (older, polled first ⇒ gen 0): resize mock 1 → 2 AND retarget to the
    // reachable B, so its rebuild dial succeeds. Risk stays Low (the stale value).
    // P has only `mock`, so it reaches its commit without parking.
    let mut p_mock = manifest_at(addr_b);
    p_mock.session = Some(SessionConfig {
        concurrency: Some(2),
        isolation: Some(SessionIsolation::Reuse),
        scope: None,
        retry_on_setup_failure: None,
    });
    let mut p = BTreeMap::new();
    p.insert("mock".into(), p_mock);

    // Q (newer ⇒ gen 1): in-place classification of mock (same A url + concurrency
    // ⇒ NOT a resize) to High, AND add `zz` at the black hole so Q parks between
    // its in-place mutation and its commit — guaranteeing P commits first.
    let mut q_mock = manifest_at(addr_a);
    q_mock.tools[0].risk = RiskTier::High;
    let mut zz = manifest_at(park);
    zz.name = "zz".into();
    let mut q = BTreeMap::new();
    q.insert("mock".into(), q_mock);
    q.insert("zz".into(), zz);

    let (_rp, _rq) = tokio::join!(pool.reload_manifests(&p), pool.reload_manifests(&q));

    // Q (newer) wins: mock keeps Q's in-place High classification and A's url —
    // P's stale rebuild (Low, B, concurrency 2) did NOT replace it.
    assert_eq!(
        pool.tool_facts("mock", "ping").risk,
        RiskTier::High,
        "a newer in-place reload's classification must survive an older resize \
         rebuild that commits first",
    );
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock present");
    assert_eq!(
        stored.url,
        Some(format!("http://{addr_a}/mcp")),
        "the older resize's url must not win over the newer in-place update",
    );
}

/// A reload that BOTH changes a tool classification AND re-points the url at an
/// unreachable target: the live re-dial fails on every lane, so the old session
/// keeps serving (no blackout) — but the classification change must still apply
/// and re-publish on that surviving session. Pins that a failed re-dial does
/// not swallow a simultaneous classification update (the old session keeps
/// serving the NEW facts).
#[tokio::test]
async fn failed_redial_keeps_old_session_serving_and_still_applies_classifications() {
    let (addr_a, calls_a) = spawn_tagged("A").await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");
    assert_eq!(call_id(&pool).await, "A");
    // Baseline classification from the boot manifest.
    assert_eq!(pool.tool_facts("mock", "ping").risk, RiskTier::Low);

    // Reload: promote `ping` to High AND re-point at a refused port. Same
    // slot count ⇒ live re-dial is attempted; the refused target fails every
    // lane ⇒ redial_failed, old session kept.
    let mut bad = manifest_at(addr_a);
    bad.url = Some("http://127.0.0.1:1/mcp".into());
    bad.tools[0].risk = RiskTier::High;
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".into(), bad);
    let report = tokio::time::timeout(Duration::from_secs(10), pool.reload_manifests(&fresh))
        .await
        .expect("reload_manifests hung");

    assert_eq!(
        report.redial_failed,
        vec!["mock".to_string()],
        "the new url is unreachable, so the re-dial fails and keeps the old shape",
    );
    assert_eq!(
        report.classifications_updated,
        vec!["mock".to_string()],
        "a classification change must still be reported even when the co-resident \
         shape re-dial fails",
    );
    // The old session keeps serving — no blackout from a failed re-dial.
    assert!(
        pool.is_connected("mock").await,
        "a failed re-dial must keep the old session connected",
    );
    let before = calls_a.load(Ordering::SeqCst);
    assert_eq!(
        call_id(&pool).await,
        "A",
        "calls still land on the kept session"
    );
    assert!(
        calls_a.load(Ordering::SeqCst) > before,
        "the surviving session served the call",
    );
    // The new classification applied (facts read the stored manifest, which the
    // reload advanced for the hot field even though the shape re-dial failed).
    assert_eq!(pool.tool_facts("mock", "ping").risk, RiskTier::High);

    // The failed re-dial did NOT advance the stored url — the kept session is
    // still A, consistent with the unchanged stored shape.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock still present");
    assert_eq!(
        stored.url,
        Some(format!("http://{addr_a}/mcp")),
        "a failed re-dial must not advance the stored url",
    );
}

/// Concurrency guard for the re-dial commit ordering. Hammer reuse-mode calls
/// across a TWO-slot upstream while a live re-dial swaps every lane from A to B.
/// The re-dial commits under all slot conn write locks, so a call either runs
/// wholly on the old shape or wholly on the new — never a new-manifest snapshot
/// paired with a still-old connection. Pins: no deadlock / panic under
/// concurrent load, every served id is a real upstream (never a torn/blank
/// shape), and the pool converges on B. (Single-threaded runtime still
/// interleaves the caller and the re-dial at every `.await` — including the
/// points where the conn locks are taken and released — which is where the
/// ordering hazard lived.)
#[tokio::test]
async fn concurrent_calls_during_multislot_redial_stay_consistent_and_converge() {
    let (addr_a, _ca) = spawn_tagged("A").await;
    let (addr_b, _cb) = spawn_tagged("B").await;

    // concurrency: 2 ⇒ two slots, so the re-dial must take BOTH conn write locks
    // to commit — exercising the all-lanes atomic swap, not just a single slot.
    let two_slot = |addr: std::net::SocketAddr| {
        let mut m = manifest_at(addr);
        m.session = Some(SessionConfig {
            concurrency: Some(2),
            isolation: Some(SessionIsolation::Reuse),
            scope: None,
            retry_on_setup_failure: None,
        });
        m
    };
    let mut map = BTreeMap::new();
    map.insert("mock".into(), two_slot(addr_a));
    let pool = Arc::new(UpstreamPool::connect(map).await);
    assert!(pool.is_connected("mock").await, "boot dial must connect");

    // A caller task hammers the upstream throughout the re-dial.
    let caller = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move {
            let mut seen = std::collections::HashSet::new();
            for _ in 0..300 {
                // A call may race a lane mid-swap and get a transient
                // not-connected error — a clean miss, not a torn shape. We only
                // assert that no call ever observes a torn id, so ignore Err.
                if let Ok(res) = pool.call_tool("mock", "ping", None, None, None).await {
                    if let Some(t) = res
                        .content
                        .iter()
                        .find_map(|c| c.as_text().map(|t| t.text.clone()))
                    {
                        seen.insert(t);
                    }
                }
                tokio::task::yield_now().await;
            }
            seen
        })
    };

    // Concurrent live re-dial A -> B (same two-slot shape ⇒ stable count).
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".into(), two_slot(addr_b));
    let report = tokio::time::timeout(Duration::from_secs(10), pool.reload_manifests(&fresh))
        .await
        .expect("reload_manifests hung under concurrent load");
    assert_eq!(report.redialed, vec!["mock".to_string()]);
    assert!(report.redial_failed.is_empty());

    let seen = caller.await.expect("caller task panicked");
    // Every observed id is a real upstream id — never a torn/blank shape.
    for id in &seen {
        assert!(
            id == "A" || id == "B",
            "torn shape: a call observed an unexpected serving id {id:?}",
        );
    }
    // Once the re-dial has settled, traffic runs on the new shape.
    assert_eq!(
        call_id(&pool).await,
        "B",
        "the pool converges on the new shape after the re-dial",
    );
}

/// A re-dial whose new target accepts TCP but never speaks
/// MCP must time out per-lane and land in `redial_failed` — not wedge the
/// awaited `reload_manifests`. Uses a short `redial_dial_timeout` so the
/// black-hole path is exercised quickly; the OUTER timeout guards the test
/// against a regression where the dial hangs.
#[tokio::test]
async fn redial_to_an_unresponsive_target_times_out_to_redial_failed() {
    let (addr_a, _ca) = spawn_tagged("A").await;
    let black_hole = spawn_black_hole().await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map)
        .await
        .with_redial_dial_timeout(Duration::from_millis(500));
    assert!(
        pool.is_connected("mock").await,
        "boot dial must connect to A"
    );
    assert_eq!(call_id(&pool).await, "A");

    // Re-point at the black hole. Same transport + concurrency:1 ⇒ stable slot
    // count ⇒ live re-dial; the new target stalls the handshake, so the lane
    // must time out rather than hang the reload.
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".into(), manifest_at(black_hole));

    // OUTER guard: with the 500ms per-lane timeout the reload must finish in
    // well under 5s. A hang here means the dial timeout regressed.
    let report = tokio::time::timeout(Duration::from_secs(5), pool.reload_manifests(&fresh))
        .await
        .expect("reload must not hang on an unresponsive target — the dial timeout regressed");
    assert_eq!(
        report.redial_failed,
        vec!["mock".to_string()],
        "an unresponsive new target must surface as redial_failed",
    );
    assert!(report.redialed.is_empty());

    // The old session kept serving; the stored url was not advanced.
    assert!(
        pool.is_connected("mock").await,
        "the old session keeps serving when the re-dial times out",
    );
    assert_eq!(call_id(&pool).await, "A");
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock still present");
    assert_eq!(stored.url, Some(format!("http://{addr_a}/mcp")));
}

/// Two reloads that read DIFFERENT target shapes (B and C)
/// from the same live A and race must not let a slower one roll back a
/// committed newer one. The commit-time CAS lets exactly ONE win and supersedes
/// the other (which dialed fine but finds the stored shape already moved), so
/// the final stored shape and live session always agree on the winner — never a
/// torn rollback to the loser.
#[tokio::test]
async fn concurrent_divergent_reloads_commit_exactly_one_shape_no_rollback() {
    let (addr_a, _ca) = spawn_tagged("A").await;
    let (addr_b, _cb) = spawn_tagged("B").await;
    let (addr_c, _cc) = spawn_tagged("C").await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map).await;
    assert!(
        pool.is_connected("mock").await,
        "boot dial must connect to A"
    );

    // Race a re-dial to B against a re-dial to C, both from live A. Both targets
    // are reachable, so neither lane fails to dial — the only way exactly one
    // wins is the commit-time CAS.
    let mut fresh_b = BTreeMap::new();
    fresh_b.insert("mock".into(), manifest_at(addr_b));
    let mut fresh_c = BTreeMap::new();
    fresh_c.insert("mock".into(), manifest_at(addr_c));
    let (rb, rc) = tokio::join!(
        pool.reload_manifests(&fresh_b),
        pool.reload_manifests(&fresh_c),
    );

    // Exactly one reload reports the redial; the other is superseded — it
    // reports neither `redialed` (the CAS aborted its commit) nor `redial_failed`
    // (its dial succeeded).
    let b_won = rb.redialed == vec!["mock".to_string()];
    let c_won = rc.redialed == vec!["mock".to_string()];
    assert!(
        b_won ^ c_won,
        "exactly one concurrent re-dial must win (rb.redialed={:?}, rc.redialed={:?})",
        rb.redialed,
        rc.redialed,
    );
    assert!(
        rb.redial_failed.is_empty() && rc.redial_failed.is_empty(),
        "both targets are reachable — neither lane should be redial_failed",
    );

    // No rollback, no torn state: the stored shape and the live session agree,
    // and both are the WINNER's — the loser's dial was discarded, not committed.
    let (winner_addr, winner_id) = if b_won { (addr_b, "B") } else { (addr_c, "C") };
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock still present");
    assert_eq!(
        stored.url,
        Some(format!("http://{winner_addr}/mcp")),
        "the stored shape is the winner's",
    );
    assert_eq!(
        call_id(&pool).await,
        winner_id,
        "the live session is the winner's — never rolled back to the loser",
    );
}

/// A live re-dial racing a concurrent REMOVAL of the same upstream
/// must not resurrect a tombstoned entry. One reload re-points `mock` at B (a
/// live re-dial); another reads a set without `mock` and tombstones it. The
/// re-dial re-checks `removed` before each lane's swap, so whichever lands
/// first, the entry ends RETIRED — a later reconnect must refuse to revive it.
#[tokio::test]
async fn redial_racing_a_removal_leaves_the_entry_retired_not_revived() {
    let (addr_a, _ca) = spawn_tagged("A").await;
    let (addr_b, _cb) = spawn_tagged("B").await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");

    // One reload keeps mock but re-points it at B (live re-dial); the other
    // drops mock entirely (as when disk loses the file between two reload
    // reads). They race.
    let mut keep_new = BTreeMap::new();
    keep_new.insert("mock".into(), manifest_at(addr_b));
    let drop_all: BTreeMap<String, UpstreamManifest> = BTreeMap::new();
    let (r_keep, r_drop) = tokio::join!(
        pool.reload_manifests(&keep_new),
        pool.reload_manifests(&drop_all),
    );

    // The dropping reload retired mock.
    assert_eq!(
        r_drop.removed,
        vec!["mock".to_string()],
        "the reload without mock must tombstone it",
    );
    // B is reachable, so the re-dial is never `redial_failed`: it either applied
    // before the tombstone (redialed) or was tombstoned mid-swap (reported as
    // neither). Asserting redial_failed is empty pins that the removal race
    // never masquerades as a dial failure.
    assert!(
        r_keep.redial_failed.is_empty(),
        "a reachable re-dial racing a removal must not report redial_failed",
    );

    // Whichever raced first, the entry is RETIRED: a reconnect must refuse to
    // revive it — the re-dial did not resurrect a tombstoned upstream.
    assert!(
        !pool.reconnect_one("mock").await,
        "a removed entry must stay retired even when a live re-dial raced its removal",
    );
}

/// On a SUCCESSFUL re-dial the coupled hot-reloadable identity
/// fields advance ATOMICALLY with the connection shape. A reload re-points
/// `mock` at B (shape change) AND adds `tier_c_peer` (a coupled identity field);
/// both must land together, and the reload reports `identity_updated` only
/// because the re-dial applied it.
#[tokio::test]
async fn successful_redial_advances_coupled_identity_with_the_shape() {
    let (addr_a, _ca) = spawn_tagged("A").await;
    let (addr_b, _cb) = spawn_tagged("B").await;

    let mut map = BTreeMap::new();
    map.insert("mock".into(), manifest_at(addr_a));
    let pool = UpstreamPool::connect(map).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");
    let before = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock present");
    assert!(before.tier_c_peer.is_none(), "baseline has no tier_c_peer");

    // Re-point at B (shape change) AND add the coupled identity field.
    let peer = uuid::Uuid::from_u128(0x315);
    let mut nb = manifest_at(addr_b);
    nb.tier_c_peer = Some(peer);
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".into(), nb);
    let report = tokio::time::timeout(Duration::from_secs(10), pool.reload_manifests(&fresh))
        .await
        .expect("reload_manifests hung");

    assert_eq!(report.redialed, vec!["mock".to_string()]);
    assert_eq!(
        report.identity_updated,
        vec!["mock".to_string()],
        "identity_updated is reported once the re-dial actually applied it",
    );
    // The shape and the coupled identity advanced together.
    let stored = pool
        .manifests()
        .into_iter()
        .find(|m| m.name == "mock")
        .expect("mock still present");
    assert_eq!(stored.url, Some(format!("http://{addr_b}/mcp")));
    assert_eq!(stored.tier_c_peer, Some(peer));
}

/// The exported bounded `tools/list` reader — the one the `classify`
/// scaffold builds manifests from — must traverse every page exactly like
/// the serving path: a single-page read would silently omit later-page
/// tools, and the scaffolded manifest would quarantine them at
/// annotation-mode cutover.
#[tokio::test]
async fn exported_tools_list_reader_traverses_every_page() {
    use rmcp::ServiceExt as _;
    let (addr, control) = spawn_dynamic_catalog().await;
    control.paginate.store(true, Ordering::SeqCst);

    let transport =
        rmcp::transport::StreamableHttpClientTransport::from_uri(format!("http://{addr}/mcp"));
    let client = rmcp::model::ClientInfo::default()
        .serve(transport)
        .await
        .expect("dial mock upstream");
    let names: Vec<String> = waygate_upstream::list_all_tools(&client)
        .await
        .expect("paginated tools/list")
        .tools
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    let _ = client.cancel().await;
    assert_eq!(
        names,
        vec!["reddit_search", "twitter_search"],
        "every tools/list page must land in the scaffold's source catalog",
    );
}

/// SEP-2549 hint capture: the paginated reader keeps the strictest
/// (minimum) `ttlMs` across pages, a hint on only one page still counts,
/// and a hint-free listing stays `None` — absent means absent, never a
/// default.
#[tokio::test]
async fn tools_list_reader_keeps_the_strictest_page_ttl_hint() {
    async fn listed_hint(control_setup: impl Fn(&DynamicCatalogControl)) -> Option<u64> {
        use rmcp::ServiceExt as _;
        let (addr, control) = spawn_dynamic_catalog().await;
        control_setup(&control);
        let transport =
            rmcp::transport::StreamableHttpClientTransport::from_uri(format!("http://{addr}/mcp"));
        let client = rmcp::model::ClientInfo::default()
            .serve(transport)
            .await
            .expect("dial mock upstream");
        let listed = waygate_upstream::list_all_tools(&client)
            .await
            .expect("paginated tools/list");
        let _ = client.cancel().await;
        listed.ttl_hint_ms
    }

    let min_across_pages = listed_hint(|c| {
        c.paginate.store(true, Ordering::SeqCst);
        *c.ttl_ms_first_page.lock().unwrap() = Some(30_000);
        *c.ttl_ms_later_pages.lock().unwrap() = Some(5_000);
    })
    .await;
    assert_eq!(min_across_pages, Some(5_000), "strictest page hint wins");

    let single_hinted_page = listed_hint(|c| {
        c.paginate.store(true, Ordering::SeqCst);
        *c.ttl_ms_later_pages.lock().unwrap() = Some(7_000);
    })
    .await;
    assert_eq!(
        single_hinted_page,
        Some(7_000),
        "a hint on any page still bounds the listing's freshness"
    );

    let unhinted = listed_hint(|_| {}).await;
    assert_eq!(unhinted, None, "no page hinted — the listing carries none");
}

/// The freshness schedule: hints may shorten the maximum catalog age, while
/// unhinted connected upstreams use that maximum as their fallback; the floor
/// and ceiling clamp hints in both directions; and a refresh re-anchors the
/// deadline.
#[tokio::test]
async fn catalog_refresh_due_is_hint_driven_clamped_and_reanchored() {
    let (hinted_addr, hinted_control) = spawn_dynamic_catalog().await;
    *hinted_control.ttl_ms_first_page.lock().unwrap() = Some(60_000);
    let (legacy_addr, _legacy_control) = spawn_dynamic_catalog().await;

    let mut hinted = dynamic_manifest_at(hinted_addr);
    hinted.name = "hinted".into();
    let mut legacy = dynamic_manifest_at(legacy_addr);
    legacy.name = "legacy".into();
    let pool = UpstreamPool::connect(BTreeMap::from([
        ("hinted".to_owned(), hinted),
        ("legacy".to_owned(), legacy),
    ]))
    .await;

    let day = Duration::from_secs(86_400);
    let now = std::time::Instant::now();

    // Fresh listing: nothing is due yet.
    assert!(
        pool.catalog_refresh_due(Duration::ZERO, day, now)
            .await
            .is_empty(),
        "a listing dialed moments ago is still fresh"
    );

    // Past the 60s hint but before the one-day ceiling: only the hinted
    // upstream is due.
    assert_eq!(
        pool.catalog_refresh_due(Duration::ZERO, day, now + Duration::from_secs(120))
            .await,
        vec!["hinted".to_owned()],
        "hint expiry schedules exactly the hinted upstream"
    );

    // Floor clamp: a floor above the hint stretches the deadline out.
    assert!(
        pool.catalog_refresh_due(
            Duration::from_secs(3_600),
            day,
            now + Duration::from_secs(120)
        )
        .await
        .is_empty(),
        "the floor bounds how often a tiny hint can force a refresh"
    );

    // The scheduled path re-evaluates eligibility under the session guard
    // before any traffic: a hint-free upstream is not eligible until its
    // fallback deadline, an unknown server reports as such, and neither sends
    // a dial.
    let recheck_at = now + Duration::from_secs(120);
    let actor = admin_principal();
    assert!(
        matches!(
            pool.scheduled_catalog_refresh("legacy", Duration::ZERO, day, recheck_at, &actor)
                .await,
            ScheduledCatalogRefresh::NotDue
        ),
        "a hint-free upstream stays untouched before the fallback deadline"
    );
    assert!(matches!(
        pool.scheduled_catalog_refresh("absent", Duration::ZERO, day, recheck_at, &actor)
            .await,
        ScheduledCatalogRefresh::Unknown
    ));

    // A clamp that pushes the deadline beyond the representable Instant
    // range means "never" — no candidate, and no panic in the driver.
    assert!(
        pool.catalog_refresh_due(Duration::MAX, Duration::MAX, recheck_at)
            .await
            .is_empty(),
        "an unrepresentable deadline never arrives"
    );

    // Ceiling clamp: a ceiling below the hint pulls the deadline in.
    let (huge_addr, huge_control) = spawn_dynamic_catalog().await;
    *huge_control.ttl_ms_first_page.lock().unwrap() = Some(u64::from(u32::MAX) * 1_000);
    let mut huge = dynamic_manifest_at(huge_addr);
    huge.name = "huge".into();
    let pool_huge = UpstreamPool::connect(BTreeMap::from([("huge".to_owned(), huge)])).await;
    assert_eq!(
        pool_huge
            .catalog_refresh_due(
                Duration::ZERO,
                Duration::from_secs(1),
                std::time::Instant::now() + Duration::from_secs(5)
            )
            .await,
        vec!["huge".to_owned()],
        "the ceiling bounds how far a huge hint can postpone a refresh"
    );

    // A refresh re-dials the lane, which re-anchors the hint's deadline.
    // The probe instant must discriminate the two anchors: it sits past the
    // ORIGINAL deadline's upper bound (`now` was taken after the connect,
    // so the original anchor cannot be later than it) but inside the
    // re-anchored one — a refresh that kept the original `dialed_at` would
    // fail the emptiness assertion. The deliberate sleep separates the two
    // anchors by more than the probe's 250ms margin.
    let original_deadline_ceiling = now + Duration::from_secs(60);
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Run the refresh through the scheduled path itself: a due, eligible
    // upstream passes the under-guard re-check and gets refreshed.
    let ScheduledCatalogRefresh::Refreshed { report, trigger } = pool
        .scheduled_catalog_refresh(
            "hinted",
            Duration::ZERO,
            day,
            std::time::Instant::now() + Duration::from_secs(120),
            &actor,
        )
        .await
    else {
        panic!("a due, eligible upstream must be refreshed by the scheduled path");
    };
    assert_eq!(trigger, CatalogFreshnessTrigger::TtlHint);
    assert_eq!(report.outcome, CatalogRefreshOutcome::Unchanged);
    let discriminator = original_deadline_ceiling + Duration::from_millis(250);
    assert!(
        pool.catalog_refresh_due(Duration::ZERO, day, discriminator)
            .await
            .is_empty(),
        "a moment past the original deadline must sit inside the re-anchored one"
    );
    assert_eq!(
        pool.catalog_refresh_due(
            Duration::ZERO,
            day,
            std::time::Instant::now() + Duration::from_secs(120)
        )
        .await,
        vec!["hinted".to_owned()],
        "the re-anchored deadline still expires on the hint's cadence"
    );
}

/// Regression for #969: an upstream without SEP-2549 subscriptions or a
/// `ttlMs` hint can add a discriminator value after deployment. The gateway
/// must retain the last-good admitted schema until its bounded fallback fires,
/// then publish the new enum and validator identity through the normal refresh
/// pipeline without a process restart.
#[tokio::test]
async fn unhinted_fallback_refreshes_a_stale_operation_enum() {
    let (addr, control) = spawn_dynamic_catalog().await;
    control.operation_schema.store(true, Ordering::SeqCst);
    let sink = Arc::new(InMemorySink::new());
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await
    .with_evidence(sink.clone());
    let actor = admin_principal();

    let ResolvedInvocationTool::Ready(before) = pool
        .resolve_invocation_tool("default", "mock", "reddit_search")
        .await
    else {
        panic!("the initially admitted tool must resolve");
    };
    let before_schema = before.input_schema().expect("input schema");
    let before_hash = waygate_catalog::validator_schema_hash(before_schema);
    assert_eq!(
        before_schema.pointer("/properties/operation/enum"),
        Some(&serde_json::json!(["projects.read"])),
    );

    control
        .expanded_operation_enum
        .store(true, Ordering::SeqCst);
    let now = std::time::Instant::now();
    let fallback = Duration::from_secs(60);
    assert!(matches!(
        pool.scheduled_catalog_refresh(
            "mock",
            Duration::ZERO,
            fallback,
            now + Duration::from_secs(30),
            &actor,
        )
        .await,
        ScheduledCatalogRefresh::NotDue
    ));

    let ResolvedInvocationTool::Ready(still_stale) = pool
        .resolve_invocation_tool("default", "mock", "reddit_search")
        .await
    else {
        panic!("the last-good admitted tool must remain available");
    };
    assert_eq!(
        waygate_catalog::validator_schema_hash(
            still_stale.input_schema().expect("stale input schema")
        ),
        before_hash,
        "the gateway must not invent a schema change before it refreshes",
    );

    let ScheduledCatalogRefresh::Refreshed { report, trigger } = pool
        .scheduled_catalog_refresh(
            "mock",
            Duration::ZERO,
            fallback,
            now + Duration::from_secs(120),
            &actor,
        )
        .await
    else {
        panic!("the unhinted fallback deadline must refresh the catalog");
    };
    assert_eq!(trigger, CatalogFreshnessTrigger::UnhintedFallback);
    assert_eq!(report.outcome, CatalogRefreshOutcome::Updated);
    assert_eq!(report.schema_changed, vec!["reddit_search"]);

    let ResolvedInvocationTool::Ready(after) = pool
        .resolve_invocation_tool("default", "mock", "reddit_search")
        .await
    else {
        panic!("the refreshed admitted tool must resolve");
    };
    let after_schema = after.input_schema().expect("refreshed input schema");
    assert_eq!(
        after_schema.pointer("/properties/operation/enum"),
        Some(&serde_json::json!([
            "projects.read",
            "certificatePolicies.update"
        ])),
    );
    assert_ne!(
        waygate_catalog::validator_schema_hash(after_schema),
        before_hash,
        "publishing the enum change must rotate validator identity",
    );

    let events = sink.snapshot().await;
    let refresh = events
        .iter()
        .find(|event| event.action == "UpstreamCatalogRefresh")
        .expect("the scheduled refresh must be attributed");
    assert!(
        refresh
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("trigger=unhinted_fallback")),
        "operators must be able to distinguish the fallback trigger",
    );
}

/// A failed fallback refresh keeps the last-good session and its overdue
/// anchor, so the next driver tick retries instead of silently granting a new
/// freshness window to a catalog it could not re-list.
#[tokio::test]
async fn failed_unhinted_fallback_stays_due_for_retry() {
    let (addr, control) = spawn_dynamic_catalog().await;
    let pool = UpstreamPool::connect(BTreeMap::from([(
        "mock".to_owned(),
        dynamic_manifest_at(addr),
    )]))
    .await;
    control.fail_list.store(true, Ordering::SeqCst);
    let actor = admin_principal();
    let due_at = std::time::Instant::now() + Duration::from_secs(120);

    let ScheduledCatalogRefresh::Refreshed { report, trigger } = pool
        .scheduled_catalog_refresh(
            "mock",
            Duration::ZERO,
            Duration::from_secs(60),
            due_at,
            &actor,
        )
        .await
    else {
        panic!("the overdue unhinted upstream must attempt a refresh");
    };
    assert_eq!(trigger, CatalogFreshnessTrigger::UnhintedFallback);
    assert_eq!(report.outcome, CatalogRefreshOutcome::Failed);
    assert_eq!(
        pool.catalog_refresh_due(Duration::ZERO, Duration::from_secs(60), due_at)
            .await,
        vec!["mock".to_owned()],
        "a failed listing must not re-anchor the freshness deadline",
    );
    assert!(
        pool.list_tools("mock")
            .await
            .expect("last-good inventory")
            .iter()
            .any(|tool| tool.name.as_ref() == "reddit_search"),
        "a failed fallback must preserve the last-good catalog",
    );
}

/// The freshness anchor is taken before the first page request: the
/// reader's `listed_at` precedes the mock's server-side handling of the
/// first page, so time spent fetching later pages can never extend an
/// earlier page's clamped deadline. Causally ordered — no timing margins.
#[tokio::test]
async fn tools_list_freshness_anchor_precedes_the_first_page() {
    use rmcp::ServiceExt as _;
    let (addr, control) = spawn_dynamic_catalog().await;
    control.paginate.store(true, Ordering::SeqCst);
    control.delay_list.store(true, Ordering::SeqCst);
    *control.ttl_ms_first_page.lock().unwrap() = Some(60_000);
    let transport =
        rmcp::transport::StreamableHttpClientTransport::from_uri(format!("http://{addr}/mcp"));
    let client = rmcp::model::ClientInfo::default()
        .serve(transport)
        .await
        .expect("dial mock upstream");
    let listed = waygate_upstream::list_all_tools(&client)
        .await
        .expect("paginated tools/list");
    let _ = client.cancel().await;
    let first_page_at = control
        .first_list_at
        .lock()
        .unwrap()
        .expect("mock served at least one page");
    assert!(
        listed.listed_at <= first_page_at,
        "the anchor must not move later than the first page's production time"
    );
}

/// Version bridging end to end: the default `auto` lifecycle negotiates
/// 2026-07-28 against a discovery-capable upstream (and dispatch works on
/// that stateless leg), `protocol: legacy` pins the initialize handshake
/// against the very same upstream, and the negotiated generation is
/// visible in the status snapshot — the fleet-migration observability
/// this item exists for.
#[tokio::test]
async fn auto_negotiates_2026_and_legacy_override_pins_the_old_generation() {
    let schema_properties = serde_json::json!({"message": {"type": "string"}});
    let (addr, _calls) = spawn_tagged_schema("gen-auto", schema_properties.clone()).await;
    let pool =
        UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest_at(addr))])).await;
    let status = pool.status_snapshot().await;
    assert_eq!(
        status[0].health.protocol_versions,
        vec!["2026-07-28".to_owned()],
        "auto against a discovery-capable upstream negotiates the new generation"
    );
    assert_eq!(
        call_id(&pool).await,
        "gen-auto",
        "dispatch works on the 2026-negotiated leg"
    );

    let (addr, _calls) = spawn_tagged_schema("gen-legacy", schema_properties).await;
    let mut legacy = manifest_at(addr);
    legacy.protocol = waygate_upstream::UpstreamProtocol::Legacy;
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), legacy)])).await;
    let status = pool.status_snapshot().await;
    assert_eq!(
        status[0].health.protocol_versions,
        vec!["2025-11-25".to_owned()],
        "the operator override skips discovery entirely"
    );
    assert_eq!(
        call_id(&pool).await,
        "gen-legacy",
        "dispatch works unchanged on the pinned legacy leg"
    );
}

/// A protocol-only manifest edit is a connection-shape change on the LIVE
/// reload path: `reload_manifests` re-dials the upstream under the new
/// lifecycle and the negotiated generation flips — pinned end to end
/// because the trigger predicate and the CAS comparison are separate
/// code, and a drift between them silently ignores the operator's edit.
#[tokio::test]
async fn protocol_only_reload_redials_and_renegotiates() {
    let schema_properties = serde_json::json!({"message": {"type": "string"}});
    let (addr, _calls) = spawn_tagged_schema("gen-flip", schema_properties).await;
    let mut legacy = manifest_at(addr);
    legacy.protocol = waygate_upstream::UpstreamProtocol::Legacy;
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), legacy)])).await;
    assert_eq!(
        pool.status_snapshot().await[0].health.protocol_versions,
        vec!["2025-11-25".to_owned()],
    );

    // Same manifest with only `protocol:` back at the default `auto`.
    let report = pool
        .reload_manifests(&BTreeMap::from([("mock".to_owned(), manifest_at(addr))]))
        .await;
    assert_eq!(
        report.redialed,
        vec!["mock".to_owned()],
        "a protocol-only edit must re-dial, not apply silently in place"
    );
    assert_eq!(
        pool.status_snapshot().await[0].health.protocol_versions,
        vec!["2026-07-28".to_owned()],
        "the re-dial ran the new lifecycle and the stored shape follows it"
    );
    assert_eq!(call_id(&pool).await, "gen-flip");
}

/// How an upstream that predates the stateless generation refuses the
/// `server/discover` probe.
///
/// Every variant is a refusal observed from a real deployed MCP server, and
/// none of them is the `METHOD_NOT_FOUND` the SDK's own downgrade waits for
/// — such a server rejects the probe at its transport or session layer,
/// before any method dispatch could answer that the method is unknown.
#[derive(Clone, Copy)]
struct DiscoveryRefusal {
    label: &'static str,
    status: u16,
    /// `Some(code)` renders a JSON-RPC error body carrying that code, the
    /// shape most SDKs return; `None` renders the bare text body the rest
    /// return instead.
    jsonrpc_code: Option<i32>,
    message: &'static str,
}

const DISCOVERY_REFUSALS: &[DiscoveryRefusal] = &[
    DiscoveryRefusal {
        label: "invalid-request unsupported version",
        status: 400,
        jsonrpc_code: Some(-32600),
        message: "Bad Request: Unsupported protocol version: 2026-07-28",
    },
    DiscoveryRefusal {
        label: "server-error unsupported version",
        status: 400,
        jsonrpc_code: Some(-32000),
        message: "Bad Request: Unsupported protocol version: 2026-07-28",
    },
    DiscoveryRefusal {
        label: "missing session id",
        status: 400,
        jsonrpc_code: Some(-32600),
        message: "Bad Request: Missing session ID",
    },
    DiscoveryRefusal {
        label: "expects initialize first",
        status: 422,
        jsonrpc_code: None,
        message: "Unexpected message, expect initialize request",
    },
    DiscoveryRefusal {
        label: "invalid session id",
        status: 404,
        jsonrpc_code: None,
        message: "Invalid session ID",
    },
    // The one refusal the SDK downgrades on natively. Held in the same table
    // so the bridge can never regress it: whatever else changes, a peer that
    // answers this way must still end up on the legacy leg.
    DiscoveryRefusal {
        label: "method not found",
        status: 200,
        jsonrpc_code: Some(-32601),
        message: "Method not found",
    },
];

/// A fully working legacy upstream: a real MCP server with the discovery
/// probe refused in front of it, so `initialize` and everything after it
/// behave exactly as they do on a server that never learned to discover.
async fn spawn_discovery_refusing(
    id: &'static str,
    refusal: DiscoveryRefusal,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let upstream = TaggedUpstream {
        id,
        calls: calls.clone(),
        schema_props: serde_json::json!({}),
    };
    let svc = StreamableHttpService::new(
        move || Ok(upstream.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app = axum::Router::new()
        .nest_service("/mcp", svc)
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| async move {
                refuse_discovery(refusal, req, next).await
            },
        ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, calls)
}

async fn refuse_discovery(
    refusal: DiscoveryRefusal,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20)
        .await
        .expect("read request body");
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
    let is_discover = parsed
        .as_ref()
        .and_then(|v| v.get("method"))
        .and_then(|m| m.as_str())
        == Some("server/discover");

    if !is_discover {
        let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes));
        return next.run(req).await;
    }

    let status = axum::http::StatusCode::from_u16(refusal.status).expect("valid status");
    match refusal.jsonrpc_code {
        Some(code) => {
            // Echo the probe's own id, the way a server answering a request
            // it dislikes does.
            let id = parsed
                .as_ref()
                .and_then(|v| v.get("id"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            (
                status,
                axum::Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": code, "message": refusal.message},
                })),
            )
                .into_response()
        }
        None => (status, refusal.message).into_response(),
    }
}

/// The `auto` bridge, end to end against a server that cannot discover.
///
/// An upstream that refuses the discovery probe is not an upstream that is
/// down, and the whole point of `auto` is that an operator does not have to
/// know which generation a server speaks before pointing the gateway at it.
/// Asserting the negotiated generation rather than mere connectivity is what
/// makes this a version-bridging test: connecting while silently reporting
/// the wrong generation would leave dispatch making 2026-only decisions on a
/// legacy leg.
#[tokio::test]
async fn auto_bridges_to_legacy_through_every_observed_discovery_refusal() {
    for refusal in DISCOVERY_REFUSALS {
        let (addr, _calls) = spawn_discovery_refusing("gen-bridged", *refusal).await;
        let pool =
            UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest_at(addr))])).await;
        let status = pool.status_snapshot().await;

        assert_eq!(
            status[0].health.protocol_versions,
            vec!["2025-11-25".to_owned()],
            "{}: auto must reach the legacy generation",
            refusal.label
        );
        assert_eq!(
            call_id(&pool).await,
            "gen-bridged",
            "{}: dispatch must work on the bridged leg",
            refusal.label
        );
    }
}

/// The bridge belongs to `auto` alone. An operator who pinned `2026-07-28`
/// asked for the new generation specifically; downgrading them anyway would
/// hide the very migration failure the pin exists to surface.
#[tokio::test]
async fn an_explicit_2026_pin_never_bridges_to_legacy() {
    let (addr, _calls) = spawn_discovery_refusing("gen-pinned", DISCOVERY_REFUSALS[0]).await;
    let mut pinned = manifest_at(addr);
    pinned.protocol = waygate_upstream::UpstreamProtocol::V20260728;
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), pinned)])).await;
    let status = pool.status_snapshot().await;

    assert_eq!(
        status[0].health.connected_lanes, 0,
        "a pinned 2026-07-28 upstream that cannot discover must fail the dial"
    );
    assert!(
        status[0].health.protocol_versions.is_empty(),
        "a failed pinned dial must report no negotiated generation, got {:?}",
        status[0].health.protocol_versions
    );
}
