//! End-to-end proof of upstream `subscriptions/listen` fan-in against a
//! real streamable-HTTP upstream: the pool's background listener consumes
//! the upstream's `tools/list_changed` stream and drives the existing
//! catalog refresh path, rate-bounded, exiting when the upstream cannot
//! serve it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
    Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerInfo, ServerNotification, SubscriptionFilter, Tool, ToolListChangedNotification,
};
use rmcp::service::{RequestContext, SubscriptionContext};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use waygate_mcp::protocol::RiskTier;
use waygate_oidc::{AuthMethod, Principal};
use waygate_upstream::pool::listen::CatalogListenerExit;
use waygate_upstream::{
    ToolClassification, Transport, UpstreamManifest, UpstreamPool, UpstreamProtocol,
};

/// Mock upstream: one tool, a `tools/list` call counter, a NON-coalescing
/// change signal its `listen` impl fans out one wire notification per
/// event, and a counter of notifications actually sent on the wire.
#[derive(Clone)]
struct ListenUpstream {
    list_calls: Arc<AtomicUsize>,
    sent_notifications: Arc<AtomicUsize>,
    changes: broadcast::Sender<u64>,
}

impl ServerHandler for ListenUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new("listen-upstream", "0.0.0"))
        .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        let schema = serde_json::json!({"type": "object", "properties": {}})
            .as_object()
            .cloned()
            .unwrap();
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "noop".to_string(),
            "no-op tool".to_string(),
            Arc::new(schema),
        )]))
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        Ok(CallToolResult::success(vec![Content::text("ok")]).into())
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        let mut accepted = SubscriptionFilter::new();
        if requested.tools_list_changed == Some(true) {
            accepted.tools_list_changed = Some(true);
        }
        Some(accepted)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), McpError> {
        let mut changes = self.changes.subscribe();
        loop {
            tokio::select! {
                _ = context.cancelled() => return Ok(()),
                changed = changes.recv() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    if context
                        .sink()
                        .send(ServerNotification::ToolListChangedNotification(
                            ToolListChangedNotification::default(),
                        ))
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                    self.sent_notifications.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }
}

struct Harness {
    addr: std::net::SocketAddr,
    list_calls: Arc<AtomicUsize>,
    sent_notifications: Arc<AtomicUsize>,
    changes: broadcast::Sender<u64>,
}

async fn spawn_upstream() -> Harness {
    let list_calls = Arc::new(AtomicUsize::new(0));
    let sent_notifications = Arc::new(AtomicUsize::new(0));
    let (changes, _keepalive) = broadcast::channel(64);
    std::mem::forget(_keepalive);
    let handler = ListenUpstream {
        list_calls: list_calls.clone(),
        sent_notifications: sent_notifications.clone(),
        changes: changes.clone(),
    };
    let svc = StreamableHttpService::new(
        move || Ok(handler.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app: Router<()> = Router::new().nest_service("/mcp", svc);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Harness {
        addr,
        list_calls,
        sent_notifications,
        changes,
    }
}

fn manifest(addr: std::net::SocketAddr, protocol: UpstreamProtocol) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: "mock".into(),
        transport: Transport::Http,
        protocol,
        url: Some(format!("http://{addr}/mcp")),
        command: None,
        tools: vec![ToolClassification::new("noop", RiskTier::Low, false, false)],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        // One lane, so one catalog refresh is exactly one tools/list call
        // and the counters below can assert EXACT refresh counts.
        session: Some(waygate_upstream::SessionConfig {
            concurrency: Some(1),
            isolation: None,
            scope: None,
            retry_on_setup_failure: None,
        }),
    }
}

async fn connect(addr: std::net::SocketAddr, protocol: UpstreamProtocol) -> Arc<UpstreamPool> {
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), manifest(addr, protocol));
    Arc::new(UpstreamPool::connect(manifests).await)
}

fn actor() -> Principal {
    Principal {
        sub: "system:subscription-listen".into(),
        email: None,
        groups: Vec::new(),
        issuer: "gateway:internal".into(),
        scopes: Vec::new(),
        tenant: waygate_core::TenantId::default(),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        roles: Vec::new(),
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn wait_for_list_calls(harness: &Harness, at_least: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if harness.list_calls.load(Ordering::SeqCst) >= at_least {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected at least {at_least} tools/list calls, saw {}",
            harness.list_calls.load(Ordering::SeqCst)
        )
    });
}

/// The listener consumes the upstream's change stream and drives the
/// existing refresh path: each out-of-window event produces a refresh
/// (visible as new `tools/list` traffic), while a burst inside the rate
/// window coalesces instead of refreshing per event.
#[tokio::test]
#[ignore = "manual live concurrency and timing diagnostic; excluded from required CI"]
async fn listener_drives_rate_bounded_event_refreshes() {
    let harness = spawn_upstream().await;
    let pool = connect(harness.addr, UpstreamProtocol::Auto).await;
    assert!(pool.is_connected("mock").await);
    assert_eq!(
        pool.catalog_listener_candidates().await,
        vec!["mock".to_owned()],
        "a connected 2026 HTTP upstream is a listener candidate",
    );
    let baseline = harness.list_calls.load(Ordering::SeqCst);

    let shutdown = CancellationToken::new();
    let listener_pool = Arc::clone(&pool);
    let listener_shutdown = shutdown.clone();
    let listener = tokio::spawn(async move {
        listener_pool
            .run_catalog_listener("mock", Duration::from_secs(1), &actor(), listener_shutdown)
            .await
    });
    // Give the listener a moment to establish its subscription.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // One event → exactly one refresh (single lane ⇒ one tools/list).
    harness.changes.send(1).expect("listener subscribed");
    wait_for_list_calls(&harness, baseline + 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after_first = harness.list_calls.load(Ordering::SeqCst);
    assert_eq!(after_first, baseline + 1, "one event drives one refresh");

    // Three DELIVERED wire events inside the rate window coalesce into
    // exactly one trailing refresh. The broadcast source does not
    // coalesce, and the mock counts the notifications it actually sent,
    // so the three deliveries are proven — the bound is the gateway's.
    harness.changes.send(2).expect("listener subscribed");
    harness.changes.send(3).expect("listener subscribed");
    harness.changes.send(4).expect("listener subscribed");
    wait_for_list_calls(&harness, after_first + 1).await;
    // Settle well past the rate window: no further refresh may land.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        harness.list_calls.load(Ordering::SeqCst),
        after_first + 1,
        "a burst inside the window coalesces into exactly one trailing refresh",
    );
    assert_eq!(
        harness.sent_notifications.load(Ordering::SeqCst),
        4,
        "all four events were delivered on the wire (the source never coalesces)",
    );

    shutdown.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(5), listener)
        .await
        .expect("listener exits on shutdown")
        .expect("listener task completes");
    assert_eq!(outcome.exit, CatalogListenerExit::Shutdown);
    assert!(
        outcome.shape.is_some(),
        "the outcome reports the shape the listener dialed (the cooldown anchor)",
    );
}

/// A `protocol: legacy` upstream is never a candidate and a listener
/// pointed at it refuses as unsupported — push invalidation exists only on
/// the generation whose transport carries it.
#[tokio::test]
async fn legacy_pinned_upstream_is_not_listened_to() {
    let harness = spawn_upstream().await;
    let pool = connect(harness.addr, UpstreamProtocol::Legacy).await;
    assert!(pool.is_connected("mock").await);
    assert!(pool.catalog_listener_candidates().await.is_empty());

    let outcome = pool
        .run_catalog_listener(
            "mock",
            Duration::from_millis(100),
            &actor(),
            CancellationToken::new(),
        )
        .await;
    assert_eq!(outcome.exit, CatalogListenerExit::Unsupported);
    assert_eq!(
        outcome.shape.as_ref().map(|shape| shape.protocol),
        Some(UpstreamProtocol::Legacy),
        "the outcome carries the exact shape that was refused",
    );
}
