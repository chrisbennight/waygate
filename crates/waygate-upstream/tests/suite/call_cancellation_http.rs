//! A tool call the gateway stops waiting for is cancelled upstream through the
//! upstream's own protocol generation: a 2026-07-28 upstream sees the request's
//! stream close, and a legacy upstream receives `notifications/cancelled`.
//! The downstream caller's cancellation and the gateway's own call deadline
//! both end the upstream request this way.
//!
//! The mock upstream's `wait` tool never completes on its own. It returns only
//! once its request is cancelled, and records that it was. The mock also
//! records each `notifications/cancelled` it receives, so a legacy case proves
//! the notification itself arrived rather than only that its session closed.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CancelledNotificationParam, Implementation,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
    Tool,
};
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use waygate_mcp::catalog::{ToolCallMrtr, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_upstream::{
    SessionConfig, SessionIsolation, ToolClassification, Transport, UpstreamManifest, UpstreamPool,
    UpstreamProtocol,
};

/// Bounds each wait so a regression fails instead of hanging the suite.
const WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
struct WaitingUpstream {
    started: Arc<Notify>,
    cancelled: Arc<Notify>,
    notified: Arc<Notify>,
}

impl ServerHandler for WaitingUpstream {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("waiting-upstream", "0.0.0"))
            .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = serde_json::json!({"type": "object", "properties": {}})
            .as_object()
            .cloned()
            .unwrap();
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "wait".to_string(),
            "waits until its request is cancelled".to_string(),
            Arc::new(schema),
        )]))
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.started.notify_one();
        ctx.ct.cancelled().await;
        self.cancelled.notify_one();
        Err(McpError::internal_error("cancelled", None))
    }

    async fn on_cancelled(
        &self,
        _notification: CancelledNotificationParam,
        _context: NotificationContext<RoleServer>,
    ) {
        self.notified.notify_one();
    }
}

/// A legacy upstream must be told with `notifications/cancelled`; closing its
/// session or stream is not a cancellation in that protocol.
async fn legacy_upstream_was_notified(protocol: UpstreamProtocol, upstream: &WaitingUpstream) {
    if matches!(protocol, UpstreamProtocol::Legacy) {
        tokio::time::timeout(WAIT, upstream.notified.notified())
            .await
            .expect("a legacy upstream receives notifications/cancelled");
    }
}

async fn spawn_upstream() -> (std::net::SocketAddr, WaitingUpstream) {
    let handler = WaitingUpstream::default();
    let factory = handler.clone();
    let svc = StreamableHttpService::new(
        move || Ok(factory.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app: Router<()> = Router::new().nest_service("/mcp", svc);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handler)
}

fn manifest(
    addr: std::net::SocketAddr,
    protocol: UpstreamProtocol,
    isolation: SessionIsolation,
) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        inline_response_threshold_bytes: None,
        long_running_tools: Vec::new(),
        limits: None,
        name: "mock".into(),
        transport: Transport::Http,
        protocol,
        url: Some(format!("http://{addr}/mcp")),
        command: None,
        env_passthrough: Vec::new(),
        tools: vec![ToolClassification::new("wait", RiskTier::Low, true, false)],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        headers: Default::default(),
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        trust: waygate_upstream::TrustLevel::Internal,
        identity: None,
        forward_trace_context: None,
        session: Some(SessionConfig {
            concurrency: Some(1),
            isolation: Some(isolation),
            // A reused session is shared across callers; this mock forwards
            // no identity.
            scope: matches!(isolation, SessionIsolation::Reuse)
                .then_some(waygate_upstream::SessionScope::Shared),
            retry_on_setup_failure: None,
        }),
    }
}

async fn connect(manifest: UpstreamManifest) -> UpstreamPool {
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), manifest);
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await);
    pool
}

fn call(
    pool: &Arc<UpstreamPool>,
    cancellation: CancellationToken,
) -> tokio::task::JoinHandle<McpError> {
    let pool = Arc::clone(pool);
    tokio::spawn(async move {
        pool.call_tool_response(
            "mock",
            "wait",
            None,
            None,
            None,
            ToolCallMrtr {
                cancellation,
                ..Default::default()
            },
        )
        .await
        .expect_err("the wait tool never completes")
    })
}

async fn caller_cancellation_reaches(protocol: UpstreamProtocol, isolation: SessionIsolation) {
    let (addr, upstream) = spawn_upstream().await;
    let pool = Arc::new(connect(manifest(addr, protocol, isolation)).await);
    let cancellation = CancellationToken::new();
    let pending = call(&pool, cancellation.clone());
    tokio::time::timeout(WAIT, upstream.started.notified())
        .await
        .expect("the call reaches the upstream");

    cancellation.cancel();

    tokio::time::timeout(WAIT, upstream.cancelled.notified())
        .await
        .expect("the upstream request is cancelled");
    legacy_upstream_was_notified(protocol, &upstream).await;
    let error = tokio::time::timeout(WAIT, pending)
        .await
        .expect("the gateway stops waiting")
        .expect("call task");
    let data = error.data.expect("bounded error data");
    assert_eq!(data["error"], "upstream_call_cancelled");
    assert_eq!(data["phase"], "dispatched_unknown_outcome");
}

#[tokio::test]
async fn caller_cancellation_closes_a_2026_upstream_request() {
    caller_cancellation_reaches(UpstreamProtocol::default(), SessionIsolation::PerCall).await;
}

#[tokio::test]
async fn cancelled_capacity_waits_do_not_dispatch_or_trip_the_breaker() {
    let (addr, upstream) = spawn_upstream().await;
    let pool = Arc::new(
        connect(manifest(
            addr,
            UpstreamProtocol::default(),
            SessionIsolation::PerCall,
        ))
        .await
        .with_call_timeout(None),
    );
    let first_cancel = CancellationToken::new();
    let first = call(&pool, first_cancel.clone());
    tokio::time::timeout(WAIT, upstream.started.notified())
        .await
        .unwrap();
    for _ in 0..6 {
        let cancellation = CancellationToken::new();
        let waiting = call(&pool, cancellation.clone());
        cancellation.cancel();
        let error = tokio::time::timeout(WAIT, waiting).await.unwrap().unwrap();
        assert_eq!(error.data.unwrap()["phase"], "pre_dispatch");
    }
    assert_eq!(
        pool.breaker_state("mock"),
        Some(waygate_upstream::breaker::BreakerState::Closed)
    );
    first_cancel.cancel();
    tokio::time::timeout(WAIT, first).await.unwrap().unwrap();
    assert!(
        tokio::time::timeout(Duration::ZERO, upstream.started.notified())
            .await
            .is_err()
    );
}

/// A reused legacy session stays open after the call, so only the
/// cancellation notification can stop the upstream's work.
#[tokio::test]
async fn caller_cancellation_notifies_a_legacy_upstream() {
    caller_cancellation_reaches(UpstreamProtocol::Legacy, SessionIsolation::Reuse).await;
}

/// A per-call legacy session closes right after the call, which must not cut
/// off the notification on its way out.
#[tokio::test]
async fn caller_cancellation_notifies_a_legacy_per_call_upstream() {
    caller_cancellation_reaches(UpstreamProtocol::Legacy, SessionIsolation::PerCall).await;
}

async fn call_deadline_reaches(protocol: UpstreamProtocol, isolation: SessionIsolation) {
    let (addr, upstream) = spawn_upstream().await;
    // Long enough for a per-call dial on a slow runner; the upstream never
    // answers, so only the deadline ends the call.
    let pool = Arc::new(
        connect(manifest(addr, protocol, isolation))
            .await
            .with_call_timeout(Some(Duration::from_secs(1))),
    );
    let pending = call(&pool, CancellationToken::new());

    tokio::time::timeout(WAIT, upstream.cancelled.notified())
        .await
        .expect("the upstream request is cancelled at the deadline");
    legacy_upstream_was_notified(protocol, &upstream).await;
    let error = tokio::time::timeout(WAIT, pending)
        .await
        .expect("the gateway stops waiting")
        .expect("call task");
    let data = error.data.expect("bounded error data");
    assert_eq!(data["error"], "upstream_call_failed");
    assert_eq!(data["phase"], "dispatched_unknown_outcome");
}

#[tokio::test]
async fn call_deadline_closes_a_2026_upstream_request() {
    call_deadline_reaches(UpstreamProtocol::default(), SessionIsolation::PerCall).await;
}

#[tokio::test]
async fn call_deadline_notifies_a_legacy_upstream() {
    call_deadline_reaches(UpstreamProtocol::Legacy, SessionIsolation::Reuse).await;
}
