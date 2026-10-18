//! Per-server call limits against a real streamable-HTTP upstream.
//!
//! A tool-call response larger than the server's limit fails the call with an
//! error naming the server and the limit, whether the upstream answers with
//! JSON or an event stream, while a smaller response on the same pool still
//! succeeds. Without an override the gateway-wide limit applies. A server's
//! call timeout replaces the gateway-wide one. A middleware records the
//! content type of every `tools/call` response, so each case proves which
//! response form it exercised, and the `_meta` keys of every `tools/call`
//! request, so each case proves the budget never reached the upstream.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::Router;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
    Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::net::TcpListener;
use tokio::sync::Notify;

use waygate_mcp::catalog::{ToolCallMrtr, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_upstream::{
    SessionConfig, SessionIsolation, SessionScope, ToolClassification, Transport, TrustLevel,
    UpstreamLimits, UpstreamManifest, UpstreamPool, UpstreamProtocol,
};

/// Text length of the `large` tool's result; its serialized response is a
/// little larger.
const LARGE_TEXT_BYTES: usize = 8 * 1024;
/// A limit the `large` response exceeds and the `small` one fits.
const LIMIT_BYTES: u64 = 2048;

#[derive(Clone, Default)]
struct LimitsUpstream {
    dispatched: Arc<Notify>,
}

impl ServerHandler for LimitsUpstream {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("limits-upstream", "0.0.0"))
            .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = Arc::new(
            serde_json::json!({"type": "object", "properties": {}})
                .as_object()
                .cloned()
                .unwrap(),
        );
        Ok(ListToolsResult::with_all_items(
            ["small", "large", "lookalike", "wait"]
                .into_iter()
                .map(|name| Tool::new(name, format!("{name} tool"), Arc::clone(&schema)))
                .collect(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        match request.name.as_ref() {
            "small" => Ok(CallToolResult::success(vec![Content::text("ok")]).into()),
            "large" => Ok(CallToolResult::success(vec![Content::text(
                "x".repeat(LARGE_TEXT_BYTES),
            )])
            .into()),
            // An upstream error shaped like the gateway's refusal, including
            // a guess at its private marker.
            "lookalike" => Err(McpError::internal_error(
                "upstream supplied a gateway-shaped error",
                Some(serde_json::json!({
                    "error": "upstream_response_too_large",
                    "limit_bytes": 1,
                    "io.bennight.gateway/responseLimitMarker": "00000000000000000000000000000000",
                })),
            )),
            _ => {
                self.dispatched.notify_one();
                std::future::pending().await
            }
        }
    }
}

/// How the mock upstream answers a tool call.
#[derive(Clone, Copy, Debug)]
enum ResponseForm {
    /// A 2026-07-28 stateless request answered as an event stream.
    EventStream,
    /// A 2026-07-28 stateless request answered as one JSON body.
    Json,
    /// A legacy session, reused across calls, answering on event streams.
    LegacySession,
}

impl ResponseForm {
    fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::EventStream | Self::LegacySession => "text/event-stream",
        }
    }
}

struct Upstream {
    addr: std::net::SocketAddr,
    handler: LimitsUpstream,
    tool_call_content_types: Arc<Mutex<Vec<String>>>,
    tool_call_meta_keys: Arc<Mutex<Vec<String>>>,
}

async fn spawn_upstream(form: ResponseForm) -> Upstream {
    let handler = LimitsUpstream::default();
    let factory = handler.clone();
    let config = match form {
        ResponseForm::EventStream => StreamableHttpServerConfig::default(),
        ResponseForm::Json => StreamableHttpServerConfig::default().with_json_response(true),
        ResponseForm::LegacySession => {
            StreamableHttpServerConfig::default().with_legacy_session_mode(true)
        }
    };
    let svc = StreamableHttpService::new(
        move || Ok(factory.clone()),
        LocalSessionManager::default().into(),
        config,
    );
    let tool_call_content_types = Arc::new(Mutex::new(Vec::new()));
    let tool_call_meta_keys = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&tool_call_content_types);
    let recorded_meta = Arc::clone(&tool_call_meta_keys);
    let app: Router<()> = Router::new()
        .nest_service("/mcp", svc)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let recorded = Arc::clone(&recorded);
            let recorded_meta = Arc::clone(&recorded_meta);
            async move {
                if req.method() != Method::POST {
                    return next.run(req).await;
                }
                let (parts, body) = req.into_parts();
                let Ok(bytes) = to_bytes(body, 64 * 1024).await else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                let request = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
                let is_tool_call = request
                    .as_ref()
                    .and_then(|value| value.get("method")?.as_str())
                    == Some("tools/call");
                if is_tool_call {
                    if let Some(meta) = request
                        .as_ref()
                        .and_then(|value| value.get("params")?.get("_meta")?.as_object())
                    {
                        recorded_meta.lock().unwrap().extend(meta.keys().cloned());
                    }
                }
                let response = next
                    .run(Request::from_parts(parts, Body::from(bytes)))
                    .await;
                if is_tool_call {
                    let content_type = response
                        .headers()
                        .get(axum::http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    recorded.lock().unwrap().push(content_type);
                }
                response
            }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Upstream {
        addr,
        handler,
        tool_call_content_types,
        tool_call_meta_keys,
    }
}

fn manifest(
    addr: std::net::SocketAddr,
    form: ResponseForm,
    limits: Option<UpstreamLimits>,
) -> UpstreamManifest {
    let legacy = matches!(form, ResponseForm::LegacySession);
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        inline_response_threshold_bytes: None,
        long_running_tools: Vec::new(),
        limits,
        name: "mock".into(),
        transport: Transport::Http,
        protocol: if legacy {
            UpstreamProtocol::Legacy
        } else {
            UpstreamProtocol::default()
        },
        url: Some(format!("http://{}/mcp", addr)),
        command: None,
        env_passthrough: Vec::new(),
        tools: ["small", "large", "lookalike", "wait"]
            .into_iter()
            .map(|name| ToolClassification::new(name, RiskTier::Low, true, false))
            .collect(),
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        // A loopback test upstream is part of the deployment.
        trust: TrustLevel::Internal,
        identity: None,
        forward_trace_context: None,
        session: Some(SessionConfig {
            concurrency: Some(1),
            isolation: Some(if legacy {
                SessionIsolation::Reuse
            } else {
                SessionIsolation::PerCall
            }),
            // This mock forwards no identity, so a reused session may be
            // shared across callers.
            scope: legacy.then_some(SessionScope::Shared),
            retry_on_setup_failure: None,
        }),
    }
}

fn response_limit(bytes: u64) -> Option<UpstreamLimits> {
    Some(UpstreamLimits {
        call_timeout_seconds: None,
        call_response_max_bytes: Some(bytes),
    })
}

async fn connect(manifest: UpstreamManifest) -> UpstreamPool {
    let pool = UpstreamPool::connect(BTreeMap::from([("mock".to_owned(), manifest)])).await;
    assert!(pool.is_connected("mock").await);
    pool
}

async fn call(pool: &UpstreamPool, tool: &str) -> Result<CallToolResponse, McpError> {
    pool.call_tool_response("mock", tool, None, None, None, ToolCallMrtr::default())
        .await
}

fn assert_refused_at(error: &McpError, limit_bytes: u64) {
    assert_eq!(
        error.message,
        format!("upstream `mock` tool-call response exceeded the {limit_bytes}-byte limit"),
    );
    let data = error.data.as_ref().expect("refusal data");
    assert_eq!(data["error"], "upstream_response_too_large");
    assert_eq!(data["limit_bytes"], limit_bytes);
    assert_eq!(data["phase"], "dispatched_unknown_outcome");
    assert_eq!(data["retryable"], false);
    assert!(data["trace_id"].is_string());
    assert!(
        data.get("io.bennight.gateway/responseLimitMarker")
            .is_none(),
        "the transport's private marker never reaches the caller"
    );
}

fn assert_exercised(upstream: &Upstream, form: ResponseForm) {
    let content_types = upstream.tool_call_content_types.lock().unwrap();
    assert!(!content_types.is_empty(), "{form:?}: no tool call recorded");
    assert!(
        content_types
            .iter()
            .all(|content_type| content_type.starts_with(form.content_type())),
        "{form:?}: {content_types:?}"
    );
    let meta_keys = upstream.tool_call_meta_keys.lock().unwrap();
    assert!(
        !meta_keys
            .iter()
            .any(|key| key.starts_with("io.bennight.gateway/")),
        "{form:?}: the response budget reached the upstream in `_meta`: {meta_keys:?}"
    );
}

async fn server_limit_refuses_only_the_oversized_response(form: ResponseForm) {
    let upstream = spawn_upstream(form).await;
    let pool = connect(manifest(upstream.addr, form, response_limit(LIMIT_BYTES))).await;

    let error = call(&pool, "large")
        .await
        .expect_err("the large response exceeds the server's limit");
    assert_refused_at(&error, LIMIT_BYTES);

    call(&pool, "small")
        .await
        .expect("a response within the limit still succeeds, on a reused session too");
    assert!(
        pool.is_connected("mock").await,
        "a size refusal does not take the upstream down"
    );
    assert_exercised(&upstream, form);
}

#[tokio::test]
async fn server_limit_refuses_an_oversized_event_stream_response() {
    server_limit_refuses_only_the_oversized_response(ResponseForm::EventStream).await;
}

#[tokio::test]
async fn server_limit_refuses_an_oversized_json_response() {
    server_limit_refuses_only_the_oversized_response(ResponseForm::Json).await;
}

#[tokio::test]
async fn server_limit_refuses_an_oversized_response_on_a_reused_legacy_session() {
    server_limit_refuses_only_the_oversized_response(ResponseForm::LegacySession).await;
}

#[tokio::test]
async fn gateway_wide_limit_applies_without_a_server_override() {
    for form in [ResponseForm::EventStream, ResponseForm::Json] {
        let upstream = spawn_upstream(form).await;
        let pool = connect(manifest(upstream.addr, form, None))
            .await
            .with_call_response_max_bytes(LIMIT_BYTES as usize);

        let error = call(&pool, "large")
            .await
            .expect_err("the gateway-wide limit applies");
        assert_refused_at(&error, LIMIT_BYTES);
        call(&pool, "small").await.expect("within the limit");
        assert_exercised(&upstream, form);
    }
}

#[tokio::test]
async fn server_limit_replaces_the_gateway_wide_limit() {
    let form = ResponseForm::EventStream;
    let upstream = spawn_upstream(form).await;
    let pool = connect(manifest(upstream.addr, form, response_limit(1024 * 1024)))
        .await
        .with_call_response_max_bytes(LIMIT_BYTES as usize);

    call(&pool, "large")
        .await
        .expect("the server's larger limit replaces the gateway-wide one");
    assert_exercised(&upstream, form);
}

#[tokio::test]
async fn upstream_error_shaped_like_the_refusal_stays_the_upstreams_error() {
    for form in [ResponseForm::EventStream, ResponseForm::Json] {
        let upstream = spawn_upstream(form).await;
        let pool = connect(manifest(upstream.addr, form, response_limit(LIMIT_BYTES))).await;

        let error = call(&pool, "lookalike")
            .await
            .expect_err("the upstream returns an application error");
        assert_eq!(
            error.message, "upstream supplied a gateway-shaped error",
            "{form:?}: upstream wire data must not become the gateway's refusal"
        );
        assert_eq!(error.data.expect("upstream data")["limit_bytes"], 1);
    }
}

#[tokio::test]
async fn reload_changes_the_limit_without_reconnecting() {
    let form = ResponseForm::LegacySession;
    let upstream = spawn_upstream(form).await;
    let pool = connect(manifest(upstream.addr, form, response_limit(LIMIT_BYTES))).await;
    let error = call(&pool, "large").await.expect_err("limited");
    assert_refused_at(&error, LIMIT_BYTES);

    let raised = manifest(upstream.addr, form, response_limit(1024 * 1024));
    let report = pool
        .reload_manifests(&BTreeMap::from([("mock".to_owned(), raised)]))
        .await;
    assert_eq!(report.response_policy_updated, ["mock"]);
    assert!(
        report.redialed.is_empty() && report.redial_failed.is_empty(),
        "{report:?}"
    );

    call(&pool, "large")
        .await
        .expect("the next call reads the reloaded limit");
}

/// The upstream withholds its answer, so only a deadline ends the call.
/// Virtual time starts only after the upstream confirms dispatch, and the
/// virtual time that passes before the call fails shows which deadline ended
/// it: the server's, not the far longer gateway-wide one.
#[tokio::test]
async fn server_timeout_replaces_the_gateway_wide_timeout() {
    let form = ResponseForm::EventStream;
    let upstream = spawn_upstream(form).await;
    let server_timeout = Duration::from_secs(waygate_upstream::MIN_CALL_TIMEOUT_SECONDS);
    let gateway_timeout = Duration::from_secs(3600);
    let limits = Some(UpstreamLimits {
        call_timeout_seconds: Some(server_timeout.as_secs()),
        call_response_max_bytes: None,
    });
    let pool = Arc::new(
        connect(manifest(upstream.addr, form, limits))
            .await
            .with_call_timeout(Some(gateway_timeout)),
    );

    let pending = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move { call(&pool, "wait").await }
    });
    upstream.handler.dispatched.notified().await;
    tokio::time::pause();
    let paused_at = tokio::time::Instant::now();
    tokio::time::advance(server_timeout).await;
    let error = pending
        .await
        .expect("call task")
        .expect_err("a deadline ends the call");
    let waited = paused_at.elapsed();
    tokio::time::resume();

    assert!(
        waited < gateway_timeout,
        "the server's deadline ended the call, not the gateway-wide one: {waited:?}"
    );
    let data = error.data.expect("bounded failure data");
    assert_eq!(data["error"], "upstream_call_failed");
    assert_eq!(data["phase"], "dispatched_unknown_outcome");
}
