//! End-to-end proof of `session.isolation` against a real streamable-HTTP
//! upstream.
//!
//! A tiny rmcp `StreamableHttpService` upstream is mounted behind an axum
//! middleware that counts MCP *session initializations* — every POST to
//! `/mcp` that lacks an `Mcp-Session-Id` header is an `initialize` (the
//! handshake that mints a new session id). The pool is then driven through
//! three `call_tool`s under each isolation mode:
//!
//! - `reuse`  → the boot dial mints ONE session and all calls run on it → 1 init.
//! - `per_call` (and the HTTP default) → the boot dial mints one session for
//!   tools/health, then EACH call dials a fresh ephemeral session → 1 + N inits.
//!
//! `concurrency: 1` pins the boot pool to a single slot so the boot init count
//! is exactly one and the per-call deltas are unambiguous. Only the tests
//! that assert NONZERO init counts pin `protocol: legacy` (sessions are a
//! legacy-lifecycle concept; under `auto` every request is sessionless and
//! the counter would tally the discovery probe instead). Everything else in
//! this file — the boot-discovery rejections, identity forwarding, and the
//! contract-recheck cases — runs on the default `auto`, exercising the
//! stateless leg like the rest of the suite.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
    Implementation, ListResourcesResult, ListToolsResult, MetaObject as Meta,
    PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
    ReadResourceResult, Resource, ResourceContents, ServerCapabilities, ServerInfo, Tool,
    ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::net::TcpListener;

use waygate_mcp::catalog::{
    AdmittedResourceReadError, ResolvedInvocationTool, ResourceReadAdmission, ToolCallMrtr,
    UpstreamCatalog, RESPONSE_MATERIALIZATION_LIMIT_ERROR, RESPONSE_MATERIALIZATION_LIMIT_META_KEY,
};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{
    AllowAllGate, DefaultInvocationService, InvocationRequest, InvocationResponse,
    InvocationService, NullSink,
};
use waygate_oidc::{IdentityClaims, IdentityIssuer};
use waygate_upstream::{
    tool_behavior_hash, ClassificationMode, SessionConfig, SessionIsolation, SessionScope,
    ToolClassification, Transport, UpstreamAuth, UpstreamManifest, UpstreamPool, UpstreamProtocol,
    IDENTITY_HEADER,
};

use super::test_identity_issuer;

/// Minimal upstream: one tool, `noop`, that always succeeds.
#[derive(Clone)]
struct MockUpstream;

impl ServerHandler for MockUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("mock-upstream", "0.0.0"))
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

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(vec![Resource::new(
            "mock://guide",
            "Guide",
        )]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if request.uri == "mock://spoof-limit" {
            return Err(McpError::internal_error(
                "upstream supplied a gateway-shaped error",
                Some(serde_json::json!({
                    "error": RESPONSE_MATERIALIZATION_LIMIT_ERROR,
                })),
            ));
        }
        if request.uri != "mock://guide" {
            return Err(McpError::method_not_found::<
                rmcp::model::ReadResourceRequestMethod,
            >());
        }
        Ok(
            ReadResourceResult::new(vec![ResourceContents::text("resource body", request.uri)])
                .into(),
        )
    }
}

/// Spawn the mock upstream; returns its base address and a counter that ticks
/// once per session-initialize POST (POST to `/mcp` without `Mcp-Session-Id`).
async fn spawn_mock_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let (addr, inits, _) = spawn_mock_upstream_with_identity_requirement(false).await;
    (addr, inits)
}

#[derive(Clone)]
struct FlakyInitializationUpstream {
    calls: Arc<AtomicUsize>,
}

impl ServerHandler for FlakyInitializationUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "flaky-initialization-upstream",
                "0.0.0",
            ))
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CallToolResult::success(vec![Content::text("ok")]).into())
    }
}

/// Boot succeeds, then the first per-call session initialization is refused.
/// The next initialization succeeds, modeling a provider-neutral transient at
/// the MCP lifecycle boundary rather than any one upstream implementation.
async fn spawn_flaky_initialization_upstream(
) -> (std::net::SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let inits = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = FlakyInitializationUpstream {
        calls: Arc::clone(&calls),
    };
    let svc = StreamableHttpService::new(
        move || Ok(handler.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let counter = Arc::clone(&inits);
    let app: Router<()> = Router::new()
        .nest_service("/mcp", svc)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let counter = Arc::clone(&counter);
            async move {
                if req.method() == Method::POST && req.headers().get("mcp-session-id").is_none() {
                    let ordinal = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if ordinal == 2 {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                }
                next.run(req).await
            }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, inits, calls)
}

/// The upstream executes `tools/call`, then the HTTP response body closes
/// with an error. This is the independent post-dispatch transport-fault case:
/// the gateway knows the request was handed off but cannot know its outcome.
async fn spawn_post_dispatch_disconnect_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = FlakyInitializationUpstream {
        calls: Arc::clone(&calls),
    };
    let svc = StreamableHttpService::new(
        move || Ok(handler.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let disconnect = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let app: Router<()> = Router::new()
        .nest_service("/mcp", svc)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let disconnect = Arc::clone(&disconnect);
            async move {
                if req.method() != Method::POST {
                    return next.run(req).await;
                }
                let (parts, body) = req.into_parts();
                let Ok(bytes) = to_bytes(body, 64 * 1024).await else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                let is_tool_call = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|value| value.get("method")?.as_str().map(str::to_owned))
                    .as_deref()
                    == Some("tools/call");
                let response = next
                    .run(Request::from_parts(parts, Body::from(bytes)))
                    .await;
                if is_tool_call && disconnect.swap(false, Ordering::SeqCst) {
                    let (parts, _) = response.into_parts();
                    let stream = futures::stream::once(async {
                        Err::<bytes::Bytes, _>(std::io::Error::other(
                            "provider-neutral post-dispatch transport close",
                        ))
                    });
                    return Response::from_parts(parts, Body::from_stream(stream));
                }
                response
            }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, calls)
}

#[derive(Clone)]
struct SlowCallUpstream {
    calls: Arc<AtomicUsize>,
    dispatched: Arc<tokio::sync::Notify>,
}

impl ServerHandler for SlowCallUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("slow-call-upstream", "0.0.0"))
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.dispatched.notify_one();
        std::future::pending().await
    }
}

async fn spawn_slow_call_upstream() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    Arc<tokio::sync::Notify>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let dispatched = Arc::new(tokio::sync::Notify::new());
    let handler = SlowCallUpstream {
        calls: Arc::clone(&calls),
        dispatched: dispatched.clone(),
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
    (addr, calls, dispatched)
}

const RETAINED_URI: &str = "mock-response:/retained/0";
const RETAINED_BODY: &str = r#"[{"name":"large result"}]"#;

#[derive(Clone, Default)]
struct SessionRetainedUpstream {
    retained: Arc<Mutex<Option<String>>>,
}

impl ServerHandler for SessionRetainedUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("session-retained-upstream", "0.0.0"))
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
            "retained".to_string(),
            "return a session-retained response".to_string(),
            Arc::new(schema),
        )]))
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        *self.retained.lock().unwrap() = Some(RETAINED_BODY.to_owned());
        let mut result = CallToolResult::structured(serde_json::json!({
            "content_type": "application/json",
            "headers": {},
            "operation_id": "retained",
            "payload": {
                "bytes": RETAINED_BODY.len(),
                "context_ceiling_bytes": 65_536,
                "inlined": false,
                "media_type": "application/json",
                "reason": "above the context-scale ceiling",
                "resource_uri": RETAINED_URI,
                "retained": true
            },
            "status": 200,
            "success": true
        }));
        result.content.push(Content::resource_link(
            Resource::new(RETAINED_URI, "retained").with_mime_type("application/json"),
        ));
        Ok(result.into())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if request.uri != RETAINED_URI {
            return Err(McpError::resource_not_found(
                format!("unknown retained resource {}", request.uri),
                None,
            ));
        }
        let Some(body) = self.retained.lock().unwrap().take() else {
            return Err(McpError::resource_not_found(
                format!("no stored payload at {}", request.uri),
                None,
            ));
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(body, request.uri)]).into())
    }
}

async fn spawn_session_retained_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let inits = Arc::new(AtomicUsize::new(0));
    let svc = StreamableHttpService::new(
        || Ok(SessionRetainedUpstream::default()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let counter = inits.clone();
    let app: Router<()> = Router::new()
        .nest_service("/mcp", svc)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let counter = counter.clone();
            async move {
                if req.method() == Method::POST && req.headers().get("mcp-session-id").is_none() {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                next.run(req).await
            }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, inits)
}

#[derive(Clone, Default)]
struct CapturedIdentities {
    tokens: Arc<Mutex<Vec<String>>>,
    missing: Arc<AtomicUsize>,
}

async fn spawn_mock_upstream_with_identity_requirement(
    require_identity: bool,
) -> (std::net::SocketAddr, Arc<AtomicUsize>, CapturedIdentities) {
    let inits = Arc::new(AtomicUsize::new(0));
    let identities = CapturedIdentities::default();
    let svc = StreamableHttpService::new(
        || Ok(MockUpstream),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );

    let counter = inits.clone();
    let captured = identities.clone();
    let app: Router<()> = Router::new()
        .nest_service("/mcp", svc)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let counter = counter.clone();
            let captured = captured.clone();
            async move {
                if req.method() == Method::POST && req.headers().get("mcp-session-id").is_none() {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                match req
                    .headers()
                    .get(IDENTITY_HEADER.as_str())
                    .and_then(|value| value.to_str().ok())
                {
                    Some(token) => captured.tokens.lock().unwrap().push(token.to_owned()),
                    None if require_identity => {
                        captured.missing.fetch_add(1, Ordering::SeqCst);
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    None => {}
                }
                next.run(req).await
            }
        }));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, inits, identities)
}

fn decode_identities(tokens: &[String], issuer: &IdentityIssuer) -> Vec<IdentityClaims> {
    let jwks = issuer.jwks();
    let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();
    tokens
        .iter()
        .map(|token| {
            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.set_issuer(&["https://mcp.test"]);
            validation.set_audience(&["mock"]);
            decode::<IdentityClaims>(token, &key, &validation)
                .expect("probe identity must verify")
                .claims
        })
        .collect()
}

fn manifest(addr: std::net::SocketAddr, isolation: Option<SessionIsolation>) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: "mock".into(),
        transport: Transport::Http,
        // Default `auto`: identity-forwarding and contract-recheck tests
        // exercise the stateless leg like the rest of the suite. Only the
        // tests that ASSERT session-init counts pin the legacy lifecycle
        // (via `legacy`), because sessions exist only there.
        protocol: Default::default(),
        url: Some(format!("http://{addr}/mcp")),
        command: None,
        tools: vec![ToolClassification::new("noop", RiskTier::Low, false, false)],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        // concurrency: 1 ⇒ exactly one boot session, so the init counter is
        // unambiguous.
        session: Some(SessionConfig {
            concurrency: Some(1),
            isolation,
            scope: None,
            retry_on_setup_failure: None,
        }),
    }
}

/// Pin the legacy lifecycle. For tests that assert SESSION-minting
/// semantics per isolation mode — a contract that exists only on the
/// legacy lifecycle; under `auto` every request is sessionless and the
/// init counter would measure the discovery probe, not sessions.
fn legacy(mut m: UpstreamManifest) -> UpstreamManifest {
    m.protocol = UpstreamProtocol::Legacy;
    m
}

async fn connect_legacy(
    addr: std::net::SocketAddr,
    isolation: Option<SessionIsolation>,
) -> UpstreamPool {
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), legacy(manifest(addr, isolation)));
    UpstreamPool::connect(manifests).await
}

#[tokio::test]
async fn negotiated_resource_capability_excludes_tool_only_upstreams() {
    let (resource_addr, _) = spawn_mock_upstream().await;
    let resource_pool = connect_legacy(resource_addr, Some(SessionIsolation::Reuse)).await;
    assert!(
        resource_pool.resource_capability_advertised("mock").await,
        "the pool must retain the Resources capability from initialization",
    );

    let (tool_addr, _, _) = spawn_slow_call_upstream().await;
    let tool_pool = connect_legacy(tool_addr, Some(SessionIsolation::Reuse)).await;
    assert!(
        !tool_pool.resource_capability_advertised("mock").await,
        "transport eligibility alone must not make a tool-only server a resource provider",
    );
}

#[tokio::test]
async fn boot_discovery_uses_verified_group_less_gateway_identity() {
    let (addr, _, captured) = spawn_mock_upstream_with_identity_requirement(true).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), manifest(addr, Some(SessionIsolation::Reuse)));
    let issuer = test_identity_issuer();

    let pool = UpstreamPool::connect_with_identity(manifests, issuer.clone()).await;
    assert!(
        pool.is_connected("mock").await,
        "an upstream that requires Tier-B identity during initialize and tools/list must connect",
    );
    assert_eq!(
        captured.missing.load(Ordering::SeqCst),
        0,
        "every discovery request must carry the probe identity",
    );

    let tokens = captured.tokens.lock().unwrap().clone();
    assert!(
        tokens.len() >= 2,
        "initialize and tools/list must both carry identity",
    );
    let discovery_token_count = tokens.len();
    for claims in decode_identities(&tokens, &issuer) {
        assert_eq!(claims.sub, "mcp-tool-search-gateway:catalog-probe");
        assert!(
            claims.groups.is_empty(),
            "probe identity must be unprivileged"
        );
        assert_eq!(claims.act.sub, "gateway-e2e");
    }

    let call = pool.call_tool("mock", "noop", None, None, None).await;
    assert!(
        call.is_err(),
        "the group-less discovery identity must be cleared before caller dispatch",
    );
    assert_eq!(
        captured.tokens.lock().unwrap().len(),
        discovery_token_count,
        "a caller-less request must not inherit the discovery identity",
    );
    assert_eq!(
        captured.missing.load(Ordering::SeqCst),
        1,
        "the post-discovery caller-less request must reach the upstream without identity",
    );
}

#[tokio::test]
async fn boot_discovery_uses_configured_groups_only_for_the_catalog_probe() {
    let (addr, _, captured) = spawn_mock_upstream_with_identity_requirement(true).await;
    let mut configured = manifest(addr, Some(SessionIsolation::PerCall));
    configured.auth = Some(UpstreamAuth {
        catalog_probe_groups: vec!["service-operators".into()],
        ..Default::default()
    });
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);
    let issuer = test_identity_issuer();

    let pool = UpstreamPool::connect_with_identity(manifests, issuer.clone()).await;
    assert!(pool.is_connected("mock").await);
    assert_eq!(captured.missing.load(Ordering::SeqCst), 0);

    let tokens = captured.tokens.lock().unwrap().clone();
    assert!(tokens.len() >= 2, "initialize and tools/list need identity");
    let discovery_token_count = tokens.len();
    for claims in decode_identities(&tokens, &issuer) {
        assert_eq!(claims.sub, "mcp-tool-search-gateway:catalog-probe");
        assert_eq!(claims.groups, ["service-operators"]);
        assert_eq!(claims.act.sub, "gateway-e2e");
    }

    let call = pool.call_tool("mock", "noop", None, None, None).await;
    assert!(
        call.is_err(),
        "a caller-less request must not inherit privileged catalog groups",
    );
    assert_eq!(
        captured.tokens.lock().unwrap().len(),
        discovery_token_count,
        "the catalog-probe identity must be cleared before caller dispatch",
    );
    // TWO, where the `reuse` sibling above sees one. What is being asserted
    // is unchanged: a caller-less request reaches the upstream carrying no
    // identity, and the privileged catalog-probe identity is not inherited —
    // the assertion directly above still pins that, and it is the security
    // property this test exists for.
    //
    // The count differs because this upstream dials per call. Under `auto`
    // a dial is two attempts, not one: a discovery probe, then the legacy
    // handshake when that probe is refused. Both attempts are caller-less
    // here, so both are counted. The `reuse` sibling reaches its upstream on
    // the pooled session and never dials again, so it stays at one.
    //
    // The extra attempt is the accepted cost of connecting to upstreams that
    // predate discovery; a per-upstream generation memo would remove it from
    // the per-call path.
    assert_eq!(
        captured.missing.load(Ordering::SeqCst),
        2,
        "both caller-less dial attempts must reach the upstream without identity",
    );
}

#[tokio::test]
async fn boot_discovery_rejects_catalog_groups_with_a_reused_session() {
    let (addr, inits) = spawn_mock_upstream().await;
    let mut configured = manifest(addr, Some(SessionIsolation::Reuse));
    configured.session.as_mut().unwrap().scope = Some(SessionScope::Shared);
    configured.auth = Some(UpstreamAuth {
        catalog_probe_groups: vec!["service-operators".into()],
        ..Default::default()
    });
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);

    let pool = UpstreamPool::connect_with_identity(manifests, test_identity_issuer()).await;
    assert!(
        !pool.is_connected("mock").await,
        "a caller-reused session must never initialize with catalog privileges",
    );
    assert_eq!(
        inits.load(Ordering::SeqCst),
        0,
        "the unsafe session shape must be rejected before contacting the upstream",
    );
}

#[tokio::test]
async fn boot_discovery_rejects_catalog_groups_without_an_identity_signer() {
    let (addr, inits) = spawn_mock_upstream().await;
    let mut configured = manifest(addr, Some(SessionIsolation::PerCall));
    configured.auth = Some(UpstreamAuth {
        catalog_probe_groups: vec!["service-operators".into()],
        ..Default::default()
    });
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);

    let pool = UpstreamPool::connect(manifests).await;
    assert!(
        !pool.is_connected("mock").await,
        "a grouped catalog probe must not silently dial without a signer",
    );
    assert_eq!(
        inits.load(Ordering::SeqCst),
        0,
        "the missing signer must be rejected before any upstream request",
    );
}

/// The HTTP default (no `isolation` set) is `per_call`: the boot dial mints one
/// session for tools/health, then each of the three calls dials a fresh
/// ephemeral session → 1 + 3 = 4 initializes.
#[tokio::test]
async fn http_default_isolation_opens_fresh_session_per_call() {
    let (addr, inits) = spawn_mock_upstream().await;
    let pool = connect_legacy(addr, None).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");

    let boot = inits.load(Ordering::SeqCst);
    assert_eq!(boot, 1, "concurrency:1 ⇒ exactly one boot session");

    for _ in 0..3 {
        pool.call_tool("mock", "noop", None, None, None)
            .await
            .expect("call_tool noop");
    }

    assert_eq!(
        inits.load(Ordering::SeqCst),
        boot + 3,
        "per_call (default) must mint a fresh session per call",
    );
}

#[tokio::test]
async fn resource_requests_preserve_per_call_session_isolation() {
    let (addr, inits) = spawn_mock_upstream().await;
    let pool = connect_legacy(addr, None).await;
    let boot = inits.load(Ordering::SeqCst);

    let listed = pool
        .list_resources("mock", None, None)
        .await
        .expect("resources/list");
    assert_eq!(listed.resources[0].uri, "mock://guide");

    let read = pool
        .read_resource("mock", ReadResourceRequestParams::new("mock://guide"), None)
        .await
        .expect("resources/read");
    assert!(matches!(
        &read.contents[0],
        ResourceContents::TextResourceContents { text, .. } if text == "resource body"
    ));
    assert_eq!(
        inits.load(Ordering::SeqCst),
        boot + 2,
        "each resource request must use a fresh upstream MCP session",
    );
}

#[tokio::test]
async fn native_response_limit_provenance_survives_rmcp_transport_erasure() {
    let (addr, _) = spawn_mock_upstream().await;
    let pool = connect_legacy(addr, Some(SessionIsolation::Reuse)).await;
    let routing = pool.resource_routing_snapshot().await;
    let admission = ResourceReadAdmission {
        generation: routing.generation,
        server: "mock".to_owned(),
        claim: None,
    };

    let mut bounded = ReadResourceRequestParams::new("mock://guide");
    let mut meta = rmcp::model::RequestMetaObject::new();
    meta.insert(
        RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
        serde_json::json!(32),
    );
    bounded.meta = Some(meta);
    let error = pool
        .read_resource_admitted("mock", bounded, None, &admission)
        .await
        .expect_err("the raw response exceeds the gateway bound");
    assert!(matches!(
        error,
        AdmittedResourceReadError::ResponseTooLarge { limit_bytes: 32 }
    ));

    let mut within_limit = ReadResourceRequestParams::new("mock://guide");
    let mut meta = rmcp::model::RequestMetaObject::new();
    meta.insert(
        RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
        serde_json::json!(4096),
    );
    within_limit.meta = Some(meta);
    pool.read_resource_admitted("mock", within_limit, None, &admission)
        .await
        .expect("a size refusal must not poison the reused connection");

    let mut spoof = ReadResourceRequestParams::new("mock://spoof-limit");
    let mut meta = rmcp::model::RequestMetaObject::new();
    meta.insert(
        RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
        serde_json::json!(4096),
    );
    spoof.meta = Some(meta);
    let error = pool
        .read_resource_admitted("mock", spoof, None, &admission)
        .await
        .expect_err("the upstream returns an application error");
    let AdmittedResourceReadError::Upstream(error) = error else {
        panic!("upstream wire data must not become a local response-limit refusal")
    };
    assert_eq!(
        error.data.expect("upstream error data")["error"],
        RESPONSE_MATERIALIZATION_LIMIT_ERROR,
    );
}

#[tokio::test]
async fn retained_resource_processing_stays_on_the_tool_calls_per_call_session() {
    let (addr, inits) = spawn_session_retained_upstream().await;
    let mut configured = legacy(manifest(addr, None));
    configured.tools = vec![ToolClassification::new(
        "retained",
        RiskTier::Low,
        false,
        false,
    )];
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let boot = inits.load(Ordering::SeqCst);

    let service = DefaultInvocationService::new(
        Arc::clone(&pool) as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );
    let response = service
        .invoke(
            None,
            InvocationRequest::new("mock", "retained")
                .with_response_delivery(waygate_mcp::ResponseDelivery::Materialize)
                .with_response_materialization_limit(1024),
        )
        .await
        .expect("retained response must hydrate before its session is released");
    let InvocationResponse::Unary(result) = response else {
        panic!("retained invocation must complete with a unary result")
    };
    let structured = result.structured_content.expect("structured result");
    assert_eq!(
        structured["data"],
        serde_json::from_str::<serde_json::Value>(RETAINED_BODY).unwrap(),
    );
    assert!(structured.get("payload").is_none());
    assert_eq!(
        inits.load(Ordering::SeqCst),
        boot + 1,
        "tool call and retained-resource read must share one ephemeral session",
    );
}

/// Opting into `reuse` keeps all calls on the single boot session → the init
/// count never grows past the boot dial.
#[tokio::test]
async fn http_reuse_isolation_keeps_one_session() {
    let (addr, inits) = spawn_mock_upstream().await;
    let pool = connect_legacy(addr, Some(SessionIsolation::Reuse)).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");

    let boot = inits.load(Ordering::SeqCst);
    assert_eq!(boot, 1, "concurrency:1 ⇒ exactly one boot session");

    for _ in 0..3 {
        pool.call_tool("mock", "noop", None, None, None)
            .await
            .expect("call_tool noop");
    }

    assert_eq!(
        inits.load(Ordering::SeqCst),
        boot,
        "reuse must run every call on the single pooled session",
    );
}

#[tokio::test]
async fn admitted_read_only_call_recovers_one_transient_initialization_failure() {
    let (addr, inits, calls) = spawn_flaky_initialization_upstream().await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), legacy(manifest(addr, None)));
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    assert_eq!(inits.load(Ordering::SeqCst), 1, "boot initializes once");
    let service = DefaultInvocationService::new(
        Arc::clone(&pool) as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );

    service
        .invoke(None, InvocationRequest::new("mock", "noop").read_only())
        .await
        .expect("the safe retry should recover the read-only call");

    assert_eq!(
        inits.load(Ordering::SeqCst),
        3,
        "one failed initialization and one recovery initialization"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "dispatch occurs once");
    let health = pool.health_snapshot().await.remove(0);
    assert_eq!(
        health.last_error_class, None,
        "a recovered setup failure must not consume breaker health"
    );
}

#[tokio::test]
async fn upstream_policy_can_disable_safe_setup_recovery() {
    let (addr, inits, calls) = spawn_flaky_initialization_upstream().await;
    let mut configured = legacy(manifest(addr, None));
    configured
        .session
        .as_mut()
        .expect("test manifest has a session policy")
        .retry_on_setup_failure = Some(false);
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let service = DefaultInvocationService::new(
        Arc::clone(&pool) as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );

    let error = service
        .invoke(None, InvocationRequest::new("mock", "noop").read_only())
        .await
        .expect_err("the upstream policy suppresses the otherwise-safe recovery");
    let waygate_mcp::InvocationError::Upstream(error) = error else {
        panic!("expected bounded upstream error")
    };
    let data = error.data.expect("bounded failure data");
    assert_eq!(data["phase"], "initialize");
    assert_eq!(data["attempts"], 1);
    assert_eq!(data["retryable"], false);
    assert_eq!(inits.load(Ordering::SeqCst), 2, "no recovery dial");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no tool dispatch");
}

#[tokio::test]
async fn consumed_approval_authority_disables_safe_setup_recovery() {
    let (addr, inits, calls) = spawn_flaky_initialization_upstream().await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), legacy(manifest(addr, None)));
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let ResolvedInvocationTool::Ready(snapshot) = pool
        .resolve_invocation_tool(waygate_core::TenantId::DEFAULT, "mock", "noop")
        .await
    else {
        panic!("the read-only tool must resolve")
    };
    let admitted = snapshot.contract_identity();

    let error = pool
        .call_tool_response(
            "mock",
            "noop",
            None,
            None,
            Some(&admitted),
            ToolCallMrtr {
                approval_gated: true,
                ..Default::default()
            },
        )
        .await
        .expect_err("single-use approval authority must permit only one setup attempt");
    let data = error.data.expect("bounded failure data");
    assert_eq!(data["phase"], "initialize");
    assert_eq!(data["attempts"], 1);
    assert_eq!(data["retryable"], false);
    assert_eq!(inits.load(Ordering::SeqCst), 2, "no recovery dial");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no tool dispatch");
}

#[tokio::test]
async fn side_effecting_call_never_retries_initialization() {
    let (addr, inits, calls) = spawn_flaky_initialization_upstream().await;
    let mut configured = legacy(manifest(addr, None));
    configured.tools = vec![ToolClassification::new("noop", RiskTier::Low, true, false)];
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let service = DefaultInvocationService::new(
        Arc::clone(&pool) as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );

    let error = service
        .invoke(None, InvocationRequest::new("mock", "noop"))
        .await
        .expect_err("a side-effecting call must not replay setup");
    let waygate_mcp::InvocationError::Upstream(error) = error else {
        panic!("expected bounded upstream error")
    };
    let data = error.data.expect("bounded failure data");
    assert_eq!(data["phase"], "initialize");
    assert_eq!(data["attempts"], 1);
    assert_eq!(data["retryable"], false);
    assert_eq!(inits.load(Ordering::SeqCst), 2, "no second attempt");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "tool was never dispatched");
}

#[tokio::test]
async fn timeout_after_dispatch_has_unknown_outcome_and_is_never_retried() {
    let (addr, calls, dispatched) = spawn_slow_call_upstream().await;
    let budget = std::time::Duration::from_secs(600);
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), legacy(manifest(addr, None)));
    let pool = Arc::new(
        UpstreamPool::connect(manifests)
            .await
            // The test-runner watchdog bounds setup; virtual time below expires
            // the call only after the upstream has confirmed dispatch.
            .with_call_timeout(Some(budget)),
    );
    let service = DefaultInvocationService::new(
        Arc::clone(&pool) as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );

    let invocation = tokio::spawn(async move {
        service
            .invoke(None, InvocationRequest::new("mock", "noop").read_only())
            .await
    });
    dispatched.notified().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::pause();
    tokio::time::advance(budget).await;
    let error = invocation
        .await
        .expect("invocation task")
        .expect_err("the upstream call should exceed its deadline");
    tokio::time::resume();
    let waygate_mcp::InvocationError::Upstream(error) = error else {
        panic!("expected bounded upstream error")
    };
    let data = error.data.expect("bounded failure data");
    assert_eq!(data["phase"], "dispatched_unknown_outcome");
    assert_eq!(data["attempts"], 1);
    assert_eq!(data["retryable"], false);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "unknown outcome is never replayed"
    );
    let health = pool.health_snapshot().await.remove(0);
    assert_eq!(
        health.last_error_class.map(|class| class.as_str()),
        Some("timeout"),
        "the breaker records the bounded terminal cause"
    );
}

#[tokio::test]
async fn http_disconnect_after_dispatch_has_unknown_outcome_and_is_never_retried() {
    let (addr, calls) = spawn_post_dispatch_disconnect_upstream().await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), legacy(manifest(addr, None)));
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let service = DefaultInvocationService::new(
        Arc::clone(&pool) as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );

    let error = service
        .invoke(None, InvocationRequest::new("mock", "noop").read_only())
        .await
        .expect_err("the response body disconnects after handler entry");
    let waygate_mcp::InvocationError::Upstream(error) = error else {
        panic!("expected bounded upstream error")
    };
    let data = error.data.expect("bounded failure data");
    assert_eq!(data["phase"], "dispatched_unknown_outcome");
    assert_eq!(data["attempts"], 1);
    assert_eq!(data["retryable"], false);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a post-dispatch transport failure must never replay the tool call"
    );
}

/// Upstream whose advertised tool descriptors can be swapped between
/// sessions, with a counter for `tools/list` requests. Models a server that
/// serves session-specific (or freshly redeployed) contracts — behavior MCP
/// does not forbid — so tests can prove which session's contract the pool
/// actually admits against.
#[derive(Clone)]
struct MutableUpstream {
    tools: Arc<Mutex<Vec<Tool>>>,
    list_calls: Arc<AtomicUsize>,
    tool_calls: Arc<AtomicUsize>,
    fail_next_list: Arc<std::sync::atomic::AtomicBool>,
    /// While set, `tools/list` stalls for several seconds before answering —
    /// long enough to exceed a short pool call timeout, short enough that a
    /// build without the bound still finishes the test run.
    stall_lists: Arc<std::sync::atomic::AtomicBool>,
}

impl ServerHandler for MutableUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("mutable-upstream", "0.0.0"))
            .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_next_list.swap(false, Ordering::SeqCst) {
            return Err(McpError::internal_error(
                "transient provider-neutral tools/list failure",
                None,
            ));
        }
        if self.stall_lists.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        }
        Ok(ListToolsResult::with_all_items(
            self.tools.lock().unwrap().clone(),
        ))
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.tool_calls.fetch_add(1, Ordering::SeqCst);
        Ok(CallToolResult::success(vec![Content::text("ok")]).into())
    }
}

struct MutableUpstreamRig {
    addr: std::net::SocketAddr,
    tools: Arc<Mutex<Vec<Tool>>>,
    list_calls: Arc<AtomicUsize>,
    tool_calls: Arc<AtomicUsize>,
    fail_next_list: Arc<std::sync::atomic::AtomicBool>,
    disconnect_next_list: Arc<std::sync::atomic::AtomicBool>,
    transport_list_calls: Arc<AtomicUsize>,
    stall_lists: Arc<std::sync::atomic::AtomicBool>,
    server_task: tokio::task::JoinHandle<()>,
}

async fn spawn_mutable_upstream_rig(initial: Vec<Tool>) -> MutableUpstreamRig {
    let tools = Arc::new(Mutex::new(initial));
    let list_calls = Arc::new(AtomicUsize::new(0));
    let tool_calls = Arc::new(AtomicUsize::new(0));
    let fail_next_list = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let disconnect_next_list = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let transport_list_calls = Arc::new(AtomicUsize::new(0));
    let stall_lists = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler = MutableUpstream {
        tools: tools.clone(),
        list_calls: list_calls.clone(),
        tool_calls: tool_calls.clone(),
        fail_next_list: fail_next_list.clone(),
        stall_lists: stall_lists.clone(),
    };
    let svc = StreamableHttpService::new(
        move || Ok(handler.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let disconnect = disconnect_next_list.clone();
    let transport_lists = transport_list_calls.clone();
    let app: Router<()> = Router::new()
        .nest_service("/mcp", svc)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let disconnect = disconnect.clone();
            let transport_lists = transport_lists.clone();
            async move {
                if req.method() != Method::POST {
                    return next.run(req).await;
                }
                let (parts, body) = req.into_parts();
                let Ok(bytes) = to_bytes(body, 64 * 1024).await else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                let is_tools_list = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|value| value.get("method")?.as_str().map(str::to_owned))
                    .as_deref()
                    == Some("tools/list");
                let req = Request::from_parts(parts, Body::from(bytes));
                if is_tools_list {
                    transport_lists.fetch_add(1, Ordering::SeqCst);
                    if disconnect.swap(false, Ordering::SeqCst) {
                        let stream = futures::stream::once(async {
                            Err::<bytes::Bytes, _>(std::io::Error::other(
                                "provider-neutral pre-dispatch transport close",
                            ))
                        });
                        return Response::builder()
                            .status(StatusCode::OK)
                            .header(axum::http::header::CONTENT_TYPE, "application/json")
                            .body(Body::from_stream(stream))
                            .expect("fault response builds");
                    }
                }
                next.run(req).await
            }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    MutableUpstreamRig {
        addr,
        tools,
        list_calls,
        tool_calls,
        fail_next_list,
        disconnect_next_list,
        transport_list_calls,
        stall_lists,
        server_task,
    }
}

async fn spawn_mutable_upstream(
    initial: Vec<Tool>,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<Tool>>>,
    Arc<AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let rig = spawn_mutable_upstream_rig(initial).await;
    (rig.addr, rig.tools, rig.list_calls, rig.stall_lists)
}

/// `noop` with the complete, valid annotation-native claim set (standard
/// behavior hints plus action metadata), so its behavior hash is admissible
/// under `classification_mode: mcp_annotations`.
fn annotated_noop(description: &str) -> Tool {
    let schema = serde_json::json!({"type": "object", "properties": {}})
        .as_object()
        .cloned()
        .unwrap();
    let mut tool = Tool::new(
        "noop".to_string(),
        description.to_string(),
        Arc::new(schema),
    );
    tool.annotations = Some(ToolAnnotations::from_raw(
        None,
        Some(true),
        Some(false),
        Some(true),
        Some(false),
    ));
    tool.meta = Some(Meta(
        serde_json::from_value(serde_json::json!({
            "io.modelcontextprotocol/action-metadata": {
                "inputMetadata": {
                    "destination": "internal",
                    "sensitivity": "sensitive"
                },
                "returnMetadata": {
                    "source": "first-party",
                    "sensitivity": "sensitive"
                },
                "outcome": "benign",
                "requiresReview": false
            }
        }))
        .expect("object"),
    ));
    tool
}

fn annotation_manifest(addr: std::net::SocketAddr, approved: &Tool) -> UpstreamManifest {
    let mut m = manifest(addr, None);
    m.classification_mode = ClassificationMode::McpAnnotations;
    m.tools[0].approved_behavior_hash = Some(tool_behavior_hash(approved));
    m
}

/// The approved annotation contract must be bound to the SESSION that
/// executes the RPC. `per_call` dials a fresh session per call, and MCP does
/// not guarantee that a new session advertises the same descriptors as the
/// boot session — so the pool must read the ephemeral session's own
/// `tools/list` and refuse when the called tool no longer matches
/// `approved_behavior_hash` there, instead of validating only the boot
/// slot's cached view.
#[tokio::test]
async fn annotation_per_call_binds_contract_to_the_executing_session() {
    let approved = annotated_noop("stable behavior");
    let (addr, tools, list_calls, _stall) = spawn_mutable_upstream(vec![approved.clone()]).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), annotation_manifest(addr, &approved));
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");
    let boot_lists = list_calls.load(Ordering::SeqCst);

    pool.call_tool("mock", "noop", None, None, None)
        .await
        .expect("a session serving the approved contract must dispatch");
    assert_eq!(
        list_calls.load(Ordering::SeqCst),
        boot_lists + 1,
        "the ephemeral session's own contract must be read before the RPC",
    );

    *tools.lock().unwrap() = vec![annotated_noop("changed behavior")];
    let err = pool
        .call_tool("mock", "noop", None, None, None)
        .await
        .expect_err("a session serving an unapproved contract must be refused");
    assert!(
        err.message.contains("advertises a different contract"),
        "refusal must name the session-contract mismatch: {}",
        err.message,
    );
}

#[tokio::test]
async fn admitted_read_only_call_recovers_one_pre_dispatch_contract_read_failure() {
    let approved = annotated_noop("stable behavior");
    let rig = spawn_mutable_upstream_rig(vec![approved.clone()]).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), annotation_manifest(rig.addr, &approved));
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let ResolvedInvocationTool::Ready(snapshot) = pool
        .resolve_invocation_tool(waygate_core::TenantId::DEFAULT, "mock", "noop")
        .await
    else {
        panic!("the annotated read-only tool must resolve")
    };
    let admitted = snapshot.contract_identity();
    let boot_lists = rig.list_calls.load(Ordering::SeqCst);
    rig.fail_next_list.store(true, Ordering::SeqCst);

    pool.call_tool("mock", "noop", None, None, Some(&admitted))
        .await
        .expect("the safe attempt must recover before tool dispatch");

    assert_eq!(
        rig.list_calls.load(Ordering::SeqCst),
        boot_lists + 2,
        "the failed contract read and one recovery read share the retry budget",
    );
    assert_eq!(
        rig.tool_calls.load(Ordering::SeqCst),
        1,
        "the tool request is dispatched exactly once",
    );
    let health = pool.health_snapshot().await.remove(0);
    assert_eq!(
        health.last_error_class, None,
        "a recovered pre-dispatch failure is breaker-neutral",
    );
}

#[tokio::test]
async fn admitted_read_only_call_recovers_pre_dispatch_http_disconnect() {
    let approved = annotated_noop("stable behavior");
    let rig = spawn_mutable_upstream_rig(vec![approved.clone()]).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), annotation_manifest(rig.addr, &approved));
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let ResolvedInvocationTool::Ready(snapshot) = pool
        .resolve_invocation_tool(waygate_core::TenantId::DEFAULT, "mock", "noop")
        .await
    else {
        panic!("the annotated read-only tool must resolve")
    };
    let admitted = snapshot.contract_identity();
    let boot_lists = rig.transport_list_calls.load(Ordering::SeqCst);
    rig.disconnect_next_list.store(true, Ordering::SeqCst);

    pool.call_tool("mock", "noop", None, None, Some(&admitted))
        .await
        .expect("the admitted read must recover from a transport close before tool dispatch");

    assert_eq!(
        rig.transport_list_calls.load(Ordering::SeqCst),
        boot_lists + 2,
        "one disconnected contract read and one recovery read share the retry budget",
    );
    assert_eq!(
        rig.tool_calls.load(Ordering::SeqCst),
        1,
        "the tool request is accepted exactly once after recovery",
    );
    assert_eq!(
        pool.health_snapshot().await.remove(0).last_error_class,
        None,
        "the recovered pre-dispatch disconnect is breaker-neutral",
    );
}

#[tokio::test]
async fn admitted_read_only_call_bounds_real_http_dial_failure() {
    let approved = annotated_noop("stable behavior");
    let rig = spawn_mutable_upstream_rig(vec![approved.clone()]).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), annotation_manifest(rig.addr, &approved));
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let ResolvedInvocationTool::Ready(snapshot) = pool
        .resolve_invocation_tool(waygate_core::TenantId::DEFAULT, "mock", "noop")
        .await
    else {
        panic!("the annotated read-only tool must resolve")
    };
    let admitted = snapshot.contract_identity();
    rig.server_task.abort();
    let _ = rig.server_task.await;

    let error = pool
        .call_tool("mock", "noop", None, None, Some(&admitted))
        .await
        .expect_err("a stopped HTTP listener must exhaust the one dial recovery attempt");
    let data = error.data.expect("bounded dial failure data");
    assert_eq!(data["phase"], "dial");
    assert_eq!(data["attempts"], 2);
    assert_eq!(rig.tool_calls.load(Ordering::SeqCst), 0);
}

/// Legacy manifest mode keeps the pre-annotation dispatch shape: the
/// operator's manifest is the classification authority, so per-call sessions
/// are not interrogated for a contract before the RPC.
#[tokio::test]
async fn manifest_per_call_does_not_read_the_session_contract() {
    let schema = serde_json::json!({"type": "object", "properties": {}})
        .as_object()
        .cloned()
        .unwrap();
    let plain = Tool::new(
        "noop".to_string(),
        "no-op tool".to_string(),
        Arc::new(schema),
    );
    let (addr, _tools, list_calls, _stall) = spawn_mutable_upstream(vec![plain]).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), manifest(addr, None));
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");
    let boot_lists = list_calls.load(Ordering::SeqCst);

    for _ in 0..3 {
        pool.call_tool("mock", "noop", None, None, None)
            .await
            .expect("call_tool noop");
    }
    assert_eq!(
        list_calls.load(Ordering::SeqCst),
        boot_lists,
        "manifest-mode per-call dispatch must not add session contract reads",
    );
}

/// Dispatch must execute the exact contract identity Stage 1 admitted: when
/// the caller pins the admitted identity, a dispatch-time resolution that no
/// longer matches it — any drifted governance or schema field — must refuse
/// before the RPC, in both isolation modes.
#[tokio::test]
async fn dispatch_refuses_a_stale_admitted_contract_identity() {
    for isolation in [None, Some(SessionIsolation::Reuse)] {
        let (addr, _inits) = spawn_mock_upstream().await;
        let mut manifests = BTreeMap::new();
        manifests.insert("mock".into(), manifest(addr, isolation));
        let pool = UpstreamPool::connect(manifests).await;
        assert!(pool.is_connected("mock").await, "boot dial must connect");

        let resolved = pool
            .resolve_invocation_tool(waygate_core::TenantId::DEFAULT, "mock", "noop")
            .await;
        let ResolvedInvocationTool::Ready(snapshot) = resolved else {
            panic!("the admitted tool must resolve");
        };
        let admitted = snapshot.contract_identity();
        pool.call_tool("mock", "noop", None, None, Some(&admitted))
            .await
            .expect("the currently-admitted identity must dispatch");

        let mut stale = admitted.clone();
        stale.pii = !stale.pii;
        let err = pool
            .call_tool("mock", "noop", None, None, Some(&stale))
            .await
            .expect_err("a stale admitted identity must be refused before the RPC");
        assert!(
            err.message.contains("changed during call setup"),
            "refusal must be the retryable contract-changed error: {}",
            err.message,
        );
    }
}

/// Reuse-mode annotation dispatch must read the EXECUTING session's current
/// contract before every RPC: the pool handles no
/// `notifications/tools/list_changed`, so a long-lived reuse session whose
/// descriptors change after dial would otherwise keep executing under the
/// stale dial-time approved view until a reconnect.
#[tokio::test]
async fn annotation_reuse_binds_contract_to_the_executing_session() {
    let approved = annotated_noop("stable behavior");
    let (addr, tools, list_calls, _stall) = spawn_mutable_upstream(vec![approved.clone()]).await;
    let mut configured = annotation_manifest(addr, &approved);
    configured.session.as_mut().unwrap().isolation = Some(SessionIsolation::Reuse);
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");
    let boot_lists = list_calls.load(Ordering::SeqCst);

    pool.call_tool("mock", "noop", None, None, None)
        .await
        .expect("a session serving the approved contract must dispatch");
    assert_eq!(
        list_calls.load(Ordering::SeqCst),
        boot_lists + 1,
        "the reuse session's current contract must be read before the RPC",
    );

    *tools.lock().unwrap() = vec![annotated_noop("changed behavior")];
    let err = pool
        .call_tool("mock", "noop", None, None, None)
        .await
        .expect_err("a session whose contract drifted after dial must be refused");
    assert!(
        err.message.contains("advertises a different contract"),
        "refusal must name the session-contract mismatch: {}",
        err.message,
    );
}

/// Legacy manifest mode in reuse isolation keeps the pre-annotation dispatch
/// shape: no per-RPC session contract reads.
#[tokio::test]
async fn manifest_reuse_does_not_read_the_session_contract() {
    let schema = serde_json::json!({"type": "object", "properties": {}})
        .as_object()
        .cloned()
        .unwrap();
    let plain = Tool::new(
        "noop".to_string(),
        "no-op tool".to_string(),
        Arc::new(schema),
    );
    let (addr, _tools, list_calls, _stall) = spawn_mutable_upstream(vec![plain]).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), manifest(addr, Some(SessionIsolation::Reuse)));
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");
    let boot_lists = list_calls.load(Ordering::SeqCst);

    for _ in 0..3 {
        pool.call_tool("mock", "noop", None, None, None)
            .await
            .expect("call_tool noop");
    }
    assert_eq!(
        list_calls.load(Ordering::SeqCst),
        boot_lists,
        "manifest-mode reuse dispatch must not add session contract reads",
    );
}

/// The dispatch-path session contract read holds a checked-out connection
/// lane, so it must observe the pool's upstream call timeout: an unbounded
/// wedged `tools/list` would pin the lane forever and enough concurrent
/// calls would exhaust every lane even with the RPC timeout configured.
#[tokio::test]
#[ignore = "wall-clock integration check; run explicitly on an idle host (docs/testing.md)"]
async fn annotation_session_contract_read_is_time_bounded() {
    let approved = annotated_noop("stable behavior");
    let (addr, _tools, _list_calls, stall) = spawn_mutable_upstream(vec![approved.clone()]).await;
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), annotation_manifest(addr, &approved));
    let pool = UpstreamPool::connect(manifests)
        .await
        .with_call_timeout(Some(std::time::Duration::from_secs(1)));
    assert!(pool.is_connected("mock").await, "boot dial must connect");

    pool.call_tool("mock", "noop", None, None, None)
        .await
        .expect("a responsive session must dispatch");

    stall.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let err = pool
        .call_tool("mock", "noop", None, None, None)
        .await
        .expect_err("a stalled session contract read must be refused, not held");
    assert!(
        !err.message.contains("tools/list"),
        "the bounded response must not expose the transport detail: {}",
        err.message,
    );
    let data = err.data.expect("bounded failure data");
    assert_eq!(data["phase"], "pre_dispatch");
    assert_eq!(data["attempts"], 1);
    assert_eq!(data["retryable"], false);
    assert!(data["trace_id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "the whole attempt must be bounded by the original call timeout, took {:?}",
        started.elapsed(),
    );
    let health = pool.health_snapshot().await.remove(0);
    assert_eq!(
        health.last_error_class.map(|class| class.as_str()),
        Some("timeout"),
        "the bounded timeout cause must remain visible to operators",
    );
}

/// Every connected lane must advertise an admitted descriptor before a name
/// is callable: publication intersects lanes, so a name present on only one
/// lane is absent from the published contract Stage 1 reads — executing it
/// from the advertising lane would bind no schemas or security metadata.
#[tokio::test]
async fn annotation_multi_lane_disagreement_fails_closed() {
    let approved = annotated_noop("stable behavior");
    let with_tool = vec![approved.clone()];
    let sessions = Arc::new(AtomicUsize::new(0));
    let svc = StreamableHttpService::new(
        {
            let sessions = sessions.clone();
            let with_tool = with_tool.clone();
            move || {
                // The first session (one boot lane) advertises the approved
                // tool; every later session (the other lane) advertises
                // nothing — a per-lane catalog disagreement.
                let n = sessions.fetch_add(1, Ordering::SeqCst);
                let tools = if n == 0 {
                    with_tool.clone()
                } else {
                    Vec::new()
                };
                Ok(MutableUpstream {
                    tools: Arc::new(Mutex::new(tools)),
                    list_calls: Arc::new(AtomicUsize::new(0)),
                    tool_calls: Arc::new(AtomicUsize::new(0)),
                    fail_next_list: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    stall_lists: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                })
            }
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app: Router<()> = Router::new().nest_service("/mcp", svc);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut configured = annotation_manifest(addr, &approved);
    configured.session = Some(SessionConfig {
        concurrency: Some(2),
        isolation: Some(SessionIsolation::Reuse),
        scope: None,
        retry_on_setup_failure: None,
    });
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), configured);
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await, "boot dial must connect");

    let err = pool
        .call_tool("mock", "noop", None, None, None)
        .await
        .expect_err("a name absent from a connected lane must be refused");
    assert!(
        err.message.contains("no admitted tool"),
        "the refusal must be the admission gate, not a lane-dependent race: {}",
        err.message,
    );
}
