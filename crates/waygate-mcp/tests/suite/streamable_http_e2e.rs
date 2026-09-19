//! Pins the rmcp `StreamableHttpService` mount + `StreamableHttpClient`
//! transport surface end-to-end. Existing tests drive
//! `dispatch_tool_call`/`list_visible_tools` directly and bypass
//! `RequestContext`/`Peer` transport behavior, so changes to rmcp's HTTP
//! server (Origin/Host validation, session handling, notification delivery)
//! could regress without tripping CI. This test boots a real
//! `StreamableHttpService` over an axum loopback listener and drives a real
//! rmcp client against it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, ContentBlock as Content,
    ErrorData as McpError, Implementation, Tool,
};
use rmcp::service::{MaybeSendFuture, NotificationContext, ServiceError, ServiceExt};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{ClientHandler, ClientServiceExt, RoleClient};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use waygate_mcp::authz::{AuthzGate, AuthzVerdict, ToolFacts};
use waygate_mcp::catalog::{SharedCatalog, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{GatewayServer, ToolCatalogEpoch};
use waygate_oidc::Principal;

const ALLOWED_HOST: &str = "127.0.0.1";

mod client_schema_compat;

#[derive(Default)]
struct DemoCatalog {
    input_schema: Option<Map<String, Value>>,
    dispatches: Option<Arc<AtomicUsize>>,
    /// When set, `read_resource` returns this upstream freshness hint AND
    /// an upstream-declared `public` cache scope — the exact combination
    /// the gateway must pass through (ttl) and override (scope).
    resource_upstream_ttl: Option<u64>,
    resource_request_meta: Option<Arc<tokio::sync::Mutex<Option<rmcp::model::RequestMetaObject>>>>,
    /// Optional mutable tool order for stable-projection regressions.
    tool_names: Option<Arc<tokio::sync::RwLock<Vec<String>>>>,
    /// Tool names whose fixture schema deliberately has a non-object root.
    non_publishable_tool_names: Vec<String>,
    /// Tool names whose fixture classification requires step-up authorization.
    high_risk_tool_names: Vec<String>,
    /// Optional dispatch witness for routing-integrity regressions.
    list_tools_calls: Option<Arc<AtomicUsize>>,
}

#[async_trait]
impl UpstreamCatalog for DemoCatalog {
    async fn list_resources(
        &self,
        server: &str,
        _params: Option<rmcp::model::PaginatedRequestParams>,
        _principal: Option<&Principal>,
    ) -> Result<rmcp::model::ListResourcesResult, McpError> {
        if server != "demo" {
            return Err(McpError::method_not_found::<
                rmcp::model::ListResourcesRequestMethod,
            >());
        }
        Ok(rmcp::model::ListResourcesResult::with_all_items(vec![
            rmcp::model::Resource::new("demo://guide", "Guide"),
        ]))
    }

    async fn read_resource(
        &self,
        server: &str,
        params: rmcp::model::ReadResourceRequestParams,
        _principal: Option<&Principal>,
    ) -> Result<rmcp::model::ReadResourceResult, McpError> {
        if server != "demo" || params.uri != "demo://guide" {
            return Err(McpError::resource_not_found("unknown resource", None));
        }
        if let Some(observed) = &self.resource_request_meta {
            *observed.lock().await = params.meta.clone();
        }
        let mut read =
            rmcp::model::ReadResourceResult::new(vec![rmcp::model::ResourceContents::text(
                "guide body",
                params.uri,
            )]);
        if let Some(ttl) = self.resource_upstream_ttl {
            read.ttl_ms = Some(ttl);
            read.cache_scope = Some(rmcp::model::CacheScope::Public);
        }
        Ok(read)
    }
    async fn list_servers(&self) -> Vec<String> {
        vec!["demo".into()]
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        if let Some(calls) = &self.list_tools_calls {
            calls.fetch_add(1, Ordering::SeqCst);
        }
        if server != "demo" {
            return Err(McpError::invalid_params(
                format!("unknown server {server}"),
                None,
            ));
        }
        let schema = self.input_schema.clone().unwrap_or_else(|| {
            json!({"type": "object", "properties": {}})
                .as_object()
                .cloned()
                .unwrap()
        });
        let names = match &self.tool_names {
            Some(names) => names.read().await.clone(),
            None => vec!["echo".to_string()],
        };
        Ok(names
            .into_iter()
            .map(|name| {
                let mut tool_schema = schema.clone();
                if self.non_publishable_tool_names.contains(&name) {
                    tool_schema.insert("type".to_string(), Value::String("string".to_string()));
                }
                Tool::new(name, "demo tool".to_string(), Arc::new(tool_schema))
            })
            .collect())
    }

    async fn call_tool(
        &self,
        server: &str,
        tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(dispatches) = &self.dispatches {
            dispatches.fetch_add(1, Ordering::SeqCst);
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "called {server}.{tool_name}"
        ))]))
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> waygate_mcp::catalog::ResolvedInvocationTool {
        waygate_mcp::catalog::ResolvedInvocationTool::Ready(
            waygate_mcp::catalog::InvocationToolSnapshot::manifest_fallback_with_input_schema(
                self.tool_facts(server, tool_name),
                true,
                self.input_schema.clone().map(Value::Object),
            ),
        )
    }

    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        let high_risk = self
            .high_risk_tool_names
            .iter()
            .any(|candidate| candidate == tool_name);
        ToolFacts {
            server: server.into(),
            name: tool_name.into(),
            risk: if high_risk {
                RiskTier::High
            } else {
                RiskTier::Low
            },
            side_effects: high_risk,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
}

struct HighRiskScopeGate;

#[async_trait]
impl AuthzGate for HighRiskScopeGate {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }

    async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
        if let Some(required_scope) = facts.action.required_scope.as_deref() {
            if !facts
                .principal
                .scopes
                .iter()
                .any(|scope| scope == required_scope)
            {
                return AuthzVerdict::StepUpRequired {
                    required_scope: required_scope.to_owned(),
                    reason: "high-risk operation requires a fresh authorization".to_owned(),
                    policy_ids: vec!["step-up-high-risk".to_owned()],
                };
            }
        }
        AuthzVerdict::Allow {
            policy_ids: vec!["permit-tool-call".to_owned()],
        }
    }
}

#[derive(Clone, Default)]
struct PassiveClient;

impl ClientHandler for PassiveClient {}

#[derive(Clone, Default)]
struct CatalogChangeClient {
    prompt_notify: Arc<Notify>,
    notifications: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl ClientHandler for CatalogChangeClient {
    fn on_prompt_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + MaybeSendFuture + '_ {
        self.prompt_notify.notify_one();
        std::future::ready(())
    }
    fn on_tool_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + MaybeSendFuture + '_ {
        self.notifications.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
        std::future::ready(())
    }
}

struct ServerHandle {
    addr: std::net::SocketAddr,
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.join.await;
    }
}

async fn spawn_gateway_with_allowed_hosts(allowed: Vec<String>) -> ServerHandle {
    let session_ct = CancellationToken::new();
    spawn_gateway_with_config(
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(allowed),
    )
    .await
}

async fn spawn_gateway_with_config(config: StreamableHttpServerConfig) -> ServerHandle {
    let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
    spawn_gateway_custom(config, move || GatewayServer::new(catalog.clone())).await
}

/// Spawn variant that lets a test customize the per-session
/// `GatewayServer` (ping interval, injected stats, …) the rmcp factory
/// builds.
async fn spawn_gateway_custom<F>(config: StreamableHttpServerConfig, make_server: F) -> ServerHandle
where
    F: Fn() -> GatewayServer + Send + Sync + 'static,
{
    spawn_gateway_custom_with_principal(config, make_server, None).await
}

async fn spawn_gateway_custom_with_principal<F>(
    config: StreamableHttpServerConfig,
    make_server: F,
    principal: Option<Principal>,
) -> ServerHandle
where
    F: Fn() -> GatewayServer + Send + Sync + 'static,
{
    let mcp_service = StreamableHttpService::new(
        move || Ok(make_server()),
        LocalSessionManager::default().into(),
        config,
    );

    let app: Router<()> = Router::new().nest_service("/mcp", mcp_service);
    let app = match principal {
        Some(principal) => app.layer(axum::Extension(principal)),
        None => app,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = CancellationToken::new();
    let shutdown_for_serve = shutdown.clone();
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown_for_serve.cancelled().await })
            .await;
    });
    ServerHandle {
        addr,
        shutdown,
        join,
    }
}

async fn connect_named_client(
    addr: std::net::SocketAddr,
    name: &str,
) -> rmcp::service::RunningService<RoleClient, ClientInfo> {
    let uri: Arc<str> = Arc::from(format!("http://{addr}/mcp"));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new(name, "test"),
    )
    .serve(transport)
    .await
    .expect("initialize named client against in-process gateway")
}

#[tokio::test]
async fn streamable_http_initialize_list_call_round_trip() {
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;

    let uri: Arc<str> = Arc::from(format!("http://{}/mcp", server.addr));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    let client: rmcp::service::RunningService<RoleClient, PassiveClient> = PassiveClient
        .serve(transport)
        .await
        .expect("initialize against in-process gateway");

    let listed = client
        .list_tools(Default::default())
        .await
        .expect("tools/list");
    let names: Vec<&str> = listed.tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(
        names.contains(&"demo.searchTools"),
        "expected demo.searchTools in tools/list, got {names:?}",
    );

    let search = client
        .call_tool(
            CallToolRequestParams::new("demo.searchTools")
                .with_arguments(json!({"mode": "operations"}).as_object().cloned().unwrap()),
        )
        .await
        .expect("tools/call demo.searchTools");
    assert!(
        !search.is_error.unwrap_or(false),
        "demo.searchTools should succeed, got: {search:?}",
    );

    let _ = client.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn eager_client_allowlist_applies_only_to_matching_session() {
    let session_ct = CancellationToken::new();
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
            GatewayServer::new(catalog).with_eager_tools_clients(vec!["claude-code".to_owned()])
        },
    )
    .await;

    let static_client = connect_named_client(server.addr, "Claude-Code").await;
    let static_names: Vec<String> = static_client
        .list_tools(Default::default())
        .await
        .expect("static client tools/list")
        .tools
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(static_names.contains(&"demo.searchTools".to_owned()));
    assert!(
        static_names.contains(&"demo.echo".to_owned()),
        "matching client must receive the authorized catalog eagerly: {static_names:?}"
    );

    let progressive_client = connect_named_client(server.addr, "compliant-client").await;
    let progressive_names: Vec<String> = progressive_client
        .list_tools(Default::default())
        .await
        .expect("progressive client tools/list")
        .tools
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(progressive_names.contains(&"demo.searchTools".to_owned()));
    assert!(
        !progressive_names.contains(&"demo.echo".to_owned()),
        "non-matching client must remain progressively disclosed: {progressive_names:?}"
    );

    let _ = static_client.cancel().await;
    let _ = progressive_client.cancel().await;
    server.shutdown().await;
}

fn mutation_catalog() -> SharedCatalog {
    Arc::new(DemoCatalog {
        tool_names: Some(Arc::new(tokio::sync::RwLock::new(vec![
            "api.get".to_owned(),
            "api.mutate".to_owned(),
            "api.destroy".to_owned(),
        ]))),
        high_risk_tool_names: vec!["api.mutate".to_owned(), "api.destroy".to_owned()],
        ..DemoCatalog::default()
    })
}

#[tokio::test]
async fn codex_eager_catalog_supports_search_then_direct_mutation() {
    let session_ct = CancellationToken::new();
    let mut principal = wire_principal();
    principal.scopes.push("mcp:invoke:high".to_owned());
    let server = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            GatewayServer::with_authz(mutation_catalog(), Arc::new(HighRiskScopeGate))
                .with_eager_tools_clients(vec!["codex-mcp-client".to_owned()])
        },
        Some(principal),
    )
    .await;

    let client = connect_named_client(server.addr, "codex-mcp-client").await;
    let listed = client
        .list_tools(Default::default())
        .await
        .expect("Codex tools/list");
    let names: Vec<_> = listed.tools.iter().map(|tool| tool.name.as_ref()).collect();
    for expected in [
        "demo.searchTools",
        "demo.api.get",
        "demo.api.mutate",
        "demo.api.destroy",
    ] {
        assert!(
            names.contains(&expected),
            "Codex must receive a callable declaration for {expected}: {names:?}"
        );
    }

    let discovered = client
        .call_tool(
            CallToolRequestParams::new("demo.searchTools").with_arguments(
                json!({"mode": "operations", "detail": "full"})
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
        .expect("search mutation operations");
    let discovered = serde_json::to_string(&discovered).expect("serialize search result");
    assert!(discovered.contains("demo.api.get"), "{discovered}");
    assert!(discovered.contains("demo.api.mutate"), "{discovered}");
    assert!(discovered.contains("demo.api.destroy"), "{discovered}");
    assert!(discovered.contains("mcp:invoke:high"), "{discovered}");

    for tool in ["demo.api.get", "demo.api.mutate", "demo.api.destroy"] {
        let called = client
            .call_tool(CallToolRequestParams::new(tool))
            .await
            .unwrap_or_else(|error| panic!("direct call to {tool} failed: {error}"));
        assert!(
            called.content.iter().any(|content| content
                .as_text()
                .is_some_and(|text| text.text == format!("called {tool}"))),
            "direct call did not reach the upstream: {called:?}"
        );
    }

    let _ = client.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn codex_direct_mutation_returns_structured_step_up_error_without_scope() {
    let session_ct = CancellationToken::new();
    let server = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            GatewayServer::with_authz(mutation_catalog(), Arc::new(HighRiskScopeGate))
                .with_eager_tools_clients(vec!["codex-mcp-client".to_owned()])
        },
        Some(wire_principal()),
    )
    .await;

    let client = connect_named_client(server.addr, "codex-mcp-client").await;
    let listed = client
        .list_tools(Default::default())
        .await
        .expect("Codex tools/list");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name.as_ref() == "demo.api.mutate"),
        "a step-up-capable operation must remain discoverable"
    );

    let discovered = client
        .call_tool(
            CallToolRequestParams::new("demo.searchTools").with_arguments(
                json!({"mode": "operations", "detail": "full"})
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
        .expect("search mutation operations");
    let discovered = serde_json::to_string(&discovered).expect("serialize search result");
    assert!(discovered.contains("demo.api.mutate"), "{discovered}");
    assert!(discovered.contains("mcp:invoke:high"), "{discovered}");

    let error = client
        .call_tool(CallToolRequestParams::new("demo.api.mutate"))
        .await
        .expect_err("mutation without the step-up scope must be refused");
    let ServiceError::McpError(error) = error else {
        panic!("expected a structured MCP authorization error");
    };
    assert!(error.message.contains("step-up required"), "{error:?}");
    let data = error.data.as_ref().expect("structured authorization error");
    assert_eq!(data["error"], "insufficient_scope");
    assert_eq!(data["required_scope"], "mcp:invoke:high");

    let read = client
        .call_tool(CallToolRequestParams::new("demo.api.get"))
        .await
        .expect("read-only direct invocation must continue to work");
    assert!(
        read.content.iter().any(|content| content
            .as_text()
            .is_some_and(|text| text.text == "called demo.api.get")),
        "read-only direct call did not reach the upstream: {read:?}"
    );

    let _ = client.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn codemode_only_client_allowlist_hides_upstream_declarations() {
    let session_ct = CancellationToken::new();
    let server = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
            GatewayServer::new(catalog)
                .with_builtin_tools(Arc::new(CodeModeTaskStub))
                .with_codemode_only_tools_clients(vec!["cursor".to_owned()])
        },
        Some(wire_principal()),
    )
    .await;

    let compact_client = connect_named_client(server.addr, "Cursor").await;
    let compact_instructions = compact_client
        .peer_info()
        .and_then(|info| info.instructions.clone())
        .expect("compact legacy initialize returns instructions");
    assert!(compact_instructions.contains("codemode.search"));
    assert!(compact_instructions.contains("codemode.execute"));
    let compact_names: Vec<String> = compact_client
        .list_tools(Default::default())
        .await
        .expect("compact client tools/list")
        .tools
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(compact_names.contains(&"codemode.execute".to_owned()));
    assert!(compact_names.contains(&"codemode.resume".to_owned()));
    assert!(
        !compact_names.iter().any(|name| name.starts_with("demo.")),
        "matching client must receive gateway built-ins without upstream declarations: {compact_names:?}"
    );
    let called = compact_client
        .call_tool(CallToolRequestParams::new("codemode.execute"))
        .await
        .expect("compact client routes the Code Mode execution facade");
    assert!(
        called
            .content
            .iter()
            .any(|content| content.as_text().is_some_and(|text| text.text == "sync")),
        "the compact projection must preserve ordinary built-in dispatch routing: {called:?}"
    );

    let progressive_client = connect_named_client(server.addr, "compliant-client").await;
    let progressive_names: Vec<String> = progressive_client
        .list_tools(Default::default())
        .await
        .expect("progressive client tools/list")
        .tools
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(progressive_names.contains(&"codemode.execute".to_owned()));
    assert!(progressive_names.contains(&"demo.searchTools".to_owned()));
    assert!(
        !progressive_names.contains(&"demo.echo".to_owned()),
        "non-matching legacy client must keep progressive disclosure: {progressive_names:?}"
    );

    let _ = compact_client.cancel().await;
    let _ = progressive_client.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn configured_skills_notify_an_already_connected_prompt_client() {
    let mut principal = wire_principal();
    principal.scopes.push("mcp:read".into());
    let epoch = ToolCatalogEpoch::new();
    let session_ct = CancellationToken::new();
    let server = {
        let epoch = epoch.clone();
        spawn_gateway_custom_with_principal(
            StreamableHttpServerConfig::default()
                .with_cancellation_token(session_ct.child_token())
                .with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
            move || {
                GatewayServer::new(Arc::new(DemoCatalog::default()))
                    .with_skill_catalog(Some(Arc::new(
                        waygate_skills::ReloadableSkillCatalog::default(),
                    )))
                    .with_tool_catalog_epoch(&epoch)
            },
            Some(principal),
        )
        .await
    };
    let uri: Arc<str> = Arc::from(format!("http://{}/mcp", server.addr));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    let handler = CatalogChangeClient::default();
    let notify = handler.prompt_notify.clone();
    let client = handler.serve(transport).await.unwrap();
    client
        .list_prompts(None)
        .await
        .expect("prompt capability exists before the first snapshot");
    epoch.mark_changed();
    tokio::time::timeout(std::time::Duration::from_secs(5), notify.notified())
        .await
        .expect("connected client receives prompts/list_changed");
    let _ = client.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn upstream_catalog_epoch_notifies_initialized_downstream_session() {
    let epoch = ToolCatalogEpoch::new();
    epoch.mark_changed();
    let session_ct = CancellationToken::new();
    let server = {
        let epoch = epoch.clone();
        spawn_gateway_custom(
            StreamableHttpServerConfig::default()
                .with_cancellation_token(session_ct.child_token())
                .with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
            move || {
                let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
                GatewayServer::new(catalog).with_tool_catalog_epoch(&epoch)
            },
        )
        .await
    };

    let uri: Arc<str> = Arc::from(format!("http://{}/mcp", server.addr));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    let handler = CatalogChangeClient::default();
    let notifications = handler.notifications.clone();
    let notify = handler.notify.clone();
    let client: rmcp::service::RunningService<RoleClient, CatalogChangeClient> = handler
        .serve(transport)
        .await
        .expect("initialize against in-process gateway");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        notifications.load(Ordering::SeqCst),
        0,
        "changes before session construction are its baseline",
    );

    epoch.mark_changed();
    tokio::time::timeout(std::time::Duration::from_secs(5), notify.notified())
        .await
        .expect("initialized client receives tools/list_changed");
    assert_eq!(notifications.load(Ordering::SeqCst), 1);

    let _ = client.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn streamable_http_rejects_disallowed_host_header() {
    // Pins rmcp 1.6.0's DNS-rebinding guard: a request with a Host header
    // outside `with_allowed_hosts` is rejected before the protocol layer
    // sees it. Production wires the same guard via
    // `resolve_mcp_allowed_hosts` in waygate-server::main.
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;

    let url = format!("http://{}/mcp", server.addr);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rebind-probe", "version": "0.0.0"}
        }
    });

    let resp = reqwest::Client::new()
        .post(&url)
        .header("host", "evil.example")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("POST /mcp with spoofed Host");

    let status = resp.status();
    assert!(
        status.is_client_error(),
        "request with disallowed Host header should be rejected with a 4xx; got {status} {}",
        resp.text().await.unwrap_or_default(),
    );

    server.shutdown().await;
}

#[tokio::test]
#[ignore = "rmcp 1.6.0 ships the Origin-validation API but it's opt-in: \
            waygate-server only calls with_allowed_hosts, not \
            with_allowed_origins, so requests with a disallowed Origin \
            still return 200. Un-ignore once the production wire-up \
            (a config knob mirroring MCP_ALLOWED_HOSTS) lands."]
async fn streamable_http_rejects_disallowed_origin_header() {
    // Pins rmcp 1.6.0's Origin-header validation surface specifically
    // (sibling to with_allowed_hosts' Host check); this test exercises
    // the Origin path end-to-end. With allowed hosts configured to
    // 127.0.0.1, sending an Origin header pointing at a disallowed
    // host should be rejected even when the Host header is legitimate.
    //
    // Why #[ignore]d even though the pinned rmcp (1.6.0+) ships Origin
    // validation: the Origin validation in rmcp is opt-in. The production
    // mount in `crates/waygate-server/src/main.rs` calls
    // `StreamableHttpServerConfig::with_allowed_hosts(...)` but does
    // not call `.with_allowed_origins(...)`, so the server still
    // returns 200 for any Origin. Un-ignoring requires a parallel
    // production change (config knob + wire-up); after that, drop the
    // `#[ignore]` in the same commit.
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;

    let url = format!("http://{}/mcp", server.addr);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "origin-probe", "version": "0.0.0"}
        }
    });

    let resp = reqwest::Client::new()
        .post(&url)
        .header("origin", "http://evil.example")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("POST /mcp with spoofed Origin");

    let status = resp.status();
    assert!(
        status.is_client_error(),
        "request with disallowed Origin header should be rejected with a 4xx; got {status} {}",
        resp.text().await.unwrap_or_default(),
    );

    server.shutdown().await;
}

/// Initialize an MCP session over raw HTTP and return the `Mcp-Session-Id`.
///
/// Raw reqwest rather than the rmcp client on purpose: the keepalive tests
/// below assert on the byte-level SSE framing of the standalone GET stream,
/// which the rmcp client consumes and hides.
async fn raw_initialize_session(client: &reqwest::Client, url: &str) -> String {
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "keepalive-probe", "version": "0.0.0"}
        }
    });
    let resp = client
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .json(&init)
        .send()
        .await
        .expect("POST initialize");
    assert!(
        resp.status().is_success(),
        "initialize should succeed, got {}",
        resp.status()
    );
    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .expect("initialize response carries Mcp-Session-Id")
        .to_str()
        .expect("session id is ASCII")
        .to_owned();
    // Drain the POST's SSE body so the response stream completes cleanly.
    let _ = resp.bytes().await;

    let resp = client
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-session-id", &session_id)
        .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .expect("POST notifications/initialized");
    assert!(
        resp.status().is_success(),
        "initialized notification should be accepted, got {}",
        resp.status()
    );
    session_id
}

/// Open the standalone GET stream and collect raw body bytes for `window`.
async fn collect_get_stream_bytes(
    client: &reqwest::Client,
    url: &str,
    session_id: &str,
    window: std::time::Duration,
) -> Vec<u8> {
    use futures::StreamExt;

    let resp = client
        .get(url)
        .header("accept", "text/event-stream")
        .header("mcp-session-id", session_id)
        .send()
        .await
        .expect("GET standalone SSE stream");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "standalone GET stream should open"
    );
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Ok(chunk))) => buf.extend_from_slice(&chunk),
            // Stream ended or errored — stop collecting; assertions on the
            // collected buffer decide pass/fail.
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => break, // window elapsed
        }
    }
    buf
}

/// Count SSE comment lines (lines that begin with `:`) — the keepalive
/// heartbeat frame. Field lines (`id:`, `retry:`, `data:`, `event:`) never
/// begin with a colon, so this cleanly separates heartbeats from priming
/// events and real messages.
fn count_sse_comment_lines(body: &[u8]) -> usize {
    body.split(|&b| b == b'\n')
        .filter(|line| line.first() == Some(&b':'))
        .count()
}

#[tokio::test]
async fn sse_keepalive_emits_comment_frames_on_standalone_get_stream() {
    // Pins the transport contract the gateway's `GATEWAY_SSE_KEEPALIVE_SECONDS`
    // knob relies on: `with_sse_keep_alive(Some(d))` must produce SSE comment
    // frames on an otherwise-idle standalone GET stream at roughly that
    // cadence. Those frames are what keep intermediaries with idle-read
    // timeouts (proxy read_timeout, LB idle timeout) from reaping a quiet
    // stream. If an rmcp bump changes or drops this behavior, this test —
    // not a production incident — is where it surfaces.
    let session_ct = CancellationToken::new();
    let server = spawn_gateway_with_config(
        StreamableHttpServerConfig::default()
            .with_sse_keep_alive(Some(std::time::Duration::from_millis(200)))
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let sid = raw_initialize_session(&client, &url).await;
    let body =
        collect_get_stream_bytes(&client, &url, &sid, std::time::Duration::from_millis(1500)).await;

    let heartbeats = count_sse_comment_lines(&body);
    assert!(
        heartbeats >= 2,
        "expected at least 2 keepalive comment frames in 1.5s at a 200ms \
         interval, got {heartbeats}; raw stream: {:?}",
        String::from_utf8_lossy(&body)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn sse_keepalive_disabled_emits_no_comment_frames() {
    // The `GATEWAY_SSE_KEEPALIVE_SECONDS=0` contract: `with_sse_keep_alive(None)`
    // must fully silence heartbeats. rmcp's `Default` heartbeats on its own,
    // so if this assertion starts failing the "0 disables" documentation has
    // become a lie and the wiring needs re-examination.
    let session_ct = CancellationToken::new();
    let server = spawn_gateway_with_config(
        StreamableHttpServerConfig::default()
            .with_sse_keep_alive(None)
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let sid = raw_initialize_session(&client, &url).await;
    let body =
        collect_get_stream_bytes(&client, &url, &sid, std::time::Duration::from_millis(1000)).await;

    let heartbeats = count_sse_comment_lines(&body);
    assert_eq!(
        heartbeats,
        0,
        "with keepalive disabled the idle GET stream must emit no comment \
         frames; raw stream: {:?}",
        String::from_utf8_lossy(&body)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn server_ping_loop_receives_pongs_from_conforming_client() {
    // The MCP ping utility end-to-end: with a ping interval configured,
    // the server periodically sends `ping` requests, and a conforming
    // client MUST respond promptly. The rmcp client answers pings in its
    // protocol layer and opens the standalone GET stream automatically,
    // so observed pongs prove the whole round trip — server request onto
    // the GET stream, client pong back via POST.
    let stats = Arc::new(waygate_mcp::PingStats::default());
    let session_ct = CancellationToken::new();
    let server = {
        let stats = stats.clone();
        spawn_gateway_custom(
            StreamableHttpServerConfig::default()
                .with_cancellation_token(session_ct.child_token())
                .with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
            move || {
                let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
                GatewayServer::new(catalog)
                    .with_client_ping_interval(Some(std::time::Duration::from_millis(100)))
                    .with_ping_stats(stats.clone())
            },
        )
        .await
    };

    let uri: Arc<str> = Arc::from(format!("http://{}/mcp", server.addr));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    let client: rmcp::service::RunningService<RoleClient, PassiveClient> = PassiveClient
        .serve(transport)
        .await
        .expect("initialize against in-process gateway");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while stats.ok() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        stats.ok() >= 2,
        "expected at least 2 pongs from a conforming client within 5s; \
         sent={} ok={} timed_out={} stopped={}",
        stats.sent(),
        stats.ok(),
        stats.timed_out(),
        stats.stopped(),
    );
    assert_eq!(
        stats.stopped(),
        0,
        "a responsive client must never trip the stop threshold"
    );

    let _ = client.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn server_ping_loop_stops_after_consecutive_unanswered_pings() {
    // The failure half of the ping contract: timeouts are treated as
    // connection failures, and after consecutive unanswered pings the
    // loop stops for the session's remaining lifetime. Stopping matters
    // because outbound pings re-arm rmcp's session idle timer — a loop
    // that pinged forever would keep a dead client's session alive past
    // the idle reap indefinitely.
    let stats = Arc::new(waygate_mcp::PingStats::default());
    let session_ct = CancellationToken::new();
    let server = {
        let stats = stats.clone();
        spawn_gateway_custom(
            StreamableHttpServerConfig::default()
                .with_cancellation_token(session_ct.child_token())
                .with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
            move || {
                let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
                GatewayServer::new(catalog)
                    .with_client_ping_interval(Some(std::time::Duration::from_millis(150)))
                    .with_ping_stats(stats.clone())
            },
        )
        .await
    };
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    // A non-conforming client: completes the handshake and holds the GET
    // stream open (so pings ARE delivered), but never answers them.
    let sid = raw_initialize_session(&client, &url).await;
    let reader = {
        let (client, url, sid) = (client.clone(), url.clone(), sid.clone());
        tokio::spawn(async move {
            collect_get_stream_bytes(&client, &url, &sid, std::time::Duration::from_secs(15)).await
        })
    };

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while stats.stopped() < 1 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        stats.stopped(),
        1,
        "loop must stop after consecutive unanswered pings; \
         sent={} ok={} timed_out={}",
        stats.sent(),
        stats.ok(),
        stats.timed_out(),
    );
    assert_eq!(
        stats.timed_out(),
        3,
        "stop threshold is 3 consecutive timeouts"
    );
    assert_eq!(stats.ok(), 0, "an unresponsive client can produce no pongs");
    let sent_at_stop = stats.sent();

    // A stopped loop must stay stopped: no further pings across several
    // would-be intervals.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(
        stats.sent(),
        sent_at_stop,
        "no pings may be sent after the loop stops"
    );

    reader.abort();
    server.shutdown().await;
}

/// A version the gateway does not serve is refused with
/// `UnsupportedProtocolVersion` (`-32022`) and mints no session — the
/// negotiation boundary that keeps an unknown future revision from being
/// silently served with the wrong semantics.
#[tokio::test]
async fn unknown_protocol_version_is_refused_with_unsupported_protocol_version() {
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;
    let url = format!("http://{}/mcp", server.addr);

    let body = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2027-01-01",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "stateless-probe",
                    "version": "0.0.0"
                }
            }
        }
    });
    let resp = reqwest::Client::new()
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2027-01-01")
        // The SDK validates the SEP-2243 routing header before version
        // negotiation, so the probe must carry it to reach the refusal
        // under test.
        .header("mcp-method", "tools/list")
        .json(&body)
        .send()
        .await
        .expect("POST stateless tools/list");

    assert!(
        resp.headers().get("mcp-session-id").is_none(),
        "a refused stateless request must not mint a session"
    );
    let text = resp.text().await.expect("response body");
    assert!(
        text.contains("-32022"),
        "an unadvertised protocol version must be refused with \
         UnsupportedProtocolVersion (-32022); got: {text}"
    );

    server.shutdown().await;
}

/// Task-capable stub whose `enqueue_task` accepts BOTH `execute` and
/// `resume` — mirroring Code Mode, whose durable-task contract covers both
/// even though `task_tool()` names only `execute`. `execute` also supports
/// ordinary synchronous calls.
#[derive(Clone)]
struct CodeModeTaskStub;

#[async_trait]
impl waygate_mcp::BuiltinTools for CodeModeTaskStub {
    fn namespace(&self) -> &str {
        "codemode"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        let schema = Arc::new(json!({"type": "object"}).as_object().unwrap().clone());
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![
                Tool::new("codemode.execute", "start a task", schema.clone()),
                Tool::new("codemode.resume", "resume a task", schema),
            ],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "codemode".into(),
            required_scope: "mcp:invoke".into(),
            summary: "task-capable stub".into(),
            tools: vec![
                waygate_mcp::BuiltinToolDescriptor {
                    name: "execute".into(),
                    description: "start a task".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                },
                waygate_mcp::BuiltinToolDescriptor {
                    name: "resume".into(),
                    description: "resume a task".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                },
            ],
        }
    }

    async fn list_tools(&self, principal: Option<&waygate_oidc::Principal>) -> Vec<Tool> {
        if principal.is_some_and(|principal| {
            principal
                .scopes
                .iter()
                .any(|scope| scope == waygate_oidc::Scope::McpInvoke.as_str())
        }) {
            self.catalog().definitions()
        } else {
            Vec::new()
        }
    }

    async fn call(
        &self,
        tool: &str,
        arguments: Option<rmcp::model::JsonObject>,
        principal: Option<&waygate_oidc::Principal>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if tool != "execute" || arguments.is_some_and(|arguments| !arguments.is_empty()) {
            return Err(McpError::invalid_params(
                "execution routing stub accepts only an empty execute call",
                None,
            ));
        }
        if !principal.is_some_and(|principal| {
            principal
                .scopes
                .iter()
                .any(|scope| scope == waygate_oidc::Scope::McpInvoke.as_str())
        }) {
            return Err(McpError::invalid_params("missing mcp:invoke", None));
        }
        Ok(CallToolResult::success(vec![Content::text("sync")]))
    }

    fn supports_tasks(&self) -> bool {
        true
    }

    fn task_tool(&self) -> Option<&str> {
        Some("execute")
    }

    async fn enqueue_task(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&waygate_oidc::Principal>,
    ) -> Result<Option<rmcp::model::Task>, rmcp::ErrorData> {
        if !matches!(tool, "execute" | "resume") {
            return Ok(None);
        }
        Ok(Some(rmcp::model::Task::new(
            format!("task-{tool}"),
            rmcp::model::TaskStatus::Working,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        )))
    }
}

/// Every tool the built-in's `enqueue_task` accepts gets task treatment for
/// a tasks-declaring client — eligibility belongs to the built-in, not to
/// `task_tool()` (which names only the primary tool). Code Mode's durable
/// resume contract depends on `resume` enqueuing, not running synchronously.
#[tokio::test]
async fn tasks_client_gets_task_treatment_for_every_enqueueable_tool() {
    let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
    let server = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()).with_builtin_tools(Arc::new(CodeModeTaskStub)),
        Some(wire_principal()),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    // Legacy handshake declaring the tasks extension capability.
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            "clientInfo": {"name": "task-probe", "version": "0.0.0"}
        }
    });
    let resp = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .json(&init)
        .send()
        .await
        .expect("POST initialize");
    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .unwrap()
        .to_owned();
    let _ = resp.bytes().await;
    let _ = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-session-id", &session_id)
        .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .expect("POST initialized");

    for (id, tool) in [(2, "codemode.execute"), (3, "codemode.resume")] {
        let resp = client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-session-id", &session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {}}
            }))
            .send()
            .await
            .expect("POST tools/call");
        let body = resp.text().await.expect("body");
        assert!(
            body.contains(&format!("task-{}", tool.trim_start_matches("codemode."))),
            "{tool} must enqueue a task for a tasks-declaring client, \
             not run synchronously; got: {body}"
        );
    }

    server.shutdown().await;
}

/// The in-memory result structs carry `result_type: Some(COMPLETE)` (the
/// rmcp 3.0 constructor shape), but the SDK's routing layer strips the
/// field for every peer that did not negotiate 2026-07-28 — which is
/// every session on the legacy path, while 2026-07-28 peers are served
/// statelessly with the field intact. Pin the legacy wire: neither
/// `tools/list` nor `resources/list` responses on a session may carry
/// `resultType`, so a future SDK regression (or a gateway change that
/// bypasses the strip) fails here instead of silently changing the
/// 2025-11-25 wire.
#[tokio::test]
async fn legacy_list_responses_carry_no_result_type_on_the_wire() {
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();
    let session_id = raw_initialize_session(&client, &url).await;

    for (id, method) in [(11, "tools/list"), (12, "resources/list")] {
        let resp = client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-session-id", &session_id)
            .json(&json!({"jsonrpc": "2.0", "id": id, "method": method}))
            .send()
            .await
            .expect("POST list request");
        let body = resp.text().await.expect("body");
        assert!(
            body.contains("\"result\""),
            "{method} should return a result on the legacy session; got: {body}"
        );
        assert!(
            !body.contains("resultType"),
            "{method} on a 2025-11-25 session must not carry resultType; got: {body}"
        );
    }

    server.shutdown().await;
}

/// Raw stateless 2026-07-28 POST helper: inline `_meta` negotiation, the
/// SEP-2243 routing header, no session anywhere.
async fn stateless_post(
    client: &reqwest::Client,
    url: &str,
    id: u64,
    method: &str,
    params: serde_json::Value,
    client_name: &str,
) -> reqwest::Response {
    let mut params = params;
    params.as_object_mut().expect("object params").insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": client_name,
                "version": "0.0.0"
            }
        }),
    );
    let mut req = client
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    // SEP-2243: name-scoped methods additionally route on the tool name
    // (`tools/call`) or resource URI (`resources/read`).
    if let Some(name) = params
        .get("name")
        .or_else(|| params.get("uri"))
        .and_then(|n| n.as_str())
    {
        req = req.header("mcp-name", name.to_owned());
    }
    req.json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .send()
        .await
        .expect("stateless POST")
}

/// Decode the one JSON-RPC message from a stateless response. rmcp may frame
/// even a complete response as one SSE `data:` event when the request accepts
/// both standard MCP response media types.
async fn stateless_response_json(response: reqwest::Response) -> Value {
    let body = response.text().await.expect("stateless response body");
    let payload = body
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(body.trim());
    serde_json::from_str(payload).unwrap_or_else(|error| {
        panic!("stateless response must carry one JSON-RPC message: {error}; body={body}")
    })
}

/// Server-level discovery guidance belongs once in `server/discover`, never
/// prepended to each raw tool description. A connector or host may choose a
/// different model-prompt rendering, but that transformation must remain
/// distinguishable from the gateway's MCP wire contract.
#[tokio::test]
async fn stateless_wire_keeps_server_instructions_out_of_tool_descriptions() {
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();
    let instructions =
        "Call tools as `<server>.<toolName>`; the authorized catalog is in `tools/list`.";

    let discover = stateless_post(&client, &url, 1, "server/discover", json!({}), "probe")
        .await
        .text()
        .await
        .expect("server/discover body");
    assert_eq!(
        discover.matches(instructions).count(),
        1,
        "raw discovery must carry the shared guidance exactly once: {discover}",
    );

    let listed = stateless_post(&client, &url, 2, "tools/list", json!({}), "probe")
        .await
        .text()
        .await
        .expect("tools/list body");
    assert_eq!(
        listed.matches(instructions).count(),
        0,
        "raw tool descriptions must not repeat server-level guidance: {listed}",
    );

    server.shutdown().await;
}

/// A 2026-07-28 request is served statelessly: no session id is minted, the
/// result carries the SEP-2322 `resultType` discriminator, and the SEP-1888
/// meta-tool catalog is visible.
#[tokio::test]
async fn stateless_request_is_served_without_a_session() {
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let resp = stateless_post(&client, &url, 1, "tools/list", json!({}), "stateless-probe").await;
    assert!(
        resp.headers().get("mcp-session-id").is_none(),
        "stateless serving must not mint a session"
    );
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("\"resultType\":\"complete\""),
        "2026-07-28 results carry resultType; got: {body}"
    );
    assert!(
        body.contains("demo.searchTools"),
        "the meta-tool catalog serves statelessly; got: {body}"
    );

    server.shutdown().await;
}

/// The 2026 projection is a stable, authorization-filtered direct-tool set:
/// search remains callable as a compatibility surface but does not mutate a
/// later `tools/list` when catalog and authorization are unchanged.
#[tokio::test]
async fn stateless_tools_list_is_stable_before_and_after_search() {
    let tool_names = Arc::new(tokio::sync::RwLock::new(vec![
        "zeta".to_string(),
        "echo".to_string(),
        "alpha".to_string(),
    ]));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        tool_names: Some(Arc::clone(&tool_names)),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let before = stateless_response_json(
        stateless_post(&client, &url, 1, "tools/list", json!({}), "probe").await,
    )
    .await;
    assert!(
        before["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .any(|tool| tool["name"] == "demo.echo"),
        "the stable 2026 list includes admitted direct tools: {before}"
    );
    let before_names: Vec<_> = before["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        before_names,
        vec!["demo.alpha", "demo.echo", "demo.searchTools", "demo.zeta"],
        "the full projection uses canonical qualified-name order",
    );

    let search = stateless_post(
        &client,
        &url,
        2,
        "tools/call",
        json!({"name": "demo.searchTools", "arguments": {"mode": "operations"}}),
        "probe",
    )
    .await
    .text()
    .await
    .expect("body");
    assert!(
        search.contains("demo.echo"),
        "searchTools reveals the demo tool; got: {search}"
    );

    // Catalog publication treats descriptor-identical reordering as no
    // change, so the downstream array must stay byte-stable without a
    // list-changed notification.
    *tool_names.write().await = vec!["alpha".to_string(), "zeta".to_string(), "echo".to_string()];

    let after = stateless_response_json(
        stateless_post(&client, &url, 3, "tools/list", json!({}), "probe").await,
    )
    .await;
    assert_eq!(
        before["result"]["tools"], after["result"]["tools"],
        "search calls must not mutate the 2026 projection"
    );

    server.shutdown().await;
}

/// The 2026 wire pages one canonical authorized view. Continuations are
/// opaque, an empty cursor starts the same traversal, and a changed catalog
/// refuses an old cursor instead of combining generations. The legacy lane
/// remains a complete unpaginated compatibility projection.
#[tokio::test]
async fn stateless_tools_list_pages_one_catalog_view_while_legacy_stays_complete() {
    let tool_names = Arc::new(tokio::sync::RwLock::new(
        (0..75)
            .rev()
            .map(|index| format!("tool-{index:03}"))
            .collect(),
    ));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        tool_names: Some(Arc::clone(&tool_names)),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()).with_eager_tools_list(true),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let first = stateless_response_json(
        stateless_post(&client, &url, 1, "tools/list", json!({}), "probe").await,
    )
    .await;
    let first_tools = first["result"]["tools"]
        .as_array()
        .expect("first tools page");
    let cursor = first["result"]["nextCursor"]
        .as_str()
        .expect("large catalog has a continuation")
        .to_owned();
    assert!(first_tools.len() < 76, "the first response must be bounded");

    let empty_cursor = stateless_response_json(
        stateless_post(
            &client,
            &url,
            2,
            "tools/list",
            json!({"cursor": ""}),
            "probe",
        )
        .await,
    )
    .await;
    assert_eq!(
        empty_cursor["result"]["tools"], first["result"]["tools"],
        "an explicitly empty cursor is a valid first-page cursor",
    );

    let second = stateless_response_json(
        stateless_post(
            &client,
            &url,
            3,
            "tools/list",
            json!({"cursor": cursor}),
            "probe",
        )
        .await,
    )
    .await;
    let all_names: Vec<_> = first_tools
        .iter()
        .chain(
            second["result"]["tools"]
                .as_array()
                .expect("second tools page"),
        )
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    let mut expected = vec!["demo.searchTools".to_owned()];
    expected.extend((0..75).map(|index| format!("demo.tool-{index:03}")));
    expected.sort_unstable();
    assert_eq!(
        all_names, expected,
        "page traversal is complete and canonical"
    );
    assert!(
        second["result"].get("nextCursor").is_none() || second["result"]["nextCursor"].is_null(),
        "the final page omits its continuation",
    );

    tool_names.write().await[74] = "tool-changed".to_owned();
    let stale = stateless_response_json(
        stateless_post(
            &client,
            &url,
            4,
            "tools/list",
            json!({"cursor": first["result"]["nextCursor"]}),
            "probe",
        )
        .await,
    )
    .await;
    assert_eq!(
        stale["error"]["code"], -32602,
        "a changed catalog invalidates its old continuation",
    );

    let malformed = stateless_response_json(
        stateless_post(
            &client,
            &url,
            5,
            "tools/list",
            json!({"cursor": "resource-list:cursor"}),
            "probe",
        )
        .await,
    )
    .await;
    assert_eq!(malformed["error"]["code"], -32602);

    let session_id = raw_initialize_session(&client, &url).await;
    let legacy_body = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-session-id", &session_id)
        .json(&json!({"jsonrpc": "2.0", "id": 6, "method": "tools/list"}))
        .send()
        .await
        .expect("POST legacy tools/list")
        .text()
        .await
        .expect("legacy response body");
    let legacy_payload = legacy_body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .find(|payload| payload.starts_with('{'))
        .expect("legacy SSE carries a JSON-RPC data event");
    let legacy: Value = serde_json::from_str(legacy_payload).expect("legacy JSON-RPC response");
    assert_eq!(
        legacy["result"]["tools"]
            .as_array()
            .expect("legacy tools")
            .len(),
        76,
        "legacy eager listing stays complete",
    );
    assert!(
        legacy["result"].get("nextCursor").is_none() || legacy["result"]["nextCursor"].is_null(),
        "legacy listing does not issue a cursor",
    );

    server.shutdown().await;
}

/// An upstream may validly publish a tool named `searchTools`. On the 2026
/// direct-tool lane it takes precedence over the gateway's closed-draft
/// adapter, so the catalog has one faithful declaration and dispatch enters
/// the ordinary governed upstream pipeline. Legacy precedence is unchanged.
#[tokio::test]
async fn stateless_upstream_search_tools_name_takes_direct_tool_precedence() {
    let tool_names = Arc::new(tokio::sync::RwLock::new(vec![
        "echo".to_string(),
        "searchTools".to_string(),
    ]));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        tool_names: Some(tool_names),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let listed = stateless_response_json(
        stateless_post(&client, &url, 1, "tools/list", json!({}), "probe").await,
    )
    .await;
    let collision: Vec<_> = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter(|tool| tool["name"] == "demo.searchTools")
        .collect();
    assert_eq!(collision.len(), 1, "the qualified name is declared once");
    assert_eq!(
        collision[0]["description"], "demo tool",
        "the declaration belongs to the ordinary upstream tool",
    );

    let called = stateless_response_json(
        stateless_post(
            &client,
            &url,
            2,
            "tools/call",
            json!({"name": "demo.searchTools", "arguments": {}}),
            "probe",
        )
        .await,
    )
    .await;
    assert!(
        called.to_string().contains("called demo.searchTools"),
        "the collision must dispatch through the upstream pipeline: {called}",
    );

    server.shutdown().await;
}

/// A collision that cannot enter the caller's direct projection must not
/// shadow the adapter or disclose its raw-catalog existence through a
/// different call result. This malformed-schema case pins the same predicate
/// used for profile, Cedar, and runtime-admission withholding.
#[tokio::test]
async fn stateless_withheld_search_tools_collision_keeps_adapter_visible_and_callable() {
    let tool_names = Arc::new(tokio::sync::RwLock::new(vec![
        "echo".to_string(),
        "searchTools".to_string(),
    ]));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        tool_names: Some(tool_names),
        non_publishable_tool_names: vec!["searchTools".to_string()],
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let listed = stateless_response_json(
        stateless_post(&client, &url, 1, "tools/list", json!({}), "probe").await,
    )
    .await;
    let collision: Vec<_> = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter(|tool| tool["name"] == "demo.searchTools")
        .collect();
    assert_eq!(collision.len(), 1, "the qualified name is declared once");
    assert_ne!(
        collision[0]["description"], "demo tool",
        "the withheld direct declaration cannot displace the adapter",
    );

    let called = stateless_response_json(
        stateless_post(
            &client,
            &url,
            2,
            "tools/call",
            json!({
                "name": "demo.searchTools",
                "arguments": {"mode": "operations"}
            }),
            "probe",
        )
        .await,
    )
    .await;
    let body = called.to_string();
    assert!(
        body.contains("demo.echo") && !body.contains("called demo.searchTools"),
        "the visible adapter must handle the collision without exposing the withheld tool: {called}",
    );

    server.shutdown().await;
}

/// The legacy client-name fallback cannot alter the 2026 projection: both a
/// matching and non-matching name receive the same full authorized set.
#[tokio::test]
async fn stateless_tools_list_ignores_legacy_eager_client_allowlist() {
    let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_eager_tools_clients(vec!["eager-probe".to_string()])
        },
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let matched = stateless_response_json(
        stateless_post(&client, &url, 1, "tools/list", json!({}), "eager-probe").await,
    )
    .await;
    assert!(
        matched["result"]["tools"]
            .as_array()
            .expect("matching tools array")
            .iter()
            .any(|tool| tool["name"] == "demo.echo"),
        "a matching 2026 client gets the full catalog; got: {matched}"
    );

    let unmatched = stateless_response_json(
        stateless_post(&client, &url, 2, "tools/list", json!({}), "other-client").await,
    )
    .await;
    assert!(
        unmatched["result"]["tools"]
            .as_array()
            .expect("non-matching tools array")
            .iter()
            .any(|tool| tool["name"] == "demo.echo"),
        "a non-matching 2026 client gets the same full catalog; got: {unmatched}"
    );
    assert_eq!(
        matched["result"]["tools"], unmatched["result"]["tools"],
        "client name cannot change the 2026 list"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn stateless_codemode_only_client_gets_compact_catalog_and_guidance() {
    let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
    let server = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_builtin_tools(Arc::new(CodeModeTaskStub))
                .with_codemode_only_tools_clients(vec!["cursor".to_string()])
        },
        Some(wire_principal()),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let matched = stateless_response_json(
        stateless_post(&client, &url, 1, "tools/list", json!({}), "Cursor").await,
    )
    .await;
    let matched_tools = matched["result"]["tools"]
        .as_array()
        .expect("matching tools array");
    assert!(matched_tools
        .iter()
        .any(|tool| tool["name"] == "codemode.execute"));
    assert!(
        !matched_tools.iter().any(|tool| {
            tool["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("demo."))
        }),
        "matching stateless client must receive only gateway built-ins: {matched}"
    );

    let discover = stateless_response_json(
        stateless_post(&client, &url, 2, "server/discover", json!({}), "Cursor").await,
    )
    .await;
    assert!(
        discover.to_string().contains("codemode.search"),
        "compact discovery guidance must direct the client to Code Mode: {discover}"
    );

    let unmatched = stateless_response_json(
        stateless_post(&client, &url, 3, "tools/list", json!({}), "other-client").await,
    )
    .await;
    let unmatched_tools = unmatched["result"]["tools"]
        .as_array()
        .expect("non-matching tools array");
    assert!(
        unmatched_tools
            .iter()
            .any(|tool| tool["name"] == "demo.echo"),
        "non-matching stateless client must keep the stable full catalog: {unmatched}"
    );
    assert!(unmatched_tools
        .iter()
        .any(|tool| tool["name"] == "demo.searchTools"));

    server.shutdown().await;
}

/// Stateless requests spawn no per-session machinery: the server-initiated
/// ping loop is keyed to `notifications/initialized`, which the stateless
/// path never sends.
#[tokio::test]
async fn stateless_requests_spawn_no_ping_loop() {
    let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
    let stats = Arc::new(waygate_mcp::PingStats::default());
    let stats_for_server = stats.clone();
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_client_ping_interval(Some(std::time::Duration::from_millis(50)))
                .with_ping_stats(stats_for_server.clone())
        },
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    for id in 1..=3 {
        let _ = stateless_post(&client, &url, id, "tools/list", json!({}), "probe").await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        stats.sent(),
        0,
        "a stateless burst must not start the session ping loop"
    );

    server.shutdown().await;
}

/// SEP-2243 routing-header integrity, SDK-enforced: a header/body mismatch
/// is rejected with `HeaderMismatch` (`-32020`) before any dispatch — no
/// session minted, no tool executed — for both the method header and the
/// tool-name header.
#[tokio::test]
async fn mismatched_routing_headers_are_rejected_with_header_mismatch() {
    let list_tools_calls = Arc::new(AtomicUsize::new(0));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        list_tools_calls: Some(Arc::clone(&list_tools_calls)),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    // Mcp-Method disagrees with the body method. The body is a
    // `tools/call` of `demo.searchTools`; the response must come from header
    // validation rather than tool dispatch.
    let resp = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        // A CORRECT name header for the body's tool, so the method/body
        // mismatch is the only violation — without it the -32020 could
        // come from the independent missing-Mcp-Name check and this test
        // would not uniquely pin method-header integrity.
        .header("mcp-name", "demo.searchTools")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "demo.searchTools",
                "arguments": {"mode": "operations"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("POST mismatched method header");
    assert!(resp.headers().get("mcp-session-id").is_none());
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("-32020"),
        "method-header mismatch must be HeaderMismatch; got: {body}"
    );

    // Mcp-Name disagrees with the called tool.
    let resp = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "demo.other")
        .json(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "demo.searchTools",
                "arguments": {"mode": "operations"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("POST mismatched name header");
    assert!(
        resp.headers().get("mcp-session-id").is_none(),
        "a rejected name-mismatch must not mint a session"
    );
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("-32020"),
        "name-header mismatch must be HeaderMismatch; got: {body}"
    );
    assert_eq!(
        list_tools_calls.load(Ordering::SeqCst),
        0,
        "routing-header mismatches must be rejected before searchTools reads the catalog",
    );

    server.shutdown().await;
}

/// SEP-2549 cache hints: gateway-owned list results carry the
/// do-not-cache/private hints for 2026-07-28 peers, and the legacy session
/// wire carries neither field.
#[tokio::test]
async fn cache_hints_are_stamped_for_stateless_and_absent_for_legacy() {
    let server = spawn_gateway_with_allowed_hosts(vec![ALLOWED_HOST.into()]).await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let stateless = stateless_post(&client, &url, 1, "tools/list", json!({}), "probe")
        .await
        .text()
        .await
        .expect("body");
    assert!(
        stateless.contains("\"ttlMs\":0") && stateless.contains("\"cacheScope\":\"private\""),
        "stateless list results carry do-not-cache/private hints; got: {stateless}"
    );

    // resources/list and a hint-less resources/read get the same stamps.
    let resources = stateless_post(&client, &url, 2, "resources/list", json!({}), "probe")
        .await
        .text()
        .await
        .expect("body");
    assert!(
        resources.contains("\"ttlMs\":0") && resources.contains("\"cacheScope\":\"private\""),
        "stateless resources/list carries do-not-cache/private; got: {resources}"
    );
    let read = stateless_post(
        &client,
        &url,
        3,
        "resources/read",
        json!({"uri": "demo://guide"}),
        "probe",
    )
    .await
    .text()
    .await
    .expect("body");
    assert!(
        read.contains("\"ttlMs\":0") && read.contains("\"cacheScope\":\"private\""),
        "a hint-less stateless resources/read carries do-not-cache/private; got: {read}"
    );

    let session_id = raw_initialize_session(&client, &url).await;
    let legacy = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-session-id", &session_id)
        .json(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}))
        .send()
        .await
        .expect("POST legacy tools/list")
        .text()
        .await
        .expect("body");
    assert!(
        !legacy.contains("ttlMs") && !legacy.contains("cacheScope"),
        "the legacy wire must not grow the cache-hint fields; got: {legacy}"
    );

    server.shutdown().await;
}

/// The security contract of the read pass-through: an upstream freshness
/// hint survives, but an upstream-declared `public` scope NEVER does — the
/// body was resolved under the current principal's authorization, so a
/// shared cache must not serve it across principals.
#[tokio::test]
async fn upstream_public_cache_scope_is_overridden_to_private() {
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        resource_upstream_ttl: Some(5000),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let read = stateless_post(
        &client,
        &url,
        1,
        "resources/read",
        json!({"uri": "demo://guide"}),
        "probe",
    )
    .await
    .text()
    .await
    .expect("body");
    assert!(
        read.contains("\"ttlMs\":5000"),
        "the upstream freshness hint must pass through; got: {read}"
    );
    assert!(
        read.contains("\"cacheScope\":\"private\"") && !read.contains("public"),
        "an upstream public scope must be overridden to private; got: {read}"
    );

    server.shutdown().await;
}

#[derive(Default)]
struct NativeResourceProcessor {
    prepares: AtomicUsize,
}

#[async_trait]
impl waygate_mcp::files::FileOutputProcessor for NativeResourceProcessor {
    fn native_https_available(&self) -> bool {
        true
    }

    async fn prepare(
        &self,
        _context: waygate_mcp::files::FileOutputContext,
        _result: CallToolResult,
    ) -> Result<waygate_mcp::files::PreparedFileOutput, McpError> {
        unreachable!("this wire test reads a resource, not a tool")
    }

    async fn prepare_resource(
        &self,
        _context: waygate_mcp::files::FileOutputContext,
        result: rmcp::model::ReadResourceResult,
    ) -> Result<waygate_mcp::files::PreparedResourceOutput, McpError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        Ok(waygate_mcp::files::PreparedResourceOutput {
            result,
            batch_id: None,
            file_count: 0,
        })
    }

    async fn publish(&self, _batch_id: &str, _file_count: usize) -> Result<(), McpError> {
        Ok(())
    }

    async fn discard(&self, _batch_id: &str) {}
}

/// rmcp removes wire `params._meta` from the typed request and carries it on
/// `RequestContext`. Exercise that exact transport boundary: an authenticated
/// caller's request-local download declaration must enable the governed path
/// and be re-emitted to the selected upstream request.
#[tokio::test]
async fn request_context_file_capability_enables_governed_resource_download() {
    let observed = Arc::new(tokio::sync::Mutex::new(None));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        resource_request_meta: Some(observed.clone()),
        ..DemoCatalog::default()
    });
    let processor = Arc::new(NativeResourceProcessor::default());
    let shared_processor: waygate_mcp::files::SharedFileOutputProcessor = processor.clone();
    let principal = Principal {
        sub: "wire-resource-reader".to_owned(),
        email: None,
        groups: Vec::new(),
        issuer: "gateway-test".to_owned(),
        scopes: Vec::new(),
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: Vec::new(),
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    };
    let server = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_file_output_processor(Some(shared_processor.clone()))
        },
        Some(principal),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let files = waygate_mcp::files::stateless_client_file_capability(
        waygate_mcp::files::FileOperation::Download,
    );
    let response = reqwest::Client::new()
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "resources/read")
        .header("mcp-name", "demo://guide")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {
                "uri": "demo://guide",
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {"files": files},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "governed-resource-test",
                        "version": "0.0.0"
                    }
                }
            }
        }))
        .send()
        .await
        .expect("send stateless resource read");
    let status = response.status();
    let body = response.text().await.expect("read resource response");
    assert!(status.is_success(), "resource read failed: {status} {body}");
    assert_eq!(
        processor.prepares.load(Ordering::SeqCst),
        1,
        "request-context capability must select governed file processing",
    );
    let forwarded = observed
        .lock()
        .await
        .clone()
        .expect("upstream received request metadata");
    let forwarded = &forwarded.0 .0;
    assert_eq!(
        forwarded
            .get(waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY)
            .and_then(|capabilities| {
                capabilities.get(waygate_mcp::files::FILES_CAPABILITY_MEMBER)
            }),
        Some(&waygate_mcp::files::stateless_client_file_capability(
            waygate_mcp::files::FileOperation::Download,
        )),
        "the gateway must forward only the capability it can honor",
    );
    server.shutdown().await;
}

/// Catalog whose one tool pauses with an elicitation `input_required`
/// on the first round and completes echoing the retry payload — the
/// full-stack MRTR wire fixture.
#[derive(Default)]
struct PausingCatalog;

#[async_trait]
impl UpstreamCatalog for PausingCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["demo".into()]
    }

    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        let schema = json!({"type": "object", "properties": {}})
            .as_object()
            .cloned()
            .unwrap();
        Ok(vec![Tool::new(
            "confirm".to_string(),
            "pauses for confirmation".to_string(),
            Arc::new(schema),
        )])
    }

    async fn call_tool(
        &self,
        _server: &str,
        _tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        unreachable!("the pipeline dispatches through call_tool_response")
    }

    async fn call_tool_response(
        &self,
        _server: &str,
        _tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        mrtr: waygate_mcp::catalog::ToolCallMrtr,
    ) -> Result<rmcp::model::CallToolResponse, McpError> {
        if let Some(responses) = mrtr.input_responses {
            let echoed = json!({
                "responses": responses,
                "request_state": mrtr.request_state,
            });
            return Ok(CallToolResult::success(vec![Content::text(echoed.to_string())]).into());
        }
        let elicit = rmcp::model::ElicitRequest::new(
            rmcp::model::ElicitRequestParams::FormElicitationParams {
                meta: None,
                message: "confirm the operation".to_owned(),
                requested_schema: rmcp::model::ElicitationSchema::builder()
                    .required_string("choice")
                    .build_unchecked(),
            },
        );
        let mut requests = rmcp::model::InputRequests::new();
        requests.insert(
            "q1".to_owned(),
            rmcp::model::InputRequest::Elicitation(elicit),
        );
        Ok(rmcp::model::CallToolResponse::InputRequired(
            rmcp::model::InputRequiredResult::new(Some(requests), Some("wire-state-9".to_owned())),
        ))
    }

    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool_name.into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
}

/// The full MRTR wire round trip through the gateway itself: a 2026
/// stateless client that declared elicitation receives the pause verbatim
/// over real streamable HTTP and completes the call by retrying with
/// `inputResponses` + the echoed `requestState`.
#[tokio::test]
async fn mrtr_pause_and_retry_round_trip_over_the_wire() {
    let session_ct = CancellationToken::new();
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || GatewayServer::new(Arc::new(PausingCatalog)),
    )
    .await;

    let uri: Arc<str> = Arc::from(format!("http://{}/mcp", server.addr));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    let client = ClientInfo::new(
        ClientCapabilities::builder().enable_elicitation().build(),
        Implementation::new("mrtr-client", "test"),
    )
    .serve_with_lifecycle(
        transport,
        rmcp::service::ClientLifecycleMode::Discover {
            preferred_versions: vec![rmcp::model::ProtocolVersion::V_2026_07_28],
        },
    )
    .await
    .expect("discover-negotiate against the in-process gateway");

    let pause = match client
        .call_tool_once(CallToolRequestParams::new("demo.confirm"))
        .await
        .expect("first round returns a result")
    {
        rmcp::model::CallToolResponse::InputRequired(pause) => pause,
        other => panic!("expected the pause on the wire, got {other:?}"),
    };
    assert_eq!(pause.request_state.as_deref(), Some("wire-state-9"));
    assert!(pause
        .input_requests
        .as_ref()
        .is_some_and(|r| r.contains_key("q1")));

    let mut responses = rmcp::model::InputResponses::new();
    responses.insert("q1".to_owned(), json!({"choice": "yes"}));
    let completed = match client
        .call_tool_once(
            CallToolRequestParams::new("demo.confirm")
                .with_input_responses(responses)
                .with_request_state("wire-state-9"),
        )
        .await
        .expect("retry completes")
    {
        rmcp::model::CallToolResponse::Complete(result) => result,
        other => panic!("expected completion, got {other:?}"),
    };
    let text = serde_json::to_value(&completed).unwrap().to_string();
    assert!(
        text.contains("wire-state-9") && text.contains("choice"),
        "the retry payload must reach the dispatch verbatim: {text}",
    );

    let _ = client.cancel().await;
    server.shutdown().await;
}

/// A legacy-handshake client calling the same pausing tool gets the
/// fail-closed structured error — never a pause its generation cannot
/// receive.
#[tokio::test]
async fn legacy_client_gets_a_structured_error_instead_of_a_pause() {
    let session_ct = CancellationToken::new();
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || GatewayServer::new(Arc::new(PausingCatalog)),
    )
    .await;

    let client = connect_named_client(server.addr, "legacy-client").await;
    let err = client
        .call_tool(CallToolRequestParams::new("demo.confirm"))
        .await
        .expect_err("a pause must fail closed for a legacy session");
    let text = err.to_string();
    assert!(
        text.contains("cannot receive an input_required result"),
        "teach-through error expected, got: {text}",
    );

    let _ = client.cancel().await;
    server.shutdown().await;
}

/// Fake task-capable built-in for the `tasks/update` wire tests: two known
/// task ids, one pausing on an execute-governed continuation and one on a
/// mutate-governed continuation, recording every delivered update.
type RecordedUpdate = (String, Vec<String>);

#[derive(Clone, Default)]
struct TaskBuiltin {
    updates: Arc<std::sync::Mutex<Vec<RecordedUpdate>>>,
}

const TASK_RESUME: &str = "11111111-1111-1111-1111-111111111111";
const TASK_MUTATE: &str = "22222222-2222-2222-2222-222222222222";

#[async_trait]
impl waygate_mcp::builtin::BuiltinTools for TaskBuiltin {
    fn namespace(&self) -> &str {
        "gateway-tasktest"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        let definition = |name: &str| {
            Tool::new(
                format!("gateway-tasktest.{name}"),
                name.to_owned(),
                Arc::new(json!({"type": "object"}).as_object().unwrap().clone()),
            )
        };
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![
                definition("execute"),
                definition("mutate"),
                definition("cancel"),
            ],
        )
    }

    async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
        Vec::new()
    }

    async fn call(
        &self,
        _tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        Err(McpError::invalid_params("unknown tool", None))
    }

    fn governance_tool<'a>(&self, tool: &'a str) -> &'a str {
        match tool {
            "resume" => "execute",
            "resume_mutation" => "mutate",
            other => other,
        }
    }

    fn supports_tasks(&self) -> bool {
        true
    }

    fn task_tool(&self) -> Option<&str> {
        Some("execute")
    }

    fn cancel_task_tool(&self) -> Option<&str> {
        Some("cancel")
    }

    async fn cancel_task(
        &self,
        task_id: &str,
        _principal: Option<&Principal>,
    ) -> Result<Option<rmcp::model::Task>, McpError> {
        if !matches!(task_id, TASK_RESUME | TASK_MUTATE) {
            return Ok(None);
        }
        Ok(Some(rmcp::model::Task::new(
            task_id,
            rmcp::model::TaskStatus::Cancelled,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        )))
    }

    async fn update_task_continuation(
        &self,
        task_id: &str,
        _principal: Option<&Principal>,
    ) -> Result<Option<&'static str>, McpError> {
        Ok(match task_id {
            TASK_RESUME => Some("resume"),
            TASK_MUTATE => Some("resume_mutation"),
            _ => None,
        })
    }

    async fn update_task(
        &self,
        task_id: &str,
        input_responses: rmcp::model::InputResponses,
        _principal: Option<&Principal>,
    ) -> Result<(), McpError> {
        self.updates.lock().unwrap().push((
            task_id.to_owned(),
            input_responses.keys().cloned().collect(),
        ));
        Ok(())
    }

    fn describe(&self) -> waygate_mcp::builtin::BuiltinSurfaceDescriptor {
        waygate_mcp::builtin::BuiltinSurfaceDescriptor {
            namespace: "gateway-tasktest".to_owned(),
            required_scope: "mcp:invoke".to_owned(),
            summary: "task update wire fixture".to_owned(),
            tools: vec![
                waygate_mcp::builtin::BuiltinToolDescriptor {
                    name: "execute".to_owned(),
                    description: "execute".to_owned(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                },
                waygate_mcp::builtin::BuiltinToolDescriptor {
                    name: "mutate".to_owned(),
                    description: "mutate".to_owned(),
                    risk: RiskTier::High,
                    side_effects: true,
                    pii: false,
                },
                waygate_mcp::builtin::BuiltinToolDescriptor {
                    name: "cancel".to_owned(),
                    description: "cancel".to_owned(),
                    risk: RiskTier::Medium,
                    side_effects: true,
                    pii: false,
                },
            ],
        }
    }
}

/// Records which governance tool the built-in Cedar overlay was consulted
/// for; always proceeds.
#[derive(Default)]
struct RecordingGate {
    builtin_tools: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl waygate_mcp::authz::AuthzGate for RecordingGate {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }

    async fn authorize_tool_call(
        &self,
        _facts: &waygate_core::Facts,
    ) -> waygate_mcp::authz::AuthzVerdict {
        waygate_mcp::authz::AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }

    async fn authorize_builtin_call(
        &self,
        _principal: &Principal,
        facts: &ToolFacts,
    ) -> waygate_mcp::authz::BuiltinAuthz {
        self.builtin_tools.lock().unwrap().push(facts.name.clone());
        waygate_mcp::authz::BuiltinAuthz::Proceed
    }
}

fn wire_principal() -> Principal {
    Principal {
        sub: "task-caller@example.com".to_owned(),
        email: None,
        groups: vec![],
        issuer: "test".to_owned(),
        scopes: vec!["mcp:invoke".to_owned()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

/// `tasks/update` routes through the BuiltinTools seam with the Cedar
/// overlay applied for the SELECTED continuation's governance tool — a
/// mutate-governed continuation is consulted as `mutate`, an
/// execute-governed one as `execute` — and an unknown task id is
/// not-found.
#[tokio::test]
async fn tasks_update_routes_with_the_selected_continuations_governance() {
    let builtin = Arc::new(TaskBuiltin::default());
    let gate = Arc::new(RecordingGate::default());
    let session_ct = CancellationToken::new();
    let builtin_for_server = Arc::clone(&builtin);
    let gate_for_server = Arc::clone(&gate);
    let mcp_service =
        StreamableHttpService::new(
            move || {
                Ok(GatewayServer::with_authz(
                    Arc::new(DemoCatalog::default()),
                    gate_for_server.clone(),
                )
                .with_builtin_tools(builtin_for_server.clone()))
            },
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default()
                .with_cancellation_token(session_ct.child_token())
                .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        );
    // The bearer layer's job in production: stamp the authenticated
    // Principal into the request extensions the MCP context reads.
    let app: Router<()> =
        Router::new()
            .nest_service("/mcp", mcp_service)
            .layer(axum::middleware::from_fn(
                |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                    req.extensions_mut().insert(wire_principal());
                    next.run(req).await
                },
            ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = CancellationToken::new();
    let shutdown_for_serve = shutdown.clone();
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown_for_serve.cancelled().await })
            .await;
    });

    let uri: Arc<str> = Arc::from(format!("http://{addr}/mcp"));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    let client = ClientInfo::new(
        ClientCapabilities::builder().enable_tasks().build(),
        Implementation::new("tasks-client", "test"),
    )
    .serve(transport)
    .await
    .expect("initialize against in-process gateway");

    let mut responses = rmcp::model::InputResponses::new();
    responses.insert("resume_mutation".to_owned(), json!(true));
    client
        .update_task(rmcp::model::UpdateTaskParams::new(TASK_MUTATE, responses))
        .await
        .expect("mutation continuation update is acknowledged");

    let mut responses = rmcp::model::InputResponses::new();
    responses.insert("resume".to_owned(), json!({"value": 1}));
    client
        .update_task(rmcp::model::UpdateTaskParams::new(TASK_RESUME, responses))
        .await
        .expect("resume continuation update is acknowledged");

    client
        .cancel_task(rmcp::model::CancelTaskParams::new(TASK_RESUME))
        .await
        .expect("task cancellation is acknowledged");

    client
        .update_task(rmcp::model::UpdateTaskParams::new(
            "33333333-3333-3333-3333-333333333333",
            rmcp::model::InputResponses::new(),
        ))
        .await
        .expect_err("an unknown task id is not-found");

    assert_eq!(
        gate.builtin_tools.lock().unwrap().clone(),
        vec![
            "mutate".to_owned(),
            "execute".to_owned(),
            "cancel".to_owned(),
        ],
        "the overlay must be consulted for the SELECTED continuation's governance",
    );
    let updates = builtin.updates.lock().unwrap().clone();
    assert_eq!(
        updates,
        vec![
            (TASK_MUTATE.to_owned(), vec!["resume_mutation".to_owned()]),
            (TASK_RESUME.to_owned(), vec!["resume".to_owned()]),
        ],
    );

    let _ = client.cancel().await;
    shutdown.cancel();
    let _ = join.await;
}

/// Search leaves the stable projection quiet; publications wake the requested
/// tool and, when skills are configured, prompt categories.
#[tokio::test]
async fn subscriptions_listen_wakes_only_on_catalog_changes() {
    for skills_enabled in [false, true] {
        check_catalog_subscription(skills_enabled).await;
    }
}

async fn check_catalog_subscription(skills_enabled: bool) {
    let epoch = ToolCatalogEpoch::new();
    let session_ct = CancellationToken::new();
    let epoch_for_server = epoch.clone();
    let mcp_service = StreamableHttpService::new(
        move || {
            let server = GatewayServer::new(Arc::new(DemoCatalog::default()))
                .with_tool_catalog_epoch(&epoch_for_server);
            Ok(if skills_enabled {
                server.with_skill_catalog(Some(Arc::new(
                    waygate_skills::ReloadableSkillCatalog::default(),
                )))
            } else {
                server
            })
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_cancellation_token(session_ct.child_token())
            .with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
    );
    let app: Router<()> =
        Router::new()
            .nest_service("/mcp", mcp_service)
            .layer(axum::middleware::from_fn(
                |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                    req.extensions_mut().insert(wire_principal());
                    next.run(req).await
                },
            ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let shutdown = CancellationToken::new();
    let shutdown_for_serve = shutdown.clone();
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown_for_serve.cancelled().await })
            .await;
    });

    let connect_2026 = |name: &'static str| {
        let uri: Arc<str> = Arc::from(format!("http://{addr}/mcp"));
        async move {
            let transport = StreamableHttpClientTransport::from_config(
                StreamableHttpClientTransportConfig::with_uri(uri),
            );
            ClientInfo::new(
                ClientCapabilities::default(),
                Implementation::new(name, "test"),
            )
            .serve_with_lifecycle(
                transport,
                rmcp::service::ClientLifecycleMode::Discover {
                    preferred_versions: vec![rmcp::model::ProtocolVersion::V_2026_07_28],
                },
            )
            .await
            .expect("discover-negotiate against in-process gateway")
        }
    };

    let subscriber = connect_2026("subscriber").await;
    let mut filter = rmcp::model::SubscriptionFilter::new();
    filter.tools_list_changed = Some(true);
    filter.prompts_list_changed = Some(true);
    let mut subscription = subscriber.listen(filter).await.expect("listen accepted");
    // The acknowledgment includes only configured notification categories.
    assert_eq!(subscription.acknowledged().tools_list_changed, Some(true));
    assert_eq!(
        subscription.acknowledged().prompts_list_changed,
        skills_enabled.then_some(true)
    );

    // A peer search call succeeds but does not mutate tools/list or notify.
    let discloser = connect_2026("discloser").await;
    let search = discloser
        .call_tool(
            CallToolRequestParams::new("demo.searchTools")
                .with_arguments(json!({"mode": "operations"}).as_object().cloned().unwrap()),
        )
        .await
        .expect("searchTools succeeds");
    assert!(!search.is_error.unwrap_or(false));
    assert!(
        tokio::time::timeout(Duration::from_millis(250), subscription.next())
            .await
            .is_err(),
        "searchTools must not wake a stable 2026 subscription",
    );

    // A real catalog publication changes the projection and wakes the stream.
    epoch.mark_changed();
    let notification = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await
        .expect("catalog change wakes the subscription")
        .expect("stream healthy")
        .expect("stream open");
    assert!(matches!(
        notification,
        rmcp::model::ServerNotification::ToolListChangedNotification(_)
    ));

    if skills_enabled {
        let notification = tokio::time::timeout(Duration::from_secs(5), subscription.next())
            .await
            .expect("prompt change wakes the subscription")
            .expect("stream healthy")
            .expect("stream open");
        assert!(matches!(
            notification,
            rmcp::model::ServerNotification::PromptListChangedNotification(_)
        ));
    }
    let _ = discloser.cancel().await;
    let _ = subscriber.cancel().await;
    shutdown.cancel();
    let _ = join.await;
}
