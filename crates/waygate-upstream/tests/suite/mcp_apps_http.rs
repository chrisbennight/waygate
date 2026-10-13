//! MCP Apps (`io.modelcontextprotocol/ui`) content through the gateway.
//!
//! An Apps upstream names a `ui://` resource in a tool's `_meta`, serves that
//! resource as HTML with its own `_meta`, and may annotate results. A client
//! renders the app only if all three reach it unchanged, so this suite drives
//! a real streamable-HTTP upstream through the gateway's ordinary governed
//! `tools/list`, `resources/read` and `tools/call` paths.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{middleware, Router};
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use waygate_mcp::{AllowAllGate, DefaultInvocationService, GatewayServer, NullSink};
use waygate_oidc::{AuthMethod, Principal};
use waygate_upstream::{UpstreamManifest, UpstreamPool};

const APP_URI: &str = "ui://demo-apps/chart";
const APP_MIME: &str = "text/html;profile=mcp-app";
const APP_HTML: &str = "<!doctype html><html><body><canvas id=\"chart\"></canvas></body></html>";

fn tool_meta() -> Value {
    json!({"ui": {"resourceUri": APP_URI}})
}

fn resource_meta() -> Value {
    json!({"ui": {"csp": {"connectDomains": [], "resourceDomains": []}, "prefersBorder": true}})
}

fn result_meta() -> Value {
    json!({"ui": {"resourceUri": APP_URI}})
}

#[derive(Clone)]
struct AppsUpstream;

impl ServerHandler for AppsUpstream {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("apps-upstream", "0.0.0"))
        .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tool: Tool = serde_json::from_value(json!({
            "name": "show_chart",
            "description": "Show a chart of the requested series.",
            "inputSchema": {"type": "object", "properties": {}},
            "_meta": tool_meta(),
        }))
        .unwrap();
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }

    async fn call_tool(
        &self,
        _: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let mut result = CallToolResult::success(vec![ContentBlock::text("Chart ready.")]);
        result.meta = Some(serde_json::from_value(result_meta()).unwrap());
        Ok(result.into())
    }

    async fn list_resources(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![Resource::new(
            APP_URI, "Chart",
        )
        .with_mime_type(APP_MIME)]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if request.uri != APP_URI {
            return Err(ErrorData::resource_not_found(request.uri, None));
        }
        Ok(
            ReadResourceResult::new(vec![ResourceContents::TextResourceContents {
                uri: APP_URI.to_owned(),
                mime_type: Some(APP_MIME.to_owned()),
                text: APP_HTML.to_owned(),
                meta: Some(serde_json::from_value(resource_meta()).unwrap()),
            }])
            .into(),
        )
    }
}

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let worker = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, worker)
}

fn principal() -> Principal {
    Principal {
        sub: "alice".into(),
        issuer: "https://test-issuer.invalid".into(),
        tenant: waygate_core::TenantId::default(),
        email: None,
        groups: vec![],
        scopes: vec!["mcp:invoke".into(), "mcp:read".into()],
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

/// Allows tools but leaves resource reads to the gate's fail-closed default.
struct ToolsOnly;
#[async_trait::async_trait]
impl waygate_mcp::AuthzGate for ToolsOnly {
    async fn may_discover_server(&self, _: &Principal, _: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _: &waygate_core::Facts) -> waygate_mcp::AuthzVerdict {
        waygate_mcp::AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }
}

async fn gateway(
    upstream_url: &str,
    authz: waygate_mcp::SharedAuthz,
) -> (String, tokio::task::JoinHandle<()>) {
    let manifest: UpstreamManifest = serde_json::from_value(json!({
        "name": "demo-apps", "transport": "http", "url": upstream_url,
        "tools": [{"name": "show_chart", "risk": "low", "side_effects": false, "pii": false}],
    }))
    .unwrap();
    let pool =
        Arc::new(UpstreamPool::connect(BTreeMap::from([("demo-apps".into(), manifest)])).await);
    let invocation = Arc::new(DefaultInvocationService::new(
        pool.clone(),
        authz.clone(),
        Arc::new(NullSink),
    ));
    let service = StreamableHttpService::new(
        move || {
            Ok(GatewayServer::with_authz(pool.clone(), authz.clone())
                .with_invocation_service(invocation.clone()))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let app = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(
            |mut request: axum::extract::Request, next: middleware::Next| async move {
                request.extensions_mut().insert(principal());
                next.run(request).await
            },
        ));
    serve(app).await
}

async fn rpc(url: &str, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"extensions": {"io.modelcontextprotocol/ui": {}}}});
    let mut request = reqwest::Client::new()
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("Mcp-Method", method)
        .header("MCP-Protocol-Version", "2026-07-28");
    if let Some(name) = params
        .get("name")
        .or_else(|| params.get("uri"))
        .and_then(Value::as_str)
    {
        request = request.header("Mcp-Name", name);
    }
    let body = request
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let body = body
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(&body);
    serde_json::from_str(body).unwrap_or_else(|_| panic!("invalid response: {body}"))
}

#[tokio::test]
async fn an_app_tool_its_ui_resource_and_its_result_metadata_reach_the_client_unchanged() {
    let upstream = StreamableHttpService::new(
        || Ok(AppsUpstream),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let (upstream_url, upstream_worker) = serve(Router::new().nest_service("/mcp", upstream)).await;
    let (gateway, gateway_worker) = gateway(&upstream_url, Arc::new(AllowAllGate)).await;

    let listed = rpc(&gateway, "tools/list", json!({})).await;
    let tool = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "demo-apps.show_chart")
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(tool["_meta"], tool_meta(), "the tool names its app");

    let read = rpc(&gateway, "resources/read", json!({"uri": APP_URI})).await;
    let contents = &read["result"]["contents"][0];
    assert_eq!(contents["uri"], APP_URI, "{read}");
    assert_eq!(contents["mimeType"], APP_MIME);
    assert_eq!(contents["text"], APP_HTML);
    assert_eq!(contents["_meta"], resource_meta());

    let called = rpc(
        &gateway,
        "tools/call",
        json!({"name": "demo-apps.show_chart", "arguments": {}}),
    )
    .await;
    assert_eq!(
        called["result"]["content"][0]["text"], "Chart ready.",
        "{called}"
    );
    assert_eq!(called["result"]["_meta"]["ui"], result_meta()["ui"]);

    gateway_worker.abort();
    upstream_worker.abort();
}

#[tokio::test]
async fn an_app_resource_is_governed_like_any_other_resource() {
    let upstream = StreamableHttpService::new(
        || Ok(AppsUpstream),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let (upstream_url, upstream_worker) = serve(Router::new().nest_service("/mcp", upstream)).await;
    let (gateway, gateway_worker) = gateway(&upstream_url, Arc::new(ToolsOnly)).await;

    let listed = rpc(&gateway, "tools/list", json!({})).await;
    assert!(
        listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "demo-apps.show_chart"),
        "{listed}"
    );
    let refused = rpc(&gateway, "resources/read", json!({"uri": APP_URI})).await;
    assert!(refused.get("error").is_some(), "{refused}");
    assert!(!refused.to_string().contains("<canvas"), "{refused}");

    gateway_worker.abort();
    upstream_worker.abort();
}
