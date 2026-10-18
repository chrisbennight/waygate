//! The request metadata an upstream receives on `resources/read`.
//!
//! Like a tool call, a resource read carries only metadata the gateway sets:
//! the SDK's own protocol keys and, for a governed download, the gateway's file
//! promise. The caller's `_meta` is not forwarded, and the gateway's private
//! response budget stays inside the gateway while still bounding the response.
//! A real streamable-HTTP upstream records what each read carried.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{middleware, Router};
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use waygate_mcp::catalog::{
    AdmittedResourceReadError, ResourceReadAdmission, UpstreamCatalog,
    RESPONSE_MATERIALIZATION_LIMIT_META_KEY,
};
use waygate_mcp::files::{CLIENT_CAPABILITIES_META_KEY, FILES_CAPABILITY_MEMBER};
use waygate_mcp::{AllowAllGate, GatewayServer};
use waygate_oidc::{AuthMethod, Principal};
use waygate_upstream::{UpstreamManifest, UpstreamPool};

const CALLER_KEY: &str = "example.test/caller";
const SMALL_URI: &str = "meta://small";
const LARGE_URI: &str = "meta://large";

type Observed = Arc<Mutex<Vec<Map<String, Value>>>>;

#[derive(Clone)]
struct RecordingUpstream {
    observed: Observed,
}

impl ServerHandler for RecordingUpstream {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("meta-recording-upstream", "0.0.0"))
        .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(Vec::new()))
    }

    async fn list_resources(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(SMALL_URI, "Small"),
            Resource::new(LARGE_URI, "Large"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.observed
            .lock()
            .unwrap()
            .push(context.meta.0 .0.clone());
        let text = match request.uri.as_str() {
            SMALL_URI => "small body".to_owned(),
            LARGE_URI => "x".repeat(4096),
            _ => return Err(ErrorData::resource_not_found(request.uri, None)),
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(text, request.uri)]).into())
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

async fn spawn_upstream() -> (String, Observed, tokio::task::JoinHandle<()>) {
    let observed = Observed::default();
    let handler = RecordingUpstream {
        observed: observed.clone(),
    };
    let upstream = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let (url, worker) = serve(Router::new().nest_service("/mcp", upstream)).await;
    (url, observed, worker)
}

async fn connect(url: &str, protocol: &str) -> Arc<UpstreamPool> {
    let manifest: UpstreamManifest = serde_json::from_value(json!({
        "name": "meta", "transport": "http", "url": url, "protocol": protocol, "tools": [],
        "resources": [{"uri_prefix": "meta://", "risk": "low"}],
    }))
    .unwrap();
    let pool = UpstreamPool::connect(BTreeMap::from([("meta".into(), manifest)])).await;
    assert!(pool.is_connected("meta").await, "the upstream must connect");
    Arc::new(pool)
}

fn last_observed(observed: &Observed) -> Map<String, Value> {
    observed
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the upstream received a resource read")
}

fn assert_no_private_or_caller_keys(meta: &Map<String, Value>) {
    assert!(
        !meta.contains_key(RESPONSE_MATERIALIZATION_LIMIT_META_KEY),
        "the gateway's response budget must stay inside the gateway: {meta:?}"
    );
    assert!(
        !meta.contains_key(CALLER_KEY),
        "a caller key must not reach the upstream: {meta:?}"
    );
}

#[tokio::test]
async fn pool_reads_send_only_the_gateway_file_promise_and_still_bound_the_response() {
    let file_promise = waygate_mcp::files::stateless_client_file_capability(
        waygate_mcp::files::FileOperation::Download,
    );
    for protocol in ["auto", "legacy"] {
        let (url, observed, worker) = spawn_upstream().await;
        let pool = connect(&url, protocol).await;
        let routing = pool.resource_routing_snapshot().await;
        let admission = ResourceReadAdmission {
            generation: routing.generation,
            server: "meta".to_owned(),
            claim: waygate_mcp::catalog::ResourceClaim {
                uri_prefix: "meta://".to_owned(),
                risk: waygate_mcp::protocol::RiskTier::Low,
            },
        };

        let mut meta = RequestMetaObject::new();
        meta.insert(
            RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
            json!(65_536),
        );
        meta.insert(
            CLIENT_CAPABILITIES_META_KEY.to_owned(),
            json!({FILES_CAPABILITY_MEMBER: file_promise}),
        );
        meta.insert(CALLER_KEY.to_owned(), json!(1));
        pool.read_resource_admitted(
            "meta",
            ReadResourceRequestParams::new(SMALL_URI).with_meta(meta),
            None,
            &admission,
        )
        .await
        .unwrap_or_else(|error| panic!("{protocol} read failed: {error:?}"));
        let forwarded = last_observed(&observed);
        assert_no_private_or_caller_keys(&forwarded);
        assert_eq!(
            forwarded
                .get(CLIENT_CAPABILITIES_META_KEY)
                .and_then(|capabilities| capabilities.get(FILES_CAPABILITY_MEMBER)),
            Some(&file_promise),
            "{protocol}: the gateway's file promise reaches the upstream: {forwarded:?}"
        );
        if protocol == "auto" {
            assert!(
                forwarded.contains_key("io.modelcontextprotocol/protocolVersion"),
                "the leg did not negotiate the stateless protocol: {forwarded:?}"
            );
        }

        let mut meta = RequestMetaObject::new();
        meta.insert(
            RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
            json!(256),
        );
        let error = pool
            .read_resource_admitted(
                "meta",
                ReadResourceRequestParams::new(LARGE_URI).with_meta(meta),
                None,
                &admission,
            )
            .await
            .expect_err("the response exceeds the gateway's budget");
        assert!(
            matches!(
                error,
                AdmittedResourceReadError::ResponseTooLarge { limit_bytes: 256 }
            ),
            "{protocol}: {error:?}"
        );
        assert_eq!(observed.lock().unwrap().len(), 2);
        assert_no_private_or_caller_keys(&last_observed(&observed));

        worker.abort();
    }
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

async fn gateway(
    pool: Arc<UpstreamPool>,
    max_bytes: usize,
) -> (String, tokio::task::JoinHandle<()>) {
    let service = StreamableHttpService::new(
        move || {
            Ok(
                GatewayServer::with_authz(pool.clone(), Arc::new(AllowAllGate))
                    .with_resource_response_max_bytes(max_bytes),
            )
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

async fn read(url: &str, uri: &str) -> Value {
    let body = reqwest::Client::new()
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("Mcp-Method", "resources/read")
        .header("Mcp-Name", uri)
        .header("MCP-Protocol-Version", "2026-07-28")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {
                "uri": uri,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "caller-client",
                        "version": "0.0.0"
                    },
                    "io.modelcontextprotocol/clientCapabilities": {},
                    CALLER_KEY: 1,
                    RESPONSE_MATERIALIZATION_LIMIT_META_KEY: 1_000_000,
                },
            },
        }))
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
async fn a_caller_read_reaches_the_upstream_with_gateway_metadata_only() {
    let (upstream_url, observed, upstream_worker) = spawn_upstream().await;
    let pool = connect(&upstream_url, "auto").await;
    let (gateway_url, gateway_worker) = gateway(pool, 1024).await;

    let small = read(&gateway_url, SMALL_URI).await;
    assert_eq!(
        small["result"]["contents"][0]["text"], "small body",
        "{small}"
    );
    let forwarded = last_observed(&observed);
    assert_no_private_or_caller_keys(&forwarded);
    let client_name = forwarded
        .get("io.modelcontextprotocol/clientInfo")
        .and_then(|info| info.get("name"))
        .and_then(Value::as_str);
    assert!(
        client_name.is_some_and(|name| name != "caller-client"),
        "the upstream sees the gateway as its client: {forwarded:?}"
    );

    let large = read(&gateway_url, LARGE_URI).await;
    assert_eq!(
        large["error"]["data"]["error"], "resource_response_too_large",
        "the gateway's bound applies, not the caller's: {large}"
    );
    assert_eq!(large["error"]["data"]["limit_bytes"], 1024);
    assert_eq!(observed.lock().unwrap().len(), 2);
    assert_no_private_or_caller_keys(&last_observed(&observed));

    gateway_worker.abort();
    upstream_worker.abort();
}
