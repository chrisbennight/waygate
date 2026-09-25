//! Opt-in, isolated PostgreSQL measurements of the real discovery HTTP path.
//! Required CI exercises correctness separately; elapsed time is diagnostic.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rmcp::model::{ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use waygate_catalog::{ImportServer, ImportTool, ManifestImporter, PgCatalogStore};
use waygate_mcp::{protocol::RiskTier, GatewayServer};
use waygate_upstream::{ToolClassification, Transport, UpstreamManifest, UpstreamPool};

#[derive(Clone)]
pub(super) struct LargeCatalog(pub(super) Arc<Vec<Tool>>);

impl ServerHandler for LargeCatalog {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.0.as_ref().clone()))
    }
}

pub(super) struct HttpFixture {
    pub(super) url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) async fn serve(handler: impl ServerHandler + Clone + 'static) -> HttpFixture {
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, axum::Router::new().nest_service("/mcp", service))
            .await
            .unwrap();
    });
    HttpFixture { url, task }
}

pub(super) struct MeasuredResponse {
    pub(super) http_status: u16,
    pub(super) result: Value,
    pub(super) error: Option<Value>,
}

pub(super) async fn request(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    mut params: Value,
) -> MeasuredResponse {
    params.as_object_mut().unwrap().insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "discovery-measurement", "version": "test"}
        }),
    );
    let mut request = client
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    if let Some(name) = params.get("name").and_then(Value::as_str) {
        request = request.header("mcp-name", name);
    }
    let response = request
        .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
        .send()
        .await
        .unwrap();
    let http_status = response.status().as_u16();
    let body = response.text().await.unwrap();
    let payload = body
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(body.trim());
    let response: Value = serde_json::from_str(payload).unwrap();
    let error = response.get("error").cloned().or_else(|| {
        (http_status >= 400 || response["result"]["isError"] == true).then(|| response.clone())
    });
    MeasuredResponse {
        http_status,
        result: response["result"].clone(),
        error,
    }
}

#[tokio::test]
#[ignore = "opt-in live PostgreSQL latency diagnostic; no timing assertion"]
async fn discovery_latency_and_database_queries() {
    let Some(setup_db) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    // All discovery-store statements acquire this dedicated pool once. Count
    // both new and reused acquisitions, excluding setup and cleanup. No other
    // task uses this pool, and it has no background database writers.
    let queries = Arc::new(AtomicUsize::new(0));
    let on_connect = queries.clone();
    let on_acquire = queries.clone();
    let db = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .test_before_acquire(false)
        .after_connect(move |_, _| {
            on_connect.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        })
        .before_acquire(move |_, _| {
            on_acquire.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(true) })
        })
        .connect(&std::env::var("AUDIT_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let counts = std::env::var("WAYGATE_DISCOVERY_BENCH_TOOLS")
        .map(|value| vec![value.parse::<usize>().expect("numeric tool count")])
        .unwrap_or_else(|_| vec![100, 1_000, 10_000]);
    let samples = std::env::var("WAYGATE_DISCOVERY_BENCH_SAMPLES")
        .map(|value| value.parse::<usize>().expect("numeric sample count"))
        .unwrap_or(3);
    assert!((1..=3).contains(&samples));
    for count in counts {
        assert!([100, 1_000, 10_000].contains(&count));
        let name = format!("scale-{}", uuid::Uuid::new_v4());
        let tools: Vec<_> = (0..count)
            .map(|i| {
                Tool::new(
                    format!("tool-{i:05}"),
                    "Representative tool",
                    json!({"type":"object"}).as_object().unwrap().clone(),
                )
            })
            .collect();
        let upstream = serve(LargeCatalog(Arc::new(tools.clone()))).await;
        let manifest = UpstreamManifest {
            name: name.clone(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some(upstream.url.clone()),
            command: None,
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            tools: tools
                .iter()
                .map(|t| ToolClassification::new(t.name.as_ref(), RiskTier::Low, false, false))
                .collect(),
            resources: vec![],
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        };
        ManifestImporter::new(setup_db.clone())
            .import_atomic(
                "default",
                &[ImportServer {
                    tenant_id: "default".into(),
                    name: name.clone(),
                    transport: "http".into(),
                    runtime_target: json!({"url":upstream.url}),
                    classification_mode: "manifest".into(),
                    tools: tools
                        .iter()
                        .map(|t| ImportTool {
                            name: t.name.to_string(),
                            approved_behavior_hash: None,
                            risk: "low".into(),
                            side_effects: false,
                            pii: false,
                            discriminator: None,
                            operations: vec![],
                        })
                        .collect(),
                }],
                false,
            )
            .await
            .unwrap();
        let store = Arc::new(PgCatalogStore::new(db.clone()));
        let pool = UpstreamPool::connect(BTreeMap::from([(name.clone(), manifest)]))
            .await
            .with_tool_reviews(store.clone())
            .await
            .with_authoritative_catalog(store);
        let gateway = serve(GatewayServer::new(Arc::new(pool)).with_eager_tools_list(true)).await;
        for sample in 0..samples {
            queries.store(0, Ordering::Relaxed);
            let start = Instant::now();
            let first = request(&client, &gateway.url, "tools/list", json!({})).await;
            println!(
                "DISCOVERY_MEASUREMENT {}",
                json!({"tools":count,"request":"first_page","sample":sample,"elapsed_ms":start.elapsed().as_secs_f64()*1000.0,"database_queries":queries.load(Ordering::Relaxed),"http_status":first.http_status,"error":first.error})
            );
            assert!(
                first.error.is_none(),
                "first-page failure: {:?}",
                first.error
            );
            let cursor = first.result["nextCursor"]
                .as_str()
                .expect("catalog needs pagination");
            queries.store(0, Ordering::Relaxed);
            let start = Instant::now();
            let second = request(
                &client,
                &gateway.url,
                "tools/list",
                json!({"cursor":cursor}),
            )
            .await;
            println!(
                "DISCOVERY_MEASUREMENT {}",
                json!({"tools":count,"request":"subsequent_page","sample":sample,"elapsed_ms":start.elapsed().as_secs_f64()*1000.0,"database_queries":queries.load(Ordering::Relaxed),"http_status":second.http_status,"error":second.error})
            );
            if second.error.is_none() {
                assert!(second.result["tools"]
                    .as_array()
                    .is_some_and(|tools| !tools.is_empty()));
            }
            queries.store(0, Ordering::Relaxed);
            let start = Instant::now();
            let search = request(&client, &gateway.url, "tools/call", json!({"name":format!("{name}.searchTools"),"arguments":{"mode":"operations","filters":{"query":"Representative"},"limit":20}})).await;
            println!(
                "DISCOVERY_MEASUREMENT {}",
                json!({"tools":count,"request":"search","sample":sample,"elapsed_ms":start.elapsed().as_secs_f64()*1000.0,"database_queries":queries.load(Ordering::Relaxed),"http_status":search.http_status,"error":search.error})
            );
        }
        drop(gateway);
        sqlx::query("DELETE FROM mcp_servers WHERE tenant_id='default' AND name=$1")
            .bind(&name)
            .execute(&setup_db)
            .await
            .unwrap();
    }
    db.close().await;
}
