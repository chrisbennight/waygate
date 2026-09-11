//! `UpstreamPool::observed_tool_contracts` — the read-only surface that lets
//! an operator obtain, from the gateway itself, the per-tool behavior hashes
//! a `classification_mode: mcp_annotations` manifest must carry as
//! `approved_behavior_hash`. The contract under test: the reported hash is
//! exactly the value annotation-native admission compares against, proven by
//! flipping the live manifest to annotation mode with the observed hash (the
//! tool stays callable) and with a placeholder hash (the call is refused).

use std::collections::BTreeMap;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
    Implementation, ListToolsResult, MetaObject as Meta, PaginatedRequestParams, ProtocolVersion,
    ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::net::TcpListener;

use waygate_mcp::catalog::UpstreamCatalog;
use waygate_mcp::protocol::RiskTier;
use waygate_upstream::{
    tool_behavior_hash, ClassificationMode, ToolClassification, Transport, UpstreamManifest,
    UpstreamPool,
};

/// The wire location of the experimental action-metadata extension. Asserted
/// against the upstream crate's constant indirectly: a drift would change the
/// observed hash and fail the flip assertions below.
const ACTION_METADATA_KEY: &str = "io.modelcontextprotocol/action-metadata";

/// Build the exact tool descriptors the mock upstream serves. The test
/// computes its expectations from the same constructors, so the observed
/// hash assertions compare against the true advertised definitions.
fn annotated_tool() -> Tool {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"target": {"type": "string"}}
    })
    .as_object()
    .cloned()
    .unwrap();
    let mut tool = Tool::new(
        "stable".to_string(),
        "annotation-native tool".to_string(),
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
            ACTION_METADATA_KEY: {
                "inputMetadata": {"destination": "internal", "sensitivity": "normal"},
                "returnMetadata": {"source": "first-party", "sensitivity": "normal"},
                "outcome": "benign",
                "requiresReview": false
            }
        }))
        .expect("object"),
    ));
    tool
}

/// A tool advertising no annotations or action metadata: it still hashes
/// (drift coverage), but annotation-native admission must refuse it, which
/// the observed contract surfaces as `metadata_error`.
fn bare_tool() -> Tool {
    Tool::new(
        "bare".to_string(),
        "no security metadata".to_string(),
        serde_json::Map::new(),
    )
}

#[derive(Clone)]
struct ContractUpstream;

impl ServerHandler for ContractUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("contract-upstream", "0.0.0"))
            .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![
            annotated_tool(),
            bare_tool(),
        ]))
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        Ok(CallToolResult::success(vec![Content::text("ok")]).into())
    }
}

async fn spawn_contract_upstream() -> std::net::SocketAddr {
    let svc = StreamableHttpService::new(
        move || Ok(ContractUpstream),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app = axum::Router::new().nest_service("/mcp", svc);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

fn manifest_at(addr: std::net::SocketAddr, mode: ClassificationMode) -> UpstreamManifest {
    let tools = match mode {
        ClassificationMode::Manifest => vec![
            ToolClassification::new("stable", RiskTier::Low, false, false),
            ToolClassification::new("bare", RiskTier::Low, false, false),
        ],
        // Filled with real observed hashes by the caller.
        ClassificationMode::McpAnnotations => Vec::new(),
    };
    UpstreamManifest {
        classification_mode: mode,
        approval_mode: Default::default(),
        name: "mock".into(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some(format!("http://{addr}/mcp")),
        command: None,
        tools,
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: None,
    }
}

fn annotation_classification(name: &str, approved: &str) -> ToolClassification {
    ToolClassification {
        approved_behavior_hash: Some(approved.to_owned()),
        ..ToolClassification::new(name, RiskTier::Low, false, false)
    }
}

async fn connected_pool(addr: std::net::SocketAddr) -> UpstreamPool {
    let mut map = BTreeMap::new();
    map.insert(
        "mock".into(),
        manifest_at(addr, ClassificationMode::Manifest),
    );
    UpstreamPool::connect(map).await
}

#[tokio::test]
async fn observed_hash_is_the_value_annotation_admission_checks() {
    let addr = spawn_contract_upstream().await;
    let pool = connected_pool(addr).await;

    let observed = pool
        .observed_tool_contracts("mock")
        .await
        .expect("known server");
    assert!(observed.connected);
    let by_name: BTreeMap<&str, _> = observed
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();

    // The observed hash equals the canonical hash of the advertised
    // definition — the same function admission compares approved hashes to.
    let stable = by_name["stable"];
    assert_eq!(
        stable.behavior_hash.as_deref(),
        Some(tool_behavior_hash(&annotated_tool()).as_str()),
    );
    assert!(stable.metadata_error.is_none());

    // A tool without valid security metadata still reports its hash (for
    // drift review) plus the reason annotation admission would refuse it.
    let bare = by_name["bare"];
    assert_eq!(
        bare.behavior_hash.as_deref(),
        Some(tool_behavior_hash(&bare_tool()).as_str()),
    );
    assert!(
        bare.metadata_error.is_some(),
        "missing annotations must surface as a metadata error"
    );

    // End-to-end proof the reported hash is sufficient: flip the live
    // manifest to annotation mode carrying the OBSERVED hash — the tool
    // stays admitted and callable, no reconnect needed.
    let mut annotation = manifest_at(addr, ClassificationMode::McpAnnotations);
    annotation.tools = vec![annotation_classification(
        "stable",
        stable.behavior_hash.as_deref().unwrap(),
    )];
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".to_string(), annotation);
    pool.reload_manifests(&fresh).await;
    pool.call_tool("mock", "stable", None, None, None)
        .await
        .expect("observed hash admits the tool under annotation mode");

    // And a placeholder hash is exactly the quarantine the preview must
    // predict: same flip, wrong hash, call refused.
    let mut placeholder = manifest_at(addr, ClassificationMode::McpAnnotations);
    placeholder.tools = vec![annotation_classification("stable", &"a".repeat(64))];
    let mut fresh = BTreeMap::new();
    fresh.insert("mock".to_string(), placeholder);
    pool.reload_manifests(&fresh).await;
    pool.call_tool("mock", "stable", None, None, None)
        .await
        .expect_err("a placeholder hash must not admit the tool");
}

/// `observe_candidate_contracts` resolves the shape verdict and the
/// catalog on one entry snapshot: a same-shape candidate observes, a
/// shape-changing candidate refuses, an unknown server is `None`.
#[tokio::test]
async fn candidate_observation_distinguishes_shape_changes() {
    let addr = spawn_contract_upstream().await;
    let pool = connected_pool(addr).await;

    let same_shape = manifest_at(addr, ClassificationMode::McpAnnotations);
    match pool.observe_candidate_contracts(&same_shape).await {
        Some(waygate_upstream::CandidateObservation::Observed(observed)) => {
            assert!(observed.connected);
            assert!(!observed.tools.is_empty());
        }
        other => panic!("same-shape candidate must observe, got {other:?}"),
    }

    let mut moved = manifest_at(addr, ClassificationMode::McpAnnotations);
    moved.url = Some("http://127.0.0.1:9/mcp".into());
    assert!(matches!(
        pool.observe_candidate_contracts(&moved).await,
        Some(waygate_upstream::CandidateObservation::ShapeChanged)
    ));

    let mut unknown = manifest_at(addr, ClassificationMode::McpAnnotations);
    unknown.name = "nope".into();
    assert!(pool.observe_candidate_contracts(&unknown).await.is_none());
}

#[tokio::test]
async fn unknown_server_is_none_and_disconnected_is_unobservable() {
    let mut map = BTreeMap::new();
    map.insert(
        "mock".into(),
        manifest_at(
            "127.0.0.1:9".parse().expect("addr"),
            ClassificationMode::Manifest,
        ),
    );
    let pool = UpstreamPool::from_manifests_disconnected(map);

    assert!(pool.observed_tool_contracts("nope").await.is_none());

    let observed = pool
        .observed_tool_contracts("mock")
        .await
        .expect("known server");
    assert!(!observed.connected, "no lane holds a connection");
    assert!(
        observed.tools.is_empty(),
        "an unobservable catalog reports no tools rather than an empty upstream"
    );
}
