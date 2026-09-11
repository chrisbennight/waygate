//! End-to-end test for the `GatewayServer` legacy compatibility surface. Drives the
//! inherent `dispatch_tool_call` / `list_meta_tools` helpers against a fake
//! upstream catalog so we don't have to stand up a real rmcp transport just
//! to assert the meta-tool shape.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock as Content, ErrorData as McpError,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, MetaObject as Meta,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult, Resource,
    ResourceContents, ResourceTemplate, Tool,
};
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

use rmcp::ServerHandler;
use waygate_mcp::audit::{AuditOutcome, InMemorySink};
use waygate_mcp::authz::ToolFacts;
use waygate_mcp::catalog::{
    AdmittedResourceReadError, ResourceClaim, ResourceReadAdmission, SharedCatalog, UpstreamCatalog,
};
use waygate_mcp::inspection::{Decision as InspectionDecision, InspectionContext, Inspector};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{
    AuthzGate, AuthzVerdict, BuiltinAuthz, BuiltinToolDescriptor, GatewayServer, SharedAuthz,
};
use waygate_oidc::{ApiKeyProfileRestrictions, AuthMethod, Principal};

type RecordedCall = (String, String, Option<Map<String, Value>>);

#[derive(Default)]
struct FakeCatalog {
    servers: Vec<(String, Vec<Tool>)>,
    resources: Vec<(String, Vec<Resource>)>,
    resource_templates: HashMap<String, Vec<ResourceTemplate>>,
    resource_claims: HashMap<String, Vec<ResourceClaim>>,
    resource_meta: HashMap<String, Meta>,
    resource_operations_unsupported: HashSet<String>,
    endless_resource_pages: bool,
    repeated_resource_cursor: bool,
    cyclic_resource_cursor: bool,
    spoof_routing_error: bool,
    resource_list_calls: AtomicUsize,
    last_call: Mutex<Option<RecordedCall>>,
    resource_read_result: Option<ReadResourceResult>,
    resource_read_error: Option<McpError>,
    bounded_unsupported_transport: Option<&'static str>,
    response_too_large_limit: Option<usize>,
    last_resource_params: Mutex<Option<ReadResourceRequestParams>>,
}

impl FakeCatalog {
    fn new(servers: Vec<(String, Vec<Tool>)>) -> Arc<Self> {
        Arc::new(Self {
            servers,
            resources: Vec::new(),
            resource_templates: HashMap::new(),
            resource_claims: HashMap::new(),
            resource_meta: HashMap::new(),
            resource_operations_unsupported: HashSet::new(),
            endless_resource_pages: false,
            repeated_resource_cursor: false,
            cyclic_resource_cursor: false,
            spoof_routing_error: false,
            resource_list_calls: AtomicUsize::new(0),
            last_call: Mutex::new(None),
            resource_read_result: None,
            resource_read_error: None,
            bounded_unsupported_transport: None,
            response_too_large_limit: None,
            last_resource_params: Mutex::new(None),
        })
    }

    fn with_resources(resources: Vec<(String, Vec<Resource>)>) -> Arc<Self> {
        Arc::new(Self {
            servers: resources
                .iter()
                .map(|(server, _)| (server.clone(), Vec::new()))
                .collect(),
            resources,
            resource_templates: HashMap::new(),
            resource_claims: HashMap::new(),
            resource_meta: HashMap::new(),
            resource_operations_unsupported: HashSet::new(),
            endless_resource_pages: false,
            repeated_resource_cursor: false,
            cyclic_resource_cursor: false,
            spoof_routing_error: false,
            resource_list_calls: AtomicUsize::new(0),
            last_call: Mutex::new(None),
            resource_read_result: None,
            resource_read_error: None,
            bounded_unsupported_transport: None,
            response_too_large_limit: None,
            last_resource_params: Mutex::new(None),
        })
    }

    fn with_resources_and_unsupported(
        resources: Vec<(String, Vec<Resource>)>,
        unsupported: impl IntoIterator<Item = String>,
    ) -> Arc<Self> {
        let mut catalog = Self::with_resources(resources);
        Arc::get_mut(&mut catalog)
            .expect("new catalog has one owner")
            .resource_operations_unsupported = unsupported.into_iter().collect();
        catalog
    }

    fn with_spoofed_routing_error(resources: Vec<(String, Vec<Resource>)>) -> Arc<Self> {
        let mut catalog = Self::with_resources(resources);
        Arc::get_mut(&mut catalog)
            .expect("new catalog has one owner")
            .spoof_routing_error = true;
        catalog
    }

    fn with_endless_resource_pages(server: &str) -> Arc<Self> {
        Arc::new(Self {
            servers: vec![(server.into(), Vec::new())],
            resources: Vec::new(),
            resource_templates: HashMap::new(),
            resource_claims: HashMap::new(),
            resource_meta: HashMap::new(),
            resource_operations_unsupported: HashSet::new(),
            endless_resource_pages: true,
            repeated_resource_cursor: false,
            cyclic_resource_cursor: false,
            spoof_routing_error: false,
            resource_list_calls: AtomicUsize::new(0),
            last_call: Mutex::new(None),
            resource_read_result: None,
            resource_read_error: None,
            bounded_unsupported_transport: None,
            response_too_large_limit: None,
            last_resource_params: Mutex::new(None),
        })
    }

    fn with_repeated_resource_cursor(server: &str) -> Arc<Self> {
        Arc::new(Self {
            servers: vec![(server.into(), Vec::new())],
            resources: Vec::new(),
            resource_templates: HashMap::new(),
            resource_claims: HashMap::new(),
            resource_meta: HashMap::new(),
            resource_operations_unsupported: HashSet::new(),
            endless_resource_pages: false,
            repeated_resource_cursor: true,
            cyclic_resource_cursor: false,
            spoof_routing_error: false,
            resource_list_calls: AtomicUsize::new(0),
            last_call: Mutex::new(None),
            resource_read_result: None,
            resource_read_error: None,
            bounded_unsupported_transport: None,
            response_too_large_limit: None,
            last_resource_params: Mutex::new(None),
        })
    }

    fn with_cyclic_resource_cursor(server: &str) -> Arc<Self> {
        Arc::new(Self {
            servers: vec![(server.into(), Vec::new())],
            resources: Vec::new(),
            resource_templates: HashMap::new(),
            resource_claims: HashMap::new(),
            resource_meta: HashMap::new(),
            resource_operations_unsupported: HashSet::new(),
            endless_resource_pages: false,
            repeated_resource_cursor: false,
            cyclic_resource_cursor: true,
            spoof_routing_error: false,
            resource_list_calls: AtomicUsize::new(0),
            last_call: Mutex::new(None),
            resource_read_result: None,
            resource_read_error: None,
            bounded_unsupported_transport: None,
            response_too_large_limit: None,
            last_resource_params: Mutex::new(None),
        })
    }

    fn with_resource_claim(server: &str, uri_prefix: &str, risk: RiskTier) -> Arc<Self> {
        let mut catalog = Self::with_resources(vec![(server.to_owned(), Vec::new())]);
        Arc::get_mut(&mut catalog)
            .expect("new catalog has one owner")
            .resource_claims
            .insert(
                server.to_owned(),
                vec![ResourceClaim {
                    uri_prefix: uri_prefix.to_owned(),
                    risk,
                }],
            );
        catalog
    }

    fn with_resource_meta(
        resources: Vec<(String, Vec<Resource>)>,
        resource_meta: HashMap<String, Meta>,
    ) -> Arc<Self> {
        let mut catalog = Self::with_resources(resources);
        Arc::get_mut(&mut catalog)
            .expect("new catalog has one owner")
            .resource_meta = resource_meta;
        catalog
    }

    fn with_resource_templates(
        templates: impl IntoIterator<Item = (String, Vec<ResourceTemplate>)>,
    ) -> Arc<Self> {
        let resource_templates: HashMap<_, _> = templates.into_iter().collect();
        Arc::new(Self {
            servers: resource_templates
                .keys()
                .cloned()
                .map(|server| (server, Vec::new()))
                .collect(),
            resource_templates,
            ..Self::default()
        })
    }
}

struct NeedleInspector {
    redact: bool,
    calls: AtomicUsize,
}

#[async_trait]
impl Inspector for NeedleInspector {
    fn name(&self) -> &'static str {
        "test_needle"
    }

    async fn inspect(
        &self,
        ctx: &InspectionContext<'_>,
        result: &CallToolResult,
    ) -> InspectionDecision {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(ctx.tool, "resources/read");
        assert!(!ctx.pii_classified);
        let matched = result
            .content
            .iter()
            .filter_map(|content| content.as_text())
            .any(|text| text.text.contains("sensitive"));
        if !matched {
            return InspectionDecision::Pass;
        }
        if !self.redact {
            return InspectionDecision::Block {
                reason: "matched test needle".to_owned(),
            };
        }
        let mut redacted = result.clone();
        for content in &mut redacted.content {
            if let rmcp::model::ContentBlock::Text(text) = content {
                text.text = text.text.replace("sensitive", "[REDACTED]");
            }
        }
        InspectionDecision::Redact {
            redacted,
            findings_count: 1,
        }
    }
}

struct MalformedRedactionInspector;

#[async_trait]
impl Inspector for MalformedRedactionInspector {
    fn name(&self) -> &'static str {
        "malformed_test"
    }

    async fn inspect(
        &self,
        _ctx: &InspectionContext<'_>,
        _result: &CallToolResult,
    ) -> InspectionDecision {
        InspectionDecision::Redact {
            redacted: CallToolResult::success(Vec::new()),
            findings_count: 1,
        }
    }
}

#[async_trait]
impl UpstreamCatalog for FakeCatalog {
    async fn list_servers(&self) -> Vec<String> {
        self.servers.iter().map(|(n, _)| n.clone()).collect()
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        self.servers
            .iter()
            .find(|(n, _)| n == server)
            .map(|(_, t)| t.clone())
            .ok_or_else(|| McpError::invalid_params(format!("unknown server {server}"), None))
    }

    fn resource_claims(&self, server: &str) -> Vec<ResourceClaim> {
        self.resource_claims
            .get(server)
            .cloned()
            .unwrap_or_default()
    }

    async fn call_tool(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        *self.last_call.lock().await = Some((server.into(), tool_name.into(), args));
        Ok(CallToolResult::success(vec![Content::text(format!(
            "called {server}.{tool_name}"
        ))]))
    }

    async fn list_resources(
        &self,
        server: &str,
        params: Option<PaginatedRequestParams>,
        _principal: Option<&Principal>,
    ) -> Result<ListResourcesResult, McpError> {
        self.resource_list_calls.fetch_add(1, Ordering::Relaxed);
        if self.resource_operations_unsupported.contains(server) {
            return Err(McpError::internal_error(
                "unsupported resource operation was dispatched",
                None,
            ));
        }
        if self.endless_resource_pages {
            let mut listed = ListResourcesResult::with_all_items(vec![Resource::new(
                "loop://page",
                "Looping page",
            )]);
            listed.next_cursor = Some(self.resource_list_calls.load(Ordering::Relaxed).to_string());
            return Ok(listed);
        }
        if self.repeated_resource_cursor {
            let mut listed = ListResourcesResult::with_all_items(vec![Resource::new(
                "repeat://page",
                "Repeating page",
            )]);
            listed.next_cursor = Some("repeat".to_owned());
            return Ok(listed);
        }
        if self.cyclic_resource_cursor {
            let current = params.and_then(|params| params.cursor);
            let next = match current.as_deref() {
                None => "cycle-a",
                Some("cycle-a") => "cycle-b",
                _ => "cycle-a",
            };
            let mut listed = ListResourcesResult::with_all_items(vec![Resource::new(
                "cycle://page",
                "Cyclic page",
            )]);
            listed.next_cursor = Some(next.to_owned());
            return Ok(listed);
        }
        self.resources
            .iter()
            .find(|(name, _)| name == server)
            .map(|(_, resources)| {
                let mut listed = ListResourcesResult::with_all_items(resources.clone());
                listed.meta = self.resource_meta.get(server).cloned();
                listed
            })
            .ok_or_else(McpError::method_not_found::<rmcp::model::ListResourcesRequestMethod>)
    }

    async fn list_resource_templates(
        &self,
        server: &str,
        _params: Option<PaginatedRequestParams>,
        _principal: Option<&Principal>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        self.resource_templates
            .get(server)
            .cloned()
            .map(ListResourceTemplatesResult::with_all_items)
            .ok_or_else(
                McpError::method_not_found::<rmcp::model::ListResourceTemplatesRequestMethod>,
            )
    }

    async fn read_resource(
        &self,
        server: &str,
        params: ReadResourceRequestParams,
        _principal: Option<&Principal>,
    ) -> Result<ReadResourceResult, McpError> {
        *self.last_resource_params.lock().await = Some(params.clone());
        if let Some(error) = self.resource_read_error.clone() {
            return Err(error);
        }
        let advertised = self
            .resources
            .iter()
            .find(|(name, _)| name == server)
            .is_some_and(|(_, resources)| {
                resources.iter().any(|resource| resource.uri == params.uri)
            })
            || self
                .resource_claims(server)
                .iter()
                .any(|claim| params.uri.starts_with(&claim.uri_prefix));
        if !advertised {
            return Err(McpError::method_not_found::<
                rmcp::model::ReadResourceRequestMethod,
            >());
        }
        if self.spoof_routing_error {
            return Err(McpError::invalid_request(
                "upstream supplied a gateway-shaped error",
                Some(json!({"error": "resource_routing_changed"})),
            ));
        }
        Ok(self.resource_read_result.clone().unwrap_or_else(|| {
            ReadResourceResult::new(vec![ResourceContents::text(
                format!("body from {server}"),
                params.uri,
            )])
        }))
    }

    async fn read_resource_admitted(
        &self,
        server: &str,
        params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        _admitted: &ResourceReadAdmission,
    ) -> Result<ReadResourceResult, AdmittedResourceReadError> {
        if let Some(transport) = self.bounded_unsupported_transport {
            return Err(AdmittedResourceReadError::BoundedUnsupported { transport });
        }
        if let Some(limit_bytes) = self.response_too_large_limit {
            return Err(AdmittedResourceReadError::ResponseTooLarge { limit_bytes });
        }
        self.read_resource(server, params, principal)
            .await
            .map_err(AdmittedResourceReadError::Upstream)
    }

    fn resource_operations_supported(&self, server: &str) -> bool {
        !self.resource_operations_unsupported.contains(server)
    }
}

struct GenerationFlipCatalog {
    index: waygate_mcp::SearchIndex,
    calls: AtomicUsize,
    before: Vec<Tool>,
    after: Vec<Tool>,
}

#[async_trait]
impl UpstreamCatalog for GenerationFlipCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-messages".to_owned()]
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        if server != "example-messages" {
            return Err(McpError::invalid_params(
                format!("unknown server {server}"),
                None,
            ));
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.index
                .replace_server("example-messages", &self.after)
                .expect("flip index generation");
            Ok(self.before.clone())
        } else {
            Ok(self.after.clone())
        }
    }

    async fn call_tool(
        &self,
        server: &str,
        tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "called {server}.{tool_name}"
        ))]))
    }
}

fn tool(name: &str, description: &str) -> Tool {
    let schema = json!({"type": "object", "properties": {}})
        .as_object()
        .cloned()
        .unwrap();
    Tool::new(name.to_string(), description.to_string(), Arc::new(schema))
}

fn tool_without_mcp_object_root(name: &str, description: &str) -> Tool {
    let schema = json!({
        "anyOf": [
            {"type": "object", "required": ["source"]},
            {"type": "object", "required": ["source_file"]}
        ]
    })
    .as_object()
    .cloned()
    .unwrap();
    Tool::new(name.to_string(), description.to_string(), Arc::new(schema))
}

fn resource(uri: &str, name: &str) -> Resource {
    Resource::new(uri.to_owned(), name.to_owned())
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

#[test]
fn server_instructions_are_concise_and_projection_specific() {
    let catalog: SharedCatalog = FakeCatalog::new(Vec::new());
    let legacy = GatewayServer::new(catalog.clone()).get_info();
    let full = GatewayServer::new(catalog)
        .with_eager_tools_list(true)
        .get_info();

    for info in [&legacy, &full] {
        assert_eq!(info.server_info.name, "mcp-tool-search-gateway");
        assert_eq!(info.server_info.title.as_deref(), Some("Waygate"));
    }

    assert_eq!(
        legacy.instructions.as_deref(),
        Some(
            "Use `<server>.searchTools` to discover tools or schemas; call results as `<server>.<toolName>`."
        ),
    );
    assert_eq!(
        full.instructions.as_deref(),
        Some("Call tools as `<server>.<toolName>`; the authorized catalog is in `tools/list`."),
    );
    for instructions in [legacy.instructions, full.instructions] {
        assert!(
            instructions.expect("server instructions").len() < 100,
            "server instructions should be concise enough to present once at namespace level",
        );
    }
}

#[tokio::test]
async fn resources_preserve_upstream_uris_and_paginate_by_server() {
    let catalog: SharedCatalog = FakeCatalog::with_resources(vec![
        (
            "printable".into(),
            vec![
                resource(
                    "printable://design/product-v1",
                    "Generic FDM product design kit",
                ),
                resource(
                    "printable://render/product-v1",
                    "Product presentation profiles",
                ),
            ],
        ),
        (
            "docs".into(),
            vec![resource("docs://operations", "Operations")],
        ),
    ]);
    let server = GatewayServer::new(catalog);
    assert!(server.get_info().capabilities.resources.is_some());

    let first = server
        .list_visible_resources(None, None)
        .await
        .expect("first resource page");
    assert_eq!(
        first
            .resources
            .iter()
            .map(|resource| resource.uri.as_str())
            .collect::<Vec<_>>(),
        vec![
            "printable://design/product-v1",
            "printable://render/product-v1"
        ]
    );
    let cursor = first.next_cursor.expect("next upstream cursor");

    let second = server
        .list_visible_resources(
            Some(PaginatedRequestParams::default().with_cursor(Some(cursor))),
            None,
        )
        .await
        .expect("second resource page");
    assert_eq!(second.resources[0].uri, "docs://operations");
    assert!(second.next_cursor.is_none());

    let read = server
        .read_visible_resource(
            ReadResourceRequestParams::new("printable://design/product-v1"),
            None,
        )
        .await
        .expect("read advertised resource");
    assert!(matches!(
        &read.contents[0],
        ResourceContents::TextResourceContents { text, uri, .. }
            if text == "body from printable" && uri == "printable://design/product-v1"
    ));
}

#[tokio::test]
async fn empty_resource_page_preserves_meta_and_advances_one_server() {
    let catalog: SharedCatalog = FakeCatalog::with_resource_meta(
        vec![
            ("empty".into(), Vec::new()),
            (
                "printable".into(),
                vec![resource("printable://design/product-v1", "Product kit")],
            ),
        ],
        HashMap::from([(
            "empty".into(),
            Meta(obj(json!({"source": "empty-upstream"}))),
        )]),
    );
    let server = GatewayServer::new(catalog);

    let first = server
        .list_visible_resources(None, None)
        .await
        .expect("empty upstream page");
    assert!(first.resources.is_empty());
    assert_eq!(
        first
            .meta
            .as_ref()
            .and_then(|meta| meta.0.get("source"))
            .and_then(Value::as_str),
        Some("empty-upstream")
    );
    assert!(first.next_cursor.is_some());
}

#[tokio::test]
async fn resource_reads_stamp_the_bound_without_erasing_caller_metadata() {
    const URI: &str = "printable://design/product-v1";
    let catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    let server = GatewayServer::new(catalog.clone()).with_resource_response_max_bytes(73);
    let mut meta = rmcp::model::RequestMetaObject::new();
    meta.insert("caller-member".into(), json!("preserved"));
    let mut params = ReadResourceRequestParams::new(URI);
    params.meta = Some(meta);

    server
        .read_visible_resource(params, None)
        .await
        .expect("bounded resource read");

    let params = catalog
        .last_resource_params
        .lock()
        .await
        .clone()
        .expect("captured read params");
    let meta = params.meta.expect("read metadata");
    assert_eq!(meta.get("caller-member"), Some(&json!("preserved")));
    assert_eq!(
        meta.get(waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY),
        Some(&json!(73)),
    );
}

#[tokio::test]
async fn native_resource_limit_errors_are_public_and_recorded_as_execution_failures() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .response_too_large_limit = Some(91);
    let sink = Arc::new(InMemorySink::new());
    let server = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    )
    .with_resource_response_max_bytes(91);

    let error = server
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect_err("oversized response must be refused");
    let data = error.data.expect("stable error data");
    assert_eq!(data["error"], "resource_response_too_large");
    assert_eq!(data["limit_bytes"], 91);
    let events = sink.snapshot().await;
    let reads: Vec<_> = events
        .iter()
        .filter(|event| event.action == "ReadResource")
        .collect();
    assert_eq!(reads.len(), 1, "one caller read produces one evidence row");
    assert_eq!(reads[0].outcome, AuditOutcome::ExecutionError);
}

#[tokio::test]
async fn upstream_cannot_spoof_a_local_response_materialization_limit() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .resource_read_error = Some(McpError::internal_error(
        "upstream supplied a gateway-shaped error",
        Some(json!({
            "error": waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_ERROR,
        })),
    ));
    let sink = Arc::new(InMemorySink::new());
    let server = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    );

    let error = server
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect_err("the fake upstream returns an application error");
    assert_eq!(
        error.data.as_ref().expect("upstream error data")["error"],
        waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_ERROR,
    );
    assert_ne!(
        error.data.as_ref().expect("upstream error data")["error"],
        "resource_response_too_large",
    );
    let events = sink.snapshot().await;
    let read = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("one final read decision");
    assert_eq!(read.outcome, AuditOutcome::ExecutionError);
}

#[tokio::test]
async fn unsupported_bounded_transport_is_denied_before_upstream_execution() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .bounded_unsupported_transport = Some("sse");
    let sink = Arc::new(InMemorySink::new());
    let server = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    );

    let error = server
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect_err("unbounded transports must be refused");
    assert_eq!(
        error.data.as_ref().expect("stable error data")["error"],
        "bounded_resource_read_unsupported",
    );
    let events = sink.snapshot().await;
    let read = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("one final read decision");
    assert_eq!(read.outcome, AuditOutcome::Denied);
}

#[tokio::test]
async fn upstream_cannot_spoof_a_local_bounded_transport_refusal() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .resource_read_error = Some(McpError::internal_error(
        "upstream supplied a gateway-shaped error",
        Some(json!({
            "error": "bounded_resource_read_unsupported",
            "transport": "sse",
        })),
    ));
    let sink = Arc::new(InMemorySink::new());
    let server = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    );

    server
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect_err("the fake upstream returns an application error");
    let events = sink.snapshot().await;
    let read = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("one final read decision");
    assert_eq!(read.outcome, AuditOutcome::ExecutionError);
}

#[tokio::test]
async fn anonymous_text_resources_are_inspected_and_blob_contents_are_opaque() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .resource_read_result = Some(ReadResourceResult::new(vec![
        ResourceContents::text("sensitive text", URI),
        ResourceContents::blob("c2Vuc2l0aXZl", URI),
    ]));
    let inspector = Arc::new(NeedleInspector {
        redact: true,
        calls: AtomicUsize::new(0),
    });
    let server = GatewayServer::new(catalog).with_resource_inspectors(vec![inspector.clone()]);

    let result = server
        .read_visible_resource(ReadResourceRequestParams::new(URI), None)
        .await
        .expect("anonymous reads still pass through response inspection");

    assert!(matches!(
        &result.contents[0],
        ResourceContents::TextResourceContents { text, .. } if text == "[REDACTED] text"
    ));
    assert!(matches!(
        &result.contents[1],
        ResourceContents::BlobResourceContents { blob, .. } if blob == "c2Vuc2l0aXZl"
    ));
    assert_eq!(inspector.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn resource_inspection_blocks_with_one_execution_error_evidence_row() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .resource_read_result = Some(ReadResourceResult::new(vec![ResourceContents::text(
        "sensitive text",
        URI,
    )]));
    let inspector = Arc::new(NeedleInspector {
        redact: false,
        calls: AtomicUsize::new(0),
    });
    let sink = Arc::new(InMemorySink::new());
    let server = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    )
    .with_resource_inspectors(vec![inspector]);

    let error = server
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect_err("inspector block must refuse the resource");
    let data = error.data.expect("stable error data");
    assert_eq!(data["error"], "response_inspection_blocked");
    assert_eq!(data["tool"], "resources/read");
    assert_eq!(data["inspector_name"], "test_needle");
    let events = sink.snapshot().await;
    let reads: Vec<_> = events
        .iter()
        .filter(|event| event.action == "ReadResource")
        .collect();
    assert_eq!(reads.len(), 1, "a blocked read still has one final row");
    assert_eq!(reads[0].outcome, AuditOutcome::ExecutionError);
    assert_eq!(reads[0].pii, None);
}

#[tokio::test]
async fn malformed_resource_redactions_fail_closed() {
    const URI: &str = "printable://design/product-v1";
    let catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    let error = GatewayServer::new(catalog)
        .with_resource_inspectors(vec![Arc::new(MalformedRedactionInspector)])
        .read_visible_resource(ReadResourceRequestParams::new(URI), None)
        .await
        .expect_err("an inspector may not change the resource projection shape");
    let data = error.data.expect("stable error data");
    assert_eq!(data["error"], "response_inspection_blocked");
    assert_eq!(data["inspector_name"], "malformed_test");
    assert_eq!(
        data["reason"],
        "inspector returned a malformed resource redaction",
    );
}

#[tokio::test]
async fn successful_resource_redaction_stays_on_the_single_final_audit_row() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .resource_read_result = Some(ReadResourceResult::new(vec![ResourceContents::text(
        "sensitive text",
        URI,
    )]));
    let sink = Arc::new(InMemorySink::new());
    let server = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    )
    .with_resource_inspectors(vec![Arc::new(NeedleInspector {
        redact: true,
        calls: AtomicUsize::new(0),
    })]);

    let result = server
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect("redacted resource remains forwardable");
    assert!(matches!(
        &result.contents[0],
        ResourceContents::TextResourceContents { text, .. } if text == "[REDACTED] text"
    ));
    let events = sink.snapshot().await;
    let reads: Vec<_> = events
        .iter()
        .filter(|event| event.action == "ReadResource")
        .collect();
    assert_eq!(reads.len(), 1, "redaction must not add evidence rows");
    assert_eq!(reads[0].outcome, AuditOutcome::Success);
    assert!(
        reads[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("test_needle") && reason.contains("1 finding")),
        "the final row should summarize the applied redaction",
    );
}

#[tokio::test]
async fn binary_only_resources_skip_text_inspectors() {
    const URI: &str = "printable://design/product-v1";
    let mut catalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .resource_read_result = Some(ReadResourceResult::new(vec![ResourceContents::blob(
        "c2Vuc2l0aXZl",
        URI,
    )]));
    let inspector = Arc::new(NeedleInspector {
        redact: false,
        calls: AtomicUsize::new(0),
    });
    let server = GatewayServer::new(catalog).with_resource_inspectors(vec![inspector.clone()]);

    server
        .read_visible_resource(ReadResourceRequestParams::new(URI), None)
        .await
        .expect("binary resource remains forwardable");
    assert_eq!(inspector.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn metadata_free_empty_upstreams_do_not_consume_client_pages() {
    let mut resources: Vec<(String, Vec<Resource>)> = (0..21)
        .map(|index| (format!("empty-{index:02}"), Vec::new()))
        .collect();
    resources.push((
        "printable".into(),
        vec![resource("printable://design/product-v1", "Product kit")],
    ));
    let catalog = FakeCatalog::with_resources(resources);
    let server = GatewayServer::new(catalog.clone());

    let listed = server
        .list_visible_resources(None, None)
        .await
        .expect("resource-bearing tail remains reachable");

    assert_eq!(listed.resources[0].uri, "printable://design/product-v1");
    assert!(listed.next_cursor.is_none());
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 22);
}

#[tokio::test]
async fn finite_all_empty_resource_fleet_exhausts_in_one_client_page() {
    let catalog = FakeCatalog::with_resources(
        (0..21)
            .map(|index| (format!("empty-{index:02}"), Vec::new()))
            .collect(),
    );
    let server = GatewayServer::new(catalog.clone());

    let listed = server
        .list_visible_resources(None, None)
        .await
        .expect("finite empty fleet");

    assert!(listed.resources.is_empty());
    assert!(listed.next_cursor.is_none());
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 21);
}

#[tokio::test]
async fn resource_templates_are_aggregated_across_visible_upstreams() {
    let catalog = FakeCatalog::with_resource_templates([
        (
            "browser".to_owned(),
            vec![ResourceTemplate::new(
                "browser://screenshot/{handle}/{name}",
                "Browser screenshot",
            )],
        ),
        (
            "reports".to_owned(),
            vec![ResourceTemplate::new(
                "reports://monthly/{year}/{month}",
                "Monthly report",
            )],
        ),
    ]);

    let listed = GatewayServer::new(catalog)
        .list_visible_resource_templates(None)
        .await
        .expect("resource template catalogs are aggregated");

    assert_eq!(listed.resource_templates.len(), 2);
    assert!(listed.next_cursor.is_none());
    assert!(listed
        .resource_templates
        .iter()
        .any(|template| { template.uri_template == "browser://screenshot/{handle}/{name}" }));
    assert!(listed
        .resource_templates
        .iter()
        .any(|template| { template.uri_template == "reports://monthly/{year}/{month}" }));
}

#[tokio::test]
async fn resource_template_aggregation_refuses_an_unbounded_item_set() {
    let templates = (0..4097)
        .map(|index| {
            ResourceTemplate::new(
                format!("oversized://template/{index}/{{value}}"),
                format!("Template {index}"),
            )
        })
        .collect();
    let catalog = FakeCatalog::with_resource_templates([("oversized".to_owned(), templates)]);

    let error = GatewayServer::new(catalog)
        .list_visible_resource_templates(None)
        .await
        .expect_err("fleet template aggregation must have a materialization bound");

    assert!(error.message.contains("4096-item fleet limit"));
}

#[tokio::test]
async fn read_resource_rejects_ambiguous_upstream_owners() {
    let catalog: SharedCatalog = FakeCatalog::with_resources(vec![
        (
            "one".into(),
            vec![resource("shared://contract", "Contract")],
        ),
        (
            "two".into(),
            vec![resource("shared://contract", "Contract")],
        ),
    ]);
    let error = GatewayServer::new(catalog)
        .read_visible_resource(ReadResourceRequestParams::new("shared://contract"), None)
        .await
        .expect_err("ambiguous URI must fail");
    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
}

#[tokio::test]
async fn legacy_resource_enumeration_cannot_claim_the_gateway_file_namespace() {
    let catalog = FakeCatalog::with_resources(vec![(
        "legacy".to_owned(),
        vec![resource(
            "MCP-FILE://gateway/attacker-controlled",
            "Reserved file handle",
        )],
    )]);
    let server = GatewayServer::new(catalog.clone());

    let error = server
        .read_visible_resource(
            ReadResourceRequestParams::new("MCP-FILE://gateway/attacker-controlled"),
            None,
        )
        .await
        .expect_err("the file-transfer namespace must never route to an upstream");

    assert_eq!(error.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn declared_resource_route_skips_enumeration_and_supplies_risk_to_authz() {
    struct CaptureRisk {
        risk: Mutex<Option<RiskTier>>,
        discovered: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl AuthzGate for CaptureRisk {
        async fn may_discover_server(&self, _principal: &Principal, server: &str) -> bool {
            self.discovered.lock().await.push(server.to_owned());
            true
        }

        async fn authorize_resource_read(
            &self,
            _principal: &Principal,
            _server: &str,
            _uri: &str,
            risk: RiskTier,
        ) -> AuthzVerdict {
            *self.risk.lock().await = Some(risk);
            AuthzVerdict::Allow {
                policy_ids: vec!["permit-browser-artifacts".to_owned()],
            }
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow { policy_ids: vec![] }
        }
    }

    let mut catalog =
        FakeCatalog::with_resource_claim("browser", "browser://screenshot/", RiskTier::High);
    Arc::get_mut(&mut catalog)
        .expect("catalog is not shared yet")
        .servers
        .extend((0..32).map(|index| (format!("unrelated-{index:02}"), Vec::new())));
    let authz = Arc::new(CaptureRisk {
        risk: Mutex::new(None),
        discovered: Mutex::new(Vec::new()),
    });
    let sink = Arc::new(InMemorySink::new());
    let server = GatewayServer::with_deps(catalog.clone(), authz.clone(), sink.clone());

    server
        .read_visible_resource(
            ReadResourceRequestParams::new("browser://screenshot/handle/capture.png"),
            Some(&maker()),
        )
        .await
        .expect("declared dynamic resource is directly routable");

    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 0);
    assert_eq!(*authz.risk.lock().await, Some(RiskTier::High));
    assert_eq!(
        *authz.discovered.lock().await,
        vec!["browser"],
        "declared routing evaluates visibility only for matching owners, not the fleet",
    );
    let events = sink.snapshot().await;
    let decision = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("declared read records its decision");
    assert_eq!(
        decision.risk_level,
        Some(RiskTier::High),
        "decision evidence must retain the risk that authorization evaluated",
    );
}

#[tokio::test]
async fn unnegotiated_file_backed_resource_metadata_is_not_forwarded() {
    struct FileMetadataCatalog;

    #[async_trait]
    impl UpstreamCatalog for FileMetadataCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["browser".to_owned()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }

        fn resource_claims(&self, server: &str) -> Vec<ResourceClaim> {
            assert_eq!(server, "browser");
            vec![ResourceClaim {
                uri_prefix: "browser://screenshot/".to_owned(),
                risk: RiskTier::High,
            }]
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<Map<String, Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("resource test never dispatches a tool")
        }

        async fn read_resource(
            &self,
            server: &str,
            params: ReadResourceRequestParams,
            _principal: Option<&Principal>,
        ) -> Result<ReadResourceResult, McpError> {
            assert_eq!(server, "browser");
            let meta = Meta(Map::from_iter([(
                waygate_mcp::files::FILE_RESOURCE_CONTENT_META_KEY.to_owned(),
                json!({"uri": "browser-private://capture", "size": 42}),
            )]));
            Ok(ReadResourceResult::new(vec![ResourceContents::text(
                "", params.uri,
            )
            .with_meta(meta)]))
        }
    }

    let error = GatewayServer::new(Arc::new(FileMetadataCatalog))
        .read_visible_resource(
            ReadResourceRequestParams::new("browser://screenshot/handle/capture.png"),
            Some(&maker()),
        )
        .await
        .expect_err("file metadata requires an individually negotiated governed download");

    assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
    assert!(error
        .message
        .contains("without a negotiated governed download"));
}

#[tokio::test]
async fn unsupported_resource_upstream_does_not_block_supported_products() {
    let catalog = FakeCatalog::with_resources_and_unsupported(
        vec![
            (
                "delegated".into(),
                vec![resource("delegated://private", "Private")],
            ),
            (
                "printable".into(),
                vec![resource(
                    "printable://design/product-v1",
                    "Generic product kit",
                )],
            ),
        ],
        ["delegated".into()],
    );
    let server = GatewayServer::new(catalog.clone());

    let listed = server
        .list_visible_resources(None, None)
        .await
        .expect("supported resource catalog remains available");
    assert_eq!(listed.resources[0].uri, "printable://design/product-v1");
    assert!(listed.next_cursor.is_none());

    let read = server
        .read_visible_resource(
            ReadResourceRequestParams::new("printable://design/product-v1"),
            None,
        )
        .await
        .expect("supported product guidance remains readable");
    assert!(matches!(
        &read.contents[0],
        ResourceContents::TextResourceContents { text, .. } if text == "body from printable"
    ));
}

#[tokio::test]
async fn resource_owner_resolution_has_one_fleet_wide_page_budget() {
    let catalog = FakeCatalog::with_endless_resource_pages("looping");
    let server = GatewayServer::new(catalog.clone());

    let error = server
        .read_visible_resource(ReadResourceRequestParams::new("missing://resource"), None)
        .await
        .expect_err("unbounded resource catalog must fail within the fleet budget");
    assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 50);
}

#[tokio::test]
async fn resource_listing_has_one_fleet_wide_page_budget() {
    let catalog = FakeCatalog::new(
        (0..51)
            .map(|index| (format!("unsupported-{index}"), Vec::new()))
            .collect(),
    );
    let server = GatewayServer::new(catalog.clone());

    let error = server
        .list_visible_resources(None, None)
        .await
        .expect_err("method-not-found fleet must fail within the page budget");
    assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 50);
}

#[tokio::test]
async fn resource_listing_budget_survives_cursor_round_trips() {
    let catalog = FakeCatalog::with_endless_resource_pages("looping");
    let server = GatewayServer::new(catalog.clone());
    let mut cursor = None;

    for _ in 0..50 {
        let listed = server
            .list_visible_resources(
                cursor.map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor))),
                None,
            )
            .await
            .expect("page within sequence budget");
        cursor = listed.next_cursor;
    }

    let error = server
        .list_visible_resources(
            cursor.map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor))),
            None,
        )
        .await
        .expect_err("sequence budget must not reset on each client request");
    assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 50);
}

#[tokio::test]
async fn resource_listing_rejects_a_repeated_upstream_cursor() {
    let catalog = FakeCatalog::with_repeated_resource_cursor("looping");
    let server = GatewayServer::new(catalog.clone());

    let first = server
        .list_visible_resources(None, None)
        .await
        .expect("first upstream page");
    let error = server
        .list_visible_resources(
            Some(PaginatedRequestParams::default().with_cursor(first.next_cursor)),
            None,
        )
        .await
        .expect_err("repeated upstream cursor must be rejected");

    assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn resource_listing_rejects_a_longer_upstream_cursor_cycle() {
    let catalog = FakeCatalog::with_cyclic_resource_cursor("looping");
    let server = GatewayServer::new(catalog.clone());
    let mut cursor = None;

    for _ in 0..2 {
        let listed = server
            .list_visible_resources(
                cursor.map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor))),
                None,
            )
            .await
            .expect("unique cursor page");
        cursor = listed.next_cursor;
    }

    let error = server
        .list_visible_resources(
            cursor.map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor))),
            None,
        )
        .await
        .expect_err("cursor cycle must be rejected");

    assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
    assert_eq!(catalog.resource_list_calls.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn resource_discovery_honors_principal_server_restrictions() {
    let catalog: SharedCatalog = FakeCatalog::with_resources(vec![
        (
            "printable".into(),
            vec![resource("printable://design/product-v1", "Product kit")],
        ),
        (
            "private-docs".into(),
            vec![resource("private://operations", "Operations")],
        ),
    ]);
    let server = GatewayServer::new(catalog);
    let mut principal = maker();
    principal.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
        profile_id: "product-user".into(),
        profile_name: "Product user".into(),
        allowed_servers: Some(vec!["printable".into()]),
        allowed_tools: None,
    });

    let listed = server
        .list_visible_resources(None, Some(&principal))
        .await
        .expect("visible resources");
    assert_eq!(listed.resources[0].uri, "printable://design/product-v1");
    assert!(listed.next_cursor.is_none());

    let error = server
        .read_visible_resource(
            ReadResourceRequestParams::new("private://operations"),
            Some(&principal),
        )
        .await
        .expect_err("hidden upstream resource must not be readable");
    assert_eq!(error.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
}

#[tokio::test]
async fn hidden_declared_owner_reserves_its_prefix_from_legacy_fallback() {
    const URI: &str = "private://operations/runbook";
    let mut catalog = FakeCatalog::with_resources(vec![
        (
            "printable".into(),
            vec![resource(URI, "Spoofed operations")],
        ),
        ("private-docs".into(), Vec::new()),
    ]);
    Arc::get_mut(&mut catalog)
        .expect("new catalog has one owner")
        .resource_claims
        .insert(
            "private-docs".into(),
            vec![ResourceClaim {
                uri_prefix: "private://operations/".into(),
                risk: RiskTier::High,
            }],
        );
    let mut principal = maker();
    principal.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
        profile_id: "printable-only".into(),
        profile_name: "Printable only".into(),
        allowed_servers: Some(vec!["printable".into()]),
        allowed_tools: None,
    });

    let error = GatewayServer::new(catalog.clone())
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&principal))
        .await
        .expect_err("an invisible declared owner must not open legacy fallback");

    assert_eq!(error.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
    assert_eq!(
        catalog.resource_list_calls.load(Ordering::Relaxed),
        0,
        "the fleet-wide declaration must settle ownership before enumeration",
    );
}

#[tokio::test]
async fn tool_scoped_profiles_do_not_inherit_native_resource_access() {
    let catalog: SharedCatalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(
            "printable://design/product-v1",
            "Generic product kit",
        )],
    )]);
    let server = GatewayServer::new(catalog);
    let mut principal = maker();
    principal.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
        profile_id: "render-only".into(),
        profile_name: "Render only".into(),
        allowed_servers: None,
        allowed_tools: Some(vec!["printable.render".into()]),
    });

    let listed = server
        .list_visible_resources(None, Some(&principal))
        .await
        .expect("tool-confined profile returns an empty resource catalog");
    assert!(listed.resources.is_empty());
    let error = server
        .read_visible_resource(
            ReadResourceRequestParams::new("printable://design/product-v1"),
            Some(&principal),
        )
        .await
        .expect_err("a concrete tool grant must not imply native resource access");
    assert_eq!(error.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
}

#[tokio::test]
async fn resource_listing_and_reading_use_distinct_authorization_decisions() {
    let catalog: SharedCatalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource(
            "printable://design/product-v1",
            "Generic product kit",
        )],
    )]);
    let principal = maker();

    let read_only = GatewayServer::with_authz(
        Arc::clone(&catalog),
        Arc::new(ResourceAuthz {
            list_allowed: false,
            read_verdict: ResourceAuthz::allow_read(),
        }),
    );
    let listed = read_only
        .list_visible_resources(None, Some(&principal))
        .await
        .expect("denied listing returns an empty visible catalog");
    assert!(listed.resources.is_empty());
    read_only
        .read_visible_resource(
            ReadResourceRequestParams::new("printable://design/product-v1"),
            Some(&principal),
        )
        .await
        .expect("read authorization is independent of list authorization");

    let list_only = GatewayServer::with_authz(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::deny_read(),
        }),
    );
    let listed = list_only
        .list_visible_resources(None, Some(&principal))
        .await
        .expect("list authorization permits discovery");
    assert_eq!(listed.resources[0].uri, "printable://design/product-v1");
    let error = list_only
        .read_visible_resource(
            ReadResourceRequestParams::new("printable://design/product-v1"),
            Some(&principal),
        )
        .await
        .expect_err("list authorization must not grant resource reads");
    assert_eq!(error.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
}

/// A resource read is a governed data access, so its decision is written down
/// the way a tool call's is: an attributable row naming what was read, carrying
/// the policy ids that produced the verdict. And a verdict the caller could
/// still act on has to survive to them as itself — collapsing step-up into a
/// flat refusal would hide the scope that would let the read succeed.
#[tokio::test]
async fn every_resource_read_verdict_is_recorded_and_reaches_the_caller_intact() {
    const URI: &str = "printable://design/product-v1";

    struct Case {
        verdict: AuthzVerdict,
        outcome: AuditOutcome,
        policy_id: &'static str,
        /// What the caller receives. `None` for the allow case, which returns
        /// contents. A hard deny is deliberately indistinguishable from an
        /// unserved URI — the denial is accountable in the row, not on the
        /// wire — while a satisfiable condition names itself so the caller can
        /// act on it.
        wire: Option<&'static str>,
    }

    let cases = vec![
        Case {
            verdict: ResourceAuthz::allow_read(),
            outcome: AuditOutcome::Success,
            policy_id: "permit-resource-read",
            wire: None,
        },
        Case {
            verdict: ResourceAuthz::deny_read(),
            outcome: AuditOutcome::Denied,
            policy_id: "forbid-resource-read",
            wire: Some("not advertised by a visible upstream"),
        },
        Case {
            verdict: AuthzVerdict::StepUpRequired {
                required_scope: "mcp:invoke:high".to_owned(),
                reason: "design guides need elevation".to_owned(),
                policy_ids: vec!["step-up-design-guides".to_owned()],
            },
            outcome: AuditOutcome::StepUpRequired,
            policy_id: "step-up-design-guides",
            // The scope is the actionable part: without it the caller cannot
            // tell a satisfiable condition from a permanent refusal.
            wire: Some("mcp:invoke:high"),
        },
        Case {
            verdict: AuthzVerdict::ApprovalRequired {
                reason: "a live per-call approval grant is required".to_owned(),
                policy_ids: vec!["approval-design-guides".to_owned()],
            },
            outcome: AuditOutcome::Denied,
            policy_id: "approval-design-guides",
            wire: Some("approval"),
        },
    ];

    for case in cases {
        let catalog: SharedCatalog = FakeCatalog::with_resources(vec![(
            "printable".into(),
            vec![resource(URI, "Generic product kit")],
        )]);
        let sink = Arc::new(InMemorySink::new());
        let server = GatewayServer::with_deps(
            catalog,
            Arc::new(ResourceAuthz {
                list_allowed: true,
                read_verdict: case.verdict.clone(),
            }),
            sink.clone(),
        );

        let result = server
            .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
            .await;

        match case.wire {
            None => {
                result.expect("an allowed read dispatches to the upstream");
            }
            Some(needle) => {
                let error = result.expect_err("a non-allow verdict refuses the read");
                assert!(
                    error.message.contains(needle),
                    "verdict {:?} must reach the caller carrying `{needle}`; got `{}`",
                    case.verdict,
                    error.message,
                );
                if matches!(case.verdict, AuthzVerdict::StepUpRequired { .. }) {
                    assert_eq!(
                        error.data.as_ref().and_then(|data| data.get("error")),
                        Some(&serde_json::json!("insufficient_scope")),
                    );
                    assert_eq!(
                        error
                            .data
                            .as_ref()
                            .and_then(|data| data.get("required_scope")),
                        Some(&serde_json::json!("mcp:invoke:high")),
                        "resource step-up must carry the machine-readable OAuth recovery hint",
                    );
                }
            }
        }

        let events = sink.snapshot().await;
        let decision = events
            .iter()
            .find(|event| event.action == "ReadResource")
            .unwrap_or_else(|| panic!("verdict {:?} recorded no decision row", case.verdict));
        assert_eq!(decision.outcome, case.outcome, "recorded outcome");
        assert_eq!(
            decision.risk_level,
            Some(RiskTier::Low),
            "the row must retain the risk supplied to authorization",
        );
        assert_eq!(
            decision.target.as_deref(),
            Some(URI),
            "the row must name the resource that was acted on",
        );
        assert!(
            decision.policy_ids.iter().any(|id| id == case.policy_id),
            "verdict {:?} must record the policy that produced it; got {:?}",
            case.verdict,
            decision.policy_ids,
        );
        assert!(
            decision.principal.is_some(),
            "a decision row must be attributable to the principal",
        );
    }
}

/// Wire data is controlled by the upstream and cannot establish whether the
/// gateway reached it. Even an exact copy of the local routing-refusal marker
/// is an execution error when it arrived through the upstream result path.
#[tokio::test]
async fn an_upstream_cannot_spoof_a_pre_dispatch_routing_refusal() {
    const URI: &str = "printable://design/product-v1";
    let catalog: SharedCatalog = FakeCatalog::with_spoofed_routing_error(vec![(
        "printable".into(),
        vec![resource(URI, "Product kit")],
    )]);
    let sink = Arc::new(InMemorySink::new());
    let error = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    )
    .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
    .await
    .expect_err("the fake upstream returns an application error");
    assert_eq!(
        error.data.as_ref().and_then(|data| data.get("error")),
        Some(&json!("resource_routing_changed")),
        "the test must exercise an indistinguishable wire payload",
    );

    let events = sink.snapshot().await;
    let decision = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("the failed upstream read records its decision");
    assert_eq!(decision.outcome, AuditOutcome::ExecutionError);
    assert!(
        decision
            .reason
            .as_deref()
            .is_none_or(|reason| !reason.contains("routing changed")),
        "upstream-controlled data must not acquire local refusal provenance",
    );
}

/// Ownership ambiguity is a fact about what the caller may read, not about
/// what the fleet advertises. A URI served by one upstream the caller can read
/// and one it cannot is served — reporting it as ambiguous would tell the
/// caller an upstream they have no standing on also holds it, which is exactly
/// the existence disclosure the deny path is careful to avoid.
#[tokio::test]
async fn ambiguity_is_decided_among_upstreams_the_caller_may_actually_read() {
    const URI: &str = "shared://design/product-v1";

    struct PerServerAuthz(&'static [&'static str]);

    #[async_trait]
    impl AuthzGate for PerServerAuthz {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn may_list_resources(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_resource_read(
            &self,
            _principal: &Principal,
            server: &str,
            _uri: &str,
            _risk: RiskTier,
        ) -> AuthzVerdict {
            if self.0.contains(&server) {
                ResourceAuthz::allow_read()
            } else {
                ResourceAuthz::deny_read()
            }
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow { policy_ids: vec![] }
        }
    }

    let two_owners = || -> SharedCatalog {
        FakeCatalog::with_resources(vec![
            ("alpha".into(), vec![resource(URI, "Product kit")]),
            ("beta".into(), vec![resource(URI, "Product kit")]),
        ])
    };

    // Readable on one of the two: served, and the other upstream is never
    // mentioned.
    let success_sink = Arc::new(InMemorySink::new());
    GatewayServer::with_deps(
        two_owners(),
        Arc::new(PerServerAuthz(&["alpha"])),
        success_sink.clone(),
    )
    .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
    .await
    .expect("a single readable owner settles the read");
    let success_events = success_sink.snapshot().await;
    let success = success_events
        .iter()
        .find(|event| event.action == "ReadResource" && event.outcome == AuditOutcome::Success)
        .expect("the successful read records its complete decision");
    assert!(success
        .policy_ids
        .contains(&"permit-resource-read".to_owned()));
    assert!(success
        .policy_ids
        .contains(&"forbid-resource-read".to_owned()));

    // Readable on both: genuinely ambiguous, and saying so reveals nothing the
    // caller could not already see by listing. The refusal is still a decision
    // the gateway made about this caller and this URI, so it is recorded —
    // an unaccounted-for resource read is the thing this whole path exists to
    // prevent.
    let sink = Arc::new(InMemorySink::new());
    let error = GatewayServer::with_deps(
        two_owners(),
        Arc::new(PerServerAuthz(&["alpha", "beta"])),
        sink.clone(),
    )
    .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
    .await
    .expect_err("two readable owners cannot be disambiguated");
    assert!(
        error.message.contains("multiple upstreams"),
        "expected an ambiguity refusal, got `{}`",
        error.message,
    );
    let events = sink.snapshot().await;
    let decision = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("an ambiguous read still records its decision");
    assert_eq!(decision.target.as_deref(), Some(URI));
    // Denied, not an execution error: the refusal never reached an upstream,
    // and the exporters read an execution error as a system failure, so
    // classifying a deterministic configuration problem that way would inflate
    // error reporting. No policy ids either — the permits that fired are not
    // what refused this.
    assert_eq!(decision.outcome, AuditOutcome::Denied);
    // The permits are not what refused the read, but they are why it became
    // ambiguous — each made another upstream readable — so a reverse lookup on
    // any of them has to reach this decision.
    assert!(
        decision
            .policy_ids
            .contains(&"permit-resource-read".to_owned()),
        "the permits that produced the conflict must be recorded; got {:?}",
        decision.policy_ids,
    );
    assert!(decision
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("multiple upstreams")));

    // Readable on neither: the ordinary non-disclosing denial, not an
    // ambiguity error that would confirm two upstreams hold it.
    let error = GatewayServer::with_authz(two_owners(), Arc::new(PerServerAuthz(&[])))
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect_err("a caller who may read neither owner gets nothing");
    assert_eq!(error.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
}

/// Resolution itself can fail — an upstream that cannot list, a repeated
/// cursor, an exhausted page budget, an expired deadline. The caller still
/// asked to read the URI, and an attempt that leaves no evidence is what
/// probing an unhealthy fleet would rely on, so the failure is recorded too.
#[tokio::test]
async fn a_read_whose_resolution_fails_is_still_recorded() {
    let catalog: SharedCatalog = FakeCatalog::with_repeated_resource_cursor("printable");
    let sink = Arc::new(InMemorySink::new());
    let error = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    )
    .read_visible_resource(
        ReadResourceRequestParams::new("printable://design/product-v1"),
        Some(&maker()),
    )
    .await
    .expect_err("a repeated cursor aborts resolution");

    let events = sink.snapshot().await;
    let decision = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("a failed resolution still records the attempt");
    // Upstreams were reached and one of them is why this failed, which is what
    // an execution error means.
    assert_eq!(decision.outcome, AuditOutcome::ExecutionError);
    assert_eq!(
        decision.target.as_deref(),
        Some("printable://design/product-v1"),
    );
    assert!(decision.principal.is_some());
    // The caller still learns nothing beyond the failure itself.
    assert!(!error.message.is_empty());
}

/// A read for a URI nothing visible serves is still an attempt this caller
/// made, and it is the shape a sweep for resource URIs takes. Without a row it
/// would leave no evidence at all, so the refusal is recorded even though no
/// policy ran to produce it.
#[tokio::test]
async fn a_read_for_an_unserved_uri_is_still_recorded() {
    let catalog: SharedCatalog = FakeCatalog::with_resources(vec![(
        "printable".into(),
        vec![resource("printable://design/product-v1", "Product kit")],
    )]);
    let sink = Arc::new(InMemorySink::new());
    let error = GatewayServer::with_deps(
        catalog,
        Arc::new(ResourceAuthz {
            list_allowed: true,
            read_verdict: ResourceAuthz::allow_read(),
        }),
        sink.clone(),
    )
    .read_visible_resource(
        ReadResourceRequestParams::new("printable://nothing/serves-this"),
        Some(&maker()),
    )
    .await
    .expect_err("no upstream advertises the URI");
    assert_eq!(error.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);

    let events = sink.snapshot().await;
    let decision = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("the attempt is recorded even with no owner to authorize against");
    assert_eq!(decision.outcome, AuditOutcome::Denied);
    assert_eq!(
        decision.target.as_deref(),
        Some("printable://nothing/serves-this"),
    );
    assert!(
        decision.policy_ids.is_empty(),
        "no policy ran, so none may be claimed; got {:?}",
        decision.policy_ids,
    );
    assert!(decision.principal.is_some());
}

/// When several upstreams advertise a URI and none of them allows the read,
/// the answer is the most actionable of their refusals rather than whichever
/// upstream the fleet happened to list first. A caller who could obtain an
/// approval needs to hear that, and the same fleet must not answer differently
/// because its listing order changed.
#[tokio::test]
async fn a_mixed_refusal_reports_the_condition_the_caller_could_still_satisfy() {
    const URI: &str = "shared://design/product-v1";

    struct MixedAuthz;

    #[async_trait]
    impl AuthzGate for MixedAuthz {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn may_list_resources(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_resource_read(
            &self,
            _principal: &Principal,
            server: &str,
            _uri: &str,
            _risk: RiskTier,
        ) -> AuthzVerdict {
            // `alpha` sorts first in fleet order and is the flat refusal, so an
            // order-driven pick would lose the approval gate on `beta`.
            if server == "alpha" {
                ResourceAuthz::deny_read()
            } else {
                AuthzVerdict::ApprovalRequired {
                    reason: "a live per-call approval grant is required".to_owned(),
                    policy_ids: vec!["approval-design-guides".to_owned()],
                }
            }
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow { policy_ids: vec![] }
        }
    }

    let catalog: SharedCatalog = FakeCatalog::with_resources(vec![
        ("alpha".into(), vec![resource(URI, "Product kit")]),
        ("beta".into(), vec![resource(URI, "Product kit")]),
    ]);
    let sink = Arc::new(InMemorySink::new());
    let error = GatewayServer::with_deps(catalog, Arc::new(MixedAuthz), sink.clone())
        .read_visible_resource(ReadResourceRequestParams::new(URI), Some(&maker()))
        .await
        .expect_err("no owner allows the read");
    assert!(
        error.message.contains("approval"),
        "the satisfiable condition must win over the flat refusal; got `{}`",
        error.message,
    );

    let events = sink.snapshot().await;
    let decision = events
        .iter()
        .find(|event| event.action == "ReadResource")
        .expect("the decision is recorded");
    assert!(
        decision
            .policy_ids
            .contains(&"approval-design-guides".to_owned()),
        "the recorded row must describe the same verdict the caller got; got {:?}",
        decision.policy_ids,
    );
    // The per-tool aggregates group by (server, tool) over every row that sets
    // both, so a resource URI in the tool column would invent a synthetic tool
    // and skew tool volume, error and denial figures.
    assert!(
        decision.tool.is_none(),
        "a resource decision must not occupy the tool column",
    );
    assert_eq!(decision.server.as_deref(), Some("beta"));
}

#[tokio::test]
async fn list_meta_tools_emits_one_per_upstream() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![
        (
            "example-messages".into(),
            vec![tool("send", "send a message")],
        ),
        (
            "example-observability".into(),
            vec![tool("query", "run a query")],
        ),
    ]);
    let server = GatewayServer::new(catalog);

    let metas = server.list_meta_tools(None).await;
    let names: Vec<&str> = metas.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(
        names,
        vec![
            "example-messages.searchTools",
            "example-observability.searchTools"
        ]
    );
    // Shared discovery and invocation guidance belongs to server instructions,
    // not every synthetic declaration. The schema teaches the request and
    // response contract while the description carries only per-server context.
    assert_eq!(
        metas[0].title.as_deref(),
        Some("example-messages — search tools")
    );
    assert_eq!(
        metas[0].description.as_deref(),
        Some("Search callable operations and type schemas on the `example-messages` upstream."),
    );
    assert_eq!(
        metas[1].description.as_deref(),
        Some(
            "Search callable operations and type schemas on the `example-observability` upstream."
        ),
    );
    assert!(metas[0].input_schema.contains_key("properties"));
    assert_eq!(metas[0].output_schema.as_ref().unwrap()["type"], "object");
    let annotations = metas[0].annotations.as_ref().expect("annotations");
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
}

#[tokio::test]
async fn legacy_visible_search_tools_collision_fails_with_recovery_guidance() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("searchTools", "ordinary upstream tool")],
    )]);
    let server = GatewayServer::new(catalog);

    let error = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect_err("a legacy peer cannot disambiguate the shared tool name");

    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(error.message.contains("use MCP 2026"));
    let data = error.data.expect("stable collision data");
    assert_eq!(data["error"], "legacy_search_tools_name_collision");
    assert_eq!(data["adapter"]["id"], "gateway.search-tools.compat");
    assert_eq!(data["adapter"]["version"], "1");
    assert_eq!(data["tool"], "example-messages.searchTools");
}

#[tokio::test]
async fn legacy_withheld_search_tools_collision_keeps_adapter_callable() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            tool("send", "send a message"),
            tool_without_mcp_object_root("searchTools", "withheld upstream tool"),
        ],
    )]);
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("a withheld collision cannot shadow the visible adapter");
    let operations = result.structured_content.unwrap()["operations"]
        .as_array()
        .cloned()
        .expect("operations array");
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["name"], "example-messages.send");
}

#[tokio::test]
async fn admitted_schema_withheld_search_tools_collision_keeps_adapter_callable() {
    struct AdmittedSchemaWithheldCollisionCatalog;

    #[async_trait]
    impl UpstreamCatalog for AdmittedSchemaWithheldCollisionCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["example-messages".to_owned()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(vec![
                tool("send", "send a message"),
                tool("searchTools", "raw definition is publishable"),
            ])
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<Map<String, Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            panic!("the withheld direct collision must not dispatch")
        }

        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> waygate_mcp::catalog::ResolvedInvocationTool {
            let facts = ToolFacts {
                server: server.to_owned(),
                name: tool_name.to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            };
            let definition = tool(tool_name, "definition captured with admitted facts");
            if tool_name == "searchTools" {
                let unavailable_input = json!({
                    "type": "object",
                    "properties": {
                        "value": {"$ref": "https://schemas.example/unavailable.json"}
                    }
                });
                waygate_mcp::catalog::ResolvedInvocationTool::Ready(
                    waygate_mcp::catalog::InvocationToolSnapshot::catalog(
                        facts,
                        uuid::Uuid::nil(),
                        "unpublishable-admission".to_owned(),
                        Some(unavailable_input),
                        None,
                    )
                    .with_published_definition(Some(definition)),
                )
            } else {
                waygate_mcp::catalog::ResolvedInvocationTool::Ready(
                    waygate_mcp::catalog::InvocationToolSnapshot::manifest_fallback(facts, true)
                        .with_published_definition(Some(definition)),
                )
            }
        }
    }

    let server = GatewayServer::new(Arc::new(AdmittedSchemaWithheldCollisionCatalog));
    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("an unpublishable admitted collision cannot shadow the adapter");
    let operations = result.structured_content.unwrap()["operations"]
        .as_array()
        .cloned()
        .expect("operations array");
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["name"], "example-messages.send");
}

#[tokio::test]
async fn search_tools_probe_hides_server_denied_by_discovery_policy() {
    struct ServerDiscoveryDenied;

    #[async_trait]
    impl AuthzGate for ServerDiscoveryDenied {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            false
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow { policy_ids: vec![] }
        }
    }

    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            tool("send", "send a message"),
            tool("searchTools", "ordinary upstream tool"),
        ],
    )]);
    let server = GatewayServer::with_authz(catalog, Arc::new(ServerDiscoveryDenied));

    let error = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            Some(&maker()),
        )
        .await
        .expect_err("server discovery denial must hide both meanings of the shared name");

    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert_eq!(error.message, "unknown upstream: example-messages");
    assert!(error.data.is_none());
}

#[tokio::test]
async fn search_tools_operations_returns_upstream_tools() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            tool("send_message", "send a message"),
            tool("list_contacts", "list contacts"),
        ],
    )]);
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("dispatch");

    let structured = result.structured_content.expect("structured_content");
    let ops = structured
        .get("operations")
        .and_then(|v| v.as_array())
        .expect("operations array");
    let names: Vec<&str> = ops
        .iter()
        .map(|o| o.get("name").and_then(|v| v.as_str()).unwrap())
        .collect();
    assert!(names.contains(&"example-messages.send_message"));
    assert!(names.contains(&"example-messages.list_contacts"));
}

#[tokio::test]
async fn malformed_upstream_input_schema_isolated_from_catalog() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            tool("list_contacts", "list contacts"),
            tool_without_mcp_object_root("send_message", "send a message"),
        ],
    )]);
    let server = GatewayServer::new(catalog).with_eager_tools_list(true);

    let visible_tools = server.list_visible_tools(None).await;
    let listed: Vec<String> = visible_tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(listed.contains(&"example-messages.list_contacts".to_owned()));
    assert!(!listed.contains(&"example-messages.send_message".to_owned()));

    let wire = serde_json::to_value(ListToolsResult::with_all_items(visible_tools))
        .expect("tools/list result serializes");
    assert!(wire["tools"]
        .as_array()
        .expect("tools/list tools array")
        .iter()
        .all(|tool| tool["inputSchema"]["type"] == "object"));

    let searched = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("valid tools remain discoverable");
    let operations = searched
        .structured_content
        .as_ref()
        .and_then(|value| value.get("operations"))
        .and_then(Value::as_array)
        .expect("operations");
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["name"], "example-messages.list_contacts");

    assert!(types_call(&server, "example-messages.send_message")
        .await
        .is_err());
}

#[tokio::test]
async fn tools_list_and_type_lookup_apply_the_final_portability_projection() {
    let input = Arc::new(
        json!({
            "type": "object",
            "properties": {
                "nullable": {"type": ["string", "null"]},
                "anything": true,
                "forbidden": false
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let output = Arc::new(
        json!({
            "type": "object",
            "properties": {"data": {"description": "free-form upstream payload"}}
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let upstream =
        Tool::new("portable_at_boundary", "test tool", input).with_raw_output_schema(output);
    let catalog: SharedCatalog =
        FakeCatalog::new(vec![("example-messages".into(), vec![upstream])]);
    let server = GatewayServer::new(catalog).with_eager_tools_list(true);

    let tools = server.list_visible_tools(None).await;
    let listed = tools
        .iter()
        .find(|tool| tool.name == "example-messages.portable_at_boundary")
        .expect("upstream tool is published");
    assert!(waygate_mcp::tool_schema::inspector_portable_schema(
        &Value::Object(listed.input_schema.as_ref().clone()),
    ));
    assert!(waygate_mcp::tool_schema::inspector_portable_schema(
        &Value::Object(listed.output_schema.as_ref().unwrap().as_ref().clone()),
    ));

    let resolved = types_call(&server, "example-messages.portable_at_boundary#output")
        .await
        .expect("portable output type resolves");
    assert!(waygate_mcp::tool_schema::inspector_portable_schema(
        &resolved.structured_content.unwrap()["jsonSchema"],
    ));
}

#[tokio::test]
async fn search_tools_operations_filters_by_query() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            tool("send_message", "send a message"),
            tool("list_contacts", "enumerate contacts"),
        ],
    )]);
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "operations", "filters": {"query": "contact"}}),
            )),
            None,
        )
        .await
        .expect("dispatch");

    let ops = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap();
    let names: Vec<&str> = ops
        .iter()
        .map(|o| o.get("name").and_then(|v| v.as_str()).unwrap())
        .collect();
    assert_eq!(names, vec!["example-messages.list_contacts"]);
}

#[tokio::test]
async fn search_tools_types_returns_input_schema() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send_message", "send")],
    )]);
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "types", "name": "example-messages.send_message"}),
            )),
            None,
        )
        .await
        .expect("dispatch");

    let structured = result.structured_content.expect("structured_content");
    assert_eq!(
        structured.get("name").and_then(|v| v.as_str()),
        Some("example-messages.send_message")
    );
    assert!(structured.get("jsonSchema").is_some());
}

#[tokio::test]
async fn search_tools_types_refuses_quarantined_tool_without_principal() {
    struct QuarantinedTypeCatalog;

    #[async_trait]
    impl UpstreamCatalog for QuarantinedTypeCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["example-messages".to_owned()]
        }

        async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
            if server == "example-messages" {
                Ok(vec![tool("quarantined", "must stay hidden")])
            } else {
                Err(McpError::invalid_params(
                    format!("unknown server {server}"),
                    None,
                ))
            }
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<Map<String, Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            panic!("quarantined tool must never be dispatched")
        }

        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> waygate_mcp::catalog::ResolvedInvocationTool {
            waygate_mcp::catalog::ResolvedInvocationTool::Quarantined {
                server: server.to_owned(),
                tool: tool_name.to_owned(),
            }
        }
    }

    let server = GatewayServer::new(Arc::new(QuarantinedTypeCatalog));
    let error = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(json!({
                "mode": "types",
                "name": "example-messages.quarantined#input"
            }))),
            None,
        )
        .await
        .expect_err("auth-disabled dispatch must still enforce runtime quarantine");

    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert_eq!(
        error.message,
        "unknown type: example-messages.quarantined#input"
    );
    assert!(error.data.is_none());
}

/// An upstream tool declaring the FULL self-documenting surface — title, output
/// schema, and behavioral annotations — so the passthrough-fidelity tests can
/// assert the gateway surfaces each verbatim. The gateway documents upstream
/// tools by faithful passthrough, never by inventing, so anything the upstream
/// declares must survive to the client unchanged.
fn rich_tool(name: &str) -> Tool {
    let input = json!({"type": "object", "properties": {"to": {"type": "string"}}})
        .as_object()
        .cloned()
        .unwrap();
    let output = json!({
        "type": "object",
        "properties": {"message_id": {"type": "string"}},
        "required": ["message_id"],
    })
    .as_object()
    .cloned()
    .unwrap();
    let mut tool = Tool::new(name.to_string(), "rich upstream tool", Arc::new(input))
        .with_title("Send a message")
        .with_raw_output_schema(Arc::new(output))
        .annotate(
            rmcp::model::ToolAnnotations::new()
                .read_only(false)
                .destructive(true),
        );
    tool.meta = Some(Meta(
        json!({
            "io.modelcontextprotocol/action-metadata": {
                "outcome": "consequential",
                "requiresReview": true
            }
        })
        .as_object()
        .cloned()
        .expect("meta object"),
    ));
    tool
}

/// Drive `example-messages.searchTools` in `mode=types` for one type name.
async fn types_call(server: &GatewayServer, name: &str) -> Result<CallToolResult, McpError> {
    server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "types", "name": name}))),
            None,
        )
        .await
}

#[tokio::test]
async fn upstream_tools_list_preserves_title_output_schema_and_annotations() {
    // tools/list must preserve an upstream tool's self-documentation — title,
    // output_schema, annotations, and every constraint — not just its name +
    // input schema. Output schemas also describe gateway delivery envelopes.
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![rich_tool("send_message")],
    )]);
    let server = GatewayServer::new(catalog).with_eager_tools_list(true);

    let tools = server.list_visible_tools(None).await;
    let t = tools
        .iter()
        .find(|t| t.name == "example-messages.send_message")
        .expect("upstream tool present in tools/list");
    assert_eq!(
        t.description.as_deref(),
        Some("rich upstream tool"),
        "upstream description must pass through without gateway boilerplate",
    );
    assert_eq!(
        t.input_schema["properties"]["to"]["type"], "string",
        "input schema fields must pass through",
    );
    assert_eq!(
        t.title.as_deref(),
        Some("Send a message"),
        "upstream title must pass through",
    );
    let out = t
        .output_schema
        .as_ref()
        .expect("upstream output_schema must pass through");
    let props = out["anyOf"][0]
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("output schema properties preserved");
    assert!(
        props.contains_key("message_id"),
        "output schema fields preserved verbatim",
    );
    let ann = t
        .annotations
        .as_ref()
        .expect("upstream annotations must pass through");
    assert_eq!(ann.read_only_hint, Some(false));
    assert_eq!(ann.destructive_hint, Some(true));
    assert_eq!(
        t.meta
            .as_ref()
            .and_then(|meta| meta.0.get("io.modelcontextprotocol/action-metadata"))
            .and_then(|action| action.get("outcome"))
            .and_then(Value::as_str),
        Some("consequential"),
        "namespaced action metadata must pass through",
    );
}

#[tokio::test]
async fn search_tools_types_resolves_input_and_output_schema() {
    // The operation descriptor advertises input_type `…#input` and output_type
    // `…#output`; mode=types must resolve BOTH — including the upstream's output
    // schema plus gateway delivery envelopes — or those handles are dead.
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            rich_tool("send_message"),
            tool("list_contacts", "list contacts"),
        ],
    )]);
    let server = GatewayServer::new(catalog);

    // #output → the upstream's OUTPUT schema with its meaning preserved.
    let out = types_call(&server, "example-messages.send_message#output")
        .await
        .expect("output type resolves");
    let body = out.structured_content.expect("structured");
    assert_eq!(body["name"], "example-messages.send_message#output");
    assert_eq!(
        body["jsonSchema"]["anyOf"][0]["properties"]["message_id"]["type"], "string",
        "output schema surfaced verbatim",
    );

    // #input → the input schema.
    let inp = types_call(&server, "example-messages.send_message#input")
        .await
        .expect("input type resolves");
    assert_eq!(
        inp.structured_content.unwrap()["jsonSchema"]["properties"]["to"]["type"],
        "string",
    );

    // Bare name still resolves to the input schema (backward compatible).
    let bare = types_call(&server, "example-messages.send_message")
        .await
        .expect("bare type resolves");
    let bare_body = bare.structured_content.unwrap();
    assert_eq!(bare_body["name"], "example-messages.send_message");
    assert_eq!(
        bare_body["jsonSchema"]["properties"]["to"]["type"],
        "string"
    );

    // #output on a tool that declares NO output schema → a faithful error, never
    // a fabricated empty schema.
    assert!(
        types_call(&server, "example-messages.list_contacts#output")
            .await
            .is_err(),
        "a tool with no output schema must error, not fabricate one",
    );
}

#[tokio::test]
async fn search_tools_operations_advertises_output_type_iff_output_schema() {
    // output_type is the handle to a tool's result schema; advertise it exactly
    // when the upstream actually declares one — present for a documented tool,
    // null for one without (so a client never chases a dead handle).
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            rich_tool("send_message"),
            tool("list_contacts", "list contacts"),
        ],
    )]);
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("dispatch");
    let ops = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap();
    let find = |name: &str| {
        ops.iter()
            .find(|o| o.get("name").and_then(|v| v.as_str()) == Some(name))
            .unwrap_or_else(|| panic!("no operation {name}"))
    };
    assert_eq!(
        find("example-messages.send_message")["outputType"],
        "example-messages.send_message#output",
        "documented tool advertises its output_type",
    );
    assert!(
        find("example-messages.list_contacts")["outputType"].is_null(),
        "tool with no output schema advertises no output_type",
    );
}

#[tokio::test]
async fn call_tool_proxies_fully_qualified_names() {
    let fake = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send_message", "send")],
    )]);
    let catalog: SharedCatalog = fake.clone();
    let server = GatewayServer::new(catalog);

    server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.send_message")
                .with_arguments(obj(json!({"to": "alice"}))),
            None,
        )
        .await
        .expect("proxy");

    let last = fake.last_call.lock().await.clone().expect("recorded");
    assert_eq!(last.0, "example-messages");
    assert_eq!(last.1, "send_message");
    assert_eq!(
        last.2.unwrap().get("to").and_then(|v| v.as_str()),
        Some("alice")
    );
}

struct ClassifiedCatalog {
    tools: Vec<Tool>,
    facts: Vec<(String, RiskTier, bool)>,
}

#[async_trait]
impl UpstreamCatalog for ClassifiedCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-messages".into()]
    }
    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(self.tools.clone())
    }
    async fn call_tool(
        &self,
        _server: &str,
        _tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }
    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        let (risk, side) = self
            .facts
            .iter()
            .find(|(n, _, _)| n == tool_name)
            .map(|(_, r, s)| (*r, *s))
            .unwrap_or((RiskTier::Low, false));
        ToolFacts {
            server: server.into(),
            name: tool_name.into(),
            risk,
            side_effects: side,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
}

#[tokio::test]
async fn descriptor_carries_classification_from_catalog() {
    let catalog: SharedCatalog = Arc::new(ClassifiedCatalog {
        tools: vec![
            tool("send_message", "send a message"),
            tool("list_contacts", "list contacts"),
        ],
        facts: vec![
            ("send_message".into(), RiskTier::High, true),
            ("list_contacts".into(), RiskTier::Low, false),
        ],
    });
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("dispatch");

    let ops = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .expect("operations");

    let send = ops
        .iter()
        .find(|o| o.get("name").and_then(|v| v.as_str()) == Some("example-messages.send_message"))
        .unwrap();
    assert_eq!(send.get("riskLevel").and_then(|v| v.as_str()), Some("high"));
    assert_eq!(
        send.get("sideEffects").and_then(|v| v.as_bool()),
        Some(true)
    );

    let list = ops
        .iter()
        .find(|o| o.get("name").and_then(|v| v.as_str()) == Some("example-messages.list_contacts"))
        .unwrap();
    assert_eq!(list.get("riskLevel").and_then(|v| v.as_str()), Some("low"));
    assert_eq!(
        list.get("sideEffects").and_then(|v| v.as_bool()),
        Some(false)
    );
}

#[tokio::test]
async fn risk_level_filter_selects_matching_tools() {
    let catalog: SharedCatalog = Arc::new(ClassifiedCatalog {
        tools: vec![tool("send_message", "send"), tool("list_contacts", "list")],
        facts: vec![
            ("send_message".into(), RiskTier::High, true),
            ("list_contacts".into(), RiskTier::Low, false),
        ],
    });
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "operations", "filters": {"riskLevel": "high"}}),
            )),
            None,
        )
        .await
        .expect("dispatch");

    let names: Vec<String> = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .map(|o| o.get("name").and_then(|v| v.as_str()).unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["example-messages.send_message"]);
}

#[tokio::test]
async fn scope_filter_selects_tools_by_required_scope() {
    // send_message is High ⇒ requires `mcp:invoke:high`; list_contacts is Low
    // ⇒ no required scope. Filtering by `scope: "mcp:invoke:high"` must return
    // only the high-risk tool, and that descriptor must expose the same scope
    // (so the value a client filters by is the value it sees and the call is
    // gated on).
    let catalog: SharedCatalog = Arc::new(ClassifiedCatalog {
        tools: vec![tool("send_message", "send"), tool("list_contacts", "list")],
        facts: vec![
            ("send_message".into(), RiskTier::High, true),
            ("list_contacts".into(), RiskTier::Low, false),
        ],
    });
    let server = GatewayServer::new(catalog);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "operations", "filters": {"scope": "mcp:invoke:high"}}),
            )),
            None,
        )
        .await
        .expect("dispatch");

    let ops = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap();
    let names: Vec<String> = ops
        .iter()
        .map(|o| o.get("name").and_then(|v| v.as_str()).unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["example-messages.send_message"]);
    // The descriptor exposes the derived scope.
    assert_eq!(
        ops[0].get("scope").and_then(|v| v.as_str()),
        Some("mcp:invoke:high"),
    );
}

#[tokio::test]
async fn low_risk_tool_omits_scope_and_is_excluded_by_scope_filter() {
    // A low-risk tool has no required scope: its descriptor omits `scope`, and
    // a `scope` filter (which only matches a concrete required scope) excludes
    // it. Filtering by a concrete scope (`mcp:invoke:high`) returns nothing here.
    let catalog: SharedCatalog = Arc::new(ClassifiedCatalog {
        tools: vec![tool("list_contacts", "list")],
        facts: vec![("list_contacts".into(), RiskTier::Low, false)],
    });
    let server = GatewayServer::new(catalog);

    // Unfiltered: the low-risk descriptor must NOT carry a scope field.
    let all = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("dispatch");
    let ops = all
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(ops.len(), 1);
    assert!(
        ops[0].get("scope").is_none(),
        "low-risk tool must omit the scope field"
    );

    // Filtered by a concrete scope: the low-risk tool is excluded.
    let filtered = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "operations", "filters": {"scope": "mcp:invoke:high"}}),
            )),
            None,
        )
        .await
        .expect("dispatch");
    let filtered_ops = filtered
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap();
    assert!(
        filtered_ops.is_empty(),
        "a concrete scope filter must exclude low-risk (no-scope) tools"
    );
}

#[tokio::test]
async fn bare_tool_name_is_rejected() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let server = GatewayServer::new(catalog);

    let err = server
        .dispatch_tool_call(CallToolRequestParams::new("send_message"), None)
        .await
        .expect_err("should reject unqualified name");
    assert!(format!("{err}").contains("not fully qualified"));
}

#[tokio::test]
async fn search_tools_uses_bm25_index_when_query_present() {
    // Two tools where the query word appears in *both* name and description,
    // but the BM25 signal should still prefer the one whose name is a direct
    // match. This pins that we're actually asking the index rather than
    // falling back to substring (substring would keep the source order).
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            tool(
                "list_contacts",
                "enumerate contacts and pick a message target",
            ),
            tool("send_message", "send a message to a contact"),
        ],
    )]);

    let index = waygate_mcp::SearchIndex::new().expect("search index init");
    // Mirror what the pool would have indexed.
    let seeded = vec![
        tool(
            "list_contacts",
            "enumerate contacts and pick a message target",
        ),
        tool("send_message", "send a message to a contact"),
    ];
    index
        .replace_server("example-messages", &seeded)
        .expect("index seed");

    let server = GatewayServer::new(catalog).with_index(index);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "operations", "filters": {"query": "message"}}),
            )),
            None,
        )
        .await
        .expect("dispatch");

    let names: Vec<String> = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .map(|o| o.get("name").and_then(|v| v.as_str()).unwrap().to_string())
        .collect();

    // BM25 should surface the tool whose *name* contains "message" ahead of
    // the one that only mentions it in a descriptive phrase. If substring
    // fallback fires instead, names stay in catalog-declaration order and
    // this assertion flips.
    assert_eq!(
        names.first().map(String::as_str),
        Some("example-messages.send_message"),
        "BM25 should rank name-hit first, got {names:?}"
    );
}

#[tokio::test]
async fn search_tools_retries_when_catalog_and_index_generations_cross() {
    let index = waygate_mcp::SearchIndex::new().expect("search index init");
    let before = vec![tool("legacy_search", "legacy message search")];
    let after = vec![tool("send_message", "send a message")];
    index
        .replace_server("example-messages", &before)
        .expect("seed old index generation");
    let catalog = Arc::new(GenerationFlipCatalog {
        index: index.clone(),
        calls: AtomicUsize::new(0),
        before,
        after,
    });
    let server = GatewayServer::new(catalog.clone()).with_index(index);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "operations", "filters": {"query": "message"}}),
            )),
            None,
        )
        .await
        .expect("dispatch");

    let names: Vec<&str> = result
        .structured_content
        .as_ref()
        .and_then(|value| value.get("operations"))
        .and_then(|value| value.as_array())
        .expect("operations")
        .iter()
        .map(|operation| operation["name"].as_str().expect("operation name"))
        .collect();
    assert_eq!(names, vec!["example-messages.send_message"]);
    assert_eq!(
        catalog.calls.load(Ordering::SeqCst),
        3,
        "two generation-stabilizing reads plus the static-catalog definition capture",
    );
}

#[tokio::test]
async fn list_visible_tools_initially_returns_only_meta_tools() {
    // Freshly-initialized session: nothing has been revealed via searchTools
    // yet, so `tools/list` must contain only the meta-tool entry.
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send_message", "send")],
    )]);
    let server = GatewayServer::new(catalog);

    let names: Vec<String> = server
        .list_visible_tools(None)
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(names, vec!["example-messages.searchTools"]);
}

#[tokio::test]
async fn search_tools_operations_reveals_tools_to_tools_list() {
    // After a `searchTools` call returns a set of operations, those tool
    // names must appear in subsequent `tools/list` responses so strict
    // clients (Claude Code today) can invoke them.
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![
            tool("send_message", "send a message"),
            tool("list_contacts", "list contacts"),
        ],
    )]);
    let server = GatewayServer::new(catalog);

    server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools").with_arguments(obj(
                json!({"mode": "operations", "filters": {"query": "message"}}),
            )),
            None,
        )
        .await
        .expect("dispatch");

    let mut names: Vec<String> = server
        .list_visible_tools(None)
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    assert!(names.contains(&"example-messages.searchTools".to_string()));
    assert!(
        names.contains(&"example-messages.send_message".to_string()),
        "expected revealed tool in tools/list, got {names:?}"
    );
    // The disclosure must arm `pending_notify` exactly once per new reveal.
    assert!(
        server.disclosed().take_pending_notify(),
        "first searchTools call should arm tools/list_changed",
    );
}

#[tokio::test]
async fn pending_notify_does_not_rearm_on_repeat_search() {
    // Calling searchTools again with the same filter re-reveals the same
    // tools — the set does not grow, so no new `tools/list_changed` is
    // warranted. This keeps notification traffic proportional to actual
    // changes even if clients re-query aggressively.
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send_message", "send")],
    )]);
    let server = GatewayServer::new(catalog);

    for _ in 0..2 {
        server
            .dispatch_tool_call(
                CallToolRequestParams::new("example-messages.searchTools")
                    .with_arguments(obj(json!({"mode": "operations"}))),
                None,
            )
            .await
            .expect("dispatch");
    }
    // Take once (arms from the first call), second take should be false.
    assert!(server.disclosed().take_pending_notify());
    assert!(!server.disclosed().take_pending_notify());
}

#[tokio::test]
async fn eager_tools_list_returns_full_catalog_without_search() {
    // Operator escape hatch for clients that ignore tools/list_changed
    // (claude-code#13646): the full upstream catalog shows up in
    // `tools/list` immediately, with no `searchTools` call required.
    // Meta-tools remain alongside so SEP #1888-aware clients can still
    // use progressive discovery.
    let catalog: SharedCatalog = FakeCatalog::new(vec![
        (
            "example-messages".into(),
            vec![
                tool("send_message", "send a message"),
                tool("list_contacts", "list contacts"),
            ],
        ),
        (
            "example-observability".into(),
            vec![tool("query", "run a query")],
        ),
    ]);
    let server = GatewayServer::new(catalog).with_eager_tools_list(true);

    let names: Vec<String> = server
        .list_visible_tools(None)
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "example-messages.list_contacts",
            "example-messages.searchTools",
            "example-messages.send_message",
            "example-observability.query",
            "example-observability.searchTools",
        ],
        "eager compatibility projections must be canonical for stable client caches",
    );
}

#[tokio::test]
async fn eager_tools_list_default_is_off() {
    // Belt-and-suspenders: a plain `::new` must not eagerly dump the
    // catalog. Covers accidental-default regressions if the flag's
    // storage type changes.
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send_message", "send")],
    )]);
    let server = GatewayServer::new(catalog);

    let names: Vec<String> = server
        .list_visible_tools(None)
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(names, vec!["example-messages.searchTools"]);
}

#[tokio::test]
async fn eager_projection_rechecks_authorization_on_every_list() {
    struct MutableToolAuthz(Arc<AtomicBool>);

    #[async_trait]
    impl AuthzGate for MutableToolAuthz {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            if self.0.load(Ordering::Relaxed) {
                AuthzVerdict::Allow { policy_ids: vec![] }
            } else {
                AuthzVerdict::Deny {
                    reason: "policy changed".to_owned(),
                    policy_ids: vec!["deny-after-change".to_owned()],
                    reasons: vec!["tool access was revoked".to_owned()],
                }
            }
        }
    }

    let allowed = Arc::new(AtomicBool::new(true));
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send_message", "send")],
    )]);
    let server = GatewayServer::with_authz(catalog, Arc::new(MutableToolAuthz(allowed.clone())))
        .with_eager_tools_list(true);
    let principal = maker();

    let before: Vec<String> = server
        .list_visible_tools(Some(&principal))
        .await
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(before.contains(&"example-messages.send_message".to_owned()));

    allowed.store(false, Ordering::Relaxed);
    let after: Vec<String> = server
        .list_visible_tools(Some(&principal))
        .await
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(after.contains(&"example-messages.searchTools".to_owned()));
    assert!(
        !after.contains(&"example-messages.send_message".to_owned()),
        "eager compatibility changes projection size, never authorization: {after:?}",
    );
}

#[tokio::test]
async fn eager_projection_uses_definition_captured_with_governance_snapshot() {
    struct SnapshotDefinitionCatalog;

    #[async_trait]
    impl UpstreamCatalog for SnapshotDefinitionCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["example-messages".to_owned()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(vec![tool(
                "send_message",
                "definition from an earlier read",
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
            panic!("discovery must not dispatch")
        }

        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> waygate_mcp::catalog::ResolvedInvocationTool {
            let facts = ToolFacts {
                server: server.to_owned(),
                name: tool_name.to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            };
            waygate_mcp::catalog::ResolvedInvocationTool::Ready(
                waygate_mcp::catalog::InvocationToolSnapshot::manifest_fallback(facts, true)
                    .with_published_definition(Some(tool(
                        "send_message",
                        "definition captured with admitted facts",
                    ))),
            )
        }
    }

    let server =
        GatewayServer::new(Arc::new(SnapshotDefinitionCatalog)).with_eager_tools_list(true);
    let listed = server.list_visible_tools(None).await;
    let definition = listed
        .iter()
        .find(|tool| tool.name.as_ref() == "example-messages.send_message")
        .expect("the admitted snapshot definition is listed");

    assert_eq!(
        definition.description.as_deref(),
        Some("definition captured with admitted facts"),
    );
}

#[tokio::test]
async fn search_tools_uses_the_schemas_admitted_for_invocation() {
    struct DivergentSchemaCatalog;

    impl DivergentSchemaCatalog {
        fn live_definition() -> Tool {
            let input = json!({
                "type": "object",
                "properties": {"stale_input": {"type": "string"}}
            })
            .as_object()
            .cloned()
            .unwrap();
            Tool::new(
                "send_message".to_owned(),
                "definition captured with admitted facts",
                Arc::new(input),
            )
        }
    }

    #[async_trait]
    impl UpstreamCatalog for DivergentSchemaCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["example-messages".to_owned()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(vec![Self::live_definition()])
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<Map<String, Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            panic!("discovery must not dispatch")
        }

        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> waygate_mcp::catalog::ResolvedInvocationTool {
            let facts = ToolFacts {
                server: server.to_owned(),
                name: tool_name.to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            };
            let input = json!({
                "type": "object",
                "properties": {"admitted_input": {"type": "string"}}
            });
            let output = json!({
                "type": "object",
                "properties": {"admitted_output": {"type": "string"}}
            });
            waygate_mcp::catalog::ResolvedInvocationTool::Ready(
                waygate_mcp::catalog::InvocationToolSnapshot::catalog(
                    facts,
                    uuid::Uuid::nil(),
                    "admitted-schema".to_owned(),
                    Some(input),
                    Some(output),
                )
                .with_published_definition(Some(Self::live_definition())),
            )
        }
    }

    let server = GatewayServer::new(Arc::new(DivergentSchemaCatalog));
    let operations = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            None,
        )
        .await
        .expect("operation discovery succeeds")
        .structured_content
        .expect("structured operation response");
    assert_eq!(
        operations["operations"][0]["outputType"], "example-messages.send_message#output",
        "operation discovery advertises the admitted output contract",
    );

    let input = types_call(&server, "example-messages.send_message#input")
        .await
        .expect("admitted input type resolves")
        .structured_content
        .expect("structured input type response");
    assert_eq!(
        input["jsonSchema"]["properties"]["admitted_input"]["type"],
        "string",
    );
    assert!(input["jsonSchema"]["properties"]
        .get("stale_input")
        .is_none());

    let output = types_call(&server, "example-messages.send_message#output")
        .await
        .expect("admitted output type resolves")
        .structured_content
        .expect("structured output type response");
    assert_eq!(
        output["jsonSchema"]["anyOf"][0]["properties"]["admitted_output"]["type"],
        "string",
    );
}

// ---- Built-in (gateway-local) tool namespace ----

/// Stub built-in namespace. `list_tools` gates its complete catalog on a
/// marker scope so we can assert the scope filter.
struct StubBuiltin;

#[async_trait]
impl waygate_mcp::BuiltinTools for StubBuiltin {
    fn namespace(&self) -> &str {
        "gateway-admin"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![
                tool("gateway-admin.ping", "check the local handler"),
                tool("gateway-admin.propose_change", "queue a change"),
            ],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "gateway-admin".into(),
            required_scope: "mcp:propose".into(),
            summary: "stub".into(),
            tools: vec![
                BuiltinToolDescriptor {
                    name: "ping".into(),
                    description: "check the local handler".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                },
                BuiltinToolDescriptor {
                    name: "propose_change".into(),
                    description: "queue a change".into(),
                    risk: RiskTier::Medium,
                    side_effects: true,
                    pii: false,
                },
            ],
        }
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        let scoped = principal
            .map(|p| p.has_scope("mcp:propose"))
            .unwrap_or(false);
        if scoped {
            self.catalog().definitions()
        } else {
            vec![]
        }
    }

    async fn call(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        match tool {
            "ping" => Ok(CallToolResult::success(vec![Content::text("pong")])),
            "propose_change" => Ok(CallToolResult::success(vec![Content::text("queued")])),
            other => Err(McpError::invalid_params(
                format!("unknown gateway-admin tool: {other}"),
                None,
            )),
        }
    }
}

struct TaskBuiltin;

#[async_trait]
impl waygate_mcp::BuiltinTools for TaskBuiltin {
    fn namespace(&self) -> &str {
        "codemode"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        waygate_mcp::BuiltinCatalog::from_descriptor(self.describe(), Vec::new())
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "codemode".into(),
            required_scope: "mcp:invoke".into(),
            summary: "task-capable stub".into(),
            tools: Vec::new(),
        }
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
        Err(McpError::invalid_params("not implemented", None))
    }

    fn supports_tasks(&self) -> bool {
        true
    }

    fn task_tool(&self) -> Option<&str> {
        Some("execute")
    }
}

#[test]
fn server_advertises_tasks_extension_only_with_a_task_builtin() {
    // Tasks are the SEP-2663 extension: advertised through the extensions
    // capability map, and only when a built-in actually serves a durable
    // task tool. A gateway with no task built-in must not invite clients
    // to call `tasks/*`.
    let without_tasks = GatewayServer::new(FakeCatalog::new(Vec::new())).get_info();
    assert!(!without_tasks.capabilities.supports_tasks());

    let with_tasks = GatewayServer::new(FakeCatalog::new(Vec::new()))
        .with_builtin_tools(Arc::new(TaskBuiltin))
        .get_info();
    assert!(
        with_tasks.capabilities.supports_tasks(),
        "configured durable task built-in advertises the tasks extension"
    );
}

fn maker() -> Principal {
    Principal {
        sub: "agent".into(),
        email: None,
        groups: vec![],
        issuer: "local-test".into(),
        scopes: vec!["mcp:propose".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

#[tokio::test]
async fn builtin_namespace_call_is_answered_locally_not_proxied() {
    // `gateway-admin.ping` must route to the built-in handler, and the
    // upstream catalog's `call_tool` must NOT be touched — the reserved
    // namespace is hermetic.
    let fake = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send", "send")],
    )]);
    let catalog: SharedCatalog = fake.clone();
    let server = GatewayServer::new(catalog).with_builtin_tools(Arc::new(StubBuiltin));

    let result = server
        .dispatch_tool_call(CallToolRequestParams::new("gateway-admin.ping"), None)
        .await
        .expect("builtin dispatch");
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    assert_eq!(text, "pong");
    assert!(
        fake.last_call.lock().await.is_none(),
        "a built-in call must never reach the upstream pool"
    );
}

#[tokio::test]
async fn builtin_unknown_tool_does_not_fall_through_to_upstream() {
    // An unknown name in the reserved namespace is the canonical catalog's
    // error, NOT an upstream proxy attempt for a server literally named
    // `gateway-admin`. Proves the prefix interception is exhaustive.
    let fake = FakeCatalog::new(vec![]);
    let catalog: SharedCatalog = fake.clone();
    let server = GatewayServer::new(catalog).with_builtin_tools(Arc::new(StubBuiltin));

    let err = server
        .dispatch_tool_call(CallToolRequestParams::new("gateway-admin.bogus"), None)
        .await
        .expect_err("unknown built-in tool");
    assert!(
        format!("{err}").contains("unknown tool: gateway-admin.bogus"),
        "got: {err}"
    );
    assert!(fake.last_call.lock().await.is_none());
}

#[tokio::test]
async fn builtin_tools_appear_in_tools_list_only_when_scoped() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send", "send")],
    )]);
    let server = GatewayServer::new(catalog).with_builtin_tools(Arc::new(StubBuiltin));

    // No principal / unscoped: only the upstream meta-tool, no built-ins.
    let anon: Vec<String> = server
        .list_visible_tools(None)
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(anon, vec!["example-messages.searchTools"]);

    // A maker holding `mcp:propose` additionally sees the built-in tool,
    // listed directly (not behind a searchTools meta-tool).
    let p = maker();
    let scoped: Vec<String> = server
        .list_visible_tools(Some(&p))
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        scoped.contains(&"gateway-admin.propose_change".to_string()),
        "maker must see the built-in tool, got {scoped:?}"
    );
}

#[tokio::test]
async fn non_builtin_call_still_proxies_when_builtin_present() {
    // Wiring a built-in namespace must not disturb ordinary upstream
    // dispatch — `example-messages.send` still reaches the pool.
    let fake = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send", "send")],
    )]);
    let catalog: SharedCatalog = fake.clone();
    let server = GatewayServer::new(catalog).with_builtin_tools(Arc::new(StubBuiltin));

    server
        .dispatch_tool_call(CallToolRequestParams::new("example-messages.send"), None)
        .await
        .expect("upstream dispatch");
    let last = fake.last_call.lock().await.clone();
    assert_eq!(
        last.map(|(s, t, _)| (s, t)),
        Some(("example-messages".to_string(), "send".to_string()))
    );
}

/// A second built-in namespace, gated on a different scope, used to prove the
/// registry hosts more than one handle. `gateway-observe.query_audit` returns
/// "observed"; its tools list only for `mcp:observe` holders.
struct StubObserve;

struct DriftedListingBuiltin;

#[async_trait]
impl waygate_mcp::BuiltinTools for DriftedListingBuiltin {
    fn namespace(&self) -> &str {
        "listing"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![tool("listing.read", "canonical definition")],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "listing".into(),
            required_scope: "mcp:read".into(),
            summary: "listing consistency fixture".into(),
            tools: vec![BuiltinToolDescriptor {
                name: "read".into(),
                description: "canonical definition".into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
            }],
        }
    }

    async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
        vec![
            tool("listing.read", "handler-local drift"),
            tool("listing.uncataloged", "must stay hidden"),
        ]
    }

    async fn call(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        Err(McpError::invalid_params(
            format!("unknown listing tool: {tool}"),
            None,
        ))
    }
}

#[async_trait]
impl waygate_mcp::BuiltinTools for StubObserve {
    fn namespace(&self) -> &str {
        "gateway-observe"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![tool("gateway-observe.query_audit", "read audit")],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "gateway-observe".into(),
            required_scope: "mcp:observe".into(),
            summary: "stub".into(),
            tools: vec![BuiltinToolDescriptor {
                name: "query_audit".into(),
                description: "read audit".into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: true,
            }],
        }
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        if principal.is_some_and(|p| p.has_scope("mcp:observe")) {
            vec![tool("gateway-observe.query_audit", "read audit")]
        } else {
            vec![]
        }
    }

    async fn call(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        match tool {
            "query_audit" => Ok(CallToolResult::success(vec![Content::text("observed")])),
            other => Err(McpError::invalid_params(
                format!("unknown gateway-observe tool: {other}"),
                None,
            )),
        }
    }
}

#[tokio::test]
async fn multiple_builtin_namespaces_coexist_and_stay_hermetic() {
    // Two built-in namespaces registered side by side: each call routes to the
    // handler that owns its prefix, neither leaks to the other or to the
    // upstream pool, and an unknown tool lands in the OWNING namespace's error.
    let fake = FakeCatalog::new(vec![(
        "example-messages".into(),
        vec![tool("send", "send")],
    )]);
    let catalog: SharedCatalog = fake.clone();
    let server = GatewayServer::new(catalog)
        .with_builtin_tools(Arc::new(StubBuiltin))
        .with_builtin_tools(Arc::new(StubObserve));

    // Each namespace answers its own tool.
    let admin = server
        .dispatch_tool_call(CallToolRequestParams::new("gateway-admin.ping"), None)
        .await
        .expect("admin dispatch");
    assert_eq!(
        admin
            .content
            .iter()
            .find_map(|c| c.as_text().map(|t| t.text.clone())),
        Some("pong".to_string())
    );
    let observe = server
        .dispatch_tool_call(
            CallToolRequestParams::new("gateway-observe.query_audit"),
            None,
        )
        .await
        .expect("observe dispatch");
    assert_eq!(
        observe
            .content
            .iter()
            .find_map(|c| c.as_text().map(|t| t.text.clone())),
        Some("observed".to_string())
    );

    // An unknown tool in the second namespace is refused at its canonical
    // catalog boundary, before any built-in handler or upstream proxy attempt.
    let err = server
        .dispatch_tool_call(CallToolRequestParams::new("gateway-observe.bogus"), None)
        .await
        .expect_err("unknown observe tool");
    assert!(
        format!("{err}").contains("unknown tool: gateway-observe.bogus"),
        "second namespace must fail closed at its catalog, got: {err}"
    );
    assert!(
        fake.last_call.lock().await.is_none(),
        "no built-in call may reach the upstream pool"
    );

    // tools/list unions the namespaces, each gated on its own scope. A
    // principal holding both scopes sees both tools.
    let mut both = maker();
    both.scopes.push("mcp:observe".into());
    let listed: Vec<String> = server
        .list_visible_tools(Some(&both))
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        listed.contains(&"gateway-admin.propose_change".to_string())
            && listed.contains(&"gateway-observe.query_audit".to_string()),
        "both namespaces' tools must list for a principal holding both scopes, got {listed:?}"
    );
}

#[tokio::test]
async fn built_in_handler_cannot_serve_a_name_missing_from_its_catalog() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let server = GatewayServer::new(catalog).with_builtin_tools(Arc::new(StubObserve));

    let err = server
        .dispatch_tool_call(CallToolRequestParams::new("gateway-observe.peek"), None)
        .await
        .expect_err("an unlisted built-in must never reach its handler");

    assert!(
        format!("{err}").contains("unknown tool: gateway-observe.peek"),
        "catalog drift must fail closed without disclosing handler behavior: {err}"
    );
}

#[tokio::test]
async fn built_in_listing_selects_only_canonical_definitions_without_a_principal() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let server = GatewayServer::new(catalog).with_builtin_tools(Arc::new(DriftedListingBuiltin));

    let listed = server.list_visible_tools(None).await;
    let local: Vec<&Tool> = listed
        .iter()
        .filter(|tool| tool.name.starts_with("listing."))
        .collect();

    assert_eq!(
        local.len(),
        1,
        "uncataloged handler output must stay hidden"
    );
    assert_eq!(local[0].name, "listing.read");
    assert_eq!(
        local[0].description.as_deref(),
        Some("canonical definition"),
        "the canonical record, not a handler-local definition, owns the wire contract"
    );
}

// ---- Cedar forbid-overlay over built-in tool calls ----

/// Built-in stub for the forbid-overlay tests. `describe()` classifies one
/// tool, `quarantine_server` (High, side-effecting), so the overlay has a
/// classification to authorize. `call()` flips `ran` so a test can prove the
/// overlay blocked the call BEFORE its side effect rather than after.
struct GovBuiltin {
    ran: Arc<AtomicBool>,
}

struct ContinuationBuiltin;

#[async_trait]
impl waygate_mcp::BuiltinTools for ContinuationBuiltin {
    fn namespace(&self) -> &str {
        "continuation"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![
                tool("continuation.execute", "start work"),
                tool("continuation.resume", "resume"),
            ],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "continuation".into(),
            required_scope: "mcp:admin".into(),
            summary: "continuation test surface".into(),
            tools: vec![
                BuiltinToolDescriptor {
                    name: "execute".into(),
                    description: "start work".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                },
                BuiltinToolDescriptor {
                    name: "resume".into(),
                    description: "resume".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                },
            ],
        }
    }

    fn governance_tool<'a>(&self, tool: &'a str) -> &'a str {
        if tool == "resume" {
            "execute"
        } else {
            tool
        }
    }

    async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
        vec![tool("continuation.resume", "resume")]
    }

    async fn call(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        match tool {
            "resume" => Ok(CallToolResult::success(vec![Content::text("resumed")])),
            other => Err(McpError::invalid_params(
                format!("unknown continuation tool: {other}"),
                None,
            )),
        }
    }
}

struct RecordingBuiltinNameAuthz {
    observed: Arc<Mutex<Vec<String>>>,
}

struct ForbidExecuteBuiltinAuthz;

#[async_trait]
impl AuthzGate for ForbidExecuteBuiltinAuthz {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }

    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::Allow { policy_ids: vec![] }
    }

    async fn authorize_builtin_call(
        &self,
        _principal: &Principal,
        facts: &ToolFacts,
    ) -> BuiltinAuthz {
        if facts.name == "execute" {
            BuiltinAuthz::Forbidden {
                reason: "execute is forbidden".into(),
                policy_ids: vec!["forbid-execute".into()],
                reasons: vec![],
            }
        } else {
            BuiltinAuthz::Proceed
        }
    }
}

#[async_trait]
impl AuthzGate for RecordingBuiltinNameAuthz {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }

    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::Allow { policy_ids: vec![] }
    }

    async fn authorize_builtin_call(
        &self,
        _principal: &Principal,
        facts: &ToolFacts,
    ) -> BuiltinAuthz {
        self.observed.lock().await.push(facts.name.clone());
        BuiltinAuthz::Proceed
    }
}

#[async_trait]
impl waygate_mcp::BuiltinTools for GovBuiltin {
    fn namespace(&self) -> &str {
        "gateway-control"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![tool(
                "gateway-control.quarantine_server",
                "quarantine an upstream",
            )],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "gateway-control".into(),
            required_scope: "mcp:admin".into(),
            summary: "stub control plane".into(),
            tools: vec![BuiltinToolDescriptor {
                name: "quarantine_server".into(),
                description: "quarantine an upstream".into(),
                risk: RiskTier::High,
                side_effects: true,
                pii: false,
            }],
        }
    }

    async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
        vec![tool("gateway-control.quarantine_server", "quarantine")]
    }

    async fn call(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        // Record that the side-effecting handler actually ran. The overlay
        // must return BEFORE this on a determining forbid / step-up.
        self.ran.store(true, Ordering::SeqCst);
        match tool {
            "quarantine_server" => Ok(CallToolResult::success(vec![Content::text("quarantined")])),
            other => Err(McpError::invalid_params(
                format!("unknown gateway-control tool: {other}"),
                None,
            )),
        }
    }
}

/// `AuthzGate` stub returning a fixed verdict, so each branch of the
/// forbid-overlay discriminator can be driven without standing up Cedar. The
/// real engine's "a fired forbid lands in `policy_ids`; a baseline default-deny
/// does not" contract is covered by `waygate-authz`'s own `cedar.rs` tests; here
/// we pin how the dispatch overlay *interprets* each verdict.
struct FixedAuthz(AuthzVerdict);

#[async_trait]
impl AuthzGate for FixedAuthz {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        self.0.clone()
    }
}

struct ResourceAuthz {
    list_allowed: bool,
    read_verdict: AuthzVerdict,
}

impl ResourceAuthz {
    fn allow_read() -> AuthzVerdict {
        AuthzVerdict::Allow {
            policy_ids: vec!["permit-resource-read".to_owned()],
        }
    }

    fn deny_read() -> AuthzVerdict {
        AuthzVerdict::Deny {
            reason: "forbid policies: forbid-resource-read".to_owned(),
            policy_ids: vec!["forbid-resource-read".to_owned()],
            reasons: vec!["resource is restricted".to_owned()],
        }
    }
}

#[async_trait]
impl AuthzGate for ResourceAuthz {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }

    async fn may_list_resources(&self, _principal: &Principal, _server: &str) -> bool {
        self.list_allowed
    }

    async fn authorize_resource_read(
        &self,
        _principal: &Principal,
        _server: &str,
        _uri: &str,
        _risk: RiskTier,
    ) -> AuthzVerdict {
        self.read_verdict.clone()
    }

    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::Allow { policy_ids: vec![] }
    }
}

/// Gate whose built-in authorization reports the engine could not decide.
/// Drives the overlay's fail-closed branch — a state `AuthzVerdict` cannot
/// express (a clean baseline deny and an engine error are byte-identical
/// through it), so only `authorize_builtin_call` can surface it.
struct IndeterminateAuthz;

#[async_trait]
impl AuthzGate for IndeterminateAuthz {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        // The overlay overrides `authorize_builtin_call`, so this is never the
        // path under test — return Allow so a stray consult can't masquerade as
        // the fail-closed behaviour we're asserting.
        AuthzVerdict::Allow { policy_ids: vec![] }
    }
    async fn authorize_builtin_call(
        &self,
        _principal: &Principal,
        _facts: &ToolFacts,
    ) -> BuiltinAuthz {
        BuiltinAuthz::Indeterminate {
            reason: "engine could not evaluate".into(),
        }
    }
}

/// A principal that DOES hold the `mcp:admin` scope floor — so the namespace's
/// own self-gate would admit the call. The overlay tests use this to prove
/// Cedar can narrow *beyond* the floor (block a caller the floor admits).
fn admin_principal() -> Principal {
    let mut p = maker();
    p.scopes = vec!["mcp:admin".into()];
    p
}

fn quarantine_call() -> CallToolRequestParams {
    CallToolRequestParams::new("gateway-control.quarantine_server")
}

#[tokio::test]
async fn continuation_operation_reenters_the_originating_tool_overlay() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(RecordingBuiltinNameAuthz {
        observed: observed.clone(),
    });
    let server =
        GatewayServer::with_authz(catalog, authz).with_builtin_tools(Arc::new(ContinuationBuiltin));

    server
        .dispatch_tool_call(
            CallToolRequestParams::new("continuation.resume"),
            Some(&admin_principal()),
        )
        .await
        .expect("continuation call proceeds");

    assert_eq!(observed.lock().await.as_slice(), ["execute"]);
}

#[tokio::test]
async fn continuation_alias_listing_uses_the_originating_tool_overlay() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(ForbidExecuteBuiltinAuthz);
    let server =
        GatewayServer::with_authz(catalog, authz).with_builtin_tools(Arc::new(ContinuationBuiltin));

    let visible = server.list_visible_tools(Some(&admin_principal())).await;
    assert!(
        visible
            .iter()
            .all(|tool| tool.name.as_ref() != "continuation.resume"),
        "an alias forbidden through its origin must not remain discoverable"
    );

    let err = server
        .dispatch_tool_call(
            CallToolRequestParams::new("continuation.resume"),
            Some(&admin_principal()),
        )
        .await
        .expect_err("the same originating-tool forbid must block invocation");
    assert!(format!("{err}").contains("execute is forbidden"));
}

#[tokio::test]
async fn builtin_overlay_blocks_on_determining_forbid() {
    // A Deny with NON-EMPTY policy_ids == a Cedar `forbid` determined the deny.
    // The overlay blocks even though the principal holds the scope floor, and
    // the side-effecting handler must never run.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Deny {
        reason: "control plane locked by operator policy".into(),
        policy_ids: vec!["50-forbid-gateway-control".into()],
        reasons: vec!["control plane is change-managed".into()],
    }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    let err = server
        .dispatch_tool_call(quarantine_call(), Some(&admin_principal()))
        .await
        .expect_err("a determining forbid must block the built-in");
    assert!(
        format!("{err}").contains("forbidden: gateway-control.quarantine_server"),
        "got: {err}"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the built-in side effect MUST NOT run when a forbid determines the deny"
    );
    let visible = server.list_visible_tools(Some(&admin_principal())).await;
    assert!(
        visible
            .iter()
            .all(|tool| tool.name.as_ref() != "gateway-control.quarantine_server"),
        "a determining forbid must hide the same built-in definition from tools/list",
    );
}

#[tokio::test]
async fn builtin_overlay_allows_on_baseline_default_deny() {
    // A Deny with EMPTY policy_ids is Cedar's baseline default-deny — NO forbid
    // named the namespace. The overlay must NOT treat that as a block: built-ins
    // ship no permits of their own, so a deny-by-default must not lock them out
    // (the scope self-gate is the floor). The stub handler runs.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Deny {
        reason: "default deny".into(),
        policy_ids: vec![],
        reasons: vec![],
    }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    let result = server
        .dispatch_tool_call(quarantine_call(), Some(&admin_principal()))
        .await
        .expect("a baseline default-deny must NOT block a built-in (no lockout)");
    assert!(
        ran.load(Ordering::SeqCst),
        "the built-in must run when no forbid fired"
    );
    assert!(
        result.content.iter().any(|c| c
            .as_text()
            .map(|t| t.text == "quarantined")
            .unwrap_or(false)),
        "the builtin's own success result must surface"
    );
    let visible = server.list_visible_tools(Some(&admin_principal())).await;
    assert!(
        visible
            .iter()
            .any(|tool| tool.name.as_ref() == "gateway-control.quarantine_server"),
        "a clean baseline deny must preserve the scope-gated built-in listing",
    );
}

#[tokio::test]
async fn builtin_overlay_allows_on_allow() {
    // An explicit Allow (an operator wrote a permit naming the built-in) lets
    // the call proceed.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Allow { policy_ids: vec![] }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    server
        .dispatch_tool_call(quarantine_call(), Some(&admin_principal()))
        .await
        .expect("Allow proceeds");
    assert!(ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn builtin_overlay_step_up_required_blocks_with_scope_hint() {
    // StepUpRequired surfaces as an insufficient_scope error carrying the scope
    // to re-authorize with; the side effect does not run.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::StepUpRequired {
        required_scope: "mcp:invoke:high".into(),
        reason: "re-authorize to touch the control plane".into(),
        policy_ids: vec![],
    }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    let err = server
        .dispatch_tool_call(quarantine_call(), Some(&admin_principal()))
        .await
        .expect_err("step-up blocks the call");
    let msg = format!("{err}");
    assert!(msg.contains("step-up required"), "got: {msg}");
    assert!(msg.contains("mcp:invoke:high"), "scope hint missing: {msg}");
    assert!(!ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn builtin_overlay_skipped_without_principal() {
    // disabled auth mode: no principal → the overlay can't classify and is
    // skipped entirely; the built-in self-gate governs. Even a forbid-returning
    // gate is never consulted — the call proceeds to the handler.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Deny {
        reason: "would forbid if consulted".into(),
        policy_ids: vec!["50-forbid-gateway-control".into()],
        reasons: vec![],
    }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    server
        .dispatch_tool_call(quarantine_call(), None)
        .await
        .expect("no principal skips the overlay");
    assert!(
        ran.load(Ordering::SeqCst),
        "overlay must skip (and the handler run) when principal is None"
    );
}

#[tokio::test]
async fn unknown_builtin_is_rejected_before_the_overlay() {
    // A name absent from the canonical catalog has no governance facts. It is
    // refused as unknown before either the Cedar overlay or handler can act.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Deny {
        reason: "would forbid if consulted".into(),
        policy_ids: vec!["50-forbid-gateway-control".into()],
        reasons: vec![],
    }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    let err = server
        .dispatch_tool_call(
            CallToolRequestParams::new("gateway-control.unknown_tool"),
            Some(&admin_principal()),
        )
        .await
        .expect_err("unknown tool");
    assert!(
        format!("{err}").contains("unknown tool: gateway-control.unknown_tool"),
        "catalog authority must reject the name before a phantom forbid: {err}"
    );
    assert!(!ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn builtin_overlay_fails_closed_on_engine_error() {
    // The security core: an authorization-engine failure must NOT wave the
    // built-in through. A clean baseline deny and an engine error are
    // indistinguishable through `AuthzVerdict` (both `Deny` with empty
    // policy_ids), so the overlay consults `authorize_builtin_call`, which
    // reports `Indeterminate` on error — and here the side effect must NOT run.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(IndeterminateAuthz);
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    let err = server
        .dispatch_tool_call(quarantine_call(), Some(&admin_principal()))
        .await
        .expect_err("an engine error must fail closed");
    assert!(
        format!("{err}").contains("authorization unavailable"),
        "got: {err}"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the built-in side effect MUST NOT run when authorization could not be decided"
    );
}

// ---- EMA: resource-scoped (server-bound) tokens are confined away from
// gateway-local built-in namespaces ----
//
// A resource-scoped ID-JAG records `allowed_servers = [one upstream]` in
// `Principal.api_key_profile_restrictions`. Built-ins are dispatched AND listed
// before the upstream invocation gate where that allow-list is otherwise
// enforced, so they must honour the SAME allow-list — otherwise a token
// aud-bound to one upstream that still carries `mcp:admin`/`mcp:observe`/
// `mcp:propose` could reach the gateway control plane. These pin both the
// dispatch and the discovery path, with an unrestricted principal as the
// control showing built-ins are NOT hidden absent a binding.

/// A principal confined to a single upstream via the resource-binding mechanism,
/// yet holding the built-in scope floor (`mcp:admin`) — proving it is the SERVER
/// binding, not a missing scope, that blocks the built-in.
fn example_observability_bound_admin_principal() -> Principal {
    let mut p = admin_principal();
    assert_eq!(
        p.auth_method,
        AuthMethod::Oauth,
        "binding applies to OAuth principals"
    );
    p.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
        profile_id: "id-jag:resource".into(),
        profile_name: "ID-JAG resource binding (example-observability)".into(),
        allowed_servers: Some(vec!["example-observability".into()]),
        allowed_tools: None,
    });
    p
}

#[tokio::test]
async fn resource_bound_principal_cannot_dispatch_builtin() {
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    // Allow at the Cedar overlay so ONLY the resource binding can block.
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Allow { policy_ids: vec![] }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    let err = server
        .dispatch_tool_call(
            quarantine_call(),
            Some(&example_observability_bound_admin_principal()),
        )
        .await
        .expect_err(
            "an example-observability-bound token must not reach gateway-control built-ins",
        );
    // Hermetic: indistinguishable from a non-existent tool — no existence leak.
    assert!(
        format!("{err}").contains("unknown tool"),
        "confined built-in must surface a hermetic not-found, got: {err}"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the built-in side effect MUST NOT run for a resource-bound principal"
    );
}

#[tokio::test]
async fn estate_principal_can_still_dispatch_builtin() {
    // Control: same call, same scope floor, but NO resource binding → allowed.
    let ran = Arc::new(AtomicBool::new(false));
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Allow { policy_ids: vec![] }));
    let server = GatewayServer::with_authz(catalog, authz)
        .with_builtin_tools(Arc::new(GovBuiltin { ran: ran.clone() }));

    server
        .dispatch_tool_call(quarantine_call(), Some(&admin_principal()))
        .await
        .expect("an unrestricted (estate) admin principal still reaches built-ins");
    assert!(
        ran.load(Ordering::SeqCst),
        "an unrestricted principal must still reach the built-in (no over-blocking)"
    );
}

#[tokio::test]
async fn resource_bound_principal_does_not_see_builtins_in_tools_list() {
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let server = GatewayServer::new(catalog).with_builtin_tools(Arc::new(GovBuiltin {
        ran: Arc::new(AtomicBool::new(false)),
    }));

    let bound = example_observability_bound_admin_principal();
    let visible = server.list_visible_tools(Some(&bound)).await;
    assert!(
        !visible
            .iter()
            .any(|t| t.name.as_ref() == "gateway-control.quarantine_server"),
        "an example-observability-bound token must not see gateway-control built-ins in tools/list",
    );

    // Control: an unrestricted admin principal DOES see the built-in, proving
    // the filter hides built-ins only for a server-bound principal.
    let visible_estate = server.list_visible_tools(Some(&admin_principal())).await;
    assert!(
        visible_estate
            .iter()
            .any(|t| t.name.as_ref() == "gateway-control.quarantine_server"),
        "an unrestricted principal must still see built-ins in tools/list",
    );
}

/// A two-tool built-in so a tool-level (`allowed_tools`) profile can be shown to
/// admit one tool and hide its sibling in the SAME namespace.
struct TwoToolBuiltin;

#[async_trait]
impl waygate_mcp::BuiltinTools for TwoToolBuiltin {
    fn namespace(&self) -> &str {
        "gateway-observe"
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![
                tool("gateway-observe.query_audit", "read the audit log"),
                tool("gateway-observe.tail_logs", "tail gateway logs"),
            ],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        let mk = |name: &str, desc: &str| BuiltinToolDescriptor {
            name: name.into(),
            description: desc.into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
        };
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: "gateway-observe".into(),
            required_scope: "mcp:observe".into(),
            summary: "stub observe plane".into(),
            tools: vec![
                mk("query_audit", "read the audit log"),
                mk("tail_logs", "tail gateway logs"),
            ],
        }
    }

    async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
        vec![
            tool("gateway-observe.query_audit", "read the audit log"),
            tool("gateway-observe.tail_logs", "tail gateway logs"),
        ]
    }

    async fn call(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        match tool {
            "query_audit" | "tail_logs" => Ok(CallToolResult::success(vec![Content::text("ok")])),
            other => Err(McpError::invalid_params(
                format!("unknown gateway-observe tool: {other}"),
                None,
            )),
        }
    }
}

/// A profile restricted to ONE built-in tool by `allowed_tools` (no
/// `allowed_servers`): `profile_blocks_server` admits the namespace (an allowed
/// tool has its prefix), so only the tool-level gate can hide the sibling.
fn observe_query_only_principal() -> Principal {
    let mut p = maker();
    p.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
        profile_id: "test:observe-query-only".into(),
        profile_name: "observe query only".into(),
        allowed_servers: None,
        allowed_tools: Some(vec!["gateway-observe.query_audit".into()]),
    });
    p
}

#[tokio::test]
async fn builtin_tool_level_restriction_hides_and_blocks_siblings() {
    // A profile whose `allowed_tools` names one built-in must not leave its
    // siblings in the same namespace reachable — built-in tool restrictions
    // must match the upstream tool-level allow-list.
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);
    let authz: SharedAuthz = Arc::new(FixedAuthz(AuthzVerdict::Allow { policy_ids: vec![] }));
    let server =
        GatewayServer::with_authz(catalog, authz).with_builtin_tools(Arc::new(TwoToolBuiltin));
    let p = observe_query_only_principal();

    // The explicitly-allowed tool dispatches (no over-blocking).
    server
        .dispatch_tool_call(
            CallToolRequestParams::new("gateway-observe.query_audit"),
            Some(&p),
        )
        .await
        .expect("the allow-listed built-in tool must dispatch");

    // The sibling is blocked by the profile, with the hermetic not-found shape —
    // distinct from the built-in's own `unknown gateway-observe tool` error,
    // proving the profile gate fired BEFORE the built-in ran.
    let err = server
        .dispatch_tool_call(
            CallToolRequestParams::new("gateway-observe.tail_logs"),
            Some(&p),
        )
        .await
        .expect_err("a built-in tool outside allowed_tools must be blocked");
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown tool: gateway-observe.tail_logs"),
        "expected the profile's hermetic not-found, got: {msg}"
    );

    // tools/list shows only the allow-listed tool.
    let visible = server.list_visible_tools(Some(&p)).await;
    let names: Vec<&str> = visible.iter().map(|t| t.name.as_ref()).collect();
    assert!(
        names.contains(&"gateway-observe.query_audit"),
        "the allow-listed built-in tool must remain visible: {names:?}"
    );
    assert!(
        !names.contains(&"gateway-observe.tail_logs"),
        "the sibling built-in tool must be hidden: {names:?}"
    );
}

// ---- EMA capability advert (SEP-1724 extensions) ----

#[test]
fn ema_capability_advertised_only_when_opted_in() {
    use rmcp::ServerHandler;
    let catalog: SharedCatalog = FakeCatalog::new(vec![]);

    // Default: EMA NOT advertised — extensions absent, or present without the
    // EMA key. Protects the working OAuth/API-key discovery for deployments that
    // haven't turned EMA on.
    let off = GatewayServer::new(catalog.clone());
    let caps_off = off.get_info().capabilities;
    assert!(
        caps_off
            .extensions
            .as_ref()
            .is_none_or(|e| !e.contains_key(waygate_mcp::server::EMA_EXTENSION_ID)),
        "EMA must NOT be advertised by default",
    );

    // Opted in: the SEP-1724 extension is present with an empty settings object
    // ("supported, no settings"), and the tools capability still stands (the
    // advert is additive).
    let on = GatewayServer::new(catalog).with_ema_capability_advert(true);
    let caps_on = on.get_info().capabilities;
    let ext = caps_on
        .extensions
        .expect("extensions present when EMA advertised");
    let settings = ext
        .get(waygate_mcp::server::EMA_EXTENSION_ID)
        .expect("EMA extension key present when advertised");
    assert!(
        settings.is_empty(),
        "the EMA extension value must be an empty settings object",
    );
    assert!(
        caps_on.tools.is_some(),
        "the tools capability must remain alongside the EMA extension",
    );
}
