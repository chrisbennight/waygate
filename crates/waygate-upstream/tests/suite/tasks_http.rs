//! Native task lifecycle through both HTTP legs, without an execution engine.
use axum::{middleware, Router};
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use waygate_mcp::tasks::TaskRouter;
use waygate_mcp::{AllowAllGate, DefaultInvocationService, GatewayServer, NullSink};
use waygate_oidc::{AuthMethod, Principal};
use waygate_test_support::task_routes::InMemoryTaskRouteStore;
use waygate_upstream::{UpstreamManifest, UpstreamPool};

#[derive(Clone)]
struct Backend {
    state: Arc<Mutex<TaskStatus>>,
    calls: Arc<AtomicUsize>,
    updates: Arc<AtomicUsize>,
    created: String,
    label: &'static str,
    prompt_cancel: bool,
}
impl Backend {
    fn new(label: &'static str, prompt_cancel: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(TaskStatus::InputRequired)),
            calls: Arc::new(AtomicUsize::new(0)),
            updates: Arc::new(AtomicUsize::new(0)),
            created: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            label,
            prompt_cancel,
        }
    }
    fn task(&self) -> Task {
        Task::new(
            "same-upstream-id",
            *self.state.lock().unwrap(),
            &self.created,
            &self.created,
        )
        .with_ttl_ms(172800000)
    }
}
impl ServerHandler for Backend {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::LATEST)
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tool = Tool::new(
            "work",
            "Run a background operation",
            Arc::new(json!({"type":"object"}).as_object().unwrap().clone()),
        );
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }
    async fn call_tool(
        &self,
        _: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if !ctx
            .client_capabilities()
            .is_some_and(|c| c.supports_tasks())
        {
            return Err(ErrorData::new(
                ErrorCode(-32021),
                "Tasks capability required",
                None,
            ));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CallToolResponse::Task(CreateTaskResult::new(self.task())))
    }
    async fn get_task(
        &self,
        request: GetTaskParams,
        _: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        assert_eq!(request.task_id, "same-upstream-id");
        let task = self.task();
        let payload = match task.status {
            TaskStatus::InputRequired => TaskPayload::InputRequired { input_requests: serde_json::from_value(json!({
                "answer": {"method":"elicitation/create", "params":{"mode":"form","message":"Continue?",
                    "requestedSchema":{"type":"object","properties":{"choice":{"type":"string"}},"required":["choice"]}}}
            })).unwrap() },
            TaskStatus::Completed => TaskPayload::Completed { result: serde_json::to_value(CallToolResult::structured(if self.label == "file-report" {
                    json!({"report":self.label,"file":{"uri":"mcp-file://fixture/report","mimeType":"text/plain"}})
                } else { json!({"report":self.label}) })).unwrap().as_object().unwrap().clone() },
            TaskStatus::Cancelled => TaskPayload::Cancelled,
            _ => TaskPayload::Working,
        };
        Ok(GetTaskResult::new(DetailedTask::new(task, payload)))
    }
    async fn update_task(
        &self,
        request: UpdateTaskParams,
        _: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        assert_eq!(request.task_id, "same-upstream-id");
        let mut state = self.state.lock().unwrap();
        if *state == TaskStatus::InputRequired && request.input_responses.contains_key("answer") {
            if request.input_responses["answer"]
                .pointer("/result/action")
                .and_then(Value::as_str)
                != Some("accept")
            {
                return Err(ErrorData::invalid_params(
                    "expected an accepted elicitation result",
                    None,
                ));
            }
            self.updates.fetch_add(1, Ordering::SeqCst);
            *state = TaskStatus::Completed;
        }
        Ok(())
    }
    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        assert_eq!(request.task_id, "same-upstream-id");
        if self.prompt_cancel {
            let mut state = self.state.lock().unwrap();
            if !state.is_terminal() {
                *state = TaskStatus::Cancelled;
            }
        }
        Ok(())
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
async fn backend(handler: Backend) -> (String, tokio::task::JoinHandle<()>) {
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    serve(Router::new().nest_service("/mcp", service)).await
}
fn manifest(name: &str, url: &str) -> UpstreamManifest {
    serde_json::from_value(json!({"name":name,"transport":"http","url":url,
        "tools":[{"name":"work","risk":"low","side_effects":false,"pii":false}]}))
    .unwrap()
}
fn principal(sub: &str) -> Principal {
    Principal {
        sub: sub.into(),
        issuer: "https://test-issuer.invalid".into(),
        tenant: waygate_core::TenantId::default(),
        email: None,
        groups: vec![],
        scopes: vec!["mcp:invoke".into()],
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}
async fn gateway(
    store: Arc<InMemoryTaskRouteStore>,
    manifests: BTreeMap<String, UpstreamManifest>,
) -> (String, tokio::task::JoinHandle<()>) {
    gateway_with_gate(store.clone(), manifests, Arc::new(AllowAllGate)).await
}
async fn gateway_with_gate(
    store: Arc<InMemoryTaskRouteStore>,
    manifests: BTreeMap<String, UpstreamManifest>,
    gate: waygate_mcp::SharedAuthz,
) -> (String, tokio::task::JoinHandle<()>) {
    gateway_with_files(store.clone(), manifests, gate, None).await
}
async fn gateway_with_files(
    store: Arc<InMemoryTaskRouteStore>,
    manifests: BTreeMap<String, UpstreamManifest>,
    gate: waygate_mcp::SharedAuthz,
    files: Option<waygate_mcp::files::SharedFileOutputProcessor>,
) -> (String, tokio::task::JoinHandle<()>) {
    let pool = Arc::new(UpstreamPool::connect(manifests).await);
    let invocation = Arc::new(
        DefaultInvocationService::new(pool.clone(), gate, Arc::new(NullSink))
            .with_file_output_processor(files)
            .with_task_router(Some(Arc::new(TaskRouter::new(store, 129600)))),
    );
    let service = StreamableHttpService::new(
        move || Ok(GatewayServer::new(pool.clone()).with_invocation_service(invocation.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let app = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(
            |mut request: axum::extract::Request, next: middleware::Next| async move {
                let sub = request
                    .headers()
                    .get("x-test-sub")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("alice")
                    .to_owned();
                request.extensions_mut().insert(principal(&sub));
                next.run(request).await
            },
        ));
    serve(app).await
}
async fn rpc(url: &str, method: &str, mut params: Value, sub: &str, tasks: bool) -> Value {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": if tasks {json!({"extensions":{"io.modelcontextprotocol/tasks":{}},"elicitation":{"form":{}}})} else {json!({})}});
    let mut request = reqwest::Client::new()
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("Mcp-Method", method)
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("x-test-sub", sub);
    if let Some(name) = params
        .get("name")
        .or_else(|| params.get("taskId"))
        .and_then(Value::as_str)
    {
        request = request.header("Mcp-Name", name);
    }
    let response = request
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .unwrap();
    let body = response.text().await.unwrap();
    let body = body
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(&body);
    serde_json::from_str(body).unwrap_or_else(|_| panic!("invalid fixture response: {body}"))
}
struct Gate(AtomicBool);
#[async_trait::async_trait]
impl waygate_mcp::AuthzGate for Gate {
    async fn may_discover_server(&self, _: &Principal, _: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _: &waygate_core::Facts) -> waygate_mcp::AuthzVerdict {
        if self.0.load(Ordering::SeqCst) {
            waygate_mcp::AuthzVerdict::Allow { policy_ids: vec![] }
        } else {
            waygate_mcp::AuthzVerdict::Deny {
                reason: "access revoked".into(),
                policy_ids: vec![],
                reasons: vec![],
            }
        }
    }
}
#[tokio::test]
async fn tasks_survive_gateway_replacement_and_route_colliding_ids_without_reexecution() {
    let store = Arc::new(InMemoryTaskRouteStore::default());
    let a = Backend::new("alpha-report", true);
    let b = Backend::new("beta-report", false);
    let (a_url, a_worker) = backend(a.clone()).await;
    let (b_url, b_worker) = backend(b.clone()).await;
    let manifests = BTreeMap::from([
        ("alpha".into(), manifest("alpha", &a_url)),
        ("beta".into(), manifest("beta", &b_url)),
    ]);
    let (first, worker) = gateway(store.clone(), manifests.clone()).await;
    let refused = rpc(
        &first,
        "tools/call",
        json!({"name":"alpha.work"}),
        "alice",
        false,
    )
    .await;
    assert!(refused.get("error").is_some(), "{refused}");
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    let first_task = rpc(
        &first,
        "tools/call",
        json!({"name":"alpha.work"}),
        "alice",
        true,
    )
    .await;
    assert_eq!(first_task["result"]["resultType"], "task", "{first_task}");
    assert_eq!(first_task["result"]["ttlMs"], 129600000);
    let alpha = first_task["result"]["taskId"].as_str().unwrap();
    let second_task = rpc(
        &first,
        "tools/call",
        json!({"name":"beta.work"}),
        "alice",
        true,
    )
    .await;
    let beta = second_task["result"]["taskId"].as_str().unwrap();
    assert_ne!(alpha, beta);
    assert_eq!(alpha.len(), 36);
    assert_eq!(beta.len(), 36);
    worker.abort();
    let gate = Arc::new(Gate(AtomicBool::new(true)));
    let (second, worker) = gateway_with_gate(store.clone(), manifests.clone(), gate.clone()).await;
    let denied = rpc(
        &second,
        "tasks/get",
        json!({"taskId":alpha}),
        "mallory",
        true,
    )
    .await;
    assert!(denied.get("error").is_some());
    let status = rpc(&second, "tasks/get", json!({"taskId":alpha}), "alice", true).await;
    assert_eq!(status["result"]["status"], "input_required", "{status}");
    assert_eq!(
        status["result"]["inputRequests"]["answer"]["method"],
        "elicitation/create"
    );
    let update = json!({"taskId":alpha,"inputResponses":{"answer":{"result":{"action":"accept","content":{"choice":"continue"}}}}});
    gate.0.store(false, Ordering::SeqCst);
    let denied = rpc(&second, "tasks/update", update.clone(), "alice", true).await;
    assert!(denied.get("error").is_some());
    assert_eq!(a.updates.load(Ordering::SeqCst), 0);
    gate.0.store(true, Ordering::SeqCst);
    let invalid = rpc(
        &second,
        "tasks/update",
        json!({"taskId":alpha,"inputResponses":{"answer":{"unexpected":true}}}),
        "alice",
        true,
    )
    .await;
    assert_eq!(invalid["error"]["code"], -32602, "{invalid}");
    assert_eq!(a.updates.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        let ack = rpc(&second, "tasks/update", update.clone(), "alice", true).await;
        assert!(ack.get("error").is_none(), "{ack}");
    }
    assert_eq!(a.updates.load(Ordering::SeqCst), 1);
    let done = rpc(&second, "tasks/get", json!({"taskId":alpha}), "alice", true).await;
    assert_eq!(
        done["result"]["result"]["structuredContent"]["report"], "alpha-report",
        "{done}"
    );
    let ack = rpc(
        &second,
        "tasks/cancel",
        json!({"taskId":beta}),
        "alice",
        true,
    )
    .await;
    assert!(ack.get("error").is_none(), "{ack}");
    let pending = rpc(&second, "tasks/get", json!({"taskId":beta}), "alice", true).await;
    assert_eq!(
        pending["result"]["status"], "input_required",
        "acknowledgement must not invent termination"
    );
    *b.state.lock().unwrap() = TaskStatus::Cancelled;
    let cancelled = rpc(&second, "tasks/get", json!({"taskId":beta}), "alice", true).await;
    assert_eq!(cancelled["result"]["status"], "cancelled");
    let ack = rpc(
        &second,
        "tasks/cancel",
        json!({"taskId":alpha}),
        "alice",
        true,
    )
    .await;
    assert!(ack.get("error").is_none());
    // A late cancellation must not overwrite an already completed result.
    let cancelled = rpc(&second, "tasks/get", json!({"taskId":alpha}), "alice", true).await;
    assert_eq!(cancelled["result"]["status"], "completed");
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
    assert_eq!(b.calls.load(Ordering::SeqCst), 1);
    worker.abort();
    // Reusing a catalog name for a different upstream must not transfer task authority.
    let (changed, worker) = gateway(
        store.clone(),
        BTreeMap::from([("alpha".into(), manifest("alpha", &b_url))]),
    )
    .await;
    let rejected = rpc(
        &changed,
        "tasks/get",
        json!({"taskId":alpha}),
        "alice",
        true,
    )
    .await;
    assert!(rejected.get("error").is_some(), "{rejected}");
    worker.abort();
    // An unavailable origin is an operational error, never a fabricated terminal state.
    a_worker.abort();
    let _ = a_worker.await;
    let (unavailable, worker) = gateway(store.clone(), manifests).await;
    let rejected = rpc(
        &unavailable,
        "tasks/get",
        json!({"taskId":alpha}),
        "alice",
        true,
    )
    .await;
    assert!(rejected.get("error").is_some(), "{rejected}");
    assert!(rejected.get("result").is_none());
    worker.abort();
    let (removed, worker) = gateway(store.clone(), BTreeMap::new()).await;
    assert!(rpc(
        &removed,
        "tasks/get",
        json!({"taskId":alpha}),
        "alice",
        true
    )
    .await
    .get("error")
    .is_some());
    worker.abort();
    b_worker.abort();
}

#[tokio::test]
async fn prompt_cancellation_reports_observed_termination() {
    let store = Arc::new(InMemoryTaskRouteStore::default());
    let upstream = Backend::new("report", true);
    let (url, upstream_worker) = backend(upstream).await;
    let (gateway, worker) = gateway(
        store.clone(),
        BTreeMap::from([("service".into(), manifest("service", &url))]),
    )
    .await;
    let created = rpc(
        &gateway,
        "tools/call",
        json!({"name":"service.work"}),
        "alice",
        true,
    )
    .await;
    let id = created["result"]["taskId"].as_str().unwrap();
    let ack = rpc(
        &gateway,
        "tasks/cancel",
        json!({"taskId":id}),
        "alice",
        true,
    )
    .await;
    assert!(ack.get("error").is_none());
    let status = rpc(&gateway, "tasks/get", json!({"taskId":id}), "alice", true).await;
    assert_eq!(status["result"]["status"], "cancelled");
    worker.abort();
    upstream_worker.abort();
}

struct Files {
    unavailable: AtomicBool,
    published: AtomicUsize,
}
#[async_trait::async_trait]
impl waygate_mcp::files::FileOutputProcessor for Files {
    async fn prepare(
        &self,
        context: waygate_mcp::files::FileOutputContext,
        mut result: CallToolResult,
    ) -> Result<waygate_mcp::files::PreparedFileOutput, ErrorData> {
        assert_eq!(context.principal.unwrap().sub, "alice");
        assert_eq!(context.server, "service");
        assert_eq!(
            result.structured_content.as_ref().unwrap()["file"]["uri"],
            "mcp-file://fixture/report"
        );
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ErrorData::internal_error(
                "fixture storage unavailable",
                None,
            ));
        }
        result.structured_content.as_mut().unwrap()["file"]["uri"] =
            json!("mcp-file://gateway/fixture-report");
        Ok(waygate_mcp::files::PreparedFileOutput {
            result,
            batch_id: Some("batch".into()),
            file_count: 1,
        })
    }
    async fn publish(&self, _: &str, file_count: usize) -> Result<(), ErrorData> {
        assert_eq!(file_count, 1);
        self.published.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn discard(&self, _: &str) {}
}
#[tokio::test]
async fn terminal_file_delivery_can_retry_without_restarting_completed_work() {
    let store = Arc::new(InMemoryTaskRouteStore::default());
    let upstream = Backend::new("file-report", false);
    *upstream.state.lock().unwrap() = TaskStatus::Completed;
    let (url, upstream_worker) = backend(upstream.clone()).await;
    let files = Arc::new(Files {
        unavailable: AtomicBool::new(true),
        published: AtomicUsize::new(0),
    });
    let (gateway, worker) = gateway_with_files(
        store.clone(),
        BTreeMap::from([("service".into(), manifest("service", &url))]),
        Arc::new(AllowAllGate),
        Some(files.clone()),
    )
    .await;
    let created = rpc(
        &gateway,
        "tools/call",
        json!({"name":"service.work"}),
        "alice",
        true,
    )
    .await;
    let id = created["result"]["taskId"].as_str().unwrap();
    let failed = rpc(&gateway, "tasks/get", json!({"taskId":id}), "alice", true).await;
    assert!(failed.get("error").is_some(), "{failed}");
    assert_eq!(*upstream.state.lock().unwrap(), TaskStatus::Completed);
    files.unavailable.store(false, Ordering::SeqCst);
    let done = rpc(&gateway, "tasks/get", json!({"taskId":id}), "alice", true).await;
    assert_eq!(done["result"]["status"], "completed", "{done}");
    assert_eq!(
        done["result"]["result"]["structuredContent"]["file"]["uri"],
        "mcp-file://gateway/fixture-report"
    );
    assert_eq!(files.published.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    worker.abort();
    upstream_worker.abort();
}

struct RequestGate {
    expected: waygate_core::RequestFacts,
    admitted: AtomicUsize,
}

#[async_trait::async_trait]
impl waygate_mcp::AuthzGate for RequestGate {
    async fn may_discover_server(&self, _: &Principal, _: &str) -> bool {
        true
    }

    async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> waygate_mcp::AuthzVerdict {
        if facts.request.as_ref() == Some(&self.expected) {
            self.admitted.fetch_add(1, Ordering::SeqCst);
            waygate_mcp::AuthzVerdict::Allow { policy_ids: vec![] }
        } else {
            waygate_mcp::AuthzVerdict::Deny {
                reason: "original request facts required".into(),
                policy_ids: vec![],
                reasons: vec![],
            }
        }
    }
}

#[tokio::test]
async fn lifecycle_preserves_argument_dependent_policy_facts_after_gateway_replacement() {
    let store = Arc::new(InMemoryTaskRouteStore::default());
    let arguments = json!({"to":["colleague@example.com"],"body":"original message"})
        .as_object()
        .unwrap()
        .clone();
    let gate = Arc::new(RequestGate {
        expected: waygate_core::RequestFacts {
            email_recipients: Some(waygate_core::EmailRecipients::from_arguments(Some(
                &arguments,
            ))),
            argument_hash: waygate_catalog::argument_hash(Some(&arguments)),
            ..Default::default()
        },
        admitted: AtomicUsize::new(0),
    });
    let upstream = Backend::new("report", true);
    let (url, upstream_worker) = backend(upstream.clone()).await;
    let manifests = BTreeMap::from([("service".into(), manifest("service", &url))]);
    let (first, worker) = gateway_with_gate(store.clone(), manifests.clone(), gate.clone()).await;
    let created = rpc(
        &first,
        "tools/call",
        json!({"name":"service.work","arguments":arguments}),
        "alice",
        true,
    )
    .await;
    let id = created["result"]["taskId"].as_str().unwrap();
    worker.abort();
    let (second, worker) = gateway_with_gate(store.clone(), manifests, gate.clone()).await;
    let status = rpc(&second, "tasks/get", json!({"taskId":id}), "alice", true).await;
    assert_eq!(status["result"]["status"], "input_required", "{status}");
    let updated = rpc(&second, "tasks/update", json!({"taskId":id,"inputResponses":{"answer":{"result":{"action":"accept","content":{"choice":"continue"}}}}}), "alice", true).await;
    assert!(updated.get("error").is_none(), "{updated}");
    let cancelled = rpc(&second, "tasks/cancel", json!({"taskId":id}), "alice", true).await;
    assert!(cancelled.get("error").is_none(), "{cancelled}");
    let completed = rpc(&second, "tasks/get", json!({"taskId":id}), "alice", true).await;
    assert_eq!(completed["result"]["status"], "completed", "{completed}");
    assert_eq!(gate.admitted.load(Ordering::SeqCst), 5);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.updates.load(Ordering::SeqCst), 1);
    worker.abort();
    upstream_worker.abort();
}
