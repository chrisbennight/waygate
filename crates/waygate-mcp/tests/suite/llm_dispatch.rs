//! Pins the LLM dispatch branch: a recognized model traverses the
//! SAME `DefaultInvocationService` pipeline as an MCP tool call (invariant I1),
//! firing the shared authorize/audit gates, and a non-streaming call returns
//! `InvocationResponse::UnaryValue` with the provider's JSON body.
//!
//! No real network / credentials: the provider is a loopback `axum` server and
//! the credential store is seeded via `from_vars`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use uuid::Uuid;

use rmcp::model::{CallToolResult, ContentBlock as Content, Tool};
use rmcp::ErrorData as McpError;
use waygate_invocation::{
    InvocationError, InvocationRequest, InvocationResponse, InvocationService,
};
use waygate_mcp::audit::{
    AuditEvent, AuditOutcome, EvidenceCategory, EvidenceError, EvidenceRecorder,
};
use waygate_mcp::authz::{AllowAllGate, AuthzGate, AuthzVerdict, ToolFacts};
use waygate_mcp::catalog::UpstreamCatalog;
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::DefaultInvocationService;
use waygate_oidc::Principal;

use waygate_llm_credentials::{LlmCredentialStore, LlmProvider};
use waygate_llm_dispatch::{
    LlmDispatcher, LlmModelResolver, LlmOperation, ModelRisk, ResolvedModel, ResolvedRoute,
    StaticModelResolver,
};
use waygate_llm_providers::ProviderClient;
use waygate_llm_translate::UpstreamProtocol;

// ---- loopback provider -----------------------------------------------------

#[derive(Default)]
struct Captured {
    /// Set on every inbound request — lets a test assert the provider was
    /// (or was not) contacted.
    called: bool,
    authorization: Option<String>,
    model: Option<String>,
    /// The full parsed upstream request body — lets a test assert a field
    /// (e.g. `response_format`) was rendered through to the provider.
    body: Option<Value>,
}

async fn provider_handler(
    State(cap): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    {
        let mut c = cap.lock().unwrap();
        c.called = true;
        if let Ok(v) = serde_json::from_str::<Value>(&body) {
            c.authorization = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string);
            c.model = v.get("model").and_then(Value::as_str).map(str::to_string);
            c.body = Some(v);
        }
    }
    let resp = json!({
        "id": "chatcmpl-7",
        "model": "served-x",
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1}
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(resp))
        .unwrap()
}

async fn spawn_provider(cap: Arc<Mutex<Captured>>) -> SocketAddr {
    let app = Router::new()
        .route("/chat/completions", post(provider_handler))
        .with_state(cap);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A capturing provider on the Anthropic `/messages` path — lets a test assert
/// whether an Anthropic-routed call reached the provider (it must not, when a
/// pre-dispatch gate rejects it).
async fn spawn_capture_messages(cap: Arc<Mutex<Captured>>) -> SocketAddr {
    let app = Router::new()
        .route("/messages", post(provider_handler))
        .with_state(cap);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A provider that returns an OpenAI-style SSE stream: two content deltas, a
/// usage-bearing terminal chunk, then `[DONE]`.
async fn stream_provider_handler() -> Response {
    let sse = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"llo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n",
        "data: [DONE]\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

async fn spawn_stream_provider() -> SocketAddr {
    let app = Router::new().route("/chat/completions", post(stream_provider_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A provider/proxy that closes the stream BEFORE the OpenAI `[DONE]` sentinel:
/// one content delta, then EOF. Per the OpenAI-chat SSE protocol this is a
/// truncated stream — a failure, not a clean completion.
async fn stream_truncated_provider_handler() -> Response {
    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n";
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

async fn spawn_truncated_stream_provider() -> SocketAddr {
    let app = Router::new().route("/chat/completions", post(stream_truncated_provider_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A provider that returns 200 OK headers immediately, then a response body that
/// never produces bytes and never closes — a slow/drip provider that would hold
/// a unary call open indefinitely without a total per-request deadline.
async fn stall_provider_handler() -> Response {
    let body = Body::from_stream(futures::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

async fn spawn_stall_provider() -> SocketAddr {
    let app = Router::new().route("/chat/completions", post(stall_provider_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

// ---- pipeline collaborators (fakes) ---------------------------------------

/// Trivial catalog — the LLM fast-path never calls it, but the service
/// constructor requires one.
struct FakeCatalog;

#[async_trait]
impl UpstreamCatalog for FakeCatalog {
    async fn list_servers(&self) -> Vec<String> {
        Vec::new()
    }
    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(Vec::new())
    }
    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        // The MCP path is not exercised by these tests; if it ever is, fail
        // loudly rather than masquerade as a successful tool call.
        Ok(CallToolResult::success(vec![Content::text(
            "unexpected MCP dispatch in an LLM test",
        )]))
    }
    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        ToolFacts {
            server: server.to_owned(),
            name: tool_name.to_owned(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
}

/// Authz gate returning a fixed verdict — lets a test prove the LLM path runs
/// through `authorize`.
struct FixedGate(AuthzVerdict);

#[async_trait]
impl AuthzGate for FixedGate {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        self.0.clone()
    }
}

/// Budget gate returning a fixed decision — `Some` rejects (over budget),
/// `None` allows. Lets a test prove the LLM path consults the budget gate and
/// refuses before dispatch.
struct FakeBudgetGate(Option<waygate_mcp::budget::BudgetRejection>);

#[async_trait]
impl waygate_mcp::budget::LlmBudgetGate for FakeBudgetGate {
    async fn check(
        &self,
        _tenant_id: &str,
        _principal_sub: Option<&str>,
        _model_alias: &str,
    ) -> Option<waygate_mcp::budget::BudgetRejection> {
        self.0.clone()
    }
}

/// Recorder that captures every non-required event and counts the selected
/// posture so tests can assert both the row and its chaining contract.
#[derive(Default)]
struct RecordingSink {
    best_effort: Mutex<Vec<AuditEvent>>,
    chained_best_effort: std::sync::atomic::AtomicUsize,
    unchained_best_effort: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl EvidenceRecorder for RecordingSink {
    async fn record_required(&self, event: AuditEvent) -> Result<Uuid, EvidenceError> {
        Ok(event.id)
    }
    async fn record_chained_best_effort(&self, event: AuditEvent) {
        self.chained_best_effort
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.best_effort.lock().unwrap().push(event);
    }
    async fn record_best_effort(&self, event: AuditEvent) {
        self.unchained_best_effort
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.best_effort.lock().unwrap().push(event);
    }
}

/// Captures the usage rows the LLM path records, so a test can assert the
/// per-call usage ledger gets the InferenceRecord's tokens / served model /
/// finish reason / identity.
#[derive(Default)]
struct RecordingUsage {
    rows: Mutex<Vec<waygate_mcp::usage::LlmUsageRow>>,
}

#[async_trait]
impl waygate_mcp::usage::LlmUsageRecorder for RecordingUsage {
    async fn record_usage(&self, row: waygate_mcp::usage::LlmUsageRow) {
        self.rows.lock().unwrap().push(row);
    }
}

/// Recorder whose non-required write parks on a semaphore until the test
/// releases it. Lets a test suspend a streamed call's terminal audit write
/// mid-flight, drop the stream, and prove the Drop net still records the
/// outcome (never zero rows). `entered` counts how many writes have begun.
struct GatedSink {
    events: Mutex<Vec<AuditEvent>>,
    entered: std::sync::atomic::AtomicUsize,
    gate: tokio::sync::Semaphore,
}

impl GatedSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            entered: std::sync::atomic::AtomicUsize::new(0),
            gate: tokio::sync::Semaphore::new(0),
        }
    }
    fn entered(&self) -> usize {
        self.entered.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl EvidenceRecorder for GatedSink {
    async fn record_required(&self, event: AuditEvent) -> Result<Uuid, EvidenceError> {
        Ok(event.id)
    }
    async fn record_chained_best_effort(&self, event: AuditEvent) {
        self.record_best_effort(event).await;
    }
    async fn record_best_effort(&self, event: AuditEvent) {
        self.entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Park until the test grants a permit. A write whose future is dropped
        // here (the stream was cancelled mid-finalize) never reaches the push.
        let _permit = self.gate.acquire().await.expect("gate not closed");
        self.events.lock().unwrap().push(event);
    }
}

/// Gate that captures the PIP `Facts` it was handed — so a test can assert
/// how the LLM path classified the resource — and returns a fixed verdict.
struct CapturingGate {
    verdict: AuthzVerdict,
    captured: Mutex<Option<waygate_core::Facts>>,
}

#[async_trait]
impl AuthzGate for CapturingGate {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
        *self.captured.lock().unwrap() = Some(facts.clone());
        self.verdict.clone()
    }
}

fn principal() -> Principal {
    Principal {
        sub: "carol".into(),
        email: Some("carol@example.test".into()),
        groups: vec!["mcp-users".into()],
        issuer: "https://auth.example.test".into(),
        scopes: vec!["mcp:invoke".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn store() -> Arc<LlmCredentialStore> {
    Arc::new(LlmCredentialStore::from_vars([(
        "LLM_CRED_OPENROUTER_MAIN".to_string(),
        "sk-test-key".to_string(),
    )]))
}

fn resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    resolver_named(addr, "gpt-x")
}

fn resolver_named(addr: SocketAddr, model: &str) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        model,
        ResolvedModel {
            operation: LlmOperation::Chat,
            route: ResolvedRoute {
                provider: LlmProvider::OpenRouter,
                credential_label: "MAIN".into(),
                base_url: format!("http://{addr}"),
                path: "chat/completions".into(),
                upstream_model: "openrouter/served-x".into(),
                protocol: UpstreamProtocol::OpenAiChat,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::High,
            ttfb: None,
            cache_ttl: None,
        },
    ))
}

fn chat_args() -> Map<String, Value> {
    json!({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]})
        .as_object()
        .cloned()
        .unwrap()
}

/// Loopback Anthropic Messages SSE provider: the event sequence Anthropic streams.
async fn anthropic_stream_provider_handler() -> Response {
    let sse = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-served-x\",\"usage\":{\"input_tokens\":5}}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"He\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"llo\"}}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

async fn spawn_anthropic_stream_provider() -> SocketAddr {
    let app = Router::new().route("/messages", post(anthropic_stream_provider_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Anthropic credential (first-party `x-api-key` — a bare key, not an OAuth blob).
fn anthropic_store() -> Arc<LlmCredentialStore> {
    Arc::new(LlmCredentialStore::from_vars([(
        "LLM_CRED_ANTHROPIC_MAIN".to_string(),
        "sk-ant-api03-test".to_string(),
    )]))
}

fn anthropic_resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "claude-x",
        ResolvedModel {
            operation: LlmOperation::Chat,
            route: ResolvedRoute {
                provider: LlmProvider::Anthropic,
                credential_label: "MAIN".into(),
                base_url: format!("http://{addr}"),
                path: "messages".into(),
                upstream_model: "claude-served-x".into(),
                protocol: UpstreamProtocol::AnthropicMessages,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::High,
            ttfb: None,
            cache_ttl: None,
        },
    ))
}

/// Loopback OpenAI **Responses** SSE provider: the named-event sequence a
/// Responses upstream streams (created → text deltas → completed). No `[DONE]`.
async fn responses_stream_provider_handler() -> Response {
    let sse = concat!(
        "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"model\":\"gpt-served-x\",\"status\":\"in_progress\",\"output\":[]}}\n\n",
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"He\"}\n\n",
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"llo\"}\n\n",
        "event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":3,\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"model\":\"gpt-served-x\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Hello\"}]}],\"usage\":{\"input_tokens\":5,\"output_tokens\":2,\"total_tokens\":7}}}\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

async fn spawn_responses_stream_provider() -> SocketAddr {
    let app = Router::new().route("/responses", post(responses_stream_provider_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn responses_resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "gpt-resp",
        ResolvedModel {
            operation: LlmOperation::Chat,
            route: ResolvedRoute {
                provider: LlmProvider::OpenRouter,
                credential_label: "MAIN".into(),
                base_url: format!("http://{addr}"),
                path: "responses".into(),
                upstream_model: "gpt-served-x".into(),
                protocol: UpstreamProtocol::OpenAiResponses,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::High,
            ttfb: None,
            cache_ttl: None,
        },
    ))
}

#[tokio::test]
async fn responses_surface_streaming_relays_named_events_through_egress() {
    // R3a: a /v1/responses streaming caller routed to an OpenAI-Responses upstream
    // receives the provider's Responses events relayed 1:1 as NAMED SSE events
    // (each chunk carries its `event_name`). There is no `[DONE]` sentinel — the
    // terminal frame is the named `response.completed` event, carrying the full
    // final response. The outcome audits exactly once at stream close.
    use futures::StreamExt;

    let addr = spawn_responses_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());
    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, responses_resolver(addr));

    let args = json!({"model": "gpt-resp", "input": "hi", "stream": true})
        .as_object()
        .cloned()
        .unwrap();
    let req = InvocationRequest::new("llm", "gpt-resp")
        .with_arguments(Some(args))
        .with_responses_surface(true);
    let resp = svc.invoke(None, req).await.expect("invoke");
    let mut stream = match resp {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };
    let mut chunks = Vec::new();
    while let Some(item) = stream.next().await {
        chunks.push(item.expect("chunk"));
    }

    // Every forwarded frame is a NAMED Responses event; none is the chat `[DONE]`.
    assert!(
        chunks.iter().all(|c| c.event_name.is_some()),
        "the Responses egress emits only named events"
    );
    assert!(
        chunks.iter().all(|c| c.event.as_str() != Some("[DONE]")),
        "the Responses transport has no [DONE] sentinel"
    );
    let names: Vec<&str> = chunks
        .iter()
        .filter_map(|c| c.event_name.as_deref())
        .collect();
    assert_eq!(names.first(), Some(&"response.created"));
    assert!(names.contains(&"response.output_text.delta"));
    assert_eq!(names.last(), Some(&"response.completed"));
    // A text delta was relayed verbatim.
    assert!(chunks
        .iter()
        .any(|c| c.event.to_string().contains("\"delta\":\"He\"")));
    // The terminal frame is the named `response.completed`, carrying the full body.
    let last = chunks.last().expect("a frame");
    assert!(last.terminal, "response.completed is the terminal frame");
    assert_eq!(last.event_name.as_deref(), Some("response.completed"));
    assert_eq!(last.event["response"]["status"], "completed");
    // Audited exactly once, at stream close (deferred — not before).
    assert_eq!(
        sink.best_effort.lock().unwrap().len(),
        1,
        "the outcome is audited exactly once, at stream close"
    );
}

#[tokio::test]
async fn responses_surface_streaming_translates_anthropic_to_responses_events() {
    // R3b: a /v1/responses streaming caller on a NON-Responses upstream (Anthropic)
    // has its normalized chat-chunk stream LIFTED into Responses streaming events:
    // response.created → output_item.added(message) → content_part.added →
    // output_text.delta(s) → the close events → response.completed. Every chunk is
    // a NAMED event; there is no [DONE] sentinel; the audit fires once at close.
    use futures::StreamExt;

    let addr = spawn_anthropic_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, anthropic_resolver(addr));

    let args = json!({"model": "claude-x", "input": "hi", "stream": true})
        .as_object()
        .cloned()
        .unwrap();
    let req = InvocationRequest::new("llm", "claude-x")
        .with_arguments(Some(args))
        .with_responses_surface(true);
    let resp = svc.invoke(None, req).await.expect("invoke");
    let mut stream = match resp {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };
    let mut chunks = Vec::new();
    while let Some(item) = stream.next().await {
        chunks.push(item.expect("chunk"));
    }

    // Every forwarded frame is a NAMED Responses event; none is the chat [DONE].
    assert!(
        chunks.iter().all(|c| c.event_name.is_some()),
        "the lifted Responses egress emits only named events"
    );
    assert!(
        chunks.iter().all(|c| c.event.as_str() != Some("[DONE]")),
        "the Responses transport has no [DONE] sentinel"
    );
    let names: Vec<&str> = chunks
        .iter()
        .filter_map(|c| c.event_name.as_deref())
        .collect();
    assert_eq!(names.first(), Some(&"response.created"));
    assert!(names.contains(&"response.output_item.added"));
    assert!(names.contains(&"response.content_part.added"));
    assert!(names.contains(&"response.output_text.delta"));
    assert_eq!(names.last(), Some(&"response.completed"));
    // The Anthropic text ("He" + "llo") was lifted into output_text deltas.
    let delta_text: String = chunks
        .iter()
        .filter(|c| c.event_name.as_deref() == Some("response.output_text.delta"))
        .filter_map(|c| c.event["delta"].as_str())
        .collect();
    assert_eq!(delta_text, "Hello");
    // The terminal frame is response.completed, carrying the assembled message.
    let last = chunks.last().expect("a frame");
    assert!(last.terminal);
    assert_eq!(last.event_name.as_deref(), Some("response.completed"));
    assert_eq!(last.event["response"]["status"], "completed");
    assert_eq!(
        last.event["response"]["output"][0]["content"][0]["text"],
        "Hello"
    );
    // Anthropic folds usage into the record (not the chat chunks); the terminal
    // response still carries it (input_tokens 5 + output_tokens 2 from the loopback).
    assert_eq!(last.event["response"]["usage"]["input_tokens"], 5);
    assert_eq!(last.event["response"]["usage"]["output_tokens"], 2);
    assert_eq!(last.event["response"]["usage"]["total_tokens"], 7);
    // Audited exactly once, at stream close.
    assert_eq!(sink.best_effort.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn recognized_model_returns_unary_value_through_the_pipeline() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    let resp = svc.invoke(None, req).await.expect("invoke");

    match resp {
        InvocationResponse::UnaryValue(body) => {
            assert_eq!(body["model"], "served-x");
            assert_eq!(body["usage"]["prompt_tokens"], 3);
        }
        other => panic!("expected UnaryValue, got {other:?}"),
    }

    // The dispatcher resolved the injected bearer and sent the *upstream* model.
    let c = cap.lock().unwrap();
    assert_eq!(c.authorization.as_deref(), Some("Bearer sk-test-key"));
    assert_eq!(c.model.as_deref(), Some("openrouter/served-x"));

    // The outcome was audited (the call shows up in the activity feed) under
    // the inference plane — `llm_completion`, not the MCP-tool `invocation`
    // category — so usage/cost analytics and SIEM routing can separate them.
    let rows = sink.best_effort.lock().unwrap();
    assert_eq!(rows.len(), 1, "one audit row");
    assert_eq!(
        rows[0].category,
        EvidenceCategory::LlmCompletion,
        "LLM completion must audit under llm_completion, not invocation"
    );
    assert_eq!(
        sink.chained_best_effort
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "LLM outcomes must extend the evidence chain"
    );
    assert_eq!(
        sink.unchained_best_effort
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "LLM outcomes must not use unchained best effort"
    );
}

#[tokio::test]
async fn response_format_is_rendered_through_to_an_openai_compatible_upstream() {
    // Structured output on an OpenAI-chat route is admitted (no longer rejected
    // at translate) and forwarded 1:1 to the upstream.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let mut args = chat_args();
    args.insert(
        "response_format".into(),
        json!({"type": "json_schema", "json_schema": {
            "name": "Out", "strict": true, "schema": {"type": "object"}
        }}),
    );
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(args));
    svc.invoke(None, req).await.expect("invoke");

    let c = cap.lock().unwrap();
    assert!(c.called, "the upstream was contacted");
    let body = c.body.as_ref().expect("captured upstream body");
    // OpenAI's native nested shape, rendered through to the provider.
    assert_eq!(body["response_format"]["type"], "json_schema");
    assert_eq!(body["response_format"]["json_schema"]["name"], "Out");
    assert_eq!(body["response_format"]["json_schema"]["strict"], true);
}

#[tokio::test]
async fn response_format_on_anthropic_is_emulated_through_to_provider() {
    // Anthropic structured output is emulated by forcing a synthetic tool,
    // so a NON-streaming request succeeds and reaches the provider rather
    // than being rejected.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_capture_messages(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, anthropic_resolver(addr));

    let mut args = json!({"model": "claude-x", "messages": [{"role": "user", "content": "hi"}]})
        .as_object()
        .cloned()
        .unwrap();
    args.insert("response_format".into(), json!({"type": "json_object"}));
    let req = InvocationRequest::new("llm", "claude-x").with_arguments(Some(args));
    svc.invoke(None, req).await.expect("invoke");

    let c = cap.lock().unwrap();
    assert!(
        c.called,
        "emulation contacts the provider (no longer rejected)"
    );
    let body = c.body.as_ref().expect("captured upstream body");
    // The emulation rendered exactly one forced tool with a tool-choice on it.
    assert_eq!(body["tools"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["tool_choice"]["type"], "tool");
}

#[tokio::test]
async fn streaming_structured_output_on_anthropic_is_admitted_and_streams() {
    // The Anthropic structured-output emulation streams as a tool call that
    // is translated (unwound to content), so a STREAMING response_format on
    // Anthropic is admitted and streams rather than being rejected.
    let addr = spawn_anthropic_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, anthropic_resolver(addr));

    let mut args = json!({"model": "claude-x", "messages": [{"role": "user", "content": "hi"}], "stream": true})
        .as_object()
        .cloned()
        .unwrap();
    args.insert("response_format".into(), json!({"type": "json_object"}));
    let req = InvocationRequest::new("llm", "claude-x").with_arguments(Some(args));

    let resp = svc.invoke(None, req).await.expect("invoke");
    assert!(
        matches!(resp, InvocationResponse::Stream(_)),
        "streaming structured output on Anthropic must be admitted and stream"
    );
}

#[tokio::test]
async fn tools_are_rendered_through_to_an_openai_compatible_upstream() {
    // tools / tool_choice on an OpenAI-chat route are admitted and forwarded 1:1.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let mut args = chat_args();
    args.insert(
        "tools".into(),
        json!([{"type": "function", "function": {
            "name": "get_weather", "parameters": {"type": "object"}
        }}]),
    );
    args.insert("tool_choice".into(), json!("auto"));
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(args));
    svc.invoke(None, req).await.expect("invoke");

    let c = cap.lock().unwrap();
    let body = c.body.as_ref().expect("captured upstream body");
    assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
    assert_eq!(body["tool_choice"], "auto");
}

#[tokio::test]
async fn streaming_tools_on_anthropic_is_admitted_and_streams() {
    // Streaming tool-call deltas are translated for Anthropic, so a
    // streaming request carrying `tools` is admitted and streams rather
    // than being rejected.
    let addr = spawn_anthropic_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, anthropic_resolver(addr));

    let mut args = json!({"model": "claude-x", "messages": [{"role": "user", "content": "hi"}], "stream": true})
        .as_object()
        .cloned()
        .unwrap();
    args.insert(
        "tools".into(),
        json!([{"type": "function", "function": {"name": "f", "parameters": {}}}]),
    );
    let req = InvocationRequest::new("llm", "claude-x").with_arguments(Some(args));

    let resp = svc.invoke(None, req).await.expect("invoke");
    assert!(
        matches!(resp, InvocationResponse::Stream(_)),
        "streaming tools on Anthropic must be admitted and stream"
    );
}

#[tokio::test]
async fn unary_call_records_a_usage_row() {
    // A completed unary LLM call persists exactly one usage row
    // carrying the InferenceRecord's tokens / served model / finish reason and
    // the caller's identity (metadata only — never content).
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr))
            .with_llm_usage_store(usage.clone());

    // Principal present so the row carries identity (tenant + sub).
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    svc.invoke(Some(&principal()), req).await.expect("invoke");

    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 1, "one usage row recorded");
    let r = &rows[0];
    assert_eq!(r.model_alias, "gpt-x");
    assert_eq!(r.provider, "openrouter");
    // The loopback provider reports model "served-x" and usage 3/1.
    assert_eq!(r.model_served.as_deref(), Some("served-x"));
    assert_eq!(r.input_tokens, Some(3));
    assert_eq!(r.output_tokens, Some(1));
    assert_eq!(r.finish_reason.as_deref(), Some("stop"));
    assert_eq!(r.principal_sub.as_deref(), Some("carol"));
    assert!(!r.refusal);
}

#[tokio::test]
async fn llm_call_authorizes_as_a_model_resource_with_no_step_up() {
    // The LLM path must hand the gate facts that classify the resource as a
    // `Model` (resource_type) and carry NO step-up scope — models are not
    // step-up-gated (model access is a Cedar-permit concern, not
    // freshness). Pins the fact-stamping in `invoke_llm`.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let gate = Arc::new(CapturingGate {
        verdict: AuthzVerdict::Allow { policy_ids: vec![] },
        captured: Mutex::new(None),
    });

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc = DefaultInvocationService::new(Arc::new(FakeCatalog), gate.clone(), sink.clone())
        .with_llm(dispatcher, resolver(addr));

    // Principal present so the gate (and the fact-stamping) runs.
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    svc.invoke(Some(&principal()), req).await.expect("invoke");

    let facts = gate
        .captured
        .lock()
        .unwrap()
        .clone()
        .expect("authorize saw the facts");
    assert_eq!(
        facts.resource.resource_type.as_deref(),
        Some("model"),
        "an LLM model authorizes as a Model resource, not a tool"
    );
    assert_eq!(
        facts.action.required_scope.as_deref(),
        None,
        "a model carries no step-up scope (model access is a permit concern, not freshness)"
    );
    assert_eq!(facts.resource.server, "llm");
    assert_eq!(facts.resource.tool, "gpt-x");
}

#[tokio::test]
async fn llm_success_row_records_fired_model_policy_ids() {
    // A model call authorizes through the same
    // gate as a tool call and can match a Cedar Model permit, so its
    // `llm_completion` SUCCESS audit row must record the fired permit ids —
    // otherwise the policy-id reverse lookup would miss successful model
    // decisions. The tool-call twin is `audit::success_records_fired_policy_ids`.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let gate = Arc::new(CapturingGate {
        verdict: AuthzVerdict::Allow {
            policy_ids: vec!["10-baseline-models".into()],
        },
        captured: Mutex::new(None),
    });

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc = DefaultInvocationService::new(Arc::new(FakeCatalog), gate.clone(), sink.clone())
        .with_llm(dispatcher, resolver(addr));

    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    svc.invoke(Some(&principal()), req).await.expect("invoke");

    let rows = sink.best_effort.lock().unwrap();
    assert_eq!(rows.len(), 1, "one audit row");
    assert_eq!(rows[0].category, EvidenceCategory::LlmCompletion);
    assert_eq!(rows[0].outcome, AuditOutcome::Success);
    assert_eq!(
        rows[0].policy_ids,
        vec!["10-baseline-models".to_string()],
        "the model-call success row must record the fired Cedar permit ids",
    );
}

#[tokio::test]
async fn authorize_denies_on_the_llm_path_before_dispatch() {
    // A denying gate must block the LLM call (proving the LLM path runs the
    // shared authorize stage, invariant I1) — and the provider must never be
    // hit. Point at an unroutable base so a dispatch would fail loudly.
    let sink = Arc::new(RecordingSink::default());
    let unroutable = Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "gpt-x",
        ResolvedModel {
            operation: LlmOperation::Chat,
            route: ResolvedRoute {
                provider: LlmProvider::OpenRouter,
                credential_label: "MAIN".into(),
                base_url: "http://127.0.0.1:1".into(),
                path: "chat/completions".into(),
                upstream_model: "openrouter/served-x".into(),
                protocol: UpstreamProtocol::OpenAiChat,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::High,
            ttfb: None,
            cache_ttl: None,
        },
    )) as Arc<dyn LlmModelResolver>;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let deny = AuthzVerdict::Deny {
        reason: "policy".into(),
        policy_ids: vec![],
        reasons: vec![],
    };
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(FixedGate(deny)),
        sink.clone(),
    )
    .with_llm(dispatcher, unroutable);

    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    let err = svc.invoke(Some(&principal()), req).await.unwrap_err();
    assert!(
        matches!(err, InvocationError::Forbidden { .. }),
        "got {err:?}"
    );

    // Regression guard: the denial row is
    // built by the SHARED authorize gate (not the LLM completion emitter), yet
    // it must still route to the inference plane. Proves the gate inherits
    // `ctx.audit_category` (set to LlmCompletion before the gates) rather than
    // falling back to the default `Invocation`.
    let rows = sink.best_effort.lock().unwrap();
    assert_eq!(rows.len(), 1, "denial audited exactly once");
    assert_eq!(rows[0].outcome, AuditOutcome::Denied);
    assert_eq!(
        rows[0].category,
        EvidenceCategory::LlmCompletion,
        "an LLM-path denial must audit under llm_completion, not invocation"
    );
}

#[tokio::test]
async fn llm_budget_exhausted_refuses_before_dispatch() {
    // An exhausted budget refuses the call with BudgetExceeded,
    // BEFORE the irreversible provider dispatch (I2), and audits the denial.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let gate = Arc::new(FakeBudgetGate(Some(waygate_mcp::budget::BudgetRejection {
        dimension: "tokens".into(),
        reason: "1000 tokens used >= 500 limit over the last 86400s".into(),
    })));

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr))
            .with_llm_budget(gate);

    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    let err = svc.invoke(Some(&principal()), req).await.unwrap_err();
    match err {
        InvocationError::BudgetExceeded { dimension, .. } => assert_eq!(dimension, "tokens"),
        other => panic!("expected BudgetExceeded, got {other:?}"),
    }
    // I2: the provider must never be contacted once the budget is exhausted.
    assert!(
        !cap.lock().unwrap().called,
        "provider must not be hit when the budget is exhausted"
    );
    // The denial is audited (one Denied row).
    assert_eq!(
        sink.best_effort.lock().unwrap().len(),
        1,
        "budget denial is audited exactly once"
    );
}

#[tokio::test]
async fn llm_call_within_budget_proceeds() {
    // A budget gate that does not reject (within budget) must not block the
    // call — it dispatches and returns normally.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let gate = Arc::new(FakeBudgetGate(None));

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr))
            .with_llm_budget(gate);

    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    let resp = svc.invoke(Some(&principal()), req).await.expect("invoke");
    assert!(
        matches!(resp, InvocationResponse::UnaryValue(_)),
        "within-budget call proceeds to dispatch"
    );
    assert!(cap.lock().unwrap().called, "provider was contacted");
}

#[tokio::test]
async fn streaming_request_yields_sse_chunks_and_audits_at_stream_close() {
    use futures::StreamExt;

    let addr = spawn_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let args = json!({
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
    .as_object()
    .cloned()
    .unwrap();
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(args));
    let resp = svc.invoke(None, req).await.expect("invoke");

    let mut stream = match resp {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };

    // The outcome audit must NOT have fired yet — it finalizes at stream CLOSE
    // (the gates fired before the stream was returned).
    assert!(
        sink.best_effort.lock().unwrap().is_empty(),
        "the outcome audit must defer to stream close"
    );

    let mut chunks = Vec::new();
    while let Some(item) = stream.next().await {
        chunks.push(item.expect("chunk"));
    }

    // Three data frames + the `[DONE]` sentinel.
    assert_eq!(chunks.len(), 4, "three deltas + [DONE]");
    assert!(chunks[0].event.to_string().contains("He"));
    assert!(chunks[3].terminal, "the last chunk is the [DONE] sentinel");
    assert!(
        chunks[..3].iter().all(|c| !c.terminal),
        "data frames are not terminal"
    );

    // Now (after close) the outcome audit row exists.
    assert_eq!(
        sink.best_effort.lock().unwrap().len(),
        1,
        "the outcome is audited exactly once, at stream close"
    );
}

#[tokio::test]
async fn anthropic_streaming_translates_events_to_openai_chunks_through_egress() {
    // End-to-end: an Anthropic-protocol model streamed through the full
    // pipeline. The egress selects the Anthropic SSE translator from the base
    // record's protocol and the CLIENT receives OpenAI chat-completion-chunks
    // (role + content deltas) ending in the `[DONE]` sentinel — never the raw
    // Anthropic events. The outcome audits exactly once at close.
    use futures::StreamExt;

    let addr = spawn_anthropic_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, anthropic_resolver(addr));

    let args = json!({
        "model": "claude-x",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
    .as_object()
    .cloned()
    .unwrap();
    let req = InvocationRequest::new("llm", "claude-x").with_arguments(Some(args));
    let resp = svc.invoke(None, req).await.expect("invoke");

    let mut stream = match resp {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };

    let mut chunks = Vec::new();
    while let Some(item) = stream.next().await {
        chunks.push(item.expect("chunk"));
    }

    // Every non-terminal client frame is an OpenAI chat.completion.chunk; the
    // last is the [DONE] sentinel. Content text was forwarded; the raw Anthropic
    // event types never reach the client.
    let combined = chunks
        .iter()
        .map(|c| c.event.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        combined.contains("chat.completion.chunk"),
        "client gets OpenAI chunks: {combined}"
    );
    assert!(
        combined.contains("\"role\":\"assistant\""),
        "role delta forwarded: {combined}"
    );
    assert!(
        combined.contains("He") && combined.contains("llo"),
        "content forwarded: {combined}"
    );
    assert!(
        !combined.contains("message_start") && !combined.contains("content_block_delta"),
        "raw Anthropic event types must NOT reach the client: {combined}"
    );
    assert!(
        chunks.last().is_some_and(|c| c.terminal),
        "the last chunk is the [DONE] sentinel"
    );

    // Audited exactly once at close.
    assert_eq!(
        sink.best_effort.lock().unwrap().len(),
        1,
        "the outcome is audited exactly once, at stream close"
    );
}

#[tokio::test]
async fn streaming_call_records_usage_at_close() {
    // A completed streamed call records one usage row at close,
    // with the tokens / finish reason the aggregator folded from the provider
    // frames (the usage chunk + [DONE]).
    use futures::StreamExt;

    let addr = spawn_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr))
            .with_llm_usage_store(usage.clone());

    let args = json!({
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
    .as_object()
    .cloned()
    .unwrap();
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(args));
    let mut stream = match svc.invoke(Some(&principal()), req).await.expect("invoke") {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };

    // Usage records at CLOSE, not before any frame is consumed.
    assert!(
        usage.rows.lock().unwrap().is_empty(),
        "usage defers to close"
    );

    while stream.next().await.is_some() {}

    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 1, "one usage row at stream close");
    let r = &rows[0];
    assert_eq!(r.model_alias, "gpt-x");
    assert_eq!(r.provider, "openrouter");
    // Folded from the provider's usage chunk (prompt 3 / completion 2) and the
    // finish_reason on the second delta.
    assert_eq!(r.input_tokens, Some(3));
    assert_eq!(r.output_tokens, Some(2));
    assert_eq!(r.finish_reason.as_deref(), Some("stop"));
    assert_eq!(r.principal_sub.as_deref(), Some("carol"));
}

#[tokio::test]
async fn streaming_client_disconnect_before_close_still_audits_exactly_once() {
    // Regression: a client that disconnects mid-stream drops the
    // `InvocationStream` before the provider EOF / `[DONE]` sentinel. The
    // outcome audit must still fire (an abandoned governed call is not an
    // unaudited call), and must fire EXACTLY once — the close-time finalizer
    // and the Drop finalizer must not both record.
    use futures::StreamExt;

    let addr = spawn_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let args = json!({
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
    .as_object()
    .cloned()
    .unwrap();
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(args));

    let mut stream = match svc.invoke(None, req).await.expect("invoke") {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };

    // Pull exactly one frame, then abandon the stream mid-flight (the provider
    // has more frames and has NOT sent `[DONE]` — this is a client disconnect).
    let first = stream.next().await.expect("first frame").expect("ok frame");
    assert!(
        !first.terminal,
        "first frame is a data delta, not the sentinel"
    );
    drop(stream);

    // The Drop finalizer spawns the close-out audit; let the runtime run it.
    let mut audited = false;
    for _ in 0..200 {
        if !sink.best_effort.lock().unwrap().is_empty() {
            audited = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(audited, "an abandoned stream must still be audited");
    assert_eq!(
        sink.best_effort.lock().unwrap().len(),
        1,
        "the abandoned-stream outcome is audited exactly once (no double-record)"
    );
}

#[tokio::test]
async fn streaming_provider_eof_before_done_is_audited_as_failure_and_surfaces_error() {
    // Regression: a provider/proxy that closes the SSE stream before the OpenAI
    // `[DONE]` sentinel is a TRUNCATED stream, not a clean completion. The
    // InvocationStream contract requires a mid-stream failure to surface as a
    // terminal error frame (never a silent end), and the outcome must be audited
    // as a failure — auditing it Success would mask a real upstream failure.
    use futures::StreamExt;

    let addr = spawn_truncated_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let args = json!({
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
    .as_object()
    .cloned()
    .unwrap();
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(args));

    let mut stream = match svc.invoke(None, req).await.expect("invoke") {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };

    let mut items = Vec::new();
    while let Some(item) = stream.next().await {
        items.push(item);
    }

    // The data delta, then a TERMINAL ERROR frame — not a silent end.
    assert!(items.len() >= 2, "got {} items", items.len());
    assert!(items[0].is_ok(), "first item is the data delta");
    assert!(
        items.last().unwrap().is_err(),
        "a truncated stream surfaces a terminal error frame, not a silent end"
    );

    // Audited exactly once, as a failure (NOT Success).
    let rows = sink.best_effort.lock().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the truncation outcome is audited exactly once"
    );
    assert!(
        matches!(rows[0].outcome, AuditOutcome::ExecutionError),
        "EOF before [DONE] is audited as a failure, got {:?}",
        rows[0].outcome
    );
}

#[tokio::test]
async fn stream_dropped_while_finalize_in_flight_still_audits_exactly_once() {
    // Regression for the finalize-ordering race: each terminal arm sets its
    // `finished` flag only AFTER the audit write completes. If the SSE future is
    // dropped while a terminal `finalize_stream_audit` await is still pending,
    // `finished` is therefore still false, so the Drop net records the outcome
    // instead of the write being silently lost. (Setting `finished` BEFORE the
    // await — the bug — would make Drop skip, yielding ZERO audit rows for a
    // governed call.)
    use futures::StreamExt;

    let addr = spawn_stream_provider().await;
    let sink = Arc::new(GatedSink::new());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let args = json!({
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
    .as_object()
    .cloned()
    .unwrap();
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(args));

    let stream = match svc.invoke(None, req).await.expect("invoke") {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };

    // Drive the stream on a separate task. It will drain the deltas and, at the
    // `[DONE]` frame, enter the terminal finalize — which parks on the gate.
    let drainer = tokio::spawn(async move {
        let mut s = stream;
        while s.next().await.is_some() {}
    });

    // Wait until the terminal `[DONE]` finalize has begun (and is parked).
    let mut started = false;
    for _ in 0..2000 {
        if sink.entered() >= 1 {
            started = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(started, "the [DONE] finalize write should have started");
    assert!(
        sink.events.lock().unwrap().is_empty(),
        "the gated write has not completed yet"
    );

    // Cancel the stream mid-finalize, then let the runtime drop the aborted
    // future (which fires the Drop net and spawns the fallback audit). The
    // fallback then parks on the gate too (entered == 2).
    drainer.abort();
    for _ in 0..2000 {
        if sink.entered() >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }

    // Release the gate; only the Drop-net fallback is still queued (the inline
    // write's future was dropped with the aborted task), so exactly one row lands.
    sink.gate.add_permits(2);
    let mut recorded = false;
    for _ in 0..2000 {
        if !sink.events.lock().unwrap().is_empty() {
            recorded = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        recorded,
        "a stream cancelled mid-finalize must still be audited (never zero rows)"
    );
    let evs = sink.events.lock().unwrap();
    assert_eq!(
        evs.len(),
        1,
        "the cancelled-mid-finalize outcome is audited exactly once"
    );
    assert!(
        matches!(evs[0].outcome, AuditOutcome::ExecutionError),
        "the Drop net records the cancellation as a failure, got {:?}",
        evs[0].outcome
    );
}

#[tokio::test]
async fn unary_call_is_bounded_by_a_total_timeout_when_provider_stalls() {
    // A non-streaming /v1 call must not hang on a slow-drip provider. The
    // ProviderClient applies a TOTAL per-request deadline to unary calls (only),
    // so a provider that returns 200 headers then never finishes the body is
    // aborted rather than holding the request open indefinitely. Without the
    // unary timeout this test would hang forever.
    let addr = spawn_stall_provider().await;
    let sink = Arc::new(RecordingSink::default());

    let providers = ProviderClient::new(reqwest::Client::new())
        .with_unary_timeout(Some(std::time::Duration::from_millis(200)));
    let dispatcher = LlmDispatcher::new(providers, store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    let err = svc.invoke(None, req).await.unwrap_err();
    assert!(
        matches!(err, InvocationError::Upstream(_)),
        "a stalled unary call must be aborted by the total timeout, got {err:?}"
    );
}

#[tokio::test]
async fn unknown_model_on_the_llm_namespace_is_rejected_not_routed_to_mcp() {
    // A request on the resolver-owned `llm` namespace whose model is NOT
    // configured must be rejected — never allowed to fall through to the MCP
    // tool path (where a same-named upstream could shadow it). The FakeCatalog
    // would return success if reached, so an InvalidArguments here proves the
    // request never reached MCP dispatch.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr));

    // `resolver(addr)` only knows `gpt-x`; ask for an unconfigured model.
    let args = json!({"model": "not-configured", "messages": [{"role": "user", "content": "hi"}]})
        .as_object()
        .cloned()
        .unwrap();
    let req = InvocationRequest::new("llm", "not-configured").with_arguments(Some(args));
    let err = svc.invoke(None, req).await.unwrap_err();

    assert!(
        matches!(err, InvocationError::InvalidArguments(_)),
        "unknown model on the llm namespace must reject, got {err:?}"
    );
    assert!(
        !cap.lock().unwrap().called,
        "an unknown-model request must not reach a provider"
    );
}

// ---- Per-principal exact-match completion cache ----------------------------

/// In-memory mock of the pipeline's [`waygate_mcp::cache::LlmCache`], keyed
/// EXACTLY as the real per-principal store: `(canonical_request, tenant,
/// principal_issuer, principal_sub)`. It records get/put counts so a test can prove a hit skipped
/// the provider and a miss stored the completion. This is an interaction fake,
/// not a canned echo — the pipeline still computes the canonical request and the
/// per-principal key and decides hit/miss; the test asserts the resulting
/// provider-contact and replayed body.
#[derive(Default)]
struct MockCache {
    #[allow(clippy::type_complexity)]
    store: Mutex<
        std::collections::HashMap<
            (String, String, Option<String>, Option<String>),
            waygate_mcp::cache::CachedCompletion,
        >,
    >,
    gets: std::sync::atomic::AtomicUsize,
    puts: std::sync::atomic::AtomicUsize,
}

impl MockCache {
    fn gets(&self) -> usize {
        self.gets.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn puts(&self) -> usize {
        self.puts.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// The single stored body, for asserting what tee-on-miss aggregated.
    fn only_stored_body(&self) -> Value {
        let store = self.store.lock().unwrap();
        assert_eq!(store.len(), 1, "expected exactly one stored entry");
        store.values().next().unwrap().body.clone()
    }
}

#[async_trait]
impl waygate_mcp::cache::LlmCache for MockCache {
    async fn get(
        &self,
        canonical_request: &str,
        tenant_id: &str,
        principal_issuer: Option<&str>,
        principal_sub: Option<&str>,
    ) -> Option<waygate_mcp::cache::CachedCompletion> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.store
            .lock()
            .unwrap()
            .get(&(
                canonical_request.to_string(),
                tenant_id.to_string(),
                principal_issuer.map(str::to_string),
                principal_sub.map(str::to_string),
            ))
            .cloned()
    }

    async fn put(&self, entry: waygate_mcp::cache::CacheStoreRequest) {
        self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.store.lock().unwrap().insert(
            (
                entry.canonical_request,
                entry.tenant_id,
                entry.principal_issuer,
                entry.principal_sub,
            ),
            waygate_mcp::cache::CachedCompletion {
                model_served: entry.model_served,
                provider: Some(entry.provider),
                body: entry.body,
            },
        );
    }
}

/// Like [`resolver`], but opts the model into the per-principal cache with a
/// generous TTL — the `Some(ttl)` is what flips the pipeline's cache branch on.
fn caching_resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "gpt-x",
        ResolvedModel {
            operation: LlmOperation::Chat,
            route: ResolvedRoute {
                provider: LlmProvider::OpenRouter,
                credential_label: "MAIN".into(),
                base_url: format!("http://{addr}"),
                path: "chat/completions".into(),
                upstream_model: "openrouter/served-x".into(),
                protocol: UpstreamProtocol::OpenAiChat,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::High,
            ttfb: None,
            cache_ttl: Some(std::time::Duration::from_secs(300)),
        },
    ))
}

/// A principal with a caller-chosen subject (the cache scope), otherwise
/// identical to [`principal`].
fn principal_named(sub: &str) -> Principal {
    Principal {
        sub: sub.into(),
        ..principal()
    }
}

#[tokio::test]
async fn cached_model_stores_on_miss_then_replays_on_hit_without_dispatch() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let cache = Arc::new(MockCache::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, caching_resolver(addr))
            .with_llm_usage_store(usage.clone())
            .with_llm_cache(cache.clone() as waygate_mcp::cache::SharedLlmCache);

    // First call: cache miss → the provider IS contacted → the completion is
    // stored for this principal.
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    let first = svc
        .invoke(Some(&principal()), req)
        .await
        .expect("invoke #1");
    let first_body = match first {
        InvocationResponse::UnaryValue(b) => b,
        other => panic!("expected UnaryValue, got {other:?}"),
    };
    assert!(
        cap.lock().unwrap().called,
        "a cache miss must dispatch to the provider"
    );
    assert_eq!(cache.puts(), 1, "a miss stores exactly one completion");

    // Clear the provider's contacted flag so the second call can prove it was
    // NOT re-dispatched.
    cap.lock().unwrap().called = false;

    // Second identical call from the SAME principal: cache hit → the provider is
    // never contacted, and the replayed body is byte-identical to the first.
    let req2 = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    let second = svc
        .invoke(Some(&principal()), req2)
        .await
        .expect("invoke #2");
    match second {
        InvocationResponse::UnaryValue(b) => {
            assert_eq!(b, first_body, "a hit replays the stored body verbatim");
        }
        other => panic!("expected UnaryValue, got {other:?}"),
    }
    assert!(
        !cap.lock().unwrap().called,
        "a cache hit must NOT contact the provider"
    );
    assert_eq!(cache.puts(), 1, "a hit does not store the entry again");

    // A hit is still a governed, audited call — both calls show in the feed.
    assert_eq!(
        sink.best_effort.lock().unwrap().len(),
        2,
        "both the miss and the hit audit under the inference plane"
    );

    // The durable usage ledger distinguishes the two: the miss row is a real
    // provider call (not a cache hit), the hit row is flagged
    // gateway_cache_hit=true and attributed to the provider that served the
    // original miss (openrouter) — not left to masquerade as a zero-token
    // provider call. This is the regression pin for the cache-hit attribution
    // gap.
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 2, "miss and hit each ledger a usage row");
    assert!(!rows[0].gateway_cache_hit, "the miss row is a real call");
    assert!(
        rows[1].gateway_cache_hit,
        "the hit row is marked a cache hit"
    );
    assert_eq!(
        rows[1].provider, "openrouter",
        "a hit attributes to the provider that served the original miss"
    );
    assert_eq!(
        rows[1].model_served.as_deref(),
        Some("served-x"),
        "a hit replays the originally-served model"
    );
}

#[tokio::test]
async fn cache_is_scoped_per_principal_no_cross_principal_hit() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let cache = Arc::new(MockCache::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, caching_resolver(addr))
            .with_llm_cache(cache.clone() as waygate_mcp::cache::SharedLlmCache);

    // Alice's call populates the cache under her principal.
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    svc.invoke(Some(&principal_named("alice")), req)
        .await
        .expect("alice invoke");
    assert_eq!(cache.puts(), 1);

    cap.lock().unwrap().called = false;

    // Bob issues the byte-identical request. Because the principal is part of
    // the cache key, his lookup MISSES and the provider IS contacted — Alice's
    // cached completion can never leak to Bob (the §9 no-cross-principal
    // guarantee, exercised end-to-end through the pipeline).
    let req2 = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    svc.invoke(Some(&principal_named("bob")), req2)
        .await
        .expect("bob invoke");
    assert!(
        cap.lock().unwrap().called,
        "a different principal must miss and dispatch"
    );
    assert_eq!(
        cache.puts(),
        2,
        "bob's miss stores his own per-principal entry"
    );
    let mut other_issuer = principal_named("alice");
    other_issuer.issuer = "https://other-issuer.example".into();
    let mut other_tenant = principal_named("alice");
    other_tenant.tenant = waygate_core::TenantId::parse("other-tenant").unwrap();
    for caller in [other_issuer, other_tenant] {
        for expected_dispatch in [true, false] {
            cap.lock().unwrap().called = false;
            let request = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
            svc.invoke(Some(&caller), request)
                .await
                .expect("invoke isolated identity");
            assert_eq!(
                cap.lock().unwrap().called,
                expected_dispatch,
                "a distinct identity first misses, then reuses its own response"
            );
        }
    }
}

#[tokio::test]
async fn model_without_cache_ttl_never_consults_the_cache() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let cache = Arc::new(MockCache::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    // `resolver` registers the model with `cache_ttl = None` (cache opt-OUT),
    // yet the cache is still wired into the service. The cache must be inert.
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr))
            .with_llm_cache(cache.clone() as waygate_mcp::cache::SharedLlmCache);

    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    svc.invoke(Some(&principal()), req).await.expect("invoke");

    assert!(
        cap.lock().unwrap().called,
        "an un-opted model still dispatches"
    );
    assert_eq!(cache.gets(), 0, "no TTL ⇒ the cache is never read");
    assert_eq!(cache.puts(), 0, "no TTL ⇒ the cache is never written");
}

#[tokio::test]
async fn streaming_request_replays_a_unary_stored_completion_as_a_synthetic_stream() {
    use futures::StreamExt;

    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await; // unary provider
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let cache = Arc::new(MockCache::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, caching_resolver(addr))
            .with_llm_usage_store(usage.clone())
            .with_llm_cache(cache.clone() as waygate_mcp::cache::SharedLlmCache);

    // Seed the cache with a UNARY call (stores the completion body).
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(chat_args()));
    svc.invoke(Some(&principal()), req)
        .await
        .expect("unary miss");
    assert!(cap.lock().unwrap().called, "the unary miss dispatches");
    assert_eq!(cache.puts(), 1);

    cap.lock().unwrap().called = false;

    // Same content, but STREAMING. The cache key ignores `stream`, so this hits
    // the unary-stored body and replays it as a synthetic SSE stream — no
    // provider contact.
    let mut stream_args = chat_args();
    stream_args.insert("stream".into(), json!(true));
    let req2 = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(stream_args));
    let resp = svc
        .invoke(Some(&principal()), req2)
        .await
        .expect("streaming hit");
    let mut stream = match resp {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected a synthetic Stream, got {other:?}"),
    };
    assert!(
        !cap.lock().unwrap().called,
        "a streaming cache hit must NOT contact the provider"
    );
    assert_eq!(cache.puts(), 1, "a hit does not store again");

    // The synthetic stream reconstructs the stored content, carries the stored
    // finish_reason, and ends with a terminal [DONE] frame.
    let mut content = String::new();
    let mut finish_reason: Option<String> = None;
    let mut saw_done = false;
    while let Some(item) = stream.next().await {
        let chunk = item.expect("chunk ok");
        if chunk.terminal {
            saw_done = true;
            continue;
        }
        if let Some(choices) = chunk.event.get("choices").and_then(|c| c.as_array()) {
            for ch in choices {
                if let Some(c) = ch
                    .get("delta")
                    .and_then(|d| d.get("content"))
                    .and_then(|v| v.as_str())
                {
                    content.push_str(c);
                }
                if let Some(fr) = ch.get("finish_reason").and_then(|v| v.as_str()) {
                    finish_reason = Some(fr.to_owned());
                }
            }
        }
    }
    assert_eq!(content, "hi", "the replay reconstructs the stored content");
    assert_eq!(finish_reason.as_deref(), Some("stop"));
    assert!(
        saw_done,
        "the synthetic stream ends with a terminal [DONE] frame"
    );

    // Two usage rows: the unary miss (a real call) and the streaming hit (free).
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 2, "miss and hit each ledger a row");
    assert!(!rows[0].gateway_cache_hit, "the unary miss is a real call");
    assert!(
        rows[1].gateway_cache_hit,
        "the streaming hit is flagged a cache hit"
    );
    assert_eq!(
        rows[1].provider, "openrouter",
        "the hit attributes to the provider that served the original miss"
    );
}

#[tokio::test]
async fn streaming_miss_tees_completion_into_cache_then_a_second_call_hits() {
    use futures::StreamExt;

    // A streaming provider that emits "He" + "llo", a finish, then a usage chunk.
    let addr = spawn_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let cache = Arc::new(MockCache::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, caching_resolver(addr))
            .with_llm_usage_store(usage.clone())
            .with_llm_cache(cache.clone() as waygate_mcp::cache::SharedLlmCache);

    let stream_args = || {
        let mut a = chat_args();
        a.insert("stream".into(), json!(true));
        a
    };

    // First streaming call: a MISS. Draining the stream to its clean close fires
    // the tee, which aggregates the forwarded chunks and stores the completion.
    let req = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(stream_args()));
    let mut s1 = match svc
        .invoke(Some(&principal()), req)
        .await
        .expect("invoke #1")
    {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };
    while s1.next().await.is_some() {}
    drop(s1);

    assert_eq!(
        cache.puts(),
        1,
        "a clean streaming close tees exactly one completion into the cache"
    );
    // The teed body reconstructs the streamed content faithfully: a unary
    // chat.completion with the concatenated content + the stream's finish reason.
    let body = cache.only_stored_body();
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["content"], "Hello");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert!(
        body.get("usage").is_some(),
        "usage is carried into the body"
    );

    // Second identical streaming call: a HIT served by replay. Because a hit
    // never dispatches, the tee does NOT run again — `puts` staying at 1 proves
    // the second call was served from cache, not re-streamed from the provider.
    let req2 = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(stream_args()));
    let mut s2 = match svc
        .invoke(Some(&principal()), req2)
        .await
        .expect("invoke #2")
    {
        InvocationResponse::Stream(s) => s,
        other => panic!("expected Stream, got {other:?}"),
    };
    let mut content = String::new();
    let mut saw_done = false;
    while let Some(item) = s2.next().await {
        let chunk = item.expect("chunk ok");
        if chunk.terminal {
            saw_done = true;
            continue;
        }
        if let Some(c) = chunk.event["choices"][0]["delta"]["content"].as_str() {
            content.push_str(c);
        }
    }
    assert_eq!(
        cache.puts(),
        1,
        "the second call hit the cache and did NOT re-tee (no re-dispatch)"
    );
    assert_eq!(content, "Hello", "the replay reconstructs the teed content");
    assert!(saw_done, "the replayed stream ends with a terminal [DONE]");

    let mut other_issuer = principal();
    other_issuer.issuer = "https://other-issuer.example".into();
    let request = InvocationRequest::new("llm", "gpt-x").with_arguments(Some(stream_args()));
    let mut stream = match svc.invoke(Some(&other_issuer), request).await.unwrap() {
        InvocationResponse::Stream(stream) => stream,
        other => panic!("expected Stream, got {other:?}"),
    };
    while stream.next().await.is_some() {}
    assert_eq!(
        cache.puts(),
        2,
        "another issuer must receive a live response and store its own entry"
    );

    // Usage ledger: the miss is a real streamed call, the hit is flagged.
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(
        !rows[0].gateway_cache_hit,
        "the streamed miss is a real call"
    );
    assert!(
        rows[1].gateway_cache_hit,
        "the replay is a flagged cache hit"
    );
    assert!(!rows[2].gateway_cache_hit);
}

// ---- Embeddings pipeline branch ---------------------------------------------

/// Loopback OpenAI-compatible embeddings provider on `/embeddings`: captures the
/// bearer + request body, returns an OpenAI embeddings response.
async fn embeddings_provider_handler(
    State(cap): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    {
        let mut c = cap.lock().unwrap();
        c.called = true;
        if let Ok(v) = serde_json::from_str::<Value>(&body) {
            c.authorization = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string);
            c.model = v.get("model").and_then(Value::as_str).map(str::to_string);
            c.body = Some(v);
        }
    }
    let resp = json!({
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
        "model": "served-embed-x",
        "usage": {"prompt_tokens": 5, "total_tokens": 5}
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(resp))
        .unwrap()
}

async fn spawn_embeddings_provider(cap: Arc<Mutex<Captured>>) -> SocketAddr {
    let app = Router::new()
        .route("/embeddings", post(embeddings_provider_handler))
        .with_state(cap);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A resolver with one **embeddings** model (`operation = Embeddings`, path
/// `embeddings`) under the `llm` namespace.
fn embeddings_resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "embed-x",
        ResolvedModel {
            operation: LlmOperation::Embeddings,
            route: ResolvedRoute {
                provider: LlmProvider::OpenRouter,
                credential_label: "MAIN".into(),
                base_url: format!("http://{addr}"),
                path: "embeddings".into(),
                upstream_model: "openrouter/served-embed-x".into(),
                protocol: UpstreamProtocol::OpenAiChat,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::Low,
            ttfb: None,
            cache_ttl: None,
        },
    ))
}

fn embeddings_args() -> Map<String, Value> {
    json!({"model": "embed-x", "input": "hi"})
        .as_object()
        .cloned()
        .unwrap()
}

#[tokio::test]
async fn recognized_embeddings_model_returns_unary_value_through_the_pipeline() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_embeddings_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, embeddings_resolver(addr))
            .with_llm_usage_store(usage.clone());

    let req = InvocationRequest::new("llm", "embed-x")
        .with_arguments(Some(embeddings_args()))
        .with_embeddings_surface(true);
    let resp = svc.invoke(Some(&principal()), req).await.expect("invoke");

    match resp {
        InvocationResponse::UnaryValue(body) => {
            // The provider's OpenAI embeddings body is returned verbatim.
            assert_eq!(body["object"], "list");
            assert_eq!(body["model"], "served-embed-x");
            assert_eq!(body["data"][0]["embedding"][0], 0.1);
        }
        other => panic!("expected UnaryValue, got {other:?}"),
    }

    // The dispatcher resolved the injected bearer and sent the *upstream* model
    // plus the verbatim input.
    {
        let c = cap.lock().unwrap();
        assert!(c.called, "the embeddings provider was contacted");
        assert_eq!(c.authorization.as_deref(), Some("Bearer sk-test-key"));
        assert_eq!(c.model.as_deref(), Some("openrouter/served-embed-x"));
        assert_eq!(
            c.body.as_ref().and_then(|b| b.get("input")),
            Some(&json!("hi"))
        );
    }

    // Audited under the inference plane (llm_completion), like a chat call.
    {
        let rows = sink.best_effort.lock().unwrap();
        assert_eq!(rows.len(), 1, "one audit row");
        assert_eq!(rows[0].category, EvidenceCategory::LlmCompletion);
    }

    // One usage row: embeddings surface, input-only tokens (no output class).
    let urows = usage.rows.lock().unwrap();
    assert_eq!(urows.len(), 1, "one usage row");
    assert_eq!(urows[0].inbound_surface, "embeddings");
    assert_eq!(urows[0].input_tokens, Some(5));
    assert_eq!(urows[0].output_tokens, None);
    assert_eq!(urows[0].model_alias, "embed-x");
}

#[tokio::test]
async fn embeddings_model_on_a_chat_surface_is_rejected_before_dispatch() {
    // An embeddings model addressed without the embeddings surface (i.e. hit on
    // /v1/chat/completions or /v1/responses) is a clean client error BEFORE any
    // gate or provider contact — never a mis-dispatch.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_embeddings_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, embeddings_resolver(addr));

    let req = InvocationRequest::new("llm", "embed-x").with_arguments(Some(embeddings_args()));
    let err = svc
        .invoke(Some(&principal()), req)
        .await
        .expect_err("an embeddings model on a chat surface is rejected");
    assert!(
        matches!(&err, InvocationError::InvalidArguments(m) if m.contains("embeddings model")),
        "got {err:?}"
    );
    assert!(
        !cap.lock().unwrap().called,
        "the provider must not be contacted on a surface mismatch"
    );
}

#[tokio::test]
async fn chat_model_on_the_embeddings_surface_is_rejected_before_dispatch() {
    // The inverse mismatch: a chat model hit on /v1/embeddings is also a clean
    // client error before dispatch.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await; // chat provider
    let sink = Arc::new(RecordingSink::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver(addr)); // chat model

    let req = InvocationRequest::new("llm", "gpt-x")
        .with_arguments(Some(chat_args()))
        .with_embeddings_surface(true);
    let err = svc
        .invoke(Some(&principal()), req)
        .await
        .expect_err("a chat model on the embeddings surface is rejected");
    assert!(
        matches!(&err, InvocationError::InvalidArguments(m) if m.contains("not an embeddings model")),
        "got {err:?}"
    );
    assert!(
        !cap.lock().unwrap().called,
        "the provider must not be contacted on a surface mismatch"
    );
}

// ---- Embeddings caching -----------------------------------------------------

/// Like [`embeddings_resolver`], but opts the embeddings model into the
/// per-principal cache (a `Some(ttl)` flips the pipeline's cache branch on).
fn caching_embeddings_resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "embed-x",
        ResolvedModel {
            operation: LlmOperation::Embeddings,
            route: ResolvedRoute {
                provider: LlmProvider::OpenRouter,
                credential_label: "MAIN".into(),
                base_url: format!("http://{addr}"),
                path: "embeddings".into(),
                upstream_model: "openrouter/served-embed-x".into(),
                protocol: UpstreamProtocol::OpenAiChat,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::Low,
            ttfb: None,
            cache_ttl: Some(std::time::Duration::from_secs(300)),
        },
    ))
}

#[tokio::test]
async fn cached_embeddings_model_stores_on_miss_then_replays_on_hit_without_dispatch() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_embeddings_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let cache = Arc::new(MockCache::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, caching_embeddings_resolver(addr))
            .with_llm_usage_store(usage.clone())
            .with_llm_cache(cache.clone() as waygate_mcp::cache::SharedLlmCache);

    let mk = || {
        InvocationRequest::new("llm", "embed-x")
            .with_arguments(Some(embeddings_args()))
            .with_embeddings_surface(true)
    };

    // First call: cache miss → the provider IS contacted → the result is stored.
    let first = svc
        .invoke(Some(&principal()), mk())
        .await
        .expect("invoke #1");
    let first_body = match first {
        InvocationResponse::UnaryValue(b) => b,
        other => panic!("expected UnaryValue, got {other:?}"),
    };
    assert!(
        cap.lock().unwrap().called,
        "a cache miss must dispatch to the provider"
    );
    assert_eq!(cache.puts(), 1, "a miss stores exactly one entry");

    cap.lock().unwrap().called = false;

    // Second identical call from the SAME principal: cache hit → no provider
    // contact, and the replayed body is byte-identical to the first.
    let second = svc
        .invoke(Some(&principal()), mk())
        .await
        .expect("invoke #2");
    match second {
        InvocationResponse::UnaryValue(b) => {
            assert_eq!(b, first_body, "a hit replays the stored body verbatim");
        }
        other => panic!("expected UnaryValue, got {other:?}"),
    }
    assert!(
        !cap.lock().unwrap().called,
        "a cache hit must NOT contact the provider"
    );

    // Two usage rows: the miss (real input-token usage) and the hit (flagged free).
    let urows = usage.rows.lock().unwrap();
    assert_eq!(urows.len(), 2, "one row per call (miss + hit)");
    assert_eq!(urows[0].inbound_surface, "embeddings");
    assert_eq!(urows[0].input_tokens, Some(5));
    assert!(
        !urows[0].gateway_cache_hit,
        "the miss is a real provider call"
    );
    assert_eq!(urows[1].inbound_surface, "embeddings");
    assert!(
        urows[1].gateway_cache_hit,
        "the hit is flagged as a free cache replay"
    );
}

#[tokio::test]
async fn embeddings_cache_is_per_principal() {
    // Principal A's stored embedding is NEVER served to principal B — the key
    // includes the principal (the §9/§13 security invariant). B's identical
    // request misses A's entry and dispatches.
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_embeddings_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let cache = Arc::new(MockCache::default());

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, caching_embeddings_resolver(addr))
            .with_llm_cache(cache.clone() as waygate_mcp::cache::SharedLlmCache);

    let mk = || {
        InvocationRequest::new("llm", "embed-x")
            .with_arguments(Some(embeddings_args()))
            .with_embeddings_surface(true)
    };

    // Alice: miss → stored under her principal.
    svc.invoke(Some(&principal_named("alice")), mk())
        .await
        .expect("alice");
    assert!(cap.lock().unwrap().called);
    cap.lock().unwrap().called = false;

    // Bob: byte-identical request, DIFFERENT principal → miss (not Alice's
    // entry) → dispatches, and stores his own entry.
    svc.invoke(Some(&principal_named("bob")), mk())
        .await
        .expect("bob");
    assert!(
        cap.lock().unwrap().called,
        "a different principal must not hit Alice's cached embedding"
    );
    assert_eq!(cache.puts(), 2, "each principal stored its own entry");
    let mut other_issuer = principal_named("alice");
    other_issuer.issuer = "https://other-issuer.example".into();
    for expected_dispatch in [true, false] {
        cap.lock().unwrap().called = false;
        svc.invoke(Some(&other_issuer), mk())
            .await
            .expect("issuer-scoped embedding");
        assert_eq!(cap.lock().unwrap().called, expected_dispatch);
    }
}

mod images;

#[tokio::test]
async fn private_embeddings_keep_authorization_and_safe_backend_error_metadata() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    async fn overloaded(State(cap): State<Arc<Mutex<Captured>>>, headers: HeaderMap) -> Response {
        let mut c = cap.lock().unwrap();
        c.called = true;
        assert!(headers.get("authorization").is_none());
        Response::builder()
            .status(429)
            .header("retry-after", "1")
            .body(Body::from("sensitive backend request echo"))
            .unwrap()
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/embeddings", post(overloaded))
        .with_state(cap.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut model = embeddings_resolver(addr).resolve("llm", "embed-x").unwrap();
    model.route.embeddings_no_auth = true;
    model.route.credential_label.clear();
    let resolver = Arc::new(StaticModelResolver::new().with_model("llm", "embed-x", model));
    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let denied = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(FixedGate(AuthzVerdict::Deny {
            reason: "policy".into(),
            policy_ids: vec![],
            reasons: vec![],
        })),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher.clone(), resolver.clone());
    let request = || {
        InvocationRequest::new("llm", "embed-x")
            .with_arguments(Some(embeddings_args()))
            .with_embeddings_surface(true)
    };
    assert!(matches!(
        denied.invoke(Some(&principal()), request()).await,
        Err(InvocationError::Forbidden { .. })
    ));
    assert!(!cap.lock().unwrap().called);
    let sink = Arc::new(RecordingSink::default());
    let allowed =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(dispatcher, resolver);
    let error = allowed
        .invoke(Some(&principal()), request())
        .await
        .unwrap_err();
    let InvocationError::Upstream(error) = error else {
        panic!("expected upstream error")
    };
    assert_eq!(error.data.as_ref().unwrap()["embedding_http_status"], 429);
    assert_eq!(error.data.as_ref().unwrap()["retry_after_seconds"], 1);
    assert!(!error.message.contains("sensitive"));
    assert!(cap.lock().unwrap().called);
}

#[tokio::test]
async fn stream_failure_metrics_distinguish_eof_abandonment_and_completion() {
    use futures::StreamExt;
    for (model, phase) in [
        ("telemetry-eof", Some("stream")),
        ("telemetry-abandon", Some("abandoned")),
        ("telemetry-complete", None),
    ] {
        let addr = if phase == Some("stream") {
            spawn_truncated_stream_provider().await
        } else {
            spawn_stream_provider().await
        };
        let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
        let svc = DefaultInvocationService::new(
            Arc::new(FakeCatalog),
            Arc::new(AllowAllGate),
            Arc::new(RecordingSink::default()),
        )
        .with_llm(dispatcher, resolver_named(addr, model));
        let args = json!({"model":model,"messages":[{"role":"user","content":"hi"}],"stream":true});
        let req = InvocationRequest::new("llm", model).with_arguments(args.as_object().cloned());
        let InvocationResponse::Stream(mut stream) = svc.invoke(None, req).await.unwrap() else {
            panic!("expected model stream");
        };
        if phase == Some("abandoned") {
            assert!(stream.next().await.unwrap().is_ok());
        } else {
            while stream.next().await.is_some() {}
        }
        drop(stream);
        let text = waygate_telemetry::gather_text();
        let matching: Vec<_> = text
            .lines()
            .filter(|line| {
                line.starts_with("gen_ai_client_request_failures_total")
                    && line.contains(&format!("model=\"{model}\""))
            })
            .collect();
        if let Some(phase) = phase {
            assert_eq!(matching.len(), 1);
            assert!(matching[0].contains(&format!("phase=\"{phase}\"")));
            assert!(matching[0].contains("user_account_id=\"unknown\""));
            assert!(matching[0].ends_with(" 1"));
        } else {
            assert!(matching.is_empty());
        }
    }
}

#[tokio::test]
async fn dispatch_failure_labels_use_the_authorized_catalog_alias() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(|| async { axum::http::StatusCode::BAD_GATEWAY }),
        )
        .await
        .unwrap();
    });
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(
        LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store()),
        resolver_named(addr, "failure-catalog-alias"),
    );
    for supplied in ["arbitrary-failure-label-one", "arbitrary-failure-label-two"] {
        let request = InvocationRequest::new("llm", "failure-catalog-alias").with_arguments(
            json!({"model":supplied,"messages":[{"role":"user","content":"test"}]})
                .as_object()
                .cloned(),
        );
        assert!(svc.invoke(Some(&principal()), request).await.is_err());
        assert!(!waygate_telemetry::gather_text().contains(supplied));
    }
    let metrics = waygate_telemetry::gather_text();
    for name in [
        "gen_ai_client_request_failures_total",
        "gen_ai_client_duration_seconds_count",
    ] {
        let line = metrics
            .lines()
            .find(|line| line.starts_with(name) && line.contains("model=\"failure-catalog-alias\""))
            .expect("catalog metric");
        assert!(line.ends_with(" 2"), "{line}");
    }
}
