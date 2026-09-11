//! End-to-end dispatch against a loopback provider (no real network, no real
//! credentials) — mirrors the `waygate-llm-providers` test pattern (ephemeral
//! `TcpListener` + `axum::serve`) with a `from_vars`-seeded credential store
//! (no env mutation, so tests stay parallel-safe and side-effect free).
//!
//! Proves the dispatcher composes the pieces: resolves the injected bearer,
//! renders the request with the *resolved upstream* model, calls the provider,
//! and produces the `InferenceRecord` — unary (extracted) and streaming (folded
//! through the aggregator) — and fails closed on a missing credential or an
//! unsupported protocol before any call.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use waygate_llm_credentials::{LlmCredentialStore, LlmProvider};
use waygate_llm_dispatch::{DispatchError, DispatchOutcome, LlmDispatcher, ResolvedRoute};
use waygate_llm_providers::{
    codex_fp_user_agent, ProviderClient, ProviderError, SharedCodexUaVersion,
    CODEX_FP_DEFAULT_VERSION,
};
use waygate_llm_translate::{
    parse_chat_completions, parse_embeddings, parse_responses, EmbeddingsRequest, FinishReason,
    LlmRequest, OpenAiChatStreamAggregator, Surface, UpstreamProtocol,
};

#[derive(Default)]
struct Captured {
    authorization: Option<String>,
    x_api_key: Option<String>,
    anthropic_beta: Option<String>,
    model: Option<String>,
    max_tokens: Option<u64>,
    stream_options_include_usage: Option<bool>,
    /// The full request body as seen on the wire (used by the Codex body-contract
    /// test to assert the exact shape the ChatGPT backend requires).
    body: Option<Value>,
    /// The `User-Agent` seen on the wire (used by the Codex fingerprint test to
    /// assert dispatch threads the shared UA version through to the header).
    user_agent: Option<String>,
}

async fn unary_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Ok(v) = serde_json::from_str::<Value>(&body) {
        let mut c = captured.lock().unwrap();
        c.authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        c.model = v.get("model").and_then(Value::as_str).map(str::to_string);
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

async fn stream_handler(State(captured): State<Arc<Mutex<Captured>>>, body: String) -> Response {
    if let Ok(v) = serde_json::from_str::<Value>(&body) {
        let mut c = captured.lock().unwrap();
        c.stream_options_include_usage = v
            .get("stream_options")
            .and_then(|s| s.get("include_usage"))
            .and_then(Value::as_bool);
    }
    let sse = concat!(
        "data: {\"id\":\"chatcmpl-7\",\"model\":\"served-x\",\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n",
        "data: {\"id\":\"chatcmpl-7\",\"model\":\"served-x\",\"choices\":[{\"delta\":{\"content\":\"llo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"id\":\"chatcmpl-7\",\"model\":\"served-x\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n",
        "data: [DONE]\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn store() -> Arc<LlmCredentialStore> {
    // An OpenRouter API-key credential: the injected value is the bare key.
    Arc::new(LlmCredentialStore::from_vars([(
        "LLM_CRED_OPENROUTER_MAIN".to_string(),
        "sk-test-key".to_string(),
    )]))
}

fn route(addr: SocketAddr, label: &str) -> ResolvedRoute {
    ResolvedRoute {
        provider: LlmProvider::OpenRouter,
        credential_label: label.to_string(),
        base_url: format!("http://{addr}"),
        path: "chat/completions".to_string(),
        upstream_model: "openrouter/served-x".to_string(),
        protocol: UpstreamProtocol::OpenAiChat,
        embeddings_no_auth: false,
        openai_chatgpt: false,
    }
}

fn chat(stream: bool) -> LlmRequest {
    parse_chat_completions(&json!({
        "model": "alias",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": stream
    }))
    .unwrap()
}

/// A Responses-surface request (`inbound_surface = Responses`) — exercises the
/// surface-aware egress (dispatch renders the canonical response to the Responses
/// shape, not chat).
fn responses_req() -> LlmRequest {
    parse_responses(&json!({"model": "alias", "input": "hi"})).unwrap()
}

#[tokio::test]
async fn unary_dispatch_resolves_bearer_renders_upstream_model_and_extracts() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/chat/completions", post(unary_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let outcome = dispatcher
        .dispatch(&chat(false), &route(addr, "MAIN"))
        .await
        .expect("dispatch");

    match outcome {
        DispatchOutcome::Unary { record, body } => {
            assert_eq!(record.model_served.as_deref(), Some("served-x"));
            assert_eq!(record.usage.input, Some(3));
            assert_eq!(record.usage.output, Some(1));
            assert_eq!(record.finish_reason, Some(FinishReason::Stop));
            assert_eq!(record.provider, LlmProvider::OpenRouter);
            assert_eq!(record.credential_label, "MAIN");
            // Requested alias is preserved distinct from the served model.
            assert_eq!(record.model_requested, "alias");
            assert_eq!(body["id"], "chatcmpl-7");
        }
        other => panic!("expected Unary, got {other:?}"),
    }

    let c = captured.lock().unwrap();
    assert_eq!(c.authorization.as_deref(), Some("Bearer sk-test-key"));
    // The dispatcher renders the *resolved upstream* model, not the alias.
    assert_eq!(c.model.as_deref(), Some("openrouter/served-x"));
}

#[tokio::test]
async fn streaming_dispatch_yields_frames_that_fold_into_the_record() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/chat/completions", post(stream_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let outcome = dispatcher
        .dispatch(&chat(true), &route(addr, "MAIN"))
        .await
        .expect("dispatch");

    let (record_base, mut frames) = match outcome {
        DispatchOutcome::Stream {
            record_base,
            frames,
        } => (record_base, frames),
        other => panic!("expected Stream, got {other:?}"),
    };

    // Fold the streamed frames exactly as the egress layer will.
    let mut agg = OpenAiChatStreamAggregator::new(record_base);
    let mut frame_count = 0;
    while let Some(frame) = frames.next().await {
        let ev = frame.expect("frame");
        agg.observe_data(&ev.data);
        frame_count += 1;
    }
    let record = agg.finish();

    assert_eq!(frame_count, 4, "three chunks + [DONE]");
    assert_eq!(record.model_served.as_deref(), Some("served-x"));
    assert_eq!(record.finish_reason, Some(FinishReason::Stop));
    assert_eq!(record.usage.input, Some(3));
    assert_eq!(record.usage.output, Some(2));
    assert_eq!(record.model_requested, "alias");

    // The dispatcher rendered a streaming body opting into usage reporting.
    assert_eq!(
        captured.lock().unwrap().stream_options_include_usage,
        Some(true)
    );
}

#[tokio::test]
async fn missing_credential_fails_closed_before_any_call() {
    // Point at an unroutable base_url so a *call* would fail loudly; the
    // missing credential must trip first (before the provider is contacted).
    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let bogus = ResolvedRoute {
        base_url: "http://127.0.0.1:1".to_string(),
        ..route("127.0.0.1:1".parse().unwrap(), "DOES_NOT_EXIST")
    };
    let err = dispatcher
        .dispatch(&chat(false), &bogus)
        .await
        .expect_err("should fail closed");
    assert!(matches!(err, DispatchError::Credential(_)), "got {err:?}");
}

/// Loopback OpenAI Responses SSE provider: emits the `/responses` streamed event
/// sequence (response.created → output_text.delta → response.completed) with no
/// `[DONE]` sentinel, mirroring the real Responses API.
async fn responses_stream_handler() -> Response {
    let sse = concat!(
        "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.4\",\"status\":\"in_progress\"}}\n\n",
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Hi\"}\n\n",
        "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.4\",\"status\":\"completed\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

#[tokio::test]
async fn responses_streaming_dispatch_returns_frames() {
    // OpenAI-Responses streaming: dispatch returns the raw provider event
    // stream; the egress (waygate-mcp) selects the Responses SSE translator from
    // record_base's protocol to map events → OpenAI chunks. Streaming is
    // body-driven, so the path is the same `responses` endpoint as unary.
    let app = Router::new().route("/responses", post(responses_stream_handler));
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        responses_store(),
    );
    let outcome = dispatcher
        .dispatch(&chat(true), &responses_route(addr))
        .await
        .expect("responses streaming dispatch");

    let (record_base, mut frames) = match outcome {
        DispatchOutcome::Stream {
            record_base,
            frames,
        } => (record_base, frames),
        other => panic!("expected Stream, got {other:?}"),
    };
    assert_eq!(
        record_base.upstream_protocol,
        UpstreamProtocol::OpenAiResponses
    );
    // The raw frames are Responses events (translation happens in the egress).
    let first = frames.next().await.expect("a frame").expect("frame ok");
    assert!(
        first.data.contains("response.created"),
        "first frame is a Responses event: {}",
        first.data
    );
}

/// Loopback Anthropic Messages SSE provider: emits the event sequence Anthropic
/// streams (message_start → content_block_delta → message_delta → message_stop).
async fn anthropic_stream_handler() -> Response {
    let sse = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-served-x\",\"usage\":{\"input_tokens\":5}}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

#[tokio::test]
async fn anthropic_streaming_returns_a_stream_of_provider_events() {
    // Anthropic streaming is supported: dispatch returns the raw provider
    // event stream; the egress (waygate-mcp) selects the Anthropic SSE translator
    // from record_base's protocol to map events → OpenAI chunks. Here we assert
    // dispatch no longer fails closed and surfaces the Anthropic events.
    let app = Router::new().route("/messages", post(anthropic_stream_handler));
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let outcome = dispatcher
        .dispatch(&chat(true), &anthropic_route(addr))
        .await
        .expect("anthropic streaming dispatch");

    let (record_base, mut frames) = match outcome {
        DispatchOutcome::Stream {
            record_base,
            frames,
        } => (record_base, frames),
        other => panic!("expected Stream, got {other:?}"),
    };
    assert_eq!(
        record_base.upstream_protocol,
        UpstreamProtocol::AnthropicMessages
    );
    // The raw frames are Anthropic events (translation happens in the egress).
    let first = frames.next().await.expect("a frame").expect("frame ok");
    assert!(
        first.data.contains("message_start"),
        "first frame is the Anthropic message_start event: {}",
        first.data
    );
}

/// An Anthropic credential. Anthropic is a first-party `x-api-key` provider, so
/// the injected material is a bare key (not an OAuth blob); `bearer()` returns
/// that key verbatim.
fn anthropic_store() -> Arc<LlmCredentialStore> {
    // Anthropic is an api-key provider: the injected value is the bare key.
    Arc::new(LlmCredentialStore::from_vars([(
        "LLM_CRED_ANTHROPIC_MAIN".to_string(),
        "sk-ant-api03-test".to_string(),
    )]))
}

fn anthropic_route(addr: SocketAddr) -> ResolvedRoute {
    ResolvedRoute {
        provider: LlmProvider::Anthropic,
        credential_label: "MAIN".to_string(),
        base_url: format!("http://{addr}"),
        path: "messages".to_string(),
        upstream_model: "claude-served-x".to_string(),
        protocol: UpstreamProtocol::AnthropicMessages,
        embeddings_no_auth: false,
        openai_chatgpt: false,
    }
}

/// Google credential (OAuth blob — the store treats Google as OAuth).
fn gemini_store() -> Arc<LlmCredentialStore> {
    let blob = r#"{"tokens":{"access_token":"ya29-test","refresh_token":"rt"},"expires_at":"2099-01-01T00:00:00Z"}"#;
    Arc::new(LlmCredentialStore::from_vars([(
        "LLM_CRED_GOOGLE_MAIN".to_string(),
        blob.to_string(),
    )]))
}

fn gemini_route(addr: SocketAddr) -> ResolvedRoute {
    ResolvedRoute {
        provider: LlmProvider::Google,
        credential_label: "MAIN".to_string(),
        base_url: format!("http://{addr}"),
        // Unused for Gemini — dispatch templates `v1beta/models/<model>:...`.
        path: "v1beta".to_string(),
        upstream_model: "gemini-served-x".to_string(),
        protocol: UpstreamProtocol::Gemini,
        embeddings_no_auth: false,
        openai_chatgpt: false,
    }
}

/// Loopback Gemini provider: captures the bearer and returns a Gemini
/// `generateContent` response so the extractor + translation can be exercised.
async fn gemini_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    _body: String,
) -> Response {
    {
        let mut c = captured.lock().unwrap();
        c.authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
    }
    let resp = json!({
        "responseId": "resp_1",
        "modelVersion": "gemini-served-x",
        "candidates": [{"finishReason":"STOP","content":{"role":"model","parts":[{"text":"hi"}]}}],
        "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2, "totalTokenCount": 7}
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(resp))
        .unwrap()
}

#[tokio::test]
async fn gemini_unary_dispatch_templates_path_renders_and_extracts() {
    // Gemini puts the model in the URL path; dispatch templates
    // `v1beta/models/<model>:generateContent`. A successful Unary outcome proves
    // the templated path matched the loopback route (a wrong path would 404).
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route(
            "/v1beta/models/gemini-served-x:generateContent",
            post(gemini_handler),
        )
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher =
        LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), gemini_store());
    let outcome = dispatcher
        .dispatch(&chat(false), &gemini_route(addr))
        .await
        .expect("gemini unary dispatch");

    let (record, body) = match outcome {
        DispatchOutcome::Unary { record, body } => (record, body),
        other => panic!("expected Unary, got {other:?}"),
    };
    assert_eq!(record.upstream_protocol, UpstreamProtocol::Gemini);
    assert_eq!(record.usage.input, Some(5));
    assert_eq!(record.usage.output, Some(2));
    assert_eq!(record.finish_reason, Some(FinishReason::Stop));
    assert_eq!(record.model_served.as_deref(), Some("gemini-served-x"));

    // Client body is the OpenAI shape, translated from the Gemini response.
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["content"], "hi");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["prompt_tokens"], 5);

    // OAuth bearer (the store resolves Google as OAuth).
    let c = captured.lock().unwrap();
    assert_eq!(c.authorization.as_deref(), Some("Bearer ya29-test"));
}

/// Loopback Gemini SSE provider: emits the `streamGenerateContent?alt=sse` frame
/// sequence — an incremental content chunk, then a final chunk carrying
/// `finishReason` + `usageMetadata` (Gemini sends no `[DONE]` sentinel).
async fn gemini_stream_handler() -> Response {
    let sse = concat!(
        "data: {\"responseId\":\"resp_1\",\"modelVersion\":\"gemini-served-x\",\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hi\"}]}}]}\n\n",
        "data: {\"candidates\":[{\"finishReason\":\"STOP\",\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"!\"}]}}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":2}}\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

#[tokio::test]
async fn gemini_streaming_dispatch_templates_sse_path_and_returns_frames() {
    // Gemini streaming templates the SSE method into the URL path
    // (`:streamGenerateContent?alt=sse`); a Stream outcome proves the templated
    // path matched the loopback route (a wrong path would 404). The egress
    // (waygate-mcp) selects the Gemini SSE translator from record_base's protocol
    // to map the raw Gemini frames to OpenAI chunks.
    let app = Router::new().route(
        "/v1beta/models/gemini-served-x:streamGenerateContent",
        post(gemini_stream_handler),
    );
    let addr = spawn(app).await;

    let dispatcher =
        LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), gemini_store());
    let outcome = dispatcher
        .dispatch(&chat(true), &gemini_route(addr))
        .await
        .expect("gemini streaming dispatch");

    let (record_base, mut frames) = match outcome {
        DispatchOutcome::Stream {
            record_base,
            frames,
        } => (record_base, frames),
        other => panic!("expected Stream, got {other:?}"),
    };
    assert_eq!(record_base.upstream_protocol, UpstreamProtocol::Gemini);
    // The raw frames are Gemini events (translation happens in the egress).
    let first = frames.next().await.expect("a frame").expect("frame ok");
    assert!(
        first.data.contains("gemini-served-x"),
        "first frame is a Gemini streamGenerateContent chunk: {}",
        first.data
    );
}

/// Loopback Anthropic Messages provider: captures the `x-api-key` header and the
/// request body's `model` / `max_tokens`, and returns an Anthropic-shaped
/// response so the extractor branch can be exercised end-to-end.
async fn anthropic_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Ok(v) = serde_json::from_str::<Value>(&body) {
        let mut c = captured.lock().unwrap();
        c.authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        c.x_api_key = headers
            .get("x-api-key")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        c.anthropic_beta = headers
            .get("anthropic-beta")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        c.model = v.get("model").and_then(Value::as_str).map(str::to_string);
        c.max_tokens = v.get("max_tokens").and_then(Value::as_u64);
        c.body = Some(v);
    }
    let resp = json!({
        "id": "msg_7",
        "model": "claude-served-x",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "hi"}],
        "usage": {"input_tokens": 12, "output_tokens": 4}
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(resp))
        .unwrap()
}

#[tokio::test]
async fn anthropic_unary_dispatch_renders_anthropic_body_and_extracts() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/messages", post(anthropic_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let outcome = dispatcher
        .dispatch(&chat(false), &anthropic_route(addr))
        .await
        .expect("anthropic unary dispatch");

    // Extracted via the Anthropic branch: usage.input comes from
    // `input_tokens` (not OpenAI's `prompt_tokens`), and the Anthropic
    // `end_turn` stop_reason normalizes to Stop.
    let (record, body) = match outcome {
        DispatchOutcome::Unary { record, body } => (record, body),
        other => panic!("expected Unary, got {other:?}"),
    };
    assert_eq!(
        record.upstream_protocol,
        UpstreamProtocol::AnthropicMessages
    );
    assert_eq!(record.usage.input, Some(12));
    assert_eq!(record.usage.output, Some(4));
    assert_eq!(record.finish_reason, Some(FinishReason::Stop));
    assert_eq!(record.model_served.as_deref(), Some("claude-served-x"));

    // The client-facing body is translated to the OpenAI chat-completions shape
    // (NOT the raw Anthropic Messages body) — the gateway's /v1/chat/completions
    // contract holds regardless of the upstream provider.
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["content"], "hi");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["prompt_tokens"], 12);
    assert_eq!(body["usage"]["completion_tokens"], 4);

    let c = captured.lock().unwrap();
    // Anthropic auth is a first-party API key in `x-api-key` — no `Authorization:
    // Bearer`, no OAuth `anthropic-beta` fingerprint. The resolved upstream model
    // and the (defaulted) `max_tokens` made it onto the wire.
    assert_eq!(c.x_api_key.as_deref(), Some("sk-ant-api03-test"));
    assert_eq!(c.authorization, None, "no Authorization: Bearer");
    assert_eq!(
        c.anthropic_beta, None,
        "no OAuth anthropic-beta fingerprint"
    );
    assert_eq!(c.model.as_deref(), Some("claude-served-x"));
    assert!(
        c.max_tokens.is_some(),
        "Anthropic render must set max_tokens"
    );
}

#[tokio::test]
async fn responses_surface_unary_dispatch_renders_a_responses_body() {
    // A Responses-surface request routed to an Anthropic upstream: the client body
    // is the *Responses* shape (provider → CanonicalResponse → responses), not chat
    // — the surface-aware egress. The metadata record is still the Anthropic branch.
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/messages", post(anthropic_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    );
    let outcome = dispatcher
        .dispatch(&responses_req(), &anthropic_route(addr))
        .await
        .expect("responses-surface dispatch");
    let (record, body) = match outcome {
        DispatchOutcome::Unary { record, body } => (record, body),
        other => panic!("expected Unary, got {other:?}"),
    };
    // Record extraction is unchanged (the Anthropic branch).
    assert_eq!(
        record.upstream_protocol,
        UpstreamProtocol::AnthropicMessages
    );
    assert_eq!(record.usage.input, Some(12));
    assert_eq!(record.finish_reason, Some(FinishReason::Stop));
    // The client-facing body is the OpenAI **Responses** shape, not chat.
    assert_eq!(body["object"], "response");
    assert_eq!(body["status"], "completed");
    assert_eq!(body["model"], "claude-served-x");
    assert_eq!(body["output"][0]["type"], "message");
    assert_eq!(body["output"][0]["content"][0]["type"], "output_text");
    assert_eq!(body["output"][0]["content"][0]["text"], "hi");
    assert_eq!(body["usage"]["input_tokens"], 12);
    assert_eq!(body["usage"]["output_tokens"], 4);
}

/// OpenAI credential (OAuth blob — the store treats OpenAI as OAuth). Far-future
/// expiry so no refresh is attempted.
fn responses_store() -> Arc<LlmCredentialStore> {
    let blob = r#"{"tokens":{"access_token":"sk-oai-test","refresh_token":"rt","account_id":"test-codex-account"},"expires_at":"2099-01-01T00:00:00Z"}"#;
    Arc::new(LlmCredentialStore::from_vars([(
        "LLM_CRED_OPENAI_MAIN".to_string(),
        blob.to_string(),
    )]))
}

fn responses_route(addr: SocketAddr) -> ResolvedRoute {
    ResolvedRoute {
        provider: LlmProvider::OpenAi,
        credential_label: "MAIN".to_string(),
        base_url: format!("http://{addr}"),
        // The Responses surface lives at `responses` (server wires it from a
        // model's `surface: responses`).
        path: "responses".to_string(),
        upstream_model: "gpt-5.4".to_string(),
        protocol: UpstreamProtocol::OpenAiResponses,
        embeddings_no_auth: false,
        openai_chatgpt: false,
    }
}

/// Same Responses surface, but flagged as the ChatGPT (Codex) backend — dispatch
/// must run the Codex body finalizer and use the Codex auth fingerprint.
fn codex_route(addr: SocketAddr) -> ResolvedRoute {
    ResolvedRoute {
        embeddings_no_auth: false,
        openai_chatgpt: true,
        upstream_model: "gpt-5.5".to_string(),
        ..responses_route(addr)
    }
}

/// A streaming chat request that carries the fields a Codex call must NOT forward
/// (temperature/top_p/max_tokens) plus a system message — exercises both the
/// strip and the instructions normalization in one shot.
fn codex_chat() -> LlmRequest {
    parse_chat_completions(&json!({
        "model": "alias",
        "messages": [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"}
        ],
        "temperature": 0.7,
        "top_p": 0.9,
        "max_tokens": 256,
        "stream": true
    }))
    .unwrap()
}

/// Loopback Codex backend: records the full request body, then returns a minimal
/// Responses SSE stream so dispatch settles a `Stream` outcome cleanly.
async fn codex_capture_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    {
        let mut c = captured.lock().unwrap();
        if let Ok(v) = serde_json::from_str::<Value>(&body) {
            c.body = Some(v);
        }
        c.user_agent = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
    }
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(concat!(
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",",
            "\"model\":\"gpt-5.5\",\"status\":\"completed\",",
            "\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        )))
        .unwrap()
}

#[tokio::test]
async fn codex_backend_dispatch_sends_a_codex_valid_body() {
    // Regression for the "Instructions are required" 400 and the
    // unsupported-parameter 400s: a Codex route (openai_chatgpt=true) must put a
    // body the ChatGPT backend accepts on the wire — `instructions` present,
    // `stream:true`, `store:false`, `include` set, and NONE of the sampling/token
    // fields that `render_openai_responses` would otherwise have set.
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/responses", post(codex_capture_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        responses_store(),
    );
    let outcome = dispatcher
        .dispatch(&codex_chat(), &codex_route(addr))
        .await
        .expect("streaming codex dispatch");
    match outcome {
        DispatchOutcome::Stream { record_base, .. } => {
            assert_eq!(
                record_base.provider_account_id.as_deref(),
                Some("test-codex-account")
            );
        }
        _ => panic!("a streaming Codex call yields a Stream outcome"),
    }

    let body = captured
        .lock()
        .unwrap()
        .body
        .clone()
        .expect("body captured");
    // Required-present fields.
    assert_eq!(
        body["instructions"], "be terse",
        "the system message renders to `instructions` (present is mandatory)"
    );
    assert_eq!(body["stream"], true);
    assert_eq!(body["store"], false);
    assert_eq!(body["parallel_tool_calls"], true);
    assert_eq!(body["include"], json!(["reasoning.encrypted_content"]));
    assert_eq!(
        body["model"], "gpt-5.5",
        "the resolved upstream model is on the wire"
    );
    // Backend-rejected fields stripped.
    for f in [
        "temperature",
        "top_p",
        "max_output_tokens",
        "max_completion_tokens",
    ] {
        assert!(
            body.get(f).is_none(),
            "`{f}` must be stripped for the Codex backend"
        );
    }
}

#[tokio::test]
async fn codex_dispatch_user_agent_tracks_the_shared_version() {
    // Dispatch reads the shared Codex UA version handle PER REQUEST, so the
    // /responses fingerprint follows the version the discovery refresher
    // hot-swaps in — and without a wired handle it falls back to the compiled
    // default. This is the seam that keeps /models and /responses presenting
    // one client identity.
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/responses", post(codex_capture_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    // No handle wired ⇒ the compiled default drives the UA.
    let bare = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        responses_store(),
    );
    bare.dispatch(&codex_chat(), &codex_route(addr))
        .await
        .expect("codex dispatch without a handle");
    assert_eq!(
        captured.lock().unwrap().user_agent.as_deref(),
        Some(codex_fp_user_agent(CODEX_FP_DEFAULT_VERSION).as_str()),
        "unwired handle falls back to the compiled default"
    );

    // A wired handle drives the UA — and a hot-swap between requests is
    // visible on the very next call (per-request read, no caching).
    let handle: SharedCodexUaVersion = Arc::new(std::sync::RwLock::new("9.8.7".to_string()));
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        responses_store(),
    )
    .with_codex_ua_version(handle.clone());
    dispatcher
        .dispatch(&codex_chat(), &codex_route(addr))
        .await
        .expect("codex dispatch with a handle");
    assert_eq!(
        captured.lock().unwrap().user_agent.as_deref(),
        Some(codex_fp_user_agent("9.8.7").as_str()),
    );
    *handle.write().unwrap() = "9.8.8".to_string();
    dispatcher
        .dispatch(&codex_chat(), &codex_route(addr))
        .await
        .expect("codex dispatch after the hot-swap");
    assert_eq!(
        captured.lock().unwrap().user_agent.as_deref(),
        Some(codex_fp_user_agent("9.8.8").as_str()),
        "the refreshed version reaches the next request's User-Agent"
    );
}

#[tokio::test]
async fn codex_backend_rejects_a_non_streaming_call_before_dispatch() {
    // The ChatGPT backend is streaming-only and this slice does not aggregate an
    // upstream stream into a unary body, so a non-streaming Codex request must
    // fail closed with a clear, non-retryable error rather than sending a body
    // whose `stream:true` contradicts a unary transport. No provider is contacted.
    let unreachable = ResolvedRoute {
        base_url: "http://127.0.0.1:1".to_string(),
        ..codex_route("127.0.0.1:1".parse().unwrap())
    };
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        responses_store(),
    );
    let err = dispatcher
        .dispatch(&chat(false), &unreachable)
        .await
        .expect_err("non-streaming codex must fail closed");
    assert!(
        matches!(err, DispatchError::Translate(_)),
        "expected a non-retryable translation error, got {err:?}"
    );
}

/// Loopback OpenAI Responses provider: captures the bearer + the request body's
/// `model`, and returns a Responses-shaped body so the extractor + translation
/// branch can be exercised end-to-end.
async fn responses_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Ok(v) = serde_json::from_str::<Value>(&body) {
        let mut c = captured.lock().unwrap();
        c.authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        c.model = v.get("model").and_then(Value::as_str).map(str::to_string);
    }
    let resp = json!({
        "id": "resp_1",
        "model": "gpt-5.4",
        "status": "completed",
        "output": [{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],
        "usage": {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7}
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(resp))
        .unwrap()
}

#[tokio::test]
async fn responses_unary_dispatch_renders_responses_body_and_extracts() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/responses", post(responses_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        responses_store(),
    );
    let outcome = dispatcher
        .dispatch(&chat(false), &responses_route(addr))
        .await
        .expect("responses unary dispatch");

    // Extracted via the OpenAI-Responses branch: usage.input from `input_tokens`,
    // and `status: completed` normalizes to Stop.
    let (record, body) = match outcome {
        DispatchOutcome::Unary { record, body } => (record, body),
        other => panic!("expected Unary, got {other:?}"),
    };
    assert_eq!(record.upstream_protocol, UpstreamProtocol::OpenAiResponses);
    assert_eq!(record.usage.input, Some(5));
    assert_eq!(record.usage.output, Some(2));
    assert_eq!(record.finish_reason, Some(FinishReason::Stop));
    assert_eq!(record.model_served.as_deref(), Some("gpt-5.4"));

    // Client body is the OpenAI chat shape, translated from the Responses body.
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["content"], "hi");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["prompt_tokens"], 5);

    let c = captured.lock().unwrap();
    // OpenAI Responses auth is Bearer; the resolved upstream model went on the wire.
    assert_eq!(c.authorization.as_deref(), Some("Bearer sk-oai-test"));
    assert_eq!(c.model.as_deref(), Some("gpt-5.4"));
}

// ---- Credential-pool failover ---------------------------------------------

async fn bad_request_handler() -> Response {
    Response::builder()
        .status(400)
        .body(Body::from("bad request"))
        .unwrap()
}

/// A two-label OpenRouter pool (API keys), so dispatch can fail over from MAIN to
/// BACKUP.
fn pool_store() -> Arc<LlmCredentialStore> {
    Arc::new(LlmCredentialStore::from_vars([
        (
            "LLM_CRED_OPENROUTER_MAIN".to_string(),
            "sk-primary".to_string(),
        ),
        (
            "LLM_CRED_OPENROUTER_BACKUP".to_string(),
            "sk-backup".to_string(),
        ),
    ]))
}

#[tokio::test]
async fn failover_advances_past_a_retryable_failure_to_a_healthy_credential() {
    // The primary target is unreachable (connection refused → transport error,
    // which is retryable); dispatch must fail over to the fallback credential /
    // endpoint and return ITS success, authenticated with the fallback bearer.
    let captured = Arc::new(Mutex::new(Captured::default()));
    let good = spawn(
        Router::new()
            .route("/chat/completions", post(unary_handler))
            .with_state(captured.clone()),
    )
    .await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), pool_store());
    let primary = route("127.0.0.1:1".parse().unwrap(), "MAIN"); // refused → transport
    let fallback = route(good, "BACKUP");
    let outcome = dispatcher
        .dispatch_with_failover(
            &chat(false),
            &primary,
            std::slice::from_ref(&fallback),
            None,
        )
        .await
        .expect("failover reaches the healthy fallback");
    match outcome {
        DispatchOutcome::Unary { record, .. } => {
            assert_eq!(record.model_served.as_deref(), Some("served-x"));
        }
        other => panic!("expected Unary, got {other:?}"),
    }
    // The fallback credential (BACKUP) served it — failover swapped the bearer.
    assert_eq!(
        captured.lock().unwrap().authorization.as_deref(),
        Some("Bearer sk-backup")
    );
}

#[tokio::test]
async fn non_retryable_error_does_not_fail_over() {
    // A 400 from the primary is a client error, not a credential problem, so the
    // dispatcher must return it immediately WITHOUT trying the fallback (another
    // credential of the same provider would fail identically).
    let bad = spawn(Router::new().route("/chat/completions", post(bad_request_handler))).await;
    let captured = Arc::new(Mutex::new(Captured::default()));
    let good = spawn(
        Router::new()
            .route("/chat/completions", post(unary_handler))
            .with_state(captured.clone()),
    )
    .await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), pool_store());
    let primary = route(bad, "MAIN");
    let fallback = route(good, "BACKUP");
    let err = dispatcher
        .dispatch_with_failover(
            &chat(false),
            &primary,
            std::slice::from_ref(&fallback),
            None,
        )
        .await
        .expect_err("a 400 is terminal");
    assert!(
        matches!(
            err,
            DispatchError::Provider(ProviderError::Status { status: 400, .. })
        ),
        "got {err:?}"
    );
    // The fallback endpoint was never contacted.
    assert!(captured.lock().unwrap().authorization.is_none());
}

/// A 503 handler that counts how many times it was hit (to prove a cooled
/// credential is skipped on a later dispatch).
async fn counting_503_handler(State(hits): State<Arc<AtomicUsize>>) -> Response {
    hits.fetch_add(1, Ordering::SeqCst);
    Response::builder()
        .status(503)
        .body(Body::from("unavailable"))
        .unwrap()
}

#[tokio::test]
async fn a_cooled_credential_is_skipped_on_the_next_dispatch() {
    // First dispatch: the primary 503s (retryable) and is cooled, then the
    // fallback serves it. Second dispatch (same dispatcher, well within the
    // cooldown window): the cooled primary is skipped — its handler is NOT hit
    // again — and the fallback serves directly.
    let primary_hits = Arc::new(AtomicUsize::new(0));
    let bad = spawn(
        Router::new()
            .route("/chat/completions", post(counting_503_handler))
            .with_state(primary_hits.clone()),
    )
    .await;
    let good_captured = Arc::new(Mutex::new(Captured::default()));
    let good = spawn(
        Router::new()
            .route("/chat/completions", post(unary_handler))
            .with_state(good_captured.clone()),
    )
    .await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), pool_store());
    let primary = route(bad, "MAIN");
    let fallback = route(good, "BACKUP");

    dispatcher
        .dispatch_with_failover(
            &chat(false),
            &primary,
            std::slice::from_ref(&fallback),
            None,
        )
        .await
        .expect("first call serves via the fallback");
    assert_eq!(
        primary_hits.load(Ordering::SeqCst),
        1,
        "primary is tried once on the first dispatch"
    );

    dispatcher
        .dispatch_with_failover(
            &chat(false),
            &primary,
            std::slice::from_ref(&fallback),
            None,
        )
        .await
        .expect("second call serves via the fallback");
    assert_eq!(
        primary_hits.load(Ordering::SeqCst),
        1,
        "the cooled primary must be skipped on the second dispatch"
    );
}

/// A handler whose hit count is recorded and whose health is togglable: 200 (a
/// minimal OpenAI body) until `fail` is set, then 503.
#[derive(Default)]
struct Toggle {
    hits: AtomicUsize,
    fail: AtomicBool,
}

async fn toggle_handler(State(t): State<Arc<Toggle>>) -> Response {
    t.hits.fetch_add(1, Ordering::SeqCst);
    if t.fail.load(Ordering::SeqCst) {
        Response::builder()
            .status(503)
            .body(Body::from("unavailable"))
            .unwrap()
    } else {
        let body = json!({
            "id": "chatcmpl-7",
            "model": "served-x",
            "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1}
        })
        .to_string();
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }
}

#[tokio::test]
async fn a_cooled_credential_is_tried_as_a_last_resort_when_the_live_one_fails() {
    // Cool MAIN first (it 503s while BACKUP, healthy, serves). Then make BACKUP
    // start failing: BACKUP (live) is tried first and fails, so the cooled MAIN
    // must STILL be tried as a last resort — cooldown deprioritizes, never
    // hard-blocks. (Regression guard for the order-built-once bug.)
    let main_hits = Arc::new(AtomicUsize::new(0));
    let main = spawn(
        Router::new()
            .route("/chat/completions", post(counting_503_handler))
            .with_state(main_hits.clone()),
    )
    .await;
    let backup = Arc::new(Toggle::default()); // starts healthy
    let backup_addr = spawn(
        Router::new()
            .route("/chat/completions", post(toggle_handler))
            .with_state(backup.clone()),
    )
    .await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), pool_store());
    let primary = route(main, "MAIN");
    let fallback = route(backup_addr, "BACKUP");

    // Call 1: MAIN 503 → cooled; BACKUP (healthy) serves. MAIN tried once.
    dispatcher
        .dispatch_with_failover(
            &chat(false),
            &primary,
            std::slice::from_ref(&fallback),
            None,
        )
        .await
        .expect("served by the healthy backup");
    assert_eq!(main_hits.load(Ordering::SeqCst), 1);

    // BACKUP now starts failing.
    backup.fail.store(true, Ordering::SeqCst);

    // Call 2: BACKUP (live) is tried first and 503s; the cooled MAIN must still
    // be attempted as a last resort, so MAIN is hit a SECOND time.
    let _ = dispatcher
        .dispatch_with_failover(
            &chat(false),
            &primary,
            std::slice::from_ref(&fallback),
            None,
        )
        .await;
    assert_eq!(
        main_hits.load(Ordering::SeqCst),
        2,
        "the cooled MAIN must be tried as a last resort when the live BACKUP fails"
    );
}

/// A streaming handler that returns its 200 headers immediately but stalls well
/// past the test's TTFB before emitting the first body frame — a
/// time-to-first-byte stall (distinct from a slow handshake).
async fn slow_first_frame_handler() -> Response {
    let body = futures::stream::once(async {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Ok::<_, std::io::Error>(String::from(
            "data: {\"id\":\"c\",\"model\":\"slow-primary\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n",
        ))
    });
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(body))
        .unwrap()
}

#[tokio::test]
async fn a_ttfb_stall_fails_over_to_a_healthy_stream() {
    // The primary returns stream headers but stalls before its first frame; with
    // a short TTFB deadline, dispatch must fail over to the healthy fallback
    // stream before any byte reaches the client.
    let slow =
        spawn(Router::new().route("/chat/completions", post(slow_first_frame_handler))).await;
    let fast = spawn(
        Router::new()
            .route("/chat/completions", post(stream_handler))
            .with_state(Arc::new(Mutex::new(Captured::default()))),
    )
    .await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), pool_store());
    let primary = route(slow, "MAIN");
    let fallback = route(fast, "BACKUP");
    let outcome = dispatcher
        .dispatch_with_failover(
            &chat(true),
            &primary,
            std::slice::from_ref(&fallback),
            Some(std::time::Duration::from_millis(150)),
        )
        .await
        .expect("fails over to the healthy fallback stream");

    let mut frames = match outcome {
        DispatchOutcome::Stream { frames, .. } => frames,
        other => panic!("expected Stream, got {other:?}"),
    };
    // The first frame is the fallback's (`served-x`), not the stalled primary's.
    let first = frames.next().await.expect("a frame").expect("frame ok");
    assert!(
        first.data.contains("served-x") && !first.data.contains("slow-primary"),
        "served by the fallback after the TTFB stall: {}",
        first.data
    );
}

// ---- Embeddings dispatch --------------------------------------------------

/// Loopback OpenAI-compatible embeddings provider: captures the bearer + the
/// request body's `model` and `input`, and returns an OpenAI embeddings response
/// so the extractor branch can be exercised end-to-end.
async fn embeddings_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Ok(v) = serde_json::from_str::<Value>(&body) {
        let mut c = captured.lock().unwrap();
        c.authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        c.model = v.get("model").and_then(Value::as_str).map(str::to_string);
        c.body = Some(v);
    }
    let resp = json!({
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
        "model": "served-embed-x",
        "usage": {"prompt_tokens": 7, "total_tokens": 7}
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(resp))
        .unwrap()
}

fn embeddings_route(addr: SocketAddr, label: &str) -> ResolvedRoute {
    ResolvedRoute {
        provider: LlmProvider::OpenRouter,
        credential_label: label.to_string(),
        base_url: format!("http://{addr}"),
        path: "embeddings".to_string(),
        upstream_model: "openrouter/served-embed-x".to_string(),
        // Inert for an embeddings route (dispatch_embeddings never reads it);
        // OpenAI-compatible embeddings auth is plain Bearer, matching OpenAiChat.
        protocol: UpstreamProtocol::OpenAiChat,
        embeddings_no_auth: false,
        openai_chatgpt: false,
    }
}

fn embeddings_req() -> EmbeddingsRequest {
    parse_embeddings(&json!({"model": "alias", "input": "hello world"})).unwrap()
}

#[tokio::test]
async fn embeddings_unary_dispatch_resolves_bearer_renders_upstream_model_and_extracts() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/embeddings", post(embeddings_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let (record, body) = dispatcher
        .dispatch_embeddings(&embeddings_req(), &embeddings_route(addr, "MAIN"))
        .await
        .expect("embeddings dispatch");

    // Record: input-only usage (no output class), served model, embeddings
    // surface, no finish reason.
    assert_eq!(record.usage.input, Some(7));
    assert_eq!(record.usage.output, None);
    assert_eq!(record.model_served.as_deref(), Some("served-embed-x"));
    assert_eq!(record.model_requested, "alias");
    assert_eq!(record.inbound_surface, Surface::Embeddings);
    assert_eq!(record.finish_reason, None);
    assert_eq!(record.provider, LlmProvider::OpenRouter);
    assert_eq!(record.credential_label, "MAIN");

    // The provider's OpenAI embeddings body is returned to the client verbatim.
    assert_eq!(body["object"], "list");
    assert_eq!(body["data"][0]["embedding"][0], 0.1);

    let c = captured.lock().unwrap();
    assert_eq!(c.authorization.as_deref(), Some("Bearer sk-test-key"));
    // The dispatcher renders the *resolved upstream* model, not the alias, and
    // forwards the input verbatim.
    assert_eq!(c.model.as_deref(), Some("openrouter/served-embed-x"));
    assert_eq!(
        c.body.as_ref().and_then(|b| b.get("input")),
        Some(&json!("hello world"))
    );
}

#[tokio::test]
async fn embeddings_missing_credential_fails_closed_before_any_call() {
    // An unroutable base_url would fail loudly if contacted; the missing
    // credential must trip first (before the provider is contacted).
    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let bogus = ResolvedRoute {
        base_url: "http://127.0.0.1:1".to_string(),
        ..embeddings_route("127.0.0.1:1".parse().unwrap(), "DOES_NOT_EXIST")
    };
    let err = dispatcher
        .dispatch_embeddings(&embeddings_req(), &bogus)
        .await
        .expect_err("should fail closed");
    assert!(matches!(err, DispatchError::Credential(_)), "got {err:?}");
}

#[tokio::test]
async fn embeddings_failover_advances_past_a_retryable_failure_to_a_healthy_credential() {
    // The primary target is unreachable (connection refused → retryable transport
    // error); dispatch must fail over to the healthy fallback credential/endpoint
    // and return ITS success, authenticated with the fallback bearer.
    let captured = Arc::new(Mutex::new(Captured::default()));
    let good = spawn(
        Router::new()
            .route("/embeddings", post(embeddings_handler))
            .with_state(captured.clone()),
    )
    .await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), pool_store());
    let primary = embeddings_route("127.0.0.1:1".parse().unwrap(), "MAIN"); // refused
    let fallback = embeddings_route(good, "BACKUP");
    let (record, _body) = dispatcher
        .dispatch_embeddings_with_failover(
            &embeddings_req(),
            &primary,
            std::slice::from_ref(&fallback),
        )
        .await
        .expect("failover reaches the healthy fallback");
    assert_eq!(record.model_served.as_deref(), Some("served-embed-x"));
    // The fallback credential (BACKUP) served it — failover swapped the bearer.
    assert_eq!(
        captured.lock().unwrap().authorization.as_deref(),
        Some("Bearer sk-backup")
    );
}

#[tokio::test]
async fn embeddings_non_retryable_error_does_not_fail_over() {
    // A 400 from the primary is a client error, not a credential problem, so the
    // dispatcher must return it immediately WITHOUT trying the fallback.
    let bad = spawn(Router::new().route("/embeddings", post(bad_request_handler))).await;
    let captured = Arc::new(Mutex::new(Captured::default()));
    let good = spawn(
        Router::new()
            .route("/embeddings", post(embeddings_handler))
            .with_state(captured.clone()),
    )
    .await;

    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), pool_store());
    let primary = embeddings_route(bad, "MAIN");
    let fallback = embeddings_route(good, "BACKUP");
    let err = dispatcher
        .dispatch_embeddings_with_failover(
            &embeddings_req(),
            &primary,
            std::slice::from_ref(&fallback),
        )
        .await
        .expect_err("a 400 is terminal");
    assert!(
        matches!(
            err,
            DispatchError::Provider(ProviderError::Status { status: 400, .. })
        ),
        "got {err:?}"
    );
    // The fallback endpoint was never contacted.
    assert!(captured.lock().unwrap().authorization.is_none());
}

#[tokio::test]
async fn private_embeddings_preserve_base64_options_without_sending_credentials() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    async fn backend(
        State(captured): State<Arc<Mutex<Captured>>>,
        headers: HeaderMap,
        axum::Json(body): axum::Json<Value>,
    ) -> axum::Json<Value> {
        let mut c = captured.lock().unwrap();
        c.authorization = headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned());
        c.body = Some(body);
        axum::Json(
            json!({"object":"list","data":[{"index":0,"embedding":"AACAPw=="}],
            "model":"voyageai/voyage-4-nano","usage":{"prompt_tokens":7,"total_tokens":7}}),
        )
    }
    let addr = spawn(
        Router::new()
            .route("/embeddings", post(backend))
            .with_state(captured.clone()),
    )
    .await;
    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store());
    let mut route = embeddings_route(addr, "NOT_CONFIGURED");
    route.embeddings_no_auth = true;
    route.upstream_model = "voyageai/voyage-4-nano".into();
    let request = parse_embeddings(&json!({"model":"voyage-4-nano","input":["technical text"],
        "encoding_format":"base64","dimensions":2048,"input_type":"document",
        "prompt_mode":"auto","timeout_seconds":120.0}))
    .unwrap();
    let (record, response) = dispatcher
        .dispatch_embeddings(&request, &route)
        .await
        .unwrap();
    assert_eq!(response["data"][0]["embedding"], "AACAPw==");
    assert_eq!(record.usage.input, Some(7));
    let c = captured.lock().unwrap();
    assert!(c.authorization.is_none());
    assert_eq!(
        c.body.as_ref().unwrap(),
        &json!({
            "model":"voyageai/voyage-4-nano","input":["technical text"],
            "encoding_format":"base64","dimensions":2048,"input_type":"document",
            "prompt_mode":"auto","timeout_seconds":120.0
        })
    );
}

#[tokio::test]
async fn invalid_image_responses_record_account_failures_once() {
    for (name, response) in [
        (
            "image-missing-created",
            json!({"data":[{"b64_json":"YQ=="}]}),
        ),
        ("image-empty-data", json!({"created":1,"data":[]})),
        (
            "image-valid",
            json!({"created":1,"data":[{"b64_json":"YQ=="}]}),
        ),
    ] {
        let addr = spawn(Router::new().route(
            "/images/generations",
            post(move || {
                let response = response.clone();
                async move { axum::Json(response) }
            }),
        ))
        .await;
        let mut route = codex_route(addr);
        route.path = "images".into();
        let dispatcher = LlmDispatcher::new(
            ProviderClient::new(reqwest::Client::new())
                .with_single_attempt_http(reqwest::Client::builder())
                .unwrap(),
            responses_store(),
        );
        let request = waygate_llm_translate::images::parse_images(
            json!({"model":name,"prompt":"test"}),
            false,
        )
        .unwrap();
        let result = dispatcher.dispatch_images(request, &route).await;
        assert_eq!(result.is_ok(), name == "image-valid", "{result:?}");
        let metrics = waygate_telemetry::gather_text();
        for metric in [
            "gen_ai_client_request_failures_total",
            "gen_ai_client_duration_seconds_count",
        ] {
            let line = metrics.lines().find(|line| {
                line.starts_with(metric) && line.contains(&format!("model=\"{name}\""))
            });
            if name == "image-valid" {
                assert!(line.is_none());
            } else {
                let line = line.expect("failed image metric");
                assert!(line.contains("user_account_id=\"test-codex-account\""));
                assert!(line.ends_with(" 1"), "{line}");
            }
        }
    }
}
