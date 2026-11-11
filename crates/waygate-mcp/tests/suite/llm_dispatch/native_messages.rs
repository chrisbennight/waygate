//! The provider-native Anthropic Messages surface: the body reaches the
//! provider untranslated, and every governance stage still applies.

use super::*;
use futures::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A Messages body using features the canonical model rejects or cannot
/// represent: a prompt-cache breakpoint, extended thinking, and native
/// `tool_use` / `tool_result` blocks.
fn native_body(stream: bool) -> Map<String, Value> {
    json!({
        "model": "claude-x",
        "max_tokens": 256,
        "stream": stream,
        "system": [{
            "type": "text",
            "text": "long reusable instructions",
            "cache_control": {"type": "ephemeral"}
        }],
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "tools": [{"name": "lookup", "description": "fixture", "defer_loading": true, "input_schema": {"type": "object"}}],
        "output_config": {"effort": "medium"},
        "future_fixture_field": {"preserve": true},
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]}
        ]
    })
    .as_object()
    .cloned()
    .unwrap()
}

fn native_request(stream: bool) -> InvocationRequest {
    InvocationRequest::new("llm", "claude-x")
        .with_arguments(Some(native_body(stream)))
        .with_native_messages_surface(true)
}

/// Captures the raw native request and answers with a Messages body that
/// reports prompt-cache reads and writes.
#[derive(Default)]
struct NativeCapture {
    calls: AtomicUsize,
    api_key: Mutex<Option<String>>,
    body: Mutex<Option<Value>>,
    headers: Mutex<HeaderMap>,
}

async fn native_provider(
    State(cap): State<Arc<NativeCapture>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    cap.calls.fetch_add(1, Ordering::SeqCst);
    *cap.api_key.lock().unwrap() = headers
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    *cap.body.lock().unwrap() = serde_json::from_str(&body).ok();
    *cap.headers.lock().unwrap() = headers;
    let resp = json!({
        "id": "msg_native",
        "type": "message",
        "role": "assistant",
        "model": "claude-served-x",
        "content": [
            {"type": "thinking", "thinking": "considering", "signature": "sig"},
            {"type": "text", "text": "done"}
        ],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 10,
            "cache_read_input_tokens": 300,
            "cache_creation_input_tokens": 40,
            "output_tokens": 7
        }
    });
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("request-id", "req_fixture")
        .header("anthropic-ratelimit-unified-status", "allowed")
        .header("set-cookie", "fixture=discard")
        .body(Body::from(resp.to_string()))
        .unwrap()
}

async fn spawn_native_provider(cap: Arc<NativeCapture>) -> SocketAddr {
    let app = Router::new()
        .route("/messages", post(native_provider))
        .with_state(cap);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn anthropic_dispatcher() -> LlmDispatcher {
    LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        anthropic_store(),
    )
}

fn openrouter_route(addr: SocketAddr) -> ResolvedRoute {
    ResolvedRoute {
        provider: LlmProvider::OpenRouter,
        credential_label: "MAIN".into(),
        base_url: format!("http://{addr}"),
        path: "chat/completions".into(),
        upstream_model: "openrouter/served-x".into(),
        protocol: UpstreamProtocol::OpenAiChat,
        embeddings_no_auth: false,
        openai_chatgpt: false,
    }
}

struct FixedQuota {
    deny: bool,
    calls: AtomicUsize,
}

#[async_trait]
impl waygate_quota::QuotaService for FixedQuota {
    async fn check_and_consume(
        &self,
        _ctx: &waygate_quota::QuotaContext,
        _actions: &[waygate_quota::QuotaAction],
    ) -> Result<(), waygate_quota::QuotaError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.deny {
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id: Uuid::nil(),
                name: "test quota".into(),
                retry_after_seconds: 1,
            })
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn native_surface_forwards_cache_control_and_returns_the_provider_body() {
    let cap = Arc::new(NativeCapture::default());
    let addr = spawn_native_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(anthropic_dispatcher(), anthropic_resolver(addr))
            .with_llm_usage_store(usage.clone());

    let mut request = native_request(false);
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("anthropic-version", "fixture-version"),
        ("anthropic-beta", "future-feature,another-feature"),
        ("anthropic-workspace-id", "workspace_fixture"),
        ("x-api-key", "gateway_fixture"),
        ("authorization", "Bearer gateway_fixture"),
    ] {
        headers.insert(name, value.parse().unwrap());
    }
    request.native_messages_headers =
        waygate_core::anthropic::RequestHeaders::from_headers(&headers);
    let resp = svc
        .invoke(Some(&principal()), request)
        .await
        .expect("invoke");
    let body = match resp {
        InvocationResponse::NativeMessages {
            metadata,
            body: waygate_invocation::NativeMessagesBody::Json(body),
        } => {
            assert_eq!(metadata.status, axum::http::StatusCode::OK);
            assert_eq!(metadata.headers()["request-id"], "req_fixture");
            assert_eq!(
                metadata.headers()["anthropic-ratelimit-unified-status"],
                "allowed"
            );
            assert!(!metadata.headers().contains_key("set-cookie"));
            body
        }
        other => panic!("expected native JSON, got {other:?}"),
    };
    // The provider's Messages body comes back untouched, thinking block included.
    assert_eq!(body["id"], "msg_native");
    assert_eq!(body["content"][0]["type"], "thinking");
    assert_eq!(body["usage"]["cache_read_input_tokens"], 300);

    // The provider received the client's body with only `model` rewritten to
    // the route's upstream model.
    let mut expected = Value::Object(native_body(false));
    expected["model"] = json!("claude-served-x");
    assert_eq!(cap.body.lock().unwrap().as_ref(), Some(&expected));
    assert_eq!(
        cap.api_key.lock().unwrap().as_deref(),
        Some("sk-ant-api03-test")
    );
    let forwarded = cap.headers.lock().unwrap();
    assert!(!forwarded.contains_key("authorization"));
    for name in [
        "anthropic-version",
        "anthropic-beta",
        "anthropic-workspace-id",
    ] {
        assert_eq!(forwarded[name], headers[name]);
    }

    // Cached-read and cache-creation tokens reach usage accounting.
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.inbound_surface, "anthropic_messages");
    assert_eq!(row.provider, "anthropic");
    assert_eq!(row.model_alias, "claude-x");
    assert_eq!(row.model_served.as_deref(), Some("claude-served-x"));
    assert_eq!(row.input_tokens, Some(350), "input includes cache subsets");
    assert_eq!(row.cached_read_tokens, Some(300));
    assert_eq!(row.cache_write_tokens, Some(40));
    assert_eq!(row.output_tokens, Some(7));
    assert_eq!(row.finish_reason.as_deref(), Some("stop"));

    // Audited once, on the inference plane, extending the evidence chain.
    let rows = sink.best_effort.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].category, EvidenceCategory::LlmCompletion);
    assert_eq!(rows[0].outcome, AuditOutcome::Success);
}

#[tokio::test]
async fn canonical_surface_still_rejects_cache_control_without_contacting_the_provider() {
    let cap = Arc::new(NativeCapture::default());
    let addr = spawn_native_provider(cap.clone()).await;
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(anthropic_dispatcher(), anthropic_resolver(addr));

    let args = json!({
        "model": "claude-x",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}
        ]}]
    })
    .as_object()
    .cloned()
    .unwrap();
    let req = InvocationRequest::new("llm", "claude-x").with_arguments(Some(args));
    let err = svc.invoke(Some(&principal()), req).await.unwrap_err();
    assert!(
        matches!(err, InvocationError::InvalidArguments(ref m) if m.contains("cache_control")),
        "got {err:?}"
    );
    assert_eq!(cap.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_surface_runs_authorization_as_a_model_and_denies_before_dispatch() {
    let cap = Arc::new(NativeCapture::default());
    let addr = spawn_native_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let gate = Arc::new(CapturingGate {
        verdict: AuthzVerdict::Deny {
            reason: "policy".into(),
            policy_ids: vec![],
            reasons: vec![],
        },
        captured: Mutex::new(None),
    });
    let svc = DefaultInvocationService::new(Arc::new(FakeCatalog), gate.clone(), sink.clone())
        .with_llm(anthropic_dispatcher(), anthropic_resolver(addr));

    let err = svc
        .invoke(Some(&principal()), native_request(false))
        .await
        .unwrap_err();
    assert!(
        matches!(err, InvocationError::Forbidden { .. }),
        "got {err:?}"
    );
    let facts = gate.captured.lock().unwrap().clone().expect("authorized");
    assert_eq!(facts.resource.resource_type.as_deref(), Some("model"));
    assert_eq!(facts.resource.tool, "claude-x");
    assert_eq!(facts.action.required_scope, None);
    assert_eq!(cap.calls.load(Ordering::SeqCst), 0, "no provider contact");
    let rows = sink.best_effort.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, AuditOutcome::Denied);
    assert_eq!(rows[0].category, EvidenceCategory::LlmCompletion);
}

#[tokio::test]
async fn native_surface_refuses_an_exhausted_budget_before_dispatch() {
    let cap = Arc::new(NativeCapture::default());
    let addr = spawn_native_provider(cap.clone()).await;
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(anthropic_dispatcher(), anthropic_resolver(addr))
    .with_llm_budget(Arc::new(FakeBudgetGate(Some(
        waygate_mcp::budget::BudgetRejection {
            dimension: "cost".into(),
            reason: "over budget".into(),
        },
    ))));

    let err = svc
        .invoke(Some(&principal()), native_request(false))
        .await
        .unwrap_err();
    assert!(
        matches!(err, InvocationError::BudgetExceeded { ref dimension, .. } if dimension == "cost"),
        "got {err:?}"
    );
    assert_eq!(cap.calls.load(Ordering::SeqCst), 0, "no provider contact");
}

#[tokio::test]
async fn native_surface_consumes_quota_and_a_denial_stops_dispatch() {
    for deny in [false, true] {
        let cap = Arc::new(NativeCapture::default());
        let addr = spawn_native_provider(cap.clone()).await;
        let quota = Arc::new(FixedQuota {
            deny,
            calls: AtomicUsize::new(0),
        });
        let svc = DefaultInvocationService::new(
            Arc::new(FakeCatalog),
            Arc::new(AllowAllGate),
            Arc::new(RecordingSink::default()),
        )
        .with_llm(anthropic_dispatcher(), anthropic_resolver(addr))
        .with_quota(Some(quota.clone()));

        let result = svc.invoke(Some(&principal()), native_request(false)).await;
        assert_eq!(quota.calls.load(Ordering::SeqCst), 1, "quota consulted");
        if deny {
            assert!(
                matches!(result, Err(InvocationError::RateLimited { .. })),
                "got {result:?}"
            );
            assert_eq!(cap.calls.load(Ordering::SeqCst), 0, "no provider contact");
        } else {
            assert!(result.is_ok(), "got {result:?}");
            assert_eq!(cap.calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn native_streaming_relays_provider_events_and_records_usage_at_close() {
    let addr = spawn_anthropic_stream_provider().await;
    let sink = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(anthropic_dispatcher(), anthropic_resolver(addr))
            .with_llm_usage_store(usage.clone());

    let mut stream = match svc
        .invoke(Some(&principal()), native_request(true))
        .await
        .expect("invoke")
    {
        InvocationResponse::NativeMessages {
            body: waygate_invocation::NativeMessagesBody::Stream(stream),
            ..
        } => stream,
        other => panic!("expected native stream, got {other:?}"),
    };
    let mut chunks = Vec::new();
    while let Some(item) = stream.next().await {
        chunks.push(item.expect("chunk"));
    }

    // Each provider event is relayed verbatim under its own event name.
    let names: Vec<&str> = chunks
        .iter()
        .map(|c| c.event_name.as_deref().expect("named event"))
        .collect();
    assert_eq!(
        names,
        [
            "message_start",
            "ping",
            "content_block_delta",
            "content_block_delta",
            "message_delta",
            "message_stop"
        ]
    );
    assert_eq!(chunks[2].event["delta"]["text"], "He");
    assert_eq!(
        chunks[0].event["message"]["usage"]["cache_read_input_tokens"],
        1
    );
    assert!(chunks.last().unwrap().terminal);
    assert!(chunks[..chunks.len() - 1].iter().all(|c| !c.terminal));

    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].inbound_surface, "anthropic_messages");
    assert_eq!(rows[0].cached_read_tokens, Some(1));
    assert_eq!(rows[0].cache_write_tokens, Some(2));
    assert_eq!(rows[0].input_tokens, Some(5));
    assert_eq!(rows[0].output_tokens, Some(2));
    assert_eq!(
        sink.best_effort.lock().unwrap().len(),
        1,
        "audited at close"
    );
}

#[tokio::test]
async fn native_surface_rejects_a_model_not_served_by_anthropic_messages() {
    let cap = Arc::new(Mutex::new(Captured::default()));
    let addr = spawn_provider(cap.clone()).await;
    let sink = Arc::new(RecordingSink::default());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), sink.clone())
            .with_llm(
                LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), store()),
                resolver_named(addr, "claude-x"),
            );

    let err = svc
        .invoke(Some(&principal()), native_request(false))
        .await
        .unwrap_err();
    assert!(
        matches!(err, InvocationError::InvalidArguments(ref m) if m.contains("Anthropic Messages")),
        "got {err:?}"
    );
    assert!(!cap.lock().unwrap().called, "no provider contact");
    assert!(
        sink.best_effort.lock().unwrap().is_empty(),
        "rejected before the gates"
    );
}

#[tokio::test]
async fn native_failover_skips_fallbacks_on_other_protocols() {
    // The primary fails with a retryable status; the only fallback speaks
    // another protocol, so the native body is never sent to it.
    let other = Arc::new(Mutex::new(Captured::default()));
    let other_addr = spawn_provider(other.clone()).await;
    let failing = Router::new().route(
        "/messages",
        post(|| async { (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down") }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let failing_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, failing).await.unwrap();
    });

    let mut model = anthropic_resolver(failing_addr)
        .resolve("llm", "claude-x")
        .expect("model");
    model.fallbacks = vec![openrouter_route(other_addr)];
    let resolver = Arc::new(StaticModelResolver::new().with_model("llm", "claude-x", model))
        as Arc<dyn LlmModelResolver>;
    let creds = Arc::new(LlmCredentialStore::from_vars([
        (
            "LLM_CRED_ANTHROPIC_MAIN".to_string(),
            "sk-ant-api03-test".to_string(),
        ),
        (
            "LLM_CRED_OPENROUTER_MAIN".to_string(),
            "sk-test-key".to_string(),
        ),
    ]));
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(
        LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), creds),
        resolver,
    );

    let response = svc
        .invoke(Some(&principal()), native_request(false))
        .await
        .expect("provider HTTP errors remain native responses");
    let InvocationResponse::NativeMessages {
        metadata,
        body: waygate_invocation::NativeMessagesBody::Error(body),
    } = response
    else {
        panic!("expected native provider error");
    };
    assert_eq!(metadata.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.as_ref(), b"down");
    assert!(
        !other.lock().unwrap().called,
        "a non-Messages fallback must not receive the native body"
    );
}

#[tokio::test]
async fn native_provider_errors_keep_status_body_and_retry_guidance() {
    let error_body = "{ \"type\": \"error\", \"error\": {\"type\":\"invalid_request_error\",\"message\":\"unsupported fixture capability\"} }";
    for status in [400, 429] {
        let app = Router::new().route(
            "/messages",
            post(move || async move {
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .header("request-id", "req_error_fixture")
                    .header("retry-after", "7")
                    .header("x-should-retry", "false")
                    .body(Body::from(error_body))
                    .unwrap()
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let sink = Arc::new(RecordingSink::default());
        let svc = DefaultInvocationService::new(
            Arc::new(FakeCatalog),
            Arc::new(AllowAllGate),
            sink.clone(),
        )
        .with_llm(anthropic_dispatcher(), anthropic_resolver(addr));
        let response = svc
            .invoke(Some(&principal()), native_request(true))
            .await
            .unwrap();
        let InvocationResponse::NativeMessages {
            metadata,
            body: waygate_invocation::NativeMessagesBody::Error(body),
        } = response
        else {
            panic!("expected native provider error");
        };
        assert_eq!(metadata.status.as_u16(), status);
        assert_eq!(metadata.headers()["retry-after"], "7");
        assert_eq!(metadata.headers()["x-should-retry"], "false");
        assert_eq!(metadata.headers()["request-id"], "req_error_fixture");
        assert_eq!(body.as_ref(), error_body.as_bytes());
        let evidence = sink.best_effort.lock().unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].outcome, AuditOutcome::ExecutionError);
        assert!(!format!("{:?}", evidence[0]).contains("unsupported fixture capability"));
    }
}
