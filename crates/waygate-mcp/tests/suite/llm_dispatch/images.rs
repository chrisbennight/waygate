use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use waygate_invocation::ImagesSurface;

fn image_resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "image-alias",
        ResolvedModel {
            operation: LlmOperation::Images,
            route: ResolvedRoute {
                provider: LlmProvider::OpenAi,
                credential_label: "TEST".into(),
                base_url: format!("http://{addr}"),
                path: "images".into(),
                upstream_model: "gpt-image-2".into(),
                protocol: UpstreamProtocol::OpenAiResponses,
                embeddings_no_auth: false,
                openai_chatgpt: true,
            },
            fallbacks: vec![],
            risk: ModelRisk::Low,
            ttfb: None,
            cache_ttl: None,
        },
    ))
}

fn dispatcher() -> LlmDispatcher {
    dispatcher_with_client(reqwest::Client::builder())
}

fn dispatcher_with_client(builder: reqwest::ClientBuilder) -> LlmDispatcher {
    let credentials = LlmCredentialStore::from_vars([("LLM_CRED_OPENAI_TEST".into(),
        json!({"tokens":{"access_token":"fixture-access","refresh_token":"fixture-refresh","account_id":"fixture-account"},"expires_at":"2099-01-01T00:00:00Z"}).to_string())]);
    LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new())
            .with_single_attempt_http(builder)
            .unwrap(),
        Arc::new(credentials),
    )
}

fn image_request() -> InvocationRequest {
    let mut request = InvocationRequest::new("llm", "image-alias").with_arguments(
        json!({"model":"image-alias", "prompt":"a blue square", "quality":"low"})
            .as_object()
            .cloned(),
    );
    request.images_surface = Some(ImagesSurface::Generations);
    request
}

async fn image_provider(calls: Arc<AtomicUsize>, status: u16) -> SocketAddr {
    let handler = post(
        move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(headers["authorization"], "Bearer fixture-access");
                assert_eq!(headers["chatgpt-account-id"], "fixture-account");
                assert_eq!(headers["originator"], "codex_cli_rs");
                assert_eq!(body["model"], "gpt-image-2");
                assert_eq!(body["quality"], "low");
                let body = if status == 200 {
                    json!({"created":42,"data":[{"b64_json":"aW1hZ2U="}],"quality":"low","usage":{"input_tokens":5,"output_tokens":20}})
                } else {
                    json!({"error":{"message":"secret prompt echoed by upstream"}})
                };
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        },
    );
    let app = Router::new()
        .route("/images/generations", handler.clone())
        .route("/images/edits", handler);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn images_use_subscription_auth_and_record_metadata_only_usage() {
    let calls = Arc::new(AtomicUsize::new(0));
    let addr = image_provider(calls.clone(), 200).await;
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher(), image_resolver(addr))
            .with_llm_usage_store(usage.clone());
    let response = svc
        .invoke(Some(&principal()), image_request())
        .await
        .unwrap();
    let InvocationResponse::UnaryValue(body) = response else {
        panic!("expected image JSON")
    };
    assert_eq!(body["data"][0]["b64_json"], "aW1hZ2U=");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].input_tokens, Some(5));
    assert_eq!(rows[0].output_tokens, Some(20));
    assert_eq!(rows[0].inbound_surface, "images_generations");
    let events = audit.best_effort.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].category, EvidenceCategory::LlmCompletion);
}

#[tokio::test]
async fn image_budget_and_authorization_refusals_never_contact_provider() {
    let calls = Arc::new(AtomicUsize::new(0));
    let addr = image_provider(calls.clone(), 200).await;
    let budget = Arc::new(FakeBudgetGate(Some(waygate_mcp::budget::BudgetRejection {
        dimension: "tokens".into(),
        reason: "budget exhausted".into(),
    })));
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher(), image_resolver(addr))
    .with_llm_budget(budget);
    assert!(matches!(
        svc.invoke(Some(&principal()), image_request()).await,
        Err(InvocationError::BudgetExceeded { .. })
    ));
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(FixedGate(AuthzVerdict::Deny {
            reason: "denied".into(),
            policy_ids: vec![],
            reasons: vec![],
        })),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher(), image_resolver(addr));
    assert!(matches!(
        svc.invoke(Some(&principal()), image_request()).await,
        Err(InvocationError::Forbidden { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn image_edits_use_the_edit_endpoint_and_usage_surface() {
    let calls = Arc::new(AtomicUsize::new(0));
    let addr = image_provider(calls.clone(), 200).await;
    let usage = Arc::new(RecordingUsage::default());
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher(), image_resolver(addr))
    .with_llm_usage_store(usage.clone());
    let mut request = image_request();
    request.images_surface = Some(ImagesSurface::Edits);
    request.arguments.as_mut().unwrap().insert(
        "images".into(),
        json!([{"image_url":"data:image/png;base64,aW1hZ2U="}]),
    );
    assert!(matches!(
        svc.invoke(Some(&principal()), request).await,
        Ok(InvocationResponse::UnaryValue(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        usage.rows.lock().unwrap()[0].inbound_surface,
        "images_edits"
    );
}

#[tokio::test]
async fn images_reject_surface_mismatch_and_invalid_options_without_contact() {
    let calls = Arc::new(AtomicUsize::new(0));
    let addr = image_provider(calls.clone(), 200).await;
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher(), image_resolver(addr));
    let mut wrong_surface = image_request();
    wrong_surface.images_surface = None;
    let mut streaming = image_request();
    streaming
        .arguments
        .as_mut()
        .unwrap()
        .insert("stream".into(), json!(true));
    for request in [wrong_surface, streaming] {
        assert!(matches!(
            svc.invoke(Some(&principal()), request).await,
            Err(InvocationError::InvalidArguments(_))
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ambiguous_provider_failure_is_not_retried_or_logged_with_content() {
    let calls = Arc::new(AtomicUsize::new(0));
    let addr = image_provider(calls.clone(), 503).await;
    let audit = Arc::new(RecordingSink::default());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher(), image_resolver(addr));
    let error = svc
        .invoke(Some(&principal()), image_request())
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("secret prompt"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let events = audit.best_effort.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(!events[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("secret prompt"));
}

#[tokio::test]
async fn image_timeout_after_provider_accepts_is_not_retried() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let provider = Router::new().route(
        "/images/generations",
        post(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<axum::Json<Value>>()
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
    let client = reqwest::Client::builder().timeout(Duration::from_secs(1));
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher_with_client(client), image_resolver(addr));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        svc.invoke(Some(&principal()), image_request()),
    )
    .await
    .unwrap();
    server.abort();
    let error = result.unwrap_err();
    assert!(error.to_string().contains("generation may have completed"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn image_rate_limits_preserve_status_without_retrying() {
    let calls = Arc::new(AtomicUsize::new(0));
    let addr = image_provider(calls.clone(), 429).await;
    let svc = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher(), image_resolver(addr));
    let error = svc
        .invoke(Some(&principal()), image_request())
        .await
        .unwrap_err();
    let InvocationError::Upstream(error) = error else {
        panic!("expected provider refusal")
    };
    assert_eq!(error.data.unwrap()["image_http_status"], 429);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn image_redirects_never_replay_the_post() {
    for status in [301, 302, 303, 307, 308] {
        let first = Arc::new(AtomicUsize::new(0));
        let redirected = Arc::new(AtomicUsize::new(0));
        let first_seen = first.clone();
        let target_seen = redirected.clone();
        let provider = Router::new()
            .route(
                "/images/generations",
                post(move || {
                    first_seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Response::builder()
                            .status(status)
                            .header("location", "/target")
                            .body(Body::empty())
                            .unwrap()
                    }
                }),
            )
            .route(
                "/target",
                axum::routing::any(move || {
                    target_seen.fetch_add(1, Ordering::SeqCst);
                    async { axum::Json(json!({"created":42,"data":[{"b64_json":"aW1hZ2U="}]})) }
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
        let svc = DefaultInvocationService::new(
            Arc::new(FakeCatalog),
            Arc::new(AllowAllGate),
            Arc::new(RecordingSink::default()),
        )
        .with_llm(dispatcher(), image_resolver(addr));
        let result = svc.invoke(Some(&principal()), image_request()).await;
        server.abort();
        assert!(matches!(result, Err(InvocationError::Upstream(_))));
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(
            redirected.load(Ordering::SeqCst),
            0,
            "HTTP {status} replayed the request"
        );
    }
}
