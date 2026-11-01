use super::*;
use futures::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use waygate_llm_translate::speech::{SpeechCapabilities, SpeechFormat};

fn capabilities() -> SpeechCapabilities {
    SpeechCapabilities {
        formats: vec![SpeechFormat::Pcm, SpeechFormat::Wav],
        voices: vec!["narrator".into()],
        custom_voices: true,
        instructions: true,
        sse_formats: vec![SpeechFormat::Pcm],
        speed_range: None,
    }
}

fn speech_resolver(addr: SocketAddr) -> Arc<dyn LlmModelResolver> {
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "speech-alias",
        ResolvedModel {
            operation: LlmOperation::Speech(capabilities()),
            route: ResolvedRoute {
                provider: LlmProvider::OpenAi,
                credential_label: "TEST".into(),
                base_url: format!("http://{addr}"),
                path: "audio/speech".into(),
                upstream_model: "voice-model".into(),
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

fn speech_dispatcher() -> LlmDispatcher {
    let creds = LlmCredentialStore::from_vars([(
        "LLM_CRED_OPENAI_TEST".into(),
        json!({"api_key":"fixture-speech-key"}).to_string(),
    )]);
    LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new())
            .with_single_attempt_http(reqwest::Client::builder())
            .unwrap(),
        Arc::new(creds),
    )
}

fn speech_request() -> InvocationRequest {
    let mut req = InvocationRequest::new("llm","speech-alias").with_arguments(json!({
        "model":"speech-alias", "input":"Private words to read", "voice":"narrator", "response_format":"pcm",
    }).as_object().cloned());
    req.speech_surface = true;
    req
}

#[tokio::test(start_paused = true)]
async fn dispatch_failure_releases_capacity_before_stalled_usage_and_returns_on_deadline() {
    struct StalledUsage(Arc<tokio::sync::Notify>);
    #[async_trait]
    impl waygate_mcp::usage::LlmUsageRecorder for StalledUsage {
        async fn record_usage(&self, _: waygate_mcp::usage::LlmUsageRow) {
            self.0.notify_one();
            futures::future::pending::<()>().await;
        }
    }
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new()),
        Arc::new(LlmCredentialStore::from_vars(Vec::<(String, String)>::new())),
    );
    let mut held = Vec::new();
    while let Some(permit) = dispatcher.try_admit_response() {
        held.push(permit);
    }
    drop(held.pop().expect("one available inference slot"));
    let usage_started = Arc::new(tokio::sync::Notify::new());
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(
        dispatcher.clone(),
        speech_resolver("127.0.0.1:9".parse().unwrap()),
    )
    .with_llm_usage_store(Arc::new(StalledUsage(usage_started.clone())));
    let call =
        tokio::spawn(async move { service.invoke(Some(&principal()), speech_request()).await });
    usage_started.notified().await;
    let available = dispatcher.try_admit_response();
    assert!(
        available.is_some(),
        "failed dispatch retained processing capacity during evidence finalization"
    );
    assert!(!call.is_finished());
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(call.await.unwrap().is_err());
}

async fn serve(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn audio_arrives_before_generation_completes_and_usage_remains_unknown() {
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let release_provider = release.clone();
    let app = Router::new().route(
        "/audio/speech",
        post(
            move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
                let release = release_provider.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer fixture-speech-key");
                    assert_eq!(body["model"], "voice-model");
                    assert!(body.get("stream").is_none());
                    let chunks = futures::stream::once(async {
                        Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"\x01\x00"))
                    })
                    .chain(futures::stream::once(async move {
                        release.acquire().await.unwrap().forget();
                        Ok(bytes::Bytes::from_static(b"\x02\x00"))
                    }));
                    Response::builder()
                        .header("content-type", "audio/pcm")
                        .body(Body::from_stream(chunks))
                        .unwrap()
                }
            },
        ),
    );
    let addr = serve(app).await;
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(speech_dispatcher(), speech_resolver(addr))
            .with_llm_usage_store(usage.clone());
    let response = service
        .invoke(Some(&principal()), speech_request())
        .await
        .unwrap();
    let InvocationResponse::Media {
        media_type,
        mut body,
    } = response
    else {
        panic!("expected audio");
    };
    assert_eq!(media_type, "audio/pcm");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .as_ref(),
        b"\x01\x00"
    );
    assert!(usage.rows.lock().unwrap().is_empty());
    release.add_permits(1);
    let mut remaining = Vec::new();
    while let Some(chunk) = body.next().await {
        remaining.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(remaining, b"\x02\x00");
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].inbound_surface, "audio_speech");
    assert_eq!(rows[0].input_tokens, None);
    assert_eq!(rows[0].output_tokens, None);
    let events = audit.best_effort.lock().unwrap();
    assert!(events
        .iter()
        .any(|e| e.action == "SpeechGeneration" && e.outcome == AuditOutcome::Success));
    assert!(events
        .iter()
        .any(|e| e.action == "SpeechDelivery" && e.outcome == AuditOutcome::Success));
    let generation = events
        .iter()
        .find(|e| e.action == "SpeechGeneration")
        .unwrap();
    let delivery = events
        .iter()
        .find(|e| e.action == "SpeechDelivery")
        .unwrap();
    assert_ne!(
        generation.id, delivery.id,
        "separate durable observations need unique IDs"
    );
    assert!(!serde_json::to_string(&*events)
        .unwrap()
        .contains("Private words"));
}

#[tokio::test]
async fn sse_requires_completion_and_never_accounts_placeholder_tokens() {
    for complete in [true, false] {
        let addr=serve(Router::new().route("/audio/speech",post(move || async move {
            let frame = |value: Value| {
                let json = serde_json::to_string_pretty(&value).unwrap();
                json.lines().map(|line| format!("data: {line}\n")).collect::<String>() + "\n"
            };
            let mut data = frame(json!({"type":"speech.audio.delta","audio":"AQACAA=="}));
            if complete { data.push_str(&frame(json!({"type":"speech.audio.done","usage":{"input_tokens":0,"output_tokens":0}}))); }
            Response::builder().header("content-type","text/event-stream").body(Body::from(data)).unwrap()
        }))).await;
        let usage = Arc::new(RecordingUsage::default());
        let audit = Arc::new(RecordingSink::default());
        let service = DefaultInvocationService::new(
            Arc::new(FakeCatalog),
            Arc::new(AllowAllGate),
            audit.clone(),
        )
        .with_llm(speech_dispatcher(), speech_resolver(addr))
        .with_llm_usage_store(usage.clone());
        let mut request = speech_request();
        request
            .arguments
            .as_mut()
            .unwrap()
            .insert("stream_format".into(), json!("sse"));
        let InvocationResponse::Media { mut body, .. } =
            service.invoke(Some(&principal()), request).await.unwrap()
        else {
            panic!("expected events");
        };
        let mut failed = false;
        let mut data = Vec::new();
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(chunk) => data.extend_from_slice(&chunk),
                Err(_) => failed = true,
            }
        }
        assert_eq!(failed, !complete);
        let data = String::from_utf8(data).unwrap();
        for event in data.split("\n\n").filter(|frame| !frame.is_empty()) {
            let payload = event
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .collect::<Vec<_>>()
                .join("\n");
            let decoded: Value = serde_json::from_str(&payload)
                .expect("downstream SSE payload must remain valid JSON");
            assert!(matches!(
                decoded["type"].as_str(),
                Some("speech.audio.delta" | "speech.audio.done")
            ));
        }
        assert_eq!(data.contains("speech.audio.done"), complete);
        let rows = usage.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].input_tokens, None);
        assert_eq!(rows[0].output_tokens, None);
        assert!(audit
            .best_effort
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.action == "SpeechGeneration"
                && (e.outcome == AuditOutcome::Success) == complete));
    }
}

#[tokio::test]
async fn refusal_and_unsupported_options_never_contact_the_provider() {
    let calls = Arc::new(AtomicUsize::new(0));
    let called = calls.clone();
    let addr = serve(Router::new().route(
        "/audio/speech",
        post(move || {
            called.fetch_add(1, Ordering::SeqCst);
            async { "unexpected provider contact" }
        }),
    ))
    .await;
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(speech_dispatcher(), speech_resolver(addr));
    for (field, value) in [
        ("speed", json!(2)),
        ("voice", json!("unknown")),
        ("response_format", json!("aac")),
        ("stream", json!(false)),
    ] {
        let mut request = speech_request();
        request
            .arguments
            .as_mut()
            .unwrap()
            .insert(field.into(), value);
        assert!(matches!(
            service.invoke(Some(&principal()), request).await,
            Err(InvocationError::InvalidArguments(_))
        ));
    }
    let mut request = speech_request();
    request.speech_surface = false;
    assert!(matches!(
        service.invoke(Some(&principal()), request).await,
        Err(InvocationError::InvalidArguments(_))
    ));
    let denied = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(FixedGate(AuthzVerdict::Deny {
            reason: "denied".into(),
            policy_ids: vec![],
            reasons: vec![],
        })),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(speech_dispatcher(), speech_resolver(addr));
    assert!(matches!(
        denied.invoke(Some(&principal()), speech_request()).await,
        Err(InvocationError::Forbidden { .. })
    ));
    let budget = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(speech_dispatcher(), speech_resolver(addr))
    .with_llm_budget(Arc::new(FakeBudgetGate(Some(
        waygate_mcp::budget::BudgetRejection {
            dimension: "cost".into(),
            reason: "exhausted".into(),
        },
    ))));
    assert!(matches!(
        budget.invoke(Some(&principal()), speech_request()).await,
        Err(InvocationError::BudgetExceeded { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn disconnect_drops_the_provider_body() {
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
    let receiver = Arc::new(Mutex::new(Some(receiver)));
    let addr = serve(Router::new().route(
        "/audio/speech",
        post(move || {
            let receiver = receiver.lock().unwrap().take().unwrap();
            async move {
                let body = futures::stream::unfold(receiver, |mut receiver| async move {
                    receiver.recv().await.map(|chunk| (chunk, receiver))
                });
                Response::builder()
                    .header("content-type", "audio/pcm")
                    .body(Body::from_stream(body))
                    .unwrap()
            }
        }),
    ))
    .await;
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(speech_dispatcher(), speech_resolver(addr));
    let response = service
        .invoke(Some(&principal()), speech_request())
        .await
        .unwrap();
    sender
        .send(Ok(bytes::Bytes::from_static(b"\x01\x00")))
        .await
        .unwrap();
    let InvocationResponse::Media { mut body, .. } = response else {
        panic!("expected audio");
    };
    body.next().await.unwrap().unwrap();
    drop(body);
    tokio::time::timeout(Duration::from_secs(5), sender.closed())
        .await
        .expect("provider body remained active after caller disconnect");
}
