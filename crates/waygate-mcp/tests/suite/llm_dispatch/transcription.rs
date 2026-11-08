use super::*;
use axum::response::IntoResponse;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use waygate_core::audio::{AudioUpload, TranscriptionInput};

const WAV: &[u8] = b"RIFF\x28\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x80\x3e\x00\x00\x00\x7d\x00\x00\x02\x00\x10\x00data\x04\x00\x00\x00\x01\x00\x02\x00";

fn dependencies(addr: SocketAddr) -> (LlmDispatcher, Arc<dyn LlmModelResolver>) {
    let caps = serde_json::from_value(
        json!({"file_types":["wav"],"response_formats":["json","verbose_json","text"],"prompt":true}),
    )
    .unwrap();
    let model = ResolvedModel {
        operation: LlmOperation::Transcription(caps),
        route: ResolvedRoute {
            provider: LlmProvider::OpenAi,
            credential_label: "TEST".into(),
            base_url: format!("http://{addr}/v1"),
            path: "audio/transcriptions".into(),
            upstream_model: "provider-asr".into(),
            protocol: UpstreamProtocol::OpenAiChat,
            embeddings_no_auth: false,
            openai_chatgpt: false,
        },
        fallbacks: vec![],
        risk: ModelRisk::Low,
        ttfb: None,
        cache_ttl: None,
    };
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new())
            .with_single_attempt_http(reqwest::Client::builder())
            .unwrap(),
        Arc::new(LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_TEST".into(),
            json!({"api_key":"fixture-stt-key"}).to_string(),
        )])),
    );
    (
        dispatcher,
        Arc::new(StaticModelResolver::new().with_model("llm", "asr", model)),
    )
}

fn transcription_request(fields: &[(&str, &str)]) -> InvocationRequest {
    let mut request = InvocationRequest::new("llm", "asr");
    request.transcription = Some(TranscriptionInput {
        upload: AudioUpload {
            bytes: Arc::from(WAV),
            content_type: "audio/wav".into(),
            file_name: "sample.wav".into(),
        },
        fields: [("model", "asr")]
            .iter()
            .chain(fields)
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect(),
    });
    request
}

async fn serve(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, server)
}

/// Each multipart form the stand-in provider received, by field name.
type ReceivedForms = Arc<Mutex<Vec<BTreeMap<String, Vec<u8>>>>>;

/// A standard provider that checks the rebuilt form and answers in the
/// requested format.
fn provider(seen: ReceivedForms) -> Router {
    Router::new().route(
        "/v1/audio/transcriptions",
        post(
            move |headers: HeaderMap, mut form: axum::extract::Multipart| {
                let seen = seen.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer fixture-stt-key");
                    let mut fields = BTreeMap::new();
                    while let Some(field) = form.next_field().await.unwrap() {
                        let name = field.name().unwrap().to_owned();
                        if name == "file" {
                            assert_eq!(field.file_name(), Some("sample.wav"));
                            assert_eq!(field.content_type(), Some("audio/wav"));
                        }
                        fields.insert(name, field.bytes().await.unwrap().to_vec());
                    }
                    let format = String::from_utf8(fields["response_format"].clone()).unwrap();
                    seen.lock().unwrap().push(fields);
                    match format.as_str() {
                        "text" => "private spoken words".into_response(),
                        "verbose_json" => {
                            axum::Json(json!({"task":"transcribe","language":"english",
                            "duration":0.5,"text":"private spoken words","segments":[]}))
                            .into_response()
                        }
                        _ => axum::Json(json!({"text":"private spoken words"})).into_response(),
                    }
                }
            },
        ),
    )
}

#[tokio::test]
async fn standard_transcription_returns_each_format_with_private_metadata_only_evidence() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (addr, server) = serve(provider(seen.clone())).await;
    let (dispatcher, resolver) = dependencies(addr);
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    // Transcription reports no cost, so an exhausted spending budget does not gate it.
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher, resolver)
            .with_llm_usage_store(usage.clone())
            .with_llm_budget(Arc::new(FakeBudgetGate(Some(
                waygate_mcp::budget::BudgetRejection {
                    dimension: "cost".into(),
                    reason: "exhausted".into(),
                },
            ))));

    let InvocationResponse::UnaryValue(body) = service
        .invoke(
            Some(&principal()),
            transcription_request(&[("prompt", "private vocabulary")]),
        )
        .await
        .unwrap()
    else {
        panic!("expected a JSON transcription")
    };
    assert_eq!(body, json!({"text":"private spoken words"}));

    let InvocationResponse::UnaryValue(verbose) = service
        .invoke(
            Some(&principal()),
            transcription_request(&[("response_format", "verbose_json")]),
        )
        .await
        .unwrap()
    else {
        panic!("expected a verbose JSON transcription")
    };
    assert_eq!(verbose["duration"], 0.5);
    assert_eq!(verbose["text"], "private spoken words");

    let InvocationResponse::Media { media_type, body } = service
        .invoke(
            Some(&principal()),
            transcription_request(&[("response_format", "text"), ("stream", "false")]),
        )
        .await
        .unwrap()
    else {
        panic!("expected a plain-text transcription")
    };
    assert_eq!(media_type, "text/plain; charset=utf-8");
    let text: Vec<_> = body.collect().await;
    assert_eq!(text.len(), 1);
    assert_eq!(text[0].as_ref().unwrap().as_ref(), b"private spoken words");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0]["model"], b"provider-asr");
    assert_eq!(seen[0]["response_format"], b"json");
    assert_eq!(seen[0]["prompt"], b"private vocabulary");
    assert_eq!(seen[0]["file"], WAV);
    assert!(!seen[2].contains_key("stream"));

    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows
        .iter()
        .all(|row| row.inbound_surface == "audio_transcription"
            && row.input_tokens == Some(0)
            && row.output_tokens == Some(0)
            && row.finish_reason.as_deref() == Some("provider_complete")));
    let events = audit.best_effort.lock().unwrap();
    let completed: Vec<_> = events
        .iter()
        .filter(|event| event.action == "AudioTranscription")
        .collect();
    assert_eq!(completed.len(), 3);
    assert!(completed
        .iter()
        .all(|event| event.outcome == AuditOutcome::Success));
    let reason: Value = serde_json::from_str(completed[0].reason.as_deref().unwrap()).unwrap();
    assert_eq!(reason["upload_bytes"], WAV.len());
    assert_eq!(reason["response_format"], "json");
    let serialized = serde_json::to_string(&*events).unwrap();
    assert!(!serialized.contains("private spoken words"));
    assert!(!serialized.contains("private vocabulary"));
    assert!(!serialized.contains("fixture-stt-key"));
    server.abort();
}

#[tokio::test]
async fn provider_busy_and_rejection_keep_their_status_and_are_not_retried() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let app = Router::new().route(
        "/v1/audio/transcriptions",
        post(move |mut form: axum::extract::Multipart| {
            let call = counted.fetch_add(1, Ordering::SeqCst);
            async move {
                while form.next_field().await.unwrap().is_some() {}
                let mut response = Response::new(Body::from("private provider detail"));
                if call == 0 {
                    *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
                    response
                        .headers_mut()
                        .insert("retry-after", "7".parse().unwrap());
                } else {
                    *response.status_mut() = axum::http::StatusCode::PAYLOAD_TOO_LARGE;
                }
                response
            }
        }),
    );
    let (addr, server) = serve(app).await;
    let (dispatcher, resolver) = dependencies(addr);
    let audit = Arc::new(RecordingSink::default());
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher, resolver);
    for (status, retry_after) in [(429, Some(7)), (413, None)] {
        let Err(InvocationError::Upstream(error)) = service
            .invoke(Some(&principal()), transcription_request(&[]))
            .await
        else {
            panic!("provider failure was reported as success")
        };
        let data = error.data.unwrap();
        assert_eq!(data["audio_http_status"], status);
        assert_eq!(data["retry_after_seconds"], json!(retry_after));
        assert!(!error.message.contains("private"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(audit
        .best_effort
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.action == "AudioTranscription")
        .all(|event| event.outcome == AuditOutcome::ExecutionError));
    server.abort();
}

#[tokio::test]
async fn unsupported_options_wrong_routes_and_denied_callers_do_not_contact_provider() {
    let calls = Arc::new(AtomicUsize::new(0));
    let called = calls.clone();
    let (addr, server) = serve(Router::new().fallback(move || {
        called.fetch_add(1, Ordering::SeqCst);
        async { "unexpected contact" }
    }))
    .await;
    let (dispatcher, resolver) = dependencies(addr);
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher.clone(), resolver.clone());
    let mut speech_route = transcription_request(&[]);
    speech_route.speech_surface = true;
    let no_upload = InvocationRequest::new("llm", "asr");
    for request in [
        transcription_request(&[("response_format", "srt")]),
        transcription_request(&[("language", "en")]),
        transcription_request(&[("stream", "true")]),
        transcription_request(&[("timestamp_granularities[]", "word")]),
        speech_route,
        no_upload,
    ] {
        assert!(matches!(
            service.invoke(Some(&principal()), request).await,
            Err(InvocationError::InvalidArguments(_))
        ));
    }
    let mut wrong_file = transcription_request(&[]);
    wrong_file.transcription.as_mut().unwrap().upload.file_name = "sample.mp3".into();
    assert!(matches!(
        service.invoke(Some(&principal()), wrong_file).await,
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
    .with_llm(dispatcher, resolver);
    assert!(matches!(
        denied
            .invoke(Some(&principal()), transcription_request(&[]))
            .await,
        Err(InvocationError::Forbidden { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn abandoned_transcription_keeps_audit_latency_and_usage_accounting() {
    let contacted = Arc::new(tokio::sync::Notify::new());
    let provider_contacted = contacted.clone();
    let app = Router::new().route(
        "/v1/audio/transcriptions",
        post(move || {
            provider_contacted.notify_one();
            futures::future::pending::<&'static str>()
        }),
    );
    let (addr, server) = serve(app).await;
    let (dispatcher, resolver) = dependencies(addr);
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let service = Arc::new(
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher, resolver)
            .with_llm_usage_store(usage.clone()),
    );
    let call = tokio::spawn({
        let service = service.clone();
        async move {
            service
                .invoke(Some(&principal()), transcription_request(&[]))
                .await
        }
    });
    contacted.notified().await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while usage.rows.lock().unwrap().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("abandoned call recorded usage");
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows[0].finish_reason.as_deref(), Some("abandoned"));
    assert!(rows[0].latency_ms.is_some());
    let events = audit.best_effort.lock().unwrap();
    let abandoned = events
        .iter()
        .find(|event| event.action == "AudioTranscription")
        .expect("abandonment audited");
    assert_eq!(abandoned.outcome, AuditOutcome::ExecutionError);
    assert!(abandoned.latency_ms.is_some());
    assert!(abandoned.reason.as_deref().unwrap().contains("abandoned"));
    server.abort();
}
