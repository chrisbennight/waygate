use super::*;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use waygate_core::audio::{AudioResourceOperation as Operation, AudioResourceRequest, AudioUpload};

const WAV: &[u8] = b"RIFF\x28\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\xc0\x5d\x00\x00\x80\xbb\x00\x00\x02\x00\x10\x00data\x04\x00\x00\x00\x01\x00\x02\x00";

fn resource_request(
    operation: Operation,
    id: Option<&str>,
    fields: &[(&str, &str)],
) -> InvocationRequest {
    let mut request = InvocationRequest::new("llm", "speech");
    request.audio_resource = Some(AudioResourceRequest {
        operation,
        id: id.map(str::to_owned),
        fields: fields
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect(),
        upload: operation.upload_field().map(|_| AudioUpload {
            bytes: Arc::from(WAV),
            content_type: "audio/wav".into(),
            file_name: "reference.wav".into(),
        }),
    });
    request
}

fn dependencies(
    addr: SocketAddr,
    operations: Vec<Operation>,
) -> (LlmDispatcher, Arc<dyn LlmModelResolver>) {
    let caps = serde_json::from_value(json!({"formats":["pcm"],"voices":["narrator"],"custom_voices":true,"resources":operations})).unwrap();
    let model = ResolvedModel {
        operation: LlmOperation::Speech(caps),
        route: ResolvedRoute {
            provider: LlmProvider::OpenAi,
            credential_label: "TEST".into(),
            base_url: format!("http://{addr}/v1"),
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
    };
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(reqwest::Client::new())
            .with_single_attempt_http(reqwest::Client::builder())
            .unwrap(),
        Arc::new(LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_TEST".into(),
            json!({"api_key":"fixture-resource-key"}).to_string(),
        )])),
    );
    (
        dispatcher,
        Arc::new(StaticModelResolver::new().with_model("llm", "speech", model)),
    )
}

async fn json_result(service: &DefaultInvocationService, request: InvocationRequest) -> Value {
    let InvocationResponse::UnaryValue(body) =
        service.invoke(Some(&principal()), request).await.unwrap()
    else {
        panic!("expected standard resource metadata")
    };
    body
}

#[tokio::test]
async fn standard_recording_creation_selection_and_deletion_preserve_provider_resources() {
    #[derive(Default)]
    struct Library {
        consent: bool,
        voice: bool,
    }
    let library = Arc::new(Mutex::new(Library::default()));
    let consent_library = library.clone();
    let voice_library = library.clone();
    let delete_voice_library = library.clone();
    let read_consent_library = library.clone();
    let speech_library = library.clone();
    let app = Router::new()
        .route("/v1/audio/voice_consents", post(move |headers: HeaderMap, mut form: axum::extract::Multipart| {
            let library = consent_library.clone();
            async move {
                assert_eq!(headers["authorization"], "Bearer fixture-resource-key");
                let mut fields = BTreeMap::new();
                while let Some(field) = form.next_field().await.unwrap() {
                    let name = field.name().unwrap().to_owned();
                    fields.insert(name, field.bytes().await.unwrap());
                }
                assert_eq!(fields.len(),3);
                assert_eq!(fields["recording"].as_ref(), WAV);
                library.lock().unwrap().consent = true;
                axum::Json(json!({"id":"cons_fixture","object":"audio.voice_consent","created_at":1,"name":"private reference label","language":"en-US"}))
            }
        }))
        .route("/v1/audio/voices", post(move |mut form: axum::extract::Multipart| {
            let library = voice_library.clone();
            async move {
                let mut fields = BTreeMap::new();
                while let Some(field) = form.next_field().await.unwrap() {
                    let name = field.name().unwrap().to_owned();
                    if name == "audio_sample" {assert_eq!(field.file_name(), Some("reference.wav"));}
                    fields.insert(name, field.bytes().await.unwrap());
                }
                assert_eq!(fields.len(),4);
                assert_eq!(fields["consent"].as_ref(), b"cons_fixture");
                assert_eq!(fields["type"].as_ref(), b"audio_sample");
                assert_eq!(fields["audio_sample"].as_ref(), WAV);
                let mut state = library.lock().unwrap();
                assert!(state.consent);
                state.voice = true;
                axum::Json(json!({"id":"voice_fixture","object":"audio.voice","created_at":1,"name":"private voice label","type":"audio_sample"}))
            }
        }))
        .route("/v1/audio/voices/{voice_id}", axum::routing::delete(move || {
            let library = delete_voice_library.clone();
            async move {
                library.lock().unwrap().voice = false;
                axum::Json(json!({"id":"voice_fixture","object":"audio.voice.deleted","deleted":true}))
            }
        }))
        .route("/v1/audio/voice_consents/{consent_id}", axum::routing::get(move || {
            let library = read_consent_library.clone();
            async move {
                assert!(library.lock().unwrap().consent,"deleting a voice deleted its separate consent");
                axum::Json(json!({"id":"cons_fixture","object":"audio.voice_consent","created_at":1,"name":"private reference label","language":"en-US"}))
            }
        }))
        .route("/v1/audio/speech", post(move |axum::Json(body):axum::Json<Value>| {
            let library = speech_library.clone();
            async move {
                assert_eq!(body["voice"]["id"], "voice_fixture");
                if library.lock().unwrap().voice {
                    Response::builder().header("content-type","audio/pcm").body(Body::from(vec![1,0,2,0])).unwrap()
                } else {
                    Response::builder().status(404).body(Body::from("voice unavailable")).unwrap()
                }
            }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (dispatcher, resolver) = dependencies(
        addr,
        vec![
            Operation::ConsentCreate,
            Operation::VoiceCreate,
            Operation::VoiceDelete,
            Operation::ConsentRetrieve,
        ],
    );
    let usage = Arc::new(RecordingUsage::default());
    let audit = Arc::new(RecordingSink::default());
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher, resolver)
            .with_llm_usage_store(usage.clone());
    let consent = json_result(
        &service,
        resource_request(
            Operation::ConsentCreate,
            None,
            &[("name", "private reference label"), ("language", "en-US")],
        ),
    )
    .await;
    assert_eq!(consent["id"], "cons_fixture");
    let voice = json_result(
        &service,
        resource_request(
            Operation::VoiceCreate,
            None,
            &[
                ("name", "private voice label"),
                ("consent", "cons_fixture"),
                ("type", "audio_sample"),
            ],
        ),
    )
    .await;
    assert_eq!(voice["id"], "voice_fixture");
    let speech = || {
        let mut request = InvocationRequest::new("llm","speech").with_arguments(json!({"model":"speech","input":"private speech words","voice":{"id":"voice_fixture"},"response_format":"pcm"}).as_object().cloned());
        request.speech_surface = true;
        request
    };
    let mut another = principal();
    another.sub = "another-authorized-caller".into();
    let InvocationResponse::Media { mut body, .. } =
        service.invoke(Some(&another), speech()).await.unwrap()
    else {
        panic!("expected saved voice audio")
    };
    let mut audio = Vec::new();
    while let Some(chunk) = body.next().await {
        audio.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(audio, [1, 0, 2, 0]);
    assert_eq!(
        json_result(
            &service,
            resource_request(Operation::VoiceDelete, Some("voice_fixture"), &[])
        )
        .await["deleted"],
        true
    );
    assert!(
        service.invoke(Some(&principal()), speech()).await.is_err(),
        "deleted voice was silently substituted"
    );
    assert_eq!(
        json_result(
            &service,
            resource_request(Operation::ConsentRetrieve, Some("cons_fixture"), &[])
        )
        .await["id"],
        "cons_fixture"
    );
    let rows = usage.rows.lock().unwrap();
    assert!(rows
        .iter()
        .all(|row| row.input_tokens.is_none() && row.output_tokens.is_none()));
    assert!(rows
        .iter()
        .any(|row| row.inbound_surface == "audio_resource"));
    let events = serde_json::to_string(&*audit.best_effort.lock().unwrap()).unwrap();
    assert!(
        !events.contains("private reference label")
            && !events.contains("private voice label")
            && !events.contains("private speech words")
    );
    server.abort();
}

#[tokio::test]
async fn unconfirmed_provider_deletion_is_not_reported_as_deleted() {
    let app = Router::new().route(
        "/v1/audio/voices/{voice_id}",
        axum::routing::delete(|| async {
            axum::Json(json!({"object":"audio.voice.deleted","id":"voice_fixture","deleted":false}))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (dispatcher, resolver) = dependencies(addr, vec![Operation::VoiceDelete]);
    let audit = Arc::new(RecordingSink::default());
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher, resolver);
    assert!(service
        .invoke(
            Some(&principal()),
            resource_request(Operation::VoiceDelete, Some("voice_fixture"), &[])
        )
        .await
        .is_err());
    assert!(audit
        .best_effort
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.action == "AudioResource"
            && event.outcome == AuditOutcome::ExecutionError));
    server.abort();
}

#[tokio::test]
async fn unsupported_resource_fields_operations_and_denied_callers_do_not_contact_provider() {
    let calls = Arc::new(AtomicUsize::new(0));
    let called = calls.clone();
    let app = Router::new().fallback(move || {
        called.fetch_add(1, Ordering::SeqCst);
        async { "unexpected contact" }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (dispatcher, resolver) = dependencies(addr, vec![Operation::VoiceCreate]);
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher.clone(), resolver.clone());
    for request in [
        resource_request(Operation::VoiceDelete, Some("voice_fixture"), &[]),
        resource_request(
            Operation::VoiceCreate,
            None,
            &[
                ("name", "voice"),
                ("consent", "cons_fixture"),
                ("transcript", "private transcript"),
            ],
        ),
        resource_request(
            Operation::VoiceCreate,
            None,
            &[
                ("name", "voice"),
                ("consent", "cons_fixture"),
                ("type", "prompt"),
            ],
        ),
    ] {
        assert!(matches!(
            service.invoke(Some(&principal()), request).await,
            Err(InvocationError::InvalidArguments(_))
        ));
    }
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
            .invoke(
                Some(&principal()),
                resource_request(
                    Operation::VoiceCreate,
                    None,
                    &[("name", "voice"), ("consent", "cons_fixture")]
                )
            )
            .await,
        Err(InvocationError::Forbidden { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}
