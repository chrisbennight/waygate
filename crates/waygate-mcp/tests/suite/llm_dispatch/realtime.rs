use super::*;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use waygate_core::realtime::{RealtimeCapabilities, RealtimeRequest};

fn caps() -> RealtimeCapabilities {
    serde_json::from_value(
        json!({"websocket":true,"webrtc":true,"voices":["narrator"],"custom_voices":true}),
    )
    .unwrap()
}

fn resolver(addr: SocketAddr, measured: bool) -> Arc<dyn LlmModelResolver> {
    let mut caps = caps();
    caps.measured_usage = measured;
    Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "live",
        ResolvedModel {
            operation: LlmOperation::Realtime(caps),
            route: ResolvedRoute {
                provider: LlmProvider::OpenAi,
                credential_label: "TEST".into(),
                base_url: format!("http://{addr}"),
                path: "realtime".into(),
                upstream_model: "upstream-live".into(),
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

fn request(request: RealtimeRequest) -> InvocationRequest {
    let mut result = InvocationRequest::new("llm", "live");
    result.realtime = Some(request);
    result
}

async fn server(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn idle_call_provider(hangups: Arc<AtomicUsize>) -> SocketAddr {
    server(
        Router::new()
            .route(
                "/realtime/calls",
                post(|| async {
                    Response::builder()
                        .status(201)
                        .header("location", "/realtime/calls/call_shared")
                        .header("content-type", "application/sdp")
                        .body(Body::from("v=0\r\n"))
                        .unwrap()
                }),
            )
            .route(
                "/realtime",
                get(|ws: WebSocketUpgrade| async {
                    ws.on_upgrade(
                        |mut socket| async move { while socket.next().await.is_some() {} },
                    )
                }),
            )
            .route(
                "/realtime/calls/call_shared/hangup",
                post(move |headers: HeaderMap| {
                    let hangups = hangups.clone();
                    async move {
                        assert_eq!(headers["authorization"], "Bearer fixture-speech-key");
                        hangups.fetch_add(1, Ordering::SeqCst);
                        axum::http::StatusCode::OK
                    }
                }),
            ),
    )
    .await
}

fn call_request() -> InvocationRequest {
    request(RealtimeRequest::WebRtc {
        sdp: "v=0\r\n".into(),
        session: json!({"type":"realtime","model":"live"}),
    })
}

#[tokio::test]
async fn graceful_shutdown_waits_for_call_hangup_and_final_evidence() {
    let hangups = Arc::new(AtomicUsize::new(0));
    let addr = idle_call_provider(hangups.clone()).await;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let work = tokio_util::task::TaskTracker::new();
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let dispatcher =
        super::speech::speech_dispatcher().with_realtime_lifecycle(shutdown.clone(), work.clone());
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher, resolver(addr, false))
            .with_llm_usage_store(usage.clone());
    let InvocationResponse::RealtimeCall { delivery_guard, .. } = service
        .invoke(Some(&principal()), call_request())
        .await
        .unwrap()
    else {
        panic!("expected call")
    };
    delivery_guard.disarm();
    work.close();
    assert!(
        !work.is_empty(),
        "an established call remains drain work after SDP delivery"
    );
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), work.wait())
        .await
        .unwrap();
    assert_eq!(hangups.load(Ordering::SeqCst), 1);
    assert_eq!(
        usage.rows.lock().unwrap()[0].finish_reason.as_deref(),
        Some("service_shutdown")
    );
    assert!(audit
        .best_effort
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.action == "RealtimeSession"
            && event
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("service_shutdown")
                    && reason.contains("\"call_termination_confirmed\":true"))));
    assert!(service
        .invoke(Some(&principal()), call_request())
        .await
        .is_err());
}

#[tokio::test]
async fn native_call_controls_follow_shared_provider_authority_and_model_authorization() {
    let hangups = Arc::new(AtomicUsize::new(0));
    let addr = idle_call_provider(hangups.clone()).await;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let work = tokio_util::task::TaskTracker::new();
    let dispatcher =
        super::speech::speech_dispatcher().with_realtime_lifecycle(shutdown.clone(), work.clone());
    let usage = Arc::new(RecordingUsage::default());
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher.clone(), resolver(addr, false))
    .with_llm_usage_store(usage.clone());
    let InvocationResponse::RealtimeCall {
        call_id,
        delivery_guard,
        ..
    } = service
        .invoke(Some(&principal()), call_request())
        .await
        .unwrap()
    else {
        panic!("expected call")
    };
    delivery_guard.disarm();
    let mut other = principal_named("another-authorized-caller");
    other.tenant = waygate_core::TenantId::parse("other-tenant").unwrap();
    assert!(service
        .invoke(
            Some(&other),
            request(RealtimeRequest::Hangup {
                call_id: call_id.clone()
            })
        )
        .await
        .is_ok());
    assert_eq!(hangups.load(Ordering::SeqCst), 1);
    {
        let rows = usage.rows.lock().unwrap();
        assert_eq!(rows[0].principal_sub.as_deref(), Some(other.sub.as_str()));
        assert_eq!(rows[0].tenant_id, other.tenant.as_str());
    }
    let denied = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(FixedGate(AuthzVerdict::Deny {
            reason: "model not granted".into(),
            policy_ids: vec![],
            reasons: vec![],
        })),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(dispatcher, resolver(addr, false));
    assert!(matches!(
        denied
            .invoke(
                Some(&principal()),
                request(RealtimeRequest::Hangup { call_id })
            )
            .await,
        Err(InvocationError::Forbidden { .. })
    ));
    assert_eq!(
        hangups.load(Ordering::SeqCst),
        1,
        "a denied caller must not reach provider controls"
    );
    work.close();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), work.wait())
        .await
        .unwrap();
}

#[tokio::test]
async fn standard_events_keep_ids_and_completion_separate_from_disconnect() {
    let ended = Arc::new(tokio::sync::Notify::new());
    let ended_provider = ended.clone();
    let addr = server(Router::new().route("/realtime",get(move |ws:WebSocketUpgrade,headers:HeaderMap,uri:axum::http::Uri| {
        let ended = ended_provider.clone(); async move {
        assert_eq!(headers["authorization"],"Bearer fixture-speech-key");
        assert_eq!(uri.query(),Some("model=upstream-live"));
        ws.on_upgrade(move |mut socket| async move {
            socket.send(Message::Text(json!({"type":"session.created","session":{"id":"sess_fixture","type":"realtime"}}).to_string().into())).await.unwrap();
            let Some(Ok(Message::Text(text))) = socket.next().await else { panic!("client event missing") };
            assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["type"],"conversation.item.create");
            let Some(Ok(Message::Text(text))) = socket.next().await else { panic!("response create missing") };
            assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["type"],"response.create");
            for value in [json!({"type":"response.created","response":{"id":"resp_fixture"}}),json!({"type":"response.output_audio.delta","response_id":"resp_fixture","delta":"AQID"}),json!({"type":"response.done","response":{"id":"resp_fixture","status":"completed","usage":{"input_tokens":0,"output_tokens":0}}})] {
                socket.send(Message::Text(value.to_string().into())).await.unwrap();
            }
            while socket.next().await.is_some_and(|result| !matches!(result,Ok(Message::Close(_))|Err(_))) {}
            ended.notify_one();
        }) }
    }))).await;
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let dispatcher = super::speech::speech_dispatcher();
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher.clone(), resolver(addr, false))
            .with_llm_usage_store(usage.clone());
    let InvocationResponse::Realtime {
        mut commands,
        mut events,
    } = service
        .invoke(Some(&principal()), request(RealtimeRequest::WebSocket))
        .await
        .unwrap()
    else {
        panic!("expected socket")
    };
    assert_eq!(
        events.next().await.unwrap().unwrap()["session"]["id"],
        "sess_fixture"
    );
    commands.send(json!({"type":"conversation.item.create","item":{"type":"message","role":"user","content":[{"type":"input_text","text":"private narration"}]}})).await.unwrap();
    commands
        .send(json!({"type":"response.create"}))
        .await
        .unwrap();
    for kind in [
        "response.created",
        "response.output_audio.delta",
        "response.done",
    ] {
        let value = events.next().await.unwrap().unwrap();
        assert_eq!(value["type"], kind);
    }
    drop(events);
    drop(commands);
    tokio::time::timeout(Duration::from_secs(3), ended.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !usage.rows.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let rows = usage.rows.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].inbound_surface, "realtime");
    assert!(rows[0].input_tokens.is_none());
    let events = audit.best_effort.lock().unwrap();
    let generation = events
        .iter()
        .find(|event| event.action == "RealtimeGeneration")
        .unwrap();
    assert_eq!(generation.outcome, AuditOutcome::Success);
    assert!(generation.reason.as_ref().unwrap().contains("completed"));
    assert!(!format!("{events:?}").contains("private narration"));
    assert!(events.iter().any(|event| event.action == "RealtimeSession"
        && event
            .reason
            .as_ref()
            .unwrap()
            .contains("client_disconnected")));
    assert!(dispatcher.try_admit_realtime_session().is_some());
}

#[tokio::test]
async fn webrtc_known_call_is_hung_up_when_answer_body_fails() {
    let hangups = Arc::new(AtomicUsize::new(0));
    let counter = hangups.clone();
    let addr = server(
        Router::new()
            .route(
                "/realtime/calls",
                post(|| async {
                    Response::builder()
                        .status(201)
                        .header("location", "/realtime/calls/call_fixture")
                        .body(Body::from("invalid SDP"))
                        .unwrap()
                }),
            )
            .route(
                "/realtime/calls/call_fixture/hangup",
                post(move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                    async { axum::http::StatusCode::OK }
                }),
            ),
    )
    .await;
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(AllowAllGate),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(super::speech::speech_dispatcher(), resolver(addr, false));
    assert!(service
        .invoke(
            Some(&principal()),
            request(RealtimeRequest::WebRtc {
                sdp: "v=0\r\n".into(),
                session: json!({"type":"realtime","model":"live"})
            })
        )
        .await
        .is_err());
    assert_eq!(hangups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn webrtc_sideband_observes_provider_media_and_explicit_hangup_uses_native_id() {
    let hangups = Arc::new(AtomicUsize::new(0));
    let counter = hangups.clone();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let release_provider = release.clone();
    let closed = Arc::new(tokio::sync::Notify::new());
    let closed_provider = closed.clone();
    let addr = server(Router::new().route("/realtime/calls",post(|mut form:axum::extract::Multipart| async move {
        let mut session = None;
        while let Some(field) = form.next_field().await.unwrap() {if field.name()==Some("session") {session=Some(serde_json::from_str::<Value>(&field.text().await.unwrap()).unwrap());}}
        assert_eq!(session.unwrap()["model"],"upstream-live");
        Response::builder().status(201).header("location","/realtime/calls/call_fixture").body(Body::from("v=0\r\n")).unwrap()
    })).route("/realtime",get(move |ws:WebSocketUpgrade,uri:axum::http::Uri| {
        let release=release_provider.clone(); let closed=closed_provider.clone(); async move {
        assert_eq!(uri.query(),Some("call_id=call_fixture"));
        ws.on_upgrade(move |mut socket| async move {
            release.acquire().await.unwrap().forget();
            for event in [json!({"type":"response.created","response":{"id":"resp_rtc"}}),json!({"type":"output_audio_buffer.started","response_id":"resp_rtc"}),json!({"type":"response.done","response":{"id":"resp_rtc","status":"cancelled","usage":{"input_tokens":5,"output_tokens":7}}}),json!({"type":"output_audio_buffer.cleared","response_id":"resp_rtc"})] {
                socket.send(Message::Text(event.to_string().into())).await.unwrap();
            }
            socket.close().await.unwrap(); closed.notify_one();
        }) }
    })).route("/realtime/calls/call_fixture/hangup",post(move || {counter.fetch_add(1,Ordering::SeqCst);async {axum::http::StatusCode::OK}}))).await;
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let service =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(super::speech::speech_dispatcher(), resolver(addr, true))
            .with_llm_usage_store(usage.clone());
    let InvocationResponse::RealtimeCall {
        call_id,
        sdp,
        delivery_guard,
    } = service
        .invoke(
            Some(&principal()),
            request(RealtimeRequest::WebRtc {
                sdp: "v=0\r\n".into(),
                session: json!({"type":"realtime","model":"live"}),
            }),
        )
        .await
        .unwrap()
    else {
        panic!("expected call")
    };
    assert_eq!(call_id, "call_fixture");
    assert!(sdp.starts_with("v=0"));
    delivery_guard.disarm();
    release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(3), closed.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !usage.rows.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(usage.rows.lock().unwrap()[0].input_tokens, Some(5));
    assert_eq!(hangups.load(Ordering::SeqCst), 1);
    {
        let evidence = audit.best_effort.lock().unwrap();
        let event = evidence
            .iter()
            .find(|event| event.action == "RealtimeGeneration")
            .unwrap();
        let reason: Value = serde_json::from_str(event.reason.as_ref().unwrap()).unwrap();
        assert_eq!(reason["provider_cancellation_confirmed"], true);
        assert_eq!(reason["first_audio_boundary"], "provider_media_started");
        assert_eq!(reason["media_outcome"], "provider_buffer_cleared");
        assert!(reason["first_audio_ms"].is_number());
    }
    assert!(service
        .invoke(
            Some(&principal()),
            request(RealtimeRequest::Hangup { call_id })
        )
        .await
        .is_ok());
    assert_eq!(hangups.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn policy_changes_end_an_existing_session_without_waiting_for_provider_close() {
    struct LiveGate(Arc<AtomicBool>);
    #[async_trait]
    impl AuthzGate for LiveGate {
        async fn may_discover_server(&self, _: &Principal, _: &str) -> bool {
            true
        }
        async fn authorize_tool_call(&self, _: &waygate_core::Facts) -> AuthzVerdict {
            if self.0.load(Ordering::SeqCst) {
                AuthzVerdict::Allow { policy_ids: vec![] }
            } else {
                AuthzVerdict::Deny {
                    reason: "revoked".into(),
                    policy_ids: vec![],
                    reasons: vec![],
                }
            }
        }
    }
    let app = Router::new().route(
        "/realtime",
        get(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut socket| async move { while socket.next().await.is_some() {} })
        }),
    );
    let addr = server(app).await;
    let allow = Arc::new(AtomicBool::new(true));
    let usage = Arc::new(RecordingUsage::default());
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog),
        Arc::new(LiveGate(allow.clone())),
        Arc::new(RecordingSink::default()),
    )
    .with_llm(super::speech::speech_dispatcher(), resolver(addr, false))
    .with_llm_usage_store(usage.clone());
    let InvocationResponse::Realtime {
        commands: _commands,
        mut events,
    } = service
        .invoke(Some(&principal()), request(RealtimeRequest::WebSocket))
        .await
        .unwrap()
    else {
        panic!("expected socket")
    };
    allow.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(7), events.next())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !usage.rows.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        usage.rows.lock().unwrap()[0].finish_reason.as_deref(),
        Some("policy_or_budget_revoked")
    );
}
