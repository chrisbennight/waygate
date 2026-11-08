//! Opt-in real SDK and WebRTC media tests, isolated from deployed services.

use super::*;
use tokio::io::AsyncBufReadExt;
use waygate_mcp::catalog::UpstreamCatalog;

struct NoTools;
#[async_trait::async_trait]
impl UpstreamCatalog for NoTools {
    async fn list_servers(&self) -> Vec<String> {
        vec![]
    }
    async fn list_tools(&self, _: &str) -> Result<Vec<rmcp::model::Tool>, rmcp::ErrorData> {
        Ok(vec![])
    }
    async fn call_tool(
        &self,
        _: &str,
        _: &str,
        _: Option<serde_json::Map<String, Value>>,
        _: Option<&waygate_oidc::Principal>,
        _: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        panic!("audio fixture must not call tools")
    }
    fn tool_facts(&self, _: &str, _: &str) -> waygate_mcp::authz::ToolFacts {
        panic!("audio fixture must use model facts")
    }
}

/// Stands in for the gateway's client authentication: only the fixture
/// gateway key reaches the inference routes, as an authenticated principal.
async fn fixture_gateway_authentication(
    mut req: Request,
    next: axum::middleware::Next,
) -> Response {
    if req
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer fixture-gateway")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    req.extensions_mut().insert(waygate_oidc::Principal {
        sub: "fixture-client".into(),
        email: None,
        groups: vec![],
        issuer: "https://fixture.invalid".into(),
        scopes: vec!["mcp:invoke".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::ApiKey,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    });
    next.run(req).await
}

#[tokio::test]
#[ignore = "requires an isolated OpenAI Python SDK; see docs/audio-api.md"]
async fn openai_transcription_sdk_through_authenticated_gateway() {
    let python = std::env::var("TRANSCRIPTION_SDK_PYTHON")
        .expect("set TRANSCRIPTION_SDK_PYTHON to the isolated SDK environment");
    // A private stand-in provider that requires the gateway's shared key.
    let provider_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = provider_calls.clone();
    let provider = Router::new().route(
        "/v1/audio/transcriptions",
        post(
            move |headers: axum::http::HeaderMap, mut form: axum::extract::Multipart| {
                let calls = calls.clone();
                async move {
                    if headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        != Some("Bearer fixture-provider")
                    {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut fields = std::collections::BTreeMap::new();
                    while let Some(field) = form.next_field().await.unwrap() {
                        let name = field.name().unwrap().to_owned();
                        fields.insert(name, field.bytes().await.unwrap());
                    }
                    assert_eq!(fields["model"].as_ref(), b"fixture-asr");
                    assert!(fields["file"].starts_with(b"RIFF"));
                    if fields["response_format"].as_ref() == b"text" {
                        "fixture transcript".into_response()
                    } else {
                        Json(json!({"text":"fixture transcript"})).into_response()
                    }
                }
            },
        ),
    );
    let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_url = format!("http://{}/v1", provider_listener.local_addr().unwrap());
    let provider_server =
        tokio::spawn(async move { axum::serve(provider_listener, provider).await.unwrap() });
    let defs: Vec<ModelDef> = serde_json::from_value(json!([{
        "alias":"local-asr", "provider":"openai", "credential_label":"TEST",
        "base_url":provider_url, "upstream_model":"fixture-asr", "kind":"transcription",
        "transcription":{"file_types":["wav"],"response_formats":["json","text"]}
    }]))
    .unwrap();
    let (_, resolver) = build_from_defs(defs, None).unwrap().unwrap();
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(http_client::client(Profile::Standard).unwrap())
            .with_single_attempt_http(http_client::builder(Profile::Standard))
            .unwrap(),
        Arc::new(LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_TEST".into(),
            json!({"api_key":"fixture-provider"}).to_string(),
        )])),
    );
    let evidence = Arc::new(waygate_mcp::audit::InMemorySink::new());
    let service = Arc::new(
        waygate_mcp::DefaultInvocationService::new(
            Arc::new(NoTools),
            Arc::new(waygate_mcp::authz::AllowAllGate),
            evidence.clone(),
        )
        .with_llm(dispatcher, resolver.clone()),
    );
    let app = router(service, None, resolver)
        .layer(axum::middleware::from_fn(fixture_gateway_authentication));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // The client receives only the gateway URL, never the provider address.
    let client = tokio::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/test-transcription-sdk.py"
        ))
        .arg(format!("http://{addr}/v1"))
        .kill_on_drop(true)
        .output();
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), client)
        .await
        .unwrap()
        .unwrap();
    gateway.abort();
    provider_server.abort();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    println!("{}", String::from_utf8_lossy(&result.stdout));
    // Unsupported options and unauthenticated callers never reach the provider.
    assert_eq!(provider_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    let events = evidence.snapshot().await;
    assert!(events
        .iter()
        .any(|event| event.action == "AudioTranscription"
            && event.outcome == waygate_mcp::audit::AuditOutcome::Success));
    assert!(!format!("{events:?}").contains("fixture transcript"));
}

#[tokio::test]
#[ignore = "requires isolated OpenAI Python SDK and aiortc; see docs/audio-api.md"]
async fn openai_audio_sdk_and_real_webrtc_media() {
    let python = std::env::var("AUDIO_SDK_PYTHON")
        .expect("set AUDIO_SDK_PYTHON to the isolated SDK environment");
    let mut provider = tokio::process::Command::new(&python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/audio-sdk-fixture.py"
        ))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = tokio::io::BufReader::new(provider.stdout.take().unwrap()).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(15), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("provider ready");
    let provider_url = serde_json::from_str::<Value>(&line).unwrap()["base_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut defs:Vec<ModelDef>=serde_json::from_value(json!([
        {"alias":"speech","provider":"openai","credential_label":"TEST","base_url":provider_url,"upstream_model":"fixture-speech","kind":"speech","speech":{"formats":["pcm","wav"],"sse_formats":["pcm"],"voices":["narrator"],"custom_voices":true,"instructions":true,"resources":["voice_create","voice_delete","consent_create","consent_list","consent_retrieve","consent_update","consent_delete"]}},
        {"alias":"live","provider":"openai","credential_label":"TEST","base_url":provider_url,"upstream_model":"fixture-live","kind":"realtime","realtime":{"websocket":true,"webrtc":true,"voices":["narrator"],"custom_voices":true,"max_session_seconds":30}}
    ])).unwrap();
    normalize_model_defs(&mut defs).unwrap();
    let (_, resolver) = build_from_defs(defs, None).unwrap().unwrap();
    let dispatcher = LlmDispatcher::new(
        ProviderClient::new(http_client::client(Profile::Standard).unwrap())
            .with_single_attempt_http(http_client::builder(Profile::Standard))
            .unwrap(),
        Arc::new(LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_TEST".into(),
            json!({"api_key":"fixture-provider"}).to_string(),
        )])),
    );
    let evidence = Arc::new(waygate_mcp::audit::InMemorySink::new());
    let service = Arc::new(
        waygate_mcp::DefaultInvocationService::new(
            Arc::new(NoTools),
            Arc::new(waygate_mcp::authz::AllowAllGate),
            evidence.clone(),
        )
        .with_llm(dispatcher, resolver.clone()),
    );
    let app = router(service, None, resolver)
        .layer(axum::middleware::from_fn(fixture_gateway_authentication));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = tokio::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/test-audio-sdk.py"
        ))
        .arg(format!("http://{addr}/v1"))
        .arg(provider_url)
        .kill_on_drop(true)
        .output();
    let result = tokio::time::timeout(std::time::Duration::from_secs(90), client)
        .await
        .unwrap()
        .unwrap();
    gateway.abort();
    provider.kill().await.unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    println!("{}", String::from_utf8_lossy(&result.stdout));
    let events = evidence.snapshot().await;
    assert!(events
        .iter()
        .any(|event| event.action == "RealtimeGeneration"
            && event
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("provider_media_started"))));
    assert!(!format!("{events:?}").contains("Fixture narration"));
}
