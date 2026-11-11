use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn api_tool_conversation_preserves_context_and_governance_through_invocation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let app=Router::new().route("/v1beta/models/qualified-gemini:generateContent",post(
        move |headers:HeaderMap,axum::Json(body):axum::Json<Value>| {
            let seen=seen.clone();
            async move {
                assert_eq!(headers["x-goog-api-key"],"synthetic-api-key");
                assert!(!headers.contains_key("authorization"));
                let index=seen.fetch_add(1,Ordering::SeqCst);
                let parts=if index==0 {
                    assert_eq!(body["tools"][0]["functionDeclarations"][0]["name"],"weather");
                    json!([{"functionCall":{"id":"provider-call","name":"weather","args":{}},"thoughtSignature":"opaque-context"}])
                } else {
                    assert_eq!(body["contents"][1]["parts"][0]["thoughtSignature"],"opaque-context");
                    assert_eq!(body["contents"][1]["parts"][0]["functionCall"]["id"],"provider-call");
                    assert_eq!(body["contents"][2]["parts"][0]["functionResponse"]["id"],"provider-call");
                    json!([{"text":"sunny"}])
                };
                axum::Json(json!({"responseId":"response","modelVersion":"qualified-gemini",
                    "candidates":[{"content":{"role":"model","parts":parts},"finishReason":"STOP"}],
                    "usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":3,"thoughtsTokenCount":1}}))
            }
        }
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let credentials = Arc::new(LlmCredentialStore::from_vars([(
        "LLM_CRED_GOOGLE_API".into(),
        r#"{"api_key":"synthetic-api-key"}"#.into(),
    )]));
    let dispatcher = LlmDispatcher::new(ProviderClient::new(reqwest::Client::new()), credentials);
    let resolver: Arc<dyn LlmModelResolver> = Arc::new(StaticModelResolver::new().with_model(
        "llm",
        "gemini-api",
        ResolvedModel {
            operation: LlmOperation::Chat,
            route: ResolvedRoute {
                provider: LlmProvider::Google,
                credential_label: "API".into(),
                base_url: format!("http://{addr}"),
                path: "v1beta".into(),
                upstream_model: "qualified-gemini".into(),
                protocol: UpstreamProtocol::Gemini,
                embeddings_no_auth: false,
                openai_chatgpt: false,
            },
            fallbacks: vec![],
            risk: ModelRisk::Low,
            ttfb: None,
            cache_ttl: None,
        },
    ));
    let audit = Arc::new(RecordingSink::default());
    let usage = Arc::new(RecordingUsage::default());
    let svc =
        DefaultInvocationService::new(Arc::new(FakeCatalog), Arc::new(AllowAllGate), audit.clone())
            .with_llm(dispatcher.clone(), resolver.clone())
            .with_llm_usage_store(usage.clone());
    let mut arguments = json!({"model":"gemini-api","messages":[{"role":"user","content":"weather?"}],
        "tools":[{"type":"function","function":{"name":"weather","parameters":{"type":"object","properties":{}}}}]});
    let request =
        InvocationRequest::new("llm", "gemini-api").with_arguments(arguments.as_object().cloned());
    let InvocationResponse::UnaryValue(first) =
        svc.invoke(Some(&principal()), request).await.unwrap()
    else {
        panic!("unary response")
    };
    assert_eq!(
        first["choices"][0]["message"]["tool_calls"][0]["id"],
        "provider-call"
    );
    arguments["messages"].as_array_mut().unwrap().extend([
        first["choices"][0]["message"].clone(),
        json!({"role":"tool","tool_call_id":"provider-call","content":"sunny"}),
    ]);
    let request =
        InvocationRequest::new("llm", "gemini-api").with_arguments(arguments.as_object().cloned());
    let InvocationResponse::UnaryValue(second) =
        svc.invoke(Some(&principal()), request).await.unwrap()
    else {
        panic!("unary response")
    };
    assert_eq!(second["choices"][0]["message"]["content"], "sunny");
    {
        let rows = usage.rows.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|row| row.input_tokens == Some(2) && row.output_tokens == Some(4)));
    }
    assert_eq!(audit.best_effort.lock().unwrap().len(), 2);
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
    let request =
        InvocationRequest::new("llm", "gemini-api").with_arguments(arguments.as_object().cloned());
    assert!(matches!(
        denied.invoke(Some(&principal()), request).await,
        Err(InvocationError::Forbidden { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
}
