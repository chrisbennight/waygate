//! Credential-free chat through a running gateway.

use std::{
    path::Path,
    process::Stdio,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tokio::{net::TcpListener, process::Command, time::Instant};
use waygate_oidc::identity_jwt::IdentityIssuer;

#[tokio::test]
async fn credential_free_chat_supports_streamed_and_non_streamed_requests() {
    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_url = format!("http://{}/v1", provider.local_addr().unwrap());
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let calls = provider_calls.clone();
    let backend = Router::new().route(
        "/v1/chat/completions",
        post(move |headers: HeaderMap, Json(request): Json<Value>| {
            calls.fetch_add(1, Ordering::Relaxed);
            async move {
                let authorization = headers.get("authorization");
                let model = request["model"].as_str();
                match (model, authorization.and_then(|value| value.to_str().ok())) {
                    (Some("upstream-chat"), Some("Bearer synthetic-test-fixture")) => {}
                    (Some("upstream-private"), _) if authorization.is_none() => {}
                    (Some("upstream-error"), _) if authorization.is_none() => {
                        return (
                            StatusCode::TOO_MANY_REQUESTS,
                            "fixture provider diagnostics",
                        )
                            .into_response();
                    }
                    _ => return StatusCode::BAD_REQUEST.into_response(),
                }
                if request["stream"] == true {
                    let events = concat!(
                        "data: {\"id\":\"chatcmpl-local\",\"model\":\"upstream-private\",",
                        "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"local completion\"},",
                        "\"finish_reason\":\"stop\"}]}\n\n",
                        "data: [DONE]\n\n",
                    );
                    return ([("content-type", "text/event-stream")], events).into_response();
                }
                Json(json!({
                    "id": "chatcmpl-local",
                    "model": model,
                    "choices": [{
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "local completion"}
                    }]
                }))
                .into_response()
            }
        }),
    );
    let backend_task = tokio::spawn(async move { axum::serve(provider, backend).await.unwrap() });
    let disconnected = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let disconnected_addr = disconnected.local_addr().unwrap().to_string();
    let disconnected_task = tokio::spawn(async move {
        while let Ok((socket, _)) = disconnected.accept().await {
            drop(socket);
        }
    });
    let models = json!([
        {"alias":"valid-chat", "model":"openai:upstream-chat", "base_url":provider_url, "credential_label":"TEST"},
        {"alias":"private-chat", "model":"openai:upstream-private", "base_url":provider_url, "authentication":"none"},
        {"alias":"restricted-chat", "model":"openai:upstream-private", "base_url":provider_url, "authentication":"none", "risk":"high"},
        {"alias":"error-chat", "model":"openai:upstream-error", "base_url":provider_url, "authentication":"none"},
        {"alias":"disconnected-chat", "model":"openai:upstream-private", "base_url":format!("http://{disconnected_addr}/v1"), "authentication":"none"},
    ])
    .to_string();

    let servers = tempfile::tempdir().unwrap();
    let policies =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../waygate-authz/tests/fixtures/policies");
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reservation.local_addr().unwrap();
    let base = format!("http://{addr}");
    let issuer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_url = format!("http://{}", issuer_listener.local_addr().unwrap());
    let fixture_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer = IdentityIssuer::from_ed25519_pkcs8_pem(
        &fixture_key.serialize_pem(),
        "chat-test",
        &issuer_url,
        "chat-test",
        Duration::from_secs(60),
    )
    .unwrap();
    let token = issuer
        .mint_access_token(
            "chat-test-client",
            None,
            &[],
            &base,
            &["mcp:read".into(), "mcp:invoke".into(), "mcp:search".into()],
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap();
    let jwks = issuer.jwks();
    let discovery = json!({"issuer": issuer_url, "jwks_uri":format!("{issuer_url}/jwks")});
    let issuer_router = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let discovery = discovery.clone();
                async move { Json(discovery) }
            }),
        )
        .route(
            "/jwks",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
    let issuer_task =
        tokio::spawn(async move { axum::serve(issuer_listener, issuer_router).await.unwrap() });
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_gateway-server"));
    gateway
        .env_clear()
        .env("GATEWAY_AUTH_MODE", "enforce")
        .env("AUTHENTIK_ISSUER", issuer_url)
        .env("GATEWAY_DEPLOYMENT_PROFILE", "dev")
        .env("GATEWAY_LISTEN_ADDR", addr.to_string())
        .env("GATEWAY_PUBLIC_URL", &base)
        .env("GATEWAY_MCP_ALLOWED_HOSTS", "")
        .env("GATEWAY_SERVERS_DIR", servers.path())
        .env("GATEWAY_POLICIES_DIR", policies)
        .env("GATEWAY_LLM_MODELS", models)
        .env(
            "LLM_CRED_OPENAI_TEST",
            r#"{"api_key":"synthetic-test-fixture"}"#,
        )
        .stdin(Stdio::null())
        .kill_on_drop(true);
    drop(reservation);
    let mut gateway = gateway.spawn().expect("start the gateway");
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            gateway.try_wait().unwrap().is_none(),
            "gateway exited during boot"
        );
        if client
            .get(format!("{base}/readyz"))
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
        {
            break;
        }
        assert!(Instant::now() < deadline, "gateway did not become ready");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_mcp_tool_works(&client, &base, &token).await;
    let anonymous = chat(&client, &base, "private-chat", false, None).await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let restricted = chat(&client, &base, "restricted-chat", false, Some(&token)).await;
    assert_eq!(restricted.status(), StatusCode::FORBIDDEN);
    assert_eq!(provider_calls.load(Ordering::Relaxed), 0);
    for alias in ["valid-chat", "private-chat"] {
        let good = chat(&client, &base, alias, false, Some(&token)).await;
        assert_eq!(good.status(), StatusCode::OK, "{alias}");
        assert_eq!(
            good.json::<Value>().await.unwrap()["choices"][0]["message"]["content"],
            "local completion",
            "{alias}"
        );
    }
    let stream = chat(&client, &base, "private-chat", true, Some(&token)).await;
    assert_eq!(stream.status(), StatusCode::OK);
    let events = stream.text().await.unwrap();
    assert!(events.contains("local completion"));
    assert!(events.contains("data: [DONE]"));
    let failure = chat(&client, &base, "error-chat", false, Some(&token)).await;
    assert_eq!(failure.status(), StatusCode::BAD_GATEWAY);
    let message = failure.text().await.unwrap();
    assert!(message.contains("provider returned HTTP 429"));
    assert!(!message.contains("fixture provider diagnostics"));
    let failure = chat(&client, &base, "disconnected-chat", false, Some(&token)).await;
    assert_eq!(failure.status(), StatusCode::BAD_GATEWAY);
    let message = failure.text().await.unwrap();
    assert!(message.contains("could not complete backend request"));
    assert!(!message.contains(&disconnected_addr));
    gateway.kill().await.unwrap();
    issuer_task.abort();
    backend_task.abort();
    disconnected_task.abort();
}

async fn chat(
    client: &Client,
    base: &str,
    alias: &str,
    stream: bool,
    token: Option<&str>,
) -> reqwest::Response {
    let request = client.post(format!("{base}/v1/chat/completions")).json(
        &json!({"model": alias, "messages":[{"role":"user","content":"hello"}], "stream": stream}),
    );
    let request = match token {
        Some(token) => request.bearer_auth(token),
        None => request,
    };
    request.send().await.unwrap()
}

async fn assert_mcp_tool_works(client: &Client, base: &str, token: &str) {
    let response = client.post(format!("{base}/mcp"))
        .bearer_auth(token)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("MCP-Method", "tools/call")
        .header("MCP-Name", "gateway-discovery.search")
        .json(&json!({
            "jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
                "name":"gateway-discovery.search", "arguments":{"query":"search"},
                "_meta":{
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities":{},
                    "io.modelcontextprotocol/clientInfo":{"name":"inference-startup-test","version":"1"}
                }
            }
        }))
        .send().await.unwrap().error_for_status().unwrap().text().await.unwrap();
    let reply: Value = serde_json::from_str(&response).unwrap_or_else(|_| {
        response
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Value>(data).ok())
            .find(|message| message["id"] == 1)
            .expect("MCP response")
    });
    assert!(reply["result"].is_object(), "{reply}");
    assert_ne!(reply["result"]["isError"], true, "{reply}");
}
