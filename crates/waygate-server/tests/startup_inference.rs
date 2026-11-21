//! Inference configuration errors must leave the serving gateway available.

use std::{path::Path, process::Stdio, time::Duration};

use axum::{routing::post, Json, Router};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tokio::{net::TcpListener, process::Command, time::Instant};

#[tokio::test]
async fn invalid_pins_leave_mcp_and_healthy_inference_available() {
    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_url = format!("http://{}/v1", provider.local_addr().unwrap());
    let backend = Router::new().route(
        "/v1/chat/completions",
        post(|Json(request): Json<Value>| async move {
            if request["model"] != "upstream-chat" {
                return (StatusCode::BAD_REQUEST, Json(json!({"error":"unexpected model"})));
            }
            (StatusCode::OK, Json(json!({
                "id":"chatcmpl-local", "model":"upstream-chat",
                "choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"local completion"}}]
            })))
        }),
    );
    let backend_task = tokio::spawn(async move { axum::serve(provider, backend).await.unwrap() });
    let mixed = json!([
        {"alias":"invalid-chat", "provider":"openai", "base_url":provider_url, "authentication":"invalid"},
        {"alias":"valid-chat", "model":"openai:upstream-chat", "base_url":provider_url, "credential_label":"TEST"},
    ])
    .to_string();

    for (models, has_valid_chat) in [("[", false), (&mixed, true)] {
        let servers = tempfile::tempdir().unwrap();
        let policies =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../waygate-authz/tests/fixtures/policies");
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);
        let base = format!("http://{addr}");
        let mut gateway = Command::new(env!("CARGO_BIN_EXE_gateway-server"))
            .env_clear()
            .env("GATEWAY_AUTH_MODE", "disabled")
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
            .kill_on_drop(true)
            .spawn()
            .expect("start the gateway");
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
        assert_mcp_tool_works(&client, &base).await;
        if has_valid_chat {
            let good = chat(&client, &base, "valid-chat").await;
            assert_eq!(good.status(), StatusCode::OK);
            assert_eq!(
                good.json::<Value>().await.unwrap()["choices"][0]["message"]["content"],
                "local completion"
            );
            let invalid = chat(&client, &base, "invalid-chat").await;
            assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
            assert!(invalid.json::<Value>().await.unwrap()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unknown model"));
        }
        gateway.kill().await.unwrap();
    }
    backend_task.abort();
}

async fn chat(client: &Client, base: &str, alias: &str) -> reqwest::Response {
    client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({"model": alias, "messages":[{"role":"user","content":"hello"}]}))
        .send()
        .await
        .unwrap()
}

async fn assert_mcp_tool_works(client: &Client, base: &str) {
    let response = client.post(format!("{base}/mcp"))
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
