//! Inference configuration errors must leave the serving gateway available.

use std::{path::Path, process::Stdio, time::Duration};

use axum::{routing::post, Json, Router};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
    process::{Child, Command},
    time::Instant,
};

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
        let (mut gateway, base, _servers) = start_gateway(models, None);
        let client = test_client();
        wait_for_gateway(&mut gateway, &client, &base).await;
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

#[tokio::test]
async fn stalled_catalog_recovers_without_losing_routes_or_mispricing_usage() {
    let Ok(database_url) = std::env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping startup catalog test: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await
        .expect("connect to isolated test database");
    waygate_storage::PgAuditSink::migrate(&pool).await.unwrap();

    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_url = format!("http://{}/v1", provider.local_addr().unwrap());
    let backend = Router::new().route(
        "/v1/chat/completions",
        post(|Json(request): Json<Value>| async move {
            Json(json!({
                "id": "chatcmpl-local", "model": request["model"],
                "choices": [{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],
                "usage": {"prompt_tokens":1000000,"completion_tokens":0}
            }))
        }),
    );
    let backend_task = tokio::spawn(async move { axum::serve(provider, backend).await.unwrap() });

    let suffix = uuid::Uuid::now_v7();
    let gated_pin = format!("z-pin-{suffix}");
    let rejected = format!("a-rejected-{suffix}");
    let historical = format!("a-historical-{suffix}");
    let discovered = format!("z-discovered-{suffix}");
    let pinned_model = format!("pinned-model-{suffix}");
    let discovered_model = format!("discovered-model-{suffix}");
    for (alias, served, source, rate) in [
        (&gated_pin, &pinned_model, "config", 7),
        (&rejected, &pinned_model, "discovered", 70),
        (&historical, &discovered_model, "config", 90),
        (&discovered, &discovered_model, "discovered", 2),
    ] {
        sqlx::query(
            "INSERT INTO llm_models
                (alias, provider, credential_label, upstream_model, base_url, risk, source,
                 input_cost_per_mtok)
             VALUES ($1, 'openai', 'TEST', $2, $3, 'low', $4, $5)",
        )
        .bind(alias)
        .bind(served)
        .bind(&provider_url)
        .bind(source)
        .bind(rate)
        .execute(&pool)
        .await
        .unwrap();
    }
    let mut lock = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT alias FROM llm_models WHERE tenant_id = 'default' AND alias = $1 FOR UPDATE",
    )
    .bind(&gated_pin)
    .execute(&mut *lock)
    .await
    .unwrap();
    let discovery = json!([{
        "provider": "openrouter", "credential_label": "MISSING", "base_url": provider_url
    }])
    .to_string();
    let models = json!([
        {"alias": rejected, "provider": "openai", "base_url": provider_url, "authentication": "invalid"},
        {"alias": gated_pin, "provider": "openai", "upstream_model": pinned_model,
         "base_url": provider_url, "credential_label": "TEST"}
    ])
    .to_string();
    let client = test_client();
    let (mut gateway, base, _servers) = start_gateway(&models, Some((&database_url, &discovery)));
    let mut logs = BufReader::new(gateway.stdout.take().unwrap()).lines();
    wait_for_gateway(&mut gateway, &client, &base).await;
    assert_mcp_tool_works(&client, &base).await;
    assert_eq!(
        chat(&client, &base, &gated_pin).await.status(),
        StatusCode::OK
    );
    assert_eq!(usage_cost(&pool, &gated_pin).await, (None, 1));
    assert_eq!(
        chat(&client, &base, &discovered).await.status(),
        StatusCode::OK
    );
    assert_eq!(usage_cost(&pool, &discovered).await, (Some(2), 1));
    lock.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(line) = logs.next_line().await.unwrap() {
            if line.contains("published configured model catalog") {
                return;
            }
        }
        panic!("gateway exited before publishing the catalog");
    })
    .await
    .expect("catalog publication recovered without restarting");
    assert_eq!(
        chat(&client, &base, &gated_pin).await.status(),
        StatusCode::OK
    );
    assert_eq!(usage_cost(&pool, &gated_pin).await, (Some(7), 2));
    gateway.kill().await.unwrap();

    let (mut gateway, base, _servers) = start_gateway("[", Some((&database_url, &discovery)));
    wait_for_gateway(&mut gateway, &client, &base).await;
    assert_mcp_tool_works(&client, &base).await;
    assert_eq!(
        chat(&client, &base, &discovered).await.status(),
        StatusCode::OK
    );
    assert_eq!(usage_cost(&pool, &discovered).await, (Some(2), 2));
    gateway.kill().await.unwrap();
    backend_task.abort();

    sqlx::query("DELETE FROM llm_usage WHERE tenant_id = 'default' AND model_alias = ANY($1)")
        .bind([gated_pin.as_str(), discovered.as_str()].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM llm_models WHERE tenant_id = 'default' AND alias = ANY($1)")
        .bind(
            [
                gated_pin.as_str(),
                rejected.as_str(),
                historical.as_str(),
                discovered.as_str(),
            ]
            .as_slice(),
        )
        .execute(&pool)
        .await
        .unwrap();
}

async fn usage_cost(pool: &sqlx::PgPool, alias: &str) -> (Option<i64>, i64) {
    sqlx::query_as("SELECT total_cost::bigint, count(*) OVER() FROM llm_usage
                    WHERE tenant_id = 'default' AND model_alias = $1 ORDER BY ts DESC, id DESC LIMIT 1")
        .bind(alias)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn test_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn start_gateway(
    models: &str,
    catalog: Option<(&str, &str)>,
) -> (Child, String, tempfile::TempDir) {
    let servers = tempfile::tempdir().unwrap();
    let policies =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../waygate-authz/tests/fixtures/policies");
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reservation.local_addr().unwrap();
    let base = format!("http://{addr}");
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateway-server"));
    command
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
        .kill_on_drop(true);
    if let Some((database_url, discovery)) = catalog {
        command
            .env("GATEWAY_DATABASE_URL", database_url)
            .env("GATEWAY_LLM_DISCOVERY", discovery)
            .stdout(Stdio::piped());
    }
    drop(reservation);
    let gateway = command.spawn().expect("start the gateway");
    (gateway, base, servers)
}

async fn wait_for_gateway(gateway: &mut Child, client: &Client, base: &str) {
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
            return;
        }
        assert!(Instant::now() < deadline, "gateway did not become ready");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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
