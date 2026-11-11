use super::*;
use waygate_mcp::client_observations::{ClientObservationQuery, ClientObservationStore};

#[tokio::test]
async fn client_observations_follow_authenticated_legacy_and_changed_stateless_declarations() {
    let observations = Arc::new(ClientObservationStore::new());
    let shared = observations.clone();
    let principal = wire_principal();
    let tenant = principal.tenant.clone();
    let subject = principal.sub.clone();
    let legacy = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
        move || {
            GatewayServer::new(Arc::new(DemoCatalog::default()))
                .with_client_observations(shared.clone())
        },
        Some(principal.clone()),
    )
    .await;
    let client = connect_named_client(legacy.addr, "session-client").await;
    client.list_tools(None).await.unwrap();
    let _ = client.cancel().await;
    legacy.shutdown().await;

    let shared = observations.clone();
    let stateless = spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default(),
        move || {
            GatewayServer::new(Arc::new(DemoCatalog::default()))
                .with_client_observations(shared.clone())
        },
        Some(principal),
    )
    .await;
    let http = reqwest::Client::new();
    let url = format!("http://{}/mcp", stateless.addr);
    for name in ["first-client", "changed-client"] {
        assert!(
            stateless_post(&http, &url, 1, "tools/list", json!({}), name)
                .await
                .status()
                .is_success()
        );
    }
    let missing = http
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .json(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}
            }}}),
        )
        .send()
        .await
        .unwrap();
    assert!(missing.status().is_success());
    let missing_body = stateless_response_json(missing).await;
    assert!(missing_body.get("error").is_none(), "{missing_body}");
    let report = observations.report(tenant, &ClientObservationQuery::default());
    assert!(report.rows.iter().all(|r| r.key.subject == subject));
    assert!(report
        .rows
        .iter()
        .any(|r| r.key.protocol_generation == "legacy"
            && r.key.client_name.as_deref() == Some("session-client")
            && r.key.client_version.as_deref() == Some("test")));
    for name in ["first-client", "changed-client"] {
        assert!(report
            .rows
            .iter()
            .any(|r| r.key.protocol_generation == "2026-07-28"
                && r.key.client_name.as_deref() == Some(name)
                && r.key.client_version.as_deref() == Some("0.0.0")));
    }
    assert!(report
        .rows
        .iter()
        .any(|r| r.key.protocol_generation == "2026-07-28"
            && r.key.client_name.is_none()
            && r.key.client_version.is_none()));
    stateless.shutdown().await;
}
