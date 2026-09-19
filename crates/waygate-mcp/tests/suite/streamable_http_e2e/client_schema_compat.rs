//! Client registration changes do not change the invoked schema contract.
use super::*;

fn conditional_schema() -> Map<String, Value> {
    serde_json::from_str::<Value>(include_str!("../../fixtures/client-schema-tools.json")).unwrap()
        [2]["inputSchema"]
        .as_object()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn selected_clients_register_simplified_tools_but_calls_keep_full_validation() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        input_schema: Some(conditional_schema()),
        dispatches: Some(dispatches.clone()),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_eager_tools_list(true)
                .with_root_composition_clients(vec!["restricted-client".to_owned()])
        },
    )
    .await;
    let legacy = connect_named_client(server.addr, "Restricted-Client").await;
    let listed = legacy.list_tools(None).await.unwrap();
    let presented = listed.tools.iter().find(|t| t.name == "demo.echo").unwrap();
    assert!(!presented.input_schema.contains_key("allOf"));
    assert!(presented
        .description
        .as_deref()
        .unwrap()
        .contains("16000000"));
    assert!(legacy
        .peer_info()
        .unwrap()
        .instructions
        .as_deref()
        .unwrap()
        .contains("Root-composition compatibility"));

    // Type discovery deliberately remains the authoritative schema as data.
    let described = legacy
        .call_tool(
            CallToolRequestParams::new("demo.searchTools").with_arguments(
                json!({"mode":"types","name":"demo.echo#input"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    assert!(described.structured_content.as_ref().unwrap()["jsonSchema"]["allOf"].is_array());

    for (args, valid) in [
        (json!({"mode":"large","size":1500000000}), true),
        (json!({"mode":"small","size":1000000}), true),
        (json!({"mode":"small","size":1500000000}), false),
    ] {
        let before = dispatches.load(Ordering::SeqCst);
        let called = legacy
            .call_tool(
                CallToolRequestParams::new("demo.echo")
                    .with_arguments(args.as_object().unwrap().clone()),
            )
            .await;
        assert_eq!(
            called
                .as_ref()
                .is_ok_and(|result| result.is_error != Some(true)),
            valid
        );
        assert_eq!(
            dispatches.load(Ordering::SeqCst) - before,
            usize::from(valid)
        );
    }
    let client = reqwest::Client::new();
    let url = format!("http://{}/mcp", server.addr);
    for (name, adapted) in [("restricted-client", true), ("standard-client", false)] {
        let listed = stateless_response_json(
            stateless_post(&client, &url, 1, "tools/list", json!({}), name).await,
        )
        .await;
        let tool = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "demo.echo")
            .unwrap();
        assert_eq!(tool["inputSchema"].get("allOf").is_none(), adapted);
        let discovered = stateless_response_json(
            stateless_post(&client, &url, 2, "server/discover", json!({}), name).await,
        )
        .await;
        assert_eq!(
            discovered
                .to_string()
                .contains("Root-composition compatibility"),
            adapted
        );
    }
    let invalid = stateless_response_json(
        stateless_post(
            &client,
            &url,
            3,
            "tools/call",
            json!({"name":"demo.echo","arguments":{"mode":"small","size":1500000000}}),
            "restricted-client",
        )
        .await,
    )
    .await;
    assert!(invalid.get("error").is_some() || invalid["result"]["isError"] == true);
    assert_eq!(dispatches.load(Ordering::SeqCst), 2);
    let _ = legacy.cancel().await;
    server.shutdown().await;
}

#[tokio::test]
async fn pagination_rejects_switching_between_canonical_and_adapted_views() {
    let names = Arc::new(tokio::sync::RwLock::new(
        (0..60).map(|i| format!("tool-{i:03}")).collect(),
    ));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        input_schema: Some(conditional_schema()),
        tool_names: Some(names),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_root_composition_clients(vec!["restricted-client".to_owned()])
        },
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();
    let first = stateless_response_json(
        stateless_post(
            &client,
            &url,
            1,
            "tools/list",
            json!({}),
            "restricted-client",
        )
        .await,
    )
    .await;
    let cursor = first["result"]["nextCursor"].as_str().unwrap();
    let second = stateless_response_json(
        stateless_post(
            &client,
            &url,
            2,
            "tools/list",
            json!({"cursor":cursor}),
            "restricted-client",
        )
        .await,
    )
    .await;
    assert!(second["result"]["tools"].is_array());
    let changed = stateless_response_json(
        stateless_post(
            &client,
            &url,
            3,
            "tools/list",
            json!({"cursor":cursor}),
            "standard-client",
        )
        .await,
    )
    .await;
    assert_eq!(changed["error"]["code"], -32602);
    server.shutdown().await;
}
