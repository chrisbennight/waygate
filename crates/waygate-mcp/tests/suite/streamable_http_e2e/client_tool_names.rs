//! Clients selected for underscore tool names see `_` in place of `.` and
//! may call with either form; every other client is unchanged.
use super::*;

const SELECTED: &str = "underscore-client";

fn tool_names(tools: &[Value]) -> Vec<String> {
    let mut names: Vec<String> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn selected_clients_see_and_call_underscore_names_while_others_are_unchanged() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let catalog: SharedCatalog = Arc::new(DemoCatalog {
        dispatches: Some(dispatches.clone()),
        tool_names: Some(Arc::new(tokio::sync::RwLock::new(vec![
            "echo".to_owned(),
            "files.read".to_owned(),
        ]))),
        ..DemoCatalog::default()
    });
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_underscore_tool_name_clients(vec![SELECTED.to_owned()])
        },
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let http = reqwest::Client::new();

    for (client, selected) in [(SELECTED, true), ("standard-client", false)] {
        let legacy = connect_named_client(server.addr, client).await;
        let listed = legacy.list_tools(None).await.unwrap();
        let legacy_names: Vec<String> = listed.tools.iter().map(|t| t.name.to_string()).collect();
        let stateless = stateless_response_json(
            stateless_post(&http, &url, 1, "tools/list", json!({}), client).await,
        )
        .await;
        let stateless_names = tool_names(stateless["result"]["tools"].as_array().unwrap());
        for names in [&legacy_names, &stateless_names] {
            assert_eq!(
                names.iter().any(|name| name == "demo_echo"),
                selected,
                "{client}: {names:?}"
            );
            assert_eq!(
                names.iter().any(|name| name == "demo_files_read"),
                selected,
                "{client}: {names:?}"
            );
            assert_eq!(
                names.iter().any(|name| name == "demo.echo"),
                !selected,
                "{client}: {names:?}"
            );
            assert_eq!(
                names.iter().any(|name| name.contains('.')),
                !selected,
                "{client}: {names:?}"
            );
        }
        assert_eq!(
            legacy
                .peer_info()
                .unwrap()
                .instructions
                .as_deref()
                .unwrap()
                .contains(waygate_mcp::client_tool_names::GUIDANCE),
            selected,
            "{client} instructions"
        );
        let discovered = stateless_response_json(
            stateless_post(&http, &url, 3, "server/discover", json!({}), client).await,
        )
        .await;
        assert_eq!(
            discovered["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains(waygate_mcp::client_tool_names::GUIDANCE),
            selected,
            "{client} stateless instructions"
        );

        // Dotted names keep working for every client. Underscore names reach
        // the real tool only for a selected client.
        for (name, real, accepted) in [
            ("demo.echo", "demo.echo", true),
            ("demo_echo", "demo.echo", selected),
            ("demo_files_read", "demo.files.read", selected),
        ] {
            let before = dispatches.load(Ordering::SeqCst);
            let called = legacy.call_tool(CallToolRequestParams::new(name)).await;
            let called_ok = called.as_ref().is_ok_and(|result| {
                result.is_error != Some(true)
                    && result.content[0].as_text().unwrap().text == format!("called {real}")
            });
            assert_eq!(called_ok, accepted, "{client} legacy {name}: {called:?}");
            assert_eq!(
                dispatches.load(Ordering::SeqCst) - before,
                usize::from(accepted)
            );

            let before = dispatches.load(Ordering::SeqCst);
            let called = stateless_response_json(
                stateless_post(
                    &http,
                    &url,
                    2,
                    "tools/call",
                    json!({"name": name, "arguments": {}}),
                    client,
                )
                .await,
            )
            .await;
            let called_ok = called.get("error").is_none()
                && called["result"]["isError"] != true
                && called["result"]["content"][0]["text"] == format!("called {real}");
            assert_eq!(called_ok, accepted, "{client} stateless {name}: {called}");
            assert_eq!(
                dispatches.load(Ordering::SeqCst) - before,
                usize::from(accepted)
            );
        }
        if selected {
            // An unknown underscore name answers exactly as an unknown dotted
            // name does, naming only what the client sent.
            let missing = stateless_response_json(
                stateless_post(
                    &http,
                    &url,
                    4,
                    "tools/call",
                    json!({"name": "demo_missing", "arguments": {}}),
                    client,
                )
                .await,
            )
            .await;
            assert_eq!(
                missing["error"]["data"]["error"], "tool_unavailable",
                "{missing}"
            );
            assert_eq!(
                missing["error"]["data"]["tool"], "demo_missing",
                "{missing}"
            );
        }
        let _ = legacy.cancel().await;
    }
    server.shutdown().await;
}
