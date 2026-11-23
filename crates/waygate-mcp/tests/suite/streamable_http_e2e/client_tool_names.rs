//! Clients selected for underscore tool names see gateway built-ins with `_`
//! in place of `.` and may call them by either form. Upstream tools keep
//! their dotted names, and every other client is unchanged.
use super::*;

const SELECTED: &str = "underscore-client";

/// A built-in namespace with one tool that lists and answers without
/// authentication, so the test exercises only naming.
struct NamingBuiltin {
    namespace: &'static str,
    tool: &'static str,
}

#[async_trait]
impl waygate_mcp::BuiltinTools for NamingBuiltin {
    fn namespace(&self) -> &str {
        self.namespace
    }

    fn catalog(&self) -> waygate_mcp::BuiltinCatalog {
        let schema = Arc::new(json!({"type": "object"}).as_object().unwrap().clone());
        waygate_mcp::BuiltinCatalog::from_descriptor(
            self.describe(),
            vec![Tool::new(
                format!("{}.{}", self.namespace, self.tool),
                "naming stub tool",
                schema,
            )],
        )
    }

    fn describe(&self) -> waygate_mcp::BuiltinSurfaceDescriptor {
        waygate_mcp::BuiltinSurfaceDescriptor {
            namespace: self.namespace.into(),
            required_scope: "mcp:invoke".into(),
            summary: "naming stub".into(),
            tools: vec![waygate_mcp::BuiltinToolDescriptor {
                name: self.tool.into(),
                description: "naming stub tool".into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
            }],
        }
    }

    async fn list_tools(&self, _principal: Option<&waygate_oidc::Principal>) -> Vec<Tool> {
        self.catalog().definitions()
    }

    async fn call(
        &self,
        tool: &str,
        _arguments: Option<rmcp::model::JsonObject>,
        _principal: Option<&waygate_oidc::Principal>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "builtin {tool}"
        ))]))
    }
}

fn listed_names(tools: &[Value]) -> Vec<String> {
    tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

fn result_text(result: &Value) -> Option<&str> {
    result["result"]["content"][0]["text"].as_str()
}

#[tokio::test]
async fn selected_clients_see_and_call_underscore_builtins_while_others_are_unchanged() {
    let catalog: SharedCatalog = Arc::new(DemoCatalog::default());
    let server = spawn_gateway_custom(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_owned()]),
        move || {
            GatewayServer::new(catalog.clone())
                .with_builtin_tools(Arc::new(NamingBuiltin {
                    namespace: "codemode",
                    tool: "search",
                }))
                .with_builtin_tools(Arc::new(NamingBuiltin {
                    namespace: "codemode0",
                    tool: "ping",
                }))
                .with_underscore_tool_name_clients(vec![SELECTED.to_owned()])
        },
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let http = reqwest::Client::new();

    for (client, selected) in [(SELECTED, true), ("standard-client", false)] {
        // Lists arrive sorted by the names the client receives: renaming
        // moves `codemode0_ping` ahead of `codemode_search`.
        let expected_names: Vec<String> = if selected {
            ["codemode0_ping", "codemode_search", "demo.echo"]
        } else {
            ["codemode.search", "codemode0.ping", "demo.echo"]
        }
        .map(str::to_owned)
        .to_vec();

        let legacy = connect_named_client(server.addr, client).await;
        let legacy_names: Vec<String> = legacy
            .list_tools(None)
            .await
            .unwrap()
            .tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(legacy_names, expected_names, "{client} legacy list");
        let stateless = stateless_response_json(
            stateless_post(&http, &url, 1, "tools/list", json!({}), client).await,
        )
        .await;
        assert_eq!(
            listed_names(stateless["result"]["tools"].as_array().unwrap()),
            expected_names,
            "{client} stateless list"
        );

        assert_eq!(
            legacy
                .peer_info()
                .unwrap()
                .instructions
                .as_deref()
                .unwrap()
                .contains(waygate_mcp::client_tool_names::GUIDANCE),
            selected,
            "{client} legacy instructions"
        );
        let discovered = stateless_response_json(
            stateless_post(&http, &url, 2, "server/discover", json!({}), client).await,
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

        // Dotted names keep working for every client; the underscore form of
        // a built-in works only for a selected client.
        for (name, answer, accepted) in [
            ("codemode.search", "builtin search", true),
            ("codemode_search", "builtin search", selected),
            ("demo.echo", "called demo.echo", true),
        ] {
            let called = legacy.call_tool(CallToolRequestParams::new(name)).await;
            let called_ok = called.as_ref().is_ok_and(|result| {
                result.is_error != Some(true) && result.content[0].as_text().unwrap().text == answer
            });
            assert_eq!(called_ok, accepted, "{client} legacy {name}: {called:?}");

            let called = stateless_response_json(
                stateless_post(
                    &http,
                    &url,
                    3,
                    "tools/call",
                    json!({"name": name, "arguments": {}}),
                    client,
                )
                .await,
            )
            .await;
            assert_eq!(
                result_text(&called) == Some(answer),
                accepted,
                "{client} stateless {name}: {called}"
            );
        }

        if selected {
            // Upstream tools have no underscore form, and an unknown
            // underscore name answers like an unknown dotted name, naming
            // only what the client sent.
            for name in ["demo_echo", "codemode_missing"] {
                let missing = stateless_response_json(
                    stateless_post(
                        &http,
                        &url,
                        4,
                        "tools/call",
                        json!({"name": name, "arguments": {}}),
                        client,
                    )
                    .await,
                )
                .await;
                assert_eq!(
                    missing["error"]["data"]["error"], "tool_unavailable",
                    "{name}: {missing}"
                );
                assert_eq!(missing["error"]["data"]["tool"], name, "{missing}");
            }
        }
        let _ = legacy.cancel().await;
    }
    server.shutdown().await;
}
