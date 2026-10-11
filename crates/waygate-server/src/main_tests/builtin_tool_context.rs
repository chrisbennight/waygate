//! Context-cost capture of the gateway's own built-in tool surface.
//!
//! Builds the complete built-in `tools/list` through the real `GatewayServer`
//! projection, with every reserved namespace attached and no upstream
//! servers, and compares it with the checked-in capture that CI measures
//! against `scripts/fixtures/tool-context/builtin-budget.json`. A change to
//! any built-in declaration therefore fails here until the capture is
//! regenerated, and then fails the budget step if it grows past the budget.
//!
//! Regenerate the capture after an intentional change:
//!
//! ```sh
//! WAYGATE_UPDATE_TOOL_CONTEXT_CAPTURE=1 cargo test -p waygate-server --bin gateway-server \
//!   builtin_tool_context
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ErrorData as McpError, JsonObject, ListToolsResult, Tool};
use serde_json::{json, Map, Value};
use waygate_mcp::catalog::{InvocationContractIdentity, UpstreamCatalog};
use waygate_mcp::{BuiltinCatalog, BuiltinTools, GatewayServer};
use waygate_oidc::Principal;

const CAPTURE: &str = "scripts/fixtures/tool-context/builtin-tools-list.json";
const UPDATE_ENV: &str = "WAYGATE_UPDATE_TOOL_CONTEXT_CAPTURE";

/// No upstream servers: the capture measures only the gateway's own tools.
struct NoUpstreams;

#[async_trait]
impl UpstreamCatalog for NoUpstreams {
    async fn list_servers(&self) -> Vec<String> {
        Vec::new()
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        Err(McpError::invalid_params(
            format!("unknown server {server}"),
            None,
        ))
    }

    async fn call_tool(
        &self,
        _server: &str,
        _tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        unreachable!("the context capture never dispatches a tool")
    }
}

/// Serves one namespace's canonical catalog without its runtime state, so the
/// capture reflects exactly the definitions a fully authorized caller sees.
struct CatalogOnly(BuiltinCatalog);

#[async_trait]
impl BuiltinTools for CatalogOnly {
    fn namespace(&self) -> &str {
        &self.0.namespace
    }

    fn catalog(&self) -> BuiltinCatalog {
        self.0.clone()
    }

    async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
        self.0.definitions()
    }

    async fn call(
        &self,
        _tool: &str,
        _arguments: Option<JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        unreachable!("the context capture never dispatches a tool")
    }
}

/// Every reserved built-in namespace the gateway can serve.
fn builtin_catalogs() -> Vec<BuiltinCatalog> {
    vec![
        crate::mcp_builtin::surface_catalog(),
        crate::mcp_codemode::surface_catalog(),
        crate::mcp_control::surface_catalog(),
        crate::mcp_discovery::surface_catalog(),
        crate::mcp_files::surface_catalog(),
        crate::mcp_observe::surface_catalog(),
        waygate_mcp::server::skill_tools::surface_catalog(),
    ]
}

async fn builtin_tools_list() -> Value {
    let mut server = GatewayServer::new(Arc::new(NoUpstreams)).with_eager_tools_list(true);
    for catalog in builtin_catalogs() {
        server = server.with_builtin_tools(Arc::new(CatalogOnly(catalog)));
    }
    let mut tools = server.list_visible_tools(None).await;
    tools.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let result = ListToolsResult::with_all_items(tools);
    json!({"jsonrpc": "2.0", "id": 7, "result": result})
}

fn capture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(CAPTURE)
}

#[tokio::test]
async fn builtin_tool_capture_covers_every_namespace() {
    let capture = builtin_tools_list().await;
    let tools = capture["result"]["tools"].as_array().expect("tools array");
    for catalog in builtin_catalogs() {
        let prefix = format!("{}.", catalog.namespace);
        let listed = tools
            .iter()
            .filter(|tool| {
                tool["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with(&prefix))
            })
            .count();
        assert_eq!(
            listed,
            catalog.tools.len(),
            "every {} tool appears in the capture",
            catalog.namespace
        );
    }
}

#[tokio::test]
async fn builtin_tool_capture_is_current() {
    let mut rendered =
        serde_json::to_string_pretty(&builtin_tools_list().await).expect("capture serializes");
    rendered.push('\n');
    let path = capture_path();
    if std::env::var_os(UPDATE_ENV).is_some() {
        std::fs::write(&path, &rendered).expect("write capture");
        return;
    }
    let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        checked_in == rendered,
        "{CAPTURE} is stale; rerun with {UPDATE_ENV}=1 and review the budget report"
    );
}
