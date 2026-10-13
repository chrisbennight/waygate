//! Emit a deterministic standard MCP `tools/list` capture from the real
//! gateway projection path for the prompt-surface CI ratchet.
//!
//! With no arguments it projects a small built-in representative catalog as
//! the full list. `--catalog <file>` projects a synthetic catalog file
//! instead, shaped `{"servers": [{"name": ..., "tools": [...]}]}`, and
//! `--projection progressive` emits what a new legacy session lists before it
//! discloses any tool, rather than the full list.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ErrorData as McpError, ListToolsResult, Tool, ToolAnnotations};
use serde_json::{json, Map, Value};
use waygate_mcp::catalog::{InvocationContractIdentity, SharedCatalog, UpstreamCatalog};
use waygate_mcp::GatewayServer;
use waygate_oidc::Principal;

struct RepresentativeCatalog {
    servers: Vec<(String, Vec<Tool>)>,
}

#[async_trait]
impl UpstreamCatalog for RepresentativeCatalog {
    async fn list_servers(&self) -> Vec<String> {
        self.servers.iter().map(|(name, _)| name.clone()).collect()
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        self.servers
            .iter()
            .find(|(name, _)| name == server)
            .map(|(_, tools)| tools.clone())
            .ok_or_else(|| McpError::invalid_params(format!("unknown server {server}"), None))
    }

    async fn call_tool(
        &self,
        _server: &str,
        _tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        unreachable!("the context projection producer never dispatches a tool")
    }
}

fn object(value: Value) -> Arc<Map<String, Value>> {
    Arc::new(value.as_object().cloned().expect("schema is an object"))
}

fn representative_catalog() -> SharedCatalog {
    let send_message = Tool::new(
        "send_message",
        "Send a message to a recipient.",
        object(json!({
            "type": "object",
            "properties": {
                "recipient": {
                    "type": "string",
                    "description": "Recipient identifier."
                },
                "message": {
                    "type": "string",
                    "description": "Message body to send."
                }
            },
            "required": ["recipient", "message"]
        })),
    )
    .with_title("Send message")
    .with_raw_output_schema(object(json!({
        "type": "object",
        "properties": {"messageId": {"type": "string"}},
        "required": ["messageId"]
    })))
    .annotate(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(false)
            .idempotent(false)
            .open_world(true),
    );
    let list_contacts = Tool::new(
        "list_contacts",
        "List messaging contacts visible to the caller.",
        object(json!({
            "type": "object",
            "properties": {
                "cursor": {
                    "type": "string",
                    "description": "Opaque continuation cursor."
                }
            }
        })),
    )
    .with_title("List contacts")
    .annotate(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    );
    let query_range = Tool::new(
        "query_range",
        "Run a read-only metrics query over a bounded time range.",
        object(json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Metrics query expression."
                },
                "start": {
                    "type": "string",
                    "description": "Inclusive RFC 3339 start time."
                },
                "end": {
                    "type": "string",
                    "description": "Exclusive RFC 3339 end time."
                }
            },
            "required": ["query", "start", "end"]
        })),
    )
    .with_title("Query time range")
    .annotate(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(true),
    );

    Arc::new(RepresentativeCatalog {
        servers: vec![
            ("demo-m".to_owned(), vec![send_message, list_contacts]),
            ("demo-o".to_owned(), vec![query_range]),
        ],
    })
}

#[derive(serde::Deserialize)]
struct CatalogFile {
    servers: Vec<CatalogServer>,
}

#[derive(serde::Deserialize)]
struct CatalogServer {
    name: String,
    tools: Vec<Tool>,
}

fn catalog_file(path: &PathBuf) -> Result<SharedCatalog, Box<dyn std::error::Error>> {
    let file: CatalogFile = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(Arc::new(RepresentativeCatalog {
        servers: file
            .servers
            .into_iter()
            .map(|server| (server.name, server.tools))
            .collect(),
    }))
}

struct Options {
    catalog: Option<PathBuf>,
    progressive: bool,
}

fn options() -> Result<Options, Box<dyn std::error::Error>> {
    let mut options = Options {
        catalog: None,
        progressive: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--catalog" => {
                options.catalog = Some(args.next().ok_or("--catalog requires a file path")?.into());
            }
            "--projection" => {
                options.progressive = match args.next().as_deref() {
                    Some("full") => false,
                    Some("progressive") => true,
                    _ => return Err("--projection must be full or progressive".into()),
                };
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    Ok(options)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = options()?;
    let catalog = match &options.catalog {
        Some(path) => catalog_file(path)?,
        None => representative_catalog(),
    };
    let server = GatewayServer::new(catalog).with_eager_tools_list(!options.progressive);
    let result = ListToolsResult::with_all_items(server.list_visible_tools(None).await);
    let capture = json!({"jsonrpc": "2.0", "id": 7, "result": result});
    serde_json::to_writer_pretty(std::io::stdout().lock(), &capture)?;
    println!();
    Ok(())
}
