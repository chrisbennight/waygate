//! Disposable MCP client qualification, using the workspace SDK and validator.

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use rmcp::{
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
    ErrorData, RoleServer, ServerHandler, ServiceExt,
};
use serde_json::Value;
use waygate_mcp::client_schema::adapt_tool;

#[derive(Clone)]
struct Fixture {
    presented: Arc<Vec<Tool>>,
    validators: Arc<HashMap<String, jsonschema::Validator>>,
    legacy: bool,
}

fn observe(
    ctx: &RequestContext<RoleServer>,
    method: &str,
    tool: Option<&str>,
    accepted: Option<bool>,
) {
    let client = ctx.client_info();
    let bounded = |value: &str| value.chars().take(128).collect::<String>();
    tracing::info!(target: "schema_fixture", method, tool, accepted,
        protocol = ctx.protocol_version().as_ref().map(ProtocolVersion::as_str),
        client_name = client.as_ref().map(|info| bounded(&info.name)),
        client_version = client.as_ref().map(|info| bounded(&info.version)),
        "synthetic client observation");
}

impl ServerHandler for Fixture {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            rmcp::model::Implementation::new("schema-fixture", env!("CARGO_PKG_VERSION")),
        )
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        if self.legacy {
            Cow::Owned(vec![ProtocolVersion::V_2025_11_25])
        } else {
            Cow::Owned(vec![
                ProtocolVersion::V_2026_07_28,
                ProtocolVersion::V_2025_11_25,
            ])
        }
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        observe(&ctx, "tools/list", None, None);
        Ok(ListToolsResult::with_all_items((*self.presented).clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let validator = self
            .validators
            .get(request.name.as_ref())
            .ok_or_else(|| ErrorData::invalid_params("Unknown synthetic fixture tool", None))?;
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let accepted = validator.is_valid(&arguments);
        observe(&ctx, "tools/call", Some(&request.name), Some(accepted));
        if !accepted {
            return Err(ErrorData::invalid_params(
                "Arguments failed the full synthetic schema",
                None,
            ));
        }
        Ok(CallToolResult::success(vec![ContentBlock::text("accepted")]).into())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut http = false;
    let mut adapt = false;
    let mut legacy = false;
    let mut presentation = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--http" => http = true,
            "--adapt" => adapt = true,
            "--legacy" => legacy = true,
            "--tools" => {
                presentation = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--tools requires a presentation file"))?,
                )
            }
            _ => anyhow::bail!("Use --http, --legacy, --adapt, or --tools <presentation file>"),
        }
    }
    // Stdio qualification deliberately negotiates the legacy generation. It
    // never represents a modern protocol through a legacy initialize exchange.
    legacy |= !http;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .json()
        .with_max_level(tracing::Level::INFO)
        .init();
    let original: Vec<Tool> =
        serde_json::from_str(include_str!("../tests/fixtures/client-schema-tools.json"))?;
    let validators = original
        .iter()
        .map(|tool| {
            jsonschema::validator_for(&Value::Object((*tool.input_schema).clone()))
                .map(|validator| (tool.name.to_string(), validator))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    let mut presented: Vec<Tool> = match presentation {
        Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
        None => original,
    };
    anyhow::ensure!(
        presented
            .iter()
            .all(|tool| validators.contains_key(tool.name.as_ref())),
        "Presentation contains a tool outside the authoritative fixture"
    );
    for tool in &mut presented {
        tool.annotations = Some(serde_json::from_value(serde_json::json!({
            "readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false
        }))?);
    }
    if adapt {
        for tool in &mut presented {
            adapt_tool(tool);
        }
    }
    let fixture = Fixture {
        presented: Arc::new(presented),
        validators: Arc::new(validators),
        legacy,
    };
    if !http {
        fixture
            .serve(rmcp::transport::stdio())
            .await?
            .waiting()
            .await?;
        return Ok(());
    }
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    let service = StreamableHttpService::new(
        move || Ok(fixture.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(legacy),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    println!(
        "{}",
        serde_json::json!({"url":format!("http://{}/mcp",listener.local_addr()?)})
    );
    axum::serve(listener, axum::Router::new().nest_service("/mcp", service))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
