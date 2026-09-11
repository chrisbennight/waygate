//! Executable proof of the portable deferred-tool host boundary.
//!
//! The host optimization may decide when a tool definition enters model
//! context, but the interoperability contract stays ordinary MCP: the tool is
//! present in `tools/list` and invoked directly by its published name.

use std::time::Instant;

use anyhow::{Context as _, Result};
use rmcp::model::{CallToolRequestParams, Tool};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::auth::resolve_bearer;
use crate::cli::{Context, HostContractArgs};
use crate::gateway::rpc;
use crate::output;
use crate::sep1888::SEARCH_TOOLS_SUFFIX;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostContractReport<'a> {
    tool: &'a str,
    protocol_version: &'static str,
    listed_as_standard_tool: bool,
    direct_call_succeeded: bool,
    elapsed_ms: u128,
}

pub async fn run(ctx: &Context, args: HostContractArgs) -> Result<()> {
    validate_tool_name(&args.tool)?;
    let arguments = parse_arguments(&args.args)?;
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect_2026(ctx, &auth).await?;
    let started = Instant::now();

    let outcome = async {
        let listed = client
            .list_tools(Default::default())
            .await
            .context("list standard MCP tools")?;
        require_listed_tool(&listed.tools, &args.tool)?;

        let params = CallToolRequestParams::new(args.tool.clone()).with_arguments(arguments);
        let result = client
            .call_tool(params)
            .await
            .with_context(|| format!("directly call {}", args.tool))?;
        if result.is_error.unwrap_or(false) {
            anyhow::bail!("direct tool call returned isError=true");
        }

        Ok::<_, anyhow::Error>(HostContractReport {
            tool: &args.tool,
            protocol_version: "2026-07-28",
            listed_as_standard_tool: true,
            direct_call_succeeded: true,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }
    .await;

    let shutdown = client
        .cancel()
        .await
        .context("shut down MCP 2026 client after host-contract probe");
    let report = match (outcome, shutdown) {
        (Ok(report), Ok(_)) => report,
        (Ok(_), Err(shutdown)) => return Err(shutdown),
        (Err(operation), Ok(_)) => return Err(operation),
        (Err(operation), Err(shutdown)) => {
            return Err(operation.context(format!("MCP client shutdown also failed: {shutdown:#}")));
        }
    };
    if ctx.json {
        output::print_json(&report)?;
    } else {
        println!("PASS  {} is listed and directly callable", report.tool);
    }
    Ok(())
}

fn validate_tool_name(name: &str) -> Result<()> {
    let qualified = name
        .split_once('.')
        .is_some_and(|(server, tool)| !server.is_empty() && !tool.is_empty());
    if !qualified {
        anyhow::bail!("--tool must be fully qualified as `<server>.<tool>`");
    }
    if name.ends_with(SEARCH_TOOLS_SUFFIX) {
        anyhow::bail!(
            "--tool cannot prove an ambiguous `<server>.searchTools` target: the MCP wire name \
             may identify either the gateway compatibility adapter or an ordinary upstream \
             collision; choose another ordinary direct tool"
        );
    }
    Ok(())
}

fn parse_arguments(raw: &str) -> Result<Map<String, Value>> {
    match serde_json::from_str(raw).context("parse --args as JSON")? {
        Value::Object(arguments) => Ok(arguments),
        other => anyhow::bail!("--args must be a JSON object, got {other}"),
    }
}

fn require_listed_tool(tools: &[Tool], name: &str) -> Result<()> {
    if tools.iter().any(|tool| tool.name.as_ref() == name) {
        return Ok(());
    }
    anyhow::bail!("`{name}` was not present in the authorization-scoped standard tools/list result")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::model::Tool;
    use serde_json::json;

    use super::{parse_arguments, require_listed_tool, validate_tool_name};

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_owned(),
            "fixture",
            Arc::new(
                json!({"type": "object"})
                    .as_object()
                    .cloned()
                    .expect("object schema"),
            ),
        )
    }

    #[test]
    fn ordinary_qualified_tool_is_the_only_accepted_probe_target() {
        assert!(validate_tool_name("modern-smoke.ping").is_ok());
        assert!(validate_tool_name("ping").is_err());
        assert!(validate_tool_name(".ping").is_err());
        assert!(validate_tool_name("modern-smoke.").is_err());
        assert!(validate_tool_name("modern-smoke.searchTools").is_err());
    }

    #[test]
    fn arguments_must_be_a_json_object() {
        assert_eq!(parse_arguments(r#"{"value": 1}"#).unwrap()["value"], 1);
        assert!(parse_arguments("[]").is_err());
        assert!(parse_arguments("not-json").is_err());
    }

    #[test]
    fn proof_requires_exact_standard_catalog_membership() {
        let tools = vec![tool("modern-smoke.ping")];
        assert!(require_listed_tool(&tools, "modern-smoke.ping").is_ok());
        assert!(require_listed_tool(&tools, "modern-smoke.missing").is_err());
    }
}
