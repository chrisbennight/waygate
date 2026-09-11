//! `tools call` — invoke a fully-qualified tool by name, and the `raw`
//! passthrough that reads a single JSON-RPC request from stdin.
//!
//! For `call`, the gateway handles `<server>.<tool>` prefix routing on its
//! side (see `dispatch_tool_call` in waygate-mcp), so the client just passes
//! the name through verbatim.

use std::io::Read;

use anyhow::{Context as _, Result};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Map, Value};

use crate::auth::resolve_bearer;
use crate::cli::{CallArgs, Context};
use crate::gateway::rpc;
use crate::output;

pub async fn run(ctx: &Context, args: CallArgs) -> Result<()> {
    let arguments = read_arguments(&args)?;
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;

    let mut params = CallToolRequestParams::new(args.name.clone());
    if let Some(obj) = arguments {
        params = params.with_arguments(obj);
    }

    let result = client
        .call_tool(params)
        .await
        .with_context(|| format!("call {}", args.name))?;

    let _ = client.cancel().await;
    render(ctx, &result)?;

    if result.is_error.unwrap_or(false) {
        // Surface a non-zero exit so shell pipelines can react to tool-side
        // failures even though the JSON-RPC call itself succeeded.
        anyhow::bail!("tool returned isError=true");
    }
    Ok(())
}

/// `raw` subcommand: read one JSON-RPC envelope from stdin, write the raw
/// response to stdout. The current implementation piggybacks on a `call_tool`
/// shape for convenience — the stdin payload must be a
/// `CallToolRequestParams` JSON object. This keeps scripting against the
/// gateway simple without pulling in a full JSON-RPC stdin harness.
pub async fn run_raw_stdio(ctx: &Context) -> Result<()> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("read raw request from stdin")?;
    let params: CallToolRequestParams =
        serde_json::from_str(&buf).context("parse stdin as CallToolRequestParams JSON")?;

    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;
    let result = client.call_tool(params).await.context("raw call_tool")?;
    let _ = client.cancel().await;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn read_arguments(args: &CallArgs) -> Result<Option<Map<String, Value>>> {
    let raw = if args.stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("read --stdin arguments")?;
        Some(s)
    } else {
        args.args.clone()
    };
    let Some(text) = raw else {
        return Ok(None);
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed: Value = serde_json::from_str(trimmed)
        .with_context(|| format!("parse tool arguments as JSON: `{trimmed}`"))?;
    match parsed {
        Value::Object(m) => Ok(Some(m)),
        other => anyhow::bail!("tool arguments must be a JSON object, got {other}"),
    }
}

fn render(ctx: &Context, result: &CallToolResult) -> Result<()> {
    if ctx.json {
        let serialized = serde_json::to_value(result)?;
        println!("{}", serde_json::to_string_pretty(&serialized)?);
        return Ok(());
    }
    if let Some(sc) = &result.structured_content {
        println!("{}", serde_json::to_string_pretty(sc)?);
        return Ok(());
    }
    let mut printed_any = false;
    for content in &result.content {
        if let Some(text) = content.as_text() {
            println!("{}", text.text);
            printed_any = true;
        }
    }
    if !printed_any {
        // Fall back to full JSON — no text, no structured content, but the
        // tool still returned something (e.g. an image or embedded
        // resource).
        output::print_json(&result)?;
    }
    Ok(())
}
