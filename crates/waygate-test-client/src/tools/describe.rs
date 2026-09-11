//! `tools describe` — SEP #1888 `mode=types` invocation for a single
//! operation. Takes a fully-qualified `<server>.<tool>` name, routes the
//! call to `<server>.searchTools`, and renders the returned JSON Schema.

use anyhow::{Context as _, Result};
use rmcp::model::CallToolRequestParams;
use serde_json::{Map, Value};

use crate::auth::resolve_bearer;
use crate::cli::{Context, DescribeArgs};
use crate::gateway::rpc;
use crate::output;
use crate::sep1888::{Mode, SearchToolsRequest, TypesResponse, SEARCH_TOOLS_SUFFIX};

pub async fn run(ctx: &Context, args: DescribeArgs) -> Result<()> {
    let (server, _tool) = split_qualified(&args.name)?;
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;

    let tool_name = format!("{server}{SEARCH_TOOLS_SUFFIX}");
    let req = SearchToolsRequest {
        mode: Mode::Types,
        filters: None,
        name: Some(args.name.clone()),
        cursor: None,
        limit: None,
    };
    let params = CallToolRequestParams::new(tool_name.clone()).with_arguments(to_object(&req)?);

    let result = client
        .call_tool(params)
        .await
        .with_context(|| format!("call {tool_name} mode=types for {}", args.name))?;
    if result.is_error.unwrap_or(false) {
        anyhow::bail!(
            "{tool_name} returned isError=true: {}",
            render_fallback(&result)
        );
    }

    let parsed: TypesResponse = if let Some(sc) = &result.structured_content {
        serde_json::from_value(sc.clone())
            .with_context(|| format!("parse {tool_name} structuredContent as TypesResponse"))?
    } else if let Some(text) = first_text(&result) {
        serde_json::from_str(&text)
            .with_context(|| format!("parse {tool_name} text content as TypesResponse"))?
    } else {
        anyhow::bail!("{tool_name} returned neither structuredContent nor text content");
    };

    if ctx.json {
        output::print_json(&parsed)?;
    } else {
        output::print_type(&parsed);
    }
    let _ = client.cancel().await;
    Ok(())
}

fn split_qualified(name: &str) -> Result<(&str, &str)> {
    match name.split_once('.') {
        Some((server, rest)) if !server.is_empty() && !rest.is_empty() => Ok((server, rest)),
        _ => anyhow::bail!("expected `<server>.<tool>`, got `{name}`"),
    }
}

fn to_object(req: &SearchToolsRequest) -> Result<Map<String, Value>> {
    match serde_json::to_value(req)? {
        Value::Object(m) => Ok(m),
        other => anyhow::bail!("SearchToolsRequest did not serialize as a JSON object: {other:?}"),
    }
}

fn first_text(result: &rmcp::model::CallToolResult) -> Option<String> {
    for c in &result.content {
        if let Some(t) = c.as_text() {
            return Some(t.text.clone());
        }
    }
    None
}

fn render_fallback(result: &rmcp::model::CallToolResult) -> String {
    if let Some(text) = first_text(result) {
        return text;
    }
    if let Some(sc) = &result.structured_content {
        return sc.to_string();
    }
    "<no content>".to_owned()
}
