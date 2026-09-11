//! `tools search` — SEP #1888 `<server>.searchTools` invocation.
//!
//! Resolves the set of upstream servers that advertise a `.searchTools`
//! meta-tool, builds a `SearchToolsRequest`, and paginates when `--all` is
//! set. Results are rendered per-server so it's clear which upstream owned
//! each row.

use anyhow::{Context as _, Result};
use rmcp::model::CallToolRequestParams;
use serde_json::{Map, Value};

use crate::auth::resolve_bearer;
use crate::cli::{Context, SearchArgs};
use crate::gateway::rpc::{self, Client};
use crate::output;
use crate::sep1888::{
    server_from_search_tool, Mode, OperationFilters, OperationsResponse, RiskTier,
    SearchToolsRequest, SEARCH_TOOLS_SUFFIX,
};

pub async fn run(ctx: &Context, args: SearchArgs) -> Result<()> {
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;

    let servers = match args.server.as_deref() {
        Some(s) => vec![s.to_owned()],
        None => discover_search_servers(&client).await?,
    };

    if servers.is_empty() {
        if ctx.json {
            output::print_json(&Value::Array(vec![]))?;
        } else {
            println!("(no upstream advertises a {SEARCH_TOOLS_SUFFIX} meta-tool)");
        }
        let _ = client.cancel().await;
        return Ok(());
    }

    let risk_level = match args.risk_level.as_deref() {
        Some(s) => Some(
            RiskTier::parse(s)
                .with_context(|| format!("--risk-level `{s}` is not low|medium|high"))?,
        ),
        None => None,
    };

    let filters = build_filters(&args, risk_level);

    let mut per_server: Vec<(String, OperationsResponse)> = Vec::with_capacity(servers.len());
    for server in servers {
        let tool_name = format!("{server}{SEARCH_TOOLS_SUFFIX}");
        let merged = fetch_operations(&client, &tool_name, &args, filters.clone()).await?;
        per_server.push((server, merged));
    }

    if ctx.json {
        let flat: Vec<Value> = per_server
            .iter()
            .map(|(server, resp)| {
                serde_json::json!({
                    "server": server,
                    "operations": resp.operations,
                    "nextCursor": resp.next_cursor,
                })
            })
            .collect();
        output::print_json(&flat)?;
    } else {
        for (i, (server, resp)) in per_server.iter().enumerate() {
            if i > 0 {
                println!();
            }
            println!("== {server} ==");
            output::print_operations(resp);
        }
    }

    let _ = client.cancel().await;
    Ok(())
}

async fn discover_search_servers(client: &Client) -> Result<Vec<String>> {
    let listed = client
        .list_tools(Default::default())
        .await
        .context("listTools to discover searchTools upstreams")?;
    let mut out = Vec::new();
    for tool in listed.tools {
        if let Some(server) = server_from_search_tool(tool.name.as_ref()) {
            out.push(server.to_owned());
        }
    }
    Ok(out)
}

fn build_filters(args: &SearchArgs, risk_level: Option<RiskTier>) -> Option<OperationFilters> {
    if args.resource_type.is_none()
        && args.action.is_none()
        && args.scope.is_none()
        && risk_level.is_none()
        && args.query.is_none()
    {
        return None;
    }
    Some(OperationFilters {
        resource_type: args.resource_type.clone(),
        action: args.action.clone(),
        scope: args.scope.clone(),
        risk_level,
        query: args.query.clone(),
    })
}

async fn fetch_operations(
    client: &Client,
    tool_name: &str,
    args: &SearchArgs,
    filters: Option<OperationFilters>,
) -> Result<OperationsResponse> {
    let mut cursor = args.cursor.clone();
    let mut merged = OperationsResponse {
        operations: Vec::new(),
        next_cursor: None,
    };

    loop {
        let req = SearchToolsRequest {
            mode: Mode::Operations,
            filters: filters.clone(),
            name: None,
            cursor: cursor.clone(),
            limit: args.limit,
        };
        let params = CallToolRequestParams::new(tool_name.to_owned())
            .with_arguments(request_as_object(&req)?);
        let call_result = client
            .call_tool(params)
            .await
            .with_context(|| format!("call {tool_name}"))?;

        if call_result.is_error.unwrap_or(false) {
            anyhow::bail!(
                "{tool_name} returned isError=true: {}",
                render_fallback(&call_result)
            );
        }

        let resp = parse_operations(&call_result, tool_name)?;
        merged.operations.extend(resp.operations);

        if args.all {
            match resp.next_cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => {
                    merged.next_cursor = None;
                    break;
                }
            }
        } else {
            merged.next_cursor = resp.next_cursor;
            break;
        }
    }

    Ok(merged)
}

fn request_as_object(req: &SearchToolsRequest) -> Result<Map<String, Value>> {
    match serde_json::to_value(req)? {
        Value::Object(m) => Ok(m),
        other => anyhow::bail!("SearchToolsRequest did not serialize as a JSON object: {other:?}"),
    }
}

fn parse_operations(
    result: &rmcp::model::CallToolResult,
    tool_name: &str,
) -> Result<OperationsResponse> {
    if let Some(sc) = &result.structured_content {
        return serde_json::from_value(sc.clone())
            .with_context(|| format!("parse {tool_name} structuredContent as OperationsResponse"));
    }
    // Fall back to the first text block — gateways that don't populate
    // structuredContent should still be parseable.
    if let Some(text) = first_text(result) {
        return serde_json::from_str(&text)
            .with_context(|| format!("parse {tool_name} text content as OperationsResponse"));
    }
    anyhow::bail!("{tool_name} returned neither structuredContent nor text content");
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
