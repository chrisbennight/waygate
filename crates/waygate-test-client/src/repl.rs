//! Interactive REPL: list upstream servers, pick one, list its operations,
//! pick an operation, enter JSON args, invoke, repeat. Aimed at humans
//! exploring a gateway; for scripting use `tools call`.

use anyhow::{Context as _, Result};
use dialoguer::{theme::ColorfulTheme, Input, Select};
use rmcp::model::CallToolRequestParams;
use serde_json::{Map, Value};

use crate::auth::resolve_bearer;
use crate::cli::Context;
use crate::gateway::rpc::{self, Client};
use crate::output;
use crate::sep1888::{
    server_from_search_tool, Mode, OperationsResponse, SearchToolsRequest, SEARCH_TOOLS_SUFFIX,
};

pub async fn run(ctx: &Context) -> Result<()> {
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;

    let result = loop_body(ctx, &client).await;
    let _ = client.cancel().await;
    result
}

async fn loop_body(ctx: &Context, client: &Client) -> Result<()> {
    let listed = client
        .list_tools(Default::default())
        .await
        .context("initial listTools for REPL")?;
    let servers: Vec<String> = listed
        .tools
        .iter()
        .filter_map(|t| server_from_search_tool(t.name.as_ref()).map(str::to_owned))
        .collect();

    if servers.is_empty() {
        println!("(gateway returned no `.searchTools` meta-tools — nothing to explore)");
        return Ok(());
    }

    let theme = ColorfulTheme::default();
    loop {
        let mut menu = servers.clone();
        menu.push("(quit)".to_owned());
        let pick = Select::with_theme(&theme)
            .with_prompt("server")
            .items(&menu)
            .default(0)
            .interact()
            .context("select server")?;
        if pick == menu.len() - 1 {
            return Ok(());
        }
        let server = &menu[pick];

        if let Err(e) = operations_loop(ctx, client, server).await {
            eprintln!("error: {:#}", e);
        }
    }
}

async fn operations_loop(ctx: &Context, client: &Client, server: &str) -> Result<()> {
    let ops = fetch_all_operations(client, server).await?;
    if ops.operations.is_empty() {
        println!("(no operations exposed by {server})");
        return Ok(());
    }

    let labels: Vec<String> = ops
        .operations
        .iter()
        .map(|op| {
            format!(
                "{} [{}]{}",
                op.name,
                op.risk_level.as_str(),
                match op.description.as_deref().unwrap_or("").lines().next() {
                    Some(l) if !l.is_empty() => format!(" — {l}"),
                    _ => String::new(),
                }
            )
        })
        .collect();

    let theme = ColorfulTheme::default();
    loop {
        let mut menu = labels.clone();
        menu.push("(back)".to_owned());
        let pick = Select::with_theme(&theme)
            .with_prompt(format!("{server} operation"))
            .items(&menu)
            .default(0)
            .interact()
            .context("select operation")?;
        if pick == menu.len() - 1 {
            return Ok(());
        }
        let op = &ops.operations[pick];

        let args: String = Input::with_theme(&theme)
            .with_prompt(format!("args for {} (JSON object, empty = {{}})", op.name))
            .allow_empty(true)
            .interact_text()
            .context("read args")?;
        let arguments = parse_args(&args)?;

        let mut params = CallToolRequestParams::new(op.name.clone());
        if let Some(obj) = arguments {
            params = params.with_arguments(obj);
        }
        let res = client
            .call_tool(params)
            .await
            .with_context(|| format!("call {}", op.name))?;

        if ctx.json {
            println!("{}", serde_json::to_string_pretty(&res)?);
        } else if let Some(sc) = &res.structured_content {
            println!("{}", serde_json::to_string_pretty(sc)?);
        } else {
            let mut any = false;
            for c in &res.content {
                if let Some(t) = c.as_text() {
                    println!("{}", t.text);
                    any = true;
                }
            }
            if !any {
                output::print_json(&res)?;
            }
        }
        if res.is_error.unwrap_or(false) {
            println!("[isError=true]");
        }
    }
}

async fn fetch_all_operations(client: &Client, server: &str) -> Result<OperationsResponse> {
    let tool_name = format!("{server}{SEARCH_TOOLS_SUFFIX}");
    let mut cursor: Option<String> = None;
    let mut merged = OperationsResponse {
        operations: Vec::new(),
        next_cursor: None,
    };
    loop {
        let req = SearchToolsRequest {
            mode: Mode::Operations,
            filters: None,
            name: None,
            cursor: cursor.clone(),
            limit: None,
        };
        let params = CallToolRequestParams::new(tool_name.clone()).with_arguments(to_object(&req)?);
        let res = client
            .call_tool(params)
            .await
            .with_context(|| format!("call {tool_name}"))?;
        if res.is_error.unwrap_or(false) {
            anyhow::bail!("{tool_name} returned isError=true");
        }
        let parsed: OperationsResponse = if let Some(sc) = &res.structured_content {
            serde_json::from_value(sc.clone()).context("parse structuredContent")?
        } else if let Some(text) = res
            .content
            .iter()
            .find_map(|c| c.as_text().map(|t| &t.text))
        {
            serde_json::from_str(text).context("parse text content")?
        } else {
            anyhow::bail!("{tool_name} returned no structuredContent or text");
        };
        merged.operations.extend(parsed.operations);
        match parsed.next_cursor {
            Some(next) if !next.is_empty() => cursor = Some(next),
            _ => {
                merged.next_cursor = None;
                break;
            }
        }
    }
    Ok(merged)
}

fn parse_args(raw: &str) -> Result<Option<Map<String, Value>>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed: Value = serde_json::from_str(trimmed).context("parse REPL args as JSON")?;
    match parsed {
        Value::Object(m) => Ok(Some(m)),
        other => anyhow::bail!("args must be a JSON object, got {other}"),
    }
}

fn to_object(req: &SearchToolsRequest) -> Result<Map<String, Value>> {
    match serde_json::to_value(req)? {
        Value::Object(m) => Ok(m),
        other => anyhow::bail!("SearchToolsRequest did not serialize as object: {other:?}"),
    }
}
