//! Interactive REPL: list the tool sources (upstream servers and gateway
//! namespaces) from `tools/list`, pick one, list its tools, pick a tool,
//! enter JSON args, invoke, repeat. Aimed at humans exploring a gateway; for
//! scripting use `tools call`.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use dialoguer::{theme::ColorfulTheme, Input, Select};
use rmcp::model::{CallToolRequestParams, Tool};
use serde_json::{Map, Value};

use crate::auth::resolve_bearer;
use crate::cli::Context;
use crate::gateway::rpc::{self, Client};
use crate::output;

pub async fn run(ctx: &Context) -> Result<()> {
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;

    let result = loop_body(ctx, &client).await;
    let _ = client.cancel().await;
    result
}

async fn loop_body(ctx: &Context, client: &Client) -> Result<()> {
    let tools = client
        .list_all_tools()
        .await
        .context("initial listTools for REPL")?;
    let by_server = group_by_server(&tools);

    if by_server.is_empty() {
        println!("(gateway returned no tools — nothing to explore)");
        return Ok(());
    }

    let servers: Vec<&str> = by_server.keys().copied().collect();
    let theme = ColorfulTheme::default();
    loop {
        let mut menu = servers.clone();
        menu.push("(quit)");
        let pick = Select::with_theme(&theme)
            .with_prompt("server")
            .items(&menu)
            .default(0)
            .interact()
            .context("select server")?;
        if pick == menu.len() - 1 {
            return Ok(());
        }
        let server = menu[pick];

        if let Err(e) = tools_loop(ctx, client, server, &by_server[server]).await {
            eprintln!("error: {:#}", e);
        }
    }
}

/// Group tools by the source before the first dot of the fully-qualified
/// `<server>.<tool>` name; a name without a dot forms its own group.
fn group_by_server(tools: &[Tool]) -> BTreeMap<&str, Vec<&Tool>> {
    let mut by_server: BTreeMap<&str, Vec<&Tool>> = BTreeMap::new();
    for tool in tools {
        let name = tool.name.as_ref();
        let server = name.split_once('.').map_or(name, |(server, _)| server);
        by_server.entry(server).or_default().push(tool);
    }
    by_server
}

async fn tools_loop(ctx: &Context, client: &Client, server: &str, tools: &[&Tool]) -> Result<()> {
    let labels: Vec<String> = tools
        .iter()
        .map(|tool| {
            format!(
                "{}{}",
                tool.name,
                match tool.description.as_deref().unwrap_or("").lines().next() {
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
            .with_prompt(format!("{server} tool"))
            .items(&menu)
            .default(0)
            .interact()
            .context("select tool")?;
        if pick == menu.len() - 1 {
            return Ok(());
        }
        let tool = tools[pick];

        let args: String = Input::with_theme(&theme)
            .with_prompt(format!(
                "args for {} (JSON object, empty = {{}})",
                tool.name
            ))
            .allow_empty(true)
            .interact_text()
            .context("read args")?;
        let arguments = parse_args(&args)?;

        let mut params = CallToolRequestParams::new(tool.name.clone());
        if let Some(obj) = arguments {
            params = params.with_arguments(obj);
        }
        let res = client
            .call_tool(params)
            .await
            .with_context(|| format!("call {}", tool.name))?;

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::model::Tool;
    use serde_json::json;

    use super::group_by_server;

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
    fn tools_group_by_the_source_before_the_first_dot() {
        let tools = vec![
            tool("example-messages.send"),
            tool("codemode.search"),
            tool("example-messages.read.thread"),
            tool("bare"),
        ];
        let grouped = group_by_server(&tools);
        let names = |server: &str| -> Vec<&str> {
            grouped[server]
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect()
        };
        assert_eq!(
            grouped.keys().copied().collect::<Vec<_>>(),
            ["bare", "codemode", "example-messages"]
        );
        assert_eq!(
            names("example-messages"),
            ["example-messages.send", "example-messages.read.thread"]
        );
        assert_eq!(names("bare"), ["bare"]);
    }
}
