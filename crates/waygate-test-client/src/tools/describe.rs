//! `tools describe` — print one tool's definition exactly as the gateway's
//! `tools/list` presents it to this client, including its JSON Schemas.

use anyhow::{Context as _, Result};

use crate::auth::resolve_bearer;
use crate::cli::{Context, DescribeArgs};
use crate::gateway::rpc;
use crate::output;

pub async fn run(ctx: &Context, args: DescribeArgs) -> Result<()> {
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;
    let listed = client.list_all_tools().await.context("list tools");
    let _ = client.cancel().await;

    let tool = listed?
        .into_iter()
        .find(|tool| tool.name == args.name)
        .with_context(|| format!("`{}` is not in the tools/list result", args.name))?;
    if ctx.json {
        output::print_json(&tool)?;
    } else {
        output::print_tool(&tool);
    }
    Ok(())
}
