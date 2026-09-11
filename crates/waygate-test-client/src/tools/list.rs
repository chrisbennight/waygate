//! `tools list` — MCP `tools/list` against the gateway. Returns the flat
//! inventory (in SEP #1888 mode that's one `.searchTools` meta-tool per
//! upstream).

use anyhow::Result;

use crate::auth::resolve_bearer;
use crate::cli::Context;
use crate::gateway::rpc;
use crate::output;

pub async fn run(ctx: &Context) -> Result<()> {
    let auth = resolve_bearer(ctx).await?;
    let client = rpc::connect(ctx, &auth).await?;

    let listed = client.list_tools(Default::default()).await?;
    if ctx.json {
        output::print_json(&listed.tools)?;
    } else {
        output::print_tool_list(&listed.tools);
    }
    let _ = client.cancel().await;
    Ok(())
}
