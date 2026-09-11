//! `login` subcommand — runs the CIMD flow and persists the resulting
//! token to the on-disk cache.

use anyhow::{Context as _, Result};
use reqwest::Client;

use crate::auth::{cache, cimd};
use crate::cli::Context as CliContext;
use crate::gateway::discover;

pub async fn run(ctx: &CliContext) -> Result<()> {
    let client_id = ctx.required_cimd_url()?;
    let http = Client::builder()
        .user_agent(concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build HTTP client")?;

    let resource = discover::fetch_resource_metadata(&http, ctx).await?;
    let as_meta = discover::fetch_as_metadata(&http, ctx, resource.as_ref())
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "gateway {} does not advertise an authorization server — \
                 use --auth bearer with a pre-issued token or run against an \
                 AS-enabled gateway",
                ctx.gateway_base
            )
        })?;

    // Scope selection: request `mcp:invoke` explicitly if the AS advertises
    // it; otherwise fall through with no `scope` param and let the AS pick
    // its default.
    let scopes: Vec<String> = as_meta
        .scopes_supported
        .iter()
        .filter(|s| *s == "mcp:invoke")
        .cloned()
        .collect();

    let token = cimd::login(&as_meta, client_id, &scopes, &http).await?;

    cache::store(ctx, &token).context("persist token to cache")?;
    eprintln!(
        "Logged in at {} (expires in ~{}s; scopes: {})",
        ctx.gateway_base,
        (token.expires_at - time::OffsetDateTime::now_utc())
            .whole_seconds()
            .max(0),
        token.scope.as_deref().unwrap_or("<unset>"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::AuthModeArg;

    #[tokio::test]
    async fn login_requires_an_explicit_identity_before_network_discovery() {
        let ctx = CliContext {
            gateway_base: "http://127.0.0.1:9".parse().unwrap(),
            auth_mode: AuthModeArg::OauthCimd,
            token_override: None,
            cimd_url: None,
            json: false,
        };
        let error = run(&ctx)
            .await
            .expect_err("missing identity must fail locally");
        assert!(error.to_string().contains("--cimd-url"));
    }
}
