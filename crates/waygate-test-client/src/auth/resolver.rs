//! Decide the `Authorization: Bearer …` value (if any) each RPC should send.
//!
//! The decision tree collapses three inputs — `--auth` flag, `--token` /
//! env, and the on-disk cache — into a single `ResolvedAuth` value used by
//! every RPC call.

use anyhow::{Context as _, Result};
use reqwest::Client;
use tracing::{debug, warn};

use crate::auth::{bearer, cache, cimd};
use crate::cli::{AuthModeArg, Context};
use crate::gateway::discover;

/// The final auth decision for a single RPC session.
#[derive(Debug, Clone)]
pub struct ResolvedAuth {
    /// The raw bearer value (no `Bearer ` prefix) to set as the
    /// `Authorization` header, or `None` for anonymous/disabled mode.
    pub bearer: Option<String>,
    /// Effective auth mode — useful for logging and conformance reports.
    pub mode: AuthModeArg,
}

/// Resolve the bearer token for this invocation. May run discovery to decide
/// the auto mode, and may refresh an expired cached token.
pub async fn resolve_bearer(ctx: &Context) -> Result<ResolvedAuth> {
    let http = Client::builder()
        .user_agent(concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build HTTP client")?;

    match ctx.auth_mode {
        AuthModeArg::None => Ok(ResolvedAuth {
            bearer: None,
            mode: AuthModeArg::None,
        }),
        AuthModeArg::Bearer => {
            let token = bearer::from_cli(ctx.token_override.as_deref())?;
            Ok(ResolvedAuth {
                bearer: Some(token),
                mode: AuthModeArg::Bearer,
            })
        }
        AuthModeArg::OauthCimd => oauth_cimd(ctx, &http).await,
        AuthModeArg::Auto => auto(ctx, &http).await,
    }
}

async fn auto(ctx: &Context, http: &Client) -> Result<ResolvedAuth> {
    // 1. An explicit token always wins — the operator told us exactly what
    //    to send.
    if let Some(tok) = ctx.token_override.as_deref() {
        let trimmed = tok.trim();
        if !trimmed.is_empty() {
            debug!("auto-auth: using explicit --token / $GATEWAY_TOKEN");
            return Ok(ResolvedAuth {
                bearer: Some(trimmed.to_owned()),
                mode: AuthModeArg::Bearer,
            });
        }
    }

    // 2. Probe the resource metadata. If the gateway advertises no AS and no
    //    resource metadata exists, assume disabled mode.
    let resource = discover::fetch_resource_metadata(http, ctx).await?;
    let as_meta = discover::fetch_as_metadata(http, ctx, resource.as_ref()).await?;

    if as_meta.is_none() {
        debug!(
            "auto-auth: gateway does not advertise AS metadata; sending no Authorization header"
        );
        return Ok(ResolvedAuth {
            bearer: None,
            mode: AuthModeArg::None,
        });
    }

    // 3. AS exists → try the cache.
    oauth_cimd(ctx, http).await
}

async fn oauth_cimd(ctx: &Context, http: &Client) -> Result<ResolvedAuth> {
    let cached = cache::load(ctx)?;
    if let Some(mut token) = cached {
        if !token.is_expired(60) {
            return Ok(ResolvedAuth {
                bearer: Some(token.access_token),
                mode: AuthModeArg::OauthCimd,
            });
        }
        if let Some(refresh_token) = token.refresh_token.clone() {
            let endpoint = token.token_endpoint.clone();
            let client_id = token
                .client_id
                .clone()
                .or_else(|| ctx.cimd_url.clone())
                .context("cached token lacks its client identity; set --cimd-url or MCP_TEST_CLIENT_CIMD_URL to the original document URL")?;
            let endpoint = match endpoint {
                Some(e) => e,
                None => {
                    let resource = discover::fetch_resource_metadata(http, ctx).await?;
                    let as_meta = discover::fetch_as_metadata(http, ctx, resource.as_ref())
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "cached token lacks token_endpoint and gateway no longer \
                                 advertises AS metadata — run `login` again",
                            )
                        })?;
                    as_meta.token_endpoint
                }
            };
            match cimd::refresh(http, &endpoint, &client_id, &refresh_token).await {
                Ok(resp) => {
                    let issuer = token.issuer.clone();
                    let new = cimd::into_token(resp, &client_id, &endpoint, issuer);
                    cache::store(ctx, &new)?;
                    return Ok(ResolvedAuth {
                        bearer: Some(new.access_token),
                        mode: AuthModeArg::OauthCimd,
                    });
                }
                Err(e) => {
                    warn!(error = %e, "refresh-token rotation failed; falling back to re-login");
                    token.refresh_token = None;
                }
            }
        }
    }

    anyhow::bail!(
        "no valid cached token for {} — run `mcp-test-client --gateway {} login`",
        ctx.gateway_base,
        ctx.gateway_base
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_oauth_modes_do_not_require_a_client_document() {
        let mut ctx = Context {
            gateway_base: "http://127.0.0.1:9".parse().unwrap(),
            auth_mode: AuthModeArg::None,
            token_override: None,
            cimd_url: None,
            json: false,
        };
        assert!(resolve_bearer(&ctx).await.unwrap().bearer.is_none());
        ctx.auth_mode = AuthModeArg::Bearer;
        ctx.token_override = Some("synthetic-test-token".to_owned());
        assert_eq!(
            resolve_bearer(&ctx).await.unwrap().bearer.as_deref(),
            Some("synthetic-test-token")
        );
    }
}
