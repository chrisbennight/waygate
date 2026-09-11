//! Fetch and pretty-print the gateway's OAuth 2.1 metadata documents.
//!
//! Two well-known URLs matter:
//!
//! * `/.well-known/oauth-protected-resource` (RFC 9728) — always exposed;
//!   tells us which AS issues tokens for this resource.
//! * `/.well-known/oauth-authorization-server` (RFC 8414) — only when the
//!   gateway is *itself* an AS (i.e. `GATEWAY_AS_ENABLED=true`).

use anyhow::{Context as _, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::cli::Context as CliContext;

/// RFC 9728 resource metadata — the subset we care about.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceMetadata {
    #[allow(dead_code)]
    pub resource: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub bearer_methods_supported: Vec<String>,
}

/// RFC 8414 AS metadata — the subset we care about.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsMetadata {
    pub issuer: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
}

const RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
const AS_PATH: &str = "/.well-known/oauth-authorization-server";

pub async fn fetch_resource_metadata(
    http: &Client,
    ctx: &CliContext,
) -> Result<Option<ResourceMetadata>> {
    let url = ctx.url(RESOURCE_PATH);
    let resp = http.get(url.clone()).send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            let parsed: ResourceMetadata = serde_json::from_str(&body)
                .with_context(|| format!("parse resource metadata from {url}"))?;
            Ok(Some(parsed))
        }
        Ok(r) if r.status().as_u16() == 404 => Ok(None),
        Ok(r) => anyhow::bail!("GET {url} returned {}", r.status()),
        Err(e) => Err(e).with_context(|| format!("GET {url}")),
    }
}

pub async fn fetch_as_metadata(
    http: &Client,
    ctx: &CliContext,
    resource: Option<&ResourceMetadata>,
) -> Result<Option<AsMetadata>> {
    // Prefer the issuer the resource document points at; this matches the
    // RFC 9728 flow a spec-compliant client would perform. Fall back to the
    // gateway base when resource metadata is absent — useful for AS-mode
    // gateways where the resource doc exists but clients dial discovery
    // on the raw host first.
    let candidates: Vec<url::Url> = match resource {
        Some(r) if !r.authorization_servers.is_empty() => r
            .authorization_servers
            .iter()
            .filter_map(|issuer| {
                let mut u = url::Url::parse(issuer).ok()?;
                u.set_path(AS_PATH);
                u.set_query(None);
                u.set_fragment(None);
                Some(u)
            })
            .collect(),
        _ => vec![ctx.url(AS_PATH)],
    };

    for url in &candidates {
        match http.get(url.clone()).send().await {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                let parsed: AsMetadata = serde_json::from_str(&body)
                    .with_context(|| format!("parse AS metadata from {url}"))?;
                return Ok(Some(parsed));
            }
            Ok(r) if r.status().as_u16() == 404 => continue,
            Ok(r) => anyhow::bail!("GET {url} returned {}", r.status()),
            Err(e) => return Err(e).with_context(|| format!("GET {url}")),
        }
    }
    Ok(None)
}

/// `discover` subcommand: probe the well-known endpoints and print a report.
pub async fn run(ctx: &CliContext) -> Result<()> {
    let http = Client::builder()
        .user_agent(concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build HTTP client")?;

    let resource = fetch_resource_metadata(&http, ctx).await?;
    let as_meta = fetch_as_metadata(&http, ctx, resource.as_ref()).await?;

    if ctx.json {
        let out = serde_json::json!({
            "gateway": ctx.gateway_base.to_string(),
            "resource_metadata": resource,
            "authorization_server": as_meta,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        render_report(ctx, resource.as_ref(), as_meta.as_ref());
    }

    Ok(())
}

fn render_report(
    ctx: &CliContext,
    resource: Option<&ResourceMetadata>,
    as_meta: Option<&AsMetadata>,
) {
    println!("Gateway: {}", ctx.gateway_base);
    println!();
    match resource {
        Some(r) => {
            println!("  [ok] /.well-known/oauth-protected-resource");
            println!(
                "      authorization_servers: {}",
                render_list(&r.authorization_servers)
            );
            println!(
                "      scopes_supported:      {}",
                render_list(&r.scopes_supported)
            );
        }
        None => {
            println!("  [ ] /.well-known/oauth-protected-resource — not present (disabled mode?)");
        }
    }
    match as_meta {
        Some(a) => {
            println!("  [ok] /.well-known/oauth-authorization-server");
            println!(
                "      issuer:           {}",
                a.issuer.as_deref().unwrap_or("<unset>")
            );
            println!("      authorize:        {}", a.authorization_endpoint);
            println!("      token:            {}", a.token_endpoint);
            println!(
                "      grant_types:      {}",
                render_list(&a.grant_types_supported)
            );
            println!(
                "      pkce_methods:     {}",
                render_list(&a.code_challenge_methods_supported)
            );
            println!(
                "      token_auth:       {}",
                render_list(&a.token_endpoint_auth_methods_supported)
            );
            println!(
                "      scopes_supported: {}",
                render_list(&a.scopes_supported)
            );
            println!(
                "      CIMD supported:   {}",
                if a.client_id_metadata_document_supported {
                    "yes"
                } else {
                    "no"
                },
            );
        }
        None => {
            println!("  [ ] /.well-known/oauth-authorization-server — not an AS (resource-only or disabled)");
        }
    }
    println!();
    let suggested = if as_meta.is_some() {
        "oauth-cimd"
    } else if resource.is_some() {
        "bearer (get a token from the upstream IdP first)"
    } else {
        "none"
    };
    println!("Suggested --auth: {suggested}");
}

fn render_list(items: &[String]) -> String {
    if items.is_empty() {
        "<none>".to_owned()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests {
    //! Cover the reqwest GET + JSON-decode paths for both metadata endpoints
    //! against a real loopback HTTP server. Catches regressions in
    //! reqwest::get(...).send().await and `.text()` body buffering, which
    //! no other test in this crate exercises (e.g. across reqwest bumps).

    use super::*;

    use std::net::SocketAddr;

    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use tokio::net::TcpListener;

    use crate::cli::{AuthModeArg, Context as CliContext};
    use url::Url;

    async fn spawn(router: Router) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    fn ctx_for(addr: &SocketAddr) -> CliContext {
        CliContext {
            gateway_base: Url::parse(&format!("http://{addr}")).unwrap(),
            auth_mode: AuthModeArg::Auto,
            token_override: None,
            cimd_url: None,
            json: false,
        }
    }

    fn http() -> Client {
        Client::builder()
            .user_agent("mcp-test-client/test")
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn fetch_resource_metadata_decodes_json() {
        async fn handler() -> impl IntoResponse {
            Json(json!({
                "resource": "https://gw.example",
                "authorization_servers": ["https://as.example"],
                "scopes_supported": ["mcp:invoke"],
                "bearer_methods_supported": ["header"],
            }))
        }
        let addr = spawn(Router::new().route(RESOURCE_PATH, get(handler))).await;
        let r = fetch_resource_metadata(&http(), &ctx_for(&addr))
            .await
            .expect("ok")
            .expect("Some metadata");
        assert_eq!(
            r.authorization_servers,
            vec!["https://as.example".to_owned()]
        );
        assert_eq!(r.scopes_supported, vec!["mcp:invoke".to_owned()]);
    }

    #[tokio::test]
    async fn fetch_resource_metadata_404_is_none() {
        async fn missing() -> impl IntoResponse {
            StatusCode::NOT_FOUND
        }
        let addr = spawn(Router::new().route(RESOURCE_PATH, get(missing))).await;
        let r = fetch_resource_metadata(&http(), &ctx_for(&addr))
            .await
            .expect("ok");
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn fetch_as_metadata_follows_resource_pointer() {
        // Spin up an AS server, point a resource doc at it, and confirm
        // fetch_as_metadata GETs the AS-mode well-known URL on the issuer
        // host (RFC 9728 → RFC 8414 flow).
        async fn as_doc() -> impl IntoResponse {
            Json(json!({
                "authorization_endpoint": "http://placeholder/oauth/authorize",
                "token_endpoint": "http://placeholder/oauth/token",
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["mcp:invoke"],
                "client_id_metadata_document_supported": true,
            }))
        }
        let as_addr = spawn(Router::new().route(AS_PATH, get(as_doc))).await;
        let resource = ResourceMetadata {
            resource: format!("http://{as_addr}"),
            authorization_servers: vec![format!("http://{as_addr}")],
            scopes_supported: vec!["mcp:invoke".to_owned()],
            bearer_methods_supported: vec!["header".to_owned()],
        };

        // The gateway base is irrelevant: with a non-empty
        // authorization_servers list, fetch_as_metadata MUST query the
        // pointed-at issuer, not the gateway.
        let dummy_addr = spawn(Router::new()).await;
        let a = fetch_as_metadata(&http(), &ctx_for(&dummy_addr), Some(&resource))
            .await
            .expect("ok")
            .expect("Some AS metadata");
        assert_eq!(a.token_endpoint, "http://placeholder/oauth/token");
        assert!(a.client_id_metadata_document_supported);
        assert!(a
            .code_challenge_methods_supported
            .iter()
            .any(|s| s == "S256"));
    }

    #[tokio::test]
    async fn fetch_as_metadata_falls_back_to_gateway_base() {
        // No resource doc → candidate URL is the gateway base. Ensures the
        // fallback `ctx.url(AS_PATH)` reqwest GET path is exercised too.
        async fn as_doc() -> impl IntoResponse {
            Json(json!({
                "authorization_endpoint": "http://placeholder/oauth/authorize",
                "token_endpoint": "http://placeholder/oauth/token",
            }))
        }
        let addr = spawn(Router::new().route(AS_PATH, get(as_doc))).await;
        let a = fetch_as_metadata(&http(), &ctx_for(&addr), None)
            .await
            .expect("ok")
            .expect("Some AS metadata");
        assert_eq!(a.token_endpoint, "http://placeholder/oauth/token");
    }
}
