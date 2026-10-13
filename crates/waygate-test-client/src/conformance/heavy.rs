//! Heavy conformance tier — adds the unsupported-version refusal shape,
//! unknown-tool routing, and refresh-token round-trip checks on top of light.
//!
//! Expected to be run against a live, representative gateway rather than a
//! minimal dev stand-up. Any PASS here should imply the gateway is ready
//! for a production cut.

use std::time::{Duration, Instant};

use reqwest::Client as HttpClient;
use rmcp::model::CallToolRequestParams;

use crate::auth::{cache, cimd, resolve_bearer, ResolvedAuth};
use crate::cli::{AuthModeArg, Context};
use crate::conformance::report::Report;
use crate::gateway::{
    discover,
    rpc::{self, Client},
};

pub async fn run(ctx: &Context, report: &mut Report) {
    let auth = match resolve_bearer(ctx).await {
        Ok(a) => a,
        Err(e) => {
            report.fail("heavy.auth.resolve", Duration::ZERO, format!("{e:#}"));
            return;
        }
    };
    unsupported_version_shape_check(ctx, &auth, report).await;
    let client = match rpc::connect(ctx, &auth).await {
        Ok(c) => c,
        Err(e) => {
            report.fail("heavy.mcp.initialize", Duration::ZERO, format!("{e:#}"));
            return;
        }
    };

    let listed = match client.list_tools(Default::default()).await {
        Ok(l) => l,
        Err(e) => {
            report.fail("heavy.mcp.listTools", Duration::ZERO, format!("{e:#}"));
            let _ = client.cancel().await;
            return;
        }
    };
    let server = listed.tools.iter().find_map(|t| {
        t.name
            .split_once('.')
            .map(|(server, _)| server)
            .filter(|server| !server.is_empty())
    });
    match server {
        Some(server) => prefix_routing_check(&client, server, report).await,
        None => report.skip(
            "heavy.prefix_routing",
            "tools/list returned no `<server>.<tool>` names",
        ),
    }

    let _ = client.cancel().await;

    refresh_round_trip_check(ctx, &auth, report).await;
}

async fn prefix_routing_check(client: &Client, server: &str, report: &mut Report) {
    let label = "heavy.prefix_routing";
    let start = Instant::now();
    // `<server>.__nope__` should be routed to <server> but return a
    // tool-not-found response — not a gateway-level 500.
    let tool = format!("{server}.__nope__");
    let params = CallToolRequestParams::new(tool);
    match client.call_tool(params).await {
        Ok(r) if r.is_error.unwrap_or(false) => report.pass(label, start.elapsed()),
        Ok(_) => report.fail(label, start.elapsed(), "expected isError=true".to_owned()),
        Err(e) if is_structured_rpc_error(&e.to_string()) => report.pass(label, start.elapsed()),
        Err(e) => report.fail(label, start.elapsed(), format!("{e:#}")),
    }
}

async fn refresh_round_trip_check(ctx: &Context, auth: &ResolvedAuth, report: &mut Report) {
    if !matches!(auth.mode, AuthModeArg::OauthCimd) {
        report.skip(
            "heavy.refresh_round_trip",
            "not OAuth-CIMD; no refresh token to rotate",
        );
        return;
    }
    let start = Instant::now();
    let label = "heavy.refresh_round_trip";
    let Some(mut token) = (match cache::load(ctx) {
        Ok(t) => t,
        Err(e) => {
            report.fail(label, start.elapsed(), format!("{e:#}"));
            return;
        }
    }) else {
        report.skip(label, "no cached token");
        return;
    };
    let Some(refresh) = token.refresh_token.clone() else {
        report.skip(label, "cached token has no refresh_token");
        return;
    };
    let Some(endpoint) = token.token_endpoint.clone() else {
        report.skip(label, "cached token has no token_endpoint");
        return;
    };
    let Some(client_id) = token.client_id.clone().or_else(|| ctx.cimd_url.clone()) else {
        report.skip(
            label,
            "cached token lacks client_id; set --cimd-url to its original identity",
        );
        return;
    };
    let http = match HttpClient::builder()
        .user_agent(concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            report.fail(label, start.elapsed(), e.to_string());
            return;
        }
    };
    match cimd::refresh(&http, &endpoint, &client_id, &refresh).await {
        Ok(resp) => {
            let issuer = token.issuer.clone();
            token = cimd::into_token(resp, &client_id, &endpoint, issuer);
            if let Err(e) = cache::store(ctx, &token) {
                report.fail(label, start.elapsed(), format!("re-store: {e:#}"));
                return;
            }
            // Actually try the new token against listTools.
            let new_auth = ResolvedAuth {
                bearer: Some(token.access_token.clone()),
                mode: AuthModeArg::OauthCimd,
            };
            match rpc::connect(ctx, &new_auth).await {
                Ok(c) => match c.list_tools(Default::default()).await {
                    Ok(_) => {
                        report.pass(label, start.elapsed());
                    }
                    Err(e) => report.fail(
                        label,
                        start.elapsed(),
                        format!("post-refresh list_tools: {e:#}"),
                    ),
                },
                Err(e) => report.fail(
                    label,
                    start.elapsed(),
                    format!("post-refresh connect: {e:#}"),
                ),
            }
        }
        Err(e) => report.fail(label, start.elapsed(), format!("refresh: {e:#}")),
    }

    // Silence discover unused when only used to preserve ctx lifetimes above.
    let _ = discover::fetch_resource_metadata;
}

fn is_structured_rpc_error(text: &str) -> bool {
    // rmcp surfaces server errors as `ServiceError::McpError` with the
    // JSON-RPC code embedded. Anything that's not a panic/connect failure
    // counts as "structured".
    let lower = text.to_ascii_lowercase();
    lower.contains("mcp error")
        || lower.contains("invalid params")
        || lower.contains("method not found")
        || lower.contains("tool not found")
        || lower.contains("invalid request")
        || lower.contains("internal error")
}

/// An unadvertised protocol version must be refused with
/// `UnsupportedProtocolVersion` (`-32022`) whose payload names every
/// version the gateway does serve — the teach-through contract a client
/// needs to retry with a mutually supported version.
async fn unsupported_version_shape_check(
    ctx: &Context,
    auth: &crate::auth::ResolvedAuth,
    report: &mut Report,
) {
    let started = std::time::Instant::now();
    let http = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(e) => {
            report.fail(
                "heavy.unsupported_version.shape",
                started.elapsed(),
                e.to_string(),
            );
            return;
        }
    };
    let mut req = http
        .post(ctx.mcp_url().to_string())
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2099-01-01")
        .header("mcp-method", "tools/list")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }));
    if let Some(token) = auth.bearer.as_deref() {
        req = req.bearer_auth(token);
    }
    match req.send().await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            // Plain JSON or SSE-framed (`data: {…}`), then a strict parse:
            // a JSON-RPC error with code -32022 whose data.supported array
            // is exactly the served-version set — the teach-through shape a
            // client needs for retry selection. Substrings anywhere else in
            // the body must not pass.
            let payload = body
                .lines()
                .find_map(|line| line.strip_prefix("data:"))
                .map(str::trim)
                .unwrap_or(body.as_str());
            let parsed: Option<serde_json::Value> = serde_json::from_str(payload).ok();
            let ok = parsed
                .as_ref()
                .and_then(|msg| msg.get("error"))
                .map(|error| {
                    let code_ok = error.get("code").and_then(|c| c.as_i64()) == Some(-32022);
                    let supported_ok = error
                        .get("data")
                        .and_then(|d| d.get("supported"))
                        .and_then(|s| s.as_array())
                        .map(|versions| {
                            let mut listed: Vec<&str> =
                                versions.iter().filter_map(|v| v.as_str()).collect();
                            listed.sort_unstable();
                            listed == ["2025-11-25", "2026-07-28"]
                        })
                        .unwrap_or(false);
                    code_ok && supported_ok
                })
                .unwrap_or(false);
            if ok {
                report.pass("heavy.unsupported_version.shape", started.elapsed());
            } else {
                report.fail(
                    "heavy.unsupported_version.shape",
                    started.elapsed(),
                    format!(
                        "refusal must be a JSON-RPC error, code -32022, with \
                         data.supported exactly the served set; body: {body:.200}"
                    ),
                );
            }
        }
        Err(e) => report.fail(
            "heavy.unsupported_version.shape",
            started.elapsed(),
            e.to_string(),
        ),
    }
}
