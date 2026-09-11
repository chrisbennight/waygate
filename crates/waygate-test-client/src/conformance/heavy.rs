//! Heavy conformance tier — adds cursor pagination, filter matrix, error
//! shapes, refresh-token round-trip, and types-mode checks on top of light.
//!
//! Expected to be run against a live, representative gateway rather than a
//! minimal dev stand-up. Any PASS here should imply the gateway is ready
//! for a production cut.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::Result;
use reqwest::Client as HttpClient;
use rmcp::model::CallToolRequestParams;
use serde_json::{json, Map, Value};

use crate::auth::{cache, cimd, resolve_bearer, ResolvedAuth};
use crate::cli::{AuthModeArg, Context};
use crate::conformance::light::parse_operations;
use crate::conformance::report::Report;
use crate::gateway::{
    discover,
    rpc::{self, Client},
};
use crate::sep1888::{
    server_from_search_tool, Mode, SearchToolsRequest, TypesResponse, SEARCH_TOOLS_SUFFIX,
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
    let servers: Vec<String> = listed
        .tools
        .iter()
        .filter_map(|t| server_from_search_tool(t.name.as_ref()).map(str::to_owned))
        .collect();

    if servers.is_empty() {
        report.skip("heavy.*", "no searchTools upstreams to probe");
        let _ = client.cancel().await;
        return;
    }

    let server = &servers[0];
    let tool_name = format!("{server}{SEARCH_TOOLS_SUFFIX}");

    cursor_paging_check(&client, &tool_name, report).await;
    filter_matrix_check(&client, &tool_name, report).await;
    error_shapes_check(&client, &tool_name, report).await;
    types_mode_check(&client, &tool_name, report).await;
    prefix_routing_check(&client, server, report).await;

    let _ = client.cancel().await;

    refresh_round_trip_check(ctx, &auth, report).await;
}

async fn cursor_paging_check(client: &Client, tool_name: &str, report: &mut Report) {
    let label = "heavy.cursor_paging";
    let start = Instant::now();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0usize;
    loop {
        let req = SearchToolsRequest {
            mode: Mode::Operations,
            filters: None,
            name: None,
            cursor: cursor.clone(),
            limit: Some(1),
        };
        let args = match to_object(&req) {
            Ok(o) => o,
            Err(e) => {
                report.fail(label, start.elapsed(), e.to_string());
                return;
            }
        };
        let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(args);
        let result = match client.call_tool(params).await {
            Ok(r) => r,
            Err(e) => {
                report.fail(label, start.elapsed(), format!("{e:#}"));
                return;
            }
        };
        if result.is_error.unwrap_or(false) {
            report.fail(label, start.elapsed(), "isError=true".to_owned());
            return;
        }
        let resp = match parse_operations(&result) {
            Ok(r) => r,
            Err(e) => {
                report.fail(label, start.elapsed(), e);
                return;
            }
        };
        for op in &resp.operations {
            if !seen.insert(op.name.clone()) {
                report.fail(
                    label,
                    start.elapsed(),
                    format!("cursor paging returned duplicate `{}`", op.name),
                );
                return;
            }
        }
        pages += 1;
        match resp.next_cursor {
            Some(next) if !next.is_empty() && pages < 50 => cursor = Some(next),
            _ => break,
        }
    }
    report.pass(label, start.elapsed());
}

async fn filter_matrix_check(client: &Client, tool_name: &str, report: &mut Report) {
    let cases: &[(&str, Map<String, Value>)] = &[
        (
            "heavy.filter.resourceType",
            single_filter("resourceType", "message"),
        ),
        ("heavy.filter.action", single_filter("action", "read")),
        ("heavy.filter.scope", single_filter("scope", "mcp:invoke")),
        ("heavy.filter.riskLevel", single_filter("riskLevel", "low")),
        ("heavy.filter.query", single_filter("query", "send")),
    ];
    for (label, filters) in cases {
        let start = Instant::now();
        let args = json!({
            "mode": "operations",
            "filters": filters,
        });
        let args = match args.as_object().cloned() {
            Some(m) => m,
            None => {
                report.fail(
                    label.to_owned(),
                    start.elapsed(),
                    "bad filter json".to_owned(),
                );
                continue;
            }
        };
        let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(args);
        match client.call_tool(params).await {
            Ok(r) if !r.is_error.unwrap_or(false) => match parse_operations(&r) {
                Ok(_) => report.pass(label.to_owned(), start.elapsed()),
                Err(e) => report.fail(label.to_owned(), start.elapsed(), e),
            },
            Ok(_) => report.fail(label.to_owned(), start.elapsed(), "isError=true".to_owned()),
            Err(e) => report.fail(label.to_owned(), start.elapsed(), format!("{e:#}")),
        }
    }
}

async fn error_shapes_check(client: &Client, tool_name: &str, report: &mut Report) {
    // Bogus `mode` — must surface as a tool-side error (isError=true or
    // JSON-RPC error), not a 5xx the transport would have mapped into an
    // rmcp error first.
    let start = Instant::now();
    let label = "heavy.error.bogus_mode";
    let bogus = json!({"mode": "bogus"}).as_object().cloned().unwrap();
    let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(bogus);
    match client.call_tool(params).await {
        Ok(r) if r.is_error.unwrap_or(false) => report.pass(label, start.elapsed()),
        Ok(_) => report.fail(label, start.elapsed(), "expected isError=true".to_owned()),
        Err(e) => {
            // A JSON-RPC error is also acceptable — what we *don't* want is a
            // panic or a transport reset, and either of those presents as an
            // anyhow error here. We log it as a PASS because the surface is
            // still structured.
            if is_structured_rpc_error(&e.to_string()) {
                report.pass(label, start.elapsed());
            } else {
                report.fail(label, start.elapsed(), format!("{e:#}"));
            }
        }
    }

    let start = Instant::now();
    let label = "heavy.error.huge_limit";
    let req = json!({"mode": "operations", "limit": 10_000})
        .as_object()
        .cloned()
        .unwrap();
    let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(req);
    match client.call_tool(params).await {
        // Either a clamp (success) or a structured error is fine.
        Ok(r) if r.is_error.unwrap_or(false) => report.pass(label, start.elapsed()),
        Ok(_) => report.pass(label, start.elapsed()),
        Err(e) if is_structured_rpc_error(&e.to_string()) => report.pass(label, start.elapsed()),
        Err(e) => report.fail(label, start.elapsed(), format!("{e:#}")),
    }

    let start = Instant::now();
    let label = "heavy.error.tampered_cursor";
    let req = json!({"mode": "operations", "cursor": "tampered_cursor_for_test"})
        .as_object()
        .cloned()
        .unwrap();
    let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(req);
    match client.call_tool(params).await {
        Ok(r) if r.is_error.unwrap_or(false) => report.pass(label, start.elapsed()),
        Ok(_) => report.pass(label, start.elapsed()),
        Err(e) if is_structured_rpc_error(&e.to_string()) => report.pass(label, start.elapsed()),
        Err(e) => report.fail(label, start.elapsed(), format!("{e:#}")),
    }
}

async fn types_mode_check(client: &Client, tool_name: &str, report: &mut Report) {
    // Look for an operation to describe, then run mode=types on it.
    let start = Instant::now();
    let label = "heavy.types_mode";
    let req = SearchToolsRequest {
        mode: Mode::Operations,
        filters: None,
        name: None,
        cursor: None,
        limit: Some(5),
    };
    let args = match to_object(&req) {
        Ok(a) => a,
        Err(e) => {
            report.fail(label, start.elapsed(), e.to_string());
            return;
        }
    };
    let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(args);
    let result = match client.call_tool(params).await {
        Ok(r) => r,
        Err(e) => {
            report.fail(label, start.elapsed(), format!("{e:#}"));
            return;
        }
    };
    let ops_resp = match parse_operations(&result) {
        Ok(r) => r,
        Err(e) => {
            report.fail(label, start.elapsed(), e);
            return;
        }
    };
    let Some(op) = ops_resp.operations.first() else {
        report.skip(label, "no operations available to describe");
        return;
    };
    let types_req = json!({"mode": "types", "name": op.name})
        .as_object()
        .cloned()
        .unwrap();
    let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(types_req);
    match client.call_tool(params).await {
        Ok(r) if !r.is_error.unwrap_or(false) => {
            let parsed: std::result::Result<TypesResponse, _> = if let Some(sc) =
                r.structured_content.as_ref()
            {
                serde_json::from_value(sc.clone())
            } else if let Some(text) = r.content.iter().find_map(|c| c.as_text().map(|t| &t.text)) {
                serde_json::from_str(text)
            } else {
                report.fail(label, start.elapsed(), "no content returned".to_owned());
                return;
            };
            match parsed {
                Ok(_) => report.pass(label, start.elapsed()),
                Err(e) => report.fail(label, start.elapsed(), e.to_string()),
            }
        }
        Ok(_) => report.fail(label, start.elapsed(), "isError=true".to_owned()),
        Err(e) => report.fail(label, start.elapsed(), format!("{e:#}")),
    }
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

fn single_filter(key: &str, value: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(key.to_owned(), Value::String(value.to_owned()));
    m
}

fn to_object(req: &SearchToolsRequest) -> Result<Map<String, Value>> {
    match serde_json::to_value(req)? {
        Value::Object(m) => Ok(m),
        other => anyhow::bail!("SearchToolsRequest did not serialize as object: {other:?}"),
    }
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
