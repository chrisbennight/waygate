//! Light conformance tier — meant to run against a live gateway in a handful
//! of seconds. Covers the shape of the well-known endpoints, the
//! `WWW-Authenticate` signal, the initialize+listTools round-trip, and one
//! `searchTools` invocation per discovered upstream (with a best-effort
//! no-side-effect tool call when one is available).

use std::time::{Duration, Instant};

use anyhow::Result;
use reqwest::Client as HttpClient;
use rmcp::model::CallToolRequestParams;
use serde_json::{Map, Value};

use crate::auth::{resolve_bearer, ResolvedAuth};
use crate::cli::{AuthModeArg, Context};
use crate::conformance::report::Report;
use crate::gateway::{
    discover,
    rpc::{self, Client},
};
use crate::sep1888::{
    server_from_search_tool, Mode, OperationDescriptor, OperationsResponse, RiskTier,
    SearchToolsRequest, TypesResponse, SEARCH_TOOLS_SUFFIX,
};

pub async fn run(ctx: &Context, report: &mut Report) {
    let http = match HttpClient::builder()
        .user_agent(concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            report.fail("http_client_build", Duration::ZERO, e.to_string());
            return;
        }
    };

    let resource = check_resource_metadata(ctx, &http, report).await;
    let as_meta = check_as_metadata(ctx, &http, resource.as_ref(), report).await;

    check_unauth_challenge(ctx, &http, resource.as_ref(), as_meta.as_ref(), report).await;

    let auth = match resolve_bearer(ctx).await {
        Ok(a) => a,
        Err(e) => {
            report.fail("auth.resolve", Duration::ZERO, format!("{e:#}"));
            return;
        }
    };

    list_tools_and_search(ctx, &auth, report).await;
    check_dual_generation(ctx, &http, &auth, report).await;
}

/// Dual-generation checks: the gateway serves 2026-07-28 statelessly (no
/// session id, `resultType` present, `server/discover` advertising both
/// versions) while the 2025-11-25 handshake still mints a session. Four
/// raw round-trips, well inside the light tier's budget.
async fn check_dual_generation(
    ctx: &Context,
    http: &HttpClient,
    auth: &ResolvedAuth,
    report: &mut Report,
) {
    let url = ctx.mcp_url().to_string();
    let bearer = auth.bearer.as_deref();
    let apply_auth = |req: reqwest::RequestBuilder| match bearer {
        Some(token) => req.bearer_auth(token),
        None => req,
    };

    // Stateless 2026-07-28 round trip.
    let started = Instant::now();
    let stateless_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")),
                "version": env!("CARGO_PKG_VERSION")
            }
        }}
    });
    let resp = apply_auth(http.post(&url))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .json(&stateless_body)
        .send()
        .await;
    match resp {
        Ok(resp) => {
            let no_session = resp.headers().get("mcp-session-id").is_none();
            let body = resp.text().await.unwrap_or_default();
            if no_session && body.contains("\"result\"") {
                report.pass("stateless.round_trip", started.elapsed());
            } else {
                report.fail(
                    "stateless.round_trip",
                    started.elapsed(),
                    format!("session minted or no result; body: {body:.200}"),
                );
            }
            if body.contains("\"resultType\":\"complete\"") {
                report.pass("stateless.result_type", started.elapsed());
            } else {
                report.fail(
                    "stateless.result_type",
                    started.elapsed(),
                    format!("resultType missing from 2026-07-28 result; body: {body:.200}"),
                );
            }
        }
        Err(e) => {
            report.fail("stateless.round_trip", started.elapsed(), e.to_string());
            report.skip("stateless.result_type", "stateless round trip failed");
        }
    }

    // server/discover advertises both generations.
    let started = Instant::now();
    let resp = apply_auth(http.post(&url))
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "server/discover")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "server/discover",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }))
        .send()
        .await;
    match resp {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // The result may arrive as plain JSON or SSE-framed (`data: {…}`).
            let payload = body
                .lines()
                .find_map(|line| line.strip_prefix("data:"))
                .map(str::trim)
                .unwrap_or(body.as_str());
            let parsed: Option<Value> = serde_json::from_str(payload).ok();
            // Exact-set check on the advertised-version field: extra or
            // missing versions are drift this independent guard exists to
            // catch, so substring or whole-result matching is not enough.
            let versions_ok = parsed
                .as_ref()
                .and_then(|msg| msg.get("result"))
                .and_then(|result| result.get("supportedVersions"))
                .and_then(|versions| versions.as_array())
                .map(|versions| {
                    let mut listed: Vec<&str> =
                        versions.iter().filter_map(|v| v.as_str()).collect();
                    listed.sort_unstable();
                    listed == ["2025-11-25", "2026-07-28"]
                })
                .unwrap_or(false);
            if status.is_success() && versions_ok {
                report.pass("discover.versions", started.elapsed());
            } else {
                report.fail(
                    "discover.versions",
                    started.elapsed(),
                    format!(
                        "discover must return a JSON-RPC result listing both \
                         served versions (status {status}); body: {body:.200}"
                    ),
                );
            }
        }
        Err(e) => report.fail("discover.versions", started.elapsed(), e.to_string()),
    }

    // Legacy handshake still mints a session.
    let started = Instant::now();
    let resp = apply_auth(http.post(&url))
        .header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "mcp-test-client", "version": env!("CARGO_PKG_VERSION")}
            }
        }))
        .send()
        .await;
    match resp {
        Ok(resp) => {
            if resp.headers().get("mcp-session-id").is_some() {
                report.pass("legacy.session_header", started.elapsed());
            } else {
                report.fail(
                    "legacy.session_header",
                    started.elapsed(),
                    "2025-11-25 initialize must mint an Mcp-Session-Id",
                );
            }
        }
        Err(e) => report.fail("legacy.session_header", started.elapsed(), e.to_string()),
    }
}

async fn check_resource_metadata(
    ctx: &Context,
    http: &HttpClient,
    report: &mut Report,
) -> Option<discover::ResourceMetadata> {
    let start = Instant::now();
    match discover::fetch_resource_metadata(http, ctx).await {
        Ok(Some(r)) => {
            report.pass("oauth-protected-resource", start.elapsed());
            Some(r)
        }
        Ok(None) => {
            report.skip(
                "oauth-protected-resource",
                "no /.well-known/oauth-protected-resource (disabled mode?)",
            );
            None
        }
        Err(e) => {
            report.fail(
                "oauth-protected-resource",
                start.elapsed(),
                format!("{e:#}"),
            );
            None
        }
    }
}

async fn check_as_metadata(
    ctx: &Context,
    http: &HttpClient,
    resource: Option<&discover::ResourceMetadata>,
    report: &mut Report,
) -> Option<discover::AsMetadata> {
    let start = Instant::now();
    match discover::fetch_as_metadata(http, ctx, resource).await {
        Ok(Some(a)) => {
            report.pass("oauth-authorization-server", start.elapsed());
            Some(a)
        }
        Ok(None) => {
            report.skip("oauth-authorization-server", "gateway is not an AS");
            None
        }
        Err(e) => {
            report.fail(
                "oauth-authorization-server",
                start.elapsed(),
                format!("{e:#}"),
            );
            None
        }
    }
}

async fn check_unauth_challenge(
    ctx: &Context,
    http: &HttpClient,
    resource: Option<&discover::ResourceMetadata>,
    as_meta: Option<&discover::AsMetadata>,
    report: &mut Report,
) {
    // Only meaningful when the gateway enforces auth. Disabled mode accepts
    // anonymous requests, so skip the challenge probe.
    if resource.is_none() && as_meta.is_none() {
        report.skip(
            "unauth_challenge",
            "no well-known auth surface — gateway is in disabled mode",
        );
        return;
    }
    let start = Instant::now();
    let url = ctx.mcp_url();
    let req = http
        .post(url.clone())
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}"#)
        .build();
    let req = match req {
        Ok(r) => r,
        Err(e) => {
            report.fail("unauth_challenge", start.elapsed(), e.to_string());
            return;
        }
    };
    match http.execute(req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let www = resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            if status == 401 && www.to_ascii_lowercase().contains("bearer") {
                report.pass("unauth_challenge", start.elapsed());
            } else {
                report.fail(
                    "unauth_challenge",
                    start.elapsed(),
                    format!(
                        "expected 401 + Bearer challenge, got {status} www-authenticate=`{www}`"
                    ),
                );
            }
        }
        Err(e) => {
            report.fail("unauth_challenge", start.elapsed(), e.to_string());
        }
    }
}

async fn list_tools_and_search(ctx: &Context, auth: &ResolvedAuth, report: &mut Report) {
    let start = Instant::now();
    let client = match rpc::connect(ctx, auth).await {
        Ok(c) => c,
        Err(e) => {
            report.fail("mcp.initialize", start.elapsed(), format!("{e:#}"));
            return;
        }
    };
    report.pass("mcp.initialize", start.elapsed());

    let start = Instant::now();
    let listed = match client.list_tools(Default::default()).await {
        Ok(l) => l,
        Err(e) => {
            report.fail("mcp.listTools", start.elapsed(), format!("{e:#}"));
            let _ = client.cancel().await;
            return;
        }
    };
    report.pass("mcp.listTools", start.elapsed());

    let servers: Vec<String> = listed
        .tools
        .iter()
        .filter_map(|t| server_from_search_tool(t.name.as_ref()).map(str::to_owned))
        .collect();

    if servers.is_empty() {
        report.skip(
            "searchTools.operations",
            "no upstream advertises a searchTools meta-tool",
        );
        let _ = client.cancel().await;
        return;
    }

    let mut candidate_op: Option<OperationDescriptor> = None;
    for server in &servers {
        let label = format!("searchTools.operations[{server}]");
        let start = Instant::now();
        let tool = format!("{server}{SEARCH_TOOLS_SUFFIX}");
        let req = SearchToolsRequest {
            mode: Mode::Operations,
            filters: None,
            name: None,
            cursor: None,
            limit: None,
        };
        let args = match to_object(&req) {
            Ok(o) => o,
            Err(e) => {
                report.fail(label, start.elapsed(), e.to_string());
                continue;
            }
        };
        let params = CallToolRequestParams::new(tool.clone()).with_arguments(args);
        match client.call_tool(params).await {
            Ok(result) if !result.is_error.unwrap_or(false) => match parse_operations(&result) {
                Ok(resp) => {
                    if shapes_valid(&resp) {
                        report.pass(label, start.elapsed());
                        if candidate_op.is_none() {
                            candidate_op = resp.operations.into_iter().find(safe_candidate);
                        }
                    } else {
                        report.fail(
                            label,
                            start.elapsed(),
                            "response shape failed validation".to_owned(),
                        );
                    }
                }
                Err(e) => report.fail(label, start.elapsed(), e),
            },
            Ok(_) => report.fail(label, start.elapsed(), "isError=true".to_owned()),
            Err(e) => report.fail(label, start.elapsed(), format!("{e:#}")),
        }
    }

    // Best-effort: call a low-risk, no-side-effects op. Anything else
    // (medium/high, or any write path) is out of scope for the light tier.
    //
    // Before invoking, fetch the op's JSON Schema via `mode=types`. If it
    // declares required properties, skip — the light tier does not
    // synthesize arguments, and a tool that needs input failing on empty
    // args would be a false negative. Otherwise call with `{}` and require
    // `isError=false` for pass; an `isError=true` response means the tool
    // itself reported a failure and must not be counted as green.
    match candidate_op {
        Some(op) => run_safe_call_probe(&client, &op, report).await,
        None => report.skip(
            "call.safe",
            "no operation advertised riskLevel=low && sideEffects=false",
        ),
    }

    if matches!(auth.mode, AuthModeArg::OauthCimd | AuthModeArg::Bearer) {
        // Authenticated round-trip implies the token was accepted — surface
        // that as its own PASS for the summary.
        report.pass("auth.accepted", Duration::ZERO);
    }

    let _ = client.cancel().await;
}

async fn run_safe_call_probe(client: &Client, op: &OperationDescriptor, report: &mut Report) {
    let label = format!("call.safe[{}]", op.name);
    let Some((server, _)) = op.name.split_once('.') else {
        report.skip(
            label,
            "candidate op name is not `<server>.<tool>`; cannot resolve searchTools meta-tool",
        );
        return;
    };

    let schema_start = Instant::now();
    let tool = format!("{server}{SEARCH_TOOLS_SUFFIX}");
    match fetch_types(client, &tool, &op.name).await {
        Ok(types) => {
            if schema_requires_input(&types.json_schema) {
                report.skip(
                    label,
                    "candidate op requires input; light tier does not synthesize arguments",
                );
                return;
            }
        }
        Err(reason) => {
            report.fail(
                label,
                schema_start.elapsed(),
                format!("mode=types: {reason}"),
            );
            return;
        }
    }

    let call_start = Instant::now();
    let params = CallToolRequestParams::new(op.name.clone());
    match client.call_tool(params).await {
        Ok(result) if !result.is_error.unwrap_or(false) => report.pass(label, call_start.elapsed()),
        Ok(result) => report.fail(
            label,
            call_start.elapsed(),
            format!("isError=true: {}", fallback_text(&result)),
        ),
        Err(e) => report.fail(label, call_start.elapsed(), format!("{e:#}")),
    }
}

pub(crate) async fn fetch_types(
    client: &Client,
    tool_name: &str,
    op_name: &str,
) -> std::result::Result<TypesResponse, String> {
    let req = SearchToolsRequest {
        mode: Mode::Types,
        filters: None,
        name: Some(op_name.to_owned()),
        cursor: None,
        limit: None,
    };
    let args = to_object(&req).map_err(|e| e.to_string())?;
    let params = CallToolRequestParams::new(tool_name.to_owned()).with_arguments(args);
    let result = client
        .call_tool(params)
        .await
        .map_err(|e| format!("{e:#}"))?;
    if result.is_error.unwrap_or(false) {
        return Err(format!("isError=true: {}", fallback_text(&result)));
    }
    if let Some(sc) = result.structured_content.as_ref() {
        return serde_json::from_value(sc.clone())
            .map_err(|e| format!("parse structuredContent: {e}"));
    }
    if let Some(text) = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
    {
        return serde_json::from_str(&text).map_err(|e| format!("parse text content: {e}"));
    }
    Err("no structuredContent or text content".to_owned())
}

/// `true` iff the schema has a non-empty `required` array. Anything else
/// (missing schema, schema without `required`, empty `required`) means the
/// tool accepts `{}` and the probe should proceed.
fn schema_requires_input(schema: &Value) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|arr| !arr.is_empty())
}

fn fallback_text(result: &rmcp::model::CallToolResult) -> String {
    for c in &result.content {
        if let Some(t) = c.as_text() {
            return t.text.clone();
        }
    }
    if let Some(sc) = &result.structured_content {
        return sc.to_string();
    }
    "<no content>".to_owned()
}

fn shapes_valid(resp: &OperationsResponse) -> bool {
    // Every op must carry a `name` (already guaranteed by the deserializer)
    // and a `risk_level` within the canonical enum. `next_cursor` is optional
    // and non-empty when present.
    for op in &resp.operations {
        match op.risk_level {
            RiskTier::Low | RiskTier::Medium | RiskTier::High => {}
        }
        if op.name.is_empty() {
            return false;
        }
    }
    if let Some(c) = &resp.next_cursor {
        if c.is_empty() {
            return false;
        }
    }
    true
}

fn safe_candidate(op: &OperationDescriptor) -> bool {
    matches!(op.risk_level, RiskTier::Low) && op.side_effects == Some(false)
}

fn to_object(req: &SearchToolsRequest) -> Result<Map<String, Value>> {
    match serde_json::to_value(req)? {
        Value::Object(m) => Ok(m),
        other => anyhow::bail!("SearchToolsRequest did not serialize as object: {other:?}"),
    }
}

pub(crate) fn parse_operations(
    result: &rmcp::model::CallToolResult,
) -> std::result::Result<OperationsResponse, String> {
    if let Some(sc) = &result.structured_content {
        return serde_json::from_value(sc.clone())
            .map_err(|e| format!("parse structuredContent: {e}"));
    }
    if let Some(text) = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| &t.text))
    {
        return serde_json::from_str(text).map_err(|e| format!("parse text content: {e}"));
    }
    Err("no structuredContent or text content".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_requires_input_detects_non_empty_required() {
        assert!(schema_requires_input(
            &json!({"type": "object", "required": ["query"]})
        ));
        assert!(schema_requires_input(
            &json!({"type": "object", "required": ["a", "b"]})
        ));
    }

    #[test]
    fn schema_requires_input_accepts_empty_or_missing_required() {
        assert!(!schema_requires_input(&json!({"type": "object"})));
        assert!(!schema_requires_input(
            &json!({"type": "object", "required": []})
        ));
        assert!(!schema_requires_input(&json!({})));
        // Malformed `required` (not an array) is treated as "no required
        // fields" — the probe's fallback is to attempt the call, which will
        // surface the error in its own right.
        assert!(!schema_requires_input(
            &json!({"type": "object", "required": "query"})
        ));
    }
}
