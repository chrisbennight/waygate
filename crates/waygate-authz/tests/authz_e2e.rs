//! End-to-end authz: real CedarEngine + real policies (`00-deny-by-default`
//! + `10-role-allow`) driving `GatewayServer` via the `CedarGate` adapter.
//!
//! Exercises the full path the live gateway takes on every request:
//!   RequestContext → Principal → AuthzGate → CedarEngine → Decision.
//! The upstream is an in-process fake so we don't have to stand up a real MCP
//! server just to watch the authz gate fire.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock as Content, ErrorData as McpError, Tool,
};
use serde_json::{json, Map, Value};

use waygate_authz::{CedarEngine, CedarGate};
use waygate_mcp::authz::{SharedAuthz, ToolFacts};
use waygate_mcp::catalog::{SharedCatalog, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::GatewayServer;
use waygate_oidc::Principal;

/// Fake upstream pool that knows which tools are high-risk vs low-risk. The
/// authz gate interrogates `tool_facts` on every call, so overriding it here
/// is how we drive a non-admin → high-risk deny path without a YAML manifest.
struct FakeCatalog {
    server: String,
    low_tool: String,
    high_tool: String,
    // A high-risk tool that is ALSO the step-up canary (name == "delete_dataset",
    // matched by crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar). Distinct from `high_tool`, which is
    // high-risk but NOT step-up-gated — the two together prove step-up is
    // decoupled from the risk tier.
    step_up_tool: String,
}

#[async_trait]
impl UpstreamCatalog for FakeCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec![self.server.clone()]
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        if server != self.server {
            return Err(McpError::invalid_params(
                format!("unknown server {server}"),
                None,
            ));
        }
        let schema = json!({"type": "object", "properties": {}})
            .as_object()
            .cloned()
            .unwrap();
        Ok(vec![
            Tool::new(self.low_tool.clone(), "read-only", Arc::new(schema.clone())),
            Tool::new(
                self.high_tool.clone(),
                "destructive",
                Arc::new(schema.clone()),
            ),
            Tool::new(self.step_up_tool.clone(), "irreversible", Arc::new(schema)),
        ])
    }

    async fn call_tool(
        &self,
        server: &str,
        tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "called {server}.{tool_name}"
        ))]))
    }

    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        let risk = if tool_name == self.high_tool || tool_name == self.step_up_tool {
            RiskTier::High
        } else {
            RiskTier::Low
        };
        ToolFacts {
            server: server.to_owned(),
            name: tool_name.to_owned(),
            risk,
            side_effects: risk == RiskTier::High,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
}

fn policies_dir() -> PathBuf {
    // crate manifest dir → workspace root → the policies fixture dir
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("crates/waygate-authz/tests/fixtures/policies")
}

fn build_server() -> GatewayServer {
    let engine =
        CedarEngine::load_dir(&policies_dir()).expect("load policies from workspace policies/");
    let gate: SharedAuthz = Arc::new(CedarGate::new(Arc::new(engine)));
    let catalog: SharedCatalog = Arc::new(FakeCatalog {
        server: "example-messages".into(),
        low_tool: "contacts.list".into(),
        high_tool: "messages.send".into(),
        step_up_tool: "delete_dataset".into(),
    });
    GatewayServer::with_authz(catalog, gate)
}

fn principal(sub: &str, groups: &[&str]) -> Principal {
    principal_with_scopes(sub, groups, &["mcp:invoke"])
}

fn principal_with_scopes(sub: &str, groups: &[&str], scopes: &[&str]) -> Principal {
    Principal {
        sub: sub.into(),
        email: Some(format!("{sub}@example.test")),
        groups: groups.iter().map(|g| (*g).to_string()).collect(),
        issuer: "https://auth.example.test".into(),
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

#[tokio::test]
async fn admin_can_call_high_risk_tool() {
    let server = build_server();
    // Admin with the step-up scope already in hand — this test is about the
    // role-allow path, not step-up. A parallel test below covers the flow
    // where the admin hasn't re-authorized yet.
    let admin = principal_with_scopes("alice", &["mcp-admins"], &["mcp:invoke", "mcp:invoke:high"]);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.messages.send")
                .with_arguments(obj(json!({"to": "bob"}))),
            Some(&admin),
        )
        .await
        .expect("admin should pass authz on high-risk tool");

    // Upstream fake returned the success envelope unchanged.
    assert!(result.is_error != Some(true));
}

#[tokio::test]
async fn generic_high_risk_tool_is_not_step_up_gated() {
    // Decouple proof: a high-risk tool that is NOT the step-up canary
    // (`messages.send`, not `delete_dataset`) carries no step-up forbid. An admin
    // WITHOUT the mcp:invoke:high scope is allowed straight through on the
    // role-allow path — `high` no longer implies a step-up prompt.
    let server = build_server();
    let admin = principal("alice", &["mcp-admins"]); // no mcp:invoke:high scope

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.messages.send")
                .with_arguments(obj(json!({"to": "bob"}))),
            Some(&admin),
        )
        .await
        .expect("generic high-risk tool must NOT require step-up (decoupled from risk)");

    assert!(result.is_error != Some(true));
}

#[tokio::test]
async fn admin_without_step_up_scope_gets_step_up_error() {
    let server = build_server();
    // Admin has the role permit but NOT the `mcp:invoke:high` scope. Cedar's
    // `30-step-up.cedar` forbid blocks the first pass; the engine re-evaluates
    // with the scope added and detects a deny→allow flip, so dispatch returns
    // a structured `insufficient_scope` error instead of a flat forbidden.
    let admin = principal("alice", &["mcp-admins"]);

    let err = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.delete_dataset")
                .with_arguments(obj(json!({"to": "bob"}))),
            Some(&admin),
        )
        .await
        .expect_err("step-up required without mcp:invoke:high");

    let data = err.data.as_ref().expect("structured error data");
    assert_eq!(
        data.get("error").and_then(|v| v.as_str()),
        Some("insufficient_scope"),
    );
    assert_eq!(
        data.get("required_scope").and_then(|v| v.as_str()),
        Some("mcp:invoke:high"),
    );
    assert!(
        err.message.contains("step-up required"),
        "message should mention step-up: {}",
        err.message
    );
}

#[tokio::test]
async fn user_blocked_on_high_risk_tool() {
    let server = build_server();
    let user = principal("carol", &["mcp-users"]);

    let err = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.delete_dataset")
                .with_arguments(obj(json!({"to": "bob"}))),
            Some(&user),
        )
        .await
        .expect_err("non-admin high-risk call must be denied");

    // `forbidden()` maps to JSON-RPC invalid_request with a recognizable
    // prefix — downstream consumers (Inspector, agent clients) can match on it.
    let msg = format!("{err}");
    assert!(
        msg.contains("forbidden"),
        "message did not advertise deny: {msg}"
    );
    assert!(msg.contains("delete_dataset"), "missing tool name: {msg}");

    // The JSON-RPC `data` envelope must also carry the structured
    // fields — a client that only parses the human message would miss
    // them, but Codex / the Inspector / the admin audit
    // deep-link all read `data`. Pin the contract end-to-end:
    // - `error: "forbidden"` discriminator
    // - `policy_ids` non-empty (the step-up forbid policy
    //   fired by name)
    // - `reasons` non-empty AND contains the operator-facing
    //   text from the `@reason("...")` annotation on
    //   `crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar`.
    let data = err
        .data
        .as_ref()
        .expect("forbidden response must carry a structured data envelope");
    let obj = data
        .as_object()
        .expect("data envelope must be a JSON object");
    assert_eq!(
        obj.get("error").and_then(Value::as_str),
        Some("forbidden"),
        "data.error discriminator missing or wrong: {data}",
    );
    let policy_ids = obj
        .get("policy_ids")
        .and_then(Value::as_array)
        .expect("data.policy_ids must be a JSON array");
    assert!(
        !policy_ids.is_empty(),
        "data.policy_ids must name the fired forbid policy ({data})",
    );
    let reasons = obj
        .get("reasons")
        .and_then(Value::as_array)
        .expect("data.reasons must be a JSON array");
    assert!(
        reasons
            .iter()
            .filter_map(Value::as_str)
            .any(|r| r.contains("mcp:invoke:high")),
        "data.reasons must include the @reason annotation from \
         crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar mentioning the required scope ({data})",
    );
}

#[tokio::test]
async fn user_can_call_low_risk_tool() {
    let server = build_server();
    let user = principal("carol", &["mcp-users"]);

    server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.contacts.list"),
            Some(&user),
        )
        .await
        .expect("non-admin low-risk call must be allowed");
}

#[tokio::test]
async fn search_tools_filters_high_risk_for_non_admins() {
    let server = build_server();
    let user = principal("carol", &["mcp-users"]);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            Some(&user),
        )
        .await
        .expect("searchTools must not itself be blocked");

    let ops = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .expect("operations array");
    let names: Vec<&str> = ops
        .iter()
        .map(|o| o.get("name").and_then(|v| v.as_str()).unwrap())
        .collect();

    // Non-admin only sees the low-risk tool; the high-risk one is filtered out
    // because Cedar denies CallTool for resource.risk != "low".
    assert!(names.contains(&"example-messages.contacts.list"));
    assert!(
        !names.contains(&"example-messages.messages.send"),
        "non-admin should not see high-risk tool in search results: {names:?}"
    );
}

#[tokio::test]
async fn search_tools_shows_everything_for_admin() {
    let server = build_server();
    let admin = principal("alice", &["mcp-admins"]);

    let result = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.searchTools")
                .with_arguments(obj(json!({"mode": "operations"}))),
            Some(&admin),
        )
        .await
        .expect("admin searchTools");

    let ops = result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("operations"))
        .and_then(|v| v.as_array())
        .unwrap();
    let names: Vec<&str> = ops
        .iter()
        .map(|o| o.get("name").and_then(|v| v.as_str()).unwrap())
        .collect();

    assert!(names.contains(&"example-messages.contacts.list"));
    assert!(names.contains(&"example-messages.messages.send"));
}

#[tokio::test]
async fn list_meta_tools_hides_servers_no_one_can_discover() {
    // Baseline forbid + role-allow both permit SearchTools for any principal,
    // so every authenticated caller sees the meta-tool. This test pins that
    // expectation so a future policy change can't silently hide servers.
    let server = build_server();
    let user = principal("carol", &["mcp-users"]);

    let metas = server.list_meta_tools(Some(&user)).await;
    let names: Vec<&str> = metas.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, vec!["example-messages.searchTools"]);
}
