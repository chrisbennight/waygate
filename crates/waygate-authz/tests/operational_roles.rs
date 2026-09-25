//! Controlled operational-role fixture: real Cedar and invocation pipeline,
//! with an in-process upstream that cannot contact an external system.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use rmcp::{
    model::{CallToolRequestParams, CallToolResult, Tool},
    ErrorData as McpError,
};
use serde_json::{json, Map, Value};
use waygate_authz::{CedarEngine, CedarGate};
use waygate_mcp::{
    authz::ToolFacts,
    catalog::{InvocationContractIdentity, UpstreamCatalog},
    protocol::RiskTier,
    GatewayServer,
};
use waygate_oidc::Principal;

const SERVER: &str = "operational-fixture";
const TOOLS: &[&str] = &[
    "stacks.status",
    "stacks.compose.read",
    "stacks.restart",
    "stacks.compose.write",
];
const POLICY: &str = r#"
permit(principal, action in [Action::"ListTools", Action::"SearchTools"], resource);
permit(principal, action == Action::"CallTool", resource is Tool)
when { resource.server == "operational-fixture" && !resource.side_effects && !resource.pii };
permit(principal in Group::"sensitive-readers", action == Action::"CallTool", resource is Tool)
when { resource.server == "operational-fixture" && !resource.side_effects };
permit(principal in Group::"operators", action == Action::"CallTool", resource is Tool)
when { resource.server == "operational-fixture" && !resource.pii };
permit(principal in Group::"administrators", action == Action::"CallTool", resource is Tool)
when { resource.server == "operational-fixture" };
@id("configuration-approval")
@layer("approval-overlay")
forbid(principal, action == Action::"CallTool", resource is Tool)
when { resource.server == "operational-fixture" && resource.side_effects && resource.pii && !context.approval_present };
"#;

#[derive(Default)]
struct Upstream {
    calls: AtomicUsize,
}

#[async_trait]
impl UpstreamCatalog for Upstream {
    async fn list_servers(&self) -> Vec<String> {
        vec![SERVER.to_owned()]
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        assert_eq!(server, SERVER);
        Ok(TOOLS
            .iter()
            .map(|name| {
                Tool::new(
                    *name,
                    "Synthetic bounded operation",
                    Arc::new(
                        json!({"type":"object", "properties":{}, "additionalProperties":false})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                )
            })
            .collect())
    }

    fn tool_facts(&self, server: &str, name: &str) -> ToolFacts {
        assert_eq!(server, SERVER);
        assert!(TOOLS.contains(&name));
        ToolFacts {
            server: server.to_owned(),
            name: name.to_owned(),
            risk: if name.ends_with("write") {
                RiskTier::High
            } else {
                RiskTier::Low
            },
            side_effects: name.ends_with("write") || name.ends_with("restart"),
            pii: name.contains("compose"),
            requires_approval: false,
            requires_approval_known: true,
        }
    }

    async fn call_tool(
        &self,
        server: &str,
        name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        assert_eq!(server, SERVER);
        assert!(TOOLS.contains(&name));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CallToolResult::structured(json!({"synthetic":true})))
    }
}

fn principal(group: &str) -> Principal {
    Principal {
        sub: format!("fixture-{group}"),
        email: None,
        groups: vec![group.to_owned()],
        issuer: "https://identity.example.test".to_owned(),
        scopes: vec!["mcp:invoke".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

#[tokio::test]
async fn discovery_and_direct_dispatch_enforce_operational_role_matrix() {
    let engine = CedarEngine::from_source(POLICY).expect("valid synthetic policy");
    let upstream = Arc::new(Upstream::default());
    let server =
        GatewayServer::with_authz(upstream.clone(), Arc::new(CedarGate::new(Arc::new(engine))))
            .with_eager_tools_list(true);
    // allow, deny, and approval-required are distinct outcomes. Approval never
    // grants an underlying permit and discovery never authorizes execution.
    for (role, expected) in [
        ("readers", ["allow", "forbidden", "forbidden", "forbidden"]),
        (
            "sensitive-readers",
            ["allow", "allow", "forbidden", "forbidden"],
        ),
        ("operators", ["allow", "forbidden", "allow", "forbidden"]),
        (
            "administrators",
            ["allow", "allow", "allow", "approval_required"],
        ),
    ] {
        let principal = principal(role);
        let visible = server.list_visible_tools(Some(&principal)).await;
        for (name, outcome) in TOOLS.iter().zip(expected) {
            let qualified = format!("{SERVER}.{name}");
            assert_eq!(
                visible.iter().any(|tool| tool.name == qualified),
                outcome != "forbidden",
                "discovery: {role} {name}"
            );
            let before = upstream.calls.load(Ordering::SeqCst);
            let result = server
                .dispatch_tool_call(
                    CallToolRequestParams::new(qualified).with_arguments(Map::new()),
                    Some(&principal),
                )
                .await;
            if outcome == "allow" {
                assert!(result.is_ok(), "dispatch: {role} {name}: {result:?}");
                assert_eq!(upstream.calls.load(Ordering::SeqCst), before + 1);
            } else {
                let error =
                    result.expect_err("excluded and unapproved operations must not dispatch");
                assert_eq!(
                    error
                        .data
                        .as_ref()
                        .and_then(|v| v.get("error"))
                        .and_then(Value::as_str),
                    Some(outcome),
                    "dispatch: {role} {name}: {error:?}"
                );
                assert_eq!(upstream.calls.load(Ordering::SeqCst), before);
            }
        }
    }
}
