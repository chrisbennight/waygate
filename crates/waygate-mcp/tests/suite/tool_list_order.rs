//! `tools/list` ordering contract.
//!
//! Hosts key prompt caches and client-side list caches on the exact tool
//! array, so the gateway promises the order rather than leaving it to
//! upstream or publication order. The canonical projections (MCP 2026, legacy
//! eager, and Code Mode-only) present one name-sorted order across built-in
//! and upstream tools. The legacy progressive projection presents tools in the
//! session's disclosure order. Neither depends on the order in which upstreams,
//! lanes, or reloads publish their tools, and an authorization filter removes
//! tools without moving the rest.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ErrorData as McpError, JsonObject, Tool};
use serde_json::{json, Map, Value};
use tokio::sync::RwLock;
use waygate_mcp::authz::{AuthzGate, AuthzVerdict};
use waygate_mcp::catalog::{InvocationContractIdentity, UpstreamCatalog};
use waygate_mcp::{BuiltinCatalog, BuiltinSurfaceDescriptor, BuiltinToolDescriptor, GatewayServer};
use waygate_oidc::Principal;

fn tool(name: &str) -> Tool {
    Tool::new(
        name.to_owned(),
        format!("{name} fixture"),
        Arc::new(
            json!({"type": "object", "properties": {}})
                .as_object()
                .cloned()
                .expect("object schema"),
        ),
    )
}

/// Upstream catalog whose server order and per-server tool order can be
/// rearranged between listings, standing in for a content-neutral reload or a
/// lane re-dial that republishes the same tools in another order.
struct ReorderingCatalog {
    servers: RwLock<Vec<(String, Vec<String>)>>,
}

impl ReorderingCatalog {
    fn new(servers: &[(&str, &[&str])]) -> Arc<Self> {
        Arc::new(Self {
            servers: RwLock::new(
                servers
                    .iter()
                    .map(|(server, tools)| {
                        (
                            (*server).to_owned(),
                            tools.iter().map(|tool| (*tool).to_owned()).collect(),
                        )
                    })
                    .collect(),
            ),
        })
    }

    /// Reverse the server order and every server's tool order.
    async fn republish_reversed(&self) {
        let mut servers = self.servers.write().await;
        servers.reverse();
        for (_, tools) in servers.iter_mut() {
            tools.reverse();
        }
    }
}

#[async_trait]
impl UpstreamCatalog for ReorderingCatalog {
    async fn list_servers(&self) -> Vec<String> {
        self.servers
            .read()
            .await
            .iter()
            .map(|(server, _)| server.clone())
            .collect()
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        self.servers
            .read()
            .await
            .iter()
            .find(|(name, _)| name == server)
            .map(|(_, tools)| tools.iter().map(|name| tool(name)).collect())
            .ok_or_else(|| McpError::invalid_params(format!("unknown server {server}"), None))
    }

    async fn call_tool(
        &self,
        _server: &str,
        _tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        unreachable!("ordering tests never dispatch a tool")
    }
}

/// A built-in namespace whose names sort between the two upstream servers, so
/// a projection that concatenated groups instead of ordering globally would
/// be visible.
struct MiddleBuiltin;

const BUILTIN_NAMESPACE: &str = "middle-ns";
const BUILTIN_TOOLS: [&str; 2] = ["zeta", "alpha"];

#[async_trait]
impl waygate_mcp::BuiltinTools for MiddleBuiltin {
    fn namespace(&self) -> &str {
        BUILTIN_NAMESPACE
    }

    fn catalog(&self) -> BuiltinCatalog {
        BuiltinCatalog::from_descriptor(
            self.describe(),
            BUILTIN_TOOLS
                .iter()
                .map(|name| tool(&format!("{BUILTIN_NAMESPACE}.{name}")))
                .collect(),
        )
    }

    fn describe(&self) -> BuiltinSurfaceDescriptor {
        BuiltinSurfaceDescriptor {
            namespace: BUILTIN_NAMESPACE.into(),
            required_scope: "mcp:read".into(),
            summary: "ordering fixture".into(),
            tools: BUILTIN_TOOLS
                .iter()
                .map(|name| BuiltinToolDescriptor {
                    name: (*name).into(),
                    description: format!("{BUILTIN_NAMESPACE}.{name} fixture"),
                    risk: waygate_core::RiskTier::Low,
                    side_effects: false,
                    pii: false,
                })
                .collect(),
        }
    }

    async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
        self.catalog().definitions()
    }

    async fn call(
        &self,
        _tool: &str,
        _arguments: Option<JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        unreachable!("ordering tests never dispatch a tool")
    }
}

/// Denies the named upstream tools to the principal `restricted`, allowing
/// everything else.
struct HideFromRestricted(HashSet<String>);

#[async_trait]
impl AuthzGate for HideFromRestricted {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }

    async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
        let qualified = format!("{}.{}", facts.resource.server, facts.resource.tool);
        if facts.principal.sub == "restricted" && self.0.contains(&qualified) {
            AuthzVerdict::Deny {
                reason: "hidden from this principal".into(),
                policy_ids: vec!["forbid-fixture".into()],
                reasons: vec![],
            }
        } else {
            AuthzVerdict::Allow {
                policy_ids: vec!["permit-fixture".into()],
            }
        }
    }
}

fn principal(sub: &str) -> Principal {
    Principal {
        sub: sub.into(),
        email: None,
        groups: vec![],
        issuer: "https://issuer.example.test".into(),
        scopes: vec!["mcp:invoke".into(), "mcp:read".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn names(tools: &[Tool]) -> Vec<String> {
    tools.iter().map(|tool| tool.name.to_string()).collect()
}

fn fixture_catalog() -> Arc<ReorderingCatalog> {
    ReorderingCatalog::new(&[
        ("zulu-srv", &["mike", "bravo"]),
        ("alpha-srv", &["yankee", "echo"]),
    ])
}

#[tokio::test]
async fn canonical_projection_orders_builtin_and_upstream_tools_globally() {
    let server = GatewayServer::new(fixture_catalog())
        .with_builtin_tools(Arc::new(MiddleBuiltin))
        .with_eager_tools_list(true);

    let listed = names(&server.list_visible_tools(None).await);

    let mut sorted = listed.clone();
    sorted.sort();
    assert_eq!(listed, sorted, "one name order across every group");
    let position = |name: &str| {
        listed
            .iter()
            .position(|listed| listed == name)
            .unwrap_or_else(|| panic!("{name} listed in {listed:?}"))
    };
    assert!(position("alpha-srv.yankee") < position("middle-ns.alpha"));
    assert!(position("middle-ns.zeta") < position("zulu-srv.bravo"));
}

#[tokio::test]
async fn canonical_projection_ignores_the_order_upstreams_publish_in() {
    let catalog = fixture_catalog();
    let server = GatewayServer::new(catalog.clone())
        .with_builtin_tools(Arc::new(MiddleBuiltin))
        .with_eager_tools_list(true);

    let before = server.list_visible_tools(None).await;
    catalog.republish_reversed().await;
    let after = server.list_visible_tools(None).await;

    assert_eq!(
        serde_json::to_value(&before).expect("serialize"),
        serde_json::to_value(&after).expect("serialize"),
        "republishing the same tools in another order must not change the array"
    );
}

#[tokio::test]
async fn authorization_filtering_removes_tools_without_reordering_the_rest() {
    let hidden: HashSet<String> = ["alpha-srv.echo".to_owned(), "zulu-srv.mike".to_owned()]
        .into_iter()
        .collect();
    let server = GatewayServer::with_authz(
        fixture_catalog(),
        Arc::new(HideFromRestricted(hidden.clone())),
    )
    .with_builtin_tools(Arc::new(MiddleBuiltin))
    .with_eager_tools_list(true);

    let full = names(&server.list_visible_tools(Some(&principal("full"))).await);
    let restricted = names(
        &server
            .list_visible_tools(Some(&principal("restricted")))
            .await,
    );

    let expected: Vec<String> = full
        .iter()
        .filter(|name| !hidden.contains(*name))
        .cloned()
        .collect();
    assert!(
        full.len() > restricted.len(),
        "the filter removed tools: {full:?} vs {restricted:?}"
    );
    assert_eq!(
        restricted, expected,
        "the restricted view is the full view minus hidden tools, in the same order"
    );
    assert_eq!(
        restricted,
        names(
            &server
                .list_visible_tools(Some(&principal("restricted")))
                .await
        ),
        "each principal's view is stable across listings"
    );
}

#[tokio::test]
async fn disclosure_order_projection_ignores_the_order_upstreams_publish_in() {
    let catalog = fixture_catalog();
    let server = GatewayServer::new(catalog.clone()).with_builtin_tools(Arc::new(MiddleBuiltin));
    server
        .disclosed()
        .record(["zulu-srv.mike", "alpha-srv.echo", "zulu-srv.bravo"]);

    let before = names(&server.list_visible_tools(None).await);
    catalog.republish_reversed().await;
    let after = names(&server.list_visible_tools(None).await);

    assert_eq!(before, after, "upstream publication order must not leak in");
    assert_eq!(
        before,
        [
            "alpha-srv.searchTools",
            "zulu-srv.searchTools",
            "middle-ns.zeta",
            "middle-ns.alpha",
            "alpha-srv.echo",
            "zulu-srv.mike",
            "zulu-srv.bravo",
        ],
        "meta-tools by server name, built-ins in declaration order, then disclosed \
         tools grouped by server name in disclosure order"
    );
}
