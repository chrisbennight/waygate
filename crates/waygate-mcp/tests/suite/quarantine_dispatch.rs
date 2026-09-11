//! Pins the enforcement half of the catalog quarantine endpoint.
//!
//! `POST /api/v1/catalog/servers/{id}/quarantine` flips a server's
//! status to `quarantined`, but that write only matters if the
//! invocation pipeline actually refuses calls to that server. The
//! pipeline learns the status through
//! `UpstreamCatalog::resolve_invocation_tool`, which returns
//! `ResolvedInvocationTool::Quarantined` for a quarantined/retired server. This
//! test drives a catalog fake that returns that variant and asserts the
//! pipeline refuses the call with `Forbidden` *before* dispatch — and,
//! crucially, that it does NOT fall back to the (still-classified)
//! manifest facts, since a fallback would defeat the quarantine.

use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, Tool};
use rmcp::ErrorData as McpError;
use waygate_invocation::{InvocationError, InvocationRequest, InvocationService};
use waygate_mcp::audit::NullSink;
use waygate_mcp::authz::{AllowAllGate, ToolFacts};
use waygate_mcp::catalog::{ResolvedInvocationTool, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::DefaultInvocationService;

/// Catalog fake whose `resolve_invocation_tool` always reports the server as
/// quarantined. `tool_facts` (the manifest fallback) still returns a
/// permissive Low-risk classification, so if the pipeline ever fell
/// back to it the call would wrongly succeed — the test would catch
/// that. `call_tool` would succeed if reached, so reaching it is itself
/// a failure of the quarantine.
struct QuarantinedCatalog;

struct UnavailableCatalog;

#[async_trait]
impl UpstreamCatalog for QuarantinedCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-messages".into()]
    }
    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(Vec::new())
    }
    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<serde_json::Map<String, serde_json::Value>>,
        _principal: Option<&waygate_oidc::Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        panic!("dispatch must not be reached for a quarantined server");
    }
    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        ToolFacts {
            server: server.to_owned(),
            name: tool_name.to_owned(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Quarantined {
            server: server.to_owned(),
            tool: tool_name.to_owned(),
        }
    }
}

#[async_trait]
impl UpstreamCatalog for UnavailableCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-messages".into()]
    }

    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(Vec::new())
    }

    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<serde_json::Map<String, serde_json::Value>>,
        _principal: Option<&waygate_oidc::Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        panic!("dispatch must not be reached while the catalog is unavailable");
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Unavailable {
            server: server.to_owned(),
            tool: tool_name.to_owned(),
        }
    }
}

#[tokio::test]
async fn quarantined_server_refuses_dispatch() {
    let svc: Arc<dyn InvocationService> = Arc::new(DefaultInvocationService::new(
        Arc::new(QuarantinedCatalog),
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    ));
    let req = InvocationRequest::new("example-messages", "send");
    let err = svc
        .invoke(None, req)
        .await
        .expect_err("quarantined server must refuse the call");
    match err {
        InvocationError::Forbidden {
            reason,
            policy_ids,
            reasons,
        } => {
            assert_eq!(reason, "server quarantined");
            // The block comes from catalog status, not a Cedar rule, so
            // there are no policy IDs (or Cedar reasons) to attribute
            // it to. `reasons` mirrors `policy_ids` for the
            // catalog-quarantine branch — both empty.
            assert!(policy_ids.is_empty());
            assert!(reasons.is_empty());
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[tokio::test]
async fn unavailable_catalog_refuses_dispatch_with_retryable_error() {
    let svc: Arc<dyn InvocationService> = Arc::new(DefaultInvocationService::new(
        Arc::new(UnavailableCatalog),
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    ));
    let err = svc
        .invoke(None, InvocationRequest::new("example-messages", "send"))
        .await
        .expect_err("catalog unavailability must refuse the call before dispatch");
    let InvocationError::Upstream(error) = err else {
        panic!("catalog unavailability must remain retryable, not a policy denial");
    };
    let data = error.data.expect("retryable catalog error data");
    assert_eq!(data["error"], "catalog_unavailable");
    assert_eq!(data["retryable"], true);
}
