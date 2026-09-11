//! Exercises the four audit outcomes emitted by `dispatch_tool_call`:
//! Denied, StepUpRequired, Success, ExecutionError. Uses `InMemorySink` so
//! the test is hermetic — no Postgres needed — and an inline `AuthzGate`
//! that returns exactly the verdict each test needs.

use std::{num::NonZeroU32, sync::Arc};

use async_trait::async_trait;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock as Content, ErrorData as McpError, Tool,
};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use waygate_invocation::InvocationHierarchy;
use waygate_mcp::audit::{AuditOutcome, EvidenceCategory, EvidencePosture, InMemorySink};
use waygate_mcp::authz::{AuthzGate, AuthzVerdict, BuiltinAuthz, SharedAuthz, ToolFacts};
use waygate_mcp::catalog::{SharedCatalog, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{
    BuiltinCatalog, BuiltinSurfaceDescriptor, BuiltinToolDescriptor, BuiltinTools,
    DefaultInvocationService, GatewayServer, InvocationRequest, InvocationService, SharedEvidence,
};
use waygate_oidc::Principal;

struct FakeCatalog {
    fail_call: bool,
}

#[async_trait]
impl UpstreamCatalog for FakeCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-messages".into()]
    }
    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        let schema = json!({"type": "object"}).as_object().cloned().unwrap();
        Ok(vec![Tool::new(
            "send_message".to_string(),
            "send".to_string(),
            Arc::new(schema),
        )])
    }
    async fn call_tool(
        &self,
        _server: &str,
        _tool_name: &str,
        _args: Option<Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        if self.fail_call {
            Err(McpError::internal_error("upstream boom", None))
        } else {
            Ok(CallToolResult::success(vec![Content::text("ok")]))
        }
    }
    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool_name.into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
}

struct FixedVerdict(AuthzVerdict);

#[async_trait]
impl AuthzGate for FixedVerdict {
    async fn may_discover_server(&self, _p: &Principal, _s: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        match &self.0 {
            AuthzVerdict::Allow { policy_ids } => AuthzVerdict::Allow {
                policy_ids: policy_ids.clone(),
            },
            AuthzVerdict::Deny {
                reason,
                policy_ids,
                reasons,
            } => AuthzVerdict::Deny {
                reason: reason.clone(),
                policy_ids: policy_ids.clone(),
                reasons: reasons.clone(),
            },
            AuthzVerdict::StepUpRequired {
                required_scope,
                reason,
                policy_ids,
            } => AuthzVerdict::StepUpRequired {
                required_scope: required_scope.clone(),
                reason: reason.clone(),
                policy_ids: policy_ids.clone(),
            },
            AuthzVerdict::ApprovalRequired { reason, policy_ids } => {
                AuthzVerdict::ApprovalRequired {
                    reason: reason.clone(),
                    policy_ids: policy_ids.clone(),
                }
            }
        }
    }
}

fn principal() -> Principal {
    Principal {
        sub: "carol".into(),
        email: Some("carol@example.test".into()),
        groups: vec!["mcp-users".into()],
        issuer: "https://auth.example.test".into(),
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

fn build(verdict: AuthzVerdict, fail_call: bool) -> (GatewayServer, Arc<InMemorySink>) {
    let catalog: SharedCatalog = Arc::new(FakeCatalog { fail_call });
    let authz: SharedAuthz = Arc::new(FixedVerdict(verdict));
    let sink = Arc::new(InMemorySink::new());
    let audit: SharedEvidence = sink.clone();
    (GatewayServer::with_deps(catalog, authz, audit), sink)
}

async fn assert_single_posture(sink: &InMemorySink, expected: EvidencePosture) {
    let records = sink.snapshot_with_posture().await;
    assert_eq!(records.len(), 1, "expected exactly one evidence row");
    assert_eq!(records[0].posture, expected);
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object literal")
}

fn search_tools_call(server: &str, mode: &str) -> CallToolRequestParams {
    CallToolRequestParams::new(format!("{server}.searchTools"))
        .with_arguments(obj(json!({ "mode": mode })))
}

/// With `GATEWAY_AUDIT_DISCOVERY` on (via `with_audit_discovery`), a
/// `searchTools` call records exactly one best-effort `Discovery` row —
/// server + principal + outcome — so SEP #1888 discovery shows up in the
/// Activity feed (it was previously unaudited).
#[tokio::test]
async fn searchtools_records_discovery_when_enabled() {
    let (server, sink) = build(AuthzVerdict::Allow { policy_ids: vec![] }, false);
    let server = server.with_audit_discovery(true);
    server
        .dispatch_tool_call(
            search_tools_call("example-messages", "operations"),
            Some(&principal()),
        )
        .await
        .expect("discovery ok");

    let events = sink.snapshot().await;
    let disc: Vec<_> = events
        .iter()
        .filter(|e| e.category == EvidenceCategory::Discovery)
        .collect();
    assert_eq!(disc.len(), 1, "exactly one discovery row");
    let e = disc[0];
    assert_eq!(e.action, "SearchTools");
    assert_eq!(e.outcome, AuditOutcome::Success);
    assert_eq!(e.server.as_deref(), Some("example-messages"));
    assert_eq!(e.tool.as_deref(), Some("searchTools"));
    assert_eq!(e.principal.as_ref().map(|p| p.sub.as_str()), Some("carol"));
    assert_single_posture(&sink, EvidencePosture::BestEffort).await;
}

/// Discovery auditing is OFF by default (it is high-volume), so a
/// `searchTools` call records no `Discovery` row unless explicitly enabled.
#[tokio::test]
async fn searchtools_no_discovery_audit_by_default() {
    let (server, sink) = build(AuthzVerdict::Allow { policy_ids: vec![] }, false);
    server
        .dispatch_tool_call(
            search_tools_call("example-messages", "operations"),
            Some(&principal()),
        )
        .await
        .expect("discovery ok");

    let events = sink.snapshot().await;
    assert!(
        events
            .iter()
            .all(|e| e.category != EvidenceCategory::Discovery),
        "no discovery audit unless GATEWAY_AUDIT_DISCOVERY is enabled",
    );
}

#[tokio::test]
async fn success_records_latency_and_risk() {
    let (server, sink) = build(AuthzVerdict::Allow { policy_ids: vec![] }, false);
    server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.send_message"),
            Some(&principal()),
        )
        .await
        .expect("allow");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::Success);
    assert_eq!(e.action, "CallTool");
    assert_eq!(e.server.as_deref(), Some("example-messages"));
    assert_eq!(e.tool.as_deref(), Some("send_message"));
    assert_eq!(e.risk_level, Some(RiskTier::High));
    assert_eq!(e.principal.as_ref().map(|p| p.sub.as_str()), Some("carol"));
    assert!(e.latency_ms.is_some(), "success must record latency");
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}

// The allow twin of `denied_records_policies_and_reason`: an allowed call's
// SUCCESS audit row must record the Cedar permit ids that fired, so the
// Decision Log's `?policy_id=...` reverse lookup surfaces allow decisions for a
// permit policy (not just denials for a forbid). This is the end-to-end
// contract the gate-level `allow_verdict_carries_fired_permit_ids` test can't
// reach — it proves the ids are threaded all the way to the audit row.
#[tokio::test]
async fn success_records_fired_policy_ids() {
    let (server, sink) = build(
        AuthzVerdict::Allow {
            policy_ids: vec!["20-team-grant".into()],
        },
        false,
    );
    server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.send_message"),
            Some(&principal()),
        )
        .await
        .expect("allow");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::Success);
    assert_eq!(e.action, "CallTool");
    assert_eq!(
        e.policy_ids,
        vec!["20-team-grant".to_string()],
        "the success row must record the fired permit ids for the allow reverse lookup",
    );
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}

#[tokio::test]
async fn denied_records_policies_and_reason() {
    let (server, sink) = build(
        AuthzVerdict::Deny {
            reason: "forbid policies: policy0".into(),
            policy_ids: vec!["policy0".into()],
            reasons: vec!["policy0: principal lacks mcp:invoke:high".into()],
        },
        false,
    );
    let _ = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.send_message"),
            Some(&principal()),
        )
        .await
        .expect_err("deny");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::Denied);
    assert_eq!(e.policy_ids, vec!["policy0".to_string()]);
    assert!(e.reason.as_deref().unwrap_or("").contains("policy0"));
    assert!(e.latency_ms.is_none(), "denied never executed");
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}

#[tokio::test]
async fn step_up_records_required_scope_in_reason() {
    let (server, sink) = build(
        AuthzVerdict::StepUpRequired {
            required_scope: "mcp:invoke:high".into(),
            reason: "needs mfa".into(),
            policy_ids: vec!["30-step-up-grant".into()],
        },
        false,
    );
    let _ = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.send_message"),
            Some(&principal()),
        )
        .await
        .expect_err("step-up");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::StepUpRequired);
    let reason = e.reason.as_deref().unwrap_or("");
    assert!(reason.contains("mcp:invoke:high"));
    assert!(reason.contains("needs mfa"));
    // The step-up audit row records the re-eval permits, so the Decision Log
    // can reverse-lookup step-up decisions by policy id (matching the deny path).
    assert_eq!(e.policy_ids, vec!["30-step-up-grant".to_string()]);
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}

#[tokio::test]
async fn execution_error_records_reason() {
    let (server, sink) = build(AuthzVerdict::Allow { policy_ids: vec![] }, true);
    let _ = server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.send_message"),
            Some(&principal()),
        )
        .await
        .expect_err("upstream boom");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::ExecutionError);
    assert!(e.reason.as_deref().unwrap_or("").contains("upstream boom"));
    assert!(
        e.latency_ms.is_some(),
        "execution attempted → record latency"
    );
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}

// --- acting_agent attribution ------------------------------------------------
//
// The pipeline (`DefaultInvocationService::invoke`) copies the request's
// `acting_agent` onto every audit row it emits, so the log attributes an
// agent-initiated call to the agent WITHOUT losing the human as the authorizing
// principal. The `dispatch_tool_call` MCP adapter never sets it, so these drive
// `invoke` directly (the only path the agent runtime uses).

/// A bare `DefaultInvocationService` over the test fakes — used to drive `invoke`
/// directly with an `acting_agent`-bearing request (the adapter doesn't set it).
fn invocation(
    verdict: AuthzVerdict,
    fail_call: bool,
) -> (DefaultInvocationService, Arc<InMemorySink>) {
    let catalog: SharedCatalog = Arc::new(FakeCatalog { fail_call });
    let authz: SharedAuthz = Arc::new(FixedVerdict(verdict));
    let sink = Arc::new(InMemorySink::new());
    let audit: SharedEvidence = sink.clone();
    (DefaultInvocationService::new(catalog, authz, audit), sink)
}

#[tokio::test]
async fn acting_agent_is_stamped_on_a_success_row() {
    let (svc, sink) = invocation(AuthzVerdict::Allow { policy_ids: vec![] }, false);
    let req = InvocationRequest::new("example-messages", "send_message")
        .with_arguments(Some(obj(json!({}))))
        .with_acting_agent("agent:helper");
    svc.invoke(Some(&principal()), req).await.expect("allow");

    let events = sink.snapshot().await;
    assert!(!events.is_empty(), "a side-effecting success records a row");
    for e in &events {
        assert_eq!(
            e.acting_agent.as_deref(),
            Some("agent:helper"),
            "every row of an agent-initiated call carries the agent attribution",
        );
        // Attribution, not replacement: the human stays the authorizing principal.
        assert_eq!(e.principal.as_ref().map(|p| p.sub.as_str()), Some("carol"));
    }
}

#[tokio::test]
async fn acting_agent_is_stamped_on_a_denied_row() {
    let (svc, sink) = invocation(
        AuthzVerdict::Deny {
            reason: "forbid".into(),
            policy_ids: vec!["p0".into()],
            reasons: vec!["p0: nope".into()],
        },
        false,
    );
    let req = InvocationRequest::new("example-messages", "send_message")
        .with_arguments(Some(obj(json!({}))))
        .with_acting_agent("agent:helper");
    let _ = svc.invoke(Some(&principal()), req).await.expect_err("deny");

    let events = sink.snapshot().await;
    assert!(
        events.iter().any(|e| e.outcome == AuditOutcome::Denied),
        "a denied agent call is audited",
    );
    for e in &events {
        assert_eq!(e.acting_agent.as_deref(), Some("agent:helper"));
    }
}

#[tokio::test]
async fn invocation_hierarchy_is_stamped_on_success_and_denial_rows() {
    let hierarchy = InvocationHierarchy::new(
        Uuid::now_v7(),
        NonZeroU32::new(3).unwrap(),
        Uuid::now_v7(),
        NonZeroU32::new(2).unwrap(),
    );

    let (allowed, allowed_sink) = invocation(AuthzVerdict::Allow { policy_ids: vec![] }, false);
    allowed
        .invoke(
            Some(&principal()),
            InvocationRequest::new("example-messages", "send_message")
                .with_arguments(Some(obj(json!({}))))
                .with_hierarchy(hierarchy),
        )
        .await
        .expect("allow");

    let (denied, denied_sink) = invocation(
        AuthzVerdict::Deny {
            reason: "forbid".into(),
            policy_ids: vec!["p0".into()],
            reasons: vec!["p0: nope".into()],
        },
        false,
    );
    denied
        .invoke(
            Some(&principal()),
            InvocationRequest::new("example-messages", "send_message")
                .with_arguments(Some(obj(json!({}))))
                .with_hierarchy(hierarchy),
        )
        .await
        .expect_err("deny");

    let allowed_events = allowed_sink.snapshot().await;
    let denied_events = denied_sink.snapshot().await;
    assert!(!allowed_events.is_empty());
    assert!(!denied_events.is_empty());
    for event in allowed_events.iter().chain(&denied_events) {
        assert_eq!(event.invocation_hierarchy, Some(hierarchy));
    }
}

#[tokio::test]
async fn no_acting_agent_for_a_direct_call() {
    // A non-agent call leaves `acting_agent` unset (the always-Some sentinel
    // guard only fires when the value is genuinely present).
    let (svc, sink) = invocation(AuthzVerdict::Allow { policy_ids: vec![] }, false);
    let req = InvocationRequest::new("example-messages", "send_message")
        .with_arguments(Some(obj(json!({}))));
    svc.invoke(Some(&principal()), req).await.expect("allow");

    let events = sink.snapshot().await;
    assert!(!events.is_empty());
    for e in &events {
        assert!(
            e.acting_agent.is_none(),
            "a direct (non-agent) call must not carry an agent attribution",
        );
        assert!(
            e.invocation_hierarchy.is_none(),
            "a direct call must not acquire orchestrated execution attribution",
        );
    }
}

#[tokio::test]
async fn anonymous_allow_is_still_audited() {
    // principal = None means disabled-auth mode; we still want a row so the
    // audit log reflects what actually ran.
    let (server, sink) = build(AuthzVerdict::Allow { policy_ids: vec![] }, false);
    server
        .dispatch_tool_call(
            CallToolRequestParams::new("example-messages.send_message"),
            None,
        )
        .await
        .expect("allow");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, AuditOutcome::Success);
    assert!(events[0].principal.is_none());
}

// ---- Built-in forbid-overlay denials must be audited too ----
//
// Built-in overlay denials must not map straight to McpError without an
// audit row: the upstream tool plane records Denied / StepUpRequired, and
// the built-in plane must match. These tests pin parity for all three deny
// shapes.

/// Built-in stub classifying one High control tool so the overlay engages.
struct GovBuiltin;

#[async_trait]
impl BuiltinTools for GovBuiltin {
    fn namespace(&self) -> &str {
        "gateway-control"
    }
    fn catalog(&self) -> BuiltinCatalog {
        let definition = Tool::new(
            "gateway-control.quarantine_server".to_owned(),
            "quarantine an upstream".to_owned(),
            Arc::new(json!({"type": "object"}).as_object().unwrap().clone()),
        );
        BuiltinCatalog::from_descriptor(self.describe(), vec![definition])
    }
    fn describe(&self) -> BuiltinSurfaceDescriptor {
        BuiltinSurfaceDescriptor {
            namespace: "gateway-control".into(),
            required_scope: "mcp:admin".into(),
            summary: "stub control plane".into(),
            tools: vec![BuiltinToolDescriptor {
                name: "quarantine_server".into(),
                description: "quarantine an upstream".into(),
                risk: RiskTier::High,
                side_effects: true,
                pii: false,
            }],
        }
    }
    async fn list_tools(&self, _p: Option<&Principal>) -> Vec<Tool> {
        vec![]
    }
    async fn call(
        &self,
        _tool: &str,
        _args: Option<rmcp::model::JsonObject>,
        _p: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("quarantined")]))
    }
}

/// Gate whose built-in authorization reports the engine could not decide,
/// driving the overlay's fail-closed (Indeterminate) audit path.
struct IndeterminateAuthz;

#[async_trait]
impl AuthzGate for IndeterminateAuthz {
    async fn may_discover_server(&self, _p: &Principal, _s: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _f: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::Allow { policy_ids: vec![] }
    }
    async fn authorize_builtin_call(&self, _p: &Principal, _f: &ToolFacts) -> BuiltinAuthz {
        BuiltinAuthz::Indeterminate {
            reason: "engine could not evaluate".into(),
        }
    }
}

fn quarantine_call() -> CallToolRequestParams {
    CallToolRequestParams::new("gateway-control.quarantine_server")
}

#[tokio::test]
async fn builtin_forbid_is_audited_as_denied() {
    let (server, sink) = build(
        AuthzVerdict::Deny {
            reason: "forbid policies: 50-gateway-control".into(),
            policy_ids: vec!["50-gateway-control".into()],
            reasons: vec![],
        },
        false,
    );
    let server = server.with_builtin_tools(Arc::new(GovBuiltin));
    let _ = server
        .dispatch_tool_call(quarantine_call(), Some(&principal()))
        .await
        .expect_err("forbidden");

    let events = sink.snapshot().await;
    assert_eq!(
        events.len(),
        1,
        "exactly one audit row for the built-in denial"
    );
    let e = &events[0];
    assert_eq!(e.action, "CallTool");
    assert_eq!(e.outcome, AuditOutcome::Denied);
    assert_eq!(e.server.as_deref(), Some("gateway-control"));
    assert_eq!(e.tool.as_deref(), Some("quarantine_server"));
    assert_eq!(e.policy_ids, vec!["50-gateway-control".to_string()]);
    assert_eq!(e.risk_level, Some(RiskTier::High));
    assert_eq!(e.principal.as_ref().map(|p| p.sub.as_str()), Some("carol"));
    // A built-in gate decision carries the captured decision inputs, so
    // the impact replay can reconstruct it — a Cedar edit that flips this
    // built-in shows in the blast radius instead of being counted not-replayable.
    // `principal()` presents scope `mcp:invoke`, oauth, no roles; the
    // `quarantine_server` built-in declares `side_effects=true`.
    assert_eq!(e.req_scopes, vec!["mcp:invoke".to_string()]);
    assert_eq!(e.auth_method.as_deref(), Some("oauth"));
    assert!(e.req_roles.is_empty());
    assert_eq!(e.side_effects, Some(true));
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}

#[tokio::test]
async fn builtin_step_up_is_audited() {
    let (server, sink) = build(
        AuthzVerdict::StepUpRequired {
            required_scope: "mcp:invoke:high".into(),
            reason: "re-authorize".into(),
            policy_ids: vec!["30-step-up-builtin".into()],
        },
        false,
    );
    let server = server.with_builtin_tools(Arc::new(GovBuiltin));
    let _ = server
        .dispatch_tool_call(quarantine_call(), Some(&principal()))
        .await
        .expect_err("step-up");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::StepUpRequired);
    assert_eq!(e.server.as_deref(), Some("gateway-control"));
    assert!(e
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("mcp:invoke:high"));
    // The built-in step-up audit row records the step-up forbid ids, so the
    // Decision Log can reverse-look-up gateway-control built-in step-up
    // decisions by policy id.
    assert_eq!(e.policy_ids, vec!["30-step-up-builtin".to_string()]);
    // Built-in step-up decisions carry the captured decision inputs too,
    // so the impact replay can reconstruct them (same as the forbid path).
    assert_eq!(e.req_scopes, vec!["mcp:invoke".to_string()]);
    assert_eq!(e.auth_method.as_deref(), Some("oauth"));
    assert!(e.req_roles.is_empty());
    assert_eq!(e.side_effects, Some(true));
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}

#[tokio::test]
async fn builtin_indeterminate_is_audited_as_denied() {
    // Even the fail-closed engine-error path is visible in the feed.
    let sink = Arc::new(InMemorySink::new());
    let audit: SharedEvidence = sink.clone();
    let catalog: SharedCatalog = Arc::new(FakeCatalog { fail_call: false });
    let authz: SharedAuthz = Arc::new(IndeterminateAuthz);
    let server =
        GatewayServer::with_deps(catalog, authz, audit).with_builtin_tools(Arc::new(GovBuiltin));

    let _ = server
        .dispatch_tool_call(quarantine_call(), Some(&principal()))
        .await
        .expect_err("fail closed");

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.outcome, AuditOutcome::Denied);
    assert_eq!(e.server.as_deref(), Some("gateway-control"));
    assert!(e
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("authorization unavailable"));
    assert_single_posture(&sink, EvidencePosture::ChainedBestEffort).await;
}
