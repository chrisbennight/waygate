//! Pins the enforcement half of catalog refusals at Stage 1.
//!
//! `POST /api/v1/catalog/servers/{id}/quarantine` flips a server's
//! status to `quarantined`, but that write only matters if the
//! invocation pipeline actually refuses calls to that server. The
//! pipeline learns why a tool will not run through
//! `UpstreamCatalog::resolve_invocation_tool`. These tests drive a catalog
//! fake that returns each kind of result and assert the pipeline refuses
//! *before* dispatch — and, crucially, that it does NOT fall back to the
//! (still-classified) manifest facts, since a fallback would defeat the
//! refusal.
//!
//! They also pin what the caller sees: a blocked server is named only to a
//! caller who may discover it, every per-tool reason shares the absent-tool
//! error, and the precise reason reaches the audit record alone.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, Tool};
use rmcp::ErrorData as McpError;
use serde_json::Value;
use uuid::Uuid;
use waygate_invocation::{InvocationError, InvocationRequest, InvocationService};
use waygate_mcp::audit::{AuditEvent, AuditOutcome, EvidenceError, EvidenceRecorder};
use waygate_mcp::authz::{AllowAllGate, AuthzGate, AuthzVerdict, SharedAuthz, ToolFacts};
use waygate_mcp::catalog::{
    ResolvedInvocationTool, TemporaryUnavailability, ToolRefusal, UpstreamCatalog,
};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::DefaultInvocationService;
use waygate_oidc::{ApiKeyProfileRestrictions, Principal};

/// What the catalog fake reports for every tool.
#[derive(Clone, Copy, Debug)]
enum Outcome {
    Refused(ToolRefusal),
    Unavailable(TemporaryUnavailability),
}

/// Catalog fake whose `resolve_invocation_tool` always reports `outcome`.
/// `tool_facts` (the manifest fallback) still returns a permissive Low-risk
/// classification, so if the pipeline ever fell back to it the call would
/// wrongly succeed — the test would catch that. `call_tool` would succeed if
/// reached, so reaching it is itself a failure of the refusal.
struct ScriptedCatalog(Outcome);

#[async_trait]
impl UpstreamCatalog for ScriptedCatalog {
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
        panic!("dispatch must not be reached for a refused tool");
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
        match self.0 {
            Outcome::Refused(reason) => ResolvedInvocationTool::refused(server, tool_name, reason),
            Outcome::Unavailable(reason) => {
                ResolvedInvocationTool::unavailable(server, tool_name, reason)
            }
        }
    }
}

/// Keeps every audit event so a test can read the recorded reason.
#[derive(Default)]
struct RecordingSink(Mutex<Vec<AuditEvent>>);

#[async_trait]
impl EvidenceRecorder for RecordingSink {
    async fn record_required(&self, event: AuditEvent) -> Result<Uuid, EvidenceError> {
        let id = event.id;
        self.0.lock().unwrap().push(event);
        Ok(id)
    }
    async fn record_chained_best_effort(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
    async fn record_best_effort(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

/// Cedar stand-in that would allow the call but lets no one discover any
/// server, as a policy confining a caller away from a namespace does.
struct NoDiscoveryGate;

#[async_trait]
impl AuthzGate for NoDiscoveryGate {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        false
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }
}

fn principal(restrictions: Option<ApiKeyProfileRestrictions>) -> Principal {
    Principal {
        sub: "caller".into(),
        email: None,
        groups: vec![],
        issuer: "https://auth.example.test".into(),
        scopes: vec!["mcp:invoke".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: restrictions,
    }
}

/// A credential profile confined to a different server.
fn confined_elsewhere() -> Principal {
    principal(Some(ApiKeyProfileRestrictions {
        profile_id: "profile-1".into(),
        profile_name: "other-only".into(),
        allowed_servers: Some(vec!["example-catalog".into()]),
        allowed_tools: None,
    }))
}

/// Invoke `example-messages.send` against `outcome` and return the error with
/// the audit events the pipeline recorded.
async fn refuse(
    outcome: Outcome,
    gate: SharedAuthz,
    caller: Option<&Principal>,
) -> (InvocationError, Vec<AuditEvent>) {
    let sink = Arc::new(RecordingSink::default());
    let svc = DefaultInvocationService::new(Arc::new(ScriptedCatalog(outcome)), gate, sink.clone());
    let err = svc
        .invoke(caller, InvocationRequest::new("example-messages", "send"))
        .await
        .expect_err("a refused tool must refuse the call");
    let events = sink.0.lock().unwrap().clone();
    (err, events)
}

fn recorded_reasons(events: &[AuditEvent]) -> Vec<(AuditOutcome, Option<String>)> {
    events
        .iter()
        .map(|event| (event.outcome, event.reason.clone()))
        .collect()
}

/// The wire error with its trace id removed, after checking it is present.
fn without_trace_id(error: McpError) -> (i32, String, Value) {
    let mut data = error.data.expect("structured error data");
    let trace_id = data
        .as_object_mut()
        .expect("object data")
        .remove("trace_id")
        .expect("refusal carries a trace id");
    assert!(
        trace_id.as_str().is_some_and(|id| !id.is_empty()),
        "trace id is a non-empty string: {trace_id}"
    );
    (error.code.0, error.message.to_string(), data)
}

fn wire(error: InvocationError) -> McpError {
    waygate_mcp::server::tool_call_error(error, "example-messages", "send")
}

#[tokio::test]
async fn quarantined_server_refuses_dispatch() {
    // No principal is the auth-disabled mode: every server is visible.
    let (err, events) = refuse(
        Outcome::Refused(ToolRefusal::ServerQuarantined),
        Arc::new(AllowAllGate),
        None,
    )
    .await;
    match &err {
        InvocationError::Forbidden {
            reason,
            policy_ids,
            reasons,
            trace_id,
        } => {
            assert_eq!(reason, "server quarantined");
            // The block comes from catalog status, not a Cedar rule, so
            // there are no policy IDs (or Cedar reasons) to attribute
            // it to. The trace id stands in as the operator's reference.
            assert!(policy_ids.is_empty());
            assert!(reasons.is_empty());
            assert!(trace_id.as_deref().is_some_and(|id| !id.is_empty()));
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
    assert_eq!(
        recorded_reasons(&events),
        vec![(
            AuditOutcome::Denied,
            Some("refused:server_quarantined".to_owned())
        )],
    );
    let (code, message, data) = without_trace_id(wire(err));
    assert_eq!(code, rmcp::model::ErrorCode::INVALID_REQUEST.0);
    assert_eq!(
        message,
        "forbidden: example-messages.send — server quarantined"
    );
    assert_eq!(
        data,
        serde_json::json!({
            "error": "forbidden",
            "reason": "server quarantined",
            "policy_ids": [],
            "reasons": [],
        })
    );
}

#[tokio::test]
async fn blocked_server_is_named_to_a_caller_who_may_discover_it() {
    let caller = principal(None);
    for (refusal, expected) in [
        (ToolRefusal::ServerQuarantined, "server quarantined"),
        (ToolRefusal::ServerRetired, "server retired"),
    ] {
        let (err, events) = refuse(
            Outcome::Refused(refusal),
            Arc::new(AllowAllGate),
            Some(&caller),
        )
        .await;
        assert!(
            matches!(&err, InvocationError::Forbidden { reason, .. } if reason == expected),
            "{expected}: {err:?}"
        );
        assert_eq!(
            events[0].reason.as_deref(),
            Some(format!("refused:{}", refusal.code()).as_str())
        );
    }
}

#[tokio::test]
async fn blocked_server_is_not_revealed_to_a_caller_who_cannot_discover_it() {
    let hidden_by_policy = principal(None);
    let hidden_by_profile = confined_elsewhere();
    let cases: [(SharedAuthz, &Principal); 2] = [
        (Arc::new(NoDiscoveryGate), &hidden_by_policy),
        (Arc::new(AllowAllGate), &hidden_by_profile),
    ];
    for (gate, caller) in cases {
        let (err, events) = refuse(
            Outcome::Refused(ToolRefusal::ServerQuarantined),
            gate,
            Some(caller),
        )
        .await;
        assert!(
            matches!(&err, InvocationError::ToolUnavailable { tool, .. } if tool == "example-messages.send"),
            "{err:?}"
        );
        // Administrators still see the precise reason.
        assert_eq!(
            recorded_reasons(&events),
            vec![(
                AuditOutcome::Denied,
                Some("refused:server_quarantined".to_owned())
            )],
        );
    }
}

#[tokio::test]
async fn temporary_condition_is_not_revealed_to_a_caller_who_cannot_discover_the_server() {
    let hidden_by_policy = principal(None);
    let hidden_by_profile = confined_elsewhere();
    let cases: [(SharedAuthz, &Principal); 2] = [
        (Arc::new(NoDiscoveryGate), &hidden_by_policy),
        (Arc::new(AllowAllGate), &hidden_by_profile),
    ];
    for (gate, caller) in cases {
        let (err, events) = refuse(
            Outcome::Unavailable(TemporaryUnavailability::NoConnectedLane),
            gate,
            Some(caller),
        )
        .await;
        assert!(
            matches!(&err, InvocationError::ToolUnavailable { tool, .. } if tool == "example-messages.send"),
            "{err:?}"
        );
        assert_eq!(
            recorded_reasons(&events),
            vec![(
                AuditOutcome::ExecutionError,
                Some("unavailable:no_connected_lane".to_owned())
            )],
        );
    }
}

#[tokio::test]
async fn the_audit_row_carries_the_trace_id_the_caller_receives() {
    // No OpenTelemetry context is active here, so the trace id is the
    // generated fallback that only this refusal knows.
    let hidden = confined_elsewhere();
    let visible = principal(None);
    let cases: [(Outcome, &Principal); 4] = [
        (Outcome::Refused(ToolRefusal::ServerQuarantined), &visible),
        (Outcome::Refused(ToolRefusal::KeptBlocked), &visible),
        (
            Outcome::Unavailable(TemporaryUnavailability::CatalogConverging),
            &visible,
        ),
        (
            Outcome::Unavailable(TemporaryUnavailability::NoConnectedLane),
            &hidden,
        ),
    ];
    for (outcome, caller) in cases {
        let (err, events) = refuse(outcome, Arc::new(AllowAllGate), Some(caller)).await;
        // Code Mode passes on only the error's text, so it must name the id.
        let text = err.to_string();
        let data = wire(err).data.expect("structured error data");
        let returned = data["trace_id"].as_str().expect("trace id in the error");
        assert_eq!(events.len(), 1, "{outcome:?}");
        assert_eq!(
            events[0].trace_id.as_deref(),
            Some(returned),
            "{outcome:?}: the audit row must be findable by the caller's trace id"
        );
        assert!(
            text.contains(&format!("(trace id {returned})")),
            "{outcome:?}: the error text must carry the trace id: {text}"
        );
    }
}

#[tokio::test]
async fn absent_and_withheld_tools_share_one_caller_error() {
    let caller = principal(None);
    let mut rendered = Vec::new();
    for (outcome, gate) in [
        (
            Outcome::Refused(ToolRefusal::NotInCatalog),
            Arc::new(AllowAllGate) as SharedAuthz,
        ),
        (
            Outcome::Refused(ToolRefusal::KeptBlocked),
            Arc::new(AllowAllGate),
        ),
        (
            Outcome::Refused(ToolRefusal::Unclassified),
            Arc::new(AllowAllGate),
        ),
        (
            Outcome::Refused(ToolRefusal::ServerQuarantined),
            Arc::new(NoDiscoveryGate),
        ),
    ] {
        let (err, _) = refuse(outcome, gate, Some(&caller)).await;
        assert_eq!(err.kind(), "tool_unavailable");
        rendered.push(without_trace_id(wire(err)));
    }
    let (code, message, data) = &rendered[0];
    assert_eq!(*code, rmcp::model::ErrorCode::INVALID_PARAMS.0);
    assert_eq!(
        message,
        "unknown or unavailable tool `example-messages.send`; refresh the tool list. When \
         available to this client, gateway-discovery.search and codemode.search find current \
         tools."
    );
    assert_eq!(
        *data,
        serde_json::json!({"error": "tool_unavailable", "tool": "example-messages.send"})
    );
    assert!(
        rendered.iter().all(|other| other == &rendered[0]),
        "every per-tool reason must render the absent-tool error: {rendered:?}"
    );
}

#[tokio::test]
async fn temporary_conditions_refuse_dispatch_with_a_retryable_error() {
    for reason in [
        TemporaryUnavailability::CatalogUnavailable,
        TemporaryUnavailability::CatalogConverging,
        TemporaryUnavailability::ReviewUnavailable,
        TemporaryUnavailability::NoConnectedLane,
    ] {
        let (err, events) = refuse(
            Outcome::Unavailable(reason),
            Arc::new(AllowAllGate),
            Some(&principal(None)),
        )
        .await;
        let InvocationError::Upstream(error) = err else {
            panic!("a temporary condition must remain retryable, not a refusal");
        };
        let (code, _, data) = without_trace_id(error);
        assert_eq!(code, rmcp::model::ErrorCode::INTERNAL_ERROR.0);
        assert_eq!(
            data,
            serde_json::json!({"error": "catalog_unavailable", "retryable": true})
        );
        assert_eq!(
            recorded_reasons(&events),
            vec![(
                AuditOutcome::ExecutionError,
                Some(format!("unavailable:{}", reason.code()))
            )],
        );
    }
}
