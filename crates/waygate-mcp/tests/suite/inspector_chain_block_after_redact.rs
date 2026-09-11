//! Inspector-chain regression: block-after-redact must not audit success.
//!
//! Pins the contract that when an EARLIER inspector returns
//! [`Decision::Redact`] and a LATER inspector in the same
//! chain returns [`Decision::Block`], the orchestrator
//! emits a `CallTool/Denied` audit row for the block but
//! does NOT emit any `CallTool/Success` "redacted" row for
//! the queued redaction. The redacted response was never
//! forwarded — telemetry must not claim otherwise.

use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock as Content, ErrorData, Tool};
use serde_json::{json, Map, Value};

use waygate_invocation::{InvocationRequest, InvocationService};
use waygate_mcp::audit::{AuditOutcome, InMemorySink};
use waygate_mcp::authz::{AllowAllGate, SharedAuthz, ToolFacts};
use waygate_mcp::catalog::{SharedCatalog, UpstreamCatalog};
use waygate_mcp::inspection::{Decision, InspectionContext, Inspector, SharedInspector};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{DefaultInvocationService, SharedEvidence};
use waygate_oidc::Principal;

/// Minimal `UpstreamCatalog` — returns a clean response so the
/// inspector chain is what drives the test, not catalog state.
struct CleanCatalog;

#[async_trait]
impl UpstreamCatalog for CleanCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["s".into()]
    }
    async fn list_tools(&self, _: &str) -> Result<Vec<Tool>, ErrorData> {
        let schema = json!({"type": "object"}).as_object().cloned().unwrap();
        Ok(vec![Tool::new(
            "t".to_string(),
            "test".to_string(),
            Arc::new(schema),
        )])
    }
    async fn call_tool(
        &self,
        _: &str,
        _: &str,
        _: Option<Map<String, Value>>,
        _: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![Content::text(
            "upstream payload",
        )]))
    }
    fn tool_facts(&self, server: &str, tool: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool.into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
}

/// Inspector that always returns `Decision::Redact` with
/// findings_count=1, leaving the result content unchanged
/// (good enough for this test — we only care about the
/// orchestrator's audit/metric behavior, not the redaction's
/// shape).
struct AlwaysRedact;
#[async_trait]
impl Inspector for AlwaysRedact {
    fn name(&self) -> &'static str {
        "always_redact"
    }
    async fn inspect(&self, _ctx: &InspectionContext<'_>, result: &CallToolResult) -> Decision {
        Decision::Redact {
            redacted: result.clone(),
            findings_count: 1,
        }
    }
}

/// Inspector that always returns `Decision::Block`.
struct AlwaysBlock;
#[async_trait]
impl Inspector for AlwaysBlock {
    fn name(&self) -> &'static str {
        "always_block"
    }
    async fn inspect(&self, _ctx: &InspectionContext<'_>, _: &CallToolResult) -> Decision {
        Decision::Block {
            reason: "always_block fired".into(),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn block_after_redact_does_not_emit_redaction_success_row() {
    let catalog: SharedCatalog = Arc::new(CleanCatalog);
    let authz: SharedAuthz = Arc::new(AllowAllGate);
    let sink = Arc::new(InMemorySink::new());
    let audit = sink.clone() as SharedEvidence;
    let svc = DefaultInvocationService::new(catalog, authz, audit).with_inspectors(vec![
        Arc::new(AlwaysRedact) as SharedInspector,
        Arc::new(AlwaysBlock) as SharedInspector,
    ]);
    let req = InvocationRequest::new("s", "t");
    let err = svc
        .invoke(None, req)
        .await
        .expect_err("chain must end in Block");
    assert!(
        matches!(
            err,
            waygate_invocation::InvocationError::ResponseInspectionBlocked { .. }
        ),
        "expected ResponseInspectionBlocked, got {err:?}",
    );

    let rows = sink.snapshot().await;
    // Check 1: no "redacted N finding(s)" Success row. The
    // earlier inspector queued one via pending_redactions but
    // the orchestrator must skip the flush because the later
    // inspector blocked and the response was never forwarded.
    let leaked_redaction = rows.iter().any(|r| {
        matches!(r.outcome, AuditOutcome::Success)
            && r.reason.as_deref().is_some_and(|s| s.contains("redacted"))
    });
    assert!(
        !leaked_redaction,
        "queued redaction emitted Success audit despite block: {rows:#?}",
    );
    // Check 2: the Block path's own Denied row IS present.
    let block_recorded = rows.iter().any(|r| {
        matches!(r.outcome, AuditOutcome::Denied)
            && r.reason.as_deref().is_some_and(|s| s.contains("blocked"))
    });
    assert!(
        block_recorded,
        "expected a CallTool/Denied row for the block, got: {rows:#?}",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn redact_only_chain_does_emit_redaction_success_row() {
    // Inverse of the above: when no later inspector blocks, the
    // flush MUST run and the redaction Success row IS emitted.
    // Ensures the gating didn't over-correct.
    let catalog: SharedCatalog = Arc::new(CleanCatalog);
    let authz: SharedAuthz = Arc::new(AllowAllGate);
    let sink = Arc::new(InMemorySink::new());
    let audit = sink.clone() as SharedEvidence;
    let svc = DefaultInvocationService::new(catalog, authz, audit)
        .with_inspectors(vec![Arc::new(AlwaysRedact) as SharedInspector]);
    let req = InvocationRequest::new("s", "t");
    let _ok = svc
        .invoke(None, req)
        .await
        .expect("redact-only chain must forward");

    let rows = sink.snapshot().await;
    let redaction_recorded = rows.iter().any(|r| {
        matches!(r.outcome, AuditOutcome::Success)
            && r.reason
                .as_deref()
                .is_some_and(|s| s.contains("redacted") && s.contains("always_redact"))
    });
    assert!(
        redaction_recorded,
        "expected a redaction Success row for the forwarded redaction, got: {rows:#?}",
    );
}

/// Replay regression: a response-redaction Success row is post-authorization
/// TELEMETRY about a forwarded call, not a distinct authorization-gate
/// decision, so it must NOT carry the captured decision inputs. Otherwise the
/// impact replay (waygate-admin) would reconstruct it as an extra `allow`
/// decision and inflate the blast-radius counts by re-counting one forwarded
/// call once per inspector. Invokes WITH a principal — whose inputs *would* be
/// stamped if the bug were present — and asserts the redaction row leaves them
/// absent (so the replay's `auth_method.is_some()` predicate skips it) while
/// the FINAL outcome row still carries them.
#[tokio::test(flavor = "current_thread")]
async fn redaction_success_row_carries_no_decision_inputs() {
    let catalog: SharedCatalog = Arc::new(CleanCatalog);
    let authz: SharedAuthz = Arc::new(AllowAllGate);
    let sink = Arc::new(InMemorySink::new());
    let audit = sink.clone() as SharedEvidence;
    let svc = DefaultInvocationService::new(catalog, authz, audit)
        .with_inspectors(vec![Arc::new(AlwaysRedact) as SharedInspector]);

    let principal = Principal {
        sub: "dave".into(),
        email: None,
        groups: vec![],
        issuer: "https://auth.example.test".into(),
        scopes: vec!["mcp:invoke".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec!["analyst".into()],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    };
    let req = InvocationRequest::new("s", "t");
    let _ok = svc
        .invoke(Some(&principal), req)
        .await
        .expect("redact-only chain must forward");

    let rows = sink.snapshot().await;
    let redaction = rows
        .iter()
        .find(|r| {
            matches!(r.outcome, AuditOutcome::Success)
                && r.reason
                    .as_deref()
                    .is_some_and(|s| s.contains("redacted") && s.contains("always_redact"))
        })
        .expect("a redaction Success row must be emitted");
    // The replay predicate is `auth_method.is_some()`; leaving it absent is what
    // makes the impact replay skip this telemetry row.
    assert!(
        redaction.auth_method.is_none(),
        "redaction telemetry row must NOT carry auth_method (would be replayed as a decision): {redaction:#?}",
    );
    assert!(redaction.req_scopes.is_empty());
    assert!(redaction.req_roles.is_empty());
    assert!(redaction.side_effects.is_none());

    // Sanity: the principal's inputs ARE present on the FINAL outcome row, so
    // the redaction row's absence is deliberate, not an artifact of a principal
    // with no inputs.
    let final_decision = rows
        .iter()
        .find(|r| {
            matches!(r.outcome, AuditOutcome::Success)
                && r.reason
                    .as_deref()
                    .map(|s| !s.contains("redacted"))
                    .unwrap_or(true)
        })
        .expect("a final outcome row must be emitted");
    assert_eq!(final_decision.auth_method.as_deref(), Some("oauth"));
    assert_eq!(final_decision.req_scopes, vec!["mcp:invoke".to_string()]);
}
