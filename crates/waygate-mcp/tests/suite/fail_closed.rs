//! Pins the fail-closed audit wiring contract.
//!
//! `DefaultInvocationService::record_pre_call` is the only stage in the
//! pipeline that can short-circuit dispatch on an audit-availability
//! failure. The contract is exhaustive across three axes:
//!
//! 1. `AuditMode` (BestEffort | FailClosed)
//! 2. Tool `side_effects` (false | true) — the campaign decoupled the
//!    fail-closed gate from the risk tier onto `side_effects`, so it is the
//!    mutating surface (any tier) that must be audited before dispatch, not
//!    just `risk == High`.
//! 3. Recorder behaviour for `record_required` (Ok | Err)
//!
//! Only the (FailClosed, side_effecting, Err) cell produces
//! `InvocationError::AuditUnavailable`; every other cell dispatches
//! normally. Locking each cell here means a future change to the matrix
//! has to break this test before it can ship.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock as Content, Tool};
use rmcp::ErrorData as McpError;
use uuid::Uuid;
use waygate_invocation::{
    InvocationError, InvocationRequest, InvocationResponse, InvocationService,
};
use waygate_mcp::audit::{AuditEvent, AuditMode, EvidenceError, EvidenceRecorder, NullSink};
use waygate_mcp::authz::{AllowAllGate, ToolFacts};
use waygate_mcp::catalog::UpstreamCatalog;
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::DefaultInvocationService;

/// Catalog fake that returns a configurable `ToolFacts` per tool and a
/// canned `CallToolResult::success` on dispatch. The `tool_facts`
/// table-lookup is what `resolve_tool` consumes, so a test can drive
/// `record_pre_call` through any cell of the decision matrix.
struct FakeCatalog {
    facts_by_tool: HashMap<String, ToolFacts>,
}

#[async_trait]
impl UpstreamCatalog for FakeCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["test".into()]
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
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }
    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        self.facts_by_tool
            .get(tool_name)
            .cloned()
            .unwrap_or_else(|| ToolFacts {
                server: server.to_owned(),
                name: tool_name.to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            })
    }
}

/// Recorder that always fails `record_required`. Both best-effort methods are
/// noops (matching their non-propagating contract). Used to exercise the "DB
/// outage" branch of the decision matrix without standing up a real Postgres.
struct AlwaysFailRecorder;

#[async_trait]
impl EvidenceRecorder for AlwaysFailRecorder {
    async fn record_required(&self, _event: AuditEvent) -> Result<Uuid, EvidenceError> {
        Err(EvidenceError::Persistence("simulated DB outage".into()))
    }
    async fn record_chained_best_effort(&self, _event: AuditEvent) {}
    async fn record_best_effort(&self, _event: AuditEvent) {}
}

fn facts(name: &str, risk: RiskTier, side_effects: bool) -> ToolFacts {
    ToolFacts {
        server: "test".into(),
        name: name.into(),
        risk,
        side_effects,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    }
}

fn build(
    facts_by_tool: HashMap<String, ToolFacts>,
    recorder: Arc<dyn EvidenceRecorder>,
    mode: AuditMode,
) -> Arc<dyn InvocationService> {
    let catalog = Arc::new(FakeCatalog { facts_by_tool });
    Arc::new(
        DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), recorder)
            .with_audit_mode(mode),
    )
}

#[tokio::test]
async fn fail_closed_blocks_side_effecting_when_required_record_errs() {
    // The only blocking cell: (FailClosed, side_effecting, Err). Uses a LOW +
    // side_effects tool — the shape a destructive tool takes after the
    // `high -> low + side_effects` re-triage — to prove the gate keys on
    // side_effects, not the risk tier (under the old risk-keyed gate this LOW
    // tool would NOT have blocked).
    let mut table = HashMap::new();
    table.insert("send_msg".into(), facts("send_msg", RiskTier::Low, true));
    let svc = build(table, Arc::new(AlwaysFailRecorder), AuditMode::FailClosed);
    let req = InvocationRequest::new("test", "send_msg");
    let err = svc.invoke(None, req).await.unwrap_err();
    match err {
        InvocationError::AuditUnavailable(detail) => {
            // Security contract: the variant carries a
            // sanitized fixed string. The full sqlx error stays on the
            // tracing log (operators see it via journalctl) but never
            // reaches the wire response. Pin that contract — a future
            // change that re-introduces `e.to_string()` here breaks
            // this assertion.
            assert_eq!(detail, "evidence backend unavailable");
            assert!(
                !detail.contains("simulated DB outage"),
                "AuditUnavailable must NOT leak the recorder's error detail: {detail}",
            );
        }
        other => panic!("expected AuditUnavailable, got {other:?}"),
    }
}

/// Recorder that *succeeds* on `record_required`. Reaching it from the
/// pipeline means `record_pre_call` wrote its row and then let dispatch
/// proceed — the happy-path cell of the matrix.
struct AlwaysOkRecorder {
    required_calls: std::sync::Mutex<Vec<waygate_mcp::audit::AuditEvent>>,
}

impl AlwaysOkRecorder {
    fn new() -> Self {
        Self {
            required_calls: std::sync::Mutex::new(Vec::new()),
        }
    }
    /// Snapshot the events written so far. Doesn't consume the
    /// recorder, so callers can keep a long-lived `Arc<dyn
    /// EvidenceRecorder>` alongside the inspection handle.
    fn snapshot(&self) -> Vec<waygate_mcp::audit::AuditEvent> {
        self.required_calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl EvidenceRecorder for AlwaysOkRecorder {
    async fn record_required(&self, event: AuditEvent) -> Result<Uuid, EvidenceError> {
        let id = event.id;
        self.required_calls.lock().unwrap().push(event);
        Ok(id)
    }
    async fn record_chained_best_effort(&self, _event: AuditEvent) {}
    async fn record_best_effort(&self, _event: AuditEvent) {}
}

#[tokio::test]
async fn fail_closed_pre_call_writes_row_and_dispatches_when_record_required_succeeds() {
    // (FailClosed, side_effecting, Ok) cell: the pre-call row lands AND the
    // upstream dispatch happens. Verifies the happy-path side of the
    // decision matrix the PR body claims — without this, the matrix
    // is only locked from the failure side.
    let mut table = HashMap::new();
    table.insert("send_msg".into(), facts("send_msg", RiskTier::Low, true));
    let catalog = Arc::new(FakeCatalog {
        facts_by_tool: table,
    });
    let recorder = Arc::new(AlwaysOkRecorder::new());
    // Keep a shared handle alongside the one we hand to the service so
    // we can snapshot the recorder's state after invoke() returns
    // without needing to unwrap the Arc (svc still holds it).
    let recorder_inspect = recorder.clone();
    let svc = DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), recorder)
        .with_audit_mode(AuditMode::FailClosed);
    let req = InvocationRequest::new("test", "send_msg");
    let out = match svc
        .invoke(None, req)
        .await
        .expect("happy path: record_required succeeds, dispatch proceeds")
    {
        InvocationResponse::Unary(r) => r,
        _ => panic!("tool dispatch must be unary"),
    };
    assert!(out.is_error.is_none() || out.is_error == Some(false));
    // Pre-call row was emitted via `record_required` with reason="pre_call".
    let calls = recorder_inspect.snapshot();
    assert_eq!(
        calls.len(),
        1,
        "expected exactly one record_required call (the pre_call row); got {}",
        calls.len(),
    );
    assert_eq!(
        calls[0].reason.as_deref(),
        Some("pre_call"),
        "pre-call audit row must carry reason='pre_call' so dashboards can filter it",
    );
}

#[tokio::test]
async fn fail_closed_lets_non_side_effecting_through_even_when_required_record_would_err() {
    // Read-only (`!side_effects`) tools deliberately stay best-effort even under
    // FailClosed — the operator opts in to evidence for the mutating surface,
    // not for every call. (Risk tier is irrelevant to the gate now.)
    let mut table = HashMap::new();
    table.insert("read_only".into(), facts("read_only", RiskTier::Low, false));
    let svc = build(table, Arc::new(AlwaysFailRecorder), AuditMode::FailClosed);
    let req = InvocationRequest::new("test", "read_only");
    let out = match svc.invoke(None, req).await.expect("read-only should pass") {
        InvocationResponse::Unary(r) => r,
        _ => panic!("tool dispatch must be unary"),
    };
    assert!(out.is_error.is_none() || out.is_error == Some(false));
}

#[tokio::test]
async fn fail_closed_lets_high_risk_non_side_effecting_through_even_when_record_would_err() {
    // The decouple proof: a `high` but `!side_effects` tool is NOT fail-closed —
    // the gate moved off the risk tier onto side_effects, so an administrative
    // read (high, no mutation) stays best-effort. (Under the old risk-keyed gate
    // this would have blocked.)
    let mut table = HashMap::new();
    table.insert(
        "admin_read".into(),
        facts("admin_read", RiskTier::High, false),
    );
    let svc = build(table, Arc::new(AlwaysFailRecorder), AuditMode::FailClosed);
    let req = InvocationRequest::new("test", "admin_read");
    let out = match svc
        .invoke(None, req)
        .await
        .expect("high-risk but non-side-effecting should pass")
    {
        InvocationResponse::Unary(r) => r,
        _ => panic!("tool dispatch must be unary"),
    };
    assert!(out.is_error.is_none() || out.is_error == Some(false));
}

#[tokio::test]
async fn best_effort_never_blocks_even_side_effecting_when_record_required_would_err() {
    // The BestEffort posture never calls `record_required`, so an
    // AlwaysFail recorder never sees its required-path triggered and
    // the dispatch reaches the catalog — even for a side-effecting tool.
    let mut table = HashMap::new();
    table.insert("send_msg".into(), facts("send_msg", RiskTier::Low, true));
    let svc = build(table, Arc::new(AlwaysFailRecorder), AuditMode::BestEffort);
    let req = InvocationRequest::new("test", "send_msg");
    let out = match svc
        .invoke(None, req)
        .await
        .expect("best-effort posture must not block on audit availability")
    {
        InvocationResponse::Unary(r) => r,
        _ => panic!("tool dispatch must be unary"),
    };
    assert!(out.is_error.is_none() || out.is_error == Some(false));
}

#[tokio::test]
async fn nullsink_default_constructor_keeps_best_effort_posture() {
    // The `DefaultInvocationService::new` constructor defaults to
    // BestEffort — operators have to call `with_audit_mode` explicitly
    // to opt into fail-closed. Regression guard so a future change to
    // the default doesn't silently make every gateway fail-closed.
    let mut table = HashMap::new();
    table.insert("send_msg".into(), facts("send_msg", RiskTier::Low, true));
    let catalog = Arc::new(FakeCatalog {
        facts_by_tool: table,
    });
    let svc = DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), Arc::new(NullSink));
    // Reach via the trait method so we exercise the full pipeline.
    let svc: Arc<dyn InvocationService> = Arc::new(svc);
    let req = InvocationRequest::new("test", "send_msg");
    svc.invoke(None, req)
        .await
        .expect("default constructor must be BestEffort — should dispatch");
}
