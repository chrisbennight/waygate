//! Pins the contract of the
//! `DefaultInvocationService::check_approval` stage:
//!
//! 1. `requires_approval=false` → stage is a no-op, dispatch proceeds.
//! 2. `requires_approval=true` + matching claim → grant is consumed,
//!    dispatch proceeds.
//! 3. A grant for a previous tool behavior hash does not match even when its
//!    arguments are identical.
//! 4. `requires_approval=true` + no match → `ApprovalRequired` error,
//!    dispatch never runs.
//! 5. `requires_approval=true` + anonymous (no principal) → refuse.
//! 6. `requires_approval=true` + catalog `claim_grant` errors → fail-
//!    closed: refuse with `ApprovalRequired` (sanitized reason), never
//!    leak the sqlx detail.
//!
//! Uses an in-memory `CatalogStore` fake so this test doesn't need a
//! live Postgres — the atomic-claim SQL itself lives in the Pg impl
//! and is exercised by the catalog integration suite that needs the DB.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock as Content};
use rmcp::ErrorData as McpError;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_catalog::{
    ApprovalAction, ApprovalGrant, ApprovalGrantExecutionBinding, CatalogError,
    CatalogServerStatus, CatalogServerSummary, CatalogStore, DriftEvent, DriftObservation,
    GrantLookup, ResolvedTool, SharedCatalogStore,
};
use waygate_invocation::{
    InvocationApprovalBinding, InvocationError, InvocationRequest, InvocationService,
};
use waygate_mcp::audit::{
    AuditMode, AuditOutcome, EvidenceCategory, EvidencePosture, InMemorySink, NullSink,
};
use waygate_mcp::authz::{AllowAllGate, AuthzGate, AuthzVerdict, ToolFacts};
use waygate_mcp::catalog::{InvocationToolSnapshot, ResolvedInvocationTool, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{
    DefaultInvocationService, InvocationStage, InvocationStageObserver, SharedEvidence,
    SharedInvocationStageObserver,
};
use waygate_oidc::Principal;

/// In-process catalog fake. Returns the configured `Live` tool from
/// `resolve_tool`, and `claim_grant` either returns the canned grant
/// (or `None`), or surfaces an error to exercise the fail-closed path.
struct FakeCatalog {
    tool_id: Uuid,
    server_id: Uuid,
    claim_outcome: ClaimOutcome,
    /// The issuer the last `claim_grant` lookup carried, so tests can pin
    /// that the pipeline binds the CALLER's issuer into the claim.
    seen_issuer: std::sync::Mutex<Option<String>>,
}

enum ClaimOutcome {
    Granted,
    StaleBehaviorGrant,
    GrantedFor(ApprovalGrantExecutionBinding),
    NotFound,
    Errored,
}

#[derive(Default)]
struct RecordingStageObserver(Mutex<Vec<InvocationStage>>);

impl InvocationStageObserver for RecordingStageObserver {
    fn enter(&self, stage: InvocationStage) {
        self.0.lock().expect("stage recorder poisoned").push(stage);
    }
}

impl RecordingStageObserver {
    fn snapshot(&self) -> Vec<InvocationStage> {
        self.0.lock().expect("stage recorder poisoned").clone()
    }
}

#[async_trait]
impl CatalogStore for FakeCatalog {
    async fn approved_servers(
        &self,
        _tenant: &str,
    ) -> Result<Vec<CatalogServerSummary>, CatalogError> {
        Ok(vec![])
    }
    async fn resolve_tool(&self, _tenant: &str, _fq: &str) -> Result<ResolvedTool, CatalogError> {
        panic!("approval must use the Stage 1 snapshot, not re-resolve the catalog")
    }
    async fn record_drift(&self, _o: DriftObservation<'_>) -> Result<(), CatalogError> {
        Ok(())
    }
    async fn record_approval(&self, _a: ApprovalAction<'_>) -> Result<(), CatalogError> {
        Ok(())
    }
    async fn list_drift_events(
        &self,
        _t: &str,
        _s: OffsetDateTime,
        _l: u32,
    ) -> Result<Vec<DriftEvent>, CatalogError> {
        Ok(vec![])
    }
    async fn set_server_status(
        &self,
        _t: &str,
        _id: Uuid,
        _s: CatalogServerStatus,
        _a: &str,
        _r: Option<&str>,
    ) -> Result<bool, CatalogError> {
        Ok(true)
    }
    async fn last_approve_actor(
        &self,
        _t: &str,
        _id: Uuid,
    ) -> Result<Option<String>, CatalogError> {
        Ok(None)
    }
    async fn find_grant<'a>(
        &self,
        _l: GrantLookup<'a>,
    ) -> Result<Option<ApprovalGrant>, CatalogError> {
        Ok(None)
    }
    async fn claim_grant<'a>(
        &self,
        lookup: GrantLookup<'a>,
    ) -> Result<Option<ApprovalGrant>, CatalogError> {
        *self.seen_issuer.lock().expect("issuer recorder") =
            Some(lookup.principal_issuer.to_owned());
        // The behavior-bound approval hash gate: a grant minted for a
        // previous reviewed behavior version must never match the current
        // one, regardless of the execution binding below.
        let grant_behavior_hash = match &self.claim_outcome {
            ClaimOutcome::Granted | ClaimOutcome::GrantedFor(_) => "h",
            ClaimOutcome::StaleBehaviorGrant => "previous-h",
            ClaimOutcome::NotFound => return Ok(None),
            ClaimOutcome::Errored => return Err(CatalogError::Unknown("simulated outage")),
        };
        let raw_argument_hash = waygate_catalog::argument_hash(None);
        let grant_binding =
            waygate_catalog::approval_binding_hash(grant_behavior_hash, &raw_argument_hash);
        if lookup.argument_hash != grant_binding {
            return Ok(None);
        }
        let granted = match &self.claim_outcome {
            ClaimOutcome::Granted | ClaimOutcome::StaleBehaviorGrant => {
                lookup.execution_binding.is_none()
            }
            ClaimOutcome::GrantedFor(expected) => lookup.execution_binding.is_some_and(|actual| {
                actual.execution_id == expected.execution_id
                    && actual.source_digest == expected.source_digest
                    && actual.call_id == expected.call_id
            }),
            ClaimOutcome::NotFound | ClaimOutcome::Errored => unreachable!("handled above"),
        };
        if granted {
            Ok(Some(ApprovalGrant {
                id: Uuid::nil(),
                tenant_id: lookup.tenant_id.to_owned(),
                principal_sub: lookup.principal_sub.to_owned(),
                principal_issuer: Some(lookup.principal_issuer.to_owned()),
                client_id: None,
                server_id: self.server_id,
                tool_id: self.tool_id,
                argument_hash: lookup.argument_hash.to_owned(),
                execution_binding: lookup.execution_binding.map(|binding| {
                    waygate_catalog::ApprovalGrantExecutionBinding {
                        execution_id: binding.execution_id,
                        source_digest: binding.source_digest.to_owned(),
                        call_id: binding.call_id,
                    }
                }),
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                consumed_at: Some(OffsetDateTime::now_utc()),
                approver: "bob@example.com".into(),
                reason: Some("vetted".into()),
                created_at: OffsetDateTime::now_utc(),
            }))
        } else {
            Ok(None)
        }
    }
    async fn create_grant<'a>(
        &self,
        _g: waygate_catalog::NewApprovalGrant<'a>,
    ) -> Result<ApprovalGrant, CatalogError> {
        Err(CatalogError::Unknown("create_grant unused in this test"))
    }
    async fn list_grants<'a>(
        &self,
        _t: &'a str,
        _f: waygate_catalog::GrantFilter<'a>,
    ) -> Result<Vec<ApprovalGrant>, CatalogError> {
        Ok(vec![])
    }
    async fn revoke_grant(&self, _t: &str, _id: Uuid) -> Result<bool, CatalogError> {
        Ok(false)
    }
    async fn revoke_execution_grants(
        &self,
        _t: &str,
        _execution_id: Uuid,
    ) -> Result<u64, CatalogError> {
        Ok(0)
    }
    async fn sweep_grants(&self, _older_than: OffsetDateTime) -> Result<u64, CatalogError> {
        Ok(0)
    }
}

/// UpstreamCatalog fake. Returns a Stage 1 snapshot whose
/// `requires_approval` mirrors the test's setting (so stage 1
/// `resolve_tool` populates the admitted facts correctly)
/// and a single canned `CallToolResult` from `call_tool`.
struct FakeUpstream {
    requires_approval: bool,
    /// Lets a test drive the manifest fallback after a catalog error. The
    /// snapshot remains visibly non-authoritative and must fail closed.
    requires_approval_known: bool,
    dispatched: Arc<std::sync::atomic::AtomicBool>,
    approval_gated_seen: Option<Arc<std::sync::atomic::AtomicBool>>,
}

#[async_trait]
impl UpstreamCatalog for FakeUpstream {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-messages".into()]
    }
    async fn list_tools(&self, _server: &str) -> Result<Vec<rmcp::model::Tool>, McpError> {
        Ok(vec![])
    }
    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        self.dispatched
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }
    async fn call_tool_response(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        mrtr: waygate_mcp::catalog::ToolCallMrtr,
    ) -> Result<rmcp::model::CallToolResponse, McpError> {
        if let Some(seen) = &self.approval_gated_seen {
            seen.store(mrtr.approval_gated, std::sync::atomic::Ordering::SeqCst);
        }
        self.dispatched
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(CallToolResult::success(vec![Content::text("ok")]).into())
    }
    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool_name.into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: false,
            requires_approval: self.requires_approval,
            requires_approval_known: self.requires_approval_known,
        }
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        let facts = self.tool_facts(server, tool_name);
        let input = serde_json::json!({"type": "object", "properties": {
            "selector": {"type": "string"}, "contents": {"type": "string"}
        }});
        let snapshot = if self.requires_approval_known {
            InvocationToolSnapshot::catalog(
                facts,
                Uuid::from_u128(1),
                "h".into(),
                Some(input.clone()),
                None,
            )
        } else {
            InvocationToolSnapshot::manifest_fallback(facts, false)
        };
        ResolvedInvocationTool::Ready(snapshot.with_published_definition(Some(rmcp::model::Tool::new(
            tool_name.to_owned(),
            "Replace desired configuration. Upstream may retain submitted values. Deploy separately.",
            Arc::new(input.as_object().unwrap().clone()),
        ))))
    }
}

fn principal(sub: &str) -> Principal {
    Principal {
        sub: sub.into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: vec![],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn service(
    requires_approval: bool,
    claim_outcome: ClaimOutcome,
    dispatched: Arc<std::sync::atomic::AtomicBool>,
) -> Arc<dyn InvocationService> {
    service_with(requires_approval, true, claim_outcome, dispatched)
}

/// Extended builder for the fail-closed snapshot cases.
fn service_with(
    requires_approval: bool,
    requires_approval_known: bool,
    claim_outcome: ClaimOutcome,
    dispatched: Arc<std::sync::atomic::AtomicBool>,
) -> Arc<dyn InvocationService> {
    service_with_observer(
        requires_approval,
        requires_approval_known,
        claim_outcome,
        dispatched,
        None,
    )
}

fn service_with_observer(
    requires_approval: bool,
    requires_approval_known: bool,
    claim_outcome: ClaimOutcome,
    dispatched: Arc<std::sync::atomic::AtomicBool>,
    observer: Option<SharedInvocationStageObserver>,
) -> Arc<dyn InvocationService> {
    service_with_observer_and_evidence(
        requires_approval,
        requires_approval_known,
        claim_outcome,
        dispatched,
        observer,
        Arc::new(NullSink),
    )
}

/// Gate that always answers `ApprovalRequired` — Cedar's approval-overlay
/// verdict — so the tests can pin that a policy-imposed approval gates
/// dispatch on a grant claim even when the catalog flag is off.
struct ApprovalOverlayGate;

#[async_trait]
impl AuthzGate for ApprovalOverlayGate {
    async fn may_discover_server(&self, _p: &Principal, _s: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::ApprovalRequired {
            reason: "approval-gated by policy".into(),
            policy_ids: vec!["codemode-mutation-approval".into()],
        }
    }
}

fn service_with_gate(
    requires_approval: bool,
    claim_outcome: ClaimOutcome,
    dispatched: Arc<std::sync::atomic::AtomicBool>,
    gate: Arc<dyn AuthzGate>,
    evidence: SharedEvidence,
) -> (
    Arc<dyn InvocationService>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let approval_gated_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream = Arc::new(FakeUpstream {
        requires_approval,
        requires_approval_known: true,
        dispatched,
        approval_gated_seen: Some(Arc::clone(&approval_gated_seen)),
    });
    let catalog_store: SharedCatalogStore = Arc::new(FakeCatalog {
        tool_id: Uuid::from_u128(1),
        server_id: Uuid::from_u128(2),
        claim_outcome,
        seen_issuer: std::sync::Mutex::new(None),
    });
    (
        Arc::new(
            DefaultInvocationService::new(upstream, gate, evidence)
                .with_audit_mode(AuditMode::BestEffort)
                .with_catalog_store(Some(catalog_store)),
        ),
        approval_gated_seen,
    )
}

fn service_with_observer_and_evidence(
    requires_approval: bool,
    requires_approval_known: bool,
    claim_outcome: ClaimOutcome,
    dispatched: Arc<std::sync::atomic::AtomicBool>,
    observer: Option<SharedInvocationStageObserver>,
    evidence: SharedEvidence,
) -> Arc<dyn InvocationService> {
    let upstream = Arc::new(FakeUpstream {
        requires_approval,
        requires_approval_known,
        dispatched,
        approval_gated_seen: None,
    });
    let catalog_store: SharedCatalogStore = Arc::new(FakeCatalog {
        tool_id: Uuid::from_u128(1),
        server_id: Uuid::from_u128(2),
        claim_outcome,
        seen_issuer: std::sync::Mutex::new(None),
    });
    let mut service = DefaultInvocationService::new(upstream, Arc::new(AllowAllGate), evidence)
        .with_audit_mode(AuditMode::BestEffort)
        .with_catalog_store(Some(catalog_store));
    if let Some(observer) = observer {
        service = service.with_stage_observer(observer);
    }
    Arc::new(service)
}

/// 1. requires_approval=false → check_approval is a no-op, dispatch
///    proceeds even with the HITL catalog wired.
#[tokio::test]
async fn check_approval_noop_when_flag_off() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(false, ClaimOutcome::NotFound, dispatched.clone());
    let res = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await;
    assert!(res.is_ok(), "non-HITL tool must dispatch: {res:?}");
    assert!(dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

/// 2. requires_approval=true + claim succeeds → dispatch proceeds.
#[tokio::test]
async fn check_approval_passes_when_grant_claims() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(true, ClaimOutcome::Granted, dispatched.clone());
    let res = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await;
    assert!(res.is_ok(), "claimed-grant call must dispatch: {res:?}");
    assert!(dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn check_approval_refuses_grant_for_previous_tool_behavior() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(true, ClaimOutcome::StaleBehaviorGrant, dispatched.clone());
    let err = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, InvocationError::ApprovalRequired { .. }),
        "stale behavior grant must not authorize dispatch: {err:?}"
    );
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

/// 4. requires_approval=true + no live grant → ApprovalRequired,

#[tokio::test]
async fn check_approval_claims_only_the_exact_execution_binding() {
    let execution_id = Uuid::now_v7();
    let call_id = Uuid::now_v7();
    let binding = ApprovalGrantExecutionBinding {
        execution_id,
        source_digest: "source-a".to_owned(),
        call_id,
    };
    let hierarchy = waygate_core::InvocationHierarchy::new(
        execution_id,
        std::num::NonZeroU32::MIN,
        call_id,
        std::num::NonZeroU32::MIN,
    );

    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(
        true,
        ClaimOutcome::GrantedFor(binding.clone()),
        dispatched.clone(),
    );
    let result = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send")
                .with_hierarchy(hierarchy)
                .with_approval_binding(InvocationApprovalBinding {
                    execution_id,
                    source_digest: binding.source_digest.clone(),
                    call_id,
                }),
        )
        .await;
    assert!(
        result.is_ok(),
        "exact execution-bound grant must dispatch: {result:?}"
    );
    assert!(dispatched.load(std::sync::atomic::Ordering::SeqCst));

    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(true, ClaimOutcome::GrantedFor(binding), dispatched.clone());
    let error = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send")
                .with_hierarchy(hierarchy)
                .with_approval_binding(InvocationApprovalBinding {
                    execution_id,
                    source_digest: "source-b".to_owned(),
                    call_id,
                }),
        )
        .await
        .expect_err("source drift must not consume an execution-bound grant");
    assert!(matches!(error, InvocationError::ApprovalRequired { .. }));
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn check_approval_does_not_use_an_unbound_grant_for_bound_execution() {
    let execution_id = Uuid::now_v7();
    let call_id = Uuid::now_v7();
    let hierarchy = waygate_core::InvocationHierarchy::new(
        execution_id,
        std::num::NonZeroU32::MIN,
        call_id,
        std::num::NonZeroU32::MIN,
    );
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(true, ClaimOutcome::Granted, dispatched.clone());
    let error = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send")
                .with_hierarchy(hierarchy)
                .with_approval_binding(InvocationApprovalBinding {
                    execution_id,
                    source_digest: "source-a".to_owned(),
                    call_id,
                }),
        )
        .await
        .expect_err("ordinary grant must not authorize a bound execution");
    assert!(matches!(error, InvocationError::ApprovalRequired { .. }));
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

/// 3. requires_approval=true + no live grant → ApprovalRequired,
///    upstream dispatch never runs.
#[tokio::test]
async fn check_approval_refuses_when_no_grant() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observer = Arc::new(RecordingStageObserver::default());
    let sink = Arc::new(InMemorySink::new());
    let svc = service_with_observer_and_evidence(
        true,
        true,
        ClaimOutcome::NotFound,
        dispatched.clone(),
        Some(observer.clone()),
        sink.clone(),
    );
    let err = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await
        .unwrap_err();
    match err {
        InvocationError::ApprovalRequired { tool, .. } => {
            assert_eq!(tool, "example-messages.send");
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    }
    assert!(
        !dispatched.load(std::sync::atomic::Ordering::SeqCst),
        "dispatch must not run when approval missing"
    );
    assert_eq!(
        observer.snapshot(),
        InvocationStage::ALL[..8],
        "approval denial must stop before pre-call evidence and dispatch"
    );
    let rows = sink.snapshot_with_posture().await;
    assert_eq!(rows.len(), 1, "approval refusal emits one evidence row");
    assert_eq!(rows[0].posture, EvidencePosture::ChainedBestEffort);
    assert_eq!(rows[0].event.category, EvidenceCategory::Invocation);
    assert_eq!(rows[0].event.outcome, AuditOutcome::Denied);
    assert_eq!(
        rows[0].event.reason.as_deref(),
        Some("approval required: tool requires human approval; no matching grant")
    );
}

/// 4. requires_approval=true + anonymous caller → refuse (we can't
///    bind a grant to a missing sub).
#[tokio::test]
async fn check_approval_refuses_anonymous_caller() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(true, ClaimOutcome::Granted, dispatched.clone());
    let err = svc
        .invoke(None, InvocationRequest::new("example-messages", "send"))
        .await
        .unwrap_err();
    assert!(matches!(err, InvocationError::ApprovalRequired { .. }));
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn check_approval_fails_closed_when_required_but_store_is_unwired() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let service = DefaultInvocationService::new(
        Arc::new(FakeUpstream {
            requires_approval: true,
            requires_approval_known: true,
            dispatched: dispatched.clone(),
            approval_gated_seen: None,
        }),
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );

    let error = service
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await
        .expect_err("required approval without a grant store must fail closed");
    assert!(matches!(
        error,
        InvocationError::ApprovalRequired { ref reason, .. }
            if reason == "approval store unavailable"
    ));
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

/// 5. requires_approval=true + catalog claim errors → fail closed:
///    refuse with ApprovalRequired carrying a sanitized reason that
///    does NOT leak the sqlx-style error string (security pin).
#[tokio::test]
async fn check_approval_fails_closed_on_catalog_error() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service(true, ClaimOutcome::Errored, dispatched.clone());
    let err = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await
        .unwrap_err();
    match err {
        InvocationError::ApprovalRequired { reason, .. } => {
            assert_eq!(reason, "approval store unavailable");
            assert!(
                !reason.contains("simulated"),
                "claim_grant error must NOT leak to the wire: {reason}",
            );
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    }
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
}

/// A catalog-error manifest fallback is permanently non-authoritative for the
/// admitted call. Approval fails closed without changing to a later catalog
/// view, even if the grant store itself is available.
#[tokio::test]
async fn check_approval_fails_closed_for_unknown_snapshot_authority() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let svc = service_with(false, false, ClaimOutcome::Granted, dispatched.clone());
    let err = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await
        .unwrap_err();
    match err {
        InvocationError::ApprovalRequired { reason, .. } => {
            assert_eq!(reason, "approval authority unavailable");
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    }
    assert!(
        !dispatched.load(std::sync::atomic::Ordering::SeqCst),
        "unknown snapshot authority must block dispatch"
    );
}

/// A Cedar `ApprovalRequired` verdict imposes the grant gate by itself:
/// the catalog flag is off, yet dispatch is refused until a grant claims.
#[tokio::test]
async fn cedar_approval_verdict_requires_a_grant_even_when_the_flag_is_off() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sink = Arc::new(InMemorySink::new());
    let (svc, _) = service_with_gate(
        false,
        ClaimOutcome::NotFound,
        dispatched.clone(),
        Arc::new(ApprovalOverlayGate),
        sink.clone(),
    );
    let res = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await;
    assert!(
        matches!(res, Err(InvocationError::ApprovalRequired { .. })),
        "policy-gated call without a grant must refuse: {res:?}",
    );
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
    // The refusal row names the demanding authority: decision-impact
    // replay maps "by policy" to the recorded approval_required verdict.
    let rows = sink.snapshot_with_posture().await;
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]
            .event
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("approval required by policy:")),
        "policy-demanded refusal must carry the authority label: {:?}",
        rows[0].event.reason,
    );
}

/// The same policy-imposed gate is satisfied by a live grant claim.
#[tokio::test]
async fn cedar_approval_verdict_dispatches_once_a_grant_claims() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sink = Arc::new(InMemorySink::new());
    let (svc, approval_gated_seen) = service_with_gate(
        false,
        ClaimOutcome::Granted,
        dispatched.clone(),
        Arc::new(ApprovalOverlayGate),
        sink.clone(),
    );
    let res = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await;
    assert!(
        res.is_ok(),
        "granted policy-gated call must dispatch: {res:?}"
    );
    assert!(dispatched.load(std::sync::atomic::Ordering::SeqCst));
    assert!(
        approval_gated_seen.load(std::sync::atomic::Ordering::SeqCst),
        "the dynamic Cedar approval gate must reach transport retry admission"
    );
    // The success row records that the effect was policy-gated, so replay
    // reproduces the approval_required verdict for the unchanged bundle.
    let rows = sink.snapshot_with_posture().await;
    let success = rows
        .iter()
        .find(|row| row.event.outcome == AuditOutcome::Success)
        .expect("dispatched call emits a success row");
    assert_eq!(
        success.event.reason.as_deref(),
        Some("policy-gated effect: approval grant consumed"),
    );
}

/// The approval-gated single-round rule, capability half: the dispatch
/// clears the caller's MRTR capabilities, so an upstream that pauses only
/// when the request declares input capabilities completes in the one round
/// the claimed grant covers. (The state-only half — an upstream that
/// pauses regardless of declared capabilities — is pinned by
/// `approval_gated_state_only_pause_names_the_consumed_grant` below.)
#[tokio::test]
async fn approval_gated_dispatch_is_single_round() {
    use rmcp::model::CallToolResponse;
    use waygate_mcp::catalog::ToolCallMrtr;

    /// Conforming interactive upstream: pauses iff the dispatch declared
    /// input capabilities; records what each dispatch declared.
    struct InteractiveUpstream {
        seen_capabilities: Mutex<Vec<bool>>,
    }

    #[async_trait]
    impl UpstreamCatalog for InteractiveUpstream {
        async fn list_servers(&self) -> Vec<String> {
            vec!["example-messages".into()]
        }
        async fn list_tools(&self, _server: &str) -> Result<Vec<rmcp::model::Tool>, McpError> {
            Ok(vec![])
        }
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: Option<rmcp::model::JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("the pipeline dispatches through call_tool_response")
        }
        async fn call_tool_response(
            &self,
            _server: &str,
            _tool: &str,
            _args: Option<rmcp::model::JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
            mrtr: ToolCallMrtr,
        ) -> Result<CallToolResponse, McpError> {
            let interactive = mrtr.caller_capabilities.is_some();
            self.seen_capabilities
                .lock()
                .expect("recorder")
                .push(interactive);
            if interactive {
                return Ok(CallToolResponse::InputRequired(
                    rmcp::model::InputRequiredResult::from_request_state("never-completable"),
                ));
            }
            Ok(CallToolResult::success(vec![Content::text("done")]).into())
        }
        fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
            ToolFacts {
                server: server.into(),
                name: tool_name.into(),
                risk: RiskTier::High,
                side_effects: true,
                pii: false,
                requires_approval: true,
                requires_approval_known: true,
            }
        }
        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> ResolvedInvocationTool {
            ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog(
                self.tool_facts(server, tool_name),
                Uuid::from_u128(1),
                "h".into(),
                Some(serde_json::json!({"type": "object"})),
                None,
            ))
        }
    }

    let upstream = Arc::new(InteractiveUpstream {
        seen_capabilities: Mutex::new(Vec::new()),
    });
    let catalog_store: SharedCatalogStore = Arc::new(FakeCatalog {
        tool_id: Uuid::from_u128(1),
        server_id: Uuid::from_u128(2),
        claim_outcome: ClaimOutcome::Granted,
        seen_issuer: std::sync::Mutex::new(None),
    });
    let svc = DefaultInvocationService::new(
        Arc::clone(&upstream) as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    )
    .with_audit_mode(AuditMode::BestEffort)
    .with_catalog_store(Some(catalog_store));

    let request =
        InvocationRequest::new("example-messages", "send").with_caller_capabilities(Some(
            rmcp::model::ClientCapabilities::builder()
                .enable_elicitation()
                .build(),
        ));
    let res = svc
        .invoke(Some(&principal("alice@example.com")), request)
        .await;
    assert!(
        matches!(res, Ok(waygate_invocation::InvocationResponse::Unary(_))),
        "an approval-gated call must complete in the round its grant covers: {res:?}",
    );
    let seen = upstream.seen_capabilities.lock().expect("recorder");
    assert_eq!(
        seen.as_slice(),
        &[false],
        "the approval-gated dispatch must advertise no input capabilities",
    );
}

/// Continuation inputs on an approval-gated call are refused BEFORE quota
/// and BEFORE the one-time grant claim: the grant is bound to the reviewed
/// tool + argument hash, and `inputResponses`/`requestState` live outside
/// that hash, so forwarding them would let unreviewed input ride the
/// operator's approval — and refusing any later would burn the grant on a
/// call that never dispatched.
#[tokio::test]
async fn approval_gated_call_refuses_continuation_inputs_before_the_grant_claim() {
    use waygate_mcp::InvocationStage;

    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observer = Arc::new(RecordingStageObserver::default());
    let svc = service_with_observer_and_evidence(
        true,
        true,
        ClaimOutcome::Granted,
        dispatched.clone(),
        Some(observer.clone()),
        Arc::new(NullSink),
    );
    let mut responses = rmcp::model::InputResponses::new();
    responses.insert("q1".to_owned(), serde_json::json!({"choice": "b"}));
    let request = InvocationRequest::new("example-messages", "send")
        .with_mrtr_retry(Some(responses), Some("state".to_owned()))
        .with_caller_capabilities(Some(
            rmcp::model::ClientCapabilities::builder()
                .enable_elicitation()
                .build(),
        ));
    let res = svc
        .invoke(Some(&principal("alice@example.com")), request)
        .await;
    match res {
        Err(waygate_invocation::InvocationError::InvalidArguments(reason)) => {
            assert!(
                reason.contains("single-round"),
                "teach-through must state the contract: {reason}",
            );
        }
        other => panic!("expected the continuation inputs to be refused, got {other:?}"),
    }
    assert!(
        !dispatched.load(std::sync::atomic::Ordering::SeqCst),
        "the refused call must never dispatch",
    );
    let stages = observer.snapshot();
    assert!(
        !stages.contains(&InvocationStage::CheckQuota)
            && !stages.contains(&InvocationStage::CheckApproval),
        "the refusal must precede quota and the grant claim: {stages:?}",
    );
}

/// The approval-gated single-round rule, state-only half: a capability-free
/// `requestState`-only pause is something no capability clearing can
/// prevent an upstream from returning, and its continuation could never
/// re-authorize (the grant is consumed; the retry's continuation inputs
/// are refused pre-claim). The pause is refused with a teach-through that
/// names the consumed grant, so the caller is not misled into retrying
/// into further grant burns.
#[tokio::test]
async fn approval_gated_state_only_pause_names_the_consumed_grant() {
    use rmcp::model::CallToolResponse;
    use waygate_mcp::catalog::ToolCallMrtr;

    /// Upstream that pauses state-only on every first round, regardless of
    /// what the dispatch declared.
    struct SheddingUpstream {
        dispatched: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl UpstreamCatalog for SheddingUpstream {
        async fn list_servers(&self) -> Vec<String> {
            vec!["example-messages".into()]
        }
        async fn list_tools(&self, _server: &str) -> Result<Vec<rmcp::model::Tool>, McpError> {
            Ok(vec![])
        }
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: Option<rmcp::model::JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("the pipeline dispatches through call_tool_response")
        }
        async fn call_tool_response(
            &self,
            _server: &str,
            _tool: &str,
            _args: Option<rmcp::model::JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
            _mrtr: ToolCallMrtr,
        ) -> Result<CallToolResponse, McpError> {
            self.dispatched
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(CallToolResponse::InputRequired(
                rmcp::model::InputRequiredResult::from_request_state("shed-1"),
            ))
        }
        fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
            ToolFacts {
                server: server.into(),
                name: tool_name.into(),
                risk: RiskTier::High,
                side_effects: true,
                pii: false,
                requires_approval: true,
                requires_approval_known: true,
            }
        }
        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> ResolvedInvocationTool {
            ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog(
                self.tool_facts(server, tool_name),
                Uuid::from_u128(1),
                "h".into(),
                Some(serde_json::json!({"type": "object"})),
                None,
            ))
        }
    }

    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream = Arc::new(SheddingUpstream {
        dispatched: dispatched.clone(),
    });
    let catalog_store: SharedCatalogStore = Arc::new(FakeCatalog {
        tool_id: Uuid::from_u128(1),
        server_id: Uuid::from_u128(2),
        claim_outcome: ClaimOutcome::Granted,
        seen_issuer: std::sync::Mutex::new(None),
    });
    let svc = DefaultInvocationService::new(
        upstream as Arc<dyn UpstreamCatalog>,
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    )
    .with_audit_mode(AuditMode::BestEffort)
    .with_catalog_store(Some(catalog_store));

    // A bare 2026 caller: state-only pauses are answerable for it on a
    // non-approval tool, which is exactly why the approval-gated refusal
    // must be its own precise branch.
    let request = InvocationRequest::new("example-messages", "send")
        .with_caller_capabilities(Some(rmcp::model::ClientCapabilities::default()));
    let res = svc
        .invoke(Some(&principal("alice@example.com")), request)
        .await;
    match res {
        Err(waygate_invocation::InvocationError::Upstream(err)) => {
            assert!(
                err.message.contains("grant was consumed"),
                "the refusal must name the consumed grant: {}",
                err.message,
            );
            assert!(
                err.message.contains("single-round"),
                "the refusal must state the contract: {}",
                err.message,
            );
        }
        other => panic!("expected the precise approval-pause refusal, got {other:?}"),
    }
    assert!(
        dispatched.load(std::sync::atomic::Ordering::SeqCst),
        "the pause arrives from a real dispatch (the grant was genuinely claimed first)",
    );
}

/// The grant claim is issuer-bound: the pipeline puts the CALLER's issuer
/// into the lookup, so a grant minted for the same `sub` under another
/// issuer (a different person) can never satisfy this call.
#[tokio::test]
async fn grant_claim_carries_the_callers_issuer() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream = Arc::new(FakeUpstream {
        requires_approval: true,
        requires_approval_known: true,
        dispatched: dispatched.clone(),
        approval_gated_seen: None,
    });
    let catalog_store = Arc::new(FakeCatalog {
        tool_id: Uuid::from_u128(1),
        server_id: Uuid::from_u128(2),
        claim_outcome: ClaimOutcome::Granted,
        seen_issuer: std::sync::Mutex::new(None),
    });
    let svc = DefaultInvocationService::new(upstream, Arc::new(AllowAllGate), Arc::new(NullSink))
        .with_audit_mode(AuditMode::BestEffort)
        .with_catalog_store(Some(catalog_store.clone() as SharedCatalogStore));
    let res = svc
        .invoke(
            Some(&principal("alice@example.com")),
            InvocationRequest::new("example-messages", "send"),
        )
        .await;
    assert!(res.is_ok(), "granted claim dispatches: {res:?}");
    assert_eq!(
        catalog_store
            .seen_issuer
            .lock()
            .expect("recorder")
            .as_deref(),
        Some("test"),
        "the claim lookup must carry the calling principal's issuer",
    );
}

#[derive(Default)]
struct SummaryNotifier(Mutex<Vec<waygate_invocation::HitlApprovalNeeded>>);

impl waygate_invocation::HitlNotifier for SummaryNotifier {
    fn notify_approval_needed(&self, event: waygate_invocation::HitlApprovalNeeded) {
        self.0.lock().unwrap().push(event);
    }
}

#[tokio::test]
async fn direct_approval_summary_uses_admitted_description_and_schema_fields_without_values() {
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream = Arc::new(FakeUpstream {
        requires_approval: true,
        requires_approval_known: true,
        dispatched: dispatched.clone(),
        approval_gated_seen: None,
    });
    let catalog_store: SharedCatalogStore = Arc::new(FakeCatalog {
        tool_id: Uuid::from_u128(1),
        server_id: Uuid::from_u128(2),
        claim_outcome: ClaimOutcome::NotFound,
        seen_issuer: Mutex::new(None),
    });
    let notifier = Arc::new(SummaryNotifier::default());
    let service =
        DefaultInvocationService::new(upstream, Arc::new(AllowAllGate), Arc::new(NullSink))
            .with_catalog_store(Some(catalog_store))
            .with_hitl_notifier(Some(notifier.clone()));
    let arguments =
        serde_json::json!({"selector": "synthetic-target", "contents": "synthetic-secret",
        "user-controlled-field-name": "opaque"})
        .as_object()
        .unwrap()
        .clone();
    let result = service
        .invoke(
            Some(&principal("fixture-reader")),
            InvocationRequest::new("example-messages", "send").with_arguments(Some(arguments)),
        )
        .await;
    assert!(matches!(
        result,
        Err(InvocationError::ApprovalRequired {
            satisfiable: true,
            ..
        })
    ));
    assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
    let events = notifier.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].summary.description.as_deref(),
        Some("Replace desired configuration. Upstream may retain submitted values. Deploy separately."));
    let mut fields = events[0].summary.affected_fields.clone();
    fields.sort_unstable();
    assert_eq!(fields, ["contents", "selector"]);
    let rendered = serde_json::to_string(&events[0].summary).unwrap();
    for forbidden in [
        "synthetic-secret",
        "synthetic-target",
        "opaque",
        "user-controlled-field-name",
        events[0].argument_hash.as_str(),
    ] {
        assert!(!rendered.contains(forbidden));
    }
}
