//! Behavioral contract for the code-owned MCP invocation-stage catalog.
//!
//! These tests observe public collaborator boundaries rather than private
//! helper implementations: a different internal algorithm must still enter
//! the same stages in order and stop at the rejecting gate.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock as Content, Tool};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use uuid::Uuid;
use waygate_invocation::{InvocationError, InvocationRequest, InvocationService};
use waygate_mcp::audit::{AuditOutcome, InMemorySink};
use waygate_mcp::authz::{AuthzGate, AuthzVerdict, ToolFacts};
use waygate_mcp::catalog::{
    InvocationToolSnapshot, OperationClassification, ResolvedInvocationTool, UpstreamCatalog,
};
use waygate_mcp::files::{
    FileOutputContext, FileOutputProcessor, PreparedFileOutput, SharedFileOutputProcessor,
};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::{DefaultInvocationService, InvocationStage, InvocationStageObserver};
use waygate_oidc::{ApiKeyProfileRestrictions, Principal};
use waygate_quota::{QuotaAction, QuotaContext, QuotaError, QuotaService};

#[derive(Default)]
struct RecordingObserver {
    stages: Mutex<Vec<InvocationStage>>,
}

impl InvocationStageObserver for RecordingObserver {
    fn enter(&self, stage: InvocationStage) {
        self.stages
            .lock()
            .expect("stage recorder poisoned")
            .push(stage);
    }
}

impl RecordingObserver {
    fn snapshot(&self) -> Vec<InvocationStage> {
        self.stages.lock().expect("stage recorder poisoned").clone()
    }
}

struct FakeCatalog {
    dispatched: Arc<AtomicBool>,
    fail_dispatch: bool,
    manifest_fallback: bool,
    input_schema: Option<Value>,
    output_schema: Option<Value>,
    side_effects: bool,
    requires_approval: bool,
    requires_approval_known: bool,
    /// Argument naming the operation, for a tool that dispatches by argument.
    /// `None` models an ordinary tool classified by name alone.
    discriminator: Option<String>,
    /// Values a reviewer classified. Each inherits the tool's own flags, which
    /// keeps every entry within the ceiling a real resolver enforces.
    operations: Vec<String>,
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
        _args: Option<rmcp::model::JsonObject>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        self.dispatched.store(true, Ordering::SeqCst);
        if self.fail_dispatch {
            Err(McpError::internal_error("canned upstream failure", None))
        } else {
            Ok(CallToolResult::success(vec![Content::text("ok")]))
        }
    }

    fn tool_facts(&self, server: &str, tool: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool.into(),
            risk: RiskTier::Low,
            side_effects: self.side_effects,
            pii: false,
            requires_approval: self.requires_approval,
            requires_approval_known: self.requires_approval_known,
        }
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool: &str,
    ) -> ResolvedInvocationTool {
        if self.manifest_fallback {
            return ResolvedInvocationTool::Ready(
                InvocationToolSnapshot::manifest_fallback_with_input_schema(
                    self.tool_facts(server, tool),
                    self.requires_approval_known,
                    self.input_schema.clone(),
                ),
            );
        }
        match (self.input_schema.clone(), self.output_schema.clone()) {
            (None, None) => {
                ResolvedInvocationTool::Ready(InvocationToolSnapshot::manifest_fallback(
                    self.tool_facts(server, tool),
                    self.requires_approval_known,
                ))
            }
            (input_schema, output_schema) => {
                let facts = self.tool_facts(server, tool);
                let operations = self
                    .operations
                    .iter()
                    .map(|value| OperationClassification {
                        value: value.clone(),
                        risk: facts.risk,
                        side_effects: facts.side_effects,
                        pii: facts.pii,
                    })
                    .collect();
                ResolvedInvocationTool::Ready(
                    InvocationToolSnapshot::catalog(
                        facts,
                        Uuid::from_u128(1),
                        "catalog-hash-without-output-schema".into(),
                        input_schema,
                        output_schema,
                    )
                    .with_operation_classifications(self.discriminator.clone(), operations),
                )
            }
        }
    }
}

enum AuthzMode {
    Allow,
    Deny,
}

struct FixedAuthz(AuthzMode);

#[async_trait]
impl AuthzGate for FixedAuthz {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }

    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        match self.0 {
            AuthzMode::Allow => AuthzVerdict::Allow { policy_ids: vec![] },
            AuthzMode::Deny => AuthzVerdict::Deny {
                reason: "canned deny".into(),
                policy_ids: vec!["deny-test".into()],
                reasons: vec!["test policy denied".into()],
            },
        }
    }
}

enum QuotaMode {
    Allow,
    Deny,
}

struct FixedQuota {
    mode: QuotaMode,
    calls: AtomicUsize,
}

#[async_trait]
impl QuotaService for FixedQuota {
    async fn check_and_consume(
        &self,
        _ctx: &QuotaContext,
        _actions: &[QuotaAction],
    ) -> Result<(), QuotaError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            QuotaMode::Allow => Ok(()),
            QuotaMode::Deny => Err(QuotaError::RateLimited {
                policy_id: Uuid::nil(),
                name: "test quota".into(),
                retry_after_seconds: 1,
            }),
        }
    }
}

struct Harness {
    service: DefaultInvocationService,
    observer: Arc<RecordingObserver>,
    quota: Arc<FixedQuota>,
    dispatched: Arc<AtomicBool>,
    audit: Arc<InMemorySink>,
}

struct FakeFileProcessor {
    output: Value,
    events: Arc<Mutex<Vec<&'static str>>>,
    publish_error: bool,
}

#[async_trait]
impl FileOutputProcessor for FakeFileProcessor {
    async fn prepare(
        &self,
        _context: FileOutputContext,
        mut result: CallToolResult,
    ) -> Result<PreparedFileOutput, McpError> {
        self.events.lock().unwrap().push("prepare");
        result.structured_content = Some(self.output.clone());
        Ok(PreparedFileOutput {
            result,
            batch_id: Some("test-batch".to_owned()),
            file_count: 1,
        })
    }

    async fn publish(&self, batch_id: &str, file_count: usize) -> Result<(), McpError> {
        assert_eq!(batch_id, "test-batch");
        assert_eq!(file_count, 1);
        self.events.lock().unwrap().push("publish");
        if self.publish_error {
            Err(McpError::internal_error("publish failed", None))
        } else {
            Ok(())
        }
    }

    async fn discard(&self, batch_id: &str) {
        assert_eq!(batch_id, "test-batch");
        self.events.lock().unwrap().push("discard");
    }
}

fn harness(authz: AuthzMode, quota: QuotaMode, fail_dispatch: bool) -> Harness {
    harness_with_schemas(authz, quota, fail_dispatch, None, None)
}

fn harness_with_output_schema(
    authz: AuthzMode,
    quota: QuotaMode,
    fail_dispatch: bool,
    output_schema: Option<Value>,
) -> Harness {
    harness_with_schemas(
        authz,
        quota,
        fail_dispatch,
        output_schema.as_ref().map(|_| json!({"type": "object"})),
        output_schema,
    )
}

fn harness_with_input_schema(
    authz: AuthzMode,
    quota: QuotaMode,
    fail_dispatch: bool,
    input_schema: Value,
) -> Harness {
    harness_with_schemas(authz, quota, fail_dispatch, Some(input_schema), None)
}

fn manifest_fallback_harness_with_input_schema(input_schema: Value) -> Harness {
    harness_with_schemas_and_file_processor(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        Some(input_schema),
        None,
        None,
        true,
    )
}

fn harness_with_schemas(
    authz: AuthzMode,
    quota: QuotaMode,
    fail_dispatch: bool,
    input_schema: Option<Value>,
    output_schema: Option<Value>,
) -> Harness {
    harness_with_schemas_and_file_processor(
        authz,
        quota,
        fail_dispatch,
        input_schema,
        output_schema,
        None,
        false,
    )
}

fn harness_with_schemas_and_file_processor(
    authz: AuthzMode,
    quota: QuotaMode,
    fail_dispatch: bool,
    input_schema: Option<Value>,
    output_schema: Option<Value>,
    file_output_processor: Option<SharedFileOutputProcessor>,
    manifest_fallback: bool,
) -> Harness {
    let observer = Arc::new(RecordingObserver::default());
    let dispatched = Arc::new(AtomicBool::new(false));
    let quota = Arc::new(FixedQuota {
        mode: quota,
        calls: AtomicUsize::new(0),
    });
    let audit = Arc::new(InMemorySink::new());
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog {
            dispatched: dispatched.clone(),
            fail_dispatch,
            manifest_fallback,
            input_schema,
            output_schema,
            side_effects: false,
            requires_approval: false,
            requires_approval_known: true,
            discriminator: None,
            operations: Vec::new(),
        }),
        Arc::new(FixedAuthz(authz)),
        audit.clone(),
    )
    .with_quota(Some(quota.clone()))
    .with_file_output_processor(file_output_processor)
    .with_stage_observer(observer.clone());
    Harness {
        service,
        observer,
        quota,
        dispatched,
        audit,
    }
}

fn read_only_harness(
    side_effects: bool,
    requires_approval: bool,
    requires_approval_known: bool,
) -> Harness {
    read_only_harness_with_lane(
        side_effects,
        requires_approval,
        requires_approval_known,
        None,
        &[],
    )
}

/// A read-only harness whose tool dispatches by `discriminator`, admitting
/// exactly the operations in `values`.
fn read_only_lane_harness(discriminator: &str, values: &[&str]) -> Harness {
    read_only_harness_with_lane(false, false, true, Some(discriminator), values)
}

fn read_only_harness_with_lane(
    side_effects: bool,
    requires_approval: bool,
    requires_approval_known: bool,
    discriminator: Option<&str>,
    values: &[&str],
) -> Harness {
    let observer = Arc::new(RecordingObserver::default());
    let dispatched = Arc::new(AtomicBool::new(false));
    let quota = Arc::new(FixedQuota {
        mode: QuotaMode::Allow,
        calls: AtomicUsize::new(0),
    });
    let audit = Arc::new(InMemorySink::new());
    let service = DefaultInvocationService::new(
        Arc::new(FakeCatalog {
            dispatched: dispatched.clone(),
            fail_dispatch: false,
            manifest_fallback: false,
            input_schema: requires_approval_known.then(|| json!({"type": "object"})),
            output_schema: None,
            side_effects,
            requires_approval,
            requires_approval_known,
            discriminator: discriminator.map(str::to_owned),
            operations: values.iter().map(|value| (*value).to_owned()).collect(),
        }),
        Arc::new(FixedAuthz(AuthzMode::Allow)),
        audit.clone(),
    )
    .with_quota(Some(quota.clone()))
    .with_stage_observer(observer.clone());
    Harness {
        service,
        observer,
        quota,
        dispatched,
        audit,
    }
}

fn principal(restrictions: Option<ApiKeyProfileRestrictions>) -> Principal {
    Principal {
        sub: "alice".into(),
        email: None,
        groups: vec![],
        issuer: "https://auth.test".into(),
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

async fn invoke(
    harness: &Harness,
    principal: &Principal,
) -> Result<waygate_invocation::InvocationResponse, InvocationError> {
    invoke_with_arguments(harness, principal, None).await
}

async fn invoke_with_arguments(
    harness: &Harness,
    principal: &Principal,
    arguments: Option<serde_json::Map<String, Value>>,
) -> Result<waygate_invocation::InvocationResponse, InvocationError> {
    let mut request = InvocationRequest::new("test", "tool");
    request.arguments = arguments;
    harness.service.invoke(Some(principal), request).await
}

async fn invoke_read_only(
    harness: &Harness,
    principal: &Principal,
) -> Result<waygate_invocation::InvocationResponse, InvocationError> {
    harness
        .service
        .invoke(
            Some(principal),
            InvocationRequest::new("test", "tool").read_only(),
        )
        .await
}

async fn invoke_read_only_with_arguments(
    harness: &Harness,
    principal: &Principal,
    arguments: Option<serde_json::Map<String, Value>>,
) -> Result<waygate_invocation::InvocationResponse, InvocationError> {
    let mut request = InvocationRequest::new("test", "tool").read_only();
    request.arguments = arguments;
    harness.service.invoke(Some(principal), request).await
}

fn selects(operation: &str) -> Option<serde_json::Map<String, Value>> {
    json!({ "operation": operation }).as_object().cloned()
}

#[tokio::test]
async fn read_only_mode_allows_a_non_effecting_snapshot_through_the_full_pipeline() {
    let harness = read_only_harness(false, false, true);

    invoke_read_only(&harness, &principal(None))
        .await
        .expect("read-only snapshot is callable");

    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 1);
    assert!(harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn saved_file_outputs_are_published_after_output_validation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let processor: SharedFileOutputProcessor = Arc::new(FakeFileProcessor {
        output: json!({"uri": "mcp-file://gateway/file"}),
        events: events.clone(),
        publish_error: false,
    });
    let harness = harness_with_schemas_and_file_processor(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        Some(json!({"type": "object"})),
        Some(json!({"type": "object", "required": ["uri"]})),
        Some(processor),
        false,
    );

    invoke(&harness, &principal(None))
        .await
        .expect("valid saved file output");

    assert_eq!(*events.lock().unwrap(), vec!["prepare", "publish"]);
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL);
}

#[tokio::test]
async fn saved_file_outputs_are_discarded_when_output_validation_fails() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let processor: SharedFileOutputProcessor = Arc::new(FakeFileProcessor {
        output: json!({"uri": "mcp-file://gateway/file"}),
        events: events.clone(),
        publish_error: false,
    });
    let harness = harness_with_schemas_and_file_processor(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        Some(json!({"type": "object"})),
        Some(json!({"type": "string"})),
        Some(processor),
        false,
    );

    invoke(&harness, &principal(None))
        .await
        .expect_err("invalid saved file output");

    assert_eq!(*events.lock().unwrap(), vec!["prepare", "discard"]);
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..14]);
}

#[tokio::test]
async fn file_publication_failure_is_discarded_and_records_the_call_failure() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let processor: SharedFileOutputProcessor = Arc::new(FakeFileProcessor {
        output: json!({"uri": "mcp-file://gateway/file"}),
        events: events.clone(),
        publish_error: true,
    });
    let harness = harness_with_schemas_and_file_processor(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        Some(json!({"type": "object"})),
        Some(json!({"type": "object", "required": ["uri"]})),
        Some(processor),
        false,
    );

    invoke(&harness, &principal(None))
        .await
        .expect_err("a failed publication must fail the call");

    assert_eq!(
        *events.lock().unwrap(),
        vec!["prepare", "publish", "discard"]
    );
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL);
    assert!(harness.audit.snapshot().await.iter().any(|event| {
        event.action == "CallTool" && event.outcome == AuditOutcome::ExecutionError
    }));
}

#[tokio::test]
async fn read_only_mode_refuses_effects_and_approval_before_any_later_stage() {
    for (side_effects, requires_approval, requires_approval_known) in [
        (true, false, true),
        (false, true, true),
        (false, false, false),
    ] {
        let harness = read_only_harness(side_effects, requires_approval, requires_approval_known);

        let error = invoke_read_only(&harness, &principal(None))
            .await
            .expect_err("read-only ceiling must refuse the snapshot");

        assert!(matches!(
            error,
            InvocationError::ReadOnlyRequired { ref tool } if tool == "test.tool"
        ));
        assert_eq!(
            harness.observer.snapshot(),
            vec![InvocationStage::ResolveTool]
        );
        assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
        assert!(!harness.dispatched.load(Ordering::SeqCst));
        let events = harness.audit.snapshot().await;
        assert_eq!(events.len(), 1, "read-only refusal is audited once");
        assert_eq!(events[0].outcome, AuditOutcome::Denied);
        assert_eq!(events[0].server.as_deref(), Some("test"));
        assert_eq!(events[0].tool.as_deref(), Some("tool"));
    }
}

#[tokio::test]
async fn read_only_mode_admits_a_reviewed_operation_of_a_dispatch_tool() {
    let harness = read_only_lane_harness("operation", &["projects.list"]);

    invoke_read_only_with_arguments(&harness, &principal(None), selects("projects.list"))
        .await
        .expect("a reviewed operation is callable under the ceiling");

    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL);
    assert!(harness.dispatched.load(Ordering::SeqCst));
}

/// A dispatch tool's own entry classifies a set nobody enumerated, and under a
/// restricted ceiling it is the claim that admitted the tool at all. An
/// operation no reviewer named must not inherit it — including the case where
/// the call names no operation whatsoever, which would otherwise be the
/// cheapest way to land on the unreviewed fallback.
#[tokio::test]
async fn read_only_mode_refuses_an_unreviewed_operation_before_any_later_stage() {
    for arguments in [selects("secrets.reveal"), None] {
        let harness = read_only_lane_harness("operation", &["projects.list"]);

        let error = invoke_read_only_with_arguments(&harness, &principal(None), arguments)
            .await
            .expect_err("an unreviewed operation must be refused");

        assert!(matches!(
            error,
            InvocationError::ReadOnlyOperationRequired { ref tool, ref discriminator, .. }
                if tool == "test.tool" && discriminator == "operation"
        ));
        assert_eq!(
            harness.observer.snapshot(),
            vec![InvocationStage::ResolveTool]
        );
        assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
        assert!(!harness.dispatched.load(Ordering::SeqCst));
        let events = harness.audit.snapshot().await;
        assert_eq!(events.len(), 1, "the refusal is audited once");
        assert_eq!(events[0].outcome, AuditOutcome::Denied);
        assert!(
            events[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no reviewed classification")),
            "the trail must say which refusal this was",
        );
    }
}

/// The ceiling is the only thing that changes. An ordinary call keeps the
/// documented refinement semantics, where a value no entry names leaves the
/// tool-level classification in force rather than refusing.
#[tokio::test]
async fn unrestricted_mode_still_admits_an_unreviewed_operation_on_its_tool_classification() {
    let harness = read_only_lane_harness("operation", &["projects.list"]);

    invoke_with_arguments(&harness, &principal(None), selects("secrets.reveal"))
        .await
        .expect("an unrestricted call falls back to the tool-level entry");

    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL);
    assert!(harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn successful_invocation_enters_every_stage_in_catalog_order() {
    let harness = harness(AuthzMode::Allow, QuotaMode::Allow, false);

    invoke(&harness, &principal(None))
        .await
        .expect("successful invocation");

    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL);
    assert!(harness.dispatched.load(Ordering::SeqCst));
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 1);
    assert_eq!(InvocationStage::ValidateInput.status().id(), "active");
}

#[tokio::test]
async fn invalid_input_stops_before_authorization_quota_and_dispatch_without_exposing_values() {
    let harness = harness_with_input_schema(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        json!({
            "type": "object",
            "additionalProperties": {"type": "integer"}
        }),
    );
    let arguments = serde_json::Map::from_iter([(
        "caller-key-secret-marker".into(),
        Value::String("argument-secret-marker".into()),
    )]);

    let error = invoke_with_arguments(&harness, &principal(None), Some(arguments))
        .await
        .expect_err("invalid input must be refused");

    assert!(matches!(
        &error,
        InvocationError::InputSchemaViolation { tool, reason }
            if tool == "test.tool" && reason.contains("type mismatch")
    ));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..2]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
    assert!(!format!("{error:?}").contains("argument-secret-marker"));
    assert!(!format!("{error:?}").contains("caller-key-secret-marker"));
    let events = harness.audit.snapshot().await;
    assert_eq!(events.len(), 1, "validation refusal is audited once");
    assert_eq!(events[0].action, "CallTool");
    assert_eq!(events[0].outcome, AuditOutcome::Denied);
    assert_eq!(events[0].server.as_deref(), Some("test"));
    assert_eq!(events[0].tool.as_deref(), Some("tool"));
    assert!(events[0]
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("input schema violation")),);
    assert!(
        !format!("{:?}", events[0]).contains("argument-secret-marker"),
        "the denied audit row must not contain argument values",
    );
    assert!(
        !format!("{:?}", events[0]).contains("caller-key-secret-marker"),
        "the denied audit row must not contain caller-controlled object keys",
    );
}

#[tokio::test]
async fn missing_arguments_validate_as_an_empty_object() {
    let harness = harness_with_input_schema(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        json!({
            "type": "object",
            "required": ["message"]
        }),
    );

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("missing required input must be refused");

    assert!(matches!(
        error,
        InvocationError::InputSchemaViolation { reason, .. }
            if reason.contains("required field `message` is missing")
    ));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..2]);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn invalid_input_schema_stops_before_authorization_quota_and_dispatch() {
    let harness = harness_with_input_schema(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        json!({"type": {"schema-secret-marker": 42}}),
    );

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("invalid approved input schema must be refused");

    assert!(matches!(
        &error,
        InvocationError::InputSchemaInvalid { tool } if tool == "test.tool"
    ));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..2]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
    assert!(!format!("{error:?}").contains("schema-secret-marker"));
}

#[tokio::test]
async fn input_schema_without_mcp_object_root_stops_before_dispatch() {
    let harness = harness_with_input_schema(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        json!({"anyOf": [{"type": "object", "required": ["message"]}]}),
    );

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("composition-only input schema must be refused");

    assert!(matches!(error, InvocationError::InputSchemaInvalid { .. }));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..2]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn manifest_fallback_with_unpublishable_input_schema_fails_closed() {
    for schema in [
        json!({"type": "array"}),
        json!({
            "type": "object",
            "properties": {
                "value": {"$ref": "https://schemas.example/unavailable.json"}
            }
        }),
    ] {
        let harness = manifest_fallback_harness_with_input_schema(schema);

        let error = invoke(&harness, &principal(None))
            .await
            .expect_err("an unavailable fallback input contract must be refused");

        assert!(matches!(error, InvocationError::InputSchemaInvalid { .. }));
        assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..2]);
        assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
        assert!(!harness.dispatched.load(Ordering::SeqCst));
        let events = harness.audit.snapshot().await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].reason.as_deref(),
            Some("admitted input schema is unavailable"),
        );
    }
}

#[tokio::test]
async fn catalog_snapshot_without_an_input_schema_fails_closed_before_dispatch() {
    let harness = harness_with_schemas(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        None,
        Some(json!({})),
    );

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("catalog calls without an admitted input schema must be refused");

    assert!(matches!(error, InvocationError::InputSchemaInvalid { .. }));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..2]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
    let events = harness.audit.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].reason.as_deref(),
        Some("admitted input schema is unavailable"),
    );
}

#[tokio::test]
async fn authorization_denial_stops_before_profile_quota_and_dispatch() {
    let harness = harness(AuthzMode::Deny, QuotaMode::Allow, false);

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("authorization must deny");

    assert!(matches!(error, InvocationError::Forbidden { .. }));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..4]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn authorization_denial_hides_invalid_output_schema_state() {
    let harness = harness_with_output_schema(
        AuthzMode::Deny,
        QuotaMode::Allow,
        false,
        Some(json!({"type": {"schema-secret-marker": 42}})),
    );

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("authorization must take precedence over schema health");

    assert!(matches!(error, InvocationError::Forbidden { .. }));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..4]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn profile_denial_occurs_after_authorization_and_before_quota() {
    let harness = harness(AuthzMode::Allow, QuotaMode::Allow, false);
    let restrictions = ApiKeyProfileRestrictions {
        profile_id: "profile-id".into(),
        profile_name: "restricted".into(),
        allowed_servers: Some(vec!["another-server".into()]),
        allowed_tools: None,
    };

    let error = invoke(&harness, &principal(Some(restrictions)))
        .await
        .expect_err("profile must deny");

    assert!(matches!(
        error,
        InvocationError::ProfileServerNotAllowed { .. }
    ));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..5]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn profile_denial_hides_invalid_output_schema_state() {
    let harness = harness_with_output_schema(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        Some(json!({"type": {"schema-secret-marker": 42}})),
    );
    let restrictions = ApiKeyProfileRestrictions {
        profile_id: "profile-id".into(),
        profile_name: "restricted".into(),
        allowed_servers: Some(vec!["another-server".into()]),
        allowed_tools: None,
    };

    let error = invoke(&harness, &principal(Some(restrictions)))
        .await
        .expect_err("profile denial must take precedence over schema health");

    assert!(matches!(
        error,
        InvocationError::ProfileServerNotAllowed { .. }
    ));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..5]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn authorized_invalid_schema_stops_before_quota_and_dispatch() {
    let harness = harness_with_output_schema(
        AuthzMode::Allow,
        QuotaMode::Allow,
        false,
        Some(json!({"type": {"schema-secret-marker": 42}})),
    );

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("authorized invalid schema must fail before resource consumption");

    assert!(matches!(&error, InvocationError::ToolSchemaInvalid { .. }));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..6]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 0);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
    assert!(!format!("{error:?}").contains("schema-secret-marker"));
}

#[tokio::test]
async fn quota_denial_stops_before_approval_and_dispatch() {
    let harness = harness(AuthzMode::Allow, QuotaMode::Deny, false);

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("quota must deny");

    assert!(matches!(error, InvocationError::RateLimited { .. }));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL[..7]);
    assert_eq!(harness.quota.calls.load(Ordering::SeqCst), 1);
    assert!(!harness.dispatched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn dispatch_failure_still_enters_inspection_validation_and_final_outcome() {
    let harness = harness(AuthzMode::Allow, QuotaMode::Allow, true);

    let error = invoke(&harness, &principal(None))
        .await
        .expect_err("dispatch must fail");

    assert!(matches!(error, InvocationError::Upstream(_)));
    assert_eq!(harness.observer.snapshot(), InvocationStage::ALL);
    assert!(harness.dispatched.load(Ordering::SeqCst));
}
