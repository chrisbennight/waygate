//! Admission-semantics contract for governed invocation tool snapshots.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock as Content, MetaObject as Meta, Tool};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use uuid::Uuid;
use waygate_invocation::{
    InvocationError, InvocationRequest, InvocationResponse, InvocationService,
};
use waygate_mcp::audit::{AuditOutcome, EvidenceCategory, EvidencePosture, InMemorySink, NullSink};
use waygate_mcp::authz::{AllowAllGate, ToolFacts};
use waygate_mcp::catalog::{
    InvocationToolSnapshot, OperationClassification, ResolvedInvocationTool, UpstreamCatalog,
};
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::DefaultInvocationService;

#[test]
fn security_metadata_is_bound_into_the_invocation_contract() {
    let snapshot = InvocationToolSnapshot::catalog_with_security_metadata(
        ToolFacts {
            server: "test".into(),
            name: "read".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: true,
            requires_approval: false,
            requires_approval_known: true,
        },
        Uuid::from_u128(9),
        "behavior-v1".into(),
        Some(json!({"type": "object"})),
        None,
        Some(json!({"readOnlyHint": true})),
        Some(json!({"outcome": "benign", "requiresReview": false})),
    );

    let identity = snapshot.contract_identity();
    assert!(identity.tool_annotations_hash.is_some());
    assert!(identity.action_metadata_hash.is_some());
}

#[test]
fn portability_projection_preserves_the_source_schema_identity() {
    let input = json!({
        "type": "object",
        "properties": {
            "value": {"type": ["string", "null"]},
            "anything": true
        }
    });
    let output = json!({
        "type": "object",
        "properties": {"result": true}
    });
    let snapshot = InvocationToolSnapshot::catalog(
        ToolFacts {
            server: "test".into(),
            name: "portable".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        },
        Uuid::from_u128(10),
        "behavior-v1".into(),
        Some(input.clone()),
        Some(output.clone()),
    );

    assert_ne!(snapshot.input_schema(), Some(&input));
    assert_ne!(snapshot.output_schema(), Some(&output));
    let identity = snapshot.contract_identity();
    assert_eq!(
        identity.input_schema_hash.as_deref(),
        Some(waygate_catalog::validator_schema_hash(&input).as_str())
    );
    assert_eq!(
        identity.output_schema_hash.as_deref(),
        Some(waygate_catalog::validator_schema_hash(&output).as_str())
    );
}

struct ChangingSchemaCatalog {
    schema: Mutex<Value>,
    resolutions: AtomicUsize,
    dispatches: AtomicUsize,
}

impl ChangingSchemaCatalog {
    fn new() -> Self {
        Self {
            schema: Mutex::new(json!({"type": "integer"})),
            resolutions: AtomicUsize::new(0),
            dispatches: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl UpstreamCatalog for ChangingSchemaCatalog {
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
        _principal: Option<&waygate_oidc::Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        *self.schema.lock().expect("schema lock poisoned") = json!({"type": "string"});
        let mut result = CallToolResult::success(vec![Content::text("changed")]);
        result.structured_content = Some(json!("changed"));
        Ok(result)
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        let schema = self.schema.lock().expect("schema lock poisoned").clone();
        ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog(
            ToolFacts {
                server: server.into(),
                name: tool_name.into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            Uuid::from_u128(1),
            "catalog-hash-without-output-schema".into(),
            Some(json!({"type": "object"})),
            Some(schema),
        ))
    }
}

#[tokio::test]
async fn in_flight_call_validates_against_its_admitted_schema() {
    let catalog = Arc::new(ChangingSchemaCatalog::new());
    let service =
        DefaultInvocationService::new(catalog.clone(), Arc::new(AllowAllGate), Arc::new(NullSink));

    let first = service
        .invoke(None, InvocationRequest::new("test", "tool"))
        .await
        .expect_err("v1 integer schema must reject the string response");
    assert!(matches!(
        first,
        InvocationError::OutputSchemaViolation { .. }
    ));
    assert_eq!(
        catalog.resolutions.load(Ordering::SeqCst),
        1,
        "one invocation must perform exactly one authoritative resolution"
    );
    assert_eq!(catalog.dispatches.load(Ordering::SeqCst), 1);

    let original_contract = InvocationToolSnapshot::catalog(
        ToolFacts {
            server: "test".into(),
            name: "tool".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        },
        Uuid::from_u128(1),
        "catalog-hash-without-output-schema".into(),
        Some(json!({"type": "object"})),
        Some(json!({"type": "integer"})),
    )
    .contract_identity();
    let changed = service
        .invoke(
            None,
            InvocationRequest::new("test", "tool").with_expected_contract(original_contract),
        )
        .await
        .expect_err("a later invocation must refuse the changed contract");
    assert!(matches!(
        changed,
        InvocationError::InvalidArguments(ref reason)
            if reason == "operation contract changed during execution: test.tool"
    ));
    assert_eq!(
        catalog.dispatches.load(Ordering::SeqCst),
        1,
        "contract drift must be refused before dispatch"
    );

    service
        .invoke(None, InvocationRequest::new("test", "tool"))
        .await
        .expect("a later invocation must admit and use the v2 string schema");
    assert_eq!(catalog.resolutions.load(Ordering::SeqCst), 3);
    assert_eq!(catalog.dispatches.load(Ordering::SeqCst), 2);
}

struct InvalidSchemaCatalog {
    dispatches: AtomicUsize,
}

#[async_trait]
impl UpstreamCatalog for InvalidSchemaCatalog {
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
        _principal: Option<&waygate_oidc::Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(CallToolResult::success(vec![Content::text("unexpected")]))
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog(
            ToolFacts {
                server: server.into(),
                name: tool_name.into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            Uuid::from_u128(2),
            "invalid-v1".into(),
            Some(json!({"type": "object"})),
            Some(json!({"type": {"schema-secret-marker": 42}})),
        ))
    }
}

#[tokio::test]
async fn invalid_approved_schema_is_refused_before_dispatch() {
    let catalog = Arc::new(InvalidSchemaCatalog {
        dispatches: AtomicUsize::new(0),
    });
    let sink = Arc::new(InMemorySink::new());
    let service =
        DefaultInvocationService::new(catalog.clone(), Arc::new(AllowAllGate), sink.clone());

    let error = service
        .invoke(None, InvocationRequest::new("test", "tool"))
        .await
        .expect_err("an invalid approved schema must fail before dispatch");

    assert!(matches!(error, InvocationError::ToolSchemaInvalid { .. }));
    assert_eq!(catalog.dispatches.load(Ordering::SeqCst), 0);
    assert!(!format!("{error:?}").contains("schema-secret-marker"));
    let rows = sink.snapshot_with_posture().await;
    assert_eq!(rows.len(), 1, "schema refusal emits one evidence row");
    assert_eq!(rows[0].posture, EvidencePosture::ChainedBestEffort);
    assert_eq!(rows[0].event.category, EvidenceCategory::Invocation);
    assert_eq!(rows[0].event.outcome, AuditOutcome::Denied);
    assert_eq!(
        rows[0].event.reason.as_deref(),
        Some("approved output schema is invalid")
    );
    assert!(!format!("{:?}", rows[0].event).contains("schema-secret-marker"));
}

struct UnresolvedOutputSchemaCatalog {
    dispatches: AtomicUsize,
}

impl UnresolvedOutputSchemaCatalog {
    fn snapshot(server: &str, tool_name: &str) -> InvocationToolSnapshot {
        InvocationToolSnapshot::catalog(
            ToolFacts {
                server: server.into(),
                name: tool_name.into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            Uuid::from_u128(4),
            "unresolved-output-v1".into(),
            Some(json!({"type": "object"})),
            Some(json!({
                "type": "object",
                "properties": {
                    "value": {"$ref": "https://schemas.example/value.json"}
                }
            })),
        )
    }
}

#[async_trait]
impl UpstreamCatalog for UnresolvedOutputSchemaCatalog {
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
        _principal: Option<&waygate_oidc::Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        let mut result = CallToolResult::success(vec![Content::text("available")]);
        result.structured_content = Some(json!({"value": "available"}));
        Ok(result)
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Ready(Self::snapshot(server, tool_name))
    }
}

#[tokio::test]
async fn unpublished_unresolved_output_schema_does_not_block_dispatch() {
    assert!(
        UnresolvedOutputSchemaCatalog::snapshot("test", "tool")
            .output_schema()
            .is_none(),
        "the unavailable optional contract must be removed during admission",
    );
    let catalog = Arc::new(UnresolvedOutputSchemaCatalog {
        dispatches: AtomicUsize::new(0),
    });
    let service =
        DefaultInvocationService::new(catalog.clone(), Arc::new(AllowAllGate), Arc::new(NullSink));

    service
        .invoke(None, InvocationRequest::new("test", "tool"))
        .await
        .expect("an omitted optional output schema must leave the tool callable");

    assert_eq!(catalog.dispatches.load(Ordering::SeqCst), 1);
}

struct TrustResultCatalog {
    annotation_native: bool,
    /// Force the dispatched result to be a tool-level error (is_error=true).
    is_error: bool,
    /// Reviewed INPUT sensitivity → projected into the `pii` fact.
    input_sensitive: bool,
    /// Reviewed RETURN sensitivity → the release gate's actual decision.
    anticipated_output: bool,
    trust: Option<Value>,
}

#[async_trait]
impl UpstreamCatalog for TrustResultCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["komodo".into()]
    }

    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(Vec::new())
    }

    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<rmcp::model::JsonObject>,
        _principal: Option<&waygate_oidc::Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        let mut result = CallToolResult::success(vec![Content::text("bounded result")]);
        result.is_error = self.is_error.then_some(true);
        let Some(trust) = self.trust.clone() else {
            return Ok(result);
        };
        let mut meta = Meta::new();
        meta.0
            .insert("io.modelcontextprotocol/trust-annotations".into(), trust);
        Ok(result.with_meta(Some(meta)))
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        let facts = ToolFacts {
            server: server.into(),
            name: tool_name.into(),
            risk: RiskTier::High,
            side_effects: false,
            pii: self.input_sensitive || self.anticipated_output,
            requires_approval: false,
            requires_approval_known: true,
        };
        let snapshot = if self.annotation_native {
            InvocationToolSnapshot::catalog_with_annotation_claims(
                facts,
                Uuid::from_u128(3),
                "trust-v1".into(),
                self.anticipated_output,
                Some(json!({"type": "object"})),
                None,
                Some(json!({
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                })),
                Some(json!({
                    "inputSensitivity": ["none"],
                    "outputSensitivity": if self.anticipated_output {
                        json!(["sensitive"])
                    } else {
                        json!(["none"])
                    }
                })),
            )
        } else {
            InvocationToolSnapshot::catalog(
                facts,
                Uuid::from_u128(3),
                "legacy-v1".into(),
                Some(json!({"type": "object"})),
                None,
            )
        };
        ResolvedInvocationTool::Ready(snapshot)
    }
}

async fn invoke_trust_result(
    catalog: TrustResultCatalog,
) -> Result<CallToolResult, InvocationError> {
    let service = DefaultInvocationService::new(
        Arc::new(catalog),
        Arc::new(AllowAllGate),
        Arc::new(NullSink),
    );
    match service
        .invoke(None, InvocationRequest::new("komodo", "stacks.config.read"))
        .await?
    {
        InvocationResponse::Unary(result) => Ok(result),
        _ => panic!("MCP tool dispatch must remain unary"),
    }
}

#[tokio::test]
async fn annotation_native_results_require_labels_and_enforce_declared_sensitivity() {
    for trust in [
        None,
        Some(json!({"sensitive": false})),
        Some(json!({"sensitive": "yes", "untrusted": true})),
    ] {
        let error = invoke_trust_result(TrustResultCatalog {
            annotation_native: true,
            is_error: false,
            input_sensitive: false,
            anticipated_output: false,
            trust,
        })
        .await
        .expect_err("missing or malformed trust labels must be withheld");
        assert!(matches!(
            error,
            InvocationError::ResponseInspectionBlocked {
                inspector_name: "trust-annotations",
                ..
            }
        ));
    }

    let error = invoke_trust_result(TrustResultCatalog {
        annotation_native: true,
        is_error: false,
        input_sensitive: false,
        anticipated_output: false,
        trust: Some(json!({"sensitive": true, "untrusted": true})),
    })
    .await
    .expect_err("unexpected sensitive output must be withheld");
    assert!(matches!(
        error,
        InvocationError::ResponseInspectionBlocked {
            inspector_name: "trust-annotations",
            ..
        }
    ));

    // A contract that anticipated protected INPUT but non-protected OUTPUT
    // must still block a sensitive result: the release gate keys on the
    // return classification, not the combined `pii` fact.
    let error = invoke_trust_result(TrustResultCatalog {
        annotation_native: true,
        is_error: false,
        input_sensitive: true,
        anticipated_output: false,
        trust: Some(json!({"sensitive": true, "untrusted": false})),
    })
    .await
    .expect_err("input-only sensitivity must not release a sensitive result");
    assert!(matches!(
        error,
        InvocationError::ResponseInspectionBlocked {
            inspector_name: "trust-annotations",
            ..
        }
    ));

    let result = invoke_trust_result(TrustResultCatalog {
        annotation_native: true,
        is_error: false,
        input_sensitive: false,
        anticipated_output: true,
        trust: Some(json!({
            "sensitive": true,
            "untrusted": true,
            "future": "preserved"
        })),
    })
    .await
    .expect("declared sensitive output must remain usable");
    let trust = result
        .meta
        .as_ref()
        .and_then(|meta| meta.0.get("io.modelcontextprotocol/trust-annotations"))
        .expect("trust labels must propagate to the caller");
    assert_eq!(trust["untrusted"], true);
    assert_eq!(trust["future"], "preserved");

    // An `is_error` result still returns its content to the caller, so the
    // trust gate governs it too: a missing-labels error is withheld rather
    // than allowed to leak unanticipated content.
    let error = invoke_trust_result(TrustResultCatalog {
        annotation_native: true,
        is_error: true,
        input_sensitive: false,
        anticipated_output: false,
        trust: None,
    })
    .await
    .expect_err("an error result must still carry trust labels");
    assert!(matches!(
        error,
        InvocationError::ResponseInspectionBlocked {
            inspector_name: "trust-annotations",
            ..
        }
    ));
}

#[tokio::test]
async fn legacy_results_do_not_require_annotation_native_trust_labels() {
    invoke_trust_result(TrustResultCatalog {
        annotation_native: false,
        is_error: false,
        input_sensitive: false,
        anticipated_output: false,
        trust: None,
    })
    .await
    .expect("legacy servers remain compatible");
}

struct AdmittedCapturingCatalog {
    admitted_seen: Mutex<Option<waygate_mcp::catalog::InvocationContractIdentity>>,
}

impl AdmittedCapturingCatalog {
    fn snapshot(server: &str, tool_name: &str) -> InvocationToolSnapshot {
        InvocationToolSnapshot::catalog(
            ToolFacts {
                server: server.into(),
                name: tool_name.into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            Uuid::from_u128(3),
            "admitted-v1".into(),
            Some(json!({"type": "object"})),
            None,
        )
    }
}

#[async_trait]
impl UpstreamCatalog for AdmittedCapturingCatalog {
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
        _principal: Option<&waygate_oidc::Principal>,
        admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        *self.admitted_seen.lock().expect("admitted lock poisoned") = admitted.cloned();
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Ready(Self::snapshot(server, tool_name))
    }
}

/// The pipeline must hand its Stage-1 admitted contract identity to the
/// dispatch boundary, so the upstream catalog can bind the RPC to the exact
/// contract that validation, authorization, and approval evaluated —
/// dispatching without it would let a racing catalog change execute a
/// contract the earlier stages never saw.
#[tokio::test]
async fn dispatch_forwards_the_admitted_contract_identity() {
    let catalog = Arc::new(AdmittedCapturingCatalog {
        admitted_seen: Mutex::new(None),
    });
    let service =
        DefaultInvocationService::new(catalog.clone(), Arc::new(AllowAllGate), Arc::new(NullSink));

    service
        .invoke(None, InvocationRequest::new("test", "tool"))
        .await
        .expect("invocation must dispatch");

    let seen = catalog
        .admitted_seen
        .lock()
        .expect("admitted lock poisoned")
        .clone();
    assert_eq!(
        seen,
        Some(AdmittedCapturingCatalog::snapshot("test", "tool").contract_identity()),
        "dispatch must carry the exact Stage-1 admitted contract identity",
    );
}

/// A high-risk executor whose narrow operation an operator has classified.
fn executor_snapshot() -> InvocationToolSnapshot {
    InvocationToolSnapshot::catalog(
        ToolFacts {
            server: "example-secrets".into(),
            name: "read".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: true,
            requires_approval: false,
            requires_approval_known: true,
        },
        Uuid::from_u128(11),
        "hash".into(),
        None,
        None,
    )
    .with_operation_classifications(
        Some("operation".into()),
        vec![OperationClassification {
            value: "projects.list".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
        }],
    )
}

#[test]
fn a_classified_operation_is_authorized_under_its_own_facts() {
    let snapshot = executor_snapshot();
    let args = json!({ "operation": "projects.list" });
    let facts = snapshot.facts_for(args.as_object());

    assert_eq!(facts.risk, RiskTier::Low);
    assert!(!facts.side_effects);
    assert!(!facts.pii);
    let resolution = snapshot.resolve_operation(args.as_object());
    assert_eq!(resolution.requested.as_deref(), Some("projects.list"));
    assert!(resolution.classified);
}

#[test]
fn anything_but_a_classified_match_keeps_the_tool_level_facts() {
    // The tool-level entry covers every value it does not name, so each of
    // these must land on it rather than on a weaker classification. The
    // manifest ceiling is what makes that the conservative direction.
    let snapshot = executor_snapshot();
    let cases: [(&str, Value, Option<&str>); 4] = [
        (
            "an argument no entry names",
            json!({"operation": "secrets.reveal"}),
            Some("secrets.reveal"),
        ),
        (
            "no discriminator argument at all",
            json!({"project": "p"}),
            None,
        ),
        (
            "a discriminator that is not a string",
            json!({"operation": 7}),
            None,
        ),
        ("no arguments", json!({}), None),
    ];

    for (case, args, expected_request) in cases {
        let facts = snapshot.facts_for(args.as_object());
        assert_eq!(facts.risk, RiskTier::High, "{case}");
        assert!(facts.side_effects, "{case}");
        assert!(facts.pii, "{case}");

        let resolution = snapshot.resolve_operation(args.as_object());
        assert!(!resolution.classified, "{case}");
        assert_eq!(
            resolution.requested.as_deref(),
            expected_request,
            "the audit trail records what was asked for: {case}"
        );
    }
}

#[test]
fn a_tool_naming_no_discriminator_is_unaffected() {
    let snapshot = InvocationToolSnapshot::catalog(
        ToolFacts {
            server: "example-messages".into(),
            name: "send".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: true,
            requires_approval: false,
            requires_approval_known: true,
        },
        Uuid::from_u128(12),
        "hash".into(),
        None,
        None,
    );
    let args = json!({ "operation": "projects.list" });

    let facts = snapshot.facts_for(args.as_object());
    assert_eq!(facts.risk, RiskTier::High);
    assert!(snapshot.discriminator().is_none());
    assert_eq!(snapshot.resolve_operation(args.as_object()).requested, None);
}

#[test]
fn identity_binds_the_operation_definition_but_not_the_call_arguments() {
    // The definition is part of what was reviewed: change it and a call
    // authorizes under different facts, so the dispatch-time re-check has to
    // see it. The call's arguments are not — the re-check rebuilds identity
    // without them, so folding them in would refuse every refined call.
    let snapshot = executor_snapshot();

    // Arguments do not enter identity: the snapshot has one identity, whatever
    // the caller later asks of it.
    let before = snapshot.contract_identity();
    let _ = snapshot.facts_for(json!({"operation": "projects.list"}).as_object());
    let _ = snapshot.facts_for(json!({"operation": "secrets.reveal"}).as_object());
    assert_eq!(snapshot.contract_identity(), before);

    // A tool naming no operations is a different contract from one that does.
    let no_operations = InvocationToolSnapshot::catalog(
        snapshot.facts().clone(),
        Uuid::from_u128(11),
        "hash".into(),
        None,
        None,
    );
    assert_ne!(
        snapshot.contract_identity(),
        no_operations.contract_identity()
    );

    // So is one whose entry classifies the same value differently.
    let relabelled = no_operations.with_operation_classifications(
        Some("operation".into()),
        vec![OperationClassification {
            value: "projects.list".into(),
            risk: RiskTier::Medium,
            side_effects: false,
            pii: false,
        }],
    );
    assert_ne!(snapshot.contract_identity(), relabelled.contract_identity());
}

#[test]
fn the_operation_definition_hashes_independently_of_entry_order() {
    // Two resolutions of one definition must compare equal, or the
    // dispatch-time re-check would refuse calls whenever a source emitted the
    // entries in a different order.
    let facts = executor_snapshot().facts().clone();
    let entry = |value: &str, risk| OperationClassification {
        value: value.into(),
        risk,
        side_effects: false,
        pii: false,
    };
    let build = |operations| {
        InvocationToolSnapshot::catalog(
            facts.clone(),
            Uuid::from_u128(11),
            "hash".into(),
            None,
            None,
        )
        .with_operation_classifications(Some("operation".into()), operations)
    };

    let ordered = build(vec![
        entry("projects.list", RiskTier::Low),
        entry("secrets.list", RiskTier::Medium),
    ]);
    let reversed = build(vec![
        entry("secrets.list", RiskTier::Medium),
        entry("projects.list", RiskTier::Low),
    ]);

    assert_eq!(ordered.contract_identity(), reversed.contract_identity());
}

/// A catalog serving one per-operation executor.
struct ExecutorCatalog;

#[async_trait]
impl UpstreamCatalog for ExecutorCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-secrets".to_owned()]
    }

    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(vec![])
    }

    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<serde_json::Map<String, Value>>,
        _principal: Option<&waygate_oidc::Principal>,
        _admitted: Option<&waygate_invocation::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }

    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Ready(
            InvocationToolSnapshot::catalog(
                ToolFacts {
                    server: server.into(),
                    name: tool_name.into(),
                    risk: RiskTier::High,
                    side_effects: true,
                    pii: true,
                    requires_approval: false,
                    requires_approval_known: true,
                },
                Uuid::from_u128(21),
                "hash".into(),
                Some(json!({"type": "object"})),
                None,
            )
            .with_operation_classifications(
                Some("operation".into()),
                vec![OperationClassification {
                    value: "projects.list".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                }],
            ),
        )
    }
}

/// Captures the facts the pipeline actually hands the gate.
#[derive(Default)]
struct RecordingGate {
    seen: Mutex<Option<waygate_core::Facts>>,
}

#[async_trait]
impl waygate_mcp::authz::AuthzGate for RecordingGate {
    async fn may_discover_server(&self, _principal: &waygate_oidc::Principal, _s: &str) -> bool {
        true
    }

    async fn authorize_tool_call(
        &self,
        facts: &waygate_core::Facts,
    ) -> waygate_mcp::authz::AuthzVerdict {
        *self.seen.lock().expect("lock poisoned") = Some(facts.clone());
        waygate_mcp::authz::AuthzVerdict::Allow { policy_ids: vec![] }
    }
}

async fn facts_for_call(operation: Option<&str>) -> waygate_core::Facts {
    let gate = Arc::new(RecordingGate::default());
    let service =
        DefaultInvocationService::new(Arc::new(ExecutorCatalog), gate.clone(), Arc::new(NullSink));

    let mut request = InvocationRequest::new("example-secrets", "read");
    if let Some(operation) = operation {
        request.arguments = Some(
            json!({ "operation": operation })
                .as_object()
                .expect("object")
                .clone(),
        );
    }

    let principal = waygate_oidc::Principal {
        sub: "someone".into(),
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
        api_key_profile_restrictions: None,
    };
    service
        .invoke(Some(&principal), request)
        .await
        .expect("call succeeds");

    let captured = gate
        .seen
        .lock()
        .expect("lock poisoned")
        .clone()
        .expect("the gate was consulted");
    drop(service);
    captured
}

#[tokio::test]
async fn the_pipeline_hands_policy_the_operation_the_call_selected() {
    // The policy-facing tests build the fact directly; this one runs a real
    // invocation, so deleting the population in the pipeline fails here rather
    // than leaving a green suite over a fact policy would never see.
    let facts = facts_for_call(Some("projects.list")).await;

    assert_eq!(facts.resource.operation.as_deref(), Some("projects.list"));
    assert_eq!(
        facts.resource.risk,
        RiskTier::Low,
        "and the classification the operation carries is what the gate sees",
    );
}

#[tokio::test]
async fn a_call_selecting_nothing_hands_policy_no_operation() {
    let facts = facts_for_call(None).await;

    assert_eq!(facts.resource.operation, None);
    assert_eq!(
        facts.resource.risk,
        RiskTier::High,
        "with the tool-level classification still in force",
    );
}

#[tokio::test]
async fn an_unclassified_operation_still_reaches_policy() {
    // The trail and a policy answer what was ASKED FOR, which is a different
    // question from what an operator has classified. A rule may want to name an
    // operation nobody has reviewed — and the classification that applied is
    // the tool's, visible in the risk beside it.
    let facts = facts_for_call(Some("secrets.reveal")).await;

    assert_eq!(
        facts.resource.operation.as_deref(),
        Some("secrets.reveal"),
        "a value no entry classifies must still be named to policy",
    );
    assert_eq!(
        facts.resource.risk,
        RiskTier::High,
        "while the tool-level classification stays in force for it",
    );
}

#[test]
fn an_oversized_discriminator_value_is_not_carried() {
    // The value is caller text and lands in an audit column and a policy
    // attribute. Anything longer than the catalog can store could never name a
    // classified operation, so carrying it would put unbounded caller input on
    // every audited call for no gain.
    let snapshot = executor_snapshot();
    let oversized = "x".repeat(257);
    let args = json!({ "operation": oversized });

    let resolution = snapshot.resolve_operation(args.as_object());
    assert!(
        resolution.inadmissible,
        "an out-of-range operation must refuse the call, not vanish from it: \
         dispatch forwards the arguments unchanged, so authorizing without it \
         would let the upstream act on an operation the gate never saw"
    );
    assert_eq!(resolution.requested, None);

    // An empty value names no operation, and the audit column will not hold it.
    let args = json!({ "operation": "" });
    assert!(snapshot.resolve_operation(args.as_object()).inadmissible);

    // Nor a control character: PostgreSQL TEXT cannot store a NUL, so the
    // operation-bearing insert would fail — and the final outcome is written
    // best-effort after dispatch, so the call would run and lose its audit row.
    // Nor one that renders as something other than what it is: a bidi override
    // or a zero-width character makes two different operations display
    // identically to whoever reads the trail.
    for name in [
        "projects\u{0}list",
        "projects\nlist",
        "projects\tlist",
        "secrets.\u{202e}laever",
        "projects\u{200b}.list",
        "projects.list\u{feff}",
        // Format controls the previous hand-written blocklist had missed. An
        // allowlist cannot fall behind a Unicode release this way.
        "projects\u{0890}.list",
        "projects\u{110cd}.list",
        "projects\u{13430}.list",
        "projects\u{1bca0}.list",
        // Whitespace, which is invisible wherever the name is later shown.
        "projects list",
        "projects.list\u{a0}",
    ] {
        let args = json!({ "operation": name });
        assert!(
            snapshot.resolve_operation(args.as_object()).inadmissible,
            "a name the audit column cannot hold must refuse the call"
        );
    }

    // The longest value the catalog accepts is still carried.
    let longest = "x".repeat(256);
    let args = json!({ "operation": longest });
    let resolution = snapshot.resolve_operation(args.as_object());
    assert!(
        !resolution.inadmissible,
        "the bound must admit what the catalog can hold"
    );
    assert_eq!(resolution.requested, Some(longest));

    // And a tool naming no discriminator is never refused for its arguments.
    let plain = InvocationToolSnapshot::catalog(
        snapshot.facts().clone(),
        Uuid::from_u128(31),
        "hash".into(),
        Some(json!({"type": "object"})),
        None,
    );
    assert!(
        !plain
            .resolve_operation(json!({ "operation": "" }).as_object())
            .inadmissible
    );
}

#[test]
fn a_legible_operation_name_is_carried_whatever_it_is_made_of() {
    // The rule is legibility, not a list of separators an upstream is expected
    // to use. Its operation names are its own, and refusing an unusual but
    // perfectly readable one is not this boundary's job.
    let snapshot = executor_snapshot();
    for name in [
        "projects.list",
        "dynamicSecretLeases.create",
        "cafe@v2",
        "secrets/reveal",
        "op[1]",
        "read+write",
        "v1::secrets",
    ] {
        let args = json!({ "operation": name });
        let resolution = snapshot.resolve_operation(args.as_object());
        assert!(
            !resolution.inadmissible,
            "`{name}` renders as itself and must be carried"
        );
        assert_eq!(resolution.requested.as_deref(), Some(name));
    }
}

#[tokio::test]
async fn the_pipeline_refuses_an_operation_it_will_not_carry() {
    // The security property, at the layer that enforces it: dispatch forwards
    // the caller's arguments unchanged, so a value the gate cannot be shown
    // must stop the call rather than be quietly omitted from the facts.
    let gate = Arc::new(RecordingGate::default());
    let service =
        DefaultInvocationService::new(Arc::new(ExecutorCatalog), gate.clone(), Arc::new(NullSink));

    let mut request = InvocationRequest::new("example-secrets", "read");
    request.arguments = Some(
        json!({ "operation": "x".repeat(257) })
            .as_object()
            .expect("object")
            .clone(),
    );

    let principal = waygate_oidc::Principal {
        sub: "someone".into(),
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
        api_key_profile_restrictions: None,
    };

    let error = service
        .invoke(Some(&principal), request)
        .await
        .expect_err("an operation the server will not carry must refuse the call");
    assert!(
        matches!(error, InvocationError::InvalidArguments(_)),
        "unexpected error: {error:?}"
    );
    assert!(
        gate.seen.lock().expect("lock poisoned").is_none(),
        "the refusal must land before authorization, not after it"
    );
}

/// The pre-parse routing-header gate's soundness contract: a snapshot
/// without operation refinements reports `facts_vary_by_arguments() ==
/// false`, and its `facts_for` returns exactly `facts()` for every
/// argument shape — including arguments that look like discriminators.
/// With refinements present the flag flips, and arguments really do
/// change the facts, so a header-only decision must not act.
#[test]
fn facts_are_argument_independent_exactly_when_unrefined() {
    let base = ToolFacts {
        server: "s".into(),
        name: "t".into(),
        risk: RiskTier::Low,
        side_effects: false,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    };
    let plain = InvocationToolSnapshot::catalog_with_security_metadata(
        base.clone(),
        Uuid::from_u128(1),
        "behavior-v1".into(),
        Some(json!({"type": "object"})),
        None,
        None,
        None,
    );
    assert!(!plain.facts_vary_by_arguments());

    let adversarial_args: Vec<Value> = vec![
        json!({}),
        json!({"mode": "delete"}),
        json!({"mode": 5}),
        json!({"mode": ""}),
        json!({"unrelated": "x", "mode": "escalate"}),
        json!({"mode": "x".repeat(4096)}),
    ];
    for args in &adversarial_args {
        let resolved = plain.facts_for(args.as_object());
        let same = resolved.server == base.server
            && resolved.name == base.name
            && resolved.risk == base.risk
            && resolved.side_effects == base.side_effects
            && resolved.pii == base.pii
            && resolved.requires_approval == base.requires_approval
            && resolved.requires_approval_known == base.requires_approval_known;
        assert!(same, "unrefined facts must not vary with arguments: {args}");
        assert_eq!(
            plain.resolve_operation(args.as_object()),
            Default::default(),
            "unrefined snapshots never name an operation: {args}"
        );
    }

    let refined = InvocationToolSnapshot::catalog_with_security_metadata(
        base,
        Uuid::from_u128(2),
        "behavior-v1".into(),
        Some(json!({"type": "object"})),
        None,
        None,
        None,
    )
    .with_operation_classifications(
        Some("mode".into()),
        vec![OperationClassification {
            value: "delete".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: false,
        }],
    );
    assert!(refined.facts_vary_by_arguments());
    let escalated = refined.facts_for(json!({"mode": "delete"}).as_object());
    assert_eq!(
        escalated.risk,
        RiskTier::High,
        "refined snapshots really do vary with arguments — the flag is load-bearing"
    );
}
