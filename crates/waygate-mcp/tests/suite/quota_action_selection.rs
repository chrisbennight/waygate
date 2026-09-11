//! Pins the quota action-selection contract after the campaign decouple: the
//! `HighRiskCall` quota bucket fires on `facts.side_effects`, NOT the risk tier.
//! A `low + side_effects` tool consumes `[Call, HighRiskCall]`; a
//! `high + !side_effects` tool consumes only `[Call]`. The quota stage no-ops
//! for anonymous calls, so these invoke WITH a principal and capture the
//! `actions` vector passed to `QuotaService::check_and_consume`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ContentBlock as Content, Tool};
use rmcp::ErrorData as McpError;
use waygate_mcp::audit::NullSink;
use waygate_mcp::authz::{AllowAllGate, ToolFacts};
use waygate_mcp::catalog::UpstreamCatalog;
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::DefaultInvocationService;
use waygate_oidc::Principal;
use waygate_quota::{QuotaAction, QuotaContext, QuotaError, QuotaService};

use waygate_invocation::{InvocationRequest, InvocationResponse, InvocationService};

/// Catalog fake returning one configured `ToolFacts` and a canned success.
struct FakeCatalog {
    facts: ToolFacts,
    input_schema: Option<serde_json::Value>,
    /// Records the `requestState` each dispatch carried, so a test can prove
    /// the upstream receives its own opaque blob rather than the gateway's
    /// envelope. `None` when this fake refuses MRTR passthrough (the default).
    dispatched_state: Option<Arc<Mutex<Vec<Option<String>>>>>,
    /// When set, the first leg of a call pauses with these input requests
    /// and the upstream's own opaque state, so a test can drive a real
    /// pause through the production sealing path.
    pause_with: Option<rmcp::model::InputRequests>,
}

#[async_trait]
impl UpstreamCatalog for FakeCatalog {
    async fn list_servers(&self) -> Vec<String> {
        vec!["test".into()]
    }
    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> waygate_mcp::catalog::ResolvedInvocationTool {
        waygate_mcp::catalog::ResolvedInvocationTool::Ready(
            waygate_mcp::catalog::InvocationToolSnapshot::manifest_fallback_with_input_schema(
                self.tool_facts(server, tool_name),
                true,
                self.input_schema.clone(),
            ),
        )
    }
    async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
        Ok(Vec::new())
    }
    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        _args: Option<serde_json::Map<String, serde_json::Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }
    async fn call_tool_response(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<serde_json::Map<String, serde_json::Value>>,
        principal: Option<&Principal>,
        admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        mrtr: waygate_mcp::catalog::ToolCallMrtr,
    ) -> Result<rmcp::model::CallToolResponse, McpError> {
        let Some(dispatched) = self.dispatched_state.as_ref() else {
            // Keep the default fake's refusal of MRTR passthrough.
            return waygate_mcp::catalog::UpstreamCatalog::call_tool(
                self, server, tool_name, args, principal, admitted,
            )
            .await
            .map(rmcp::model::CallToolResponse::Complete);
        };
        // First leg of a pausing tool: hand back the upstream's own pause so
        // the gateway seals it exactly as it would in production.
        if let (Some(requests), None) = (self.pause_with.as_ref(), mrtr.input_responses.as_ref()) {
            let mut pause = rmcp::model::InputRequiredResult::from_input_requests(requests.clone());
            pause.request_state = Some("upstream-blob".to_owned());
            return Ok(rmcp::model::CallToolResponse::InputRequired(pause));
        }
        dispatched.lock().unwrap().push(mrtr.request_state.clone());
        Ok(rmcp::model::CallToolResponse::Complete(
            CallToolResult::success(vec![Content::text("ok")]),
        ))
    }

    fn tool_facts(&self, _server: &str, _tool: &str) -> ToolFacts {
        self.facts.clone()
    }
}

/// QuotaService fake that records every action class it is asked to consume and
/// always allows the call.
#[derive(Default)]
struct RecordingQuota {
    seen: Mutex<Vec<QuotaAction>>,
}

#[async_trait]
impl QuotaService for RecordingQuota {
    async fn check_and_consume(
        &self,
        _ctx: &QuotaContext,
        actions: &[QuotaAction],
    ) -> Result<(), QuotaError> {
        self.seen.lock().unwrap().extend_from_slice(actions);
        Ok(())
    }
}

fn principal() -> Principal {
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
        api_key_profile_restrictions: None,
    }
}

fn facts(risk: RiskTier, side_effects: bool) -> ToolFacts {
    ToolFacts {
        server: "test".into(),
        name: "t".into(),
        risk,
        side_effects,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    }
}

/// Invoke a tool with the given facts and a wired recording quota; return the
/// action classes the quota stage was asked to consume.
async fn quota_actions_for(f: ToolFacts) -> Vec<QuotaAction> {
    let quota = Arc::new(RecordingQuota::default());
    let quota_dyn: Arc<dyn QuotaService> = quota.clone();
    let catalog = Arc::new(FakeCatalog {
        facts: f,
        input_schema: None,
        dispatched_state: None,
        pause_with: None,
    });
    let svc: Arc<dyn InvocationService> = Arc::new(
        DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), Arc::new(NullSink))
            .with_quota(Some(quota_dyn)),
    );
    let p = principal();
    svc.invoke(Some(&p), InvocationRequest::new("test", "t"))
        .await
        .expect("dispatch should succeed (AllowAll gate, quota allows)");
    let seen = quota.seen.lock().unwrap().clone();
    seen
}

/// File-input processor whose deterministic admission always refuses; its
/// delivery stage must never be reached for a refused call.
struct RefusingFileProcessor;

#[async_trait]
impl waygate_mcp::files::FileInputProcessor for RefusingFileProcessor {
    fn admit(
        &self,
        _input_schema: Option<&serde_json::Value>,
        _compiled: Option<&jsonschema::Validator>,
        _arguments: &mut Option<serde_json::Map<String, serde_json::Value>>,
        _input_responses: Option<&std::collections::BTreeMap<String, serde_json::Value>>,
        _deliverable_keys: &[String],
    ) -> Result<(), McpError> {
        Err(McpError::invalid_params(
            "tool input does not admit inline data: values here; upload the file instead",
            None,
        ))
    }

    async fn prepare(
        &self,
        _context: waygate_mcp::files::FileInputContext,
        _input_schema: Option<&serde_json::Value>,
        _arguments: &mut Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<bool, McpError> {
        panic!("file delivery must not run for a call whose admission was refused");
    }

    async fn prepare_continuation(
        &self,
        _context: waygate_mcp::files::FileInputContext,
        _input_responses: &mut std::collections::BTreeMap<String, serde_json::Value>,
        _file_keys: &[String],
    ) -> Result<bool, McpError> {
        panic!("continuation delivery must not run for a call whose admission was refused");
    }
}

/// Records whether continuation delivery was reached, so a test can tell a
/// verified retry from one the pipeline refused or skipped.
#[derive(Default)]
struct ContinuationRecordingProcessor {
    delivered: Mutex<Vec<String>>,
}

#[async_trait]
impl waygate_mcp::files::FileInputProcessor for ContinuationRecordingProcessor {
    fn admit(
        &self,
        _input_schema: Option<&serde_json::Value>,
        _compiled: Option<&jsonschema::Validator>,
        _arguments: &mut Option<serde_json::Map<String, serde_json::Value>>,
        _input_responses: Option<&std::collections::BTreeMap<String, serde_json::Value>>,
        _deliverable_keys: &[String],
    ) -> Result<(), McpError> {
        Ok(())
    }

    async fn prepare(
        &self,
        _context: waygate_mcp::files::FileInputContext,
        _input_schema: Option<&serde_json::Value>,
        _arguments: &mut Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<bool, McpError> {
        Ok(false)
    }

    async fn prepare_continuation(
        &self,
        context: waygate_mcp::files::FileInputContext,
        _input_responses: &mut std::collections::BTreeMap<String, serde_json::Value>,
        file_keys: &[String],
    ) -> Result<bool, McpError> {
        assert!(
            !file_keys.is_empty(),
            "delivery must only run for keys the sealed pause asked a file for"
        );
        self.delivered
            .lock()
            .unwrap()
            .push(format!("{}.{}", context.server, context.tool));
        Ok(true)
    }
}

/// Elicited-file delivery requires provenance: the retry must present
/// continuation state this gateway sealed for the very call that paused.
/// Every envelope here comes from a real pause driven through the
/// production sealing path, so a disconnected first leg fails the test.
#[tokio::test]
async fn elicited_file_delivery_requires_a_verified_continuation() {
    use waygate_mcp::invocation::continuation::ContinuationSealer;

    let sealer = Arc::new(ContinuationSealer::new(
        waygate_oidc::session::SessionKey::from_bytes([3u8; 32]),
    ));
    let processor = Arc::new(ContinuationRecordingProcessor::default());
    let dispatched_state = Arc::new(Mutex::new(Vec::new()));
    let file_request = rmcp::model::InputRequests::from([(
        "attachment".to_owned(),
        serde_json::from_value(serde_json::json!({
            "method": "elicitation/create",
            "params": {
                "mode": "form",
                "message": "attach the report",
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "x-mcp-file": {"transferModes": ["upload"]}}
                    }
                }
            }
        }))
        .expect("elicitation request"),
    )]);
    // `risk` is part of the admitted contract, so the second catalog stands
    // for a reload that puts a different tool behind the same names.
    let build = |risk: RiskTier| {
        let catalog = Arc::new(FakeCatalog {
            facts: facts(risk, false),
            input_schema: None,
            dispatched_state: Some(dispatched_state.clone()),
            pause_with: Some(file_request.clone()),
        });
        Arc::new(
            DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), Arc::new(NullSink))
                .with_file_input_processor(Some(processor.clone()))
                .with_continuation_sealer(Some(sealer.clone())),
        ) as Arc<dyn InvocationService>
    };
    let responses = rmcp::model::InputResponses::from([(
        "attachment".to_owned(),
        serde_json::json!({"file": "mcp-file://gateway/01999999-9999-7999-8999-999999999999"}),
    )]);
    // A caller that can answer an elicitation, so the pause is relayable.
    let capable = || {
        let mut caps = rmcp::model::ClientCapabilities::default();
        caps.elicitation = Some(rmcp::model::ElicitationCapability::default());
        Some(caps)
    };
    // Drive a real first leg and take the envelope the gateway sealed.
    let pause_for = |svc: Arc<dyn InvocationService>, tool: &'static str, args| async move {
        let response = svc
            .invoke(
                Some(&principal()),
                InvocationRequest::new("test", tool)
                    .with_arguments(args)
                    .with_caller_capabilities(capable()),
            )
            .await
            .expect("the upstream pause is relayed");
        match response {
            InvocationResponse::InputRequired(pause) => pause
                .request_state
                .expect("the gateway seals its own state onto the relayed pause"),
            other => panic!("expected a relayed pause, got {other:?}"),
        }
    };
    let retry = |svc: Arc<dyn InvocationService>, tool: &'static str, state: String, args| {
        let responses = responses.clone();
        async move {
            svc.invoke(
                Some(&principal()),
                InvocationRequest::new("test", tool)
                    .with_arguments(args)
                    .with_mrtr_retry(Some(responses), Some(state)),
            )
            .await
        }
    };

    let sealed = pause_for(build(RiskTier::Low), "t", None).await;
    assert_ne!(
        sealed, "upstream-blob",
        "the upstream's own state must not be relayed in the clear"
    );

    // A continuation the caller assembled: no envelope this gateway issued.
    let forged = retry(build(RiskTier::Low), "t", "fabricated-state".into(), None)
        .await
        .expect_err("unverifiable continuation state is refused");
    assert!(
        forged.to_string().contains("did not issue"),
        "unexpected refusal: {forged}"
    );

    // An envelope from another tool's real pause cannot be transplanted onto
    // this one, which would otherwise make any permitted tool an upload
    // target.
    let for_other_tool = pause_for(build(RiskTier::Low), "other-tool", None).await;
    let transplanted = retry(build(RiskTier::Low), "t", for_other_tool, None)
        .await
        .expect_err("an envelope minted for another tool is refused");
    assert!(transplanted.to_string().contains("did not issue"));

    // Same tool, but the pause was raised for a different call.
    let other_args = serde_json::json!({"path": "/etc/shadow"})
        .as_object()
        .expect("arguments object")
        .clone();
    let for_other_call = pause_for(build(RiskTier::Low), "t", Some(other_args)).await;
    let wrong_call = retry(build(RiskTier::Low), "t", for_other_call, None)
        .await
        .expect_err("an envelope raised for another call is refused");
    assert!(wrong_call.to_string().contains("did not issue"));

    // A reload that swaps a different contract behind the same names
    // invalidates the outstanding pause rather than inheriting it.
    let swapped = retry(build(RiskTier::High), "t", sealed.clone(), None)
        .await
        .expect_err("an envelope for a replaced contract is refused");
    assert!(swapped.to_string().contains("did not issue"));

    assert!(
        processor.delivered.lock().unwrap().is_empty(),
        "no refused continuation may reach file delivery"
    );
    assert!(
        dispatched_state.lock().unwrap().is_empty(),
        "no refused continuation may reach the upstream"
    );

    // The genuine answer to the pause this gateway relayed for this call:
    // delivery runs, and the upstream sees its own opaque state restored.
    retry(build(RiskTier::Low), "t", sealed, None)
        .await
        .expect("a verified continuation dispatches");
    assert_eq!(
        processor.delivered.lock().unwrap().as_slice(),
        &["test.t".to_owned()],
        "a verified continuation delivers its elicited files"
    );
    assert_eq!(
        dispatched_state.lock().unwrap().as_slice(),
        &[Some("upstream-blob".to_owned())],
        "the upstream must receive its own opaque state, never the gateway envelope"
    );
}

/// Configuring a seal key must not break MRTR for the auth-disabled
/// development path. With no authenticated caller there was no principal to
/// seal against on the pausing leg, so the retry carries the upstream's own
/// state and is forwarded as it always was — elicited files stay
/// unauthorized because no continuation verified.
#[tokio::test]
async fn an_unauthenticated_retry_still_forwards_upstream_state() {
    use waygate_mcp::invocation::continuation::ContinuationSealer;

    let dispatched_state = Arc::new(Mutex::new(Vec::new()));
    let processor = Arc::new(ContinuationRecordingProcessor::default());
    let catalog = Arc::new(FakeCatalog {
        facts: facts(RiskTier::Low, false),
        input_schema: None,
        dispatched_state: Some(dispatched_state.clone()),
        pause_with: None,
    });
    let svc: Arc<dyn InvocationService> = Arc::new(
        DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), Arc::new(NullSink))
            .with_file_input_processor(Some(processor.clone()))
            .with_continuation_sealer(Some(Arc::new(ContinuationSealer::new(
                waygate_oidc::session::SessionKey::from_bytes([5u8; 32]),
            )))),
    );

    svc.invoke(
        None,
        InvocationRequest::new("test", "t").with_mrtr_retry(
            Some(rmcp::model::InputResponses::from([(
                "confirm".to_owned(),
                serde_json::json!({"ok": true}),
            )])),
            Some("upstream-blob".into()),
        ),
    )
    .await
    .expect("an unauthenticated MRTR retry still dispatches");

    assert_eq!(
        dispatched_state.lock().unwrap().as_slice(),
        &[Some("upstream-blob".to_owned())],
        "the upstream must receive the state the caller echoed"
    );
    assert!(
        processor.delivered.lock().unwrap().is_empty(),
        "no verified continuation means no elicited-file delivery"
    );
}

/// A deterministic file-admission refusal is argument validation: it must
/// surface before the quota stage consumes any bucket (and therefore before
/// the later one-time approval claim can burn a grant).
#[tokio::test]
async fn file_admission_refusal_consumes_no_quota() {
    let quota = Arc::new(RecordingQuota::default());
    let quota_dyn: Arc<dyn QuotaService> = quota.clone();
    let catalog = Arc::new(FakeCatalog {
        facts: facts(RiskTier::Low, false),
        dispatched_state: None,
        pause_with: None,
        // Admission only runs for tools whose schema declares a file input.
        input_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "file": {"type": "string", "x-mcp-file": {"transferModes": ["upload"]}}
            }
        })),
    });
    let svc: Arc<dyn InvocationService> = Arc::new(
        DefaultInvocationService::new(catalog, Arc::new(AllowAllGate), Arc::new(NullSink))
            .with_quota(Some(quota_dyn))
            .with_file_input_processor(Some(Arc::new(RefusingFileProcessor))),
    );
    let p = principal();
    let error = svc
        .invoke(Some(&p), InvocationRequest::new("test", "t"))
        .await
        .expect_err("refused file admission surfaces to the caller");
    assert!(
        error.to_string().contains("does not admit"),
        "unexpected refusal: {error}"
    );
    assert!(
        quota.seen.lock().unwrap().is_empty(),
        "a deterministic admission refusal must not consume quota"
    );
}

#[tokio::test]
async fn high_risk_call_quota_fires_on_side_effects_not_risk() {
    // low + side_effects → the mutating surface → [Call, HighRiskCall].
    let low_se = quota_actions_for(facts(RiskTier::Low, true)).await;
    assert!(
        low_se.contains(&QuotaAction::Call),
        "every call consumes the Call bucket: {low_se:?}"
    );
    assert!(
        low_se.contains(&QuotaAction::HighRiskCall),
        "a low + side_effects tool must consume HighRiskCall — the gate keys on \
         side_effects, not the risk tier: {low_se:?}"
    );

    // high + !side_effects → read-only → only [Call] (proves it moved OFF risk).
    let high_ro = quota_actions_for(facts(RiskTier::High, false)).await;
    assert!(
        high_ro.contains(&QuotaAction::Call),
        "every call consumes the Call bucket: {high_ro:?}"
    );
    assert!(
        !high_ro.contains(&QuotaAction::HighRiskCall),
        "a high + !side_effects tool must NOT consume HighRiskCall after the \
         decouple from the risk tier: {high_ro:?}"
    );
}
