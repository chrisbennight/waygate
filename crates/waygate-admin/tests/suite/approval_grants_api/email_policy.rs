use super::*;
use waygate_authz::{CedarEngine, CedarGate};
use waygate_invocation::{InvocationError, InvocationRequest, InvocationService};
use waygate_mcp::{
    audit::{AuditMode, InMemorySink},
    authz::ToolFacts,
    catalog::{
        InvocationContractIdentity, InvocationToolSnapshot, ResolvedInvocationTool, UpstreamCatalog,
    },
    DefaultInvocationService,
};

const POLICY: &str = include_str!("../../../../../examples/email-policy/email.cedar");

struct MailTool {
    tool_id: Uuid,
    sent: Mutex<Vec<serde_json::Map<String, Value>>>,
}

#[async_trait]
impl UpstreamCatalog for MailTool {
    async fn list_servers(&self) -> Vec<String> {
        vec!["example-messages".into()]
    }
    async fn list_tools(&self, _server: &str) -> Result<Vec<rmcp::model::Tool>, rmcp::ErrorData> {
        Ok(vec![])
    }
    fn tool_facts(&self, server: &str, tool: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool.into(),
            risk: waygate_core::RiskTier::Low,
            side_effects: true,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }
    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog(
            self.tool_facts(server, tool),
            self.tool_id,
            "h".into(),
            Some(json!({"type":"object", "additionalProperties":false,
                "properties":{
                    "to":{"type":"array","items":{"type":"string"}},
                    "cc":{"type":"array","items":{"type":"string"}},
                    "bcc":{"type":"array","items":{"type":"string"}},
                    "subject":{"type":"string"},"body":{"type":"string"}
                },"required":["to","subject","body"]})),
            None,
        ))
    }
    async fn call_tool(
        &self,
        _server: &str,
        _tool: &str,
        args: Option<serde_json::Map<String, Value>>,
        _principal: Option<&Principal>,
        _admitted: Option<&InvocationContractIdentity>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        self.sent.lock().unwrap().push(args.unwrap());
        Ok(rmcp::model::CallToolResult::success(vec![
            rmcp::model::ContentBlock::text("Message accepted"),
        ]))
    }
}

fn message(to: &str) -> Value {
    json!({"to":[to],"cc":[],"bcc":[],"subject":"Quarterly update","body":"The report is ready."})
}

fn request(arguments: &Value) -> InvocationRequest {
    InvocationRequest::new("example-messages", "send")
        .with_arguments(arguments.as_object().cloned())
}

#[tokio::test]
async fn internal_mail_is_autonomous_and_external_approval_covers_only_one_exact_message() {
    let mut catalog = GrantFakeCatalog::new(true);
    catalog.requires_approval = false;
    let catalog = Arc::new(catalog);
    let upstream = Arc::new(MailTool {
        tool_id: catalog.tool_id,
        sent: Mutex::new(Vec::new()),
    });
    let sink = Arc::new(InMemorySink::new());
    let service = DefaultInvocationService::new(
        upstream.clone(),
        Arc::new(CedarGate::new(Arc::new(
            CedarEngine::from_source(POLICY).unwrap(),
        ))),
        sink.clone(),
    )
    .with_audit_mode(AuditMode::BestEffort)
    .with_catalog_store(Some(catalog.clone()));
    let mut caller = principal_with(&["mcp:invoke"]);
    caller.sub = "assistant@example.com".into();
    caller.issuer = "https://issuer.test".into();
    caller.groups = vec!["mail-assistants".into()];

    use waygate_mcp::authz::AuthzGate;
    let discovery = CedarGate::new(Arc::new(CedarEngine::from_source(POLICY).unwrap()));
    assert!(
        discovery
            .may_discover_server(&caller, "example-messages")
            .await
    );
    assert!(discovery
        .may_call_tool(&caller, &upstream.tool_facts("example-messages", "send"))
        .await
        .is_discoverable());
    let mut outsider = caller.clone();
    outsider.groups.clear();
    assert!(!discovery
        .may_call_tool(&outsider, &upstream.tool_facts("example-messages", "send"))
        .await
        .is_discoverable());
    assert!(service
        .invoke(Some(&outsider), request(&message("alice@example.com")))
        .await
        .is_err());

    service
        .invoke(Some(&caller), request(&message("alice@EXAMPLE.COM")))
        .await
        .unwrap();
    let external = message("partner@outside.example");
    assert!(matches!(
        service.invoke(Some(&caller), request(&external)).await,
        Err(InvocationError::ApprovalRequired { .. })
    ));
    for field in ["cc", "bcc"] {
        let mut mixed = message("alice@example.com");
        mixed[field] = json!(["partner@outside.example"]);
        assert!(matches!(
            service.invoke(Some(&caller), request(&mixed)).await,
            Err(InvocationError::ApprovalRequired { .. })
        ));
    }
    assert_eq!(upstream.sent.lock().unwrap().len(), 1);

    let app = api_router(state_with(Some(catalog.clone())).await);
    let response = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &json!({
                "principal_sub":caller.sub, "principal_issuer":caller.issuer,
                "tool":"example-messages.send", "behavior_hash":"h",
                "arguments":external, "expires_in_seconds":600,
                "reason":"Send the quarterly update to our partner"
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    for field in ["to", "cc", "bcc", "subject", "body"] {
        let mut changed = external.clone();
        changed[field] = if ["to", "cc", "bcc"].contains(&field) {
            json!(["another@outside.example"])
        } else {
            json!("Changed content")
        };
        assert!(
            matches!(
                service.invoke(Some(&caller), request(&changed)).await,
                Err(InvocationError::ApprovalRequired { .. })
            ),
            "changed {field} reused approval"
        );
    }
    assert_eq!(upstream.sent.lock().unwrap().len(), 1);
    let (first, second) = tokio::join!(
        service.invoke(Some(&caller), request(&external)),
        service.invoke(Some(&caller), request(&external)),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(upstream.sent.lock().unwrap().len(), 2);
    assert!(matches!(
        service.invoke(Some(&caller), request(&external)).await,
        Err(InvocationError::ApprovalRequired { .. })
    ));

    for bad in [
        "Someone <alice@example.com>",
        "alice@example.com\r\nBcc: attacker@outside.example",
        "alice",
    ] {
        assert!(service
            .invoke(Some(&caller), request(&message(bad)))
            .await
            .is_err());
    }
    assert_eq!(upstream.sent.lock().unwrap().len(), 2);
    let evidence = format!("{:?}", sink.snapshot().await);
    assert!(!evidence.contains("The report is ready."));
    assert!(!evidence.contains("partner@outside.example"));
}

#[test]
fn recipient_policy_replay_refuses_missing_recipient_facts() {
    let facts = waygate_authz::simulation_facts(
        &principal_with(&[]),
        &waygate_authz::Action::CallTool {
            name: "send".into(),
            risk: waygate_core::RiskTier::Low,
        },
        &waygate_authz::ResourceSpec::Tool(waygate_authz::ToolSpec {
            server: "example-messages".into(),
            name: "send".into(),
            risk: waygate_core::RiskTier::Low,
            side_effects: true,
            pii: false,
            operation: None,
        }),
    );
    assert!(CedarEngine::from_source(POLICY)
        .unwrap()
        .evaluate_facts_strict(&facts)
        .is_err());
}
