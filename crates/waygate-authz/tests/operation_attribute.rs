//! A policy can name the operation a call selected.
//!
//! A tool that carries many operations behind one name reaches the gate under
//! that single name, so `resource.name` cannot distinguish listing projects
//! from revealing a secret. The resolved classification already moves
//! `resource.risk` and the flags, which is what most rules should gate on; this
//! attribute is for the rule that has to name the operation itself.

use waygate_authz::{CedarEngine, Decision};
use waygate_core::{Facts, RiskTier};

/// A call to a per-operation executor, selecting `operation`.
fn call_facts(operation: Option<&str>) -> Facts {
    Facts {
        principal: waygate_core::PrincipalFacts {
            sub: "someone".into(),
            email: None,
            groups: vec!["mcp-users".into()],
            scopes: vec!["mcp:invoke".into()],
            auth_method: "oauth".into(),
            roles: vec![],
            scim: None,
        },
        client: waygate_core::ClientFacts::default(),
        tenant: waygate_core::TenantFacts {
            tenant_id: waygate_core::TenantId::default(),
        },
        action: waygate_core::ActionFacts {
            kind: "CallTool".into(),
            required_scope: None,
        },
        resource: waygate_core::ResourceFacts {
            server: "example-secrets".into(),
            tool: "read".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            data_classification: None,
            cost_class: None,
            uri: None,
            source_origin: None,
            artifact_digest: None,
            source_tree_digest: None,
            skill_uri: None,
            revision_digest: None,
            content_digest: None,
            source_path: None,
            source_object: None,
            resource_type: None,
            operation: operation.map(str::to_owned),
        },
        request: None,
        context: waygate_core::RuntimeContextFacts {
            approval_present: false,
            mfa: false,
            time: time::OffsetDateTime::UNIX_EPOCH,
            source_ip: None,
            channel: waygate_core::InvocationChannelFact::Direct,
        },
    }
}

const POLICIES: &str = r#"
permit(principal, action, resource);

@id("forbid-reveal")
forbid(principal, action, resource)
when { resource has operation && resource.operation == "secrets.reveal" };
"#;

/// A rule that fires on the mere presence of the attribute, which is how a
/// policy would express "this tool is operation-governed".
const PRESENCE_POLICIES: &str = r#"
permit(principal, action, resource);

@id("forbid-any-operation")
forbid(principal, action, resource) when { resource has operation };
"#;

fn engine() -> CedarEngine {
    CedarEngine::from_source(POLICIES).expect("load policies")
}

#[test]
fn a_policy_can_forbid_one_operation_of_a_tool() {
    let engine = engine();

    let revealing = engine
        .evaluate_facts(&call_facts(Some("secrets.reveal")))
        .expect("evaluate");
    assert_eq!(
        revealing.decision,
        Decision::Deny,
        "a rule naming the operation must reach it; the tool name is the same for every \
         operation this executor carries"
    );

    let listing = engine
        .evaluate_facts(&call_facts(Some("projects.list")))
        .expect("evaluate");
    assert_eq!(
        listing.decision,
        Decision::Allow,
        "a different operation of the same tool is a different decision"
    );
}

#[test]
fn a_call_without_an_operation_leaves_existing_policies_unchanged() {
    // Every policy written before tools carried operations evaluates against a
    // resource with no such attribute. The entity omits it rather than
    // rendering an empty string, so a `has` guard is false and the rule that
    // names it simply does not apply.
    let engine = engine();

    let decision = engine.evaluate_facts(&call_facts(None)).expect("evaluate");
    assert_eq!(
        decision.decision,
        Decision::Allow,
        "a tool classified by name alone must decide exactly as it did before"
    );
}

#[test]
fn the_attribute_is_absent_rather_than_empty_when_no_operation_was_selected() {
    // `has` is the guard every operation-naming policy must write, so whether
    // the attribute exists is itself a policy input. Rendering an unselected
    // operation as an empty string would make `resource has operation` true for
    // every tool in the deployment and silently fire rules meant only for
    // operation-governed ones.
    let engine = CedarEngine::from_source(PRESENCE_POLICIES).expect("load policies");

    assert_eq!(
        engine
            .evaluate_facts(&call_facts(None))
            .expect("evaluate")
            .decision,
        Decision::Allow,
        "no operation selected means the attribute must not be there at all"
    );
    assert_eq!(
        engine
            .evaluate_facts(&call_facts(Some("projects.list")))
            .expect("evaluate")
            .decision,
        Decision::Deny,
        "a selected operation must make `has` true"
    );
}
