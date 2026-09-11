//! Cedar policy golden tests.
//!
//! Each `tests/golden/*.json` file declares one
//! `(principal, action, resource, expected verdict)` case.  The harness
//! loads the representative `policies/` Cedar fixture set
//! (`crates/waygate-authz/tests/fixtures/policies/`) and
//! asserts each case's verdict — and (when the case specifies it) that
//! the `@reason("...")` annotation on the fired forbid surfaces through
//! `AuthzResult.reasons` (the wire contract).
//!
//! Why goldens beyond the existing `cedar::tests` unit tests:
//! - Unit tests construct policies in-line; goldens exercise the complete
//!   representative fixture set, so a refactor that drops a
//!   forbid or strips a `@reason` annotation is caught in CI.
//! - JSON cases are cheap to add (no Rust recompile, no test-helper
//!   plumbing), so an authorization deny pattern surfaced during review can
//!   become a regression pin quickly.
//!
//! The harness intentionally fails LOUD on a missing or malformed case
//! file: each golden is supposed to be operator-readable
//! documentation of "this is what we promise this policy does",
//! so a typo should surface immediately, not silently skip.
//!
//! Schema: see `tests/golden/README.md`.
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;

use waygate_authz::{Action, AuthzEngine, CedarEngine, Decision, ResourceSpec, ToolSpec};
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::{AuthMethod, Principal, ScimGroupRef, ScimPrincipalAttrs};

#[derive(Debug, Deserialize)]
struct GoldenCase {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
    principal: PrincipalSpec,
    action: ActionSpec,
    resource: ResourceJson,
    expected: ExpectedSpec,
}

#[derive(Debug, Deserialize)]
struct PrincipalSpec {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    auth_method: String,
    #[serde(default = "default_tenant")]
    tenant: String,
    #[serde(default)]
    scim: Option<ScimSpec>,
}

#[derive(Debug, Deserialize)]
struct ScimSpec {
    user_id: String,
    user_name: String,
    #[serde(default)]
    external_id: Option<String>,
    active: bool,
    #[serde(default)]
    groups: Vec<ScimGroupSpec>,
    #[serde(default)]
    attrs: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ScimGroupSpec {
    display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
enum ActionSpec {
    ListTools,
    SearchTools,
    CallTool { name: String, risk: String },
    ListResources,
    ReadResource { uri: String },
    AdminManagePolicies,
    AdminManageServers,
    AdminViewTelemetry,
    GrantCrossAppAccess,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
enum ResourceJson {
    Server {
        name: String,
    },
    Tool {
        server: String,
        name: String,
        risk: String,
        #[serde(default)]
        side_effects: bool,
        #[serde(default)]
        pii: bool,
    },
}

#[derive(Debug, Deserialize)]
struct ExpectedSpec {
    decision: String,
    #[serde(default)]
    reason_contains: Vec<String>,
    #[serde(default)]
    policy_id_contains: Vec<String>,
}

fn default_scopes() -> Vec<String> {
    vec!["mcp:invoke".into()]
}

fn default_tenant() -> String {
    "default".into()
}

fn risk_from_str(s: &str, ctx: &str) -> RiskTier {
    match s {
        "low" => RiskTier::Low,
        "medium" => RiskTier::Medium,
        "high" => RiskTier::High,
        other => panic!("golden {ctx}: unknown risk tier {other:?} (want low|medium|high)"),
    }
}

fn auth_method_from_str(s: &str, ctx: &str) -> AuthMethod {
    match s {
        "oauth" => AuthMethod::Oauth,
        "api_key" => AuthMethod::ApiKey,
        other => panic!("golden {ctx}: unknown auth_method {other:?} (want oauth|api_key)"),
    }
}

fn build_principal(p: &PrincipalSpec, ctx: &str) -> Principal {
    let tenant = waygate_core::TenantId::parse(&p.tenant)
        .unwrap_or_else(|e| panic!("golden {ctx}: invalid tenant {:?}: {e}", p.tenant));
    let scim = p.scim.as_ref().map(|s| ScimPrincipalAttrs {
        user_id: s.user_id.clone(),
        user_name: s.user_name.clone(),
        external_id: s.external_id.clone(),
        active: s.active,
        groups: s
            .groups
            .iter()
            .enumerate()
            .map(|(i, g)| ScimGroupRef {
                // Goldens don't assert on group UUIDs (only
                // display_name); a deterministic placeholder keeps
                // failure diffs stable without making the JSON
                // authoring surface harder.
                id: format!("golden-group-{i}"),
                display_name: g.display_name.clone(),
            })
            .collect(),
        attrs: serde_json::Value::Object(s.attrs.clone()),
    });
    Principal {
        sub: p.sub.clone(),
        email: p.email.clone(),
        groups: p.groups.clone(),
        issuer: "https://auth.example.test".into(),
        scopes: p.scopes.clone(),
        tenant,
        auth_method: auth_method_from_str(&p.auth_method, ctx),
        raw_token: None,
        roles: vec![],
        scim,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn build_action(a: &ActionSpec, ctx: &str) -> Action {
    match a {
        ActionSpec::ListTools => Action::ListTools,
        ActionSpec::SearchTools => Action::SearchTools,
        ActionSpec::CallTool { name, risk } => Action::CallTool {
            name: name.clone(),
            risk: risk_from_str(risk, ctx),
        },
        ActionSpec::ListResources => Action::ListResources,
        ActionSpec::ReadResource { uri } => Action::ReadResource { uri: uri.clone() },
        ActionSpec::AdminManagePolicies => Action::AdminManagePolicies,
        ActionSpec::AdminManageServers => Action::AdminManageServers,
        ActionSpec::AdminViewTelemetry => Action::AdminViewTelemetry,
        ActionSpec::GrantCrossAppAccess => Action::GrantCrossAppAccess,
    }
}

fn build_resource(r: &ResourceJson, ctx: &str) -> ResourceSpec {
    match r {
        ResourceJson::Server { name } => ResourceSpec::Server { name: name.clone() },
        ResourceJson::Tool {
            server,
            name,
            risk,
            side_effects,
            pii,
        } => ResourceSpec::Tool(ToolSpec {
            operation: None,
            server: server.clone(),
            name: name.clone(),
            risk: risk_from_str(risk, ctx),
            side_effects: *side_effects,
            pii: *pii,
        }),
    }
}

fn decision_from_str(s: &str, ctx: &str) -> Decision {
    match s {
        "Allow" => Decision::Allow,
        "Deny" => Decision::Deny,
        "StepUpRequired" => Decision::StepUpRequired,
        other => panic!("golden {ctx}: unknown expected decision {other:?}"),
    }
}

fn workspace_policies_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("crates/waygate-authz/tests/fixtures/policies")
}

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn load_engine() -> Arc<CedarEngine> {
    let engine = CedarEngine::load_dir(&workspace_policies_dir()).expect(
        "policy fixtures must parse — golden tests run against the representative reviewed set",
    );
    Arc::new(engine)
}

#[test]
fn policy_goldens() {
    let engine = load_engine();
    let dir = goldens_dir();
    let mut cases: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read goldens dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    // Deterministic order — failure messages mention the file, but a
    // stable ordering keeps test logs diff-friendly across runs.
    cases.sort();
    assert!(
        !cases.is_empty(),
        "no goldens found under {} — at least one golden test case must be present",
        dir.display()
    );

    let mut failures: Vec<String> = Vec::new();
    for path in &cases {
        let body = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read golden {}: {e}", path.display()));
        let case: GoldenCase = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("parse golden {}: {e}", path.display()));
        let ctx = format!("{} ({})", case.name, path.display());

        let principal = build_principal(&case.principal, &ctx);
        let action = build_action(&case.action, &ctx);
        let resource = build_resource(&case.resource, &ctx);
        let expected_decision = decision_from_str(&case.expected.decision, &ctx);

        // Route through the AuthzEngine trait (which fails closed
        // on Cedar engine errors with `Decision::Deny` + empty
        // reasons), not the inherent CedarEngine::evaluate which
        // returns a Result. Goldens should exercise the same path
        // production takes.
        let result =
            <CedarEngine as AuthzEngine>::evaluate(engine.as_ref(), &principal, &action, &resource);

        if result.decision != expected_decision {
            failures.push(format!(
                "{ctx}: expected {:?} but got {:?}; policy_ids={:?} reasons={:?}",
                expected_decision, result.decision, result.policy_ids, result.reasons
            ));
            continue;
        }
        for want in &case.expected.reason_contains {
            if !result.reasons.iter().any(|r| r.contains(want)) {
                failures.push(format!(
                    "{ctx}: expected one of reasons={:?} to contain {want:?} but found none; \
                     check that the fired forbid policy still carries a matching @reason(\"...\") \
                     annotation in policies/",
                    result.reasons
                ));
            }
        }
        for want in &case.expected.policy_id_contains {
            if !result.policy_ids.iter().any(|id| id.contains(want)) {
                failures.push(format!(
                    "{ctx}: expected one of policy_ids={:?} to contain {want:?} but found none",
                    result.policy_ids
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "policy goldens failed ({} of {} cases):\n  - {}",
        failures.len(),
        cases.len(),
        failures.join("\n  - ")
    );
}
