//! Cost of an authorization decision, with and without the per-engine cache.
//!
//! Reports the two numbers that decide how a catalog traversal behaves: the
//! price of deciding one question for the first time against a policy set, and
//! the price of answering it again. The traversal rows put those per-decision
//! figures in the shape the discovery path actually uses — one decision per
//! visible tool, repeated on every listing.
//!
//! Timings are machine-dependent observations for comparing a change against
//! its own baseline, not release thresholds or a capacity forecast.

use std::hint::black_box;
use std::time::Instant;

use waygate_authz::CedarEngine;
use waygate_core::{
    ActionFacts, ClientFacts, Facts, InvocationChannelFact, PrincipalFacts, ResourceFacts,
    RiskTier, RuntimeContextFacts, TenantFacts, TenantId,
};

/// Shaped like a deployment policy set: a few broad permits, a few narrowing
/// forbids, and step-up and approval rules that make a deny do the extra
/// inference passes.
const POLICY: &str = r#"
    @id("permit-readers")
    permit(principal, action, resource) when {
        principal.groups.contains("readers") && resource.risk == "low"
    };
    @id("permit-invokers")
    permit(principal, action, resource) when {
        principal.groups.contains("invokers") && resource.risk != "high"
    };
    @id("permit-operators")
    permit(principal, action, resource) when {
        principal.roles.contains("operator")
    };
    @id("step-up-high-risk")
    forbid(principal, action, resource) when {
        resource.risk == "high" && !principal.scopes.contains("mcp:invoke:high")
    };
    @id("forbid-pii-without-approval")
    forbid(principal, action, resource) when {
        resource has pii && resource.pii
        && context has approval_present && !context.approval_present
    };
    @id("forbid-codemode-side-effects")
    forbid(principal, action, resource) when {
        context has channel && context.channel == "codemode"
        && resource has side_effects && resource.side_effects
    };
"#;

fn percentile(mut samples: Vec<u128>, percentile: usize) -> u128 {
    samples.sort_unstable();
    samples[(samples.len() - 1) * percentile / 100]
}

fn facts_for(tool_index: usize) -> Facts {
    // Spread risk tiers so a share of decisions take the deny path through the
    // step-up and approval inferences rather than all hitting a first-pass
    // permit.
    let risk = match tool_index % 3 {
        0 => RiskTier::Low,
        1 => RiskTier::Medium,
        _ => RiskTier::High,
    };
    Facts {
        principal: PrincipalFacts {
            sub: "bench-principal".into(),
            email: Some("principal@example.test".into()),
            groups: vec!["invokers".into(), "staff".into()],
            scopes: vec!["mcp:invoke".into()],
            auth_method: "oauth".into(),
            roles: vec!["reader".into()],
            scim: None,
        },
        client: ClientFacts {
            client_id: Some("bench-client".into()),
        },
        tenant: TenantFacts {
            tenant_id: TenantId::default(),
        },
        action: ActionFacts {
            kind: "CallTool".into(),
            required_scope: Some("mcp:invoke:high".into()),
        },
        resource: ResourceFacts {
            server: format!("server-{}", tool_index % 16),
            tool: format!("tool-{tool_index}"),
            risk,
            side_effects: tool_index.is_multiple_of(2),
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
            operation: None,
        },
        request: None,
        context: RuntimeContextFacts {
            approval_present: false,
            mfa: false,
            time: time::OffsetDateTime::UNIX_EPOCH,
            source_ip: None,
            channel: InvocationChannelFact::Direct,
        },
    }
}

fn main() {
    const ITERATIONS: usize = 20_000;
    // Representative of an aggregate catalog large enough that per-decision
    // cost is what determines listing latency.
    const CATALOG: usize = 800;

    let corpus: Vec<Facts> = (0..CATALOG).map(facts_for).collect();

    // One decision, never previously asked: a fresh engine per iteration, so
    // the cache is always empty. Engine construction is excluded from the
    // sample.
    let mut uncached = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let engine = CedarEngine::from_source(POLICY).expect("policy parses");
        let facts = &corpus[index % CATALOG];
        let start = Instant::now();
        let verdict = engine.evaluate_facts(facts).expect("decide");
        uncached.push(start.elapsed().as_nanos());
        black_box(verdict);
    }

    // The same decision, already decided against this engine's policy set.
    let engine = CedarEngine::from_source(POLICY).expect("policy parses");
    for facts in &corpus {
        engine.evaluate_facts(facts).expect("warm the cache");
    }
    let mut cached = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let facts = &corpus[index % CATALOG];
        let start = Instant::now();
        let verdict = engine.evaluate_facts(facts).expect("decide");
        cached.push(start.elapsed().as_nanos());
        black_box(verdict);
    }

    // A full authorization-filtered traversal: one decision per visible tool.
    let cold_engine = CedarEngine::from_source(POLICY).expect("policy parses");
    let start = Instant::now();
    for facts in &corpus {
        black_box(cold_engine.evaluate_facts(facts).expect("decide"));
    }
    let cold_traversal = start.elapsed().as_micros();

    let start = Instant::now();
    for facts in &corpus {
        black_box(cold_engine.evaluate_facts(facts).expect("decide"));
    }
    let warm_traversal = start.elapsed().as_micros();

    println!("iterations={ITERATIONS} catalog={CATALOG}");
    println!(
        "one decision, not previously decided:  p50={}ns p99={}ns",
        percentile(uncached.clone(), 50),
        percentile(uncached, 99)
    );
    println!(
        "one decision, already decided:         p50={}ns p99={}ns",
        percentile(cached.clone(), 50),
        percentile(cached, 99)
    );
    println!("traversal of {CATALOG} tools, first pass:  {cold_traversal}us");
    println!("traversal of {CATALOG} tools, repeat pass: {warm_traversal}us");
}
