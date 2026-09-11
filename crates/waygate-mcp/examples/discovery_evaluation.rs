//! Emit a representative, machine-readable evaluation of the production
//! authorization-after-filtering discovery ranker.
//!
//! The report is comparative evidence, not a release threshold. It records
//! retrieval usefulness, selected-definition context cost, and elapsed ranking
//! time so two runs can be compared. The input is an already-authorized catalog
//! projection; production authorization, exact inspection, and publication
//! lifecycle contracts are exercised by gateway discovery handler tests. Only
//! ranker invariants fail this command.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Serialize;
use waygate_mcp::{rank_visible_tools, CatalogTool};

mod discovery_evaluation_support;
use discovery_evaluation_support::{
    contract_bytes, qualified, representative_corpus, representative_scenarios, EvaluationScenario,
    Provenance, QueryShape,
};

const RESULT_LIMIT: usize = 5;

#[derive(Serialize)]
struct ExpectedRank {
    name: String,
    rank: Option<usize>,
}

#[derive(Serialize)]
struct ScenarioReport {
    id: &'static str,
    intent: &'static str,
    query_shape: QueryShape,
    expected: Vec<&'static str>,
    intended_invocations: Vec<IntendedInvocation>,
    expected_ranks: Vec<ExpectedRank>,
    top_results: Vec<String>,
    reciprocal_rank: f64,
    recall_at_limit: f64,
    expected_tools_in_working_set: bool,
    selected_definitions_serializable: bool,
    expected_contracts_available: bool,
    selected_contract_bytes: usize,
    full_catalog_contract_bytes: usize,
    ranking_duration_microseconds: u64,
}

#[derive(Serialize)]
struct IntendedInvocation {
    tool: &'static str,
    query: &'static str,
    expected_outcome: &'static str,
}

#[derive(Serialize)]
struct CorpusSummary {
    tools: usize,
    sources: usize,
    remote_http_tools: usize,
    local_upstream_tools: usize,
    gateway_local_tools: usize,
}

#[derive(Serialize)]
struct EvaluationReport {
    contract_version: &'static str,
    result_limit: usize,
    corpus: CorpusSummary,
    scenarios: Vec<ScenarioReport>,
    mean_reciprocal_rank: f64,
    mean_recall_at_limit: f64,
    contract_checks_passed: bool,
}

fn evaluate_scenario(catalog: &[CatalogTool], scenario: &EvaluationScenario) -> ScenarioReport {
    let started = Instant::now();
    let ranked = rank_visible_tools(scenario.intent, catalog.to_vec());
    let duration = started.elapsed();
    let names: Vec<String> = ranked.iter().map(qualified).collect();
    let expected_ranks: Vec<ExpectedRank> = scenario
        .expected
        .iter()
        .map(|name| ExpectedRank {
            name: (*name).to_owned(),
            rank: names
                .iter()
                .position(|candidate| candidate == name)
                .map(|rank| rank + 1),
        })
        .collect();
    let reciprocal_rank = expected_ranks
        .iter()
        .filter_map(|expected| expected.rank)
        .min()
        .map_or(0.0, |rank| 1.0 / rank as f64);
    let recalled = expected_ranks
        .iter()
        .filter(|expected| expected.rank.is_some_and(|rank| rank <= RESULT_LIMIT))
        .count();
    let expected_count = scenario.expected.len();
    let expected_tools_in_working_set = expected_ranks
        .iter()
        .all(|expected| expected.rank.is_some_and(|rank| rank <= RESULT_LIMIT));
    let selected_definitions_serializable = expected_ranks.iter().all(|expected| {
        expected.rank.is_some_and(|rank| rank <= RESULT_LIMIT)
            && catalog.iter().any(|tool| {
                qualified(tool) == expected.name && serde_json::to_value(&tool.definition).is_ok()
            })
    });
    let expected_contracts_available =
        expected_tools_in_working_set && selected_definitions_serializable;
    ScenarioReport {
        id: scenario.id,
        intent: scenario.intent,
        query_shape: scenario.query_shape,
        expected: scenario.expected.to_vec(),
        intended_invocations: scenario
            .invocation_steps
            .iter()
            .map(|step| IntendedInvocation {
                tool: step.tool,
                query: step.query,
                expected_outcome: step.expected_outcome,
            })
            .collect(),
        expected_ranks,
        top_results: names.into_iter().take(RESULT_LIMIT).collect(),
        reciprocal_rank,
        recall_at_limit: recalled as f64 / expected_count.max(1) as f64,
        expected_tools_in_working_set,
        selected_definitions_serializable,
        expected_contracts_available,
        selected_contract_bytes: contract_bytes(
            &ranked.into_iter().take(RESULT_LIMIT).collect::<Vec<_>>(),
        ),
        full_catalog_contract_bytes: contract_bytes(catalog),
        ranking_duration_microseconds: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let records = representative_corpus();
    let unrestricted: Vec<CatalogTool> = records.iter().map(|record| record.tool.clone()).collect();
    let scenarios = representative_scenarios()
        .into_iter()
        .map(|scenario| evaluate_scenario(&unrestricted, &scenario))
        .collect::<Vec<_>>();
    let mean_reciprocal_rank = scenarios
        .iter()
        .map(|scenario| scenario.reciprocal_rank)
        .sum::<f64>()
        / scenarios.len() as f64;
    let mean_recall_at_limit = scenarios
        .iter()
        .map(|scenario| scenario.recall_at_limit)
        .sum::<f64>()
        / scenarios.len() as f64;
    let exact_selector_passed = scenarios
        .iter()
        .find(|scenario| scenario.id == "exact_selector")
        .is_some_and(|scenario| scenario.expected_ranks[0].rank == Some(1));
    let contract_checks_passed = exact_selector_passed;
    let sources: BTreeSet<String> = unrestricted
        .iter()
        .map(|tool| tool.identity.source.name().to_owned())
        .collect();
    let mut provenance_counts = BTreeMap::new();
    for record in &records {
        *provenance_counts
            .entry(match record.provenance {
                Provenance::RemoteHttp => "remote_http",
                Provenance::LocalUpstream => "local_upstream",
                Provenance::GatewayLocal => "gateway_local",
            })
            .or_insert(0usize) += 1;
    }
    let report = EvaluationReport {
        contract_version: "gateway-discovery-evaluation-v2",
        result_limit: RESULT_LIMIT,
        corpus: CorpusSummary {
            tools: unrestricted.len(),
            sources: sources.len(),
            remote_http_tools: provenance_counts
                .get("remote_http")
                .copied()
                .unwrap_or_default(),
            local_upstream_tools: provenance_counts
                .get("local_upstream")
                .copied()
                .unwrap_or_default(),
            gateway_local_tools: provenance_counts
                .get("gateway_local")
                .copied()
                .unwrap_or_default(),
        },
        scenarios,
        mean_reciprocal_rank,
        mean_recall_at_limit,
        contract_checks_passed,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    if !report.contract_checks_passed {
        return Err("discovery ranker contract check failed".into());
    }
    Ok(())
}
