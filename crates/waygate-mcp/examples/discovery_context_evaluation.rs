//! Compare broad descriptor scanning with compact search and selected inspection.
//! This is an offline fixture comparison, not a model or network latency benchmark.

use std::sync::Arc;
use std::time::Instant;

use rmcp::model::Tool;
use serde::Deserialize;
use serde_json::json;
use waygate_mcp::{compact_tool_description, rank_visible_tools, CatalogTool, ToolFacts};

#[derive(Deserialize)]
struct Fixture {
    source: String,
    name: String,
    purpose: String,
    query: Option<String>,
    expected: Option<String>,
}

fn valid_selection(tool: &Tool, expected: &str, query: &str) -> bool {
    tool.name == expected
        && jsonschema::validator_for(&json!(tool.input_schema))
            .expect("fixture schema is valid")
            .is_valid(&json!({"query": query}))
}

fn baseline(
    catalog: &[CatalogTool],
    query: &str,
    expected: &str,
    budget: usize,
) -> serde_json::Value {
    let started = Instant::now();
    let definitions: Vec<_> = catalog
        .iter()
        .filter(|tool| {
            tool.definition
                .description
                .as_deref()
                .unwrap()
                .contains("search")
        })
        .map(|tool| &tool.definition)
        .collect();
    let bytes = serde_json::to_vec(&definitions).unwrap();
    let delivered = &bytes[..bytes.len().min(budget)];
    let decoded: Option<Vec<Tool>> = serde_json::from_slice(delivered).ok();
    let valid = decoded.is_some_and(|definitions| {
        let records = definitions
            .into_iter()
            .map(|definition| {
                let mut record = catalog
                    .iter()
                    .find(|record| record.identity.qualified_name() == definition.name)
                    .unwrap()
                    .clone();
                record.definition = definition;
                record
            })
            .collect();
        rank_visible_tools(query, records)
            .first()
            .is_some_and(|tool| valid_selection(&tool.definition, expected, query))
    });
    json!({
        "modeled_discovery_calls":1, "response_bytes":bytes.len(),
        "delivered_bytes":delivered.len(), "simulated_truncation":delivered.len()<bytes.len(),
        "valid_fixture_selection":valid,
        "time_to_valid_fixture_selection_microseconds":valid.then(|| started.elapsed().as_micros()),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let budget =
        match (arguments.next(), arguments.next(), arguments.next()) {
            (None, None, None) => 16_384,
            (Some(flag), Some(value), None) if flag == "--response-budget-bytes" => {
                value.parse::<usize>()?
            }
            _ => return Err(
                "usage: discovery_context_evaluation [--response-budget-bytes positive-integer]"
                    .into(),
            ),
        };
    if budget == 0 {
        return Err("response budget must be positive".into());
    }
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("../tests/fixtures/discovery_tasks.json"))?;
    let catalog: Vec<_> = fixtures.iter().map(|fixture| {
        let description = format!("{}\n\n{} {}", waygate_mcp::server::skill_tools::GUIDANCE,
            fixture.purpose, "Additional operation documentation. ".repeat(300));
        let definition = Tool::new(fixture.name.clone(), description,
            Arc::new(json!({"type":"object", "properties":{"query":{"type":"string"}}, "required":["query"]})
                .as_object().unwrap().clone()));
        CatalogTool::upstream(&fixture.source, &definition, ToolFacts {
            server: fixture.source.clone(), name: fixture.name.clone(),
            risk: waygate_mcp::protocol::RiskTier::Low, side_effects: false, pii: false,
            requires_approval: false, requires_approval_known: true,
        }).expect("synthetic contract is publishable")
    }).collect();
    let raw_search_matches: Vec<_> = catalog
        .iter()
        .filter(|tool| {
            tool.definition
                .description
                .as_deref()
                .unwrap()
                .contains("search")
        })
        .map(|tool| &tool.definition)
        .collect();
    let broad_bytes = serde_json::to_vec(&raw_search_matches)?.len();
    let mut tasks = Vec::new();
    for fixture in &fixtures {
        let Some(query) = fixture.query.as_deref() else {
            continue;
        };
        let expected = fixture.expected.as_deref().unwrap();
        let before = baseline(&catalog, query, expected, budget);
        let before_unbounded = baseline(&catalog, query, expected, usize::MAX);
        let started = Instant::now();
        let ranked = rank_visible_tools(query, catalog.clone());
        let previews: Vec<_> = ranked
            .iter()
            .take(5)
            .map(|tool| {
                json!({
                    "source":tool.identity.source.name(), "tool":tool.identity.name,
                    "source_kind":"upstream",
                    "name":tool.identity.qualified_name(),
                    "description":compact_tool_description(tool.definition.description.as_deref()),
                    "governance":{"risk":"low","side_effects":false,"pii":false,"requires_approval":false,"requires_approval_known":true},
                })
            })
            .collect();
        let preview_payload = serde_json::to_vec(&previews)?;
        let delivered = &preview_payload[..preview_payload.len().min(budget)];
        let received: Option<Vec<serde_json::Value>> = serde_json::from_slice(delivered).ok();
        let expected_rank = ranked
            .iter()
            .position(|tool| {
                Some(tool.identity.qualified_name().as_str()) == fixture.expected.as_deref()
            })
            .map(|rank| rank + 1);
        let selected = received
            .as_ref()
            .and_then(|tools| tools.first())
            .and_then(|tool| {
                catalog
                    .iter()
                    .find(|candidate| candidate.identity.qualified_name() == tool["name"])
            });
        let contract = selected
            .map(|tool| serde_json::to_vec(&tool.definition))
            .transpose()?;
        let inspected = contract.as_ref().and_then(|bytes| {
            serde_json::from_slice::<Tool>(&bytes[..bytes.len().min(budget)]).ok()
        });
        let valid = inspected
            .as_ref()
            .is_some_and(|tool| valid_selection(tool, expected, query));
        let truncated = preview_payload.len() > budget
            || contract.as_ref().is_some_and(|bytes| bytes.len() > budget);
        tasks.push(json!({
            "query": query, "expected": fixture.expected, "expected_rank":expected_rank,
            "baseline":before, "baseline_unbounded":before_unbounded,
            "compact":{
                "candidate_count":previews.len(), "preview_bytes":preview_payload.len(),
                "selected_contract_bytes":contract.as_ref().map(Vec::len),
                "modeled_discovery_calls":1+usize::from(contract.is_some()),
                "simulated_truncation":truncated, "valid_fixture_selection":valid,
                "time_to_valid_fixture_selection_microseconds":valid.then(|| started.elapsed().as_micros()),
            },
        }));
    }
    let report = json!({
        "measurement":"offline deterministic client comparison using the same ranker; modeled calls and simulated per-response truncation; elapsed time excludes model and network",
        "response_budget_bytes":budget,
        "broad_search_word_matches":raw_search_matches.len(),
        "broad_descriptor_bytes":broad_bytes,
        "compact_search_word_matches":rank_visible_tools("search", catalog.clone()).len(),
        "tasks":tasks,
        "no_match_candidates":rank_visible_tools("quantum entanglement", catalog).len(),
    });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(())
}
