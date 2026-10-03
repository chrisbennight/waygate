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

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        let started = Instant::now();
        let ranked = rank_visible_tools(query, catalog.clone());
        let previews: Vec<_> = ranked
            .iter()
            .take(5)
            .map(|tool| {
                json!({
                    "source":tool.identity.source.name(), "tool":tool.identity.name,
                    "name":tool.identity.qualified_name(),
                    "description":compact_tool_description(tool.definition.description.as_deref()),
                })
            })
            .collect();
        let preview_bytes = serde_json::to_vec(&previews)?.len();
        let expected_rank = ranked
            .iter()
            .position(|tool| {
                Some(tool.identity.qualified_name().as_str()) == fixture.expected.as_deref()
            })
            .map(|rank| rank + 1);
        let selected_contract_bytes = ranked
            .iter()
            .find(|tool| {
                Some(tool.identity.qualified_name().as_str()) == fixture.expected.as_deref()
            })
            .map(|tool| serde_json::to_vec(&tool.definition).map(|bytes| bytes.len()))
            .transpose()?;
        tasks.push(json!({
            "query": query, "expected": fixture.expected, "expected_rank":expected_rank,
            "candidate_count": previews.len(), "preview_bytes": preview_bytes,
            "selected_contract_bytes":selected_contract_bytes,
            "modeled_search_and_inspection_calls": 2,
            "local_search_and_contract_encoding_microseconds":started.elapsed().as_micros(),
        }));
    }
    let report = json!({
        "measurement":"offline synthetic comparison; call counts are modeled, elapsed time excludes model and network",
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
