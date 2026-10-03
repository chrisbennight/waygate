//! Offline client comparison through the production workflow handlers.

#[path = "support/skill_client.rs"]
mod skill_client;
#[path = "support/workflow_fixture.rs"]
mod workflow_fixture;

use anyhow::{ensure, Result};
use async_trait::async_trait;
use rmcp::{
    model::{CallToolResult, JsonObject, Tool},
    ErrorData as McpError,
};
use serde_json::{json, Value};
use skill_client::Workflow;
use std::{sync::Arc, time::Instant};
use waygate_mcp::server::skill_tools::SkillTools;
use waygate_mcp::{BuiltinTools, GatewayServer, UpstreamCatalog};
use waygate_oidc::Principal;
use waygate_skills::*;

struct EmptyCatalog;
#[async_trait]
impl UpstreamCatalog for EmptyCatalog {
    async fn list_servers(&self) -> Vec<String> {
        Vec::new()
    }
    async fn list_tools(&self, _: &str) -> Result<Vec<Tool>, McpError> {
        Ok(Vec::new())
    }
    async fn call_tool(
        &self,
        _: &str,
        _: &str,
        _: Option<JsonObject>,
        _: Option<&Principal>,
        _: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        Err(McpError::invalid_params(
            "fixture has no upstream operations",
            None,
        ))
    }
}
struct Source(SkillCatalogSnapshot);
#[async_trait]
impl SkillCatalogSource for Source {
    async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        Ok(self.0.clone())
    }
}

fn principal() -> Principal {
    Principal {
        sub: "fixture-reader".into(),
        email: None,
        groups: Vec::new(),
        issuer: "fixture".into(),
        scopes: vec!["mcp:read".into()],
        tenant: Default::default(),
        auth_method: waygate_oidc::AuthMethod::ApiKey,
        raw_token: None,
        roles: Vec::new(),
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn tools() -> Result<SkillTools> {
    let catalog = Arc::new(ReloadableSkillCatalog::default());
    catalog
        .refresh(&Source(workflow_fixture::snapshot("A")))
        .await?;
    let approvals = waygate_test_support::skills::approved_catalog(
        catalog.clone(),
        waygate_core::TenantId::DEFAULT,
    );
    Ok(SkillTools::new(
        GatewayServer::new(Arc::new(EmptyCatalog))
            .with_skill_catalog(Some(catalog))
            .with_reviewed_skills(Some(approvals)),
    ))
}

async fn call(tools: &SkillTools, name: &str, arguments: Value) -> Result<Value> {
    let result = tools
        .call(
            name,
            Some(arguments.as_object().unwrap().clone()),
            Some(&principal()),
        )
        .await?;
    result
        .structured_content
        .ok_or_else(|| anyhow::anyhow!("missing structured workflow result"))
}

fn bytes(value: &Value) -> usize {
    serde_json::to_vec(value).unwrap().len()
}

fn legacy_projection(authorized: &Value, query: &str) -> Value {
    let metadata = workflow_fixture::fixture().skills;
    let lower = query.to_lowercase();
    let terms: Vec<_> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .collect();
    let mut candidates: Vec<_> = authorized["skills"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|skill| {
            let original = metadata
                .iter()
                .find(|metadata| metadata.name == skill["name"])?;
            let name = original.name.to_lowercase();
            let description = original.description.to_lowercase();
            let score: usize = terms
                .iter()
                .map(|term| {
                    usize::from(description.contains(term)) + 3 * usize::from(name.contains(term))
                })
                .sum();
            if !terms.is_empty() && score == 0 {
                return None;
            }
            let mut full = skill.clone();
            full["description"] = json!(original.description);
            Some((score, full))
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1["uri"].as_str().cmp(&b.1["uri"].as_str()))
    });
    json!({"skills":candidates.into_iter().take(20).map(|(_,skill)| skill).collect::<Vec<_>>(),"next_cursor":null})
}

async fn evaluate(tools: &SkillTools) -> Result<Value> {
    let mut reports = Vec::new();
    for task in workflow_fixture::fixture().tasks {
        let before_start = Instant::now();
        let authorized = call(tools, "search", json!({})).await?;
        let before_search = legacy_projection(&authorized, &task.query);
        let before_candidate = before_search["skills"].as_array().unwrap().first();
        let before_load = if let Some(skill) = before_candidate {
            Some(
                call(
                    tools,
                    "load",
                    json!({"uri":skill["uri"],"revision":skill["revision"]}),
                )
                .await?,
            )
        } else {
            None
        };
        let before_valid =
            before_candidate.and_then(|skill| skill["name"].as_str()) == task.expected.as_deref();
        let before_time =
            (before_valid && before_load.is_some()).then(|| before_start.elapsed().as_micros());
        let before_reload = if let Some(skill) = before_candidate {
            Some(
                call(
                    tools,
                    "load",
                    json!({"uri":skill["uri"],"revision":skill["revision"]}),
                )
                .await?,
            )
        } else {
            None
        };

        let after_start = Instant::now();
        let after_search = call(tools, "search", json!({"query":task.query,"limit":3})).await?;
        let after_candidate = after_search["skills"].as_array().unwrap().first();
        let after_load = if let Some(skill) = after_candidate {
            Some(
                call(
                    tools,
                    "load",
                    json!({"uri":skill["uri"],"revision":skill["revision"]}),
                )
                .await?,
            )
        } else {
            None
        };
        let after_valid =
            after_candidate.and_then(|skill| skill["name"].as_str()) == task.expected.as_deref();
        let after_time =
            (after_valid && after_load.is_some()).then(|| after_start.elapsed().as_micros());
        ensure!(after_valid, "fixture selection failed for {}", task.query);
        let mut recheck_bytes = None;
        let mut recovery_bytes = None;
        let mut supporting_bytes = None;
        if let Some(loaded) = after_load.as_ref() {
            let mut retained = Workflow::from_complete(loaded.clone())?;
            let file = call(
                tools,
                "read_file",
                retained.file_arguments("references/check.md")?,
            )
            .await?;
            ensure!(file["text"] == "A", "supporting revision mismatch");
            supporting_bytes = Some(bytes(&file));
            let recheck = call(tools, "load", retained.load_arguments()).await?;
            ensure!(recheck["unchanged"] == true, "fixture should be unchanged");
            recheck_bytes = Some(bytes(&recheck));
            retained.accept(recheck)?;
            ensure!(
                retained.complete()? == loaded,
                "retained instructions changed"
            );
            retained.forget_content();
            ensure!(
                retained
                    .load_arguments()
                    .get("known_document_hash")
                    .is_none(),
                "hash alone skipped required content"
            );
            let recovery = call(tools, "load", retained.load_arguments()).await?;
            recovery_bytes = Some(bytes(&recovery));
            retained.accept(recovery)?;
            ensure!(retained.complete()? == loaded, "full recovery failed");
        }
        reports.push(json!({
            "query":task.query,"expected":task.expected,
            "before":{"search_calls_before_selection":1,"candidates":before_search["skills"].as_array().unwrap().len(),"search_bytes":bytes(&before_search),"load_bytes":before_load.as_ref().map(bytes),"redundant_full_loads":usize::from(before_reload.is_some()),"repeat_load_bytes":before_reload.as_ref().map(bytes),"valid_selection":before_valid,"time_to_usable_instructions_microseconds":before_time},
            "after":{"search_calls_before_selection":1,"candidates":after_search["skills"].as_array().unwrap().len(),"search_bytes":bytes(&after_search),"load_bytes":after_load.as_ref().map(bytes),"redundant_full_loads":0,"freshness_response_bytes":recheck_bytes,"necessary_recovery_bytes":recovery_bytes,"supporting_file_reads":usize::from(supporting_bytes.is_some()),"supporting_response_bytes":supporting_bytes,"valid_selection":after_valid,"time_to_usable_instructions_microseconds":after_time}
        }));
    }
    Ok(
        json!({"measurement":"offline fixture client; legacy search projection rebuilt from a current authorized list, same initial load handler on both paths; elapsed includes local handler work and excludes model/network; reuse and recovery are separate subsequent steps","tasks":reports}),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&evaluate(&tools().await?).await?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn client_comparison_keeps_correct_selection_and_recovers_lost_content() {
        let report = evaluate(&tools().await.unwrap()).await.unwrap();
        for task in report["tasks"].as_array().unwrap() {
            assert_eq!(task["after"]["valid_selection"], true);
            assert_eq!(task["after"]["redundant_full_loads"], 0);
            if !task["expected"].is_null() {
                assert!(
                    task["after"]["freshness_response_bytes"].as_u64().unwrap()
                        < task["after"]["load_bytes"].as_u64().unwrap()
                );
                assert_eq!(
                    task["after"]["necessary_recovery_bytes"],
                    task["after"]["load_bytes"]
                );
            }
        }
    }
}
