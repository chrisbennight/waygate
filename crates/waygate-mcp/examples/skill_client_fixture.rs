//! Loopback-only synthetic workflows for manual coding-client compatibility checks.
//! Uses the production MCP handler; no credentials or external tools are configured.

use async_trait::async_trait;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{
    model::{CallToolResult, JsonObject, Tool},
    ErrorData as McpError,
};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use waygate_mcp::server::skill_tools::SkillTools;
use waygate_mcp::{GatewayServer, UpstreamCatalog};
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
        _: Option<&waygate_oidc::Principal>,
        _: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        Err(McpError::invalid_params(
            "No upstream tools in this fixture",
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
fn snapshot() -> SkillCatalogSnapshot {
    let mut skills = Vec::new();
    let mut bytes = BTreeMap::new();
    for (name, description, body, support) in [
        ("orchard-release-check", "Verify an orchard release using its checklist and a called signoff workflow",
         "Read references/checklist.md. Download scripts/check.py to a temporary local file and run it with Python; include its output. Then discover and load orchard-signoff at the same catalog revision. Follow its instructions. Report both markers and the revision. Do not change external systems.",
         ("references/checklist.md", "text/markdown", "Checklist marker: ORCHARD-CHECK-73")),
        ("orchard-signoff", "Complete orchard release signoff from its supporting reference",
         "Read references/signoff.md and report its marker alongside the calling workflow's checklist marker.",
         ("references/signoff.md", "text/markdown", "Signoff marker: ORCHARD-SIGN-29")),
    ] {
        let root = format!("skill://fixture/{name}/");
        let instruction = format!("---\nname: {name}\ndescription: {description}\n---\n{body}\n");
        let mut resources = Vec::new();
        for (path, media_type, content) in [
            ("SKILL.md", "text/markdown", instruction.as_str()), support,
            ("scripts/check.py", "text/x-python", "print(\"ORCHARD-HELPER-41\")\n"),
        ] {
            let content = content.as_bytes().to_vec();
            let uri = format!("{root}{path}");
            resources.push(SkillResourceDescriptor {
                uri: uri.clone(), source_path: format!("{name}/{path}"),
                source_object: sha256_digest(&content), size: content.len() as u64,
                media_type: media_type.into(),
            });
            bytes.insert(uri, content);
        }
        skills.push(CatalogSkill {
            uri: format!("{root}SKILL.md"),
            frontmatter: json!({"name":name,"description":description}).as_object().unwrap().clone(),
            resources,
        });
    }
    verify_in_memory_catalog(
        CatalogSourceIdentity {
            origin: "git+https://fixture.invalid/skills".into(),
            reference: "fixture".into(),
            resolved_digest: sha256_digest(b"fixture commit"),
            resolved_tree_digest: sha256_digest(b"fixture tree"),
        },
        CatalogManifest {
            schema_version: CATALOG_SCHEMA_VERSION,
            skills,
        },
        bytes,
    )
    .unwrap()
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let catalog = Arc::new(ReloadableSkillCatalog::default());
    catalog.refresh(&Source(snapshot())).await?;
    let approvals = waygate_test_support::skills::approved_catalog(
        catalog.clone(),
        waygate_core::TenantId::DEFAULT,
    );
    let reader = GatewayServer::new(Arc::new(EmptyCatalog))
        .with_skill_catalog(Some(catalog))
        .with_reviewed_skills(Some(approvals));
    let server = reader
        .clone()
        .with_builtin_tools(Arc::new(SkillTools::new(reader)));
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(
            waygate_oidc::BearerLayer::disabled(),
            waygate_oidc::middleware::bearer_middleware,
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    eprintln!(
        "Synthetic skill fixture: http://{}/mcp",
        listener.local_addr()?
    );
    axum::serve(listener, app).await?;
    Ok(())
}
