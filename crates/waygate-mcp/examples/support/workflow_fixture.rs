//! Synthetic instructions with adapted published workflow discovery metadata.

use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use waygate_skills::*;

#[derive(Deserialize)]
pub struct Fixture {
    pub skills: Vec<Metadata>,
    pub tasks: Vec<Task>,
}

#[derive(Deserialize)]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub version: String,
}

#[derive(Deserialize)]
pub struct Task {
    pub query: String,
    pub expected: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

pub fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../../tests/fixtures/workflow_tasks.json")).unwrap()
}

pub fn snapshot(label: &str) -> SkillCatalogSnapshot {
    let mut skills = Vec::new();
    let mut bytes = BTreeMap::new();
    for metadata in fixture().skills {
        let name = metadata.name;
        let root = format!("skill://fixture/{name}/");
        let instructions = format!("---\nname: {name}\ndescription: {}\nmetadata:\n  version: '{}'\n---\nRead references/check.md. Revision marker: {label}.\n{}", serde_json::to_string(&metadata.description).unwrap(), metadata.version, "Synthetic workflow instructions retained by the client.\n".repeat(400));
        let mut resources = Vec::new();
        for (path, content) in [
            ("SKILL.md", instructions.as_str()),
            ("references/check.md", label),
            ("references/unused.md", "Unneeded supporting content"),
        ] {
            let content = content.as_bytes().to_vec();
            let uri = format!("{root}{path}");
            resources.push(SkillResourceDescriptor {
                uri: uri.clone(),
                source_path: format!("{name}/{path}"),
                source_object: sha256_digest(&content),
                size: content.len() as u64,
                media_type: "text/markdown".into(),
            });
            bytes.insert(uri, content);
        }
        skills.push(CatalogSkill { uri: format!("{root}SKILL.md"), frontmatter: json!({"name":name,"description":metadata.description,"metadata":{"version":metadata.version}}).as_object().unwrap().clone(), resources });
    }
    verify_in_memory_catalog(
        CatalogSourceIdentity {
            origin: "git+https://fixture.invalid/workflows".into(),
            reference: "fixture".into(),
            resolved_digest: sha256_digest(label.as_bytes()),
            resolved_tree_digest: sha256_digest(label.as_bytes()),
        },
        CatalogManifest {
            schema_version: CATALOG_SCHEMA_VERSION,
            skills,
        },
        bytes,
    )
    .unwrap()
}
