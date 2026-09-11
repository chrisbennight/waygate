//! Draft Agent Skills MCP extension projection.
//!
//! The catalog crate owns acquisition and validation. This module only projects
//! one already-verified immutable snapshot onto SEP-2640's current list/get
//! methods and the standard `resources/read` response. Skill bytes remain
//! untrusted model input; making them discoverable grants no execution
//! permission.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rmcp::{
    model::{CacheScope, ReadResourceResult, ResourceContents},
    ErrorData as McpError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use waygate_oidc::Principal;
use waygate_skills::{LoadedSkillResource, SkillCatalogSnapshot, SkillEntry};

use crate::tool_list_pagination::{paginate_bound, BoundListDomain, ToolListCursorSealer};

pub const EXTENSION_ID: &str = "io.modelcontextprotocol/skills";
pub const LIST_METHOD: &str = "skills/list";
pub const GET_METHOD: &str = "skills/get";

const RESULT_COMPLETE: &str = "complete";
const LIST_CURSOR_KIND: &str = "sl1";
const LIST_VIEW_DOMAIN: &[u8] = b"skills-list-view-v1\0";
const LIST_PAGE_SIZE: usize = 50;
const LIST_DOMAIN: BoundListDomain = BoundListDomain::new(
    LIST_PAGE_SIZE,
    LIST_CURSOR_KIND,
    LIST_VIEW_DOMAIN,
    LIST_METHOD,
);

pub(crate) fn is_method(method: &str) -> bool {
    matches!(method, LIST_METHOD | GET_METHOD)
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListSkillsParams {
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetSkillParams {
    uri: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct Skill {
    uri: String,
    frontmatter: Map<String, Value>,
    resources: &'static str,
}

impl From<&SkillEntry> for Skill {
    fn from(entry: &SkillEntry) -> Self {
        Self {
            uri: entry.uri.clone(),
            frontmatter: entry.frontmatter.clone(),
            // The Git tree gives the gateway immutable object identities but
            // not SEP-2640's required SHA-256 content digests. Advertising a
            // dynamic set preserves progressive disclosure instead of reading
            // every file merely to populate discovery metadata.
            resources: "dynamic",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListSkillsResult {
    result_type: &'static str,
    skills: Vec<Skill>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_scope: Option<CacheScope>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetSkillResult {
    result_type: &'static str,
    skill: Skill,
}

/// Handle a draft Skills custom method against one immutable snapshot.
pub(crate) fn handle_custom(
    snapshot: &SkillCatalogSnapshot,
    method: &str,
    raw_params: Value,
    principal: Option<&Principal>,
    sealer: &ToolListCursorSealer,
    include_cache_hints: bool,
) -> Result<Value, McpError> {
    handle_entries(
        &snapshot.skills().iter().collect::<Vec<_>>(),
        method,
        raw_params,
        principal,
        sealer,
        include_cache_hints,
    )
}

pub(crate) fn handle_entries(
    entries: &[&SkillEntry],
    method: &str,
    raw_params: Value,
    principal: Option<&Principal>,
    sealer: &ToolListCursorSealer,
    include_cache_hints: bool,
) -> Result<Value, McpError> {
    let result = match method {
        LIST_METHOD => {
            let params: ListSkillsParams = if raw_params.is_null() {
                ListSkillsParams::default()
            } else {
                serde_json::from_value(raw_params).map_err(|error| {
                    McpError::invalid_params(
                        format!("invalid skills/list parameters: {error}"),
                        None,
                    )
                })?
            };
            let skills = entries.iter().map(|entry| Skill::from(*entry)).collect();
            let page = paginate_bound(
                skills,
                params.cursor.as_deref(),
                principal,
                sealer,
                LIST_DOMAIN,
            )?;
            serde_json::to_value(ListSkillsResult {
                result_type: RESULT_COMPLETE,
                skills: page.items,
                next_cursor: page.next_cursor,
                ttl_ms: include_cache_hints.then_some(0),
                cache_scope: include_cache_hints.then_some(CacheScope::Private),
            })
        }
        GET_METHOD => {
            let params: GetSkillParams = serde_json::from_value(raw_params).map_err(|error| {
                McpError::invalid_params(format!("invalid skills/get parameters: {error}"), None)
            })?;
            let skill = entries
                .iter()
                .copied()
                .find(|skill| skill.uri == params.uri)
                .ok_or_else(|| {
                    McpError::invalid_params(
                        "skills/get URI does not identify a skill in the current catalog",
                        Some(serde_json::json!({"uri": params.uri})),
                    )
                })?;
            serde_json::to_value(GetSkillResult {
                result_type: RESULT_COMPLETE,
                skill: Skill::from(skill),
            })
        }
        _ => unreachable!("caller checks is_method"),
    };
    result.map_err(|_| McpError::internal_error("failed to serialize Skills response", None))
}

/// Project already-verified bytes from the same snapshot advertised by
/// list/get without loading the source again. Textual media with valid UTF-8
/// uses MCP text contents; all other bytes use a base64 blob.
pub(crate) fn render_loaded_resource(
    resource: &LoadedSkillResource,
    include_cache_hints: bool,
) -> ReadResourceResult {
    let uri = &resource.descriptor.uri;
    let contents = if is_textual_media_type(&resource.descriptor.media_type) {
        match std::str::from_utf8(&resource.bytes) {
            Ok(text) => ResourceContents::text(text.to_owned(), uri)
                .with_mime_type(resource.descriptor.media_type.clone()),
            Err(_) => ResourceContents::blob(BASE64_STANDARD.encode(&resource.bytes), uri)
                .with_mime_type(resource.descriptor.media_type.clone()),
        }
    } else {
        ResourceContents::blob(BASE64_STANDARD.encode(&resource.bytes), uri)
            .with_mime_type(resource.descriptor.media_type.clone())
    };
    let mut result = ReadResourceResult::new(vec![contents]);
    if include_cache_hints {
        result.ttl_ms = Some(0);
        result.cache_scope = Some(CacheScope::Private);
    } else {
        result.result_type = None;
    }
    result
}

fn is_textual_media_type(media_type: &str) -> bool {
    let subtype = media_type.strip_prefix("application/");
    media_type.starts_with("text/")
        || matches!(
            subtype,
            Some("json" | "xml" | "yaml" | "x-yaml" | "javascript" | "ecmascript")
        )
        || subtype.is_some_and(|subtype| subtype.ends_with("+json") || subtype.ends_with("+xml"))
        || media_type == "image/svg+xml"
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fmt::Write as _};

    use serde_json::json;
    use sha2::{Digest, Sha256};
    use waygate_skills::{
        verify_in_memory_catalog, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
        SkillResourceDescriptor, CATALOG_SCHEMA_VERSION,
    };

    use super::*;

    fn digest(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut encoded = String::from("sha256:");
        for byte in digest {
            write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }

    fn snapshot() -> SkillCatalogSnapshot {
        let skill_md = b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n";
        let binary = *b"plain binary bytes";
        let skill_uri = "skill://catalog/demo/SKILL.md".to_owned();
        let binary_uri = "skill://catalog/demo/assets/data.bin".to_owned();
        let resources = vec![
            SkillResourceDescriptor {
                uri: skill_uri.clone(),
                source_path: "demo/SKILL.md".into(),
                source_object: digest(skill_md),
                size: skill_md.len() as u64,
                media_type: "text/markdown".into(),
            },
            SkillResourceDescriptor {
                uri: binary_uri.clone(),
                source_path: "demo/assets/data.bin".into(),
                source_object: digest(&binary),
                size: binary.len() as u64,
                media_type: "application/octet-stream".into(),
            },
        ];
        verify_in_memory_catalog(
            CatalogSourceIdentity {
                origin: "git+https://git.example/team/skills".into(),
                reference: "main".into(),
                resolved_digest: format!("git-sha1:{}", "a".repeat(40)),
                resolved_tree_digest: format!("git-sha1:{}", "b".repeat(40)),
            },
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills: vec![CatalogSkill {
                    uri: skill_uri.clone(),
                    frontmatter: json!({
                        "name": "demo",
                        "description": "Demo skill"
                    })
                    .as_object()
                    .expect("frontmatter object")
                    .clone(),
                    resources,
                }],
            },
            BTreeMap::from([
                (skill_uri, skill_md.to_vec()),
                (binary_uri, binary.to_vec()),
            ]),
        )
        .expect("valid snapshot")
    }

    #[test]
    fn list_and_get_preserve_frontmatter_and_advertise_dynamic_resources() {
        let snapshot = snapshot();
        let sealer = ToolListCursorSealer::process_local();
        let listed =
            handle_custom(&snapshot, LIST_METHOD, Value::Null, None, &sealer, true).expect("list");
        assert_eq!(listed["resultType"], "complete");
        assert_eq!(listed["ttlMs"], 0);
        assert_eq!(listed["cacheScope"], "private");
        assert_eq!(listed["skills"][0]["frontmatter"]["name"], "demo");
        assert_eq!(listed["skills"][0]["resources"], "dynamic");

        let uri = listed["skills"][0]["uri"].clone();
        let fetched = handle_custom(
            &snapshot,
            GET_METHOD,
            json!({"uri": uri}),
            None,
            &sealer,
            true,
        )
        .expect("get");
        assert_eq!(fetched["skill"], listed["skills"][0]);
        // SEP-2640 applies the MCP 2026 list-cache attributes only to
        // skills/list; skills/get has no corresponding fields.
        assert!(fetched.get("ttlMs").is_none());
        assert!(fetched.get("cacheScope").is_none());
    }

    #[test]
    fn list_cursor_is_bound_to_the_skill_view_and_cursor_namespace() {
        let skills = (0..3)
            .map(|index| Skill {
                uri: format!("skill://catalog/demo-{index}/SKILL.md"),
                frontmatter: Map::new(),
                resources: "dynamic",
            })
            .collect::<Vec<_>>();
        let sealer = ToolListCursorSealer::process_local();
        let first = paginate_bound(
            skills.clone(),
            None,
            None,
            &sealer,
            BoundListDomain::new(2, LIST_CURSOR_KIND, LIST_VIEW_DOMAIN, LIST_METHOD),
        )
        .expect("first page");
        let cursor = first.next_cursor.expect("continuation");
        let second = paginate_bound(
            skills.clone(),
            Some(&cursor),
            None,
            &sealer,
            BoundListDomain::new(2, LIST_CURSOR_KIND, LIST_VIEW_DOMAIN, LIST_METHOD),
        )
        .expect("same skill view");
        assert_eq!(second.items.len(), 1);

        let mut changed = skills.clone();
        changed[2].uri = "skill://catalog/changed/SKILL.md".into();
        for result in [
            paginate_bound(
                changed,
                Some(&cursor),
                None,
                &sealer,
                BoundListDomain::new(2, LIST_CURSOR_KIND, LIST_VIEW_DOMAIN, LIST_METHOD),
            ),
            paginate_bound(
                skills,
                Some(&cursor),
                None,
                &sealer,
                BoundListDomain::new(2, "other-list", LIST_VIEW_DOMAIN, LIST_METHOD),
            ),
        ] {
            let error = result.expect_err("cursor binding must fail closed");
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        }
    }

    #[test]
    fn get_rejects_resource_and_unknown_uris() {
        let snapshot = snapshot();
        let sealer = ToolListCursorSealer::process_local();
        for uri in [
            "skill://catalog/demo/assets/data.bin",
            "skill://catalog/missing/SKILL.md",
        ] {
            let error = handle_custom(
                &snapshot,
                GET_METHOD,
                json!({"uri": uri}),
                None,
                &sealer,
                true,
            )
            .expect_err("not a current skill URI");
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        }
    }

    #[tokio::test]
    async fn resource_read_preserves_text_binary_media_type_and_generation_shape() {
        let snapshot = snapshot();
        let text = snapshot
            .load_resource("skill://catalog/demo/SKILL.md")
            .await
            .expect("resource load")
            .expect("text resource");
        let text = render_loaded_resource(&text, true);
        assert_eq!(text.result_type, Some(rmcp::model::ResultType::COMPLETE));
        assert_eq!(text.ttl_ms, Some(0));
        assert_eq!(text.cache_scope, Some(CacheScope::Private));
        match &text.contents[0] {
            ResourceContents::TextResourceContents {
                text, mime_type, ..
            } => {
                assert!(text.starts_with("---\nname: demo"));
                assert_eq!(mime_type.as_deref(), Some("text/markdown"));
            }
            other => panic!("expected text, got {other:?}"),
        }

        let blob = snapshot
            .load_resource("skill://catalog/demo/assets/data.bin")
            .await
            .expect("resource load")
            .expect("binary resource");
        let blob = render_loaded_resource(&blob, false);
        assert_eq!(blob.result_type, None);
        match &blob.contents[0] {
            ResourceContents::BlobResourceContents {
                blob, mime_type, ..
            } => {
                assert_eq!(BASE64_STANDARD.decode(blob).unwrap(), b"plain binary bytes");
                assert_eq!(mime_type.as_deref(), Some("application/octet-stream"));
            }
            other => panic!("expected blob, got {other:?}"),
        }
    }
}
