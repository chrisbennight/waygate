use std::{collections::BTreeMap, fmt, fmt::Write as _, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Version of the source-neutral catalog index consumed by the gateway.
pub const CATALOG_SCHEMA_VERSION: u32 = 1;

/// Optional publisher-reported Code Mode test results, encoded as a JSON string
/// in Agent Skills metadata. These hints never authorize or block execution.
pub const CODE_MODE_METADATA_KEY: &str = "io.cacahuate.mcp-gateway.code-mode";

/// Identity of the external snapshot that supplied a catalog.
///
/// `reference` is what the operator configured, while `resolved_digest` and
/// `resolved_tree_digest` identify the source revision and its verified root
/// tree. Policy and approval code must bind to both immutable identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSourceIdentity {
    pub origin: String,
    pub reference: String,
    pub resolved_digest: String,
    pub resolved_tree_digest: String,
}

/// Source-neutral description of one immutable catalog generation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogManifest {
    pub schema_version: u32,
    pub skills: Vec<CatalogSkill>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSkill {
    /// Resource URI of the skill's root `SKILL.md`.
    pub uri: String,
    /// Verbatim YAML frontmatter rendered as JSON.
    pub frontmatter: Map<String, Value>,
    /// Complete static file set for this skill.
    pub resources: Vec<SkillResourceDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillResourceDescriptor {
    pub uri: String,
    /// Path of this resource inside the configured source boundary.
    pub source_path: String,
    /// Immutable object identity supplied by the source.
    pub source_object: String,
    pub size: u64,
    pub media_type: String,
}

/// One immutable, fully verified catalog generation.
#[derive(Clone)]
pub struct SkillCatalogSnapshot {
    revision: String,
    source: CatalogSourceIdentity,
    skills: Arc<[SkillEntry]>,
    resources: Arc<BTreeMap<String, SkillResourceDescriptor>>,
    known_content_digests: Arc<BTreeMap<String, String>>,
    loader: Arc<dyn crate::SkillResourceLoader>,
}

impl fmt::Debug for SkillCatalogSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillCatalogSnapshot")
            .field("source", &self.source)
            .field("skills", &self.skills)
            .field("resources", &self.resources)
            .finish_non_exhaustive()
    }
}

impl SkillCatalogSnapshot {
    pub(crate) fn new(
        source: CatalogSourceIdentity,
        skills: Vec<SkillEntry>,
        resources: BTreeMap<String, SkillResourceDescriptor>,
        known_content_digests: BTreeMap<String, String>,
        loader: Arc<dyn crate::SkillResourceLoader>,
    ) -> Self {
        let revision = {
            let manifest = CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills: skills
                    .iter()
                    .map(|skill| CatalogSkill {
                        uri: skill.uri.clone(),
                        frontmatter: skill.frontmatter.clone(),
                        resources: skill.resources.to_vec(),
                    })
                    .collect(),
            };
            crate::sha256_digest(
                &serde_json::to_vec(&(&source, manifest))
                    .expect("verified catalog is serializable"),
            )
        };
        Self {
            revision,
            source,
            skills: skills.into(),
            resources: Arc::new(resources),
            known_content_digests: Arc::new(known_content_digests),
            loader,
        }
    }

    pub fn source(&self) -> &CatalogSourceIdentity {
        &self.source
    }

    /// Content-bound identity for a complete catalog and its configured origin.
    pub fn revision(&self) -> String {
        self.revision.clone()
    }

    pub fn skills(&self) -> &[SkillEntry] {
        &self.skills
    }

    pub fn resource(&self, uri: &str) -> Option<&SkillResourceDescriptor> {
        self.resources.get(uri)
    }

    /// Return a SHA-256 already established while validating discovery
    /// metadata. Supporting files remain absent until they are read.
    pub fn known_content_digest(&self, uri: &str) -> Option<&str> {
        self.known_content_digests.get(uri).map(String::as_str)
    }

    /// Load and verify one resource from this exact catalog generation.
    pub async fn load_resource(
        &self,
        uri: &str,
    ) -> Result<Option<LoadedSkillResource>, crate::SkillResourceLoadError> {
        let Some(descriptor) = self.resources.get(uri) else {
            return Ok(None);
        };
        let bytes = self.loader.load(descriptor).await?;
        if descriptor.size != bytes.len() as u64 {
            return Err(crate::SkillResourceLoadError::SizeMismatch(uri.to_owned()));
        }
        let content_digest = crate::sha256_digest(&bytes);
        if descriptor.source_object.starts_with("sha256:")
            && descriptor.source_object != content_digest
        {
            return Err(crate::SkillResourceLoadError::DigestMismatch(
                uri.to_owned(),
            ));
        }
        Ok(Some(LoadedSkillResource {
            descriptor: descriptor.clone(),
            bytes: Arc::from(bytes),
            content_digest,
        }))
    }

    /// Return the immutable identity of the skill that owns `uri`.
    ///
    /// The identity carries both the configured source origin and every
    /// verified content digest. Approval and evidence consumers can therefore
    /// distinguish the same skill URI served by another origin or at another
    /// revision without retaining the resource bytes themselves.
    pub fn revision_identity(&self, uri: &str) -> Option<SkillRevisionIdentity> {
        let skill = self
            .skills
            .iter()
            .find(|skill| skill.resources.iter().any(|resource| resource.uri == uri))?;
        Some(SkillRevisionIdentity::new(&self.source, skill))
    }

    /// Return the content-bound identity for one resource read.
    pub fn resource_identity(
        &self,
        uri: &str,
        content_digest: String,
    ) -> Option<SkillResourceIdentity> {
        let revision = self.revision_identity(uri)?;
        let descriptor = self.resources.get(uri)?;
        Some(SkillResourceIdentity {
            revision,
            resource_uri: uri.to_owned(),
            source_path: descriptor.source_path.clone(),
            source_object: descriptor.source_object.clone(),
            resource_digest: content_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SkillEntry {
    pub uri: String,
    pub frontmatter: Map<String, Value>,
    pub resources: Arc<[SkillResourceDescriptor]>,
}

impl SkillEntry {
    /// Whether the publisher reports testing this resource in Code Mode.
    /// Missing, malformed, legacy, and unknown metadata provide no hint.
    /// This method is for client guidance only, never execution admission.
    pub fn code_mode_tested_for(&self, resource_uri: &str) -> Option<bool> {
        let raw = self
            .frontmatter
            .get("metadata")?
            .as_object()?
            .get(CODE_MODE_METADATA_KEY)?
            .as_str()?;
        let hint: SkillCodeModeCompatibility = serde_json::from_str(raw).ok()?;
        if hint.version != 2 {
            return None;
        }
        let root = self.uri.strip_suffix("/SKILL.md")?;
        let relative = resource_uri.strip_prefix(&format!("{root}/"))?;
        hint.scripts.get(relative).copied()
    }

    /// Human-readable interpretation shared by skill discovery and review.
    pub fn code_mode_compatibility_hint(&self, resource_uri: &str) -> &'static str {
        if resource_uri == self.uri {
            return "Not applicable (skill instructions)";
        }
        match self.code_mode_tested_for(resource_uri) {
            Some(true) => "Publisher reports tested in Code Mode; informational only",
            Some(false) => {
                "Publisher does not report successful Code Mode testing; does not restrict execution"
            }
            None => "No Code Mode test information; does not restrict execution",
        }
    }
}

#[derive(Debug, Deserialize)]
struct SkillCodeModeCompatibility {
    version: u32,
    scripts: BTreeMap<String, bool>,
}

#[derive(Debug, Clone)]
pub struct LoadedSkillResource {
    pub descriptor: SkillResourceDescriptor,
    pub bytes: Arc<[u8]>,
    pub content_digest: String,
}

/// Immutable identity of one verified skill revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillRevisionIdentity {
    pub source_origin: String,
    pub artifact_digest: String,
    pub source_tree_digest: String,
    pub skill_uri: String,
    /// Digest of the skill URI and its ordered resource descriptors. This is
    /// deliberately separate from the source revision so evidence can identify
    /// one skill inside a repository containing several skills.
    pub revision_digest: String,
}

impl SkillRevisionIdentity {
    fn new(source: &CatalogSourceIdentity, skill: &SkillEntry) -> Self {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, b"gateway-skill-revision-v1");
        hash_field(&mut hasher, source.resolved_digest.as_bytes());
        hash_field(&mut hasher, source.resolved_tree_digest.as_bytes());
        hash_field(&mut hasher, skill.uri.as_bytes());
        for resource in skill.resources.iter() {
            hash_field(&mut hasher, resource.uri.as_bytes());
            hash_field(&mut hasher, resource.source_path.as_bytes());
            hash_field(&mut hasher, resource.source_object.as_bytes());
            hash_field(&mut hasher, &resource.size.to_be_bytes());
            hash_field(&mut hasher, resource.media_type.as_bytes());
        }
        Self {
            source_origin: source.origin.clone(),
            artifact_digest: source.resolved_digest.clone(),
            source_tree_digest: source.resolved_tree_digest.clone(),
            skill_uri: skill.uri.clone(),
            revision_digest: finish_digest(hasher),
        }
    }

    /// Produce the binding used by an approval for a particular kind of use.
    pub fn approval_binding(&self, purpose: SkillApprovalPurpose) -> SkillApprovalBinding {
        SkillApprovalBinding {
            source_origin: self.source_origin.clone(),
            artifact_digest: self.artifact_digest.clone(),
            source_tree_digest: self.source_tree_digest.clone(),
            skill_uri: self.skill_uri.clone(),
            revision_digest: self.revision_digest.clone(),
            purpose,
        }
    }

    /// Preserve the source identity stored by older Code Mode executions.
    /// This digest is retry metadata only; no execution approval is consulted.
    pub fn legacy_script_execution_digest(&self) -> String {
        self.approval_binding(SkillApprovalPurpose::Activate)
            .digest_for_purpose(b"execute_scripts")
    }
}

/// Identity recorded for a specific resource access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillResourceIdentity {
    #[serde(flatten)]
    pub revision: SkillRevisionIdentity,
    pub resource_uri: String,
    pub source_path: String,
    pub source_object: String,
    /// SHA-256 of the exact bytes authorized and returned.
    pub resource_digest: String,
}

/// The distribution authority a human reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillApprovalPurpose {
    Activate,
}

/// Content-bound approval input. A source revision, skill, content, or purpose
/// change produces a different digest and therefore cannot reuse a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillApprovalBinding {
    pub source_origin: String,
    pub artifact_digest: String,
    pub source_tree_digest: String,
    pub skill_uri: String,
    pub revision_digest: String,
    pub purpose: SkillApprovalPurpose,
}

impl SkillApprovalBinding {
    pub fn digest(&self) -> String {
        self.digest_for_purpose(match self.purpose {
            SkillApprovalPurpose::Activate => b"activate",
        })
    }

    fn digest_for_purpose(&self, purpose: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, b"gateway-skill-approval-v1");
        hash_field(&mut hasher, self.source_origin.as_bytes());
        hash_field(&mut hasher, self.artifact_digest.as_bytes());
        hash_field(&mut hasher, self.source_tree_digest.as_bytes());
        hash_field(&mut hasher, self.skill_uri.as_bytes());
        hash_field(&mut hasher, self.revision_digest.as_bytes());
        hash_field(&mut hasher, purpose);
        finish_digest(hasher)
    }
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn finish_digest(hasher: Sha256) -> String {
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SkillApprovalBinding {
        SkillApprovalBinding {
            source_origin: "git+https://git.example/skills".into(),
            artifact_digest: format!("git-sha1:{}", "a".repeat(40)),
            source_tree_digest: format!("git-sha1:{}", "e".repeat(40)),
            skill_uri: "skill://catalog/demo/SKILL.md".into(),
            revision_digest: format!("sha256:{}", "b".repeat(64)),
            purpose: SkillApprovalPurpose::Activate,
        }
    }

    #[test]
    fn legacy_script_execution_digest_matches_persisted_identity() {
        let revision = SkillRevisionIdentity {
            source_origin: "git+https://git.example/team/skills".into(),
            artifact_digest: format!("git-sha1:{}", "a".repeat(40)),
            source_tree_digest: format!("git-sha1:{}", "b".repeat(40)),
            skill_uri: "skill://homelab/pr-and-monitor/SKILL.md".into(),
            revision_digest: format!("sha256:{}", "c".repeat(64)),
        };
        assert_eq!(
            revision.legacy_script_execution_digest(),
            "sha256:3da6b484a7300e2105fa54a068ce9ee38796ee8c60fd3f87edca1dd08d0e4f51"
        );
    }

    #[test]
    fn approval_binding_changes_with_every_authority_dimension() {
        let baseline = binding();
        let baseline_digest = baseline.digest();

        for changed in [
            SkillApprovalBinding {
                source_origin: "git+https://other.example/skills".into(),
                ..baseline.clone()
            },
            SkillApprovalBinding {
                artifact_digest: format!("git-sha1:{}", "c".repeat(40)),
                ..baseline.clone()
            },
            SkillApprovalBinding {
                source_tree_digest: format!("git-sha1:{}", "f".repeat(40)),
                ..baseline.clone()
            },
            SkillApprovalBinding {
                skill_uri: "skill://catalog/other/SKILL.md".into(),
                ..baseline.clone()
            },
            SkillApprovalBinding {
                revision_digest: format!("sha256:{}", "d".repeat(64)),
                ..baseline.clone()
            },
        ] {
            assert_ne!(baseline_digest, changed.digest());
        }
    }

    #[test]
    fn code_mode_test_information_is_optional_and_resource_specific() {
        let uri = "skill://homelab/demo/scripts/demo.js";
        for (raw, expected) in [
            (None, None),
            (
                Some(
                    serde_json::json!({"version": 2, "scripts": {"scripts/demo.js": true}})
                        .to_string(),
                ),
                Some(true),
            ),
            (
                Some(
                    serde_json::json!({"version": 2, "scripts": {"scripts/demo.js": false}})
                        .to_string(),
                ),
                Some(false),
            ),
            (
                Some(
                    serde_json::json!({"version": 2, "scripts": {"scripts/other.js": true}})
                        .to_string(),
                ),
                None,
            ),
            (
                Some(
                    serde_json::json!({"version": 1, "scripts": {"scripts/demo.js": "direct"}})
                        .to_string(),
                ),
                None,
            ),
            (
                Some(
                    serde_json::json!({"version": 99, "scripts": {"scripts/demo.js": true}})
                        .to_string(),
                ),
                None,
            ),
            (Some("not JSON".into()), None),
            (Some("false".into()), None),
            (Some("disabled".into()), None),
        ] {
            let mut entry = SkillEntry {
                uri: "skill://homelab/demo/SKILL.md".into(),
                frontmatter: Map::new(),
                resources: Arc::from([]),
            };
            if let Some(raw) = raw {
                entry.frontmatter.insert(
                    "metadata".into(),
                    serde_json::json!({(CODE_MODE_METADATA_KEY): raw}),
                );
            }
            assert_eq!(entry.code_mode_tested_for(uri), expected);
            assert_eq!(
                entry.code_mode_tested_for("skill://other/demo/scripts/demo.js"),
                None
            );
            assert_eq!(
                entry.code_mode_compatibility_hint(&entry.uri),
                "Not applicable (skill instructions)"
            );
        }
    }
}
