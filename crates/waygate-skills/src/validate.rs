use std::{collections::BTreeMap, fmt::Write as _, sync::Arc};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    CatalogManifest, CatalogSourceIdentity, InMemorySkillResourceLoader, SkillCatalogSnapshot,
    SkillEntry, SkillResourceDescriptor, SkillResourceLoader, CATALOG_SCHEMA_VERSION,
};

/// SEP-2640 host interoperability boundary, including the root `SKILL.md`.
pub const MAX_SKILL_RESOURCE_ENTRIES: usize = 512;
/// SEP-2640 host interoperability boundary for one skill resource set.
pub const MAX_SKILL_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CatalogValidationError {
    #[error("unsupported catalog schema version {0}")]
    UnsupportedSchema(u32),
    #[error("catalog source {field} is empty")]
    EmptySourceIdentity { field: &'static str },
    #[error("catalog resolved revision is not a supported immutable digest")]
    InvalidResolvedDigest,
    #[error("skill URI is invalid: {0}")]
    InvalidSkillUri(String),
    #[error("skill name is invalid: {0}")]
    InvalidSkillName(String),
    #[error("skill frontmatter is missing string field {0}")]
    MissingFrontmatter(&'static str),
    #[error("skill description must contain 1 to 1024 characters")]
    InvalidDescription,
    #[error("skill URI name does not match frontmatter name")]
    SkillNameMismatch,
    #[error("skill has no resources: {0}")]
    EmptyResources(String),
    #[error("skill resources do not include its SKILL.md: {0}")]
    MissingSkillMarkdown(String),
    #[error("skill exceeds SEP-2640 resource-entry limit: {0}")]
    TooManySkillResources(String),
    #[error("skill exceeds SEP-2640 total-byte limit: {0}")]
    SkillTooLarge(String),
    #[error("resource URI is outside its skill: {0}")]
    ResourceOutsideSkill(String),
    #[error("resource URI is invalid: {0}")]
    InvalidResourceUri(String),
    #[error("duplicate resource URI: {0}")]
    DuplicateResource(String),
    #[error("resource content is missing: {0}")]
    MissingResource(String),
    #[error("source supplied undeclared resource content: {0}")]
    UndeclaredResource(String),
    #[error("resource size does not match its descriptor: {0}")]
    SizeMismatch(String),
    #[error("resource source path is invalid: {0}")]
    InvalidResourceSourcePath(String),
    #[error("resource source object is not a supported immutable digest: {0}")]
    InvalidResourceSourceObject(String),
    #[error("resource source object does not match its bytes: {0}")]
    SourceObjectMismatch(String),
    #[error("resource media type is not a canonical type/subtype value: {0}")]
    InvalidResourceMediaType(String),
    #[error("SKILL.md is not UTF-8: {0}")]
    SkillMarkdownNotUtf8(String),
    #[error("SKILL.md has no leading YAML frontmatter: {0}")]
    MissingYamlFrontmatter(String),
    #[error("SKILL.md frontmatter is invalid: {0}")]
    InvalidYamlFrontmatter(String),
    #[error("catalog frontmatter differs from SKILL.md: {0}")]
    FrontmatterMismatch(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SkillFrontmatterError {
    #[error("SKILL.md is not UTF-8")]
    NotUtf8,
    #[error("SKILL.md has no leading YAML frontmatter")]
    MissingYamlFrontmatter,
    #[error("SKILL.md frontmatter is invalid")]
    InvalidYamlFrontmatter,
}

/// Verify an immutable catalog index and the `SKILL.md` files needed for
/// discovery, without loading the remaining skill resources.
pub fn verify_catalog_snapshot(
    source: CatalogSourceIdentity,
    manifest: CatalogManifest,
    mut skill_markdown_by_uri: BTreeMap<String, Vec<u8>>,
    loader: Arc<dyn SkillResourceLoader>,
) -> Result<SkillCatalogSnapshot, CatalogValidationError> {
    validate_source_identity(&source)?;
    if manifest.schema_version != CATALOG_SCHEMA_VERSION {
        return Err(CatalogValidationError::UnsupportedSchema(
            manifest.schema_version,
        ));
    }

    let mut entries = Vec::with_capacity(manifest.skills.len());
    let mut resources = BTreeMap::new();
    let mut known_content_digests = BTreeMap::new();
    for skill in manifest.skills {
        let skill_root = validate_skill_uri(&skill.uri, &skill.frontmatter)?;
        if skill.resources.is_empty() {
            return Err(CatalogValidationError::EmptyResources(skill.uri));
        }
        if !skill
            .resources
            .iter()
            .any(|resource| resource.uri == skill.uri)
        {
            return Err(CatalogValidationError::MissingSkillMarkdown(skill.uri));
        }
        if skill.resources.len() > MAX_SKILL_RESOURCE_ENTRIES {
            return Err(CatalogValidationError::TooManySkillResources(skill.uri));
        }
        let total_bytes = skill
            .resources
            .iter()
            .try_fold(0_u64, |total, resource| total.checked_add(resource.size))
            .ok_or_else(|| CatalogValidationError::SkillTooLarge(skill.uri.clone()))?;
        if total_bytes > MAX_SKILL_TOTAL_BYTES {
            return Err(CatalogValidationError::SkillTooLarge(skill.uri));
        }

        for descriptor in &skill.resources {
            validate_resource_uri(&descriptor.uri, &skill_root)?;
            validate_resource_descriptor(descriptor)?;
            if resources.contains_key(&descriptor.uri) {
                return Err(CatalogValidationError::DuplicateResource(
                    descriptor.uri.clone(),
                ));
            }
            resources.insert(descriptor.uri.clone(), descriptor.clone());
        }

        let skill_md = skill_markdown_by_uri
            .remove(&skill.uri)
            .ok_or_else(|| CatalogValidationError::MissingResource(skill.uri.clone()))?;
        let descriptor = resources
            .get(&skill.uri)
            .expect("SKILL.md presence checked above");
        validate_resource_bytes(descriptor, &skill_md)?;
        validate_frontmatter(&skill.uri, &skill.frontmatter, &skill_md)?;
        known_content_digests.insert(skill.uri.clone(), sha256_digest(&skill_md));
        entries.push(SkillEntry {
            uri: skill.uri,
            frontmatter: skill.frontmatter,
            resources: skill.resources.into(),
        });
    }

    if let Some((uri, _)) = skill_markdown_by_uri.into_iter().next() {
        return Err(CatalogValidationError::UndeclaredResource(uri));
    }
    entries.sort_by(|left, right| left.uri.cmp(&right.uri));
    Ok(SkillCatalogSnapshot::new(
        source,
        entries,
        resources,
        known_content_digests,
        loader,
    ))
}

/// Build a catalog backed by already-available bytes. This is useful for
/// tests and embedded sources; network sources should use
/// [`verify_catalog_snapshot`] so non-root resources remain lazy.
pub fn verify_in_memory_catalog(
    source: CatalogSourceIdentity,
    manifest: CatalogManifest,
    content_by_uri: BTreeMap<String, Vec<u8>>,
) -> Result<SkillCatalogSnapshot, CatalogValidationError> {
    let mut skill_markdown_by_uri = BTreeMap::new();
    for skill in &manifest.skills {
        let bytes = content_by_uri
            .get(&skill.uri)
            .ok_or_else(|| CatalogValidationError::MissingResource(skill.uri.clone()))?;
        skill_markdown_by_uri.insert(skill.uri.clone(), bytes.clone());
    }
    let declared = manifest
        .skills
        .iter()
        .flat_map(|skill| skill.resources.iter())
        .map(|resource| resource.uri.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(uri) = content_by_uri
        .keys()
        .find(|uri| !declared.contains(uri.as_str()))
    {
        return Err(CatalogValidationError::UndeclaredResource(uri.clone()));
    }
    let loader = Arc::new(InMemorySkillResourceLoader::new(content_by_uri.clone()));
    let snapshot =
        verify_catalog_snapshot(source, manifest.clone(), skill_markdown_by_uri, loader)?;
    for skill in &manifest.skills {
        for descriptor in &skill.resources {
            let bytes = content_by_uri
                .get(&descriptor.uri)
                .ok_or_else(|| CatalogValidationError::MissingResource(descriptor.uri.clone()))?;
            validate_resource_bytes(descriptor, bytes)?;
        }
    }
    Ok(snapshot)
}

fn validate_source_identity(source: &CatalogSourceIdentity) -> Result<(), CatalogValidationError> {
    for (field, value) in [
        ("origin", source.origin.as_str()),
        ("reference", source.reference.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(CatalogValidationError::EmptySourceIdentity { field });
        }
    }
    if !valid_immutable_digest(&source.resolved_digest) {
        return Err(CatalogValidationError::InvalidResolvedDigest);
    }
    if !valid_immutable_digest(&source.resolved_tree_digest) {
        return Err(CatalogValidationError::InvalidResolvedDigest);
    }
    Ok(())
}

fn validate_skill_uri(
    uri: &str,
    frontmatter: &Map<String, Value>,
) -> Result<String, CatalogValidationError> {
    validate_uri_shape(uri).map_err(|_| CatalogValidationError::InvalidSkillUri(uri.into()))?;
    let root = uri
        .strip_suffix("/SKILL.md")
        .ok_or_else(|| CatalogValidationError::InvalidSkillUri(uri.into()))?;
    let uri_name = root
        .rsplit('/')
        .next()
        .ok_or_else(|| CatalogValidationError::InvalidSkillUri(uri.into()))?;
    let name = frontmatter
        .get("name")
        .and_then(Value::as_str)
        .ok_or(CatalogValidationError::MissingFrontmatter("name"))?;
    if !valid_skill_name(name) {
        return Err(CatalogValidationError::InvalidSkillName(name.into()));
    }
    let description = frontmatter
        .get("description")
        .and_then(Value::as_str)
        .ok_or(CatalogValidationError::MissingFrontmatter("description"))?;
    if !(1..=1024).contains(&description.chars().count()) {
        return Err(CatalogValidationError::InvalidDescription);
    }
    if uri_name != name {
        return Err(CatalogValidationError::SkillNameMismatch);
    }
    Ok(root.to_owned())
}

fn validate_resource_uri(uri: &str, skill_root: &str) -> Result<(), CatalogValidationError> {
    validate_uri_shape(uri).map_err(|_| CatalogValidationError::InvalidResourceUri(uri.into()))?;
    let prefix = format!("{skill_root}/");
    if !uri.starts_with(&prefix) {
        return Err(CatalogValidationError::ResourceOutsideSkill(uri.into()));
    }
    Ok(())
}

fn validate_uri_shape(uri: &str) -> Result<(), ()> {
    if uri.contains('%') || uri.contains('\\') || uri.chars().any(char::is_control) {
        return Err(());
    }
    let raw = uri.strip_prefix("skill://").ok_or(())?;
    if raw
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(());
    }
    let parsed = Url::parse(uri).map_err(|_| ())?;
    let host = parsed.host_str().ok_or(())?;
    if parsed.scheme() != "skill"
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != uri
    {
        return Err(());
    }
    parsed.path_segments().ok_or(())?;
    Ok(())
}

pub fn valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_resource_descriptor(
    descriptor: &SkillResourceDescriptor,
) -> Result<(), CatalogValidationError> {
    if descriptor.source_path.is_empty()
        || descriptor.source_path.starts_with('/')
        || descriptor.source_path.contains('\\')
        || descriptor.source_path.chars().any(char::is_control)
        || descriptor
            .source_path
            .split('/')
            .any(invalid_source_segment)
    {
        return Err(CatalogValidationError::InvalidResourceSourcePath(
            descriptor.uri.clone(),
        ));
    }
    if !valid_media_type(&descriptor.media_type) {
        return Err(CatalogValidationError::InvalidResourceMediaType(
            descriptor.uri.clone(),
        ));
    }
    if !valid_immutable_digest(&descriptor.source_object) {
        return Err(CatalogValidationError::InvalidResourceSourceObject(
            descriptor.uri.clone(),
        ));
    }
    Ok(())
}

fn validate_resource_bytes(
    descriptor: &SkillResourceDescriptor,
    bytes: &[u8],
) -> Result<(), CatalogValidationError> {
    validate_resource_descriptor(descriptor)?;
    if descriptor.size != bytes.len() as u64 {
        return Err(CatalogValidationError::SizeMismatch(descriptor.uri.clone()));
    }
    if valid_sha256_digest(&descriptor.source_object)
        && descriptor.source_object != sha256_digest(bytes)
    {
        return Err(CatalogValidationError::SourceObjectMismatch(
            descriptor.uri.clone(),
        ));
    }
    Ok(())
}

fn invalid_source_segment(segment: &str) -> bool {
    segment.is_empty() || segment == "." || segment == ".."
}

fn valid_media_type(value: &str) -> bool {
    let Some((type_name, subtype_name)) = value.split_once('/') else {
        return false;
    };
    !subtype_name.contains('/')
        && valid_media_type_name(type_name)
        && valid_media_type_name(subtype_name)
}

fn valid_media_type_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 127
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
                )
        })
}

fn validate_frontmatter(
    uri: &str,
    expected: &Map<String, Value>,
    bytes: &[u8],
) -> Result<(), CatalogValidationError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CatalogValidationError::SkillMarkdownNotUtf8(uri.into()))?;
    let rest = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
        .ok_or_else(|| CatalogValidationError::MissingYamlFrontmatter(uri.into()))?;
    let yaml = rest
        .split_once("\n---\n")
        .or_else(|| rest.split_once("\r\n---\r\n"))
        .map(|(yaml, _)| yaml)
        .ok_or_else(|| CatalogValidationError::MissingYamlFrontmatter(uri.into()))?;
    let parsed: Value = serde_yaml::from_str(yaml)
        .map_err(|_| CatalogValidationError::InvalidYamlFrontmatter(uri.into()))?;
    let actual = parsed
        .as_object()
        .ok_or_else(|| CatalogValidationError::InvalidYamlFrontmatter(uri.into()))?;
    if actual != expected {
        return Err(CatalogValidationError::FrontmatterMismatch(uri.into()));
    }
    Ok(())
}

/// Parse the portable YAML frontmatter at the start of a `SKILL.md` file.
pub fn parse_skill_frontmatter(bytes: &[u8]) -> Result<Map<String, Value>, SkillFrontmatterError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SkillFrontmatterError::NotUtf8)?;
    let rest = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
        .ok_or(SkillFrontmatterError::MissingYamlFrontmatter)?;
    let yaml = rest
        .split_once("\n---\n")
        .or_else(|| rest.split_once("\r\n---\r\n"))
        .map(|(yaml, _)| yaml)
        .ok_or(SkillFrontmatterError::MissingYamlFrontmatter)?;
    let parsed: Value =
        serde_yaml::from_str(yaml).map_err(|_| SkillFrontmatterError::InvalidYamlFrontmatter)?;
    parsed
        .as_object()
        .cloned()
        .ok_or(SkillFrontmatterError::InvalidYamlFrontmatter)
}

pub(crate) fn valid_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_immutable_digest(value: &str) -> bool {
    valid_sha256_digest(value)
        || valid_hex_digest(value, "git-sha1:", 40)
        || valid_hex_digest(value, "git-sha256:", 64)
}

fn valid_hex_digest(value: &str, prefix: &str, length: usize) -> bool {
    let Some(hex) = value.strip_prefix(prefix) else {
        return false;
    };
    hex.len() == length
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CatalogSkill, CATALOG_SCHEMA_VERSION};

    fn fixture() -> (
        CatalogSourceIdentity,
        CatalogManifest,
        BTreeMap<String, Vec<u8>>,
    ) {
        let skill_md = b"---\nname: pr-review\ndescription: Review a pull request\nmetadata:\n  version: 1.0.0\n---\n# Review\n";
        let script = b"return { ok: true };\n";
        let root_uri = "skill://homelab/pr-review/SKILL.md".to_owned();
        let script_uri = "skill://homelab/pr-review/scripts/review.js".to_owned();
        let frontmatter = serde_json::from_value(serde_json::json!({
            "name": "pr-review",
            "description": "Review a pull request",
            "metadata": {"version": "1.0.0"}
        }))
        .expect("object");
        let resources = vec![
            SkillResourceDescriptor {
                uri: root_uri.clone(),
                source_path: "pr-review/SKILL.md".into(),
                source_object: sha256_digest(skill_md),
                size: skill_md.len() as u64,
                media_type: "text/markdown".into(),
            },
            SkillResourceDescriptor {
                uri: script_uri.clone(),
                source_path: "pr-review/scripts/review.js".into(),
                source_object: sha256_digest(script),
                size: script.len() as u64,
                media_type: "application/javascript".into(),
            },
        ];
        (
            CatalogSourceIdentity {
                origin: "git+https://git.example/team/skills".into(),
                reference: "main".into(),
                resolved_digest: format!("git-sha1:{}", "a".repeat(40)),
                resolved_tree_digest: format!("git-sha1:{}", "b".repeat(40)),
            },
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills: vec![CatalogSkill {
                    uri: root_uri.clone(),
                    frontmatter,
                    resources,
                }],
            },
            BTreeMap::from([(root_uri, skill_md.to_vec()), (script_uri, script.to_vec())]),
        )
    }

    #[test]
    fn verifies_complete_script_bearing_skill() {
        let (source, manifest, content) = fixture();
        let snapshot = verify_in_memory_catalog(source, manifest, content).expect("valid");

        assert_eq!(snapshot.skills().len(), 1);
        assert!(snapshot
            .resource("skill://homelab/pr-review/scripts/review.js")
            .is_some());
    }

    #[test]
    fn refuses_content_digest_drift() {
        let (source, manifest, mut content) = fixture();
        content
            .get_mut("skill://homelab/pr-review/scripts/review.js")
            .expect("script fixture")[0] = b'R';

        assert_eq!(
            verify_in_memory_catalog(source, manifest, content)
                .expect_err("equal-length content drift must fail digest verification"),
            CatalogValidationError::SourceObjectMismatch(
                "skill://homelab/pr-review/scripts/review.js".into()
            )
        );
    }

    #[tokio::test]
    async fn accepts_crlf_frontmatter_and_preserves_its_bytes() {
        let (source, mut manifest, mut content) = fixture();
        let uri = manifest.skills[0].uri.clone();
        let skill_md =
            b"---\r\nname: pr-review\r\ndescription: Review a pull request\r\nmetadata:\r\n  version: 1.0.0\r\n---\r\n# Review\r\n";
        let descriptor = manifest.skills[0]
            .resources
            .iter_mut()
            .find(|resource| resource.uri == uri)
            .expect("SKILL.md descriptor");
        descriptor.size = skill_md.len() as u64;
        descriptor.source_object = sha256_digest(skill_md);
        content.insert(uri.clone(), skill_md.to_vec());

        let snapshot =
            verify_in_memory_catalog(source, manifest, content).expect("valid CRLF skill");

        assert_eq!(
            snapshot
                .load_resource(&uri)
                .await
                .expect("resource load")
                .expect("SKILL.md resource")
                .bytes
                .as_ref(),
            skill_md
        );
    }

    #[test]
    fn refuses_frontmatter_that_differs_from_skill_markdown() {
        let (source, mut manifest, content) = fixture();
        manifest.skills[0].frontmatter.insert(
            "description".into(),
            Value::String("Different description".into()),
        );

        assert!(matches!(
            verify_in_memory_catalog(source, manifest, content),
            Err(CatalogValidationError::FrontmatterMismatch(_))
        ));
    }

    #[test]
    fn refuses_path_aliases_and_traversal() {
        for uri in [
            "skill://homelab/pr-review/scripts/%2e%2e/SKILL.md",
            "skill://homelab/pr-review/scripts/../SKILL.md",
            "skill://homelab/pr-review/scripts\\review.js",
            "skill://HOMELAB/pr-review/SKILL.md",
        ] {
            assert!(validate_uri_shape(uri).is_err(), "accepted {uri}");
        }
    }

    #[test]
    fn refuses_description_outside_the_specification_range() {
        for description in [String::new(), "a".repeat(1025)] {
            let (source, mut manifest, content) = fixture();
            manifest.skills[0]
                .frontmatter
                .insert("description".into(), Value::String(description));

            assert_eq!(
                verify_in_memory_catalog(source, manifest, content)
                    .expect_err("description must be bounded"),
                CatalogValidationError::InvalidDescription
            );
        }
    }

    #[test]
    fn accepts_the_sep_resource_entry_boundary_and_refuses_the_next_entry() {
        let (source, mut manifest, mut content) = fixture();
        let root = "skill://homelab/pr-review";
        let empty_digest = sha256_digest(&[]);
        while manifest.skills[0].resources.len() < MAX_SKILL_RESOURCE_ENTRIES {
            let index = manifest.skills[0].resources.len();
            let uri = format!("{root}/assets/{index}.txt");
            manifest.skills[0].resources.push(SkillResourceDescriptor {
                uri: uri.clone(),
                source_path: format!("pr-review/assets/{index}.txt"),
                source_object: empty_digest.clone(),
                size: 0,
                media_type: "text/plain".into(),
            });
            content.insert(uri, Vec::new());
        }
        let accepted = verify_in_memory_catalog(source.clone(), manifest.clone(), content.clone())
            .expect("SEP-2640 boundary is supported");
        assert_eq!(
            accepted.skills()[0].resources.len(),
            MAX_SKILL_RESOURCE_ENTRIES
        );

        let uri = format!("{root}/assets/overflow.txt");
        manifest.skills[0].resources.push(SkillResourceDescriptor {
            uri,
            source_path: "pr-review/assets/overflow.txt".into(),
            source_object: empty_digest,
            size: 0,
            media_type: "text/plain".into(),
        });
        assert!(matches!(
            verify_in_memory_catalog(source, manifest, content),
            Err(CatalogValidationError::TooManySkillResources(_))
        ));
    }

    #[test]
    fn accepts_the_sep_total_byte_boundary() {
        let (source, mut manifest, _) = fixture();
        let uri = manifest.skills[0].uri.clone();
        let mut skill_md =
            b"---\nname: pr-review\ndescription: Review a pull request\nmetadata:\n  version: 1.0.0\n---\n# Review\n"
                .to_vec();
        skill_md.resize(MAX_SKILL_TOTAL_BYTES as usize, 120);
        manifest.skills[0].resources = vec![SkillResourceDescriptor {
            uri: uri.clone(),
            source_path: "pr-review/SKILL.md".into(),
            source_object: sha256_digest(&skill_md),
            size: MAX_SKILL_TOTAL_BYTES,
            media_type: "text/markdown".into(),
        }];

        let snapshot =
            verify_in_memory_catalog(source, manifest, BTreeMap::from([(uri, skill_md)]))
                .expect("SEP-2640 byte boundary is supported");
        assert_eq!(
            snapshot.skills()[0].resources[0].size,
            MAX_SKILL_TOTAL_BYTES
        );
    }

    #[test]
    fn refuses_a_skill_above_the_sep_total_byte_boundary() {
        let (source, mut manifest, content) = fixture();
        manifest.skills[0].resources[0].size = MAX_SKILL_TOTAL_BYTES + 1;

        assert!(matches!(
            verify_in_memory_catalog(source, manifest, content),
            Err(CatalogValidationError::SkillTooLarge(_))
        ));
    }

    #[test]
    fn refuses_noncanonical_or_malformed_resource_media_types() {
        for media_type in ["", "text", "Text/Markdown", "text/markdown; charset=utf-8"] {
            let (source, mut manifest, content) = fixture();
            manifest.skills[0].resources[0].media_type = media_type.into();

            assert!(matches!(
                verify_in_memory_catalog(source, manifest, content),
                Err(CatalogValidationError::InvalidResourceMediaType(_))
            ));
        }
    }

    #[test]
    fn refuses_undeclared_source_content() {
        let (source, manifest, mut content) = fixture();
        content.insert("skill://homelab/pr-review/hidden.txt".into(), vec![]);

        assert!(matches!(
            verify_in_memory_catalog(source, manifest, content),
            Err(CatalogValidationError::UndeclaredResource(_))
        ));
    }
}
