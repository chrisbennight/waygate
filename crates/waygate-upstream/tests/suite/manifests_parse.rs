//! Parse the fixture `servers/*.yaml` manifests under `tests/fixtures/servers/`.
//! The gateway repo no longer ships a real served set; deployments supply their
//! own through the shared runtime volume. These fixtures keep the
//! manifest loader + schema covered: a YAML typo or schema drift in
//! `load_manifests`/`UpstreamManifest` still fails here before it could blow up
//! at startup.

use std::path::PathBuf;

use waygate_upstream::{load_manifests, UpstreamManifest};

fn fixtures_servers_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/servers")
}

#[test]
fn fixture_servers_parse_cleanly() {
    let dir = fixtures_servers_dir();
    assert!(
        dir.exists(),
        "fixture servers dir missing at {}",
        dir.display()
    );
    let manifests = load_manifests(&dir).expect("load_manifests");

    // Keeps this file honest: the fixtures must load *something*, or the schema
    // coverage here is vacuous.
    assert!(
        !manifests.is_empty(),
        "no manifests found under {}",
        dir.display()
    );

    // Every manifest must classify at least one tool; "unclassified" is fine for
    // unknown tools (falls back to Low) but an empty tool list on a known server
    // is almost always a mistake.
    for (name, m) in &manifests {
        assert!(
            !m.tools.is_empty(),
            "{name} has no tool classifications — add at least one entry",
        );
    }
}

/// Round-trip a manifest with `auth.bearer_env` to pin down the YAML shape
/// operators have to write. Catches accidental rename of the `auth:` key or
/// the `bearer_env` field, which would silently degrade a public-internet
/// upstream to unauthenticated.
#[test]
fn manifest_with_bearer_env_auth_parses() {
    let yaml = r#"
name: example
transport: http
url: https://example.test/mcp
auth:
  bearer_env: EXAMPLE_BEARER
tools:
  - name: ping
    risk: low
"#;
    let m: UpstreamManifest = serde_yaml::from_str(yaml).expect("parse");
    let auth = m.auth.expect("auth block present");
    assert_eq!(auth.bearer_env.as_deref(), Some("EXAMPLE_BEARER"));
}

/// Non-regression: the existing manifests have no `auth:` key. Deserializing
/// such a YAML must yield `auth: None` rather than a parse error — otherwise
/// the eleven shipped manifests would fail to load at boot.
#[test]
fn manifest_without_auth_field_defaults_to_none() {
    let yaml = r#"
name: example
transport: http
url: http://example.test/mcp
tools:
  - name: ping
    risk: low
"#;
    let m: UpstreamManifest = serde_yaml::from_str(yaml).expect("parse");
    assert!(m.auth.is_none(), "missing `auth:` must deserialize to None");
}
