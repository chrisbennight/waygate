//! Pin the contract the `dump-openapi`
//! binary and `scripts/gen-clients.sh` depend on.
//!
//! The binary itself is a 5-line wrapper around
//! `ApiDoc::openapi()` → `serde_json::to_string_pretty`,
//! so this test exercises the same call sites directly
//! (and stays in-process). A regression here means the
//! whole client-SDK codegen pipeline breaks; failing
//! loud at `cargo test` is much cheaper than chasing a
//! release-time `openapi-generator-cli: invalid spec`.

use serde_json::Value;
use utoipa::OpenApi;

use waygate_admin::ApiDoc;

#[test]
fn openapi_spec_serializes_to_pretty_json() {
    let spec = ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&spec).expect("ApiDoc::openapi() must serialize");
    assert!(
        json.starts_with("{\n  "),
        "must be pretty-printed (gen-clients.sh writes it to disk so reviewers diff it)"
    );
    // A regression that drops `paths` or `components`
    // would let codegen "succeed" but produce empty
    // clients — pin both keys.
    let value: Value = serde_json::from_str(&json).expect("must round-trip");
    assert!(
        value.get("openapi").is_some(),
        "missing top-level `openapi` version"
    );
    assert!(value.get("paths").is_some(), "missing top-level `paths`");
    assert!(
        value.get("components").is_some(),
        "missing top-level `components`"
    );
}

#[test]
fn openapi_spec_advertises_expected_admin_paths() {
    // The codegen pipeline produces clients keyed off these
    // paths. A typo or accidental rename here would silently
    // ship a broken SDK; pin the load-bearing surfaces.
    let spec = ApiDoc::openapi();
    let json = serde_json::to_value(&spec).expect("serializable");
    let paths = json
        .get("paths")
        .and_then(Value::as_object)
        .expect("paths object");

    for expected in [
        "/api/v1/admin/oauth_consent",
        "/api/v1/admin/break_glass",
        "/api/v1/admin/upstream_sessions",
        "/api/v1/admin/rbac/roles",
        "/api/v1/admin/tenants",
        "/api/v1/admin/rate_limit_policies",
        "/api/v1/admin/api_key_profiles",
    ] {
        assert!(
            paths.contains_key(expected),
            "OpenAPI spec must include `{expected}` so the generated SDK exposes it; \
             a rename / drop here is a load-bearing contract change",
        );
    }
}
