//! The `cimd/mcp-test-client.json` template contains the metadata required by
//! this client. A publisher replaces its example client_id with the real
//! document URL before hosting it.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CimdDoc {
    client_id: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    #[allow(dead_code)]
    client_name: Option<String>,
}

fn path() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/waygate-test-client during `cargo test`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("cimd")
        .join("mcp-test-client.json")
        .canonicalize()
        .expect("canonicalize cimd doc path")
}

#[test]
fn doc_parses() {
    let raw = std::fs::read(path()).expect("read cimd doc");
    let _: CimdDoc = serde_json::from_slice(&raw).expect("parse cimd doc");
}

#[test]
fn doc_has_required_fields() {
    let raw = std::fs::read(path()).unwrap();
    let doc: CimdDoc = serde_json::from_slice(&raw).unwrap();
    assert!(
        doc.client_id.starts_with("https://"),
        "client_id must be https, got {}",
        doc.client_id
    );
    assert!(
        !doc.redirect_uris.is_empty(),
        "redirect_uris must be non-empty"
    );
    // Two bare-loopback patterns mirror Claude Code's CIMD and let the
    // gateway's match_redirect_uri accept any ephemeral port.
    let has_127 = doc
        .redirect_uris
        .iter()
        .any(|u| u == "http://127.0.0.1/callback");
    let has_localhost = doc
        .redirect_uris
        .iter()
        .any(|u| u == "http://localhost/callback");
    assert!(
        has_127 && has_localhost,
        "redirect_uris must include bare-loopback 127.0.0.1 and localhost patterns"
    );
    assert_eq!(
        doc.token_endpoint_auth_method, "none",
        "CIMD clients must use `none` auth method"
    );
    assert!(
        doc.grant_types.iter().any(|g| g == "authorization_code"),
        "grant_types must include authorization_code"
    );
    assert!(
        doc.response_types.iter().any(|r| r == "code"),
        "response_types must include `code`"
    );
}
