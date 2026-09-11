//! Exercises `UpstreamPool::tool_facts` without standing up a live MCP
//! upstream. The disconnected constructor lets us seed just the manifest
//! side of the pool — enough to prove classification lookup routes through
//! `manifest.tools` and falls back to Low for anything unclassified.

use std::collections::BTreeMap;

use waygate_mcp::catalog::UpstreamCatalog;
use waygate_mcp::protocol::RiskTier;
use waygate_upstream::{ToolClassification, Transport, UpstreamManifest, UpstreamPool};

fn manifest() -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: "example-messages".into(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some("http://unused.test/mcp".into()),
        command: None,
        tools: vec![
            ToolClassification::new("list_contacts", RiskTier::Low, false, false),
            ToolClassification::new("send_message", RiskTier::High, true, true),
        ],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: None,
    }
}

fn pool() -> UpstreamPool {
    let mut map = BTreeMap::new();
    map.insert("example-messages".into(), manifest());
    UpstreamPool::from_manifests_disconnected(map)
}

#[tokio::test]
async fn classified_tool_returns_manifest_risk() {
    let p = pool();
    let facts = p.tool_facts("example-messages", "send_message");
    assert_eq!(facts.risk, RiskTier::High);
    assert!(facts.side_effects);
    assert_eq!(facts.server, "example-messages");
    assert_eq!(facts.name, "send_message");
}

#[tokio::test]
async fn unclassified_tool_falls_back_to_low_no_side_effects() {
    // Operators onboard new upstream tools before remembering to classify
    // them; the default must be *safe* in the sense that it falls through
    // to the conservative permit rule (low-risk only), not opened-up.
    let p = pool();
    let facts = p.tool_facts("example-messages", "new_unclassified_tool");
    assert_eq!(facts.risk, RiskTier::Low);
    assert!(!facts.side_effects);
}

#[tokio::test]
async fn unknown_server_returns_low_default() {
    let p = pool();
    let facts = p.tool_facts("no-such-server", "whatever");
    assert_eq!(facts.risk, RiskTier::Low);
    assert!(!facts.side_effects);
}

/// An unclassified tool name must
/// not reach the upstream even if a client crafts an explicit `call_tool`
/// for it. Live unclassified tools are filtered out of the search index
/// and `Connection.tools` at publish time, but a hardcoded by-name call
/// would otherwise still hit the rmcp client and run against the catalog
/// default (Low / no-side-effects). The pool rejects with `invalid_params`
/// before the breaker is touched, so a flood of typo'd calls can't drain
/// the failure budget on a healthy upstream either.
#[tokio::test]
async fn call_tool_rejects_unclassified_tool_name_without_touching_breaker() {
    let p = pool();
    let err = p
        .call_tool(
            "example-messages",
            "definitely_not_classified",
            None,
            None,
            None,
        )
        .await
        .expect_err("unclassified tool must not be callable");
    assert!(
        err.message.contains("no admitted tool"),
        "expected classification rejection, got: {}",
        err.message
    );
    // Sanity: a known classification name still passes the gate. The
    // disconnected pool has no live `Connection`, so the call falls through
    // to the not-connected path — but that proves the classification check
    // accepted the name rather than rejecting it.
    let err = p
        .call_tool("example-messages", "send_message", None, None, None)
        .await
        .expect_err("disconnected pool always errors on call_tool");
    assert!(
        err.message.contains("is not connected"),
        "classified call should reach the connection check, got: {}",
        err.message
    );
}
