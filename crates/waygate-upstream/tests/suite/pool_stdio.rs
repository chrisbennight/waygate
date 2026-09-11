//! Dial-level coverage for `Transport::Stdio`.
//!
//! These tests don't stand up a full rmcp-speaking subprocess — they pin down
//! the contract documented in `pool/mod.rs`: a failed dial (whether the binary
//! is missing or the child exits without speaking MCP) leaves the entry in
//! the pool as `Disconnected` and never panics or takes the pool down.

use std::collections::BTreeMap;
use std::time::Duration;

use waygate_mcp::catalog::UpstreamCatalog;
use waygate_upstream::{UpstreamManifest, UpstreamPool};

fn stdio_manifest(name: &str, command: Vec<String>) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: name.to_owned(),
        transport: waygate_upstream::Transport::Stdio,
        protocol: Default::default(),
        url: None,
        command: Some(command),
        tools: Vec::new(),
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: None,
    }
}

/// Wrap `UpstreamPool::connect` in a safety-net timeout so a hang in the
/// subprocess code path surfaces as a test failure instead of a stuck CI
/// run. rmcp's `info.serve(...).await` has no client-side timeout on the
/// initialize handshake; if that ever changes this guard becomes a tighter
/// assertion.
async fn connect_with_timeout(manifests: BTreeMap<String, UpstreamManifest>) -> UpstreamPool {
    tokio::time::timeout(Duration::from_secs(10), UpstreamPool::connect(manifests))
        .await
        .expect("UpstreamPool::connect hung on a stdio upstream")
}

#[tokio::test]
async fn stdio_nonexistent_binary_leaves_entry_disconnected() {
    // ENOENT during spawn: the pool logs a warn and records the entry as
    // disconnected. No connection is ever established, but the pool keeps
    // serving other upstreams.
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "missing".into(),
        stdio_manifest(
            "missing",
            vec!["/nonexistent/mcp-server-xyz-abc-123".into()],
        ),
    );

    let pool = connect_with_timeout(manifests).await;

    assert!(!pool.is_connected("missing").await);
    let health = pool.health_snapshot().await;
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].name, "missing");
    assert!(!health[0].connected);
    assert_eq!(health[0].connected_lanes, 0);
    assert_eq!(health[0].total_lanes, 1);
    assert_eq!(health[0].published_tool_count, 0);
    assert_eq!(health[0].quarantined_tool_count, 0);
    assert_eq!(health[0].breaker.as_str(), "closed");

    // The upstream still appears in the catalog — `list_tools` just returns
    // an empty vec until someone fixes the manifest and restarts.
    let tools = pool
        .list_tools("missing")
        .await
        .expect("listed server should be known to the catalog");
    assert!(tools.is_empty());
}

#[tokio::test]
async fn stdio_child_that_exits_immediately_leaves_entry_disconnected() {
    // /bin/true exits 0 with no output. rmcp's initialize handshake will
    // fail (EOF on stdout) and dial returns DialError::Init. Pool stays
    // alive; the entry is disconnected.
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "quick-exit".into(),
        stdio_manifest("quick-exit", vec!["/bin/true".into()]),
    );

    let pool = connect_with_timeout(manifests).await;

    assert!(!pool.is_connected("quick-exit").await);
    let snapshot = pool.health_snapshot().await;
    assert_eq!(snapshot.len(), 1);
    assert!(!snapshot[0].connected);
}

#[tokio::test]
async fn stdio_missing_command_leaves_entry_disconnected() {
    // A stdio manifest that forgot to set `command:` must fail dial with
    // MissingCommand — don't panic, don't hang, stay disconnected.
    let mut manifests = BTreeMap::new();
    let mut m = stdio_manifest("no-cmd", vec!["unused".into()]);
    m.command = None;
    manifests.insert("no-cmd".into(), m);

    let pool = connect_with_timeout(manifests).await;
    assert!(!pool.is_connected("no-cmd").await);
}
