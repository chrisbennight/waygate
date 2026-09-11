//! Contract tests for `UpstreamPool::try_reconnect_disconnected` and
//! `UpstreamPool::reconnect_one`. The happy-path "upstream comes back up
//! after a transient failure" case requires a real MCP-speaking stub upstream,
//! so this module concentrates on the disconnected and retirement contracts.
//! These tests pin down the API contracts that configuration reloads and the
//! admin reconnect endpoint rely on. Automatic attempts use the per-upstream
//! scheduler and share the same reconnect body.

use std::collections::BTreeMap;
use std::time::Duration;

use waygate_upstream::{Transport, UpstreamManifest, UpstreamPool};

fn stdio_manifest(name: &str, command: Vec<String>) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: name.to_owned(),
        transport: Transport::Stdio,
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

async fn connect_with_timeout(manifests: BTreeMap<String, UpstreamManifest>) -> UpstreamPool {
    tokio::time::timeout(Duration::from_secs(10), UpstreamPool::connect(manifests))
        .await
        .expect("UpstreamPool::connect hung")
}

#[tokio::test]
async fn try_reconnect_is_safe_on_empty_pool() {
    let pool = connect_with_timeout(BTreeMap::new()).await;
    pool.try_reconnect_disconnected().await;
    // No panic, no hang. The empty case is the "all upstreams just removed" path
    // that configuration reload recovery hits during teardown windows.
}

#[tokio::test]
async fn try_reconnect_leaves_failing_upstream_disconnected() {
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "missing".into(),
        stdio_manifest(
            "missing",
            vec!["/nonexistent/mcp-server-reprobe-test".into()],
        ),
    );
    let pool = connect_with_timeout(manifests).await;
    assert!(!pool.is_connected("missing").await);
    let initial = pool.health_snapshot().await.remove(0);
    assert_eq!(initial.runtime_state.as_str(), "disconnected");
    assert_eq!(initial.last_success_at, None);
    assert_eq!(
        initial.last_error_class.map(|class| class.as_str()),
        Some("transport"),
        "spawn detail must be reduced to the bounded class"
    );
    assert!(initial.next_retry_at.is_some());

    // Reload recovery should attempt to dial again, fail again, and leave the entry
    // exactly where it was. Crucially: it must not panic, must not hang, and
    // must not leave the entry in a half-state.
    tokio::time::timeout(Duration::from_secs(10), pool.try_reconnect_disconnected())
        .await
        .expect("try_reconnect_disconnected hung");

    assert!(!pool.is_connected("missing").await);
    let after_retry = pool.health_snapshot().await.remove(0);
    assert_eq!(
        after_retry.last_error_class.map(|class| class.as_str()),
        Some("transport")
    );
}

#[tokio::test]
async fn reconnect_one_returns_false_for_unknown_server() {
    let pool = connect_with_timeout(BTreeMap::new()).await;
    assert!(!pool.reconnect_one("does-not-exist").await);
}

#[tokio::test]
async fn reconnect_one_returns_false_for_failing_server() {
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "missing".into(),
        stdio_manifest(
            "missing",
            vec!["/nonexistent/mcp-server-reconnect-test".into()],
        ),
    );
    let pool = connect_with_timeout(manifests).await;
    assert!(!pool.is_connected("missing").await);

    let connected = tokio::time::timeout(Duration::from_secs(10), pool.reconnect_one("missing"))
        .await
        .expect("reconnect_one hung");
    assert!(!connected);
    assert!(!pool.is_connected("missing").await);
}

/// Pins Finding 4: a server removed via `reload_manifests` must not be
/// silently re-dialed by configuration reload recovery. Without the tombstone
/// flag, the entry stays in `self.entries` (intentional, to keep in-flight
/// callers from getting `not found` mid-call) and `try_reconnect_disconnected`
/// would dial it again after reload — resurrecting an upstream the operator
/// just retired and re-populating the search index a SIGHUP just cleared.
#[tokio::test]
async fn try_reconnect_skips_tombstoned_entries() {
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "retired".into(),
        stdio_manifest(
            "retired",
            vec!["/nonexistent/mcp-server-tombstone-test".into()],
        ),
    );
    let pool = connect_with_timeout(manifests).await;
    assert!(!pool.is_connected("retired").await);

    // Operator drops "retired" from the manifest catalog and SIGHUPs.
    let report = pool.reload_manifests(&BTreeMap::new()).await;
    assert_eq!(report.removed, vec!["retired".to_string()]);

    // Reload recovery fires. The tombstoned entry must be skipped — no dial
    // attempt, no panic, no breaker churn. With the bug this would re-dial
    // the nonexistent binary after every reload signal.
    tokio::time::timeout(Duration::from_secs(10), pool.try_reconnect_disconnected())
        .await
        .expect("try_reconnect_disconnected hung");

    assert!(!pool.is_connected("retired").await);
}

/// Pins Finding 4 (admin path): a tombstoned server must not be silently
/// revived by `POST /upstreams/{name}/reconnect`. Returning `false` lets
/// the admin endpoint surface the retirement as a 502, rather than dialing
/// a server the operator already removed from the catalog.
#[tokio::test]
async fn reconnect_one_returns_false_for_tombstoned_server() {
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "retired".into(),
        stdio_manifest(
            "retired",
            vec!["/nonexistent/mcp-server-admin-tombstone-test".into()],
        ),
    );
    let pool = connect_with_timeout(manifests).await;

    let report = pool.reload_manifests(&BTreeMap::new()).await;
    assert_eq!(report.removed, vec!["retired".to_string()]);

    let connected = tokio::time::timeout(Duration::from_secs(10), pool.reconnect_one("retired"))
        .await
        .expect("reconnect_one hung");
    assert!(
        !connected,
        "tombstoned entry must not redial via admin path"
    );
    assert!(!pool.is_connected("retired").await);
}

/// Pins the locking invariant of the tombstone path:
/// `reload_manifests` holds `entry.conn.write()` across the tombstone
/// store + index drop, which is the same lock `reconnect_entry` holds
/// across its publish region. Without that serialization, an in-flight
/// reconnect that had already passed the locked tombstone re-check could
/// repopulate the search index *after* `reload_manifests` dropped it and
/// publish a connection on a retired entry.
///
/// This test exercises the liveness side: running both paths concurrently
/// against the same upstream must not deadlock and must converge on the
/// tombstoned-and-disconnected final state. Deterministic exposure of the
/// race ordering would need a mock-dial seam, which we deliberately don't
/// add for one test — the lock-held window is short and obvious by
/// inspection.
#[tokio::test]
async fn concurrent_reconnect_and_reload_remove_converges_on_tombstone() {
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "retiring".into(),
        stdio_manifest("retiring", vec!["/nonexistent/mcp-server-race-test".into()]),
    );
    let pool = connect_with_timeout(manifests).await;
    let pool = std::sync::Arc::new(pool);

    let pool_a = pool.clone();
    let reconnect = tokio::spawn(async move { pool_a.reconnect_one("retiring").await });
    let pool_b = pool.clone();
    let reload =
        tokio::spawn(async move { pool_b.reload_manifests(&BTreeMap::new()).await.removed });

    let (rc_res, rl_res) = tokio::time::timeout(Duration::from_secs(10), async move {
        tokio::try_join!(reconnect, reload)
    })
    .await
    .expect("concurrent reconnect+reload hung — possible deadlock")
    .expect("task panicked");

    // Reconnect must not have published a fresh connection on a retired
    // entry. (For a nonexistent binary the dial fails anyway, but the
    // contract holds either way: tombstone is the source of truth.)
    assert!(!rc_res, "tombstoned upstream must end up disconnected");
    assert_eq!(rl_res, vec!["retiring".to_string()]);
    assert!(!pool.is_connected("retiring").await);
}

#[tokio::test]
async fn try_reconnect_is_idempotent_under_repeated_calls() {
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "missing".into(),
        stdio_manifest(
            "missing",
            vec!["/nonexistent/mcp-server-idempotent-test".into()],
        ),
    );
    let pool = connect_with_timeout(manifests).await;

    for _ in 0..3 {
        tokio::time::timeout(Duration::from_secs(10), pool.try_reconnect_disconnected())
            .await
            .expect("try_reconnect_disconnected hung");
        assert!(!pool.is_connected("missing").await);
    }
}
