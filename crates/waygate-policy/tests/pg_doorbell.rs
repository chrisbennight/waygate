//! Live Postgres smoke test for the policy doorbell notify:
//! `PolicyStore::notify_reload` → a `PgListener` on the `mcp_policy_reload`
//! channel receives the notification with the content hash as its payload.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset, the same convention as the
//! other `*_pg` smokes, so a DB-less `cargo test` passes. `NOTIFY` only reaches
//! `LISTEN`ers connected at notify time, so the test connects + listens first,
//! then fires the notify, then receives it (bounded by a timeout). Mirrors
//! `waygate-manifest-store`'s `pg_doorbell.rs`.

use std::env;
use std::time::Duration;

use sqlx::postgres::{PgListener, PgPoolOptions};

use waygate_policy::{PgPolicyStore, PolicyStore, POLICY_RELOAD_CHANNEL};

#[tokio::test]
async fn notify_reload_reaches_a_listener() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping policy doorbell notify Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");

    // A listener on the policy doorbell channel, established BEFORE the notify.
    let mut listener = PgListener::connect_with(&pool)
        .await
        .expect("connect listener");
    listener
        .listen(POLICY_RELOAD_CHANNEL)
        .await
        .expect("LISTEN mcp_policy_reload");

    // Fire the doorbell from the store, carrying a content hash as the payload.
    let store = PgPolicyStore::new(pool.clone());
    store
        .notify_reload("deadbeefcafef00d")
        .await
        .expect("notify_reload");

    // The listener must receive OUR notify promptly, channel + payload intact.
    // The sibling test `notify_reload_uses_a_distinct_channel_from_manifests`
    // fires its own notify on this SAME channel against the SAME shared test DB
    // and runs concurrently, so a foreign payload can arrive first. NOTIFY is
    // DB-wide, so a shared-DB CI run is exactly when "this test owns the
    // channel" breaks. Skip payloads that aren't ours and keep waiting (bounded)
    // for ours — the real contract is "a notify carrying this hash is
    // delivered", not "no one else ever notifies this channel".
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let notif = tokio::time::timeout_at(deadline, listener.recv())
            .await
            .expect("our doorbell notify must arrive within 5s")
            .expect("listener recv ok");
        assert_eq!(notif.channel(), POLICY_RELOAD_CHANNEL);
        if notif.payload() == "deadbeefcafef00d" {
            break;
        }
    }
}

#[tokio::test]
async fn notify_reload_uses_a_distinct_channel_from_manifests() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!(
            "skipping policy doorbell channel-isolation Pg smoke: AUDIT_DATABASE_URL not set"
        );
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");

    // A listener on the MANIFEST channel must NOT receive a POLICY notify — a
    // policy write rebuilds Cedar, it must not also wake a manifest re-dial. The
    // manifest channel name is a literal here (not the `waygate_manifest_store`
    // const) to avoid a cross-crate dev-dep just for this assertion; the unit
    // test `channel_is_distinct_from_the_manifest_channel` pins that the policy
    // const really differs from this literal.
    let mut manifest_listener = PgListener::connect_with(&pool)
        .await
        .expect("connect listener");
    manifest_listener
        .listen("mcp_manifest_reload")
        .await
        .expect("LISTEN mcp_manifest_reload");

    let store = PgPolicyStore::new(pool.clone());
    store
        .notify_reload("policyhash01")
        .await
        .expect("notify_reload");

    // The manifest listener must time out (no cross-channel delivery). A short
    // bound is enough: pg_notify delivery is sub-second when it happens.
    let crossed = tokio::time::timeout(Duration::from_secs(1), manifest_listener.recv()).await;
    assert!(
        crossed.is_err(),
        "a policy notify must NOT reach a manifest-channel listener (distinct channels)",
    );
}
