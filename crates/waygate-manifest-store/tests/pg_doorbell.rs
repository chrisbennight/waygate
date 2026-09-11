//! Live Postgres smoke test for the manifest-reload doorbell:
//! `ManifestStore::notify_reload` → a `PgListener` on the
//! `mcp_manifest_reload` channel receives the notification with the content
//! hash as its payload.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset, the same convention as
//! the other `*_pg` smokes, so a DB-less `cargo test` passes. `NOTIFY` only
//! reaches `LISTEN`ers connected at notify time, so the test connects + listens
//! first, then fires the notify, then receives it (bounded by a timeout).

use std::env;
use std::time::Duration;

use sqlx::postgres::{PgListener, PgPoolOptions};

use waygate_manifest_store::{ManifestStore, PgManifestStore, MANIFEST_RELOAD_CHANNEL};

#[tokio::test]
async fn notify_reload_reaches_a_listener() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping doorbell notify Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");

    // A listener on the doorbell channel, established BEFORE the notify fires.
    let mut listener = PgListener::connect_with(&pool)
        .await
        .expect("connect listener");
    listener
        .listen(MANIFEST_RELOAD_CHANNEL)
        .await
        .expect("LISTEN mcp_manifest_reload");

    // Fire the doorbell from the store, carrying a content hash as the payload.
    let store = PgManifestStore::new(pool.clone());
    store
        .notify_reload("deadbeefcafef00d")
        .await
        .expect("notify_reload");

    // The listener must receive OUR notify promptly, channel + payload intact.
    // NOTIFY is DB-wide, so on a shared-DB CI run a concurrent manifest-store
    // test firing on this same channel can deliver a foreign payload first.
    // Skip payloads that aren't ours and keep waiting (bounded) for ours — the
    // real contract is "a notify carrying this hash is delivered", not "no one
    // else ever notifies this channel".
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let notif = tokio::time::timeout_at(deadline, listener.recv())
            .await
            .expect("our doorbell notify must arrive within 5s")
            .expect("listener recv ok");
        assert_eq!(notif.channel(), MANIFEST_RELOAD_CHANNEL);
        if notif.payload() == "deadbeefcafef00d" {
            break;
        }
    }
}
