//! Live Postgres smoke test for the cross-replica write turnstile
//! (`seed_pointer` / `read_pointer` / `cas_pointer`, migration
//! `0038_server_manifest_pointer`).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset — the same convention as
//! every other `*_pg` smoke in the workspace (policy / oauth / audit) — so a
//! DB-less `cargo test` passes without special-casing. When the var IS set we
//! connect, apply migrations, and exercise the real conditional-UPDATE
//! contract on a throwaway tenant: seed-if-absent (no clobber), a winning
//! swap, a losing swap on a stale base, and two concurrent swaps where
//! exactly one wins (the lost-update prevention the turnstile exists for).

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_manifest_store::{ManifestStore, PgManifestStore, TurnstileOutcome};

#[tokio::test]
async fn turnstile_cas_serializes_writers() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping manifest turnstile Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    // Unique tenant per run so concurrent / repeated runs don't collide and
    // cleanup is scoped to exactly our rows.
    let tenant = format!("turnstile-smoke-{}", Uuid::now_v7());
    let store = PgManifestStore::new(pool.clone());

    // No pointer yet on a fresh tenant.
    assert!(
        store.read_pointer(&tenant).await.unwrap().is_none(),
        "fresh tenant has no turnstile pointer",
    );

    // Seed at base "h0". A second seed with a different value is a no-op:
    // seed_pointer never clobbers an existing pointer.
    store.seed_pointer(&tenant, "h0").await.unwrap();
    store.seed_pointer(&tenant, "DIFFERENT").await.unwrap();
    assert_eq!(
        store
            .read_pointer(&tenant)
            .await
            .unwrap()
            .unwrap()
            .current_hash,
        "h0",
        "seed_pointer must not clobber an existing pointer",
    );

    // A CAS from the live base wins and advances the pointer.
    assert_eq!(
        store
            .cas_pointer(&tenant, "h0", "h1", "alice")
            .await
            .unwrap(),
        TurnstileOutcome::Won,
    );
    assert_eq!(
        store
            .read_pointer(&tenant)
            .await
            .unwrap()
            .unwrap()
            .current_hash,
        "h1",
    );

    // A CAS from a now-stale base loses and leaves the pointer untouched.
    assert_eq!(
        store.cas_pointer(&tenant, "h0", "h2", "bob").await.unwrap(),
        TurnstileOutcome::Lost,
    );
    assert_eq!(
        store
            .read_pointer(&tenant)
            .await
            .unwrap()
            .unwrap()
            .current_hash,
        "h1",
        "a losing CAS must not move the pointer",
    );

    // Two concurrent CAS from the same base: exactly one wins. This is the
    // cross-replica lost-update prevention — the whole point of the turnstile.
    let s1 = store.clone();
    let s2 = store.clone();
    let t1 = tenant.clone();
    let t2 = tenant.clone();
    let (r1, r2) = tokio::join!(
        async move { s1.cas_pointer(&t1, "h1", "concur-A", "a").await.unwrap() },
        async move { s2.cas_pointer(&t2, "h1", "concur-B", "b").await.unwrap() },
    );
    let wins = [r1, r2]
        .iter()
        .filter(|o| matches!(o, TurnstileOutcome::Won))
        .count();
    assert_eq!(wins, 1, "exactly one concurrent writer wins the turnstile");

    // Cleanup our throwaway rows.
    sqlx::query("DELETE FROM server_manifest_pointer WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
}
