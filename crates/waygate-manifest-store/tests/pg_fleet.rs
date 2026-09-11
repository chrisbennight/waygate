//! Live Postgres smoke test for the fleet heartbeat
//! (`upsert_replica_heartbeat` / `list_replica_heartbeats`, migration
//! `0040_fleet_replicas`).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset — the same convention as
//! every other `*_pg` smoke in the workspace — so a DB-less `cargo test`
//! passes. When the var IS set we connect, apply migrations, and exercise the
//! real UPSERT contract on throwaway replica ids: an insert, an
//! `ON CONFLICT (replica_id) DO UPDATE` that replaces (not duplicates) the row,
//! a NULL-version round-trip, and a multi-replica list scoped to the tenant.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_manifest_store::{ManifestStore, PgManifestStore};

#[tokio::test]
async fn fleet_heartbeat_upsert_and_list() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping manifest fleet Pg smoke: AUDIT_DATABASE_URL not set");
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

    // Unique tenant AND unique replica ids per run. `replica_id` is the GLOBAL
    // primary key and the upsert moves `tenant_id` on conflict, so fixed ids
    // would let a concurrent / shared-DB run hijack an existing pod-a row into
    // this smoke tenant (then delete it during cleanup). Per-run
    // unique ids keep the test fully isolated.
    let run = Uuid::now_v7();
    let tenant = format!("fleet-smoke-{run}");
    let rid_a = format!("pod-a-{run}");
    let rid_b = format!("pod-b-{run}");
    let store = PgManifestStore::new(pool.clone());

    assert!(
        store
            .list_replica_heartbeats(&tenant)
            .await
            .unwrap()
            .is_empty(),
        "fresh tenant has no heartbeats",
    );

    // First heartbeat from replica A (committed version).
    store
        .upsert_replica_heartbeat(&rid_a, &tenant, Some(3), "hashA")
        .await
        .unwrap();
    let rows = store.list_replica_heartbeats(&tenant).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].replica_id, rid_a);
    assert_eq!(rows[0].version, Some(3));
    assert_eq!(rows[0].content_hash, "hashA");

    // Re-heartbeat from the SAME replica with a new version/hash: ON CONFLICT
    // updates the existing row in place — no duplicate.
    store
        .upsert_replica_heartbeat(&rid_a, &tenant, Some(4), "hashA2")
        .await
        .unwrap();
    let rows = store.list_replica_heartbeats(&tenant).await.unwrap();
    assert_eq!(rows.len(), 1, "re-heartbeat updates in place, no duplicate");
    assert_eq!(rows[0].version, Some(4));
    assert_eq!(rows[0].content_hash, "hashA2");

    // A second replica with a NULL version (uncommitted/out-of-band on disk).
    store
        .upsert_replica_heartbeat(&rid_b, &tenant, None, "hashB")
        .await
        .unwrap();
    let rows = store.list_replica_heartbeats(&tenant).await.unwrap();
    assert_eq!(rows.len(), 2, "two distinct replicas listed");
    let b = rows
        .iter()
        .find(|r| r.replica_id == rid_b)
        .expect("rid_b present");
    assert_eq!(b.version, None, "NULL version round-trips as None");
    assert_eq!(b.content_hash, "hashB");

    // touch_replica_heartbeat refreshes only updated_at, leaving version/hash.
    store.touch_replica_heartbeat(&rid_a).await.unwrap();
    let a = store
        .list_replica_heartbeats(&tenant)
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.replica_id == rid_a)
        .expect("rid_a present");
    assert_eq!(a.version, Some(4), "touch must not change the version");
    assert_eq!(a.content_hash, "hashA2", "touch must not change the hash");

    // Cleanup our throwaway rows, keyed by the unique replica ids.
    sqlx::query("DELETE FROM fleet_replicas WHERE replica_id = $1 OR replica_id = $2")
        .bind(&rid_a)
        .bind(&rid_b)
        .execute(&pool)
        .await
        .unwrap();
}
