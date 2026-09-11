//! Live Postgres contract test for [`PgPlaygroundScenarioStore`]'s
//! upsert merge semantics.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so `cargo test`
//! without a DB passes; CI provisions Postgres.
//!
//! The pinned contract: `save` is an ATOMIC top-level JSONB merge on
//! overwrite — submitted keys win, keys already on the row survive.
//! This is what lets the dashboard handler send only the fields it
//! knows about (no read-modify-write) while a newer dashboard
//! version's extra keys round-trip untouched. It mirrors
//! `activity_saved_views`: an application-layer read-modify-write
//! merge would reopen the same race that atomic upsert closes.

use std::env;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;

use waygate_dashboard_stores::playground_scenarios::{
    PgPlaygroundScenarioStore, PlaygroundScenarioStore,
};

async fn connect() -> Option<sqlx::PgPool> {
    let url = match env::var("AUDIT_DATABASE_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("skipping: AUDIT_DATABASE_URL not set");
            return None;
        }
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    Some(pool)
}

async fn seed_tenant(pool: &sqlx::PgPool, tenant_id: &str) {
    sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("seed tenant");
}

#[tokio::test]
async fn upsert_merges_atomically_preserving_unknown_keys() {
    let Some(pool) = connect().await else { return };
    let tenant = "pg-scen-merge";
    seed_tenant(&pool, tenant).await;
    let store = PgPlaygroundScenarioStore::new(pool.clone());

    // First save: a body carrying a key this "dashboard version"
    // does not know about (as if written by a newer version).
    store
        .save(
            tenant,
            "merge-contract",
            json!({"sub": "alice", "future_field": "must-survive"}),
            Some("alice"),
        )
        .await
        .expect("first save");

    // Re-save with ONLY the known fields — the store must merge,
    // not replace: submitted keys win, the unknown key survives.
    let after = store
        .save(tenant, "merge-contract", json!({"sub": "bob"}), Some("bob"))
        .await
        .expect("second save");

    assert_eq!(after.body["sub"], "bob", "submitted key must win");
    assert_eq!(
        after.body["future_field"], "must-survive",
        "unknown forward-compat key must survive a known-fields-only re-save"
    );
    // COALESCE authorship: the original operator stays attributed.
    assert_eq!(after.created_by.as_deref(), Some("alice"));

    // And the round-trip via get agrees with what save returned.
    let got = store
        .get(tenant, "merge-contract")
        .await
        .expect("get")
        .expect("row exists");
    assert_eq!(got.body, after.body);

    store
        .delete(tenant, "merge-contract")
        .await
        .expect("cleanup");
}
