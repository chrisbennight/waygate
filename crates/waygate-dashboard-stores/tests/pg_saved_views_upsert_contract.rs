//! Live Postgres contract test for [`PgActivitySavedViewStore`]'s
//! upsert merge semantics.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so `cargo test`
//! without a DB passes; CI provisions Postgres.
//!
//! The pinned contract: `save` is an ATOMIC top-level JSONB merge on
//! overwrite (`filters || EXCLUDED.filters`)
//! — submitted keys win, keys already on the row survive — so the
//! dashboard handler sends only known fields and no caller ever needs
//! a racy read-modify-write. `playground_scenarios` mirrors
//! this contract; this test is what keeps a future copy-paste of
//! either store from silently picking different upsert semantics.

use std::env;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;

use waygate_dashboard_stores::activity_saved_views::{
    ActivitySavedViewStore, PgActivitySavedViewStore,
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
    let tenant = "pg-views-merge";
    seed_tenant(&pool, tenant).await;
    let store = PgActivitySavedViewStore::new(pool.clone());

    store
        .save(
            tenant,
            "merge-contract",
            json!({"outcome": "denied", "future_field": "must-survive"}),
            Some("alice"),
        )
        .await
        .expect("first save");

    let after = store
        .save(
            tenant,
            "merge-contract",
            json!({"outcome": "success"}),
            Some("bob"),
        )
        .await
        .expect("second save");

    assert_eq!(
        after.filters["outcome"], "success",
        "submitted key must win"
    );
    assert_eq!(
        after.filters["future_field"], "must-survive",
        "unknown forward-compat key must survive a known-fields-only re-save"
    );
    assert_eq!(after.created_by.as_deref(), Some("alice"));

    let got = store
        .get(tenant, "merge-contract")
        .await
        .expect("get")
        .expect("row exists");
    assert_eq!(got.filters, after.filters);

    store
        .delete(tenant, "merge-contract")
        .await
        .expect("cleanup");
}
