//! The SCIM 2.0 Group surface
//! must stay scoped to IdP-provisioned `source='scim'` groups after
//! migration 0066 backfills api-key labels as `source='local'` rows into
//! the same `scim_groups` table. Pins the security boundary: a SCIM
//! client cannot enumerate, read, replace, or delete a local catalog
//! group through `/scim/v2/Groups`.
//!
//! Skips when `AUDIT_DATABASE_URL` is unset (CI provisions Postgres).

use std::env;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_scim::{ListParams, PgScimGroupStore, ScimError, ScimFilter, ScimGroupStore};

async fn pool_or_skip() -> Option<sqlx::PgPool> {
    let url = env::var("AUDIT_DATABASE_URL").ok()?;
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

#[tokio::test]
async fn scim_group_surface_excludes_local_catalog_groups() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("skipping pg group-boundary smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let store = PgScimGroupStore::new(pool.clone());
    let tenant = format!("test-grpbound-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    // An IdP-provisioned group via the SCIM store (source='scim').
    let scim_grp = store
        .create(&tenant, Some("ext-eng"), "eng", json!({}), &[])
        .await
        .expect("create scim group");

    // A local group inserted directly — the migration-0066 backfill shape.
    let local_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO scim_groups (id, tenant_id, display_name, source) VALUES ($1, $2, 'mcp-users', 'local')",
    )
    .bind(local_id)
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert local group");

    // list: only the SCIM group; the local one is never enumerated.
    let listed = store
        .list(&tenant, ScimFilter::None, ListParams::default())
        .await
        .expect("list");
    assert_eq!(
        listed.total_results, 1,
        "the SCIM list count must exclude local groups",
    );
    assert!(listed.resources.iter().any(|g| g.id == scim_grp.id));
    assert!(
        !listed
            .resources
            .iter()
            .any(|g| g.display_name == "mcp-users"),
        "a local group must not appear in the SCIM Group list",
    );

    // get: the local group id is invisible to the SCIM surface (404 at the handler).
    assert!(
        store
            .get(&tenant, local_id)
            .await
            .expect("get local")
            .is_none(),
        "SCIM get must not resolve a local group",
    );
    assert!(store
        .get(&tenant, scim_grp.id)
        .await
        .expect("get scim")
        .is_some());

    // delete: a SCIM write client cannot delete the local catalog group.
    assert!(
        !store.delete(&tenant, local_id).await.expect("delete local"),
        "SCIM delete of a local group must be a no-op",
    );
    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM scim_groups WHERE id = $1")
        .bind(local_id)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        still, 1,
        "the local group must survive a SCIM delete attempt"
    );

    // replace: a SCIM write client cannot rewrite the local group either.
    let replaced = store
        .replace(&tenant, local_id, Some("x"), "hijacked", json!({}), &[])
        .await
        .expect("replace local");
    assert!(
        replaced.is_none(),
        "SCIM replace of a local group must be a no-op",
    );
    let name: String = sqlx::query_scalar("SELECT display_name FROM scim_groups WHERE id = $1")
        .bind(local_id)
        .fetch_one(&pool)
        .await
        .expect("name");
    assert_eq!(
        name, "mcp-users",
        "the local group's name must be unchanged"
    );
}

#[tokio::test]
async fn scim_create_promotes_an_existing_local_group() {
    // An IdP provisioning a group whose displayName first
    // appeared as a local api-key label must ADOPT (promote) that row, not
    // 409. A second SCIM create of the same name then collides for real.
    let Some(pool) = pool_or_skip().await else {
        eprintln!("skipping pg group-promote smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let store = PgScimGroupStore::new(pool.clone());
    let tenant = format!("test-promote-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    // A local group, as migration 0066 would backfill it.
    let local_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO scim_groups (id, tenant_id, display_name, source) VALUES ($1, $2, 'mcp-users', 'local')",
    )
    .bind(local_id)
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert local group");

    // IdP provisions a SCIM group with the same name → promotes the local row.
    let created = store
        .create(&tenant, Some("idp-ext-1"), "mcp-users", json!({}), &[])
        .await
        .expect("SCIM create promotes the local group instead of 409");
    assert_eq!(created.id, local_id, "promotion keeps the existing row id");
    assert_eq!(
        created.external_id.as_deref(),
        Some("idp-ext-1"),
        "promotion adopts the IdP external_id",
    );

    // The row is now source='scim' and visible to the SCIM surface.
    let src: String = sqlx::query_scalar("SELECT source FROM scim_groups WHERE id = $1")
        .bind(local_id)
        .fetch_one(&pool)
        .await
        .expect("source");
    assert_eq!(src, "scim", "the local group was promoted to scim");
    assert!(
        store.get(&tenant, local_id).await.expect("get").is_some(),
        "the promoted group is now visible via the SCIM surface",
    );

    // A second SCIM create of the same name is now a real scim-vs-scim
    // collision → 409.
    let err = store
        .create(&tenant, Some("idp-ext-2"), "mcp-users", json!({}), &[])
        .await
        .expect_err("a second SCIM group with the same name must collide");
    assert!(
        matches!(err, ScimError::Uniqueness(_)),
        "scim-vs-scim displayName collision must be a uniqueness error",
    );
}
