//! Group catalog read-view store against real Postgres. Pins:
//!
//!   1. `list_with_usage` returns both SCIM (`source='scim'`) and local
//!      (`source='local'`) groups for the tenant, exposing the mutable version,
//!      counting SCIM-user, LIVE api-key, and role-mapping references, and
//!      excluding revoked keys + soft-deleted users.
//!   2. `delete_all_local_for_tenant` removes only `source='local'`
//!      groups; SCIM-provisioned groups survive (the tenant-DELETE
//!      cascade contract).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset (CI provisions a
//! live Postgres so it runs).

use std::env;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_apikeys::{
    ApiKeyRow, ApiKeyStore, GroupStore, GroupStoreError, LocalGroupDeleteTarget, PgGroupStore,
};

async fn group_delete_target(
    store: &PgGroupStore,
    tenant_id: &str,
    display_name: &str,
) -> LocalGroupDeleteTarget {
    let id = store
        .list_with_usage(tenant_id)
        .await
        .expect("list groups for delete target")
        .into_iter()
        .find(|group| group.display_name == display_name)
        .expect("named group exists")
        .id;
    store
        .get_local_delete_target(tenant_id, id)
        .await
        .expect("load local group delete target")
}

#[tokio::test]
async fn list_with_usage_counts_members_then_local_cleanup_keeps_scim() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let tenant = format!("test-group-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    let scim_gid = Uuid::new_v4();
    let local_gid = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // A SCIM group (source defaults to 'scim') + a local group.
    sqlx::query("INSERT INTO scim_groups (id, tenant_id, display_name) VALUES ($1, $2, 'eng')")
        .bind(scim_gid)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert scim group");
    sqlx::query(
        "INSERT INTO scim_groups (id, tenant_id, display_name, source) VALUES ($1, $2, 'mcp-users', 'local')",
    )
    .bind(local_gid)
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert local group");

    // A SCIM user who is a member of the SCIM group.
    sqlx::query("INSERT INTO scim_users (id, tenant_id, user_name) VALUES ($1, $2, 'alice')")
        .bind(user_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert scim user");
    sqlx::query("INSERT INTO scim_user_groups (user_id, group_id, tenant_id) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(scim_gid)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert membership");

    // A live key in both groups + a revoked key (must not count).
    let keys = ApiKeyStore::new(pool.clone());
    keys.insert(&key_row(&tenant, "live", &["mcp-users", "eng"], false))
        .await
        .expect("insert live key");
    keys.insert(&key_row(&tenant, "revoked", &["mcp-users"], true))
        .await
        .expect("insert revoked key");
    let role_id: Uuid = sqlx::query_scalar(
        "INSERT INTO gateway_roles (tenant_id, name) VALUES ($1, 'eng-role') RETURNING id",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("insert role");
    sqlx::query(
        "INSERT INTO group_role_mappings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)",
    )
    .bind(&tenant)
    .bind(scim_gid)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("insert group role mapping");

    let store = PgGroupStore::new(pool.clone());
    let rows = store.list_with_usage(&tenant).await.expect("list");

    let eng = rows
        .iter()
        .find(|r| r.display_name == "eng")
        .expect("scim group");
    assert_eq!(eng.source, "scim");
    assert_eq!(eng.user_member_count, 1, "the SCIM user is a member of eng");
    assert!(
        eng.updated_at >= eng.created_at,
        "the mutable version is observable"
    );
    assert_eq!(
        eng.key_member_count, 1,
        "the live key carries the eng label"
    );
    assert_eq!(eng.role_mapping_count, 1, "the role mapping is observable");

    let mu = rows
        .iter()
        .find(|r| r.display_name == "mcp-users")
        .expect("local group");
    assert_eq!(mu.source, "local");
    assert_eq!(mu.user_member_count, 0, "no SCIM users in the local group");
    assert_eq!(
        mu.key_member_count, 1,
        "only the live key counts; the revoked key is excluded",
    );
    assert_eq!(mu.role_mapping_count, 0);

    // Cleanup deletes only the local group; the SCIM group survives.
    let deleted = store
        .delete_all_local_for_tenant(&tenant)
        .await
        .expect("cleanup");
    assert_eq!(deleted, 1, "exactly the one local group is deleted");

    let after = store.list_with_usage(&tenant).await.expect("list after");
    assert!(
        after.iter().all(|r| r.source == "scim"),
        "only SCIM-provisioned groups remain after local cleanup",
    );
    assert!(
        after.iter().any(|r| r.display_name == "eng"),
        "the SCIM group must survive the local cleanup",
    );
    assert!(
        !after.iter().any(|r| r.display_name == "mcp-users"),
        "the local group must be gone",
    );
}

#[tokio::test]
async fn create_local_creates_then_rejects_duplicate_and_scim_shadow() {
    // Operator-defined local group create. Fresh name succeeds;
    // re-creating it, or a name already held by a SCIM group,
    // returns Conflict (can't shadow a provisioned group).
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let tenant = format!("test-gcreate-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    let store = PgGroupStore::new(pool.clone());

    store
        .create_local(&tenant, "ops")
        .await
        .expect("create fresh local group");
    let rows = store.list_with_usage(&tenant).await.expect("list");
    let created = rows
        .iter()
        .find(|r| r.display_name == "ops")
        .expect("created group present");
    assert_eq!(created.source, "local");

    // Duplicate local name → Conflict.
    let dup = store.create_local(&tenant, "ops").await.unwrap_err();
    assert!(
        matches!(dup, GroupStoreError::Conflict(_)),
        "duplicate local group must conflict"
    );

    // A name already held by a SCIM group → Conflict (no shadow).
    sqlx::query(
        "INSERT INTO scim_groups (tenant_id, display_name, source) VALUES ($1, 'eng', 'scim')",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert scim group");
    let shadow = store.create_local(&tenant, "eng").await.unwrap_err();
    assert!(
        matches!(shadow, GroupStoreError::Conflict(_)),
        "creating a local group shadowing a SCIM group must conflict",
    );
}

#[tokio::test]
async fn guarded_local_delete_requires_current_unreferenced_local_target() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let tenant = format!("test-gdelete-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert tenant");
    let store = PgGroupStore::new(pool.clone());
    store
        .create_local(&tenant, "unused")
        .await
        .expect("create unused local group");
    store
        .create_local(&tenant, "active")
        .await
        .expect("create active local group");
    store
        .create_local(&tenant, "membered")
        .await
        .expect("create membered local group");
    store
        .create_local(&tenant, "mapped")
        .await
        .expect("create mapped local group");
    sqlx::query(
        "INSERT INTO scim_groups (tenant_id, display_name, source) VALUES ($1, 'directory', 'scim')",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert SCIM group");

    let unused = group_delete_target(&store, &tenant, "unused").await;
    let stale = store
        .delete_local_if_unchanged(
            &tenant,
            unused.id,
            &unused.display_name,
            unused.updated_at - time::Duration::seconds(1),
        )
        .await
        .expect_err("stale generation must be refused");
    assert!(matches!(stale, GroupStoreError::Changed(id) if id == unused.id));
    store
        .delete_local_if_unchanged(&tenant, unused.id, &unused.display_name, unused.updated_at)
        .await
        .expect("delete current unreferenced local group");
    assert!(matches!(
        store.get_local_delete_target(&tenant, unused.id).await,
        Err(GroupStoreError::NotFound(id)) if id == unused.id
    ));

    let active = group_delete_target(&store, &tenant, "active").await;
    ApiKeyStore::new(pool.clone())
        .insert_catalog_checked(
            &key_row(&tenant, "active-key", &["active"], false),
            false,
            true,
        )
        .await
        .expect("insert catalog-checked referencing key");
    let stale_active = store
        .delete_local_if_unchanged(
            &tenant,
            active.id,
            &active.display_name,
            active.updated_at - time::Duration::seconds(1),
        )
        .await
        .expect_err("stale witness takes precedence over current references");
    assert!(matches!(
        stale_active,
        GroupStoreError::Changed(id) if id == active.id
    ));
    let in_use = store
        .delete_local_if_unchanged(&tenant, active.id, &active.display_name, active.updated_at)
        .await
        .expect_err("referenced group must be refused");
    assert!(matches!(
        in_use,
        GroupStoreError::InUse {
            user_members: 0,
            key_members: 1,
            role_mappings: 0
        }
    ));

    let membered = group_delete_target(&store, &tenant, "membered").await;
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO scim_users (id, tenant_id, user_name) VALUES ($1, $2, 'active-user')")
        .bind(user_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert referencing user");
    sqlx::query("INSERT INTO scim_user_groups (user_id, group_id, tenant_id) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(membered.id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert referencing user membership");
    let membered_error = store
        .delete_local_if_unchanged(
            &tenant,
            membered.id,
            &membered.display_name,
            membered.updated_at,
        )
        .await
        .expect_err("user membership must block group deletion");
    assert!(matches!(
        membered_error,
        GroupStoreError::InUse {
            user_members: 1,
            key_members: 0,
            role_mappings: 0
        }
    ));

    let mapped = group_delete_target(&store, &tenant, "mapped").await;
    let role_id: Uuid = sqlx::query_scalar(
        "INSERT INTO gateway_roles (tenant_id, name) VALUES ($1, 'active-role') RETURNING id",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("insert referencing role");
    sqlx::query(
        "INSERT INTO group_role_mappings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)",
    )
    .bind(&tenant)
    .bind(mapped.id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("insert referencing role mapping");
    let mapped_error = store
        .delete_local_if_unchanged(&tenant, mapped.id, &mapped.display_name, mapped.updated_at)
        .await
        .expect_err("role mapping must block group deletion");
    assert!(matches!(
        mapped_error,
        GroupStoreError::InUse {
            user_members: 0,
            key_members: 0,
            role_mappings: 1
        }
    ));

    let directory_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM scim_groups WHERE tenant_id = $1 AND display_name = 'directory'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("load SCIM group id");
    assert!(matches!(
        store
            .get_local_delete_target(&tenant, directory_id)
            .await,
        Err(GroupStoreError::NotLocal(id)) if id == directory_id
    ));
}

#[tokio::test]
async fn unknown_groups_returns_only_uncataloged_names() {
    // The mint-enforcement check. SCIM + local groups in the
    // tenant are "known"; anything else is returned as unknown.
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let tenant = format!("test-unkgrp-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("INSERT INTO scim_groups (tenant_id, display_name, source) VALUES ($1, 'eng', 'scim'), ($1, 'ops', 'local')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed groups");
    let store = PgGroupStore::new(pool.clone());

    let names = vec![
        "eng".to_owned(),    // scim → known
        "ops".to_owned(),    // local → known
        "ghosts".to_owned(), // neither → unknown
    ];
    let unknown = store
        .unknown_groups(&tenant, &names)
        .await
        .expect("unknown");
    assert_eq!(unknown.len(), 1, "only the uncataloged name is unknown");
    assert!(unknown.contains(&"ghosts".to_owned()));

    assert!(store
        .unknown_groups(&tenant, &[])
        .await
        .expect("empty")
        .is_empty());
}

fn key_row(tenant: &str, name: &str, groups: &[&str], revoked: bool) -> ApiKeyRow {
    let now = OffsetDateTime::now_utc();
    ApiKeyRow {
        id: Uuid::now_v7(),
        key_prefix: format!("pfx{}", &Uuid::new_v4().to_string()[..8]),
        key_hash: "argon2id$dummy".to_owned(),
        name: name.to_owned(),
        sub: format!("{name}@example.com"),
        tenant_id: tenant.to_owned(),
        email: None,
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        scopes: vec![],
        created_by: "pg-group-test".to_owned(),
        created_at: now,
        last_used_at: None,
        expires_at: None,
        revoked_at: revoked.then_some(now),
        profile_id: None,
        owner: None,
        reason: None,
        rotation_due_at: None,
    }
}
