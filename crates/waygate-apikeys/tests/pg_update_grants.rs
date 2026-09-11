//! `ApiKeyStore::update_grants` is the storage primitive behind editable
//! per-key grants. This pg_smoke proves the conditional UPDATE: (1) a live key
//! in its tenant has its scopes + groups replaced and returns true; (2) a
//! cross-tenant id is a no-op (false) and leaves the row untouched — the tenant
//! guard; (3) a revoked key cannot be re-scoped (false) — the
//! `revoked_at IS NULL` resurrection guard mirroring `revoke`.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set.

use std::env;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_apikeys::{token, ApiKeyRow, ApiKeyStore, StoreError};

fn seed_row(tenant: &str, name: &str) -> (Uuid, ApiKeyRow) {
    let m = token::mint().expect("mint");
    let id = Uuid::new_v4();
    (
        id,
        ApiKeyRow {
            id,
            key_prefix: m.key_prefix,
            key_hash: m.key_hash,
            name: name.into(),
            sub: format!("system:{tenant}:{name}"),
            tenant_id: tenant.into(),
            email: None,
            groups: vec!["g-old".into()],
            scopes: vec!["mcp:read".into()],
            created_by: "test".into(),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            profile_id: None,
            owner: None,
            reason: None,
            rotation_due_at: None,
        },
    )
}

async fn grants_of(pool: &sqlx::PgPool, id: Uuid) -> (serde_json::Value, serde_json::Value) {
    sqlx::query_as("SELECT scopes, groups FROM api_keys WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("fetch grants")
}

#[tokio::test]
async fn update_grants_replaces_live_key_and_guards_tenant_and_revoke() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
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

    let store = ApiKeyStore::new(pool.clone());
    let tenant = format!("test-editgrants-store-{}", Uuid::new_v4());
    let other = format!("test-editgrants-other-{}", Uuid::new_v4());

    let (id, row) = seed_row(&tenant, "k");
    store.insert(&row).await.expect("insert");

    // (1) live key in its tenant: replace scopes + groups, returns true.
    let ok = store
        .update_grants(
            id,
            &tenant,
            &["mcp:read".into(), "mcp:invoke".into()],
            &["g-new".into()],
        )
        .await
        .expect("update_grants");
    assert!(ok, "updating a live key in its tenant must report a change");
    let (scopes, groups) = grants_of(&pool, id).await;
    assert_eq!(scopes, serde_json::json!(["mcp:read", "mcp:invoke"]));
    assert_eq!(groups, serde_json::json!(["g-new"]));

    // (2) wrong tenant: no-op (false), row untouched.
    let cross = store
        .update_grants(id, &other, &["mcp:admin".into()], &[])
        .await
        .expect("update_grants cross-tenant");
    assert!(!cross, "a cross-tenant edit must not match");
    let (scopes, groups) = grants_of(&pool, id).await;
    assert_eq!(
        scopes,
        serde_json::json!(["mcp:read", "mcp:invoke"]),
        "a cross-tenant edit must not mutate the row",
    );
    assert_eq!(groups, serde_json::json!(["g-new"]));

    // (3) revoked key: cannot be re-scoped (false), resurrection guard.
    store.revoke(id).await.expect("revoke");
    let after_revoke = store
        .update_grants(id, &tenant, &["mcp:admin".into()], &[])
        .await
        .expect("update_grants after revoke");
    assert!(
        !after_revoke,
        "a revoked key must not be editable (revoked_at IS NULL guard)",
    );
    let (scopes, _groups) = grants_of(&pool, id).await;
    assert_eq!(
        scopes,
        serde_json::json!(["mcp:read", "mcp:invoke"]),
        "an edit on a revoked key must not mutate grants",
    );

    // Cleanup.
    sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn catalog_enforcement_is_independent_for_scopes_and_groups() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
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

    let store = ApiKeyStore::new(pool);
    let tenant = format!("test-catalog-modes-{}", Uuid::new_v4());
    let (_, mut unchecked) = seed_row(&tenant, "unchecked");
    unchecked.scopes = vec!["scope:uncataloged".into()];
    unchecked.groups = vec!["group-uncataloged".into()];
    store
        .insert_catalog_checked(&unchecked, false, false)
        .await
        .expect("disabled catalog dimensions accept free-form grants");

    let (_, mut unknown_scope) = seed_row(&tenant, "unknown-scope");
    unknown_scope.scopes = vec!["scope:missing".into()];
    unknown_scope.groups.clear();
    assert!(matches!(
        store
            .insert_catalog_checked(&unknown_scope, true, false)
            .await,
        Err(StoreError::UnknownScopes(names)) if names == ["scope:missing"]
    ));

    let (_, mut unknown_group) = seed_row(&tenant, "unknown-group");
    unknown_group.scopes.clear();
    unknown_group.groups = vec!["group-missing".into()];
    assert!(matches!(
        store
            .insert_catalog_checked(&unknown_group, false, true)
            .await,
        Err(StoreError::UnknownGroups(names)) if names == ["group-missing"]
    ));
}

#[tokio::test]
async fn catalog_checked_insert_holds_grant_write_behind_catalog_row_locks() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let tenant = format!("test-catalog-lock-{}", Uuid::new_v4());
    let scope_id = Uuid::new_v4();
    let group_id = Uuid::new_v4();
    let scope_name = format!("scope:{scope_id}");
    let group_name = format!("group-{group_id}");
    sqlx::query("INSERT INTO scopes (id, tenant_id, name, source) VALUES ($1, $2, $3, 'local')")
        .bind(scope_id)
        .bind(&tenant)
        .bind(&scope_name)
        .execute(&pool)
        .await
        .expect("seed scope");
    sqlx::query(
        "INSERT INTO scim_groups (id, tenant_id, display_name, source) VALUES ($1, $2, $3, 'local')",
    )
    .bind(group_id)
    .bind(&tenant)
    .bind(&group_name)
    .execute(&pool)
    .await
    .expect("seed group");

    let mut blocker = pool.begin().await.expect("begin blocker");
    sqlx::query("SELECT id FROM scopes WHERE id = $1 FOR UPDATE")
        .bind(scope_id)
        .fetch_one(&mut *blocker)
        .await
        .expect("lock scope");
    sqlx::query("SELECT id FROM scim_groups WHERE id = $1 FOR UPDATE")
        .bind(group_id)
        .fetch_one(&mut *blocker)
        .await
        .expect("lock group");

    let (_, mut row) = seed_row(&tenant, "locked-write");
    row.scopes = vec![scope_name];
    row.groups = vec![group_name];
    let store = ApiKeyStore::new(pool.clone());
    let mut write =
        tokio::spawn(async move { store.insert_catalog_checked(&row, true, true).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut write)
            .await
            .is_err(),
        "catalog-checked insert must wait for the reviewed rows instead of racing deletion"
    );
    sqlx::query("DELETE FROM scopes WHERE id = $1")
        .bind(scope_id)
        .execute(&mut *blocker)
        .await
        .expect("delete scope while write waits");
    sqlx::query("DELETE FROM scim_groups WHERE id = $1")
        .bind(group_id)
        .execute(&mut *blocker)
        .await
        .expect("delete group while write waits");
    blocker.commit().await.expect("publish catalog deletion");
    let error = tokio::time::timeout(Duration::from_secs(5), write)
        .await
        .expect("catalog write unblocks")
        .expect("catalog write task")
        .expect_err("catalog write must reject targets deleted while it waited");
    assert!(matches!(
        error,
        waygate_apikeys::StoreError::UnknownScopes(_)
    ));
}
