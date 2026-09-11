//! Scope-registry store + migration smoke against real
//! Postgres. Pins:
//!
//!   1. The migration seeds EXACTLY `waygate_oidc::Scope::ALL` as the
//!      global `source='builtin'` rows. This is the enum-vs-catalog
//!      drift guard: add a `Scope` variant without teaching
//!      `0064_scope_registry.sql` the new built-in and this fails.
//!   2. `list_with_usage` unions global + tenant-local rows, counts
//!      LIVE api-keys and roles that reference each scope, and excludes
//!      revoked keys from the count.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset (matches the other
//! `*_pg` suites; CI provisions a live Postgres so it actually runs).

use std::collections::HashSet;
use std::env;
use std::time::Duration as StdDuration;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_apikeys::{ApiKeyRow, ApiKeyStore, PgScopeStore, ScopeStore, ScopeStoreError};
use waygate_oidc::Scope;

#[tokio::test]
async fn builtins_seeded_match_scope_enum() {
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

    let seeded: HashSet<String> = sqlx::query_scalar(
        "SELECT name FROM scopes WHERE source = 'builtin' AND tenant_id IS NULL",
    )
    .fetch_all(&pool)
    .await
    .expect("select builtins")
    .into_iter()
    .collect();

    let expected: HashSet<String> = Scope::ALL.iter().map(|s| s.as_str().to_owned()).collect();

    assert_eq!(
        seeded, expected,
        "migration 0064 builtin seed drifted from waygate_oidc::Scope::ALL — \
         update the migration's INSERT to match the enum",
    );
}

#[tokio::test]
async fn list_with_usage_unions_global_local_and_counts_live_refs() {
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

    let tenant = format!("test-scope-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    // A tenant-local scope the operator "defined".
    sqlx::query("INSERT INTO scopes (tenant_id, name, source) VALUES ($1, 'team:zeta', 'local')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert local scope");

    // A live key referencing the local scope + a global builtin.
    let keys = ApiKeyStore::new(pool.clone());
    keys.insert(&key_row(
        &tenant,
        "live-zeta",
        &["team:zeta", "mcp:read"],
        /* revoked */ false,
    ))
    .await
    .expect("insert live key");
    // A revoked key referencing the local scope — must NOT be counted.
    keys.insert(&key_row(
        &tenant,
        "revoked-zeta",
        &["team:zeta"],
        /* revoked */ true,
    ))
    .await
    .expect("insert revoked key");

    // A role in the tenant referencing the local scope.
    sqlx::query("INSERT INTO gateway_roles (tenant_id, name, scopes) VALUES ($1, 'zeta-role', $2)")
        .bind(&tenant)
        .bind(vec!["team:zeta".to_owned()])
        .execute(&pool)
        .await
        .expect("insert role");

    let store = PgScopeStore::new(pool.clone());
    let rows = store.list_with_usage(&tenant).await.expect("list");

    let zeta = rows
        .iter()
        .find(|r| r.name == "team:zeta")
        .expect("local scope present");
    assert_eq!(zeta.tenant_id.as_deref(), Some(tenant.as_str()));
    assert_eq!(zeta.source, "local");
    assert_eq!(
        zeta.key_refs, 1,
        "revoked key must be excluded from key_refs"
    );
    assert_eq!(zeta.role_refs, 1);

    let read = rows
        .iter()
        .find(|r| r.name == "mcp:read")
        .expect("global builtin present in tenant view");
    assert!(
        read.tenant_id.is_none(),
        "builtins are global (NULL tenant)"
    );
    assert_eq!(read.source, "builtin");
    assert!(
        read.key_refs >= 1,
        "the live key references mcp:read, so it must count at least once",
    );

    // All 8 builtins are visible to the tenant.
    let builtin_names: HashSet<&str> = rows
        .iter()
        .filter(|r| r.source == "builtin")
        .map(|r| r.name.as_str())
        .collect();
    for s in Scope::ALL {
        assert!(
            builtin_names.contains(s.as_str()),
            "builtin {} missing from tenant view",
            s.as_str(),
        );
    }
}

#[tokio::test]
async fn delete_all_for_tenant_drops_local_but_keeps_global_builtins() {
    // The tenant-DELETE cascade must clear tenant-local scope
    // rows so a re-created tenant id can't inherit
    // stale `source='local'` entries — while global built-ins survive.
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

    let tenant = format!("test-scope-del-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query(
        "INSERT INTO scopes (tenant_id, name, source) VALUES ($1, 'team:del-a', 'local'), ($1, 'team:del-b', 'local')",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert local scopes");

    let store = PgScopeStore::new(pool.clone());

    let deleted = store.delete_all_for_tenant(&tenant).await.expect("delete");
    assert_eq!(deleted, 2, "both tenant-local rows must be deleted");

    let after = store.list_with_usage(&tenant).await.expect("list after");
    assert!(
        after.iter().all(|r| r.tenant_id.is_none()),
        "only global rows should remain after the tenant cascade",
    );
    // Global built-ins are untouched.
    let builtins = after.iter().filter(|r| r.source == "builtin").count();
    assert_eq!(builtins, Scope::ALL.len(), "global builtins must survive");
}

#[tokio::test]
async fn upsert_policy_scopes_adds_global_rows_without_touching_builtins() {
    // Policy-referenced scopes register as global `source='policy'`
    // rows; a name that's already a built-in is a no-op
    // (the built-in keeps its source), and the upsert is idempotent.
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

    let store = PgScopeStore::new(pool.clone());
    // Unique global name so the test is re-runnable against a persistent DB.
    let novel = format!("policy:test-{}", Uuid::new_v4());

    // `novel` is new; `mcp:admin` is already a built-in → only `novel` inserts.
    let inserted = store
        .upsert_policy_scopes(&[novel.clone(), "mcp:admin".to_owned()])
        .await
        .expect("upsert");
    assert_eq!(
        inserted, 1,
        "only the novel scope should insert; the builtin conflicts",
    );

    // Idempotent.
    let again = store
        .upsert_policy_scopes(std::slice::from_ref(&novel))
        .await
        .expect("upsert again");
    assert_eq!(again, 0, "re-upserting an existing policy scope is a no-op");

    let tenant = format!("test-policy-view-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    let rows = store.list_with_usage(&tenant).await.expect("list");

    let p = rows
        .iter()
        .find(|r| r.name == novel)
        .expect("policy scope visible to the tenant");
    assert_eq!(p.source, "policy");
    assert!(p.tenant_id.is_none(), "policy scopes are global");

    let admin = rows
        .iter()
        .find(|r| r.name == "mcp:admin")
        .expect("builtin present");
    assert_eq!(
        admin.source, "builtin",
        "upserting a builtin name must NOT flip its source to policy",
    );
}

#[tokio::test]
async fn create_local_creates_then_rejects_duplicates_and_builtins() {
    // Operator-defined local scope create. Creating a fresh
    // name succeeds; re-creating it, or a name that's already a
    // global builtin, returns Conflict.
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

    let tenant = format!("test-screate-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    let store = PgScopeStore::new(pool.clone());
    let name = format!("team:custom-{}", Uuid::new_v4());

    store
        .create_local(&tenant, &name, Some("a custom scope"))
        .await
        .expect("create fresh local scope");
    let rows = store.list_with_usage(&tenant).await.expect("list");
    let created = rows
        .iter()
        .find(|r| r.name == name)
        .expect("created scope present");
    assert_eq!(created.source, "local");
    assert_eq!(created.tenant_id.as_deref(), Some(tenant.as_str()));
    assert_eq!(created.description.as_deref(), Some("a custom scope"));

    // Duplicate of the same local name → Conflict.
    let dup = store.create_local(&tenant, &name, None).await.unwrap_err();
    assert!(
        matches!(dup, ScopeStoreError::Conflict(_)),
        "duplicate local scope must conflict"
    );

    // A name that's already a GLOBAL builtin → Conflict (no shadow dup).
    let builtin = store
        .create_local(&tenant, "mcp:admin", None)
        .await
        .unwrap_err();
    assert!(
        matches!(builtin, ScopeStoreError::Conflict(_)),
        "creating a local scope shadowing a global builtin must conflict",
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

    let tenant = format!("test-sdelete-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert tenant");
    let store = PgScopeStore::new(pool.clone());
    let unused_name = format!("team:unused-{}", Uuid::new_v4());
    let active_name = format!("team:active-{}", Uuid::new_v4());
    store
        .create_local(&tenant, &unused_name, None)
        .await
        .expect("create unused local scope");
    store
        .create_local(&tenant, &active_name, None)
        .await
        .expect("create active local scope");
    let managed_name = format!("team:managed-{}", Uuid::new_v4());
    let managed_id: Uuid = sqlx::query_scalar(
        "INSERT INTO scopes (tenant_id, name, source) VALUES ($1, $2, 'policy') RETURNING id",
    )
    .bind(&tenant)
    .bind(&managed_name)
    .fetch_one(&pool)
    .await
    .expect("insert tenant-owned non-local scope");
    assert!(matches!(
        store.get_local_delete_target(&tenant, managed_id).await,
        Err(ScopeStoreError::NotLocal(id)) if id == managed_id
    ));
    assert!(matches!(
        store
            .delete_local_if_unchanged(
                &tenant,
                managed_id,
                &managed_name,
                OffsetDateTime::UNIX_EPOCH,
            )
            .await,
        Err(ScopeStoreError::NotLocal(id)) if id == managed_id
    ));

    let unused_id: Uuid =
        sqlx::query_scalar("SELECT id FROM scopes WHERE tenant_id = $1 AND name = $2")
            .bind(&tenant)
            .bind(&unused_name)
            .fetch_one(&pool)
            .await
            .expect("load unused scope id");
    let unused = store
        .get_local_delete_target(&tenant, unused_id)
        .await
        .expect("load unused delete target");
    let stale = store
        .delete_local_if_unchanged(
            &tenant,
            unused.id,
            &unused.name,
            unused.updated_at - time::Duration::seconds(1),
        )
        .await
        .expect_err("stale version must be refused");
    assert!(matches!(stale, ScopeStoreError::Changed(id) if id == unused.id));
    store
        .delete_local_if_unchanged(&tenant, unused.id, &unused.name, unused.updated_at)
        .await
        .expect("delete current unreferenced local scope");
    assert!(matches!(
        store.get_local_delete_target(&tenant, unused.id).await,
        Err(ScopeStoreError::NotFound(id)) if id == unused.id
    ));

    let active_id: Uuid =
        sqlx::query_scalar("SELECT id FROM scopes WHERE tenant_id = $1 AND name = $2")
            .bind(&tenant)
            .bind(&active_name)
            .fetch_one(&pool)
            .await
            .expect("load active scope id");
    let active = store
        .get_local_delete_target(&tenant, active_id)
        .await
        .expect("load active delete target");
    ApiKeyStore::new(pool.clone())
        .insert_catalog_checked(
            &key_row(&tenant, "active-key", &[&active_name], false),
            true,
            false,
        )
        .await
        .expect("insert catalog-checked referencing key");
    sqlx::query(
        "INSERT INTO gateway_roles (tenant_id, name, scopes) VALUES ($1, 'active-role', ARRAY[$2]::text[])",
    )
    .bind(&tenant)
    .bind(&active_name)
    .execute(&pool)
    .await
    .expect("insert referencing role");
    let stale_active = store
        .delete_local_if_unchanged(
            &tenant,
            active.id,
            &active.name,
            active.updated_at - time::Duration::seconds(1),
        )
        .await
        .expect_err("stale witness takes precedence over current references");
    assert!(matches!(
        stale_active,
        ScopeStoreError::Changed(id) if id == active.id
    ));
    let in_use = store
        .delete_local_if_unchanged(&tenant, active.id, &active.name, active.updated_at)
        .await
        .expect_err("referenced scope must be refused");
    assert!(matches!(
        in_use,
        ScopeStoreError::InUse {
            key_refs: 1,
            role_refs: 1
        }
    ));

    let racing_name = format!("team:racing-{}", Uuid::new_v4());
    store
        .create_local(&tenant, &racing_name, None)
        .await
        .expect("create racing local scope");
    let racing_id: Uuid =
        sqlx::query_scalar("SELECT id FROM scopes WHERE tenant_id = $1 AND name = $2")
            .bind(&tenant)
            .bind(&racing_name)
            .fetch_one(&pool)
            .await
            .expect("load racing scope id");
    let racing = store
        .get_local_delete_target(&tenant, racing_id)
        .await
        .expect("load racing delete target");
    let mut role_write = pool.begin().await.expect("begin role write");
    sqlx::query(
        "INSERT INTO gateway_roles (tenant_id, name, scopes) VALUES ($1, 'racing-role', ARRAY[$2]::text[])",
    )
    .bind(&tenant)
    .bind(&racing_name)
    .execute(&mut *role_write)
    .await
    .expect("stage overlapping role write");
    let delete_store = PgScopeStore::new(pool.clone());
    let delete_tenant = tenant.clone();
    let mut delete = tokio::spawn(async move {
        delete_store
            .delete_local_if_unchanged(&delete_tenant, racing.id, &racing.name, racing.updated_at)
            .await
    });
    assert!(
        tokio::time::timeout(StdDuration::from_millis(250), &mut delete)
            .await
            .is_err(),
        "scope deletion must wait for an overlapping role write"
    );
    role_write.commit().await.expect("commit role write");
    let raced = tokio::time::timeout(StdDuration::from_secs(5), delete)
        .await
        .expect("scope delete unblocks")
        .expect("scope delete task")
        .expect_err("committed overlapping role reference blocks deletion");
    assert!(matches!(raced, ScopeStoreError::InUse { role_refs: 1, .. }));

    let builtin_id: Uuid =
        sqlx::query_scalar("SELECT id FROM scopes WHERE tenant_id IS NULL AND name = 'mcp:admin'")
            .fetch_one(&pool)
            .await
            .expect("load builtin scope id");
    assert!(matches!(
        store.get_local_delete_target(&tenant, builtin_id).await,
        Err(ScopeStoreError::NotLocal(id)) if id == builtin_id
    ));
}

#[tokio::test]
async fn unknown_scopes_returns_only_uncataloged_names() {
    // The mint-enforcement check. Global builtins and
    // tenant-local scopes are "known"; anything else is returned as unknown.
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

    let tenant = format!("test-unkscope-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("INSERT INTO scopes (tenant_id, name, source) VALUES ($1, 'team:x', 'local')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed local scope");
    let store = PgScopeStore::new(pool.clone());

    let names = vec![
        "mcp:read".to_owned(), // global builtin → known
        "team:x".to_owned(),   // tenant-local → known
        "bad:nope".to_owned(), // neither → unknown
    ];
    let unknown = store
        .unknown_scopes(&tenant, &names)
        .await
        .expect("unknown");
    assert_eq!(unknown.len(), 1, "only the uncataloged name is unknown");
    assert!(unknown.contains(&"bad:nope".to_owned()));

    // Empty input is trivially all-known.
    assert!(store
        .unknown_scopes(&tenant, &[])
        .await
        .expect("empty")
        .is_empty());
}

fn key_row(tenant: &str, name: &str, scopes: &[&str], revoked: bool) -> ApiKeyRow {
    let now = OffsetDateTime::now_utc();
    ApiKeyRow {
        id: Uuid::now_v7(),
        key_prefix: format!("pfx{}", &Uuid::new_v4().to_string()[..8]),
        key_hash: "argon2id$dummy".to_owned(),
        name: name.to_owned(),
        sub: format!("{name}@example.com"),
        tenant_id: tenant.to_owned(),
        email: None,
        groups: vec![],
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        created_by: "pg-scope-test".to_owned(),
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
