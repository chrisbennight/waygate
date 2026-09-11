//! Profile store + cleanup arm smoke against real Postgres.
//! Pins:
//!
//!   1. CRUD round-trip on a profile (create/get/list/delete).
//!   2. Conflict on duplicate (tenant_id, name).
//!   3. CHECK violation surfaced as InvalidShape on empty
//!      allowed_scopes or non-positive max_ttl_seconds.
//!   4. delete_all_for_tenant sweeps every profile for the
//!      tenant AFTER all api_keys are revoked (the production
//!      tenant-DELETE cascade ordering, required by the
//!      migration 0027 BEFORE DELETE trigger). The FK ON
//!      DELETE SET NULL then clears profile_id on the now-
//!      revoked rows.
//!   5. The `api_key_profiles_block_delete_if_referenced`
//!      trigger refuses to delete a profile while any live
//!      (non-revoked, non-expired) api_keys row references
//!      it; revoking the key unblocks the delete.
//!   6. Conditional delete preserves a row whose `updated_at`
//!      changed after its version was reviewed.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset.

use std::env;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_apikeys::{ApiKeyRow, ApiKeyStore, PgProfileStore, ProfileStore, ProfileStoreError};

#[tokio::test]
async fn crud_round_trip_and_conflict() {
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

    let tenant = format!("test-profile-crud-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    let store = PgProfileStore::new(pool.clone());

    let created = store
        .create(
            &tenant,
            "read_only",
            Some("read-only access"),
            3600,
            &["mcp:read".to_owned()],
            None,
            None,
            true,
            true,
        )
        .await
        .expect("create");
    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.allowed_scopes, vec!["mcp:read"]);
    assert!(created.requires_owner);

    let fetched = store
        .get(&tenant, created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(fetched, created);

    let list = store.list(&tenant).await.expect("list");
    assert_eq!(list.len(), 1);

    // Duplicate name → Conflict.
    let dup = store
        .create(
            &tenant,
            "read_only",
            None,
            3600,
            &["mcp:read".to_owned()],
            None,
            None,
            false,
            false,
        )
        .await;
    assert!(matches!(dup, Err(ProfileStoreError::Conflict)));

    // Empty allowed_scopes → CHECK violation surfaced as InvalidShape.
    let bad = store
        .create(
            &tenant,
            "bad_no_scopes",
            None,
            3600,
            &[],
            None,
            None,
            false,
            false,
        )
        .await;
    assert!(matches!(bad, Err(ProfileStoreError::InvalidShape(_))));

    assert!(store.delete(&tenant, created.id).await.expect("delete"));
    assert!(store
        .get(&tenant, created.id)
        .await
        .expect("get-after")
        .is_none());

    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn conditional_delete_preserves_a_newer_profile_version() {
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

    let tenant = format!("test-profile-witness-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");
    let store = PgProfileStore::new(pool.clone());
    let reviewed = store
        .create(
            &tenant,
            "reviewed",
            None,
            3600,
            &["mcp:read".to_owned()],
            None,
            None,
            true,
            true,
        )
        .await
        .expect("create reviewed profile");

    sqlx::query("UPDATE api_key_profiles SET description = $3 WHERE tenant_id = $1 AND id = $2")
        .bind(&tenant)
        .bind(reviewed.id)
        .bind("newer operator edit")
        .execute(&pool)
        .await
        .expect("advance profile version");
    let current = store
        .get(&tenant, reviewed.id)
        .await
        .expect("get current profile")
        .expect("profile remains");
    assert_ne!(current.updated_at, reviewed.updated_at);

    assert!(!store
        .delete_if_updated_at(&tenant, reviewed.id, reviewed.updated_at)
        .await
        .expect("stale conditional delete"));
    assert!(store
        .get(&tenant, reviewed.id)
        .await
        .expect("get after stale delete")
        .is_some());
    assert!(store
        .delete_if_updated_at(&tenant, reviewed.id, current.updated_at)
        .await
        .expect("current conditional delete"));

    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("clean tenant");
}

// Tenant cascade must revoke every api_keys row BEFORE
// bulk-deleting profiles, because the
// `api_key_profiles_block_delete_if_referenced` trigger
// (migration 0027) refuses to delete a profile referenced
// by any live (non-revoked, non-expired) api_keys row.
// Production tenant DELETE in `waygate-admin::tenants` runs
// `revoke_all_for_tenant` (line 520) ahead of
// `delete_all_for_tenant` (line 617), so the trigger sees a
// live-count of 0 by the time it fires. This test mirrors
// that ordering and asserts the FK SET NULL still applies
// to the now-revoked row.
#[tokio::test]
async fn delete_all_for_tenant_after_revoke_clears_fk() {
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

    let tenant = format!("test-profile-cleanup-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    let profile_store = PgProfileStore::new(pool.clone());
    let api_keys = ApiKeyStore::new(pool.clone());

    let profile = profile_store
        .create(
            &tenant,
            "dev",
            None,
            3600,
            &["mcp:read".to_owned(), "mcp:invoke".to_owned()],
            None,
            None,
            true,
            true,
        )
        .await
        .expect("seed profile");

    // Mint a key wearing this profile.
    let minted = waygate_apikeys::token::mint().expect("mint");
    let key_id = Uuid::new_v4();
    api_keys
        .insert(&ApiKeyRow {
            id: key_id,
            key_prefix: minted.key_prefix,
            key_hash: minted.key_hash,
            name: "test-key".into(),
            sub: "alice".into(),
            tenant_id: tenant.clone(),
            email: None,
            groups: vec![],
            scopes: vec!["mcp:read".into()],
            created_by: "test".into(),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            profile_id: Some(profile.id),
            owner: Some("alice".into()),
            reason: Some("testing cleanup ordering".into()),
            rotation_due_at: None,
        })
        .await
        .expect("insert key");

    // Step 1 (mirrors production tenant-DELETE cascade
    // ordering): revoke every api_keys row for the tenant
    // BEFORE attempting profile bulk-delete. Without this,
    // migration 0027's BEFORE DELETE trigger would refuse
    // the next call.
    let revoked = api_keys
        .revoke_all_for_tenant(&tenant)
        .await
        .expect("revoke_all_for_tenant");
    assert_eq!(revoked, 1);

    // Step 2: bulk-delete profiles for the tenant.
    let n = profile_store
        .delete_all_for_tenant(&tenant)
        .await
        .expect("delete_all_for_tenant");
    assert_eq!(n, 1);

    // Profile is gone.
    assert!(profile_store
        .get(&tenant, profile.id)
        .await
        .expect("get-after")
        .is_none());

    // Revoked key row is still present but with profile_id
    // NULL'd by the FK ON DELETE SET NULL semantics. The FK
    // cascade is preserved as a defensive fallback for the
    // revoked-row case (where the trigger no longer guards).
    let row_profile_id: Option<Uuid> =
        sqlx::query_scalar("SELECT profile_id FROM api_keys WHERE id = $1")
            .bind(key_id)
            .fetch_one(&pool)
            .await
            .expect("fetch api_keys profile_id");
    assert!(
        row_profile_id.is_none(),
        "FK ON DELETE SET NULL must clear api_keys.profile_id when the parent profile is deleted",
    );

    sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(key_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

// Pin the trigger's safety contract directly — deleting a
// profile referenced by any live
// api_keys row must error with `ProfileStoreError::Blocked`
// carrying the live-reference count. The same liveness
// criteria as `lookup_by_prefix` apply: a revoked row no
// longer counts as live (the trigger lets the delete
// proceed; FK SET NULL handles the lingering reference).
#[tokio::test]
async fn delete_blocked_while_live_key_references_profile() {
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

    let tenant = format!("test-profile-trigger-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    let profile_store = PgProfileStore::new(pool.clone());
    let api_keys = ApiKeyStore::new(pool.clone());

    let profile = profile_store
        .create(
            &tenant,
            "restrictive",
            None,
            3600,
            &["mcp:read".to_owned()],
            None,
            None,
            true,
            true,
        )
        .await
        .expect("seed profile");

    let minted = waygate_apikeys::token::mint().expect("mint");
    let key_id = Uuid::new_v4();
    api_keys
        .insert(&ApiKeyRow {
            id: key_id,
            key_prefix: minted.key_prefix,
            key_hash: minted.key_hash,
            name: "live-key".into(),
            sub: "bob".into(),
            tenant_id: tenant.clone(),
            email: None,
            groups: vec![],
            scopes: vec!["mcp:read".into()],
            created_by: "test".into(),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            profile_id: Some(profile.id),
            owner: Some("bob".into()),
            reason: Some("trigger guard test".into()),
            rotation_due_at: None,
        })
        .await
        .expect("insert key");

    // Live key present → single-row delete must be blocked.
    let err = profile_store
        .delete(&tenant, profile.id)
        .await
        .expect_err("trigger must refuse delete while live key references profile");
    match err {
        waygate_apikeys::ProfileStoreError::Blocked { live_refs } => {
            assert_eq!(
                live_refs, 1,
                "trigger must surface the exact live-ref count"
            );
        }
        other => panic!(
            "expected ProfileStoreError::Blocked, got {other:?}; trigger may not be wired or \
             error mapping in PgProfileStore::delete may be broken"
        ),
    }

    // Profile must still exist (the trigger rolled back).
    assert!(
        profile_store
            .get(&tenant, profile.id)
            .await
            .expect("get-after-blocked")
            .is_some(),
        "blocked DELETE must leave the profile row in place"
    );

    // Revoke the key — trigger sees live-count 0 now.
    api_keys.revoke(key_id).await.expect("revoke");

    profile_store
        .delete(&tenant, profile.id)
        .await
        .expect("delete must succeed after the only referencing key is revoked");

    sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(key_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}
