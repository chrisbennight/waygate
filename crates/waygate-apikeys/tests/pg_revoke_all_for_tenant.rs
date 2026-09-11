//! Tenant DELETE must soft-revoke all api_keys for the
//! tenant. This pg_smoke
//! proves `ApiKeyStore::revoke_all_for_tenant` (the method the
//! tenants admin handler now calls on delete) does exactly
//! that: live keys for the target tenant get `revoked_at` set,
//! live keys for OTHER tenants are untouched, already-revoked
//! keys are not re-stamped (preserving the original revoked_at
//! timestamp).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set.

use std::env;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_apikeys::{token, ApiKeyRow, ApiKeyStore};

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
            groups: vec![],
            scopes: vec!["scim:read".into()],
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

#[tokio::test]
async fn revoke_all_for_tenant_soft_revokes_only_target_tenant() {
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

    // Per-test tenant ids so concurrent runs don't race.
    let target = format!("test-revoke-target-{}", Uuid::new_v4());
    let other = format!("test-revoke-other-{}", Uuid::new_v4());

    let (target_a, row_a) = seed_row(&target, "target_a");
    let (target_b, row_b) = seed_row(&target, "target_b");
    let (other_a, row_o) = seed_row(&other, "other_a");
    store.insert(&row_a).await.expect("insert target_a");
    store.insert(&row_b).await.expect("insert target_b");
    store.insert(&row_o).await.expect("insert other_a");

    // Pre-revoke one target row by id; revoke_all must not
    // overwrite the existing revoked_at timestamp on that row
    // (the WHERE clause filters `revoked_at IS NULL`).
    store.revoke(target_b).await.expect("pre-revoke target_b");
    let pre_target_b_revoked: Option<(OffsetDateTime,)> =
        sqlx::query_as("SELECT revoked_at FROM api_keys WHERE id = $1")
            .bind(target_b)
            .fetch_one(&pool)
            .await
            .map(|r: (Option<OffsetDateTime>,)| r.0.map(|t| (t,)))
            .expect("fetch pre-revoke timestamp");
    let pre_target_b_revoked_at = pre_target_b_revoked.expect("target_b should be revoked").0;

    // Act.
    let n = store
        .revoke_all_for_tenant(&target)
        .await
        .expect("revoke_all_for_tenant");
    // Only target_a was live; target_b was already revoked.
    assert_eq!(
        n, 1,
        "revoke_all should affect exactly the one previously-live row in the target tenant",
    );

    // target_a is now revoked.
    let after_a: (Option<OffsetDateTime>,) =
        sqlx::query_as("SELECT revoked_at FROM api_keys WHERE id = $1")
            .bind(target_a)
            .fetch_one(&pool)
            .await
            .expect("fetch target_a");
    assert!(after_a.0.is_some(), "target_a should now be revoked");

    // target_b's revoked_at is unchanged (we did NOT re-stamp).
    let after_b: (Option<OffsetDateTime>,) =
        sqlx::query_as("SELECT revoked_at FROM api_keys WHERE id = $1")
            .bind(target_b)
            .fetch_one(&pool)
            .await
            .expect("fetch target_b");
    assert_eq!(
        after_b.0,
        Some(pre_target_b_revoked_at),
        "revoke_all_for_tenant must NOT re-stamp already-revoked rows",
    );

    // other-tenant row is untouched.
    let after_o: (Option<OffsetDateTime>,) =
        sqlx::query_as("SELECT revoked_at FROM api_keys WHERE id = $1")
            .bind(other_a)
            .fetch_one(&pool)
            .await
            .expect("fetch other_a");
    assert!(
        after_o.0.is_none(),
        "revoke_all_for_tenant must NOT touch other tenants' rows",
    );

    // Cleanup.
    sqlx::query("DELETE FROM api_keys WHERE tenant_id = ANY($1)")
        .bind(&[target, other][..])
        .execute(&pool)
        .await
        .ok();
}
