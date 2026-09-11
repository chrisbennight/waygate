//! Admin CRUD store smoke against real Postgres.
//!
//! Pins:
//!   1. Create / get / list / update / delete round-trip on a
//!      `scope=tenant` policy.
//!   2. Conflict on duplicate (tenant, scope, scope_value, action).
//!   3. delete_all_for_tenant sweeps every policy for the tenant
//!      AND cascades to rate_limit_counters via the FK ON DELETE
//!      CASCADE (so a re-created tenant id starts with empty
//!      bucket state).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_quota::{
    PgQuotaService, PgRateLimitPolicyStore, QuotaAction, QuotaContext, QuotaScope, QuotaService,
    RateLimitPolicyStore, RateLimitStoreError,
};

#[tokio::test]
async fn crud_round_trip_against_real_postgres() {
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

    let tenant = format!("test-quota-crud-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    let store = PgRateLimitPolicyStore::new(pool.clone());

    let created = store
        .create(
            &tenant,
            "tenant-broad",
            QuotaScope::Tenant,
            None,
            10,
            1.0,
            QuotaAction::Call,
        )
        .await
        .expect("create");
    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.scope, QuotaScope::Tenant);
    assert!(created.scope_value.is_none());

    let fetched = store
        .get(&tenant, created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(fetched, created);

    let list = store.list(&tenant).await.expect("list");
    assert_eq!(list.len(), 1);

    // Duplicate (tenant, scope, scope_value=NULL, action) → Conflict.
    let dup = store
        .create(
            &tenant,
            "tenant-broad-2",
            QuotaScope::Tenant,
            None,
            5,
            0.5,
            QuotaAction::Call,
        )
        .await;
    assert!(matches!(dup, Err(RateLimitStoreError::Conflict)));

    // Update only capacity; refill stays.
    let updated = store
        .update(&tenant, created.id, Some(20), None)
        .await
        .expect("update")
        .expect("present");
    assert_eq!(updated.bucket_capacity, 20);
    assert!((updated.refill_per_second - 1.0).abs() < f64::EPSILON);

    // Delete.
    let deleted = store.delete(&tenant, created.id).await.expect("delete");
    assert!(deleted);
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

// Pin the cleanup arm: delete_all_for_tenant must drop every
// policy AND cascade the counter rows so a re-created tenant id
// can't resurrect bucket state.
#[tokio::test]
async fn delete_all_for_tenant_cascades_to_counters() {
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

    let target = format!("test-quota-cleanup-target-{}", Uuid::new_v4());
    let other = format!("test-quota-cleanup-other-{}", Uuid::new_v4());
    for t in [&target, &other] {
        sqlx::query(
            "INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING",
        )
        .bind(t)
        .execute(&pool)
        .await
        .ok();
    }

    let store = PgRateLimitPolicyStore::new(pool.clone());
    // Seed two policies for the target tenant + one for the
    // other tenant.
    let _ = store
        .create(
            &target,
            "a",
            QuotaScope::Tenant,
            None,
            2,
            10.0,
            QuotaAction::Call,
        )
        .await
        .expect("seed target a");
    let _ = store
        .create(
            &target,
            "b",
            QuotaScope::Tool,
            Some("srv.t"),
            2,
            10.0,
            QuotaAction::Call,
        )
        .await
        .expect("seed target b");
    let other_policy = store
        .create(
            &other,
            "c",
            QuotaScope::Tenant,
            None,
            2,
            10.0,
            QuotaAction::Call,
        )
        .await
        .expect("seed other");

    // Warm the counters so the cascade has something to chew on.
    let quota = PgQuotaService::new(pool.clone());
    let ctx = QuotaContext {
        tenant_id: target.clone(),
        principal_sub: Some("s".into()),
        client_id: None,
        server: "srv".into(),
        fq_tool: "srv.t".into(),
    };
    quota
        .check_and_consume(&ctx, &[QuotaAction::Call])
        .await
        .expect("warm");

    let counters_before: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM rate_limit_counters c
            JOIN rate_limit_policies p ON c.policy_id = p.id
           WHERE p.tenant_id = $1",
    )
    .bind(&target)
    .fetch_one(&pool)
    .await
    .expect("count counters before");
    assert!(
        counters_before.0 >= 1,
        "warming should have created counter rows for the target tenant",
    );

    // Act.
    let n = store
        .delete_all_for_tenant(&target)
        .await
        .expect("delete_all_for_tenant");
    assert_eq!(n, 2, "both target policies should be deleted");

    let target_policies_left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM rate_limit_policies WHERE tenant_id = $1")
            .bind(&target)
            .fetch_one(&pool)
            .await
            .expect("count target policies");
    assert_eq!(target_policies_left.0, 0);

    let target_counters_left: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM rate_limit_counters c
            LEFT JOIN rate_limit_policies p ON c.policy_id = p.id
           WHERE p.tenant_id = $1 OR p.id IS NULL",
    )
    .bind(&target)
    .fetch_one(&pool)
    .await
    .expect("count target counters");
    assert_eq!(
        target_counters_left.0, 0,
        "ON DELETE CASCADE should sweep rate_limit_counters when the parent policy goes",
    );

    // Other tenant's policy untouched.
    let other_left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM rate_limit_policies WHERE id = $1")
            .bind(other_policy.id)
            .fetch_one(&pool)
            .await
            .expect("count other policy");
    assert_eq!(
        other_left.0, 1,
        "delete_all_for_tenant must not touch other tenants",
    );

    sqlx::query("DELETE FROM rate_limit_policies WHERE tenant_id = $1")
        .bind(&other)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
        .bind(&[target, other][..])
        .execute(&pool)
        .await
        .ok();
}
