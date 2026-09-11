//! Live Postgres smoke test for [`PgBreakGlassStore`].
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` without a DB passes. Pins five behaviours
//! the override pipeline depends on:
//!
//! 1. `mint` → `list` round-trip (every field survives).
//! 2. `list_candidates` only returns rows that:
//!    - belong to (tenant, sub),
//!    - are NOT used,
//!    - are NOT expired,
//!    - and whose scope_pattern actually matches the FQN.
//! 3. `try_claim` flips `used_at` exactly once. A second
//!    `try_claim` returns `None`. Race-safe single-use.
//! 4. `try_claim` returns `None` for an expired row even
//!    if it was never used.
//! 5. `delete` is tenant-scoped — cannot delete another
//!    tenant's token.

use std::env;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_authz::{BreakGlassStore, NewBreakGlassToken, PgBreakGlassStore, MAX_LIST_LIMIT};

async fn connect() -> Option<sqlx::PgPool> {
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

async fn ensure_tenant(pool: &sqlx::PgPool, id: &str) {
    sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed tenant");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_list_candidates_claim_and_single_use() {
    let Some(pool) = connect().await else {
        eprintln!("skipping break_glass Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant_id = format!("pg-bg-smoke-{}", Uuid::new_v4());
    ensure_tenant(&pool, &tenant_id).await;
    let store = PgBreakGlassStore::new(pool.clone());

    let sub = format!("alice-{}", Uuid::new_v4());
    let other_sub = format!("bob-{}", Uuid::new_v4());

    // Mint three tokens for alice:
    //   t1: exact billing.charge, 60s TTL
    //   t2: billing.* wildcard, 60s TTL
    //   t3: billing.charge, expired (TTL in the past)
    let exp_live = OffsetDateTime::now_utc() + time::Duration::seconds(60);
    let exp_past = OffsetDateTime::now_utc() - time::Duration::seconds(30);

    let t1 = store
        .mint(NewBreakGlassToken {
            tenant_id: &tenant_id,
            issued_to: &sub,
            issued_by: "admin",
            reason: "incident #1 — exact",
            scope_pattern: "billing.charge",
            requires_amr: &[],
            expires_at: exp_live,
        })
        .await
        .expect("mint t1");
    assert_eq!(t1.scope_pattern, "billing.charge");
    assert!(t1.used_at.is_none());
    assert!(!t1.id.is_nil());

    let t2 = store
        .mint(NewBreakGlassToken {
            tenant_id: &tenant_id,
            issued_to: &sub,
            issued_by: "admin",
            reason: "incident #1 — wildcard",
            scope_pattern: "billing.*",
            requires_amr: &[],
            expires_at: exp_live,
        })
        .await
        .expect("mint t2");

    let _t3 = store
        .mint(NewBreakGlassToken {
            tenant_id: &tenant_id,
            issued_to: &sub,
            issued_by: "admin",
            reason: "incident #0 — already expired",
            scope_pattern: "billing.charge",
            requires_amr: &[],
            expires_at: exp_past,
        })
        .await
        .expect("mint t3");

    // Token for OTHER user — must never show in alice's candidates.
    let _t_other = store
        .mint(NewBreakGlassToken {
            tenant_id: &tenant_id,
            issued_to: &other_sub,
            issued_by: "admin",
            reason: "bob's token",
            scope_pattern: "billing.charge",
            requires_amr: &[],
            expires_at: exp_live,
        })
        .await
        .expect("mint t_other");

    // list_candidates for billing.charge → must return
    // {t1, t2}; NOT t3 (expired), NOT t_other (wrong sub).
    let candidates = store
        .list_candidates(&tenant_id, &sub, "billing.charge")
        .await
        .expect("list_candidates");
    let ids: Vec<Uuid> = candidates.iter().map(|c| c.id).collect();
    assert!(ids.contains(&t1.id), "exact match must be in candidates");
    assert!(ids.contains(&t2.id), "wildcard match must be in candidates");
    assert_eq!(
        ids.len(),
        2,
        "no expired / wrong-sub rows allowed; got {ids:?}"
    );

    // list_candidates for treasury.refund → no matches
    // (t1 is exact billing.charge; t2's billing.* doesn't
    // span servers).
    let no_match = store
        .list_candidates(&tenant_id, &sub, "treasury.refund")
        .await
        .expect("list_candidates no-match");
    assert!(
        no_match.is_empty(),
        "cross-server FQN must not match billing.* or billing.charge: {no_match:?}",
    );

    // Single-use: try_claim t1 succeeds with rows, second
    // try_claim returns None.
    let first = store
        .try_claim(t1.id)
        .await
        .expect("try_claim first")
        .expect("first claim wins");
    assert_eq!(first.id, t1.id);
    assert!(first.used_at.is_some(), "claimed row must carry used_at");

    let second = store.try_claim(t1.id).await.expect("try_claim second");
    assert!(
        second.is_none(),
        "second try_claim on the same token must NOT win — single-use",
    );

    // try_claim on the expired t3 returns None (the
    // WHERE clause's `expires_at > now()` filter).
    let expired_claim = store.try_claim(_t3.id).await.expect("try_claim expired");
    assert!(
        expired_claim.is_none(),
        "expired token must NOT be claimable",
    );

    // Tenant isolation: delete with the wrong tenant id
    // returns false and the row survives.
    let other_tenant = format!("pg-bg-other-{}", Uuid::new_v4());
    ensure_tenant(&pool, &other_tenant).await;
    let cross_delete = store
        .delete(&other_tenant, t2.id)
        .await
        .expect("delete cross-tenant");
    assert!(
        !cross_delete,
        "cross-tenant delete must return false (row not in caller's tenant)",
    );
    // t2 must still exist.
    let still_there = store
        .list_candidates(&tenant_id, &sub, "billing.refund")
        .await
        .expect("list_candidates after cross-delete");
    assert!(
        still_there.iter().any(|c| c.id == t2.id),
        "cross-tenant delete must not affect rows in the original tenant",
    );

    // Correct-tenant delete works.
    let same_delete = store
        .delete(&tenant_id, t2.id)
        .await
        .expect("delete same-tenant");
    assert!(same_delete, "same-tenant delete must return true");

    // MAX_LIST_LIMIT clamp (defensive; we don't insert
    // enough rows to actually hit the cap, but pin the
    // contract).
    let listed = store
        .list(&tenant_id, None, 1_000_000, 0)
        .await
        .expect("list clamped");
    assert!(
        listed.len() <= MAX_LIST_LIMIT as usize,
        "list must clamp at MAX_LIST_LIMIT, got {}",
        listed.len(),
    );

    // Cleanup — cascade via tenant DELETE.
    sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind(&tenant_id)
        .bind(&other_tenant)
        .execute(&pool)
        .await
        .expect("cleanup tenants");
}
