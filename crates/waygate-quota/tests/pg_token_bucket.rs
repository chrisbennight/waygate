//! Token-bucket end-to-end smoke against real Postgres.
//!
//! Pins three contracts the unit tests in `src/lib.rs` can't
//! verify alone:
//!
//!   1. The atomic conditional UPDATE denies a call when the
//!      bucket is empty (`token_bucket_denies_when_empty`).
//!   2. The refill math credits tokens proportional to elapsed
//!      time, capped at capacity, so a paused caller gets back
//!      in (`token_bucket_refills_after_elapsed_time`).
//!   3. The scope_value match identifies the right bucket — a
//!      policy with scope=tool, scope_value='X.y' doesn't fire
//!      on calls to a different tool
//!      (`tool_scoped_policy_only_fires_on_matching_tool`).
//!
//! ## Determinism: never race wall-clock refill
//!
//! Refill is computed in SQL against the DB clock
//! (`tokens += EXTRACT(EPOCH FROM (now() - last_refill)) * rate`),
//! so any assertion whose outcome depends on *how much* real time
//! elapsed between two DB round-trips is a flake waiting to
//! happen (issue #368: a deny seeded at refill=10/s — 1 token per
//! 100 ms — flipped to *allow* when a loaded runner stalled for
//! more than 100 ms between the drain and the deny, because the
//! bucket had legitimately credited a token). Two rules keep every
//! assertion deterministic:
//!
//!   - **Deny legs (and the drains feeding them) use a negligible
//!     refill rate** (0.001/s = 1 token per ~1000 s), so an empty
//!     bucket cannot cross the 1-token boundary no matter how much
//!     jitter sits between calls. The deny becomes a property of
//!     the bucket being empty, not of the test running fast.
//!   - **Refill legs drive elapsed time explicitly** by backdating
//!     the counter's `last_refill` column, rather than sleeping and
//!     hoping the wall clock advanced the intended amount. The
//!     credited token count and the capacity cap become exact and
//!     checkable.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` on a laptop without a DB passes. Mirrors
//! `waygate-tenants::tests::pg_enforce_smoke`.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_quota::{PgQuotaService, QuotaAction, QuotaContext, QuotaError, QuotaService};

fn ctx(tenant: &str, fq_tool: &str) -> QuotaContext {
    QuotaContext {
        tenant_id: tenant.into(),
        principal_sub: Some("test-sub".into()),
        client_id: None,
        server: fq_tool
            .split_once('.')
            .map(|(s, _)| s)
            .unwrap_or("srv")
            .into(),
        fq_tool: fq_tool.into(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn seed_policy(
    pool: &sqlx::PgPool,
    tenant: &str,
    name: &str,
    scope: &str,
    scope_value: Option<&str>,
    capacity: i32,
    refill_per_second: f64,
    action: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO rate_limit_policies
            (id, tenant_id, name, scope, scope_value, bucket_capacity, refill_per_second, action)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(id)
    .bind(tenant)
    .bind(name)
    .bind(scope)
    .bind(scope_value)
    .bind(capacity)
    .bind(refill_per_second)
    .bind(action)
    .execute(pool)
    .await
    .expect("seed policy");
    id
}

#[tokio::test]
async fn token_bucket_denies_when_empty() {
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

    let tenant = format!("test-quota-deny-{}", Uuid::new_v4());
    // Seed the tenant row so a later FK from the rate-limit
    // tables onto tenants (none today, but plausible) doesn't fail.
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    // capacity=2, refill=0.001/s (1 token per ~1000 s). The
    // negligible refill is deliberate: it makes the third-call
    // deny a property of the bucket being EMPTY, not of the test
    // running fast. At 0.001/s the bucket would need ~1000 s of
    // jitter between the drain and the deny to credit a single
    // token, so no amount of CI scheduling stall can flip this
    // assertion — issue #368, where the old seed of refill=10/s
    // gave only a 100 ms window and flaked.
    let policy_id = seed_policy(
        &pool,
        &tenant,
        "smoke-call",
        "tenant",
        None,
        2,
        0.001,
        "call",
    )
    .await;

    let svc = PgQuotaService::new(pool.clone());

    // First two calls consume the full bucket.
    svc.check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("call 1");
    svc.check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("call 2");

    // Third call denied: the bucket is empty and the refill over
    // any realistic gap between round-trips is far below 1 token.
    let denied = svc
        .check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await;
    match denied {
        Err(QuotaError::RateLimited {
            policy_id: pid,
            retry_after_seconds,
            ..
        }) => {
            assert_eq!(pid, policy_id);
            assert!(retry_after_seconds >= 1);
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }

    // Cleanup.
    sqlx::query("DELETE FROM rate_limit_policies WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn token_bucket_refills_after_elapsed_time() {
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

    let tenant = format!("test-quota-refill-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    // capacity=2, refill=0.001/s. Same negligible rate as the deny
    // test so the drain leaves the bucket genuinely empty (the
    // refill accrued between two back-to-back round-trips is
    // ~gap*0.001 — well under 0.01 even on a badly stalled runner).
    // The refill under test is driven by backdating last_refill
    // below, not by this rate ticking in real time.
    let policy_id = seed_policy(
        &pool,
        &tenant,
        "smoke-refill",
        "tenant",
        None,
        2,
        0.001,
        "call",
    )
    .await;
    let svc = PgQuotaService::new(pool.clone());

    // Drain the bucket to empty.
    svc.check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("call 1");
    svc.check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("call 2");

    // Confirm the bucket really is empty before simulating the
    // pause. A SELECT does no refill, so this reads the stored
    // post-drain value deterministically — it proves the later
    // success is *caused* by refill, not a bucket that was never
    // emptied. scope='tenant' ⇒ the counter's bucket key is the
    // tenant_id.
    let (empty,): (f64,) = sqlx::query_as(
        "SELECT tokens_remaining FROM rate_limit_counters
           WHERE policy_id = $1 AND scope_value = $2",
    )
    .bind(policy_id)
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("counter row exists after drain");
    assert!(
        empty.abs() < 0.01,
        "bucket should be empty after draining capacity, got {empty}"
    );

    // Simulate ~5000 s of elapsed time DETERMINISTICALLY by
    // backdating last_refill, instead of sleeping and hoping the
    // wall clock advanced the intended amount. The next consume
    // computes refill against the DB clock exactly as production
    // does: credited = 5000 s * 0.001/s = 5 tokens, which LEAST()
    // then caps at the capacity of 2.
    sqlx::query(
        "UPDATE rate_limit_counters
            SET last_refill = now() - interval '5000 seconds'
          WHERE policy_id = $1 AND scope_value = $2",
    )
    .bind(policy_id)
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("backdate last_refill");

    // The paused caller is re-admitted.
    svc.check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("refill should re-admit one call");

    // And the capacity cap held: 5 credited, capped at 2, minus 1
    // consumed = 1 remaining. Without the LEAST() cap this would be
    // ~0 + 5 - 1 = 4, so asserting ~1 pins BOTH the refill math and
    // the capacity cap in a single check.
    let (after,): (f64,) = sqlx::query_as(
        "SELECT tokens_remaining FROM rate_limit_counters
           WHERE policy_id = $1 AND scope_value = $2",
    )
    .bind(policy_id)
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("counter row exists after refill");
    assert!(
        (after - 1.0).abs() < 0.01,
        "expected ~1 token remaining (5 credited, capped at 2, 1 spent), got {after}"
    );

    // Cleanup.
    sqlx::query("DELETE FROM rate_limit_policies WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

// Regression: when a request matches multiple layered policies
// and one denies, NO bucket should be debited. Setup:
//   - Policy A (scope=tenant): capacity 100, low refill — won't
//     deny on the first call (plenty of headroom).
//   - Policy B (scope=tool, scope_value="t.deny"): capacity 0
//     effectively, so the first call to t.deny ALWAYS denies.
// Call to t.deny: A would allow, B denies. After the call, A's
// counter row should NOT exist (or should still hold 100 tokens),
// proving the transaction rolled back A's debit.
#[tokio::test]
async fn cross_policy_rollback_undoes_debits_on_denial() {
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

    let tenant = format!("test-quota-rollback-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    let policy_a = seed_policy(
        &pool,
        &tenant,
        "tenant-broad",
        "tenant",
        None,
        100,
        1.0,
        "call",
    )
    .await;
    // Capacity 1 + refill 0.001/s + we'll call twice — the
    // second call will deny.
    let _policy_b = seed_policy(
        &pool,
        &tenant,
        "tool-deny",
        "tool",
        Some("t.deny"),
        1,
        0.001,
        "call",
    )
    .await;
    let svc = PgQuotaService::new(pool.clone());

    // First call: A allows (debits 1 of 100), B allows
    // (debits 1 of 1). Both buckets touched.
    svc.check_and_consume(&ctx(&tenant, "t.deny"), &[QuotaAction::Call])
        .await
        .expect("first call passes");

    let a_after_first: (f64,) = sqlx::query_as(
        "SELECT tokens_remaining FROM rate_limit_counters
         WHERE policy_id = $1 AND scope_value = $2",
    )
    .bind(policy_a)
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("A counter exists");
    assert!(
        (a_after_first.0 - 99.0).abs() < 0.01,
        "A should have 99 tokens after first call, got {}",
        a_after_first.0
    );

    // Second call: A would allow (~99 tokens), B denies (0 tokens,
    // negligible refill). With cross-policy rollback, A's counter
    // must NOT drop to 98.
    let denied = svc
        .check_and_consume(&ctx(&tenant, "t.deny"), &[QuotaAction::Call])
        .await;
    assert!(matches!(denied, Err(QuotaError::RateLimited { .. })));

    let a_after_denial: (f64,) = sqlx::query_as(
        "SELECT tokens_remaining FROM rate_limit_counters
         WHERE policy_id = $1 AND scope_value = $2",
    )
    .bind(policy_a)
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("A counter still exists");
    assert!(
        (a_after_denial.0 - 99.0).abs() < 0.1,
        "A's bucket MUST NOT have been debited by the denied call. \
         Expected ~99 tokens, got {}",
        a_after_denial.0,
    );

    sqlx::query("DELETE FROM rate_limit_policies WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn tool_scoped_policy_only_fires_on_matching_tool() {
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

    let tenant = format!("test-quota-toolscope-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1) ON CONFLICT DO NOTHING")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();

    // scope=tool, scope_value='email.send', capacity 1,
    // refill=0.001/s. Should fire on email.send and ONLY on
    // email.send. The negligible refill keeps the second-call
    // deny deterministic: a `weather.get` round-trip sits between
    // the two email.send calls, so a faster refill (the original
    // 1.0/s) could credit a token across a stalled runner and let
    // the second email.send through — the same wall-clock race as
    // issue #368, just with a 1 s window instead of 100 ms.
    let _ = seed_policy(
        &pool,
        &tenant,
        "tool-email-send",
        "tool",
        Some("email.send"),
        1,
        0.001,
        "call",
    )
    .await;
    let svc = PgQuotaService::new(pool.clone());

    // Burn the bucket for email.send.
    svc.check_and_consume(&ctx(&tenant, "email.send"), &[QuotaAction::Call])
        .await
        .expect("email.send call 1");

    // Different tool — should NOT match the policy.
    svc.check_and_consume(&ctx(&tenant, "weather.get"), &[QuotaAction::Call])
        .await
        .expect("weather.get untouched by tool-scoped policy");

    // Second email.send — denied by the empty bucket.
    let denied = svc
        .check_and_consume(&ctx(&tenant, "email.send"), &[QuotaAction::Call])
        .await;
    assert!(matches!(denied, Err(QuotaError::RateLimited { .. })));

    sqlx::query("DELETE FROM rate_limit_policies WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

/// The non-consuming probe: denies a genuinely exhausted bucket without
/// touching it, leans allow inside the refill margin, and treats a
/// never-used bucket as full.
#[tokio::test]
async fn non_consuming_probe_denies_beyond_margin_and_never_debits() {
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
    let tenant = format!("test-quota-probe-{}", Uuid::new_v4());

    // A never-used bucket probes as full.
    seed_policy(
        &pool,
        &tenant,
        "probe-call",
        "tenant",
        None,
        2,
        0.001,
        "call",
    )
    .await;
    let svc = PgQuotaService::new(pool.clone());
    svc.check(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("never-used bucket allows");

    // Drain it (negligible refill — deny legs must not race the clock),
    // then the probe denies WITHOUT consuming: the consuming check's
    // outcome afterwards is byte-for-byte what it would have been had
    // the probe never run (still denied, bucket still empty).
    svc.check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("call 1");
    svc.check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("call 2");
    let probe = svc
        .check(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await;
    assert!(
        matches!(probe, Err(QuotaError::RateLimited { .. })),
        "an empty bucket beyond the refill margin probes as denied"
    );
    let consume = svc
        .check_and_consume(&ctx(&tenant, "srv.t"), &[QuotaAction::Call])
        .await;
    assert!(
        matches!(consume, Err(QuotaError::RateLimited { .. })),
        "the probe's denial is one the consuming path also issues"
    );

    // Margin: a bucket refilling at >= 1 token/second never probes as
    // denied — its denial would be stale within the advisory window —
    // even when the instantaneous token count is below one.
    let tenant_fast = format!("test-quota-probe-fast-{}", Uuid::new_v4());
    seed_policy(
        &pool,
        &tenant_fast,
        "probe-fast",
        "tenant",
        None,
        2,
        1.5,
        "call",
    )
    .await;
    svc.check_and_consume(&ctx(&tenant_fast, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("fast call 1");
    svc.check_and_consume(&ctx(&tenant_fast, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("fast call 2");
    svc.check(&ctx(&tenant_fast, "srv.t"), &[QuotaAction::Call])
        .await
        .expect("a fast-refilling bucket probes as allowed inside the margin");
}
