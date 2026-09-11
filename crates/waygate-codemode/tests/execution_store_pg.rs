use std::time::Duration;

use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_codemode::{
    source_digest, DetachedExecutionSlot, ExecutionEventKind, ExecutionStatus, ExecutionStore,
    ExecutionTransition, NewExecution, NewExecutionEvent, OwnedInFlight, PgExecutionStore,
    ResumeExecution, RetryEquivalence, SourceArtifactOwner, SourceArtifactStore, StartExecution,
    StartExecutionResult, MAX_RETAINED_SOURCES_PER_OWNER, MAX_SOURCE_LOCATORS_PER_OWNER,
};
use waygate_tenants::{PgTenantStore, TenantStore};

async fn connect() -> Option<sqlx::PgPool> {
    waygate_test_support::pg::audit_pool_or_skip().await
}

async fn seed_tenant(pool: &sqlx::PgPool, suffix: &str) -> String {
    let tenant = format!("codemode-execution-{suffix}");
    sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(&tenant)
    .execute(pool)
    .await
    .expect("seed tenant");
    tenant
}

fn new_execution(tenant_id: &str, id: Uuid) -> NewExecution {
    NewExecution {
        program_input: None,
        id,
        tenant_id: tenant_id.to_owned(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
        source: None,
        source_digest: source_digest(execution_source()),
        execution_profile: json!({"name": "read_only", "nested_call_limit": 16}),
        sdk_contract_version: 1,
        runner_contract_version: 3,
        retention_until: OffsetDateTime::now_utc() + time::Duration::days(7),
    }
}

fn execution_source() -> &'static str {
    "return await connectors.weather.read({city: 'Austin'});"
}

fn event(kind: ExecutionEventKind) -> NewExecutionEvent {
    NewExecutionEvent {
        kind,
        step_number: None,
        call_id: None,
        attempt: None,
        detail: json!({}),
    }
}

async fn cleanup(pool: &sqlx::PgPool, tenant_id: &str) {
    let mut tx = pool.begin().await.expect("begin cleanup");
    sqlx::query("SET LOCAL app.codemode_retention_delete = 'enabled'")
        .execute(&mut *tx)
        .await
        .expect("enable transaction-local retention delete");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .expect("cleanup tenant");
    tx.commit().await.expect("commit cleanup");
}

#[tokio::test]
async fn retained_source_is_private_reusable_and_expires() {
    let Some(pool) = connect().await else {
        eprintln!("skipping retained source Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let owner = SourceArtifactOwner {
        tenant_id: tenant.clone(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
    };
    let source = "return rows.filter(row => row.enabled);";
    let digest = source_digest(source);

    let retained = store
        .retain_source(&owner, source, &digest, Duration::from_secs(3600))
        .await
        .expect("retain source");
    assert_eq!(retained.source, source);
    assert_eq!(retained.source_digest, digest);
    assert_eq!(
        store
            .resolve_source(&owner, &digest)
            .await
            .expect("resolve source")
            .expect("live source")
            .source,
        source
    );
    assert_eq!(
        store
            .resolve_source_expiry(&owner, &digest)
            .await
            .expect("resolve source expiry"),
        Some(retained.expires_at),
        "decision-shaped reads return the deadline without source bytes"
    );

    let other_issuer = SourceArtifactOwner {
        principal_issuer: "https://other-issuer.test".to_owned(),
        ..owner.clone()
    };
    assert!(store
        .resolve_source(&other_issuer, &digest)
        .await
        .expect("owner-scoped miss")
        .is_none());
    assert!(store
        .resolve_source_expiry(&other_issuer, &digest)
        .await
        .expect("owner-scoped expiry miss")
        .is_none());

    sqlx::query(
        "UPDATE codemode_source_artifacts SET expires_at = now() - interval '1 second' \
         WHERE tenant_id = $1 AND principal_issuer = $2 AND principal_sub = $3 \
         AND source_digest = $4",
    )
    .bind(&owner.tenant_id)
    .bind(&owner.principal_issuer)
    .bind(&owner.principal_sub)
    .bind(&digest)
    .execute(&pool)
    .await
    .expect("expire source");
    assert!(store
        .resolve_source(&owner, &digest)
        .await
        .expect("expired source lookup")
        .is_none());
    assert!(store
        .resolve_source_expiry(&owner, &digest)
        .await
        .expect("expired source expiry lookup")
        .is_none());

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn retained_source_owner_capacity_is_intrinsic_and_extensions_still_work() {
    let Some(pool) = connect().await else {
        eprintln!("skipping retained source capacity Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let owner = SourceArtifactOwner {
        tenant_id: tenant.clone(),
        principal_sub: "capacity-owner".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
    };
    sqlx::query(
        r#"
        INSERT INTO codemode_source_artifacts (
            tenant_id, principal_sub, principal_issuer,
            source_digest, source, expires_at
        )
        SELECT $1, $2, $3, lpad(to_hex(n), 64, '0'), 'return null;',
               now() + interval '1 hour'
          FROM generate_series(1, $4::integer) AS n
        "#,
    )
    .bind(&owner.tenant_id)
    .bind(&owner.principal_sub)
    .bind(&owner.principal_issuer)
    .bind(i32::try_from(MAX_RETAINED_SOURCES_PER_OWNER).expect("owner limit fits i32"))
    .execute(&pool)
    .await
    .expect("fill owner source capacity");

    let existing_digest = format!("{:064x}", 1);
    store
        .retain_source(
            &owner,
            "return null;",
            &existing_digest,
            Duration::from_secs(7200),
        )
        .await
        .expect("extending an existing hash consumes no new capacity");
    let new_source = "return 'new';";
    let error = store
        .retain_source(
            &owner,
            new_source,
            &source_digest(new_source),
            Duration::from_secs(3600),
        )
        .await
        .expect_err("a new hash is refused at the intrinsic owner ceiling");
    assert!(matches!(error, waygate_core::store::StoreError::Conflict));

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn source_locator_owner_capacity_is_intrinsic_and_extensions_still_work() {
    let Some(pool) = connect().await else {
        eprintln!("skipping source locator capacity Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let owner = SourceArtifactOwner {
        tenant_id: tenant.clone(),
        principal_sub: "locator-capacity-owner".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
    };
    sqlx::query(
        r#"
        INSERT INTO codemode_source_locators (
            tenant_id, principal_sub, principal_issuer,
            source_locator, source_digest, expires_at
        )
        SELECT $1, $2, $3, lpad(to_hex(n), 64, '0'),
               lpad(to_hex(n), 64, '0'), now() + interval '1 hour'
          FROM generate_series(1, $4::integer) AS n
        "#,
    )
    .bind(&owner.tenant_id)
    .bind(&owner.principal_sub)
    .bind(&owner.principal_issuer)
    .bind(i32::try_from(MAX_SOURCE_LOCATORS_PER_OWNER).expect("locator limit fits i32"))
    .execute(&pool)
    .await
    .expect("fill owner locator capacity");

    let existing = format!("{:064x}", 1);
    store
        .bind_source_locator(
            &owner,
            &existing,
            &existing,
            time::OffsetDateTime::now_utc() + time::Duration::hours(2),
        )
        .await
        .expect("extending an existing locator consumes no new capacity");
    let new_locator = format!("{:064x}", MAX_SOURCE_LOCATORS_PER_OWNER + 1);
    let error = store
        .bind_source_locator(
            &owner,
            &new_locator,
            &source_digest("return 'new';"),
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        )
        .await
        .expect_err("a new locator is refused at the intrinsic owner ceiling");
    assert!(matches!(error, waygate_core::store::StoreError::Conflict));

    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_principal_slot_is_cross_replica_and_holder_fenced() {
    let Some(pool) = connect().await else {
        eprintln!("skipping detached principal slot Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let replica_a = PgExecutionStore::new(pool.clone());
    let replica_b = PgExecutionStore::new(pool.clone());
    let slot_a = DetachedExecutionSlot {
        tenant_id: tenant.clone(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
        holder: Uuid::now_v7(),
    };
    let slot_b = DetachedExecutionSlot {
        holder: Uuid::now_v7(),
        ..slot_a.clone()
    };

    let (a, b) = tokio::join!(
        replica_a.acquire_detached_slot(&slot_a, Duration::from_secs(30)),
        replica_b.acquire_detached_slot(&slot_b, Duration::from_secs(30)),
    );
    let (a, b) = (
        a.expect("replica A acquisition"),
        b.expect("replica B acquisition"),
    );
    assert_ne!(a, b, "exactly one replica acquires the principal slot");
    let (winner_store, winner, loser_store, loser) = if a {
        (&replica_a, &slot_a, &replica_b, &slot_b)
    } else {
        (&replica_b, &slot_b, &replica_a, &slot_a)
    };
    assert!(
        !loser_store
            .release_detached_slot(loser)
            .await
            .expect("loser release probe"),
        "a non-holder cannot release the active replica's lease"
    );
    assert!(
        winner_store
            .acquire_detached_slot(winner, Duration::from_secs(30))
            .await
            .expect("winner renewal"),
        "the current holder can renew its lease"
    );

    let other_principal = DetachedExecutionSlot {
        principal_sub: "bob".to_owned(),
        holder: Uuid::now_v7(),
        ..slot_a.clone()
    };
    assert!(
        replica_b
            .acquire_detached_slot(&other_principal, Duration::from_secs(30))
            .await
            .expect("other-principal acquisition"),
        "another principal in the tenant retains an independent slot"
    );

    sqlx::query(
        r#"
        UPDATE codemode_detached_principal_slots
           SET lease_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1
           AND principal_sub = $2
           AND principal_issuer = $3
        "#,
    )
    .bind(&winner.tenant_id)
    .bind(&winner.principal_sub)
    .bind(&winner.principal_issuer)
    .execute(&pool)
    .await
    .expect("expire winner lease");
    assert!(
        loser_store
            .acquire_detached_slot(loser, Duration::from_secs(30))
            .await
            .expect("expired-slot takeover"),
        "an expired holder cannot strand the principal"
    );
    assert!(
        !winner_store
            .release_detached_slot(winner)
            .await
            .expect("stale-holder release probe"),
        "a stale holder cannot release its replacement's lease"
    );
    assert!(
        loser_store
            .release_detached_slot(loser)
            .await
            .expect("replacement release"),
        "the replacement holder releases its own lease"
    );
    assert!(replica_b
        .release_detached_slot(&other_principal)
        .await
        .expect("other-principal release"));
    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_principal_slot_renewal_extends_the_lease_and_is_holder_fenced() {
    let Some(pool) = connect().await else {
        eprintln!("skipping detached slot renewal Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let held = DetachedExecutionSlot {
        tenant_id: tenant.clone(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
        holder: Uuid::now_v7(),
    };
    assert!(store
        .acquire_detached_slot(&held, Duration::from_secs(1))
        .await
        .expect("acquire short-leased slot"));
    let stranger = DetachedExecutionSlot {
        holder: Uuid::now_v7(),
        ..held.clone()
    };
    assert!(
        !store
            .renew_detached_slot(&stranger, Duration::from_secs(30))
            .await
            .expect("stranger renewal probe"),
        "a non-holder cannot renew the active lease"
    );
    assert!(
        store
            .renew_detached_slot(&held, Duration::from_secs(30))
            .await
            .expect("holder renewal"),
        "the holder renews its own lease"
    );
    // Past the original one-second lease: only the renewal keeps the row
    // fenced against a contender's expired-lease takeover.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !store
            .acquire_detached_slot(&stranger, Duration::from_secs(30))
            .await
            .expect("contender acquisition after renewal"),
        "renewal must extend the lease beyond its original expiry"
    );

    sqlx::query(
        r#"
        UPDATE codemode_detached_principal_slots
           SET lease_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1
           AND principal_sub = $2
           AND principal_issuer = $3
        "#,
    )
    .bind(&held.tenant_id)
    .bind(&held.principal_sub)
    .bind(&held.principal_issuer)
    .execute(&pool)
    .await
    .expect("expire renewed lease");
    assert!(store
        .acquire_detached_slot(&stranger, Duration::from_secs(30))
        .await
        .expect("expired-slot takeover"));
    assert!(
        !store
            .renew_detached_slot(&held, Duration::from_secs(30))
            .await
            .expect("stale-holder renewal probe"),
        "a usurped holder cannot renew a replacement's lease"
    );
    assert!(store
        .release_detached_slot(&stranger)
        .await
        .expect("replacement release"));
    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_sweeps_long_abandoned_slots_but_preserves_recent_expiry() {
    let Some(pool) = connect().await else {
        eprintln!("skipping abandoned slot sweep Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let abandoned = DetachedExecutionSlot {
        tenant_id: tenant.clone(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
        holder: Uuid::now_v7(),
    };
    let recent = DetachedExecutionSlot {
        principal_sub: "bob".to_owned(),
        holder: Uuid::now_v7(),
        ..abandoned.clone()
    };
    for slot in [&abandoned, &recent] {
        assert!(store
            .acquire_detached_slot(slot, Duration::from_secs(1))
            .await
            .expect("acquire slot"));
    }
    sqlx::query(
        r#"
        UPDATE codemode_detached_principal_slots
           SET lease_expires_at = now() - interval '2 days'
         WHERE tenant_id = $1
           AND principal_sub = $2
        "#,
    )
    .bind(&abandoned.tenant_id)
    .bind(&abandoned.principal_sub)
    .execute(&pool)
    .await
    .expect("age the abandoned slot");
    sqlx::query(
        r#"
        UPDATE codemode_detached_principal_slots
           SET lease_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1
           AND principal_sub = $2
        "#,
    )
    .bind(&recent.tenant_id)
    .bind(&recent.principal_sub)
    .execute(&pool)
    .await
    .expect("expire the recent slot");

    // The sweep selects abandoned rows FOR UPDATE SKIP LOCKED inside the
    // submitting transaction, so a concurrent test's still-open submission
    // can hold the aged row's lock at this instant and leave it briefly
    // visible here. Re-running the sweep converges; in an isolated run a
    // broken sweep still fails this loop because nothing else ever removes
    // the row.
    let mut remaining: Vec<String> = Vec::new();
    for _ in 0..10 {
        store
            .submit(new_execution(&tenant, Uuid::now_v7()))
            .await
            .expect("submission runs the retention sweep");
        remaining = sqlx::query_scalar(
            r#"
            SELECT principal_sub
              FROM codemode_detached_principal_slots
             WHERE tenant_id = $1
            "#,
        )
        .bind(&tenant)
        .fetch_all(&pool)
        .await
        .expect("list surviving slots");
        if remaining == vec!["bob".to_owned()] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        remaining,
        vec!["bob".to_owned()],
        "the sweep removes long-abandoned rows and preserves recent expiry"
    );
    cleanup(&pool, &tenant).await;
}

fn start_request(tenant_id: &str, repeat_after: Option<Uuid>) -> StartExecution {
    StartExecution {
        execution: new_execution(tenant_id, Uuid::now_v7()),
        dedupe_key: format!("start-{tenant_id}"),
        source_locator: None,
        repeat_after,
        owner: Uuid::now_v7(),
        lease: Duration::from_secs(30),
        source: execution_source().to_owned(),
        tool_snapshot: json!([]),
    }
}

fn retry_probe(tenant_id: &str) -> RetryEquivalence {
    let template = new_execution(tenant_id, Uuid::nil());
    RetryEquivalence {
        tenant_id: template.tenant_id,
        principal_sub: template.principal_sub,
        principal_issuer: template.principal_issuer,
        dedupe_key: format!("start-{tenant_id}"),
        source_digest: template.source_digest,
        execution_profile: template.execution_profile,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_or_reuse_converges_retries_and_distinguishes_repetition() {
    let Some(pool) = connect().await else {
        eprintln!("skipping retry-safe start Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let source_locator = source_digest("mcp-file\u{1f}retry-source");
    let mut first_request = start_request(&tenant, None);
    first_request.source_locator = Some(source_locator.clone());

    let first = match store
        .start_or_reuse(first_request)
        .await
        .expect("first start")
    {
        StartExecutionResult::Claimed { execution, claim } => {
            assert_eq!(execution.status, ExecutionStatus::Running);
            assert_eq!(claim.epoch, execution.claim_epoch);
            assert_eq!(Some(claim.owner), execution.claim_owner);
            execution
        }
        other => panic!("first start must claim, got {other:?}"),
    };
    let owner = SourceArtifactOwner {
        tenant_id: tenant.clone(),
        principal_sub: first.principal_sub.clone(),
        principal_issuer: first
            .principal_issuer
            .clone()
            .expect("new execution issuer"),
    };
    assert_eq!(
        store
            .resolve_source_locator(&owner, &source_locator)
            .await
            .expect("resolve source locator"),
        Some(first.source_digest.clone()),
        "admission durably binds the immutable upload identity to exact bytes"
    );
    let mut other_owner = owner.clone();
    other_owner.principal_sub.push_str("-other");
    assert!(
        store
            .resolve_source_locator(&other_owner, &source_locator)
            .await
            .expect("resolve other owner's source locator")
            .is_none(),
        "source locator bindings are private to the full owner"
    );
    assert_eq!(
        store
            .find_retry_equivalent(&retry_probe(&tenant), None)
            .await
            .expect("probe after first start")
            .map(|execution| execution.id),
        Some(first.id),
        "the probe sees the retained start"
    );
    match store
        .start_or_reuse(start_request(&tenant, None))
        .await
        .expect("retry")
    {
        StartExecutionResult::Existing(execution) => assert_eq!(
            execution.id, first.id,
            "a retry converges on the original execution"
        ),
        other => panic!("a retry must converge, got {other:?}"),
    }

    match store
        .start_or_reuse(start_request(&tenant, Some(first.id)))
        .await
        .expect("premature repetition")
    {
        StartExecutionResult::RepeatNotTerminal(execution) => assert_eq!(execution.id, first.id),
        other => panic!("repeating a running execution must refuse, got {other:?}"),
    }
    match store
        .start_or_reuse(start_request(&tenant, Some(Uuid::now_v7())))
        .await
        .expect("unknown repetition")
    {
        StartExecutionResult::RepeatUnavailable => {}
        other => panic!("an unknown repeat handle must refuse, got {other:?}"),
    }

    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET status = 'succeeded', completed_at = now(),
               claim_owner = NULL, claim_expires_at = NULL
         WHERE id = $1
        "#,
    )
    .bind(first.id)
    .execute(&pool)
    .await
    .expect("terminalize the first execution");

    let second = match store
        .start_or_reuse(start_request(&tenant, Some(first.id)))
        .await
        .expect("deliberate repetition")
    {
        StartExecutionResult::Claimed { execution, .. } => {
            assert_ne!(execution.id, first.id, "a repetition is new work");
            execution
        }
        other => panic!("naming the latest terminal execution must claim, got {other:?}"),
    };

    match store
        .start_or_reuse(start_request(&tenant, Some(first.id)))
        .await
        .expect("repetition retry")
    {
        StartExecutionResult::Existing(execution) => assert_eq!(
            execution.id, second.id,
            "a lost-response repetition retry converges on the newer handle"
        ),
        other => panic!("a repetition retry must converge, got {other:?}"),
    }
    assert_eq!(
        store
            .find_retry_equivalent(&retry_probe(&tenant), None)
            .await
            .expect("probe after repetition")
            .map(|execution| execution.id),
        Some(second.id),
        "the probe reports the newest chain member"
    );

    let mut different = start_request(&tenant, None);
    different.execution.source_digest = source_digest("return 'other';");
    match store
        .start_or_reuse(different)
        .await
        .expect("different program")
    {
        StartExecutionResult::Claimed { .. } => {}
        other => panic!("a different program must not converge, got {other:?}"),
    }

    // Chain membership is decided under the same dedupe-key and retention
    // predicate as `start_or_reuse`: an ordinary blocking execution with a
    // NULL key never passes as a member even with an identical digest and
    // profile, and an expired chain row stops being one.
    let blocking = store
        .submit(new_execution(&tenant, Uuid::now_v7()))
        .await
        .expect("ordinary blocking submission");
    assert!(
        store
            .find_retry_equivalent(&retry_probe(&tenant), Some(blocking.id))
            .await
            .expect("blocking membership probe")
            .is_none(),
        "a NULL-keyed blocking execution is not a chain member"
    );
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET retention_until = now() - interval '1 second'
         WHERE id = $1
        "#,
    )
    .bind(first.id)
    .execute(&pool)
    .await
    .expect("expire the first chain member");
    assert!(
        store
            .find_retry_equivalent(&retry_probe(&tenant), Some(first.id))
            .await
            .expect("expired membership probe")
            .is_none(),
        "an expired row is no longer a chain member"
    );
    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn racing_retry_equivalent_starts_claim_exactly_once() {
    let Some(pool) = connect().await else {
        eprintln!("skipping racing retry-safe start Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let replica_a = PgExecutionStore::new(pool.clone());
    let replica_b = PgExecutionStore::new(pool.clone());

    // Nothing but the store's own serialization prevents two overlapping
    // retry-equivalent starts from both inserting: the dedupe index is not
    // unique. One overlapping pair can still interleave serially by luck, so
    // the race repeats on fresh keys; every round must produce exactly one
    // claim and one retained row.
    for round in 0..10 {
        let dedupe_key = format!("race-{tenant}-{round}");
        let mut left = start_request(&tenant, None);
        left.dedupe_key.clone_from(&dedupe_key);
        let mut right = start_request(&tenant, None);
        right.dedupe_key.clone_from(&dedupe_key);

        let (left, right) = tokio::join!(
            replica_a.start_or_reuse(left),
            replica_b.start_or_reuse(right),
        );
        let mut claimed = None;
        let mut converged = None;
        for outcome in [left.expect("left racer"), right.expect("right racer")] {
            match outcome {
                StartExecutionResult::Claimed { execution, .. } => assert!(
                    claimed.replace(execution.id).is_none(),
                    "only one racer may claim"
                ),
                StartExecutionResult::Existing(execution) => assert!(
                    converged.replace(execution.id).is_none(),
                    "only one racer converges"
                ),
                other => panic!("a racing start must claim or converge, got {other:?}"),
            }
        }
        assert_eq!(
            converged,
            Some(claimed.expect("one racer claims")),
            "the losing racer converges on the winner's execution"
        );
        let retained: i64 = sqlx::query_scalar(
            r#"
            SELECT count(*)
              FROM codemode_executions
             WHERE tenant_id = $1
               AND start_dedupe_key = $2
            "#,
        )
        .bind(&tenant)
        .bind(&dedupe_key)
        .fetch_one(&pool)
        .await
        .expect("count retained chain members");
        assert_eq!(retained, 1, "a raced start retains exactly one execution");
    }
    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owned_in_flight_listing_is_identity_scoped_and_keyset_bounded() {
    let Some(pool) = connect().await else {
        eprintln!("skipping owned in-flight listing Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());

    let confined_profile = |confinement: serde_json::Value| {
        json!({
            "name": "read_only",
            "nested_call_limit": 16,
            "profile_confinement": confinement,
        })
    };
    // Every excluded row below carries the caller's confinement (or differs
    // in nothing but the predicate under test), so each absence is
    // attributable to exactly one clause rather than to an accidental
    // profile mismatch.
    let mut mine = Vec::new();
    for minutes_ago in [3i32, 2, 1] {
        let mut execution = new_execution(&tenant, Uuid::now_v7());
        execution.execution_profile = confined_profile(json!(null));
        let submitted = store.submit(execution).await.expect("submit mine");
        sqlx::query(
            r#"
            UPDATE codemode_executions
               SET submitted_at = now() - ($2::int * interval '1 minute')
             WHERE id = $1
            "#,
        )
        .bind(submitted.id)
        .bind(minutes_ago)
        .execute(&pool)
        .await
        .expect("spread submission times");
        mine.push(
            store
                .get(&tenant, submitted.id)
                .await
                .expect("re-read spread row")
                .expect("spread row exists"),
        );
    }

    let mut terminal = new_execution(&tenant, Uuid::now_v7());
    terminal.execution_profile = confined_profile(json!(null));
    let terminal = store.submit(terminal).await.expect("submit terminal row");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET status = 'succeeded', completed_at = now()
         WHERE id = $1
        "#,
    )
    .bind(terminal.id)
    .execute(&pool)
    .await
    .expect("terminalize row");

    let mut expired = new_execution(&tenant, Uuid::now_v7());
    expired.execution_profile = confined_profile(json!(null));
    let expired = store.submit(expired).await.expect("submit expired row");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET retention_until = now() - interval '1 second'
         WHERE id = $1
        "#,
    )
    .bind(expired.id)
    .execute(&pool)
    .await
    .expect("expire row");

    let mut other_sub = new_execution(&tenant, Uuid::now_v7());
    other_sub.principal_sub = "bob".to_owned();
    other_sub.execution_profile = confined_profile(json!(null));
    store.submit(other_sub).await.expect("submit other-sub row");

    let mut other_issuer = new_execution(&tenant, Uuid::now_v7());
    other_issuer.principal_issuer = "https://other-issuer.test".to_owned();
    other_issuer.execution_profile = confined_profile(json!(null));
    store
        .submit(other_issuer)
        .await
        .expect("submit other-issuer row");

    let mut legacy = new_execution(&tenant, Uuid::now_v7());
    legacy.execution_profile = confined_profile(json!(null));
    let legacy = store.submit(legacy).await.expect("submit legacy row");
    sqlx::query("UPDATE codemode_executions SET principal_issuer = NULL WHERE id = $1")
        .bind(legacy.id)
        .execute(&pool)
        .await
        .expect("simulate pre-upgrade issuer-less row");

    // The by-id read treats a profile without the confinement key as owned
    // by no caller; the listing must not enumerate what retrieval refuses.
    store
        .submit(new_execution(&tenant, Uuid::now_v7()))
        .await
        .expect("submit keyless-profile row");

    let restriction = json!({"allowed_servers": ["docs"], "allowed_tools": []});
    let mut restricted = new_execution(&tenant, Uuid::now_v7());
    restricted.execution_profile = confined_profile(restriction.clone());
    let restricted = store
        .submit(restricted)
        .await
        .expect("submit restricted-profile row");

    let owner = OwnedInFlight {
        tenant_id: tenant.clone(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
        profile_confinement: json!(null),
    };
    let listed = store
        .list_owned_in_flight(&owner, None, 10)
        .await
        .expect("full listing");
    assert_eq!(
        listed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![mine[2].id, mine[1].id, mine[0].id],
        "only the caller's matching in-flight rows are listed, newest first"
    );

    let first_page = store
        .list_owned_in_flight(&owner, None, 2)
        .await
        .expect("first page");
    assert_eq!(
        first_page.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![mine[2].id, mine[1].id],
        "the page bound truncates without reordering"
    );
    let tail = first_page.last().expect("page tail");
    let second_page = store
        .list_owned_in_flight(&owner, Some((tail.submitted_at, tail.id)), 2)
        .await
        .expect("second page");
    assert_eq!(
        second_page.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![mine[0].id],
        "the keyset bound resumes exactly after the prior page"
    );
    let exhausted = store
        .list_owned_in_flight(
            &owner,
            Some((second_page[0].submitted_at, second_page[0].id)),
            2,
        )
        .await
        .expect("exhausted page");
    assert!(
        exhausted.is_empty(),
        "paging past the last row yields nothing"
    );

    let confined_owner = OwnedInFlight {
        profile_confinement: restriction,
        ..owner.clone()
    };
    assert_eq!(
        store
            .list_owned_in_flight(&confined_owner, None, 10)
            .await
            .expect("confined listing")
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![restricted.id],
        "a confined caller sees exactly the rows sharing its confinement"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owned_in_flight_listing_admits_confinements_larger_than_an_index_tuple() {
    let Some(pool) = connect().await else {
        eprintln!("skipping oversized confinement Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());

    // A profile's allowlists have no size bound, and a B-tree rejects index
    // tuples above roughly a third of a page. This confinement is far past
    // that ceiling, so the row only stores and lists if the owned in-flight
    // index keys a digest of the confinement rather than its raw JSON.
    let tools: Vec<String> = (0..200)
        .map(|i| format!("server-{i:03}.{}", "t".repeat(240)))
        .collect();
    let confinement = json!({"allowed_servers": [], "allowed_tools": tools});
    let mut execution = new_execution(&tenant, Uuid::now_v7());
    execution.execution_profile = json!({
        "name": "read_only",
        "nested_call_limit": 16,
        "profile_confinement": confinement,
    });
    let submitted = store
        .submit(execution)
        .await
        .expect("a valid confinement larger than an index tuple stores");

    let owner = OwnedInFlight {
        tenant_id: tenant.clone(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
        profile_confinement: confinement,
    };
    assert_eq!(
        store
            .list_owned_in_flight(&owner, None, 10)
            .await
            .expect("oversized-confinement listing")
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![submitted.id],
        "the caller lists exactly its own row under the oversized confinement"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_listing_spans_principals_and_respects_tenancy_and_liveness() {
    let Some(pool) = connect().await else {
        eprintln!("skipping operator listing Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let other_tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());

    let older = store
        .submit(new_execution(&tenant, Uuid::now_v7()))
        .await
        .expect("submit alice's row");
    sqlx::query(
        "UPDATE codemode_executions SET submitted_at = now() - interval '2 minutes' WHERE id = $1",
    )
    .bind(older.id)
    .execute(&pool)
    .await
    .expect("age alice's row");
    let mut bobs = new_execution(&tenant, Uuid::now_v7());
    bobs.principal_sub = "bob".to_owned();
    let bobs = store.submit(bobs).await.expect("submit bob's row");
    let _ = store
        .claim(
            &tenant,
            bobs.id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim bob's row")
        .expect("bob's claim succeeds");

    let terminal = store
        .submit(new_execution(&tenant, Uuid::now_v7()))
        .await
        .expect("submit terminal row");
    sqlx::query(
        "UPDATE codemode_executions SET status = 'succeeded', completed_at = now() WHERE id = $1",
    )
    .bind(terminal.id)
    .execute(&pool)
    .await
    .expect("terminalize row");
    let expired = store
        .submit(new_execution(&tenant, Uuid::now_v7()))
        .await
        .expect("submit expired row");
    store
        .submit(new_execution(&other_tenant, Uuid::now_v7()))
        .await
        .expect("submit other-tenant row");
    // Backdated only after the last submission: every submit runs the
    // retention sweep, which would delete an already-expired row and make
    // the exclusion assertion vacuous — the listing's own retention
    // predicate must be what hides this row.
    sqlx::query(
        "UPDATE codemode_executions SET retention_until = now() - interval '1 second' WHERE id = $1",
    )
    .bind(expired.id)
    .execute(&pool)
    .await
    .expect("expire row");

    let listed = store
        .list_in_flight_for_operator(&tenant, None, 10, 0)
        .await
        .expect("operator listing");
    assert_eq!(
        listed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![bobs.id, older.id],
        "the operator sees every principal's live in-flight rows in the tenant, newest first, \
         and never terminal, expired, or foreign-tenant rows"
    );
    let bob_row = &listed[0];
    assert_eq!(bob_row.principal_sub, "bob");
    assert!(bob_row.claimed, "a live worker claim is visible");
    assert!(bob_row.claim_expires_at.is_some());
    assert!(!listed[1].claimed, "an unclaimed submission shows no claim");

    assert_eq!(
        store
            .list_in_flight_for_operator(&tenant, Some("alice"), 10, 0)
            .await
            .expect("filtered operator listing")
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![older.id],
        "the subject filter narrows to one principal"
    );
    assert_eq!(
        store
            .list_in_flight_for_operator(&tenant, None, 1, 1)
            .await
            .expect("offset operator listing")
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![older.id],
        "offset paging resumes after the prior page"
    );

    cleanup(&pool, &tenant).await;
    cleanup(&pool, &other_tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_cancellation_is_tenant_scoped_and_names_the_operator() {
    let Some(pool) = connect().await else {
        eprintln!("skipping operator cancellation Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let other_tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());

    let unclaimed = store
        .submit(new_execution(&tenant, Uuid::now_v7()))
        .await
        .expect("submit unclaimed row");
    assert!(
        store
            .request_cancellation_for_operator(&other_tenant, unclaimed.id, "op-admin")
            .await
            .expect("cross-tenant cancellation attempt")
            .is_none(),
        "tenant scoping fences the operator authority"
    );
    let cancelled = store
        .request_cancellation_for_operator(&tenant, unclaimed.id, "op-admin")
        .await
        .expect("cancel unclaimed row")
        .expect("row exists in the tenant");
    assert_eq!(cancelled.status, ExecutionStatus::Cancelled);
    assert_eq!(
        cancelled.terminal_reason_code.as_deref(),
        Some("cancelled_by_operator"),
        "an operator cancellation is distinguishable from the owner's"
    );
    let events = store
        .events(&tenant, unclaimed.id)
        .await
        .expect("read cancellation history");
    let request = events
        .iter()
        .find(|e| e.kind == "cancellation_requested")
        .expect("request event recorded");
    assert_eq!(
        request.detail.get("operator_sub").and_then(|v| v.as_str()),
        Some("op-admin"),
        "the journal names the operator who intervened"
    );
    assert!(
        events.iter().any(|e| e.kind == "cancelled"),
        "immediate cancellation records the terminal event"
    );

    let claimed_id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, claimed_id))
        .await
        .expect("submit claimed row");
    let _ = store
        .claim(
            &tenant,
            claimed_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim row")
        .expect("claim succeeds");
    let requested = store
        .request_cancellation_for_operator(&tenant, claimed_id, "op-admin")
        .await
        .expect("cancel claimed row")
        .expect("row exists");
    assert_eq!(
        requested.status,
        ExecutionStatus::Running,
        "a live claim keeps its lease; the runner observes the request"
    );
    assert!(requested.cancellation_requested_at.is_some());
    assert_eq!(
        requested.cancellation_reason_code.as_deref(),
        Some("cancelled_by_operator"),
        "provenance is durable for the runner's later finalization"
    );

    cleanup(&pool, &tenant).await;
    cleanup(&pool, &other_tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_history_is_tenant_scoped_and_terminal_is_monotonic() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode execution store Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant = seed_tenant(&pool, &suffix).await;
    let other_tenant = seed_tenant(&pool, &format!("other-{suffix}")).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();

    let submitted = store
        .submit(new_execution(&tenant, id))
        .await
        .expect("submit execution");
    assert_eq!(submitted.status, ExecutionStatus::Submitted);
    assert!(submitted.source.is_none());
    assert_eq!(submitted.source_digest, source_digest(execution_source()));
    assert!(store
        .get(&other_tenant, id)
        .await
        .expect("cross-tenant get")
        .is_none());

    let owner = Uuid::now_v7();
    let (_, claim) = store
        .claim(
            &tenant,
            id,
            owner,
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"tools": [{"connector": "weather", "operation": "read"}]}),
        )
        .await
        .expect("claim execution")
        .expect("claim admitted");
    assert_eq!(
        store
            .get(&tenant, id)
            .await
            .expect("read admitted execution")
            .expect("admitted execution exists")
            .source
            .as_deref(),
        Some(execution_source())
    );
    let call_id = Uuid::now_v7();
    assert!(store
        .append_event(
            &claim,
            NewExecutionEvent {
                kind: ExecutionEventKind::ConnectorCallSucceeded,
                step_number: Some(1),
                call_id: Some(call_id),
                attempt: Some(1),
                detail: json!({"result": "bounded-reference"}),
            },
        )
        .await
        .expect("append call result"));
    let artifact_id = Uuid::now_v7();
    assert!(store
        .append_event(
            &claim,
            NewExecutionEvent {
                kind: ExecutionEventKind::ArtifactEmitted,
                step_number: None,
                call_id: None,
                attempt: None,
                detail: json!({
                    "artifact_id": artifact_id,
                    "value": {"kind": "preview", "rows": [1, 2]},
                }),
            },
        )
        .await
        .expect("append artifact"));

    let succeeded = store
        .transition(
            &claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::Succeeded,
                event: event(ExecutionEventKind::Succeeded),
                terminal_reason_code: None,
                result_metadata: Some(json!({"stored": false, "connector_calls": 1})),
                result_payload: Some(json!({"execution_id": id, "result": 42})),
                resume_context: None,
            },
        )
        .await
        .expect("finish execution")
        .expect("claim remains current");
    assert_eq!(succeeded.status, ExecutionStatus::Succeeded);
    assert!(succeeded.completed_at.is_some());
    assert!(succeeded.claim_owner.is_none());
    assert_eq!(
        succeeded.result_payload,
        Some(json!({"execution_id": id, "result": 42}))
    );

    assert!(store
        .transition(
            &claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Succeeded],
                to: ExecutionStatus::Failed,
                event: event(ExecutionEventKind::Failed),
                terminal_reason_code: Some("late_failure".to_owned()),
                result_metadata: None,
                result_payload: None,
                resume_context: None,
            },
        )
        .await
        .expect("terminal CAS")
        .is_none());

    let history = store.events(&tenant, id).await.expect("read history");
    assert_eq!(
        history
            .iter()
            .map(|entry| entry.kind.as_str())
            .collect::<Vec<_>>(),
        [
            "submitted",
            "admitted",
            "claimed",
            "running",
            "connector_call_succeeded",
            "artifact_emitted",
            "succeeded",
        ]
    );
    let artifact = history
        .iter()
        .find(|entry| entry.kind == "artifact_emitted")
        .expect("artifact remains in append-only history");
    assert_eq!(artifact.detail["artifact_id"], artifact_id.to_string());
    assert_eq!(
        artifact.detail["value"],
        json!({"kind": "preview", "rows": [1, 2]})
    );
    let artifact_page = store
        .list_artifacts(&tenant, id, None, 10)
        .await
        .expect("list artifact references without materializing content");
    assert_eq!(artifact_page.len(), 1);
    assert_eq!(artifact_page[0].artifact_id, artifact_id);
    let stored_artifact = store
        .get_artifact(&tenant, id, artifact_id)
        .await
        .expect("retrieve artifact content")
        .expect("artifact exists");
    assert_eq!(
        stored_artifact.value,
        json!({"kind": "preview", "rows": [1, 2]})
    );
    assert!(store
        .events(&other_tenant, id)
        .await
        .expect("cross-tenant history")
        .is_empty());

    cleanup(&pool, &tenant).await;
    cleanup(&pool, &other_tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_is_owner_scoped_and_stops_unclaimed_or_claimed_work() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode cancellation Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());

    let submitted_id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, submitted_id))
        .await
        .expect("submit unclaimed execution");
    assert!(store
        .request_cancellation(&tenant, "mallory", "https://issuer.test", submitted_id)
        .await
        .expect("wrong-owner cancellation")
        .is_none());
    let cancelled = store
        .request_cancellation(&tenant, "alice", "https://issuer.test", submitted_id)
        .await
        .expect("cancel unclaimed execution")
        .expect("owner sees execution");
    assert_eq!(cancelled.status, ExecutionStatus::Cancelled);
    assert_eq!(
        store
            .events(&tenant, submitted_id)
            .await
            .expect("unclaimed cancellation history")
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        ["submitted", "cancellation_requested", "cancelled"],
    );
    store
        .request_cancellation(&tenant, "alice", "https://issuer.test", submitted_id)
        .await
        .expect("idempotent cancellation");
    assert_eq!(
        store
            .events(&tenant, submitted_id)
            .await
            .expect("idempotent cancellation history")
            .len(),
        3,
    );

    let running_id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, running_id))
        .await
        .expect("submit claimed execution");
    let (_, claim) = store
        .claim(
            &tenant,
            running_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"snapshot": 1}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    let requested = store
        .request_cancellation(&tenant, "alice", "https://issuer.test", running_id)
        .await
        .expect("request running cancellation")
        .expect("running execution exists");
    assert_eq!(requested.status, ExecutionStatus::Running);
    assert!(requested.cancellation_requested_at.is_some());
    assert!(!store
        .append_event(
            &claim,
            NewExecutionEvent {
                kind: ExecutionEventKind::StepStarted,
                step_number: Some(1),
                call_id: None,
                attempt: None,
                detail: json!({}),
            },
        )
        .await
        .expect("post-cancellation progress fence"));
    assert!(store
        .transition(
            &claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::Succeeded,
                event: event(ExecutionEventKind::Succeeded),
                terminal_reason_code: None,
                result_metadata: Some(json!({"connector_calls": 0})),
                result_payload: Some(json!({"result": "must not commit"})),
                resume_context: None,
            },
        )
        .await
        .expect("post-cancellation success fence")
        .is_none());
    let cancelled = store
        .transition(
            &claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::Cancelled,
                event: event(ExecutionEventKind::Cancelled),
                terminal_reason_code: Some("cancelled_by_client".to_owned()),
                result_metadata: None,
                result_payload: None,
                resume_context: None,
            },
        )
        .await
        .expect("worker acknowledges cancellation")
        .expect("worker claim remains current");
    assert_eq!(cancelled.status, ExecutionStatus::Cancelled);

    let expired_id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, expired_id))
        .await
        .expect("submit crash-recovery execution");
    store
        .claim(
            &tenant,
            expired_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"snapshot": 1}),
        )
        .await
        .expect("claim crash-recovery execution")
        .expect("claim succeeds");
    let requested = store
        .request_cancellation(&tenant, "alice", "https://issuer.test", expired_id)
        .await
        .expect("request cancellation before worker loss")
        .expect("running execution exists");
    assert_eq!(requested.status, ExecutionStatus::Running);
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET claim_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(expired_id)
    .execute(&pool)
    .await
    .expect("expire abandoned worker claim");
    let recovered = store
        .request_cancellation(&tenant, "alice", "https://issuer.test", expired_id)
        .await
        .expect("repeat cancellation after claim expiry")
        .expect("execution remains visible to owner");
    assert_eq!(recovered.status, ExecutionStatus::Cancelled);
    assert!(recovered.claim_owner.is_none());
    assert_eq!(
        store
            .events(&tenant, expired_id)
            .await
            .expect("expired-claim cancellation history")
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        [
            "submitted",
            "admitted",
            "claimed",
            "running",
            "cancellation_requested",
            "cancelled",
        ],
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn paused_execution_resumes_once_with_bound_context_and_a_new_fence() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode resume Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let tool_snapshot = json!({
        "contract_version": 1,
        "bindings": [{"connector": "weather", "operation": "read"}],
    });
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "read_only", "resumable": true});
    submitted.runner_contract_version = 4;
    store.submit(submitted).await.expect("submit execution");
    let (_, first_claim) = store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            tool_snapshot.clone(),
        )
        .await
        .expect("claim execution")
        .expect("initial claim succeeds");
    let checkpoint = json!({
        "checkpoint": {
            "prompt": "Choose a region",
            "state": {"candidate_ids": [1, 2]},
        },
    });
    let paused = store
        .transition(
            &first_claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::WaitingForResume,
                event: event(ExecutionEventKind::WaitingForResume),
                terminal_reason_code: None,
                result_metadata: Some(json!({"connector_calls": 1})),
                result_payload: None,
                resume_context: Some(checkpoint.clone()),
            },
        )
        .await
        .expect("pause execution")
        .expect("pause fence is current");
    assert_eq!(paused.status, ExecutionStatus::WaitingForResume);
    assert!(paused.claim_owner.is_none());

    let resume_context = json!({
        "checkpoint": checkpoint["checkpoint"],
        "input": {"region": "west"},
    });
    let expected_claim_epoch = paused.claim_epoch;
    let expected_resume_context = paused.resume_context.clone();
    let delayed_resume = ResumeExecution {
        tenant_id: tenant.clone(),
        principal_sub: "alice".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
        id,
        owner: Uuid::now_v7(),
        lease: Duration::from_secs(30),
        expected_status: ExecutionStatus::WaitingForResume,
        resume_context: json!({
            "checkpoint": checkpoint["checkpoint"],
            "input": {"region": "delayed"},
        }),
        expected_claim_epoch,
        expected_resume_context: expected_resume_context.clone(),
        expected_source_digest: source_digest(execution_source()),
        expected_tool_snapshot: tool_snapshot.clone(),
        expected_sdk_contract_version: 1,
        expected_runner_contract_version: 4,
        next_sdk_contract_version: 2,
        next_runner_contract_version: 5,
    };
    let (resumed, second_claim) = store
        .resume(ResumeExecution {
            tenant_id: tenant.clone(),
            principal_sub: "alice".to_owned(),
            principal_issuer: "https://issuer.test".to_owned(),
            id,
            owner: Uuid::now_v7(),
            lease: Duration::from_secs(30),
            expected_status: ExecutionStatus::WaitingForResume,
            resume_context: resume_context.clone(),
            expected_claim_epoch,
            expected_resume_context: expected_resume_context.clone(),
            expected_source_digest: source_digest(execution_source()),
            expected_tool_snapshot: tool_snapshot.clone(),
            expected_sdk_contract_version: 1,
            expected_runner_contract_version: 4,
            next_sdk_contract_version: 2,
            next_runner_contract_version: 5,
        })
        .await
        .expect("resume execution")
        .expect("resume claim succeeds");
    assert_eq!(resumed.status, ExecutionStatus::Running);
    assert_eq!(resumed.claim_epoch, first_claim.epoch + 1);
    assert_eq!(resumed.resume_context, Some(resume_context));
    assert_eq!(resumed.sdk_contract_version, 2);
    assert_eq!(resumed.runner_contract_version, 5);
    assert_eq!(second_claim.epoch, resumed.claim_epoch);
    assert!(store
        .resume(ResumeExecution {
            tenant_id: tenant.clone(),
            principal_sub: "alice".to_owned(),
            principal_issuer: "https://issuer.test".to_owned(),
            id,
            owner: Uuid::now_v7(),
            lease: Duration::from_secs(30),
            expected_status: ExecutionStatus::WaitingForResume,
            resume_context: json!({"checkpoint": null, "input": "different"}),
            expected_claim_epoch,
            expected_resume_context,
            expected_source_digest: source_digest(execution_source()),
            expected_tool_snapshot: tool_snapshot.clone(),
            expected_sdk_contract_version: 1,
            expected_runner_contract_version: 4,
            next_sdk_contract_version: 2,
            next_runner_contract_version: 5,
        })
        .await
        .expect("concurrent resume attempt")
        .is_none());
    let next_checkpoint = json!({"checkpoint": {"prompt": "Choose a city"}});
    store
        .transition(
            &second_claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::WaitingForResume,
                event: event(ExecutionEventKind::WaitingForResume),
                terminal_reason_code: None,
                result_metadata: Some(json!({"connector_calls": 2})),
                result_payload: None,
                resume_context: Some(next_checkpoint.clone()),
            },
        )
        .await
        .expect("pause resumed execution")
        .expect("second claim pauses at a new boundary");
    assert!(store
        .resume(delayed_resume)
        .await
        .expect("delayed prior-generation resume")
        .is_none());
    assert_eq!(
        store
            .get(&tenant, id)
            .await
            .expect("read latest pause")
            .expect("execution remains resumable")
            .resume_context,
        Some(next_checkpoint),
        "a delayed request cannot overwrite the newer checkpoint"
    );
    assert_eq!(
        store
            .events(&tenant, id)
            .await
            .expect("resume history")
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        [
            "submitted",
            "admitted",
            "claimed",
            "running",
            "waiting_for_resume",
            "claimed",
            "resumed",
            "running",
            "waiting_for_resume",
        ],
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn interrupted_resumable_attempt_returns_to_a_reclaimable_boundary() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode resumable recovery Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "read_only", "resumable": true});
    store.submit(submitted).await.expect("submit execution");
    let (_, stale_claim) = store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET claim_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(id)
    .execute(&pool)
    .await
    .expect("expire worker claim");

    let waiting = store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://issuer.test",
            id,
            Duration::from_secs(30),
        )
        .await
        .expect("reconcile interrupted attempt")
        .expect("owner sees execution");
    assert_eq!(waiting.status, ExecutionStatus::WaitingForResume);
    assert_eq!(waiting.resume_context, Some(json!({"checkpoint": null})));
    assert!(waiting.completed_at.is_none());
    assert!(waiting.claim_owner.is_none());
    assert!(store
        .transition(
            &stale_claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::Succeeded,
                event: event(ExecutionEventKind::Succeeded),
                terminal_reason_code: None,
                result_metadata: None,
                result_payload: Some(json!({"result": "must not commit"})),
                resume_context: None,
            },
        )
        .await
        .expect("stale transition is fenced")
        .is_none());

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn interrupted_mutation_attempt_terminalizes_instead_of_waiting_for_resume() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode mutation recovery Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    // Mutation executions are not ordinarily resumable: no continuation API
    // accepts a mutation-profile `waiting_for_resume` row, so an abandoned
    // attempt must reach an explicit terminal outcome instead.
    submitted.execution_profile = json!({"name": "approval_bound_mutation", "resumable": false});
    store.submit(submitted).await.expect("submit execution");
    store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET claim_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(id)
    .execute(&pool)
    .await
    .expect("expire worker claim");

    let reconciled = store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://issuer.test",
            id,
            Duration::from_secs(30),
        )
        .await
        .expect("reconcile interrupted mutation attempt")
        .expect("owner sees execution");
    assert_eq!(reconciled.status, ExecutionStatus::Expired);
    assert_eq!(
        reconciled.terminal_reason_code.as_deref(),
        Some("worker_lease_expired")
    );
    assert!(reconciled.completed_at.is_some());
    assert!(reconciled.claim_owner.is_none());

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn effect_lease_renewal_survives_cancellation_and_blocks_reconcile() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode effect lease Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "approval_bound_mutation", "resumable": false});
    store.submit(submitted).await.expect("submit execution");
    let (_, claim) = store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    store
        .request_cancellation(&tenant, "alice", "https://issuer.test", id)
        .await
        .expect("request cancellation")
        .expect("owner sees execution");

    // The ordinary renewal refuses once cancellation is requested — that
    // refusal is the broker's pre-dispatch fence…
    assert!(!store
        .renew(&claim, Duration::from_secs(30))
        .await
        .expect("fenced renew resolves"));
    // …but the in-flight effect keeps its lease so its outcome can land.
    assert!(store
        .renew_effect_lease(&claim, Duration::from_secs(300))
        .await
        .expect("effect lease renewal resolves"));
    // With a live lease, abandonment reconciliation leaves the row untouched:
    // still running, still claimed, not terminalized.
    let untouched = store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://issuer.test",
            id,
            Duration::from_secs(30),
        )
        .await
        .expect("reconcile resolves")
        .expect("owner sees execution");
    assert_eq!(untouched.status, ExecutionStatus::Running);
    assert!(untouched.completed_at.is_none());
    assert!(untouched.claim_owner.is_some());
    assert!(store
        .append_effect_outcome(&claim, event(ExecutionEventKind::ConnectorCallSucceeded))
        .await
        .expect("effect outcome append resolves"));

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn cancellation_request_closes_the_bound_grant_atomically() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode grant cancellation Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let grants = waygate_catalog::PgCatalogStore::new(pool.clone());
    let id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "approval_bound_mutation", "resumable": false});
    store.submit(submitted).await.expect("submit execution");
    store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    let call_id = Uuid::new_v5(&id, &1_u32.to_be_bytes());
    let source_digest_value = source_digest(execution_source());
    let tool_id = Uuid::new_v4();
    use waygate_catalog::CatalogStore as _;
    grants
        .create_grant(waygate_catalog::NewApprovalGrant {
            tenant_id: &tenant,
            principal_sub: "alice",
            principal_issuer: "https://issuer.test",
            client_id: None,
            server_id: Uuid::new_v4(),
            tool_id,
            argument_hash: "args-v1:test",
            execution_binding: Some(waygate_catalog::GrantExecutionBinding {
                execution_id: id,
                source_digest: &source_digest_value,
                call_id,
            }),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
            approver: "operator@example.com",
            reason: None,
        })
        .await
        .expect("create bound grant");
    let lookup = || waygate_catalog::GrantLookup {
        tenant_id: &tenant,
        principal_sub: "alice",
        principal_issuer: "https://issuer.test",
        client_id: None,
        tool_id,
        argument_hash: "args-v1:test",
        execution_binding: Some(waygate_catalog::GrantExecutionBinding {
            execution_id: id,
            source_digest: &source_digest_value,
            call_id,
        }),
    };
    assert!(
        grants
            .find_grant(lookup())
            .await
            .expect("find bound grant")
            .is_some(),
        "the bound grant is claimable while no cancellation is requested"
    );

    store
        .request_cancellation(&tenant, "alice", "https://issuer.test", id)
        .await
        .expect("request cancellation")
        .expect("owner sees execution");

    // Once the cancellation request is recorded, the one-time grant can no
    // longer be found or consumed — no dispatch follows an accepted
    // cancellation, atomically with authority consumption.
    assert!(grants
        .find_grant(lookup())
        .await
        .expect("find after cancellation")
        .is_none());
    assert!(grants
        .claim_grant(lookup())
        .await
        .expect("claim after cancellation")
        .is_none());

    sqlx::query("DELETE FROM approval_grants WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("clean test grants");
    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn effect_outcome_append_survives_lease_expiry_until_the_claim_is_taken() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode lease fence Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "approval_bound_mutation", "resumable": false});
    store.submit(submitted).await.expect("submit execution");
    let (_, claim) = store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET claim_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(id)
    .execute(&pool)
    .await
    .expect("expire worker claim");

    // Ordinary appends lose their fence with the lease…
    assert!(!store
        .append_event(&claim, event(ExecutionEventKind::ConnectorCallStarted))
        .await
        .expect("fenced append resolves"));
    // …but the outcome of an effect that already left the gateway still
    // lands while the same owner/epoch holds the row.
    assert!(store
        .append_effect_outcome(&claim, event(ExecutionEventKind::ConnectorCallSucceeded))
        .await
        .expect("effect outcome append resolves"));
    // Once reconciliation takes the abandoned row, the fence closes.
    store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://issuer.test",
            id,
            Duration::from_secs(30),
        )
        .await
        .expect("reconcile abandoned mutation")
        .expect("owner sees execution");
    assert!(!store
        .append_effect_outcome(&claim, event(ExecutionEventKind::ConnectorCallFailed))
        .await
        .expect("post-reconcile append resolves"));

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn effect_outcome_append_survives_cancellation_request() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode cancellation fence Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "approval_bound_mutation", "resumable": false});
    store.submit(submitted).await.expect("submit execution");
    let (_, claim) = store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    store
        .request_cancellation(&tenant, "alice", "https://issuer.test", id)
        .await
        .expect("request cancellation")
        .expect("owner sees execution");

    // Ordinary appends refuse once cancellation is requested — this is the
    // pre-dispatch boundary that closes later dispatch.
    assert!(!store
        .append_event(&claim, event(ExecutionEventKind::ConnectorCallStarted))
        .await
        .expect("fenced append resolves"));
    // The outcome of an effect that already left the gateway still reaches
    // the journal.
    assert!(store
        .append_effect_outcome(&claim, event(ExecutionEventKind::ConnectorCallSucceeded))
        .await
        .expect("effect outcome append resolves"));
    // The cancellation itself can still terminalize the execution afterward.
    let cancelled = store
        .transition(
            &claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::Cancelled,
                event: event(ExecutionEventKind::Cancelled),
                terminal_reason_code: Some("cancelled_by_client".to_owned()),
                result_metadata: None,
                result_payload: None,
                resume_context: None,
            },
        )
        .await
        .expect("cancellation transition resolves")
        .expect("cancellation lands despite the requested flag");
    assert_eq!(cancelled.status, ExecutionStatus::Cancelled);

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn expired_pause_cannot_resume_and_reconciles_as_expired() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode expired resume Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let tool_snapshot = json!({"contract_version": 1, "bindings": []});
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "read_only", "resumable": true});
    submitted.runner_contract_version = 4;
    store.submit(submitted).await.expect("submit execution");
    let (_, claim) = store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            tool_snapshot.clone(),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    let paused = store
        .transition(
            &claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::WaitingForResume,
                event: event(ExecutionEventKind::WaitingForResume),
                terminal_reason_code: None,
                result_metadata: None,
                result_payload: None,
                resume_context: Some(json!({"checkpoint": ["page", 2]})),
            },
        )
        .await
        .expect("pause execution")
        .expect("pause succeeds");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET retention_until = now() - interval '1 second'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(id)
    .execute(&pool)
    .await
    .expect("expire paused execution");

    assert!(store
        .resume(ResumeExecution {
            tenant_id: tenant.clone(),
            principal_sub: "alice".to_owned(),
            principal_issuer: "https://issuer.test".to_owned(),
            id,
            owner: Uuid::now_v7(),
            lease: Duration::from_secs(30),
            expected_status: ExecutionStatus::WaitingForResume,
            resume_context: json!({"checkpoint": ["page", 2], "input": null}),
            expected_claim_epoch: paused.claim_epoch,
            expected_resume_context: paused.resume_context,
            expected_source_digest: source_digest(execution_source()),
            expected_tool_snapshot: tool_snapshot,
            expected_sdk_contract_version: 1,
            expected_runner_contract_version: 4,
            next_sdk_contract_version: 2,
            next_runner_contract_version: 5,
        })
        .await
        .expect("expired resume attempt")
        .is_none());
    let expired = store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://issuer.test",
            id,
            Duration::from_secs(30),
        )
        .await
        .expect("reconcile expired pause");
    if let Some(expired) = expired {
        assert_eq!(expired.status, ExecutionStatus::Expired);
        assert_eq!(
            expired.terminal_reason_code.as_deref(),
            Some("retention_expired")
        );
    } else {
        assert!(
            store
                .get(&tenant, id)
                .await
                .expect("confirm expired pause was retention-swept")
                .is_none(),
            "an expired pause is either terminalized or already retention-swept"
        );
    }

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn waiting_approval_can_be_listed_and_denied_once() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode approval Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "approval_bound_mutation"});
    store.submit(submitted).await.expect("submit mutation");
    let (_, claim) = store
        .claim(
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim mutation")
        .expect("mutation claim succeeds");
    store
        .transition(
            &claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::WaitingForApproval,
                event: event(ExecutionEventKind::WaitingForApproval),
                terminal_reason_code: None,
                result_metadata: None,
                result_payload: None,
                resume_context: Some(json!({
                    "approval": {"argument_hash": "sha256:arguments"}
                })),
            },
        )
        .await
        .expect("persist approval pause")
        .expect("approval pause succeeds");

    let pending = store
        .list_waiting_approvals(&tenant, 10)
        .await
        .expect("list approval requests");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert!(!store
        .deny_waiting_approval("other-tenant", id, "reviewer", None)
        .await
        .expect("cross-tenant denial is refused"));
    assert!(store
        .deny_waiting_approval(&tenant, id, "reviewer", Some("recipient mismatch"))
        .await
        .expect("deny approval request"));
    assert!(!store
        .deny_waiting_approval(&tenant, id, "reviewer", None)
        .await
        .expect("second denial is refused"));

    let denied = store
        .get(&tenant, id)
        .await
        .expect("read denied execution")
        .expect("denied execution remains");
    assert_eq!(denied.status, ExecutionStatus::Failed);
    assert_eq!(
        denied.terminal_reason_code.as_deref(),
        Some("approval_denied")
    );
    let events = store.events(&tenant, id).await.expect("read denial event");
    let denial = events.last().expect("denial event");
    assert_eq!(denial.kind, ExecutionEventKind::Failed.as_str());
    assert_eq!(denial.detail["approver"], "reviewer");
    assert_eq!(denial.detail["reason"], "recipient mismatch");

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn abandoned_submissions_and_worker_claims_terminalize_on_owner_poll() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode abandoned-work Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());

    let submitted_id = Uuid::now_v7();
    let mut submitted = new_execution(&tenant, submitted_id);
    submitted.source = Some(execution_source().to_owned());
    submitted.execution_profile = json!({"name": "read_only", "resumable": true});
    store
        .submit(submitted)
        .await
        .expect("submit unclaimed execution");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET submitted_at = now() - interval '2 seconds'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(submitted_id)
    .execute(&pool)
    .await
    .expect("age unclaimed execution");
    assert!(store
        .reconcile_abandoned(
            &tenant,
            "mallory",
            "https://issuer.test",
            submitted_id,
            Duration::from_secs(1)
        )
        .await
        .expect("wrong-owner reconciliation")
        .is_none());
    let expired = store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://issuer.test",
            submitted_id,
            Duration::from_secs(1),
        )
        .await
        .expect("reconcile unclaimed execution")
        .expect("owner sees execution");
    assert_eq!(expired.status, ExecutionStatus::Expired);
    assert_eq!(
        expired.terminal_reason_code.as_deref(),
        Some("worker_never_claimed")
    );
    assert!(
        expired.tool_snapshot.is_none(),
        "an unacknowledged pre-claim row is terminal, never falsely resumable"
    );

    let running_id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, running_id))
        .await
        .expect("submit claimed execution");
    let (_, stale_claim) = store
        .claim(
            &tenant,
            running_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"snapshot": 1}),
        )
        .await
        .expect("claim execution")
        .expect("claim succeeds");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET claim_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(running_id)
    .execute(&pool)
    .await
    .expect("expire worker claim");
    let expired = store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://issuer.test",
            running_id,
            Duration::from_secs(30),
        )
        .await
        .expect("reconcile expired claim")
        .expect("owner sees execution");
    assert_eq!(expired.status, ExecutionStatus::Expired);
    assert_eq!(
        expired.terminal_reason_code.as_deref(),
        Some("worker_lease_expired")
    );
    assert!(expired.claim_owner.is_none());
    assert!(store
        .transition(
            &stale_claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::Succeeded,
                event: event(ExecutionEventKind::Succeeded),
                terminal_reason_code: None,
                result_metadata: None,
                result_payload: Some(json!({"result": "must not commit"})),
                resume_context: None,
            },
        )
        .await
        .expect("stale worker transition")
        .is_none());
    assert_eq!(
        store
            .events(&tenant, running_id)
            .await
            .expect("abandoned-worker history")
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        ["submitted", "admitted", "claimed", "running", "expired"],
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_is_single_owner_and_epoch_fences_stale_workers() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode claim Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant = seed_tenant(&pool, &suffix).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, id))
        .await
        .expect("submit execution");

    let first = store.claim(
        &tenant,
        id,
        Uuid::now_v7(),
        Duration::from_secs(30),
        execution_source().to_owned(),
        json!({"snapshot": 1}),
    );
    let second = store.claim(
        &tenant,
        id,
        Uuid::now_v7(),
        Duration::from_secs(30),
        execution_source().to_owned(),
        json!({"snapshot": 2}),
    );
    let (first, second) = tokio::join!(first, second);
    let first = first.expect("first claim attempt");
    let second = second.expect("second claim attempt");
    assert_eq!(
        usize::from(first.is_some()) + usize::from(second.is_some()),
        1,
        "exactly one worker must own the execution",
    );
    let (_, stale_claim) = first.or(second).expect("one winning claim");

    assert!(store
        .fail_submission(
            &tenant,
            id,
            event(ExecutionEventKind::Failed),
            "late_preclaim_failure".to_owned(),
        )
        .await
        .expect("pre-claim failure attempt against claimed execution")
        .is_none());
    assert_eq!(
        store
            .get(&tenant, id)
            .await
            .expect("read claimed execution")
            .expect("claimed execution exists")
            .status,
        ExecutionStatus::Running,
        "an unfenced pre-claim failure cannot overtake a live claim",
    );

    let replacement_owner = Uuid::now_v7();
    let mut transfer_tx = pool.begin().await.expect("begin recovery claim transfer");
    sqlx::query(
        r#"
        UPDATE codemode_executions
           SET claim_owner = $3,
               claim_epoch = claim_epoch + 1,
               claim_expires_at = now() + interval '30 seconds'
         WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&tenant)
    .bind(id)
    .bind(replacement_owner)
    .execute(&mut *transfer_tx)
    .await
    .expect("stage recovery claim");

    let mut stale_append =
        Box::pin(store.append_event(&stale_claim, event(ExecutionEventKind::StepStarted)));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stale_append.as_mut())
            .await
            .is_err(),
        "event append must serialize behind an in-flight claim transfer",
    );
    transfer_tx.commit().await.expect("commit recovery claim");
    assert!(
        !tokio::time::timeout(Duration::from_secs(1), stale_append.as_mut())
            .await
            .expect("stale append resumes after claim transfer")
            .expect("stale event attempt")
    );
    assert!(!store
        .renew(&stale_claim, Duration::from_secs(30))
        .await
        .expect("stale renewal attempt"));

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn submission_sweeps_expired_rows_but_preserves_live_claims() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode retention Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant = seed_tenant(&pool, &suffix).await;
    let store = PgExecutionStore::new(pool.clone());
    let terminal_id = Uuid::now_v7();
    let in_flight_id = Uuid::now_v7();
    let waiting_id = Uuid::now_v7();
    let approval_id = Uuid::now_v7();
    let terminal = new_execution(&tenant, terminal_id);
    let in_flight = new_execution(&tenant, in_flight_id);
    let mut waiting = new_execution(&tenant, waiting_id);
    waiting.source = Some(execution_source().to_owned());
    waiting.execution_profile = json!({"name": "read_only", "resumable": true});
    waiting.runner_contract_version = 4;
    let mut approval = new_execution(&tenant, approval_id);
    approval.source = Some(execution_source().to_owned());
    approval.execution_profile = json!({"name": "approval_bound_mutation"});

    store
        .submit(terminal)
        .await
        .expect("submit terminal fixture");
    store
        .submit(in_flight)
        .await
        .expect("submit in-flight fixture");
    store.submit(waiting).await.expect("submit waiting fixture");
    store
        .submit(approval)
        .await
        .expect("submit approval fixture");
    let (_, waiting_claim) = store
        .claim(
            &tenant,
            waiting_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim waiting fixture")
        .expect("waiting fixture claim succeeds");
    store
        .transition(
            &waiting_claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::WaitingForResume,
                event: event(ExecutionEventKind::WaitingForResume),
                terminal_reason_code: None,
                result_metadata: None,
                result_payload: None,
                resume_context: Some(json!({"checkpoint": "resume later"})),
            },
        )
        .await
        .expect("pause waiting fixture")
        .expect("waiting fixture pauses");
    let (_, approval_claim) = store
        .claim(
            &tenant,
            approval_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim approval fixture")
        .expect("approval fixture claim succeeds");
    store
        .transition(
            &approval_claim,
            ExecutionTransition {
                from: vec![ExecutionStatus::Running],
                to: ExecutionStatus::WaitingForApproval,
                event: event(ExecutionEventKind::WaitingForApproval),
                terminal_reason_code: None,
                result_metadata: None,
                result_payload: None,
                resume_context: Some(json!({"approval": {"argument_hash": "sha256:test"}})),
            },
        )
        .await
        .expect("pause approval fixture")
        .expect("approval fixture pauses");
    store
        .fail_submission(
            &tenant,
            terminal_id,
            event(ExecutionEventKind::Failed),
            "execution_failed".to_owned(),
        )
        .await
        .expect("terminal transition")
        .expect("submitted execution transitions");
    // A running row whose claim is still live is its runner's to finish,
    // even past retention; the same row with a dead claim has no remaining
    // path and sweeps. Every fixture reaches its intended state at valid
    // retention and is backdated afterwards, because each submission runs
    // the sweep and would otherwise reap the earlier fixtures mid-setup.
    let live_claim_id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, live_claim_id))
        .await
        .expect("submit live-claim fixture");
    let _ = store
        .claim(
            &tenant,
            live_claim_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim live-claim fixture")
        .expect("live-claim fixture claim succeeds");
    let dead_claim_id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, dead_claim_id))
        .await
        .expect("submit dead-claim fixture");
    let _ = store
        .claim(
            &tenant,
            dead_claim_id,
            Uuid::now_v7(),
            Duration::from_secs(30),
            execution_source().to_owned(),
            json!({"contract_version": 1, "bindings": []}),
        )
        .await
        .expect("claim dead-claim fixture")
        .expect("dead-claim fixture claim succeeds");
    sqlx::query(
        "UPDATE codemode_executions SET retention_until = now() - interval '1 second' WHERE id = ANY($1)",
    )
    .bind(vec![
        terminal_id,
        in_flight_id,
        waiting_id,
        approval_id,
        live_claim_id,
        dead_claim_id,
    ])
    .execute(&pool)
    .await
    .expect("expire the fixtures");
    sqlx::query(
        "UPDATE codemode_executions SET claim_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(dead_claim_id)
    .execute(&pool)
    .await
    .expect("kill the dead claim");
    // The sweep selects rows FOR UPDATE SKIP LOCKED inside the submitting
    // transaction, so a concurrent test's still-open submission can hold a
    // fixture's lock at this instant and leave it briefly visible here.
    // Re-running the sweep converges; in an isolated run a broken sweep
    // still fails this loop because nothing else ever removes the rows.
    let swept = [
        terminal_id,
        in_flight_id,
        waiting_id,
        approval_id,
        dead_claim_id,
    ];
    let mut survivors = usize::MAX;
    for _ in 0..10 {
        store
            .submit(new_execution(&tenant, Uuid::now_v7()))
            .await
            .expect("submission runs retention sweep");
        survivors = 0;
        for id in swept {
            if store
                .get(&tenant, id)
                .await
                .expect("re-read swept fixture")
                .is_some()
            {
                survivors += 1;
            }
        }
        if survivors == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        survivors, 0,
        "every expired row without a live claim sweeps: terminal history, an \
         abandoned submission, released pauses, and a dead-claim attempt"
    );
    assert!(store
        .events(&tenant, terminal_id)
        .await
        .expect("read expired terminal history")
        .is_empty());
    assert!(store
        .events(&tenant, in_flight_id)
        .await
        .expect("read expired abandoned submission history")
        .is_empty());
    assert!(
        store
            .get(&tenant, live_claim_id)
            .await
            .expect("read live-claim execution")
            .is_some(),
        "a live claim holds its row past retention until the runner finishes"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_claim_failure_is_durable_and_event_rows_are_append_only() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode terminal Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant = seed_tenant(&pool, &suffix).await;
    let store = PgExecutionStore::new(pool.clone());
    let id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, id))
        .await
        .expect("submit execution");

    let failed = store
        .fail_submission(
            &tenant,
            id,
            NewExecutionEvent {
                kind: ExecutionEventKind::Failed,
                step_number: None,
                call_id: None,
                attempt: None,
                detail: json!({"reason_code": "tenant_execution_capacity"}),
            },
            "tenant_execution_capacity".to_owned(),
        )
        .await
        .expect("record rejection")
        .expect("submitted execution transitions");
    assert_eq!(failed.status, ExecutionStatus::Failed);
    assert_eq!(
        failed.terminal_reason_code.as_deref(),
        Some("tenant_execution_capacity")
    );

    let event_id = store
        .events(&tenant, id)
        .await
        .expect("read events")
        .last()
        .expect("terminal event")
        .id;
    let update =
        sqlx::query("UPDATE codemode_execution_events SET kind = 'tampered' WHERE id = $1")
            .bind(event_id)
            .execute(&pool)
            .await;
    assert!(update
        .expect_err("event update must be rejected")
        .to_string()
        .contains("append-only"));

    let mut retention_tx = pool.begin().await.expect("begin retention transaction");
    sqlx::query("SET LOCAL app.codemode_retention_delete = 'enabled'")
        .execute(&mut *retention_tx)
        .await
        .expect("enable retention delete");
    let update =
        sqlx::query("UPDATE codemode_execution_events SET kind = 'tampered' WHERE id = $1")
            .bind(event_id)
            .execute(&mut *retention_tx)
            .await;
    assert!(update
        .expect_err("retention authority must permit deletes only")
        .to_string()
        .contains("append-only"));
    retention_tx
        .rollback()
        .await
        .expect("rollback rejected retention update");

    let mut direct_delete_tx = pool.begin().await.expect("begin direct delete probe");
    sqlx::query("SET LOCAL app.codemode_retention_delete = 'enabled'")
        .execute(&mut *direct_delete_tx)
        .await
        .expect("enable retention marker");
    let direct_delete = sqlx::query("DELETE FROM codemode_execution_events WHERE id = $1")
        .bind(event_id)
        .execute(&mut *direct_delete_tx)
        .await;
    let delete_error = direct_delete
        .expect_err("retention marker must not authorize a direct history delete")
        .to_string();
    direct_delete_tx
        .rollback()
        .await
        .expect("rollback rejected direct delete");
    assert!(delete_error.contains("append-only"));

    let mut truncate_tx = pool.begin().await.expect("begin truncate probe");
    let truncate = sqlx::query("TRUNCATE codemode_execution_events")
        .execute(&mut *truncate_tx)
        .await;
    let truncate_error = truncate
        .expect_err("append-only history must reject statement-level truncation")
        .to_string();
    truncate_tx
        .rollback()
        .await
        .expect("rollback rejected truncate");
    assert!(truncate_error.contains("append-only"));

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn tenant_store_hard_delete_cascades_append_only_history() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode tenant delete Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant = seed_tenant(&pool, &suffix).await;
    let execution_store = PgExecutionStore::new(pool.clone());
    let execution_id = Uuid::now_v7();
    execution_store
        .submit(new_execution(&tenant, execution_id))
        .await
        .expect("submit execution");

    assert!(PgTenantStore::new(pool.clone())
        .delete(&tenant)
        .await
        .expect("hard-delete tenant with Code Mode history"));
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM codemode_execution_events WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("count remaining Code Mode history");
    assert_eq!(remaining, 0);
}

/// Owner surfaces bind tenant + issuer + subject: the same `sub` under a
/// different issuer owns nothing, and a pre-upgrade row that recorded no
/// issuer fails closed for everyone (it ages out on retention instead).
#[tokio::test]
async fn owner_surfaces_are_issuer_scoped_and_legacy_rows_fail_closed() {
    let Some(pool) = connect().await else {
        eprintln!("skipping Code Mode issuer scoping Pg contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let store = PgExecutionStore::new(pool.clone());

    let id = Uuid::now_v7();
    store
        .submit(new_execution(&tenant, id))
        .await
        .expect("submit execution");
    assert!(
        store
            .request_cancellation(&tenant, "alice", "https://other-issuer.test", id)
            .await
            .expect("cross-issuer cancellation probe")
            .is_none(),
        "the same sub under another issuer is a different person",
    );
    assert!(store
        .reconcile_abandoned(
            &tenant,
            "alice",
            "https://other-issuer.test",
            id,
            Duration::from_secs(30),
        )
        .await
        .expect("cross-issuer reconcile probe")
        .is_none());

    // A pre-upgrade row records no issuer (exactly what a deployment that
    // predates the column left behind): owned by no one at every surface.
    sqlx::query("UPDATE codemode_executions SET principal_issuer = NULL WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("simulate legacy issuer-less row");
    for issuer in ["https://issuer.test", "https://other-issuer.test"] {
        assert!(store
            .request_cancellation(&tenant, "alice", issuer, id)
            .await
            .expect("legacy-row cancellation probe")
            .is_none());
        assert!(store
            .reconcile_abandoned(&tenant, "alice", issuer, id, Duration::from_secs(30))
            .await
            .expect("legacy-row reconcile probe")
            .is_none());
    }

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn configured_source_byte_quotas_are_atomic_across_concurrent_writers() {
    let Some(pool) = connect().await else {
        return;
    };
    let tenant = seed_tenant(&pool, &Uuid::new_v4().to_string()).await;
    let source_a = "return 1;";
    let source_b = "return 2;";
    let store = PgExecutionStore::new(pool.clone())
        .with_source_limits(waygate_codemode::SourceRetentionLimits {
            owner_bytes: source_a.len() as i64,
            tenant_bytes: source_a.len() as i64,
            owner_count: 2,
            tenant_count: 2,
        })
        .expect("valid configured quotas");
    let owner = SourceArtifactOwner {
        tenant_id: tenant.clone(),
        principal_sub: "quota-owner".to_owned(),
        principal_issuer: "https://issuer.test".to_owned(),
    };
    let digest_a = source_digest(source_a);
    let digest_b = source_digest(source_b);
    let (a, b) = tokio::join!(
        store.retain_source(&owner, source_a, &digest_a, Duration::from_secs(60)),
        store.retain_source(&owner, source_b, &digest_b, Duration::from_secs(60)),
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "only one source fits the configured byte quota"
    );
    let (winner, refused) = if let Ok(winner) = a {
        (winner, b)
    } else {
        (b.expect("one writer succeeds"), a)
    };
    assert!(matches!(
        refused,
        Err(waygate_core::store::StoreError::Conflict)
    ));
    store
        .retain_source(
            &owner,
            &winner.source,
            &winner.source_digest,
            Duration::from_secs(120),
        )
        .await
        .expect("extending the retained hash does not consume more bytes");
    let other_owner = SourceArtifactOwner {
        principal_sub: "another-owner".to_owned(),
        ..owner
    };
    assert!(
        matches!(
            store
                .retain_source(&other_owner, source_a, &digest_a, Duration::from_secs(60))
                .await,
            Err(waygate_core::store::StoreError::Conflict)
        ),
        "a second owner cannot exceed the configured tenant byte quota"
    );
    cleanup(&pool, &tenant).await;
}
