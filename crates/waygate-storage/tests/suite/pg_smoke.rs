//! Live Postgres smoke test for [`PgAuditSink`]. Skips cleanly when
//! `AUDIT_DATABASE_URL` is not set so CI and local `cargo test` runs without
//! a DB pass without special casing. When the env var *is* set we connect,
//! apply migrations (idempotent), insert a row, read it back, and then
//! delete it — leaving the database as we found it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sqlx::{postgres::PgPoolOptions, Row};
use tokio::sync::Semaphore;
use uuid::Uuid;

use waygate_core::RiskTier;
use waygate_evidence::audit::{
    AuditEvent, AuditOutcome, AuditPrincipal, EvidenceCategory, EvidenceRecorder,
};
use waygate_storage::{PgAuditSink, RetentionStore, Sweeper};

fn chained_best_effort_metric_value(outcome: &str) -> f64 {
    let outcome_label = format!("outcome=\"{outcome}\"");
    waygate_telemetry::gather_text()
        .lines()
        .find(|line| {
            line.starts_with("mcp_evidence_chained_best_effort_total{")
                && line.contains(&outcome_label)
        })
        .and_then(|line| line.split_whitespace().last())
        .map(|value| value.parse().expect("metric sample value is numeric"))
        .unwrap_or(0.0)
}

fn chained_best_effort_failure_metric_value(stage: &str) -> f64 {
    let stage_label = format!("stage=\"{stage}\"");
    waygate_telemetry::gather_text()
        .lines()
        .find(|line| {
            line.starts_with("mcp_evidence_chained_best_effort_failures_total{")
                && line.contains(&stage_label)
        })
        .and_then(|line| line.split_whitespace().last())
        .map(|value| value.parse().expect("metric sample value is numeric"))
        .unwrap_or(0.0)
}

#[tokio::test]
async fn target_etag_schema_comment_describes_an_opaque_action_specific_witness() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };

    let comment: Option<String> = sqlx::query_scalar(
        r#"
        SELECT col_description('change_requests'::regclass, attnum)
          FROM pg_attribute
         WHERE attrelid = 'change_requests'::regclass
           AND attname = 'target_etag'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("read change_requests.target_etag schema comment");

    assert_eq!(
        comment.as_deref(),
        Some(
            "Opaque action-specific freshness witness captured at propose time. \
             The owning executor may store a digest or structured non-secret \
             version token and is solely responsible for interpreting it."
        ),
        "the live schema must not describe every target witness as a hash",
    );
}

#[tokio::test]
async fn roundtrip_audit_event() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };

    let sink = PgAuditSink::with_pool(pool.clone());
    let event = AuditEvent {
        // Non-null on purpose: with `None` here the suite stays green even if
        // the operation is dropped on insert or read back empty, which is the
        // one thing about this column PostgreSQL has to prove.
        operation: Some("secrets.reveal".into()),
        id: Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        category: EvidenceCategory::Invocation,
        tenant: waygate_core::TenantId::default(),
        principal: Some(AuditPrincipal {
            sub: "pg-smoke-user".into(),
            email: Some("pg-smoke@example.test".into()),
            groups: vec!["mcp-users".into(), "mcp-admins".into()],
            issuer: "https://idp.example.test".into(),
            scim_active: None,
            scim_groups: Vec::new(),
        }),
        action: "CallTool".into(),
        server: Some("example-messages".into()),
        tool: Some("send_message".into()),
        outcome: AuditOutcome::Denied,
        risk_level: Some(RiskTier::High),
        pii: Some(true),
        policy_ids: vec!["policy-42".into()],
        reason: Some("pg_smoke: forbid policies: policy-42".into()),
        trace_id: Some("trace-xyz".into()),
        latency_ms: None,
        target: None,
        req_scopes: Vec::new(),
        auth_method: None,
        req_roles: Vec::new(),
        side_effects: None,
        acting_agent: None,
        invocation_hierarchy: None,
    };

    sink.record_required(event.clone())
        .await
        .expect("record_required");

    let row = sqlx::query(
        r#"
        SELECT id, action, outcome, principal_sub, principal_email,
               principal_groups, issuer, server, tool, operation, risk_level,
               policy_ids, reason, trace_id
          FROM audit_log
         WHERE id = $1
        "#,
    )
    .bind(event.id)
    .fetch_one(&pool)
    .await
    .expect("row round-trips");

    assert_eq!(row.get::<Uuid, _>("id"), event.id);
    assert_eq!(row.get::<String, _>("action"), "CallTool");
    assert_eq!(row.get::<String, _>("outcome"), "denied");
    assert_eq!(
        row.get::<Option<String>, _>("principal_sub").as_deref(),
        Some("pg-smoke-user"),
    );
    assert_eq!(
        row.get::<Vec<String>, _>("principal_groups"),
        vec!["mcp-users".to_string(), "mcp-admins".into()],
    );
    assert_eq!(
        row.get::<Option<String>, _>("tool").as_deref(),
        Some("send_message")
    );
    assert_eq!(
        row.get::<Option<String>, _>("operation").as_deref(),
        Some("secrets.reveal"),
        "the operation must survive the insert and read back as written"
    );
    assert_eq!(
        row.get::<Option<String>, _>("risk_level").as_deref(),
        Some("high")
    );
    assert_eq!(
        row.get::<Vec<String>, _>("policy_ids"),
        vec!["policy-42".to_string()]
    );
    assert_eq!(
        row.get::<Option<String>, _>("trace_id").as_deref(),
        Some("trace-xyz")
    );

    // The audit_log tamper-evidence guard is intentionally
    // complete — BEFORE UPDATE, BEFORE DELETE, and BEFORE
    // TRUNCATE all RAISE on attempted mutation, so an operator
    // with TRUNCATE privilege has no bypass around the UPDATE/
    // DELETE triggers. Trade-off: this test
    // can no longer clean up after itself. It's operator-opt-in
    // via AUDIT_DATABASE_URL and is expected to run against an
    // isolated test DB that the operator wipes by dropping the
    // DB / schema between runs, not by mutating audit_log.
    // Smoke-test row accumulation is acceptable in that
    // environment.
}

#[tokio::test]
async fn hierarchy_chained_best_effort_exports_without_changing_direct_rows() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };

    let sink = std::sync::Arc::new(
        PgAuditSink::with_pool(pool.clone()).with_outbox_targets(vec!["test-export".into()]),
    );
    let tenant_id = format!("pg-chained-{}", Uuid::now_v7());
    let tenant = waygate_core::TenantId::parse(tenant_id.clone()).expect("tenant id valid");

    let mut required = AuditEvent::new("required", AuditOutcome::Success)
        .with_category(EvidenceCategory::AdminMutation)
        .with_tenant(tenant.clone());
    // One row in this chain carries an operation, so verification walks the
    // shape whose canonical bytes gained a tail. With every row operation-free
    // the walk proves only that the unchanged encoding still agrees with
    // itself.
    required.operation = Some("secrets.reveal".into());
    let required_id = required.id;
    sink.record_required(required)
        .await
        .expect("required row must persist");

    let attempted_before = chained_best_effort_metric_value("attempted");
    let inserted_before = chained_best_effort_metric_value("inserted");
    let mut chained_ids = Vec::new();
    for index in 0..12 {
        let event = AuditEvent::new(format!("security-decision-{index}"), AuditOutcome::Denied)
            .with_category(EvidenceCategory::AuthAttempt)
            .with_tenant(tenant.clone());
        chained_ids.push(event.id);
        sink.record_chained_best_effort(event).await;
    }
    let hierarchy = waygate_core::InvocationHierarchy::new(
        Uuid::now_v7(),
        std::num::NonZeroU32::new(1).unwrap(),
        Uuid::now_v7(),
        std::num::NonZeroU32::new(1).unwrap(),
    );
    let nested = AuditEvent::new("nested-read", AuditOutcome::Success)
        .with_category(EvidenceCategory::Invocation)
        .with_tenant(tenant.clone())
        .with_invocation_hierarchy(Some(hierarchy));
    let nested_id = nested.id;
    sink.record_chained_best_effort(nested).await;
    let attempted_after = chained_best_effort_metric_value("attempted");
    let inserted_after = chained_best_effort_metric_value("inserted");
    assert!(
        attempted_after - attempted_before >= 13.0,
        "every production recorder call must emit an attempted transition",
    );
    assert!(
        inserted_after - inserted_before >= 13.0,
        "every successful production recorder call must emit an inserted transition",
    );

    let rows = sqlx::query(
        r#"
        SELECT id, prev_hash, row_hash
          FROM audit_log
         WHERE tenant_id = $1
         ORDER BY chain_seq ASC
        "#,
    )
    .bind(&tenant_id)
    .fetch_all(&pool)
    .await
    .expect("read tenant chain");
    assert_eq!(rows.len(), 14, "every healthy best-effort attempt lands");
    assert!(
        rows.iter()
            .all(|row| row.get::<Option<String>, _>("row_hash").is_some()),
        "required and chained-best-effort rows must all carry row hashes",
    );
    assert!(
        rows.iter()
            .skip(1)
            .all(|row| row.get::<Option<String>, _>("prev_hash").is_some()),
        "every row after the chain root must name its predecessor",
    );
    for id in chained_ids {
        assert!(
            rows.iter().any(|row| row.get::<Uuid, _>("id") == id),
            "chained best-effort call returned only after its task completed",
        );
    }

    let outbox_event_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT outbox.event_id
          FROM evidence_outbox AS outbox
          JOIN audit_log AS audit ON audit.id = outbox.event_id
         WHERE audit.tenant_id = $1
         ORDER BY audit.chain_seq ASC
        "#,
    )
    .bind(&tenant_id)
    .fetch_all(&pool)
    .await
    .expect("read tenant outbox rows");
    assert_eq!(outbox_event_ids, vec![required_id, nested_id]);

    use waygate_storage::AuditReader;
    let report = sink
        .verify_chain(&tenant_id, None, None, None, 100)
        .await
        .expect("verify mixed required and chained-best-effort chain");
    assert_eq!(report.status, waygate_storage::ChainVerifyStatus::Ok);
    assert_eq!(report.rows_walked, 14);
}

#[tokio::test]
async fn chained_best_effort_returns_after_a_closed_pool_drop() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let sink = PgAuditSink::with_pool(pool.clone());
    pool.close().await;
    let event = AuditEvent::new("closed-pool", AuditOutcome::ExecutionError)
        .with_category(EvidenceCategory::AuthAttempt);
    let tx_begin_failures_before = chained_best_effort_failure_metric_value("tx_begin");

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        sink.record_chained_best_effort(event),
    )
    .await
    .expect("a dropped best-effort write must not block or fail the caller");
    let tx_begin_failures_after = chained_best_effort_failure_metric_value("tx_begin");
    assert!(
        tx_begin_failures_after - tx_begin_failures_before >= 1.0,
        "a closed pool must identify transaction begin as the failed stage",
    );

    let metrics = waygate_telemetry::gather_text();
    assert!(
        metrics.lines().any(|line| {
            line.contains("mcp_evidence_chained_best_effort_total")
                && line.contains("outcome=\"dropped\"")
        }),
        "the dropped write must be observable:\n{metrics}",
    );
}

#[tokio::test]
async fn chained_best_effort_tenant_lock_contention_releases_pool_connection() {
    let Some(bootstrap_pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    drop(bootstrap_pool);
    let database_url = std::env::var("AUDIT_DATABASE_URL")
        .expect("the test helper only returns a pool when AUDIT_DATABASE_URL is set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect(&database_url)
        .await
        .expect("connect bounded test pool");
    let tenant_id = format!("pg-chained-lock-{}", Uuid::now_v7());
    let tenant = waygate_core::TenantId::parse(tenant_id.clone()).expect("tenant id valid");

    let mut lock_tx = pool.begin().await.expect("begin lock holder");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(&tenant_id)
        .execute(&mut *lock_tx)
        .await
        .expect("hold tenant chain lock");

    let sink = PgAuditSink::with_pool(pool.clone());
    let event = AuditEvent::new("contended-lock", AuditOutcome::Denied)
        .with_category(EvidenceCategory::AuthAttempt)
        .with_tenant(tenant);
    let event_id = event.id;

    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sink.record_chained_best_effort(event),
    )
    .await
    .expect("best-effort lock contention must reach its local drop deadline");

    let inserted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE id = $1")
        .bind(event_id)
        .fetch_one(&pool)
        .await
        .expect("contention must release the second connection while the lock remains held");
    assert_eq!(
        inserted, 0,
        "a contended chained-best-effort write must roll back without inserting",
    );
    lock_tx.rollback().await.expect("release tenant chain lock");
}

/// End-to-end retention sweep against a real Postgres.
/// Inserts a small contiguous chain plus one unchained best-effort row,
/// runs the sweep with a cutoff in the future (every row
/// matches), and verifies:
///
/// - both chained and unchained rows are deleted through the controlled path;
/// - exactly the expected number of marker rows is written;
/// - the chain verifier (`AuditReader::verify_chain`) reports
///   `Ok` (or `Empty`) after the sweep, proving the marker
///   chain bridging stitches the gap the sweep created.
///
/// Uses a unique synthetic tenant per run
/// (`pg-smoke-sweep-{nanos}`) so concurrent invocations and
/// cumulative residue don't interfere. The marker rows that
/// survive the sweep are NOT cleaned up — same operator-
/// opt-in posture as the first test (run against an
/// isolated DB that gets reset between runs).
#[tokio::test]
async fn retention_sweep_round_trip() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };

    let sink = PgAuditSink::with_pool(pool.clone());

    // Unique synthetic tenant — concurrent test invocations
    // don't collide on per-tenant advisory locks or each
    // other's chain head.
    let tenant_str = format!(
        "pg-smoke-sweep-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tenant = waygate_core::TenantId::parse(tenant_str.clone()).expect("tenant id valid");

    // Insert three chain-bearing rows and one unchained best-effort row. The
    // latter is the common informational-event path and must not grow forever
    // merely because it has no chain hash to bridge.
    let past_ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    for i in 0..4u32 {
        let event = AuditEvent {
            operation: None,
            id: Uuid::now_v7(),
            ts: past_ts + time::Duration::seconds(i as i64),
            category: EvidenceCategory::Invocation,
            tenant: tenant.clone(),
            principal: None,
            action: "CallTool".into(),
            server: None,
            tool: None,
            outcome: AuditOutcome::Success,
            risk_level: None,
            pii: None,
            policy_ids: vec![],
            reason: Some(format!("sweep-test row {}", i)),
            trace_id: None,
            latency_ms: None,
            target: None,
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            acting_agent: None,
            invocation_hierarchy: None,
        };
        if i == 3 {
            sink.record_best_effort(event).await;
        } else {
            sink.record_required(event).await.expect("record_required");
        }
    }

    let before_sweep: (i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(*), COUNT(*) FILTER (WHERE row_hash IS NULL)
          FROM audit_log
         WHERE tenant_id = $1
           AND category = 'invocation'
        "#,
    )
    .bind(&tenant_str)
    .fetch_one(&pool)
    .await
    .expect("count seeded retention rows");
    assert_eq!(
        before_sweep,
        (4, 1),
        "fixture must include one unchained row"
    );

    // Cutoff: a moment after the last inserted ts; every
    // inserted row matches.
    let cutoff = past_ts + time::Duration::seconds(60);
    let report = waygate_storage::run_retention_sweep(&pool, &tenant_str, "invocation", cutoff)
        .await
        .expect("sweep runs");

    // Three contiguous chained candidates collapse to one marker; the
    // unchained candidate needs no marker. All four rows are reclaimed.
    assert_eq!(
        report.markers_written, 1,
        "three contiguous chain rows collapse to one marker",
    );
    assert_eq!(report.rows_deleted, 4, "all four candidates deleted");
    assert!(
        !report.batch_limit_reached,
        "the small fixture must drain in one bounded transaction",
    );

    // Verify the surviving chain via the chain verifier. After
    // the sweep, the tenant's chain consists of one marker
    // row (which the verifier walks and stitches against
    // its own deleted_rows for self-bootstrap). PgAuditSink
    // itself implements AuditReader.
    use waygate_storage::AuditReader;
    let verify_report = sink
        .verify_chain(&tenant_str, None, None, None, 1000)
        .await
        .expect("verify_chain runs");
    assert_eq!(
        verify_report.status,
        waygate_storage::ChainVerifyStatus::Ok,
        "post-sweep chain must verify: {:?}",
        verify_report,
    );

    // The candidate rows must no longer exist in audit_log
    // for this tenant. The walker would have surfaced their
    // absence via BrokenLink had the markers not bridged,
    // but this also pins the operational claim directly.
    let surviving: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
          FROM audit_log
         WHERE tenant_id = $1
           AND category  = 'invocation'
        "#,
    )
    .bind(&tenant_str)
    .fetch_one(&pool)
    .await
    .expect("count survivors");
    assert_eq!(
        surviving.0, 0,
        "all invocation rows for the tenant were deleted",
    );

    let marker_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
          FROM audit_log
         WHERE tenant_id = $1
           AND category  = 'retention_sweep'
        "#,
    )
    .bind(&tenant_str)
    .fetch_one(&pool)
    .await
    .expect("count markers");
    assert_eq!(marker_count.0, 1, "exactly one marker row written");
}

struct StaticRetentionStore {
    policy: waygate_storage::RetentionPolicy,
}

#[async_trait::async_trait]
impl RetentionStore for StaticRetentionStore {
    async fn list(
        &self,
        _tenant_id: Option<&str>,
    ) -> Result<Vec<waygate_storage::RetentionPolicy>, sqlx::Error> {
        Ok(vec![self.policy.clone()])
    }

    async fn upsert(
        &self,
        _tenant_id: &str,
        _category: &str,
        _delete_after_days: i32,
    ) -> Result<waygate_storage::RetentionPolicy, sqlx::Error> {
        panic!("scheduler tick test never mutates policy state")
    }

    async fn delete(&self, _tenant_id: &str, _category: &str) -> Result<bool, sqlx::Error> {
        panic!("scheduler tick test never mutates policy state")
    }
}

struct BlockingTickSweeper {
    calls: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}

impl BlockingTickSweeper {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }

    async fn guarded_sweep(
        &self,
        tenant_id: &str,
        category: &str,
        cutoff: time::OffsetDateTime,
    ) -> Result<waygate_storage::SweepReport, waygate_storage::SweepError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("test release semaphore remains open")
            .forget();
        Ok(waygate_storage::SweepReport {
            tenant_id: tenant_id.to_owned(),
            category: category.to_owned(),
            cutoff,
            markers_written: 0,
            rows_deleted: 0,
            batch_limit_reached: false,
        })
    }
}

#[async_trait::async_trait]
impl Sweeper for BlockingTickSweeper {
    async fn sweep(
        &self,
        _tenant_id: &str,
        _category: &str,
        _cutoff: time::OffsetDateTime,
    ) -> Result<waygate_storage::SweepReport, waygate_storage::SweepError> {
        panic!("scheduler uses the policy-current sweep path")
    }

    async fn sweep_remaining_categories(
        &self,
        _tenant_id: &str,
        _excluded_categories: &[String],
        _cutoff: time::OffsetDateTime,
    ) -> Result<waygate_storage::SweepReport, waygate_storage::SweepError> {
        panic!("scheduler uses the policy-current sweep path")
    }

    async fn sweep_if_policy_current(
        &self,
        tenant_id: &str,
        category: &str,
        cutoff: time::OffsetDateTime,
        _expected_policy: &waygate_storage::RetentionPolicy,
    ) -> Result<waygate_storage::SweepReport, waygate_storage::SweepError> {
        self.guarded_sweep(tenant_id, category, cutoff).await
    }

    async fn sweep_remaining_categories_if_policies_current(
        &self,
        tenant_id: &str,
        _excluded_categories: &[String],
        cutoff: time::OffsetDateTime,
        _expected_policies: &[waygate_storage::RetentionPolicy],
    ) -> Result<waygate_storage::SweepReport, waygate_storage::SweepError> {
        self.guarded_sweep(tenant_id, "*", cutoff).await
    }
}

#[tokio::test]
async fn retention_sweep_scheduler_tick_claim_is_fleet_wide() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    sqlx::query(
        "INSERT INTO audit_retention_scheduler_state (singleton, next_eligible_at) \
         VALUES (TRUE, clock_timestamp() - INTERVAL '1 second') \
         ON CONFLICT (singleton) DO UPDATE \
         SET next_eligible_at = EXCLUDED.next_eligible_at",
    )
    .execute(&pool)
    .await
    .expect("seed an expired scheduler cadence claim");
    let sweeper = Arc::new(BlockingTickSweeper::new());
    let store = Arc::new(StaticRetentionStore {
        policy: waygate_storage::RetentionPolicy {
            tenant_id: format!("pg-retention-claim-{}", Uuid::now_v7()),
            category: "invocation".to_owned(),
            delete_after_days: 30,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        },
    });

    let first_pool = pool.clone();
    let first_sweeper = sweeper.clone();
    let first_store = store.clone();
    let first = tokio::spawn(async move {
        waygate_storage::sweep_all_policies_if_tick_claimed(
            &first_pool,
            first_sweeper.as_ref(),
            first_store.as_ref(),
            std::time::Duration::from_secs(3600),
        )
        .await
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), sweeper.entered.acquire())
        .await
        .expect("first scheduler worker enters the tick without blocking")
        .expect("first scheduler worker enters the tick")
        .forget();
    sqlx::query(
        "UPDATE audit_retention_scheduler_state \
         SET next_eligible_at = clock_timestamp() - INTERVAL '1 second'",
    )
    .execute(&pool)
    .await
    .expect("expire cadence while the first fleet pass remains active");
    let cadence_is_still_expired: bool = sqlx::query_scalar(
        "SELECT next_eligible_at <= clock_timestamp() \
         FROM audit_retention_scheduler_state WHERE singleton = TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("read cadence state while the active pass owns its transaction");
    assert!(
        cadence_is_still_expired,
        "the fleet lock must exclude another active pass independently of cadence state",
    );
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        waygate_storage::sweep_all_policies_if_tick_claimed(
            &pool,
            sweeper.as_ref(),
            store.as_ref(),
            std::time::Duration::from_secs(3600),
        ),
    )
    .await;
    sqlx::query(
        "UPDATE audit_retention_scheduler_state \
         SET next_eligible_at = clock_timestamp() + INTERVAL '1 hour'",
    )
    .execute(&pool)
    .await
    .expect("restore the active pass cadence before completion");
    sweeper.release.add_permits(1);
    let first = first
        .await
        .expect("first scheduler worker joins")
        .expect("first scheduler worker releases its claim");

    assert_eq!(first, waygate_storage::RetentionSchedulerTick::Completed);
    assert_eq!(
        second
            .expect("second scheduler claim is non-blocking")
            .unwrap(),
        waygate_storage::RetentionSchedulerTick::AlreadyClaimed,
    );
    let sequential = waygate_storage::sweep_all_policies_if_tick_claimed(
        &pool,
        sweeper.as_ref(),
        store.as_ref(),
        std::time::Duration::from_secs(3600),
    )
    .await
    .expect("completed worker leaves the cadence durably claimed");
    assert_eq!(
        sequential,
        waygate_storage::RetentionSchedulerTick::AlreadyClaimed,
        "a phase-skewed replica must not run after the first worker completes",
    );
    assert_eq!(
        sweeper.calls.load(Ordering::SeqCst),
        1,
        "overlapping and sequential replicas must collectively execute one scheduler tick",
    );

    sqlx::query(
        "UPDATE audit_retention_scheduler_state \
            SET next_eligible_at = clock_timestamp() - INTERVAL '1 second'",
    )
    .execute(&pool)
    .await
    .expect("expire scheduler cadence claim");
    sweeper.release.add_permits(1);
    let next_cadence = waygate_storage::sweep_all_policies_if_tick_claimed(
        &pool,
        sweeper.as_ref(),
        store.as_ref(),
        std::time::Duration::from_secs(3600),
    )
    .await
    .expect("expired cadence permits one new fleet tick");
    assert_eq!(
        next_cadence,
        waygate_storage::RetentionSchedulerTick::Completed,
    );
    assert_eq!(
        sweeper.calls.load(Ordering::SeqCst),
        2,
        "the next cadence permits exactly one additional scheduler tick",
    );
    sqlx::query("DELETE FROM audit_retention_scheduler_state")
        .execute(&pool)
        .await
        .expect("clean scheduler claim state");
}

/// A replica running the pre-index writer can insert a valid marker without
/// calling the locator function. The database must index it automatically,
/// and a new replica's explicit same-transaction call must remain idempotent.
#[tokio::test]
async fn retention_bridge_index_covers_a_rolling_writer() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let marker_id = Uuid::now_v7();
    let tenant_id = format!("pg-sweep-rolling-writer-{}", Uuid::now_v7());
    sqlx::query(
        r#"
        INSERT INTO audit_log (
            id, ts, category, tenant_id, action, outcome, reason, row_hash
        ) VALUES (
            $1, clock_timestamp(), 'retention_sweep', $2,
            'retention.sweep', 'success',
            jsonb_build_object(
                'kind', 'retention_sweep',
                'deleted_rows', jsonb_build_array(jsonb_build_object(
                    'prev_hash', 'rolling-start',
                    'row_hash', 'rolling-end'
                ))
            )::TEXT,
            'rolling-marker-row-hash'
        )
        "#,
    )
    .bind(marker_id)
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .expect("insert marker through the rolling-deployment writer path");

    let indexed_boundary: (Option<String>, String) = sqlx::query_as(
        "SELECT start_hash, end_hash FROM audit_retention_bridge_index WHERE marker_id = $1",
    )
    .bind(marker_id)
    .fetch_one(&pool)
    .await
    .expect("the database boundary indexes a rolling-writer marker");
    assert_eq!(indexed_boundary.0.as_deref(), Some("rolling-start"));
    assert_eq!(indexed_boundary.1, "rolling-end");

    let indexed_again: bool = sqlx::query_scalar("SELECT audit_retention_bridge_index_marker($1)")
        .bind(marker_id)
        .fetch_one(&pool)
        .await
        .expect("the new writer's explicit indexing call is idempotent");
    assert!(indexed_again);
    let locator_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_bridge_index WHERE marker_id = $1",
    )
    .bind(marker_id)
    .fetch_one(&pool)
    .await
    .expect("count the idempotently indexed marker");
    assert_eq!(locator_count, 1);
}

/// Sequential bounded sweeps may create more than one hundred marker bridges
/// across a single retained gap. The verifier must follow the finite marker
/// graph rather than rejecting legitimate history at a fixed depth.
#[tokio::test]
async fn retention_chain_verifies_beyond_hundred_marker_bridges() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let sink = PgAuditSink::with_pool(pool.clone());
    let tenant_id = format!("pg-sweep-deep-{}", Uuid::now_v7());
    let tenant = waygate_core::TenantId::parse(tenant_id.clone()).expect("tenant id valid");
    let base_ts = time::OffsetDateTime::from_unix_timestamp(1_700_100_000).unwrap();
    const MARKER_DEPTH: usize = 102;

    for index in 0..MARKER_DEPTH {
        let mut event = AuditEvent::new(format!("deep-retention-{index}"), AuditOutcome::Success)
            .with_category(EvidenceCategory::Invocation)
            .with_tenant(tenant.clone());
        event.ts = base_ts + time::Duration::seconds(index as i64);
        sink.record_required(event)
            .await
            .expect("seed chained retention row");
    }

    // Advancing the cutoff one row at a time creates the same sequential
    // bridge graph as repeated full batches while keeping the regression fast.
    for index in 0..MARKER_DEPTH {
        let cutoff = base_ts + time::Duration::seconds(index as i64 + 1);
        let report = waygate_storage::run_retention_sweep(&pool, &tenant_id, "invocation", cutoff)
            .await
            .expect("bounded chained sweep");
        assert_eq!(report.rows_deleted, 1);
        assert_eq!(report.markers_written, 1);
        assert!(!report.batch_limit_reached);
    }

    use waygate_storage::AuditReader;
    let verify_report = sink
        .verify_chain(&tenant_id, None, None, None, 1_000)
        .await
        .expect("verify deep retention chain");
    assert_eq!(
        verify_report.status,
        waygate_storage::ChainVerifyStatus::Ok,
        "deep marker history must remain verifiable: {verify_report:?}",
    );

    let indexed_bridges: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_bridge_index WHERE tenant_id = $1",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .expect("count deep-retention bridge locators");
    assert_eq!(indexed_bridges as usize, MARKER_DEPTH);

    let surviving_invocations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1 AND category = 'invocation'",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .expect("count deep-retention survivors");
    assert_eq!(surviving_invocations, 0);
}

/// Permanent marker history must not be part of a new batch's authorization
/// cost. Invalid decoy payloads make this a behavioral assertion: a historical
/// marker scan would try to parse them and fail, while exact marker ids ignore
/// them entirely.
#[tokio::test]
async fn retention_delete_authorization_ignores_permanent_marker_history() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("pg-sweep-marker-history-{}", Uuid::now_v7());
    sqlx::query(
        r#"
        INSERT INTO audit_log (
            id, ts, category, tenant_id, action, outcome, reason, row_hash
        )
        SELECT md5($1 || '-marker-' || n::TEXT)::UUID,
               to_timestamp(1600000000) + n * interval '1 microsecond',
               'retention_sweep', $1, 'retention.sweep', 'success',
               'historical marker payload must not be parsed',
               md5($1 || '-row-hash-' || n::TEXT)
          FROM generate_series(1, 1000) AS n
        "#,
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("seed permanent marker history");

    sqlx::query(
        "INSERT INTO audit_log (id, ts, category, tenant_id, action, outcome) \
         VALUES ($1, to_timestamp(1700000000), 'invocation', $2, 'CallTool', 'success')",
    )
    .bind(Uuid::now_v7())
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("seed unchained row after marker history");

    let cutoff = time::OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap();
    let report = waygate_storage::run_retention_sweep(&pool, &tenant, "invocation", cutoff)
        .await
        .expect("exact current-batch markers authorize deletion");
    assert_eq!(report.rows_deleted, 1);
    assert_eq!(report.markers_written, 1);
}

/// A large unchained backlog is split at the production batch boundary. This
/// proves one request cannot materialise the full table in memory and that a
/// follow-up request drains the remainder through the controlled DB function.
#[tokio::test]
async fn retention_sweep_bounds_each_transaction() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("pg-sweep-batch-{}", Uuid::now_v7());
    let seeded = waygate_storage::RETENTION_SWEEP_BATCH_ROWS + 1;
    sqlx::query(
        r#"
        INSERT INTO audit_log (id, ts, category, tenant_id, action, outcome)
        SELECT md5($1 || '-' || n::TEXT)::UUID,
               to_timestamp(1700000000) + n * interval '1 microsecond',
               'invocation', $1, 'CallTool', 'success'
          FROM generate_series(1, $2::INT) AS n
        "#,
    )
    .bind(&tenant)
    .bind(i32::try_from(seeded).expect("batch fixture fits i32"))
    .execute(&pool)
    .await
    .expect("seed unchained retention backlog");

    let uncovered_id: Uuid =
        sqlx::query_scalar("SELECT id FROM audit_log WHERE tenant_id = $1 LIMIT 1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("read uncovered unchained id");
    let legacy_delete = sqlx::query_scalar::<_, i64>("SELECT audit_log_sweep_delete($1, $2)")
        .bind(&tenant)
        .bind(vec![uncovered_id])
        .fetch_one(&pool)
        .await
        .expect_err("the legacy wrapper must refuse deletion without exact markers");
    assert!(
        legacy_delete
            .as_database_error()
            .is_some_and(|error| error.message().contains("exact marker ids are required")),
        "legacy replicas must fail closed: {legacy_delete}",
    );

    let direct_delete = sqlx::query_scalar::<_, i64>("SELECT audit_log_sweep_delete($1, $2, $3)")
        .bind(&tenant)
        .bind(vec![uncovered_id])
        .bind(Vec::<Uuid>::new())
        .fetch_one(&pool)
        .await
        .expect_err("an unmarked unchained row must not be deletable");
    assert!(
        direct_delete
            .as_database_error()
            .is_some_and(|error| error.message().contains("marker-coverage precondition")),
        "database must reject direct unmarked deletion: {direct_delete}",
    );

    let cutoff = time::OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
    let first = waygate_storage::run_retention_sweep(&pool, &tenant, "invocation", cutoff)
        .await
        .expect("first bounded sweep");
    assert_eq!(
        first.rows_deleted as usize,
        waygate_storage::RETENTION_SWEEP_BATCH_ROWS,
    );
    assert!(
        first.batch_limit_reached,
        "a full batch must tell the caller to continue",
    );
    assert_eq!(
        first.markers_written, 1,
        "unchained ids must be covered by a visible chain-bearing marker",
    );
    let unchained_bridge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_bridge_index WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("count unchained-only marker bridge locators");
    assert_eq!(
        unchained_bridge_count, 0,
        "an unchained-only marker creates no hash-chain bridge locator",
    );

    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1 AND category = 'invocation'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("count bounded-sweep remainder");
    assert_eq!(remaining, 1, "only the overflow row may remain");

    let second = waygate_storage::run_retention_sweep(&pool, &tenant, "invocation", cutoff)
        .await
        .expect("second bounded sweep");
    assert_eq!(second.rows_deleted, 1);
    assert_eq!(second.markers_written, 1);
    assert!(
        !second.batch_limit_reached,
        "the final partial batch proves the scope drained",
    );

    let exact_tenant = format!("pg-sweep-exact-batch-{}", Uuid::now_v7());
    sqlx::query(
        r#"
        INSERT INTO audit_log (id, ts, category, tenant_id, action, outcome)
        SELECT md5($1 || '-' || n::TEXT)::UUID,
               to_timestamp(1700000000) + n * interval '1 microsecond',
               'invocation', $1, 'CallTool', 'success'
          FROM generate_series(1, $2::INT) AS n
        "#,
    )
    .bind(&exact_tenant)
    .bind(i32::try_from(waygate_storage::RETENTION_SWEEP_BATCH_ROWS).expect("batch limit fits i32"))
    .execute(&pool)
    .await
    .expect("seed exact-size retention batch");
    let exact = waygate_storage::run_retention_sweep(&pool, &exact_tenant, "invocation", cutoff)
        .await
        .expect("sweep exact-size batch");
    assert_eq!(
        exact.rows_deleted as usize,
        waygate_storage::RETENTION_SWEEP_BATCH_ROWS,
    );
    assert!(
        !exact.batch_limit_reached,
        "a batch with no look-ahead row is drained, not backlogged",
    );
}

/// Wildcard execution must exclude categories with more-specific policies.
/// This pins the SQL predicate, not only the scheduler's fake-call plumbing.
#[tokio::test]
async fn retention_wildcard_preserves_explicit_categories() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("pg-sweep-wildcard-{}", Uuid::now_v7());
    sqlx::query(
        r#"
        INSERT INTO audit_log (id, ts, category, tenant_id, action, outcome)
        VALUES ($1, to_timestamp(1700000000), 'invocation', $3, 'CallTool', 'success'),
               ($2, to_timestamp(1700000000), 'discovery',  $3, 'SearchTools', 'success')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("seed wildcard precedence rows");

    let sweeper = waygate_storage::PgSweeper::new(pool.clone());
    let report = sweeper
        .sweep_remaining_categories(
            &tenant,
            &["invocation".to_owned()],
            time::OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap(),
        )
        .await
        .expect("wildcard sweep");
    assert_eq!(report.category, "*");
    assert_eq!(report.rows_deleted, 1);
    assert_eq!(report.markers_written, 1);

    let categories: Vec<String> = sqlx::query_scalar(
        "SELECT category FROM audit_log WHERE tenant_id = $1 AND category <> 'retention_sweep'",
    )
    .bind(&tenant)
    .fetch_all(&pool)
    .await
    .expect("read wildcard survivors");
    assert_eq!(
        categories,
        vec!["invocation".to_owned()],
        "the explicit invocation policy must override the wildcard cutoff",
    );
}

/// Policy-derived sweeps revalidate their authority inside the destructive
/// transaction. A changed exact policy or wildcard exclusion set must stop the
/// sweep without deleting rows under the stale cutoff.
#[tokio::test]
async fn retention_policy_guard_rejects_stale_exact_and_wildcard_snapshots() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = waygate_storage::PgRetentionStore::new(pool.clone());
    let sweeper = waygate_storage::PgSweeper::new(pool.clone());
    let cutoff = time::OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();

    let exact_tenant = format!("pg-sweep-stale-exact-{}", Uuid::now_v7());
    sqlx::query(
        r#"
        INSERT INTO audit_log (id, ts, category, tenant_id, action, outcome)
        VALUES ($1, to_timestamp(1700000000), 'invocation', $2, 'CallTool', 'success')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(&exact_tenant)
    .execute(&pool)
    .await
    .expect("seed exact-policy row");
    let stale_exact = store
        .upsert(&exact_tenant, "invocation", 1)
        .await
        .expect("seed exact policy");
    store
        .upsert(&exact_tenant, "invocation", 365)
        .await
        .expect("change exact policy");
    let exact_error = sweeper
        .sweep_if_policy_current(&exact_tenant, "invocation", cutoff, &stale_exact)
        .await
        .expect_err("stale exact policy must stop deletion");
    assert!(matches!(
        exact_error,
        waygate_storage::SweepError::PolicyChanged { .. }
    ));
    let exact_survivors: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1 AND category = 'invocation'",
    )
    .bind(&exact_tenant)
    .fetch_one(&pool)
    .await
    .expect("count exact-policy survivor");
    assert_eq!(exact_survivors, 1);

    let current_exact = store
        .upsert(&exact_tenant, "invocation", 365)
        .await
        .expect("read current exact policy");
    store
        .upsert(&exact_tenant, "*", 730)
        .await
        .expect("seed less-specific fallback");
    let current_exact_report = sweeper
        .sweep_if_policy_current(
            &exact_tenant,
            "invocation",
            time::OffsetDateTime::now_utc() - time::Duration::days(365),
            &current_exact,
        )
        .await
        .expect("current exact policy must authorise its category");
    assert_eq!(current_exact_report.rows_deleted, 1);

    let fallback_tenant = format!("pg-sweep-current-fallback-{}", Uuid::now_v7());
    sqlx::query(
        r#"
        INSERT INTO audit_log (id, ts, category, tenant_id, action, outcome)
        VALUES ($1, to_timestamp(1700000000), 'discovery', $2, 'SearchTools', 'success')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(&fallback_tenant)
    .execute(&pool)
    .await
    .expect("seed wildcard fallback row");
    let current_fallback = store
        .upsert(&fallback_tenant, "*", 30)
        .await
        .expect("seed current wildcard fallback");
    let current_fallback_report = sweeper
        .sweep_if_policy_current(
            &fallback_tenant,
            "discovery",
            time::OffsetDateTime::now_utc() - time::Duration::days(30),
            &current_fallback,
        )
        .await
        .expect("current wildcard fallback must authorise an unlisted category");
    assert_eq!(current_fallback_report.rows_deleted, 1);

    let wildcard_tenant = format!("pg-sweep-stale-wildcard-{}", Uuid::now_v7());
    sqlx::query(
        r#"
        INSERT INTO audit_log (id, ts, category, tenant_id, action, outcome)
        VALUES ($1, to_timestamp(1700000000), 'discovery', $2, 'SearchTools', 'success')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(&wildcard_tenant)
    .execute(&pool)
    .await
    .expect("seed wildcard-policy row");
    store
        .upsert(&wildcard_tenant, "*", 1)
        .await
        .expect("seed wildcard policy");
    let stale_wildcard = store
        .list(Some(&wildcard_tenant))
        .await
        .expect("snapshot wildcard policy");
    store
        .upsert(&wildcard_tenant, "discovery", 365)
        .await
        .expect("add explicit policy");
    let wildcard_error = sweeper
        .sweep_remaining_categories_if_policies_current(
            &wildcard_tenant,
            &[],
            cutoff,
            &stale_wildcard,
        )
        .await
        .expect_err("new explicit policy must stop stale wildcard deletion");
    assert!(matches!(
        wildcard_error,
        waygate_storage::SweepError::PolicyChanged { .. }
    ));

    let surviving_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1 AND category <> 'retention_sweep'",
    )
    .bind(wildcard_tenant)
    .fetch_one(&pool)
    .await
    .expect("count rows protected by stale-policy guard");
    assert_eq!(
        surviving_rows, 1,
        "stale policy authority must delete nothing"
    );
}

/// Tier-2: the audit rollup recompute reflects new `audit_log` rows correctly
/// and idempotently. Seeds a known mix of outcomes under a unique synthetic
/// tenant, runs the recompute, and asserts `rollup_histogram` returns the
/// seeded per-outcome counts for that tenant's recent bucket. Re-running must
/// NOT change them — the recompute is idempotent (it re-derives each bucket
/// from audit_log rather than additively folding), which is exactly what makes
/// it robust to commit order / non-UUIDv7 ids / late rows. Same isolated-DB /
/// no-cleanup posture as the tests above.
#[tokio::test]
async fn rollup_folds_counts_exactly_once() {
    use waygate_storage::{rollup_histogram, rollup_once};

    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let sink = PgAuditSink::with_pool(pool.clone());

    let tenant_str = format!(
        "pg-smoke-rollup-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tenant = waygate_core::TenantId::parse(tenant_str.clone()).expect("tenant id valid");

    let mk = |outcome: AuditOutcome| AuditEvent {
        operation: None,
        id: Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        category: EvidenceCategory::Invocation,
        tenant: tenant.clone(),
        principal: None,
        action: "CallTool".into(),
        server: Some("example-compute".into()),
        tool: Some("status".into()),
        outcome,
        risk_level: Some(RiskTier::Low),
        pii: Some(false),
        policy_ids: Vec::new(),
        reason: None,
        trace_id: None,
        latency_ms: Some(5),
        target: None,
        req_scopes: Vec::new(),
        auth_method: None,
        req_roles: Vec::new(),
        side_effects: None,
        acting_agent: None,
        invocation_hierarchy: None,
    };
    // 3 success + 2 denied.
    for ev in [
        mk(AuditOutcome::Success),
        mk(AuditOutcome::Success),
        mk(AuditOutcome::Success),
        mk(AuditOutcome::Denied),
        mk(AuditOutcome::Denied),
    ] {
        sink.record_required(ev).await.expect("record_required");
    }

    rollup_once(&pool).await.expect("rollup_once");

    // Sum the rollup's counts per outcome for this tenant's recent window.
    let counts = |buckets: &[waygate_storage::HistogramBucket]| {
        let mut success = 0i64;
        let mut denied = 0i64;
        for b in buckets {
            match b.outcome.as_str() {
                "success" => success += b.count,
                "denied" => denied += b.count,
                _ => {}
            }
        }
        (success, denied)
    };
    let since = time::OffsetDateTime::now_utc() - time::Duration::hours(2);
    let first = rollup_histogram(
        &pool,
        Some(&tenant_str),
        Some(since),
        None,
        None,
        None,
        None,
        None,
        3600,
    )
    .await
    .expect("rollup_histogram");
    assert_eq!(
        counts(&first),
        (3, 2),
        "rollup should reflect the seeded 3 success + 2 denied"
    );

    // Idempotency: a second fold advances over no new rows for this tenant, so
    // the counts must be unchanged (no double-count).
    rollup_once(&pool).await.expect("second rollup_once");
    let second = rollup_histogram(
        &pool,
        Some(&tenant_str),
        Some(since),
        None,
        None,
        None,
        None,
        None,
        3600,
    )
    .await
    .expect("rollup_histogram 2");
    assert_eq!(counts(&second), (3, 2), "re-folding must not double-count");

    // rollup_tool_stats: the seeded rows are all server=example-compute tool=status,
    // so one (server,tool) group with total=5, denied=2, errors=0, p95=None.
    let tstats = waygate_storage::rollup_tool_stats(
        &pool,
        Some(&tenant_str),
        Some(since),
        None,
        None,
        None,
        None,
        None,
        20,
    )
    .await
    .expect("rollup_tool_stats");
    assert_eq!(tstats.len(), 1, "one (server,tool) group");
    let s = &tstats[0];
    assert_eq!((s.total, s.denied, s.errors), (5, 2, 0));
    assert!(s.p95_latency_ms.is_none(), "p95 is not rolled up");

    // rollup_facets: outcome dim reflects 3 success + 2 denied; server dim is
    // example-compute=5. Categorical filters do not narrow the rail (tenant+window only).
    let facets = waygate_storage::rollup_facets(&pool, Some(&tenant_str), Some(since), None)
        .await
        .expect("rollup_facets");
    let outcome: std::collections::HashMap<_, _> = facets.outcome.iter().cloned().collect();
    assert_eq!(outcome.get("success").copied(), Some(3));
    assert_eq!(outcome.get("denied").copied(), Some(2));
    let server: std::collections::HashMap<_, _> = facets.server.iter().cloned().collect();
    assert_eq!(server.get("example-compute").copied(), Some(5));
}

#[tokio::test]
async fn query_events_filters_by_policy_id() {
    // The Decision Log "decisions that matched this policy"
    // reverse lookup is `policy_ids @> ARRAY[$id]`, served by the
    // audit_log_policy_ids_gin index (migration 0059).
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    use waygate_storage::{AuditQuery, AuditReader};

    let sink = PgAuditSink::with_pool(pool.clone());

    let tenant = waygate_core::TenantId::default();
    // Unique target id so the assertion is isolated from any other rows.
    let target = format!("p-target-{}", Uuid::now_v7());
    let mk = |policy_ids: Vec<String>| AuditEvent {
        operation: None,
        id: Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        category: EvidenceCategory::Invocation,
        tenant: tenant.clone(),
        principal: Some(AuditPrincipal {
            sub: "pg-pol-user".into(),
            email: None,
            groups: vec![],
            issuer: "https://idp.example.test".into(),
            scim_active: None,
            scim_groups: Vec::new(),
        }),
        action: "CallTool".into(),
        server: Some("example-messages".into()),
        tool: Some("send".into()),
        outcome: AuditOutcome::Denied,
        risk_level: Some(RiskTier::Low),
        pii: None,
        policy_ids,
        reason: None,
        trace_id: None,
        latency_ms: None,
        target: None,
        req_scopes: Vec::new(),
        auth_method: None,
        req_roles: Vec::new(),
        side_effects: None,
        acting_agent: None,
        invocation_hierarchy: None,
    };
    sink.record_required(mk(vec![target.clone(), "other-policy".into()]))
        .await
        .expect("record hit");
    sink.record_required(mk(vec!["unrelated-policy".into()]))
        .await
        .expect("record miss");

    let q = AuditQuery {
        tenant_id: Some(tenant.as_str().to_owned()),
        policy_id: Some(target.clone()),
        ..Default::default()
    };
    let rows = sink.query_events(&q, 50, None).await.expect("query_events");
    assert!(!rows.is_empty(), "policy_id filter found the matching row");
    assert!(
        rows.iter().all(|r| r.policy_ids.contains(&target)),
        "every returned row matched the policy_id; the unrelated row is excluded"
    );
}

#[tokio::test]
async fn query_events_filters_by_category_set() {
    // The Decision Log filters to the decision-class SET
    // {invocation, llm_completion} via `category = ANY($n)`, so the policy-id
    // reverse lookup surfaces both tool-call and model decisions while
    // excluding non-decision categories (admin_mutation, …).
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    use waygate_storage::{AuditQuery, AuditReader};

    let sink = PgAuditSink::with_pool(pool.clone());

    let tenant = waygate_core::TenantId::default();
    // Unique fired policy id so the three rows are isolated from any others.
    let policy = format!("p-catset-{}", Uuid::now_v7());
    let mk = |cat: EvidenceCategory, outcome: AuditOutcome| AuditEvent {
        operation: None,
        id: Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        category: cat,
        tenant: tenant.clone(),
        principal: Some(AuditPrincipal {
            sub: "pg-catset-user".into(),
            email: None,
            groups: vec![],
            issuer: "https://idp.example.test".into(),
            scim_active: None,
            scim_groups: Vec::new(),
        }),
        action: "CallTool".into(),
        server: Some("example-messages".into()),
        tool: Some("send".into()),
        outcome,
        risk_level: Some(RiskTier::Low),
        pii: None,
        policy_ids: vec![policy.clone()],
        reason: None,
        trace_id: None,
        latency_ms: None,
        target: None,
        req_scopes: Vec::new(),
        auth_method: None,
        req_roles: Vec::new(),
        side_effects: None,
        acting_agent: None,
        invocation_hierarchy: None,
    };
    // Two decisions (tool + model) and one non-decision, all the same policy id.
    sink.record_required(mk(EvidenceCategory::Invocation, AuditOutcome::Denied))
        .await
        .expect("tool decision");
    sink.record_required(mk(EvidenceCategory::LlmCompletion, AuditOutcome::Success))
        .await
        .expect("model decision");
    sink.record_required(mk(EvidenceCategory::AdminMutation, AuditOutcome::Success))
        .await
        .expect("non-decision");

    let q = AuditQuery {
        tenant_id: Some(tenant.as_str().to_owned()),
        policy_id: Some(policy.clone()),
        categories: vec!["invocation".to_owned(), "llm_completion".to_owned()],
        ..Default::default()
    };
    let rows = sink.query_events(&q, 50, None).await.expect("query_events");
    assert_eq!(
        rows.len(),
        2,
        "both decision classes returned; the admin_mutation row is excluded"
    );
    assert!(
        rows.iter().all(|r| matches!(
            r.category.as_deref(),
            Some("invocation") | Some("llm_completion")
        )),
        "no non-decision category leaks through the set filter"
    );
}

#[tokio::test]
async fn query_events_excludes_pre_call_rows() {
    // The Decision Log drops fail-closed `pre_call` evidence
    // rows (reason_ne='pre_call' → SQL `reason IS DISTINCT FROM`), so a
    // side-effecting call under fail_closed isn't double-counted.
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    use waygate_storage::{AuditQuery, AuditReader};

    let sink = PgAuditSink::with_pool(pool.clone());

    let tenant = waygate_core::TenantId::default();
    let policy = format!("p-precall-{}", Uuid::now_v7());
    let mk = |reason: Option<&str>| AuditEvent {
        operation: None,
        id: Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        category: EvidenceCategory::Invocation,
        tenant: tenant.clone(),
        principal: Some(AuditPrincipal {
            sub: "pg-precall-user".into(),
            email: None,
            groups: vec![],
            issuer: "https://idp.example.test".into(),
            scim_active: None,
            scim_groups: Vec::new(),
        }),
        action: "CallTool".into(),
        server: Some("example-messages".into()),
        tool: Some("send".into()),
        outcome: AuditOutcome::Success,
        risk_level: Some(RiskTier::Low),
        pii: None,
        policy_ids: vec![policy.clone()],
        reason: reason.map(|s| s.to_owned()),
        trace_id: None,
        latency_ms: None,
        target: None,
        req_scopes: Vec::new(),
        auth_method: None,
        req_roles: Vec::new(),
        side_effects: None,
        acting_agent: None,
        invocation_hierarchy: None,
    };
    // The fail-closed pair: a pre-dispatch evidence row and the final row.
    sink.record_required(mk(Some("pre_call")))
        .await
        .expect("pre_call row");
    sink.record_required(mk(None)).await.expect("final row");

    let q = AuditQuery {
        tenant_id: Some(tenant.as_str().to_owned()),
        policy_id: Some(policy.clone()),
        reason_ne: Some("pre_call".to_owned()),
        ..Default::default()
    };
    let rows = sink.query_events(&q, 50, None).await.expect("query_events");
    assert_eq!(
        rows.len(),
        1,
        "only the final outcome row; the paired pre_call evidence row is excluded"
    );
    assert!(
        rows.iter().all(|r| r.reason.as_deref() != Some("pre_call")),
        "no pre_call row leaks through the reason_ne filter"
    );
}

/// The four authorization-decision INPUTS round-trip through
/// `audit_log`, AND a hash chain mixing a legacy-shaped row (all four inputs
/// absent) with a new row (all four present) verifies clean. This is the
/// load-bearing migration-safety assertion: the `b'D'` tail extension MUST be
/// zero-bytes-when-absent so the legacy-shaped row hashes byte-identically to
/// the pre-0062 chain while the new row is hashed WITH its inputs — and both
/// must walk `Ok` in the same chain. A regression that hashed the legacy row
/// differently (or dropped the new row's inputs at verify time) surfaces here
/// as a `BadRowHash` / `BrokenLink`. Same isolated-DB / no-cleanup posture as
/// the tests above.
#[tokio::test]
async fn decision_inputs_round_trip_and_mixed_chain_verifies() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    use waygate_storage::{AuditReader, ChainVerifyStatus};

    let sink = PgAuditSink::with_pool(pool.clone());

    // Unique synthetic tenant so this chain is isolated from any other rows.
    let tenant_str = format!(
        "pg-smoke-di-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tenant = waygate_core::TenantId::parse(tenant_str.clone()).expect("tenant id valid");
    let past_ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

    // Row 1: legacy-shaped decision row — principal present but the four
    // decision inputs left at their absent defaults (empty scopes/roles, None
    // auth_method, None side_effects). This is exactly how a pre-0062 row
    // deserializes, so it must hash byte-identically to the pre-extension chain.
    let legacy = AuditEvent::new("CallTool", AuditOutcome::Denied)
        .with_tenant(tenant.clone())
        .with_tool("example-messages", "send")
        .with_risk(RiskTier::Low)
        .with_pii(false)
        .with_reason("legacy-shaped: no decision inputs");
    let legacy = AuditEvent {
        ts: past_ts,
        ..legacy
    };
    let legacy_id = legacy.id;

    // Row 2: a fully-populated decision row carrying all four inputs.
    let new_row = AuditEvent::new("CallTool", AuditOutcome::Success)
        .with_tenant(tenant.clone())
        .with_tool("example-messages", "send")
        .with_risk(RiskTier::High)
        .with_pii(true)
        .with_policies(vec!["permit-mcp-users".to_owned()])
        .with_decision_inputs(
            vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()],
            Some("api_key".to_owned()),
            vec!["tenant_admin".to_owned()],
            Some(true),
        )
        .with_reason("captured decision inputs");
    let new_row = AuditEvent {
        ts: past_ts + time::Duration::seconds(1),
        ..new_row
    };
    let new_id = new_row.id;

    sink.record_required(legacy).await.expect("record legacy");
    sink.record_required(new_row).await.expect("record new");

    // Columns round-trip via the read path (fetch_event → AuditRow::from_row).
    let legacy_back = sink
        .fetch_event(legacy_id)
        .await
        .expect("fetch legacy")
        .expect("legacy row exists");
    assert!(
        legacy_back.req_scopes.is_empty()
            && legacy_back.auth_method.is_none()
            && legacy_back.req_roles.is_empty()
            && legacy_back.side_effects.is_none(),
        "legacy-shaped row reads back with all four decision inputs absent",
    );

    let new_back = sink
        .fetch_event(new_id)
        .await
        .expect("fetch new")
        .expect("new row exists");
    assert_eq!(
        new_back.req_scopes,
        vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()],
        "req_scopes round-trips",
    );
    assert_eq!(new_back.auth_method.as_deref(), Some("api_key"));
    assert_eq!(new_back.req_roles, vec!["tenant_admin".to_owned()]);
    assert_eq!(new_back.side_effects, Some(true));

    // The load-bearing assertion: a chain MIXING the absent-input legacy row
    // and the present-input new row verifies clean. If the `b'D'` extension
    // weren't zero-bytes-when-absent, the legacy row would BadRowHash; if the
    // verifier didn't thread the columns, the new row would BadRowHash.
    let report = sink
        .verify_chain(&tenant_str, None, None, None, 1000)
        .await
        .expect("verify_chain runs");
    assert_eq!(
        report.status,
        ChainVerifyStatus::Ok,
        "a chain mixing absent-input (legacy-shaped) and present-input rows \
         must verify clean: {:?}",
        report,
    );
    assert_eq!(report.rows_walked, 2, "both rows walked");
    assert!(report.first_mismatch.is_none());
}

/// The `acting_agent` column round-trips through
/// `audit_log`, AND a hash chain mixing a row with NO acting_agent (the legacy
/// shape) and a row WITH one verifies clean. Same load-bearing migration-safety
/// shape as `decision_inputs_round_trip_and_mixed_chain_verifies`: the `b'A'`
/// (migration 0068) tail extension MUST be zero-bytes-when-absent so the
/// no-agent row hashes byte-identically to the pre-0068 chain while the
/// agent-tagged row is hashed WITH it — and both walk `Ok` in the same chain. A
/// regression that hashed the no-agent row differently (or dropped the tagged
/// row's `acting_agent` at verify time) surfaces here as `BadRowHash` /
/// `BrokenLink`. The column is read back via raw SQL (the `AuditRow` read model
/// doesn't surface `acting_agent` yet — deferred to the display PR). Same
/// isolated-DB / no-cleanup posture as the tests above.
#[tokio::test]
async fn acting_agent_round_trip_and_mixed_chain_verifies() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    use waygate_storage::{AuditReader, ChainVerifyStatus};

    let sink = PgAuditSink::with_pool(pool.clone());

    let tenant_str = format!(
        "pg-smoke-agent-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tenant = waygate_core::TenantId::parse(tenant_str.clone()).expect("tenant id valid");
    let past_ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

    // Row 1: no acting_agent — exactly how a pre-0068 row deserializes, so it
    // must hash byte-identically to the pre-extension chain.
    let human = AuditEvent::new("CallTool", AuditOutcome::Success)
        .with_tenant(tenant.clone())
        .with_tool("example-messages", "send")
        .with_reason("human acted directly");
    let human = AuditEvent {
        ts: past_ts,
        ..human
    };
    let human_id = human.id;

    // Row 2: an agent-attributed row (actor = agent, on-behalf-of = principal).
    let agent = AuditEvent::new("CallTool", AuditOutcome::Success)
        .with_tenant(tenant.clone())
        .with_tool("example-messages", "send")
        .with_acting_agent(Some("agent:ops-chat".to_owned()))
        .with_reason("agent acted on behalf of the human");
    let agent = AuditEvent {
        ts: past_ts + time::Duration::seconds(1),
        ..agent
    };
    let agent_id = agent.id;

    sink.record_required(human).await.expect("record human");
    sink.record_required(agent).await.expect("record agent");

    // Column round-trips via raw SQL (AuditRow doesn't surface it yet).
    let human_agent: Option<String> =
        sqlx::query_scalar("SELECT acting_agent FROM audit_log WHERE id = $1")
            .bind(human_id)
            .fetch_one(&pool)
            .await
            .expect("read human acting_agent");
    assert_eq!(
        human_agent, None,
        "a direct human action has no acting_agent"
    );

    let agent_agent: Option<String> =
        sqlx::query_scalar("SELECT acting_agent FROM audit_log WHERE id = $1")
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .expect("read agent acting_agent");
    assert_eq!(
        agent_agent.as_deref(),
        Some("agent:ops-chat"),
        "the agent-attributed row records acting_agent",
    );

    // Load-bearing: a chain MIXING the no-agent row and the agent-tagged row
    // verifies clean. If the `b'A'` extension weren't zero-bytes-when-absent the
    // human row would BadRowHash; if the verifier didn't thread the column the
    // agent row would BadRowHash.
    let report = sink
        .verify_chain(&tenant_str, None, None, None, 1000)
        .await
        .expect("verify_chain runs");
    assert_eq!(
        report.status,
        ChainVerifyStatus::Ok,
        "a chain mixing no-acting_agent and agent-tagged rows must verify clean: {:?}",
        report,
    );
    assert_eq!(report.rows_walked, 2, "both rows walked");
    assert!(report.first_mismatch.is_none());
}

#[tokio::test]
async fn invocation_hierarchy_round_trips_and_mixed_chain_verifies() {
    use std::num::NonZeroU32;

    use waygate_core::InvocationHierarchy;
    use waygate_storage::{AuditReader, ChainVerifyStatus};

    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let sink = PgAuditSink::with_pool(pool);
    let tenant_str = format!(
        "pg-smoke-execution-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tenant = waygate_core::TenantId::parse(tenant_str.clone()).expect("tenant id valid");
    let hierarchy = InvocationHierarchy::new(
        Uuid::now_v7(),
        NonZeroU32::new(2).unwrap(),
        Uuid::now_v7(),
        NonZeroU32::new(1).unwrap(),
    );

    sink.record_required(
        AuditEvent::new("CallTool", AuditOutcome::Success)
            .with_tenant(tenant.clone())
            .with_tool("email", "read"),
    )
    .await
    .expect("record direct call");
    let nested = AuditEvent::new("CallTool", AuditOutcome::Success)
        .with_tenant(tenant)
        .with_tool("email", "read")
        .with_invocation_hierarchy(Some(hierarchy));
    let nested_id = nested.id;
    sink.record_required(nested)
        .await
        .expect("record nested call");

    let stored = sink
        .fetch_event(nested_id)
        .await
        .expect("fetch nested call")
        .expect("nested call exists");
    assert_eq!(stored.invocation_hierarchy, Some(hierarchy));

    let report = sink
        .verify_chain(&tenant_str, None, None, None, 1000)
        .await
        .expect("verify chain");
    assert_eq!(report.status, ChainVerifyStatus::Ok, "{report:?}");
    assert_eq!(report.rows_walked, 2);
}
