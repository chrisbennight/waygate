//! Opt-in throughput diagnostic for the per-tenant audit hash chain.
//!
//! A chained write takes a tenant-scoped advisory lock, reads the chain head,
//! and inserts, all in one transaction, so within one tenant the chain is
//! serial by construction. This diagnostic measures what that serialization
//! actually costs, so a decision about restructuring the chain can rest on a
//! number rather than on the shape of the code:
//!
//! - the sequential rate one tenant's chain sustains on each write path:
//!   required (fail-closed) writes, which the invocation pipeline makes inline
//!   for side-effecting calls and which also look up the tenant's export
//!   routing before commit; and chained best-effort writes in their local
//!   mode, which skip that lookup and are what the chained best-effort queue's
//!   worker calls, in order, for one tenant's events — so that rate is the
//!   queue's per-tenant ceiling. A best-effort event that carries an
//!   invocation hierarchy uses the export mode and pays the routing lookup
//!   too, so it runs at roughly the required rate;
//! - whether per-write cost grows with chain length, which would mean the
//!   chain-head lookup is not index-backed;
//! - what concurrent writers on one tenant achieve, versus the same
//!   concurrency spread across tenants.
//!
//! Every chain written is verified afterwards, so concurrency is also shown
//! not to fork a chain.
//!
//! It is `#[ignore]`d because its output is timing, and required tests must
//! not depend on timing (see `docs/testing.md`). Run it explicitly against a
//! disposable database:
//!
//! ```text
//! AUDIT_DATABASE_URL=postgres://... cargo test -p waygate-storage --test suite \
//!     pg_audit_chain_throughput -- --ignored --nocapture
//! ```
//!
//! Figures are machine- and database-dependent comparison observations, not
//! thresholds or capacity forecasts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_core::TenantId;
use waygate_evidence::audit::{AuditEvent, AuditOutcome, EvidenceRecorder};
use waygate_storage::{AuditReader, ChainVerifyStatus, PgAuditSink};

/// Writes per measured phase. Large enough to read a stable median and a
/// meaningful high percentile, small enough to run in seconds.
const WRITES: usize = 2_000;
/// Concurrent writers in the contended phases.
const WRITERS: usize = 8;

fn tenant(run: &str, label: &str) -> TenantId {
    TenantId::parse(format!("chain-{run}-{label}")).expect("valid tenant id")
}

fn event(tenant: &TenantId, index: usize) -> AuditEvent {
    AuditEvent::new(format!("chain-throughput-{index}"), AuditOutcome::Success)
        .with_tenant(tenant.clone())
        .with_tool("throughput-server", "throughput-tool")
}

fn percentile(samples: &mut [Duration], percentile: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() - 1) * percentile / 100]
}

fn rate(writes: usize, elapsed: Duration) -> f64 {
    writes as f64 / elapsed.as_secs_f64()
}

/// Sequential required writes on one tenant, timing each.
async fn sequential(sink: &PgAuditSink, tenant: &TenantId, offset: usize) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(WRITES);
    for index in 0..WRITES {
        let started = Instant::now();
        sink.record_required(event(tenant, offset + index))
            .await
            .expect("record_required");
        samples.push(started.elapsed());
    }
    samples
}

/// Sequential chained best-effort writes on one tenant, timing each. This is
/// the call the chained best-effort queue's worker makes for each event of one
/// tenant, in order; with a single writer there is no lock contention, so
/// every event lands, which the caller verifies.
async fn sequential_best_effort(sink: &PgAuditSink, tenant: &TenantId) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(WRITES);
    for index in 0..WRITES {
        let started = Instant::now();
        sink.record_chained_best_effort(event(tenant, index)).await;
        samples.push(started.elapsed());
    }
    samples
}

/// `WRITERS` tasks writing `WRITES` events in total, each task on the tenant
/// `tenant_for(task)` chooses. Returns the wall-clock time for all writes.
async fn concurrent(sink: &Arc<PgAuditSink>, tenant_for: impl Fn(usize) -> TenantId) -> Duration {
    let per_writer = WRITES / WRITERS;
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(WRITERS);
    for writer in 0..WRITERS {
        let sink = sink.clone();
        let tenant = tenant_for(writer);
        tasks.push(tokio::spawn(async move {
            for index in 0..per_writer {
                sink.record_required(event(&tenant, writer * per_writer + index))
                    .await
                    .expect("record_required");
            }
        }));
    }
    for task in tasks {
        task.await.expect("writer task");
    }
    started.elapsed()
}

async fn assert_chain_intact(sink: &PgAuditSink, tenant: &TenantId, expected_rows: usize) {
    let report = sink
        .verify_chain(
            tenant.as_str(),
            None,
            None,
            None,
            (expected_rows + 1) as i64,
        )
        .await
        .expect("verify_chain");
    assert!(
        matches!(report.status, ChainVerifyStatus::Ok),
        "chain for {tenant} must verify intact after concurrent writes: {:?}",
        report.status,
    );
    assert_eq!(
        report.rows_walked as usize, expected_rows,
        "chain for {tenant} must contain every write exactly once",
    );
}

#[tokio::test]
#[ignore = "timing diagnostic; run with --ignored against a disposable AUDIT_DATABASE_URL"]
async fn chained_write_throughput_by_tenant_concurrency() {
    // Applies migrations; the measured pool below needs more than its two
    // connections to exercise concurrency.
    let Some(bootstrap) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    bootstrap.close().await;
    let url = std::env::var("AUDIT_DATABASE_URL").expect("checked by the skip preamble");
    let pool = PgPoolOptions::new()
        .max_connections((WRITERS + 2) as u32)
        .connect(&url)
        .await
        .expect("connect measured pool");
    let sink = Arc::new(PgAuditSink::with_pool(pool));
    let run = Uuid::new_v4().simple().to_string()[..12].to_owned();

    // One tenant, one writer: the chain's serial rate. Run twice on the same
    // chain so the second phase starts WRITES rows deep.
    let serial = tenant(&run, "serial");
    let mut shallow = sequential(&sink, &serial, 0).await;
    let mut deep = sequential(&sink, &serial, WRITES).await;
    let shallow_total: Duration = shallow.iter().sum();
    let deep_total: Duration = deep.iter().sum();
    assert_chain_intact(&sink, &serial, 2 * WRITES).await;

    // One tenant, one writer, chained best-effort in its local mode: the
    // queue worker's per-tenant ceiling. Every write must land, so a lost
    // write here would show as a short chain rather than as a faster rate.
    let best_effort = tenant(&run, "best-effort");
    let mut best_effort_samples = sequential_best_effort(&sink, &best_effort).await;
    let best_effort_total: Duration = best_effort_samples.iter().sum();
    assert_chain_intact(&sink, &best_effort, WRITES).await;

    // One tenant, many writers: concurrency the advisory lock serializes.
    let contended = tenant(&run, "contended");
    let contended_elapsed = concurrent(&sink, |_| contended.clone()).await;
    assert_chain_intact(&sink, &contended, WRITES / WRITERS * WRITERS).await;

    // Many tenants, one writer each: the cross-tenant parallelism the lock
    // is scoped to preserve.
    let spread_elapsed =
        concurrent(&sink, |writer| tenant(&run, &format!("spread-{writer}"))).await;
    for writer in 0..WRITERS {
        assert_chain_intact(
            &sink,
            &tenant(&run, &format!("spread-{writer}")),
            WRITES / WRITERS,
        )
        .await;
    }

    println!("writes per phase: {WRITES}, concurrent writers: {WRITERS}");
    println!(
        "required, one tenant, sequential, chain 0..{WRITES}:      {:>8.0} writes/s  p50 {:?}  p99 {:?}",
        rate(WRITES, shallow_total),
        percentile(&mut shallow, 50),
        percentile(&mut shallow, 99),
    );
    println!(
        "required, one tenant, sequential, chain {WRITES}..{}:   {:>8.0} writes/s  p50 {:?}  p99 {:?}",
        2 * WRITES,
        rate(WRITES, deep_total),
        percentile(&mut deep, 50),
        percentile(&mut deep, 99),
    );
    println!(
        "best-effort (local), one tenant, sequential:        {:>8.0} writes/s  p50 {:?}  p99 {:?}",
        rate(WRITES, best_effort_total),
        percentile(&mut best_effort_samples, 50),
        percentile(&mut best_effort_samples, 99),
    );
    println!(
        "required, one tenant, {WRITERS} concurrent writers:          {:>8.0} writes/s",
        rate(WRITES / WRITERS * WRITERS, contended_elapsed),
    );
    println!(
        "required, {WRITERS} tenants, one writer each:               {:>8.0} writes/s",
        rate(WRITES / WRITERS * WRITERS, spread_elapsed),
    );
}
