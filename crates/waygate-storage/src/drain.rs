//! Background drain worker for `evidence_outbox`.
//!
//! Walks [`crate::outbox::dequeue_ready`] batches every tick,
//! dispatches each row to its matching exporter in
//! [`crate::exporter::ExporterRegistry`], and:
//!
//! - `Ok` from the exporter → [`crate::outbox::mark_delivered`].
//! - `ExportError::Transient` → [`crate::outbox::mark_failed`]
//!   with status `Failed` and a backoff-scheduled
//!   `next_attempt`. Eligible to retry on the next tick that
//!   sees `next_attempt <= now()`.
//! - `ExportError::Permanent` → `mark_failed` with status
//!   `DeadLetter` immediately. The exporter declared the row
//!   unshippable; no amount of retry will fix it.
//! - Attempt count past `MAX_ATTEMPTS` for a Transient failure
//!   → also `DeadLetter`. Bounds the retry storm.
//! - No exporter registered for `target_sink` → `DeadLetter`
//!   immediately, with a WARN. This is an operator config
//!   error (a target named in `GATEWAY_EVIDENCE_OUTBOX_TARGETS`
//!   without a corresponding registered impl); failing loudly
//!   beats silently retrying forever.
//!
//! Backoff is exponential with jitter, bounded:
//!   attempt 0 → ~5s, attempt 1 → ~10s, attempt 2 → ~20s, …
//!   capped at MAX_BACKOFF.
//!
//! The drain awaits `shutdown` on every tick so SIGTERM drains
//! cleanly. Mirrors the shape of the AS and grant sweepers.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use tokio::pin;
use tokio::time::interval;

use crate::exporter::{ExportError, ExporterRegistry};
use crate::outbox::{dequeue_ready, mark_delivered, mark_failed, OutboxEntry, OutboxStatus};

/// Number of dispatch attempts allowed per row before
/// dead-lettering. The dispatch uses `>= MAX_ATTEMPTS` so:
///   - 7 retry-backoff slots fire (5+10+20+40+80+160+320 ≈
///     10.6 minutes total elapsed wall-clock)
///   - The 8th dispatch attempt's failure dead-letters
///     immediately (no further backoff)
///
/// In total the row is attempted at most 8 times — matching
/// the README's "dead-letters after 8 transient failures"
/// claim. Pure `next_attempt_after` still computes a slot for
/// attempt 8 (640s) because it's a pure schedule function and
/// callers other than the dispatch may want it, but the
/// dispatch never waits that slot.
///
/// (The dispatch compares with `>=`, not `>`: a `>` comparison
/// would let the 8th backoff slot fire and dead-letter on the
/// 9th failure — off-by-one against the README.)
const MAX_ATTEMPTS: i32 = 8;
/// Initial backoff slot. The schedule below doubles per attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
/// Cap so the schedule plateaus rather than growing forever
/// past `MAX_ATTEMPTS`.
const MAX_BACKOFF: Duration = Duration::from_secs(3600);
/// How many outbox rows the drain pulls per tick. A higher
/// batch helps catch up after an outage; an unbounded batch
/// would stall the tick on a backlog. 100 is a conservative
/// per-tick ceiling. (`outbox::dequeue_ready` binds the
/// caller-supplied `limit` directly with no cap of its own —
/// this is the only ceiling.)
const BATCH_SIZE: i64 = 100;

/// Compute the next-attempt time for a row that just failed
/// transiently. Pure function so the schedule is unit-testable.
///
/// `attempt_count` is the row's count *after* this failure was
/// recorded — so attempt_count=1 means "one transient failure
/// has been observed; this is the schedule for the next retry."
/// Returns the `OffsetDateTime` at which the row becomes
/// eligible for retry.
pub fn next_attempt_after(now: OffsetDateTime, attempt_count: i32) -> OffsetDateTime {
    // Exponential: 5s × 2^(attempt_count-1), capped at 1h.
    // Shift `attempt_count - 1` so the first failure backoff is
    // ~5s (not 10s).
    let n = attempt_count.saturating_sub(1).max(0) as u32;
    let multiplier = 1u64.checked_shl(n).unwrap_or(u64::MAX);
    let backoff_secs = INITIAL_BACKOFF
        .as_secs()
        .saturating_mul(multiplier)
        .min(MAX_BACKOFF.as_secs());
    now + time::Duration::seconds(backoff_secs as i64)
}

/// Run the outbox drain until `shutdown` fires.
///
/// `interval_period` is the polling cadence — how often the
/// drain pulls a fresh batch from `dequeue_ready`. A small
/// value (5–30s) catches up quickly after a transient outage;
/// too small wastes DB round-trips on the idle path. Operators
/// tune via `GATEWAY_EVIDENCE_DRAIN_INTERVAL_SECONDS`.
///
/// `registry` is the operator-configured target→exporter map.
/// Rows whose `target_sink` doesn't match any registered
/// exporter are immediately dead-lettered with a WARN — that's
/// a config error (target named in env without a registered
/// impl), and failing loudly is the safer direction.
pub async fn run_outbox_drain(
    pool: PgPool,
    registry: Arc<ExporterRegistry>,
    interval_period: Duration,
    shutdown: impl Future<Output = ()>,
) {
    pin!(shutdown);
    let mut ticker = interval(interval_period);
    // Skip the immediate t=0 tick — the table is presumably
    // empty at boot, and the recorder integration just landed
    // any startup audit row in its own transaction. Real work
    // starts after one interval.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    tracing::info!(
        interval_secs = interval_period.as_secs(),
        targets = ?registry.target_names(),
        batch = BATCH_SIZE,
        "evidence outbox drain started",
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("evidence outbox drain shutting down");
                return;
            }
            _ = ticker.tick() => {
                drain_one_batch(&pool, registry.as_ref()).await;
            }
        }
    }
}

/// Pull a batch and dispatch each row. Exposed so a test can
/// drive a single drain pass deterministically without
/// instantiating the interval loop.
pub async fn drain_one_batch(pool: &PgPool, registry: &ExporterRegistry) {
    let batch = match dequeue_ready(pool, BATCH_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "outbox dequeue failed; retrying on next tick");
            waygate_telemetry::metrics::record_evidence_drain_error();
            return;
        }
    };
    if batch.is_empty() {
        tracing::debug!("outbox drain: no pending rows");
        return;
    }
    tracing::debug!(count = batch.len(), "outbox drain: dispatching batch");
    for row in batch {
        dispatch_one(pool, registry, row).await;
    }
}

/// Dispatch one row. Pure async wrapper around the
/// per-target exporter call + post-call status update.
async fn dispatch_one(pool: &PgPool, registry: &ExporterRegistry, row: OutboxEntry) {
    let Some(exporter) = registry.get(&row.target_sink) else {
        // Operator named a target in the env without
        // registering an exporter for it. Dead-letter
        // immediately so the row doesn't tie up the drain
        // forever, and WARN loudly so the operator notices.
        tracing::warn!(
            event_id = %row.event_id,
            target = %row.target_sink,
            "no exporter registered for target_sink; dead-lettering",
        );
        let _ = mark_failed(
            pool,
            row.event_id,
            &row.target_sink,
            OffsetDateTime::now_utc(),
            OutboxStatus::DeadLetter,
        )
        .await;
        waygate_telemetry::metrics::record_evidence_drain(&row.target_sink, "dead_letter");
        return;
    };

    match exporter
        .export(&row.target_sink, row.event_id, &row.payload)
        .await
    {
        Ok(()) => {
            if let Err(e) = mark_delivered(pool, row.event_id, &row.target_sink).await {
                tracing::warn!(
                    event_id = %row.event_id,
                    target = %row.target_sink,
                    error = %e,
                    "outbox mark_delivered failed; the next drain tick will see the row pending again",
                );
            }
            waygate_telemetry::metrics::record_evidence_drain(&row.target_sink, "delivered");
        }
        Err(ExportError::Permanent(detail)) => {
            tracing::warn!(
                event_id = %row.event_id,
                target = %row.target_sink,
                detail,
                "exporter declared permanent failure; dead-lettering",
            );
            let _ = mark_failed(
                pool,
                row.event_id,
                &row.target_sink,
                OffsetDateTime::now_utc(),
                OutboxStatus::DeadLetter,
            )
            .await;
            waygate_telemetry::metrics::record_evidence_drain(&row.target_sink, "dead_letter");
        }
        Err(ExportError::Transient(detail)) => {
            // Bump the count; if past the retry budget, give up.
            // `>=` so the dispatch makes at most
            // MAX_ATTEMPTS = 8 attempts total before
            // dead-lettering (matches the README + the
            // "8 transient failures" claim). `saturating_add`
            // guards the i32 add — an extreme attempt_count
            // value won't wrap to negative and cause the row
            // to never dead-letter.
            let new_attempt_count = row.attempt_count.saturating_add(1);
            let (status, next_attempt) = if new_attempt_count >= MAX_ATTEMPTS {
                (OutboxStatus::DeadLetter, OffsetDateTime::now_utc())
            } else {
                (
                    OutboxStatus::Failed,
                    next_attempt_after(OffsetDateTime::now_utc(), new_attempt_count),
                )
            };
            let outcome = match status {
                OutboxStatus::Failed => "failed",
                OutboxStatus::DeadLetter => "dead_letter",
                _ => "failed",
            };
            tracing::info!(
                event_id = %row.event_id,
                target = %row.target_sink,
                attempt = new_attempt_count,
                detail,
                next_attempt = %next_attempt,
                "exporter transient failure; will retry (or dead-letter at budget)",
            );
            if let Err(e) =
                mark_failed(pool, row.event_id, &row.target_sink, next_attempt, status).await
            {
                tracing::warn!(
                    event_id = %row.event_id,
                    target = %row.target_sink,
                    error = %e,
                    "outbox mark_failed failed; row state may be inconsistent",
                );
            }
            waygate_telemetry::metrics::record_evidence_drain(&row.target_sink, outcome);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the backoff schedule. Attempt N goes to roughly
    /// 5s × 2^(N-1), capped at MAX_BACKOFF. Tests the pure
    /// function so a regression in the multiplier is caught
    /// without driving the whole drain loop.
    #[test]
    fn backoff_schedule_matches_documented_curve() {
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let cases = [
            (1, 5),
            (2, 10),
            (3, 20),
            (4, 40),
            (5, 80),
            (6, 160),
            (7, 320),
            (8, 640),
        ];
        for (attempt, expected_secs) in cases {
            let delta = (next_attempt_after(now, attempt) - now).whole_seconds();
            assert_eq!(
                delta, expected_secs,
                "attempt={attempt} should schedule +{expected_secs}s, got +{delta}s",
            );
        }
    }

    #[test]
    fn backoff_is_capped_at_max() {
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        // attempt=20 would compute 5 × 2^19 = ~2.6M seconds
        // without the cap; the cap floors it at 3600s.
        let delta = (next_attempt_after(now, 20) - now).whole_seconds();
        assert_eq!(delta, MAX_BACKOFF.as_secs() as i64);
    }

    #[test]
    fn backoff_handles_zero_and_negative_attempt_safely() {
        // attempt=0 (caller mis-passed): doesn't panic, doesn't
        // overflow; returns the floor backoff slot.
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let delta = (next_attempt_after(now, 0) - now).whole_seconds();
        assert_eq!(delta, INITIAL_BACKOFF.as_secs() as i64);
        let delta = (next_attempt_after(now, -1) - now).whole_seconds();
        assert_eq!(delta, INITIAL_BACKOFF.as_secs() as i64);
    }
}
