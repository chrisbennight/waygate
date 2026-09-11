//! Typed surface over the `evidence_outbox` table.
//!
//! [`PgAuditSink::record_required`] writes outbox rows alongside
//! the audit INSERT; the background drain worker
//! ([`crate::drain`]) ships them through the exporter registry.
//!
//! The helpers here are the API the recorder + the drain
//! worker share:
//!
//! - [`OutboxStatus`] mirrors the SQL CHECK constraint as a
//!   typed enum so callers can pattern-match without
//!   stringly-typed slipups.
//! - [`OutboxEntry`] is the row shape the drain worker
//!   consumes.
//! - [`enqueue`] writes one row INSIDE an existing transaction —
//!   so the audit INSERT and N outbox INSERTs commit atomically
//!   (the outbox-pattern correctness property).
//! - [`dequeue_ready`] / [`mark_delivered`] / [`mark_failed`]
//!   are the drain worker's read/write surface; they don't take
//!   an explicit transaction because each is a single statement.
//!
//! Backoff schedule + dead-letter threshold are
//! drain-worker concerns; this module is the persistence layer.

use serde_json::Value;
use sqlx::postgres::{PgPool, Postgres};
use sqlx::{Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::StorageError;

/// Lifecycle of one outbox row. Mirrors the SQL `CHECK
/// (status IN (...))` constraint; round-tripping through
/// [`OutboxStatus::as_str`] / [`OutboxStatus::parse`] keeps the
/// app-side enum and the DB-side string in lock-step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxStatus {
    /// Awaiting drain — the next sweep that picks up rows where
    /// `next_attempt <= now()` will try to ship this one.
    Pending,
    /// Terminal success.
    Delivered,
    /// Most recent ship attempt failed; the drain re-flips to
    /// `Pending` after computing the next backoff slot.
    Failed,
    /// Exhausted retry budget; operator action needed (admin
    /// view, manual replay, or delete).
    DeadLetter,
}

impl OutboxStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OutboxStatus::Pending => "pending",
            OutboxStatus::Delivered => "delivered",
            OutboxStatus::Failed => "failed",
            OutboxStatus::DeadLetter => "dead_letter",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => OutboxStatus::Pending,
            "delivered" => OutboxStatus::Delivered,
            "failed" => OutboxStatus::Failed,
            "dead_letter" => OutboxStatus::DeadLetter,
            _ => return None,
        })
    }
}

/// One outbox row as the drain worker sees it. Carries the
/// rendered `payload` plus the backoff bookkeeping.
#[derive(Debug, Clone)]
pub struct OutboxEntry {
    pub event_id: Uuid,
    pub target_sink: String,
    pub payload: Value,
    pub attempt_count: i32,
    pub last_attempt: Option<OffsetDateTime>,
    pub next_attempt: OffsetDateTime,
    pub status: OutboxStatus,
    pub created_at: OffsetDateTime,
}

/// Enqueue one outbox row INSIDE the caller's transaction.
///
/// The recorder's `record_required` is the intended caller: it
/// opens a `tx`, INSERTs the audit row, calls `enqueue(&mut tx,
/// ...)` once per configured target sink, then commits. If any
/// INSERT fails the whole tx rolls back, so an audit_log row
/// without its outbox companions can never exist (the outbox
/// pattern's correctness property — exactly what makes "shipped
/// to N sinks" reliable).
///
/// `next_attempt` defaults to `now()` in the SQL — the new row
/// is immediately eligible for the next drain sweep.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    event_id: Uuid,
    target_sink: &str,
    payload: &Value,
) -> Result<(), StorageError> {
    sqlx::query(
        r#"
        INSERT INTO evidence_outbox
            (event_id, target_sink, payload)
        VALUES
            ($1, $2, $3)
        "#,
    )
    .bind(event_id)
    .bind(target_sink)
    .bind(payload)
    .execute(&mut **tx)
    .await
    .map_err(StorageError::Connect)?;
    Ok(())
}

/// Read up to `limit` outbox rows that are eligible for ship
/// (`status IN ('pending','failed') AND next_attempt <= now()`),
/// oldest-first. `pending` = never attempted; `failed` = tried
/// at least once and ready to retry — both belong in the drain
/// queue per the retry-loop contract documented on
/// `evidence_outbox.status`.
///
/// Does NOT lock the rows — the drain worker calls this to
/// build a batch, then per row attempts the exporter and
/// follows with [`mark_delivered`] or [`mark_failed`]. Two
/// drain workers running against the same DB would each
/// dequeue overlapping batches; that's acceptable because each
/// per-row UPDATE has a `status IN ('pending','failed')` guard
/// that prevents a stale worker from overwriting a row another
/// worker already moved to a terminal state. For tight
/// one-worker-per-row semantics a follow-up could add
/// `FOR UPDATE SKIP LOCKED`, but the operator doesn't run
/// multiple drains today.
pub async fn dequeue_ready(pool: &PgPool, limit: i64) -> Result<Vec<OutboxEntry>, StorageError> {
    let rows = sqlx::query(
        r#"
        SELECT event_id, target_sink, payload, attempt_count,
               last_attempt, next_attempt, status, created_at
          FROM evidence_outbox
         WHERE status IN ('pending', 'failed')
           AND next_attempt <= now()
         ORDER BY next_attempt
         LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(StorageError::Connect)?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let status: String = r.get("status");
            Some(OutboxEntry {
                event_id: r.get("event_id"),
                target_sink: r.get("target_sink"),
                payload: r.get("payload"),
                attempt_count: r.get("attempt_count"),
                last_attempt: r.get("last_attempt"),
                next_attempt: r.get("next_attempt"),
                status: OutboxStatus::parse(&status)?,
                created_at: r.get("created_at"),
            })
        })
        .collect())
}

/// Mark a row terminally `delivered` (the exporter shipped it
/// successfully). Idempotent — a second call returns
/// `rows_affected = 0` because the row is no longer in an
/// active state. The `status IN ('pending','failed')` guard
/// prevents a stale worker from
/// overwriting an already-terminal row (delivered or
/// dead_letter); without it, a duplicate `mark_delivered` would
/// clobber the original `last_attempt`.
pub async fn mark_delivered(
    pool: &PgPool,
    event_id: Uuid,
    target_sink: &str,
) -> Result<u64, StorageError> {
    let r = sqlx::query(
        r#"
        UPDATE evidence_outbox
           SET status       = 'delivered',
               last_attempt = now()
         WHERE event_id    = $1
           AND target_sink = $2
           AND status IN ('pending', 'failed')
        "#,
    )
    .bind(event_id)
    .bind(target_sink)
    .execute(pool)
    .await
    .map_err(StorageError::Connect)?;
    Ok(r.rows_affected())
}

/// Mark a row `failed` (or `dead_letter` if it's reached the
/// retry budget). Bumps `attempt_count`, sets `last_attempt =
/// now()`, and sets `next_attempt = $next_attempt` so the
/// caller controls the backoff curve.
///
/// `dead_letter` is reserved for the explicit-give-up path —
/// callers pass `OutboxStatus::DeadLetter` when they've decided
/// the row is unrecoverable. The default `failed` status is
/// re-picked-up by [`dequeue_ready`] once `next_attempt <=
/// now()` (no separate "flip back to pending" step needed; the
/// drain query reads `status IN ('pending','failed')`).
///
/// Idempotent at terminal states: the `status IN
/// ('pending','failed')` guard prevents a stale worker from
/// overwriting a row another worker already moved to `delivered`
/// or `dead_letter`. A second `mark_failed` against a delivered
/// row returns `rows_affected = 0`.
pub async fn mark_failed(
    pool: &PgPool,
    event_id: Uuid,
    target_sink: &str,
    next_attempt: OffsetDateTime,
    new_status: OutboxStatus,
) -> Result<u64, StorageError> {
    // Pin to the two legal "not delivered" terminal states so a
    // typo can't smuggle in a status the CHECK constraint
    // accepts but the drain semantics don't.
    let status = match new_status {
        OutboxStatus::Failed | OutboxStatus::DeadLetter => new_status,
        _ => OutboxStatus::Failed,
    };
    let r = sqlx::query(
        r#"
        UPDATE evidence_outbox
           SET status        = $3,
               attempt_count = attempt_count + 1,
               last_attempt  = now(),
               next_attempt  = $4
         WHERE event_id    = $1
           AND target_sink = $2
           AND status IN ('pending', 'failed')
        "#,
    )
    .bind(event_id)
    .bind(target_sink)
    .bind(status.as_str())
    .bind(next_attempt)
    .execute(pool)
    .await
    .map_err(StorageError::Connect)?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_via_strings() {
        for s in [
            OutboxStatus::Pending,
            OutboxStatus::Delivered,
            OutboxStatus::Failed,
            OutboxStatus::DeadLetter,
        ] {
            assert_eq!(OutboxStatus::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn unknown_status_string_returns_none() {
        assert!(OutboxStatus::parse("retrying").is_none());
        assert!(OutboxStatus::parse("").is_none());
        // CHECK constraint is case-sensitive, parser matches.
        assert!(OutboxStatus::parse("PENDING").is_none());
    }

    #[test]
    fn status_strings_match_migration_check_constraint() {
        // The SQL CHECK is `status IN ('pending','delivered',
        // 'failed','dead_letter')`. A rename here without the
        // migration would silently reject every outbox INSERT
        // — pin the canonical strings.
        assert_eq!(OutboxStatus::Pending.as_str(), "pending");
        assert_eq!(OutboxStatus::Delivered.as_str(), "delivered");
        assert_eq!(OutboxStatus::Failed.as_str(), "failed");
        assert_eq!(OutboxStatus::DeadLetter.as_str(), "dead_letter");
    }
}
