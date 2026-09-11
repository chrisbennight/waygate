-- Phase 7 PR7-1: evidence outbox.
--
-- Migration-only scaffolding for the evidence pipeline's
-- transactional outbox. Today's `PgAuditSink::record_required`
-- writes a single INSERT into `audit_log` and returns; an
-- external exporter (OCSF / syslog / S3 / webhook) that wants a
-- copy of that event has no place to receive it without ad-hoc
-- triggers.
--
-- The outbox pattern fixes this: the recorder writes the audit
-- row AND one outbox row per configured export target in the
-- SAME transaction (lands in PR7-2). A background drain worker
-- (also PR7-2) reads outbox rows in `status='pending'`, ships
-- each to its `target_sink`, and updates the row to `delivered`
-- or `failed`. Failed rows retry with exponential backoff and
-- eventually settle in `dead_letter`.
--
-- This migration ONLY lays the table. No code consumes it yet;
-- the recorder integration + drain worker + first exporter
-- ship as PR7-2.

-- ---------------------------------------------------------------
-- evidence_outbox — one row per (audit event × export target).
--
-- `event_id` is a FK to `audit_log(id)` (NOT a soft reference,
-- unlike `catalog_approvals.subject_id`) because the outbox row's
-- whole purpose is to ship a copy of THIS audit row to an
-- external sink. An orphan outbox row would point at a deleted
-- audit row — semantically meaningless — so cascade-delete is
-- the right behavior.
--
-- `target_sink` is a free-form identifier ("ocsf", "webhook:siem",
-- "s3:cold-storage"). The drain worker routes on this string;
-- there's no enum at the SQL level because target shapes
-- evolve faster than migrations.
--
-- `payload` is the rendered shape the drain worker hands to the
-- exporter. For most targets this is the audit event JSON; for
-- transformer targets (OCSF, ECS) the recorder pre-renders the
-- target-specific shape so the drain stays a dumb HTTP/file
-- sender. JSONB so the renderer can query it for debugging.
--
-- `status` is the row's lifecycle:
--   `pending`     — never attempted; drain picks up at first eligible tick.
--   `failed`      — attempted ≥1 time, retrying; drain re-attempts
--                   once `next_attempt <= now()`.
--   `delivered`   — terminal success.
--   `dead_letter` — terminal give-up; operator action needed.
--
-- `attempt_count` + `last_attempt` + `next_attempt` are the
-- backoff state. The drain reads
-- `WHERE status IN ('pending','failed') AND next_attempt <= now()`
-- so both unattempted AND retrying rows are eligible — the
-- exporter just bumps `next_attempt` further into the future on
-- each failure, no status flip needed.
--
-- `(target_sink, status, next_attempt)` is the drain's hot path
-- query shape, so we add a partial index on `pending` rows to
-- keep dequeue fast at high outbox volume.

CREATE TABLE evidence_outbox (
    event_id      UUID NOT NULL REFERENCES audit_log(id) ON DELETE CASCADE,
    target_sink   TEXT NOT NULL,
    payload       JSONB NOT NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    last_attempt  TIMESTAMPTZ,
    next_attempt  TIMESTAMPTZ NOT NULL DEFAULT now(),
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','delivered','failed','dead_letter')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, target_sink)
);

-- Hot-path index for the drain worker:
--   SELECT ... FROM evidence_outbox
--    WHERE status IN ('pending','failed') AND next_attempt <= now()
--    ORDER BY next_attempt
--    LIMIT $batch
-- Both `pending` (never attempted) and `failed` (tried at least
-- once, retrying) are eligible for the next sweep — that's the
-- retry loop the lifecycle comment promises. The partial-on-
-- status predicate is still immutable (`IN` over the enum) so
-- legal, and keeps the index small: steady state, the
-- delivered/dead_letter rows that won't be re-attempted aren't
-- in the index.
CREATE INDEX evidence_outbox_pending_idx
    ON evidence_outbox (next_attempt)
 WHERE status IN ('pending', 'failed');

-- Per-event lookup for the admin "where did this event go?"
-- view + the recorder's outbox INSERT path (which inserts N
-- rows per event keyed by `(event_id, target_sink)` —
-- PK lookup is already covered, this is for full-event scans).
CREATE INDEX evidence_outbox_event_idx
    ON evidence_outbox (event_id);
