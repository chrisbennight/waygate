-- Tier-2: hourly pre-aggregation of audit_log for fast wide-window dashboard
-- reads on an unboundedly-growing table (retention defaults to unbounded, so
-- "all time" / 30d aggregate views must stay fast as the raw table grows).
--
-- Maintained by the in-gateway rollup worker
-- (gateway_storage::run_rollup_maintenance): each tick RECOMPUTES every bucket
-- newer than a "finalized hour" watermark directly from audit_log (DELETE the
-- window's rollup rows, then re-aggregate). This recompute is idempotent, so
-- it is robust to out-of-order commits, non-UUIDv7 ids (the retention-sweep
-- markers in sweep.rs use Uuid::new_v4()), and late-arriving rows within the
-- window — unlike a monotonic-id cursor, which could skip rows forever. The
-- watermark advances only past hours old enough that every row in them has
-- certainly committed (a safety lag), so finalized buckets are never touched
-- again. p95 latency is deliberately NOT rolled up — not additive across
-- buckets, so the dashboard keeps computing it live over the bounded window.
--
-- Retention note: this rollup is an INDEPENDENT long-term aggregate. Buckets
-- older than the safety lag are frozen, so if a retention policy later sweeps
-- the underlying raw rows, the rollup retains the aggregate counts by design
-- (the "keep aggregate history beyond raw retention" half of the hot/cold
-- split). Wide-window rollup reads may therefore exceed the retained raw
-- window — intended, not a discrepancy. With retention unbounded (the default)
-- the two always agree.

CREATE TABLE IF NOT EXISTS audit_rollup_hourly (
    tenant_id    TEXT        NOT NULL,
    -- date_trunc('hour', ts) of the source rows.
    bucket_hour  TIMESTAMPTZ NOT NULL,
    -- Dimension columns mirror audit_log. server/tool/risk_level/pii are
    -- nullable (non-tool-call rows); category is COALESCE'd to 'invocation'
    -- at fold time so it is never NULL here (matches the row-query semantics).
    server       TEXT,
    tool         TEXT,
    outcome      TEXT        NOT NULL,
    category     TEXT        NOT NULL,
    risk_level   TEXT,
    pii          BOOLEAN,
    -- Folded count of source rows in this (tenant, hour, dimensions) bucket.
    n            BIGINT      NOT NULL DEFAULT 0,
    -- NULLS NOT DISTINCT (PG15+) so a NULL dimension collapses to a single
    -- bucket in the upsert. With the default NULLS DISTINCT, rows whose key
    -- contains a NULL would never conflict, so the additive ON CONFLICT path
    -- would silently insert duplicates and double-count.
    UNIQUE NULLS NOT DISTINCT
        (tenant_id, bucket_hour, server, tool, outcome, category, risk_level, pii)
);

-- Wide-window reads scan a tenant's buckets by time, then GROUP BY the wanted
-- dimension(s). Leading (tenant_id, bucket_hour) serves that window scan.
CREATE INDEX IF NOT EXISTS audit_rollup_hourly_window_idx
    ON audit_rollup_hourly (tenant_id, bucket_hour);

-- Single-row watermark: the latest hour bucket that is FINALIZED (frozen). The
-- worker recomputes every bucket with bucket_hour >= finalized_hour each tick
-- and then advances finalized_hour to date_trunc('hour', now() - safety_lag),
-- all inside one transaction (a crash rolls back). NULL means "nothing
-- finalized yet" — the first tick recomputes the whole table (initial
-- backfill of all historical hours).
CREATE TABLE IF NOT EXISTS audit_rollup_state (
    -- Singleton guard: only the row with id = true may exist.
    id             BOOLEAN     PRIMARY KEY DEFAULT TRUE,
    finalized_hour TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_rollup_state_singleton CHECK (id)
);

INSERT INTO audit_rollup_state (id, finalized_hour)
VALUES (TRUE, NULL)
ON CONFLICT (id) DO NOTHING;
