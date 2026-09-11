-- Audit log: one row per tool-call attempt through the gateway. Denied and
-- step-up attempts are recorded alongside successful and failed executions
-- so the log doubles as a record of *attempted* access, not just what ran.
--
-- `id` is a UUIDv7 so primary-key order aligns with insertion order and
-- range scans over `ts` hit an index-friendly key distribution without
-- needing a separate sequence.

CREATE TABLE IF NOT EXISTS audit_log (
    id               UUID PRIMARY KEY,
    ts               TIMESTAMPTZ NOT NULL,
    action           TEXT NOT NULL,
    outcome          TEXT NOT NULL,

    principal_sub    TEXT,
    principal_email  TEXT,
    principal_groups TEXT[] NOT NULL DEFAULT '{}',
    issuer           TEXT,

    server           TEXT,
    tool             TEXT,
    risk_level       TEXT,

    policy_ids       TEXT[] NOT NULL DEFAULT '{}',
    reason           TEXT,

    trace_id         TEXT,
    latency_ms       BIGINT
);

-- "who called what recently" — most common query pattern.
CREATE INDEX IF NOT EXISTS audit_log_principal_ts_idx
    ON audit_log (principal_sub, ts DESC);

-- "what happened on this tool recently" — second most common.
CREATE INDEX IF NOT EXISTS audit_log_tool_ts_idx
    ON audit_log (server, tool, ts DESC);

-- "show me every denial today" — outcome-filtered scans.
CREATE INDEX IF NOT EXISTS audit_log_outcome_ts_idx
    ON audit_log (outcome, ts DESC);
