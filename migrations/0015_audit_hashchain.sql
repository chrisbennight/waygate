-- Phase 7 PR7-4: tamper-evidence hash chain on audit_log.
--
-- Each new audit row carries two new columns:
--
--   prev_hash  TEXT NULL  — `row_hash` of the immediately
--              previous row in the SAME `tenant_id` chain.
--              NULL for the genesis row of that tenant's chain
--              (no previous row exists yet for the tenant).
--
--   row_hash   TEXT NULL  — sha256(prev_hash || \x00 ||
--              canonical_audit_bytes(event)), hex-encoded.
--              Application-computed at INSERT time (the
--              recorder integration in this PR's
--              gateway-storage change). The byte format is
--              defined in `gateway_storage::hashchain` and is
--              length-prefixed (no separator characters) so
--              the verifier rehashing from the durable columns
--              gets the same bytes by construction. The
--              leading `"audit-v1"` tag pins the format for
--              future evolution.
--
-- Verification (PR7-5) walks each tenant's chain in
-- chain_seq ASC order (which is insert order — see
-- chain_seq's column comment below): for each row with a
-- non-NULL row_hash, recompute
-- sha256(prev_hash || \x00 || canonical_audit_bytes(row))
-- and check it equals the stored row_hash; check that
-- prev_hash equals the previous row's row_hash. A mismatch
-- is the tamper signal.
--
-- BOTH columns are nullable on this migration:
--   1. Existing pre-PR7-4 rows have no chain context (no
--      previous row's row_hash to point at), so leaving them
--      NULL is correct — verification just skips them.
--   2. record_best_effort callers writing through a `NullSink`
--      or before the recorder learns its tenant's chain head
--      would also write NULL, and the chain just starts from
--      whatever row first carries a real row_hash. This is
--      defensible: best-effort writes are by contract allowed
--      to lose, so them being outside the tamper chain is
--      consistent.
--
-- A Postgres trigger then blocks UPDATE / DELETE on audit_log
-- so the chain stays append-only — an operator attempt to
-- mutate or remove a chain row would be rejected by the DB.
-- This is the core tamper-evidence property: even direct DB
-- access can't silently rewrite the chain.

ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN row_hash TEXT;
-- AERB PR #125 round 1 high: caller-assigned `ts` is set BEFORE
-- the recorder runs, so under concurrent record_required calls
-- the order rows are persisted in does NOT necessarily match
-- their ts values. A naive `ORDER BY ts` would have the
-- verifier walk rows out of insert order and falsely flag chain
-- breaks. `chain_seq BIGSERIAL` is auto-assigned at INSERT and
-- is monotonic by insert order; combined with the per-tenant
-- `pg_advisory_xact_lock` the recorder takes, chain_seq is
-- dense and strictly increasing per tenant. The verifier
-- (PR7-5) walks `ORDER BY chain_seq ASC`; the recorder reads
-- the previous head via `ORDER BY chain_seq DESC LIMIT 1`.
ALTER TABLE audit_log ADD COLUMN chain_seq BIGSERIAL;

-- Chain-walk index (PR7-5 will SELECT through it):
--   SELECT id, prev_hash, row_hash, ...
--     FROM audit_log
--    WHERE tenant_id = $1 AND row_hash IS NOT NULL
--    ORDER BY chain_seq ASC;
-- Partial-on-row_hash-not-null keeps the index restricted to
-- chain-bearing rows (pre-PR7-4 NULL rows aren't part of the
-- chain and don't need to be indexed for the walk).
CREATE INDEX audit_log_chainwalk_idx
    ON audit_log (tenant_id, chain_seq ASC)
 WHERE row_hash IS NOT NULL;

-- Append-only guard. A trigger BEFORE UPDATE OR DELETE that
-- RAISEs the row mutation off. The recorder only INSERTs (and
-- the outbox path INSERTs to `evidence_outbox`, also append-
-- only in spirit), so this doesn't restrict the production
-- code path. Any future code path that needs to UPDATE
-- audit_log (none today) would have to (a) prove the change
-- preserves the chain, (b) drop or replace this trigger
-- explicitly. The trigger is the operator's tamper deterrent
-- — an admin running raw SQL to "fix" an audit row gets a
-- clear error rather than silently rewriting history.
CREATE OR REPLACE FUNCTION audit_log_no_mutate() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'audit_log is append-only (tamper-evidence chain); UPDATE/DELETE denied';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_no_mutate();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_no_mutate();

-- AERB PR #125 round 2 high: BEFORE TRUNCATE so operators with
-- TRUNCATE privilege can't erase audit_log without firing the
-- guard. Postgres TRUNCATE triggers are STATEMENT-level (not
-- per-row), so it's a single trigger here rather than a
-- per-row trigger like the UPDATE/DELETE pair above.
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_no_mutate();
