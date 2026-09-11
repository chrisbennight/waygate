-- Phase 2 PR5: index supporting the re-encrypt sweeper's
-- `WHERE key_id <> $1` filter.
--
-- Why: the sweeper runs at `GATEWAY_UPSTREAM_REENCRYPT_INTERVAL_SECONDS`
-- (default 1h) and reads off-key rows via `list_off_active_key`.
-- Without this index every tick performs a sequential scan over
-- `user_upstream_sessions`. AERB-flagged on PR #92: large
-- deployments would burn DB CPU every interval even when no
-- rotation is in progress (steady-state: every row's `key_id`
-- equals the active id, the result set is empty, but the scan
-- still walks the heap).
--
-- A B-tree on `key_id` lets Postgres serve the inequality cheaply:
-- in steady state (one distinct value) the planner returns zero
-- rows after a tiny index lookup; during rotation (two distinct
-- values, dominant being the active id) the planner reads the
-- off-key subset directly. Cardinality of `key_id` distinct
-- values is bounded to the size of the operator's keyring (1-3
-- during rotation, eventually 1), so the index stays small.

CREATE INDEX user_upstream_sessions_key_id_idx
    ON user_upstream_sessions (key_id);
