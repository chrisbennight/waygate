-- Phase 2 PR4c: per-row key id for `tokens_ciphertext`.
--
-- Why: the gateway encrypts the upstream token envelope at rest with
-- AES-256-GCM under a key supplied by the operator. PR4c introduces a
-- *keyring*: multiple keys identified by id, one active for new
-- encrypts. Decrypt picks the key by the row's stamped id. This makes
-- key rotation a non-event (write new key alongside the old, flip the
-- active id, run the PR5 re-encrypt sweeper) instead of an outage.
--
-- Existing rows were encrypted with whatever single key
-- `GATEWAY_UPSTREAM_TOKEN_KEY` held at the time. Tagging them `'v1'`
-- gives the operator a canonical id to use for the legacy key when
-- they configure the new `GATEWAY_UPSTREAM_TOKEN_KEY_V1=...` env var.
-- A compat shim in `gateway_as::config` accepts the legacy single-key
-- env var and maps it to `v1` automatically, so deployments that
-- haven't yet migrated their env-var shape keep working.
--
-- NOT NULL DEFAULT 'v1' makes the migration online-safe: existing
-- rows backfill atomically with the ALTER, no separate UPDATE pass
-- needed.

ALTER TABLE user_upstream_sessions
    ADD COLUMN key_id TEXT NOT NULL DEFAULT 'v1';
