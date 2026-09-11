-- Phase 2 (PR2-3b-iii): per-replica fleet heartbeat for the upstream-manifest set.
--
-- ## What
--
-- One row per gateway replica. Each replica UPSERTs its current state here on
-- every reload (boot + the doorbell/poll/SIGHUP reload loop), so the admin
-- dashboard can render a fleet roll-up: which config version + content hash each
-- replica has loaded, and how recently it checked in.
--
-- ## Why
--
-- After PR2-3a (pointer reconcile) and PR2-3b-i (out-of-band ledger capture) the
-- fleet converges on the shared `servers/*.yaml`, and PR2-3b-ii emits a
-- per-replica activation AUDIT event on each change. But there was no queryable,
-- current-state view of the fleet — "is every replica alive and on the same
-- config?". This table is that view: a replica whose `updated_at` is stale may
-- be down or wedged; one whose `content_hash` lags the others has not yet
-- reloaded the latest set.
--
-- This is OBSERVABILITY state — NOT a coordination point (the turnstile pointer
-- `server_manifest_pointer`, 0038, is that) and NOT a boot source (boot loads
-- `servers/*.yaml` directly; see `resolve_manifests`). The heartbeat write is
-- best-effort: a failure is logged, never fails boot/reload.
--
-- `replica_id` is the primary key — one row per replica, last-write-wins on each
-- heartbeat (`INSERT … ON CONFLICT (replica_id) DO UPDATE`). The id is the
-- container/pod `HOSTNAME` (or `GATEWAY_REPLICA_ID`, or a process-scoped
-- fallback) chosen at boot in PR2-3b-ii. `version` is NULL when the on-disk set
-- is uncommitted / out-of-band (no matching committed ledger version). Servers
-- are gateway-global today, so `tenant_id` defaults to 'default' for
-- forward-compat, mirroring `server_manifests` (0037) and the pointer (0038).
--
-- The "fully applied vs restart-pending" nuance is deliberately NOT a column
-- here: accurately deciding whether a replica's RUNNING connection shapes match
-- disk needs a running-pool-vs-disk comparison, and that per-change signal
-- already lives in the activation audit (PR2-3b-ii). Keep this schema minimal —
-- columns can be added by a later migration if a durable restart-pending view is
-- needed.

CREATE TABLE fleet_replicas (
    replica_id   TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    version      INT,
    content_hash TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
