-- Phase 2 (PR2-1): cross-replica write turnstile for the upstream-manifest set.
--
-- Under file-as-truth (Phase 1) the live config is `servers/*.yaml` on a
-- SHARED volume (NFS in the target deploy) that every replica mounts. There
-- is no atomic compare-and-swap on NFS file *content*: two dashboard writes
-- from different replicas can both read base hash H, both validate, and both
-- `rename` their file over the other's — a lost update, and worse, a torn
-- read for a concurrent reader.
--
-- This single row is the serialization point. A writer CAS-swaps
-- `current_hash` from the base it edited (H) to the new content hash (H'):
--
--     UPDATE server_manifest_pointer
--        SET current_hash = $new, updated_at = now(), updated_by = $actor
--      WHERE tenant_id = $t AND current_hash = $base
--
-- A single conditional UPDATE is atomic in Postgres, so among concurrent
-- writers sharing base H exactly one gets rows_affected = 1 (wins the
-- turnstile and goes on to write the file) and the rest get 0 (a stale-edit
-- refusal: "another replica changed the config — reload and retry"). The CAS
-- happens BEFORE the file write, so only the winner ever renames a file —
-- preventing the clobber, not just detecting it after the fact.
--
-- `current_hash` tracks the hash of the CURRENT live on-disk set. Boot and
-- `--import-server-bundle` seed it (idempotent, never clobbering); a later
-- slice (PR2-3) reconciles it against the disk on out-of-band edits. It is
-- COORDINATION state, not the boot source: boot still loads `servers/*.yaml`
-- directly (see `resolve_manifests`). Servers are gateway-global today, so
-- the row keys on tenant_id='default' for forward-compat, mirroring
-- `server_manifests` (0037).

CREATE TABLE server_manifest_pointer (
    tenant_id    TEXT PRIMARY KEY DEFAULT 'default',
    current_hash TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   TEXT
);
