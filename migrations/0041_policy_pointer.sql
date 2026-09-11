-- Phase 2 (PR2-6-2): cross-replica write turnstile for the Cedar policy set.
--
-- The policy analogue of `0038_server_manifest_pointer.sql`. Under file-as-truth
-- (PR2-6-1) the live authorization policy is `policies/*.cedar` on a SHARED
-- volume (NFS in the target deploy) that every replica mounts and the gate loads
-- at boot/SIGHUP (`resolve_policies`). There is no atomic compare-and-swap on
-- NFS file *content*: two dashboard/API policy publishes from different replicas
-- can both read base hash H, both mirror their bundle, and both `rename` over the
-- other's `00-published.cedar` — a lost update of the authorization policy, and a
-- torn read for a concurrent gate reload.
--
-- This single row is the serialization point. A writer CAS-swaps `current_hash`
-- from the base it edited (H) to the new content hash (H'):
--
--     UPDATE policy_pointer
--        SET current_hash = $new, updated_at = now(), updated_by = $actor
--      WHERE tenant_id = $t AND current_hash = $base
--
-- A single conditional UPDATE is atomic in Postgres, so among concurrent writers
-- sharing base H exactly one gets rows_affected = 1 (wins the turnstile and goes
-- on to mirror the bundle to disk) and the rest get 0 (a stale-edit refusal:
-- "another replica changed the policy set — reload and retry"). The CAS happens
-- BEFORE the file write, so only the winner ever renames — preventing the
-- clobber, not just detecting it after the fact.
--
-- `current_hash` tracks the canonical hash of the CURRENT live on-disk policy
-- set, computed the SAME way a disk read computes it
-- (`content_hash(read_policy_dir(dir).source)` — see
-- `gateway_policy::canonical_policy_disk_hash`), NOT the raw bundle bytes: the
-- per-file concatenation a disk read performs (each file + a trailing newline)
-- means a draft's submitted bytes differ from the on-disk canonical form, so a
-- CAS keyed on raw bytes would advance the pointer to a hash that never matches
-- disk and lose every later write (the manifest AERB #301 footgun).
--
-- Boot seeds it (idempotent, never clobbering); a later slice (PR2-6-4)
-- reconciles it against disk on out-of-band `policies/*.cedar` edits. It is
-- COORDINATION state, not the boot source: boot still loads `policies/*.cedar`
-- directly (`resolve_policies`). Policies are gateway-global today, so the row
-- keys on tenant_id='default' for forward-compat, mirroring `policy_bundles`
-- (0012) and `server_manifest_pointer` (0038).

CREATE TABLE policy_pointer (
    tenant_id    TEXT PRIMARY KEY DEFAULT 'default',
    current_hash TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   TEXT
);
