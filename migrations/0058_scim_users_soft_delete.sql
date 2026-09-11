-- PR-EMA-0b: soft-delete tombstone for SCIM users.
--
-- ## The gap this closes
--
-- The enricher (`gateway-scim::PgScimResolver`) blocks a request when
-- the principal's `scim_users` row has `active = false`
-- (`Principal::scim_blocks_request()`). Account *deactivation* arrives
-- as `active = false` (via PUT/PATCH) and is caught. But provider
-- *scope-exit* — e.g. an IdP removing a user from the group the SCIM
-- provider is filtered on — arrives as `DELETE /scim/v2/Users/{id}`,
-- which previously hard-deleted the row. With the row gone the resolver
-- returns `None`, and "no SCIM row" is intentionally treated as active
-- (service accounts, dev mode, and pre-SCIM API keys legitimately have
-- no row). So a deprovisioned user was silently treated as active — a
-- real authorization gap that goes live the moment SCIM provisioning is
-- enabled.
--
-- ## The fix
--
-- DELETE becomes a soft-delete: the handler/store set `active = false,
-- deleted_at = now()` instead of removing the row. The resolver's
-- primary lookup filters `deleted_at IS NULL` (so live resolution and
-- the existing ambiguity guard are unchanged), and when no live row
-- matches it falls back to a tombstone probe — a matching tombstone
-- resolves as `active = false`, so `scim_blocks_request()` blocks the
-- deprovisioned user on every gateway surface. SCIM reads
-- (GET/LIST/PUT) filter `deleted_at IS NULL` so a deleted resource
-- still 404s to the IdP (RFC 7644 — DELETE removes it from the client's
-- view); the retained row is an internal block signal + forensic record.
--
-- A never-provisioned `sub` still has no row at all → resolver `None` →
-- treated active, preserving the service-account / API-key semantics.

ALTER TABLE scim_users ADD COLUMN deleted_at TIMESTAMPTZ;

-- Migration 0019 declared `UNIQUE (tenant_id, user_name)` and
-- `UNIQUE (tenant_id, external_id)` as table constraints. A tombstone
-- must NOT block re-provisioning the same userName/externalId, so swap
-- both full constraints for partial unique indexes scoped to LIVE rows.
-- Postgres auto-named the inline constraints `<table>_<cols>_key`.
ALTER TABLE scim_users DROP CONSTRAINT IF EXISTS scim_users_tenant_id_user_name_key;
ALTER TABLE scim_users DROP CONSTRAINT IF EXISTS scim_users_tenant_id_external_id_key;

-- Per-tenant uniqueness on userName, live rows only (RFC 7643). A
-- tombstoned row drops out of the index so the same userName can be
-- re-provisioned into a fresh live row.
CREATE UNIQUE INDEX scim_users_tenant_username_live_idx
    ON scim_users (tenant_id, user_name)
 WHERE deleted_at IS NULL;

-- Per-tenant uniqueness on externalId, live rows with a non-null
-- externalId only (NULLs stay distinct, matching the original
-- constraint's semantics).
CREATE UNIQUE INDEX scim_users_tenant_external_id_live_idx
    ON scim_users (tenant_id, external_id)
 WHERE deleted_at IS NULL AND external_id IS NOT NULL;

-- Index the tombstones so the resolver's tombstone-fallback probe and
-- the retention sweep are both index-bound.
CREATE INDEX scim_users_deleted_at_idx
    ON scim_users (deleted_at)
 WHERE deleted_at IS NOT NULL;
