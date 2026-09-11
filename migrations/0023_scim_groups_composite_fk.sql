-- Issue #148 (Phase 8): make scim_groups.tenant_id effectively
-- immutable when referenced by group_role_mappings — same
-- composite-FK defense PR #147 round 2 applied to
-- gateway_roles.tenant_id.
--
-- ## Background
--
-- Migration 0020 (scim_groups) added the table and the
-- `scim_user_groups_tenant_match` trigger that enforces
-- per-row tenant consistency on the membership side. Migration
-- 0021 (RBAC) added `group_role_mappings` with a single-column
-- FK `group_id REFERENCES scim_groups(id)` and a
-- `group_role_mappings_tenant_match` trigger that checks
-- mapping.tenant_id == group.tenant_id == role.tenant_id on
-- INSERT/UPDATE of the mapping. PR #147 round 2 closed the
-- equivalent gap on the gateway_roles side with composite FKs;
-- AERB round 3 of PR #147 flagged the same gap remaining on
-- the scim_groups parent side and the user agreed to track it
-- as #148 rather than expand PR #147's scope.
--
-- Today: an operator who UPDATEs `scim_groups.tenant_id` after
-- a mapping exists leaves the mapping pointing at a parent
-- whose tenant has changed — silent cross-tenant linkage
-- without any trigger firing.
--
-- ## Fix
--
-- 1. Add `UNIQUE (id, tenant_id)` to `scim_groups`. This is the
--    target a composite child FK needs.
-- 2. Drop `group_role_mappings`' existing single-column FK on
--    `group_id` and replace with a composite FK against
--    `scim_groups(id, tenant_id)`.
--
-- With the default `ON UPDATE NO ACTION`, Postgres now refuses
-- to UPDATE `scim_groups.tenant_id` while any
-- `group_role_mapping` references it — the SQL-layer way to
-- enforce the invariant the triggers were trying to express by
-- hand. `ON DELETE CASCADE` is preserved so dropping a group
-- still drops its mappings.
--
-- The existing `group_role_mappings_tenant_match` trigger
-- stays as defense-in-depth: it catches INSERT-time mismatches
-- with a clearer error message ("group tenant `X` mismatches
-- row tenant `Y`") than the bare FK violation surfaced by the
-- composite FK lookup.

ALTER TABLE scim_groups
    ADD CONSTRAINT scim_groups_id_tenant_uk UNIQUE (id, tenant_id);

ALTER TABLE group_role_mappings
    DROP CONSTRAINT group_role_mappings_group_id_fkey;

ALTER TABLE group_role_mappings
    ADD CONSTRAINT group_role_mappings_group_id_tenant_fkey
        FOREIGN KEY (group_id, tenant_id)
        REFERENCES scim_groups (id, tenant_id)
        ON DELETE CASCADE;
