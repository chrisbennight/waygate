-- Phase 8 PR8-e: canonical tenants table.
--
-- Up through PR8-d2 every `tenant_id` column in the gateway
-- (audit_log, api_keys, scim_users, scim_groups, gateway_roles,
-- role_assignments, group_role_mappings, …) was a plain TEXT
-- column with no canonical registry. Existence of a tenant was
-- implicit — if a JWT carried `tenant=acme` then `acme` rows
-- existed; otherwise they didn't. That's good enough for the
-- single-tenant deployments PR8-c shipped but not enough for
-- multi-tenant productization:
--
-- - Operators can't list "what tenants does this gateway serve?"
-- - There's no way to deactivate a tenant en bloc (today every
--   tenant_id column would need a status check independently).
-- - Tenant-onboarding workflows (clone default policy bundle,
--   provision SCIM API key, seed default RBAC roles) need a
--   single place to hook off.
--
-- This migration adds the canonical registry. Subsequent PRs
-- (`PR8-e2`, `PR8-f`) layer onboarding side-effects + bearer-
-- middleware "tenant must exist and be active" enforcement on
-- top.
--
-- ## Shape
--
-- `id` is TEXT (not UUID) to match the existing `tenant_id`
-- columns the rest of the schema uses. The `gateway_core::TenantId`
-- type validates the format (alphanumeric + dash, length cap) at
-- every boundary that takes external input; the admin API
-- enforces the same on insert.
--
-- `status` is an enum-style TEXT column with a CHECK constraint
-- so a typo can't quietly land a row in some unexpected state.
-- Active / suspended is the minimum two-state model that lets
-- operators take a tenant offline without `DELETE`-ing it.
--
-- ## Default tenant
--
-- `INSERT … ON CONFLICT DO NOTHING` seeds the `default` tenant
-- so single-tenant deployments (which have always relied on the
-- `tenant_id NOT NULL DEFAULT 'default'` columns) don't trip an
-- FK violation when bearer-middleware enforcement lands in PR8-e2.

CREATE TABLE tenants (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'suspended')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION tenants_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenants_touch_updated_at_trg
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION tenants_touch_updated_at();

-- Seed `default` so existing single-tenant deployments keep
-- working when later PRs add `tenant_id` FKs against this table.
-- Idempotent so re-running migrations on a primed DB is safe.
INSERT INTO tenants (id, display_name, status)
VALUES ('default', 'Default tenant', 'active')
ON CONFLICT (id) DO NOTHING;

-- AERB PR #152 round 2 medium: backfill from existing
-- tenant-scoped tables. Before this migration `tenant_id` was an
-- implicit TEXT column populated from JWT claims; deployments
-- that already saw non-default tenants would have those values
-- scattered across audit_log, api_keys, scim_users, etc., with
-- no row in `tenants` to match. When PR8-e2 turns on bearer-
-- middleware "tenant must exist and be active" enforcement those
-- principals would suddenly be rejected.
--
-- Collect every distinct `tenant_id` ever written to a known
-- scoped table and INSERT one tenant row per value, with
-- `display_name = id` and `status = 'active'`. Operators can
-- PATCH display_name later via /api/v1/admin/tenants/{id}; the
-- important property is the rows exist so enforcement won't lock
-- them out.
--
-- ON CONFLICT keeps `default` (and any future re-runs)
-- idempotent. The UNION is over the full set of tables that
-- carried `tenant_id` by the time this migration runs (i.e. all
-- of them up through 0023); a new table added by a later
-- migration only needs to ensure its own seeding path inserts
-- the tenant row, not this backfill.
INSERT INTO tenants (id, display_name, status)
SELECT DISTINCT tenant_id, tenant_id, 'active'
  FROM (
        SELECT tenant_id FROM audit_log
        UNION SELECT tenant_id FROM oauth_transactions
        UNION SELECT tenant_id FROM oauth_codes
        UNION SELECT tenant_id FROM oauth_refresh_tokens
        UNION SELECT tenant_id FROM api_keys
        UNION SELECT tenant_id FROM api_key_usage
        UNION SELECT tenant_id FROM user_upstream_sessions
        UNION SELECT tenant_id FROM mcp_servers
        UNION SELECT tenant_id FROM catalog_approvals
        UNION SELECT tenant_id FROM catalog_drift_events
        UNION SELECT tenant_id FROM policy_bundles
        UNION SELECT tenant_id FROM approval_grants
        UNION SELECT tenant_id FROM tenant_evidence_routing
        UNION SELECT tenant_id FROM evidence_retention_policy
        UNION SELECT tenant_id FROM scim_users
        UNION SELECT tenant_id FROM scim_groups
        UNION SELECT tenant_id FROM scim_user_groups
        UNION SELECT tenant_id FROM gateway_roles
        UNION SELECT tenant_id FROM role_assignments
        UNION SELECT tenant_id FROM group_role_mappings
  ) all_tenant_ids
 WHERE tenant_id IS NOT NULL
   AND tenant_id <> ''
ON CONFLICT (id) DO NOTHING;
