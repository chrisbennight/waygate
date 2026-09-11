-- Phase 8 PR8-b: SCIM 2.0 Group resource + user-group
-- membership.
--
-- Companion to migration 0019 (scim_users). Group rows
-- carry the SCIM `displayName` as the unique-per-tenant
-- identifier; membership is a separate join table so
-- group changes don't have to rewrite the user row's
-- attrs.
--
-- ## Tenant scoping
--
-- Same per-tenant model as scim_users: every row is
-- stamped with `tenant_id`; uniqueness constraints are
-- per-tenant; cross-tenant access is structurally
-- impossible at the SQL layer.
--
-- ## Shape vs RFC 7643 §4.2
--
-- SCIM Core Group has: `displayName`, `members[]`,
-- `meta`, and (optional) `externalId`. We split the
-- `members[]` array out into a separate join table
-- because:
--
-- 1. Membership churn dominates Group writes. Storing
--    members inline forces a full Group rewrite per
--    add/remove; the join lets PATCH-like operations
--    target just the affected rows once we ship PATCH
--    in a follow-up.
-- 2. The future RBAC layer (PR8-d) joins
--    `group_role_mappings` ↔ `scim_user_groups` ↔
--    `scim_users` to compute "what roles does this
--    principal have." Inline membership would force a
--    JSON-array unnest on every bearer-validate call.
--
-- The handler reassembles the `members[]` array at GET
-- time by joining scim_user_groups → scim_users.
--
-- ## Cascade behaviour
--
-- Deleting a scim_group cascades to scim_user_groups
-- (membership rows disappear with the group). Deleting a
-- scim_user cascades the same way (user dropped from
-- every group). Both are appropriate: SCIM clients
-- expect Group / User deletes to drop the relationships.

CREATE TABLE scim_groups (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    -- SCIM `externalId` — IdP-assigned, opaque, nullable.
    external_id  TEXT,
    -- SCIM `displayName` per RFC 7643 §4.2: human-readable
    -- group name. Unique per tenant to match how SCIM
    -- clients normally look up groups by name.
    display_name TEXT NOT NULL,
    -- Other SCIM Group attributes (extensions, etc.) ride
    -- here verbatim. `members[]` does NOT — see the join
    -- table below.
    attrs        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, display_name),
    UNIQUE (tenant_id, external_id)
);

CREATE INDEX scim_groups_external_id_idx
    ON scim_groups (tenant_id, external_id)
 WHERE external_id IS NOT NULL;

-- Updated-at trigger so SCIM clients lean on
-- meta.lastModified for delta-sync correctly.
CREATE TRIGGER scim_groups_touch_updated_at_trg
    BEFORE UPDATE ON scim_groups
    FOR EACH ROW
    EXECUTE FUNCTION scim_users_touch_updated_at();

-- Membership join. `ON DELETE CASCADE` on both sides so
-- the SCIM spec's "deleting a User removes their group
-- memberships" / "deleting a Group removes the
-- memberships" expectations hold without per-handler
-- cleanup loops.
CREATE TABLE scim_user_groups (
    user_id    UUID NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    -- Carry tenant_id explicitly so the PR8-d RBAC join
    -- can scope without dragging in scim_users /
    -- scim_groups for the tenant predicate. A trigger
    -- below enforces that both sides' tenants match this
    -- value — no cross-tenant memberships possible.
    tenant_id  TEXT NOT NULL DEFAULT 'default',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX scim_user_groups_group_idx
    ON scim_user_groups (group_id);
CREATE INDEX scim_user_groups_tenant_user_idx
    ON scim_user_groups (tenant_id, user_id);

-- Tenancy-invariant guard. Refuses INSERTs / UPDATEs
-- whose user or group is in a different tenant. Catches
-- handler bugs that would otherwise let a tenant-A SCIM
-- client add a tenant-B user to a tenant-A group (or
-- vice versa) — both individual rows would each be valid
-- in their own tenant; only the cross-tenant linkage is
-- the violation.
CREATE OR REPLACE FUNCTION scim_user_groups_tenant_match() RETURNS TRIGGER AS $$
DECLARE
    user_tenant TEXT;
    group_tenant TEXT;
BEGIN
    SELECT tenant_id INTO user_tenant FROM scim_users WHERE id = NEW.user_id;
    SELECT tenant_id INTO group_tenant FROM scim_groups WHERE id = NEW.group_id;
    IF user_tenant IS NULL THEN
        RAISE EXCEPTION 'scim_user_groups: user % not found', NEW.user_id;
    END IF;
    IF group_tenant IS NULL THEN
        RAISE EXCEPTION 'scim_user_groups: group % not found', NEW.group_id;
    END IF;
    IF user_tenant <> NEW.tenant_id THEN
        RAISE EXCEPTION
            'scim_user_groups: user tenant `%` mismatches row tenant `%`',
            user_tenant, NEW.tenant_id;
    END IF;
    IF group_tenant <> NEW.tenant_id THEN
        RAISE EXCEPTION
            'scim_user_groups: group tenant `%` mismatches row tenant `%`',
            group_tenant, NEW.tenant_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER scim_user_groups_tenant_match_trg
    BEFORE INSERT OR UPDATE ON scim_user_groups
    FOR EACH ROW
    EXECUTE FUNCTION scim_user_groups_tenant_match();
