-- Phase 8 PR8-d: RBAC tables.
--
-- Three tables compose role-based access on top of the
-- SCIM-provisioned identity surface (migrations 0019 +
-- 0020):
--
-- 1. `gateway_roles` — per-tenant named roles, each
--    carrying a set of OAuth-scope strings. Adding a user
--    to a role grants them those scopes for the lifetime
--    of the assignment.
-- 2. `role_assignments` — direct (sub-keyed) bindings of
--    a principal to a role. Use this for service-account
--    `sub`s and for one-off "alice is also an auditor"
--    grants that don't fit a SCIM group.
-- 3. `group_role_mappings` — indirect bindings: every
--    user in SCIM group G inherits role R. The common
--    path: IdP provisions SCIM users + groups, operator
--    maps groups → roles once, principal scope membership
--    follows group membership automatically.
--
-- Both paths feed a single resolver (PR8-d's
-- `RbacEnricher`) that runs after `PrincipalEnricher`
-- (PR8-c) has populated `principal.scim.groups`. The
-- resolver unions: direct-assignment roles + groups-mapped
-- roles → flatten to role.scopes → merged into
-- `principal.scopes`. Cedar policies that gate on
-- `principal.scopes.contains("mcp:invoke:high")` get the
-- right answer without writing one policy per IdP claim.
--
-- ## Tenancy
--
-- Each table carries `tenant_id`; uniqueness constraints
-- are per-tenant; triggers below enforce that role,
-- group, and assignment rows agree on tenant — so
-- crossing tenants via a mapping is structurally
-- impossible at the SQL layer, same defense pattern as
-- the scim_user_groups trigger in migration 0020.
--
-- ## Cascade behaviour
--
-- - Dropping a role cascades to its role_assignments +
--   group_role_mappings (no orphan FKs).
-- - Dropping a SCIM group cascades to
--   group_role_mappings (the mapping vanishes; users
--   keep any direct role_assignments).
-- - role_assignments key on `subject_sub` (plain text),
--   not a FK — assignments may exist for principals the
--   gateway has never seen yet (provisioned by sub
--   ahead of first login).

CREATE TABLE gateway_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    name        TEXT NOT NULL,
    description TEXT,
    -- OAuth-scope strings the role grants. Stored as a
    -- text array so the resolver can do a single SQL
    -- `UNION ALL` + `array_agg` without parsing CSV.
    scopes      TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    -- AERB PR #147 round 2 medium: the (id, tenant_id)
    -- unique key gives child rows a composite FK target.
    -- Combined with the FK declarations below, that means
    -- Postgres refuses to UPDATE this row's tenant_id while
    -- ANY child role_assignment or group_role_mapping
    -- references it — the SQL-layer "parent tenant
    -- effectively immutable when referenced" invariant.
    UNIQUE (id, tenant_id)
);

CREATE OR REPLACE FUNCTION gateway_roles_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER gateway_roles_touch_updated_at_trg
    BEFORE UPDATE ON gateway_roles
    FOR EACH ROW
    EXECUTE FUNCTION gateway_roles_touch_updated_at();

-- Direct sub→role binding. `subject_sub` is the JWT `sub`
-- as the gateway sees it (the same string the bearer
-- validator drops into `Principal.sub`). Not a FK because
-- the gateway doesn't durably store every principal it's
-- ever seen — assignments can be pre-provisioned by sub.
CREATE TABLE role_assignments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    role_id     UUID NOT NULL,
    subject_sub TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- AERB PR #147 round 2 medium: composite FK against
    -- gateway_roles(id, tenant_id) — Postgres now refuses
    -- both (a) inserting a role_id whose row has a
    -- different tenant, AND (b) UPDATEing the parent's
    -- tenant_id while this child row references it.
    -- ON DELETE CASCADE keeps the existing "drop a role
    -- ⇒ drop its assignments" semantic.
    FOREIGN KEY (role_id, tenant_id)
        REFERENCES gateway_roles (id, tenant_id)
        ON DELETE CASCADE,
    -- Same (tenant, role, sub) cannot be added twice — a
    -- POST that re-adds is idempotent at the SQL layer.
    UNIQUE (tenant_id, role_id, subject_sub)
);

CREATE INDEX role_assignments_subject_idx
    ON role_assignments (tenant_id, subject_sub);

-- Refuse cross-tenant: an assignment's `tenant_id` must
-- match the role's `tenant_id`. Otherwise tenant A could
-- bind a role to tenant B's sub and accidentally leak
-- scopes across tenants.
CREATE OR REPLACE FUNCTION role_assignments_tenant_match() RETURNS TRIGGER AS $$
DECLARE
    role_tenant TEXT;
BEGIN
    SELECT tenant_id INTO role_tenant FROM gateway_roles WHERE id = NEW.role_id;
    IF role_tenant IS NULL THEN
        RAISE EXCEPTION 'role_assignments: role % not found', NEW.role_id;
    END IF;
    IF role_tenant <> NEW.tenant_id THEN
        RAISE EXCEPTION
            'role_assignments: role tenant `%` mismatches row tenant `%`',
            role_tenant, NEW.tenant_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER role_assignments_tenant_match_trg
    BEFORE INSERT OR UPDATE ON role_assignments
    FOR EACH ROW
    EXECUTE FUNCTION role_assignments_tenant_match();

-- SCIM group → role mapping. The bread-and-butter RBAC
-- path: provision SCIM groups via the IdP, map each one
-- to a role once, and forget. Composite PK on (tenant,
-- group, role) so the same group can carry multiple
-- roles and re-POSTing is idempotent.
CREATE TABLE group_role_mappings (
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    group_id    UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id, role_id),
    -- AERB PR #147 round 2 medium: composite FK against
    -- gateway_roles(id, tenant_id). Same defense as
    -- role_assignments above — UPDATEing a parent role's
    -- tenant_id is refused by Postgres while any mapping
    -- references it. The `group_id` FK to scim_groups is
    -- single-column because cross-tenant defense for the
    -- group side is enforced by the
    -- `group_role_mappings_tenant_match` trigger below
    -- (PR #144 deferred adding (id, tenant_id) to
    -- scim_groups; same fix would land there for full
    -- parent-immutable coverage).
    FOREIGN KEY (role_id, tenant_id)
        REFERENCES gateway_roles (id, tenant_id)
        ON DELETE CASCADE
);

CREATE INDEX group_role_mappings_role_idx
    ON group_role_mappings (tenant_id, role_id);

-- All three sides (mapping row, role, group) must agree
-- on tenant. Same shape as the scim_user_groups trigger
-- in migration 0020; without this, a tenant-A operator
-- with the wrong SQL-injection-y handler bug could bridge
-- a tenant-B group to a tenant-A role.
CREATE OR REPLACE FUNCTION group_role_mappings_tenant_match() RETURNS TRIGGER AS $$
DECLARE
    role_tenant TEXT;
    group_tenant TEXT;
BEGIN
    SELECT tenant_id INTO role_tenant FROM gateway_roles WHERE id = NEW.role_id;
    SELECT tenant_id INTO group_tenant FROM scim_groups WHERE id = NEW.group_id;
    IF role_tenant IS NULL THEN
        RAISE EXCEPTION 'group_role_mappings: role % not found', NEW.role_id;
    END IF;
    IF group_tenant IS NULL THEN
        RAISE EXCEPTION 'group_role_mappings: group % not found', NEW.group_id;
    END IF;
    IF role_tenant <> NEW.tenant_id THEN
        RAISE EXCEPTION
            'group_role_mappings: role tenant `%` mismatches row tenant `%`',
            role_tenant, NEW.tenant_id;
    END IF;
    IF group_tenant <> NEW.tenant_id THEN
        RAISE EXCEPTION
            'group_role_mappings: group tenant `%` mismatches row tenant `%`',
            group_tenant, NEW.tenant_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER group_role_mappings_tenant_match_trg
    BEFORE INSERT OR UPDATE ON group_role_mappings
    FOR EACH ROW
    EXECUTE FUNCTION group_role_mappings_tenant_match();
