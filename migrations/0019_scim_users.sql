-- Phase 8 PR8-a: SCIM 2.0 User resource storage.
--
-- One row per SCIM-provisioned user. The identity provider
-- (Okta, Authentik, EntraID, ...) POSTs `/scim/v2/Users`
-- and the row lands here. The future attribute resolver
-- (PR8-b+) reads from this table to enrich `Principal.attrs`
-- at bearer-validate time.
--
-- ## Per-tenant scoping
--
-- The gateway is multi-tenant from Phase 3 (`tenant_id`
-- everywhere). SCIM clients are tenant-scoped too: each
-- identity provider's tenant configuration includes a
-- gateway API key minted with `scim:write` scope, and
-- inserts are stamped with that key's `tenant_id`. A
-- tenant-A SCIM client can't see or mutate tenant-B users —
-- the per-tenant constraint pair below makes that
-- structurally true regardless of handler-level checks.
--
-- ## Shape vs RFC 7643 §4.1
--
-- The SCIM Core User schema has many optional fields
-- (name.{family,given,middle,formatted}, emails[], phones[],
-- addresses[], photos[], roles[], ...). Storing them as
-- top-level columns would force a column per ever-evolving
-- SCIM attribute. Instead:
--
-- - The fixed-by-the-spec attributes (`id`, `userName`,
--   `externalId`, `active`) get dedicated columns — they
--   appear in filter queries (`userName eq "x"`) and
--   uniqueness constraints.
-- - Everything else lives in a single `attrs JSONB` column
--   verbatim. JSONB preserves the IdP's emitted shape and
--   lets future filter / projection queries reach into
--   sub-fields without schema migration.
--
-- ## Updates
--
-- SCIM updates are RFC 7644 §3.5.1 PUT (full replace) and
-- §3.5.2 PATCH (incremental). Round 1 supports PUT only
-- (Okta + Authentik both support PUT-only mode); PATCH
-- lands in a follow-up. The `updated_at` column tracks
-- last write for SCIM clients that lean on the
-- `meta.lastModified` field.

CREATE TABLE scim_users (
    -- SCIM `id` per RFC 7643 §3.1: server-assigned, opaque,
    -- immutable. We use UUIDv4 (random); UUIDv7 would also
    -- work but timestamp-ordering of SCIM ids isn't useful
    -- (the IdP doesn't sort by `id`).
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    -- SCIM `externalId` per §3.1: caller-assigned, opaque,
    -- the IdP's own primary key. Nullable because some IdPs
    -- (notably homegrown ones) don't emit it.
    external_id  TEXT,
    -- SCIM `userName` per §4.1.1: the unique-per-tenant
    -- identifier the IdP wants the gateway to use as the
    -- principal name. MUST be unique per (tenant, userName)
    -- per RFC 7643.
    user_name    TEXT NOT NULL,
    -- SCIM `active` per §4.1.1: false ⇒ user is deactivated
    -- (login should be refused). RFC 7644 lets clients
    -- toggle this via PUT or PATCH; the gateway treats
    -- `active = false` as "skip when resolving attrs onto
    -- a bearer principal."
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    -- The rest of the SCIM User resource as JSONB.
    -- Includes `name.*`, `emails[]`, `groups[]` (mirrored;
    -- groups also live in a separate table for relational
    -- joins in PR8-b), `photos[]`, `roles[]`,
    -- enterprise-extension fields, ... whatever the IdP
    -- sent. The handler validates JSON shape on POST/PUT;
    -- this column is the source of truth for the rest of
    -- the resource.
    attrs        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Per-tenant uniqueness on `userName` per RFC 7643.
    UNIQUE (tenant_id, user_name),
    -- Per-tenant uniqueness on `externalId` when present;
    -- PostgreSQL treats NULLs as distinct so multiple rows
    -- without `externalId` don't collide.
    UNIQUE (tenant_id, external_id)
);

-- Filter lookup index. The most common SCIM filter Okta
-- and Authentik emit is `userName eq "x"`, which the
-- UNIQUE (tenant_id, user_name) above already covers.
-- Add an explicit index on `externalId` since IdPs also
-- frequently filter by it during initial-sync de-duplication.
CREATE INDEX scim_users_external_id_idx
    ON scim_users (tenant_id, external_id)
 WHERE external_id IS NOT NULL;

-- Updated-at trigger: keeps the column accurate so SCIM
-- clients honouring `meta.lastModified` for delta-sync see
-- correct values. RFC 7643 §3.1 mandates this metadata.
CREATE OR REPLACE FUNCTION scim_users_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER scim_users_touch_updated_at_trg
    BEFORE UPDATE ON scim_users
    FOR EACH ROW
    EXECUTE FUNCTION scim_users_touch_updated_at();
