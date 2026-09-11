-- 0064_scope_registry.sql
--
-- Identities revamp PR1 — the scope catalog.
--
-- Scopes (capability strings like `mcp:invoke:high`) have always been
-- implicit in this gateway: free strings typed into the api-key mint
-- form, baked into the `gateway_oidc::Scope` enum, or referenced by
-- Cedar policies — with no registry an operator could browse. This
-- table makes the set of *known* scopes first-class and visible. It is
-- an authoring + visibility layer ONLY: Cedar still evaluates
-- `principal.scopes` as plain strings, so nothing on the request hot
-- path changes.
--
-- ## Global vs tenant-local
--
-- `tenant_id IS NULL` marks a GLOBAL scope — the built-in `mcp:*` /
-- `scim:*` set, and (PR2) scopes discovered in the single, global Cedar
-- policy set. These apply to every tenant, so seeding them per-tenant
-- would silently miss tenants created later. `tenant_id = '<slug>'`
-- marks a tenant-local scope (operator-defined, or backfilled from that
-- tenant's existing keys/roles). Reads — and (PR3) mint validation —
-- UNION the two: a scope is known to tenant T iff a global row OR a
-- `(T, name)` row exists.
--
-- ## source
--
--   'builtin' — the gateway's own `Scope` enum; undeletable (PR3 gate).
--   'policy'  — referenced by a loaded Cedar policy; populated by the
--               boot/reload reconcile in PR2; undeletable.
--   'local'   — operator-defined, or backfilled from existing data.
--
-- The CHECK admits all three now so PR2 (policy reconcile) needs no
-- schema change.
--
-- ## Seeding / backfill (this migration)
--
--   1. Seed the 8 built-ins GLOBAL. KEEP THIS LIST == `gateway_oidc::
--      Scope::ALL`; the `pg_scope_store` test compares the seeded
--      `source='builtin'` rows against the enum and fails on drift.
--   2. Backfill every distinct scope already referenced by a LIVE
--      `api_keys` row (its `scopes` JSONB array) or any `gateway_roles`
--      row (its `scopes` TEXT[]) as a tenant-local `'local'` row,
--      skipping names already covered by a global built-in. "Everything
--      that exists now is first-class/managed" — no second-class
--      `legacy` tier. Revoked keys are excluded: their scopes are not
--      part of the forward-looking catalog the mint path (PR3) will
--      validate against.

CREATE TABLE scopes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL = global (built-in / policy-referenced); a tenant slug = a
    -- tenant-local scope.
    tenant_id   TEXT,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('builtin', 'policy', 'local')),
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Uniqueness: one global row per name; one tenant-local row per
-- (tenant, name). Partial indexes because a NULL tenant_id can't carry
-- its identity through a plain composite UNIQUE the way a non-NULL one
-- does (NULLs are distinct), and the two namespaces must not collide.
CREATE UNIQUE INDEX scopes_global_name_uq
    ON scopes (name) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX scopes_tenant_name_uq
    ON scopes (tenant_id, name) WHERE tenant_id IS NOT NULL;

-- Built-ins, GLOBAL. KEEP == gateway_oidc::Scope::ALL (asserted by the
-- pg_scope_store integration test).
INSERT INTO scopes (tenant_id, name, source) VALUES
    (NULL, 'mcp:invoke',      'builtin'),
    (NULL, 'mcp:invoke:high', 'builtin'),
    (NULL, 'mcp:read',        'builtin'),
    (NULL, 'mcp:admin',       'builtin'),
    (NULL, 'mcp:propose',     'builtin'),
    (NULL, 'mcp:observe',     'builtin'),
    (NULL, 'scim:read',       'builtin'),
    (NULL, 'scim:write',      'builtin')
ON CONFLICT DO NOTHING;

-- Backfill from LIVE api_keys. `scopes` is a JSONB array of text; the
-- CASE guards the rare/legacy non-array row so the set-returning
-- function never raises on a malformed value (it would error per outer
-- row before the WHERE could filter it).
INSERT INTO scopes (tenant_id, name, source)
SELECT DISTINCT k.tenant_id, elem, 'local'
  FROM api_keys k
  CROSS JOIN LATERAL jsonb_array_elements_text(
      CASE WHEN jsonb_typeof(k.scopes) = 'array' THEN k.scopes ELSE '[]'::jsonb END
  ) AS elem
 WHERE k.revoked_at IS NULL
   AND NOT EXISTS (SELECT 1 FROM scopes g WHERE g.tenant_id IS NULL AND g.name = elem)
ON CONFLICT DO NOTHING;

-- Backfill from gateway_roles. `scopes` is TEXT[].
INSERT INTO scopes (tenant_id, name, source)
SELECT DISTINCT r.tenant_id, elem, 'local'
  FROM gateway_roles r
  CROSS JOIN LATERAL unnest(r.scopes) AS elem
 WHERE NOT EXISTS (SELECT 1 FROM scopes g WHERE g.tenant_id IS NULL AND g.name = elem)
ON CONFLICT DO NOTHING;

-- Reuse the shared updated-at trigger fn defined in 0019_scim_users.sql
-- so `updated_at` tracks edits (PR3 description edits) without a
-- per-handler bump.
CREATE TRIGGER scopes_touch_updated_at_trg
    BEFORE UPDATE ON scopes
    FOR EACH ROW
    EXECUTE FUNCTION scim_users_touch_updated_at();
