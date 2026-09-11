-- 0066_groups_source.sql
--
-- Identities revamp PR3 — unify groups.
--
-- Today there are two disconnected notions of "group": IdP-provisioned
-- SCIM groups (`scim_groups`, browsable + role-mappable) and the
-- free-text labels typed into the api-key mint form (`api_keys.groups`
-- JSONB, invisible — nothing lists them). Cedar treats both as plain
-- `principal.groups` strings, so they look equivalent at eval time but
-- are completely disconnected in the UI.
--
-- This migration unifies them onto one table. It adds a `source`
-- discriminator to `scim_groups` so the table holds BOTH provisioned
-- SCIM groups (`source='scim'`, every existing row) and operator /
-- api-key `'local'` groups, then backfills every distinct free-text
-- api-key label as a first-class local group. "Everything that exists
-- now is first-class/managed" — the labels stop being shadow groups.
--
-- Authoring/visibility only: Cedar still evaluates `principal.groups`
-- as plain strings, so the request hot path is unchanged. The SCIM 2.0
-- surface (`gateway-scim::PgScimGroupStore`) is source-scoped to
-- `source='scim'` so it never exposes or mutates these local rows, and
-- its create promotes a conflicting local row to `'scim'` rather than
-- 409 — see that crate (AERB #547). (This comment was corrected before
-- 0066 shipped to main; the immutable-migration guard permits it because
-- 0066 is a new file, not a modification of a base-branch migration.)

ALTER TABLE scim_groups
    ADD COLUMN source TEXT NOT NULL DEFAULT 'scim'
        CHECK (source IN ('scim', 'local'));

-- Backfill: every distinct group label on a LIVE api-key becomes a
-- first-class `local` group — UNLESS a SCIM group with that
-- `display_name` already exists in the tenant, in which case the label
-- resolves to that SCIM group (the unification; `ON CONFLICT … DO
-- NOTHING` on the existing `UNIQUE (tenant_id, display_name)`). Local
-- rows leave `external_id` NULL (the `external_id` unique index is
-- partial on non-NULL, and `UNIQUE (tenant_id, display_name)` gives a
-- local group its identity); `attrs` defaults to '{}'. Revoked keys are
-- excluded — their labels aren't part of the forward-looking catalog.
-- The CASE guards a rare/legacy non-array `groups` value so the
-- set-returning function never raises before the WHERE can filter.
INSERT INTO scim_groups (tenant_id, display_name, source)
SELECT DISTINCT k.tenant_id, elem, 'local'
  FROM api_keys k
  CROSS JOIN LATERAL jsonb_array_elements_text(
      CASE WHEN jsonb_typeof(k.groups) = 'array' THEN k.groups ELSE '[]'::jsonb END
  ) AS elem
 WHERE k.revoked_at IS NULL
   AND elem <> ''
ON CONFLICT (tenant_id, display_name) DO NOTHING;
