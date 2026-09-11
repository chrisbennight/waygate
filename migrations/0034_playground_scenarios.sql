-- D4c-2: per-tenant playground saved scenarios.
--
-- ## What
--
-- New `playground_scenarios` table holding named, operator-saved
-- form inputs for the Cedar policy playground page
-- (`/admin/t/<tenant>/playground`). Each row is one snapshot of
-- the playground form's principal/action/resource state, keyed by
-- a human-friendly name the operator picks. Load + Save + Delete
-- are dashboard-only — no runtime path consults this table.
--
-- ## Why a dedicated table (not config / not policy_bundles)
--
-- Policy authors iterate by tweaking a small set of canonical
-- scenarios ("alice on send_message — deny", "service account on
-- search_tools — allow") and re-running them after each policy
-- edit. The D4c-1 playground page is stateless: each visit
-- requires the operator to retype every form value. Saved
-- scenarios are the natural fix and have no overlap with the
-- policy bundle versioning surface (`policy_bundles`).
--
-- ## Shape
--
-- - `tenant_id` FKs `tenants(id) ON DELETE CASCADE` — scenarios
--   are tenant-scoped (a tenant operator saves scenarios specific
--   to their roles + servers; cross-tenant reuse is meaningless).
-- - Composite PK on `(tenant_id, name)` — list/upsert/delete are
--   all keyed by name; the operator never sees the surrogate id
--   so we don't need one.
-- - `body JSONB` carries the form values verbatim. We deliberately
--   don't schema-validate at the SQL layer — the dashboard
--   handler owns the shape (Pydantic-style validation lives in
--   Rust), and a future form-field addition shouldn't require a
--   migration.
-- - `created_by` records the principal `sub` at save time so an
--   operator scanning the list can see who owns each scenario.
--   Nullable — saving without an authenticated principal (dev
--   mode) shouldn't break.
--
-- ## Tenant deletion cascade
--
-- `ON DELETE CASCADE` on the FK matches the rest of the
-- tenant-scoped tables (rate_limit_policies, scim_users,
-- federated_peers, etc.). A tenant DELETE wipes its scenarios
-- with it, no orphan rows.

CREATE TABLE playground_scenarios (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    body        JSONB NOT NULL,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

CREATE INDEX playground_scenarios_tenant ON playground_scenarios (tenant_id);

-- updated_at auto-bump (same shape as
-- federated_peers_touch_updated_at and the
-- inspection_rules_touch_updated_at_trg from PR9-c5).
CREATE OR REPLACE FUNCTION playground_scenarios_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER playground_scenarios_touch_updated_at_trg
    BEFORE UPDATE ON playground_scenarios
    FOR EACH ROW EXECUTE FUNCTION playground_scenarios_touch_updated_at();
