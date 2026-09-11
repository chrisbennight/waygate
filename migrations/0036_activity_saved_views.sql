-- D6b-2a: per-tenant activity saved views.
--
-- ## What
--
-- New `activity_saved_views` table holding named, operator-saved
-- filter combinations for the activity / audit-log page
-- (`/admin/t/<tenant>/activity`). Each row is one snapshot of the
-- activity page's filter state (outcome, risk, server, principal,
-- category, pii, since), keyed by a human-friendly name the
-- operator picks. Load + Save + Delete are dashboard-only — no
-- runtime path consults this table.
--
-- ## Why a dedicated table (not config / not user-prefs)
--
-- Compliance + on-call operators iterate by reapplying the SAME
-- filter combos repeatedly ("today's high-risk denials", "this
-- week's PII calls from the contractor groups"). The D6b-1
-- activity page is stateless beyond the URL: the only way to
-- recall a filter combo is to bookmark every shape. Saved views
-- are the natural fix.
--
-- ## Shape
--
-- - `tenant_id` FKs `tenants(id) ON DELETE CASCADE` — saved
--   views are tenant-scoped (a tenant operator's "today's high-
--   risk denials" doesn't generalise across tenants whose
--   servers/principals differ).
-- - Composite PK on `(tenant_id, name)` — list/upsert/delete are
--   all keyed by name; the operator never sees the surrogate id
--   so we don't need one. Mirrors `playground_scenarios`.
-- - `filters JSONB` carries the filter shape verbatim. We
--   deliberately don't schema-validate at the SQL layer — the
--   dashboard handler owns the shape (filter validation lives in
--   Rust at the activity-page layer), and a future facet addition
--   shouldn't require a migration. The handler treats unknown
--   keys as forward-compat.
-- - `created_by` records the principal `sub` at save time so an
--   operator scanning the list can see who owns each view.
--   Nullable — saving without an authenticated principal (dev
--   mode) shouldn't break.
--
-- ## Tenant deletion cascade
--
-- `ON DELETE CASCADE` on the FK matches the rest of the
-- tenant-scoped tables (playground_scenarios, scim_users,
-- federated_peers, etc.). A tenant DELETE wipes its saved views
-- with it, no orphan rows.

CREATE TABLE activity_saved_views (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    filters     JSONB NOT NULL,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

CREATE INDEX activity_saved_views_tenant ON activity_saved_views (tenant_id);

-- updated_at auto-bump (same shape as playground_scenarios_touch_updated_at
-- and the federated_peers_touch_updated_at trigger).
CREATE OR REPLACE FUNCTION activity_saved_views_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER activity_saved_views_touch_updated_at_trg
    BEFORE UPDATE ON activity_saved_views
    FOR EACH ROW EXECUTE FUNCTION activity_saved_views_touch_updated_at();
