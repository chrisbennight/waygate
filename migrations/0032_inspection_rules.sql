-- Phase 9 PR9-c5: per-tenant response-inspector rule overrides.
--
-- ## What
--
-- New `inspection_rules` table holding per-tenant custom rules
-- the response-inspector pipeline can layer on top of the hard-
-- coded built-in rulesets shipped in PR9-c2 / c3 / c4 (PII,
-- secrets, poisoning). Operators use this to:
--
-- - Add tenant-specific PII patterns the built-in ruleset
--   doesn't know about (internal employee-ID formats, customer
--   identifiers, etc.).
-- - Override the decision mode (block vs. redact) per tool or
--   per principal for the same built-in pattern.
-- - Bound which tools/principals a rule applies to (the
--   `applies_to` JSONB carries operator-authored selectors).
--
-- ## Why PR9-c5 is admin-CRUD-only
--
-- The runtime consumption — an `Inspector` impl that loads rows
-- from this table on each invoke (or via a cached refresh
-- worker) — lands with PR9-c5b. Shipping the storage + admin
-- surface first means operators can seed rules ahead of the
-- runtime flip; until the runtime consumer ships, rows in this
-- table are inert (visible via the admin REST but not
-- enforced).
--
-- ## Shape
--
-- - `id` UUID surrogate so the admin REST can address a rule
--   without quoting the composite key.
-- - `tenant_id` FKs `tenants(id) ON DELETE CASCADE` — a hard-
--   deleted tenant takes its custom rules with it. Same cascade
--   pattern as `oauth_consent`, `break_glass_tokens`,
--   `task_states`.
-- - `inspector` is the operator-facing label of the built-in
--   inspector this rule layers onto (`"pii"`, `"secrets"`,
--   `"poisoning"`, or `"custom"` for an inspector type that
--   PR9-c5b will introduce). Closed CHECK so a typo at insert
--   time fails fast.
-- - `name` is the operator-friendly label that surfaces in
--   audit reasons + admin UI. UNIQUE per (tenant, inspector)
--   so operators can't accidentally create two rules with the
--   same label that would be ambiguous in audit rows.
-- - `config` JSONB carries the rule body (pattern, replacement
--   token, label, etc.). Shape is inspector-specific and
--   validated by the runtime consumer (PR9-c5b); the storage
--   layer is opaque so future inspector kinds can store
--   richer data without a schema rev.
-- - `applies_to` JSONB carries operator-authored selectors
--   (e.g. `{"tools": ["signal.send"], "principals": ["*"]}`
--   or `{}` for "any tool, any principal"). Same shape-
--   evolution rationale as `config`.
-- - `enabled` lets operators toggle a rule off without
--   deleting it. Default `true` so a freshly-created rule
--   is immediately active.
-- - `created_at`, `updated_at` for audit trail. Trigger
--   bumps `updated_at` on every UPDATE.
--
-- ## Indexes
--
-- - `(tenant_id, inspector)` so the runtime per-call lookup
--   (PR9-c5b) scopes to the calling tenant + the relevant
--   inspector cheaply.
-- - `(tenant_id, enabled)` partial index for "enabled only"
--   page in the admin UI.

CREATE TABLE inspection_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    inspector     TEXT NOT NULL
                  CHECK (inspector IN ('pii', 'secrets', 'poisoning', 'custom')),
    name          TEXT NOT NULL,
    config        JSONB NOT NULL,
    applies_to    JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, inspector, name)
);

CREATE INDEX inspection_rules_by_tenant_inspector
    ON inspection_rules (tenant_id, inspector);

CREATE INDEX inspection_rules_by_tenant_enabled
    ON inspection_rules (tenant_id, created_at DESC)
    WHERE enabled = true;

-- updated_at auto-bump on UPDATE (mirrors tenants.touch_updated_at
-- and task_states_touch_updated_at_trg from PR11-2).
CREATE OR REPLACE FUNCTION inspection_rules_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER inspection_rules_touch_updated_at_trg
    BEFORE UPDATE ON inspection_rules
    FOR EACH ROW
    EXECUTE FUNCTION inspection_rules_touch_updated_at();
