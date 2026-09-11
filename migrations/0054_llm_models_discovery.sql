-- Dynamic model discovery: provenance + upstream-presence on llm_models.
--
-- The catalog is upsert-seeded from `GATEWAY_LLM_MODELS` today
-- (crates/gateway-server/src/llm.rs `seed_models`). The discovery
-- slice adds a background refresher that enumerates each provider's
-- live model list and upserts the discovered models into this table,
-- so an operator no longer hand-lists every model. That needs the
-- catalog to record two facts the original schema lacked:
--
--   - `source` — who owns the row. `config` rows come from the env
--     pins (`GATEWAY_LLM_MODELS`); `discovered` rows are minted by the
--     refresher. Reconciliation (soft-disable below) and the discovery
--     upsert's provenance gate only ever touch `discovered` rows, so a
--     pinned model is never auto-disabled or clobbered by discovery.
--
--   - `present_upstream` — whether the most recent successful discovery
--     for this row's provider still returned it. When a provider drops
--     a model the refresher sets this FALSE (soft-disable) rather than
--     deleting the row: usage rows reference the catalog, and deletion
--     would lose operator costing/history. The row stays for re-enable
--     if the model reappears.
--
-- These two flags are orthogonal to the operator's `enabled`:
-- `enabled` is the operator's intent (only the operator writes it);
-- `present_upstream` is discovery's view (only discovery writes it).
-- A row is offered for discovery/dispatch when it is enabled AND
-- (operator-pinned OR still present upstream) — the "effective-live"
-- predicate the listing and the catalog view below now use. A `config`
-- row is always effective-live when enabled (its `present_upstream` is
-- irrelevant), so existing pins are unaffected.

ALTER TABLE llm_models
    ADD COLUMN source TEXT NOT NULL DEFAULT 'config'
        CHECK (source IN ('config', 'discovered')),
    ADD COLUMN present_upstream BOOLEAN NOT NULL DEFAULT TRUE;

-- Every pre-existing row was written by the env seeder, so the
-- `config` / TRUE column defaults already classify them correctly —
-- no backfill UPDATE is needed.

-- Reconciliation scans a tenant's discovered rows for one provider to
-- soft-disable the ones a fresh discovery no longer returned. Support
-- that lookup directly.
CREATE INDEX llm_models_discovered_idx
    ON llm_models (tenant_id, provider)
 WHERE source = 'discovered';

-- The catalog-compatible projection (searchTools / facts surface, I7)
-- must hide a discovered model that is no longer present upstream, the
-- same way the listing does — otherwise discovery could keep
-- advertising a model the provider has dropped. Re-create the view with
-- the effective-live predicate; the column shape is unchanged.
CREATE OR REPLACE VIEW llm_models_catalog AS
SELECT
    tenant_id,
    'llm'                AS server_name,
    alias                AS tool_name,
    COALESCE(description, provider || ':' || upstream_model) AS description,
    risk                 AS risk_tier,
    TRUE                 AS pii,
    TRUE                 AS side_effects,
    requires_approval
FROM llm_models
WHERE enabled AND (source = 'config' OR present_upstream);
