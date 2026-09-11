-- Gateway-Agents foundation PR 0.1: per-tenant agent configuration.
--
-- ## What
--
-- New `agent_configs` table holding the operator-authored definitions of the
-- in-app LLM agents: the interactive chat agent (Phase 1) and, later, the
-- policy-review / classification task agents (Phases 2-3). One row per
-- `(tenant, name)` agent. The admin dashboard "Gateway Agents" tab is the
-- writer; the agent runtime loop (Phase 0.4+) and the chat handler (Phase 1.2)
-- are the readers.
--
-- ## Why PR 0.1 is config-only
--
-- Nothing *runs* an agent yet. This slice ships the storage + admin surface so
-- operators can define and tune an agent (model, tool allowlist, loop caps)
-- ahead of the runtime flip. Until the loop lands, rows here are inert config.
--
-- ## Shape
--
-- - `id` UUID surrogate so the admin surface (and a future `conversations` FK)
--   can address an agent without quoting the composite key. A rename therefore
--   never orphans a reference.
-- - `tenant_id` is plain TEXT with a `'default'` fallback (NOT a FK to
--   `tenants`) — matching the sibling per-tenant config catalog `llm_models`
--   (0047), which is also config rather than principal/credential data. A
--   deleted tenant leaves inert orphan config rows; that is acceptable for a
--   config table and avoids requiring a seeded tenant row for inserts.
-- - `name` is the operator-friendly label, UNIQUE per tenant.
-- - `kind` is the agent role. Closed CHECK so a typo fails fast; the three
--   values are the planned agent kinds (chat now; policy_review /
--   classification later).
-- - `model_alias` names the `llm_models` row the agent dispatches reasoning
--   to. Deliberately NOT a FK: a discovered model can come and go, so the
--   alias is a soft reference validated at agent run time.
-- - `instructions` is an optional operator system-prompt addendum.
-- - `allowed_tools` JSONB array is the agent's tool allowlist (fully-qualified
--   tool ids). DEFAULT '[]' — empty by default, so a freshly-created agent can
--   call NOTHING until an operator opts tools in. This is the primary capability
--   boundary; the runtime enforces it by narrowing the acting principal's
--   api-key-profile restrictions to this set.
-- - `max_steps` / `max_tool_calls` bound the loop (a runaway agent can't spin);
--   `token_budget` is an optional per-run token cap. CHECKs keep them sane.
-- - `enabled` DEFAULT false — a new agent is inert until an operator turns it
--   on.
-- - `created_at` / `updated_at` for the audit trail; trigger bumps
--   `updated_at` on UPDATE (mirrors inspection_rules / task_states).
--
-- ## Indexes
--
-- - `(tenant_id)` for the admin list page.
-- - `(tenant_id) WHERE enabled` partial index for the runtime's "enabled
--   agents for this tenant" lookup (Phase 1.2+).

CREATE TABLE agent_configs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      TEXT NOT NULL DEFAULT 'default',
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'chat'
                   CHECK (kind IN ('chat', 'policy_review', 'classification')),
    model_alias    TEXT NOT NULL,
    instructions   TEXT,
    allowed_tools  JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_steps      INTEGER NOT NULL DEFAULT 8
                   CHECK (max_steps > 0 AND max_steps <= 100),
    max_tool_calls INTEGER NOT NULL DEFAULT 16
                   CHECK (max_tool_calls > 0 AND max_tool_calls <= 500),
    token_budget   INTEGER CHECK (token_budget IS NULL OR token_budget > 0),
    enabled        BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX agent_configs_by_tenant ON agent_configs (tenant_id);

CREATE INDEX agent_configs_by_tenant_enabled
    ON agent_configs (tenant_id)
    WHERE enabled;

-- updated_at auto-bump on UPDATE (mirrors inspection_rules_touch_updated_at).
CREATE OR REPLACE FUNCTION agent_configs_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_configs_touch_updated_at_trg
    BEFORE UPDATE ON agent_configs
    FOR EACH ROW
    EXECUTE FUNCTION agent_configs_touch_updated_at();
