-- Phase 3 PR3-1a: the inference plane's model catalog.
--
-- Phase 2 routes LLM calls from a static env catalog
-- (`GATEWAY_LLM_MODELS` JSON → `StaticModelResolver`, see
-- crates/gateway-server/src/llm.rs). That is enough to dispatch a
-- call, but Phase 3 needs the catalog to be a queryable table so
-- the rest of the inference plane can hang off it:
--
--   - PR3-1b surfaces each model as an `llm.<alias>` operation in
--     `searchTools` (discovery) and upserts the configured models
--     into this table at boot (the writer).
--   - PR3-2 reads `risk` here to drive the Cedar `Model` resource
--     and the `llm:invoke:high` step-up.
--   - PR3-3 reads the (optional) costing columns to weight token
--     budgets and to compute `InferenceRecord.total_cost` when the
--     provider does not report a cost (`ComputedFromCatalog`).
--
-- Like 0011_catalog.sql, this migration only lays the schema: the
-- table is empty until PR3-1b's boot-time upsert fills it, and the
-- per-call routing hot path keeps using the env-built resolver
-- until DB-backed routing/pooling lands in Phase 4. Nothing in the
-- running code reads this table yet.
--
-- Routing vs. catalog: `provider` / `credential_label` /
-- `upstream_model` / `base_url` / `path` mirror the env `ModelDef` so
-- the table is a faithful materialization of the configured models
-- (and the seam Phase 4 routing will read). Risk, costing, surface,
-- and approval are the governance metadata layered on top.

-- ---------------------------------------------------------------
-- llm_models — one row per (tenant, client-facing model alias).
--
-- `(tenant_id, alias)` is the natural primary key: the alias is
-- what a client names in the `model` field, and it is unique within
-- a tenant. There is no surrogate id (mirrors the composite-key
-- style of mcp_tool_versions).
--
-- `native_surface` records the provider-native API shape for the
-- model (Chat Completions today; Responses arrives with the
-- per-provider adapters in Phase 4). The inbound surface a client
-- uses is independent — translation is the inference plane's job.
--
-- `risk` reuses the tool risk vocabulary (low|medium|high|critical)
-- so the Cedar mapping for models can share the tool risk→scope
-- pattern. Default `high`: an unclassified model is treated as
-- high-risk (fail-safe), matching the Phase 2 synthetic facts.
--
-- Costing is OPTIONAL (every cost column nullable). NULL costing ⇒
-- token budgets still apply but cost-based budgets skip for this
-- model, and `InferenceRecord.cost_source = Unknown` (design §4.2).
-- Rates are per **million** tokens (the unit providers publish), in
-- `currency`. NUMERIC (exact) rather than float — money math must
-- not carry binary-fraction error.
-- ---------------------------------------------------------------

CREATE TABLE llm_models (
    tenant_id                  TEXT NOT NULL DEFAULT 'default',
    alias                      TEXT NOT NULL,
    provider                   TEXT NOT NULL
                               CHECK (provider IN ('openai','anthropic','google','openrouter')),
    -- which pooled credential serves this model: the dispatcher
    -- resolves the bearer via `bearer(provider, credential_label)`
    -- (LLM_CRED_<PROVIDER>_<LABEL>). Part of the env `ModelDef`, so
    -- it must be here for the table to faithfully back Phase 4's
    -- DB-backed routing. NOT NULL: routing cannot select a credential
    -- without it (the table is empty until PR3-1b seeds it, so there
    -- are no legacy rows needing a default).
    credential_label           TEXT NOT NULL,
    upstream_model             TEXT NOT NULL,
    base_url                   TEXT NOT NULL,
    path                       TEXT NOT NULL DEFAULT 'chat/completions',
    native_surface             TEXT NOT NULL DEFAULT 'chat_completions'
                               CHECK (native_surface IN ('chat_completions','responses')),
    risk                       TEXT NOT NULL DEFAULT 'high'
                               CHECK (risk IN ('low','medium','high','critical')),
    requires_approval          BOOLEAN NOT NULL DEFAULT FALSE,
    description                TEXT,
    -- optional costing, per MILLION tokens, in `currency`. A rate is
    -- either unset (NULL) or non-negative — a negative price is
    -- nonsensical and, since PR3-3 multiplies these by token counts to
    -- weight budgets and compute `InferenceRecord.total_cost`, a stray
    -- negative would *credit* a budget. Reject it at the schema
    -- boundary so no writer can persist one.
    input_cost_per_mtok        NUMERIC,
    output_cost_per_mtok       NUMERIC,
    cached_read_cost_per_mtok  NUMERIC,
    cache_write_cost_per_mtok  NUMERIC,
    currency                   TEXT NOT NULL DEFAULT 'USD',
    -- a disabled model stays in the catalog (history / re-enable)
    -- but is not offered for discovery or dispatch.
    enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, alias),
    CONSTRAINT llm_models_costs_nonnegative CHECK (
        (input_cost_per_mtok       IS NULL OR input_cost_per_mtok       >= 0) AND
        (output_cost_per_mtok      IS NULL OR output_cost_per_mtok      >= 0) AND
        (cached_read_cost_per_mtok IS NULL OR cached_read_cost_per_mtok >= 0) AND
        (cache_write_cost_per_mtok IS NULL OR cache_write_cost_per_mtok >= 0)
    )
);

-- Discovery / risk lookups scan a tenant's enabled models.
CREATE INDEX llm_models_tenant_enabled_idx
    ON llm_models (tenant_id)
 WHERE enabled;

-- ---------------------------------------------------------------
-- llm_models_catalog — a catalog-compatible projection.
--
-- Projects each enabled model into the same column shape the tool
-- discovery/facts surface speaks (server_name / tool_name /
-- description / risk_tier / pii / side_effects / requires_approval),
-- so `searchTools` (PR3-1b) and the facts path can consume models
-- and tools uniformly. The synthetic server is the reserved `llm`
-- namespace (matches `LLM_SERVER` and the resolver's owned server).
--
-- pii = TRUE: an LLM call carries user prompt/response content.
-- side_effects = TRUE: it is a billable external call. Both mirror
-- the Phase 2 synthetic model facts so governance is unchanged when
-- the facts begin reading from the catalog (PR3-2).
-- ---------------------------------------------------------------

CREATE VIEW llm_models_catalog AS
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
WHERE enabled;
