-- 0065_llm_models_catalog_kind.sql
--
-- Surface a model's operation kind in the catalog projection so embeddings
-- models read as first-class-distinct from chat-family models wherever the
-- `llm_models_catalog` view is consumed (the searchTools / facts surface and
-- any catalog reader). Derived from `upstream_api` — the single source of truth
-- for a model's operation (`embeddings` vs the chat-family
-- chat_completions / responses / messages / generate_content), the same value
-- the resolver maps to `LlmOperation` and the `/v1/models` `modality` field
-- exposes. Additive: appends one column to the existing view; `CREATE OR
-- REPLACE VIEW` preserves the prior column order/types (the 0054 effective-live
-- predicate is carried forward unchanged).
CREATE OR REPLACE VIEW llm_models_catalog AS
SELECT
    tenant_id,
    'llm'                AS server_name,
    alias                AS tool_name,
    COALESCE(description, provider || ':' || upstream_model) AS description,
    risk                 AS risk_tier,
    TRUE                 AS pii,
    TRUE                 AS side_effects,
    requires_approval,
    CASE WHEN upstream_api = 'embeddings' THEN 'embeddings' ELSE 'chat' END AS kind
FROM llm_models
WHERE enabled AND (source = 'config' OR present_upstream);
