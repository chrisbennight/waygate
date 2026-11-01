-- Realtime is explicitly configured and never inferred from a model name.
ALTER TABLE llm_models DROP CONSTRAINT llm_models_upstream_api_check;
ALTER TABLE llm_models ADD CONSTRAINT llm_models_upstream_api_check
    CHECK (upstream_api IN ('chat_completions', 'responses', 'messages',
                           'generate_content', 'embeddings', 'images', 'speech', 'realtime'));

CREATE OR REPLACE VIEW llm_models_catalog AS
SELECT
    tenant_id,
    'llm' AS server_name,
    alias AS tool_name,
    COALESCE(description, provider || ':' || upstream_model) AS description,
    risk AS risk_tier,
    TRUE AS pii,
    TRUE AS side_effects,
    requires_approval,
    CASE upstream_api
        WHEN 'embeddings' THEN 'embeddings'
        WHEN 'images' THEN 'images'
        WHEN 'speech' THEN 'speech'
        WHEN 'realtime' THEN 'realtime'
        ELSE 'chat'
    END AS kind
FROM llm_models
WHERE enabled AND (source = 'config' OR present_upstream);
