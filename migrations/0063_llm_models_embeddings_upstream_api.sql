-- Widen the `llm_models.upstream_api` CHECK to admit `embeddings`, the wire API
-- of an OpenAI-compatible embeddings model (PR-E4).
--
-- For chat models `upstream_api` is cosmetic — routing derives the protocol from
-- `provider` (+ the `responses`/`openai_chatgpt` flags), never from this column.
-- For an *embeddings* model the column IS the catalog marker the routing resolver
-- maps to `LlmOperation::Embeddings` (`resolved_from_catalog_row` in
-- `gateway-server/src/llm.rs`), so a row with `upstream_api = embeddings` routes
-- the call through the embeddings dispatch path. Discovery is chat-only today, so
-- `embeddings` rows are written only by the env-pin seeder (`model_def_to_upsert`).
--
-- The inline CHECK added by 0056 is named `llm_models_upstream_api_check`; drop it
-- (else it would still reject `embeddings`) and re-add it with the widened value
-- set. Additive only — no existing row changes, so it is safe on a populated
-- table (every current value is still permitted).

ALTER TABLE llm_models DROP CONSTRAINT IF EXISTS llm_models_upstream_api_check;
ALTER TABLE llm_models ADD CONSTRAINT llm_models_upstream_api_check
    CHECK (upstream_api IN ('chat_completions','responses','messages','generate_content','embeddings'));
