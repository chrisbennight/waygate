-- Rename the `native_surface` column to `upstream_api` and widen it to record
-- the model's REAL upstream wire API, not a coarse two-value placeholder (#395).
--
-- 0047 could only store `chat_completions | responses`, so an Anthropic model
-- (Messages API) or a Gemini model (generateContent) was mislabeled
-- `chat_completions` on the read-only `/admin/llm_models` dashboard. The value
-- is cosmetic — routing derives the protocol from `provider` (+ the
-- `responses`/`openai_chatgpt` flags), never from this column — so widening it
-- is safe. The boot seeder (`model_def_to_upsert` → `upstream_api_for`) and the
-- discovery refresher now write the resolved `UpstreamProtocol`'s name; this
-- migration renames the column, widens the CHECK to the four real wire APIs,
-- and backfills the rows 0047's CHECK had forced to `chat_completions`.
--
-- The inline CHECK from 0047 is auto-named `llm_models_native_surface_check`;
-- it must be dropped (else it would still reject `messages`/`generate_content`).

ALTER TABLE llm_models RENAME COLUMN native_surface TO upstream_api;

ALTER TABLE llm_models DROP CONSTRAINT IF EXISTS llm_models_native_surface_check;
ALTER TABLE llm_models ADD CONSTRAINT llm_models_upstream_api_check
    CHECK (upstream_api IN ('chat_completions','responses','messages','generate_content'));

-- Backfill the provider-default native shapes the old CHECK couldn't represent.
-- `responses` rows (incl. Codex) and openai/openrouter `chat_completions` rows
-- are already correct and left untouched.
UPDATE llm_models SET upstream_api = 'messages'
    WHERE provider = 'anthropic' AND upstream_api = 'chat_completions';
UPDATE llm_models SET upstream_api = 'generate_content'
    WHERE provider = 'google' AND upstream_api = 'chat_completions';
