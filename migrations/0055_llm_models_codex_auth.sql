-- Codex (ChatGPT-backend) auth variant on llm_models, so a DISCOVERED model
-- can route through the Codex backend.
--
-- A model's transport auth is otherwise fully determined by its `provider`
-- (+ `native_surface` for the OpenAI Responses shape): the dispatcher picks
-- `ProviderAuth` from those. The one exception is OpenAI's Codex subscription:
-- it speaks the OpenAI **Responses** shape (`native_surface = 'responses'`) but
-- against the ChatGPT backend (`chatgpt.com/backend-api/codex`) with the Codex
-- request fingerprint (`ProviderAuth::OpenAiChatGpt` — originator / session /
-- `chatgpt-account-id`), NOT a plain `Authorization: Bearer`. `provider='openai'`
-- + `native_surface='responses'` alone can't distinguish that Codex variant from
-- a standard OpenAI Responses endpoint.
--
-- For **pins** this is carried in the env `ModelDef` (`surface: codex`) and lives
-- only in the in-memory resolver. A **discovered** Codex model has no `ModelDef`
-- — it routes from its catalog row via `resolved_from_catalog_row` — so the
-- catalog must record the variant. `openai_chatgpt = TRUE` is that flag: the
-- resolver maps it to `ResolvedRoute.openai_chatgpt`, which selects the Codex
-- fingerprint auth at dispatch.
--
-- Every existing row is non-Codex, so the `FALSE` default classifies them
-- correctly — no backfill.

ALTER TABLE llm_models
    ADD COLUMN openai_chatgpt BOOLEAN NOT NULL DEFAULT FALSE;
