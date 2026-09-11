-- Phase 3 PR3-3a-ii: per-call inference usage records.
--
-- One append-only row per completed LLM invocation, written at the
-- pipeline's record_outcome stage (stage 11) from the call's
-- `InferenceRecord`. This is the metadata-only usage ledger the rest
-- of Phase 3 reads:
--
--   - PR3-3b's lagging token budgets SUM a principal's recent token
--     columns to decide "already exhausted" (I3 — no estimation, the
--     gate reads *recorded* usage).
--   - PR3-3a-iii fills the cost columns (rate x tokens from the
--     llm_models catalog); they are nullable and unset until then.
--   - Phase 3.4 analytics / OTel and the activity feed read it.
--
-- Invariant I9 — metadata, NOT content: this table stores token
-- counts, the served model, finish reason, latency, and (later) cost.
-- It never stores prompts or completions.
--
-- Append-only by application contract (no UPDATE/DELETE in the hot
-- path); retention/rollup is a later concern. `id` is a
-- caller-assigned UUIDv7 (time-ordered) rather than a DB default, so
-- no pgcrypto/uuid-ossp extension is required (matches the rest of the
-- schema, which supplies UUIDs from the app).

CREATE TABLE llm_usage (
    id                  UUID PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- identity, for budget attribution (PR3-3b) + audit correlation.
    -- principal_sub is NULL for anonymous / auth-disabled calls.
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    principal_sub       TEXT,
    -- routing identity: the client-facing alias and the resolved
    -- provider; model_served is what the upstream actually ran (may
    -- differ from the alias — aliasing/fallback), NULL if not reported.
    model_alias         TEXT NOT NULL,
    provider            TEXT NOT NULL,
    model_served        TEXT,
    inbound_surface     TEXT NOT NULL,
    -- token counts. NULL = the provider did not report that class
    -- (distinct from a reported zero — load-bearing for budgets).
    input_tokens        BIGINT,
    output_tokens       BIGINT,
    cached_read_tokens  BIGINT,
    cache_write_tokens  BIGINT,
    reasoning_tokens    BIGINT,
    -- outcome
    finish_reason       TEXT,
    refusal             BOOLEAN NOT NULL DEFAULT FALSE,
    latency_ms          BIGINT,
    -- cost (PR3-3a-iii populates from the catalog; NULL until then).
    -- cost_source ∈ provider_reported | computed_from_catalog | unknown.
    input_cost          NUMERIC,
    output_cost         NUMERIC,
    total_cost          NUMERIC,
    cost_source         TEXT,
    -- Counts and money are non-negative when present (a negative would
    -- corrupt a budget SUM). Mirrors the llm_models cost CHECK.
    CONSTRAINT llm_usage_nonnegative CHECK (
        (input_tokens       IS NULL OR input_tokens       >= 0) AND
        (output_tokens      IS NULL OR output_tokens      >= 0) AND
        (cached_read_tokens IS NULL OR cached_read_tokens >= 0) AND
        (cache_write_tokens IS NULL OR cache_write_tokens >= 0) AND
        (reasoning_tokens   IS NULL OR reasoning_tokens   >= 0) AND
        (latency_ms         IS NULL OR latency_ms         >= 0) AND
        (input_cost         IS NULL OR input_cost         >= 0) AND
        (output_cost        IS NULL OR output_cost        >= 0) AND
        (total_cost         IS NULL OR total_cost         >= 0)
    )
);

-- Budget queries (PR3-3b) sum a principal's recent usage in a window.
CREATE INDEX llm_usage_tenant_principal_ts_idx
    ON llm_usage (tenant_id, principal_sub, ts DESC);

-- Per-model analytics / cost rollups (Phase 3.4).
CREATE INDEX llm_usage_tenant_model_ts_idx
    ON llm_usage (tenant_id, model_alias, ts DESC);
