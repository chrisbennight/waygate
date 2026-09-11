-- Phase 3 PR3-3b: per-principal LLM token/cost budgets (lagging enforcement).
--
-- Formalizes invariant I3 — "lagging budgets, bounded overrun". A budget caps
-- a principal's (or a tenant's) LLM consumption over a rolling window. The
-- check_quota stage of the LLM path reads RECORDED usage (the llm_usage ledger
-- from PR3-3a) and rejects the NEXT call iff the principal is ALREADY at/over a
-- limit — no estimation of the in-flight call. That makes the gate cheap and
-- exact at the cost of at most a ~1-request overrun for calls that COMPLETE
-- (the call that crosses the threshold finishes and is ledgered; the one after
-- it is refused).
--
-- Scope of the bound (important). The ledger advances only when a call's usage
-- is recorded: at unary collection, or at a stream's `[DONE]`. For OpenAI-chat
-- streaming — the v1 protocol — the provider reports usage ONLY in the terminal
-- frame, so a client that streams deltas and disconnects BEFORE `[DONE]`
-- consumes tokens the gateway cannot observe (the count does not exist on the
-- wire until completion, and fabricating one is disallowed — the usage
-- aggregator never invents counts). The token ledger therefore does NOT bound
-- that abandoned-stream path; the complementary control is the request-rate
-- quota (the stage-6 token-bucket QuotaService), which caps how frequently such
-- calls can be started. So: the token/cost ledger bounds completed-call
-- overrun to ~1 request; request-rate quota bounds abandoned-stream abuse.
--
-- A budget row is a scoped limit:
--   - tenant_id: always set.
--   - principal_sub: NULL ⇒ tenant-wide (applies to every principal);
--     set ⇒ applies only to that principal.
--   - model_alias: NULL ⇒ all models; set ⇒ only that alias.
-- A call is governed by every enabled row whose scope matches it; if ANY
-- matching row is exhausted, the call is refused. (Most-specific-wins is not
-- needed — overlapping budgets compose as "all must pass", the safe default.)
--
-- Window: `window_seconds` defines a ROLLING window — the gate sums llm_usage
-- with `ts >= now() - window_seconds`. Calendar windows (daily/monthly aligned
-- to a boundary) are a later refinement; a rolling window is the simplest model
-- that enforces I3 and is what the acceptance test exercises.
--
-- Limits are OPTIONAL per dimension (both nullable): a row can cap tokens, or
-- cost, or both. A NULL dimension is not enforced. At least one must be set for
-- the row to do anything (CHECK).

CREATE TABLE llm_budgets (
    id               UUID PRIMARY KEY,
    tenant_id        TEXT NOT NULL DEFAULT 'default',
    -- NULL = tenant-wide; set = this principal only.
    principal_sub    TEXT,
    -- NULL = all models; set = this alias only.
    model_alias      TEXT,
    -- Rolling window width in seconds (e.g. 86400 = last 24h).
    window_seconds   BIGINT NOT NULL CHECK (window_seconds > 0),
    -- Optional caps. total tokens = input + output (the billable sum).
    max_total_tokens BIGINT  CHECK (max_total_tokens IS NULL OR max_total_tokens >= 0),
    max_total_cost   NUMERIC CHECK (max_total_cost   IS NULL OR max_total_cost   >= 0),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A budget with no cap enforces nothing — reject the misconfiguration.
    CONSTRAINT llm_budgets_has_a_limit CHECK (
        max_total_tokens IS NOT NULL OR max_total_cost IS NOT NULL
    )
);

-- The gate looks up a tenant's enabled budgets and filters by scope in-app.
CREATE INDEX llm_budgets_tenant_enabled_idx
    ON llm_budgets (tenant_id)
 WHERE enabled;

-- Prevent duplicate rows for the same scope (NULLs included): one budget per
-- (tenant, principal_sub, model_alias). NULLS NOT DISTINCT treats two NULL
-- scopes as equal so a second tenant-wide / all-models row conflicts rather
-- than silently double-counting.
CREATE UNIQUE INDEX llm_budgets_scope_uniq
    ON llm_budgets (tenant_id, principal_sub, model_alias) NULLS NOT DISTINCT;
