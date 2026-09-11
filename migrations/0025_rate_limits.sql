-- Phase 9 PR9-a: per-tenant token-bucket rate limiting.
--
-- Two-table model:
--
--   rate_limit_policies — operator-authored declarations of "for
--   THIS scope (e.g. principal=$sub), THIS action class (e.g.
--   high_risk_call), refill at $rate tokens/sec capped at $capacity".
--
--   rate_limit_counters — per-(policy, scope_value) bucket state.
--   Created lazily on the first call that matches a policy; reused
--   thereafter. The token-bucket calculation runs in a single
--   atomic conditional UPDATE so two concurrent dispatches can't
--   double-spend a token.
--
-- ## Scope dimension
--
-- `scope` answers "what does scope_value identify?":
--
--   tenant     — `scope_value` is the tenant_id. Limits the
--                tenant en bloc regardless of which principal called.
--                Use this to bound the noisy-neighbor blast radius.
--   principal  — `scope_value` is the principal's `sub`. Per-user
--                rate-limit, scoped to the policy's tenant.
--   client     — `scope_value` is the OAuth client_id (or
--                api-key-derived synthetic). Lets operators bound
--                a single integration without limiting humans.
--   server     — `scope_value` is the upstream MCP server name.
--                Useful when a specific upstream is fragile.
--   tool       — `scope_value` is `<server>.<tool>`. Finest-grained
--                control, e.g. limit just `email.send`.
--
-- A request can match multiple policies; the gate enforces the
-- MOST RESTRICTIVE one that matches (first denial wins) so
-- operators can layer broad + targeted limits without the
-- narrowest one "winning" by accident.
--
-- ## Action dimension
--
-- `action` matches against the resolved tool's facts at gate time:
--
--   call             — every tool call. Default for blanket
--                       per-tenant or per-principal limits.
--   high_risk_call   — tools with risk_tier ∈ {high, critical}.
--                       For cost or compliance hot-paths.
--   cost_bearing     — tools where `cost_class` is non-null.
--                       Operator-defined "expensive" hint.
--   discovery        — tools/list + tools/search hits. Separate
--                       bucket so a chatty client's discovery
--                       traffic can't starve real call traffic.
--
-- The action match is INCLUSIVE: a `call`-scope policy fires on
-- every dispatch including high-risk ones (a high_risk_call
-- policy is in ADDITION to, not in place of, a call policy).
--
-- ## Counters
--
-- `tokens_remaining` is NUMERIC (not INT) because the refill
-- math accumulates fractional tokens between calls
-- (`tokens += elapsed_seconds * refill_per_second`). Capacity
-- bounds the result so a long idle period doesn't let a burst
-- build past the operator's intent. The atomic UPDATE pattern
-- the storage layer uses is:
--
--   UPDATE rate_limit_counters SET
--     tokens_remaining = LEAST(
--       capacity,
--       tokens_remaining + EXTRACT(EPOCH FROM (now() - last_refill)) * refill_per_second
--     ) - 1,
--     last_refill = now()
--   WHERE policy_id = $1 AND scope_value = $2
--     AND tokens_remaining >= 1
--     OR  tokens_remaining + EXTRACT(EPOCH FROM (now() - last_refill)) * refill_per_second >= 1
--   RETURNING tokens_remaining;
--
-- Zero rows-affected ⇒ deny. The integer 1 is the per-call cost
-- (always 1 today; the plan leaves room for per-tool weights).
--
-- ## What's NOT here (deferred follow-ups)
--
-- - Admin REST CRUD on `rate_limit_policies` — lands as PR9-a2
--   (same surface shape as PR8-d2 RBAC). For now operators seed
--   via SQL or via a future onboarding side-effect.
-- - Distributed counter sync — the bucket is purely DB-backed,
--   so single-instance and multi-instance deployments behave
--   identically. The plan's optional "in-process cache with
--   periodic sync" is a future optimisation only worth wiring
--   when the DB round-trip becomes a hot-path issue.
-- - Tenant DELETE cleanup of orphan policies/counters — lands
--   alongside the admin CRUD in PR9-a2 (matches the cleanup
--   pattern PR8-f established for rbac + policy_bundles).

CREATE TABLE rate_limit_policies (
    id                UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    -- Human-friendly label so operators can identify policies in
    -- admin lists without parsing the (scope, scope_value) tuple.
    name              TEXT NOT NULL,
    scope             TEXT NOT NULL
                      CHECK (scope IN ('tenant', 'principal', 'client', 'server', 'tool')),
    -- NULL when `scope = 'tenant'` because the policy's own
    -- `tenant_id` column already identifies the bucket key — a
    -- separate `scope_value` would just be a duplicate of
    -- `tenant_id`. For the other four scopes this MUST be set;
    -- enforced by the CHECK below.
    scope_value       TEXT,
    bucket_capacity   INT NOT NULL CHECK (bucket_capacity > 0),
    -- DOUBLE PRECISION not NUMERIC: f64 precision is plenty
    -- for refill rates (typical: 1 → 100 tokens/sec) and lets
    -- the workspace avoid the sqlx bigdecimal feature for a
    -- single column. NUMERIC would only matter for arbitrary-
    -- precision audit math, not for token bucket throughput.
    refill_per_second DOUBLE PRECISION NOT NULL CHECK (refill_per_second > 0),
    action            TEXT NOT NULL
                      CHECK (action IN ('call', 'high_risk_call', 'cost_bearing', 'discovery')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Two-state constraint: scope='tenant' ⇒ scope_value NULL;
    -- everything else ⇒ scope_value NOT NULL. Keeps the
    -- gate's bucket-key computation a single CASE rather than
    -- a hash of optional fields.
    CONSTRAINT rate_limit_policies_scope_value_shape
        CHECK ((scope = 'tenant' AND scope_value IS NULL)
            OR (scope <> 'tenant' AND scope_value IS NOT NULL)),
    -- Uniqueness so an operator can't accidentally create two
    -- identical (scope, action) policies fighting each other on
    -- the same bucket key. The COALESCE-on-scope_value lives in
    -- a separate unique INDEX below because table-level UNIQUE
    -- constraints in Postgres can't reference expressions.
    CONSTRAINT rate_limit_policies_nonneg_capacity CHECK (bucket_capacity > 0)
);

-- COALESCE flattens the optional scope_value into the index
-- key so the NULL case for scope='tenant' is treated as a
-- single value (Postgres's default "two NULLs are distinct"
-- would let the operator accidentally insert duplicates).
CREATE UNIQUE INDEX rate_limit_policies_scope_unique
    ON rate_limit_policies (tenant_id, scope, COALESCE(scope_value, ''), action);

CREATE INDEX rate_limit_policies_action_idx
    ON rate_limit_policies (tenant_id, action);

CREATE TABLE rate_limit_counters (
    policy_id        UUID NOT NULL REFERENCES rate_limit_policies(id) ON DELETE CASCADE,
    -- Bucket key. For `scope='tenant'` this is the tenant_id
    -- (denormalised from the parent policy so the counter row
    -- is self-contained). For the other four scopes it's the
    -- principal sub / client_id / server name / fq_tool_name.
    scope_value      TEXT NOT NULL,
    -- DOUBLE PRECISION; see refill_per_second rationale on the
    -- parent policy table.
    tokens_remaining DOUBLE PRECISION NOT NULL,
    last_refill      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, scope_value)
);

-- Touch trigger for updated_at on policies. Counters
-- intentionally don't have one — `last_refill` already records
-- the wall-clock anchor of the most recent token math.
CREATE OR REPLACE FUNCTION rate_limit_policies_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER rate_limit_policies_touch_updated_at_trg
    BEFORE UPDATE ON rate_limit_policies
    FOR EACH ROW
    EXECUTE FUNCTION rate_limit_policies_touch_updated_at();
