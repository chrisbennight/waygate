-- Static API keys — long-lived bearers the gateway validates alongside
-- OAuth-issued JWTs. Used by headless callers (Codex, CI jobs, scripts)
-- that can't drive an interactive OAuth flow.
--
-- Storage shape:
-- * `key_prefix` is the first 8 chars after the `mcpgw_` literal — indexed
--   so the validator can do a single O(log n) lookup and then run an
--   Argon2id `verify` against `key_hash`. The full secret is never stored.
-- * `key_hash` is the argon2id `$argon2id$…` PHC string.
-- * `expires_at` is nullable. NULL = never expires (operator's choice;
--   this gateway intentionally has no enforced ceiling — see
--   `docs/agents/identity.md`).
-- * `revoked_at` is set immediately when the dashboard revokes a key.
--   The validator's cache (default 60s TTL) bounds the propagation lag.
--
-- Sweep policy lives in code (gateway-apikeys::store): only revoked-or-expired
-- rows older than 90 days are deleted, so audit history survives a while.
CREATE TABLE IF NOT EXISTS api_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_prefix    TEXT NOT NULL,
    key_hash      TEXT NOT NULL,
    name          TEXT NOT NULL,
    sub           TEXT NOT NULL,
    email         TEXT,
    groups        JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes        JSONB NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

-- Partial index: live keys only. The validator hot path always filters
-- `revoked_at IS NULL`, so excluding revoked rows keeps the index tight
-- even after years of rotated-out keys.
CREATE INDEX IF NOT EXISTS api_keys_key_prefix_live_idx
    ON api_keys (key_prefix) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS api_keys_expires_at_idx
    ON api_keys (expires_at) WHERE expires_at IS NOT NULL;

-- Hourly usage rollup. Validator bumps the current hour's bucket on each
-- successful authentication so the dashboard can draw a sparkline without
-- scanning a per-request table. Coalesced upserts (`ON CONFLICT … DO UPDATE`)
-- keep contention low even under burst load.
CREATE TABLE IF NOT EXISTS api_key_usage (
    api_key_id    UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    bucket_start  TIMESTAMPTZ NOT NULL,
    request_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (api_key_id, bucket_start)
);

CREATE INDEX IF NOT EXISTS api_key_usage_bucket_start_idx
    ON api_key_usage (bucket_start);
