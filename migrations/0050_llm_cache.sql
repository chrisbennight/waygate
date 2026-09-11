-- Phase 5 PR5-1a: per-principal exact-match completion cache.
--
-- An opt-in, exact-match response cache (design §9). The key is a BLAKE3 hash
-- over the canonical request PLUS the principal, so a cache entry is
-- per-principal scoped: one user's completion is NEVER served to another. That
-- isolation is structural — a cross-principal hit is impossible because the
-- principal is part of the key (the security invariant for this table).
--
-- Unlike the audit / usage ledgers (metadata only, invariant I9), the cache
-- DELIBERATELY stores response content — a hit must replay the completion. The
-- per-principal key is precisely what makes storing content safe.
--
-- TTL: `expires_at` bounds an entry's lifetime; a background sweep (PR5-1d,
-- reusing the audit-retention sweep pattern) deletes expired rows. Reads also
-- filter `expires_at > now()`, so an expired-but-not-yet-swept row is never
-- served.

CREATE TABLE llm_cache (
    -- BLAKE3 hex over (tenant, principal, canonical request) — see
    -- gateway_storage::llm_cache::cache_key. PK: an exact-match lookup.
    cache_key       TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    -- NULL for anonymous / auth-disabled calls. Part of the key's input, so a
    -- NULL-principal entry can only ever be re-served to another NULL-principal
    -- request (still scoped, never cross-user).
    principal_sub   TEXT,
    -- Client-facing model alias the entry was produced for (diagnostics only;
    -- the alias is already folded into `cache_key`).
    model_alias     TEXT NOT NULL,
    -- The upstream model that actually served the original call, replayed into
    -- the hit's `InferenceRecord.model_served`.
    model_served    TEXT,
    -- The cached client-facing response — the OpenAI chat-completions body the
    -- gateway returns. Content by design (a cache must replay it); the
    -- per-principal key keeps that safe.
    response_body   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

-- The TTL sweep (PR5-1d) and the read-time freshness filter both scan by expiry.
CREATE INDEX llm_cache_expires_at_idx ON llm_cache (expires_at);
