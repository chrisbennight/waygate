-- Phase 2 (Tier-A durable upstream sessions) — per-user, per-upstream
-- ciphertext store for the encrypted upstream token envelope.
--
-- Why this table exists (and not e.g. a column on `oauth_refresh_tokens`):
-- the existing `oauth_codes.upstream_tokens_ciphertext` column is wiped
-- by `take_code()` during the first `/oauth/token` exchange, so the
-- ciphertext only survives `code_ttl` (~60s). The gateway's Tier-A
-- identity-chaining path needs the ciphertext to last as long as the
-- user's session with the upstream IdP — naturally keyed by
-- (gateway sub, upstream issuer), not by the rotating gateway refresh
-- token. Refresh-on-demand updates the row in place; no rotation chain
-- (that's what `oauth_refresh_tokens` is for — different problem). A
-- separate table also makes multi-IdP support (Authentik + Google +
-- GitHub for different upstreams) a row, not a schema rewrite.
--
-- This migration adds the table and the index. The wiring that actually
-- writes / reads it ships in `gateway-as::sessions` (this PR) and the
-- Tier-A read path in `gateway-upstream::identity_client` (next slice).
-- The existing one-shot column on `oauth_codes` stays harmless for now;
-- it goes away once every consumer reads from this table.

CREATE TABLE user_upstream_sessions (
    -- Identity key: one row per (gateway sub, upstream issuer). The
    -- pair survives upstream refresh — that's the whole point — so the
    -- composite is the natural primary key.
    sub                 TEXT        NOT NULL,
    upstream_issuer     TEXT        NOT NULL,
    -- Encrypted envelope: { access_token, refresh_token?, id_token?,
    -- expires_in?, scope? } serialised then AES-256-GCM-encrypted with
    -- the active `GATEWAY_UPSTREAM_TOKEN_KEY_*`. Same shape as
    -- `oauth_codes.upstream_tokens_ciphertext`.
    tokens_ciphertext   BYTEA       NOT NULL,
    -- When the encrypted `access_token` itself expires (NOT when the
    -- ciphertext was written). The refresh-on-demand helper consults
    -- this to decide whether to spend a refresh token before handing
    -- the access token to an upstream call.
    access_expires_at   TIMESTAMPTZ NOT NULL,
    -- Last time the encrypted envelope was rewritten (initial UPSERT
    -- on /oauth/callback or a refresh-on-demand). Observability only —
    -- nothing keys off it.
    refreshed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sub, upstream_issuer)
);

-- Index supports the "sweep rows whose access token expired N days
-- ago" cleanup pattern. Not a hot-path read (the per-call lookup is
-- by primary key) — kept lean.
CREATE INDEX user_upstream_sessions_expires_idx
    ON user_upstream_sessions (access_expires_at);
