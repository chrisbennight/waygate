-- OAuth 2.1 Authorization Server state.
--
-- The gateway fronts Authentik for MCP clients: clients hit the gateway's
-- /oauth/authorize and /oauth/token endpoints, the gateway drives the
-- upstream login server-side, then mints its own short-lived JWT for the
-- MCP session. These three tables persist the transient state of that
-- flow. All rows carry `expires_at` with an index; a periodic sweep
-- runs in `gateway-server` (see `run_sweeper` in `gateway-as::store`)
-- and deletes expired transactions, codes, and refresh tokens. Revoked-
-- but-unexpired refresh rows are kept deliberately — replay detection
-- in `/oauth/token` reads `revoked_at` to chain-revoke stolen tokens.

-- One row per in-flight /oauth/authorize request. Created when the gateway
-- redirects the browser to Authentik; consumed (deleted) by /oauth/callback
-- when Authentik returns. TTL ~15 minutes — longer than any realistic
-- interactive login, short enough that an abandoned login doesn't hang
-- around forever.
CREATE TABLE IF NOT EXISTS oauth_transactions (
    txn_id                    TEXT PRIMARY KEY,
    client_id                 TEXT NOT NULL,
    client_redirect_uri       TEXT NOT NULL,
    client_state              TEXT,
    code_challenge            TEXT NOT NULL,
    code_challenge_method     TEXT NOT NULL,
    scopes                    JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource                  TEXT,
    proxy_code_verifier       TEXT NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_transactions_expires_at_idx
    ON oauth_transactions (expires_at);

-- One row per gateway-minted authorization code. Created by /oauth/callback
-- after the upstream exchange succeeds; consumed (deleted) by /oauth/token.
-- TTL ~60 seconds — just long enough for the client to finish the PKCE
-- round-trip.
--
-- `upstream_tokens_ciphertext` holds the Authentik access + refresh tokens
-- encrypted with AES-256-GCM under GATEWAY_UPSTREAM_TOKEN_KEY. The nonce is
-- prefixed to the ciphertext. Needed later for Tier A identity chaining.
CREATE TABLE IF NOT EXISTS oauth_codes (
    code                         TEXT PRIMARY KEY,
    client_id                    TEXT NOT NULL,
    redirect_uri                 TEXT NOT NULL,
    code_challenge               TEXT NOT NULL,
    scopes                       JSONB NOT NULL DEFAULT '[]'::jsonb,
    sub                          TEXT NOT NULL,
    email                        TEXT,
    groups                       JSONB NOT NULL DEFAULT '[]'::jsonb,
    upstream_tokens_ciphertext   BYTEA,
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                   TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_codes_expires_at_idx
    ON oauth_codes (expires_at);

-- One row per live refresh token. Rotation: when a refresh succeeds we mint
-- a fresh row and set `revoked_at = now()` on the predecessor, linking via
-- `rotated_from`. A refresh that presents a revoked token is treated as
-- a replay attack — the whole chain is revoked.
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token          TEXT PRIMARY KEY,
    sub            TEXT NOT NULL,
    email          TEXT,
    groups         JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes         JSONB NOT NULL DEFAULT '[]'::jsonb,
    client_id      TEXT NOT NULL,
    rotated_from   TEXT REFERENCES oauth_refresh_tokens(token) ON DELETE SET NULL,
    issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expires_at_idx
    ON oauth_refresh_tokens (expires_at);

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_sub_idx
    ON oauth_refresh_tokens (sub);
