-- Phase 10 PR10-1b: interactive OAuth consent screen
-- pending-state table.
--
-- Adds `oauth_consent_pending` to hold the post-id-token
-- pre-consent state across the user's trip through the
-- `/oauth/consent` screen.
--
-- ## What
--
-- When the `GATEWAY_REQUIRE_EXPLICIT_CONSENT` flag is on
-- (a gateway-wide env var in PR10-1b; PR10-1c plans to
-- replace this with a per-tenant `tenants.require_explicit_consent`
-- column), the AS `/oauth/callback` refuses to mint a
-- gateway code until a covering `oauth_consent` row
-- exists for `(tenant_id, principal_sub, client_id)`.
-- The callback path 302s to `/oauth/consent?token=…`
-- so the user can approve; on approve, the grant lands
-- via the PR10-1a `ConsentStore` and the code mint
-- proceeds.
--
-- ## Why a separate table (not oauth_transactions)
--
-- `oauth_transactions` carries pre-authorize state
-- (PKCE verifier the AS will redeem upstream); rows
-- get DELETEd by `take_transaction` on the FIRST
-- callback hit. The new pending state is
-- POST-callback — different lifecycle, different
-- columns, deserves its own table.
--
-- ## Pending row lifecycle
--
-- - Created at `/oauth/callback` when the consent
--   screen is required. `token` is a random 32-byte
--   URL-safe identifier that also serves as the CSRF
--   token for the POST handler.
-- - `expires_at` is the OAuth code TTL plus a small
--   buffer (`code_ttl + 5min`) so the user has time
--   to click "approve" before the gateway-side code
--   mint would itself expire.
-- - On approve: DELETEd by token, carried state
--   becomes a fresh `oauth_codes` row, redirect to
--   client.
-- - On deny: DELETEd by token, redirect to client
--   with `error=access_denied` per RFC 6749 §4.1.2.1.
-- - On expiry: a periodic sweeper drops stale rows.
--   No security impact — an expired row's encrypted
--   tokens are no longer usable upstream anyway.
--
-- ## Why upstream_tokens_ciphertext on the row
--
-- Same `UpstreamCrypto` keyring + `key_id` shape that
-- `user_upstream_sessions` and
-- `oauth_codes.upstream_tokens_ciphertext` already use.
-- The pending row's `key_id` routes the decrypt at
-- approve time. New rows always write under the active
-- key.

CREATE TABLE oauth_consent_pending (
    token                         TEXT PRIMARY KEY,
    tenant_id                     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub                 TEXT NOT NULL,
    principal_email               TEXT,
    principal_groups              TEXT[] NOT NULL DEFAULT '{}',
    client_id                     TEXT NOT NULL,
    client_redirect_uri           TEXT NOT NULL,
    client_state                  TEXT,
    code_challenge                TEXT NOT NULL,
    scopes                        TEXT[] NOT NULL,
    upstream_tokens_ciphertext    BYTEA NOT NULL,
    key_id                        TEXT NOT NULL,
    -- AERB PR #178 round 1 medium (design-goal): carry
    -- the upstream IdP's `access_expires_at` (the value
    -- callback.rs derives from `token_resp.expires_in`)
    -- so the approve-path's Tier-A
    -- `user_upstream_sessions` write records the REAL
    -- upstream expiry — not a synthetic now()+1h.
    -- Without this column a 5-min upstream access token
    -- could be treated as fresh for the full hour after
    -- consent.
    access_expires_at             TIMESTAMPTZ NOT NULL,
    expires_at                    TIMESTAMPTZ NOT NULL,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sweep predicate: a periodic OAuth-state cleaner
-- walks `expires_at < now()` and DELETEs. Plain btree
-- index — Postgres can't do a partial index against
-- `now()` (it's volatile), so the index covers every
-- row. Cheap regardless since the table is small.
CREATE INDEX oauth_consent_pending_expires_at
    ON oauth_consent_pending (expires_at);
