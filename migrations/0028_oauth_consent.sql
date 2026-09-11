-- Phase 10 PR10-1a: OAuth consent grant persistence.
--
-- ## What
--
-- New `oauth_consent` table. One row per
-- `(tenant_id, principal_sub, client_id)` tuple recording
-- that the named CIMD client has been authorized to act
-- on behalf of the user with a particular scope set.
-- Recorded at `/oauth/callback` completion: right after the
-- upstream IdP proves the user's identity (id_token
-- signature + iss + aud validated) and right before the
-- gateway mints its own authorization code into
-- `oauth_codes`.
--
-- ## Why
--
-- Confused-deputy mitigation per OAuth 2.1 §10.4. The
-- gateway brokers tokens for multiple downstream clients
-- against a single upstream IdP, so without a per-client
-- consent record there's nothing distinguishing "user
-- approved client A and got token B" from "client C
-- replayed user B's token because the upstream IdP doesn't
-- distinguish downstream clients." This row is also the
-- audit trail SOC2 reviewers expect: "what clients does
-- user X have active grants to?" answered by a single
-- table scan, and the kill switch an admin uses when a
-- user reports a suspicious client.
--
-- PR10-1a (this PR) lands the data layer + admin REST.
-- Today the row is recorded post-authentication as an
-- AUDIT FACT — the callback path UPSERTs unconditionally
-- so revocation + scope-update both flow through the same
-- write. PR10-1b will layer an INTERACTIVE consent screen
-- + per-tenant `require_explicit_consent` flag on top: the
-- same row becomes the lookup the gate consults ("does
-- this user already have a grant covering this client +
-- scopes?"), and absence triggers the consent UI before
-- the code-mint write. Splitting that way keeps this PR
-- small, lets the audit trail land immediately, and means
-- the screen+gate PR doesn't have to also introduce the
-- schema + admin surface in the same diff.
--
-- ## Shape
--
-- - `id` is a UUID surrogate so revoke endpoints can
--   reference a single row without quoting the composite
--   key in the URL path (and so future audit rows can FK
--   the specific grant they came from if needed).
-- - `tenant_id` FKs `tenants(id)` with ON DELETE CASCADE.
--   When a tenant is hard-deleted the grants go with it,
--   matching the cascade pattern PR8-f established for
--   `api_keys`, `rate_limit_policies`, etc.
-- - `principal_sub` mirrors `Principal.sub` (the upstream
--   IdP's `sub` claim). NOT a FK to `scim_users` because
--   not every authenticated principal has a SCIM row —
--   SCIM provisioning is optional, and unprovisioned users
--   still need consent records.
-- - `client_id` is the CIMD client URL (per
--   `crates/gateway-as/src/cimd.rs::is_cimd_client_id`).
--   Not normalized to a separate `clients` table — CIMD
--   client identity is the URL itself; there's no separate
--   registration row.
-- - `scopes` is TEXT[]. A grant captures the scope set
--   the gateway asked the upstream for, mirroring
--   `oauth_codes.scopes` / `oauth_refresh_tokens.scopes`
--   shape.
-- - `granted_at` defaults to `now()`. UPSERTs (re-consent
--   with broader scopes) bump it via the ON CONFLICT
--   branch so an operator can see "last touched."
-- - `expires_at` is nullable. NULL means "no expiry; lives
--   until revoked." PR10-1b may grow per-tenant
--   max-grant-ttl that populates this on upsert.
-- - `revoked_at` is the soft-delete column the admin
--   revoke endpoint sets. Soft rather than hard so an audit
--   reader can answer "did this user ever consent to this
--   client?" even after revocation; the gate (PR10-1b)
--   treats `revoked_at IS NOT NULL` as "no covering grant."
--
-- ## Uniqueness + lookup
--
-- The composite `UNIQUE (tenant_id, principal_sub,
-- client_id)` lets the callback `INSERT ... ON CONFLICT
-- DO UPDATE` instead of read-then-write; that's the same
-- race-free pattern the rest of the AS uses
-- (`user_upstream_sessions`, `oauth_refresh_tokens`).
--
-- The partial index on `(tenant_id, principal_sub)` WHERE
-- `revoked_at IS NULL` is the only hot-path lookup
-- PR10-1b needs ("does this user have any non-revoked
-- grants?"). The composite UNIQUE already covers
-- "lookup by full triple," so no separate index for that.

CREATE TABLE oauth_consent (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    scopes        TEXT[] NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    UNIQUE (tenant_id, principal_sub, client_id)
);

CREATE INDEX oauth_consent_active_by_principal
    ON oauth_consent (tenant_id, principal_sub)
    WHERE revoked_at IS NULL;
