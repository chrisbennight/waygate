-- Phase 11 PR11-1a: federated gateway peer storage.
--
-- ## What
--
-- New `federated_peers` table holding the operator-approved
-- list of remote MCP gateways this gateway will federate
-- with (Tier-C identity chaining — gateway-to-gateway
-- assertions). A peer row pins:
--
-- - the peer's stable id (`peer_name`, operator-friendly)
-- - the peer's OIDC `issuer` claim (token validation)
-- - the peer's JWKS endpoint URL (key material for
--   verifying signed peer assertions)
-- - a `trust_tier` enum that future runtime code uses to
--   pick between "full" (peer's identity propagates as-is)
--   vs "restricted" (peer's identity wraps under this
--   gateway's tenant scope)
--
-- ## Why PR11-1a is admin-CRUD-only
--
-- The runtime federation handshake — JWKS fetch + cache,
-- peer-assertion verification, per-upstream
-- `tier_c_peer:<id>` identity selection — lands in
-- PR11-1b+. Shipping the peer registry + admin REST
-- first means:
--
-- 1. Operators can enroll peers ahead of the runtime
--    flip.
-- 2. Rows in this table are inert at the dispatch layer
--    until the consumer ships — same shape as PR9-c5's
--    inspection_rules.
--
-- ## Shape
--
-- - `id` UUID surrogate so the admin REST + future
--   per-upstream config can address a peer without
--   quoting the composite key.
-- - `tenant_id` FKs `tenants(id) ON DELETE CASCADE` —
--   peers are tenant-scoped (a tenant operator enrolls
--   peers their tenant trusts; cross-tenant trust is a
--   separate design question for later). Same cascade
--   pattern as oauth_consent / break_glass_tokens /
--   task_states / inspection_rules.
-- - `peer_name` is the operator-friendly label
--   (`"acme-prod-gateway"`). UNIQUE per tenant so an
--   admin UI table never shows two rows with the same
--   identifier.
-- - `issuer` is the peer's OIDC `iss` claim. Must be an
--   absolute URL (the runtime JWT validator pivots on
--   it). UNIQUE per tenant — a single peer should have a
--   single canonical issuer; alias support, if ever
--   wanted, comes via a separate join table.
-- - `jwks_url` is where this gateway fetches the peer's
--   signing keys. HTTPS-only check is enforced at the
--   runtime layer (PR11-1b) where the fetcher lives;
--   storage stays opaque to keep CIDR / proxy / local-
--   dev shapes accessible.
-- - `trust_tier` is a closed enum (`full` / `restricted`)
--   — the runtime uses it to choose between "propagate
--   peer's principal" vs "wrap in this gateway's tenant
--   scope". CHECK constraint locks the set.
-- - `created_at`, `updated_at` for audit trail. Trigger
--   bumps `updated_at` on every UPDATE — same shape as
--   `inspection_rules_touch_updated_at_trg`.
--
-- ## Indexes
--
-- - `(tenant_id, peer_name)` UNIQUE — admin UI / lookup
--   by friendly id.
-- - `(tenant_id, issuer)` UNIQUE — runtime JWT validator
--   pivots on `(tenant, iss)` to find the matching peer
--   row for assertion verification.

CREATE TABLE federated_peers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    peer_name     TEXT NOT NULL,
    issuer        TEXT NOT NULL,
    jwks_url      TEXT NOT NULL,
    trust_tier    TEXT NOT NULL
                  CHECK (trust_tier IN ('full', 'restricted')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, peer_name),
    UNIQUE (tenant_id, issuer)
);

-- updated_at auto-bump (same shape as
-- tenants.touch_updated_at and
-- inspection_rules_touch_updated_at_trg from PR9-c5).
CREATE OR REPLACE FUNCTION federated_peers_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER federated_peers_touch_updated_at_trg
    BEFORE UPDATE ON federated_peers
    FOR EACH ROW
    EXECUTE FUNCTION federated_peers_touch_updated_at();
