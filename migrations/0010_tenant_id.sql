-- Phase 3 PR2: add `tenant_id` to every tenant-scoped table.
--
-- Why: Phase 3 PR1 added `Principal.tenant` (gateway-core::TenantId)
-- but every storage row still belongs to the implicit single
-- "default" tenant. PR2 wires the column so every audit row,
-- API key, OAuth artifact, and durable upstream session carries
-- the tenant the principal acted under. Every future query
-- can then filter by tenant, every audit search can pivot by
-- tenant, and the Phase 8 SCIM/RBAC machinery has a stable
-- substrate to enforce isolation on.
--
-- All columns use `NOT NULL DEFAULT 'default'` so the migration
-- is online-safe: existing rows backfill atomically to the
-- `TenantId::DEFAULT` sentinel that single-tenant deployments
-- already use. PR1's `TenantId::DEFAULT = "default"` constant
-- matches the literal here, so the storage layer never has to
-- branch on "is this row pre-PR2?" — every row has a tenant.
--
-- Indexes target the operator-facing query shapes:
--
-- * `audit_log (tenant_id, ts DESC)` — the admin audit endpoint
--   pages by recency; per-tenant browsing needs to land in the
--   right column without a sequential scan once multi-tenant
--   deployments exist.
-- * `api_keys (tenant_id, key_prefix) WHERE revoked_at IS NULL`
--   — the validator's hot-path lookup is by key_prefix, and
--   tenant scoping turns it into a single-row narrow index hit
--   even when two tenants happen to mint the same prefix
--   (4 bytes; birthday-low). Replaces the existing partial
--   unique index on key_prefix alone.
-- * `oauth_refresh_tokens (tenant_id, sub)` — the dashboard
--   sessions view groups by (sub, tenant_id); a per-tenant
--   index keeps it cheap as the table grows.
-- * `user_upstream_sessions` primary key stays
--   `(sub, upstream_issuer)` rather than gaining tenant_id —
--   a given (sub, upstream_issuer) pair is unique across the
--   whole gateway since `sub` already carries the IdP-issued
--   user identity. The tenant_id column is informational
--   (operator visibility) until the Phase 8 multi-tenant
--   IdP work introduces a need for per-tenant subs.

ALTER TABLE audit_log              ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE oauth_transactions     ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE oauth_codes            ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE oauth_refresh_tokens   ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE api_keys               ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE api_key_usage          ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE user_upstream_sessions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX audit_log_tenant_ts_idx
    ON audit_log (tenant_id, ts DESC);

-- Replace the existing pre-PR2 non-unique partial index on
-- key_prefix with a (key_prefix, tenant_id) index. Column
-- order is deliberate: the validator's current hot-path SQL
-- filters by key_prefix only (the request doesn't yet carry
-- a tenant context — that lands in Phase 8 SCIM/RBAC).
-- Prefix-first keeps that lookup a cheap index hit. A future
-- Phase 8 query that filters by BOTH still uses the same
-- index. The previous index was NOT unique (a 4-byte prefix
-- has a realistic birthday collision risk; the validator
-- iterates matching rows and hash-verifies each), so this
-- one stays non-unique too.
DROP INDEX IF EXISTS api_keys_key_prefix_live_idx;
CREATE INDEX api_keys_prefix_tenant_live_idx
    ON api_keys (key_prefix, tenant_id)
 WHERE revoked_at IS NULL;

CREATE INDEX oauth_refresh_tokens_tenant_sub_idx
    ON oauth_refresh_tokens (tenant_id, sub);
