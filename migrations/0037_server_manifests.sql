-- PR-S1: durable, versioned upstream-manifest bundles.
--
-- Today the upstream MCP server set lives in `servers/*.yaml` on disk:
-- the gateway loads it at boot, hot-reloads it on SIGHUP, and a broken
-- file fails the load loud. The distroless image is read-only, so an
-- operator can't edit `servers/` in place. This table is the DB overlay
-- that lets the whole manifest set be versioned, drafted, and published
-- — an exact mirror of 0012_policy.sql, minus its policy-only `tests`
-- column.
--
-- A bundle's `content` is the FULL manifest set serialized as ONE YAML
-- document (a YAML sequence of UpstreamManifest), not one row per
-- server: the pool is built from the set as a unit, so versioning the
-- set as a whole is what makes rollback atomic and `content_hash`
-- meaningful. Servers are GLOBAL today (the pool is gateway-wide), so
-- the table keys on tenant_id='default' for forward-compat and boot
-- reads the default-tenant bundle.
--
-- Nothing forces a row to exist: boot dual-reads (active bundle if
-- present, else the `servers/` YAML dir), preserving the no-lockout
-- invariant when no DB is configured, the tenant has no published
-- bundle, the store read errors, or the active bundle does not parse.
-- (A configured-but-unreachable DB aborts earlier, in the shared
-- audit-sink connect, exactly as it did before this overlay existed —
-- the manifest fallback covers store-level misses/errors, not a dead
-- connection.) A later slice (PR-S2/S3) adds the admin REST + UI; PR-S1
-- lands the table + store + dual-read boot/SIGHUP + the
-- `--import-server-bundle` seed.

CREATE TABLE server_manifests (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    -- Monotonic per tenant. UNIQUE(tenant_id, version) backstops
    -- concurrent create_draft races (one commits, the other retries on
    -- the unique violation); versions are never reused, so history is
    -- append-only.
    version      INT NOT NULL,
    -- draft       ⇒ staged, not yet built into the pool.
    -- published   ⇒ eligible to be the active bundle. The MOST RECENTLY
    --               PUBLISHED bundle wins (ORDER BY published_at DESC),
    --               so a rollback that re-publishes older content takes
    --               effect immediately. version is a monotonic identity
    --               counter, not the active-selection key.
    -- rolled_back ⇒ was published, later superseded. Audit trail only.
    status       TEXT NOT NULL
                 CHECK (status IN ('draft','published','rolled_back')),
    -- Full manifest-set source: a YAML sequence of UpstreamManifest.
    content      TEXT NOT NULL,
    -- sha256(content) hex. Lets the loader skip a pool rebuild when the
    -- active bundle's hash is unchanged, and gives the admin UI (S2/S3)
    -- a stable identifier alongside the version.
    content_hash TEXT NOT NULL,
    author       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    published_by TEXT,
    UNIQUE (tenant_id, version),
    -- A draft has never been published (published_at IS NULL); any
    -- non-draft row carries a timestamp. Keeps the active-bundle lookup
    -- safe under ORDER BY published_at DESC and stops a seed publishing
    -- a published bundle without a timestamp.
    CHECK (
        (status =  'draft' AND published_at IS NULL) OR
        (status <> 'draft' AND published_at IS NOT NULL)
    )
);

-- Active-bundle lookup hot path: newest published bundle per tenant.
CREATE INDEX server_manifests_active
    ON server_manifests (tenant_id, published_at DESC)
    WHERE status = 'published';
