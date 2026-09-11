-- Phase 4 PR4b-1: durable policy bundles.
--
-- Today the Cedar authorization policies live in `policies/*.cedar`
-- on disk: the gateway loads them at boot, reloads on SIGHUP, and a
-- broken file is logged-and-skipped so a typo can't lock the operator
-- out. That works for a single-operator, single-tenant deployment,
-- but it doesn't survive the Phase 4-8 work:
--
-- - No version history (the active policy is whatever the files
--   currently say; rollback is "git revert + redeploy + SIGHUP").
-- - No draft/publish workflow (every edit to the files is live the
--   moment SIGHUP fires; no staging, no two-person review trail).
-- - No per-tenant overlays (Phase 8 tenant-scoped policy composition
--   has nowhere to land).
--
-- This migration lays the schema, mirroring 0011_catalog. Nothing in
-- the running code reads `policy_bundles` yet: PR4b-1 (this slice)
-- lands the table + the `PolicyStore` trait + `PgPolicyStore`; a later
-- slice imports the on-disk `policies/*.cedar` into a v1 bundle and
-- swaps `ReloadableCedar` to load `active_bundle()` instead of the
-- filesystem, retiring the SIGHUP reload path.
--
-- A bundle's `content` is the full Cedar source (the concatenation of
-- the policy set), not one row per policy: Cedar evaluates a policy
-- *set* as a unit, and versioning the set as a whole is what makes
-- rollback atomic and a `content_hash` meaningful.

CREATE TABLE policy_bundles (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    -- Monotonic per tenant. `UNIQUE (tenant_id, version)` is the
    -- integrity backstop for concurrent draft creation: two racing
    -- `create_draft` calls that compute the same next-version both try
    -- to insert it; one commits, the other gets a unique violation and
    -- retries. Versions are never reused, so history is append-only.
    version      INT NOT NULL,
    -- draft     ⇒ staged, not yet evaluated by the gate.
    -- published ⇒ eligible to be the tenant's active bundle. The
    --             MOST RECENTLY PUBLISHED bundle wins (ORDER BY
    --             published_at DESC), not the highest version number:
    --             "publish makes it live" is the operator model, and
    --             it lets a rollback re-publish an older version's
    --             content and have it take effect immediately. Version
    --             is a monotonic identity/history counter, not the
    --             active-selection key. `version DESC` only breaks ties
    --             between rows published in the same instant. See the
    --             partial index below.
    -- rolled_back ⇒ was published, later superseded. Kept for the
    --             audit trail, never re-activated.
    status       TEXT NOT NULL
                 CHECK (status IN ('draft','published','rolled_back')),
    -- Full Cedar policy-set source for this version.
    content      TEXT NOT NULL,
    -- sha256(content) hex. Lets the loader skip a recompile when the
    -- active bundle's hash is unchanged, and gives the admin UI a
    -- stable identifier to show alongside the version.
    content_hash TEXT NOT NULL,
    -- Optional simulation cases ({principal, action, resource,
    -- expected_verdict}[]) carried with the bundle so a publish can be
    -- gated on them passing. Evaluated by a later slice once the gate
    -- can run Cedar against a candidate bundle; stored here now so the
    -- shape is stable.
    tests        JSONB,
    author       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    published_by TEXT,
    UNIQUE (tenant_id, version),
    -- Enforce the published_at invariant at the DB level: a draft has
    -- never been published (published_at IS NULL); any non-draft row
    -- (published / rolled_back) was published and therefore carries a
    -- timestamp. This makes the active-bundle lookup safe — a
    -- `published` row can't have a NULL published_at that would sort
    -- ahead of real ones under `ORDER BY published_at DESC` — and stops
    -- a future --import-policies seeding a published bundle without a
    -- timestamp (AERB PR #101).
    CHECK (
        (status =  'draft' AND published_at IS NULL) OR
        (status <> 'draft' AND published_at IS NOT NULL)
    )
);

-- The active-bundle lookup is the hot path: "newest published bundle
-- for this tenant". Partial index keyed on the published rows only,
-- ordered so `ORDER BY published_at DESC LIMIT 1` is an index scan.
CREATE INDEX policy_bundles_active
    ON policy_bundles (tenant_id, published_at DESC)
    WHERE status = 'published';
