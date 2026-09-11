-- Phase 4 PR4a-1: governed catalog tables.
--
-- Today the upstream catalog lives in `servers/*.yaml` on disk:
-- the gateway loads them at boot, reloads on SIGHUP, and serves
-- the parsed structs through `UpstreamPool::tool_facts()` /
-- `UpstreamCatalog`. That works for a single-operator, single-
-- tenant deployment, but it doesn't survive the Phase 4-8 work:
--
-- - No version history (a tool's input schema is whatever the
--   YAML currently says; rollback is "git revert + redeploy").
-- - No approval workflow (every operator commit ships to prod;
--   no two-person review trail).
-- - No drift detection (an upstream silently mutating its tool
--   schemas is invisible until a call fails).
-- - No per-tenant overlays (Phase 8 tenant catalog pinning has
--   nowhere to land).
--
-- This migration lays the schema. The PR4a-2 importer reads
-- existing `servers/*.yaml` files and populates these tables;
-- PR4a-3 swaps `UpstreamPool::tool_facts()` to read from
-- `CatalogStore::resolve_tool()`; PR4a-4 adds admin CRUD
-- endpoints and removes the SIGHUP reload path. Nothing in this
-- migration changes the running code's behaviour — the tables
-- exist and are empty until the importer fills them.
--
-- Foreign keys (and `ON DELETE CASCADE` where appropriate) keep
-- the model self-cleaning: deleting an mcp_servers row cascades
-- through its tools, versions, classifications, approvals, and
-- drift events. Operators rarely delete; the audit trail
-- (catalog_approvals + catalog_drift_events) survives via
-- application-level archival when that matters.

-- ---------------------------------------------------------------
-- mcp_servers — one row per upstream the gateway knows about.
--
-- `runtime_target` is JSONB rather than a column-per-transport
-- because Phase 5's `TransportFactory` needs to evolve the shape
-- without a migration per transport variant. Today's shape
-- mirrors the YAML manifest:
--   {"url": "http://signal:8000/mcp"}                  (http)
--   {"command": ["/bin/foo", "--arg"]}                 (stdio)
--   {"url": "https://upstream/sse", "auth": {...}}     (sse)
--
-- `status` is the catalog-level lifecycle (proposed by an
-- operator, approved by a reviewer, live and routing traffic,
-- quarantined for drift, retired). The per-call hot path only
-- ever consults `live` rows.
--
-- `visibility` controls which tenants see this server in the
-- discovery surface. `global` ⇒ every tenant; `tenant_only` ⇒
-- only the row's own `tenant_id`. Phase 8 SCIM/RBAC adds
-- tenant overlays on top.
-- ---------------------------------------------------------------

CREATE TABLE mcp_servers (
    id              UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    name            TEXT NOT NULL,
    transport       TEXT NOT NULL CHECK (transport IN ('http','sse','stdio')),
    runtime_target  JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'proposed'
                    CHECK (status IN ('proposed','approved','live','quarantined','retired')),
    visibility      TEXT NOT NULL DEFAULT 'tenant_only'
                    CHECK (visibility IN ('global','tenant_only')),
    owner           TEXT,
    signing_pubkey  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX mcp_servers_tenant_status_idx
    ON mcp_servers (tenant_id, status);

-- ---------------------------------------------------------------
-- mcp_tools — one row per (server, tool name).
--
-- Distinct from `mcp_tool_versions` because the tool's *identity*
-- ((server, name)) is stable across schema evolutions: an
-- upstream that ships a new input schema doesn't change `name`,
-- only the version row. A given tool can therefore have multiple
-- historical versions in `mcp_tool_versions`, with the approved
-- one selected via `mcp_tool_versions.approved_at IS NOT NULL`.
-- ---------------------------------------------------------------

CREATE TABLE mcp_tools (
    id          UUID PRIMARY KEY,
    server_id   UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    UNIQUE (server_id, name)
);

-- ---------------------------------------------------------------
-- mcp_tool_versions — one row per observed schema.
--
-- `schema_hash` is the SHA-256 of the canonicalised (input,
-- output, description) tuple. Stamped at observation time by the
-- Phase 5 `ToolObserver`; drift is "the upstream's current
-- schema_hash != the catalog's approved schema_hash for this
-- tool". `approved_at` flips to NOT NULL when an operator
-- explicitly approves a version (today via the admin API;
-- Phase 6 adds the two-person workflow).
--
-- `(tool_id, schema_hash)` is the natural primary key: a given
-- tool can only have one row per distinct schema, and the
-- approval-history view materialises across all rows for a
-- tool ordered by `observed_at`.
-- ---------------------------------------------------------------

CREATE TABLE mcp_tool_versions (
    tool_id         UUID NOT NULL REFERENCES mcp_tools(id) ON DELETE CASCADE,
    schema_hash     TEXT NOT NULL,
    description     TEXT NOT NULL,
    input_schema    JSONB,
    output_schema   JSONB,
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    approved_by     TEXT,
    PRIMARY KEY (tool_id, schema_hash)
);

CREATE INDEX mcp_tool_versions_tool_approved_idx
    ON mcp_tool_versions (tool_id)
 WHERE approved_at IS NOT NULL;

-- ---------------------------------------------------------------
-- tool_classifications — one row per tool, holds the risk
-- assessment + side-effect flag + PII flag + cost class.
--
-- One-to-one with mcp_tools because re-classifying a tool is an
-- operator decision (UPDATE the row) rather than a new
-- classification (INSERT). Phase 6's auto-classifier runs the
-- `classify` CLI when a tool version's schema_hash changes; the
-- operator approves the suggested update through the admin UI.
-- ---------------------------------------------------------------

CREATE TABLE tool_classifications (
    tool_id             UUID PRIMARY KEY REFERENCES mcp_tools(id) ON DELETE CASCADE,
    risk                TEXT NOT NULL CHECK (risk IN ('low','medium','high','critical')),
    side_effects        BOOLEAN NOT NULL,
    pii                 BOOLEAN NOT NULL,
    data_classification TEXT,
    cost_class          TEXT,
    reviewed_at         TIMESTAMPTZ,
    reviewer            TEXT
);

-- ---------------------------------------------------------------
-- catalog_approvals — append-only audit log for catalog mutations.
--
-- Every status transition on a server / tool / version /
-- classification produces a row here, with `actor` + `reason` +
-- timestamp. The admin UI surfaces this as a per-subject history
-- panel; the Phase 7 evidence pipeline mirrors it into the
-- compliance-grade outbox.
--
-- Append-only by application contract (no UPDATE / DELETE
-- statements ever issued); enforcement via Postgres trigger
-- lands in Phase 7.
--
-- `subject_id` is a DELIBERATE soft reference, NOT a foreign key.
-- An audit log of "who approved/rejected/quarantined what" must
-- OUTLIVE the subject it references — an approval for a server
-- that was later retired-and-deleted is exactly the history a
-- compliance auditor needs. A hard FK would force one of two
-- wrong behaviours: `ON DELETE CASCADE` (deleting a server
-- erases its approval trail) or `ON DELETE RESTRICT` (a server
-- can never be deleted while any approval references it). Both
-- defeat the audit model. (AERB-flagged on PR #96.)
--
-- The integrity guarantee instead lives at the WRITE boundary:
-- `CatalogStore::record_approval` callers (the PR4a-4 admin
-- endpoints + the ManifestImporter) validate that the subject
-- exists before inserting. The polymorphic `subject_type` +
-- `subject_id` (+ `subject_version_hash`) shape is the standard
-- audit-log association pattern; FK enforcement is intentionally
-- traded for trail durability.
-- ---------------------------------------------------------------

-- `subject_version_hash` disambiguates `tool_version` subjects.
-- mcp_tool_versions has a COMPOSITE primary key
-- (tool_id, schema_hash), so `subject_id` alone (the tool_id)
-- can't say WHICH schema was approved once a tool has multiple
-- versions. For `subject_type = 'tool_version'` rows the column
-- carries the approved schema_hash; for every other subject_type
-- it stays NULL (their `subject_id` is a real single-column PK).
-- A CHECK enforces the pairing so a tool_version approval can't
-- be written without naming its version.
CREATE TABLE catalog_approvals (
    id                   UUID PRIMARY KEY,
    tenant_id            TEXT NOT NULL DEFAULT 'default',
    subject_type         TEXT NOT NULL
                         CHECK (subject_type IN ('server','tool','tool_version','classification')),
    subject_id           UUID NOT NULL,
    subject_version_hash TEXT,
    action               TEXT NOT NULL
                         CHECK (action IN ('proposed','approved','rejected','quarantined','retired')),
    actor                TEXT NOT NULL,
    reason               TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- tool_version subjects MUST name their schema_hash; all
    -- other subjects MUST NOT (their identity is subject_id alone).
    CONSTRAINT catalog_approvals_version_hash_pairing CHECK (
        (subject_type =  'tool_version' AND subject_version_hash IS NOT NULL) OR
        (subject_type <> 'tool_version' AND subject_version_hash IS NULL)
    )
);

CREATE INDEX catalog_approvals_subject_idx
    ON catalog_approvals (subject_type, subject_id, created_at DESC);

-- ---------------------------------------------------------------
-- catalog_drift_events — observed schema mismatches.
--
-- Written by the Phase 5 `ToolObserver` when the live upstream's
-- schema_hash differs from the catalog's approved hash. The
-- severity column distinguishes informational drift (low-risk
-- tool, schema changed in compatible ways) from critical drift
-- (high-risk tool, breaking change) — the latter triggers
-- automatic quarantine in Phase 6.
-- ---------------------------------------------------------------

CREATE TABLE catalog_drift_events (
    id              UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    tool_id         UUID NOT NULL REFERENCES mcp_tools(id) ON DELETE CASCADE,
    observed_hash   TEXT NOT NULL,
    approved_hash   TEXT,
    severity        TEXT NOT NULL CHECK (severity IN ('info','warn','critical')),
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX catalog_drift_events_tool_time_idx
    ON catalog_drift_events (tool_id, observed_at DESC);

CREATE INDEX catalog_drift_events_tenant_time_idx
    ON catalog_drift_events (tenant_id, observed_at DESC);
