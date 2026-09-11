-- Phase 6 PR6-6: scaffolding for pre-call human-in-the-loop (HITL)
-- approval grants.
--
-- This migration lays the SCHEMA. The PR that wires enforcement
-- (PR6-7) makes InvocationService stage `check_approval` consult
-- this table and refuse dispatch when `requires_approval=true` AND
-- no matching grant exists. Until then, the column defaults to
-- false everywhere (existing imported tools, ManifestImporter
-- output) so behavior is unchanged.
--
-- Two changes, both additive:
--
-- 1. `tool_classifications.requires_approval BOOLEAN NOT NULL
--    DEFAULT false` — per-tool flag. When true, every call to this
--    tool by every principal needs an active grant (a row in
--    approval_grants below) before dispatch. Operators set this
--    via the admin UI for tools that need a human in the loop on
--    every call regardless of caller (e.g. destructive prod ops,
--    cost-bearing API calls, off-network sends).
--
-- 2. `approval_grants` — one row per (principal × tool × argument
--    shape) pre-approval. A grant binds:
--      - the principal who's allowed to make the call (sub),
--      - the tool they're allowed to call (server_id + tool_id),
--      - the argument hash they're allowed to call it with
--        (sha256 of canonical-JSON arguments — same hash function
--         as `gateway_catalog::schema_hash`, prefixed `args-v1`),
--      - an expiry (TIMESTAMPTZ NOT NULL — never an open-ended
--        grant; HITL approval is by-request, not perpetual),
--      - the approver (sub) and optional reason.
--    Approver MUST be distinct from principal_sub when the
--    GATEWAY_REQUIRE_TWO_APPROVALS-style rule lands for grants
--    too (a follow-up); for v1 we accept any approver and let
--    the admin UI's two-eyes rule layer above.

-- ---------------------------------------------------------------
-- requires_approval flag on tool_classifications.
--
-- NOT NULL DEFAULT false means existing rows backfill silently
-- (no manual data migration needed). The PR6-7 enforcement slice
-- keys off this column; until then the column exists but is
-- ignored by the per-call path.
-- ---------------------------------------------------------------

ALTER TABLE tool_classifications
    ADD COLUMN requires_approval BOOLEAN NOT NULL DEFAULT false;

-- ---------------------------------------------------------------
-- approval_grants — one row per pre-approved (principal × tool ×
-- arguments × time-window) call.
--
-- argument_hash is the SHA-256 of the canonical-JSON serialised
-- call arguments (the same canonicalization used by
-- gateway_catalog::schema_hash, but with prefix "args-v1" so the
-- two hash spaces can never collide). Binding to argument shape
-- prevents an approval for "send 1 message to alice" from being
-- replayed against "send 1000 messages to a public channel."
--
-- expires_at is REQUIRED (NOT NULL) — a grant's *outer* time
-- bound. Open-ended grants would defeat the by-request HITL model.
--
-- consumed_at is the *one-time-use* bound (AERB PR #118 medium).
-- HITL on high-risk ops means an admin approves "send THIS message
-- to THIS recipient" — that approval is not replayable for the
-- expires_at window. find_grant filters consumed_at IS NULL; the
-- enforcement gate (PR6-7) atomically claims the row with an
-- `UPDATE ... FOR UPDATE SKIP LOCKED RETURNING` so concurrent
-- dispatches can't both consume one grant.
--
-- Operators wanting a standing exception should flip
-- requires_approval=false on the classification instead.
--
-- (server_id, tool_id) are soft references — the audit trail for
-- a grant must outlive deletion of the tool it referenced, same
-- reasoning as catalog_approvals.subject_id (AERB PR #96). For
-- v1 we accept the simplicity loss; a follow-up can revisit if
-- the table grows large enough that the missing FK becomes a
-- maintenance burden.
--
-- client_id is OPTIONAL: a grant can be scoped to "any OAuth
-- client this principal uses" (NULL) or to a specific client_id
-- (locked-down service-account flow). The PR6-7 lookup matches
-- with `(client_id IS NULL OR client_id = $caller_client_id)`.
-- ---------------------------------------------------------------

CREATE TABLE approval_grants (
    id              UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    principal_sub   TEXT NOT NULL,
    client_id       TEXT,
    server_id       UUID NOT NULL,
    tool_id         UUID NOT NULL,
    argument_hash   TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    -- NULL = not yet consumed (grant is live). Set to the
    -- consumption time by the PR6-7 enforcement gate on the
    -- atomic-claim path. Once non-NULL, find_grant excludes the
    -- row and dispatch refuses (subject to a fresh grant).
    consumed_at     TIMESTAMPTZ,
    approver        TEXT NOT NULL,
    reason          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot-path lookup index. The PR6-7 check_approval stage runs:
--   SELECT ... FROM approval_grants
--    WHERE tenant_id = $1 AND principal_sub = $2 AND tool_id = $3
--      AND argument_hash = $4
--      AND consumed_at IS NULL
--      AND expires_at > now()
--      AND (client_id IS NULL OR client_id = $5)
--    LIMIT 1
-- Index covers the four equality keys; the `expires_at > now()`
-- and `consumed_at IS NULL` filters happen at query time. A
-- partial index gated on `expires_at > now()` would be more
-- selective but Postgres requires partial-index predicates be
-- IMMUTABLE and `now()` is not. A `WHERE consumed_at IS NULL`
-- partial index IS legal (the predicate is immutable) but we
-- keep the v1 index full to also serve admin "all grants" views;
-- a background sweep (PR6-7 or later) prunes expired+consumed
-- rows so the un-partial index stays small in practice.
CREATE INDEX approval_grants_lookup_idx
    ON approval_grants (tenant_id, principal_sub, tool_id, argument_hash);

-- Audit / list index for the admin UI's "grants for this principal"
-- and "grants for this tool" panels.
CREATE INDEX approval_grants_tenant_principal_idx
    ON approval_grants (tenant_id, principal_sub, created_at DESC);
CREATE INDEX approval_grants_tenant_tool_idx
    ON approval_grants (tenant_id, tool_id, created_at DESC);
