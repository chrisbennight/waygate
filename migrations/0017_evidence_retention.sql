-- =====================================================================
-- SCOPE: POLICY STORAGE ONLY. NO sweep. NO trigger bypass.
-- Enforcement (DELETE-from-audit_log + audit_log_no_mutate() bypass
-- + GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS) is deferred to PR7-8.
-- This migration only adds the evidence_retention_policy table.
-- PR7-4's audit_log append-only trigger (0015_audit_hashchain.sql)
-- is NOT modified by this migration. tamper-evidence stays as-is.
-- =====================================================================
--
-- Phase 7 PR7-7: per-tenant per-category retention POLICY TABLE.
--
-- Operator-facing intent: configure when audit_log rows for a
-- given (tenant_id, category) become deletable. This PR ships the
-- CONFIGURATION SURFACE only — the actual sweep + DB-trigger
-- bypass machinery that enforces these policies lands in a
-- follow-up PR (PR7-8). That separation lets us debate the
-- enforcement design (chain-aware verification with documented
-- gap markers; SECURITY DEFINER + separate Postgres role for
-- the function owner) in isolation, without coupling it to the
-- policy-storage surface that's straightforward to land safely.
--
-- Once this PR ships, the surface is:
--
--   PUT  /api/v1/audit/retention  body {tenant_id, category, delete_after_days}
--   GET  /api/v1/audit/retention?tenant_id=<id>
--   DELETE /api/v1/audit/retention?tenant_id=&category=
--
-- — all gated by mcp:admin, all emitting AdminMutation evidence
-- on success. Operators can document their intended retention
-- windows now; enforcement lands when PR7-8 ships the sweep.
--
-- Policy row semantics (what the follow-up sweep will honour):
--
-- - Each row says "for THIS tenant and THIS evidence category,
--   delete any audit_log row older than `delete_after_days`
--   days." PK is `(tenant_id, category)`.
-- - `category = '*'` is the wildcard — applies to every category
--   for that tenant that doesn't have its own explicit row.
--   Most-specific wins.
-- - No rows for a tenant ⇒ that tenant's audit data is retained
--   indefinitely. Pre-PR7-7 behaviour for every existing
--   deployment.
-- - `delete_after_days` must be > 0; 0 would mean "delete
--   everything immediately" which is almost certainly a typo.
--   Admin handler rejects; CHECK constraint here is defense-
--   in-depth.

CREATE TABLE evidence_retention_policy (
    tenant_id          TEXT NOT NULL,
    -- One of the EvidenceCategory.as_str() values from
    -- crates/gateway-mcp/src/audit.rs, OR the literal '*'
    -- wildcard. Free-form text (not an enum) because adding a
    -- new category shouldn't require an ALTER TABLE; the sweep
    -- matches by string at enforcement time.
    category           TEXT NOT NULL,
    delete_after_days  INT  NOT NULL CHECK (delete_after_days > 0),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, category)
);
