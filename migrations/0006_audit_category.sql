-- Add the `category` column to audit_log so each event row carries a
-- typed discriminator (invocation, policy_reload, manifest_reload,
-- api_key_lifecycle, etc.). Phase 1a of the rearchitecture extends
-- the recorded set beyond tool-call outcomes; downstream
-- SIEM/OCSF/syslog exporters key off the category to format the row.
--
-- See `gateway_mcp::audit::EvidenceCategory` for the canonical
-- string values written here. Existing rows pre-dating this migration
-- have NULL `category`; readers treat NULL as `invocation` (the only
-- thing recorded before this slice).

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS category TEXT;

-- Composite index for category-filtered reads (the admin activity view's
-- common case is "show me policy reloads in the last 24h" or "show me
-- denials" — the latter already uses `outcome`). Plain composite, not
-- a partial index — NULL `category` rows are also useful for queries
-- like "show me everything pre-migration" so we don't want to exclude
-- them. Cheap to add; drop without ceremony if usage shows it's not
-- pulling its weight.
CREATE INDEX IF NOT EXISTS audit_log_category_ts_idx
    ON audit_log (category, ts DESC);
