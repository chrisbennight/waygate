-- Indexes serving the admin dashboard's hot read paths (Tier-1).
--
-- Both are plain (non-CONCURRENT) CREATE INDEX: sqlx runs each migration in a
-- transaction, inside which CREATE INDEX CONCURRENTLY is illegal. A regular
-- build takes a brief SHARE lock on audit_log; on this table that is seconds,
-- and audit writes are best-effort, so the short stall is acceptable.

-- 1. Keyset feed. The Activity feed and Overview "what changed" / notable feeds
--    page with `... WHERE tenant_id = $ ORDER BY id DESC LIMIT $`. The existing
--    (tenant_id, ts DESC) index can't satisfy id-ordering without a sort; this
--    composite makes the keyset query a pure index range scan (no sort node),
--    and keeps each page exactly LIMIT matching rows as the table grows.
CREATE INDEX IF NOT EXISTS audit_log_tenant_id_desc_idx
    ON audit_log (tenant_id, id DESC);

-- 2. Non-success feed. The Overview "notable" feed (and any error/denial view)
--    selects `... WHERE tenant_id = $ AND outcome <> 'success' ORDER BY id DESC`.
--    Non-success rows are a tiny fraction of the table, so a PARTIAL index keeps
--    it small and turns that query into an index probe over only the matching
--    rows instead of scanning the keyset index until it finds enough. The
--    predicate is a constant comparison (immutable), as a partial-index WHERE
--    requires.
CREATE INDEX IF NOT EXISTS audit_log_tenant_nonsuccess_idx
    ON audit_log (tenant_id, id DESC)
    WHERE outcome <> 'success';
