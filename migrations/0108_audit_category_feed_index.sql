-- The overview reads the newest events for one tenant and category. Both
-- equality predicates must precede the ordering key: a tenant-only index can
-- scan the tenant's entire history when a category is rare or absent, while a
-- category/timestamp index cannot supply UUID ordering without a sort.
-- Built during migration in the usual transaction; allow for the audit-log
-- index build and its write lock when planning the release rollout.
CREATE INDEX IF NOT EXISTS audit_log_tenant_category_id_desc_idx
    ON audit_log (tenant_id, category, id DESC);
