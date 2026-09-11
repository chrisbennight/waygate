-- Phase 5 PR5-1d-ii: support the per-tenant eviction cap.
--
-- `enforce_tenant_cap` runs on every store:
--   DELETE FROM llm_cache WHERE tenant_id = $1 AND cache_key NOT IN
--     (SELECT cache_key FROM llm_cache WHERE tenant_id = $1
--      ORDER BY created_at DESC, cache_key DESC LIMIT $2)
-- Without an index on (tenant_id, created_at, cache_key), that subquery
-- seq-scans + sorts the whole table per put once a tenant has many rows. This
-- index lets the keep-set come straight off an index scan (the column order +
-- DESC match the ORDER BY exactly; tenant_id is an equality prefix), and the
-- outer DELETE's `tenant_id = $1` rides the same prefix. cache_key is included
-- so the keep-set scan is index-only.
CREATE INDEX llm_cache_tenant_created_idx
    ON llm_cache (tenant_id, created_at DESC, cache_key DESC);
