-- The freshness column is intentionally action-specific. Executors own the
-- representation and must not infer a universal hash contract from its name.
COMMENT ON COLUMN change_requests.target_etag IS
    'Opaque action-specific freshness witness captured at propose time. The owning executor may store a digest or structured non-secret version token and is solely responsible for interpreting it.';
