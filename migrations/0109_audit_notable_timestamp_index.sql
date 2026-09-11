-- The notable feed selects the newest event timestamps, which need not follow
-- ID order. Exclude non-displayable events in the index so LIMIT bounds the
-- work even when recent history consists mostly of successful or pre-call rows.
-- The normal transactional migration build temporarily blocks audit writes.
CREATE INDEX IF NOT EXISTS audit_log_notable_ts_idx
    ON audit_log (tenant_id, ts DESC, id DESC)
    WHERE outcome <> 'success' AND reason IS DISTINCT FROM 'pre_call';
