-- Terminal file-transfer authority rows are temporary. Requests are removed by
-- the grant's ON DELETE CASCADE after the grant expires.
CREATE INDEX file_transfer_grants_terminal_expiry_sweep_idx
    ON file_transfer_grants (expires_at, id)
    WHERE status IN ('completed', 'revoked', 'failed');

ALTER TABLE file_transfer_grants
    ADD COLUMN active_heartbeat_at TIMESTAMPTZ;

UPDATE file_transfer_grants
   SET active_heartbeat_at = updated_at
 WHERE requests_used > 0;

ALTER TABLE file_transfer_grants
    ADD CONSTRAINT file_transfer_grants_used_request_has_heartbeat
    CHECK (requests_used = 0 OR active_heartbeat_at IS NOT NULL);

CREATE INDEX file_transfer_grants_active_heartbeat_sweep_idx
    ON file_transfer_grants (expires_at, requests_used, active_heartbeat_at, id)
    WHERE status = 'active';
