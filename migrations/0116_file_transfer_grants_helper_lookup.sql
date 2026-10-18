-- A helper may redeem a pending grant with its DPoP key and the file URI
-- instead of the grant handle. issued_at is set only after the grant's
-- creation audit is recorded, so that lookup never selects a grant whose
-- required audit is still pending or failed. The handle form needs no such
-- marker because the handle is not returned before the same point.
ALTER TABLE file_transfer_grants
    ADD COLUMN issued_at TIMESTAMPTZ;

CREATE INDEX file_transfer_grants_pending_helper_idx
    ON file_transfer_grants (helper_jkt, file_uri, direction, created_at DESC)
    WHERE status = 'pending' AND issued_at IS NOT NULL;
