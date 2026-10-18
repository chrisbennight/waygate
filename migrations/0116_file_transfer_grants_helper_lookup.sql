-- A helper may redeem a pending grant with its DPoP key and the file URI
-- instead of the grant handle. This serves that lookup without scanning
-- grants that can no longer be redeemed.
CREATE INDEX file_transfer_grants_pending_helper_idx
    ON file_transfer_grants (helper_jkt, file_uri, direction, created_at DESC)
    WHERE status = 'pending';
