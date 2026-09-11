-- Gateway-owned file references for outbound transfers. File bytes live in a
-- configured shared directory; this table stores ownership, integrity data,
-- lifetime, and the opaque storage key.

CREATE TABLE gateway_files (
    id                UUID PRIMARY KEY,
    batch_id          UUID NOT NULL,
    tenant_id         TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    principal_sub     TEXT NOT NULL,
    principal_issuer  TEXT NOT NULL,
    invocation_id     TEXT NOT NULL,
    upstream_server   TEXT NOT NULL,
    upstream_tool     TEXT NOT NULL,
    upstream_uri      TEXT NOT NULL,
    storage_key       TEXT NOT NULL UNIQUE,
    display_name      TEXT,
    media_type        TEXT,
    size_bytes        BIGINT CHECK (size_bytes IS NULL OR size_bytes >= 0),
    sha256_digest     BYTEA CHECK (
                          sha256_digest IS NULL OR octet_length(sha256_digest) = 32
                      ),
    inspection_status TEXT NOT NULL
                      CHECK (inspection_status IN ('checked', 'uninspectable')),
    state             TEXT NOT NULL DEFAULT 'pending'
                      CHECK (state IN ('pending', 'ready', 'deleting')),
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (state <> 'ready' OR (size_bytes IS NOT NULL AND sha256_digest IS NOT NULL)),
    CHECK (tenant_id IS NOT NULL OR state = 'deleting')
);

-- File bytes live outside Postgres. Keep the metadata row as a retryable
-- deletion record when its tenant is removed instead of cascading away the
-- only storage key that can locate those bytes.
CREATE FUNCTION mark_gateway_files_deleting_on_tenant_delete()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE gateway_files
       SET state = 'deleting'
     WHERE tenant_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenants_mark_gateway_files_deleting
    BEFORE DELETE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION mark_gateway_files_deleting_on_tenant_delete();

CREATE INDEX gateway_files_owner_uri_idx
    ON gateway_files (tenant_id, principal_issuer, principal_sub, id)
    WHERE state = 'ready';

CREATE INDEX gateway_files_batch_idx
    ON gateway_files (batch_id);

CREATE INDEX gateway_files_ready_expiry_idx
    ON gateway_files (expires_at, id)
    WHERE state = 'ready';

CREATE INDEX gateway_files_pending_activity_idx
    ON gateway_files (updated_at, id)
    WHERE state = 'pending' AND size_bytes IS NULL;

CREATE INDEX gateway_files_pending_expiry_idx
    ON gateway_files (expires_at, id)
    WHERE state = 'pending' AND size_bytes IS NOT NULL;

CREATE INDEX gateway_files_delete_idx
    ON gateway_files (id)
    WHERE state = 'deleting';

CREATE TRIGGER gateway_files_touch_updated_at
    BEFORE UPDATE ON gateway_files
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();
