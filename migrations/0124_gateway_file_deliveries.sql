-- Ownership and routing for private upstream upload staging. Source bytes remain
-- in gateway_files; a delivery never owns or deletes the source file.
CREATE TABLE gateway_file_deliveries (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub TEXT NOT NULL,
    principal_issuer TEXT NOT NULL,
    file_id UUID NOT NULL,
    invocation_id TEXT NOT NULL,
    upstream_server TEXT NOT NULL,
    upstream_tool TEXT NOT NULL,
    source_server TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    upstream_uri TEXT NOT NULL,
    lifecycle_supported BOOLEAN NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('prepared','transferring','ready','dispatched','completed','rejected','completion_unknown','cancelled','cancelling')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX gateway_file_deliveries_owner_file_idx ON gateway_file_deliveries
    (tenant_id, principal_issuer, principal_sub, file_id, created_at DESC);
CREATE INDEX gateway_file_deliveries_invocation_idx ON gateway_file_deliveries (invocation_id);
CREATE INDEX gateway_file_deliveries_expiry_idx ON gateway_file_deliveries (expires_at);
