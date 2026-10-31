-- Retained references identify a refused direct invocation, not queued work.
-- Argument values are never copied into this review queue.
CREATE TABLE pending_invocation_requests (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id UUID NOT NULL,
    principal_issuer TEXT NOT NULL,
    principal_sub TEXT NOT NULL,
    tool_id UUID NOT NULL,
    server_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    behavior_hash TEXT NOT NULL,
    argument_hash TEXT NOT NULL,
    summary JSONB CHECK (summary IS NULL OR jsonb_typeof(summary)='object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+INTERVAL '15 minutes',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired')),
    decided_at TIMESTAMPTZ,
    decided_by_issuer TEXT,
    decided_by_sub TEXT,
    reason TEXT,
    grant_id UUID,
    PRIMARY KEY (tenant_id,id),
    CHECK ((status IN ('pending','expired') AND decided_at IS NULL AND grant_id IS NULL)
        OR (status='denied' AND decided_at IS NOT NULL AND decided_by_issuer IS NOT NULL AND decided_by_sub IS NOT NULL AND grant_id IS NULL)
        OR (status='approved' AND decided_at IS NOT NULL AND decided_by_issuer IS NOT NULL AND decided_by_sub IS NOT NULL AND grant_id IS NOT NULL))
);
CREATE UNIQUE INDEX pending_invocation_requests_identity
    ON pending_invocation_requests(tenant_id,principal_issuer,principal_sub,tool_id,behavior_hash,argument_hash)
    WHERE status='pending';
CREATE INDEX pending_invocation_requests_queue
    ON pending_invocation_requests(tenant_id,status,created_at,id);
