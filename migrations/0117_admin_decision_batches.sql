-- Dashboard receipts retain reviewed identities and observed outcomes, never
-- tool arguments or full review documents. Domain stores still own decisions.
CREATE TABLE admin_decision_batches (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id UUID NOT NULL,
    actor_issuer TEXT NOT NULL,
    actor_sub TEXT NOT NULL,
    request JSONB NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + INTERVAL '7 days',
    started_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX admin_decision_batches_owner
    ON admin_decision_batches (tenant_id, actor_issuer, actor_sub, created_at DESC);

CREATE TABLE admin_decision_batch_items (
    tenant_id TEXT NOT NULL,
    batch_id UUID NOT NULL,
    item_index INTEGER NOT NULL CHECK (item_index >= 0 AND item_index < 50),
    started_at TIMESTAMPTZ,
    result JSONB CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    PRIMARY KEY (tenant_id, batch_id, item_index),
    FOREIGN KEY (tenant_id, batch_id)
        REFERENCES admin_decision_batches(tenant_id, id) ON DELETE CASCADE,
    CHECK (result IS NULL OR started_at IS NOT NULL)
);
