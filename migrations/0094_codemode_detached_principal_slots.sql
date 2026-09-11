-- Deployment-wide fairness lease for detached Code Mode attempts. The holder
-- token fences renewal/release after expiry; acquisition may replace only an
-- expired row, so stateless requests routed to different replicas still share
-- one active slot per exact principal identity.
CREATE TABLE codemode_detached_principal_slots (
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub    TEXT NOT NULL CHECK (principal_sub <> ''),
    principal_issuer TEXT NOT NULL CHECK (principal_issuer <> ''),
    holder           UUID NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, principal_issuer, principal_sub)
);

CREATE INDEX codemode_detached_principal_slots_expiry
    ON codemode_detached_principal_slots (lease_expires_at);
