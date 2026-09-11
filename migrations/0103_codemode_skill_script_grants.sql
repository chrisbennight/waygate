CREATE TABLE codemode_skill_script_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub TEXT NOT NULL,
    principal_issuer TEXT NOT NULL,
    source_origin TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    skill_uri TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    approval_digest TEXT NOT NULL,
    resource_uri TEXT NOT NULL,
    resource_digest TEXT NOT NULL,
    execution_profile TEXT NOT NULL CHECK (execution_profile = 'read_only'),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    approver TEXT NOT NULL,
    approver_issuer TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX codemode_skill_script_grants_lookup_idx
    ON codemode_skill_script_grants (
        tenant_id, principal_issuer, principal_sub,
        approval_digest, resource_uri, resource_digest, execution_profile
    )
    WHERE revoked_at IS NULL;

CREATE INDEX codemode_skill_script_grants_expiry_idx
    ON codemode_skill_script_grants (expires_at)
    WHERE revoked_at IS NULL;
