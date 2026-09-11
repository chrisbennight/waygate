CREATE TABLE codemode_source_artifacts (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub TEXT NOT NULL,
    principal_issuer TEXT NOT NULL,
    source_digest TEXT NOT NULL CHECK (
        length(source_digest) = 64
        AND source_digest ~ '^[0-9a-f]+$'
    ),
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, principal_issuer, principal_sub, source_digest)
);

CREATE INDEX codemode_source_artifacts_expiry_idx
    ON codemode_source_artifacts (expires_at);

CREATE TABLE codemode_source_locators (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub TEXT NOT NULL,
    principal_issuer TEXT NOT NULL,
    source_locator TEXT NOT NULL CHECK (
        length(source_locator) = 64
        AND source_locator ~ '^[0-9a-f]+$'
    ),
    source_digest TEXT NOT NULL CHECK (
        length(source_digest) = 64
        AND source_digest ~ '^[0-9a-f]+$'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, principal_issuer, principal_sub, source_locator)
);

CREATE INDEX codemode_source_locators_expiry_idx
    ON codemode_source_locators (expires_at);
