-- Durable authority for out-of-context file transfer. Public grant handles
-- identify an authorized movement but are not bearer credentials; exchange
-- also requires proof of the helper key bound to the row. Transfer credentials
-- are high-entropy values and only their SHA-256 digests are persisted.

CREATE TABLE file_transfer_grants (
    id                    UUID PRIMARY KEY,
    tenant_id             TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    handle_hash           BYTEA NOT NULL UNIQUE,
    principal_sub         TEXT NOT NULL,
    principal_issuer      TEXT NOT NULL,
    credential_profile_id TEXT,
    invocation_id         TEXT NOT NULL,
    file_uri              TEXT NOT NULL,
    direction             TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    source_kind           TEXT NOT NULL CHECK (source_kind IN ('client', 'upstream')),
    source_ref            TEXT NOT NULL,
    destination_kind      TEXT NOT NULL CHECK (destination_kind IN ('client', 'upstream')),
    destination_ref       TEXT NOT NULL,
    helper_jkt            TEXT NOT NULL,
    max_bytes             BIGINT NOT NULL CHECK (max_bytes > 0),
    expected_size         BIGINT CHECK (expected_size IS NULL OR expected_size >= 0),
    media_type            TEXT,
    digest_algorithm      TEXT,
    expected_digest       BYTEA,
    max_requests          BIGINT NOT NULL CHECK (max_requests > 0),
    credential_ttl_seconds BIGINT NOT NULL CHECK (credential_ttl_seconds > 0),
    requests_used         BIGINT NOT NULL DEFAULT 0 CHECK (requests_used >= 0),
    status                TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'active', 'completed', 'revoked', 'failed')),
    credential_hash       BYTEA,
    credential_expires_at TIMESTAMPTZ,
    failure_code          TEXT,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at          TIMESTAMPTZ,
    completed_at          TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expected_size IS NULL OR expected_size <= max_bytes),
    CHECK ((digest_algorithm IS NULL) = (expected_digest IS NULL)),
    CHECK ((credential_hash IS NULL) = (credential_expires_at IS NULL)),
    CHECK (requests_used <= max_requests)
);

CREATE INDEX file_transfer_grants_tenant_expiry_idx
    ON file_transfer_grants (tenant_id, expires_at);

-- The global sweeper does not have a tenant predicate. Keep its ordered,
-- eligible-row scan bounded even as terminal grant history accumulates.
CREATE INDEX file_transfer_grants_expiry_sweep_idx
    ON file_transfer_grants (expires_at, id)
    WHERE status = 'pending' OR (status = 'active' AND requests_used = 0);

CREATE UNIQUE INDEX file_transfer_grants_credential_idx
    ON file_transfer_grants (credential_hash)
    WHERE credential_hash IS NOT NULL;

CREATE TRIGGER file_transfer_grants_touch_updated_at
    BEFORE UPDATE ON file_transfer_grants
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

-- A DPoP proof identifier is claimed only after its signature and request
-- binding validate. The unique key makes replay refusal atomic across replicas.
CREATE TABLE file_transfer_dpop_replays (
    helper_jkt TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (helper_jkt, jti)
);

CREATE INDEX file_transfer_dpop_replays_expiry_idx
    ON file_transfer_dpop_replays (expires_at);

-- A request authorization is a durable start decision. Grant and credential
-- expiry prevent new starts; they do not impose a hidden total timeout on an
-- already-streaming transfer. Completion must present this opaque internal id.
CREATE TABLE file_transfer_requests (
    id             UUID PRIMARY KEY,
    grant_id       UUID NOT NULL REFERENCES file_transfer_grants(id) ON DELETE CASCADE,
    request_number BIGINT NOT NULL CHECK (request_number > 0),
    status         TEXT NOT NULL DEFAULT 'authorized'
                   CHECK (status IN ('authorized', 'completed', 'failed')),
    observed_size  BIGINT CHECK (observed_size IS NULL OR observed_size >= 0),
    observed_digest BYTEA,
    failure_code   TEXT,
    authorized_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ,
    failed_at      TIMESTAMPTZ,
    CHECK ((status = 'failed') = (failure_code IS NOT NULL)),
    CHECK ((status = 'failed') = (failed_at IS NOT NULL)),
    CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    UNIQUE (grant_id, request_number)
);

CREATE INDEX file_transfer_requests_grant_status_idx
    ON file_transfer_requests (grant_id, status);
