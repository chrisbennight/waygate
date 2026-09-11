-- Confidential OAuth clients for EMA ID-JAG redemption (PR-2).
--
-- The Resource-AS redeem path (jwt-bearer grant) requires the redeeming client
-- to authenticate with its own registered credential
-- (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.4 / §9.1: confidential
-- clients only). The gateway's CIMD clients are public (token endpoint auth
-- method `none`), so confidential clients are a distinct, operator-registered
-- set recorded here.
--
-- A client may authenticate by client_secret (argon2id hash) and/or
-- private_key_jwt (its public JWKS, used to verify a client_assertion). At
-- least one method MUST be present. These rows are operator-managed AS
-- infrastructure (the apps allowed to redeem), not per-end-user state, so they
-- are not tenant-scoped — tenant correctness on a redeemed token comes from the
-- ID-JAG subject's tenant claim, not the client.
CREATE TABLE oauth_confidential_clients (
    -- The OAuth client_id. For CIMD-style clients this is the metadata-document
    -- URL; the ID-JAG's `client_id` claim MUST equal this at redeem.
    client_id   TEXT PRIMARY KEY,
    -- argon2id PHC string (`$argon2id$…`); NULL when the client uses
    -- private_key_jwt only. Never the plaintext secret.
    secret_hash TEXT,
    -- The client's public JWKS, used to verify a private_key_jwt
    -- `client_assertion`; NULL when the client uses client_secret only.
    jwks        JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A client with neither credential could never authenticate — reject it at
    -- write time rather than minting a useless, un-redeemable registration.
    CONSTRAINT oauth_confidential_clients_has_credential
        CHECK (secret_hash IS NOT NULL OR jwks IS NOT NULL)
);
