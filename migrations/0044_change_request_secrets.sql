-- HITL control-plane: retrievable secrets for secret-producing change-request
-- actions (e.g. api_key.mint, where the maker proposes a mint and must later
-- retrieve the freshly minted key to hand to a secret store).
--
-- Why a side table (not columns on change_requests):
--   * The change_requests poll / list / decision queries each inline a 23-column
--     RETURNING list that must stay in lockstep with the FromRow decoder
--     (see crates/gateway-changeset/src/lib.rs). Adding secret columns there
--     would thread the secret through every one of those read paths — exactly
--     where it must NOT appear. Keeping it separate guarantees the secret is
--     never carried by a status poll, the maker's list view, or the operator's
--     decision response.
--
-- The secret is stored as AES-256-GCM ciphertext (nonce||ct||tag — the same
-- envelope used for upstream tokens), with the keyring `key_id` alongside so
-- decrypt can pick the right key. The plaintext is surfaced to the maker
-- EXACTLY ONCE via a single-use burn-on-read: the retrieve path atomically
-- stamps `retrieved_at` and a second read returns nothing ("shown once").
CREATE TABLE IF NOT EXISTS change_request_secrets (
    -- One secret per change request; cascade-delete with the parent row so a
    -- removed/expired change request can't leave an orphaned ciphertext behind.
    change_request_id UUID PRIMARY KEY REFERENCES change_requests(id) ON DELETE CASCADE,
    -- Denormalised for tenant-scoped retrieve/burn queries (the burn UPDATE
    -- filters on both id AND tenant_id, mirroring every other store method).
    tenant_id         TEXT        NOT NULL,
    -- nonce(12) || ciphertext || GCM tag.
    ciphertext        BYTEA       NOT NULL,
    -- Keyring id that produced `ciphertext`; decrypt selects the matching key.
    key_id            TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Burn marker: non-NULL once the secret has been retrieved. The single-use
    -- claim is `UPDATE ... SET retrieved_at = now() WHERE ... AND retrieved_at
    -- IS NULL RETURNING`, so a double-read or race can't surface it twice.
    retrieved_at      TIMESTAMPTZ
);
