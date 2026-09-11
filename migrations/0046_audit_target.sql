-- Add the `target` column to audit_log so every recorded event can name
-- WHAT it acted on, as a structured column rather than only inside the
-- free-text `reason`.
--
-- Background: lifecycle events (ApiKeyMinted / ApiKeyRevoked / ApiKeyRenamed,
-- and later the change-request ceremony) record the acting principal in the
-- `principal_*` columns ("who authorized it") but the *subject* of the action
-- — the API key's `sub`, the change's action_type — lived only in `reason`.
-- The admin "What changed" feed renders `<action> · <principal>`, so two
-- mints of different keys collapsed to an identical row. A typed `target`
-- column lets the feed/drawer/compare views render the subject and lets the
-- hash chain cover it (see `gateway_storage::hashchain`).
--
-- Column is nullable so:
--   1. Every pre-migration row reads back `target IS NULL` (no backfill).
--   2. Event categories that have no meaningful target (tool-call
--      invocations, policy reloads, …) leave it unset.
--
-- Hash-chain compatibility: `canonical_audit_bytes_with_ext` appends the
-- target as a tail extension that contributes ZERO bytes when NULL, so every
-- legacy row hashes byte-identically under the extended function and the
-- PR7-5 verifier keeps accepting them — the same technique migration 0022
-- used for the SCIM columns.

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS target TEXT;

-- No index. No query filters on `target` today (it's a render/display field
-- and chain-covered evidence, not a search facet). NULL on every legacy row,
-- so a future partial index is cheap to add if an access pattern emerges.
