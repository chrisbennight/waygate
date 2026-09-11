-- Add the four authorization-decision INPUTS to audit_log so a recorded
-- decision (CallTool / llm_completion) can be reconstructed and re-evaluated
-- (policy-UX PR8a "capture", with PR8b building the exact replay on top).
--
-- Background: a Cedar authorization decision branches on more than the
-- principal_*/server/tool/risk/pii columns audit_log already records. Four
-- inputs that policies can gate on were never persisted on the decision row:
--   * principal.scopes       — the OAuth scopes the caller presented.
--   * principal.auth_method   — "oauth" / "api_key" / "peer_assertion".
--   * principal.roles         — RBAC role names resolved at auth time.
--   * resource.side_effects   — whether the called tool mutates external state.
-- Without them a recorded allow/deny can't be replayed deterministically: the
-- same row could re-evaluate to a different verdict because the inputs that
-- drove the original decision aren't on the row. PR8a captures them; PR8b reads
-- them back to re-run the engine against a candidate policy set.
--
-- All four columns are NULLABLE so:
--   1. Every pre-migration row reads back NULL (no backfill). NULL is the
--      "absent" signal the hash-chain extension keys off (see below).
--   2. Non-decision categories (admin_mutation, oauth_event, retention_sweep,
--      manifest_reload, …) that have no principal/resource leave them unset.
-- `req_scopes` / `req_roles` are TEXT[] (multi-valued, like principal_groups /
-- policy_ids); `auth_method` is TEXT; `side_effects` is BOOLEAN.
--
-- Hash-chain compatibility: `canonical_audit_bytes_with_ext2` appends these as
-- a NEW tail extension AFTER the `target` block (migration 0046), gated on
-- "any of the four is present" and led by a sentinel byte. When all four are
-- absent the extension contributes ZERO bytes, so every legacy row (NULL
-- columns) hashes byte-identically under the extended function and the PR7-5
-- verifier keeps accepting them — the same technique migrations 0022 (SCIM)
-- and 0046 (`target`) used.

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS req_scopes  TEXT[],
    ADD COLUMN IF NOT EXISTS auth_method TEXT,
    ADD COLUMN IF NOT EXISTS req_roles   TEXT[],
    ADD COLUMN IF NOT EXISTS side_effects BOOLEAN;

-- No index. These are replay-evidence / chain-covered columns, not search
-- facets (no Decision Log filter pivots on them today). NULL on every legacy
-- row, so a future partial index is cheap to add if an access pattern emerges.
