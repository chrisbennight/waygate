-- Phase 8 PR8-c round 5 (AERB medium): persist SCIM-resolved
-- principal facts on every audit row, not only ones that flow
-- through the outbox.
--
-- Round 2 added `scim_active` + `scim_groups` to the in-memory
-- `AuditPrincipal`; rounds 2-4 wired them through OCSF / ECS /
-- syslog exporters. AERB round 5 caught that the exporters only
-- see events routed through the outbox (record_required +
-- effective_targets), while the common case
-- (record_best_effort) bypasses the outbox entirely — so for
-- ordinary requests, SCIM facts never reached audit at all.
--
-- Two typed columns close the gap on every recorder path:
-- BOOLEAN for active, TEXT[] for groups. Typed columns
-- (rather than a single JSONB) so:
-- 1. The chain hash (canonical_audit_bytes_with_scim) consumes
--    typed primitives — `write_opt_bool` + `write_str_vec` —
--    the same way every other audit column is hashed. No
--    JSON canonicalisation step that risks producer/verifier
--    drift.
-- 2. Reader code maps to the same `Option<bool>` /
--    `Vec<String>` shape the producer wrote; no serde
--    reconstruction round-trip.
--
-- Hash-chain compatibility: when the principal has no SCIM data
-- (`scim_active IS NULL AND scim_groups IS NULL/empty`),
-- `canonical_audit_bytes_with_scim` writes ZERO bytes to its
-- tail, so legacy rows hash byte-identically under the extended
-- function and the verifier continues to accept them. When SCIM
-- IS present, a sentinel byte + the typed bytes contribute;
-- any tamper (add / remove / flip) trips the chain walker.

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS scim_active BOOLEAN;

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS scim_groups TEXT[];

-- No indexes — query patterns over these columns haven't been
-- defined yet (PR8-e admin UI work will surface the access
-- pattern). Both columns are NULL on every legacy row so future
-- partial indexes are cheap to add.
