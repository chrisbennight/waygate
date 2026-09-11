-- Issuer-scoped continuation ownership: two accepted issuers may mint the
-- same `sub` for different people, so ownership of a continuation anchor
-- (an approval grant, a Code Mode execution) must bind
-- tenant + issuer + subject, not tenant + subject alone.
--
-- Nullable on purpose, with NO backfill: rows created before this upgrade
-- carry no trustworthy issuer, so the read/claim paths require an exact
-- issuer match (a NULL row never matches) — pre-upgrade rows fail closed
-- at every owner-gated surface and age out on their existing
-- expiry/retention clocks. The write paths always populate the column.

ALTER TABLE approval_grants
    ADD COLUMN principal_issuer TEXT;

ALTER TABLE codemode_executions
    ADD COLUMN principal_issuer TEXT;
