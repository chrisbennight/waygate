-- Detached starts carry a gateway-derived key so retries can converge without
-- relying on a caller-generated idempotency token. Ordinary synchronous
-- executions remain NULL and are never candidates for detached-start reuse.
-- The key is a fixed-width digest of the full identity, so this index's rows
-- stay bounded no matter how long the identity claims are; the remaining
-- identity columns are compared against the table row, not the index.
ALTER TABLE codemode_executions
    ADD COLUMN start_dedupe_key TEXT
    CHECK (start_dedupe_key IS NULL OR start_dedupe_key <> '');

CREATE INDEX codemode_executions_retry_safe_start
    ON codemode_executions (
        tenant_id, start_dedupe_key, submitted_at DESC, id DESC
    )
    WHERE start_dedupe_key IS NOT NULL;
