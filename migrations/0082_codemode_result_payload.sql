-- Result content is stored only when the operator explicitly enables the
-- Code Mode result-storage policy. The default execution profile continues to
-- persist non-content outcome metadata only.

ALTER TABLE codemode_executions
    ADD COLUMN result_payload JSONB;
