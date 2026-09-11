-- A resumable execution releases its runner and claim while retaining only the
-- bounded checkpoint needed to start a fresh attempt. Once input is supplied,
-- the same document binds that input durably so a crashed read-only attempt can
-- be retried without silently changing what the client provided.

ALTER TABLE codemode_executions
    ADD COLUMN resume_context JSONB;
