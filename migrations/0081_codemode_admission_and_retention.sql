-- Pre-admission records retain compact attribution without copying program
-- source into the control database. Claiming admitted work attaches the source
-- atomically with its immutable tool snapshot and worker fence.
ALTER TABLE codemode_executions
    ALTER COLUMN source DROP NOT NULL;

-- Submissions opportunistically remove bounded batches of completed executions
-- whose retention horizon elapsed. In-flight work is never swept.
CREATE INDEX codemode_executions_retention
    ON codemode_executions (retention_until, id)
    WHERE completed_at IS NOT NULL;
