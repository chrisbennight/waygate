-- Preserve the parent execution, ordered step, stable nested call, and attempt
-- for every orchestrated invocation. Direct MCP calls leave all four columns
-- NULL. The all-or-none constraint prevents ambiguous partial attribution.

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS parent_execution_id UUID,
    ADD COLUMN IF NOT EXISTS execution_step BIGINT,
    ADD COLUMN IF NOT EXISTS execution_call_id UUID,
    ADD COLUMN IF NOT EXISTS execution_attempt BIGINT,
    ADD CONSTRAINT audit_log_invocation_hierarchy_complete
        CHECK (
            num_nonnulls(
                parent_execution_id,
                execution_step,
                execution_call_id,
                execution_attempt
            ) IN (0, 4)
        ) NOT VALID,
    ADD CONSTRAINT audit_log_execution_step_range
        CHECK (
            execution_step IS NULL
            OR execution_step BETWEEN 1 AND 4294967295
        ) NOT VALID,
    ADD CONSTRAINT audit_log_execution_attempt_range
        CHECK (
            execution_attempt IS NULL
            OR execution_attempt BETWEEN 1 AND 4294967295
        ) NOT VALID;

-- New writes are checked as soon as each constraint is installed. Historical
-- rows are validated without blocking concurrent inserts into the audit log.
ALTER TABLE audit_log
    VALIDATE CONSTRAINT audit_log_invocation_hierarchy_complete,
    VALIDATE CONSTRAINT audit_log_execution_step_range,
    VALIDATE CONSTRAINT audit_log_execution_attempt_range;
