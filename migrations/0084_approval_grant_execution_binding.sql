-- Code Mode mutation approvals bind one grant to one durable execution and
-- one stable connector call. Ordinary direct-call grants leave all three
-- columns NULL; the all-or-nothing constraint prevents a partially scoped
-- grant from weakening either lookup path.

ALTER TABLE approval_grants
    ADD COLUMN execution_id UUID,
    ADD COLUMN source_digest TEXT,
    ADD COLUMN call_id UUID,
    ADD CONSTRAINT approval_grants_execution_binding_complete
        CHECK (
            (execution_id IS NULL AND source_digest IS NULL AND call_id IS NULL)
            OR
            (
                execution_id IS NOT NULL
                AND source_digest IS NOT NULL
                AND source_digest <> ''
                AND call_id IS NOT NULL
            )
        );

CREATE INDEX approval_grants_execution_lookup_idx
    ON approval_grants (
        tenant_id,
        principal_sub,
        execution_id,
        call_id,
        tool_id,
        argument_hash
    )
    WHERE execution_id IS NOT NULL AND consumed_at IS NULL;
