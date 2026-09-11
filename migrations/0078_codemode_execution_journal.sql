-- Durable Code Mode execution truth is separate from the client-facing MCP
-- Tasks projection. The execution row is the current projection; the event
-- rows are the append-only history used for recovery, attribution, and
-- operator evidence.

CREATE TABLE codemode_executions (
    id                      UUID PRIMARY KEY,
    tenant_id               TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub           TEXT NOT NULL,
    source                  TEXT NOT NULL,
    source_digest           TEXT NOT NULL,
    execution_profile       JSONB NOT NULL,
    tool_snapshot           JSONB,
    sdk_contract_version    INTEGER NOT NULL,
    runner_contract_version INTEGER NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN (
        'submitted',
        'admitted',
        'running',
        'waiting_for_approval',
        'waiting_for_resume',
        'compensating',
        'compensated',
        'succeeded',
        'failed',
        'cancelled',
        'expired',
        'ambiguous',
        'reconciled_applied',
        'reconciled_not_applied'
    )),
    terminal_reason_code    TEXT,
    -- Outcome metadata only. Tool-result content requires a separate
    -- information-flow persistence decision and is not stored by this profile.
    result_metadata         JSONB,
    claim_owner             UUID,
    claim_epoch             BIGINT NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    claim_expires_at        TIMESTAMPTZ,
    cancellation_requested_at TIMESTAMPTZ,
    submitted_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ,
    retention_until         TIMESTAMPTZ NOT NULL,
    UNIQUE (id, tenant_id),
    CHECK ((claim_owner IS NULL) = (claim_expires_at IS NULL)),
    CHECK (
        (
            status IN (
                'compensated',
                'succeeded',
                'failed',
                'cancelled',
                'expired',
                'reconciled_applied',
                'reconciled_not_applied'
            )
        ) = (completed_at IS NOT NULL)
    ),
    CHECK (
        status NOT IN ('failed', 'cancelled', 'expired', 'ambiguous')
        OR terminal_reason_code IS NOT NULL
    )
);

CREATE INDEX codemode_executions_by_owner
    ON codemode_executions (tenant_id, principal_sub, submitted_at DESC, id);

CREATE INDEX codemode_executions_in_flight
    ON codemode_executions (tenant_id, status, updated_at, id)
    WHERE status IN (
        'submitted',
        'admitted',
        'running',
        'waiting_for_approval',
        'waiting_for_resume',
        'compensating',
        'ambiguous'
    );

CREATE INDEX codemode_executions_expired_claim
    ON codemode_executions (claim_expires_at, id)
    WHERE claim_owner IS NOT NULL;

CREATE TRIGGER codemode_executions_touch_updated_at_trg
    BEFORE UPDATE ON codemode_executions
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

CREATE TABLE codemode_execution_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    execution_id    UUID NOT NULL,
    tenant_id       TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind <> ''),
    step_number     INTEGER CHECK (step_number > 0),
    call_id         UUID,
    attempt         INTEGER CHECK (attempt > 0),
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (execution_id, tenant_id)
        REFERENCES codemode_executions(id, tenant_id)
        ON DELETE CASCADE
);

CREATE INDEX codemode_execution_events_history
    ON codemode_execution_events (tenant_id, execution_id, id);

CREATE OR REPLACE FUNCTION codemode_execution_events_append_only()
RETURNS TRIGGER AS $$
BEGIN
    -- Retention deletes the parent execution and its event history in one
    -- transaction. The worker must opt in transaction-locally; ordinary
    -- application UPDATE/DELETE statements remain rejected.
    IF TG_OP = 'DELETE'
       AND current_setting('app.codemode_retention_delete', true) = 'enabled' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION
        'codemode_execution_events is append-only; UPDATE/DELETE denied';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER codemode_execution_events_append_only_trg
    BEFORE UPDATE OR DELETE ON codemode_execution_events
    FOR EACH ROW
    EXECUTE FUNCTION codemode_execution_events_append_only();
