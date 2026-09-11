-- HITL control-plane: distinct-approver ledger for multi-approver
-- (required_approvals > 1) change requests.
--
-- The single-approver path stays the atomic single-UPDATE in `try_approve`
-- (no row here). This table collects the N distinct approvals an M-of-N
-- change needs before `record_approval` flips it `pending -> approved`.
--
-- One row per (change request, approver): the UNIQUE constraint makes a
-- repeat approval by the same human a no-op (the insert is ON CONFLICT DO
-- NOTHING), so a double-click can't inflate the tally toward quorum.
-- Four-eyes (the maker can't approve) is enforced by the handler AND
-- re-guarded by the `requested_by <> approver` predicate on the
-- pending->approved flip, so a maker's sub never completes a quorum.
CREATE TABLE IF NOT EXISTS change_request_approvals (
    id                UUID        PRIMARY KEY,
    -- Cascade-delete with the parent change request so a removed/expired
    -- change can't leave orphaned approval rows behind.
    change_request_id UUID        NOT NULL REFERENCES change_requests(id) ON DELETE CASCADE,
    -- Denormalised for tenant-scoped queries, mirroring the other stores.
    tenant_id         TEXT        NOT NULL,
    approver_sub      TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (change_request_id, approver_sub)
);

CREATE INDEX IF NOT EXISTS change_request_approvals_by_cr
    ON change_request_approvals (change_request_id);
