-- A cancellation request records which authority made it, because the row
-- may terminalize later than the request: a live worker claim keeps its
-- lease and finalizes the cancellation at its next journal boundary, at
-- which point the requester is no longer on the call path. Without durable
-- provenance that finalization could only guess, and an operator
-- intervention on a running execution would be misreported as the owner's
-- own cancellation. The first request wins — a second requester never
-- rewrites who caused the cancellation already in progress. Rows whose
-- request predates this column finalize under the historical
-- `cancelled_by_client` reason.
ALTER TABLE codemode_executions
    ADD COLUMN cancellation_reason_code TEXT
    CHECK (cancellation_reason_code IN ('cancelled_by_client', 'cancelled_by_operator'));
