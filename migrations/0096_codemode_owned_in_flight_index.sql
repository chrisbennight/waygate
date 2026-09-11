-- Listing a principal's in-flight executions filters on the full owner
-- identity — subject, issuer, and the effective-profile confinement — plus
-- liveness, but the generic owner index keys neither the issuer nor
-- completion, so filling or refusing a small page could scan a principal's
-- entire retained history of terminal rows, and paused work released from
-- the detached slot can accumulate live rows under other confinements.
--
-- The owner identity enters the key as one fixed-width digest, never as raw
-- values: the confinement JSON embeds a profile's server/tool allowlists,
-- which no validation bounds, and identity claims carry no schema length
-- limit either, while a B-tree rejects tuples above roughly a third of a
-- page — a large valid value in the key would break this migration or every
-- later insert for that principal. The digest keys the whole triple
-- (subject, issuer, confinement) with unambiguous separators, so the tuple
-- stays bounded no matter how large the identity grows. The listing pairs
-- the digest predicate (which must match this expression verbatim for the
-- planner to use it) with exact equality against the table row, so a digest
-- collision can widen the scan but never the result. SQL NULL — a
-- pre-upgrade issuer-less row or a profile without the confinement key —
-- nulls the whole digest and matches no caller, exactly as the by-id read
-- fails closed on those rows. The listing orders by
-- (submitted_at DESC, id DESC); the index carries that order after the
-- equality columns.
CREATE INDEX codemode_executions_owned_in_flight
    ON codemode_executions (
        tenant_id,
        (md5(principal_sub || chr(31) || principal_issuer || chr(31)
             || (execution_profile -> 'profile_confinement')::text)),
        submitted_at DESC,
        id DESC
    )
    WHERE completed_at IS NULL;

-- The retention sweep also reaps expired rows that never completed (an
-- abandoned submission, a dead-claim attempt). The 0081 retention index
-- covers only completed rows, so without a live counterpart that arm of
-- the sweep would scan the table on every submission. Same key shape as
-- 0081, opposite partial predicate; the sweep's claim-liveness conditions
-- filter the few retention-expired rows this index yields.
CREATE INDEX codemode_executions_abandoned_retention
    ON codemode_executions (retention_until, id)
    WHERE completed_at IS NULL;
