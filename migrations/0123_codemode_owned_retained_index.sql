-- Listing a principal's retained Code Mode executions, finished ones
-- included, filters on the full owner identity, retention, and the exclusion
-- of background tool-call rows. The owned in-flight index covers only
-- unfinished rows, and the general owner index keys neither the issuer nor
-- the confinement, so without this index a small page could scan every
-- retained row of the subject, including rows under other confinements and
-- tool-call rows the listing never returns.
--
-- The key matches the owned in-flight index: one fixed-width digest of the
-- owner triple (subject, issuer, confinement), then the listing order. The
-- digest keeps index tuples bounded however large the identity grows, and
-- SQL NULL in the issuer or confinement nulls it, so such rows match no
-- caller. Tool-call rows are left out of the index entirely. The listing
-- repeats the digest expression and the tool-call predicate verbatim so the
-- planner can use this index; exact equality against the row remains the
-- correctness filter, so a digest collision can widen the scan but never the
-- result.
CREATE INDEX codemode_executions_owned_retained
    ON codemode_executions (
        tenant_id,
        (md5(principal_sub || chr(31) || principal_issuer || chr(31)
             || (execution_profile -> 'profile_confinement')::text)),
        submitted_at DESC,
        id DESC
    )
    WHERE execution_profile ->> 'name' IS DISTINCT FROM 'tool_call';
