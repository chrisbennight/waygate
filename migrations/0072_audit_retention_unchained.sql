-- Retention applies to both hash-chained evidence and unchained best-effort
-- evidence. Chained rows require a chain-bearing retention marker that covers
-- their row hash. Unchained rows have no chain link to bridge, but the marker
-- records their ids so their deletion remains visible and pre-authorized.
--
-- The function remains SECURITY DEFINER, retains its pinned search_path, and
-- remains executable only by roles that already hold EXECUTE on the existing
-- function. Replacing its body does not change ownership or grants.

CREATE OR REPLACE FUNCTION audit_log_sweep_delete(p_tenant TEXT, p_ids UUID[])
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    deleted_count BIGINT;
    covered_count INT;
    expected_count INT;
BEGIN
    expected_count := COALESCE(array_length(p_ids, 1), 0);
    IF expected_count = 0 THEN
        RETURN 0;
    END IF;

    -- Every requested id must belong to the target tenant and be covered by a
    -- chain-bearing retention marker. Chained rows are covered by row hash;
    -- unchained rows are covered by UUID plus chain sequence. The chain verifier remains
    -- responsible for validating marker hashes and links when it walks the
    -- surviving chain.
    SELECT COUNT(*) INTO covered_count
      FROM public.audit_log al
     WHERE al.id = ANY(p_ids)
       AND al.tenant_id = p_tenant
       AND (
           (
               al.row_hash IS NULL
               AND EXISTS (
                   SELECT 1
                     FROM public.audit_log m
                     CROSS JOIN LATERAL jsonb_array_elements(
                         COALESCE(m.reason::jsonb -> 'deleted_unchained_rows', '[]'::jsonb)
                     ) AS deleted
                    WHERE m.tenant_id = p_tenant
                      AND m.category = 'retention_sweep'
                      AND m.reason IS NOT NULL
                      AND m.row_hash IS NOT NULL
                      AND deleted ->> 'id' = al.id::TEXT
                      AND deleted ->> 'chain_seq' = al.chain_seq::TEXT
               )
           )
           OR al.row_hash IN (
               SELECT jsonb_array_elements(m.reason::jsonb -> 'deleted_rows') ->> 'row_hash'
                 FROM public.audit_log m
                WHERE m.tenant_id = p_tenant
                  AND m.category = 'retention_sweep'
                  AND m.reason IS NOT NULL
                  AND m.row_hash IS NOT NULL
           )
       );
    IF covered_count <> expected_count THEN
        RAISE EXCEPTION
            'audit_log_sweep_delete: marker-coverage precondition violated: % of % ids covered by chain-bearing retention markers',
            covered_count, expected_count;
    END IF;

    -- Retention markers are permanent chain bridges. NULL-category rows are
    -- legacy best-effort evidence and remain eligible for wildcard retention.
    DELETE FROM public.audit_log
     WHERE tenant_id = p_tenant
       AND id = ANY(p_ids)
       AND (category IS NULL OR category <> 'retention_sweep');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;
