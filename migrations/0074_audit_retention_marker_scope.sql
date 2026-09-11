-- Retention markers are permanent chain bridges, so tenant marker history
-- grows without bound. Deletion authorization must expand only the exact
-- marker rows written by the current bounded batch, never all prior markers.
--
-- The legacy two-argument signature remains during rolling deploys but refuses
-- deletion. New binaries call the three-argument function with marker ids from
-- the same transaction. Its EXECUTE grants are copied from the legacy wrapper.

CREATE OR REPLACE FUNCTION audit_log_sweep_delete(p_tenant TEXT, p_ids UUID[])
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION
        'audit_log_sweep_delete: exact marker ids are required; upgrade the gateway replica';
END;
$$;

CREATE FUNCTION audit_log_sweep_delete(
    p_tenant TEXT,
    p_ids UUID[],
    p_marker_ids UUID[]
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    deleted_count BIGINT;
    covered_count INT;
    expected_count INT;
    marker_count INT;
BEGIN
    expected_count := COALESCE(array_length(p_ids, 1), 0);
    IF expected_count = 0 THEN
        RETURN 0;
    END IF;
    marker_count := COALESCE(array_length(p_marker_ids, 1), 0);
    IF expected_count > 500 OR marker_count = 0 OR marker_count > expected_count THEN
        RAISE EXCEPTION
            'audit_log_sweep_delete: bounded marker-coverage precondition violated: % ids and % markers',
            expected_count, marker_count;
    END IF;

    -- Every requested id must belong to the target tenant and be covered by a
    -- supplied chain-bearing retention marker. Chained rows are covered by row
    -- hash; unchained rows are covered by UUID plus chain sequence. The chain
    -- verifier remains responsible for validating marker hashes and links.
    SELECT COUNT(*) INTO covered_count
      FROM public.audit_log al
     WHERE al.id = ANY(p_ids)
       AND al.tenant_id = p_tenant
       AND EXISTS (
           SELECT 1
             FROM public.audit_log m
            WHERE m.id = ANY(p_marker_ids)
              AND m.tenant_id = p_tenant
              AND m.category = 'retention_sweep'
              AND m.reason IS NOT NULL
              AND m.row_hash IS NOT NULL
              AND (
                  (
                      al.row_hash IS NULL
                      AND EXISTS (
                          SELECT 1
                            FROM jsonb_array_elements(
                                COALESCE(
                                    m.reason::jsonb -> 'deleted_unchained_rows',
                                    '[]'::jsonb
                                )
                            ) AS deleted
                           WHERE deleted ->> 'id' = al.id::TEXT
                             AND deleted ->> 'chain_seq' = al.chain_seq::TEXT
                      )
                  )
                  OR (
                      al.row_hash IS NOT NULL
                      AND EXISTS (
                          SELECT 1
                            FROM jsonb_array_elements(
                                COALESCE(m.reason::jsonb -> 'deleted_rows', '[]'::jsonb)
                            ) AS deleted
                           WHERE deleted ->> 'row_hash' = al.row_hash
                      )
                  )
              )
       );
    IF covered_count <> expected_count THEN
        RAISE EXCEPTION
            'audit_log_sweep_delete: marker-coverage precondition violated: % of % ids covered by supplied chain-bearing retention markers',
            covered_count, expected_count;
    END IF;

    DELETE FROM public.audit_log
     WHERE tenant_id = p_tenant
       AND id = ANY(p_ids)
       AND (category IS NULL OR category <> 'retention_sweep');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

ALTER FUNCTION audit_log_sweep_delete(TEXT, UUID[], UUID[])
    OWNER TO audit_log_sweep_role;
REVOKE EXECUTE ON FUNCTION audit_log_sweep_delete(TEXT, UUID[], UUID[])
    FROM PUBLIC;

DO $$
DECLARE
    grantee_name TEXT;
BEGIN
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION audit_log_sweep_delete(TEXT, UUID[], UUID[]) TO %I',
        current_user
    );

    FOR grantee_name IN
        SELECT role.rolname
          FROM pg_proc proc
          CROSS JOIN LATERAL aclexplode(proc.proacl) acl
          JOIN pg_roles role ON role.oid = acl.grantee
         WHERE proc.oid = 'public.audit_log_sweep_delete(text,uuid[])'::regprocedure
           AND acl.privilege_type = 'EXECUTE'
    LOOP
        EXECUTE format(
            'GRANT EXECUTE ON FUNCTION audit_log_sweep_delete(TEXT, UUID[], UUID[]) TO %I',
            grantee_name
        );
    END LOOP;
END;
$$;
