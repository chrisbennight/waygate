-- Retention marker rows are permanent, but chain verification only needs the
-- marker paths that bridge gaps in its bounded row window. This append-only
-- index maps a marker's first deleted-row predecessor hash to its last deleted
-- row hash so verification can follow those paths without parsing every marker
-- ever written for the tenant.
--
-- The index is a locator, not an integrity authority. The verifier still loads
-- each selected audit_log row, recomputes its row hash, validates the complete
-- marker payload, checks both indexed boundaries against that payload, and
-- admits the bridge only when the marker's own chain link is authenticated.

CREATE TABLE audit_retention_bridge_index (
    marker_id  UUID PRIMARY KEY REFERENCES audit_log(id) ON DELETE RESTRICT,
    tenant_id  TEXT NOT NULL,
    start_hash TEXT,
    start_key  TEXT GENERATED ALWAYS AS (
        CASE
            WHEN start_hash IS NULL THEN 'null'
            ELSE 'hash:' || start_hash
        END
    ) STORED,
    end_hash   TEXT NOT NULL
);

CREATE UNIQUE INDEX audit_retention_bridge_start_idx
    ON audit_retention_bridge_index (tenant_id, start_key);

ALTER TABLE audit_retention_bridge_index OWNER TO audit_log_sweep_role;
REVOKE ALL ON TABLE audit_retention_bridge_index FROM PUBLIC;

-- Only server-side database code can populate the locator. Boundary values are
-- derived from the immutable marker payload inside this SECURITY DEFINER
-- function instead of being accepted from the caller.
CREATE FUNCTION audit_retention_bridge_index_marker(p_marker_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    marker_tenant TEXT;
    marker_reason JSONB;
    deleted_rows JSONB;
    start_hash TEXT;
    end_hash TEXT;
BEGIN
    SELECT tenant_id, reason::JSONB
      INTO STRICT marker_tenant, marker_reason
      FROM public.audit_log
     WHERE id = p_marker_id
       AND category = 'retention_sweep'
       AND row_hash IS NOT NULL
       AND reason IS NOT NULL;

    IF marker_reason ->> 'kind' <> 'retention_sweep' THEN
        RAISE EXCEPTION 'retention bridge index: marker kind is invalid';
    END IF;

    deleted_rows := marker_reason -> 'deleted_rows';
    IF jsonb_typeof(deleted_rows) <> 'array' THEN
        RAISE EXCEPTION 'retention bridge index: deleted_rows must be an array';
    END IF;
    IF jsonb_array_length(deleted_rows) = 0 THEN
        RETURN FALSE;
    END IF;

    start_hash := deleted_rows -> 0 ->> 'prev_hash';
    end_hash := deleted_rows -> (jsonb_array_length(deleted_rows) - 1) ->> 'row_hash';
    IF end_hash IS NULL OR end_hash = '' THEN
        RAISE EXCEPTION 'retention bridge index: final row_hash is required';
    END IF;

    INSERT INTO public.audit_retention_bridge_index
        (marker_id, tenant_id, start_hash, end_hash)
    VALUES
        (p_marker_id, marker_tenant, start_hash, end_hash)
    ON CONFLICT (marker_id) DO NOTHING;

    RETURN TRUE;
END;
$$;

-- Rolling deployments can leave an old replica writing markers after this
-- migration's backfill but before that replica is replaced. Index every future
-- marker at the database boundary so old and new writers share the invariant.
-- Malformed unrelated audit rows remain inert; the new writer also calls the
-- strict function explicitly, so a malformed marker it creates aborts its TX.
CREATE FUNCTION audit_retention_bridge_index_after_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.category = 'retention_sweep'
       AND NEW.row_hash IS NOT NULL
       AND NEW.reason IS NOT NULL
    THEN
        BEGIN
            PERFORM public.audit_retention_bridge_index_marker(NEW.id);
        EXCEPTION
            WHEN invalid_text_representation OR raise_exception THEN
                RAISE WARNING
                    'retention bridge trigger skipped invalid marker %',
                    NEW.id;
        END;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_retention_bridge_index_after_insert
AFTER INSERT ON audit_log
FOR EACH ROW
EXECUTE FUNCTION audit_retention_bridge_index_after_insert();

-- Existing permanent markers must be available to the new lookup immediately
-- after the migration commits. Reuse the same server-side derivation as the
-- runtime write path so historical and new locator rows have identical checks.
DO $$
DECLARE
    historical_marker_id UUID;
BEGIN
    FOR historical_marker_id IN
        SELECT id
          FROM public.audit_log
         WHERE category = 'retention_sweep'
           AND row_hash IS NOT NULL
           AND reason IS NOT NULL
         ORDER BY chain_seq ASC
    LOOP
        BEGIN
            PERFORM public.audit_retention_bridge_index_marker(historical_marker_id);
        EXCEPTION
            WHEN invalid_text_representation OR raise_exception THEN
                -- An invalid historical marker is not an integrity authority.
                -- Leave it unindexed so verification fails closed if a gap
                -- depends on it, while allowing unrelated malformed history
                -- to remain inert as it was before this migration.
                RAISE WARNING
                    'retention bridge backfill skipped invalid marker %',
                    historical_marker_id;
        END;
    END LOOP;
END;
$$;

ALTER FUNCTION audit_retention_bridge_index_marker(UUID)
    OWNER TO audit_log_sweep_role;
ALTER FUNCTION audit_retention_bridge_index_after_insert()
    OWNER TO audit_log_sweep_role;
REVOKE EXECUTE ON FUNCTION audit_retention_bridge_index_marker(UUID)
    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION audit_retention_bridge_index_after_insert()
    FROM PUBLIC;

-- The migration role is the runtime role in the standard deployment. Copy
-- split runtime roles already authorized for exact-marker retention deletion.
DO $$
DECLARE
    grantee_name TEXT;
BEGIN
    EXECUTE format(
        'GRANT SELECT ON TABLE audit_retention_bridge_index TO %I',
        current_user
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION audit_retention_bridge_index_marker(UUID) TO %I',
        current_user
    );

    FOR grantee_name IN
        SELECT DISTINCT role.rolname
          FROM pg_proc proc
          CROSS JOIN LATERAL aclexplode(proc.proacl) acl
          JOIN pg_roles role ON role.oid = acl.grantee
         WHERE proc.oid =
               'public.audit_log_sweep_delete(text,uuid[],uuid[])'::regprocedure
           AND acl.privilege_type = 'EXECUTE'
    LOOP
        EXECUTE format(
            'GRANT SELECT ON TABLE audit_retention_bridge_index TO %I',
            grantee_name
        );
        EXECUTE format(
            'GRANT EXECUTE ON FUNCTION audit_retention_bridge_index_marker(UUID) TO %I',
            grantee_name
        );
    END LOOP;
END;
$$;
