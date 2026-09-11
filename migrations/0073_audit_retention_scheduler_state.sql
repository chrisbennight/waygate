-- The retention scheduler runs on every gateway replica, but the bounded
-- per-policy work budget is fleet-wide. A durable singleton claim prevents
-- independently phased replicas from each consuming that budget during the
-- same cadence.
--
-- The gateway can only call the SECURITY DEFINER claim function. The state
-- table is owned by the existing non-login retention role and is not exposed
-- to PUBLIC. The function advances next_eligible_at atomically before sweep
-- work starts. A crashed claimant can defer work until the next cadence, but
-- cannot multiply database pressure.

CREATE TABLE audit_retention_scheduler_state (
    singleton        BOOLEAN PRIMARY KEY DEFAULT TRUE,
    next_eligible_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT audit_retention_scheduler_state_singleton CHECK (singleton)
);

ALTER TABLE audit_retention_scheduler_state OWNER TO audit_log_sweep_role;
REVOKE ALL ON TABLE audit_retention_scheduler_state FROM PUBLIC;

CREATE FUNCTION audit_retention_scheduler_claim(p_interval_seconds BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    claim_time TIMESTAMPTZ := clock_timestamp();
    claimed BOOLEAN;
BEGIN
    IF p_interval_seconds <= 0 THEN
        RAISE EXCEPTION 'retention scheduler interval must be positive';
    END IF;

    INSERT INTO public.audit_retention_scheduler_state
        (singleton, next_eligible_at)
    VALUES
        (TRUE, claim_time + make_interval(secs => p_interval_seconds::DOUBLE PRECISION))
    ON CONFLICT (singleton) DO UPDATE
       SET next_eligible_at = EXCLUDED.next_eligible_at
     WHERE public.audit_retention_scheduler_state.next_eligible_at <= claim_time
    RETURNING TRUE INTO claimed;

    RETURN COALESCE(claimed, FALSE);
END;
$$;

ALTER FUNCTION audit_retention_scheduler_claim(BIGINT) OWNER TO audit_log_sweep_role;
REVOKE EXECUTE ON FUNCTION audit_retention_scheduler_claim(BIGINT) FROM PUBLIC;

-- The migration user is the runtime user in the standard deployment. Copy any
-- additional roles already authorized to execute the retention-delete wrapper
-- so split migration/runtime-role deployments inherit the new claim privilege.
DO $$
DECLARE
    grantee_name TEXT;
BEGIN
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION audit_retention_scheduler_claim(BIGINT) TO %I',
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
            'GRANT EXECUTE ON FUNCTION audit_retention_scheduler_claim(BIGINT) TO %I',
            grantee_name
        );
    END LOOP;
END;
$$;
