-- The application role can request a retention cascade, but it must not gain
-- direct DELETE authority over individual history rows. A foreign-key cascade
-- invokes the child trigger beneath the parent-delete trigger; a direct child
-- DELETE remains at the outermost trigger depth.
CREATE OR REPLACE FUNCTION codemode_execution_events_append_only()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND pg_trigger_depth() > 1
       AND current_setting('app.codemode_retention_delete', true) = 'enabled' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION
        'codemode_execution_events is append-only; UPDATE/DELETE denied';
END;
$$ LANGUAGE plpgsql;
