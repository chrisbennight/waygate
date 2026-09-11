-- Statement-level protection complements the row-level append-only trigger.
-- Retention removes parent executions with guarded cascaded DELETEs; it never
-- needs unrestricted table truncation.
CREATE OR REPLACE FUNCTION codemode_execution_events_reject_truncate()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'codemode_execution_events is append-only; TRUNCATE denied';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER codemode_execution_events_no_truncate_trg
    BEFORE TRUNCATE ON codemode_execution_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION codemode_execution_events_reject_truncate();
