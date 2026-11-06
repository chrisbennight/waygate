-- Argument values shown to the administrator while a held call is pending.
-- Credentials are redacted before storage. Deciding a request clears its
-- values, and expired values are cleared within a minute; only a pending
-- request may hold them.
ALTER TABLE pending_invocation_requests
    ADD COLUMN argument_values JSONB
        CHECK (argument_values IS NULL OR jsonb_typeof(argument_values) = 'object'),
    ADD CONSTRAINT pending_invocation_requests_values_pending
        CHECK (argument_values IS NULL OR status = 'pending');
CREATE INDEX pending_invocation_requests_values_expiry
    ON pending_invocation_requests (expires_at)
    WHERE argument_values IS NOT NULL;
