-- AERB PR #163 round 9 medium (security): close the race
-- window in `delete_profile`'s separate count + delete by
-- enforcing the live-key-reference check inside a BEFORE
-- DELETE trigger.
--
-- Background:
--
-- The DELETE handler at `gateway-admin::api_key_profiles::
-- delete_profile` originally:
--   1. SELECT COUNT(*) FROM api_keys WHERE profile_id = $
--      AND not revoked AND not expired  → if > 0, refuse.
--   2. DELETE FROM api_key_profiles WHERE id = $.
--
-- Two gaps:
--   - The two statements are not atomic. A concurrent mint
--     that lands after step 1 but before step 2 commits is
--     invisible to the count yet its INSERT into api_keys
--     succeeded; our DELETE then fires the
--     `ON DELETE SET NULL` cascade and strips the new key's
--     allowed_servers/allowed_tools enforcement.
--   - The handler-side guard was conditional on
--     `state.api_keys` being wired (which only happens when
--     API-key auth is enabled), but the DELETE handler is
--     exposed whenever the profile store is wired. Deployment
--     with profiles configured but API-key auth disabled
--     would skip the guard entirely.
--
-- A BEFORE DELETE trigger closes both gaps: it runs inside
-- the same transaction as the DELETE, after the row-level
-- EXCLUSIVE lock on api_key_profiles is acquired. Concurrent
-- mints take a SHARE lock on the referenced profile row via
-- the FK, so they either commit before our DELETE acquires
-- EXCLUSIVE (the count then sees them) or wait until after
-- our DELETE commits (FK violation against the now-gone
-- profile). The trigger is database-level, so the guard
-- applies regardless of whether the calling crate wired up
-- the api_keys store.
--
-- Tenant DELETE cascade path is unaffected:
-- `gateway-admin::tenants::cleanup_onboarding_residue` calls
-- `revoke_all_for_tenant` BEFORE `delete_all_for_tenant`,
-- so by the time the bulk-delete on api_key_profiles runs
-- every api_keys row for the tenant has revoked_at set and
-- the trigger's live-count is 0.
--
-- The trigger raises SQLSTATE 'P0001' (raise_exception, the
-- default for plpgsql RAISE EXCEPTION without USING) with a
-- detail message of the form "blocked: N live api_keys still
-- reference this profile". The PgProfileStore::delete impl
-- parses the count out of the message and maps to a typed
-- ProfileStoreError::Blocked variant the admin handler
-- surfaces as HTTP 409.

CREATE OR REPLACE FUNCTION api_key_profiles_block_delete_if_referenced()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    n bigint;
BEGIN
    SELECT COUNT(*) INTO n
      FROM api_keys
     WHERE profile_id = OLD.id
       AND tenant_id = OLD.tenant_id
       AND revoked_at IS NULL
       AND (expires_at IS NULL OR expires_at > now());
    IF n > 0 THEN
        RAISE EXCEPTION 'blocked: % live api_keys still reference this profile', n;
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER api_key_profiles_block_delete_if_referenced
BEFORE DELETE ON api_key_profiles
FOR EACH ROW
EXECUTE FUNCTION api_key_profiles_block_delete_if_referenced();
