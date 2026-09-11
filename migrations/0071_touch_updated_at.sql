-- 0071: one generic `touch_updated_at()` trigger function (Tier 2 WS10-B).
--
-- Fourteen tables carried a BEFORE UPDATE trigger bumping `updated_at`;
-- twelve of them defined their own byte-identical `<table>_touch_updated_at()`
-- copy (scopes and scim_groups already reused `scim_users_touch_updated_at`).
-- This migration installs the single shared function, repoints all fourteen
-- triggers at it (same trigger names), and drops the twelve per-table copies.
-- Shipped migrations are immutable, so this is a new migration, not an edit
-- (docs/agents/migrations.md).
--
-- No behavior change: every function body was exactly
-- `NEW.updated_at = now(); RETURN NEW;`.
--
-- New tables wanting an `updated_at` bump should EXECUTE FUNCTION
-- touch_updated_at() — never mint another per-table copy.

CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Repoint the fourteen triggers. DROP + CREATE (not OR REPLACE) so a
-- missing trigger fails loudly instead of silently diverging from the
-- inventory this migration was written against.

DROP TRIGGER scim_users_touch_updated_at_trg ON scim_users;
CREATE TRIGGER scim_users_touch_updated_at_trg
    BEFORE UPDATE ON scim_users
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER scim_groups_touch_updated_at_trg ON scim_groups;
CREATE TRIGGER scim_groups_touch_updated_at_trg
    BEFORE UPDATE ON scim_groups
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER gateway_roles_touch_updated_at_trg ON gateway_roles;
CREATE TRIGGER gateway_roles_touch_updated_at_trg
    BEFORE UPDATE ON gateway_roles
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER tenants_touch_updated_at_trg ON tenants;
CREATE TRIGGER tenants_touch_updated_at_trg
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER rate_limit_policies_touch_updated_at_trg ON rate_limit_policies;
CREATE TRIGGER rate_limit_policies_touch_updated_at_trg
    BEFORE UPDATE ON rate_limit_policies
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER api_key_profiles_touch_updated_at_trg ON api_key_profiles;
CREATE TRIGGER api_key_profiles_touch_updated_at_trg
    BEFORE UPDATE ON api_key_profiles
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER task_states_touch_updated_at_trg ON task_states;
CREATE TRIGGER task_states_touch_updated_at_trg
    BEFORE UPDATE ON task_states
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER inspection_rules_touch_updated_at_trg ON inspection_rules;
CREATE TRIGGER inspection_rules_touch_updated_at_trg
    BEFORE UPDATE ON inspection_rules
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER federated_peers_touch_updated_at_trg ON federated_peers;
CREATE TRIGGER federated_peers_touch_updated_at_trg
    BEFORE UPDATE ON federated_peers
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER playground_scenarios_touch_updated_at_trg ON playground_scenarios;
CREATE TRIGGER playground_scenarios_touch_updated_at_trg
    BEFORE UPDATE ON playground_scenarios
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER activity_saved_views_touch_updated_at_trg ON activity_saved_views;
CREATE TRIGGER activity_saved_views_touch_updated_at_trg
    BEFORE UPDATE ON activity_saved_views
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER scopes_touch_updated_at_trg ON scopes;
CREATE TRIGGER scopes_touch_updated_at_trg
    BEFORE UPDATE ON scopes
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER agent_configs_touch_updated_at_trg ON agent_configs;
CREATE TRIGGER agent_configs_touch_updated_at_trg
    BEFORE UPDATE ON agent_configs
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER agent_conversations_touch_updated_at_trg ON agent_conversations;
CREATE TRIGGER agent_conversations_touch_updated_at_trg
    BEFORE UPDATE ON agent_conversations
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

-- Drop the twelve per-table copies. Plain DROP FUNCTION (no IF EXISTS):
-- if a trigger still depends on one, or a name is wrong, the migration
-- fails instead of leaving a stray copy behind.
-- (agent_conversations_bump_on_message stays — it bumps the *parent*
-- conversation row from the messages table, a different contract.)

DROP FUNCTION scim_users_touch_updated_at();
DROP FUNCTION gateway_roles_touch_updated_at();
DROP FUNCTION tenants_touch_updated_at();
DROP FUNCTION rate_limit_policies_touch_updated_at();
DROP FUNCTION api_key_profiles_touch_updated_at();
DROP FUNCTION task_states_touch_updated_at();
DROP FUNCTION inspection_rules_touch_updated_at();
DROP FUNCTION federated_peers_touch_updated_at();
DROP FUNCTION playground_scenarios_touch_updated_at();
DROP FUNCTION activity_saved_views_touch_updated_at();
DROP FUNCTION agent_configs_touch_updated_at();
DROP FUNCTION agent_conversations_touch_updated_at();
