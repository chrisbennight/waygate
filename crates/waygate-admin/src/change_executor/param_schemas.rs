//! The advertised params schema for every proposable action.
//!
//! Split from the registry module so the executor plumbing and this pure
//! `action_type` -> schema table can each grow without crowding the other.
//! `action_catalog_keys_match_registry` fails if the two ever diverge.

use super::*;

/// The single place mapping each proposable `action_type` to the params type
/// its executor deserializes. Kept beside [`builtin_executors`] so adding an
/// action updates both together; `action_catalog_keys_match_registry` fails
/// if the two ever diverge. Each schema is generated from the EXACT type the
/// executor parses, so it reflects the real accepted shape.
pub(super) fn action_param_schemas() -> Vec<(&'static str, Value)> {
    let schemas = api_key_profiles::append_param_schemas(vec![
        (
            "agent_config.create",
            params_schema_of::<crate::agent_configs::AgentConfigInput>(),
        ),
        (
            "agent_config.update",
            params_schema_of::<AgentConfigUpdateParams>(),
        ),
        (
            "agent_config.delete",
            params_schema_of::<AgentConfigDeleteParams>(),
        ),
        (
            "rate_limit.update",
            params_schema_of::<RateLimitUpdateParams>(),
        ),
        (
            "rate_limit.create",
            params_schema_of::<CreatePolicyRequest>(),
        ),
        (
            "rate_limit.delete",
            params_schema_of::<RateLimitDeleteParams>(),
        ),
        (
            "inspection_rule.delete",
            params_schema_of::<InspectionRuleDeleteParams>(),
        ),
        (
            "oauth_consent.revoke",
            params_schema_of::<OAuthConsentRevokeParams>(),
        ),
        ("peer.create", params_schema_of::<CreatePeerRequest>()),
        ("peer.update", params_schema_of::<PeerUpdateParams>()),
        ("peer.delete", params_schema_of::<PeerDeleteParams>()),
        ("rbac.role.create", params_schema_of::<CreateRoleRequest>()),
        (
            "rbac.role.update",
            params_schema_of::<RbacRoleUpdateParams>(),
        ),
        (
            "rbac.role.delete",
            params_schema_of::<RbacRoleDeleteParams>(),
        ),
        (
            "rbac.assignment.grant",
            params_schema_of::<RbacAssignmentGrantParams>(),
        ),
        (
            "rbac.assignment.grant_privileged",
            params_schema_of::<RbacAssignmentGrantParams>(),
        ),
        (
            "rbac.assignment.revoke",
            params_schema_of::<RbacAssignmentRevokeParams>(),
        ),
        (
            "rbac.assignment.revoke_privileged",
            params_schema_of::<RbacAssignmentRevokeParams>(),
        ),
        (
            "rbac.group_mapping.grant",
            params_schema_of::<RbacGroupMappingParams>(),
        ),
        (
            "rbac.group_mapping.grant_privileged",
            params_schema_of::<RbacGroupMappingParams>(),
        ),
        (
            "rbac.group_mapping.revoke",
            params_schema_of::<RbacGroupMappingParams>(),
        ),
        (
            "rbac.group_mapping.revoke_privileged",
            params_schema_of::<RbacGroupMappingParams>(),
        ),
        ("tenant.update", params_schema_of::<TenantUpdateParams>()),
        (
            "audit.retention.set",
            params_schema_of::<AuditRetentionSetParams>(),
        ),
        (
            "audit.retention.clear",
            params_schema_of::<AuditRetentionClearParams>(),
        ),
        (
            "audit.routing.set",
            params_schema_of::<AuditRoutingSetParams>(),
        ),
        (
            "audit.routing.clear",
            params_schema_of::<AuditRoutingClearParams>(),
        ),
        (
            "upstream_session.revoke",
            params_schema_of::<UpstreamSessionRevokeParams>(),
        ),
        ("break_glass.mint", params_schema_of::<MintRequest>()),
        (
            "break_glass.revoke",
            params_schema_of::<BreakGlassRevokeParams>(),
        ),
        ("api_key.mint", params_schema_of::<ApiKeyMintParams>()),
        ("api_key.revoke", params_schema_of::<ApiKeyRevokeParams>()),
        (
            "api_key.update_grants",
            params_schema_of::<ApiKeyUpdateGrantsParams>(),
        ),
        ("policy.publish", params_schema_of::<PolicyPublishParams>()),
        (
            "policy.rollback",
            params_schema_of::<PolicyRollbackParams>(),
        ),
        (
            "policy.upsert_fragment",
            params_schema_of::<PolicyUpsertFragmentParams>(),
        ),
        (
            "manifest.publish",
            params_schema_of::<ManifestPublishParams>(),
        ),
        (
            "manifest.rollback",
            params_schema_of::<ManifestRollbackParams>(),
        ),
        (
            "manifest.stage_and_publish",
            params_schema_of::<ManifestStageAndPublishParams>(),
        ),
        (
            "manifest.upsert_servers",
            params_schema_of::<ManifestUpsertServersParams>(),
        ),
        (
            "manifest.remove_servers",
            params_schema_of::<ManifestRemoveServersParams>(),
        ),
    ]);
    let schemas = local_catalog::append_param_schemas(schemas);
    skills::append_param_schemas(operations::append_param_schemas(schemas))
}
