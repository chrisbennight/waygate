//! A plain title and the approval outcome for every registered action.
//!
//! Each outcome states what approval does: what is affected, when it takes
//! effect, and whether another action can undo it. It claims only what the
//! action's executor does. A card description that can name the target
//! replaces the generic title.

/// Card text for one registered action.
pub(crate) struct ActionText {
    /// Starts with a verb; names the kind of object, not a specific one.
    pub title: &'static str,
    pub outcome: &'static str,
}

/// The title and outcome for `action_type`, or `None` for an unregistered
/// action.
pub(crate) fn action_text(action_type: &str) -> Option<ActionText> {
    let (title, outcome) = match action_type {
        "tool_contract.approve" => (
            "Accept a new tool definition",
            "The tool becomes callable with this exact definition, subject to access policies. \
             A later definition change is blocked for review again.",
        ),
        "tool_contract.reject" => (
            "Keep a changed tool blocked",
            "The tool stays hidden and its calls stay blocked. A later definition change opens \
             a new review.",
        ),
        "rate_limit.create" => (
            "Create a rate limit",
            "Matching calls are limited by the new rate limit from the next call. Deleting the \
             limit removes it.",
        ),
        "rate_limit.update" => (
            "Change a rate limit",
            "The rate limit uses the new capacity and refill rate from the next call. Its scope \
             and action do not change.",
        ),
        "rate_limit.delete" => (
            "Delete a rate limit",
            "Calls the rate limit governed are no longer limited by it from the next call. \
             Restoring it requires creating a new limit.",
        ),
        "inspection_rule.delete" => (
            "Delete a stored inspection rule",
            "The stored rule is permanently deleted. Stored rules are not enforced, so call \
             handling does not change.",
        ),
        "oauth_consent.revoke" => (
            "Revoke a user's consent for a client",
            "The consent is marked revoked and tokens already issued keep working. When the \
             gateway requires explicit consent, the user's next sign-in through the client asks \
             again.",
        ),
        "peer.create" => (
            "Add a peer gateway",
            "Tokens signed by the peer are accepted as identities in this tenant once its \
             signing keys are next fetched, and tool access is still governed by policy. \
             Deleting the peer stops this.",
        ),
        "peer.update" => (
            "Change a peer gateway",
            "The peer's tokens are checked against the new issuer and signing keys once the keys \
             are next fetched.",
        ),
        "peer.delete" => (
            "Remove a peer gateway",
            "The gateway instance that processes the approval stops accepting the peer's tokens \
             at once, and other instances stop at their next key refresh. Re-adding it requires \
             creating a new peer.",
        ),
        "rbac.role.create" => (
            "Create a role",
            "A role with the listed scopes is created. It grants nothing until it is assigned.",
        ),
        "rbac.role.update" => (
            "Change a role",
            "Everyone who holds the role gets the new scope list in place of the old one within \
             a minute. The role's name and description are also replaced.",
        ),
        "rbac.role.delete" => (
            "Delete a role",
            "The role is deleted with its user assignments and group mappings, and holders lose \
             its scopes within a minute. Recreating the role does not restore the assignments.",
        ),
        "rbac.assignment.grant" => (
            "Assign a role to a user",
            "The user receives the role and its scopes within a minute. Revoking the assignment \
             removes them.",
        ),
        "rbac.assignment.grant_privileged" => (
            "Assign a control-plane role to a user",
            "The user receives the role, including its control-plane scopes, within a minute. \
             Revoking the assignment removes them.",
        ),
        "rbac.assignment.revoke" => (
            "Remove a role from a user",
            "The user loses the role within a minute, unless another role or group gives them \
             the same scopes.",
        ),
        "rbac.assignment.revoke_privileged" => (
            "Remove a control-plane role from a user",
            "The user loses the role, including its control-plane scopes, on their next request, \
             unless another role or group gives them the same scopes.",
        ),
        "rbac.group_mapping.grant" => (
            "Give a group a role",
            "Every member of the group receives the role and its scopes within a minute. \
             Revoking the mapping removes them.",
        ),
        "rbac.group_mapping.grant_privileged" => (
            "Give a group a control-plane role",
            "Every member of the group receives the role, including its control-plane scopes, \
             within a minute. Revoking the mapping removes them.",
        ),
        "rbac.group_mapping.revoke" => (
            "Remove a role from a group",
            "Members of the group stop receiving the role through this group within a minute.",
        ),
        "rbac.group_mapping.revoke_privileged" => (
            "Remove a control-plane role from a group",
            "Members of the group stop receiving the role, including its control-plane scopes, \
             through this group on their next request.",
        ),
        "tenant.update" => (
            "Rename the tenant",
            "The tenant's display name changes. Another rename can change it back.",
        ),
        "audit.retention.set" => (
            "Set audit retention for a category",
            "Audit records in the category older than the set age are permanently deleted at \
             each scheduled retention sweep, starting with the next.",
        ),
        "audit.retention.clear" => (
            "Remove audit retention for a category",
            "The category's records follow the tenant's catch-all retention rule if one exists, \
             and are otherwise no longer deleted automatically.",
        ),
        "audit.routing.set" => (
            "Set audit routing for an exporter",
            "From the next audit event, the tenant's events go only to exporters with an enabled \
             routing rule, and this rule sets whether the exporter is one of them.",
        ),
        "audit.routing.clear" => (
            "Remove audit routing for an exporter",
            "From the next audit event, the exporter receives the tenant's events only if no \
             other routing rule remains, in which case every configured exporter receives them.",
        ),
        "upstream_session.revoke" => (
            "Delete a user's upstream sign-in",
            "The user's stored sign-in with the upstream issuer is deleted. Tools that call \
             upstream services as that user fail until the user signs in again.",
        ),
        "break_glass.mint" => (
            "Issue a break-glass token",
            "The user can make one call that policy would otherwise deny, to a tool matching the \
             pattern, until the token expires. Revoking the token before then cancels it.",
        ),
        "break_glass.revoke" => (
            "Revoke a break-glass token",
            "The token is deleted, and its holder can no longer use it to override a policy \
             denial.",
        ),
        "api_key.mint" => (
            "Create an API key",
            "A key with the listed scopes is created, and its secret is delivered once to the \
             agent that requested it. Revoking the key disables it.",
        ),
        "api_key.revoke" => (
            "Revoke an API key",
            "The key is permanently revoked, and requests using it are refused once the \
             gateway's key cache expires, one minute by default.",
        ),
        "api_key.update_grants" => (
            "Change an API key's scopes and groups",
            "The listed scopes and groups replace the key's current ones once the gateway's key \
             cache expires, one minute by default. Its secret and expiry do not change.",
        ),
        "api_key_profile.create" => (
            "Create an API key profile",
            "Keys minted with the profile are limited to its scopes, lifetime, and server and \
             tool restrictions. The profile cannot be edited later.",
        ),
        "api_key_profile.delete" => (
            "Delete an API key profile",
            "The profile is permanently deleted, and keys can no longer be minted with it.",
        ),
        "policy.publish" => (
            "Publish an access policy draft",
            "The draft replaces the whole live access policy set, and gateways apply it on the \
             reload this triggers. Rolling back restores the previous version.",
        ),
        "policy.rollback" => (
            "Roll back the access policy set",
            "The selected version's content is published as a new version and replaces the live \
             access policy set on the reload this triggers.",
        ),
        "policy.upsert_fragment" => (
            "Add or replace an access policy",
            "The policy is added to or replaced in the live policy set, other policies are \
             unchanged, and gateways apply it on the reload this triggers.",
        ),
        "manifest.publish" => (
            "Publish an upstream server set draft",
            "The draft replaces the whole live upstream server set, and gateways apply it on the \
             reload this triggers. Rolling back restores the previous set.",
        ),
        "manifest.rollback" => (
            "Roll back the upstream server set",
            "The selected version's content is published as a new version and replaces the live \
             upstream server set on the reload this triggers.",
        ),
        "manifest.stage_and_publish" => (
            "Replace the upstream server set",
            "The submitted set replaces the live upstream server set, and servers it leaves out \
             are removed on the reload this triggers. Rolling back restores the previous set.",
        ),
        "manifest.upsert_servers" => (
            "Add or replace upstream servers",
            "The listed servers are added to or replaced in the live server set, other servers \
             are unchanged, and gateways apply it on the reload this triggers.",
        ),
        "manifest.remove_servers" => (
            "Remove upstream servers",
            "The listed servers are removed from the live server set, and their tools become \
             unavailable on the reload this triggers. Rolling back restores them.",
        ),
        "upstream.reconnect" => (
            "Reconnect an upstream server",
            "The gateway instance that processes the approval reconnects to the server if it is \
             disconnected or its circuit breaker is open, and leaves a healthy connection as is. \
             If the request also clears quarantine, tools that instance blocked after a \
             definition change are released.",
        ),
        "upstream.refresh_catalog" => (
            "Refresh an upstream server's tools",
            "The gateway instance that processes the approval opens a new session to the server \
             and replaces its tool list with what the server now reports. If that fails, the \
             old session and tool list stay.",
        ),
        "upstream.quarantine.clear" => (
            "Release a server's blocked tools",
            "Tools that the processing gateway instance blocked after a definition change can be \
             called again. Tools awaiting a contract review stay blocked.",
        ),
        "catalog.server.unquarantine" => (
            "Restore a quarantined server",
            "The server goes from quarantined to live in the catalog, and its tools can be \
             discovered and called again. Quarantining it reverses this.",
        ),
        "config.reload" => (
            "Reload published configuration",
            "Every gateway instance reloads the published policy set, server set, or both. \
             Nothing stored changes.",
        ),
        "agent_config.create" => (
            "Create a gateway agent",
            "An agent with the listed model, tools, and limits is created. If it is enabled, it \
             can be run immediately.",
        ),
        "agent_config.update" => (
            "Change a gateway agent",
            "The agent's whole configuration, including its tool allowlist, is replaced. Runs \
             started afterwards use it.",
        ),
        "agent_config.delete" => (
            "Delete a gateway agent",
            "The agent is permanently deleted and can no longer be run.",
        ),
        "group.create_local" => (
            "Create a local group",
            "The group is added to the tenant's group catalog, so API keys can be granted it.",
        ),
        "group.delete_local" => (
            "Delete a local group",
            "The unused group is removed from the tenant's group catalog. A group with the same \
             name can be created again.",
        ),
        "scope.create_local" => (
            "Create a local scope",
            "The scope is added to the tenant's scope catalog, so API keys can be granted it.",
        ),
        "scope.delete_local" => (
            "Delete a local scope",
            "The unused scope is removed from the tenant's scope catalog. A scope with the same \
             name can be created again.",
        ),
        "skill.approve" => (
            "Approve a skill version",
            "Agents in the tenant receive this exact version from their next request, in place \
             of any earlier approved version. Quarantining the skill withdraws it.",
        ),
        "skill.reject" => (
            "Reject a skill version",
            "This version is not distributed, and any previously approved version stays \
             available. It can still be approved later.",
        ),
        "skill.quarantine" => (
            "Withdraw a skill",
            "The skill, including any previously approved version, is withdrawn from agents in \
             the tenant until a version is approved again.",
        ),
        _ => return None,
    };
    Some(ActionText { title, outcome })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_action_has_a_title_and_outcome() {
        let missing: Vec<_> = crate::change_executor::registry()
            .action_types()
            .into_iter()
            .filter(|action| action_text(action).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "add a title and outcome for: {missing:?}"
        );
    }

    /// Mechanical guard for the dashboard writing rules: a title is short
    /// and verb-first, and an outcome states effects without reassurance,
    /// hedging, or value claims.
    #[test]
    fn action_text_follows_the_card_writing_rules() {
        const AVOID: [&str; 10] = [
            "safe",
            "routine",
            "simply",
            "potentially",
            "critical",
            "significant",
            "ensur",
            "seamless",
            "Are you sure",
            "Please",
        ];
        for action in crate::change_executor::registry().action_types() {
            let text = action_text(action).expect("registered action has text");
            assert!(
                text.title.split_whitespace().count() <= 7,
                "{action}: title is too long"
            );
            assert!(
                text.title.starts_with(char::is_uppercase) && !text.title.ends_with('.'),
                "{action}: title must be a capitalized phrase"
            );
            assert!(
                text.outcome.ends_with('.') && text.outcome.split(". ").count() <= 2,
                "{action}: outcome must be one or two sentences"
            );
            for word in AVOID {
                assert!(
                    !text.outcome.to_lowercase().contains(&word.to_lowercase()),
                    "{action}: outcome uses {word:?}"
                );
            }
        }
    }
}
