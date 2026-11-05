//! Roles, user role assignments, and group role mappings.

use serde_json::Value;
use uuid::Uuid;
use waygate_changeset::ChangeRequest;
use waygate_rbac::Role;

use super::{
    change, field_change, found, list_changes, param, param_id, param_list, quoted, quoted_list,
    ChangeDescription, Lookup,
};
use crate::state::AdminState;

const ROLE_CREATE_KEYS: &[&str] = &["name", "description", "scopes"];
const ROLE_UPDATE_KEYS: &[&str] = &["id", "name", "description", "scopes"];
const ID_KEYS: &[&str] = &["id"];
const GRANT_KEYS: &[&str] = &["role_id", "subject_sub"];
const MAPPING_KEYS: &[&str] = &["group_id", "role_id"];
/// Holders named on a deletion card before the rest are counted.
const NAMED_HOLDERS: usize = 5;

pub(super) async fn describe(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    match request.action_type.as_str() {
        "rbac.role.create" => role_create(&request.params),
        "rbac.role.update" => role_update(state, request).await,
        "rbac.role.delete" => role_delete(state, request).await,
        "rbac.assignment.grant" | "rbac.assignment.grant_privileged" => {
            assignment_grant(state, request).await
        }
        "rbac.assignment.revoke" | "rbac.assignment.revoke_privileged" => {
            assignment_revoke(state, request).await
        }
        "rbac.group_mapping.grant" | "rbac.group_mapping.grant_privileged" => {
            group_mapping(state, request, true).await
        }
        "rbac.group_mapping.revoke" | "rbac.group_mapping.revoke_privileged" => {
            group_mapping(state, request, false).await
        }
        other => ChangeDescription::undescribed(other),
    }
}

fn role_create(params: &Value) -> ChangeDescription {
    let action = "rbac.role.create";
    let Some(name) = param(params, "name") else {
        return ChangeDescription::undescribed(action);
    };
    let mut description = ChangeDescription::titled(
        action,
        format!("Create role {}", quoted(name)),
        params,
        ROLE_CREATE_KEYS,
    );
    description.changes.push(change(format!(
        "Scopes: {}",
        quoted_list(&param_list(params, "scopes"))
    )));
    if let Some(text) = param(params, "description").filter(|text| !text.is_empty()) {
        description
            .changes
            .push(change(format!("Description: {}", quoted(text))));
    }
    description
}

async fn role_update(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let params = &request.params;
    let role = found!(role(state, request, param_id(params, "id")).await);
    let mut description = ChangeDescription::titled(
        &request.action_type,
        format!("Change role {}", quoted(&role.name)),
        params,
        ROLE_UPDATE_KEYS,
    );
    if let Some(name) = param(params, "name").filter(|name| *name != role.name) {
        description
            .changes
            .push(field_change("Name", quoted(&role.name), quoted(name)));
    }
    // An omitted description clears the current one.
    let proposed = param(params, "description").filter(|text| !text.is_empty());
    let current = role.description.as_deref().filter(|text| !text.is_empty());
    if proposed != current {
        description.changes.push(field_change(
            "Description",
            current.map_or_else(|| "none".to_owned(), quoted),
            proposed.map_or_else(|| "none".to_owned(), quoted),
        ));
    }
    description.changes.extend(list_changes(
        "Scopes",
        &role.scopes,
        &param_list(params, "scopes"),
    ));
    if description.changes.is_empty() {
        description.note = Some("The proposed values match the current ones.".into());
    }
    description
}

async fn role_delete(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let role = found!(role(state, request, param_id(&request.params, "id")).await);
    let mut description = ChangeDescription::titled(
        &request.action_type,
        format!("Delete role {}", quoted(&role.name)),
        &request.params,
        ID_KEYS,
    );
    description
        .changes
        .push(change(format!("Scopes: {}", quoted_list(&role.scopes))));
    let Some(store) = state.identity.rbac.get() else {
        return description;
    };
    let tenant = &request.tenant_id;
    let holders = store.list_assignments(tenant, Some(role.id), None).await;
    let mappings = store.list_group_mappings(tenant, Some(role.id), None).await;
    match (holders, mappings) {
        (Ok(holders), Ok(mappings)) => {
            let subjects: Vec<String> = holders.into_iter().map(|a| a.subject_sub).collect();
            if !subjects.is_empty() {
                description
                    .changes
                    .push(change(format!("Assigned to: {}", named(&subjects))));
            }
            let groups = group_names(
                state,
                tenant,
                &mappings.iter().map(|m| m.group_id).collect::<Vec<_>>(),
            )
            .await;
            if !groups.is_empty() {
                description
                    .changes
                    .push(change(format!("Granted to groups: {}", named(&groups))));
            }
        }
        (holders, mappings) => {
            for error in [holders.err(), mappings.err()].into_iter().flatten() {
                tracing::warn!(error = %error, "approval card could not read role holders");
            }
            description.note = Some("The role's current holders cannot be read.".into());
        }
    }
    description
}

async fn assignment_grant(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let params = &request.params;
    let Some(subject) = param(params, "subject_sub") else {
        return ChangeDescription::undescribed(&request.action_type);
    };
    let role = found!(role(state, request, param_id(params, "role_id")).await);
    let mut description = ChangeDescription::titled(
        &request.action_type,
        format!("Assign role {} to {}", quoted(&role.name), quoted(subject)),
        params,
        GRANT_KEYS,
    );
    description
        .changes
        .push(change(format!("Scopes: {}", quoted_list(&role.scopes))));
    description
}

async fn assignment_revoke(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let read = match (state.identity.rbac.get(), param_id(&request.params, "id")) {
        (Some(store), Some(id)) => Some(store.get_assignment(&request.tenant_id, id).await),
        (_, None) => return ChangeDescription::undescribed(action),
        (None, Some(_)) => None,
    };
    let assignment = found!(Lookup::from_read(action, "role assignment", read));
    let role = found!(role(state, request, Some(assignment.role_id)).await);
    let mut description = ChangeDescription::titled(
        action,
        format!(
            "Remove role {} from {}",
            quoted(&role.name),
            quoted(&assignment.subject_sub)
        ),
        &request.params,
        ID_KEYS,
    );
    description
        .changes
        .push(change(format!("Scopes: {}", quoted_list(&role.scopes))));
    description
}

async fn group_mapping(
    state: &AdminState,
    request: &ChangeRequest,
    grant: bool,
) -> ChangeDescription {
    let action = request.action_type.as_str();
    let params = &request.params;
    let Some(group_id) = param_id(params, "group_id") else {
        return ChangeDescription::undescribed(action);
    };
    let role = found!(role(state, request, param_id(params, "role_id")).await);
    let group = found!(group(state, action, &request.tenant_id, group_id).await);
    let mut description = ChangeDescription::titled(
        action,
        if grant {
            format!(
                "Give group {} role {}",
                quoted(&group.display_name),
                quoted(&role.name)
            )
        } else {
            format!(
                "Remove role {} from group {}",
                quoted(&role.name),
                quoted(&group.display_name)
            )
        },
        params,
        MAPPING_KEYS,
    );
    description.changes = vec![
        change(format!("Scopes: {}", quoted_list(&role.scopes))),
        change(format!("Group members: {}", group.user_member_count)),
    ];
    if !grant {
        if let Some(store) = state.identity.rbac.get() {
            match store
                .list_group_mappings(&request.tenant_id, Some(role.id), Some(group_id))
                .await
            {
                Ok(mappings) if mappings.is_empty() => {
                    return description.blocked(super::gone("group mapping"));
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "approval card could not read the group mapping");
                }
            }
        }
    }
    description
}

/// The role a change targets.
async fn role(state: &AdminState, request: &ChangeRequest, id: Option<Uuid>) -> Lookup<Role> {
    let action = request.action_type.as_str();
    let Some(id) = id else {
        return Lookup::Fallback(ChangeDescription::undescribed(action));
    };
    let read = match state.identity.rbac.get() {
        Some(store) => Some(store.get_role(&request.tenant_id, id).await),
        None => None,
    };
    Lookup::from_read(action, "role", read)
}

/// The group a mapping names.
async fn group(
    state: &AdminState,
    action: &str,
    tenant: &str,
    id: Uuid,
) -> Lookup<waygate_apikeys::GroupView> {
    let read = match state.identity.groups.get() {
        Some(store) => Some(
            store
                .list_with_usage(tenant)
                .await
                .map(|groups| groups.into_iter().find(|group| group.id == id)),
        ),
        None => None,
    };
    Lookup::from_read(action, "group", read)
}

/// Display names of `ids`, in the given order; unknown groups are left out.
async fn group_names(state: &AdminState, tenant: &str, ids: &[Uuid]) -> Vec<String> {
    if ids.is_empty() {
        return Vec::new();
    }
    let Some(store) = state.identity.groups.get() else {
        return Vec::new();
    };
    match store.list_with_usage(tenant).await {
        Ok(groups) => ids
            .iter()
            .filter_map(|id| groups.iter().find(|group| group.id == *id))
            .map(|group| group.display_name.clone())
            .collect(),
        Err(error) => {
            tracing::warn!(error = %error, "approval card could not read group names");
            Vec::new()
        }
    }
}

/// Up to [`NAMED_HOLDERS`] names, quoted, with the rest counted.
fn named(names: &[String]) -> String {
    let shown: Vec<String> = names
        .iter()
        .take(NAMED_HOLDERS)
        .map(|name| quoted(name))
        .collect();
    match names.len().saturating_sub(NAMED_HOLDERS) {
        0 => shown.join(", "),
        more => format!("{} and {more} more", shown.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_new_role_lists_its_scopes() {
        let description = role_create(&json!({"name": "operators",
            "scopes": ["mcp:read", "mcp:invoke"], "description": "Run tools"}));
        assert_eq!(description.title, "Create role “operators”");
        let texts: Vec<_> = description
            .changes
            .iter()
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(
            texts,
            [
                "Scopes: “mcp:read”, “mcp:invoke”",
                "Description: “Run tools”"
            ]
        );
        assert!(description.covers_params);
    }

    #[test]
    fn holder_lists_name_the_first_few_and_count_the_rest() {
        let names: Vec<String> = (0..7).map(|i| format!("user{i}")).collect();
        assert_eq!(
            named(&names),
            "“user0”, “user1”, “user2”, “user3”, “user4” and 2 more"
        );
        assert_eq!(named(&names[..1]), "“user0”");
    }
}
