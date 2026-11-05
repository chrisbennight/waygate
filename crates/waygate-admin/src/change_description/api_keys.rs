//! API keys and API key profiles.

use serde_json::Value;
use waygate_apikeys::{ApiKeyRow, Profile};
use waygate_changeset::ChangeRequest;

use super::{
    change, found, list_changes, param, param_id, param_list, quoted, quoted_list,
    ChangeDescription, Lookup,
};
use crate::state::AdminState;

const MINT_KEYS: &[&str] = &[
    "name",
    "sub",
    "scopes",
    "email",
    "groups",
    "ttl",
    "profile_id",
    "owner",
    "reason",
];
const REVOKE_KEYS: &[&str] = &["api_key_id"];
const GRANTS_KEYS: &[&str] = &["api_key_id", "scopes", "groups"];
const PROFILE_CREATE_KEYS: &[&str] = &[
    "name",
    "description",
    "max_ttl_seconds",
    "allowed_scopes",
    "allowed_servers",
    "allowed_tools",
    "requires_reason",
    "requires_owner",
];
const PROFILE_DELETE_KEYS: &[&str] = &["profile_id"];

pub(super) async fn describe(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    match request.action_type.as_str() {
        "api_key.mint" => mint(state, request).await,
        "api_key.revoke" => revoke(state, request).await,
        "api_key.update_grants" => update_grants(state, request).await,
        "api_key_profile.create" => profile_create(&request.params),
        "api_key_profile.delete" => profile_delete(state, request).await,
        other => ChangeDescription::undescribed(other),
    }
}

async fn mint(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = "api_key.mint";
    let params = &request.params;
    let (Some(name), Some(subject)) = (param(params, "name"), param(params, "sub")) else {
        return ChangeDescription::undescribed(action);
    };
    let mut description = ChangeDescription::titled(
        action,
        format!("Create API key {} for {}", quoted(name), quoted(subject)),
        params,
        MINT_KEYS,
    );
    let changes = &mut description.changes;
    changes.push(change(format!(
        "Scopes: {}",
        quoted_list(&param_list(params, "scopes"))
    )));
    let groups = param_list(params, "groups");
    if !groups.is_empty() {
        changes.push(change(format!("Groups: {}", quoted_list(&groups))));
    }
    changes.push(change(match param(params, "ttl").map(str::trim) {
        None | Some("" | "never" | "none" | "unlimited") => {
            "Requested lifetime: no expiry".to_owned()
        }
        Some(ttl) => format!("Requested lifetime: {}", quoted(ttl)),
    }));
    for (key, label) in [("owner", "Owner"), ("email", "Email"), ("reason", "Reason")] {
        if let Some(value) = param(params, key).filter(|value| !value.is_empty()) {
            changes.push(change(format!("{label}: {}", quoted(value))));
        }
    }
    if let Some(id) = param(params, "profile_id") {
        let read = match (id.parse().ok(), state.identity.api_key_profiles.get()) {
            (Some(profile_id), Some(store)) => store.get(&request.tenant_id, profile_id).await.ok(),
            _ => None,
        };
        description.changes.push(change(match read {
            Some(Some(profile)) => format!("Profile: {}", quoted(&profile.name)),
            Some(None) => format!("Profile: {} not found", quoted(id)),
            None => format!("Profile: {} cannot be read", quoted(id)),
        }));
    }
    description
}

async fn revoke(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let key = found!(key(state, request).await);
    let mut description = ChangeDescription::titled(
        &request.action_type,
        format!("Revoke API key {}", quoted(&key.name)),
        &request.params,
        REVOKE_KEYS,
    );
    description.changes = vec![
        change(format!("Belongs to: {}", quoted(&key.sub))),
        change(format!("Scopes: {}", quoted_list(&key.scopes))),
    ];
    if key.revoked_at.is_some() {
        return description.blocked("This API key is already revoked.");
    }
    description
}

async fn update_grants(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let params = &request.params;
    let key = found!(key(state, request).await);
    let mut description = ChangeDescription::titled(
        &request.action_type,
        format!("Change API key {}", quoted(&key.name)),
        params,
        GRANTS_KEYS,
    );
    // Both lists replace the key's current ones; an omitted list is empty.
    description.changes.extend(list_changes(
        "Scopes",
        &key.scopes,
        &param_list(params, "scopes"),
    ));
    description.changes.extend(list_changes(
        "Groups",
        &key.groups,
        &param_list(params, "groups"),
    ));
    if key.revoked_at.is_some() {
        return description.blocked("This API key is revoked.");
    }
    if description.changes.is_empty() {
        description.note = Some("The proposed scopes and groups match the current ones.".into());
    }
    description
}

fn profile_create(params: &Value) -> ChangeDescription {
    let action = "api_key_profile.create";
    let (Some(name), Some(max_ttl)) = (
        param(params, "name"),
        params.get("max_ttl_seconds").and_then(Value::as_i64),
    ) else {
        return ChangeDescription::undescribed(action);
    };
    let mut description = ChangeDescription::titled(
        action,
        format!("Create API key profile {}", quoted(name)),
        params,
        PROFILE_CREATE_KEYS,
    );
    let changes = &mut description.changes;
    changes.push(change(format!(
        "Allowed scopes: {}",
        quoted_list(&param_list(params, "allowed_scopes"))
    )));
    changes.push(change(format!(
        "Longest key lifetime: {}",
        duration(max_ttl)
    )));
    for (key, label) in [("allowed_servers", "Servers"), ("allowed_tools", "Tools")] {
        if params.get(key).is_some_and(|value| !value.is_null()) {
            changes.push(change(format!(
                "{label}: {}",
                quoted_list(&param_list(params, key))
            )));
        }
    }
    // Both requirements default to on when omitted.
    let required = |key: &str| params.get(key).and_then(Value::as_bool).unwrap_or(true);
    changes.push(change(format!(
        "Keys must name: {}",
        match (required("requires_owner"), required("requires_reason")) {
            (true, true) => "an owner and a reason",
            (true, false) => "an owner",
            (false, true) => "a reason",
            (false, false) => "nothing extra",
        }
    )));
    if let Some(text) = param(params, "description").filter(|text| !text.is_empty()) {
        changes.push(change(format!("Description: {}", quoted(text))));
    }
    description
}

async fn profile_delete(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let read = match (
        state.identity.api_key_profiles.get(),
        param_id(&request.params, "profile_id"),
    ) {
        (_, None) => return ChangeDescription::undescribed(action),
        (Some(store), Some(id)) => Some(store.get(&request.tenant_id, id).await),
        (None, Some(_)) => None,
    };
    let profile: Profile = found!(Lookup::from_read(action, "API key profile", read));
    let mut description = ChangeDescription::titled(
        action,
        format!("Delete API key profile {}", quoted(&profile.name)),
        &request.params,
        PROFILE_DELETE_KEYS,
    );
    description.changes.push(change(format!(
        "Allowed scopes: {}",
        quoted_list(&profile.allowed_scopes)
    )));
    description
}

/// The key a revocation or grant change targets, within the request's tenant.
async fn key(state: &AdminState, request: &ChangeRequest) -> Lookup<ApiKeyRow> {
    let action = request.action_type.as_str();
    let Some(id) = param_id(&request.params, "api_key_id") else {
        return Lookup::Fallback(ChangeDescription::undescribed(action));
    };
    let read = match state.identity.api_keys.get() {
        Some(store) => Some(
            store
                .find_by_id(id)
                .await
                .map(|row| row.filter(|row| row.tenant_id == request.tenant_id)),
        ),
        None => None,
    };
    Lookup::from_read(action, "API key", read)
}

/// A whole number of days, hours, or minutes when one fits exactly.
fn duration(seconds: i64) -> String {
    let unit = |count: i64, singular: &str| {
        format!("{count} {singular}{}", if count == 1 { "" } else { "s" })
    };
    match seconds {
        s if s > 0 && s % 86_400 == 0 => unit(s / 86_400, "day"),
        s if s > 0 && s % 3_600 == 0 => unit(s / 3_600, "hour"),
        s if s > 0 && s % 60 == 0 => unit(s / 60, "minute"),
        s => unit(s, "second"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_profile_states_its_limits_and_defaults() {
        let description = profile_create(&json!({"name": "ci", "max_ttl_seconds": 7_776_000,
            "allowed_scopes": ["mcp:read"], "allowed_tools": ["docs.search"],
            "requires_reason": false}));
        assert_eq!(description.title, "Create API key profile “ci”");
        let texts: Vec<_> = description
            .changes
            .iter()
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(
            texts,
            [
                "Allowed scopes: “mcp:read”",
                "Longest key lifetime: 90 days",
                "Tools: “docs.search”",
                "Keys must name: an owner"
            ]
        );
        assert!(description.covers_params);
    }

    #[test]
    fn durations_use_the_largest_exact_unit() {
        assert_eq!(duration(3_600), "1 hour");
        assert_eq!(duration(90), "90 seconds");
        assert_eq!(duration(120), "2 minutes");
    }
}
