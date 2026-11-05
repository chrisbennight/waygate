//! API keys and API key profiles.

use serde_json::Value;
use waygate_apikeys::{ApiKeyRow, Profile};
use waygate_changeset::ChangeRequest;

use super::{
    change, found, list_changes, param, param_id, param_list, quoted, quoted_list,
    ChangeDescription, DescribedChange, Lookup,
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
#[cfg(test)]
pub(super) const DECLARED: &[(&str, &[&str])] = &[
    ("api_key.mint", MINT_KEYS),
    ("api_key.revoke", REVOKE_KEYS),
    ("api_key.update_grants", GRANTS_KEYS),
    ("api_key_profile.create", PROFILE_CREATE_KEYS),
    ("api_key_profile.delete", PROFILE_DELETE_KEYS),
];

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
    let params = &request.params;
    let Some(mut description) = requested_key(params) else {
        return ChangeDescription::undescribed("api_key.mint");
    };
    if let Some(id) = param(params, "profile_id") {
        let read = match (id.parse().ok(), state.identity.api_key_profiles.get()) {
            (Some(profile_id), Some(store)) => store.get(&request.tenant_id, profile_id).await.ok(),
            _ => None,
        };
        match read {
            Some(Some(profile)) => description
                .changes
                .push(change(format!("Profile: {}", quoted(&profile.name)))),
            // Minting enforces the profile's ceiling, so a missing profile
            // fails execution.
            Some(None) => return description.blocked(super::gone("API key profile")),
            None => return description.cannot_read("API key profile"),
        }
    }
    description
}

/// The key a mint request asks for, as minting will store it.
fn requested_key(params: &Value) -> Option<ChangeDescription> {
    let (name, subject) = (param(params, "name")?, param(params, "sub")?);
    // Minting trims the name, subject, owner, and reason before storing them.
    let mut description = ChangeDescription::titled(
        "api_key.mint",
        format!(
            "Create API key {} for {}",
            quoted(name.trim()),
            quoted(subject.trim())
        ),
        params,
        MINT_KEYS,
    );
    let changes = &mut description.changes;
    changes.push(change(format!("Scopes: {}", quoted_list(&scopes(params)))));
    let groups = groups(params);
    if !groups.is_empty() {
        changes.push(change(format!("Groups: {}", quoted_list(&groups))));
    }
    let ttl = param(params, "ttl").map(str::trim).unwrap_or_default();
    changes.push(change(match crate::api_keys::parse_ttl(ttl) {
        Ok(None) => "Requested lifetime: no expiry".to_owned(),
        _ => format!("Requested lifetime: {}", quoted(ttl)),
    }));
    for (key, label) in [("owner", "Owner"), ("reason", "Reason")] {
        if let Some(value) = param(params, key)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            changes.push(change(format!("{label}: {}", quoted(value))));
        }
    }
    // Email is stored as given unless it is blank.
    if let Some(email) = param(params, "email").filter(|email| !email.trim().is_empty()) {
        changes.push(change(format!("Email: {}", quoted(email))));
    }
    Some(description)
}

async fn revoke(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let key = found!(key(state, request).await);
    let mut description = ChangeDescription::titled(
        &request.action_type,
        format!("Revoke API key {}", key_label(&key)),
        &request.params,
        REVOKE_KEYS,
    );
    description.changes = vec![
        change(format!("Scopes: {}", quoted_list(&key.scopes))),
        change(format!("Groups: {}", quoted_list(&key.groups))),
        change(format!(
            "Expires: {}",
            key.expires_at
                .map_or_else(|| "never".to_owned(), waygate_core::fmt::format_ts_abs)
        )),
    ];
    // Revoking a revoked key is an idempotent no-op.
    if key.revoked_at.is_some() {
        description.note =
            Some("This API key is already revoked, so approval changes nothing.".into());
    }
    description
}

async fn update_grants(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let params = &request.params;
    let key = found!(key(state, request).await);
    let mut description = ChangeDescription::titled(
        &request.action_type,
        format!("Change API key {}", key_label(&key)),
        params,
        GRANTS_KEYS,
    );
    // Both lists replace the key's current ones; an omitted list is empty.
    description
        .changes
        .extend(list_changes("Scopes", &key.scopes, &scopes(params)));
    description
        .changes
        .extend(list_changes("Groups", &key.groups, &groups(params)));
    if key.revoked_at.is_some() {
        return description.blocked("This API key is revoked.");
    }
    if description.changes.is_empty() {
        description.note = Some("The proposed scopes and groups match the current ones.".into());
    }
    description
}

/// A key's name, prefix, and subject. Names are not unique, so the prefix
/// and subject tell apart keys that share one.
fn key_label(key: &ApiKeyRow) -> String {
    format!(
        "{} ({}…) for {}",
        quoted(&key.name),
        key.key_prefix,
        quoted(&key.sub)
    )
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
    let list = |key: &str| {
        params
            .get(key)
            .filter(|value| value.is_array())
            .map(|_| param_list(params, key))
    };
    // Both requirements default to on when omitted.
    let required = |key: &str| params.get(key).and_then(Value::as_bool).unwrap_or(true);
    description.changes = profile_limits(
        &param_list(params, "allowed_scopes"),
        max_ttl,
        list("allowed_servers").as_deref(),
        list("allowed_tools").as_deref(),
        required("requires_owner"),
        required("requires_reason"),
    );
    let changes = &mut description.changes;
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
    // Deletion discards the profile's description with its limits.
    description.changes = profile_limits(
        &profile.allowed_scopes,
        i64::from(profile.max_ttl_seconds),
        profile.allowed_servers.as_deref(),
        profile.allowed_tools.as_deref(),
        profile.requires_owner,
        profile.requires_reason,
    );
    if let Some(text) = profile
        .description
        .as_deref()
        .filter(|text| !text.is_empty())
    {
        description
            .changes
            .push(change(format!("Description: {}", quoted(text))));
    }
    description
}

/// The limits a profile places on keys minted with it. An absent or empty
/// server or tool list places no restriction, as invocation enforces it.
fn profile_limits(
    scopes: &[String],
    max_ttl_seconds: i64,
    servers: Option<&[String]>,
    tools: Option<&[String]>,
    requires_owner: bool,
    requires_reason: bool,
) -> Vec<DescribedChange> {
    let restriction = |values: Option<&[String]>, what: &str| match values {
        Some(values) if !values.is_empty() => quoted_list(values),
        _ => format!("any {what}, no restriction"),
    };
    vec![
        change(format!("Allowed scopes: {}", quoted_list(scopes))),
        change(format!(
            "Longest key lifetime: {}",
            duration(max_ttl_seconds)
        )),
        change(format!("Servers: {}", restriction(servers, "server"))),
        change(format!("Tools: {}", restriction(tools, "tool"))),
        change(format!(
            "Keys must name: {}",
            match (requires_owner, requires_reason) {
                (true, true) => "an owner and a reason",
                (true, false) => "an owner",
                (false, true) => "a reason",
                (false, false) => "nothing extra",
            }
        )),
    ]
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

/// Requested scopes as minting and grant updates store them: each entry
/// split on whitespace.
fn scopes(params: &Value) -> Vec<String> {
    param_list(params, "scopes")
        .iter()
        .flat_map(|scope| scope.split_whitespace())
        .map(str::to_owned)
        .collect()
}

/// Requested groups as minting and grant updates store them: trimmed, with
/// blank entries dropped.
fn groups(params: &Value) -> Vec<String> {
    param_list(params, "groups")
        .iter()
        .map(|group| group.trim())
        .filter(|group| !group.is_empty())
        .map(str::to_owned)
        .collect()
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
                "Servers: any server, no restriction",
                "Tools: “docs.search”",
                "Keys must name: an owner"
            ]
        );
        assert!(description.covers_params);
    }

    #[test]
    fn an_empty_allowlist_reads_as_no_restriction() {
        // Invocation skips an empty server or tool list, so it restricts nothing.
        let description = profile_create(&json!({"name": "open", "max_ttl_seconds": 3600,
            "allowed_scopes": ["mcp:read"], "allowed_servers": [], "allowed_tools": []}));
        let texts: Vec<_> = description
            .changes
            .iter()
            .map(|c| c.text.as_str())
            .collect();
        assert!(texts.contains(&"Servers: any server, no restriction"));
        assert!(texts.contains(&"Tools: any tool, no restriction"));
        assert!(!texts.iter().any(|text| text.ends_with(": none")));
    }

    #[test]
    fn requested_grants_are_normalized_like_the_executor() {
        let params = json!({"scopes": ["mcp:read mcp:invoke", " "], "groups": [" ops ", ""]});
        assert_eq!(scopes(&params), ["mcp:read", "mcp:invoke"]);
        assert_eq!(groups(&params), ["ops"]);
    }

    #[test]
    fn a_requested_key_reads_as_minting_stores_it() {
        let description = requested_key(&json!({"name": " ci ", "sub": " alice ",
            "scopes": ["mcp:read"], "ttl": "0", "owner": " ops ", "reason": " "}))
        .expect("described");
        assert_eq!(description.title, "Create API key “ci” for “alice”");
        let texts: Vec<_> = description
            .changes
            .iter()
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(
            texts,
            [
                "Scopes: “mcp:read”",
                "Requested lifetime: no expiry",
                "Owner: “ops”"
            ]
        );
        let description = requested_key(&json!({"name": "ci", "sub": "alice", "ttl": " 30d "}))
            .expect("described");
        assert!(description
            .changes
            .iter()
            .any(|c| c.text == "Requested lifetime: “30d”"));
    }

    #[test]
    fn keys_sharing_a_name_are_told_apart_by_prefix_and_subject() {
        let row = |prefix: &str, sub: &str| ApiKeyRow {
            id: uuid::Uuid::nil(),
            key_prefix: prefix.into(),
            key_hash: String::new(),
            name: "ci-runner".into(),
            sub: sub.into(),
            tenant_id: "default".into(),
            email: None,
            groups: Vec::new(),
            scopes: Vec::new(),
            created_by: String::new(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            profile_id: None,
            owner: None,
            reason: None,
            rotation_due_at: None,
        };
        assert_eq!(
            key_label(&row("mcpgw_AB", "alice")),
            "“ci-runner” (mcpgw_AB…) for “alice”"
        );
        assert_ne!(
            key_label(&row("mcpgw_AB", "alice")),
            key_label(&row("mcpgw_CD", "bob"))
        );
    }

    #[test]
    fn durations_use_the_largest_exact_unit() {
        assert_eq!(duration(3_600), "1 hour");
        assert_eq!(duration(90), "90 seconds");
        assert_eq!(duration(120), "2 minutes");
    }
}
