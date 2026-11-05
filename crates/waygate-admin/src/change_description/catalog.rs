//! Local groups and scopes, stored inspection rules, skills, and upstream
//! server operations.

use waygate_changeset::ChangeRequest;

use super::{
    change, found, param, param_id, quoted, quoted_list, ChangeDescription, EvidenceLink, Lookup,
};
use crate::state::AdminState;

const GROUP_CREATE_KEYS: &[&str] = &["display_name"];
const GROUP_DELETE_KEYS: &[&str] = &["group_id", "display_name"];
const SCOPE_CREATE_KEYS: &[&str] = &["name", "description"];
const SCOPE_DELETE_KEYS: &[&str] = &["scope_id", "name"];
const RULE_KEYS: &[&str] = &["id"];
const SKILL_KEYS: &[&str] = &["skill_uri", "generation", "content_digest", "reason"];
const SERVER_KEYS: &[&str] = &["server"];
const RECONNECT_KEYS: &[&str] = &["server", "clear_quarantine"];
const UNQUARANTINE_KEYS: &[&str] = &["server_id", "expected_name", "reason"];
const RELOAD_KEYS: &[&str] = &["target"];
#[cfg(test)]
pub(super) const DECLARED: &[(&str, &[&str])] = &[
    ("group.create_local", GROUP_CREATE_KEYS),
    ("group.delete_local", GROUP_DELETE_KEYS),
    ("scope.create_local", SCOPE_CREATE_KEYS),
    ("scope.delete_local", SCOPE_DELETE_KEYS),
    ("inspection_rule.delete", RULE_KEYS),
    ("skill.approve", SKILL_KEYS),
    ("skill.reject", SKILL_KEYS),
    ("skill.quarantine", SKILL_KEYS),
    ("upstream.reconnect", RECONNECT_KEYS),
    ("upstream.refresh_catalog", SERVER_KEYS),
    ("upstream.quarantine.clear", SERVER_KEYS),
    ("catalog.server.unquarantine", UNQUARANTINE_KEYS),
    ("config.reload", RELOAD_KEYS),
];

pub(super) async fn describe(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let params = &request.params;
    // Local catalog deletions and server restoration capture their target
    // at proposal, and the card checks it against current state before
    // approval, so their names come from the parameters.
    let (title, keys) = match action {
        "group.create_local" => match param(params, "display_name") {
            Some(name) => (
                format!("Create local group {}", quoted(name)),
                GROUP_CREATE_KEYS,
            ),
            None => return ChangeDescription::undescribed(action),
        },
        "group.delete_local" => match param(params, "display_name") {
            Some(name) => (
                format!("Delete local group {}", quoted(name)),
                GROUP_DELETE_KEYS,
            ),
            None => return ChangeDescription::undescribed(action),
        },
        "scope.create_local" => match param(params, "name") {
            Some(name) => (
                format!("Create local scope {}", quoted(name)),
                SCOPE_CREATE_KEYS,
            ),
            None => return ChangeDescription::undescribed(action),
        },
        "scope.delete_local" => match param(params, "name") {
            Some(name) => (
                format!("Delete local scope {}", quoted(name)),
                SCOPE_DELETE_KEYS,
            ),
            None => return ChangeDescription::undescribed(action),
        },
        "inspection_rule.delete" => return inspection_rule(state, request).await,
        "skill.approve" | "skill.reject" | "skill.quarantine" => {
            return skill(state, request).await
        }
        "upstream.reconnect" | "upstream.refresh_catalog" | "upstream.quarantine.clear" => {
            return server_operation(state, request).await
        }
        "catalog.server.unquarantine" => match param(params, "expected_name") {
            Some(name) => (
                format!("Restore quarantined server {}", quoted(name)),
                UNQUARANTINE_KEYS,
            ),
            None => return ChangeDescription::undescribed(action),
        },
        "config.reload" => (
            match param(params, "target") {
                Some("policy") => "Reload the published policy set",
                Some("manifest") => "Reload the published server set",
                _ => "Reload the published policy and server sets",
            }
            .to_owned(),
            RELOAD_KEYS,
        ),
        other => return ChangeDescription::undescribed(other),
    };
    let mut description = ChangeDescription::titled(action, title, params, keys);
    for (key, label) in [
        ("description", "Description"),
        ("reason", "Recorded reason"),
    ] {
        if let Some(text) = param(params, key).filter(|text| !text.is_empty()) {
            description
                .changes
                .push(change(format!("{label}: {}", quoted(text))));
        }
    }
    description
}

async fn inspection_rule(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let read = match (
        state.policy.inspection_rules.get(),
        param_id(&request.params, "id"),
    ) {
        (_, None) => return ChangeDescription::undescribed(action),
        (Some(store), Some(id)) => Some(store.get(&request.tenant_id, id).await),
        (None, Some(_)) => None,
    };
    let rule = found!(Lookup::from_read(action, "stored inspection rule", read));
    let mut description = ChangeDescription::titled(
        action,
        format!("Delete stored inspection rule {}", quoted(&rule.name)),
        &request.params,
        RULE_KEYS,
    );
    // Names repeat across inspectors, so the card names the inspector and
    // shows the stored settings that the deletion removes.
    description.changes = vec![
        change(format!("Inspector: {}", quoted(rule.inspector.as_str()))),
        change(format!(
            "Enabled: {}",
            if rule.enabled { "yes" } else { "no" }
        )),
        change(format!("Settings: {}", quoted(&rule.config.to_string()))),
        change(format!(
            "Applies to: {}",
            quoted(&rule.applies_to.to_string())
        )),
    ];
    description
}

async fn skill(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let params = &request.params;
    let Some(uri) = param(params, "skill_uri") else {
        return ChangeDescription::undescribed(action);
    };
    let mut description = ChangeDescription::titled(
        action,
        match action {
            "skill.approve" => format!("Approve the reviewed version of skill {}", quoted(uri)),
            "skill.reject" => format!("Reject the reviewed version of skill {}", quoted(uri)),
            _ => format!("Withdraw skill {}", quoted(uri)),
        },
        params,
        SKILL_KEYS,
    );
    description.evidence = Some(EvidenceLink {
        label: "Skill review",
        path: crate::dashboard_skills::review_url(uri),
    });
    if let Some(reason) = param(params, "reason").filter(|reason| !reason.is_empty()) {
        description
            .changes
            .push(change(format!("Recorded reason: {}", quoted(reason))));
    }
    // The decision core accepts only the reviewed generation and content.
    match crate::skill_reviews::current_review(state, &request.tenant_id, uri).await {
        Ok(review)
            if Some(review.generation) == params.get("generation").and_then(|v| v.as_i64())
                && Some(review.candidate.content_digest()) == param(params, "content_digest") => {}
        Ok(_) => {
            return description.blocked(
                "The skill changed after this request. Review the current version on the skill \
                 review page.",
            )
        }
        // The decision core refuses a skill that left the configured source.
        Err(crate::error::ApiError::NotFound(_)) => {
            return description.blocked("The skill is no longer in the configured source.")
        }
        Err(error) => {
            description.covers_params = false;
            description.note = Some(format!(
                "The current skill review cannot be read: {}",
                error.detail()
            ));
        }
    }
    description
}

async fn server_operation(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let params = &request.params;
    let Some(server) = param(params, "server") else {
        return ChangeDescription::undescribed(action);
    };
    let (title, keys) = match action {
        "upstream.reconnect" => (
            format!("Reconnect upstream server {}", quoted(server)),
            RECONNECT_KEYS,
        ),
        "upstream.refresh_catalog" => (
            format!("Refresh the tools of upstream server {}", quoted(server)),
            SERVER_KEYS,
        ),
        _ => (
            format!(
                "Release blocked tools of upstream server {}",
                quoted(server)
            ),
            SERVER_KEYS,
        ),
    };
    let mut description = ChangeDescription::titled(action, title, params, keys);
    if !state
        .upstreams
        .manifests()
        .iter()
        .any(|manifest| manifest.name == server)
    {
        return description.blocked(super::gone("upstream server"));
    }
    let releases = action == "upstream.quarantine.clear"
        || params
            .get("clear_quarantine")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
    if action == "upstream.reconnect" && releases {
        description
            .changes
            .push(change("Also clears quarantine for this server's tools"));
    }
    if releases {
        let blocked = state
            .upstreams
            .quarantined_tools(server)
            .await
            .unwrap_or_default();
        // Tools awaiting a contract review stay blocked; the outcome says so.
        description.changes.push(change(if blocked.is_empty() {
            "No tools are blocked after a definition change".to_owned()
        } else {
            format!(
                "Blocked after a definition change: {}",
                quoted_list(&blocked)
            )
        }));
    }
    description
}
