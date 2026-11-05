//! Gateway agent configurations.

use serde_json::Value;
use waygate_changeset::ChangeRequest;
use waygate_dashboard_stores::agent_config::AgentConfig;

use super::{
    change, field_change, found, list_changes, param, param_id, quoted, quoted_list,
    ChangeDescription, Lookup,
};
use crate::state::AdminState;

/// Scalar settings in reading order, with their card labels. Instructions
/// and the tool allowlist are described separately.
const SETTINGS: [(&str, &str); 7] = [
    ("name", "Name"),
    ("kind", "Kind"),
    ("model_alias", "Model"),
    ("max_steps", "Step limit"),
    ("max_tool_calls", "Tool call limit"),
    ("token_budget", "Token budget"),
    ("enabled", "Enabled"),
];
/// Instructions are a document; the card notes a change and leaves the text
/// to the exact parameters, which therefore stay open when it is present.
const CONFIG_KEYS: &[&str] = &[
    "name",
    "kind",
    "model_alias",
    "allowed_tools",
    "max_steps",
    "max_tool_calls",
    "token_budget",
    "enabled",
];
const UPDATE_KEYS: &[&str] = &["agent_id", "config"];
const DELETE_KEYS: &[&str] = &["agent_id"];

pub(super) async fn describe(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let params = &request.params;
    match request.action_type.as_str() {
        "agent_config.create" => {
            let Some(name) = param(params, "name") else {
                return ChangeDescription::undescribed("agent_config.create");
            };
            let mut description = ChangeDescription::titled(
                "agent_config.create",
                format!("Create gateway agent {}", quoted(name)),
                params,
                CONFIG_KEYS,
            );
            for (key, label) in SETTINGS.iter().skip(1) {
                if let Some(value) = params.get(*key) {
                    description
                        .changes
                        .push(change(format!("{label}: {}", shown(value))));
                }
            }
            description.changes.push(change(format!(
                "Tools: {}",
                quoted_list(&super::param_list(params, "allowed_tools"))
            )));
            if param(params, "instructions").is_some_and(|text| !text.is_empty()) {
                description
                    .changes
                    .push(change("Instructions: included in the exact parameters"));
            }
            description
        }
        "agent_config.update" => {
            let agent = found!(agent(state, request).await);
            let Some(config) = params.get("config").filter(|config| config.is_object()) else {
                return ChangeDescription::undescribed("agent_config.update");
            };
            let mut description = ChangeDescription::titled(
                "agent_config.update",
                format!("Change gateway agent {}", quoted(&agent.name)),
                params,
                UPDATE_KEYS,
            );
            // The configuration replaces the agent's whole configuration;
            // a setting the card does not describe keeps the parameters open.
            let mut config_keys = CONFIG_KEYS.to_vec();
            config_keys.push("instructions");
            description.covers_params &= super::only_keys(config, &config_keys);
            let current = serde_json::to_value(&agent).unwrap_or(Value::Null);
            for (key, label) in SETTINGS {
                let (now, next) = (
                    current.get(key).unwrap_or(&Value::Null),
                    config.get(key).unwrap_or(&Value::Null),
                );
                if now != next {
                    description
                        .changes
                        .push(field_change(label, shown(now), shown(next)));
                }
            }
            description.changes.extend(list_changes(
                "Tools",
                &agent.allowed_tools,
                &super::param_list(config, "allowed_tools"),
            ));
            let instructions = config.get("instructions").and_then(Value::as_str);
            if instructions.filter(|text| !text.is_empty())
                != agent
                    .instructions
                    .as_deref()
                    .filter(|text| !text.is_empty())
            {
                description.changes.push(change(
                    "Instructions changed; the new text is in the exact parameters",
                ));
                description.covers_params = false;
            }
            if description.changes.is_empty() {
                description.note =
                    Some("The proposed configuration matches the current one.".into());
            }
            description
        }
        "agent_config.delete" => {
            let agent = found!(agent(state, request).await);
            let mut description = ChangeDescription::titled(
                "agent_config.delete",
                format!("Delete gateway agent {}", quoted(&agent.name)),
                params,
                DELETE_KEYS,
            );
            description.changes = vec![
                change(format!("Model: {}", quoted(&agent.model_alias))),
                change(format!("Tools: {}", quoted_list(&agent.allowed_tools))),
            ];
            description
        }
        other => ChangeDescription::undescribed(other),
    }
}

/// The agent a change or deletion targets.
async fn agent(state: &AdminState, request: &ChangeRequest) -> Lookup<AgentConfig> {
    let action = request.action_type.as_str();
    let Some(id) = param_id(&request.params, "agent_id") else {
        return Lookup::Fallback(ChangeDescription::undescribed(action));
    };
    let read = match state.agent.agent_configs.get() {
        Some(store) => Some(store.get(&request.tenant_id, id).await),
        None => None,
    };
    Lookup::from_read(action, "gateway agent", read)
}

/// A setting value in words: text quoted, numbers as written, yes or no,
/// and none for an absent value.
fn shown(value: &Value) -> String {
    match value {
        Value::String(text) => quoted(text),
        Value::Bool(true) => "yes".to_owned(),
        Value::Bool(false) => "no".to_owned(),
        Value::Null => "none".to_owned(),
        other => other.to_string(),
    }
}
