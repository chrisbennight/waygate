//! Rate-limit creation, change, and deletion.

use serde_json::Value;
use waygate_changeset::ChangeRequest;
use waygate_quota::RateLimitPolicy;

use super::{change, field_change, found, param, param_id, quoted, ChangeDescription, Lookup};
use crate::state::AdminState;

const CREATE_KEYS: &[&str] = &[
    "name",
    "scope",
    "scope_value",
    "action",
    "bucket_capacity",
    "refill_per_second",
];
const UPDATE_KEYS: &[&str] = &["policy_id", "bucket_capacity", "refill_per_second"];
const DELETE_KEYS: &[&str] = &["policy_id"];
#[cfg(test)]
pub(super) const DECLARED: &[(&str, &[&str])] = &[
    ("rate_limit.create", CREATE_KEYS),
    ("rate_limit.update", UPDATE_KEYS),
    ("rate_limit.delete", DELETE_KEYS),
];

pub(super) async fn describe(state: &AdminState, change: &ChangeRequest) -> ChangeDescription {
    let params = &change.params;
    match change.action_type.as_str() {
        "rate_limit.create" => create(params),
        "rate_limit.update" => update(state, change).await,
        "rate_limit.delete" => delete(state, change).await,
        other => ChangeDescription::undescribed(other),
    }
}

fn create(params: &Value) -> ChangeDescription {
    let action = "rate_limit.create";
    let (Some(name), Some(scope), Some(limited), Some(capacity), Some(refill)) = (
        param(params, "name"),
        param(params, "scope"),
        param(params, "action"),
        params.get("bucket_capacity").and_then(Value::as_i64),
        params.get("refill_per_second").and_then(Value::as_f64),
    ) else {
        return ChangeDescription::undescribed(action);
    };
    let mut description = ChangeDescription::titled(
        action,
        format!("Create rate limit {}", quoted(name)),
        params,
        CREATE_KEYS,
    );
    description.changes = vec![
        change(format!(
            "Applies to: {}",
            applies_to(limited, scope, param(params, "scope_value"))
        )),
        change(format!("Limit: {}", limit(capacity, refill))),
    ];
    description
}

async fn update(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = "rate_limit.update";
    let params = &request.params;
    let current = found!(current(state, request).await);
    let mut description = ChangeDescription::titled(
        action,
        format!("Change rate limit {}", quoted(&current.name)),
        params,
        UPDATE_KEYS,
    );
    // Names are not unique, so the card also states which calls the limit covers.
    description.changes.push(change(format!(
        "Applies to: {}",
        applies_to(
            current.action.as_str(),
            current.scope.as_str(),
            current.scope_value.as_deref()
        )
    )));
    if let Some(reason) = current.inactive_reason() {
        return description.blocked(format!(
            "This rate limit is inactive, so it cannot be changed: {reason}"
        ));
    }
    let mut unchanged = true;
    if let Some(capacity) = params.get("bucket_capacity").and_then(Value::as_i64) {
        if capacity != i64::from(current.bucket_capacity) {
            unchanged = false;
            description
                .changes
                .push(field_change("Capacity", current.bucket_capacity, capacity));
        }
    }
    if let Some(refill) = params.get("refill_per_second").and_then(Value::as_f64) {
        if refill != current.refill_per_second {
            unchanged = false;
            description.changes.push(field_change(
                "Refill per second",
                rate(current.refill_per_second),
                rate(refill),
            ));
        }
    }
    if unchanged {
        description.note = Some("The proposed values match the current ones.".into());
    }
    description
}

async fn delete(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let current = found!(current(state, request).await);
    let mut description = ChangeDescription::titled(
        "rate_limit.delete",
        format!("Delete rate limit {}", quoted(&current.name)),
        &request.params,
        DELETE_KEYS,
    );
    description.changes = vec![
        change(format!(
            "Applies to: {}",
            applies_to(
                current.action.as_str(),
                current.scope.as_str(),
                current.scope_value.as_deref()
            )
        )),
        change(format!(
            "Limit: {}",
            limit(
                i64::from(current.bucket_capacity),
                current.refill_per_second
            )
        )),
    ];
    description
}

/// The policy a change or deletion targets.
async fn current(state: &AdminState, request: &ChangeRequest) -> Lookup<RateLimitPolicy> {
    let action = request.action_type.as_str();
    let Some(id) = param_id(&request.params, "policy_id") else {
        return Lookup::Fallback(ChangeDescription::undescribed(action));
    };
    let read = match state.policy.rate_limit_policies.get() {
        Some(store) => Some(store.get(&request.tenant_id, id).await),
        None => None,
    };
    Lookup::from_read(action, "rate limit", read)
}

/// Which calls a policy limits, in words.
fn applies_to(action: &str, scope: &str, scope_value: Option<&str>) -> String {
    let calls = match action {
        "call" => "Every call",
        "side_effecting_call" => "Side-effecting calls",
        "cost_bearing" => "Cost-bearing calls",
        "discovery" => "Tool discovery",
        other => other,
    };
    let value = scope_value.map(quoted).unwrap_or_default();
    match scope {
        "tenant" => format!("{calls} across the tenant"),
        "principal" => format!("{calls} by principal {value}"),
        "client" => format!("{calls} by client {value}"),
        "server" => format!("{calls} to server {value}"),
        "tool" => format!("{calls} to tool {value}"),
        other => format!("{calls} for {other} {value}"),
    }
}

fn limit(capacity: i64, refill: f64) -> String {
    format!("capacity {capacity}, refilling {} per second", rate(refill))
}

/// A refill rate without a trailing `.0`.
fn rate(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_new_limit_names_what_it_applies_to_and_its_limit() {
        let params = json!({"name": "search-burst", "scope": "tool", "scope_value": "docs.search",
            "action": "call", "bucket_capacity": 60, "refill_per_second": 1.0});
        let description = create(&params);
        assert_eq!(description.title, "Create rate limit “search-burst”");
        let texts: Vec<_> = description
            .changes
            .iter()
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(
            texts,
            [
                "Applies to: Every call to tool “docs.search”",
                "Limit: capacity 60, refilling 1 per second"
            ]
        );
        assert!(description.covers_params);
        assert!(description.outcome.is_some());
    }

    #[test]
    fn an_unexpected_parameter_keeps_the_parameters_open() {
        let params = json!({"name": "all", "scope": "tenant", "action": "discovery",
            "bucket_capacity": 5, "refill_per_second": 0.5, "extra": true});
        let description = create(&params);
        assert_eq!(
            description.changes[0].text,
            "Applies to: Tool discovery across the tenant"
        );
        assert_eq!(
            description.changes[1].text,
            "Limit: capacity 5, refilling 0.5 per second"
        );
        assert!(!description.covers_params);
    }
}
