//! The tenant's display name and its audit retention and routing rules.

use serde_json::Value;
use waygate_changeset::ChangeRequest;

use super::{change, field_change, param, quoted, unreadable, ChangeDescription};
use crate::state::AdminState;

const TENANT_KEYS: &[&str] = &["display_name"];
const RETENTION_SET_KEYS: &[&str] = &["category", "delete_after_days"];
const RETENTION_CLEAR_KEYS: &[&str] = &["category"];
const ROUTING_SET_KEYS: &[&str] = &["exporter_name", "enabled"];
const ROUTING_CLEAR_KEYS: &[&str] = &["exporter_name"];

pub(super) async fn describe(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let params = &request.params;
    let tenant = request.tenant_id.as_str();
    match action {
        "tenant.update" => {
            let Some(name) = param(params, "display_name") else {
                return ChangeDescription::undescribed(action);
            };
            let mut description = ChangeDescription::titled(
                action,
                "Rename the tenant".to_owned(),
                params,
                TENANT_KEYS,
            );
            let current = match state.identity.tenants.get() {
                Some(store) => store.get(tenant).await.ok().flatten(),
                None => None,
            };
            description.changes.push(match current {
                Some(current) => field_change("Name", quoted(&current.display_name), quoted(name)),
                None => change(format!("Name: {}", quoted(name))),
            });
            description
        }
        "audit.retention.set" | "audit.retention.clear" => {
            let Some(category) = param(params, "category") else {
                return ChangeDescription::undescribed(action);
            };
            let set = action == "audit.retention.set";
            let mut description = ChangeDescription::titled(
                action,
                if set {
                    format!("Set audit retention for {}", quoted(category))
                } else {
                    format!("Remove audit retention for {}", quoted(category))
                },
                params,
                if set {
                    RETENTION_SET_KEYS
                } else {
                    RETENTION_CLEAR_KEYS
                },
            );
            let current = match state.observability.retention.get() {
                Some(store) => store.list(Some(tenant)).await.map(|rules| {
                    rules
                        .into_iter()
                        .find(|rule| rule.category == category)
                        .map(|rule| rule.delete_after_days)
                }),
                None => return description.noted(unreadable("retention rule")),
            };
            let Ok(current) = current else {
                return description.noted(unreadable("retention rule"));
            };
            let proposed = set
                .then(|| params.get("delete_after_days").and_then(Value::as_i64))
                .flatten();
            if current.map(i64::from) == proposed {
                description.note = Some("The proposed rule matches the current one.".into());
            } else {
                description.changes.push(field_change(
                    "Delete records older than",
                    current.map_or_else(|| "never".to_owned(), |days| days_text(i64::from(days))),
                    proposed.map_or_else(|| "never".to_owned(), days_text),
                ));
            }
            description
        }
        "audit.routing.set" | "audit.routing.clear" => {
            let Some(exporter) = param(params, "exporter_name") else {
                return ChangeDescription::undescribed(action);
            };
            let set = action == "audit.routing.set";
            let mut description = ChangeDescription::titled(
                action,
                if set {
                    format!("Set audit routing for exporter {}", quoted(exporter))
                } else {
                    format!("Remove audit routing for exporter {}", quoted(exporter))
                },
                params,
                if set {
                    ROUTING_SET_KEYS
                } else {
                    ROUTING_CLEAR_KEYS
                },
            );
            let rules = match state.observability.routing.get() {
                Some(store) => store.list(Some(tenant)).await,
                None => return description.noted(unreadable("routing rule")),
            };
            let Ok(rules) = rules else {
                return description.noted(unreadable("routing rule"));
            };
            let current = rules
                .iter()
                .find(|rule| rule.exporter_name == exporter)
                .map(|rule| rule.enabled);
            let proposed = set
                .then(|| params.get("enabled").and_then(Value::as_bool))
                .flatten();
            let rule = |enabled: Option<bool>| match enabled {
                Some(true) => "enabled",
                Some(false) => "disabled",
                None => "no rule",
            };
            if current == proposed {
                description.note = Some("The proposed rule matches the current one.".into());
            } else {
                description
                    .changes
                    .push(field_change("Rule", rule(current), rule(proposed)));
            }
            if set && rules.is_empty() {
                description.changes.push(change(
                    "This is the tenant's first routing rule, so exporters without an enabled \
                     rule stop receiving its events",
                ));
            }
            description
        }
        other => ChangeDescription::undescribed(other),
    }
}

fn days_text(days: i64) -> String {
    format!("{days} day{}", if days == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_periods_read_as_days() {
        assert_eq!(days_text(1), "1 day");
        assert_eq!(days_text(30), "30 days");
    }
}
