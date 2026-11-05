//! The tenant's display name and its audit retention and routing rules.

use serde_json::Value;
use waygate_changeset::ChangeRequest;

use super::{change, field_change, param, quoted, ChangeDescription, DescribedChange};
use crate::state::AdminState;

const TENANT_KEYS: &[&str] = &["display_name"];
const RETENTION_SET_KEYS: &[&str] = &["category", "delete_after_days"];
const RETENTION_CLEAR_KEYS: &[&str] = &["category"];
const ROUTING_SET_KEYS: &[&str] = &["exporter_name", "enabled", "config"];
const ROUTING_CLEAR_KEYS: &[&str] = &["exporter_name"];
#[cfg(test)]
pub(super) const DECLARED: &[(&str, &[&str])] = &[
    ("tenant.update", TENANT_KEYS),
    ("audit.retention.set", RETENTION_SET_KEYS),
    ("audit.retention.clear", RETENTION_CLEAR_KEYS),
    ("audit.routing.set", ROUTING_SET_KEYS),
    ("audit.routing.clear", ROUTING_CLEAR_KEYS),
];

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
            match current {
                Some(current) => description.changes.push(field_change(
                    "Name",
                    quoted(&current.display_name),
                    quoted(name),
                )),
                None => {
                    description
                        .changes
                        .push(change(format!("Name: {}", quoted(name))));
                    return description.cannot_read("tenant");
                }
            }
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
            let rules = match state.observability.retention.get() {
                Some(store) => store.list(Some(tenant)).await,
                None => return description.cannot_read("retention rule"),
            };
            let Ok(rules) = rules else {
                return description.cannot_read("retention rule");
            };
            let rules: Vec<(String, i64)> = rules
                .into_iter()
                .map(|rule| (rule.category, i64::from(rule.delete_after_days)))
                .collect();
            let requested = params.get("delete_after_days").and_then(Value::as_i64);
            match retention_change(&rules, category, set.then_some(requested).flatten(), set) {
                Ok(change) => description.changes.push(change),
                Err(unchanged) => description.note = Some(unchanged),
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
                None => return description.cannot_read("routing rule"),
            };
            let Ok(rules) = rules else {
                return description.cannot_read("routing rule");
            };
            let current = rules.iter().find(|rule| rule.exporter_name == exporter);
            let proposed = set
                .then(|| params.get("enabled").and_then(Value::as_bool))
                .flatten();
            let rule = |enabled: Option<bool>| match enabled {
                Some(true) => "enabled",
                Some(false) => "disabled",
                None => "no rule",
            };
            let current_enabled = current.map(|rule| rule.enabled);
            if current_enabled != proposed {
                description.changes.push(field_change(
                    "Rule",
                    rule(current_enabled),
                    rule(proposed),
                ));
            }
            // Setting a rule replaces its exporter settings, and an omitted
            // setting object is empty; clearing deletes them with the rule.
            {
                let empty = Value::Object(serde_json::Map::new());
                let proposed_config = if set {
                    params.get("config").unwrap_or(&empty)
                } else {
                    &empty
                };
                let current_config = current.map_or(&empty, |rule| &rule.config);
                if proposed_config != current_config {
                    let settings = |config: &Value| match config.as_object() {
                        Some(map) if map.is_empty() => "none".to_owned(),
                        _ => quoted(&config.to_string()),
                    };
                    description.changes.push(field_change(
                        "Exporter settings",
                        settings(current_config),
                        settings(proposed_config),
                    ));
                }
            }
            if description.changes.is_empty() {
                description.note = Some("The proposed rule matches the current one.".into());
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

/// How long a category's records are kept before and after the change,
/// or `None` when that does not change. A category without its own rule
/// follows the tenant's catch-all rule (`*`); the catch-all itself has
/// nothing to fall back to.
fn retention_change(
    rules: &[(String, i64)],
    category: &str,
    requested: Option<i64>,
    set: bool,
) -> Result<DescribedChange, String> {
    let days = |name: &str| {
        rules
            .iter()
            .find(|(rule, _)| rule == name)
            .map(|(_, days)| *days)
    };
    let fallback = (category != "*").then(|| days("*")).flatten();
    let own = days(category);
    // Each side records whether the period comes from the catch-all rule,
    // since moving between an own rule and the catch-all is a change even
    // when the period is the same.
    let current = (own.or(fallback), own.is_none() && fallback.is_some());
    let proposed = if set {
        (requested, false)
    } else {
        (fallback, fallback.is_some())
    };
    let shown = |(days, from_catch_all): (Option<i64>, bool)| match days {
        None => "never".to_owned(),
        Some(days) if from_catch_all => {
            format!("{}, by the tenant's catch-all rule", days_text(days))
        }
        Some(days) => days_text(days),
    };
    let label = if category == "*" {
        "Delete records without their own rule older than"
    } else {
        "Delete records older than"
    };
    if current == proposed {
        return Err(format!(
            "The rule is unchanged: {} {}.",
            label.to_lowercase(),
            shown(current)
        ));
    }
    Ok(field_change(label, shown(current), shown(proposed)))
}

fn days_text(days: i64) -> String {
    format!("{days} day{}", if days == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(pairs: &[(&str, i64)]) -> Vec<(String, i64)> {
        pairs
            .iter()
            .map(|(name, days)| ((*name).to_owned(), *days))
            .collect()
    }

    #[test]
    fn retention_changes_account_for_the_catch_all_rule() {
        let with_catch_all = rules(&[("*", 30), ("invocation", 365)]);
        let text = |change: Result<DescribedChange, String>| change.ok().map(|change| change.text);
        // Clearing an override falls back to the catch-all, not to "never".
        assert_eq!(
            text(retention_change(&with_catch_all, "invocation", None, false)).as_deref(),
            Some("Delete records older than: 365 days → 30 days, by the tenant's catch-all rule")
        );
        // A category without its own rule starts from the catch-all.
        assert_eq!(
            text(retention_change(&with_catch_all, "admin", Some(7), true)).as_deref(),
            Some("Delete records older than: 30 days, by the tenant's catch-all rule → 7 days")
        );
        // Clearing the catch-all leaves categories without a rule kept forever.
        assert_eq!(
            text(retention_change(&with_catch_all, "*", None, false)).as_deref(),
            Some("Delete records without their own rule older than: 30 days → never")
        );
        assert!(retention_change(&with_catch_all, "invocation", Some(365), true).is_err());
        assert!(retention_change(&rules(&[]), "admin", None, false).is_err());
        // An own rule equal to the catch-all is still a different rule.
        let only_catch_all = rules(&[("*", 30)]);
        assert_eq!(
            text(retention_change(
                &only_catch_all,
                "invocation",
                Some(30),
                true
            ))
            .as_deref(),
            Some("Delete records older than: 30 days, by the tenant's catch-all rule → 30 days")
        );
        let equal_override = rules(&[("*", 30), ("invocation", 30)]);
        assert_eq!(
            text(retention_change(&equal_override, "invocation", None, false)).as_deref(),
            Some("Delete records older than: 30 days → 30 days, by the tenant's catch-all rule")
        );
        assert_eq!(
            retention_change(&equal_override, "invocation", Some(30), true).unwrap_err(),
            "The rule is unchanged: delete records older than 30 days."
        );
    }

    #[test]
    fn retention_periods_read_as_days() {
        assert_eq!(days_text(1), "1 day");
        assert_eq!(days_text(30), "30 days");
    }
}
