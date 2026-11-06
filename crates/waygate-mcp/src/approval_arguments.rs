//! The argument view shown to an administrator deciding whether a held tool
//! call may run. Approval binds the complete original arguments; this view
//! changes only what is displayed, never what is hashed or dispatched.

use serde_json::{Map, Value};

/// Shown in place of every value of a tool whose reviewed input
/// classification is sensitive.
pub const SENSITIVE_INPUT: &str = "[REDACTED:SENSITIVE_INPUT]";
/// Shown in place of a value whose field name marks credential material.
pub const SENSITIVE_FIELD: &str = "[REDACTED:SENSITIVE_FIELD]";

/// The approver's view of a call's arguments.
///
/// For a tool whose reviewed input classification is sensitive, only the
/// submitted schema fields appear, each with [`SENSITIVE_INPUT`]. Otherwise
/// every value appears with recognized credentials redacted.
pub fn approval_view<'a>(
    arguments: &Value,
    sensitive_input: bool,
    schema_fields: impl IntoIterator<Item = &'a str>,
) -> Value {
    if !sensitive_input {
        return redacted_arguments(arguments);
    }
    // Use schema-owned names, not arbitrary user-controlled object keys.
    Value::Object(
        schema_fields
            .into_iter()
            .filter(|name| arguments.get(*name).is_some())
            .map(|name| (name.to_owned(), Value::String(SENSITIVE_INPUT.to_owned())))
            .collect::<Map<String, Value>>(),
    )
}

/// How many submitted fields [`approval_view`] leaves out: for sensitive
/// input, the fields the schema does not declare. Their names are
/// caller-controlled, so the view does not show them.
pub fn undisclosed_fields<'a>(
    arguments: &Value,
    sensitive_input: bool,
    schema_fields: impl IntoIterator<Item = &'a str>,
) -> u32 {
    let Some(arguments) = arguments.as_object() else {
        return 0;
    };
    if !sensitive_input {
        return 0;
    }
    let declared: Vec<&str> = schema_fields.into_iter().collect();
    let undeclared = arguments
        .keys()
        .filter(|key| !declared.contains(&key.as_str()))
        .count();
    u32::try_from(undeclared).unwrap_or(u32::MAX)
}

/// Every argument value with recognized credential material and sensitive
/// field names replaced by labeled markers.
pub fn redacted_arguments(arguments: &Value) -> Value {
    // The approver must see effect destinations and payload content to make
    // the decision — including PII-shaped values, since an unintended
    // recipient or an exfiltrated value is exactly what a human review
    // exists to catch. Every value the approval hash covers is shown in
    // full; only recognized credential material and sensitive key names are
    // replaced, and each replacement is an explicit labeled marker, never a
    // silent omission.
    let (without_secrets, _) = crate::inspection::secrets::redact_json_value(arguments);
    redact_sensitive_argument_keys(without_secrets)
}

/// Normalize a field name to lower snake_case before sensitive-marker
/// matching, so `clientSecret`, `client-secret`, `client.secret`, and
/// `client_secret` all reach the same comparison form. Camel boundaries
/// (a lowercase letter or digit followed by an uppercase letter) become
/// underscores; consecutive capitals collapse (`APIKey` → `apikey`).
fn normalize_argument_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len() + 4);
    let mut previous_lower_or_digit = false;
    for ch in key.chars() {
        if ch == '-' || ch == '.' {
            normalized.push('_');
            previous_lower_or_digit = false;
            continue;
        }
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            normalized.push('_');
        }
        previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        normalized.push(ch.to_ascii_lowercase());
    }
    normalized
}

fn redact_sensitive_argument_keys(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(redact_sensitive_argument_keys)
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    // Match markers as whole underscore-delimited segments
                    // anywhere in the key, so `aws_secret_access_key` and
                    // `secretAccessKey` redact the same as `secret` — a
                    // credential-bearing word buried mid-key must not slip
                    // past an exact/suffix comparison.
                    let padded = format!("_{}_", normalize_argument_key(&key));
                    let sensitive = [
                        "authorization",
                        "password",
                        "passwd",
                        "secret",
                        "token",
                        "api_key",
                        "apikey",
                        "credential",
                        "private_key",
                    ]
                    .iter()
                    .any(|marker| padded.contains(&format!("_{marker}_")));
                    (
                        key,
                        if sensitive {
                            Value::String(SENSITIVE_FIELD.to_owned())
                        } else {
                            redact_sensitive_argument_keys(value)
                        },
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn values_are_shown_with_credential_fields_redacted() {
        let view = approval_view(
            &json!({"to": "alice@example.test", "body": "hello",
                "auth": {"clientSecret": "x", "region": "us"}}),
            false,
            ["to", "body", "auth"],
        );
        assert_eq!(
            view,
            json!({"to": "alice@example.test", "body": "hello",
                "auth": {"clientSecret": SENSITIVE_FIELD, "region": "us"}})
        );
    }

    #[test]
    fn sensitive_input_shows_only_submitted_schema_fields() {
        let view = approval_view(
            &json!({"selector": "#id", "contents": "secret text", "extra": 1}),
            true,
            ["selector", "contents", "unused"],
        );
        assert_eq!(
            view,
            json!({"selector": SENSITIVE_INPUT, "contents": SENSITIVE_INPUT})
        );
        let arguments = json!({"selector": "#id", "extra": 1, "other": 2});
        assert_eq!(undisclosed_fields(&arguments, true, ["selector"]), 2);
        assert_eq!(undisclosed_fields(&arguments, false, ["selector"]), 0);
    }

    #[test]
    fn marker_words_inside_keys_are_found() {
        assert_eq!(normalize_argument_key("APIKey"), "apikey");
        assert_eq!(normalize_argument_key("client.secret"), "client_secret");
        let view = redacted_arguments(&json!({"aws_secret_access_key": "k", "note": "n"}));
        assert_eq!(view["aws_secret_access_key"], SENSITIVE_FIELD);
        assert_eq!(view["note"], "n");
    }
}
