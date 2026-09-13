//! Recipient facts for tools whose complete delivery envelope is `to`, `cc`,
//! and `bcc`. Policies must opt in for a tool with that explicit contract.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

/// Only normalized domains leave the argument boundary. An invalid envelope
/// never exposes a partial set that a policy could mistake for all recipients.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmailRecipients {
    pub valid: bool,
    pub domains: BTreeSet<String>,
}

impl EmailRecipients {
    /// Accept bare ASCII mailboxes, individually or in arrays, in `to`, `cc`,
    /// and `bcc`. Missing fields are empty; at least one recipient is required.
    /// Display names, address lists inside strings, aliases without domains,
    /// domain literals, and internationalized addresses need upstream-specific
    /// normalization and are deliberately outside this contract.
    pub fn from_arguments(arguments: Option<&Map<String, Value>>) -> Self {
        let Some(arguments) = arguments else {
            return Self::default();
        };
        let mut domains = BTreeSet::new();
        let mut count = 0usize;
        for field in ["to", "cc", "bcc"] {
            let Some(value) = arguments.get(field) else {
                continue;
            };
            let values = match value {
                Value::String(_) => std::slice::from_ref(value),
                Value::Array(values) => values.as_slice(),
                _ => return Self::default(),
            };
            for value in values {
                count += 1;
                if count > 1000 {
                    return Self::default();
                }
                let Some(domain) = value.as_str().and_then(mailbox_domain) else {
                    return Self::default();
                };
                domains.insert(domain.to_ascii_lowercase());
            }
        }
        Self {
            valid: count > 0,
            domains,
        }
    }
}

fn mailbox_domain(address: &str) -> Option<&str> {
    if address.len() > 254 || !address.is_ascii() {
        return None;
    }
    let (local, domain) = address.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
    {
        return None;
    }
    if domain.is_empty()
        || !domain.contains('.')
        || domain.len() > 253
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn includes_every_delivery_field_and_normalizes_domains() {
        let value = json!({"to": ["alice@EXAMPLE.COM"], "cc": "bob@example.com", "bcc": ["eve@outside.example"]});
        let facts = EmailRecipients::from_arguments(value.as_object());
        assert!(facts.valid);
        assert_eq!(
            facts.domains,
            BTreeSet::from(["example.com".into(), "outside.example".into()])
        );
    }

    #[test]
    fn ambiguous_or_malformed_recipients_invalidate_the_entire_envelope() {
        for recipient in [
            json!(null),
            json!(42),
            json!({"email":"eve@outside.example"}),
            json!("Eve <eve@outside.example>"),
            json!("a@example.com,b@outside.example"),
            json!("a@outside.example@example.com"),
            json!("a@example.com\r\nBcc: b@outside.example"),
            json!("a@éxample.com"),
            json!("a@example.com."),
            json!("a@-example.com"),
        ] {
            let value = json!({"to":"alice@example.com", "bcc":[recipient]});
            assert_eq!(
                EmailRecipients::from_arguments(value.as_object()),
                EmailRecipients::default()
            );
        }
        for value in [json!({}), json!({"to":[]}), json!({"to":null})] {
            assert!(!EmailRecipients::from_arguments(value.as_object()).valid);
        }
    }

    #[test]
    fn lookalike_domains_stay_distinct_and_large_lists_are_refused() {
        let value = json!({"to":"a@example.com.attacker.example"});
        assert!(!EmailRecipients::from_arguments(value.as_object())
            .domains
            .contains("example.com"));
        let value = json!({"to":vec!["a@example.com"; 1001]});
        assert!(!EmailRecipients::from_arguments(value.as_object()).valid);
    }
}
