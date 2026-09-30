//! JSON Schema validation shared by admitted input and output contracts,
//! plus the denial-evidence recorders for the pipeline's early refusals.

use waygate_invocation::{InvocationError, InvocationMode};

use crate::audit::AuditOutcome;

use super::{DefaultInvocationService, InvocationContext};

impl DefaultInvocationService {
    pub(super) async fn record_contract_drift_refusal(&self, ctx: &InvocationContext<'_>) {
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::Denied)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_reason("operation contract changed during execution"),
            )
            .await;
    }

    pub(super) async fn record_read_only_refusal(&self, ctx: &InvocationContext<'_>) {
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::Denied)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_reason("operation is not admitted under the read-only authority ceiling"),
            )
            .await;
    }

    pub(super) async fn record_read_only_operation_refusal(&self, ctx: &InvocationContext<'_>) {
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::Denied)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_reason(
                        "dispatch tool has no reviewed classification for this operation, so the \
                         read-only authority ceiling does not admit it",
                    ),
            )
            .await;
    }
}

pub(super) fn enforce_invocation_mode(
    ctx: &InvocationContext<'_>,
    mode: InvocationMode,
) -> Result<(), InvocationError> {
    if mode != InvocationMode::ReadOnly {
        return Ok(());
    }
    if !ctx.tool_snapshot().facts().admitted_by_read_only_ceiling() {
        return Err(InvocationError::ReadOnlyRequired {
            tool: format!("{}.{}", ctx.server, ctx.tool),
        });
    }
    // A tool that dispatches by argument admits only the operations its
    // manifest reviewed. Falling back to the tool-level entry is the
    // conservative direction for risk, because the ceiling holds that entry at
    // least as severe as every operation it names — but for a dispatch tool
    // that entry is a claim about a set nobody enumerated, and here it is the
    // claim that admitted the tool under this ceiling at all. Inheriting it
    // would let an unreviewed operation ride in on the reviewed ones.
    //
    // Only under a restricted ceiling. An ordinary call keeps the documented
    // refinement semantics, where an unnamed value leaves the tool-level
    // classification in force.
    let Some(discriminator) = ctx.tool_snapshot().discriminator() else {
        return Ok(());
    };
    if !ctx.operation_classified {
        return Err(InvocationError::ReadOnlyOperationRequired {
            tool: format!("{}.{}", ctx.server, ctx.tool),
            discriminator: discriminator.to_owned(),
            // Bounded printable ASCII by the admissibility check in
            // `admit_snapshot`, and already recorded in the audit trail's
            // operation column, so naming it here teaches the caller what to
            // fix without widening exposure. A call that carried no
            // discriminator at all names no value to echo, and says so rather
            // than rendering an empty one.
            operation: ctx.operation.clone().unwrap_or_else(|| "<none>".to_owned()),
        });
    }
    Ok(())
}

/// Result of checking one JSON value with its admitted validator.
#[derive(Debug)]
pub(super) enum SchemaCheck {
    /// The value validates against the schema.
    Pass,
    /// The value does not match the schema. Carries schema-side metadata only,
    /// including schema-declared required-field names, but never keys or values
    /// read from the caller or upstream instance.
    Violation(String),
}

/// Validate a JSON value with the validator compiled for its admitted schema.
///
/// `schema` is the source schema the validator was compiled from, when the
/// caller has it. Supplying it lets a rejection name the properties the schema
/// does accept; omitting it only costs that detail.
pub(super) fn check_value_against_validator(
    validator: &jsonschema::Validator,
    value: &serde_json::Value,
    schema: Option<&serde_json::Value>,
) -> SchemaCheck {
    match validator.validate(value) {
        Ok(()) => SchemaCheck::Pass,
        Err(first) => SchemaCheck::Violation(sanitize_validation_error(&first, schema)),
    }
}

/// Upper bound on schema-declared names or values listed in one reason string.
/// The reason reaches durable audit storage, so a large schema must not be able
/// to grow an unbounded row.
const MAX_LISTED: usize = 12;

/// Join schema-declared items into a bounded, comma-separated list.
fn render_list(items: impl Iterator<Item = String>) -> String {
    let mut listed: Vec<String> = items.take(MAX_LISTED + 1).collect();
    let overflow = listed.len() > MAX_LISTED;
    listed.truncate(MAX_LISTED);
    let body = listed.join(", ");
    if overflow {
        format!("{body}, and more")
    } else {
        body
    }
}

/// The property names the schema node that raised this error declares.
///
/// Resolves the parent of the failing rule's schema path and reads its
/// `properties` keys. These are schema-declared names, never keys read from the
/// instance being validated.
fn declared_properties(
    e: &jsonschema::ValidationError,
    schema: Option<&serde_json::Value>,
) -> Option<String> {
    let schema = schema?;
    let path = e.schema_path().to_string();
    let parent = path.rsplit_once('/').map_or("", |(head, _)| head);
    let node = if parent.is_empty() {
        schema
    } else {
        schema.pointer(parent)?
    };
    let properties = node.get("properties")?.as_object()?;
    if properties.is_empty() {
        return None;
    }
    Some(render_list(properties.keys().map(|k| format!("`{k}`"))))
}

/// Build a payload-safe reason string from a validation error.
///
/// Validator display text includes offending instance values for common
/// variants. Instance paths can also contain caller-controlled object keys.
/// Only schema-side rule metadata is retained here — declared field names,
/// declared bounds, and declared permitted values — so the same reason is safe
/// for client errors, logs, and durable audit storage.
///
/// A caller already knows what it sent; what it cannot see is what the schema
/// accepts. Naming the accepted side turns a rejection the caller can only
/// guess against into one it can correct in a single retry, without echoing
/// anything the caller supplied. `pattern` is the deliberate exception: the
/// regex is schema-side but is withheld, because it describes how a value is
/// checked rather than what the caller may send.
pub fn sanitize_validation_error(
    e: &jsonschema::ValidationError,
    schema: Option<&serde_json::Value>,
) -> String {
    use jsonschema::error::ValidationErrorKind as K;
    let label: String = match e.kind() {
        K::Minimum { limit } => format!("value below minimum {limit}"),
        K::Maximum { limit } => format!("value above maximum {limit}"),
        K::ExclusiveMinimum { limit } => format!("value not above exclusive minimum {limit}"),
        K::ExclusiveMaximum { limit } => format!("value not below exclusive maximum {limit}"),
        K::MinItems { limit } => format!("fewer items than the minimum {limit}"),
        K::MaxItems { limit } => format!("more items than the maximum {limit}"),
        K::MinLength { limit } => format!("shorter than the minimum length {limit}"),
        K::MaxLength { limit } => format!("longer than the maximum length {limit}"),
        K::MinProperties { limit } => format!("fewer properties than the minimum {limit}"),
        K::MaxProperties { limit } => format!("more properties than the maximum {limit}"),
        K::Enum { options } => match options.as_array() {
            Some(values) => format!(
                "value is not one of the permitted values: {}",
                render_list(values.iter().map(ToString::to_string))
            ),
            None => "value is not one of the permitted values".into(),
        },
        K::Constant { expected_value } => {
            format!("value does not equal the required constant {expected_value}")
        }
        K::AdditionalProperties { .. } => match declared_properties(e, schema) {
            Some(accepted) => {
                format!("unexpected property; accepted properties are {accepted}")
            }
            None => "unexpected property".into(),
        },
        K::OneOfNotValid { .. } => "value matches none of the permitted variants".into(),
        K::OneOfMultipleValid { .. } => "value matches more than one permitted variant".into(),
        K::Pattern { .. } => "pattern mismatch".into(),
        K::Required { property } => match property {
            serde_json::Value::String(s) => format!("required field `{s}` is missing"),
            _ => "required field is missing".into(),
        },
        K::Type { kind } => format!("type mismatch (expected {kind:?})"),
        _ => "validation failure".into(),
    };
    format!("{label} (schema rule `{}`)", e.schema_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(schema: &serde_json::Value, value: &serde_json::Value) -> SchemaCheck {
        let validator = jsonschema::validator_for(schema).expect("test schema must compile");
        check_value_against_validator(&validator, value, Some(schema))
    }

    fn violation(schema: &serde_json::Value, value: &serde_json::Value) -> String {
        match check(schema, value) {
            SchemaCheck::Violation(reason) => reason,
            SchemaCheck::Pass => panic!("value was expected to violate the schema"),
        }
    }

    #[test]
    fn sanitizer_does_not_leak_caller_controlled_object_keys() {
        let schema = json!({
            "type": "object",
            "additionalProperties": {"type": "integer"}
        });
        let value = json!({"caller-key-secret-marker": "wrong type"});
        let SchemaCheck::Violation(reason) = check(&schema, &value) else {
            panic!("dynamic property type mismatch must be a Violation");
        };
        assert!(!reason.contains("caller-key-secret-marker"));
        assert!(!reason.contains("wrong type"));
        assert!(reason.contains("schema rule `"));
    }

    #[test]
    fn sanitizer_does_not_leak_payload_values_on_pattern_violation() {
        let schema = json!({"type": "string", "pattern": "^[a-z]+$"});
        let value = json!("ssn-leak-payload-1234567");
        let SchemaCheck::Violation(reason) = check(&schema, &value) else {
            panic!("pattern mismatch must be a Violation");
        };
        assert!(reason.starts_with("pattern mismatch"));
        assert!(!reason.contains("^[a-z]+$"));
        assert!(!reason.contains("ssn-leak-payload"));
        assert!(!reason.contains("1234567"));
    }

    #[test]
    fn sanitizer_does_not_leak_payload_values_on_minimum_violation() {
        let schema = json!({"type": "integer", "minimum": 0});
        let value = json!(-987654321);
        let SchemaCheck::Violation(reason) = check(&schema, &value) else {
            panic!("minimum violation must be a Violation");
        };
        assert!(reason.contains("below minimum"));
        assert!(!reason.contains("987654321"));
    }

    #[test]
    fn empty_object_schema_accepts_anything() {
        assert!(matches!(
            check(&json!({}), &json!({"anything": [1, 2, 3]})),
            SchemaCheck::Pass,
        ));
    }

    #[test]
    fn scalar_payload_follows_scalar_schema() {
        let schema = json!({"type": "integer", "minimum": 0});
        assert!(matches!(check(&schema, &json!(7)), SchemaCheck::Pass));
        assert!(matches!(
            check(&schema, &json!(-1)),
            SchemaCheck::Violation(_),
        ));
    }

    /// An unexpected property names the accepted side of the contract and never
    /// the key the caller sent, which is the half that can carry arbitrary
    /// caller text into durable audit storage.
    #[test]
    fn unexpected_property_names_accepted_properties_not_the_rejected_key() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "operation": {"type": "string"},
                "includeOutputSchema": {"type": "boolean"},
            },
        });
        let reason = violation(&schema, &json!({"caller-key-secret-marker": "x"}));
        assert!(!reason.contains("caller-key-secret-marker"), "{reason}");
        assert!(reason.contains("`operation`"), "{reason}");
        assert!(reason.contains("`includeOutputSchema`"), "{reason}");
    }

    /// Without the source schema the rejection still refuses to echo the
    /// caller's key; it only loses the accepted-property detail.
    #[test]
    fn unexpected_property_without_schema_still_withholds_the_rejected_key() {
        let schema = json!({"type": "object", "additionalProperties": false});
        let validator = jsonschema::validator_for(&schema).expect("test schema must compile");
        let value = json!({"caller-key-secret-marker": "x"});
        let SchemaCheck::Violation(reason) =
            check_value_against_validator(&validator, &value, None)
        else {
            panic!("unexpected property must be a Violation");
        };
        assert!(!reason.contains("caller-key-secret-marker"), "{reason}");
    }

    /// Generated upstream contracts put object bodies behind `$ref`. The
    /// accepted-property lookup resolves the node that owns the failing rule,
    /// and degrades to the plain refusal rather than naming some other node's
    /// properties when it cannot.
    #[test]
    fn unexpected_property_under_a_ref_never_names_an_unrelated_node() {
        let schema = json!({
            "type": "object",
            "properties": {"body": {"$ref": "#/definitions/CreateIssue"}},
            "definitions": {
                "CreateIssue": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {"title": {"type": "string"}},
                },
            },
        });
        let reason = violation(&schema, &json!({"body": {"caller-key-secret-marker": "x"}}));
        assert!(!reason.contains("caller-key-secret-marker"), "{reason}");
        assert!(!reason.contains("`body`"), "{reason}");
        assert!(reason.starts_with("unexpected property"), "{reason}");
    }

    #[test]
    fn bound_violations_state_the_declared_bound() {
        let reason = violation(
            &json!({"type": "object", "properties": {"limit": {"type": "integer", "maximum": 50}}}),
            &json!({"limit": 100}),
        );
        assert!(reason.contains("maximum 50"), "{reason}");
        assert!(!reason.contains("100"), "{reason}");

        let reason = violation(
            &json!({"type": "object", "properties": {"sections": {"type": "array", "minItems": 1}}}),
            &json!({"sections": []}),
        );
        assert!(reason.contains("minimum 1"), "{reason}");
    }

    #[test]
    fn enum_violation_lists_the_permitted_values() {
        let reason = violation(
            &json!({"enum": ["read", "mutation", "destructive"]}),
            &json!("write"),
        );
        assert!(reason.contains("read"), "{reason}");
        assert!(reason.contains("destructive"), "{reason}");
        assert!(!reason.contains("write"), "{reason}");
    }

    /// A wide schema must not grow an unbounded audit row.
    #[test]
    fn listed_schema_names_are_bounded() {
        let properties: serde_json::Map<String, serde_json::Value> = (0..MAX_LISTED + 10)
            .map(|i| (format!("field_{i}"), json!({"type": "string"})))
            .collect();
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": properties,
        });
        let reason = violation(&schema, &json!({"nope": "x"}));
        assert!(reason.contains("and more"), "{reason}");
        assert_eq!(reason.matches("`field_").count(), MAX_LISTED, "{reason}");
    }
}
