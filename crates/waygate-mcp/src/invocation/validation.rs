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
pub(super) fn check_value_against_validator(
    validator: &jsonschema::Validator,
    value: &serde_json::Value,
) -> SchemaCheck {
    match validator.validate(value) {
        Ok(()) => SchemaCheck::Pass,
        Err(first) => SchemaCheck::Violation(sanitize_validation_error(&first)),
    }
}

/// Build a payload-safe reason string from a validation error.
///
/// Validator display text includes offending instance values for common
/// variants. Instance paths can also contain caller-controlled object keys.
/// Only schema-side rule metadata, including declared required-field names, is
/// retained here, so the same reason is safe for client errors, logs, and
/// durable audit storage.
pub fn sanitize_validation_error(e: &jsonschema::ValidationError) -> String {
    use jsonschema::error::ValidationErrorKind as K;
    let label: String = match e.kind() {
        K::Minimum { .. } => "value below minimum".into(),
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
        check_value_against_validator(&validator, value)
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
}
