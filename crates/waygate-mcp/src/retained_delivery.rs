//! Caller-visible retained-response delivery contract.

use std::sync::OnceLock;

use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::files::{FileValue, RETAINED_DELIVERY_META_KEY};

pub const FIELD: &str = "_gateway_delivery";
/// Envelope member carrying a filed result's preview text.
pub const PREVIEW_FIELD: &str = "_gateway_preview";

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationStatus {
    Succeeded,
}

#[derive(Serialize, JsonSchema)]
#[serde(tag = "delivery_status", rename_all = "snake_case")]
pub(crate) enum Delivery {
    File {
        operation_status: OperationStatus,
        file: FileValue,
    },
    Unavailable {
        operation_status: OperationStatus,
        error: String,
        retry_operation: bool,
    },
}

#[derive(Serialize, JsonSchema)]
struct Envelope {
    _gateway_delivery: Delivery,
    /// The upstream's own text for a result delivered as a file, when it
    /// fits the inline threshold and the result is not labeled sensitive.
    /// It sits beside the delivery descriptor rather than in it, so the
    /// `_meta` descriptor stays identical to `_gateway_delivery`.
    #[serde(skip_serializing_if = "Option::is_none")]
    _gateway_preview: Option<String>,
}

fn envelope_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let mut settings = schemars::generate::SchemaSettings::draft2020_12();
        settings.inline_subschemas = true;
        serde_json::to_value(settings.into_generator().into_root_schema_for::<Envelope>())
            .expect("delivery schema is serializable")
    })
}

pub(crate) fn validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(envelope_schema()).expect("valid delivery schema")
    })
}

/// The delivery alternative listed in every tool's output schema. It accepts
/// every envelope the gateway emits but leaves out the file descriptor and
/// error fields, which are the same for every tool: listing them once per
/// tool multiplied the size of each output schema. The full form is returned
/// on request by [`detailed_output_schema`], and the gateway still checks each
/// envelope it emits against it ([`validator`]).
fn listed_envelope_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let statuses: Vec<Value> = envelope_schema()["properties"][FIELD]["oneOf"]
            .as_array()
            .expect("delivery forms are alternatives")
            .iter()
            .map(|form| form["properties"]["delivery_status"]["const"].clone())
            .collect();
        json!({
            "type": "object",
            "required": [FIELD],
            "properties": {
                FIELD: {
                    "type": "object",
                    "required": ["delivery_status", "operation_status"],
                    "properties": {"delivery_status": {"enum": statuses}}
                }
            }
        })
    })
}

/// Keep upstream-local references scoped to the original schema when adding
/// the gateway's alternative response form. The source schema remains the
/// authority for validating recovered upstream bodies.
fn with_delivery_alternative(
    upstream: &Map<String, Value>,
    delivery: &Value,
) -> Map<String, Value> {
    let mut upstream = upstream.clone();
    upstream
        .entry("$id")
        .or_insert_with(|| json!("urn:mcp-gateway:upstream-output"));
    json!({"type":"object", "anyOf":[upstream, delivery]})
        .as_object()
        .expect("object schema")
        .clone()
}

/// The output schema listed for an upstream tool: the upstream's own schema
/// or the compact delivery envelope.
pub fn output_schema(upstream: &Map<String, Value>) -> Map<String, Value> {
    with_delivery_alternative(upstream, listed_envelope_schema())
}

/// [`output_schema`] with the delivery envelope described in full, for a
/// caller that asked for one tool's contract.
pub fn detailed_output_schema(upstream: &Map<String, Value>) -> Map<String, Value> {
    with_delivery_alternative(upstream, envelope_schema())
}

/// Add a filed result's preview to its structured envelope, for clients that
/// give the model only `structuredContent`. Call after [`attach`].
pub(crate) fn attach_preview(result: &mut CallToolResult, preview: String) {
    if let Some(Value::Object(root)) = result.structured_content.as_mut() {
        root.insert(PREVIEW_FIELD.to_owned(), Value::String(preview));
    }
}

/// Mark `result` as a succeeded operation whose response could not be
/// delivered, so a caller never repeats the operation to recover it.
pub fn delivery_failure(mut result: CallToolResult, reason: &str) -> CallToolResult {
    attach(
        &mut result,
        Delivery::Unavailable {
            operation_status: OperationStatus::Succeeded,
            error: reason.to_owned(),
            retry_operation: false,
        },
    );
    result.content.push(ContentBlock::text(format!(
        "The operation succeeded, but its response attachment is unavailable ({reason}). Do not repeat the operation to retrieve its attachment."
    )));
    result
}

pub(crate) fn attach(result: &mut CallToolResult, delivery: Delivery) {
    let delivery = serde_json::to_value(delivery).expect("delivery is serializable");
    result
        .meta
        .get_or_insert_with(Default::default)
        .insert(RETAINED_DELIVERY_META_KEY.to_owned(), delivery.clone());
    let mut root = result
        .structured_content
        .take()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    root.insert(FIELD.to_owned(), delivery);
    result.structured_content = Some(Value::Object(root));
    result.content = vec![ContentBlock::text(
        result
            .structured_content
            .as_ref()
            .expect("delivery object")
            .to_string(),
    )];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_and_detailed_schemas_accept_upstream_data_and_every_delivery_form() {
        let upstream = json!({
            "type": "object",
            "required": ["data"],
            "properties": {"data": {"$ref": "#/$defs/Body"}},
            "$defs": {"Body": {"type": "string"}},
            "additionalProperties": false
        });
        let listed = Value::Object(output_schema(upstream.as_object().unwrap()));
        let detailed = Value::Object(detailed_output_schema(upstream.as_object().unwrap()));
        for schema in [&listed, &detailed] {
            assert_accepts_upstream_data_and_every_delivery_form(schema);
        }
        assert!(listed.to_string().len() < detailed.to_string().len());
    }

    /// `schema` keeps the upstream's local references scoped, so upstream
    /// data still validates against them, and accepts each delivery form.
    fn assert_accepts_upstream_data_and_every_delivery_form(schema: &Value) {
        let client = jsonschema::validator_for(schema).unwrap();
        assert!(client.is_valid(&json!({"data": "response"})));
        assert!(!client.is_valid(&json!({"data": 42})));
        assert!(!client.is_valid(&json!({})));
        for delivery in [
            Delivery::File {
                operation_status: OperationStatus::Succeeded,
                file: FileValue {
                    uri: "mcp-file://response".to_owned(),
                    name: None,
                    mime_type: None,
                    size: Some(8),
                    digest: None,
                },
            },
            Delivery::Unavailable {
                operation_status: OperationStatus::Succeeded,
                error: "retained_response_staging_failed".to_owned(),
                retry_operation: false,
            },
        ] {
            let mut result = CallToolResult::success(Vec::new());
            attach(&mut result, delivery);
            let structured = result.structured_content.as_ref().unwrap();
            assert!(client.is_valid(structured));
            assert!(validator().is_valid(structured));
            assert_eq!(
                structured[FIELD],
                result.meta.as_ref().unwrap()[RETAINED_DELIVERY_META_KEY]
            );
        }
        assert!(!client.is_valid(&json!({FIELD: {"delivery_status": "file"}})));
    }
}
