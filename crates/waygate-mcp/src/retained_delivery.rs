//! Caller-visible retained-response delivery contract.

use std::sync::OnceLock;

use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::files::{FileValue, RETAINED_DELIVERY_META_KEY};

pub const FIELD: &str = "_gateway_delivery";

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

/// Keep upstream-local references scoped to the original schema when adding
/// the gateway's alternative response form. The source schema remains the
/// authority for validating recovered upstream bodies.
pub fn output_schema(upstream: &Map<String, Value>) -> Map<String, Value> {
    let mut upstream = upstream.clone();
    upstream
        .entry("$id")
        .or_insert_with(|| json!("urn:mcp-gateway:upstream-output"));
    json!({"type":"object", "anyOf":[upstream, envelope_schema()]})
        .as_object()
        .expect("object schema")
        .clone()
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
    fn published_schema_accepts_upstream_data_and_delivery_with_local_references() {
        let upstream = json!({
            "type": "object",
            "required": ["data"],
            "properties": {"data": {"$ref": "#/$defs/Body"}},
            "$defs": {"Body": {"type": "string"}},
            "additionalProperties": false
        });
        let schema = Value::Object(output_schema(upstream.as_object().unwrap()));
        let client = jsonschema::validator_for(&schema).unwrap();
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
