//! Opt-in client presentation for tools with root composition constraints.
//!
//! This module never participates in schema admission or invocation validation.
//! Discovery and Code Mode retain the complete authoritative contract.

use std::sync::Arc;

use rmcp::model::{JsonObject, Tool};
use serde_json::Value;

const ROOT_APPLICATORS: &[&str] = &["allOf", "anyOf", "oneOf", "not", "if", "then", "else"];

pub const GUIDANCE: &str = "Root-composition compatibility is enabled. tools/list may present \
    simplified input schemas; the gateway still enforces the full constraints. \
    gateway-discovery.inspect, legacy searchTools types, and codemode.describe return the \
    authoritative schemas as data. If a tool cannot be registered, use the existing \
    codemode.search, codemode.describe, and codemode.execute route when available.";

/// Result of adapting a client-facing copy, not the admitted tool definition.
#[derive(Debug, PartialEq, Eq)]
pub enum Adaptation {
    Unchanged,
    Adapted,
    Unsupported(&'static str),
}

/// Broaden only a supported generation schema; preserve names and arguments.
pub fn adapt_tool(tool: &mut Tool) -> Adaptation {
    let schema = tool.input_schema.as_ref();
    if !ROOT_APPLICATORS.iter().any(|key| schema.contains_key(*key)) {
        return Adaptation::Unchanged;
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Adaptation::Unsupported("root properties must describe the arguments");
    };
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Adaptation::Unsupported("input schema requires an object root");
    }
    if schema.contains_key("patternProperties") {
        return Adaptation::Unsupported("root patternProperties requires the original schema");
    }

    // Removing an applicator can remove a reference target or change which
    // properties an unevaluatedProperties rule considers evaluated. Leave
    // those contracts alone instead of attempting reference rewriting.
    let mut pending = vec![schema];
    while let Some(node) = pending.pop() {
        if [
            "$ref",
            "$dynamicRef",
            "$recursiveRef",
            "unevaluatedProperties",
        ]
        .iter()
        .any(|key| node.contains_key(*key))
        {
            return Adaptation::Unsupported(
                "references or unevaluatedProperties require the original schema",
            );
        }
        pending.extend(crate::tool_schema::subschemas(node).filter_map(Value::as_object));
    }

    let mut constraints = JsonObject::new();
    for key in ROOT_APPLICATORS {
        if let Some(value) = schema.get(*key) {
            constraints.insert((*key).to_owned(), value.clone());
        }
    }
    if !supported_constraints(&constraints, properties) {
        return Adaptation::Unsupported(
            "root branches must only constrain arguments declared in root properties",
        );
    }
    let constraints = Value::Object(constraints).to_string();
    // Keep tool descriptions usable for the model. Larger contracts remain
    // available as data through inspection and Code Mode.
    if constraints.len() > 4096 {
        return Adaptation::Unsupported(
            "root constraints exceed the compatibility description budget",
        );
    }
    let schema = Arc::make_mut(&mut tool.input_schema);
    for key in ROOT_APPLICATORS {
        schema.remove(*key);
    }
    tool.description = Some(
        format!(
        "{}\nAdditional input constraints (JSON Schema), enforced by the gateway: {constraints}",
        tool.description.as_deref().unwrap_or_default()
    )
        .into(),
    );
    Adaptation::Adapted
}

fn supported_constraints(constraints: &JsonObject, properties: &JsonObject) -> bool {
    // Only follow applicators at the argument-object level here. Property
    // schemas describe values, so their property names are not argument names.
    let mut pending = vec![constraints];
    while let Some(node) = pending.pop() {
        for (key, value) in node {
            match key.as_str() {
                "allOf" | "anyOf" | "oneOf" => {
                    let Some(branches) = value.as_array() else {
                        return false;
                    };
                    for branch in branches {
                        if let Some(branch) = branch.as_object() {
                            pending.push(branch);
                        } else if !branch.is_boolean() {
                            return false;
                        }
                    }
                }
                "not" | "if" | "then" | "else" => {
                    if let Some(branch) = value.as_object() {
                        pending.push(branch);
                    } else if !value.is_boolean() {
                        return false;
                    }
                }
                "properties" => {
                    let Some(branch) = value.as_object() else {
                        return false;
                    };
                    if branch.keys().any(|name| !properties.contains_key(name)) {
                        return false;
                    }
                }
                "required" => {
                    let Some(names) = value.as_array() else {
                        return false;
                    };
                    if names.iter().any(|name| {
                        !name
                            .as_str()
                            .is_some_and(|name| properties.contains_key(name))
                    }) {
                        return false;
                    }
                }
                "type" | "minProperties" | "maxProperties" | "title" | "description"
                | "$comment" => {}
                _ => return false,
            }
        }
    }
    true
}

/// Apply presentation to an already authorized tool list. Unsupported tools
/// keep their original declaration so other discovery paths remain useful.
pub(crate) fn adapt_tools(tools: &mut [Tool]) {
    for tool in tools {
        match adapt_tool(tool) {
            Adaptation::Unchanged => {}
            Adaptation::Adapted => tracing::debug!(
                tool = %tool.name, profile = "root-composition",
                "presenting simplified schema; invocation enforces the original constraints"
            ),
            Adaptation::Unsupported(reason) => tracing::warn!(
                tool = %tool.name, profile = "root-composition", reason,
                "client schema adaptation unavailable; use codemode.search, codemode.describe, and codemode.execute when available"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(schema: Value) -> Tool {
        Tool::new(
            "fixture",
            "Fixture",
            Arc::new(schema.as_object().unwrap().clone()),
        )
    }

    #[test]
    fn conditional_presentation_does_not_mutate_validation_contract() {
        let original: Tool = serde_json::from_value(
            serde_json::from_str::<Value>(include_str!(
                "../tests/fixtures/client-schema-tools.json"
            ))
            .unwrap()[2]
                .clone(),
        )
        .unwrap();
        let mut presented = original.clone();
        assert_eq!(adapt_tool(&mut presented), Adaptation::Adapted);
        let strict =
            jsonschema::validator_for(&Value::Object((*original.input_schema).clone())).unwrap();
        let generation =
            jsonschema::validator_for(&Value::Object((*presented.input_schema).clone())).unwrap();
        for (args, valid) in [
            (json!({"mode":"large","size":1500000000}), true),
            (json!({"mode":"small","size":1000000}), true),
            (json!({"mode":"small","size":1500000000}), false),
        ] {
            assert!(generation.is_valid(&args));
            assert_eq!(strict.is_valid(&args), valid);
        }
        assert!(original.input_schema.contains_key("allOf"));
        assert!(!presented.input_schema.contains_key("allOf"));
        assert!(presented
            .description
            .as_deref()
            .unwrap()
            .contains("16000000"));
        assert_eq!(presented.name, original.name);
    }

    #[test]
    fn root_and_nested_applicators_are_distinguished() {
        for (keyword, constraint) in [
            ("allOf", json!([{"required":["name"]}])),
            ("anyOf", json!([{"required":["name"]}])),
            ("oneOf", json!([{"required":["name"]}])),
            ("not", json!({"required":["name"]})),
            ("if", json!({"required":["name"]})),
        ] {
            let mut schema = json!({"type":"object","properties":{"name":{"type":"string"}}});
            schema[keyword] = constraint;
            let mut root = tool(schema.clone());
            assert_eq!(adapt_tool(&mut root), Adaptation::Adapted, "{keyword}");
            assert!(!root.input_schema.contains_key(keyword));
            let nested_schema = json!({"type":"object","properties":{"target":schema}});
            let mut nested = tool(nested_schema.clone());
            assert_eq!(adapt_tool(&mut nested), Adaptation::Unchanged);
            assert_eq!(Value::Object((*nested.input_schema).clone()), nested_schema);
        }
    }

    #[test]
    fn unsupported_shapes_remain_unchanged() {
        for addition in [
            json!({"oneOf":[{"properties":{"branch_only":{"type":"string"}}}]}),
            json!({"allOf":[{"additionalProperties":false}]}),
            json!({"allOf":[{"$ref":"#/$defs/value"}]}),
            json!({"allOf":[{}],"unevaluatedProperties":false}),
            json!({"allOf":[{}],"patternProperties":{".*":{"type":"string"}}}),
        ] {
            let mut schema = json!({"type":"object","properties":{"name":{"type":"string"}}});
            schema
                .as_object_mut()
                .unwrap()
                .extend(addition.as_object().unwrap().clone());
            let mut candidate = tool(schema.clone());
            assert!(matches!(
                adapt_tool(&mut candidate),
                Adaptation::Unsupported(_)
            ));
            assert_eq!(Value::Object((*candidate.input_schema).clone()), schema);
            assert_eq!(candidate.description.as_deref(), Some("Fixture"));
        }
    }
}
