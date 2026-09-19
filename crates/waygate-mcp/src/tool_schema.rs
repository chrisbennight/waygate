//! MCP-specific tool-schema checks that are stricter than JSON Schema itself.
//!
//! A composition-only schema such as `{ "anyOf": [...] }` can be valid JSON
//! Schema while still being invalid as an MCP tool input schema. MCP tool
//! arguments are objects, and the wire contract requires the schema root to
//! say so explicitly. Keep that protocol check separate from ordinary schema
//! compilation so publication and invocation enforce the same rule.

use std::collections::HashMap;
use std::sync::Arc;

use rmcp::model::{JsonObject, Tool};
use serde_json::{json, Value};
use url::Url;

const SUBSCHEMA_KEYWORDS: &[&str] = &[
    "items",
    "contains",
    "not",
    "propertyNames",
    "if",
    "then",
    "else",
    "additionalProperties",
    "unevaluatedProperties",
    "additionalItems",
    "unevaluatedItems",
    "contentSchema",
];
const SUBSCHEMA_ARRAY_KEYWORDS: &[&str] = &["allOf", "anyOf", "oneOf", "prefixItems"];
const SUBSCHEMA_MAP_KEYWORDS: &[&str] = &[
    "properties",
    "patternProperties",
    "dependentSchemas",
    "dependencies",
    "$defs",
    "definitions",
];
const BOOLEAN_VALUED_KEYWORDS: &[&str] = &[
    "additionalProperties",
    "unevaluatedProperties",
    "additionalItems",
    "unevaluatedItems",
];
const REFERENCE_KEYWORDS: &[&str] = &["$ref", "$dynamicRef", "$recursiveRef"];
const CONSTRAINING_KEYWORDS: &[&str] = &[
    "type",
    "enum",
    "const",
    "multipleOf",
    "maximum",
    "exclusiveMaximum",
    "minimum",
    "exclusiveMinimum",
    "maxLength",
    "minLength",
    "pattern",
    "format",
    "contentMediaType",
    "contentEncoding",
    "contentSchema",
    "maxItems",
    "minItems",
    "uniqueItems",
    "maxContains",
    "minContains",
    "maxProperties",
    "minProperties",
    "required",
    "dependentRequired",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "items",
    "prefixItems",
    "contains",
    "additionalItems",
    "unevaluatedItems",
    "properties",
    "patternProperties",
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "dependentSchemas",
    "dependencies",
    "$ref",
    "$dynamicRef",
    "$recursiveRef",
];
const JSON_SCHEMA_TYPES: &[&str] = &[
    "null", "boolean", "object", "array", "number", "string", "integer",
];

/// Whether an MCP tool input schema explicitly declares an object root.
pub fn input_schema_has_object_root(schema: &JsonObject) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("object")
}

/// The JSON Schema composition keyword an input schema applies at its root, if
/// any.
///
/// A root union is valid JSON Schema and valid MCP — an object root may carry
/// `anyOf`/`oneOf`/`allOf` alongside `type: "object"`. It is nonetheless
/// unusable in practice: the tool-calling APIs that consume `tools/list` refuse
/// a tool definition whose input schema applies one of those keywords at the
/// root, so a client either drops the tool or fails the whole request. Declare
/// mutually exclusive arguments as independent optional properties and enforce
/// the exclusion when the call is handled.
///
/// Only the three keywords those APIs name are reported. Other applicators are
/// not known to be refused, and guessing at them would withhold or fail tools
/// that work.
pub fn root_composition_keyword(schema: &JsonObject) -> Option<&'static str> {
    ["anyOf", "oneOf", "allOf"]
        .into_iter()
        .find(|keyword| schema.contains_key(*keyword))
}

/// [`input_schema_has_object_root`] for schemas carried as JSON values in an
/// admitted invocation snapshot.
pub fn input_schema_value_has_object_root(schema: &Value) -> bool {
    schema.as_object().is_some_and(input_schema_has_object_root)
}

/// Project legal JSON Schema spellings into the validation-equivalent subset
/// accepted consistently by MCP clients.
///
/// The projection handles boolean schemas, legal array-valued `type` unions,
/// and unconstrained schema objects. It never guesses a more specific type.
/// A remote reference cannot be made self-contained without its target, so an
/// input containing one is not publishable. An optional output schema with an
/// unresolved remote reference is omitted while the tool itself remains
/// callable.
pub fn make_tool_schemas_portable(tool: &mut Tool) -> bool {
    if !input_schema_has_object_root(tool.input_schema.as_ref()) {
        return false;
    }
    let Some(input) = portable_schema_object(tool.input_schema.as_ref()) else {
        return false;
    };
    tool.input_schema = Arc::new(input);

    if let Some(output) = tool.output_schema.as_ref() {
        tool.output_schema = portable_schema_object(output.as_ref()).map(Arc::new);
    }
    true
}

/// Return a validation-equivalent portable schema, or `None` when the schema
/// depends on an unresolved remote reference.
pub fn portable_schema_object(schema: &JsonObject) -> Option<JsonObject> {
    let mut value = Value::Object(schema.clone());
    let mut embedded_resources = HashMap::new();
    if !collect_embedded_resources(&value, None, &mut embedded_resources)
        || contains_unresolved_reference(&value, None, &value, &embedded_resources)
    {
        return None;
    }
    normalize_schema(&mut value, None);
    inspector_portable_schema(&value).then(|| {
        value
            .as_object()
            .cloned()
            .expect("an object-rooted schema remains an object")
    })
}

/// Project an object-rooted schema into the same optional wire contract.
pub fn portable_schema_value(schema: &Value) -> Option<Value> {
    schema
        .as_object()
        .and_then(portable_schema_object)
        .map(Value::Object)
}

/// Project an MCP input schema only when it also declares an object root.
pub fn portable_input_schema_value(schema: &Value) -> Option<Value> {
    input_schema_value_has_object_root(schema).then(|| portable_schema_value(schema))?
}

/// Whether a schema has none of MCP Inspector's portability findings.
///
/// This is not a general JSON Schema validator. It mirrors the Inspector's
/// narrower client-compatibility rules so tests can enforce the same wire
/// contract that operators see there.
pub fn inspector_portable_schema(schema: &Value) -> bool {
    let has_embedded_id = declares_any_id(schema);
    inspector_portable_node(schema, None, has_embedded_id)
}

fn inspector_portable_node(
    node: &Value,
    parent_keyword: Option<&str>,
    has_embedded_id: bool,
) -> bool {
    if node.is_boolean() {
        return parent_keyword.is_some_and(|keyword| BOOLEAN_VALUED_KEYWORDS.contains(&keyword));
    }
    let Some(object) = node.as_object() else {
        // Malformed schema nodes belong to protocol/schema validation rather
        // than Inspector's portability lint.
        return true;
    };
    if object
        .get("type")
        .and_then(Value::as_array)
        .is_some_and(|types| is_legal_type_union(types))
    {
        return false;
    }
    if !has_embedded_id
        && object
            .get("$ref")
            .and_then(Value::as_str)
            .is_some_and(|reference| !reference.is_empty() && !reference.starts_with('#'))
    {
        return false;
    }
    if parent_keyword != Some("not") && !constrains_instance(object) {
        return false;
    }
    inspector_subschemas(object)
        .all(|(child, keyword)| inspector_portable_node(child, Some(keyword), has_embedded_id))
}

fn normalize_schema(node: &mut Value, parent_keyword: Option<&str>) {
    if let Value::Bool(allowed) = node {
        if parent_keyword.is_some_and(|keyword| BOOLEAN_VALUED_KEYWORDS.contains(&keyword)) {
            return;
        }
        *node = if *allowed {
            unconstrained_object_schema()
        } else {
            json!({"not": {}})
        };
    }

    let Some(object) = node.as_object_mut() else {
        return;
    };

    normalize_type_union(object);
    normalize_children(object);

    if parent_keyword != Some("not") && !constrains_instance(object) {
        object.insert("not".to_owned(), json!({"not": {}}));
    }
}

fn normalize_type_union(object: &mut JsonObject) {
    let Some(types) = object.get("type").and_then(Value::as_array) else {
        return;
    };
    if !is_legal_type_union(types) {
        return;
    }

    let branches = Value::Array(types.iter().map(|kind| json!({"type": kind})).collect());
    let original_type = object
        .remove("type")
        .expect("the union was read from this object");
    if object.contains_key("anyOf") {
        if let Some(all_of) = object.get_mut("allOf") {
            let Some(all_of) = all_of.as_array_mut() else {
                object.insert("type".to_owned(), original_type);
                return;
            };
            all_of.push(json!({"anyOf": branches}));
        } else {
            object.insert(
                "allOf".to_owned(),
                Value::Array(vec![json!({"anyOf": branches})]),
            );
        }
    } else {
        object.insert("anyOf".to_owned(), branches);
    }
}

fn is_legal_type_union(types: &[Value]) -> bool {
    if types.is_empty()
        || !types.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|kind| JSON_SCHEMA_TYPES.contains(&kind))
        })
    {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    types
        .iter()
        .filter_map(Value::as_str)
        .all(|kind| seen.insert(kind))
}

fn normalize_children(object: &mut JsonObject) {
    for keyword in SUBSCHEMA_MAP_KEYWORDS {
        let Some(children) = object.get_mut(*keyword).and_then(Value::as_object_mut) else {
            continue;
        };
        for child in children.values_mut() {
            normalize_schema(child, Some(keyword));
        }
    }
    for keyword in SUBSCHEMA_ARRAY_KEYWORDS {
        let Some(children) = object.get_mut(*keyword).and_then(Value::as_array_mut) else {
            continue;
        };
        for child in children {
            normalize_schema(child, Some(keyword));
        }
    }
    for keyword in SUBSCHEMA_KEYWORDS {
        let Some(child) = object.get_mut(*keyword) else {
            continue;
        };
        if *keyword == "items" {
            if let Some(children) = child.as_array_mut() {
                for child in children {
                    normalize_schema(child, Some(keyword));
                }
                continue;
            }
        }
        normalize_schema(child, Some(keyword));
    }
}

fn constrains_instance(object: &JsonObject) -> bool {
    object
        .keys()
        .any(|keyword| CONSTRAINING_KEYWORDS.contains(&keyword.as_str()))
        || (object.contains_key("if")
            && (object.contains_key("then") || object.contains_key("else")))
}

fn unconstrained_object_schema() -> Value {
    // Double negation accepts every instance while remaining an object-form
    // schema. It is substantially smaller on the wire than enumerating all
    // seven JSON Schema types.
    json!({"not": {"not": {}}})
}

fn declares_any_id(node: &Value) -> bool {
    let Some(object) = node.as_object() else {
        return false;
    };
    if object
        .get("$id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty())
    {
        return true;
    }
    subschemas(object).any(declares_any_id)
}

fn collect_embedded_resources<'a>(
    node: &'a Value,
    parent_base: Option<&Url>,
    resources: &mut HashMap<String, &'a Value>,
) -> bool {
    let Some(object) = node.as_object() else {
        return true;
    };
    let current_base = schema_base(object, parent_base);
    if object.contains_key("$id") {
        if let Some(base) = current_base.as_ref() {
            resources.insert(resource_uri(base), node);
        }
    }
    subschemas(object)
        .all(|child| collect_embedded_resources(child, current_base.as_ref(), resources))
}

fn contains_unresolved_reference<'a>(
    node: &'a Value,
    parent_base: Option<&Url>,
    parent_resource: &'a Value,
    resources: &HashMap<String, &'a Value>,
) -> bool {
    let Some(object) = node.as_object() else {
        return false;
    };
    let current_base = schema_base(object, parent_base);
    let current_resource = if object.contains_key("$id") {
        node
    } else {
        parent_resource
    };
    if REFERENCE_KEYWORDS.iter().any(|keyword| {
        object
            .get(*keyword)
            .and_then(Value::as_str)
            .is_some_and(|reference| {
                !reference_target_exists(
                    reference,
                    current_base.as_ref(),
                    current_resource,
                    resources,
                )
            })
    }) {
        return true;
    }
    subschemas(object).any(|child| {
        contains_unresolved_reference(child, current_base.as_ref(), current_resource, resources)
    })
}

fn reference_target_exists<'a>(
    reference: &str,
    current_base: Option<&Url>,
    current_resource: &'a Value,
    resources: &HashMap<String, &'a Value>,
) -> bool {
    if reference.is_empty() {
        return true;
    }
    if let Some(fragment) = reference.strip_prefix('#') {
        return fragment_target_exists(current_resource, fragment);
    }
    let Some(resolved) = resolve_uri(reference, current_base) else {
        return false;
    };
    let Some(resource) = resources.get(&resource_uri(&resolved)) else {
        return false;
    };
    resolved
        .fragment()
        .is_none_or(|fragment| fragment_target_exists(resource, fragment))
}

fn fragment_target_exists(resource: &Value, fragment: &str) -> bool {
    let Some(fragment) = percent_decode_fragment(fragment) else {
        return false;
    };
    if fragment.is_empty() {
        return true;
    }
    if fragment.starts_with('/') {
        return resource
            .pointer(&fragment)
            .is_some_and(|target| target.is_object() || target.is_boolean());
    }
    resource_declares_anchor(resource, &fragment, true)
}

fn percent_decode_fragment(fragment: &str) -> Option<String> {
    let bytes = fragment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = hex_value(*bytes.get(index + 1)?)?;
        let low = hex_value(*bytes.get(index + 2)?)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn resource_declares_anchor(node: &Value, anchor: &str, resource_root: bool) -> bool {
    let Some(object) = node.as_object() else {
        return false;
    };
    if !resource_root && object.contains_key("$id") {
        return false;
    }
    if ["$anchor", "$dynamicAnchor"].iter().any(|keyword| {
        object
            .get(*keyword)
            .and_then(Value::as_str)
            .is_some_and(|candidate| candidate == anchor)
    }) {
        return true;
    }
    subschemas(object).any(|child| resource_declares_anchor(child, anchor, false))
}

fn schema_base(object: &JsonObject, parent_base: Option<&Url>) -> Option<Url> {
    object
        .get("$id")
        .and_then(Value::as_str)
        .map_or_else(|| parent_base.cloned(), |id| resolve_uri(id, parent_base))
}

fn resolve_uri(reference: &str, base: Option<&Url>) -> Option<Url> {
    Url::parse(reference)
        .ok()
        .or_else(|| base.and_then(|base| base.join(reference).ok()))
}

fn resource_uri(uri: &Url) -> String {
    let mut resource = uri.clone();
    resource.set_fragment(None);
    resource.into()
}

pub(crate) fn subschemas(object: &JsonObject) -> impl Iterator<Item = &Value> {
    inspector_subschemas(object).map(|(child, _)| child)
}

fn inspector_subschemas(object: &JsonObject) -> impl Iterator<Item = (&Value, &str)> {
    let maps = SUBSCHEMA_MAP_KEYWORDS.iter().flat_map(|keyword| {
        object
            .get(*keyword)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(move |children| children.values().map(move |child| (child, *keyword)))
    });
    let arrays = SUBSCHEMA_ARRAY_KEYWORDS.iter().flat_map(|keyword| {
        object
            .get(*keyword)
            .and_then(Value::as_array)
            .into_iter()
            .flat_map(move |children| children.iter().map(move |child| (child, *keyword)))
    });
    let singles = SUBSCHEMA_KEYWORDS.iter().flat_map(|keyword| {
        object.get(*keyword).into_iter().flat_map(move |child| {
            if *keyword == "items" {
                child.as_array().map_or_else(
                    || vec![(child, *keyword)],
                    |children| children.iter().map(|child| (child, *keyword)).collect(),
                )
            } else {
                vec![(child, *keyword)]
            }
        })
    });
    maps.chain(arrays).chain(singles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::Tool;
    use serde_json::json;

    #[test]
    fn requires_an_explicit_object_root() {
        let object = json!({"type": "object", "anyOf": [{"required": ["value"]}]});
        let composition_only = json!({"anyOf": [{"type": "object"}]});
        let array = json!({"type": "array"});

        assert!(input_schema_value_has_object_root(&object));
        assert!(!input_schema_value_has_object_root(&composition_only));
        assert!(!input_schema_value_has_object_root(&array));
    }

    #[test]
    fn reports_a_root_composition_keyword_even_under_an_object_root() {
        let object_rooted_union = json!({"type": "object", "anyOf": [{"required": ["value"]}]});
        let flat = json!({"type": "object", "properties": {"value": {"type": "string"}}});
        // A union nested inside a property is what a client can consume; only
        // the root placement is refused.
        let nested_union =
            json!({"type": "object", "properties": {"value": {"oneOf": [{"type": "string"}]}}});

        assert_eq!(
            root_composition_keyword(object_rooted_union.as_object().unwrap()),
            Some("anyOf")
        );
        assert_eq!(root_composition_keyword(flat.as_object().unwrap()), None);
        assert_eq!(
            root_composition_keyword(nested_union.as_object().unwrap()),
            None
        );
    }

    #[test]
    fn portability_projection_is_validation_equivalent() {
        let original = json!({
            "type": "object",
            "properties": {
                "anything": true,
                "forbidden": false,
                "nullable": {"type": ["string", "null"], "minLength": 2},
                "annotated": {"description": "accepts every JSON value"},
                "conditional": {"if": {"const": 1}},
                "definitions_only": {"$defs": {"named": {"type": "string"}}},
                "already_portable": {"not": {}}
            },
            "additionalProperties": true
        });
        let projected = portable_schema_object(original.as_object().unwrap())
            .expect("self-contained schema projects");
        let projected = Value::Object(projected);
        assert!(inspector_portable_schema(&projected));

        let before = jsonschema::validator_for(&original).expect("original schema compiles");
        let after = jsonschema::validator_for(&projected).expect("projected schema compiles");
        let samples = [
            json!({}),
            json!({"anything": [1, 2], "nullable": null}),
            json!({"anything": false, "nullable": "ok", "annotated": 4}),
            json!({"nullable": "x"}),
            json!({"forbidden": 1}),
            json!({"conditional": "value", "definitions_only": null}),
        ];
        for sample in samples {
            assert_eq!(
                before.is_valid(&sample),
                after.is_valid(&sample),
                "projection changed validation for {sample}",
            );
        }

        assert_eq!(projected["additionalProperties"], true);
        assert_eq!(projected["properties"]["forbidden"], json!({"not": {}}));
        assert_eq!(
            projected["properties"]["already_portable"],
            json!({"not": {}})
        );
        assert_eq!(
            projected["properties"]["anything"],
            json!({"not": {"not": {}}})
        );
        assert!(projected["properties"]["nullable"]["anyOf"].is_array());
        assert_eq!(
            projected["properties"]["annotated"]["not"],
            json!({"not": {}})
        );
        assert_eq!(
            projected["properties"]["conditional"]["not"],
            json!({"not": {}})
        );
        assert_eq!(
            projected["properties"]["definitions_only"]["not"],
            json!({"not": {}})
        );
    }

    #[test]
    fn a_type_union_composes_with_an_existing_any_of() {
        let original = json!({
            "type": "object",
            "properties": {
                "value": {
                    "type": ["string", "null"],
                    "anyOf": [{"minLength": 2}, {"const": null}],
                    "allOf": [{"description": "annotation-only branch"}]
                }
            }
        });
        let projected = portable_schema_object(original.as_object().unwrap())
            .expect("self-contained schema projects");
        let projected = Value::Object(projected);
        assert!(inspector_portable_schema(&projected));
        let before = jsonschema::validator_for(&original).unwrap();
        let after = jsonschema::validator_for(&projected).unwrap();
        for sample in [
            json!({}),
            json!({"value": null}),
            json!({"value": "ok"}),
            json!({"value": "x"}),
            json!({"value": 3}),
        ] {
            assert_eq!(before.is_valid(&sample), after.is_valid(&sample));
        }
        assert!(projected["properties"]["value"].get("type").is_none());
        assert_eq!(
            projected["properties"]["value"]["allOf"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn unresolved_remote_references_are_not_published() {
        let input = Arc::new(
            json!({
                "type": "object",
                "properties": {"value": {"$ref": "https://schemas.example/value.json"}}
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let output = Arc::new(
            json!({
                "type": "object",
                "properties": {"data": {"$ref": "https://schemas.example/data.json"}}
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        let mut bad_input = Tool::new("bad-input", "test", input);
        assert!(!make_tool_schemas_portable(&mut bad_input));

        let good_input = Arc::new(json!({"type": "object"}).as_object().unwrap().clone());
        let mut bad_output =
            Tool::new("bad-output", "test", good_input).with_raw_output_schema(output);
        assert!(make_tool_schemas_portable(&mut bad_output));
        assert!(bad_output.output_schema.is_none());
    }

    #[test]
    fn non_object_input_roots_are_not_published() {
        for schema in [
            json!({"type": "array"}),
            json!({"anyOf": [{"type": "object"}]}),
        ] {
            let input = Arc::new(schema.as_object().unwrap().clone());
            let mut tool = Tool::new("bad-root", "test", input);
            assert!(!make_tool_schemas_portable(&mut tool));
        }
    }

    #[test]
    fn a_remote_reference_to_an_embedded_id_is_self_contained() {
        let schema = json!({
            "$id": "https://schemas.example/root.json",
            "type": "object",
            "properties": {
                "value": {"$ref": "https://schemas.example/root.json#/$defs/value"}
            },
            "$defs": {"value": {"type": "string"}}
        });
        assert!(portable_schema_object(schema.as_object().unwrap()).is_some());
    }

    #[test]
    fn an_unrelated_remote_reference_is_rejected_despite_an_embedded_id() {
        let schema = json!({
            "$id": "https://schemas.example/root.json",
            "type": "object",
            "properties": {
                "value": {"$ref": "https://other.example/value.json"}
            }
        });
        assert!(portable_schema_object(schema.as_object().unwrap()).is_none());

        let dynamic = json!({
            "type": "object",
            "properties": {
                "value": {"$dynamicRef": "https://other.example/value.json"}
            }
        });
        assert!(portable_schema_object(dynamic.as_object().unwrap()).is_none());

        let relative_without_base = json!({
            "$id": "child.json",
            "type": "object",
            "properties": {"value": {"$ref": "child.json#/$defs/value"}},
            "$defs": {"value": {"type": "string"}}
        });
        assert!(portable_schema_object(relative_without_base.as_object().unwrap()).is_none());
    }

    #[test]
    fn relative_embedded_ids_resolve_against_the_closest_parent_id() {
        let schema = json!({
            "$id": "https://schemas.example/root.json",
            "type": "object",
            "properties": {
                "value": {"$ref": "child.json#/$defs/value"}
            },
            "$defs": {
                "child": {
                    "$id": "child.json",
                    "$defs": {"value": {"type": "string"}}
                }
            }
        });

        assert!(portable_schema_object(schema.as_object().unwrap()).is_some());
    }

    #[test]
    fn a_relative_root_id_is_self_contained_without_base_dependent_references() {
        let without_reference = json!({
            "$id": "tool.json",
            "type": "object"
        });
        assert!(portable_schema_object(without_reference.as_object().unwrap()).is_some());

        let local_reference = json!({
            "$id": "tool.json",
            "type": "object",
            "properties": {
                "value": {"$ref": "#/$defs/value"}
            },
            "$defs": {"value": {"type": "string"}}
        });
        assert!(portable_schema_object(local_reference.as_object().unwrap()).is_some());
    }

    #[test]
    fn embedded_reference_fragments_must_name_existing_schema_targets() {
        let valid = json!({
            "$id": "https://schemas.example/root.json",
            "$anchor": "root",
            "type": "object",
            "properties": {
                "by_pointer": {"$ref": "https://schemas.example/root.json#/$defs/value"},
                "by_encoded_pointer": {"$ref": "https://schemas.example/root.json#/$defs/c%25d"},
                "by_anchor": {"$ref": "https://schemas.example/root.json#root"}
            },
            "$defs": {
                "value": {"type": "string"},
                "c%d": {"type": "number"}
            }
        });
        assert!(portable_schema_object(valid.as_object().unwrap()).is_some());

        for reference in [
            "https://schemas.example/root.json#missing",
            "https://schemas.example/root.json#/$defs/missing",
            "https://schemas.example/root.json#/$defs/%GG",
            "https://schemas.example/root.json#/$defs/%FF",
            "#missing",
        ] {
            let invalid = json!({
                "$id": "https://schemas.example/root.json",
                "type": "object",
                "properties": {"value": {"$ref": reference}}
            });
            assert!(portable_schema_object(invalid.as_object().unwrap()).is_none());
        }
    }

    #[test]
    fn deeply_nested_self_contained_schemas_remain_publishable() {
        let mut nested = json!(true);
        for _ in 0..=80 {
            nested = json!({"not": nested});
        }
        let schema = json!({
            "type": "object",
            "properties": {"value": nested}
        });
        let portable = portable_schema_object(schema.as_object().unwrap())
            .expect("valid self-contained schemas are not withheld because of nesting depth");
        assert!(inspector_portable_schema(&Value::Object(portable)));
    }

    #[test]
    fn gateway_owned_search_tools_schemas_pass_inspector_portability_rules() {
        let input = Value::Object(
            crate::compat::search_tools_v1::input_schema()
                .as_ref()
                .clone(),
        );
        let output = Value::Object(
            crate::compat::search_tools_v1::output_schema()
                .as_ref()
                .clone(),
        );
        assert!(inspector_portable_schema(&input));
        assert!(inspector_portable_schema(&output));
    }
}
