//! Admit explicit result counts above a wrapped text tool's native ceiling.

use rmcp::model::{CallToolResult, ContentBlock, Tool};
use serde::Serialize;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub(crate) struct CountBound {
    maximum: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CountAdjustment {
    requested: Value,
    effective: u64,
    upstream_maximum: u64,
    returned: Option<u64>,
    clamped: bool,
}

impl CountBound {
    pub(crate) fn from_projected_input(input: &Value) -> Self {
        Self {
            maximum: input
                .pointer("/properties/limit/x-mcp-result-count/upstreamMaximum")
                .and_then(Value::as_u64)
                .expect("admitted count projection retains its native maximum"),
        }
    }

    pub(crate) fn project(tool: &Tool, input: &Value) -> Option<(Self, Value)> {
        // A reference can share the limit's constraints with another budget.
        // Keep those schemas intact rather than relax every referencing field.
        if contains_reference(input) {
            return None;
        }
        let output = tool.output_schema.as_ref()?;
        // Wrapped text has no reliable row count. Its extensible object lets
        // the gateway report an adjustment without rewriting the text result.
        if output.get("x-fastmcp-wrap-result") != Some(&Value::Bool(true))
            || output.get("type")?.as_str()? != "object"
            || output
                .get("additionalProperties")
                .is_some_and(|value| value != &Value::Bool(true))
            || output
                .get("properties")?
                .get("result")?
                .get("type")?
                .as_str()?
                != "string"
            || output.get("properties")?.as_object()?.len() != 1
            || output.keys().any(|key| {
                ![
                    "$schema",
                    "$id",
                    "title",
                    "description",
                    "type",
                    "properties",
                    "required",
                    "additionalProperties",
                    "x-fastmcp-wrap-result",
                ]
                .contains(&key.as_str())
            })
        {
            return None;
        }
        let descriptor = serde_json::to_value(tool).ok()?;
        if descriptor
            .pointer("/execution/taskSupport")
            .is_some_and(|support| support.as_str() != Some("forbidden"))
        {
            return None;
        }
        let limit = input.get("properties")?.get("limit")?;
        if limit.get("type")?.as_str()? != "integer"
            || limit.get("minimum")?.as_u64()? < 1
            || limit.as_object()?.keys().any(|key| {
                ![
                    "type",
                    "title",
                    "description",
                    "default",
                    "minimum",
                    "maximum",
                    "examples",
                    "deprecated",
                    "readOnly",
                    "writeOnly",
                    "$comment",
                ]
                .contains(&key.as_str())
            })
            || input.as_object()?.keys().any(|key| {
                ![
                    "$schema",
                    "$id",
                    "title",
                    "description",
                    "type",
                    "properties",
                    "required",
                    "additionalProperties",
                    "$defs",
                    "definitions",
                    "examples",
                    "$comment",
                ]
                .contains(&key.as_str())
            })
        {
            return None;
        }
        let maximum = limit.get("maximum")?.as_u64()?;
        if maximum == 0
            || maximum > 9_007_199_254_740_991
            || maximum < limit.get("minimum")?.as_u64()?
        {
            return None;
        }
        let mut projected = input.clone();
        let property = projected
            .get_mut("properties")?
            .get_mut("limit")?
            .as_object_mut()?;
        property.remove("maximum");
        property.insert(
            "x-mcp-result-count".into(),
            json!({
                "upstreamMaximum":maximum,
                "metadataProperty":"_gateway_counts"
            }),
        );
        let description = property
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        property.insert("description".into(), format!(
            "{description} Counts above the upstream maximum are clamped; _gateway_counts.limit reports the requested and effective counts."
        ).trim().into());
        Some((Self { maximum }, projected))
    }

    pub(crate) fn clamp(&self, arguments: &mut Map<String, Value>) -> Option<CountAdjustment> {
        let requested = arguments.get("limit")?;
        let exceeds = requested.as_u64().map_or_else(
            || {
                requested.as_f64().is_some_and(|count| {
                    count
                        > Value::from(self.maximum)
                            .as_f64()
                            .expect("bounded integer has a finite JSON number representation")
                })
            },
            |count| count > self.maximum,
        );
        if !exceeds {
            return None;
        }
        let requested = arguments.insert("limit".into(), self.maximum.into())?;
        Some(CountAdjustment {
            requested,
            effective: self.maximum,
            upstream_maximum: self.maximum,
            returned: None,
            clamped: true,
        })
    }

    pub(crate) fn metadata_schema() -> Value {
        json!({"type":"object","additionalProperties":false,
            "properties":{"limit":{"type":"object","additionalProperties":false,
                "properties":{
                    "requested":{"type":"integer","minimum":1},
                    "effective":{"type":"integer","minimum":1},
                    "upstreamMaximum":{"type":"integer","minimum":1},
                    "returned":{"type":["integer","null"],"minimum":0},
                    "clamped":{"type":"boolean"}},
                "required":["requested","effective","upstreamMaximum","returned","clamped"]}},
            "required":["limit"]})
    }
}

fn contains_reference(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(key.as_str(), "$ref" | "$dynamicRef" | "$recursiveRef")
                || contains_reference(value)
        }),
        Value::Array(items) => items.iter().any(contains_reference),
        _ => false,
    }
}

impl CountAdjustment {
    pub(crate) fn attach(self, result: &mut CallToolResult) {
        let counts = json!({"limit":self});
        if let Some(Value::Object(payload)) = result.structured_content.as_mut() {
            payload.insert("_gateway_counts".into(), counts.clone());
        }
        result.content.push(ContentBlock::text(format!(
            "Result count adjustment: {counts}"
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn tool() -> Tool {
        Tool::new(
            "search",
            "Search",
            Arc::new(
                json!({"type":"object","properties":{
            "limit":{"type":"integer","minimum":1,"maximum":1024,"default":10},
            "extract_count":{"type":"integer","minimum":0,"maximum":10}}})
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .with_raw_output_schema(Arc::new(
            json!({"type":"object", "x-fastmcp-wrap-result":true,
                "properties":{"result":{"type":"string"}},"required":["result"]})
            .as_object()
            .unwrap()
            .clone(),
        ))
    }

    #[test]
    fn projection_keeps_defaults_minimum_and_other_budgets() {
        let tool = tool();
        let (_, input) = CountBound::project(&tool, &json!(tool.input_schema)).unwrap();
        assert!(input["properties"]["limit"].get("maximum").is_none());
        assert_eq!(input["properties"]["limit"]["minimum"], 1);
        assert_eq!(input["properties"]["limit"]["default"], 10);
        assert_eq!(input["properties"]["extract_count"]["maximum"], 10);
        assert_eq!(
            input["properties"]["limit"]["x-mcp-result-count"]["upstreamMaximum"],
            1024
        );
        assert_eq!(tool.input_schema["properties"]["limit"]["maximum"], 1024);
    }

    #[test]
    fn oversized_counts_forward_the_native_maximum_and_preserve_text() {
        let tool = tool();
        let (bound, _) = CountBound::project(&tool, &json!(tool.input_schema)).unwrap();
        for requested in [json!(2048), json!(u64::MAX), json!(1e30)] {
            let mut arguments = json!({"limit":requested,"query":"fixture"})
                .as_object()
                .unwrap()
                .clone();
            let adjustment = bound.clamp(&mut arguments).unwrap();
            assert_eq!(arguments["limit"], 1024);
            assert_eq!(arguments["query"], "fixture");
            let mut result = CallToolResult::structured(json!({"result":"original result"}));
            adjustment.attach(&mut result);
            let output = result.structured_content.unwrap();
            assert_eq!(output["result"], "original result");
            assert_eq!(output["_gateway_counts"]["limit"]["requested"], requested);
            assert_eq!(output["_gateway_counts"]["limit"]["effective"], 1024);
            assert!(output["_gateway_counts"]["limit"]["returned"].is_null());
            assert_eq!(output["_gateway_counts"]["limit"]["clamped"], true);
        }
    }

    #[test]
    fn omitted_or_accepted_counts_do_not_change_arguments() {
        let tool = tool();
        let (bound, _) = CountBound::project(&tool, &json!(tool.input_schema)).unwrap();
        for input in [json!({}), json!({"limit":1}), json!({"limit":1024})] {
            let mut arguments = input.as_object().unwrap().clone();
            assert!(bound.clamp(&mut arguments).is_none());
            assert_eq!(json!(arguments), input);
        }
    }

    #[test]
    fn additional_count_constraints_keep_the_native_contract() {
        let tool = tool();
        let mut input = json!(tool.input_schema);
        input["properties"]["limit"]["enum"] = json!([10, 20]);
        assert!(CountBound::project(&tool, &input).is_none());
        let mut input = json!(tool.input_schema);
        input["allOf"] = json!([{"properties":{"limit":{"maximum":100}}}]);
        assert!(CountBound::project(&tool, &input).is_none());
    }
}
