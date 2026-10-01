//! Version 1 of the gateway-owned legacy `searchTools` compatibility adapter.
//!
//! SEP #1888 never became core MCP. Upstream servers publish ordinary MCP tools
//! and do not implement this adapter. Request defaults and accepted spellings
//! live in the same implementation as the advertised contract.

use std::sync::{Arc, OnceLock};

use rmcp::model::JsonObject;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::RiskTier;

/// Stable internal identity of this gateway-owned compatibility contract.
pub const ADAPTER_ID: &str = "gateway.search-tools.compat";
/// Internal wire-contract identity.
pub const ADAPTER_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SearchToolsRequest {
    /// Search operations by default; a supplied `name` selects type lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// Optional gateway compatibility filters for operation discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<OperationFilters>,
    /// Fully-qualified `<server>.<tool>#input|#output` handle for `types` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Opaque offset cursor returned by the previous operations page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum operations returned in this page. Defaults to 50.
    #[schemars(range(min = 1))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Verbosity of each returned `OperationDescriptor`. Omitted ⇒ `Full`
    /// (back-compat). Lighter levels let a client fetch a cheap representation
    /// first, then re-query for detail on the few tools it cares about
    /// (SEP #1888 / Anthropic Tool-Search progressive disclosure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
    #[schemars(skip)]
    #[serde(default, skip_serializing)]
    pub query: Option<String>,
}

impl SearchToolsRequest {
    pub fn mode(&self) -> Mode {
        self.mode.unwrap_or(if self.name.is_some() {
            Mode::Types
        } else {
            Mode::Operations
        })
    }

    /// Fold accepted query spellings into the canonical filters before search.
    pub fn normalize(mut self) -> Result<Self, &'static str> {
        if let Some(query) = self.query.take() {
            let filters = self.filters.get_or_insert_with(OperationFilters::default);
            if filters
                .query
                .as_ref()
                .is_some_and(|existing| existing != &query)
            {
                return Err("query and filters.query must agree when both are supplied");
            }
            filters.query = Some(query);
        }
        self.validate()?;
        Ok(self)
    }

    /// Validate the constraints published by [`input_schema`]. Serde and
    /// schemars share the field shape; this pins the one numeric constraint
    /// that serde alone cannot enforce.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.limit == Some(0) {
            return Err("limit must be positive");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Search for callable operations.
    #[serde(alias = "search")]
    Operations,
    /// Resolve one input or output type handle to JSON Schema.
    #[serde(alias = "describe")]
    Types,
}

/// Per-descriptor verbosity for `mode=operations`. `Full` is the default and
/// preserves the historical wire shape exactly.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Detail {
    /// Name + risk tier only — the cheapest representation for ranking.
    #[serde(alias = "names")]
    NameOnly,
    /// Name + description + risk tier.
    #[serde(alias = "summary")]
    NameDescription,
    /// Every field (current behaviour).
    #[default]
    Full,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationFilters {
    /// RESERVED — not yet enforced. The gateway has no per-tool
    /// `resource_type` model (it would require semantic metadata the
    /// manifest/catalog don't carry), so a value here is currently
    /// **ignored** rather than silently dropping all results. Kept in the
    /// wire schema for SEP #1888 compatibility; documented as a no-op so a
    /// client knows not to rely on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Gateway-local action classification. Omitted classifications do not
    /// match a supplied value; this is not a core MCP field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Filter to operations whose risk-tier step-up scope equals this value
    /// (e.g. `mcp:invoke:high`). Backed by the same `required_scope_for`
    /// mapping the descriptor exposes as `scope` and the step-up verdict
    /// advises — NOT a guarantee the call is gated on it: actual enforcement
    /// is the deployment's Cedar policy. Low-risk tools (no scope) never
    /// match — filter by `risk_level: "low"` for those. Applied in the
    /// handler (where each tool's facts are resolved), like `risk_level`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Gateway risk classification (`low`, `medium`, or `high`), not the risk
    /// vocabulary proposed by SEP #1888 and not a core MCP field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskTier>,
    /// Free-text query evaluated by the gateway's bounded BM25 index, with a
    /// catalog substring fallback when the index cannot serve the query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SearchToolsResponse {
    /// Operation-discovery result.
    Operations(OperationsResponse),
    /// Type-schema lookup result.
    Types(TypesResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationsResponse {
    /// Caller-visible operations in ranked or catalog order.
    pub operations: Vec<OperationDescriptor>,
    /// Opaque cursor for the next page, omitted on the final page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationDescriptor {
    /// Fully-qualified `<server>.<tool>` call name.
    pub name: String,
    /// Description published by the upstream tool.
    pub description: Option<String>,
    /// Gateway policy classification, not core MCP tool metadata.
    pub risk_level: RiskTier,
    /// Reserved compatibility field; currently always absent.
    pub resource_type: Option<String>,
    /// Optional gateway action classification.
    pub action: Option<String>,
    /// The OAuth step-up scope associated with this tool's risk tier
    /// (`waygate_mcp::authz::required_scope_for`); `None` for low-risk. This
    /// is the scope a `StepUpRequired` verdict advises and `build_call_facts`
    /// carries in `facts.action.required_scope`, exposed so a client can see
    /// and filter by it. It is NOT a guarantee the call is denied without it
    /// — actual enforcement is the deployment's Cedar policy. Omitted when
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Type handle accepted by `mode=types` for the upstream input schema.
    pub input_type: Option<String>,
    /// Type handle accepted by `mode=types` when the upstream published an
    /// output schema.
    pub output_type: Option<String>,
    /// Gateway classification of whether the operation may mutate state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side_effects: Option<bool>,
}

impl OperationDescriptor {
    /// Project this descriptor down to the requested verbosity. `Full` (the
    /// default) is unchanged; lighter levels null out the heavier fields so a
    /// client can ask for a cheap representation up front. `name` and
    /// `risk_level` are always kept — they're what a client ranks on.
    pub fn project(mut self, detail: Detail) -> Self {
        match detail {
            Detail::Full => {}
            Detail::NameDescription => {
                self.resource_type = None;
                self.action = None;
                self.scope = None;
                self.input_type = None;
                self.output_type = None;
                self.side_effects = None;
            }
            Detail::NameOnly => {
                self.description = None;
                self.resource_type = None;
                self.action = None;
                self.scope = None;
                self.input_type = None;
                self.output_type = None;
                self.side_effects = None;
            }
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TypesResponse {
    /// Echo of the resolved fully-qualified type handle.
    pub name: String,
    /// JSON Schema published by the upstream tool.
    pub json_schema: serde_json::Value,
    /// Sorted names found under the schema's `$defs` or `definitions` blocks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

static INPUT_SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
static OUTPUT_SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();

/// Input schema generated from the exact request DTO used at dispatch.
pub fn input_schema() -> Arc<JsonObject> {
    Arc::clone(INPUT_SCHEMA.get_or_init(|| Arc::new(schema_object::<SearchToolsRequest>())))
}

/// Output schema generated from the exact response enum returned as
/// `structuredContent`.
///
/// Both untagged variants serialize as objects. The explicit object root keeps
/// the schema valid for pre-2026 MCP peers while retaining schemars' generated
/// `oneOf` branches.
pub fn output_schema() -> Arc<JsonObject> {
    Arc::clone(OUTPUT_SCHEMA.get_or_init(|| {
        let mut schema = schema_object::<SearchToolsResponse>();
        schema.insert("type".to_owned(), Value::String("object".to_owned()));
        Arc::new(schema)
    }))
}

fn schema_object<T: JsonSchema>() -> JsonObject {
    let schema = serde_json::to_value(schemars::schema_for!(T))
        .expect("legacy searchTools schema serializes")
        .as_object()
        .cloned()
        .expect("legacy searchTools schema has an object root");
    crate::tool_schema::portable_schema_object(&schema)
        .expect("gateway-owned searchTools schema is self-contained")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> OperationDescriptor {
        OperationDescriptor {
            name: "srv.tool".into(),
            description: Some("does a thing".into()),
            risk_level: RiskTier::Low,
            resource_type: Some("server".into()),
            action: Some("read".into()),
            scope: Some("mcp:invoke:high".into()),
            input_type: Some("In".into()),
            output_type: Some("Out".into()),
            side_effects: Some(false),
        }
    }

    #[test]
    fn project_full_is_unchanged() {
        let d = sample().project(Detail::Full);
        assert_eq!(d.description.as_deref(), Some("does a thing"));
        assert_eq!(d.input_type.as_deref(), Some("In"));
        assert_eq!(d.side_effects, Some(false));
        assert_eq!(d.scope.as_deref(), Some("mcp:invoke:high"));
    }

    #[test]
    fn project_name_description_keeps_name_desc_risk_only() {
        let d = sample().project(Detail::NameDescription);
        assert_eq!(d.name, "srv.tool");
        assert_eq!(d.description.as_deref(), Some("does a thing"));
        assert_eq!(d.risk_level, RiskTier::Low);
        assert!(d.resource_type.is_none());
        assert!(d.action.is_none());
        assert!(d.scope.is_none());
        assert!(d.input_type.is_none());
        assert!(d.output_type.is_none());
        assert!(d.side_effects.is_none());
    }

    #[test]
    fn project_name_only_drops_description() {
        let d = sample().project(Detail::NameOnly);
        assert_eq!(d.name, "srv.tool");
        assert_eq!(d.risk_level, RiskTier::Low);
        assert!(d.description.is_none());
        assert!(d.scope.is_none());
        assert!(d.input_type.is_none());
    }

    #[test]
    fn detail_defaults_to_full_and_deserialises_camelcase() {
        assert_eq!(Detail::default(), Detail::Full);
        // Omitted in the request → None → the handler defaults to Full.
        let req: SearchToolsRequest = serde_json::from_str(r#"{"mode":"operations"}"#).unwrap();
        assert!(req.detail.is_none());
        let req: SearchToolsRequest =
            serde_json::from_str(r#"{"mode":"operations","detail":"nameOnly"}"#).unwrap();
        assert_eq!(req.detail, Some(Detail::NameOnly));
    }

    #[test]
    fn mode_is_inferred_only_when_omitted() {
        for (value, expected) in [
            (json!({}), Mode::Operations),
            (json!({"query": "message"}), Mode::Operations),
            (json!({"name": "srv.tool#input"}), Mode::Types),
            (
                json!({"mode": "operations", "name": "srv.tool#input"}),
                Mode::Operations,
            ),
            (json!({"mode": "search"}), Mode::Operations),
            (
                json!({"mode": "describe", "name": "srv.tool#input"}),
                Mode::Types,
            ),
        ] {
            let request: SearchToolsRequest = serde_json::from_value(value).unwrap();
            assert_eq!(request.mode(), expected);
        }
    }

    #[test]
    fn query_normalization_preserves_other_filters_and_rejects_conflicts() {
        let request: SearchToolsRequest = serde_json::from_value(json!({
            "query": "message", "filters": {"riskLevel": "low", "scope": "read"}
        }))
        .unwrap();
        let request = request.normalize().unwrap();
        let filters = request.filters.unwrap();
        assert_eq!(filters.query.as_deref(), Some("message"));
        assert_eq!(filters.risk_level, Some(RiskTier::Low));
        assert_eq!(filters.scope.as_deref(), Some("read"));

        for (query, accepted) in [("message", true), ("contact", false)] {
            let request: SearchToolsRequest = serde_json::from_value(json!({
                "query": query, "filters": {"query": "message"}
            }))
            .unwrap();
            assert_eq!(request.normalize().is_ok(), accepted);
        }
    }

    #[test]
    fn schema_advertises_optional_mode_and_only_canonical_spellings() {
        let input = Value::Object((*input_schema()).clone());
        let validator = jsonschema::validator_for(&input).unwrap();
        assert!(validator.is_valid(&json!({})));
        assert!(validator.is_valid(&json!({"name": "srv.tool#input"})));
        let properties = input["properties"].as_object().unwrap();
        assert!(!properties.contains_key("query"));
        for alias in ["search", "describe", "summary", "names"] {
            assert!(!input.to_string().contains(&format!("\"{alias}\"")));
        }
        for value in [json!({"mode": "invalid"}), json!({"detail": "invalid"})] {
            assert!(serde_json::from_value::<SearchToolsRequest>(value).is_err());
        }
    }

    #[test]
    fn generated_schemas_compile_and_validate_runtime_values() {
        let input = Value::Object((*input_schema()).clone());
        let input_validator = jsonschema::validator_for(&input).expect("input schema compiles");
        let request = json!({
            "mode": "operations",
            "filters": {"riskLevel": "low", "query": "message"},
            "limit": 50,
            "detail": "nameDescription"
        });
        assert!(input_validator.is_valid(&request));
        let request: SearchToolsRequest = serde_json::from_value(request).expect("request DTO");
        assert!(request.validate().is_ok());

        let output = Value::Object((*output_schema()).clone());
        assert_eq!(
            output["type"], "object",
            "legacy peers require object output"
        );
        let output_validator = jsonschema::validator_for(&output).expect("output schema compiles");
        let responses = [
            SearchToolsResponse::Operations(OperationsResponse {
                operations: vec![sample()],
                next_cursor: Some("1".to_owned()),
            }),
            SearchToolsResponse::Types(TypesResponse {
                name: "srv.tool#input".to_owned(),
                json_schema: json!({"type": "object"}),
                references: vec!["Nested".to_owned()],
            }),
        ];
        for response in responses {
            let value = serde_json::to_value(response).expect("response DTO serializes");
            assert!(
                output_validator.is_valid(&value),
                "generated schema must accept the runtime DTO: {value}"
            );
        }
    }

    #[test]
    fn published_limit_constraint_matches_runtime_validation() {
        let input = Value::Object((*input_schema()).clone());
        let validator = jsonschema::validator_for(&input).expect("input schema compiles");
        let value = json!({"mode": "operations", "limit": 0});
        assert!(!validator.is_valid(&value));
        let request: SearchToolsRequest =
            serde_json::from_value(value).expect("shape deserializes before validation");
        assert!(request.validate().is_err());
        for limit in [501, 100_000, usize::MAX] {
            let value = json!({"limit": limit});
            assert!(validator.is_valid(&value));
            let request: SearchToolsRequest = serde_json::from_value(value).unwrap();
            assert!(request.normalize().is_ok());
        }
    }
}
