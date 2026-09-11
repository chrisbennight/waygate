//! SEP #1888 wire types, mirrored from `waygate-mcp` so this crate does not
//! take a runtime dependency on the server it's testing.
//!
//! Keeping the shapes local also means a breaking change in the gateway's
//! types surfaces as a deserialization failure in conformance rather than
//! as a compile error we'd silently patch.

use serde::{Deserialize, Serialize};

pub const SEARCH_TOOLS_SUFFIX: &str = ".searchTools";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchToolsRequest {
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<OperationFilters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Operations,
    Types,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationFilters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl RiskTier {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationsResponse {
    pub operations: Vec<OperationDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationDescriptor {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub risk_level: RiskTier,
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    /// The step-up scope associated with this tool's risk tier (derived
    /// server-side; `None` for low-risk). Mirrors the server's
    /// `OperationDescriptor.scope` so `--json` round-trips it and operators
    /// can inspect the advisory step-up scope (actual gating is Cedar policy).
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub input_type: Option<String>,
    #[serde(default)]
    pub output_type: Option<String>,
    #[serde(default)]
    pub side_effects: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypesResponse {
    pub name: String,
    pub json_schema: serde_json::Value,
    #[serde(default)]
    pub references: Vec<String>,
}

/// Given a tool name emitted by `tools/list`, return the upstream server
/// name iff the tool is a `<server>.searchTools` meta-tool.
pub fn server_from_search_tool(tool_name: &str) -> Option<&str> {
    tool_name.strip_suffix(SEARCH_TOOLS_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_operations_response() {
        let raw = serde_json::json!({
            "operations": [{
                "name": "example-messages.send_message",
                "description": "Send a message",
                "riskLevel": "medium",
                "action": "write",
                "inputType": "example-messages.send_message#input",
                "outputType": "example-messages.send_message#output",
                "sideEffects": true
            }],
            "nextCursor": null
        });
        let parsed: OperationsResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.operations.len(), 1);
        assert_eq!(parsed.operations[0].risk_level, RiskTier::Medium);
        assert_eq!(parsed.operations[0].side_effects, Some(true));
    }

    #[test]
    fn parse_types_response() {
        let raw = serde_json::json!({
            "name": "example-messages.send_message",
            "jsonSchema": {"type": "object"},
            "references": []
        });
        let parsed: TypesResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.name, "example-messages.send_message");
    }

    #[test]
    fn risk_tier_round_trips() {
        for r in [RiskTier::Low, RiskTier::Medium, RiskTier::High] {
            let s = r.as_str();
            assert_eq!(RiskTier::parse(s), Some(r));
        }
    }

    #[test]
    fn server_from_search_tool_extracts_prefix() {
        assert_eq!(
            server_from_search_tool("example-messages.searchTools"),
            Some("example-messages")
        );
        assert_eq!(
            server_from_search_tool("example-mailbox.searchTools"),
            Some("example-mailbox")
        );
        assert_eq!(server_from_search_tool("foo.bar"), None);
    }
}
