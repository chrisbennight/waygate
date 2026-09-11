//! Minimal subset of MCP JSON-RPC 2.0 envelope types.
//!
//! The gateway uses `rmcp` at runtime for full protocol handling; these types
//! are kept here for the admin API surface that renders tool metadata.

use rmcp::model::CallToolResult;
use rmcp::ErrorData;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

// `RiskTier` lives in `waygate-core` as a cross-cutting
// domain type the typed `Facts` also carry. Re-exported here so the
// established `waygate_mcp::protocol::RiskTier` path keeps resolving.
pub use waygate_core::RiskTier;

/// OTel semconv `error.type` for a `tools/call` result
/// (<https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/>):
///
/// - `Some("tool_error")` when the tool itself returned `isError: true`
///   (a JSON-RPC call that succeeded but whose `CallToolResult` signals a
///   tool-level error),
/// - `Some(<code>)` — the string form of the JSON-RPC error code — on a
///   protocol/transport error,
/// - `None` on success.
///
/// Shared by the inbound server span (`waygate-mcp`) and the upstream client
/// span (`waygate-upstream`) so both legs label errors identically.
pub fn tool_call_error_type(result: &Result<CallToolResult, ErrorData>) -> Option<String> {
    match result {
        Ok(r) if r.is_error == Some(true) => Some("tool_error".to_owned()),
        Ok(_) => None,
        Err(e) => Some(e.code.0.to_string()),
    }
}

/// [`tool_call_error_type`] over the full MRTR response union: an
/// `input_required` pause and a task envelope are successful round trips
/// (`None`), a complete result classifies exactly as before. Both call
/// legs share this so a pause is never miscounted as an upstream failure.
pub fn tool_call_response_error_type(
    result: &Result<rmcp::model::CallToolResponse, ErrorData>,
) -> Option<String> {
    match result {
        Ok(rmcp::model::CallToolResponse::Complete(r)) if r.is_error == Some(true) => {
            Some("tool_error".to_owned())
        }
        Ok(_) => None,
        Err(e) => Some(e.code.0.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ErrorCode;

    #[test]
    fn error_type_none_on_success() {
        assert_eq!(
            tool_call_error_type(&Ok(CallToolResult::success(vec![]))),
            None
        );
    }

    #[test]
    fn error_type_tool_error_when_is_error_set() {
        assert_eq!(
            tool_call_error_type(&Ok(CallToolResult::error(vec![]))).as_deref(),
            Some("tool_error"),
        );
    }

    #[test]
    fn error_type_is_jsonrpc_code_on_err() {
        let err = ErrorData::new(ErrorCode::INVALID_PARAMS, "bad params", None);
        assert_eq!(tool_call_error_type(&Err(err)).as_deref(), Some("-32602"),);
    }
}
