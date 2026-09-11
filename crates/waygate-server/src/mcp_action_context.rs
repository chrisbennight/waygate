//! MCP-wire adapter for proposer preparation context.
//!
//! The action-aware read logic and response types live in
//! `waygate-admin::change_context`; this module only translates the
//! `gateway-admin.get_action_context` tool call to that shared core.

use std::sync::{Arc, OnceLock};

use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use waygate_admin::change_context::{read_action_context, ActionContextResponse};
use waygate_admin::AdminState;
use waygate_oidc::Principal;

use crate::mcp_builtin::{api_to_mcp, schema_obj, structured, NAMESPACE};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GetActionContextRequest {
    /// Registered action whose current preparation context is needed. Call
    /// `gateway-admin.describe_action` first; only entries with non-null
    /// `context` support this read.
    action_type: String,
    /// Action-specific read selector. Validate this object against
    /// `describe_action(action_type).actions[0].context.selector_schema`.
    /// Omit it for the action's paginated candidate or identifier listing.
    #[serde(default)]
    selector: Option<JsonObject>,
}

pub(crate) fn tool_def() -> Tool {
    Tool::new(
        format!("{NAMESPACE}.get_action_context"),
        "Read authoritative current state required by `describe_action`. Copy returned hashes or \
         versions verbatim; never calculate them. For manifest upserts, select the server and \
         preserve its complete returned manifest. Tenant comes from your maker identity; \
         credential references remain unresolved. No change is queued.",
        input_schema::<GetActionContextRequest>(),
    )
    .with_title("Read proposal preparation context")
    .with_output_schema::<ActionContextResponse>()
    .annotate(ToolAnnotations::new().read_only(true))
}

pub(crate) async fn call(
    admin_state: &Arc<OnceLock<Arc<AdminState>>>,
    principal: &Principal,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let request: GetActionContextRequest = serde_json::from_value(Value::Object(args.clone()))
        .map_err(|e| {
            McpError::invalid_params(
                format!(
                    "invalid get_action_context arguments: {e}; inspect this tool's inputSchema \
                     and call describe_action(action_type) for the selector schema. Example: \
                     {{\"action_type\":\"manifest.upsert_servers\",\"selector\":\
                     {{\"server_name\":\"example-messages\"}}}}"
                ),
                None,
            )
        })?;
    let selector = Value::Object(request.selector.unwrap_or_default());
    let state = admin_state.get().ok_or_else(|| {
        McpError::internal_error("action context is not ready (gateway still starting)", None)
    })?;
    let response = read_action_context(
        state,
        principal.tenant.as_str(),
        &request.action_type,
        selector,
    )
    .await
    .map_err(api_to_mcp)?;
    Ok(structured(&response))
}

fn input_schema<T: JsonSchema>() -> Arc<JsonObject> {
    schema_obj(
        serde_json::to_value(schemars::schema_for!(T))
            .expect("schemars action-context input schema serializes to JSON"),
    )
}
