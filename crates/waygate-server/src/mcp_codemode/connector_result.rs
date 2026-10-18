//! Preserve inspected MCP result content in the Code Mode connector value.

use rmcp::{model::CallToolResult, ErrorData as McpError};
use serde_json::{json, Value};
use waygate_invocation::InvocationError;
use waygate_mcp::{
    invocation::mirrors_structured,
    retained_delivery::{CODEMODE_CONTENT_FIELD, FIELD},
};

pub(super) fn connector_result_value(mut result: CallToolResult) -> Result<Value, InvocationError> {
    if result.is_error.unwrap_or(false) {
        return Err(InvocationError::Upstream(McpError::internal_error(
            "connector reported a tool error",
            result.structured_content,
        )));
    }
    let delivery = result
        .meta
        .as_ref()
        .and_then(|meta| meta.get(waygate_mcp::files::RETAINED_DELIVERY_META_KEY))
        .cloned();
    let Some(structured) = result.structured_content.take() else {
        let mut value = serde_json::to_value(&result).map_err(|_| {
            InvocationError::Upstream(McpError::internal_error(
                "connector result could not be encoded",
                None,
            ))
        })?;
        if let Some(delivery) = delivery {
            value[FIELD] = delivery;
        }
        return Ok(value);
    };
    let content: Vec<_> = result
        .content
        .into_iter()
        .filter(|block| {
            !block
                .as_text()
                .is_some_and(|text| mirrors_structured(&text.text, &structured))
        })
        .collect();
    // Gateway members cannot overwrite an upstream value or make it appear
    // to be gateway-authored. Scalars need an object only when adding members.
    let reserved_member =
        structured.get(FIELD).is_some() || structured.get(CODEMODE_CONTENT_FIELD).is_some();
    let mut value = if reserved_member
        || (!structured.is_object() && (!content.is_empty() || delivery.is_some()))
    {
        json!({"data": structured})
    } else {
        structured
    };
    if let Some(object) = value.as_object_mut() {
        if !content.is_empty() {
            object.insert(CODEMODE_CONTENT_FIELD.to_owned(), json!(content));
        }
        if let Some(delivery) = delivery {
            object.insert(FIELD.to_owned(), delivery);
        }
    }
    Ok(value)
}
