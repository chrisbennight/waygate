//! Preserve inspected MCP result content in the Code Mode connector value.

use rmcp::model::CallToolResult;
use serde_json::{json, Value};
use waygate_mcp::{
    invocation::mirrors_structured,
    retained_delivery::{CODEMODE_CONTENT_FIELD, FIELD},
};

use crate::process_mode::codemode_protocol::{ConnectorCallError, ToolErrorDetail};

/// Upstream results reach this boundary after invocation inspection and release.
pub(super) fn connector_result_value(
    mut result: CallToolResult,
) -> Result<Value, ConnectorCallError> {
    if result.is_error.unwrap_or(false) {
        return Err(ConnectorCallError::Tool {
            tool_error: tool_error_detail(&result),
        });
    }
    let delivery = result
        .meta
        .as_ref()
        .and_then(|meta| meta.get(waygate_mcp::files::RETAINED_DELIVERY_META_KEY))
        .cloned();
    let Some(structured) = result.structured_content.take() else {
        let mut value = serde_json::to_value(&result).map_err(|_| {
            super::connector_error("upstream", "connector result could not be encoded")
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

fn tool_error_detail(result: &CallToolResult) -> Option<ToolErrorDetail> {
    const MAX_CODE_BYTES: usize = 64;
    const MAX_MESSAGE_BYTES: usize = 1024;
    const MAX_TEXT_BYTES: usize = 4096;

    // Prefer structured content. Only a sole JSON text block is a legacy
    // envelope; mixed content and transport errors are never interpreted.
    let parsed;
    let value = if let Some(value) = result.structured_content.as_ref() {
        value
    } else {
        let [block] = result.content.as_slice() else {
            return None;
        };
        let text = &block.as_text()?.text;
        if text.len() > MAX_TEXT_BYTES {
            return None;
        }
        parsed = serde_json::from_str::<Value>(text).ok()?;
        &parsed
    };
    let error = value.get("error")?.as_object()?;
    let code = error.get("code")?.as_str()?;
    let message = error.get("message")?.as_str()?;
    if code.is_empty()
        || code.len() > MAX_CODE_BYTES
        || !code.as_bytes()[0].is_ascii_lowercase()
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || message.len() > MAX_MESSAGE_BYTES
        || message.chars().any(char::is_control)
    {
        return None;
    }
    // Only these fields are released; context, diagnostics and metadata are
    // not part of the connector error detail contract.
    Some(ToolErrorDetail {
        code: code.to_owned(),
        message: message.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ContentBlock as Content;

    fn projected_error(result: CallToolResult) -> Option<ToolErrorDetail> {
        match connector_result_value(result).expect_err("tool result must fail") {
            ConnectorCallError::Tool { tool_error } => tool_error,
            error => panic!("unexpected refusal: {error:?}"),
        }
    }

    #[test]
    fn structured_and_legacy_tool_errors_preserve_only_domain_detail() {
        for code in [
            "flow_not_found",
            "flow_permission_denied",
            "target_mismatch",
            "invalid_arguments",
        ] {
            let envelope = json!({"error": {"code": code, "message": "safe domain detail",
                "context": {"diagnostic": "excluded synthetic diagnostic"}}, "extra": "excluded"});
            for structured in [true, false] {
                let mut result = if structured {
                    CallToolResult::structured(envelope.clone())
                } else {
                    CallToolResult::error(vec![Content::text(envelope.to_string())])
                };
                result.is_error = Some(true);
                assert_eq!(
                    projected_error(result),
                    Some(ToolErrorDetail {
                        code: code.into(),
                        message: "safe domain detail".into(),
                    })
                );
            }
        }
    }

    #[test]
    fn domain_error_bounds_accept_the_documented_utf8_limits() {
        let code = "a".repeat(64);
        let message = "é".repeat(512);
        let envelope = json!({"error": {"code": code, "message": message}});
        let mut result = CallToolResult::structured(envelope.clone());
        result.is_error = Some(true);
        assert_eq!(
            projected_error(result),
            Some(ToolErrorDetail {
                code: code.clone(),
                message: message.clone()
            })
        );
        let mut text = envelope.to_string();
        text.push_str(&" ".repeat(4096 - text.len()));
        assert_eq!(
            projected_error(CallToolResult::error(vec![Content::text(text)])),
            Some(ToolErrorDetail { code, message })
        );
    }

    #[test]
    fn malformed_ambiguous_and_oversized_errors_stay_generic() {
        for envelope in [
            json!({"error": {"code": "invalid-code", "message": "safe"}}),
            json!({"error": {"code": "a".repeat(65), "message": "safe"}}),
            json!({"error": {"code": "valid_code", "message": "é".repeat(513)}}),
            json!({"error": {"code": "valid_code", "message": "line\nbreak"}}),
            json!({"error": {"code": "", "message": "safe"}}),
            json!({"error": {"code": 42, "message": "safe"}}),
            json!({"error": {"code": "valid_code"}}),
            json!({"reason": "excluded raw diagnostic"}),
        ] {
            let mut result = CallToolResult::structured(envelope);
            result.is_error = Some(true);
            assert_eq!(projected_error(result), None);
        }
        let mut result = CallToolResult::error(vec![Content::text(" ".repeat(4097))]);
        assert_eq!(projected_error(result.clone()), None);
        result.content = vec![Content::text("not JSON")];
        assert_eq!(projected_error(result.clone()), None);
        result.content = vec![
            Content::text(r#"{"error":{"code":"valid_code","message":"safe"}}"#),
            Content::text("extra"),
        ];
        assert_eq!(projected_error(result.clone()), None);
        result.content.truncate(1);
        result.structured_content = Some(json!({"reason": "structured wins"}));
        assert_eq!(projected_error(result), None);
    }
}
