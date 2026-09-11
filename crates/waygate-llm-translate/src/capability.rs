//! Pre-dispatch capability gate: reject feature/provider combinations the
//! resolved route cannot render faithfully BEFORE any irreversible cost (I2),
//! producing a clean client error rather than a render-time failure deep in
//! dispatch (which would surface as a transport `502`). The renderers in
//! [`crate::outbound`] remain independently fail-closed (I6) for
//! directly-constructed requests; this gate is the earlier, friendlier check on
//! the request path, run once the route's [`UpstreamProtocol`] is known.

use crate::canonical::{LlmRequest, UpstreamProtocol};
use crate::inbound::TranslateError;

/// Verify the canonical request's features are renderable on the resolved
/// upstream protocol. Returns [`TranslateError::Unsupported`] for a combination
/// the target provider cannot faithfully express, so the caller can surface a
/// clean client error before authorizing/charging/dispatching the call.
///
/// This is the single source of truth for the provider-capability matrix; the
/// per-provider renderers enforce the same rules locally as a fail-closed
/// backstop (I6). Streaming tool calls are now translated on every provider
/// (the Anthropic / Gemini / Responses streaming tool-delta translators); the
/// remaining gates are the structurally-impossible response_format+tools
/// combination on the Anthropic emulation, and a Responses `previous_response_id`
/// targeting a non-Responses upstream (which cannot render the state handle).
pub fn check_provider_support(
    req: &LlmRequest,
    protocol: UpstreamProtocol,
) -> Result<(), TranslateError> {
    // Anthropic emulates `response_format` by forcing a synthetic tool, which is
    // ambiguous if combined with the caller's own tools — reject that pair (the
    // renderer enforces the same rule as a backstop).
    if protocol == UpstreamProtocol::AnthropicMessages
        && req.response_format.is_some()
        && (!req.tools.is_empty() || req.tool_choice.is_some())
    {
        return Err(TranslateError::Unsupported {
            surface: "anthropic_messages",
            param: "response_format combined with tools".into(),
        });
    }
    // A Responses-surface `previous_response_id` is a server-side conversation
    // handle only the OpenAI Responses backend can honor — its own store provides
    // continuity (the gateway is stateless and stores nothing, I9). On any other
    // protocol the renderer drops it, silently changing the request's meaning, so
    // reject it here for a clean client error rather than a lossy dispatch (I6).
    if req.previous_response_id.is_some() && protocol != UpstreamProtocol::OpenAiResponses {
        return Err(TranslateError::Unsupported {
            surface: protocol.wire_name(),
            param: "previous_response_id (only an OpenAI Responses upstream can honor a \
                    server-side conversation handle)"
                .into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{
        CanonicalMessage, CanonicalTool, ContentPart, ResponseFormat, Role, Sampling, Surface,
        ToolChoice,
    };
    use serde_json::json;

    fn req() -> LlmRequest {
        LlmRequest {
            inbound_surface: Surface::ChatCompletions,
            model_requested: "m".into(),
            messages: vec![CanonicalMessage {
                role: Role::User,
                content: vec![ContentPart::Text { text: "x".into() }],
            }],
            sampling: Sampling::default(),
            tools: vec![],
            tool_choice: None,
            parallel_tool_calls: None,
            response_format: None,
            previous_response_id: None,
            store: None,
            stream: false,
        }
    }

    fn a_tool() -> CanonicalTool {
        CanonicalTool {
            name: "f".into(),
            description: None,
            parameters: json!({"type": "object"}),
            strict: None,
        }
    }

    #[test]
    fn anthropic_response_format_is_now_supported_unary() {
        // Anthropic structured output is emulated (as a forced tool call), so
        // a non-stream request passes the capability check.
        let mut r = req();
        r.response_format = Some(ResponseFormat::JsonObject);
        assert!(check_provider_support(&r, UpstreamProtocol::AnthropicMessages).is_ok());
    }

    #[test]
    fn unary_tools_pass_on_every_provider() {
        let mut r = req();
        r.tools = vec![a_tool()];
        for p in [
            UpstreamProtocol::OpenAiChat,
            UpstreamProtocol::OpenAiResponses,
            UpstreamProtocol::Gemini,
            UpstreamProtocol::AnthropicMessages,
        ] {
            assert!(
                check_provider_support(&r, p).is_ok(),
                "unary tools on {p:?}"
            );
        }
    }

    #[test]
    fn streaming_tools_pass_on_every_provider() {
        // Streaming tool-call deltas are translated on every provider.
        let mut r = req();
        r.tools = vec![a_tool()];
        r.stream = true;
        for p in [
            UpstreamProtocol::OpenAiChat,
            UpstreamProtocol::OpenAiResponses,
            UpstreamProtocol::Gemini,
            UpstreamProtocol::AnthropicMessages,
        ] {
            assert!(
                check_provider_support(&r, p).is_ok(),
                "streaming tools on {p:?}"
            );
        }
    }

    #[test]
    fn streaming_anthropic_structured_output_passes() {
        // The Anthropic structured-output emulation streams as a tool call
        // that gets translated (unwound to content), so a streaming
        // response_format on Anthropic is supported.
        let mut r = req();
        r.response_format = Some(ResponseFormat::JsonObject);
        r.stream = true;
        for p in [
            UpstreamProtocol::AnthropicMessages,
            UpstreamProtocol::Gemini,
            UpstreamProtocol::OpenAiResponses,
        ] {
            assert!(
                check_provider_support(&r, p).is_ok(),
                "streaming structured output on {p:?}"
            );
        }
    }

    #[test]
    fn anthropic_response_format_with_tools_rejects() {
        let mut r = req();
        r.response_format = Some(ResponseFormat::JsonObject);
        r.tool_choice = Some(ToolChoice::Auto);
        assert!(matches!(
            check_provider_support(&r, UpstreamProtocol::AnthropicMessages),
            Err(TranslateError::Unsupported { param, .. }) if param == "response_format combined with tools"
        ));
    }

    #[test]
    fn plain_request_passes_every_provider_streaming_or_not() {
        for stream in [false, true] {
            let mut r = req();
            r.stream = stream;
            for p in [
                UpstreamProtocol::OpenAiChat,
                UpstreamProtocol::OpenAiResponses,
                UpstreamProtocol::Gemini,
                UpstreamProtocol::AnthropicMessages,
            ] {
                assert!(check_provider_support(&r, p).is_ok());
            }
        }
    }

    #[test]
    fn previous_response_id_rejected_off_a_responses_route() {
        let mut r = req();
        r.previous_response_id = Some("resp_abc".into());
        // Honored only on the OpenAI Responses upstream (its store provides
        // continuity); the gateway stores nothing (I9).
        assert!(check_provider_support(&r, UpstreamProtocol::OpenAiResponses).is_ok());
        // Rejected on every other protocol — it would be silently dropped at
        // render time, changing the request's meaning.
        for p in [
            UpstreamProtocol::OpenAiChat,
            UpstreamProtocol::AnthropicMessages,
            UpstreamProtocol::Gemini,
        ] {
            assert!(
                matches!(check_provider_support(&r, p),
                    Err(TranslateError::Unsupported { param, .. }) if param.contains("previous_response_id")),
                "previous_response_id must reject on {p:?}"
            );
        }
        // Absent ⇒ no gate, on any protocol.
        assert!(check_provider_support(&req(), UpstreamProtocol::OpenAiChat).is_ok());
    }
}
