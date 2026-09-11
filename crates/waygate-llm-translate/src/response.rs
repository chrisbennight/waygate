//! Response extraction: a provider response body → the [`InferenceRecord`]
//! response-metadata fields (model served, token usage, finish reason, upstream
//! ids), plus the per-provider body translations into the OpenAI Chat
//! Completions shape the gateway's `/v1/chat/completions` route promises.
//! Covers OpenAI Chat, Anthropic Messages, Gemini, and OpenAI Responses —
//! including unwinding tool calls into `message.tool_calls` and the Anthropic
//! structured-output emulation. Streaming (terminal-frame) extraction lives in
//! `stream.rs`, sharing the usage / finish-reason parsers here.

use serde_json::{json, Value};

use crate::canonical::UpstreamProtocol;
use crate::outbound::STRUCTURED_OUTPUT_TOOL_NAME;
use crate::record::{FinishReason, InferenceRecord, TokenUsage};

/// Fold an OpenAI Chat Completions response into the `InferenceRecord` started
/// before dispatch (`base` carries provider / credential / requested-model /
/// surface). Missing fields stay `None` — never fabricated.
pub fn extract_openai_chat(mut base: InferenceRecord, response: &Value) -> InferenceRecord {
    base.upstream_protocol = UpstreamProtocol::OpenAiChat;
    base.model_served = str_field(response, "model");
    base.upstream_request_id = str_field(response, "id");
    base.system_fingerprint = str_field(response, "system_fingerprint");

    if let Some(usage) = response.get("usage") {
        base.usage = token_usage_from(usage);
        base.provider_prompt_cache = base.usage.cached_read.map(|c| c > 0);
    }

    if let Some(choice) = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
    {
        if let Some(reason) = str_field(choice, "finish_reason") {
            if reason == "content_filter" {
                base.refusal = true;
            }
            base.finish_reason = Some(normalize_finish_reason(&reason));
        }
        // OpenAI structured outputs report a refusal in `message.refusal` (a
        // non-empty string) even when `finish_reason` is "stop" — surface it so
        // the refusal metadata is not lost on that path.
        if choice
            .get("message")
            .and_then(|m| m.get("refusal"))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            base.refusal = true;
        }
    }

    base
}

/// Parse an OpenAI-style `usage` object into canonical [`TokenUsage`]. Shared by
/// the unary extractor and the streaming aggregator so both stay aligned with
/// one token-accounting contract. Unreported classes stay `None`.
pub(crate) fn token_usage_from(usage: &Value) -> TokenUsage {
    TokenUsage {
        input: u64_field(usage, "prompt_tokens"),
        output: u64_field(usage, "completion_tokens"),
        cached_read: usage
            .get("prompt_tokens_details")
            .and_then(|d| u64_field(d, "cached_tokens")),
        cache_write: None,
        reasoning: usage
            .get("completion_tokens_details")
            .and_then(|d| u64_field(d, "reasoning_tokens")),
    }
}

/// Fold an **Anthropic Messages API** response into the `InferenceRecord`
/// started before dispatch. Anthropic reports usage under `usage`
/// (`input_tokens` / `output_tokens` plus `cache_read_input_tokens` /
/// `cache_creation_input_tokens`), a top-level `stop_reason`, and `id` / `model`
/// for correlation; there is no `system_fingerprint`. Missing fields stay
/// `None` — never fabricated.
///
/// Token-semantics note: Anthropic's `input_tokens` is the **non-cached** prompt
/// count, with cache reads/writes reported separately — unlike OpenAI's
/// `prompt_tokens`, which is the total *including* cached. Each canonical field
/// maps directly from its corresponding provider field (no summing /
/// fabrication); cost prices the classes separately (design §4.2).
pub fn extract_anthropic_messages(mut base: InferenceRecord, response: &Value) -> InferenceRecord {
    base.upstream_protocol = UpstreamProtocol::AnthropicMessages;
    base.model_served = str_field(response, "model");
    base.upstream_request_id = str_field(response, "id");

    if let Some(usage) = response.get("usage") {
        base.usage = anthropic_token_usage_from(usage);
        base.provider_prompt_cache = base.usage.cached_read.map(|c| c > 0);
    }

    if let Some(reason) = str_field(response, "stop_reason") {
        if reason == "refusal" {
            base.refusal = true;
        }
        base.finish_reason = Some(normalize_anthropic_stop_reason(&reason));
    }
    // A structured-output emulation response stops with `tool_use` (the forced
    // sentinel tool), but the client receives a normal completion (the tool call
    // is unwound into content). Record `Stop` so the usage/audit metadata matches
    // the client-visible finish rather than logging it as a tool call.
    if base.finish_reason == Some(FinishReason::ToolUse) && is_structured_output_emulation(response)
    {
        base.finish_reason = Some(FinishReason::Stop);
    }
    base
}

/// Whether an Anthropic response body is the structured-output emulation — i.e.
/// it carries a `tool_use` block named [`STRUCTURED_OUTPUT_TOOL_NAME`]. Used to
/// keep the `InferenceRecord` finish reason aligned with the client-visible one
/// (a normal completion, not a tool call) — matching what
/// `anthropic_response_to_openai_chat` does to the client body.
fn is_structured_output_emulation(response: &Value) -> bool {
    response
        .get("content")
        .and_then(Value::as_array)
        .is_some_and(|blocks| {
            blocks.iter().any(|b| {
                b.get("type").and_then(Value::as_str) == Some("tool_use")
                    && b.get("name").and_then(Value::as_str) == Some(STRUCTURED_OUTPUT_TOOL_NAME)
            })
        })
}

/// Parse an Anthropic `usage` object into canonical [`TokenUsage`]. Each field
/// maps directly from the corresponding Anthropic field; Anthropic reports no
/// separate reasoning-token count (extended-thinking tokens fold into
/// `output_tokens`), so `reasoning` stays `None`.
pub(crate) fn anthropic_token_usage_from(usage: &Value) -> TokenUsage {
    TokenUsage {
        input: u64_field(usage, "input_tokens"),
        output: u64_field(usage, "output_tokens"),
        cached_read: u64_field(usage, "cache_read_input_tokens"),
        cache_write: u64_field(usage, "cache_creation_input_tokens"),
        reasoning: None,
    }
}

/// Map an Anthropic `stop_reason` to the canonical [`FinishReason`].
/// `end_turn` / `stop_sequence` are both natural stops; `max_tokens` is a length
/// cap; `tool_use` is a tool call; `refusal` is a safety stop (also flagged on
/// `base.refusal`). Unknown reasons fall to `Other`.
pub(crate) fn normalize_anthropic_stop_reason(s: &str) -> FinishReason {
    match s {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolUse,
        "refusal" => FinishReason::ContentFilter,
        _ => FinishReason::Other,
    }
}

/// Translate an Anthropic Messages **response body** into the OpenAI Chat
/// Completions response shape. The gateway's public `/v1/chat/completions` route
/// promises the OpenAI shape regardless of which provider served the call, so an
/// Anthropic upstream's body must be converted before it reaches the client
/// (the OpenAI path passes its body through unchanged). Text content blocks are
/// concatenated into `choices[0].message.content`; `stop_reason` →
/// `finish_reason`; `input_tokens` / `output_tokens` → `prompt_tokens` /
/// `completion_tokens` (+ `total_tokens`). Missing fields are simply omitted —
/// nothing fabricated.
///
/// Tool-use content blocks become OpenAI `tool_calls` (id / function name /
/// arguments-as-JSON-string). A tool_use-only response yields `content: null`
/// with `finish_reason: "tool_calls"`. The structured-output emulation is
/// unwound here: a `tool_use` named [`STRUCTURED_OUTPUT_TOOL_NAME`] (forced by
/// the renderer for a `response_format` request that routed to Anthropic) is
/// rendered as the assistant `content` (its `input` serialized to JSON) with a
/// normal `stop` finish, since to the client it is a structured *answer*, not a
/// tool call.
pub fn anthropic_response_to_openai_chat(resp: &Value) -> Value {
    let blocks = resp.get("content").and_then(Value::as_array);
    let mut finish_reason = resp
        .get("stop_reason")
        .and_then(Value::as_str)
        .map(anthropic_stop_reason_to_openai);

    let mut message = serde_json::Map::new();
    message.insert("role".into(), Value::from("assistant"));

    let emulated = blocks.and_then(|bs| {
        bs.iter().find(|b| {
            b.get("type").and_then(Value::as_str) == Some("tool_use")
                && b.get("name").and_then(Value::as_str) == Some(STRUCTURED_OUTPUT_TOOL_NAME)
        })
    });
    if let Some(b) = emulated {
        let input = b.get("input").cloned().unwrap_or_else(|| json!({}));
        message.insert(
            "content".into(),
            Value::from(serde_json::to_string(&input).unwrap_or_default()),
        );
        // A structured answer reads as a normal completion, not a tool call.
        finish_reason = Some("stop");
    } else {
        let content_text: String = blocks
            .map(|bs| {
                bs.iter()
                    .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                    .filter_map(|b| b.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        let tool_calls = anthropic_tool_calls(blocks);
        // OpenAI's canonical no-text-but-tool-calls form is `content: null`.
        if content_text.is_empty() && !tool_calls.is_empty() {
            message.insert("content".into(), Value::Null);
        } else {
            message.insert("content".into(), Value::from(content_text));
        }
        if !tool_calls.is_empty() {
            // OpenAI signals a tool-call turn via `finish_reason: "tool_calls"`.
            // Anthropic's `stop_reason: "tool_use"` already maps to it, but force
            // it whenever tool_calls are present so the contract holds even if the
            // upstream reported a different stop reason.
            finish_reason = Some("tool_calls");
            message.insert("tool_calls".into(), Value::Array(tool_calls));
        }
    }

    let mut obj = serde_json::Map::new();
    if let Some(id) = resp.get("id") {
        obj.insert("id".into(), id.clone());
    }
    obj.insert("object".into(), Value::from("chat.completion"));
    if let Some(model) = resp.get("model") {
        obj.insert("model".into(), model.clone());
    }
    obj.insert(
        "choices".into(),
        serde_json::json!([{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }]),
    );
    if let Some(usage) = resp.get("usage") {
        let prompt = u64_field(usage, "input_tokens");
        let completion = u64_field(usage, "output_tokens");
        if prompt.is_some() || completion.is_some() {
            let total = match (prompt, completion) {
                (Some(p), Some(c)) => Some(p + c),
                _ => None,
            };
            obj.insert(
                "usage".into(),
                serde_json::json!({
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                    "total_tokens": total,
                }),
            );
        }
    }
    Value::Object(obj)
}

/// Collect Anthropic `tool_use` content blocks into OpenAI `tool_calls`
/// (`[{id, type:function, function:{name, arguments}}]`). Anthropic's `input` is
/// an object; OpenAI's `arguments` is a JSON string, so it is serialized.
fn anthropic_tool_calls(blocks: Option<&Vec<Value>>) -> Vec<Value> {
    blocks
        .map(|bs| {
            bs.iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
                .map(|b| {
                    let id = b.get("id").and_then(Value::as_str).unwrap_or_default();
                    let name = b.get("name").and_then(Value::as_str).unwrap_or_default();
                    let arguments = b
                        .get("input")
                        .map(|i| serde_json::to_string(i).unwrap_or_default())
                        .unwrap_or_else(|| "{}".to_string());
                    json!({
                        "id": id,
                        "type": "function",
                        "function": { "name": name, "arguments": arguments },
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Map an Anthropic `stop_reason` to the OpenAI `finish_reason` string used in
/// the translated response body. Distinct from [`normalize_anthropic_stop_reason`],
/// which yields the canonical [`FinishReason`] enum for the `InferenceRecord`.
/// Shared with the streaming translator so the unary and streamed response
/// surfaces agree on one finish-reason vocabulary.
pub(crate) fn anthropic_stop_reason_to_openai(s: &str) -> &'static str {
    match s {
        "end_turn" | "stop_sequence" => "stop",
        "max_tokens" => "length",
        "tool_use" => "tool_calls",
        "refusal" => "content_filter",
        _ => "stop",
    }
}

/// Fold a **Gemini `generateContent`** response into the `InferenceRecord`.
/// Gemini reports usage under `usageMetadata` (`promptTokenCount` /
/// `candidatesTokenCount` plus `cachedContentTokenCount` / `thoughtsTokenCount`),
/// the finish reason at `candidates[0].finishReason`, the served model at
/// `modelVersion`, and an optional `responseId`. Missing fields stay `None`.
pub fn extract_gemini(mut base: InferenceRecord, response: &Value) -> InferenceRecord {
    base.upstream_protocol = UpstreamProtocol::Gemini;
    base.model_served = str_field(response, "modelVersion");
    base.upstream_request_id = str_field(response, "responseId");

    if let Some(um) = response.get("usageMetadata") {
        base.usage = gemini_token_usage_from(um);
        base.provider_prompt_cache = base.usage.cached_read.map(|c| c > 0);
    }

    let candidate = response
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|c| c.first());
    if let Some(reason) = candidate.and_then(|c| str_field(c, "finishReason")) {
        let canon = normalize_gemini_finish_reason(&reason);
        if canon == FinishReason::ContentFilter {
            base.refusal = true;
        }
        base.finish_reason = Some(canon);
    }
    // Gemini reports `STOP` even on a function-call turn; the client body is
    // mapped to `tool_calls`, so the durable record must agree — record
    // `ToolUse` when the response carries a functionCall (a content filter still
    // wins, so it isn't overridden).
    let parts = candidate
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(Value::as_array);
    if base.finish_reason != Some(FinishReason::ContentFilter)
        && !gemini_tool_calls(parts).is_empty()
    {
        base.finish_reason = Some(FinishReason::ToolUse);
    }
    base
}

/// Parse a Gemini `usageMetadata` object into canonical [`TokenUsage`]. Shared by
/// the unary extractor and the streaming translator so both stay aligned with one
/// token-accounting contract. `thoughtsTokenCount` (extended-thinking tokens)
/// maps to `reasoning`; Gemini has no separate cache-write count. Unreported
/// classes stay `None`.
pub(crate) fn gemini_token_usage_from(um: &Value) -> TokenUsage {
    TokenUsage {
        input: u64_field(um, "promptTokenCount"),
        output: u64_field(um, "candidatesTokenCount"),
        cached_read: u64_field(um, "cachedContentTokenCount"),
        cache_write: None,
        reasoning: u64_field(um, "thoughtsTokenCount"),
    }
}

/// Translate a **Gemini `generateContent` response body** into the OpenAI Chat
/// Completions response shape (the gateway's `/v1/chat/completions` contract).
/// `candidates[0].content.parts` text is concatenated into the message;
/// `finishReason` and `usageMetadata` are mapped to OpenAI vocabulary. Missing
/// fields are omitted — nothing fabricated.
pub fn gemini_response_to_openai_chat(resp: &Value) -> Value {
    let candidate = resp
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|c| c.first());

    let parts = candidate
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(Value::as_array);

    let content_text: String = parts
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    let tool_calls = gemini_tool_calls(parts);

    let finish_reason = candidate
        .and_then(|c| str_field(c, "finishReason"))
        .map(|fr| gemini_finish_reason_to_openai(&fr));
    // OpenAI signals a tool-call turn via `finish_reason: "tool_calls"`, but
    // Gemini reports `STOP` even when it emitted a functionCall — override so a
    // client keying its tool loop off finish_reason sees the tool-call turn.
    let finish_reason = if tool_calls.is_empty() {
        finish_reason
    } else {
        Some("tool_calls")
    };

    let mut message = serde_json::Map::new();
    message.insert("role".into(), Value::from("assistant"));
    if content_text.is_empty() && !tool_calls.is_empty() {
        message.insert("content".into(), Value::Null);
    } else {
        message.insert("content".into(), Value::from(content_text));
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".into(), Value::Array(tool_calls));
    }

    let mut obj = serde_json::Map::new();
    if let Some(id) = resp.get("responseId") {
        obj.insert("id".into(), id.clone());
    }
    obj.insert("object".into(), Value::from("chat.completion"));
    if let Some(model) = resp.get("modelVersion") {
        obj.insert("model".into(), model.clone());
    }
    obj.insert(
        "choices".into(),
        serde_json::json!([{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }]),
    );
    if let Some(um) = resp.get("usageMetadata") {
        let prompt = u64_field(um, "promptTokenCount");
        let completion = u64_field(um, "candidatesTokenCount");
        if prompt.is_some() || completion.is_some() {
            let total = u64_field(um, "totalTokenCount").or(match (prompt, completion) {
                (Some(p), Some(c)) => Some(p + c),
                _ => None,
            });
            obj.insert(
                "usage".into(),
                serde_json::json!({
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                    "total_tokens": total,
                }),
            );
        }
    }
    Value::Object(obj)
}

/// Collect Gemini `functionCall` parts into OpenAI `tool_calls`. Gemini emits no
/// call id, so a synthetic `call_N` (over the function-call parts) is minted for
/// client-side correlation; `args` (an object) is serialized to OpenAI's
/// arguments string.
fn gemini_tool_calls(parts: Option<&Vec<Value>>) -> Vec<Value> {
    parts
        .map(|ps| {
            ps.iter()
                .filter_map(|p| p.get("functionCall"))
                .enumerate()
                .map(|(i, fc)| {
                    let name = fc.get("name").and_then(Value::as_str).unwrap_or_default();
                    let arguments = fc
                        .get("args")
                        .map(|a| serde_json::to_string(a).unwrap_or_default())
                        .unwrap_or_else(|| "{}".to_string());
                    json!({
                        "id": format!("call_{i}"),
                        "type": "function",
                        "function": { "name": name, "arguments": arguments },
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Map a Gemini `finishReason` to the canonical [`FinishReason`]. `STOP` →
/// natural stop; `MAX_TOKENS` → length; `SAFETY` / `RECITATION` / `BLOCKLIST` /
/// `PROHIBITED_CONTENT` → content filter (also flagged on `base.refusal`); other
/// reasons fall to `Other`.
pub(crate) fn normalize_gemini_finish_reason(s: &str) -> FinishReason {
    match s {
        "STOP" => FinishReason::Stop,
        "MAX_TOKENS" => FinishReason::Length,
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => {
            FinishReason::ContentFilter
        }
        _ => FinishReason::Other,
    }
}

/// Map a Gemini `finishReason` to the OpenAI `finish_reason` string for the
/// translated response body.
pub(crate) fn gemini_finish_reason_to_openai(s: &str) -> &'static str {
    match s {
        "STOP" => "stop",
        "MAX_TOKENS" => "length",
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => "content_filter",
        _ => "stop",
    }
}

/// Fold an **OpenAI Responses API** (`/responses`) response into the
/// `InferenceRecord`. Usage lives under `usage` (`input_tokens` / `output_tokens`
/// plus `input_tokens_details.cached_tokens` /
/// `output_tokens_details.reasoning_tokens`); `id` / `model` correlate; the finish
/// reason derives from `status` + `incomplete_details.reason`. There is no
/// `system_fingerprint`. Missing fields stay `None` — never fabricated.
pub fn extract_openai_responses(mut base: InferenceRecord, response: &Value) -> InferenceRecord {
    base.upstream_protocol = UpstreamProtocol::OpenAiResponses;
    base.model_served = str_field(response, "model");
    base.upstream_request_id = str_field(response, "id");

    if let Some(usage) = response.get("usage") {
        base.usage = responses_token_usage_from(usage);
        base.provider_prompt_cache = base.usage.cached_read.map(|c| c > 0);
    }

    if let Some(finish) = responses_finish(response) {
        if finish == FinishReason::ContentFilter {
            base.refusal = true;
        }
        base.finish_reason = Some(finish);
    }
    // Responses reports `status: completed` even on a function-call turn; the
    // client body is mapped to `tool_calls`, so the durable record must agree —
    // record `ToolUse` when the output carries a function_call (a content filter
    // still wins, so it isn't overridden).
    let output = response.get("output").and_then(Value::as_array);
    if base.finish_reason != Some(FinishReason::ContentFilter)
        && !responses_tool_calls(output).is_empty()
    {
        base.finish_reason = Some(FinishReason::ToolUse);
    }
    base
}

/// Parse an OpenAI Responses `usage` object into canonical [`TokenUsage`]. Shared
/// by the unary extractor and the streaming translator so both agree on one
/// token-accounting contract. Cache reads are under `input_tokens_details`;
/// reasoning tokens under `output_tokens_details`; Responses reports no separate
/// cache-write count.
pub(crate) fn responses_token_usage_from(usage: &Value) -> TokenUsage {
    TokenUsage {
        input: u64_field(usage, "input_tokens"),
        output: u64_field(usage, "output_tokens"),
        cached_read: usage
            .get("input_tokens_details")
            .and_then(|d| u64_field(d, "cached_tokens")),
        cache_write: None,
        reasoning: usage
            .get("output_tokens_details")
            .and_then(|d| u64_field(d, "reasoning_tokens")),
    }
}

/// Derive the canonical [`FinishReason`] from a Responses object's `status`
/// (+ `incomplete_details.reason`). `completed` → `Stop`; `incomplete` with
/// `max_output_tokens` → `Length`, with `content_filter` → `ContentFilter`;
/// any other `incomplete` reason → `Other`. An absent / `in_progress` /
/// `failed` status yields `None` (no terminal finish reason recorded). Shared
/// with the streaming translator.
pub(crate) fn responses_finish(resp: &Value) -> Option<FinishReason> {
    match str_field(resp, "status").as_deref() {
        Some("completed") => Some(FinishReason::Stop),
        Some("incomplete") => Some(
            match resp
                .get("incomplete_details")
                .and_then(|d| str_field(d, "reason"))
                .as_deref()
            {
                Some("max_output_tokens") => FinishReason::Length,
                Some("content_filter") => FinishReason::ContentFilter,
                _ => FinishReason::Other,
            },
        ),
        _ => None,
    }
}

/// Map a canonical [`FinishReason`] to the OpenAI Chat Completions
/// `finish_reason` string used in a translated response body / stream chunk.
pub(crate) fn finish_reason_openai_str(f: FinishReason) -> &'static str {
    match f {
        // `Error` has no OpenAI chat finish_reason; it never originates from
        // `responses_finish` (which yields only Stop/Length/ContentFilter/Other),
        // so it falls in with the `stop` default for exhaustiveness.
        FinishReason::Stop | FinishReason::Other | FinishReason::Error => "stop",
        FinishReason::Length => "length",
        FinishReason::ToolUse => "tool_calls",
        FinishReason::ContentFilter => "content_filter",
    }
}

/// Collect Responses `output[]` `function_call` items into OpenAI `tool_calls`.
/// Responses already carries `call_id` and a string `arguments`, so each maps
/// directly.
fn responses_tool_calls(output: Option<&Vec<Value>>) -> Vec<Value> {
    output
        .map(|items| {
            items
                .iter()
                .filter(|it| it.get("type").and_then(Value::as_str) == Some("function_call"))
                .map(|it| {
                    let id = it
                        .get("call_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let name = it.get("name").and_then(Value::as_str).unwrap_or_default();
                    let arguments = it.get("arguments").and_then(Value::as_str).unwrap_or("");
                    json!({
                        "id": id,
                        "type": "function",
                        "function": { "name": name, "arguments": arguments },
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Translate an **OpenAI Responses API response body** into the OpenAI Chat
/// Completions response shape (the gateway's `/v1/chat/completions` contract).
/// The `output[]` message items' `output_text` parts are concatenated into the
/// assistant message; any `function_call` items become `tool_calls`; `status` →
/// `finish_reason`; `usage` token classes → OpenAI usage names. Missing fields
/// are omitted — nothing fabricated.
pub fn openai_responses_to_openai_chat(resp: &Value) -> Value {
    let output = resp.get("output").and_then(Value::as_array);
    let content_text: String = output
        .map(|items| {
            items
                .iter()
                .filter(|it| it.get("type").and_then(Value::as_str) == Some("message"))
                .filter_map(|it| it.get("content").and_then(Value::as_array))
                .flatten()
                .filter(|p| p.get("type").and_then(Value::as_str) == Some("output_text"))
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    let tool_calls = responses_tool_calls(output);

    let finish_reason = responses_finish(resp).map(finish_reason_openai_str);
    // Responses reports `status: completed` even when it emitted a function_call;
    // override to OpenAI's `tool_calls` finish so a client's tool loop fires.
    let finish_reason = if tool_calls.is_empty() {
        finish_reason
    } else {
        Some("tool_calls")
    };

    let mut message = serde_json::Map::new();
    message.insert("role".into(), Value::from("assistant"));
    if content_text.is_empty() && !tool_calls.is_empty() {
        message.insert("content".into(), Value::Null);
    } else {
        message.insert("content".into(), Value::from(content_text));
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".into(), Value::Array(tool_calls));
    }

    let mut obj = serde_json::Map::new();
    if let Some(id) = resp.get("id") {
        obj.insert("id".into(), id.clone());
    }
    obj.insert("object".into(), Value::from("chat.completion"));
    if let Some(model) = resp.get("model") {
        obj.insert("model".into(), model.clone());
    }
    obj.insert(
        "choices".into(),
        serde_json::json!([{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }]),
    );
    if let Some(usage) = resp.get("usage") {
        let prompt = u64_field(usage, "input_tokens");
        let completion = u64_field(usage, "output_tokens");
        if prompt.is_some() || completion.is_some() {
            let total = u64_field(usage, "total_tokens").or(match (prompt, completion) {
                (Some(p), Some(c)) => Some(p + c),
                _ => None,
            });
            obj.insert(
                "usage".into(),
                serde_json::json!({
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                    "total_tokens": total,
                }),
            );
        }
    }
    Value::Object(obj)
}

pub(crate) fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

pub(crate) fn u64_field(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

pub(crate) fn normalize_finish_reason(s: &str) -> FinishReason {
    match s {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "tool_calls" | "function_call" => FinishReason::ToolUse,
        "content_filter" => FinishReason::ContentFilter,
        _ => FinishReason::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Surface;
    use crate::record::InferenceRecord;
    use serde_json::json;
    use waygate_llm_credentials::LlmProvider;

    fn base() -> InferenceRecord {
        InferenceRecord::new(
            LlmProvider::OpenRouter,
            "MAIN",
            "alias",
            Surface::ChatCompletions,
            UpstreamProtocol::OpenAiChat,
        )
    }

    #[test]
    fn extracts_model_usage_finish_and_ids() {
        let resp = json!({
            "id": "chatcmpl-123",
            "model": "served-model-x",
            "system_fingerprint": "fp_abc",
            "choices": [{"finish_reason": "stop", "message": {"role":"assistant","content":"hi"}}],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "prompt_tokens_details": {"cached_tokens": 4},
                "completion_tokens_details": {"reasoning_tokens": 2}
            }
        });
        let rec = extract_openai_chat(base(), &resp);
        assert_eq!(rec.model_served.as_deref(), Some("served-model-x"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("chatcmpl-123"));
        assert_eq!(rec.system_fingerprint.as_deref(), Some("fp_abc"));
        assert_eq!(rec.usage.input, Some(10));
        assert_eq!(rec.usage.output, Some(5));
        assert_eq!(rec.usage.cached_read, Some(4));
        assert_eq!(rec.usage.reasoning, Some(2));
        assert_eq!(rec.provider_prompt_cache, Some(true));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert!(!rec.refusal);
        // Identity from `base` is preserved.
        assert_eq!(rec.provider, LlmProvider::OpenRouter);
        assert_eq!(rec.model_requested, "alias");
    }

    #[test]
    fn content_filter_marks_refusal_and_unreported_usage_stays_none() {
        let resp = json!({
            "model": "m",
            "choices": [{"finish_reason": "content_filter"}]
        });
        let rec = extract_openai_chat(base(), &resp);
        assert_eq!(rec.finish_reason, Some(FinishReason::ContentFilter));
        assert!(rec.refusal);
        // No usage object ⇒ token counts remain None (not fabricated zeros).
        assert_eq!(rec.usage.input, None);
        assert_eq!(rec.usage.output, None);
    }

    #[test]
    fn tool_calls_finish_reason_normalizes_to_tool_use() {
        let resp = json!({"model": "m", "choices": [{"finish_reason": "tool_calls"}]});
        assert_eq!(
            extract_openai_chat(base(), &resp).finish_reason,
            Some(FinishReason::ToolUse)
        );
    }

    #[test]
    fn message_refusal_marks_refusal_even_when_finish_is_stop() {
        // Structured-outputs refusal: finish_reason is "stop" but the message
        // carries a refusal string. The record must flag refusal=true.
        let resp = json!({
            "model": "m",
            "choices": [{
                "finish_reason": "stop",
                "message": {"role": "assistant", "refusal": "I can't help with that."}
            }]
        });
        let rec = extract_openai_chat(base(), &resp);
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert!(rec.refusal);
    }

    #[test]
    fn empty_message_refusal_does_not_flag() {
        // A null/empty refusal field is not a refusal.
        let resp = json!({
            "model": "m",
            "choices": [{
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "hi", "refusal": null}
            }]
        });
        assert!(!extract_openai_chat(base(), &resp).refusal);
    }

    // ---- Anthropic Messages extractor -------------------------------------

    fn anthropic_base() -> InferenceRecord {
        InferenceRecord::new(
            LlmProvider::Anthropic,
            "MAIN",
            "claude-alias",
            Surface::ChatCompletions,
            UpstreamProtocol::AnthropicMessages,
        )
    }

    #[test]
    fn extracts_anthropic_model_usage_stop_and_id() {
        let resp = json!({
            "id": "msg_123",
            "model": "claude-served-x",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 12,
                "output_tokens": 7,
                "cache_read_input_tokens": 5,
                "cache_creation_input_tokens": 3
            }
        });
        let rec = extract_anthropic_messages(anthropic_base(), &resp);
        assert_eq!(rec.upstream_protocol, UpstreamProtocol::AnthropicMessages);
        assert_eq!(rec.model_served.as_deref(), Some("claude-served-x"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("msg_123"));
        // No system_fingerprint in Anthropic responses.
        assert_eq!(rec.system_fingerprint, None);
        // Each class mapped directly from its Anthropic field (no summing).
        assert_eq!(rec.usage.input, Some(12));
        assert_eq!(rec.usage.output, Some(7));
        assert_eq!(rec.usage.cached_read, Some(5));
        assert_eq!(rec.usage.cache_write, Some(3));
        assert_eq!(rec.usage.reasoning, None);
        assert_eq!(rec.provider_prompt_cache, Some(true));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert!(!rec.refusal);
    }

    #[test]
    fn anthropic_stop_reasons_map_to_canonical() {
        let case = |sr: &str| {
            extract_anthropic_messages(anthropic_base(), &json!({ "stop_reason": sr }))
                .finish_reason
        };
        assert_eq!(case("end_turn"), Some(FinishReason::Stop));
        assert_eq!(case("stop_sequence"), Some(FinishReason::Stop));
        assert_eq!(case("max_tokens"), Some(FinishReason::Length));
        assert_eq!(case("tool_use"), Some(FinishReason::ToolUse));
        assert_eq!(case("something_new"), Some(FinishReason::Other));
    }

    #[test]
    fn anthropic_refusal_stop_reason_flags_refusal() {
        let rec =
            extract_anthropic_messages(anthropic_base(), &json!({ "stop_reason": "refusal" }));
        assert_eq!(rec.finish_reason, Some(FinishReason::ContentFilter));
        assert!(rec.refusal);
    }

    #[test]
    fn anthropic_missing_usage_leaves_counts_none() {
        let rec = extract_anthropic_messages(anthropic_base(), &json!({ "model": "m" }));
        assert_eq!(rec.usage.input, None);
        assert_eq!(rec.usage.output, None);
        assert_eq!(rec.provider_prompt_cache, None);
    }

    #[test]
    fn anthropic_response_translates_to_openai_chat_shape() {
        let anthropic = json!({
            "id": "msg_7",
            "model": "claude-served-x",
            "stop_reason": "end_turn",
            "content": [
                {"type": "text", "text": "Hel"},
                {"type": "text", "text": "lo"}
            ],
            "usage": {"input_tokens": 12, "output_tokens": 4}
        });
        let out = anthropic_response_to_openai_chat(&anthropic);
        // OpenAI chat-completions envelope.
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["id"], "msg_7");
        assert_eq!(out["model"], "claude-served-x");
        // Text blocks concatenated into the assistant message.
        assert_eq!(out["choices"][0]["message"]["role"], "assistant");
        assert_eq!(out["choices"][0]["message"]["content"], "Hello");
        // stop_reason → finish_reason (OpenAI vocabulary).
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        // Anthropic token classes → OpenAI usage names, with total.
        assert_eq!(out["usage"]["prompt_tokens"], 12);
        assert_eq!(out["usage"]["completion_tokens"], 4);
        assert_eq!(out["usage"]["total_tokens"], 16);
    }

    #[test]
    fn anthropic_response_finish_reason_vocabulary() {
        let finish = |sr: &str| {
            anthropic_response_to_openai_chat(&json!({ "stop_reason": sr }))["choices"][0]
                ["finish_reason"]
                .as_str()
                .map(str::to_owned)
        };
        assert_eq!(finish("end_turn").as_deref(), Some("stop"));
        assert_eq!(finish("max_tokens").as_deref(), Some("length"));
        assert_eq!(finish("tool_use").as_deref(), Some("tool_calls"));
        assert_eq!(finish("refusal").as_deref(), Some("content_filter"));
        // No usage object ⇒ no usage key fabricated.
        assert!(
            anthropic_response_to_openai_chat(&json!({ "stop_reason": "end_turn" }))
                .get("usage")
                .is_none()
        );
    }

    // ---- Gemini extractor + response translation --------------------------

    fn gemini_base() -> InferenceRecord {
        InferenceRecord::new(
            LlmProvider::Google,
            "MAIN",
            "gemini-alias",
            Surface::ChatCompletions,
            UpstreamProtocol::Gemini,
        )
    }

    #[test]
    fn extracts_gemini_model_usage_and_finish() {
        let resp = json!({
            "responseId": "resp_1",
            "modelVersion": "gemini-served-x",
            "candidates": [{"finishReason": "STOP", "content": {"role":"model","parts":[{"text":"hi"}]}}],
            "usageMetadata": {
                "promptTokenCount": 11,
                "candidatesTokenCount": 6,
                "cachedContentTokenCount": 4,
                "thoughtsTokenCount": 3
            }
        });
        let rec = extract_gemini(gemini_base(), &resp);
        assert_eq!(rec.upstream_protocol, UpstreamProtocol::Gemini);
        assert_eq!(rec.model_served.as_deref(), Some("gemini-served-x"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("resp_1"));
        assert_eq!(rec.usage.input, Some(11));
        assert_eq!(rec.usage.output, Some(6));
        assert_eq!(rec.usage.cached_read, Some(4));
        assert_eq!(rec.usage.reasoning, Some(3));
        assert_eq!(rec.provider_prompt_cache, Some(true));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert!(!rec.refusal);
    }

    #[test]
    fn gemini_safety_finish_flags_refusal() {
        let rec = extract_gemini(
            gemini_base(),
            &json!({"candidates":[{"finishReason":"SAFETY"}]}),
        );
        assert_eq!(rec.finish_reason, Some(FinishReason::ContentFilter));
        assert!(rec.refusal);
    }

    #[test]
    fn gemini_response_translates_to_openai_chat_shape() {
        let resp = json!({
            "responseId": "resp_1",
            "modelVersion": "gemini-served-x",
            "candidates": [{
                "finishReason": "MAX_TOKENS",
                "content": {"role":"model","parts":[{"text":"He"},{"text":"llo"}]}
            }],
            "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 6, "totalTokenCount": 17}
        });
        let out = gemini_response_to_openai_chat(&resp);
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["id"], "resp_1");
        assert_eq!(out["model"], "gemini-served-x");
        assert_eq!(out["choices"][0]["message"]["content"], "Hello");
        assert_eq!(out["choices"][0]["finish_reason"], "length");
        assert_eq!(out["usage"]["prompt_tokens"], 11);
        assert_eq!(out["usage"]["completion_tokens"], 6);
        assert_eq!(out["usage"]["total_tokens"], 17);
    }

    #[test]
    fn gemini_finish_reason_vocabulary_and_missing_usage() {
        let finish = |fr: &str| {
            gemini_response_to_openai_chat(&json!({"candidates":[{"finishReason":fr}]}))["choices"]
                [0]["finish_reason"]
                .as_str()
                .map(str::to_owned)
        };
        assert_eq!(finish("STOP").as_deref(), Some("stop"));
        assert_eq!(finish("MAX_TOKENS").as_deref(), Some("length"));
        assert_eq!(finish("RECITATION").as_deref(), Some("content_filter"));
        // No usageMetadata ⇒ no usage key.
        assert!(gemini_response_to_openai_chat(&json!({"candidates":[]}))
            .get("usage")
            .is_none());
    }

    // ---- OpenAI Responses extractor + response translation -----------------

    fn responses_base() -> InferenceRecord {
        InferenceRecord::new(
            LlmProvider::OpenAi,
            "MAIN",
            "responses-alias",
            Surface::ChatCompletions,
            UpstreamProtocol::OpenAiResponses,
        )
    }

    #[test]
    fn extracts_responses_model_usage_and_finish() {
        let resp = json!({
            "id": "resp_1",
            "model": "gpt-5.4",
            "status": "completed",
            "output": [{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],
            "usage": {
                "input_tokens": 11,
                "output_tokens": 6,
                "total_tokens": 17,
                "input_tokens_details": {"cached_tokens": 4},
                "output_tokens_details": {"reasoning_tokens": 3}
            }
        });
        let rec = extract_openai_responses(responses_base(), &resp);
        assert_eq!(rec.upstream_protocol, UpstreamProtocol::OpenAiResponses);
        assert_eq!(rec.model_served.as_deref(), Some("gpt-5.4"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("resp_1"));
        assert_eq!(rec.usage.input, Some(11));
        assert_eq!(rec.usage.output, Some(6));
        assert_eq!(rec.usage.cached_read, Some(4));
        assert_eq!(rec.usage.reasoning, Some(3));
        assert_eq!(rec.provider_prompt_cache, Some(true));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert!(!rec.refusal);
        // No system_fingerprint in Responses.
        assert_eq!(rec.system_fingerprint, None);
    }

    #[test]
    fn responses_status_maps_to_finish_reason() {
        let case = |resp: serde_json::Value| extract_openai_responses(responses_base(), &resp);
        assert_eq!(
            case(json!({"status":"completed"})).finish_reason,
            Some(FinishReason::Stop)
        );
        let length = case(
            json!({"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}),
        );
        assert_eq!(length.finish_reason, Some(FinishReason::Length));
        let filtered =
            case(json!({"status":"incomplete","incomplete_details":{"reason":"content_filter"}}));
        assert_eq!(filtered.finish_reason, Some(FinishReason::ContentFilter));
        assert!(filtered.refusal);
        // in_progress / absent status ⇒ no terminal finish reason.
        assert_eq!(case(json!({"status":"in_progress"})).finish_reason, None);
        assert_eq!(case(json!({})).finish_reason, None);
    }

    #[test]
    fn responses_response_translates_to_openai_chat_shape() {
        let resp = json!({
            "id": "resp_7",
            "model": "gpt-5.4",
            "status": "completed",
            "output": [
                {"type":"reasoning","summary":[]},
                {"type":"message","role":"assistant","content":[
                    {"type":"output_text","text":"Hel"},
                    {"type":"output_text","text":"lo"}
                ]}
            ],
            "usage": {"input_tokens": 11, "output_tokens": 4}
        });
        let out = openai_responses_to_openai_chat(&resp);
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["id"], "resp_7");
        assert_eq!(out["model"], "gpt-5.4");
        // output_text parts of message items concatenated; non-message items
        // (reasoning) ignored.
        assert_eq!(out["choices"][0]["message"]["content"], "Hello");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        // total_tokens synthesized from input+output when absent.
        assert_eq!(out["usage"]["prompt_tokens"], 11);
        assert_eq!(out["usage"]["completion_tokens"], 4);
        assert_eq!(out["usage"]["total_tokens"], 15);
    }

    #[test]
    fn responses_translate_finish_vocabulary_and_missing_usage() {
        let finish = |resp: serde_json::Value| {
            openai_responses_to_openai_chat(&resp)["choices"][0]["finish_reason"]
                .as_str()
                .map(str::to_owned)
        };
        assert_eq!(
            finish(json!({"status":"completed"})).as_deref(),
            Some("stop")
        );
        assert_eq!(
            finish(
                json!({"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}})
            )
            .as_deref(),
            Some("length")
        );
        // No usage ⇒ no usage key fabricated; no status ⇒ null finish_reason.
        let bare = openai_responses_to_openai_chat(&json!({"output": []}));
        assert!(bare.get("usage").is_none());
        assert!(bare["choices"][0]["finish_reason"].is_null());
    }

    // ---- unary tool-call extraction ---------------------------------------

    #[test]
    fn anthropic_response_tool_use_becomes_tool_calls() {
        let resp = json!({
            "id": "msg_1", "model": "claude-x", "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "let me check"},
                {"type": "tool_use", "id": "tu_1", "name": "get_weather",
                    "input": {"city": "SF"}}
            ]
        });
        let out = anthropic_response_to_openai_chat(&resp);
        let msg = &out["choices"][0]["message"];
        assert_eq!(msg["content"], "let me check");
        assert_eq!(msg["tool_calls"][0]["id"], "tu_1");
        assert_eq!(msg["tool_calls"][0]["function"]["name"], "get_weather");
        // Anthropic's object input is serialized to OpenAI's arguments string.
        let args = msg["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(args).unwrap(),
            json!({"city": "SF"})
        );
        // tool_use stop → tool_calls finish.
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");

        // A tool-use-only response has null content.
        let only = anthropic_response_to_openai_chat(&json!({
            "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "t", "name": "f", "input": {}}]
        }));
        assert!(only["choices"][0]["message"]["content"].is_null());
    }

    #[test]
    fn anthropic_structured_output_emulation_is_unwrapped_to_content() {
        // A tool_use named with the structured-output sentinel is rendered as
        // the assistant content (its input serialized), with a normal stop —
        // NOT as a tool_call.
        let resp = json!({
            "id": "msg_1", "model": "claude-x", "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "tu_1",
                "name": STRUCTURED_OUTPUT_TOOL_NAME, "input": {"answer": 42}}]
        });
        let out = anthropic_response_to_openai_chat(&resp);
        let msg = &out["choices"][0]["message"];
        assert!(
            msg.get("tool_calls").is_none(),
            "emulation must not surface a tool_call"
        );
        assert_eq!(
            serde_json::from_str::<Value>(msg["content"].as_str().unwrap()).unwrap(),
            json!({"answer": 42})
        );
        // Reads as a normal completion, not a tool call.
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn anthropic_emulation_record_finish_matches_client_stop() {
        use crate::canonical::Surface;
        use waygate_llm_credentials::LlmProvider;
        // The InferenceRecord (usage/audit metadata) must record the emulation as
        // a normal Stop — matching the client-visible finish — not ToolUse, even
        // though Anthropic stopped with `tool_use`.
        let base = InferenceRecord::new(
            LlmProvider::Anthropic,
            "MAIN",
            "claude-alias",
            Surface::ChatCompletions,
            UpstreamProtocol::AnthropicMessages,
        );
        let resp = json!({
            "id": "msg_1", "model": "claude-x", "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "tu_1",
                "name": STRUCTURED_OUTPUT_TOOL_NAME, "input": {"answer": 42}}]
        });
        assert_eq!(
            extract_anthropic_messages(base, &resp).finish_reason,
            Some(FinishReason::Stop)
        );

        // A *real* tool call (non-sentinel) still records ToolUse.
        let base2 = InferenceRecord::new(
            LlmProvider::Anthropic,
            "MAIN",
            "claude-alias",
            Surface::ChatCompletions,
            UpstreamProtocol::AnthropicMessages,
        );
        let real = json!({
            "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "t", "name": "get_weather", "input": {}}]
        });
        assert_eq!(
            extract_anthropic_messages(base2, &real).finish_reason,
            Some(FinishReason::ToolUse)
        );
    }

    #[test]
    fn gemini_response_function_call_becomes_tool_calls() {
        let resp = json!({
            "responseId": "r1", "modelVersion": "gemini-x",
            "candidates": [{"finishReason": "STOP", "content": {"role": "model", "parts": [
                {"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}
            ]}}]
        });
        let out = gemini_response_to_openai_chat(&resp);
        let msg = &out["choices"][0]["message"];
        assert!(msg["content"].is_null());
        assert_eq!(msg["tool_calls"][0]["function"]["name"], "get_weather");
        // A synthetic id is minted (Gemini provides none).
        assert_eq!(msg["tool_calls"][0]["id"], "call_0");
        assert_eq!(
            serde_json::from_str::<Value>(
                msg["tool_calls"][0]["function"]["arguments"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            json!({"city": "SF"})
        );
        // Gemini reports STOP, but a tool-call turn must surface as "tool_calls".
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn responses_response_function_call_becomes_tool_calls() {
        let resp = json!({
            "id": "resp_1", "model": "gpt-x", "status": "completed",
            "output": [
                {"type": "function_call", "call_id": "c1", "name": "get_weather",
                    "arguments": "{\"city\":\"SF\"}"}
            ]
        });
        let out = openai_responses_to_openai_chat(&resp);
        let msg = &out["choices"][0]["message"];
        assert!(msg["content"].is_null());
        assert_eq!(msg["tool_calls"][0]["id"], "c1");
        assert_eq!(msg["tool_calls"][0]["function"]["name"], "get_weather");
        assert_eq!(
            msg["tool_calls"][0]["function"]["arguments"],
            "{\"city\":\"SF\"}"
        );
        // Responses reports `completed`, but a tool-call turn → "tool_calls".
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn gemini_record_finish_matches_client_tool_calls() {
        // The durable record must agree with the client body: a Gemini
        // functionCall turn (which reports STOP) records ToolUse, not Stop.
        let resp = json!({
            "responseId": "r1", "modelVersion": "gemini-x",
            "candidates": [{"finishReason": "STOP", "content": {"role": "model", "parts": [
                {"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}
            ]}}]
        });
        assert_eq!(
            extract_gemini(gemini_base(), &resp).finish_reason,
            Some(FinishReason::ToolUse)
        );
        // A plain STOP (no functionCall) still records Stop.
        let plain = json!({"candidates": [{"finishReason": "STOP",
            "content": {"role": "model", "parts": [{"text": "hi"}]}}]});
        assert_eq!(
            extract_gemini(gemini_base(), &plain).finish_reason,
            Some(FinishReason::Stop)
        );
    }

    #[test]
    fn responses_record_finish_matches_client_tool_calls() {
        // A Responses function_call turn (status completed) records ToolUse.
        let resp = json!({
            "id": "resp_1", "model": "gpt-x", "status": "completed",
            "output": [{"type": "function_call", "call_id": "c1",
                "name": "get_weather", "arguments": "{}"}]
        });
        assert_eq!(
            extract_openai_responses(responses_base(), &resp).finish_reason,
            Some(FinishReason::ToolUse)
        );
        // A completed turn with only a message records Stop.
        let plain = json!({"status": "completed", "output": [
            {"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "hi"}]}
        ]});
        assert_eq!(
            extract_openai_responses(responses_base(), &plain).finish_reason,
            Some(FinishReason::Stop)
        );
    }
}
