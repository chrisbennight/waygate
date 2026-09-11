//! Outbound translation: canonical [`LlmRequest`] → a provider-native request
//! body. Renders the **OpenAI Chat Completions** shape (OpenAI's chat endpoint
//! and OpenAI-compatible providers like OpenRouter) plus the
//! **Anthropic Messages**, **Gemini** (`generateContent`), and **OpenAI
//! Responses** (`/responses`) shapes.

use serde_json::{json, Map, Value};

use std::collections::HashMap;

use crate::canonical::{
    CanonicalMessage, CanonicalTool, ContentPart, LlmRequest, ResponseFormat, Role, ToolChoice,
};
use crate::inbound::TranslateError;

/// Partition a message's content parts into the text/image parts, the
/// assistant tool-call parts, and the tool-result parts — the split every
/// provider renderer needs (each places them differently). Returns references
/// into `content`.
fn partition_parts(
    content: &[ContentPart],
) -> (Vec<&ContentPart>, Vec<&ContentPart>, Vec<&ContentPart>) {
    let mut textish = Vec::new();
    let mut tool_uses = Vec::new();
    let mut tool_results = Vec::new();
    for p in content {
        match p {
            ContentPart::ToolUse { .. } => tool_uses.push(p),
            ContentPart::ToolResult { .. } => tool_results.push(p),
            // Reasoning parts are opaque Responses-input echoes with no Chat/
            // Anthropic/Gemini equivalent; they are emitted only by the
            // OpenAI-Responses renderer (which collects them directly from the
            // message), so they are dropped here rather than mis-bucketed as text.
            ContentPart::Reasoning { .. } => {}
            _ => textish.push(p),
        }
    }
    (textish, tool_uses, tool_results)
}

/// Parse a [`ContentPart::ToolUse`]'s `arguments` JSON string into an object for
/// providers (Anthropic, Gemini) whose tool-call input is a structured object
/// rather than OpenAI's string. This is a replay of arguments a model already
/// produced, so on the rare parse failure (or an empty string) we fall back to
/// an empty object rather than failing the whole request.
fn tool_arguments_object(arguments: &str) -> Value {
    if arguments.trim().is_empty() {
        return json!({});
    }
    match serde_json::from_str::<Value>(arguments) {
        Ok(v @ Value::Object(_)) => v,
        _ => json!({}),
    }
}

/// Sentinel function name for the Anthropic structured-output emulation: when a
/// `response_format` request is rendered to Anthropic (which has no native
/// structured output), it is turned into a single forced tool call with this
/// name, and the response translator unwraps a `tool_use` with this name back
/// into message content. Chosen to be collision-unlikely with a real tool name.
pub(crate) const STRUCTURED_OUTPUT_TOOL_NAME: &str = "__gateway_structured_output__";

/// Map every `tool_call_id` issued by an assistant turn to the tool's function
/// name, by scanning all [`ContentPart::ToolUse`] parts. Gemini keys tool
/// results by function name (not call id), so its tool-result renderer needs
/// this to resolve a [`ContentPart::ToolResult`]'s `tool_call_id` back to a name.
fn tool_call_names(messages: &[CanonicalMessage]) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    for m in messages {
        for p in &m.content {
            if let ContentPart::ToolUse { id, name, .. } = p {
                map.insert(id.as_str(), name.as_str());
            }
        }
    }
    map
}

/// Render a canonical request as an OpenAI Chat Completions request body.
/// `model` is the resolved upstream model name (which may differ from the
/// client's requested alias). For a streaming request, `stream_options.
/// include_usage=true` is added so the terminal chunk carries token usage —
/// required so the `InferenceRecord` (and budgets) always have it.
///
/// Tools / `tool_choice` / `parallel_tool_calls` and `response_format` are
/// OpenAI's native shapes and emitted 1:1; assistant tool calls render as
/// `message.tool_calls` and a `Role::Tool` message as `{role:tool,
/// tool_call_id, content}`.
///
/// Fallible: a canonical construct this renderer cannot faithfully emit returns
/// `TranslateError::Unsupported` rather than a lossy body — keeping the renderer
/// a fail-closed translation boundary (I6) even for directly-constructed
/// `LlmRequest`s that bypass the inbound parser's guards.
pub fn render_openai_chat(req: &LlmRequest, model: &str) -> Result<Value, TranslateError> {
    let messages = req
        .messages
        .iter()
        .map(render_message)
        .collect::<Result<Vec<_>, _>>()?;
    let mut obj = Map::new();
    obj.insert("model".into(), json!(model));
    obj.insert("messages".into(), Value::Array(messages));
    if let Some(t) = req.sampling.temperature {
        obj.insert("temperature".into(), json!(t));
    }
    if let Some(p) = req.sampling.top_p {
        obj.insert("top_p".into(), json!(p));
    }
    if let Some(m) = req.sampling.max_tokens {
        obj.insert("max_tokens".into(), json!(m));
    }
    if !req.sampling.stop.is_empty() {
        obj.insert("stop".into(), json!(req.sampling.stop));
    }
    if let Some(s) = req.sampling.seed {
        obj.insert("seed".into(), json!(s));
    }
    // Chat Completions carries reasoning depth as a top-level `reasoning_effort`.
    if let Some(effort) = &req.sampling.reasoning_effort {
        obj.insert("reasoning_effort".into(), json!(effort));
    }
    // Structured output is OpenAI's native `response_format` shape — emit 1:1.
    if let Some(rf) = &req.response_format {
        obj.insert("response_format".into(), openai_chat_response_format(rf));
    }
    // Tools / tool_choice are OpenAI's native shape — emit 1:1.
    if !req.tools.is_empty() {
        obj.insert("tools".into(), openai_chat_tools(&req.tools));
    }
    if let Some(tc) = &req.tool_choice {
        obj.insert("tool_choice".into(), openai_tool_choice(tc));
    }
    if let Some(p) = req.parallel_tool_calls {
        obj.insert("parallel_tool_calls".into(), json!(p));
    }
    if req.stream {
        obj.insert("stream".into(), json!(true));
        obj.insert("stream_options".into(), json!({ "include_usage": true }));
    }
    Ok(Value::Object(obj))
}

/// Render canonical tools as the OpenAI Chat Completions `tools` array —
/// `[{type:function, function:{name, description?, parameters}}]`, OpenAI's
/// native shape.
fn openai_chat_tools(tools: &[CanonicalTool]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|t| {
                let mut f = Map::new();
                f.insert("name".into(), json!(t.name));
                if let Some(d) = &t.description {
                    f.insert("description".into(), json!(d));
                }
                f.insert("parameters".into(), t.parameters.clone());
                if let Some(s) = t.strict {
                    f.insert("strict".into(), json!(s));
                }
                json!({ "type": "function", "function": Value::Object(f) })
            })
            .collect(),
    )
}

/// Render a [`ToolChoice`] in the OpenAI Chat Completions / Responses shape:
/// `auto` / `none` / `required` as a bare string, or a specific function as
/// `{type:function, function:{name}}`.
fn openai_tool_choice(tc: &ToolChoice) -> Value {
    match tc {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Function(name) => {
            json!({ "type": "function", "function": { "name": name } })
        }
    }
}

/// Render the canonical [`ResponseFormat`] as an OpenAI Chat Completions
/// `response_format` value — OpenAI's native shape, so this is the 1:1 form the
/// other surfaces translate away from. `description` / `strict` are emitted only
/// when the caller set them (no null pollution).
fn openai_chat_response_format(rf: &ResponseFormat) -> Value {
    match rf {
        ResponseFormat::JsonObject => json!({ "type": "json_object" }),
        ResponseFormat::JsonSchema {
            name,
            description,
            strict,
            schema,
        } => {
            let mut js = Map::new();
            js.insert("name".into(), json!(name));
            if let Some(d) = description {
                js.insert("description".into(), json!(d));
            }
            if let Some(s) = strict {
                js.insert("strict".into(), json!(s));
            }
            js.insert("schema".into(), schema.clone());
            json!({ "type": "json_schema", "json_schema": Value::Object(js) })
        }
    }
}

fn render_message(m: &CanonicalMessage) -> Result<Value, TranslateError> {
    // A tool-result message renders to OpenAI's `{role:tool, tool_call_id,
    // content}` shape. The inbound parser produces exactly one `ToolResult` part
    // per tool message; a directly-constructed message with a different shape
    // fails closed (I6).
    if matches!(m.role, Role::Tool) {
        let [ContentPart::ToolResult {
            tool_call_id,
            content,
        }] = m.content.as_slice()
        else {
            return Err(TranslateError::Unsupported {
                surface: "openai_chat",
                param: "tool message must carry exactly one tool_result".into(),
            });
        };
        return Ok(json!({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": content,
        }));
    }
    let role = match m.role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => unreachable!("handled above"),
    };
    let (textish, tool_uses, tool_results) = partition_parts(&m.content);
    // A tool-result outside a tool message has no faithful OpenAI shape.
    if !tool_results.is_empty() {
        return Err(TranslateError::Unsupported {
            surface: "openai_chat",
            param: "tool_result on a non-tool message".into(),
        });
    }
    // No textish content → JSON `null`, OpenAI's canonical no-content form (and
    // what an assistant message that carries only tool calls needs). A lone text
    // part collapses to a plain string; anything else is the typed multi-part
    // array.
    let content = match textish.as_slice() {
        [] => Value::Null,
        [ContentPart::Text { text }] => json!(text),
        parts => render_parts(parts),
    };
    let mut obj = Map::new();
    obj.insert("role".into(), json!(role));
    obj.insert("content".into(), content);
    if !tool_uses.is_empty() {
        obj.insert("tool_calls".into(), openai_tool_calls(&tool_uses));
    }
    Ok(Value::Object(obj))
}

/// Render assistant tool-call parts as OpenAI `tool_calls`
/// (`[{id, type:function, function:{name, arguments}}]`). `arguments` is the
/// JSON *string* the model produced, forwarded verbatim.
fn openai_tool_calls(tool_uses: &[&ContentPart]) -> Value {
    Value::Array(
        tool_uses
            .iter()
            .filter_map(|p| match p {
                ContentPart::ToolUse {
                    id,
                    name,
                    arguments,
                } => Some(json!({
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments },
                })),
                _ => None,
            })
            .collect(),
    )
}

/// Render text/image content parts as the OpenAI multi-part array. Tool parts
/// are partitioned out before this is called, so only `Text`/`ImageUrl` reach
/// it; any tool part here is a caller bug and is skipped.
fn render_parts(parts: &[&ContentPart]) -> Value {
    Value::Array(
        parts
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text } => Some(json!({ "type": "text", "text": text })),
                ContentPart::ImageUrl { url } => {
                    Some(json!({ "type": "image_url", "image_url": { "url": url } }))
                }
                _ => None,
            })
            .collect(),
    )
}

/// Anthropic's Messages API requires `max_tokens`; the canonical request makes
/// it optional (OpenAI-chat does not require it). When a caller omits it we fall
/// back to this conservative cap so the request stays valid across Claude models
/// (the Claude 3 family caps output at 4096 tokens). Callers wanting longer
/// outputs set `max_tokens` explicitly; this is only the required-field fallback.
pub const DEFAULT_ANTHROPIC_MAX_TOKENS: u64 = 4096;

/// Render a canonical request as an **Anthropic Messages API** request body.
/// Differences from OpenAI-chat, all handled here:
/// - `system` is hoisted to a top-level field (Anthropic has no system-role
///   message); multiple system messages join with blank lines, order preserved.
/// - `max_tokens` is required — defaulted to [`DEFAULT_ANTHROPIC_MAX_TOKENS`]
///   when the canonical request omits it.
/// - `stop` → `stop_sequences`; image parts use Anthropic's
///   `{type:image, source:{type:url,...}}` block.
/// - `seed` has no Anthropic equivalent and is dropped (advisory only — not a
///   faithfulness-critical field).
/// - tools render with `input_schema` (vs OpenAI's `function.parameters`);
///   assistant tool calls become `tool_use` blocks and `Role::Tool` results are
///   merged into a following user turn as `tool_result` blocks.
/// - `response_format` has no native Anthropic equivalent, so it is EMULATED:
///   a single synthetic tool (the `__gateway_structured_output__` sentinel) is
///   forced, and the response translator unwinds that tool call back into
///   content. Combining `response_format` with the caller's own tools is
///   rejected.
///
/// Fallible: a construct this renderer cannot faithfully emit (e.g. `reasoning_
/// effort`, an image in a system message) returns `TranslateError::Unsupported`
/// rather than a lossy body — a fail-closed translation boundary (I6).
pub fn render_anthropic_messages(req: &LlmRequest, model: &str) -> Result<Value, TranslateError> {
    // Anthropic expresses reasoning as a thinking-token *budget*, not an effort
    // level; the effort→budget mapping is a follow-up. Until then, fail closed
    // rather than silently drop the caller's reasoning control (I6).
    if req.sampling.reasoning_effort.is_some() {
        return Err(TranslateError::Unsupported {
            surface: "anthropic_messages",
            param: "reasoning_effort".into(),
        });
    }
    // Anthropic has no native structured-output control, so `response_format` is
    // EMULATED by forcing a single synthetic tool whose `input_schema` is the
    // requested schema; the response translator unwraps that tool call back into
    // message content (keyed on the sentinel tool name). Combining it with the
    // caller's own tools is ambiguous (which tool gets forced?), so reject that
    // combination rather than guess (I6).
    let (eff_tools, eff_tool_choice) = if let Some(rf) = &req.response_format {
        if !req.tools.is_empty() || req.tool_choice.is_some() {
            return Err(TranslateError::Unsupported {
                surface: "anthropic_messages",
                param: "response_format combined with tools".into(),
            });
        }
        let schema = match rf {
            ResponseFormat::JsonSchema { schema, .. } => schema.clone(),
            ResponseFormat::JsonObject => json!({ "type": "object" }),
        };
        let tool = CanonicalTool {
            name: STRUCTURED_OUTPUT_TOOL_NAME.to_string(),
            description: Some(
                "Return the response by calling this function with the structured output.".into(),
            ),
            parameters: schema,
            strict: None,
        };
        (
            vec![tool],
            Some(ToolChoice::Function(
                STRUCTURED_OUTPUT_TOOL_NAME.to_string(),
            )),
        )
    } else {
        (req.tools.clone(), req.tool_choice.clone())
    };

    let mut system_chunks: Vec<String> = Vec::new();
    let mut messages: Vec<Value> = Vec::new();
    // Anthropic carries tool results as `tool_result` blocks inside a USER turn,
    // and parallel results share one turn. Buffer consecutive canonical tool
    // messages and flush them as a single user message before the next non-tool
    // message (and at the end).
    let mut pending_tool_results: Vec<Value> = Vec::new();
    for m in &req.messages {
        if !matches!(m.role, Role::Tool) {
            flush_anthropic_tool_results(&mut messages, &mut pending_tool_results);
        }
        match m.role {
            Role::System => system_chunks.push(anthropic_system_text(&m.content)?),
            Role::User | Role::Assistant => {
                let role = if matches!(m.role, Role::User) {
                    "user"
                } else {
                    "assistant"
                };
                messages.push(json!({
                    "role": role,
                    "content": anthropic_content(&m.content),
                }));
            }
            Role::Tool => {
                for p in &m.content {
                    if let ContentPart::ToolResult {
                        tool_call_id,
                        content,
                    } = p
                    {
                        pending_tool_results.push(json!({
                            "type": "tool_result",
                            "tool_use_id": tool_call_id,
                            "content": content,
                        }));
                    }
                }
            }
        }
    }
    flush_anthropic_tool_results(&mut messages, &mut pending_tool_results);

    let mut obj = Map::new();
    obj.insert("model".into(), json!(model));
    // Required by Anthropic; default only when the caller omitted it.
    obj.insert(
        "max_tokens".into(),
        json!(req
            .sampling
            .max_tokens
            .unwrap_or(DEFAULT_ANTHROPIC_MAX_TOKENS)),
    );
    obj.insert("messages".into(), Value::Array(messages));
    if !system_chunks.is_empty() {
        obj.insert("system".into(), json!(system_chunks.join("\n\n")));
    }
    if let Some(t) = req.sampling.temperature {
        obj.insert("temperature".into(), json!(t));
    }
    if let Some(p) = req.sampling.top_p {
        obj.insert("top_p".into(), json!(p));
    }
    if !req.sampling.stop.is_empty() {
        obj.insert("stop_sequences".into(), json!(req.sampling.stop));
    }
    if !eff_tools.is_empty() {
        obj.insert("tools".into(), anthropic_tools(&eff_tools));
        if let Some(tc) = anthropic_tool_choice(eff_tool_choice.as_ref(), req.parallel_tool_calls) {
            obj.insert("tool_choice".into(), tc);
        }
    }
    if req.stream {
        obj.insert("stream".into(), json!(true));
    }
    Ok(Value::Object(obj))
}

/// Flush buffered `tool_result` blocks as a single Anthropic user message.
fn flush_anthropic_tool_results(messages: &mut Vec<Value>, pending: &mut Vec<Value>) {
    if !pending.is_empty() {
        messages.push(json!({
            "role": "user",
            "content": Value::Array(std::mem::take(pending)),
        }));
    }
}

/// Render canonical tools as the Anthropic `tools` array. Anthropic names the
/// JSON-schema field `input_schema` (vs OpenAI's `function.parameters`).
fn anthropic_tools(tools: &[CanonicalTool]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|t| {
                let mut o = Map::new();
                o.insert("name".into(), json!(t.name));
                if let Some(d) = &t.description {
                    o.insert("description".into(), json!(d));
                }
                o.insert("input_schema".into(), t.parameters.clone());
                Value::Object(o)
            })
            .collect(),
    )
}

/// Render a [`ToolChoice`] (and the parallel-tool-calls flag) in the Anthropic
/// shape: `{type:auto|any|none}` or `{type:tool, name}`, with
/// `disable_parallel_tool_use` set when the caller disabled parallel calls.
/// Returns `None` when there is nothing to emit (no choice and parallel left at
/// the provider default).
fn anthropic_tool_choice(tc: Option<&ToolChoice>, parallel: Option<bool>) -> Option<Value> {
    let mut obj = match tc {
        Some(ToolChoice::Auto) => json!({ "type": "auto" }),
        Some(ToolChoice::None) => json!({ "type": "none" }),
        Some(ToolChoice::Required) => json!({ "type": "any" }),
        Some(ToolChoice::Function(name)) => json!({ "type": "tool", "name": name }),
        // No explicit choice: only emit an object if we must carry the
        // parallel-disable flag (which rides on tool_choice for Anthropic).
        None if parallel == Some(false) => json!({ "type": "auto" }),
        None => return None,
    };
    if parallel == Some(false) {
        obj.as_object_mut()
            .unwrap()
            .insert("disable_parallel_tool_use".into(), json!(true));
    }
    Some(obj)
}

/// Flatten a content-part list to plain text for Anthropic's top-level `system`
/// field (which is text, not the message block array). A non-text part in a
/// system message has no faithful representation in Anthropic's text-only
/// `system`, so it fails closed (I6) rather than being silently dropped.
fn anthropic_system_text(parts: &[ContentPart]) -> Result<String, TranslateError> {
    let mut text = String::new();
    for p in parts {
        match p {
            ContentPart::Text { text: t } => text.push_str(t),
            _ => {
                return Err(TranslateError::Unsupported {
                    surface: "anthropic_messages",
                    param: "non-text content in a system message".into(),
                })
            }
        }
    }
    Ok(text)
}

/// Render message content for Anthropic: a lone text part collapses to a plain
/// string (the idiomatic shape); empty content becomes an empty string (never
/// `null` — Anthropic rejects null content); mixed/typed parts become the typed
/// block array. Assistant `tool_use` parts render to `tool_use` blocks; tool
/// results are handled separately (merged into a following user turn).
fn anthropic_content(parts: &[ContentPart]) -> Value {
    match parts {
        [] => json!(""),
        [ContentPart::Text { text }] => json!(text),
        parts => Value::Array(
            parts
                .iter()
                .filter_map(|p| match p {
                    ContentPart::Text { text } => Some(json!({ "type": "text", "text": text })),
                    ContentPart::ImageUrl { url } => Some(json!({
                        "type": "image",
                        "source": { "type": "url", "url": url },
                    })),
                    ContentPart::ToolUse {
                        id,
                        name,
                        arguments,
                    } => Some(json!({
                        "type": "tool_use",
                        "id": id,
                        "name": name,
                        "input": tool_arguments_object(arguments),
                    })),
                    // Tool results never appear on a user/assistant message;
                    // they're rendered from their own Role::Tool message.
                    ContentPart::ToolResult { .. } => None,
                    // A Responses-input reasoning echo has no Anthropic equivalent
                    // (its encrypted payload is OpenAI-specific) — dropped.
                    ContentPart::Reasoning { .. } => None,
                })
                .collect(),
        ),
    }
}

/// Render a canonical request as a **Gemini `generateContent`** request body.
/// Gemini diverges most: the model is in the URL path (not the body — dispatch
/// templates it), system messages hoist to a top-level `systemInstruction`,
/// turn roles are `user` / `model` (not `assistant`), message content is
/// `parts`, and sampling lives under `generationConfig`
/// (`maxOutputTokens` / `topP` / `stopSequences`). `seed` has no Gemini
/// equivalent and is dropped. A `Role::Tool` message, or an image in a system
/// message, fails closed (I6) — symmetric with the other renderers.
pub fn render_gemini(req: &LlmRequest) -> Result<Value, TranslateError> {
    // Gemini expresses reasoning as a `thinkingConfig` token budget, not an effort
    // level; that mapping is a follow-up. Until then, fail closed rather than
    // silently drop the caller's reasoning control (I6).
    if req.sampling.reasoning_effort.is_some() {
        return Err(TranslateError::Unsupported {
            surface: "gemini",
            param: "reasoning_effort".into(),
        });
    }
    let names = tool_call_names(&req.messages);
    let mut system_parts: Vec<Value> = Vec::new();
    let mut contents: Vec<Value> = Vec::new();
    // Gemini carries tool results as `functionResponse` parts in a user turn;
    // buffer consecutive tool messages and flush them as one user content.
    let mut pending_fn_responses: Vec<Value> = Vec::new();
    for m in &req.messages {
        if !matches!(m.role, Role::Tool) {
            flush_gemini_tool_results(&mut contents, &mut pending_fn_responses);
        }
        match m.role {
            Role::System => {
                for p in &m.content {
                    match p {
                        ContentPart::Text { text } => system_parts.push(json!({ "text": text })),
                        _ => {
                            return Err(TranslateError::Unsupported {
                                surface: "gemini",
                                param: "non-text content in a system message".into(),
                            })
                        }
                    }
                }
            }
            Role::User | Role::Assistant => {
                let role = if matches!(m.role, Role::User) {
                    "user"
                } else {
                    "model"
                };
                contents.push(json!({ "role": role, "parts": gemini_parts(&m.content) }));
            }
            Role::Tool => {
                for p in &m.content {
                    if let ContentPart::ToolResult {
                        tool_call_id,
                        content,
                    } = p
                    {
                        // Gemini keys a functionResponse by the function NAME, not
                        // the call id; resolve it from the assistant turn's
                        // tool_use. A result with no matching call can't be
                        // rendered faithfully (I6).
                        let name = names.get(tool_call_id.as_str()).ok_or_else(|| {
                            TranslateError::Unsupported {
                                surface: "gemini",
                                param: "tool_result without a matching tool_use (no function name)"
                                    .into(),
                            }
                        })?;
                        pending_fn_responses.push(json!({
                            "functionResponse": {
                                "name": name,
                                "response": { "result": content },
                            }
                        }));
                    }
                }
            }
        }
    }
    flush_gemini_tool_results(&mut contents, &mut pending_fn_responses);

    let mut obj = Map::new();
    obj.insert("contents".into(), Value::Array(contents));
    if !system_parts.is_empty() {
        obj.insert("systemInstruction".into(), json!({ "parts": system_parts }));
    }
    if !req.tools.is_empty() {
        obj.insert("tools".into(), gemini_tools(&req.tools));
        if let Some(cfg) = gemini_tool_config(req.tool_choice.as_ref()) {
            obj.insert("toolConfig".into(), cfg);
        }
    }
    let mut gc = Map::new();
    if let Some(t) = req.sampling.temperature {
        gc.insert("temperature".into(), json!(t));
    }
    if let Some(p) = req.sampling.top_p {
        gc.insert("topP".into(), json!(p));
    }
    if let Some(m) = req.sampling.max_tokens {
        gc.insert("maxOutputTokens".into(), json!(m));
    }
    if !req.sampling.stop.is_empty() {
        gc.insert("stopSequences".into(), json!(req.sampling.stop));
    }
    // Gemini expresses structured output via generationConfig: a JSON MIME type
    // plus (for json_schema) the schema itself under `responseJsonSchema`.
    // json_object constrains only the MIME type; the name / strict / description
    // metadata has no Gemini equivalent and is dropped (advisory, not
    // faithfulness-critical — the schema and JSON-ness are what bind output).
    if let Some(rf) = &req.response_format {
        gc.insert("responseMimeType".into(), json!("application/json"));
        if let ResponseFormat::JsonSchema { schema, .. } = rf {
            gc.insert("responseJsonSchema".into(), schema.clone());
        }
    }
    if !gc.is_empty() {
        obj.insert("generationConfig".into(), Value::Object(gc));
    }
    Ok(Value::Object(obj))
}

/// Render message content as Gemini `parts`. Text → `{text}`; an image URL →
/// `{fileData:{fileUri}}` (Gemini's by-reference image form); an assistant
/// tool call → `{functionCall:{name,args}}`. Tool results are handled separately
/// (rendered as `functionResponse` parts in a user turn).
fn gemini_parts(parts: &[ContentPart]) -> Value {
    Value::Array(
        parts
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text } => Some(json!({ "text": text })),
                ContentPart::ImageUrl { url } => Some(json!({ "fileData": { "fileUri": url } })),
                ContentPart::ToolUse {
                    name, arguments, ..
                } => Some(json!({
                    "functionCall": { "name": name, "args": tool_arguments_object(arguments) }
                })),
                ContentPart::ToolResult { .. } => None,
                // A Responses-input reasoning echo has no Gemini equivalent — dropped.
                ContentPart::Reasoning { .. } => None,
            })
            .collect(),
    )
}

/// Flush buffered `functionResponse` parts as a single Gemini user content.
fn flush_gemini_tool_results(contents: &mut Vec<Value>, pending: &mut Vec<Value>) {
    if !pending.is_empty() {
        contents.push(json!({
            "role": "user",
            "parts": Value::Array(std::mem::take(pending)),
        }));
    }
}

/// Render canonical tools as Gemini's single `functionDeclarations` group.
/// Gemini names the JSON-schema field `parametersJsonSchema`.
fn gemini_tools(tools: &[CanonicalTool]) -> Value {
    let decls: Vec<Value> = tools
        .iter()
        .map(|t| {
            let mut o = Map::new();
            o.insert("name".into(), json!(t.name));
            if let Some(d) = &t.description {
                o.insert("description".into(), json!(d));
            }
            o.insert("parametersJsonSchema".into(), t.parameters.clone());
            Value::Object(o)
        })
        .collect();
    json!([{ "functionDeclarations": decls }])
}

/// Render a [`ToolChoice`] as Gemini's `toolConfig.functionCallingConfig`.
/// `auto`→AUTO, `none`→NONE, `required`→ANY, a specific function→ANY with
/// `allowedFunctionNames`. `None` ⇒ omit (provider default is AUTO).
fn gemini_tool_config(tc: Option<&ToolChoice>) -> Option<Value> {
    let cfg = match tc? {
        ToolChoice::Auto => json!({ "mode": "AUTO" }),
        ToolChoice::None => json!({ "mode": "NONE" }),
        ToolChoice::Required => json!({ "mode": "ANY" }),
        ToolChoice::Function(name) => json!({ "mode": "ANY", "allowedFunctionNames": [name] }),
    };
    Some(json!({ "functionCallingConfig": cfg }))
}

/// Render a canonical request as an **OpenAI Responses API** (`/responses`)
/// request body. Differences from Chat Completions, all handled here:
/// - messages become `input` items (`{type:"message", role, content:[...]}`),
///   with text parts typed `input_text` (user) / `output_text` (assistant) and
///   image parts `input_image` (Responses' input-image form, the URL as a
///   string);
/// - `system` is hoisted to the top-level `instructions` field (Responses has no
///   system-role message — its equivalent, `developer`, folds into
///   `instructions`); multiple system messages join with blank lines, order
///   preserved;
/// - `max_tokens` → `max_output_tokens`;
/// - `stop` and `seed` have no Responses equivalent and are dropped (advisory
///   only — not faithfulness-critical);
/// - tools render to the flat Responses `function` shape; assistant tool calls
///   become `function_call` input items and `Role::Tool` results
///   `function_call_output` items; `response_format` maps to `text.format`.
///
/// Fallible: a construct this renderer cannot faithfully emit (e.g. an image in
/// a system message) returns [`TranslateError::Unsupported`] rather than a lossy
/// body — a fail-closed translation boundary (I6), symmetric with the other
/// renderers.
pub fn render_openai_responses(req: &LlmRequest, model: &str) -> Result<Value, TranslateError> {
    let mut system_chunks: Vec<String> = Vec::new();
    let mut input: Vec<Value> = Vec::new();
    for m in &req.messages {
        match m.role {
            Role::System => system_chunks.push(responses_system_text(&m.content)?),
            Role::User | Role::Assistant => {
                let assistant = matches!(m.role, Role::Assistant);
                let role = if assistant { "assistant" } else { "user" };
                let (textish, tool_uses, tool_results) = partition_parts(&m.content);
                if !tool_results.is_empty() {
                    return Err(TranslateError::Unsupported {
                        surface: "openai_responses",
                        param: "tool_result on a non-tool message".into(),
                    });
                }
                // Prior-turn reasoning items (assistant-side, opaque) are replayed
                // verbatim as `reasoning` input items BEFORE this turn's message /
                // function_call items — the order OpenAI emitted them and requires
                // on a stateless replay. `partition_parts` drops them, so they are
                // collected directly here.
                for p in &m.content {
                    if let ContentPart::Reasoning { raw } = p {
                        input.push(raw.clone());
                    }
                }
                // A message item carries the text/image content. Skip it when the
                // turn is only tool calls (no faithful empty-message item).
                if !textish.is_empty() {
                    input.push(json!({
                        "type": "message",
                        "role": role,
                        "content": responses_content(&textish, assistant),
                    }));
                }
                // Each assistant tool call is its own `function_call` input item.
                for p in tool_uses {
                    if let ContentPart::ToolUse {
                        id,
                        name,
                        arguments,
                    } = p
                    {
                        input.push(json!({
                            "type": "function_call",
                            "call_id": id,
                            "name": name,
                            "arguments": arguments,
                        }));
                    }
                }
            }
            // Tool results become `function_call_output` input items.
            Role::Tool => {
                for p in &m.content {
                    if let ContentPart::ToolResult {
                        tool_call_id,
                        content,
                    } = p
                    {
                        input.push(json!({
                            "type": "function_call_output",
                            "call_id": tool_call_id,
                            "output": content,
                        }));
                    }
                }
            }
        }
    }

    let mut obj = Map::new();
    obj.insert("model".into(), json!(model));
    obj.insert("input".into(), Value::Array(input));
    if !system_chunks.is_empty() {
        obj.insert("instructions".into(), json!(system_chunks.join("\n\n")));
    }
    if !req.tools.is_empty() {
        obj.insert("tools".into(), responses_tools(&req.tools));
        if let Some(tc) = &req.tool_choice {
            obj.insert("tool_choice".into(), responses_tool_choice(tc));
        }
    }
    if let Some(p) = req.parallel_tool_calls {
        obj.insert("parallel_tool_calls".into(), json!(p));
    }
    if let Some(t) = req.sampling.temperature {
        obj.insert("temperature".into(), json!(t));
    }
    if let Some(p) = req.sampling.top_p {
        obj.insert("top_p".into(), json!(p));
    }
    if let Some(m) = req.sampling.max_tokens {
        obj.insert("max_output_tokens".into(), json!(m));
    }
    // The Responses API nests reasoning depth under `reasoning.effort` (vs. the
    // top-level `reasoning_effort` of Chat Completions). The Codex finalizer does
    // NOT strip `reasoning`, so this survives onto the ChatGPT-backend route too.
    if let Some(effort) = &req.sampling.reasoning_effort {
        obj.insert("reasoning".into(), json!({ "effort": effort }));
    }
    // The Responses API expresses structured output under `text.format`, with the
    // json_schema fields flattened directly into the `format` object (vs Chat
    // Completions' nested `json_schema` key). The Codex finalizer does NOT strip
    // `text`, so this survives onto the ChatGPT-backend route too.
    if let Some(rf) = &req.response_format {
        obj.insert("text".into(), responses_text_format(rf));
    }
    // Forward the server-side conversation handle so the OpenAI Responses backend
    // threads the turn from its own store (the gateway stores nothing — I9). The
    // Codex finalizer strips it (the ChatGPT backend rejects it); the standard
    // `/v1/responses` endpoint accepts it. Only ever set on a Responses-inbound
    // request; a Chat-inbound request carries `None`.
    if let Some(prev) = &req.previous_response_id {
        obj.insert("previous_response_id".into(), json!(prev));
    }
    // Forward the persistence flag so a client's `store:false` opt-out is honored
    // by the backend (which persists by default) rather than silently dropped.
    // The Codex finalizer overrides it to `false` (the ChatGPT backend is
    // stateless); the standard `/v1/responses` endpoint honors the value.
    if let Some(store) = req.store {
        obj.insert("store".into(), json!(store));
    }
    if req.stream {
        obj.insert("stream".into(), json!(true));
    }
    Ok(Value::Object(obj))
}

/// Render the canonical [`ResponseFormat`] as an OpenAI Responses `text` value
/// (`{"format": {...}}`). For json_schema the `name` / `strict` / `schema` fields
/// are flattened directly into the `format` object — the Responses shape — rather
/// than nested under a `json_schema` key as in Chat Completions.
fn responses_text_format(rf: &ResponseFormat) -> Value {
    let format = match rf {
        ResponseFormat::JsonObject => json!({ "type": "json_object" }),
        ResponseFormat::JsonSchema {
            name,
            description,
            strict,
            schema,
        } => {
            let mut f = Map::new();
            f.insert("type".into(), json!("json_schema"));
            f.insert("name".into(), json!(name));
            if let Some(d) = description {
                f.insert("description".into(), json!(d));
            }
            if let Some(s) = strict {
                f.insert("strict".into(), json!(s));
            }
            f.insert("schema".into(), schema.clone());
            Value::Object(f)
        }
    };
    json!({ "format": format })
}

/// Apply the ChatGPT-backend (Codex) body constraints to an already-rendered
/// OpenAI Responses body. **Only** for routes that target the ChatGPT backend
/// (`chatgpt.com/backend-api/codex`, `ResolvedRoute::openai_chatgpt`) — the
/// standard OpenAI Responses endpoint (`api.openai.com/v1/responses`) accepts the
/// sampling/token fields and does not require `stream`, so it must NOT be run
/// through here.
///
/// Mirrors the reference proxy's `ConvertOpenAIResponsesRequestToCodex` +
/// `codex_executor` normalizations. The Codex backend is strict and rejects a
/// generic Responses body in several ways the gateway must pre-empt:
/// - **`instructions` MUST be present** (absent ⇒ `400 {"detail":"Instructions
///   are required"}`); an empty string is accepted. A present-but-`null` value
///   counts as absent. Mirrors `normalizeCodexInstructions`.
/// - it is a **streaming-only** backend, so `stream` is forced `true` (the
///   transport must stream too — dispatch only runs this on a streaming call).
/// - `store: false` + `include: ["reasoning.encrypted_content"]` +
///   `parallel_tool_calls: true` are what the Codex CLI sends (a stateless,
///   encrypted-reasoning-replay client).
/// - **token-limit + sampling fields are rejected** (`Unsupported parameter`):
///   `max_output_tokens`, `max_completion_tokens`, `temperature`, `top_p` are
///   stripped — note `render_openai_responses` *sets* `temperature`/`top_p`/
///   `max_output_tokens`, so this strip is load-bearing, not defensive.
/// - a set of fields the backend does not accept (`truncation`,
///   `context_management`, `user`, `previous_response_id`,
///   `prompt_cache_retention`, `safety_identifier`, `stream_options`) are stripped
///   so a future caller (or a translated inbound body) cannot smuggle one in.
///
/// Idempotent and total: a non-object body is returned unchanged.
pub fn finalize_codex_responses_body(mut body: Value) -> Value {
    let Value::Object(obj) = &mut body else {
        return body;
    };
    obj.insert("stream".into(), Value::Bool(true));
    obj.insert("store".into(), Value::Bool(false));
    obj.insert("parallel_tool_calls".into(), Value::Bool(true));
    obj.insert("include".into(), json!(["reasoning.encrypted_content"]));
    // Present-but-null counts as absent for the backend's required-field check.
    if !matches!(obj.get("instructions"), Some(v) if !v.is_null()) {
        obj.insert("instructions".into(), json!(""));
    }
    for field in [
        "max_output_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "truncation",
        "context_management",
        "user",
        "previous_response_id",
        "prompt_cache_retention",
        "safety_identifier",
        "stream_options",
    ] {
        obj.remove(field);
    }
    body
}

/// Flatten content to plain text for the Responses top-level `instructions`
/// field (text-only). An image in a system message fails closed (I6) —
/// symmetric with the Anthropic/Gemini system-image rejection.
fn responses_system_text(parts: &[ContentPart]) -> Result<String, TranslateError> {
    let mut text = String::new();
    for p in parts {
        match p {
            ContentPart::Text { text: t } => text.push_str(t),
            _ => {
                return Err(TranslateError::Unsupported {
                    surface: "openai_responses",
                    param: "non-text content in a system message".into(),
                })
            }
        }
    }
    Ok(text)
}

/// Render text/image content parts as Responses `input` content parts. Text is
/// typed `output_text` for an assistant turn and `input_text` otherwise; an
/// image URL becomes `input_image`. Tool parts are partitioned out by the
/// caller (rendered as their own `function_call` / `function_call_output`
/// items), so only `Text`/`ImageUrl` reach here.
fn responses_content(parts: &[&ContentPart], assistant: bool) -> Value {
    let text_type = if assistant {
        "output_text"
    } else {
        "input_text"
    };
    Value::Array(
        parts
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text } => Some(json!({ "type": text_type, "text": text })),
                ContentPart::ImageUrl { url } => {
                    Some(json!({ "type": "input_image", "image_url": url }))
                }
                _ => None,
            })
            .collect(),
    )
}

/// Render canonical tools as the OpenAI Responses `tools` array — the flat
/// `[{type:function, name, description?, parameters}]` shape (vs Chat
/// Completions' nested `function` object).
fn responses_tools(tools: &[CanonicalTool]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|t| {
                let mut o = Map::new();
                o.insert("type".into(), json!("function"));
                o.insert("name".into(), json!(t.name));
                if let Some(d) = &t.description {
                    o.insert("description".into(), json!(d));
                }
                o.insert("parameters".into(), t.parameters.clone());
                if let Some(s) = t.strict {
                    o.insert("strict".into(), json!(s));
                }
                Value::Object(o)
            })
            .collect(),
    )
}

/// Render a [`ToolChoice`] in the OpenAI Responses shape: `auto`/`none`/
/// `required` as a bare string, or a specific function as `{type:function,
/// name}` (flat — vs Chat Completions' nested `function.name`).
fn responses_tool_choice(tc: &ToolChoice) -> Value {
    match tc {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Function(name) => json!({ "type": "function", "name": name }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::parse_chat_completions;
    use serde_json::json;

    #[test]
    fn reasoning_effort_renders_per_surface_and_survives_codex() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "reasoning_effort": "high"
        }))
        .unwrap();
        // Chat Completions: top-level `reasoning_effort`.
        assert_eq!(
            render_openai_chat(&req, "served").unwrap()["reasoning_effort"],
            "high"
        );
        // Responses: nested `reasoning.effort`.
        let resp = render_openai_responses(&req, "served").unwrap();
        assert_eq!(resp["reasoning"]["effort"], "high");
        // The Codex finalizer must NOT strip `reasoning` (it controls reasoning
        // depth on the ChatGPT backend).
        assert_eq!(
            finalize_codex_responses_body(resp)["reasoning"]["effort"],
            "high"
        );

        // Anthropic/Gemini express reasoning as a token *budget*, not an effort
        // level; until that mapping lands they fail closed (I6) rather than
        // silently drop the caller's reasoning control.
        assert!(matches!(
            render_anthropic_messages(&req, "served").unwrap_err(),
            TranslateError::Unsupported { surface: "anthropic_messages", param } if param == "reasoning_effort"
        ));
        assert!(matches!(
            render_gemini(&req).unwrap_err(),
            TranslateError::Unsupported { surface: "gemini", param } if param == "reasoning_effort"
        ));

        // A request that omits it renders no reasoning field (no null pollution).
        let plain = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}]
        }))
        .unwrap();
        assert!(render_openai_chat(&plain, "served")
            .unwrap()
            .get("reasoning_effort")
            .is_none());
        assert!(render_openai_responses(&plain, "served")
            .unwrap()
            .get("reasoning")
            .is_none());
    }

    #[test]
    fn renders_model_messages_and_sampling() {
        let req = parse_chat_completions(&json!({
            "model": "alias",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.5,
            "max_tokens": 32
        }))
        .unwrap();
        // The resolved upstream model overrides the requested alias.
        let out = render_openai_chat(&req, "openrouter/gpt-5.4").unwrap();
        assert_eq!(out["model"], "openrouter/gpt-5.4");
        assert_eq!(out["messages"][0]["role"], "user");
        assert_eq!(out["messages"][0]["content"], "hi");
        assert_eq!(out["temperature"], 0.5);
        assert_eq!(out["max_tokens"], 32);
        assert!(out.get("stream").is_none());
    }

    #[test]
    fn streaming_request_opts_into_usage() {
        let req = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role":"user","content":"x"}], "stream": true
        }))
        .unwrap();
        let out = render_openai_chat(&req, "m").unwrap();
        assert_eq!(out["stream"], true);
        assert_eq!(out["stream_options"]["include_usage"], true);
    }

    #[test]
    fn multipart_content_round_trips_to_typed_array() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role":"user","content":[
                {"type":"text","text":"describe"},
                {"type":"image_url","image_url":{"url":"u"}}
            ]}]
        }))
        .unwrap();
        let out = render_openai_chat(&req, "m").unwrap();
        let content = &out["messages"][0]["content"];
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[1]["type"], "image_url");
        assert_eq!(content[1]["image_url"]["url"], "u");
    }

    #[test]
    fn openai_renders_tools_calls_and_results() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [
                {"role": "assistant", "content": "ok",
                    "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]},
                {"role": "tool", "content": "72F", "tool_call_id": "c1"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "get_weather", "description": "Get weather", "parameters": {"type": "object"}
            }}],
            "tool_choice": "auto",
            "parallel_tool_calls": false
        }))
        .unwrap();
        let out = render_openai_chat(&req, "m").unwrap();
        // Request-level tools / tool_choice / parallel_tool_calls (native 1:1).
        assert_eq!(out["tools"][0]["type"], "function");
        assert_eq!(out["tools"][0]["function"]["name"], "get_weather");
        assert_eq!(out["tool_choice"], "auto");
        assert_eq!(out["parallel_tool_calls"], false);
        // Assistant message carries content + tool_calls.
        assert_eq!(out["messages"][0]["role"], "assistant");
        assert_eq!(out["messages"][0]["content"], "ok");
        assert_eq!(out["messages"][0]["tool_calls"][0]["id"], "c1");
        assert_eq!(
            out["messages"][0]["tool_calls"][0]["function"]["arguments"],
            "{\"city\":\"SF\"}"
        );
        // Tool result → a tool-role message keyed by tool_call_id.
        assert_eq!(out["messages"][1]["role"], "tool");
        assert_eq!(out["messages"][1]["tool_call_id"], "c1");
        assert_eq!(out["messages"][1]["content"], "72F");
    }

    #[test]
    fn null_content_round_trips_to_null_not_empty_array() {
        // `content: null` parses to zero parts; it must render back as JSON
        // null (OpenAI's no-content form), keeping the inbound→outbound
        // round-trip lossless rather than turning it into an empty array.
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "assistant", "content": null}]
        }))
        .unwrap();
        let out = render_openai_chat(&req, "m").unwrap();
        assert!(
            out["messages"][0]["content"].is_null(),
            "expected null content, got {}",
            out["messages"][0]["content"]
        );
    }

    // ---- Anthropic Messages renderer --------------------------------------

    #[test]
    fn anthropic_hoists_system_and_requires_max_tokens() {
        let req = parse_chat_completions(&json!({
            "model": "alias",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"}
            ],
            "temperature": 0.3
        }))
        .unwrap();
        let out = render_anthropic_messages(&req, "claude-x").unwrap();
        assert_eq!(out["model"], "claude-x");
        // System hoisted to a top-level field, not left in `messages`.
        assert_eq!(out["system"], "be terse");
        assert_eq!(out["messages"].as_array().unwrap().len(), 1);
        assert_eq!(out["messages"][0]["role"], "user");
        assert_eq!(out["messages"][0]["content"], "hi");
        assert_eq!(out["temperature"], 0.3);
        // max_tokens is required by Anthropic; defaulted when the caller omits it.
        assert_eq!(out["max_tokens"], DEFAULT_ANTHROPIC_MAX_TOKENS);
        assert!(out.get("stream").is_none());
    }

    #[test]
    fn anthropic_honors_explicit_max_tokens_stop_and_stream() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "max_tokens": 100,
            "stop": ["END"],
            "stream": true
        }))
        .unwrap();
        let out = render_anthropic_messages(&req, "m").unwrap();
        assert_eq!(out["max_tokens"], 100);
        // OpenAI `stop` becomes Anthropic `stop_sequences`.
        assert_eq!(out["stop_sequences"][0], "END");
        assert_eq!(out["stream"], true);
        // No system messages ⇒ no top-level `system` field.
        assert!(out.get("system").is_none());
    }

    #[test]
    fn anthropic_renders_image_parts_as_image_source_blocks() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "describe"},
                {"type": "image_url", "image_url": {"url": "https://x/y.png"}}
            ]}]
        }))
        .unwrap();
        let out = render_anthropic_messages(&req, "m").unwrap();
        let content = &out["messages"][0]["content"];
        assert_eq!(content[0]["type"], "text");
        // Anthropic image block shape, not OpenAI's image_url.
        assert_eq!(content[1]["type"], "image");
        assert_eq!(content[1]["source"]["type"], "url");
        assert_eq!(content[1]["source"]["url"], "https://x/y.png");
    }

    #[test]
    fn anthropic_renders_tools_tool_use_and_tool_result() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [
                {"role": "assistant", "content": null,
                    "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]},
                {"role": "tool", "content": "72F", "tool_call_id": "c1"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "get_weather", "description": "Get weather", "parameters": {"type": "object"}
            }}],
            "tool_choice": "required"
        }))
        .unwrap();
        let out = render_anthropic_messages(&req, "m").unwrap();
        // Anthropic names the schema field `input_schema`.
        assert_eq!(out["tools"][0]["name"], "get_weather");
        assert_eq!(out["tools"][0]["input_schema"]["type"], "object");
        // required → {type:any}.
        assert_eq!(out["tool_choice"]["type"], "any");
        // Assistant tool_use block carries a parsed-object input.
        let asst = &out["messages"][0];
        assert_eq!(asst["role"], "assistant");
        assert_eq!(asst["content"][0]["type"], "tool_use");
        assert_eq!(asst["content"][0]["id"], "c1");
        assert_eq!(asst["content"][0]["input"]["city"], "SF");
        // Tool result is a tool_result block inside a USER turn.
        let user = &out["messages"][1];
        assert_eq!(user["role"], "user");
        assert_eq!(user["content"][0]["type"], "tool_result");
        assert_eq!(user["content"][0]["tool_use_id"], "c1");
        assert_eq!(user["content"][0]["content"], "72F");
    }

    #[test]
    fn anthropic_rejects_image_in_system_message() {
        use crate::canonical::{CanonicalMessage, Role, Sampling, Surface};
        // Anthropic's top-level `system` is text-only, so an image in a system
        // message has no faithful rendering — it must fail closed (I6), not be
        // silently dropped.
        let req = LlmRequest {
            inbound_surface: Surface::ChatCompletions,
            model_requested: "m".into(),
            messages: vec![CanonicalMessage {
                role: Role::System,
                content: vec![
                    ContentPart::Text {
                        text: "be terse".into(),
                    },
                    ContentPart::ImageUrl {
                        url: "https://x/y.png".into(),
                    },
                ],
            }],
            sampling: Sampling::default(),
            tools: vec![],
            tool_choice: None,
            parallel_tool_calls: None,
            response_format: None,
            previous_response_id: None,
            store: None,
            stream: false,
        };
        let err = render_anthropic_messages(&req, "m").unwrap_err();
        assert!(
            matches!(&err,
                TranslateError::Unsupported { surface: "anthropic_messages", param }
                    if param == "non-text content in a system message"),
            "got {err:?}"
        );
    }

    // ---- Gemini renderer --------------------------------------------------

    #[test]
    fn gemini_hoists_system_maps_roles_and_sampling() {
        let req = parse_chat_completions(&json!({
            "model": "alias",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"}
            ],
            "temperature": 0.4,
            "max_tokens": 64,
            "top_p": 0.9,
            "stop": ["END"]
        }))
        .unwrap();
        let out = render_gemini(&req).unwrap();
        // No model in the body (it's in the URL path).
        assert!(out.get("model").is_none());
        // System → top-level systemInstruction.
        assert_eq!(out["systemInstruction"]["parts"][0]["text"], "be terse");
        // user stays user; assistant → model; content → parts.
        assert_eq!(out["contents"][0]["role"], "user");
        assert_eq!(out["contents"][0]["parts"][0]["text"], "hi");
        assert_eq!(out["contents"][1]["role"], "model");
        // Sampling → generationConfig with Gemini field names.
        assert_eq!(out["generationConfig"]["temperature"], 0.4);
        assert_eq!(out["generationConfig"]["maxOutputTokens"], 64);
        assert_eq!(out["generationConfig"]["topP"], 0.9);
        assert_eq!(out["generationConfig"]["stopSequences"][0], "END");
    }

    #[test]
    fn gemini_renders_image_parts_as_filedata() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "describe"},
                {"type": "image_url", "image_url": {"url": "https://x/y.png"}}
            ]}]
        }))
        .unwrap();
        let out = render_gemini(&req).unwrap();
        let parts = &out["contents"][0]["parts"];
        assert_eq!(parts[0]["text"], "describe");
        assert_eq!(parts[1]["fileData"]["fileUri"], "https://x/y.png");
    }

    #[test]
    fn gemini_renders_tools_function_call_and_function_response() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [
                {"role": "assistant", "content": null,
                    "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]},
                {"role": "tool", "content": "72F", "tool_call_id": "c1"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "get_weather", "parameters": {"type": "object"}
            }}],
            "tool_choice": "auto"
        }))
        .unwrap();
        let out = render_gemini(&req).unwrap();
        // Gemini names the schema field `parametersJsonSchema`, under a single
        // functionDeclarations group.
        assert_eq!(
            out["tools"][0]["functionDeclarations"][0]["name"],
            "get_weather"
        );
        assert_eq!(
            out["tools"][0]["functionDeclarations"][0]["parametersJsonSchema"]["type"],
            "object"
        );
        assert_eq!(out["toolConfig"]["functionCallingConfig"]["mode"], "AUTO");
        // Assistant tool call → functionCall part with a parsed-object `args`.
        assert_eq!(
            out["contents"][0]["parts"][0]["functionCall"]["name"],
            "get_weather"
        );
        assert_eq!(
            out["contents"][0]["parts"][0]["functionCall"]["args"]["city"],
            "SF"
        );
        // Tool result → functionResponse keyed by the function NAME, in a user turn.
        let resp = &out["contents"][1];
        assert_eq!(resp["role"], "user");
        assert_eq!(resp["parts"][0]["functionResponse"]["name"], "get_weather");
        assert_eq!(
            resp["parts"][0]["functionResponse"]["response"]["result"],
            "72F"
        );
    }

    #[test]
    fn gemini_rejects_system_image() {
        use crate::canonical::{CanonicalMessage, Role, Sampling, Surface};
        let sys_img = LlmRequest {
            inbound_surface: Surface::ChatCompletions,
            model_requested: "m".into(),
            messages: vec![CanonicalMessage {
                role: Role::System,
                content: vec![ContentPart::ImageUrl {
                    url: "https://x/y.png".into(),
                }],
            }],
            sampling: Sampling::default(),
            tools: vec![],
            tool_choice: None,
            parallel_tool_calls: None,
            response_format: None,
            previous_response_id: None,
            store: None,
            stream: false,
        };
        assert!(matches!(render_gemini(&sys_img).unwrap_err(),
            TranslateError::Unsupported { surface: "gemini", param } if param == "non-text content in a system message"));
    }

    // ---- OpenAI Responses renderer ----------------------------------------

    #[test]
    fn responses_hoists_system_to_instructions_and_maps_input() {
        let req = parse_chat_completions(&json!({
            "model": "alias",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"}
            ],
            "temperature": 0.4,
            "max_tokens": 64,
            "top_p": 0.9,
            "stop": ["END"],
            "seed": 7
        }))
        .unwrap();
        let out = render_openai_responses(&req, "gpt-5.4").unwrap();
        assert_eq!(out["model"], "gpt-5.4");
        // System → top-level instructions, not an input item.
        assert_eq!(out["instructions"], "be terse");
        let input = out["input"].as_array().unwrap();
        assert_eq!(input.len(), 2);
        // user → input_text part; assistant → output_text part.
        assert_eq!(input[0]["type"], "message");
        assert_eq!(input[0]["role"], "user");
        assert_eq!(input[0]["content"][0]["type"], "input_text");
        assert_eq!(input[0]["content"][0]["text"], "hi");
        assert_eq!(input[1]["role"], "assistant");
        assert_eq!(input[1]["content"][0]["type"], "output_text");
        // Sampling: max_tokens → max_output_tokens; stop/seed dropped (no
        // Responses equivalent).
        assert_eq!(out["temperature"], 0.4);
        assert_eq!(out["top_p"], 0.9);
        assert_eq!(out["max_output_tokens"], 64);
        assert!(out.get("stop").is_none());
        assert!(out.get("seed").is_none());
        assert!(out.get("stream").is_none());
    }

    #[test]
    fn responses_streaming_sets_stream_and_maps_image_input() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "describe"},
                {"type": "image_url", "image_url": {"url": "https://x/y.png"}}
            ]}],
            "stream": true
        }))
        .unwrap();
        let out = render_openai_responses(&req, "m").unwrap();
        assert_eq!(out["stream"], true);
        let content = &out["input"][0]["content"];
        assert_eq!(content[0]["type"], "input_text");
        // Responses input-image form: type input_image, URL as a string.
        assert_eq!(content[1]["type"], "input_image");
        assert_eq!(content[1]["image_url"], "https://x/y.png");
    }

    #[test]
    fn responses_renders_tools_function_call_and_output_items() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [
                {"role": "assistant", "content": null,
                    "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]},
                {"role": "tool", "content": "72F", "tool_call_id": "c1"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "get_weather", "parameters": {"type": "object"}
            }}],
            "tool_choice": {"type": "function", "function": {"name": "get_weather"}}
        }))
        .unwrap();
        let out = render_openai_responses(&req, "m").unwrap();
        // Responses tools are the flat shape; tool_choice is flat too.
        assert_eq!(out["tools"][0]["type"], "function");
        assert_eq!(out["tools"][0]["name"], "get_weather");
        assert_eq!(out["tool_choice"]["type"], "function");
        assert_eq!(out["tool_choice"]["name"], "get_weather");
        // Assistant tool call → a function_call input item (no empty message item).
        let input = out["input"].as_array().unwrap();
        assert_eq!(input[0]["type"], "function_call");
        assert_eq!(input[0]["call_id"], "c1");
        assert_eq!(input[0]["name"], "get_weather");
        assert_eq!(input[0]["arguments"], "{\"city\":\"SF\"}");
        // Tool result → a function_call_output item.
        assert_eq!(input[1]["type"], "function_call_output");
        assert_eq!(input[1]["call_id"], "c1");
        assert_eq!(input[1]["output"], "72F");
    }

    #[test]
    fn responses_rejects_system_image() {
        use crate::canonical::{CanonicalMessage, Role, Sampling, Surface};
        let sys_img = LlmRequest {
            inbound_surface: Surface::ChatCompletions,
            model_requested: "m".into(),
            messages: vec![CanonicalMessage {
                role: Role::System,
                content: vec![ContentPart::ImageUrl {
                    url: "https://x/y.png".into(),
                }],
            }],
            sampling: Sampling::default(),
            tools: vec![],
            tool_choice: None,
            parallel_tool_calls: None,
            response_format: None,
            previous_response_id: None,
            store: None,
            stream: false,
        };
        assert!(
            matches!(render_openai_responses(&sys_img, "m").unwrap_err(),
            TranslateError::Unsupported { surface: "openai_responses", param } if param == "non-text content in a system message")
        );
    }

    // ---- Codex (ChatGPT backend) body finalizer ---------------------------

    #[test]
    fn finalize_codex_responses_body_enforces_backend_contract() {
        // A rendered Responses body for a request that carried sampling +
        // max_tokens but no system message: `render_openai_responses` set
        // temperature/top_p/max_output_tokens and (no system ⇒) omitted
        // `instructions`. The Codex finalizer must make it backend-valid.
        let req = parse_chat_completions(&json!({
            "model": "alias",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.7,
            "top_p": 0.9,
            "max_tokens": 1024
        }))
        .unwrap();
        let rendered = render_openai_responses(&req, "gpt-5.5").unwrap();
        // Pre-conditions the finalizer has to fix.
        assert!(rendered.get("instructions").is_none());
        assert_eq!(rendered["temperature"], 0.7);
        assert_eq!(rendered["max_output_tokens"], 1024);

        let out = finalize_codex_responses_body(rendered);
        // Required-present fields: instructions (empty ok), and the streaming-only
        // backend's stateless-replay contract.
        assert_eq!(
            out["instructions"], "",
            "instructions must be present (absent ⇒ 400 'Instructions are required')"
        );
        assert_eq!(out["stream"], true, "Codex backend is streaming-only");
        assert_eq!(out["store"], false);
        assert_eq!(out["parallel_tool_calls"], true);
        assert_eq!(out["include"], json!(["reasoning.encrypted_content"]));
        // Rejected fields stripped (the backend 400s on these).
        for f in [
            "temperature",
            "top_p",
            "max_output_tokens",
            "max_completion_tokens",
        ] {
            assert!(
                out.get(f).is_none(),
                "`{f}` must be stripped for the Codex backend"
            );
        }
        // Untouched passthrough.
        assert_eq!(out["model"], "gpt-5.5");
        assert!(out["input"].is_array());
    }

    #[test]
    fn finalize_codex_keeps_real_instructions_but_replaces_null() {
        // A non-empty system message renders to `instructions`; the finalizer
        // must preserve it (only absent/null gets the empty-string fallback).
        let req = parse_chat_completions(&json!({
            "model": "alias",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"}
            ]
        }))
        .unwrap();
        let out = finalize_codex_responses_body(render_openai_responses(&req, "gpt-5.5").unwrap());
        assert_eq!(out["instructions"], "be terse");

        // A present-but-null instructions counts as absent → empty string.
        let nulled = json!({"input": [], "instructions": Value::Null});
        assert_eq!(finalize_codex_responses_body(nulled)["instructions"], "");
    }

    #[test]
    fn finalize_codex_is_total_on_a_non_object() {
        // Defensive: a non-object body is returned unchanged rather than panicking.
        assert_eq!(finalize_codex_responses_body(json!("x")), json!("x"));
    }

    // ---- response_format rendering (structured output) --------------------

    #[test]
    fn openai_chat_renders_response_format_natively() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "Out", "strict": true, "schema": {"type": "object"}
            }}
        }))
        .unwrap();
        let out = render_openai_chat(&req, "m").unwrap();
        // OpenAI's native nested shape, emitted 1:1.
        assert_eq!(out["response_format"]["type"], "json_schema");
        assert_eq!(out["response_format"]["json_schema"]["name"], "Out");
        assert_eq!(out["response_format"]["json_schema"]["strict"], true);
        assert_eq!(
            out["response_format"]["json_schema"]["schema"]["type"],
            "object"
        );

        let obj = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role":"user","content":"x"}],
            "response_format": {"type": "json_object"}
        }))
        .unwrap();
        assert_eq!(
            render_openai_chat(&obj, "m").unwrap()["response_format"],
            json!({"type":"json_object"})
        );

        // Omitted ⇒ no response_format key (no null pollution).
        let plain = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role":"user","content":"x"}]
        }))
        .unwrap();
        assert!(render_openai_chat(&plain, "m")
            .unwrap()
            .get("response_format")
            .is_none());
    }

    #[test]
    fn responses_renders_response_format_as_flattened_text_format() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "Out", "strict": true, "schema": {"type": "object"}
            }}
        }))
        .unwrap();
        let out = render_openai_responses(&req, "m").unwrap();
        // Responses flattens the json_schema fields into `format` (no nested
        // `json_schema` key), under `text`.
        let fmt = &out["text"]["format"];
        assert_eq!(fmt["type"], "json_schema");
        assert_eq!(fmt["name"], "Out");
        assert_eq!(fmt["strict"], true);
        assert_eq!(fmt["schema"]["type"], "object");
        assert!(fmt.get("json_schema").is_none());
        // The Codex finalizer must NOT strip `text` — structured output must
        // survive onto the ChatGPT-backend route.
        assert!(finalize_codex_responses_body(out).get("text").is_some());

        let obj = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role":"user","content":"x"}],
            "response_format": {"type": "json_object"}
        }))
        .unwrap();
        assert_eq!(
            render_openai_responses(&obj, "m").unwrap()["text"]["format"],
            json!({"type":"json_object"})
        );
    }

    #[test]
    fn gemini_renders_response_format_as_mime_and_schema() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "Out", "schema": {"type": "object"}
            }}
        }))
        .unwrap();
        let out = render_gemini(&req).unwrap();
        let gc = &out["generationConfig"];
        assert_eq!(gc["responseMimeType"], "application/json");
        assert_eq!(gc["responseJsonSchema"]["type"], "object");

        // json_object constrains only the MIME type (no schema).
        let obj = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role":"user","content":"x"}],
            "response_format": {"type": "json_object"}
        }))
        .unwrap();
        let gc = render_gemini(&obj).unwrap();
        let gc = &gc["generationConfig"];
        assert_eq!(gc["responseMimeType"], "application/json");
        assert!(gc.get("responseJsonSchema").is_none());
    }

    #[test]
    fn anthropic_emulates_response_format_via_forced_tool() {
        // Anthropic has no native structured output, so a `response_format`
        // request is emulated: a single synthetic tool is forced. The response
        // translator unwraps the resulting tool_use back into content.
        let schema = json!({"type": "object", "properties": {"k": {"type": "string"}}});
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "Out", "schema": schema.clone()
            }}
        }))
        .unwrap();
        let out = render_anthropic_messages(&req, "m").unwrap();
        // A single forced tool whose input_schema is the requested schema.
        assert_eq!(out["tools"].as_array().unwrap().len(), 1);
        assert_eq!(out["tools"][0]["name"], STRUCTURED_OUTPUT_TOOL_NAME);
        assert_eq!(out["tools"][0]["input_schema"], schema);
        assert_eq!(out["tool_choice"]["type"], "tool");
        assert_eq!(out["tool_choice"]["name"], STRUCTURED_OUTPUT_TOOL_NAME);
    }

    #[test]
    fn anthropic_response_format_with_tools_is_rejected() {
        // Combining the structured-output emulation with the caller's own tools
        // is ambiguous → reject (the capability gate enforces the same).
        let mut req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_object"}
        }))
        .unwrap();
        req.tools = vec![crate::canonical::CanonicalTool {
            name: "f".into(),
            description: None,
            parameters: json!({"type": "object"}),
            strict: None,
        }];
        assert!(matches!(
            render_anthropic_messages(&req, "m").unwrap_err(),
            TranslateError::Unsupported { surface: "anthropic_messages", param } if param == "response_format combined with tools"
        ));
    }
}
