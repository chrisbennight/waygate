//! Inbound translation: an OpenAI-shaped client request → the canonical
//! [`LlmRequest`]. Covers both client surfaces — Chat Completions
//! ([`parse_chat_completions`]) and the Responses API ([`parse_responses`]) —
//! each fail-closed (I6): a field the parser does not translate surfaces as
//! `Unsupported` rather than being silently dropped.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::canonical::{
    CanonicalMessage, CanonicalTool, ContentPart, LlmRequest, ResponseFormat, Role, Sampling,
    Surface, ToolChoice,
};
use crate::outbound::STRUCTURED_OUTPUT_TOOL_NAME;

/// Failure modes when translating a client request into canonical form.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TranslateError {
    /// The request was structurally invalid (bad JSON shape, empty messages,
    /// unknown role, …). The carried string is operator/client-facing detail.
    #[error("invalid request: {0}")]
    Invalid(String),
    /// A parameter that cannot be honored on the target surface/provider.
    #[error("unsupported on {surface}: {param}")]
    Unsupported {
        surface: &'static str,
        param: String,
    },
}

#[derive(Deserialize)]
struct ChatReq {
    model: String,
    #[serde(default)]
    messages: Vec<ChatMsg>,
    #[serde(default)]
    temperature: Option<f64>,
    #[serde(default)]
    top_p: Option<f64>,
    #[serde(default)]
    max_tokens: Option<u64>,
    #[serde(default)]
    max_completion_tokens: Option<u64>,
    #[serde(default)]
    stop: Option<StopField>,
    #[serde(default)]
    seed: Option<i64>,
    /// Reasoning depth for reasoning models (`minimal`/`low`/`medium`/`high`).
    /// A typed field (not in `rest`) so it is forwarded, not rejected. Carried to
    /// the OpenAI-chat (`reasoning_effort`) and Responses (`reasoning.effort`)
    /// renderers; Anthropic/Gemini thinking-budget mapping is a follow-up.
    #[serde(default)]
    reasoning_effort: Option<String>,
    /// Structured-output constraint (`json_object` / `json_schema`). A typed
    /// field (not in `rest`) so it is parsed into the canonical
    /// [`ResponseFormat`], not rejected by the unsupported-field guard.
    #[serde(default)]
    response_format: Option<Value>,
    /// Number of completions to return. The gateway returns exactly one, so a
    /// typed field that accepts `1` (or absent) and rejects anything else,
    /// rather than silently under-delivering (I6).
    #[serde(default)]
    n: Option<u64>,
    /// Function/tool definitions. A typed field so they are parsed into canonical
    /// [`CanonicalTool`]s rather than rejected.
    #[serde(default)]
    tools: Option<Vec<Value>>,
    /// Tool-selection constraint (`auto`/`none`/`required` or a specific
    /// function). Parsed into [`ToolChoice`].
    #[serde(default)]
    tool_choice: Option<Value>,
    /// Whether the model may emit multiple tool calls in one turn. Forwarded
    /// where the provider supports it.
    #[serde(default)]
    parallel_tool_calls: Option<bool>,
    #[serde(default)]
    stream: bool,
    /// Any Chat Completions field this slice does not translate (e.g.
    /// `presence_penalty`, `logit_bias`, `logprobs`). Serde would otherwise
    /// ignore unknown fields and we would silently strip request semantics —
    /// instead these are rejected with `Unsupported` (design I6: no silent lossy
    /// degradation). As support lands, fields graduate out of here into typed
    /// fields above.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StopField {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct ChatMsg {
    role: String,
    #[serde(default)]
    content: ChatContent,
    /// Assistant-issued tool calls (`[{id, type:function, function:{name,
    /// arguments}}]`). A typed field so it is parsed into
    /// [`ContentPart::ToolUse`] parts rather than rejected.
    #[serde(default)]
    tool_calls: Option<Vec<Value>>,
    /// Correlation id on a `tool`-role result message.
    #[serde(default)]
    tool_call_id: Option<String>,
    /// Remaining message-level fields this slice does not translate
    /// (`function_call` (deprecated), `name`, `refusal`, …). Rejected rather than
    /// silently dropped (I6).
    #[serde(flatten)]
    rest: Map<String, Value>,
}

#[derive(Deserialize, Default)]
#[serde(untagged)]
enum ChatContent {
    Text(String),
    /// Multipart content is kept as raw JSON and converted by `convert_part`,
    /// which rejects unknown keys at every level (I6) rather than letting serde
    /// silently drop extra semantics inside a content part.
    Parts(Vec<Value>),
    /// `content: null` (e.g. an assistant message that only carries tool calls).
    #[default]
    Absent,
}

/// Parse an OpenAI Chat Completions request body into the canonical model.
pub fn parse_chat_completions(body: &Value) -> Result<LlmRequest, TranslateError> {
    let req: ChatReq =
        serde_json::from_value(body.clone()).map_err(|e| TranslateError::Invalid(e.to_string()))?;
    if req.model.trim().is_empty() {
        return Err(TranslateError::Invalid("`model` must not be empty".into()));
    }
    if req.messages.is_empty() {
        return Err(TranslateError::Invalid(
            "`messages` must not be empty".into(),
        ));
    }
    // Reject — never silently drop — request fields this slice cannot translate
    // faithfully (design I6). The key list is sorted for a stable error.
    if !req.rest.is_empty() {
        let mut params: Vec<&str> = req.rest.keys().map(String::as_str).collect();
        params.sort_unstable();
        return Err(TranslateError::Unsupported {
            surface: "chat_completions",
            param: params.join(", "),
        });
    }
    let messages = req
        .messages
        .into_iter()
        .map(convert_message)
        .collect::<Result<Vec<_>, _>>()?;
    let stop = match req.stop {
        Some(StopField::One(s)) => vec![s],
        Some(StopField::Many(v)) => v,
        None => Vec::new(),
    };
    // `max_completion_tokens` is the newer spelling for the same output-token
    // cap. Honor either, but if both are present with *different* values the
    // intent is ambiguous — reject rather than silently discard one (I6).
    // Equal duplicates carry no information loss and are accepted.
    let max_tokens = match (req.max_tokens, req.max_completion_tokens) {
        (Some(a), Some(b)) if a != b => {
            return Err(TranslateError::Invalid(format!(
                "ambiguous output-token limit: max_tokens ({a}) and \
                 max_completion_tokens ({b}) differ"
            )))
        }
        (a, b) => a.or(b),
    };
    // `n` selects how many completions to return; the gateway streams/returns
    // exactly one. Honor 1 (or absent); reject anything else rather than
    // silently under-delivering what the client asked for (I6).
    if let Some(n) = req.n {
        if n != 1 {
            return Err(TranslateError::Unsupported {
                surface: "chat_completions",
                param: format!("n={n} (only a single completion is supported)"),
            });
        }
    }
    let response_format = req
        .response_format
        .map(parse_response_format)
        .transpose()?
        .flatten();
    let tools = match req.tools {
        Some(ts) => ts
            .into_iter()
            .map(parse_tool)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    let tool_choice = req.tool_choice.map(parse_tool_choice).transpose()?;
    // A tool_choice with no tools is an impossible constraint that several
    // providers would silently omit — reject it rather than drop it (I6).
    if tool_choice.is_some() && tools.is_empty() {
        return Err(TranslateError::Invalid(
            "`tool_choice` requires at least one tool".into(),
        ));
    }
    Ok(LlmRequest {
        inbound_surface: Surface::ChatCompletions,
        model_requested: req.model,
        messages,
        sampling: Sampling {
            temperature: req.temperature,
            top_p: req.top_p,
            max_tokens,
            stop,
            seed: req.seed,
            reasoning_effort: req.reasoning_effort,
        },
        tools,
        tool_choice,
        parallel_tool_calls: req.parallel_tool_calls,
        response_format,
        // Chat Completions has no server-side conversation handle or store flag.
        previous_response_id: None,
        store: None,
        stream: req.stream,
    })
}

/// Parse one OpenAI Chat Completions tool definition into a [`CanonicalTool`].
/// Only `type:function` tools are supported; a provider built-in tool type
/// (web search, code interpreter, …) is rejected rather than silently dropped
/// (I6). A missing `parameters` defaults to an empty-object schema (OpenAI
/// permits omitting it for a no-argument function).
fn parse_tool(t: Value) -> Result<CanonicalTool, TranslateError> {
    let obj = t
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("tool must be an object".into()))?;
    match obj.get("type") {
        // `type` is conventionally "function"; treat an absent type as function
        // (some clients omit it) but reject any other named type. A present
        // non-string type is malformed, not absent — fail closed (I6).
        None => {}
        Some(Value::String(s)) if s == "function" => {}
        Some(Value::String(other)) => {
            return Err(TranslateError::Unsupported {
                surface: "chat_completions",
                param: format!("tool type `{other}`"),
            })
        }
        Some(_) => {
            return Err(TranslateError::Invalid(
                "tool `type` must be a string".into(),
            ))
        }
    }
    // Reject unknown keys on the tool wrapper so unsupported tool semantics are
    // not silently dropped (I6).
    reject_extra_keys(obj, &["type", "function"], "tool")?;
    let func = obj
        .get("function")
        .and_then(Value::as_object)
        .ok_or_else(|| TranslateError::Invalid("function tool missing object `function`".into()))?;
    // Likewise reject unknown keys inside the function object; the known ones
    // (name / description / parameters / strict) are parsed below.
    reject_extra_keys(
        func,
        &["name", "description", "parameters", "strict"],
        "tool.function",
    )?;
    let name = func
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("function tool missing string `name`".into()))?
        .to_string();
    // The sentinel name is reserved for the Anthropic structured-output
    // emulation; a caller tool using it would be unwrapped as content instead of
    // a tool call. Reject it so the emulation stays unambiguous (I6).
    if name == STRUCTURED_OUTPUT_TOOL_NAME {
        return Err(TranslateError::Invalid(format!(
            "`{STRUCTURED_OUTPUT_TOOL_NAME}` is a reserved tool name"
        )));
    }
    let description = match func.get("description") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            return Err(TranslateError::Invalid(
                "function tool `description` must be a string".into(),
            ))
        }
    };
    let parameters = func.get("parameters").cloned().unwrap_or_else(|| json!({}));
    // `strict` is optional but, if present, must be a boolean — a wrong type is
    // malformed, not an omission (I6), consistent with response_format.
    let strict = match func.get("strict") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => {
            return Err(TranslateError::Invalid(
                "function tool `strict` must be a boolean".into(),
            ))
        }
    };
    Ok(CanonicalTool {
        name,
        description,
        parameters,
        strict,
    })
}

/// Parse an OpenAI `tool_choice` value into the canonical [`ToolChoice`]. Accepts
/// the strings `auto`/`none`/`required` or `{type:function, function:{name}}`.
fn parse_tool_choice(tc: Value) -> Result<ToolChoice, TranslateError> {
    match &tc {
        Value::String(s) => match s.as_str() {
            "auto" => Ok(ToolChoice::Auto),
            "none" => Ok(ToolChoice::None),
            "required" => Ok(ToolChoice::Required),
            other => Err(TranslateError::Unsupported {
                surface: "chat_completions",
                param: format!("tool_choice `{other}`"),
            }),
        },
        Value::Object(o) => {
            // Must be exactly `{type:"function", function:{name}}`; verify the
            // discriminator and reject unknown keys (I6) rather than accepting any
            // object that merely happens to carry a function name.
            match o.get("type").and_then(Value::as_str) {
                Some("function") => {}
                _ => {
                    return Err(TranslateError::Invalid(
                        "object tool_choice must have type \"function\"".into(),
                    ))
                }
            }
            reject_extra_keys(o, &["type", "function"], "tool_choice")?;
            let f = o
                .get("function")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    TranslateError::Invalid(
                        "object tool_choice must be {type:function, function:{name}}".into(),
                    )
                })?;
            reject_extra_keys(f, &["name"], "tool_choice.function")?;
            let name = f.get("name").and_then(Value::as_str).ok_or_else(|| {
                TranslateError::Invalid("tool_choice function missing string `name`".into())
            })?;
            Ok(ToolChoice::Function(name.to_string()))
        }
        _ => Err(TranslateError::Invalid(
            "tool_choice must be a string or an object".into(),
        )),
    }
}

/// Parse one assistant `tool_calls[]` entry into a [`ContentPart::ToolUse`].
/// `arguments` is OpenAI's JSON *string*, carried verbatim.
fn parse_tool_call(c: &Value) -> Result<ContentPart, TranslateError> {
    let obj = c
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("tool_call must be an object".into()))?;
    // Only function tool calls are modeled; verify the discriminator and reject
    // unknown keys (I6) rather than normalizing an arbitrary object into a call.
    // A present non-string `type` is malformed, not absent — fail closed, like
    // the top-level tool parser.
    match obj.get("type") {
        None => {}
        Some(Value::String(s)) if s == "function" => {}
        Some(Value::String(other)) => {
            return Err(TranslateError::Unsupported {
                surface: "chat_completions",
                param: format!("tool_call type `{other}`"),
            })
        }
        Some(_) => {
            return Err(TranslateError::Invalid(
                "tool_call `type` must be a string".into(),
            ))
        }
    }
    reject_extra_keys(obj, &["id", "type", "function"], "tool_call")?;
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("tool_call missing string `id`".into()))?
        .to_string();
    let func = obj
        .get("function")
        .and_then(Value::as_object)
        .ok_or_else(|| TranslateError::Invalid("tool_call missing object `function`".into()))?;
    reject_extra_keys(func, &["name", "arguments"], "tool_call.function")?;
    let name = func
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("tool_call function missing string `name`".into()))?
        .to_string();
    // `arguments` is OpenAI's JSON *string*, kept verbatim. Default to empty when
    // absent, but a present non-string value is malformed — reject it (I6)
    // rather than silently strip the call's arguments.
    let arguments = match func.get("arguments") {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            return Err(TranslateError::Invalid(
                "tool_call `arguments` must be a string".into(),
            ))
        }
    };
    Ok(ContentPart::ToolUse {
        id,
        name,
        arguments,
    })
}

/// Parse an OpenAI Chat Completions `response_format` value into the canonical
/// [`ResponseFormat`]. `{"type":"text"}` is the unconstrained default and maps
/// to `None` (the faithful rendering of "no constraint" is to emit nothing).
/// Unknown keys at any level reject (I6) rather than silently dropping
/// output-format semantics; an unknown `type` is `Unsupported`.
fn parse_response_format(rf: Value) -> Result<Option<ResponseFormat>, TranslateError> {
    let obj = rf
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("`response_format` must be an object".into()))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("`response_format` missing string `type`".into()))?;
    match kind {
        "text" => {
            reject_extra_keys(obj, &["type"], "response_format[text]")?;
            Ok(None)
        }
        "json_object" => {
            reject_extra_keys(obj, &["type"], "response_format[json_object]")?;
            Ok(Some(ResponseFormat::JsonObject))
        }
        "json_schema" => {
            reject_extra_keys(
                obj,
                &["type", "json_schema"],
                "response_format[json_schema]",
            )?;
            let js = obj
                .get("json_schema")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    TranslateError::Invalid(
                        "json_schema response_format missing object `json_schema`".into(),
                    )
                })?;
            reject_extra_keys(
                js,
                &["name", "description", "strict", "schema"],
                "response_format.json_schema",
            )?;
            let name = js
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    TranslateError::Invalid(
                        "json_schema response_format missing string `name`".into(),
                    )
                })?
                .to_string();
            let schema = js.get("schema").cloned().ok_or_else(|| {
                TranslateError::Invalid("json_schema response_format missing `schema`".into())
            })?;
            // `strict` / `description` are optional, but a present-but-wrong-typed
            // value is a malformed request, not an omission — reject it (I6
            // fail-closed), consistent with the missing-`name`/`schema` and
            // extra-key checks above, rather than silently coercing it to None
            // and dropping part of a supported request.
            let strict = match js.get("strict") {
                None => None,
                Some(Value::Bool(b)) => Some(*b),
                Some(_) => {
                    return Err(TranslateError::Invalid(
                        "json_schema response_format `strict` must be a boolean".into(),
                    ))
                }
            };
            let description = match js.get("description") {
                None => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => {
                    return Err(TranslateError::Invalid(
                        "json_schema response_format `description` must be a string".into(),
                    ))
                }
            };
            Ok(Some(ResponseFormat::JsonSchema {
                name,
                description,
                strict,
                schema,
            }))
        }
        other => Err(TranslateError::Unsupported {
            surface: "chat_completions",
            param: format!("response_format type `{other}`"),
        }),
    }
}

fn convert_message(m: ChatMsg) -> Result<CanonicalMessage, TranslateError> {
    // Reject remaining message-level fields we cannot translate faithfully (I6)
    // — e.g. the deprecated `function_call`, or `name`/`refusal`. `tool_calls`
    // and `tool_call_id` are typed fields (handled below), not in `rest`.
    if !m.rest.is_empty() {
        let mut params: Vec<String> = m.rest.keys().map(|k| format!("message.{k}")).collect();
        params.sort_unstable();
        return Err(TranslateError::Unsupported {
            surface: "chat_completions",
            param: params.join(", "),
        });
    }
    let role = match m.role.as_str() {
        // OpenAI's `developer` role is a system-level instruction.
        "system" | "developer" => Role::System,
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        other => {
            return Err(TranslateError::Invalid(format!(
                "unknown message role `{other}`"
            )))
        }
    };
    // A `tool`-role message is a tool result: its content is the result text and
    // it must carry the `tool_call_id` that correlates it with the call.
    if matches!(role, Role::Tool) {
        if m.tool_calls.is_some() {
            return Err(TranslateError::Invalid(
                "a `tool` message cannot also carry `tool_calls`".into(),
            ));
        }
        let tool_call_id = m.tool_call_id.ok_or_else(|| {
            TranslateError::Invalid("a `tool` message requires `tool_call_id`".into())
        })?;
        let content = chat_content_text(m.content)?;
        return Ok(CanonicalMessage {
            role,
            content: vec![ContentPart::ToolResult {
                tool_call_id,
                content,
            }],
        });
    }
    // `tool_call_id` is only meaningful on a tool message.
    if m.tool_call_id.is_some() {
        return Err(TranslateError::Invalid(
            "`tool_call_id` is only valid on a `tool` message".into(),
        ));
    }
    let mut content = match m.content {
        ChatContent::Text(text) => vec![ContentPart::Text { text }],
        ChatContent::Parts(parts) => parts
            .into_iter()
            .map(convert_part)
            .collect::<Result<Vec<_>, _>>()?,
        ChatContent::Absent => Vec::new(),
    };
    // Assistant tool calls become `ToolUse` parts appended after any text.
    if let Some(calls) = m.tool_calls {
        if !matches!(role, Role::Assistant) {
            return Err(TranslateError::Invalid(
                "`tool_calls` are only valid on an `assistant` message".into(),
            ));
        }
        for c in &calls {
            content.push(parse_tool_call(c)?);
        }
    }
    Ok(CanonicalMessage { role, content })
}

/// Flatten a `tool` message's content (string, multipart text, or null) to the
/// single result string the canonical [`ContentPart::ToolResult`] carries. A
/// non-text part in a tool result has no faithful representation, so it rejects
/// (I6) rather than being dropped.
fn chat_content_text(content: ChatContent) -> Result<String, TranslateError> {
    match content {
        ChatContent::Text(text) => Ok(text),
        ChatContent::Absent => Ok(String::new()),
        ChatContent::Parts(parts) => {
            let mut s = String::new();
            for p in parts {
                match convert_part(p)? {
                    ContentPart::Text { text } => s.push_str(&text),
                    _ => {
                        return Err(TranslateError::Unsupported {
                            surface: "chat_completions",
                            param: "non-text content in a tool result".into(),
                        })
                    }
                }
            }
            Ok(s)
        }
    }
}

/// Convert one multipart content element. Unknown content-part *types* and
/// unknown keys *within* a supported part both reject with `Unsupported` (I6),
/// so extra semantics (e.g. `image_url.detail`, `cache_control`) are never
/// silently dropped during canonicalization.
fn convert_part(part: Value) -> Result<ContentPart, TranslateError> {
    let obj = part
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("content part must be an object".into()))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("content part missing string `type`".into()))?;
    match kind {
        "text" => {
            reject_extra_keys(obj, &["type", "text"], "content[text]")?;
            let text = obj
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| TranslateError::Invalid("text part missing string `text`".into()))?
                .to_string();
            Ok(ContentPart::Text { text })
        }
        "image_url" => {
            reject_extra_keys(obj, &["type", "image_url"], "content[image_url]")?;
            let image_url = obj
                .get("image_url")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    TranslateError::Invalid("image_url part missing object `image_url`".into())
                })?;
            reject_extra_keys(image_url, &["url"], "content[image_url].image_url")?;
            let url = image_url
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| TranslateError::Invalid("image_url missing string `url`".into()))?
                .to_string();
            Ok(ContentPart::ImageUrl { url })
        }
        other => Err(TranslateError::Unsupported {
            surface: "chat_completions",
            param: format!("content part type `{other}`"),
        }),
    }
}

/// Reject any key in `obj` not in `allowed`, reporting them (sorted, prefixed
/// with `ctx`) as `Unsupported` on `surface` rather than ignoring them. The two
/// inbound surfaces share this nested fail-closed helper; the per-surface
/// wrappers ([`reject_extra_keys`] / [`reject_extra_keys_responses`]) attribute
/// the client-facing error to the right surface.
fn reject_extra_keys_on(
    surface: &'static str,
    obj: &Map<String, Value>,
    allowed: &[&str],
    ctx: &str,
) -> Result<(), TranslateError> {
    let mut extra: Vec<&str> = obj
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    if !extra.is_empty() {
        extra.sort_unstable();
        return Err(TranslateError::Unsupported {
            surface,
            param: format!("{ctx}.{}", extra.join(", ")),
        });
    }
    Ok(())
}

/// Chat Completions surface wrapper for [`reject_extra_keys_on`].
fn reject_extra_keys(
    obj: &Map<String, Value>,
    allowed: &[&str],
    ctx: &str,
) -> Result<(), TranslateError> {
    reject_extra_keys_on("chat_completions", obj, allowed, ctx)
}

/// Responses surface wrapper for [`reject_extra_keys_on`] — so a malformed
/// *nested* Responses structure (content part, function_call, text.format, tool,
/// …) reports `surface: "responses"`, not the Chat surface.
fn reject_extra_keys_responses(
    obj: &Map<String, Value>,
    allowed: &[&str],
    ctx: &str,
) -> Result<(), TranslateError> {
    reject_extra_keys_on("responses", obj, allowed, ctx)
}

// ===========================================================================
// Responses API inbound parser
//
// The OpenAI Responses surface differs from Chat Completions on the wire:
// `input` (string OR an array of typed items) instead of `messages`,
// `instructions` for the system channel, FLAT tool / tool_choice shapes (vs
// Chat's nested `function` object), structured output under `text.format`, and
// `max_output_tokens` / `reasoning.effort`. All normalize into the *same*
// canonical [`LlmRequest`], so the per-provider renderers are unchanged. This
// parser is the exact inverse of `outbound::render_openai_responses` for the
// supported subset (asserted by the round-trip property test).
// ===========================================================================

#[derive(Deserialize)]
struct ResponsesReq {
    model: String,
    /// `input` is a string OR an array of input items.
    #[serde(default)]
    input: Option<ResponsesInput>,
    /// The Responses system channel (a leading `System` message).
    #[serde(default)]
    instructions: Option<String>,
    #[serde(default)]
    temperature: Option<f64>,
    #[serde(default)]
    top_p: Option<f64>,
    #[serde(default)]
    max_output_tokens: Option<u64>,
    /// Reasoning *config* (`{effort, summary?}`) — distinct from `reasoning`
    /// *items* inside `input`. Only `effort` is carried (→ `reasoning_effort`).
    #[serde(default)]
    reasoning: Option<Value>,
    /// Structured-output constraint (`{format: {...}}`).
    #[serde(default)]
    text: Option<Value>,
    /// Flat Responses tools (`{type:function, name, parameters, …}`).
    #[serde(default)]
    tools: Option<Vec<Value>>,
    #[serde(default)]
    tool_choice: Option<Value>,
    #[serde(default)]
    parallel_tool_calls: Option<bool>,
    /// Server-side conversation handle — carried into the canonical request; the
    /// OpenAI-Responses renderer forwards it (the backend's own store provides
    /// continuity — I9), and the capability gate rejects it for a non-Responses
    /// route, where it is meaningless.
    #[serde(default)]
    previous_response_id: Option<String>,
    /// Server-side persistence flag — **forwarded** to the Responses renderer. A
    /// `store:false` opt-out must be honored (the OpenAI backend persists by
    /// default), so dropping it would silently store the response against the
    /// client's explicit wish; `store:true` is forwarded too (and enables
    /// `previous_response_id` continuity). Not rejected — that would break default
    /// SDK usage, where `store` defaults on. Non-Responses backends do not persist
    /// responses at all, so the flag has no effect there.
    #[serde(default)]
    store: Option<bool>,
    #[serde(default)]
    stream: bool,
    /// Any Responses field this parser does not translate (`include`, `metadata`,
    /// `service_tier`, `truncation`, `user`, `background`, `conversation`, …).
    /// Rejected with `Unsupported` (I6) rather than silently dropped; fields
    /// graduate out of here as support lands.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ResponsesInput {
    Text(String),
    Items(Vec<Value>),
}

/// Parse an OpenAI Responses API request body into the canonical [`LlmRequest`].
/// `instructions` becomes a leading `System` message; `input` items normalize
/// into the conversation (assistant-side `message` / `function_call` /
/// `reasoning` items accumulate into one `Assistant` turn, in order; a
/// `function_call_output` or a user/system message flushes that turn). Built-in
/// tool calls/definitions and any untranslated field reject with `Unsupported`
/// (I6) — they are not silently dropped.
pub fn parse_responses(body: &Value) -> Result<LlmRequest, TranslateError> {
    let req: ResponsesReq =
        serde_json::from_value(body.clone()).map_err(|e| TranslateError::Invalid(e.to_string()))?;
    if req.model.trim().is_empty() {
        return Err(TranslateError::Invalid("`model` must not be empty".into()));
    }
    // Reject untranslated top-level fields (I6). Sorted for a stable error.
    if !req.rest.is_empty() {
        let mut params: Vec<&str> = req.rest.keys().map(String::as_str).collect();
        params.sort_unstable();
        return Err(TranslateError::Unsupported {
            surface: "responses",
            param: params.join(", "),
        });
    }

    let mut messages: Vec<CanonicalMessage> = Vec::new();
    // `instructions` is the Responses system channel — render hoists every
    // `System` message into it, so it inverts to a single leading System message.
    if let Some(instr) = &req.instructions {
        messages.push(CanonicalMessage {
            role: Role::System,
            content: vec![ContentPart::Text {
                text: instr.clone(),
            }],
        });
    }
    match req.input {
        Some(ResponsesInput::Text(t)) => messages.push(CanonicalMessage {
            role: Role::User,
            content: vec![ContentPart::Text { text: t }],
        }),
        Some(ResponsesInput::Items(items)) => parse_responses_input(items, &mut messages)?,
        None => {}
    }
    if messages.is_empty() {
        return Err(TranslateError::Invalid(
            "a Responses request must carry `input` or `instructions`".into(),
        ));
    }

    let reasoning_effort = req
        .reasoning
        .map(parse_responses_reasoning)
        .transpose()?
        .flatten();
    let response_format = req
        .text
        .map(parse_responses_text_format)
        .transpose()?
        .flatten();
    let tools = match req.tools {
        Some(ts) => ts
            .into_iter()
            .map(parse_responses_tool)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    let tool_choice = req
        .tool_choice
        .map(parse_responses_tool_choice)
        .transpose()?;
    if tool_choice.is_some() && tools.is_empty() {
        return Err(TranslateError::Invalid(
            "`tool_choice` requires at least one tool".into(),
        ));
    }

    Ok(LlmRequest {
        inbound_surface: Surface::Responses,
        model_requested: req.model,
        messages,
        sampling: Sampling {
            temperature: req.temperature,
            top_p: req.top_p,
            max_tokens: req.max_output_tokens,
            // `stop` / `seed` have no Responses equivalent.
            stop: Vec::new(),
            seed: None,
            reasoning_effort,
        },
        tools,
        tool_choice,
        parallel_tool_calls: req.parallel_tool_calls,
        response_format,
        previous_response_id: req.previous_response_id,
        store: req.store,
        stream: req.stream,
    })
}

/// Walk the Responses `input` items into canonical messages. Assistant-side items
/// (`message` role=assistant, `function_call`, `reasoning`) accumulate into one
/// `Assistant` turn (preserving order); a user/system `message` or a
/// `function_call_output` flushes the pending turn first. Mirrors how
/// `render_openai_responses` emits a turn (reasoning, then the message item, then
/// function_call items).
fn parse_responses_input(
    items: Vec<Value>,
    messages: &mut Vec<CanonicalMessage>,
) -> Result<(), TranslateError> {
    let mut pending: Vec<ContentPart> = Vec::new();
    for item in items {
        let obj = item
            .as_object()
            .ok_or_else(|| TranslateError::Invalid("input item must be an object".into()))?;
        // Items are tagged by `type`; a bare `{role, content}` defaults to a
        // `message` (some clients omit the type on plain messages).
        let kind = match obj.get("type") {
            Some(Value::String(s)) => s.as_str(),
            Some(_) => {
                return Err(TranslateError::Invalid(
                    "input item `type` must be a string".into(),
                ))
            }
            None if obj.contains_key("role") => "message",
            None => return Err(TranslateError::Invalid("input item missing `type`".into())),
        };
        match kind {
            "message" => {
                // Fail closed on the message item itself like every other item /
                // content part (I6). `id` / `status` are response metadata carried
                // on an echoed assistant message (as on `function_call`) — allowed
                // and ignored; anything else rejects rather than being dropped.
                reject_extra_keys_responses(
                    obj,
                    &["type", "role", "content", "id", "status"],
                    "message",
                )?;
                let role = obj.get("role").and_then(Value::as_str).ok_or_else(|| {
                    TranslateError::Invalid("message item missing string `role`".into())
                })?;
                let parts = parse_responses_message_content(obj.get("content"))?;
                match role {
                    "assistant" => pending.extend(parts),
                    "user" => {
                        flush_assistant(messages, &mut pending);
                        messages.push(CanonicalMessage {
                            role: Role::User,
                            content: parts,
                        });
                    }
                    "system" | "developer" => {
                        flush_assistant(messages, &mut pending);
                        messages.push(CanonicalMessage {
                            role: Role::System,
                            content: parts,
                        });
                    }
                    other => {
                        return Err(TranslateError::Invalid(format!(
                            "unknown message role `{other}`"
                        )))
                    }
                }
            }
            "function_call" => pending.push(parse_responses_function_call(obj)?),
            "function_call_output" => {
                flush_assistant(messages, &mut pending);
                messages.push(parse_responses_function_call_output(obj)?);
            }
            // A reasoning item is an opaque assistant-side echo — carried verbatim
            // (it may hold provider `encrypted_content`), in turn order.
            "reasoning" => pending.push(ContentPart::Reasoning { raw: item.clone() }),
            // Built-in tool calls/outputs (web_search_call, code_interpreter_call,
            // file_search_call, …) land with the built-in-tools work; until then,
            // reject rather than silently drop (I6).
            other => {
                return Err(TranslateError::Unsupported {
                    surface: "responses",
                    param: format!("input item type `{other}`"),
                })
            }
        }
    }
    flush_assistant(messages, &mut pending);
    Ok(())
}

/// Emit the accumulated assistant-turn parts as one `Assistant` message and clear
/// the accumulator. A no-op when empty.
fn flush_assistant(messages: &mut Vec<CanonicalMessage>, pending: &mut Vec<ContentPart>) {
    if !pending.is_empty() {
        messages.push(CanonicalMessage {
            role: Role::Assistant,
            content: std::mem::take(pending),
        });
    }
}

/// Convert a Responses message `content` (string, or array of `input_text` /
/// `output_text` / `input_image` parts) into canonical parts. Unknown part types
/// and extra keys reject (I6).
fn parse_responses_message_content(
    content: Option<&Value>,
) -> Result<Vec<ContentPart>, TranslateError> {
    match content {
        None => Ok(Vec::new()),
        Some(Value::String(s)) => Ok(vec![ContentPart::Text { text: s.clone() }]),
        Some(Value::Array(parts)) => parts
            .iter()
            .map(parse_responses_content_part)
            .collect::<Result<Vec<_>, _>>(),
        Some(_) => Err(TranslateError::Invalid(
            "message `content` must be a string or an array".into(),
        )),
    }
}

/// Convert one Responses content part. `input_text` / `output_text` → `Text`;
/// `input_image` (URL as a string) → `ImageUrl`. Other types / extra keys reject.
fn parse_responses_content_part(part: &Value) -> Result<ContentPart, TranslateError> {
    let obj = part
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("content part must be an object".into()))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("content part missing string `type`".into()))?;
    match kind {
        "input_text" | "output_text" => {
            reject_extra_keys_responses(obj, &["type", "text"], "content[text]")?;
            let text = obj
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| TranslateError::Invalid("text part missing string `text`".into()))?
                .to_string();
            Ok(ContentPart::Text { text })
        }
        "input_image" => {
            // Responses carries the input-image URL as a plain string under
            // `image_url` (vs Chat's `{image_url:{url}}` object).
            reject_extra_keys_responses(obj, &["type", "image_url"], "content[input_image]")?;
            let url = obj
                .get("image_url")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    TranslateError::Invalid("input_image part missing string `image_url`".into())
                })?
                .to_string();
            Ok(ContentPart::ImageUrl { url })
        }
        other => Err(TranslateError::Unsupported {
            surface: "responses",
            param: format!("content part type `{other}`"),
        }),
    }
}

/// Convert a Responses `function_call` item into a [`ContentPart::ToolUse`]. The
/// correlation id is `call_id` (matching `function_call_output.call_id`); the
/// item-level `id` / `status` are response metadata and ignored.
fn parse_responses_function_call(obj: &Map<String, Value>) -> Result<ContentPart, TranslateError> {
    reject_extra_keys_responses(
        obj,
        &["type", "id", "call_id", "name", "arguments", "status"],
        "function_call",
    )?;
    let id = obj
        .get("call_id")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("function_call missing string `call_id`".into()))?
        .to_string();
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("function_call missing string `name`".into()))?
        .to_string();
    let arguments = responses_arguments_string(obj.get("arguments"))?;
    Ok(ContentPart::ToolUse {
        id,
        name,
        arguments,
    })
}

/// Convert a Responses `function_call_output` item into a `Tool` message carrying
/// a [`ContentPart::ToolResult`].
fn parse_responses_function_call_output(
    obj: &Map<String, Value>,
) -> Result<CanonicalMessage, TranslateError> {
    reject_extra_keys_responses(
        obj,
        &["type", "id", "call_id", "output", "status"],
        "function_call_output",
    )?;
    let tool_call_id = obj
        .get("call_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            TranslateError::Invalid("function_call_output missing string `call_id`".into())
        })?
        .to_string();
    let content = responses_output_string(obj.get("output"))?;
    Ok(CanonicalMessage {
        role: Role::Tool,
        content: vec![ContentPart::ToolResult {
            tool_call_id,
            content,
        }],
    })
}

/// Coerce a Responses tool-call `arguments` value to the canonical JSON *string*.
/// Accepts the native JSON string OR — leniently — a JSON object/value, which is
/// stringified (heterogeneous SDKs send either form; the canonical form is a
/// string, so no fidelity is lost). Absent ⇒ empty string.
fn responses_arguments_string(arguments: Option<&Value>) -> Result<String, TranslateError> {
    match arguments {
        None => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(v) => serde_json::to_string(v).map_err(|e| {
            TranslateError::Invalid(format!("function_call `arguments` not serializable: {e}"))
        }),
    }
}

/// Flatten a `function_call_output` `output` (a string, or an array of output
/// content parts) to the single result string the canonical
/// [`ContentPart::ToolResult`] carries. A non-text content part has no faithful
/// representation and rejects (I6).
fn responses_output_string(output: Option<&Value>) -> Result<String, TranslateError> {
    match output {
        None => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Array(parts)) => {
            let mut s = String::new();
            for p in parts {
                let obj = p.as_object().ok_or_else(|| {
                    TranslateError::Invalid(
                        "function_call_output content part must be an object".into(),
                    )
                })?;
                match obj.get("type").and_then(Value::as_str) {
                    Some("output_text") | Some("input_text") | Some("text") => {
                        // Fail closed like every other content part: reject extra
                        // keys, and require the `text` string rather than silently
                        // appending nothing for a malformed part (I6).
                        reject_extra_keys_responses(
                            obj,
                            &["type", "text"],
                            "function_call_output.content",
                        )?;
                        let t = obj.get("text").and_then(Value::as_str).ok_or_else(|| {
                            TranslateError::Invalid(
                                "function_call_output text part missing string `text`".into(),
                            )
                        })?;
                        s.push_str(t);
                    }
                    _ => {
                        return Err(TranslateError::Unsupported {
                            surface: "responses",
                            param: "non-text content in a function_call_output".into(),
                        })
                    }
                }
            }
            Ok(s)
        }
        Some(_) => Err(TranslateError::Invalid(
            "function_call_output `output` must be a string or an array".into(),
        )),
    }
}

/// Extract `reasoning.effort` (→ canonical `reasoning_effort`). `summary` /
/// `generate_summary` are advisory generation config and dropped (like `stop` /
/// `seed` on the Responses renderer); unknown keys reject (I6).
fn parse_responses_reasoning(r: Value) -> Result<Option<String>, TranslateError> {
    let obj = r
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("`reasoning` must be an object".into()))?;
    reject_extra_keys_responses(obj, &["effort", "summary", "generate_summary"], "reasoning")?;
    match obj.get("effort") {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(TranslateError::Invalid(
            "`reasoning.effort` must be a string".into(),
        )),
    }
}

/// Parse a Responses `text` value (`{format: {...}}`) into the canonical
/// [`ResponseFormat`]. The Responses shape flattens `name` / `description` /
/// `strict` / `schema` directly into `format` (vs Chat's nested `json_schema`).
/// `{type:text}` (or no `format`) is the unconstrained default ⇒ `None`.
fn parse_responses_text_format(text: Value) -> Result<Option<ResponseFormat>, TranslateError> {
    let obj = text
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("`text` must be an object".into()))?;
    reject_extra_keys_responses(obj, &["format"], "text")?;
    let format = match obj.get("format") {
        None => return Ok(None),
        Some(f) => f
            .as_object()
            .ok_or_else(|| TranslateError::Invalid("`text.format` must be an object".into()))?,
    };
    let kind = format
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("`text.format` missing string `type`".into()))?;
    match kind {
        "text" => {
            reject_extra_keys_responses(format, &["type"], "text.format[text]")?;
            Ok(None)
        }
        "json_object" => {
            reject_extra_keys_responses(format, &["type"], "text.format[json_object]")?;
            Ok(Some(ResponseFormat::JsonObject))
        }
        "json_schema" => {
            reject_extra_keys_responses(
                format,
                &["type", "name", "description", "strict", "schema"],
                "text.format",
            )?;
            let name = format
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    TranslateError::Invalid("json_schema text.format missing string `name`".into())
                })?
                .to_string();
            let schema = format.get("schema").cloned().ok_or_else(|| {
                TranslateError::Invalid("json_schema text.format missing `schema`".into())
            })?;
            let strict = match format.get("strict") {
                None => None,
                Some(Value::Bool(b)) => Some(*b),
                Some(_) => {
                    return Err(TranslateError::Invalid(
                        "json_schema text.format `strict` must be a boolean".into(),
                    ))
                }
            };
            let description = match format.get("description") {
                None => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => {
                    return Err(TranslateError::Invalid(
                        "json_schema text.format `description` must be a string".into(),
                    ))
                }
            };
            Ok(Some(ResponseFormat::JsonSchema {
                name,
                description,
                strict,
                schema,
            }))
        }
        other => Err(TranslateError::Unsupported {
            surface: "responses",
            param: format!("text.format type `{other}`"),
        }),
    }
}

/// Parse one flat Responses tool (`{type:function, name, description?, parameters,
/// strict?}`) into a [`CanonicalTool`]. A built-in tool type (web_search, …)
/// rejects (`Unsupported`) — it lands with the built-in-tools work. The
/// structured-output sentinel name is reserved (I6).
fn parse_responses_tool(t: Value) -> Result<CanonicalTool, TranslateError> {
    let obj = t
        .as_object()
        .ok_or_else(|| TranslateError::Invalid("tool must be an object".into()))?;
    match obj.get("type") {
        Some(Value::String(s)) if s == "function" => {}
        Some(Value::String(other)) => {
            return Err(TranslateError::Unsupported {
                surface: "responses",
                param: format!("tool type `{other}`"),
            })
        }
        // Responses tools carry an explicit `type` (the flat shape can't
        // distinguish a function from a built-in without it).
        None => return Err(TranslateError::Invalid("tool missing string `type`".into())),
        Some(_) => {
            return Err(TranslateError::Invalid(
                "tool `type` must be a string".into(),
            ))
        }
    }
    reject_extra_keys_responses(
        obj,
        &["type", "name", "description", "parameters", "strict"],
        "tool",
    )?;
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| TranslateError::Invalid("function tool missing string `name`".into()))?
        .to_string();
    if name == STRUCTURED_OUTPUT_TOOL_NAME {
        return Err(TranslateError::Invalid(format!(
            "`{STRUCTURED_OUTPUT_TOOL_NAME}` is a reserved tool name"
        )));
    }
    let description = match obj.get("description") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            return Err(TranslateError::Invalid(
                "function tool `description` must be a string".into(),
            ))
        }
    };
    let parameters = obj.get("parameters").cloned().unwrap_or_else(|| json!({}));
    let strict = match obj.get("strict") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => {
            return Err(TranslateError::Invalid(
                "function tool `strict` must be a boolean".into(),
            ))
        }
    };
    Ok(CanonicalTool {
        name,
        description,
        parameters,
        strict,
    })
}

/// Parse a Responses `tool_choice` into the canonical [`ToolChoice`]. Accepts the
/// strings `auto`/`none`/`required`, or `{type:function, name}` (FLAT — vs Chat's
/// nested `function.name`). A non-function object type (a built-in tool choice)
/// rejects (`Unsupported`).
fn parse_responses_tool_choice(tc: Value) -> Result<ToolChoice, TranslateError> {
    match &tc {
        Value::String(s) => match s.as_str() {
            "auto" => Ok(ToolChoice::Auto),
            "none" => Ok(ToolChoice::None),
            "required" => Ok(ToolChoice::Required),
            other => Err(TranslateError::Unsupported {
                surface: "responses",
                param: format!("tool_choice `{other}`"),
            }),
        },
        Value::Object(o) => {
            match o.get("type").and_then(Value::as_str) {
                Some("function") => {}
                Some(other) => {
                    return Err(TranslateError::Unsupported {
                        surface: "responses",
                        param: format!("tool_choice type `{other}`"),
                    })
                }
                None => {
                    return Err(TranslateError::Invalid(
                        "object tool_choice must have a string `type`".into(),
                    ))
                }
            }
            reject_extra_keys_responses(o, &["type", "name"], "tool_choice")?;
            let name = o.get("name").and_then(Value::as_str).ok_or_else(|| {
                TranslateError::Invalid("tool_choice function missing string `name`".into())
            })?;
            Ok(ToolChoice::Function(name.to_string()))
        }
        _ => Err(TranslateError::Invalid(
            "tool_choice must be a string or an object".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_string_content_and_basic_params() {
        let body = json!({
            "model": "gpt-5.4",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"}
            ],
            "temperature": 0.2,
            "max_tokens": 64,
            "stream": true
        });
        let req = parse_chat_completions(&body).unwrap();
        assert_eq!(req.inbound_surface, Surface::ChatCompletions);
        assert_eq!(req.model_requested, "gpt-5.4");
        assert_eq!(req.messages.len(), 2);
        assert_eq!(req.messages[0].role, Role::System);
        assert_eq!(
            req.messages[0].content,
            vec![ContentPart::Text {
                text: "be terse".into()
            }]
        );
        assert_eq!(req.sampling.temperature, Some(0.2));
        assert_eq!(req.sampling.max_tokens, Some(64));
        assert!(req.stream);
    }

    #[test]
    fn parses_multipart_content_with_image() {
        let body = json!({
            "model": "m",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is this"},
                    {"type": "image_url", "image_url": {"url": "https://x/y.png"}}
                ]
            }]
        });
        let req = parse_chat_completions(&body).unwrap();
        assert_eq!(
            req.messages[0].content,
            vec![
                ContentPart::Text {
                    text: "what is this".into()
                },
                ContentPart::ImageUrl {
                    url: "https://x/y.png".into()
                },
            ]
        );
    }

    #[test]
    fn developer_role_maps_to_system_and_max_completion_tokens_is_honored() {
        let body = json!({
            "model": "m",
            "messages": [{"role": "developer", "content": "rules"}],
            "max_completion_tokens": 100
        });
        let req = parse_chat_completions(&body).unwrap();
        assert_eq!(req.messages[0].role, Role::System);
        assert_eq!(req.sampling.max_tokens, Some(100));
    }

    #[test]
    fn conflicting_token_limits_reject_equal_or_single_accepted() {
        // Both present with different values → ambiguous → reject, never
        // silently drop one (I6).
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "max_tokens": 100, "max_completion_tokens": 200
            })),
            Err(TranslateError::Invalid(_))
        ));
        // Both present and equal → no ambiguity, no loss → accepted.
        let eq = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}],
            "max_tokens": 100, "max_completion_tokens": 100
        }))
        .unwrap();
        assert_eq!(eq.sampling.max_tokens, Some(100));
    }

    #[test]
    fn reasoning_effort_is_parsed_not_rejected() {
        // It is a typed field, so it is forwarded into the canonical request
        // rather than tripping the unsupported-field guard (I6).
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "reasoning_effort": "high"
        }))
        .unwrap();
        assert_eq!(req.sampling.reasoning_effort.as_deref(), Some("high"));
        // Omitted ⇒ None (and, via skip_serializing_if, absent from the cache key).
        let none = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}]
        }))
        .unwrap();
        assert_eq!(none.sampling.reasoning_effort, None);
    }

    #[test]
    fn stop_accepts_string_or_array() {
        let one = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role":"user","content":"x"}], "stop": "END"
        }))
        .unwrap();
        assert_eq!(one.sampling.stop, vec!["END".to_string()]);
        let many = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role":"user","content":"x"}], "stop": ["A","B"]
        }))
        .unwrap();
        assert_eq!(many.sampling.stop, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn rejects_empty_messages_and_unknown_role() {
        assert!(matches!(
            parse_chat_completions(&json!({"model": "m", "messages": []})),
            Err(TranslateError::Invalid(_))
        ));
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "wizard", "content": "x"}]
            })),
            Err(TranslateError::Invalid(_))
        ));
    }

    #[test]
    fn null_assistant_content_parses_to_empty() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "assistant", "content": null}]
        }))
        .unwrap();
        assert!(req.messages[0].content.is_empty());
    }

    #[test]
    fn rejects_untranslated_fields_instead_of_silently_dropping() {
        // Penalties / logit_bias / logprobs are not translated by this slice;
        // they must surface as Unsupported (I6), not be silently ignored.
        // `response_format` and `tools` are now typed fields (parsed, not
        // rejected), so they are intentionally absent from the rejected set.
        let err = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "tools": [{"type": "function", "function": {"name": "f", "parameters": {}}}],
            "presence_penalty": 0.5,
            "logit_bias": {"1": 2}
        }))
        .unwrap_err();
        match err {
            TranslateError::Unsupported { surface, param } => {
                assert_eq!(surface, "chat_completions");
                // Sorted, comma-joined key list — tools is NOT here (it parsed).
                assert_eq!(param, "logit_bias, presence_penalty");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn parses_response_format_json_object_and_json_schema() {
        // json_object → the bare canonical variant.
        let obj = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_object"}
        }))
        .unwrap();
        assert_eq!(obj.response_format, Some(ResponseFormat::JsonObject));

        // json_schema → name / strict / schema carried verbatim; description optional.
        let schema = json!({"type": "object", "properties": {"k": {"type": "string"}}});
        let js = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "Out", "strict": true, "schema": schema.clone()
            }}
        }))
        .unwrap();
        assert_eq!(
            js.response_format,
            Some(ResponseFormat::JsonSchema {
                name: "Out".into(),
                description: None,
                strict: Some(true),
                schema,
            })
        );

        // `{type:text}` is the unconstrained default ⇒ None (and, via
        // skip_serializing_if, absent from the cache key).
        let text = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "text"}
        }))
        .unwrap();
        assert_eq!(text.response_format, None);

        // Omitted ⇒ None.
        let none = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}]
        }))
        .unwrap();
        assert_eq!(none.response_format, None);
    }

    #[test]
    fn rejects_malformed_response_format() {
        // Unknown `type` → Unsupported (not silently dropped).
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "response_format": {"type": "xml"}
            })),
            Err(TranslateError::Unsupported {
                surface: "chat_completions",
                ..
            })
        ));
        // json_schema missing the required `name` → Invalid.
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "response_format": {"type": "json_schema", "json_schema": {"schema": {}}}
            })),
            Err(TranslateError::Invalid(_))
        ));
        // Extra key inside json_schema → Unsupported (no silent semantic drop).
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "response_format": {"type": "json_schema", "json_schema": {
                    "name": "O", "schema": {}, "bogus": 1
                }}
            })),
            Err(TranslateError::Unsupported {
                surface: "chat_completions",
                ..
            })
        ));
        // Present-but-wrong-typed `strict` (string, not bool) → Invalid, not
        // silently coerced to None (I6 fail-closed — a supported request must
        // not have part of its meaning dropped).
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "response_format": {"type": "json_schema", "json_schema": {
                    "name": "O", "schema": {}, "strict": "true"
                }}
            })),
            Err(TranslateError::Invalid(_))
        ));
        // Present-but-wrong-typed `description` (number, not string) → Invalid.
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "response_format": {"type": "json_schema", "json_schema": {
                    "name": "O", "schema": {}, "description": 7
                }}
            })),
            Err(TranslateError::Invalid(_))
        ));
        // Sanity: correctly-typed optional metadata still parses.
        assert!(parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "O", "schema": {}, "strict": false, "description": "ok"
            }}
        }))
        .is_ok());
    }

    #[test]
    fn honors_n_equal_one_and_rejects_n_greater_than_one() {
        // n:1 (or absent) is honored; the field no longer trips the unknown-field
        // guard now that it is typed.
        assert!(parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}], "n": 1
        }))
        .is_ok());
        // n>1 asks for multiple completions the gateway will not deliver → reject.
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}], "n": 2
            })),
            Err(TranslateError::Unsupported {
                surface: "chat_completions",
                ..
            })
        ));
    }

    #[test]
    fn parses_assistant_tool_calls_and_tool_results() {
        // Assistant `tool_calls` graduate to `ToolUse` content parts (appended
        // after any text); a `tool` message graduates to a `ToolResult` part.
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": "checking",
                    "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]},
                {"role": "tool", "content": "72F", "tool_call_id": "c1"}
            ]
        }))
        .unwrap();
        // Assistant: text part + tool_use part.
        assert_eq!(req.messages[1].role, Role::Assistant);
        assert_eq!(
            req.messages[1].content,
            vec![
                ContentPart::Text {
                    text: "checking".into()
                },
                ContentPart::ToolUse {
                    id: "c1".into(),
                    name: "get_weather".into(),
                    arguments: "{\"city\":\"SF\"}".into(),
                },
            ]
        );
        // Tool result message.
        assert_eq!(req.messages[2].role, Role::Tool);
        assert_eq!(
            req.messages[2].content,
            vec![ContentPart::ToolResult {
                tool_call_id: "c1".into(),
                content: "72F".into(),
            }]
        );
    }

    #[test]
    fn rejects_misplaced_tool_correlation_fields() {
        // A `tool` message without its correlation id can't be rendered → Invalid.
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "tool", "content": "42"}]
            })),
            Err(TranslateError::Invalid(_))
        ));
        // `tool_call_id` on a non-tool message is meaningless → Invalid.
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m",
                "messages": [{"role": "user", "content": "x", "tool_call_id": "c1"}]
            })),
            Err(TranslateError::Invalid(_))
        ));
        // `tool_calls` on a non-assistant message → Invalid.
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m",
                "messages": [{"role": "user", "content": "x",
                    "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "f", "arguments": "{}"}}]}]
            })),
            Err(TranslateError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_unknown_keys_inside_content_parts() {
        // Extra semantics nested inside a supported part (here `image_url.detail`)
        // must reject, not be dropped during canonicalization (I6).
        let img_extra = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "u", "detail": "high"}}
            ]}]
        }))
        .unwrap_err();
        assert!(
            matches!(&img_extra,
                TranslateError::Unsupported { surface: "chat_completions", param }
                    if param == "content[image_url].image_url.detail"),
            "got {img_extra:?}"
        );

        // A `cache_control` key on a text part is likewise rejected.
        let text_extra = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}
            ]}]
        }))
        .unwrap_err();
        assert!(
            matches!(&text_extra,
                TranslateError::Unsupported { surface: "chat_completions", param }
                    if param == "content[text].cache_control"),
            "got {text_extra:?}"
        );
    }

    #[test]
    fn rejects_unsupported_content_part_type() {
        // An unknown content-part type surfaces as Unsupported (not silently
        // kept, and not a generic Invalid).
        let err = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "input_audio", "input_audio": {"data": "..."}}
            ]}]
        }))
        .unwrap_err();
        assert!(
            matches!(&err,
                TranslateError::Unsupported { surface: "chat_completions", param }
                    if param == "content part type `input_audio`"),
            "got {err:?}"
        );
    }

    #[test]
    fn parses_tools_and_tool_choice() {
        let req = parse_chat_completions(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "tools": [{"type": "function", "function": {
                "name": "get_weather", "description": "Get weather",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
            }}],
            "tool_choice": "required",
            "parallel_tool_calls": false
        }))
        .unwrap();
        assert_eq!(req.tools.len(), 1);
        assert_eq!(req.tools[0].name, "get_weather");
        assert_eq!(req.tools[0].description.as_deref(), Some("Get weather"));
        assert_eq!(
            req.tools[0].parameters["properties"]["city"]["type"],
            "string"
        );
        assert_eq!(req.tool_choice, Some(ToolChoice::Required));
        assert_eq!(req.parallel_tool_calls, Some(false));

        // Object tool_choice → a specific function.
        let forced = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}],
            "tools": [{"type": "function", "function": {"name": "f", "parameters": {}}}],
            "tool_choice": {"type": "function", "function": {"name": "f"}}
        }))
        .unwrap();
        assert_eq!(forced.tool_choice, Some(ToolChoice::Function("f".into())));

        // A non-function tool type is rejected (I6), not silently dropped.
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "tools": [{"type": "web_search"}]
            })),
            Err(TranslateError::Unsupported {
                surface: "chat_completions",
                ..
            })
        ));

        // The structured-output emulation sentinel is reserved; a caller tool
        // using it must reject (else the Anthropic response translator would
        // unwrap it as content rather than a tool call).
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "tools": [{"type": "function", "function": {
                    "name": STRUCTURED_OUTPUT_TOOL_NAME, "parameters": {}
                }}]
            })),
            Err(TranslateError::Invalid(_))
        ));

        // `strict` is preserved; an unknown key inside the function object is
        // rejected (I6: the tools path is 1:1, not lossy).
        let strict = parse_chat_completions(&json!({
            "model": "m", "messages": [{"role": "user", "content": "x"}],
            "tools": [{"type": "function", "function": {
                "name": "f", "parameters": {}, "strict": true
            }}]
        }))
        .unwrap();
        assert_eq!(strict.tools[0].strict, Some(true));
        assert!(matches!(
            parse_chat_completions(&json!({
                "model": "m", "messages": [{"role": "user", "content": "x"}],
                "tools": [{"type": "function", "function": {
                    "name": "f", "parameters": {}, "bogus": 1
                }}]
            })),
            Err(TranslateError::Unsupported {
                surface: "chat_completions",
                ..
            })
        ));
    }

    #[test]
    fn rejects_malformed_tool_payloads_fail_closed() {
        let user = json!([{"role": "user", "content": "x"}]);
        let bad = |extra: serde_json::Value| {
            let mut body = json!({"model": "m", "messages": user.clone()});
            for (k, v) in extra.as_object().unwrap() {
                body[k] = v.clone();
            }
            parse_chat_completions(&body)
        };
        // Non-string tool.type is malformed, not "absent".
        assert!(bad(json!({"tools": [{"type": 1, "function": {"name": "f"}}]})).is_err());
        // Non-string tool.function.description rejects.
        assert!(bad(
            json!({"tools": [{"type": "function", "function": {"name": "f", "description": 5}}]})
        )
        .is_err());
        // Object tool_choice without type:function rejects.
        assert!(bad(json!({
            "tools": [{"type": "function", "function": {"name": "f"}}],
            "tool_choice": {"function": {"name": "f"}}
        }))
        .is_err());
        // Extra key on object tool_choice rejects.
        assert!(bad(json!({
            "tools": [{"type": "function", "function": {"name": "f"}}],
            "tool_choice": {"type": "function", "function": {"name": "f"}, "x": 1}
        }))
        .is_err());
        // Assistant tool_call with an unknown function key rejects.
        assert!(bad(json!({
            "messages": [{"role": "assistant", "content": null, "tool_calls": [
                {"id": "c1", "type": "function",
                    "function": {"name": "f", "arguments": "{}", "bogus": 1}}
            ]}]
        }))
        .is_err());
        // tool_call arguments must be the JSON *string*; a non-string (object)
        // value is malformed and must reject, not be silently stripped.
        assert!(bad(json!({
            "messages": [{"role": "assistant", "content": null, "tool_calls": [
                {"id": "c1", "type": "function",
                    "function": {"name": "f", "arguments": {"city": "SF"}}}
            ]}]
        }))
        .is_err());
        // A present non-string tool_call.type is malformed (not "absent").
        assert!(bad(json!({
            "messages": [{"role": "assistant", "content": null, "tool_calls": [
                {"id": "c1", "type": 1,
                    "function": {"name": "f", "arguments": "{}"}}
            ]}]
        }))
        .is_err());
        // tool_choice with no tools is an impossible constraint → reject.
        assert!(matches!(
            bad(json!({"tool_choice": "required"})),
            Err(TranslateError::Invalid(_))
        ));
    }

    // ---- Responses inbound parser ----------------------------------------

    #[test]
    fn parses_responses_string_input_and_params() {
        let req = parse_responses(&json!({
            "model": "gpt-5.4",
            "instructions": "be terse",
            "input": "hi",
            "temperature": 0.2,
            "max_output_tokens": 64,
            "stream": true
        }))
        .unwrap();
        assert_eq!(req.inbound_surface, Surface::Responses);
        assert_eq!(req.model_requested, "gpt-5.4");
        // instructions → leading System; string input → a User message.
        assert_eq!(req.messages.len(), 2);
        assert_eq!(req.messages[0].role, Role::System);
        assert_eq!(
            req.messages[0].content,
            vec![ContentPart::Text {
                text: "be terse".into()
            }]
        );
        assert_eq!(req.messages[1].role, Role::User);
        assert_eq!(
            req.messages[1].content,
            vec![ContentPart::Text { text: "hi".into() }]
        );
        assert_eq!(req.sampling.temperature, Some(0.2));
        assert_eq!(req.sampling.max_tokens, Some(64));
        assert!(req.stream);
    }

    #[test]
    fn parses_responses_message_items_with_roles_and_image() {
        let req = parse_responses(&json!({
            "model": "m",
            "input": [
                {"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": "what is this"},
                    {"type": "input_image", "image_url": "https://x/y.png"}
                ]},
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "a cat"}
                ]}
            ]
        }))
        .unwrap();
        assert_eq!(req.messages[0].role, Role::User);
        assert_eq!(
            req.messages[0].content,
            vec![
                ContentPart::Text {
                    text: "what is this".into()
                },
                ContentPart::ImageUrl {
                    url: "https://x/y.png".into()
                },
            ]
        );
        assert_eq!(req.messages[1].role, Role::Assistant);
        assert_eq!(
            req.messages[1].content,
            vec![ContentPart::Text {
                text: "a cat".into()
            }]
        );
        // A bare `{role, content}` (no `type`) defaults to a message.
        let bare = parse_responses(&json!({
            "model": "m",
            "input": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();
        assert_eq!(
            bare.messages[0].content,
            vec![ContentPart::Text {
                text: "hello".into()
            }]
        );
        // A message item is fail-closed: echoed response metadata (`id` / `status`)
        // is allowed and ignored...
        assert!(parse_responses(&json!({
            "model": "m",
            "input": [{"type": "message", "id": "msg_1", "status": "completed",
                "role": "assistant", "content": [{"type": "output_text", "text": "hi"}]}]
        }))
        .is_ok());
        // ...but an unknown key on the message item rejects (surface responses),
        // rather than being silently dropped.
        assert!(matches!(
            parse_responses(&json!({
                "model": "m",
                "input": [{"type": "message", "role": "user", "content": "hi", "bogus": 1}]
            })),
            Err(TranslateError::Unsupported {
                surface: "responses",
                ..
            })
        ));
    }

    #[test]
    fn parses_responses_function_call_and_output_grouping() {
        // A reasoning + function_call (assistant-side) accumulate into ONE
        // Assistant turn; the function_call_output flushes it into its own Tool
        // message. Mirrors how the renderer emits a turn.
        let req = parse_responses(&json!({
            "model": "m",
            "input": [
                {"type": "message", "role": "user", "content": "weather?"},
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "checking"}
                ]},
                {"type": "function_call", "call_id": "c1", "name": "get_weather",
                    "arguments": "{\"city\":\"SF\"}", "id": "fc_1", "status": "completed"},
                {"type": "function_call_output", "call_id": "c1", "output": "72F"}
            ]
        }))
        .unwrap();
        assert_eq!(req.messages[0].role, Role::User);
        // Assistant turn: text part + tool_use part (call_id → ToolUse.id).
        assert_eq!(req.messages[1].role, Role::Assistant);
        assert_eq!(
            req.messages[1].content,
            vec![
                ContentPart::Text {
                    text: "checking".into()
                },
                ContentPart::ToolUse {
                    id: "c1".into(),
                    name: "get_weather".into(),
                    arguments: "{\"city\":\"SF\"}".into(),
                },
            ]
        );
        // function_call_output → its own Tool message.
        assert_eq!(req.messages[2].role, Role::Tool);
        assert_eq!(
            req.messages[2].content,
            vec![ContentPart::ToolResult {
                tool_call_id: "c1".into(),
                content: "72F".into(),
            }]
        );
    }

    #[test]
    fn responses_reasoning_item_carried_opaquely() {
        // A reasoning input item is carried verbatim as ContentPart::Reasoning,
        // in order on the assistant turn — never interpreted (it may hold the
        // encrypted_content the model needs to continue a stateless loop).
        let raw = json!({
            "type": "reasoning", "id": "rs_1", "summary": [],
            "encrypted_content": "OPAQUE=="
        });
        let req = parse_responses(&json!({
            "model": "m",
            "input": [
                {"type": "message", "role": "user", "content": "go"},
                raw.clone(),
                {"type": "function_call", "call_id": "c1", "name": "f", "arguments": "{}"}
            ]
        }))
        .unwrap();
        assert_eq!(req.messages[1].role, Role::Assistant);
        assert_eq!(
            req.messages[1].content,
            vec![
                ContentPart::Reasoning { raw },
                ContentPart::ToolUse {
                    id: "c1".into(),
                    name: "f".into(),
                    arguments: "{}".into(),
                },
            ]
        );
    }

    #[test]
    fn parses_responses_tools_tool_choice_and_text_format() {
        let req = parse_responses(&json!({
            "model": "m",
            "input": "x",
            "tools": [{"type": "function", "name": "get_weather", "description": "Get weather",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
                "strict": true}],
            "tool_choice": {"type": "function", "name": "get_weather"},
            "parallel_tool_calls": false,
            "text": {"format": {"type": "json_schema", "name": "Out", "strict": true,
                "schema": {"type": "object"}}}
        }))
        .unwrap();
        assert_eq!(req.tools.len(), 1);
        assert_eq!(req.tools[0].name, "get_weather");
        assert_eq!(req.tools[0].description.as_deref(), Some("Get weather"));
        assert_eq!(req.tools[0].strict, Some(true));
        assert_eq!(
            req.tool_choice,
            Some(ToolChoice::Function("get_weather".into()))
        );
        assert_eq!(req.parallel_tool_calls, Some(false));
        assert_eq!(
            req.response_format,
            Some(ResponseFormat::JsonSchema {
                name: "Out".into(),
                description: None,
                strict: Some(true),
                schema: json!({"type": "object"}),
            })
        );
        // String tool_choice forms.
        let auto = parse_responses(&json!({
            "model": "m", "input": "x",
            "tools": [{"type": "function", "name": "f", "parameters": {}}],
            "tool_choice": "required"
        }))
        .unwrap();
        assert_eq!(auto.tool_choice, Some(ToolChoice::Required));
        // text.format json_object and the unconstrained text default.
        let obj = parse_responses(&json!({
            "model": "m", "input": "x", "text": {"format": {"type": "json_object"}}
        }))
        .unwrap();
        assert_eq!(obj.response_format, Some(ResponseFormat::JsonObject));
        let plain = parse_responses(&json!({
            "model": "m", "input": "x", "text": {"format": {"type": "text"}}
        }))
        .unwrap();
        assert_eq!(plain.response_format, None);
    }

    #[test]
    fn responses_reasoning_effort_and_previous_response_id_and_store() {
        let req = parse_responses(&json!({
            "model": "m", "input": "x",
            "reasoning": {"effort": "high", "summary": "auto"},
            "previous_response_id": "resp_abc",
            "store": true
        }))
        .unwrap();
        // reasoning.effort → sampling.reasoning_effort; summary dropped (advisory).
        assert_eq!(req.sampling.reasoning_effort.as_deref(), Some("high"));
        // previous_response_id AND store are both carried and forwarded by the
        // Responses renderer — a `store:false` opt-out must be honored, not dropped.
        assert_eq!(req.previous_response_id.as_deref(), Some("resp_abc"));
        assert_eq!(req.store, Some(true));
        let rendered = crate::outbound::render_openai_responses(&req, "m").unwrap();
        assert_eq!(rendered["previous_response_id"], "resp_abc");
        assert_eq!(rendered["store"], true);
        // store:false is carried and forwarded verbatim (the privacy opt-out is
        // honored, never silently dropped to the default-on backend).
        let no_store = parse_responses(&json!({
            "model": "m", "input": "x", "store": false
        }))
        .unwrap();
        assert_eq!(no_store.store, Some(false));
        assert_eq!(
            crate::outbound::render_openai_responses(&no_store, "m").unwrap()["store"],
            false
        );
    }

    #[test]
    fn responses_lenient_arguments_object_coerced_to_string() {
        // A heterogeneous SDK may send `arguments` as a JSON object; it is
        // stringified to the canonical form (no fidelity loss).
        let req = parse_responses(&json!({
            "model": "m",
            "input": [
                {"type": "function_call", "call_id": "c1", "name": "f",
                    "arguments": {"city": "SF"}}
            ]
        }))
        .unwrap();
        match &req.messages[0].content[0] {
            ContentPart::ToolUse { arguments, .. } => {
                assert_eq!(
                    serde_json::from_str::<Value>(arguments).unwrap(),
                    json!({"city": "SF"})
                );
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn responses_rejects_builtin_tools_unknown_fields_and_items() {
        // A built-in tool definition is Unsupported (lands with #4), not dropped.
        assert!(matches!(
            parse_responses(&json!({
                "model": "m", "input": "x", "tools": [{"type": "web_search"}]
            })),
            Err(TranslateError::Unsupported {
                surface: "responses",
                ..
            })
        ));
        // Unknown top-level field rejects (I6).
        let err = parse_responses(&json!({
            "model": "m", "input": "x", "include": ["reasoning.encrypted_content"], "metadata": {}
        }))
        .unwrap_err();
        assert!(
            matches!(&err, TranslateError::Unsupported { surface: "responses", param }
                if param == "include, metadata"),
            "got {err:?}"
        );
        // A built-in tool-call input item is Unsupported (lands with #4).
        assert!(matches!(
            parse_responses(&json!({
                "model": "m", "input": [{"type": "web_search_call", "id": "ws_1"}]
            })),
            Err(TranslateError::Unsupported {
                surface: "responses",
                ..
            })
        ));
        // The structured-output sentinel name is reserved.
        assert!(matches!(
            parse_responses(&json!({
                "model": "m", "input": "x",
                "tools": [{"type": "function", "name": STRUCTURED_OUTPUT_TOOL_NAME, "parameters": {}}]
            })),
            Err(TranslateError::Invalid(_))
        ));
        // Empty request (no input, no instructions) rejects.
        assert!(matches!(
            parse_responses(&json!({"model": "m"})),
            Err(TranslateError::Invalid(_))
        ));
    }

    #[test]
    fn responses_nested_rejections_report_the_responses_surface() {
        // A malformed NESTED Responses structure must attribute its fail-closed
        // error to the Responses surface, not Chat — `reject_extra_keys` is shared
        // across both parsers, so the Responses helpers go through the
        // `_responses` wrapper. Regression for the hardcoded "chat_completions".
        let err = parse_responses(&json!({
            "model": "m",
            "input": [{"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "hi", "bogus": 1}
            ]}]
        }))
        .unwrap_err();
        assert!(
            matches!(&err, TranslateError::Unsupported { surface: "responses", param }
                if param == "content[text].bogus"),
            "got {err:?}"
        );
        // Likewise for a flat tool and for text.format with an unknown nested key.
        for body in [
            json!({"model": "m", "input": "x",
                "tools": [{"type": "function", "name": "f", "parameters": {}, "bogus": 1}]}),
            json!({"model": "m", "input": "x",
                "text": {"format": {"type": "json_object", "bogus": 1}}}),
        ] {
            assert!(
                matches!(
                    parse_responses(&body),
                    Err(TranslateError::Unsupported {
                        surface: "responses",
                        ..
                    })
                ),
                "expected responses-surface Unsupported for {body}"
            );
        }
    }

    #[test]
    fn responses_function_call_output_array_fails_closed() {
        // An array `output` concatenates its text parts...
        let ok = parse_responses(&json!({
            "model": "m",
            "input": [{"type": "function_call_output", "call_id": "c1", "output": [
                {"type": "output_text", "text": "72"},
                {"type": "output_text", "text": "F"}
            ]}]
        }))
        .unwrap();
        assert_eq!(
            ok.messages[0].content,
            vec![ContentPart::ToolResult {
                tool_call_id: "c1".into(),
                content: "72F".into(),
            }]
        );
        // ...but each part is fail-closed: an extra key rejects (surface responses)...
        assert!(matches!(
            parse_responses(&json!({"model": "m", "input": [
                {"type": "function_call_output", "call_id": "c1", "output": [
                    {"type": "output_text", "text": "x", "bogus": 1}]}]})),
            Err(TranslateError::Unsupported {
                surface: "responses",
                ..
            })
        ));
        // ...and a text part missing its `text` string rejects (no silent drop).
        assert!(matches!(
            parse_responses(&json!({"model": "m", "input": [
                {"type": "function_call_output", "call_id": "c1", "output": [
                    {"type": "output_text"}]}]})),
            Err(TranslateError::Invalid(_))
        ));
    }

    /// Build a Responses-surface canonical request for the round-trip corpus.
    fn responses_canon(messages: Vec<CanonicalMessage>) -> LlmRequest {
        LlmRequest {
            inbound_surface: Surface::Responses,
            model_requested: "m".into(),
            messages,
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

    /// Assert a canonical request survives `render_openai_responses` → bytes →
    /// `parse_responses` unchanged. This pins the parser as the exact inverse of
    /// the renderer for the supported subset (the renderer is the authority on
    /// the wire shape).
    fn assert_round_trip(req: LlmRequest) {
        let model = req.model_requested.clone();
        let rendered = crate::outbound::render_openai_responses(&req, &model).unwrap();
        let parsed = parse_responses(&rendered)
            .unwrap_or_else(|e| panic!("re-parse failed: {e}; rendered = {rendered}"));
        assert_eq!(parsed, req, "round-trip mismatch; rendered = {rendered}");
    }

    #[test]
    fn responses_render_parse_round_trips() {
        let text = |t: &str| ContentPart::Text { text: t.into() };
        let user = |t: &str| CanonicalMessage {
            role: Role::User,
            content: vec![text(t)],
        };

        // Text only, with a leading system instruction.
        assert_round_trip(responses_canon(vec![
            CanonicalMessage {
                role: Role::System,
                content: vec![text("be terse")],
            },
            user("hi"),
        ]));

        // A user image + an assistant text turn.
        assert_round_trip(responses_canon(vec![
            CanonicalMessage {
                role: Role::User,
                content: vec![
                    text("describe"),
                    ContentPart::ImageUrl {
                        url: "https://x/y.png".into(),
                    },
                ],
            },
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![text("a cat")],
            },
        ]));

        // A full tool turn: assistant text + tool_use, then a tool result, with a
        // reasoning echo (verbatim) leading the assistant turn.
        assert_round_trip(responses_canon(vec![
            user("weather?"),
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![
                    ContentPart::Reasoning {
                        raw: json!({"type": "reasoning", "id": "rs_1", "summary": []}),
                    },
                    text("checking"),
                    ContentPart::ToolUse {
                        id: "c1".into(),
                        name: "get_weather".into(),
                        arguments: "{\"city\":\"SF\"}".into(),
                    },
                ],
            },
            CanonicalMessage {
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    tool_call_id: "c1".into(),
                    content: "72F".into(),
                }],
            },
        ]));

        // A tool-call-only assistant turn (no text → no message item emitted).
        assert_round_trip(responses_canon(vec![
            user("go"),
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::ToolUse {
                    id: "c2".into(),
                    name: "f".into(),
                    arguments: "{}".into(),
                }],
            },
        ]));

        // Sampling, tools, tool_choice, structured output, parallel_tool_calls,
        // previous_response_id — every forwarded scalar.
        let mut req = responses_canon(vec![user("x")]);
        req.sampling.temperature = Some(0.3);
        req.sampling.top_p = Some(0.9);
        req.sampling.max_tokens = Some(128);
        req.sampling.reasoning_effort = Some("high".into());
        req.tools = vec![CanonicalTool {
            name: "f".into(),
            description: Some("d".into()),
            parameters: json!({"type": "object"}),
            strict: Some(true),
        }];
        req.tool_choice = Some(ToolChoice::Function("f".into()));
        req.parallel_tool_calls = Some(true);
        req.response_format = Some(ResponseFormat::JsonSchema {
            name: "Out".into(),
            description: Some("schema".into()),
            strict: Some(false),
            schema: json!({"type": "object", "properties": {}}),
        });
        req.previous_response_id = Some("resp_xyz".into());
        req.store = Some(false);
        req.stream = true;
        assert_round_trip(req);
    }
}
