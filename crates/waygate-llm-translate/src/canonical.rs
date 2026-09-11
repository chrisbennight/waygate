//! The provider-neutral canonical request model. The OpenAI-shaped client
//! surfaces (`/v1/chat/completions` and `/v1/responses`) normalize *into* this,
//! and the per-provider outbound adapters render *from* it — so provider
//! divergence lives only at the edges (design invariant I6).

use serde::{Deserialize, Serialize};

/// Which OpenAI-shaped client surface a request arrived on. `ChatCompletions`
/// and `Responses` are chat surfaces (they normalize into [`LlmRequest`]);
/// `Embeddings` is the `/v1/embeddings` operation, which carries its own
/// canonical request ([`crate::EmbeddingsRequest`]) rather than an `LlmRequest`.
/// The value is recorded on the [`crate::InferenceRecord`] so the usage ledger's
/// `inbound_surface` distinguishes chat, embeddings, image generation, and
/// image editing calls. Images carry a separate [`crate::images::ImagesRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    ChatCompletions,
    Responses,
    Embeddings,
    ImagesGenerations,
    ImagesEdits,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat_completions",
            Self::Responses => "responses",
            Self::Embeddings => "embeddings",
            Self::ImagesGenerations => "images_generations",
            Self::ImagesEdits => "images_edits",
        }
    }
}

/// The provider-native protocol an outbound request is rendered into. Each
/// provider declares its native surface; a request whose inbound surface
/// differs round-trips through the canonical model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    OpenAiResponses,
    OpenAiChat,
    AnthropicMessages,
    Gemini,
}

impl UpstreamProtocol {
    /// Stable name of the upstream wire API this protocol speaks — the value the
    /// model catalog records in `llm_models.upstream_api` and the dashboard shows
    /// in the "Upstream API" column. Distinct from [`Surface::as_str`], which
    /// names the *inbound* client surface; this names the *outbound* one.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::OpenAiResponses => "responses",
            Self::OpenAiChat => "chat_completions",
            Self::AnthropicMessages => "messages",
            Self::Gemini => "generate_content",
        }
    }
}

/// Canonical message role. OpenAI's `developer` role maps to `System`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// One piece of message content. Extensible (audio/file parts land with the
/// providers that support them).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text {
        text: String,
    },
    ImageUrl {
        url: String,
    },
    /// An assistant-issued function/tool call. Carried on an `Assistant` message
    /// alongside any text. `arguments` is the JSON *string* the provider emitted
    /// (OpenAI's native form — kept verbatim for lossless round-trip; the
    /// Anthropic/Gemini renderers parse it into an object).
    ToolUse {
        id: String,
        name: String,
        arguments: String,
    },
    /// A tool-result, carried on a `Tool` message. `tool_call_id` correlates it
    /// with the [`ContentPart::ToolUse`] it answers; `content` is the result text.
    ToolResult {
        tool_call_id: String,
        content: String,
    },
    /// A prior-turn **reasoning** item echoed back in a Responses-surface
    /// request's `input` (a stateless agent loop replaying the model's own
    /// output). Carried opaquely on an `Assistant` message, in order with the
    /// `ToolUse`/`Text` parts of that turn, and **never interpreted** — the raw
    /// item (which may include provider `encrypted_content` the model needs to
    /// continue) is round-tripped verbatim. The OpenAI-Responses renderer emits
    /// it back as a `reasoning` input item; every other renderer drops it (it
    /// has no Chat/Anthropic/Gemini equivalent and the encrypted payload is
    /// meaningless off its origin provider). Only ever produced by the Responses
    /// inbound parser; the Chat parser never emits it.
    Reasoning {
        raw: serde_json::Value,
    },
}

/// A single conversation message in canonical form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMessage {
    pub role: Role,
    pub content: Vec<ContentPart>,
}

/// Sampling / generation parameters, normalized across surfaces.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sampling {
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    pub seed: Option<i64>,
    /// Reasoning depth for reasoning models (OpenAI `reasoning_effort`:
    /// `minimal` / `low` / `medium` / `high`). Forwarded verbatim — the provider
    /// is the authority on accepted values. `skip_serializing_if` keeps the
    /// completion-cache canonical key byte-identical for requests that omit it,
    /// so adding this field does not invalidate existing cache entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
}

/// Structured-output constraint, normalized across surfaces (OpenAI Chat
/// `response_format`, Responses `text.format`, Gemini `responseMimeType` /
/// `responseJsonSchema`). The plain `{type:"text"}` form is the unconstrained
/// default and normalizes to `None` on [`LlmRequest::response_format`] rather
/// than a variant here — emitting nothing is the faithful rendering of "no
/// constraint", so the canonical model only carries the *constraining* forms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseFormat {
    /// Free-form JSON object (`{"type":"json_object"}`).
    JsonObject,
    /// JSON conforming to a named schema (`{"type":"json_schema", …}`).
    JsonSchema {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Strict schema adherence. Forwarded verbatim — the provider is the
        /// authority on the accepted/default value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
        /// The JSON Schema the output must satisfy.
        schema: serde_json::Value,
    },
}

/// A function/tool the model may call. Only function tools are modeled (the
/// providers' other built-in tool types — web search, code interpreter, … — are
/// rejected at the inbound boundary). `parameters` is the JSON Schema for the
/// function's arguments, rendered to each provider's own field name
/// (OpenAI `function.parameters`, Anthropic `input_schema`, Gemini
/// `parametersJsonSchema`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parameters: serde_json::Value,
    /// Strict schema adherence for the function's arguments (OpenAI Chat /
    /// Responses `function.strict`). Forwarded where the provider supports it;
    /// Anthropic/Gemini have no per-tool equivalent and drop it (advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

/// How the model should choose among the provided tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolChoice {
    /// Model decides whether to call a tool (OpenAI/Responses `auto`,
    /// Anthropic `{type:auto}`, Gemini `AUTO`).
    Auto,
    /// Model must not call a tool (`none` / `{type:none}` / `NONE`).
    None,
    /// Model must call some tool (`required` / `{type:any}` / `ANY`).
    Required,
    /// Model must call this specific function.
    Function(String),
}

/// Canonical inbound request, normalized from a client surface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmRequest {
    pub inbound_surface: Surface,
    pub model_requested: String,
    pub messages: Vec<CanonicalMessage>,
    #[serde(default)]
    pub sampling: Sampling,
    /// Function/tool definitions the model may call. Empty ⇒ no tools;
    /// `skip_serializing_if` keeps the completion-cache canonical key
    /// byte-identical for requests that omit it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<CanonicalTool>,
    /// Tool-selection constraint. `None` ⇒ provider default (auto when tools are
    /// present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Whether the model may emit multiple tool calls in one turn. `None` ⇒
    /// provider default. Forwarded where the provider supports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    /// Structured-output constraint. `None` ⇒ unconstrained text (the default);
    /// `skip_serializing_if` keeps the completion-cache canonical key
    /// byte-identical for requests that omit it, so adding this field does not
    /// invalidate existing cache entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// Responses-surface server-side conversation handle (`previous_response_id`).
    /// `None` for Chat Completions (which has no equivalent) and for a Responses
    /// request that omits it. Carried so the OpenAI-Responses renderer can forward
    /// it — the backend's own store provides continuity; the gateway stores
    /// nothing (invariant I9). The capability gate rejects it for a non-Responses
    /// route, where it is meaningless. `skip_serializing_if` keeps the
    /// completion-cache canonical key byte-identical for requests that omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// Responses-surface server-side persistence flag (`store`). `None` for Chat
    /// Completions and for a Responses request that omits it. **Forwarded** to the
    /// OpenAI-Responses renderer so a `store:false` opt-out is honored by the
    /// backend (which persists by default) — dropping it would silently store the
    /// response against the client's explicit wish. Non-Responses backends do not
    /// persist responses at all, so the flag has no effect there and is dropped
    /// (`store:false` is satisfied trivially; `store:true` retrieval is gated by
    /// the `previous_response_id` rejection). `skip_serializing_if` keeps the
    /// completion-cache canonical key byte-identical for requests that omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(default)]
    pub stream: bool,
}
