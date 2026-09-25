//! Streaming response handling for the inference plane: fold a provider's SSE
//! `data:` frames into the terminal [`InferenceRecord`] while translating them
//! to the OpenAI `chat.completion.chunk` shape the gateway streams to clients.
//! The [`StreamTranslator`] selects a per-provider variant from the base
//! record's `upstream_protocol` — OpenAI/OpenRouter frames pass through 1:1
//! ([`OpenAiChatStreamAggregator`]), while Anthropic Messages, Gemini
//! `streamGenerateContent`, and OpenAI Responses events are translated — sharing
//! the unary extractors' usage / finish-reason parsing so the unary and
//! streaming surfaces agree on one token-accounting contract.
//!
//! It captures **metadata only** (invariant I9) — never the streamed content
//! deltas — and never fabricates: a class the provider did not report stays
//! `None`. Token counts come from the terminal usage chunk (present because the
//! request set `stream_options.include_usage`); `model`/`id`/
//! `system_fingerprint` from the first chunk that carries them; `finish_reason`
//! from the chunk that ends the turn.
//!
//! The aggregator is fed the raw `data:` payload string (the provider transport
//! lives in `waygate-llm-providers`); it ignores the `[DONE]` sentinel and any
//! non-JSON keepalive rather than fabricating from unparseable data.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::canonical::UpstreamProtocol;
use crate::outbound::STRUCTURED_OUTPUT_TOOL_NAME;
use crate::record::{FinishReason, InferenceRecord};
use crate::response::{
    anthropic_stop_reason_to_openai, anthropic_token_usage_from, finish_reason_openai_str,
    gemini_finish_reason_to_openai, gemini_token_usage_from, normalize_anthropic_stop_reason,
    normalize_finish_reason, normalize_gemini_finish_reason, responses_finish,
    responses_token_usage_from, str_field, token_usage_from, u64_field,
};

/// Folds OpenAI chat streaming chunks into an [`InferenceRecord`]. Build from
/// the pre-dispatch base record (provider / credential / requested model /
/// surface), [`observe_data`](Self::observe_data) each SSE frame as it streams,
/// then [`finish`](Self::finish) at stream close.
pub struct OpenAiChatStreamAggregator {
    record: InferenceRecord,
}

impl OpenAiChatStreamAggregator {
    /// Start from the baseline record stamped before dispatch.
    pub fn new(mut base: InferenceRecord) -> Self {
        base.upstream_protocol = UpstreamProtocol::OpenAiChat;
        Self { record: base }
    }

    /// Observe one SSE `data:` payload. The `[DONE]` sentinel, blank frames, and
    /// any non-JSON keepalive are ignored (no fabrication from unparseable
    /// data); a JSON chunk updates the in-progress record.
    pub fn observe_data(&mut self, data: &str) {
        let trimmed = data.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            return;
        }
        if let Ok(chunk) = serde_json::from_str::<Value>(trimmed) {
            self.observe(&chunk);
        }
    }

    /// Observe one already-parsed `chat.completion.chunk` object.
    pub fn observe(&mut self, chunk: &Value) {
        // Identity fields: take the first non-empty value seen. Later chunks
        // repeat them, so first-wins keeps a stable value.
        if self.record.model_served.is_none() {
            self.record.model_served = str_field(chunk, "model");
        }
        if self.record.upstream_request_id.is_none() {
            self.record.upstream_request_id = str_field(chunk, "id");
        }
        if self.record.system_fingerprint.is_none() {
            self.record.system_fingerprint = str_field(chunk, "system_fingerprint");
        }

        // Usage: only the terminal chunk (stream_options.include_usage) carries
        // a non-null usage object; earlier chunks have `usage: null`.
        if let Some(usage) = chunk.get("usage").filter(|u| !u.is_null()) {
            self.record.usage = token_usage_from(usage);
            self.record.provider_prompt_cache = self.record.usage.cached_read.map(|c| c > 0);
        }

        // Outcome from the choice that ends the turn.
        if let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        {
            if let Some(reason) = str_field(choice, "finish_reason") {
                if reason == "content_filter" {
                    self.record.refusal = true;
                }
                self.record.finish_reason = Some(normalize_finish_reason(&reason));
            }
            // Structured-outputs refusal can stream in the delta.
            if choice
                .get("delta")
                .and_then(|d| d.get("refusal"))
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                self.record.refusal = true;
            }
        }
    }

    /// Finalize and return the accumulated record.
    pub fn finish(self) -> InferenceRecord {
        self.record
    }

    /// A clone of the record accumulated so far, without consuming the
    /// aggregator. Used by the streaming usage-ledger writer at the `[DONE]`
    /// frame, where the aggregator must keep living inside the stream state.
    pub fn snapshot(&self) -> InferenceRecord {
        self.record.clone()
    }
}

/// The result of feeding one provider SSE `data:` frame to a [`StreamTranslator`]:
/// the OpenAI chat-completion-chunk frames to forward to the client (0..N — a
/// provider event may map to no client frame, e.g. an Anthropic `ping`, or to
/// several), and whether the logical stream has ended.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamStep {
    /// OpenAI-shaped client frames to emit, in order. A `Value::String("[DONE]")`
    /// element is the OpenAI terminal sentinel (the egress renders it as
    /// `data: [DONE]`).
    pub chunks: Vec<Value>,
    /// True once this frame ended the logical stream: the `[DONE]` sentinel for
    /// OpenAI, the `message_stop` event for Anthropic.
    pub done: bool,
}

/// Folds a provider's streamed SSE frames into the terminal [`InferenceRecord`]
/// AND translates them to the OpenAI chat-completions-chunk shape the gateway's
/// `/v1/chat/completions` route streams to clients — regardless of upstream
/// provider. OpenAI/OpenRouter frames pass through 1:1; Anthropic Messages
/// events are translated (and end on `message_stop`, re-emitted as `[DONE]`);
/// Gemini `streamGenerateContent` events are translated (and end on the frame
/// carrying `finishReason`, re-emitted as `[DONE]` — Gemini sends no sentinel);
/// OpenAI Responses events are translated (and end on `response.completed` /
/// `response.incomplete`, re-emitted as `[DONE]` — Responses sends no sentinel).
///
/// Built from the pre-dispatch base record, whose `upstream_protocol` selects
/// the variant — so no extra protocol plumbing is needed at the call site.
pub enum StreamTranslator {
    OpenAi(OpenAiChatStreamAggregator),
    Anthropic(AnthropicStreamTranslator),
    Gemini(GeminiStreamTranslator),
    Responses(ResponsesStreamTranslator),
}

impl StreamTranslator {
    /// Choose the translator matching the call's upstream protocol (carried on
    /// the pre-dispatch base record).
    pub fn for_record(base: InferenceRecord) -> Self {
        match base.upstream_protocol {
            UpstreamProtocol::AnthropicMessages => {
                Self::Anthropic(AnthropicStreamTranslator::new(base))
            }
            UpstreamProtocol::Gemini => Self::Gemini(GeminiStreamTranslator::new(base)),
            UpstreamProtocol::OpenAiResponses => {
                Self::Responses(ResponsesStreamTranslator::new(base))
            }
            _ => Self::OpenAi(OpenAiChatStreamAggregator::new(base)),
        }
    }

    /// Observe one provider `data:` payload: update the in-progress record and
    /// return the client frames to forward plus the terminal flag.
    pub fn push(&mut self, data: &str) -> StreamStep {
        match self {
            Self::OpenAi(agg) => {
                // The client already speaks OpenAI: fold for metering and forward
                // the frame verbatim (1:1), preserving the prior passthrough.
                agg.observe_data(data);
                let trimmed = data.trim();
                let done = trimmed == "[DONE]";
                let event = serde_json::from_str::<Value>(trimmed)
                    .unwrap_or_else(|_| Value::String(data.to_string()));
                StreamStep {
                    chunks: vec![event],
                    done,
                }
            }
            Self::Anthropic(t) => t.push(data),
            Self::Gemini(t) => t.push(data),
            Self::Responses(t) => t.push(data),
        }
    }

    /// A clone of the record accumulated so far (for the close-time usage row).
    pub fn snapshot(&self) -> InferenceRecord {
        match self {
            Self::OpenAi(a) => a.snapshot(),
            Self::Anthropic(t) => t.snapshot(),
            Self::Gemini(t) => t.snapshot(),
            Self::Responses(t) => t.snapshot(),
        }
    }
}

/// Per-Anthropic-content-block state for a `tool_use` block being streamed.
struct AnthropicToolBlock {
    /// OpenAI `delta.tool_calls[].index` for this call.
    tool_index: u64,
    /// True when this is the structured-output emulation's forced tool: its
    /// streamed `input_json_delta` IS the JSON answer, routed to `delta.content`
    /// (not `delta.tool_calls`), and the turn finishes as a normal `stop`.
    emulated: bool,
}

/// Translates an Anthropic Messages SSE event stream into OpenAI
/// chat-completion-chunk client frames while folding usage / finish-reason into
/// the [`InferenceRecord`]. Captures **metadata only** (I9) — content text is
/// forwarded to the client but never retained in the record.
///
/// Event mapping (Anthropic → OpenAI):
/// - `message_start` → a `{"role":"assistant"}` delta chunk; records id / model
///   and the prompt-side usage (`input_tokens`, cache read/write).
/// - `content_block_start` (`tool_use`) → a tool_call header; `content_block_delta`
///   (`text_delta`) → a `{"content": …}` delta, (`input_json_delta`) → tool_call
///   argument deltas.
/// - `message_delta` → a `{}`-delta chunk carrying `finish_reason`; records the
///   `stop_reason` and `output_tokens`.
/// - `message_stop` → the `[DONE]` sentinel (`done = true`).
/// - `ping` / `content_block_stop` / unknown / non-JSON → no client frame.
pub struct AnthropicStreamTranslator {
    record: InferenceRecord,
    id: Option<String>,
    model: Option<String>,
    /// Anthropic content-block index → tool-call state, for the `tool_use`
    /// blocks (so `input_json_delta` frames can find their OpenAI tool index).
    tool_blocks: HashMap<u64, AnthropicToolBlock>,
    /// Next OpenAI `tool_calls[].index` to assign.
    next_tool_index: u64,
    /// Whether any real (non-emulated) tool call streamed — used to map the
    /// finish reason to `tool_calls`.
    has_tool_calls: bool,
    /// Whether the structured-output emulation tool streamed — its `tool_use`
    /// stop maps to a normal `stop` finish (the client sees content, not a call).
    emulated_present: bool,
}

impl AnthropicStreamTranslator {
    pub fn new(mut base: InferenceRecord) -> Self {
        base.upstream_protocol = UpstreamProtocol::AnthropicMessages;
        Self {
            record: base,
            id: None,
            model: None,
            tool_blocks: HashMap::new(),
            next_tool_index: 0,
            has_tool_calls: false,
            emulated_present: false,
        }
    }

    pub fn snapshot(&self) -> InferenceRecord {
        self.record.clone()
    }

    /// Build an OpenAI `chat.completion.chunk` carrying `delta` (and an optional
    /// `finish_reason`) stamped with the served id / model from `message_start`.
    fn chunk(&self, delta: Value, finish_reason: Option<&str>) -> Value {
        json!({
            "id": self.id.clone().unwrap_or_default(),
            "object": "chat.completion.chunk",
            "model": self.model.clone().unwrap_or_default(),
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }],
        })
    }

    fn push(&mut self, data: &str) -> StreamStep {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return StreamStep::default();
        }
        let Ok(ev) = serde_json::from_str::<Value>(trimmed) else {
            // Non-JSON keepalive — no client frame, no fabrication.
            return StreamStep::default();
        };
        match ev.get("type").and_then(Value::as_str).unwrap_or("") {
            "message_start" => {
                if let Some(msg) = ev.get("message") {
                    self.id = str_field(msg, "id");
                    self.model = str_field(msg, "model");
                    if self.record.model_served.is_none() {
                        self.record.model_served = self.model.clone();
                    }
                    if self.record.upstream_request_id.is_none() {
                        self.record.upstream_request_id = self.id.clone();
                    }
                    if let Some(usage) = msg.get("usage") {
                        // Prompt-side classes arrive here; output_tokens arrives
                        // in message_delta, so it is NOT taken from the start.
                        let u = anthropic_token_usage_from(usage);
                        self.record.usage.input = u.input;
                        self.record.usage.cached_read = u.cached_read;
                        self.record.usage.cache_write = u.cache_write;
                        self.record.provider_prompt_cache =
                            self.record.usage.cached_read.map(|c| c > 0);
                    }
                }
                StreamStep {
                    chunks: vec![self.chunk(json!({ "role": "assistant" }), None)],
                    done: false,
                }
            }
            // A `tool_use` block opens a streamed tool call: emit the OpenAI
            // tool_call header (index/id/name). The structured-output emulation's
            // forced tool is recorded but emits no header — its arguments stream
            // as content instead.
            "content_block_start" => {
                let index = ev.get("index").and_then(Value::as_u64).unwrap_or(0);
                let cb = ev.get("content_block");
                if cb.and_then(|c| c.get("type")).and_then(Value::as_str) != Some("tool_use") {
                    return StreamStep::default();
                }
                let cb = cb.unwrap();
                let name = str_field(cb, "name").unwrap_or_default();
                if name == STRUCTURED_OUTPUT_TOOL_NAME {
                    self.emulated_present = true;
                    self.tool_blocks.insert(
                        index,
                        AnthropicToolBlock {
                            tool_index: 0,
                            emulated: true,
                        },
                    );
                    return StreamStep::default();
                }
                let tool_index = self.next_tool_index;
                self.next_tool_index += 1;
                self.has_tool_calls = true;
                self.tool_blocks.insert(
                    index,
                    AnthropicToolBlock {
                        tool_index,
                        emulated: false,
                    },
                );
                StreamStep {
                    chunks: vec![self.chunk(
                        json!({ "tool_calls": [{
                            "index": tool_index,
                            "id": str_field(cb, "id").unwrap_or_default(),
                            "type": "function",
                            "function": { "name": name, "arguments": "" },
                        }] }),
                        None,
                    )],
                    done: false,
                }
            }
            "content_block_delta" => {
                let index = ev.get("index").and_then(Value::as_u64).unwrap_or(0);
                let delta = ev.get("delta");
                match delta.and_then(|d| d.get("type")).and_then(Value::as_str) {
                    Some("text_delta") => {
                        match delta.and_then(|d| d.get("text")).and_then(Value::as_str) {
                            Some(t) => StreamStep {
                                chunks: vec![self.chunk(json!({ "content": t }), None)],
                                done: false,
                            },
                            None => StreamStep::default(),
                        }
                    }
                    // Tool-call arguments stream as partial JSON.
                    Some("input_json_delta") => {
                        let partial = delta
                            .and_then(|d| d.get("partial_json"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        match self.tool_blocks.get(&index) {
                            // Emulated structured output: the args ARE the JSON
                            // answer, forwarded to the client as content.
                            Some(tb) if tb.emulated => StreamStep {
                                chunks: vec![self.chunk(json!({ "content": partial }), None)],
                                done: false,
                            },
                            Some(tb) => StreamStep {
                                chunks: vec![self.chunk(
                                    json!({ "tool_calls": [{
                                        "index": tb.tool_index,
                                        "function": { "arguments": partial },
                                    }] }),
                                    None,
                                )],
                                done: false,
                            },
                            None => StreamStep::default(),
                        }
                    }
                    // thinking_delta / unknown → not forwarded.
                    _ => StreamStep::default(),
                }
            }
            "message_delta" => {
                let mut chunks = Vec::new();
                if let Some(delta) = ev.get("delta") {
                    if let Some(sr) = str_field(delta, "stop_reason") {
                        if sr == "refusal" {
                            self.record.refusal = true;
                        }
                        // The structured-output emulation stops with `tool_use`,
                        // but the client received a normal structured completion —
                        // record/emit `stop`, matching the unary path. A real tool
                        // call keeps the normal `tool_use` → `tool_calls` mapping.
                        let (canon, client) = if self.emulated_present && sr == "tool_use" {
                            (FinishReason::Stop, "stop")
                        } else {
                            (
                                normalize_anthropic_stop_reason(&sr),
                                anthropic_stop_reason_to_openai(&sr),
                            )
                        };
                        self.record.finish_reason = Some(canon);
                        chunks.push(self.chunk(json!({}), Some(client)));
                    }
                }
                if let Some(usage) = ev.get("usage") {
                    if let Some(out) = u64_field(usage, "output_tokens") {
                        self.record.usage.output = Some(out);
                    }
                }
                StreamStep {
                    chunks,
                    done: false,
                }
            }
            // The logical end: re-emit the OpenAI terminal sentinel.
            "message_stop" => StreamStep {
                chunks: vec![Value::String("[DONE]".to_string())],
                done: true,
            },
            // ping / content_block_start / content_block_stop / unknown.
            _ => StreamStep::default(),
        }
    }
}

/// Translates a Gemini `streamGenerateContent?alt=sse` event stream into OpenAI
/// chat-completion-chunk client frames while folding usage / finish-reason into
/// the [`InferenceRecord`]. Captures **metadata only** (I9) — content text is
/// forwarded to the client but never retained in the record.
///
/// Gemini has **no `[DONE]` sentinel**: the stream simply ends after the frame
/// carrying `finishReason`. Each `data:` frame is a partial
/// `GenerateContentResponse` whose `candidates[0].content.parts[].text` is the
/// INCREMENTAL text for that chunk. Mapping (Gemini → OpenAI):
/// - first frame → a `{"role":"assistant"}` delta chunk (Gemini has no separate
///   start event), emitted once before that frame's content;
/// - each frame's `parts[].text` (concatenated) → a `{"content": …}` delta;
/// - records `modelVersion` / `responseId` (first-wins) and folds `usageMetadata`
///   whenever present (Gemini reports it on the final frame);
/// - the frame with `finishReason` → a `{}`-delta finish chunk PLUS the
///   synthesized `[DONE]` sentinel, and marks `done` so the egress finalizes.
///   A stream that closes WITHOUT a `finishReason` never sets `done`, so the
///   egress surfaces it as a truncation rather than a clean completion.
pub struct GeminiStreamTranslator {
    record: InferenceRecord,
    /// Whether the leading `{"role":"assistant"}` chunk has been emitted (Gemini
    /// has no start event, so the first observed frame emits it).
    started: bool,
    /// Next OpenAI `tool_calls[].index` to assign (Gemini emits each functionCall
    /// whole, so a call needs only one index).
    next_tool_index: u64,
    /// Whether any functionCall streamed — maps the finish reason to `tool_calls`
    /// (Gemini reports `STOP` even on a tool-call turn).
    has_tool_calls: bool,
}

impl GeminiStreamTranslator {
    pub fn new(mut base: InferenceRecord) -> Self {
        base.upstream_protocol = UpstreamProtocol::Gemini;
        Self {
            record: base,
            started: false,
            next_tool_index: 0,
            has_tool_calls: false,
        }
    }

    pub fn snapshot(&self) -> InferenceRecord {
        self.record.clone()
    }

    /// Build an OpenAI `chat.completion.chunk` carrying `delta` (and an optional
    /// `finish_reason`) stamped with the served id / model from the response.
    fn chunk(&self, delta: Value, finish_reason: Option<&str>) -> Value {
        json!({
            "id": self.record.upstream_request_id.clone().unwrap_or_default(),
            "object": "chat.completion.chunk",
            "model": self.record.model_served.clone().unwrap_or_default(),
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }],
        })
    }

    fn push(&mut self, data: &str) -> StreamStep {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return StreamStep::default();
        }
        let Ok(ev) = serde_json::from_str::<Value>(trimmed) else {
            // Non-JSON keepalive — no client frame, no fabrication.
            return StreamStep::default();
        };

        // Identity: first-wins (later frames repeat it).
        if self.record.model_served.is_none() {
            self.record.model_served = str_field(&ev, "modelVersion");
        }
        if self.record.upstream_request_id.is_none() {
            self.record.upstream_request_id = str_field(&ev, "responseId");
        }

        let mut chunks = Vec::new();
        // Gemini has no start event: emit the assistant role on the first frame.
        if !self.started {
            self.started = true;
            chunks.push(self.chunk(json!({ "role": "assistant" }), None));
        }

        let candidate = ev
            .get("candidates")
            .and_then(Value::as_array)
            .and_then(|c| c.first());

        // Incremental text for this frame (parts concatenated).
        let text: String = candidate
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if !text.is_empty() {
            chunks.push(self.chunk(json!({ "content": text }), None));
        }

        // functionCall parts → OpenAI tool_calls. Gemini streams each call whole
        // (no incremental args), so the complete call is emitted in one chunk;
        // Gemini provides no id, so a `call_N` is minted.
        if let Some(parts) = candidate
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
        {
            for fc in parts.iter().filter_map(|p| p.get("functionCall")) {
                let name = fc.get("name").and_then(Value::as_str).unwrap_or_default();
                let arguments = fc
                    .get("args")
                    .map(|a| serde_json::to_string(a).unwrap_or_default())
                    .unwrap_or_else(|| "{}".to_string());
                let index = self.next_tool_index;
                self.next_tool_index += 1;
                self.has_tool_calls = true;
                chunks.push(self.chunk(
                    json!({ "tool_calls": [{
                        "index": index,
                        "id": format!("call_{index}"),
                        "type": "function",
                        "function": { "name": name, "arguments": arguments },
                    }] }),
                    None,
                ));
            }
        }

        // Usage: Gemini reports usageMetadata (typically on the final frame).
        // Fold whenever present; the snapshot at stream close carries the last.
        if let Some(um) = ev.get("usageMetadata") {
            self.record.usage = gemini_token_usage_from(um);
            self.record.provider_prompt_cache = self.record.usage.cached_read.map(|c| c > 0);
        }

        // Finish: the frame carrying finishReason ends the turn. Gemini sends no
        // [DONE], so synthesize one and mark the step done.
        let mut done = false;
        if let Some(fr) = candidate.and_then(|c| str_field(c, "finishReason")) {
            let canon = normalize_gemini_finish_reason(&fr);
            if canon == FinishReason::ContentFilter {
                self.record.refusal = true;
            }
            // A tool-call turn reports `STOP`; align with the client body, which
            // maps to `tool_calls` (a content filter still wins).
            let (canon, client) = if self.has_tool_calls && canon != FinishReason::ContentFilter {
                (FinishReason::ToolUse, "tool_calls")
            } else {
                (canon, gemini_finish_reason_to_openai(&fr))
            };
            self.record.finish_reason = Some(canon);
            chunks.push(self.chunk(json!({}), Some(client)));
            chunks.push(Value::String("[DONE]".to_string()));
            done = true;
        }

        StreamStep { chunks, done }
    }
}

/// Translates an OpenAI **Responses API** (`/responses`) streamed event sequence
/// into OpenAI chat-completion-chunk client frames while folding usage /
/// finish-reason into the [`InferenceRecord`]. Captures **metadata only** (I9).
///
/// Responses streams typed events; the event's kind rides in the `data:`
/// payload's own `type` field (the transport drops the `event:` line), so the
/// translator dispatches on `data.type`. There is **no `[DONE]` sentinel** — the
/// stream ends after the terminal `response.completed` (or `response.incomplete`)
/// event, which also carries the final `response` object with usage + status.
/// Mapping:
/// - first frame → a `{"role":"assistant"}` delta chunk (no separate start
///   event), emitted before that frame's content;
/// - `response.output_text.delta` → a `{"content": …}` delta (only the answer
///   text; reasoning-summary deltas are not forwarded as content);
/// - identity (`response.id` / `response.model`, first-wins) is captured from any
///   event's nested `response` object;
/// - `response.completed` / `response.incomplete` → fold `response.usage`, derive
///   the finish reason from `response.status`, emit a finish chunk PLUS the
///   synthesized `[DONE]`, and mark `done`. A `response.failed` (or any close)
///   without a terminal event never sets `done`, so the egress surfaces it as a
///   truncation rather than a clean completion.
pub struct ResponsesStreamTranslator {
    record: InferenceRecord,
    /// Whether the leading `{"role":"assistant"}` chunk has been emitted.
    started: bool,
    /// Responses output-item id → OpenAI `tool_calls[].index`, so a
    /// `function_call_arguments.delta` (keyed by `item_id`) finds its index.
    tool_items: HashMap<String, u64>,
    /// Next OpenAI `tool_calls[].index` to assign.
    next_tool_index: u64,
    /// Whether any `function_call` streamed — maps the finish reason to
    /// `tool_calls` (Responses reports `completed` even on a tool-call turn).
    has_tool_calls: bool,
}

impl ResponsesStreamTranslator {
    pub fn new(mut base: InferenceRecord) -> Self {
        base.upstream_protocol = UpstreamProtocol::OpenAiResponses;
        Self {
            record: base,
            started: false,
            tool_items: HashMap::new(),
            next_tool_index: 0,
            has_tool_calls: false,
        }
    }

    pub fn snapshot(&self) -> InferenceRecord {
        self.record.clone()
    }

    fn chunk(&self, delta: Value, finish_reason: Option<&str>) -> Value {
        json!({
            "id": self.record.upstream_request_id.clone().unwrap_or_default(),
            "object": "chat.completion.chunk",
            "model": self.record.model_served.clone().unwrap_or_default(),
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }],
        })
    }

    /// Capture identity (first-wins) from an event's nested `response` object.
    fn record_identity(&mut self, resp_obj: &Value) {
        if self.record.model_served.is_none() {
            self.record.model_served = str_field(resp_obj, "model");
        }
        if self.record.upstream_request_id.is_none() {
            self.record.upstream_request_id = str_field(resp_obj, "id");
        }
    }

    fn push(&mut self, data: &str) -> StreamStep {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return StreamStep::default();
        }
        let Ok(ev) = serde_json::from_str::<Value>(trimmed) else {
            // Non-JSON keepalive — no client frame, no fabrication.
            return StreamStep::default();
        };
        // Identity may ride on any event's nested `response` object.
        if let Some(r) = ev.get("response") {
            self.record_identity(r);
        }

        let mut chunks = Vec::new();
        // Responses has no start event: emit the assistant role on the first frame.
        if !self.started {
            self.started = true;
            chunks.push(self.chunk(json!({ "role": "assistant" }), None));
        }

        match ev.get("type").and_then(Value::as_str).unwrap_or("") {
            "response.output_text.delta" => {
                if let Some(t) = ev.get("delta").and_then(Value::as_str) {
                    if !t.is_empty() {
                        chunks.push(self.chunk(json!({ "content": t }), None));
                    }
                }
                StreamStep {
                    chunks,
                    done: false,
                }
            }
            // A `function_call` output item opens a streamed tool call: emit the
            // OpenAI tool_call header and map its item id → tool index so the
            // argument deltas (keyed by `item_id`) can find it.
            "response.output_item.added" => {
                let item = ev.get("item");
                if item.and_then(|i| i.get("type")).and_then(Value::as_str) == Some("function_call")
                {
                    let item = item.unwrap();
                    let item_id = str_field(item, "id").unwrap_or_default();
                    let tool_index = self.next_tool_index;
                    self.next_tool_index += 1;
                    self.has_tool_calls = true;
                    self.tool_items.insert(item_id, tool_index);
                    chunks.push(self.chunk(
                        json!({ "tool_calls": [{
                            "index": tool_index,
                            "id": str_field(item, "call_id").unwrap_or_default(),
                            "type": "function",
                            "function": {
                                "name": str_field(item, "name").unwrap_or_default(),
                                "arguments": "",
                            },
                        }] }),
                        None,
                    ));
                }
                StreamStep {
                    chunks,
                    done: false,
                }
            }
            // Incremental tool-call arguments.
            "response.function_call_arguments.delta" => {
                let item_id = str_field(&ev, "item_id").unwrap_or_default();
                if let (Some(&tool_index), Some(delta)) = (
                    self.tool_items.get(&item_id),
                    ev.get("delta").and_then(Value::as_str),
                ) {
                    chunks.push(self.chunk(
                        json!({ "tool_calls": [{
                            "index": tool_index,
                            "function": { "arguments": delta },
                        }] }),
                        None,
                    ));
                }
                StreamStep {
                    chunks,
                    done: false,
                }
            }
            // Terminal: the final `response` object carries usage + status.
            "response.completed" | "response.incomplete" => {
                if let Some(r) = ev.get("response") {
                    if let Some(usage) = r.get("usage") {
                        self.record.usage = responses_token_usage_from(usage);
                        self.record.provider_prompt_cache =
                            self.record.usage.cached_read.map(|c| c > 0);
                    }
                    if let Some(finish) = responses_finish(r) {
                        if finish == FinishReason::ContentFilter {
                            self.record.refusal = true;
                        }
                        // A tool-call turn reports `completed`; align with the
                        // client body's `tool_calls` finish (content filter wins).
                        let finish = if self.has_tool_calls && finish != FinishReason::ContentFilter
                        {
                            FinishReason::ToolUse
                        } else {
                            finish
                        };
                        self.record.finish_reason = Some(finish);
                        chunks.push(self.chunk(json!({}), Some(finish_reason_openai_str(finish))));
                    }
                }
                chunks.push(Value::String("[DONE]".to_string()));
                StreamStep { chunks, done: true }
            }
            // response.created / output_item.added / content_part.added /
            // output_text.done / reasoning deltas / response.failed / unknown →
            // identity only (captured above), no client frame, not terminal.
            _ => StreamStep {
                chunks,
                done: false,
            },
        }
    }
}

/// Lifts the gateway's normalized OpenAI **chat-completion-chunk** stream into
/// OpenAI **Responses** streaming events, for a `/v1/responses` client whose call
/// routed to a non-Responses upstream (Anthropic / Gemini / OpenAI-chat). Because
/// every [`StreamTranslator`] variant already normalizes its provider stream to
/// the same chat-chunk shape (role / content delta / `tool_calls[]` / finish), one
/// provider-agnostic lifter covers all three — no per-provider state machine.
///
/// Fidelity matches the chat / unary-Responses projection for these providers:
/// assistant text and function calls are carried (as `message` + `output_text` and
/// `function_call` items); reasoning / annotations are not (the chat translators
/// drop them upstream of this point). An OpenAI-Responses upstream keeps full
/// fidelity via the separate 1:1 frame passthrough, not this lifter.
///
/// The lifter is self-contained on the chat chunks — `id` / `model` from the first
/// chunk that carries them, text accumulated from `content` deltas, tool calls from
/// `tool_calls[]`, `finish_reason` and `usage` from the terminal chunks — so it
/// needs no separate record. Drive [`push`](Self::push) per chat chunk, then
/// [`finish`](Self::finish) once at stream close; each returns `(event_name,
/// payload)` pairs, already stamped with `type` and a monotonic `sequence_number`.
#[derive(Debug, Default)]
pub struct ChatStreamToResponses {
    seq: u64,
    created: bool,
    id: Option<String>,
    model: Option<String>,
    msg: Option<ResponsesMsgItem>,
    next_output_index: u64,
    tools: Vec<ResponsesToolItem>,
    /// chat `tool_calls[].index` → position in `tools`.
    tool_by_index: HashMap<u64, usize>,
    finish_reason: Option<String>,
    usage: Option<Value>,
}

#[derive(Debug)]
struct ResponsesMsgItem {
    output_index: u64,
    item_id: String,
    /// Next `content_index` to assign as parts open (text, refusal).
    next_content_index: u64,
    /// The `output_text` content part, opened lazily on the first content delta.
    text: Option<ResponsesContentPart>,
    /// The `refusal` content part, opened lazily on the first refusal delta
    /// (OpenAI structured-output refusals stream a `delta.refusal` string).
    refusal: Option<ResponsesContentPart>,
}

#[derive(Debug)]
struct ResponsesContentPart {
    content_index: u64,
    text: String,
}

#[derive(Debug)]
struct ResponsesToolItem {
    output_index: u64,
    item_id: String,
    call_id: String,
    name: String,
    args: String,
}

impl ChatStreamToResponses {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_index(&mut self) -> u64 {
        let i = self.next_output_index;
        self.next_output_index += 1;
        i
    }

    /// Ensure the assistant `message` output item is open (emitting
    /// `response.output_item.added` exactly once), returning `(item_id,
    /// output_index)`. Its content parts (`output_text` / `refusal`) open lazily.
    fn ensure_message(&mut self, out: &mut Vec<(String, Value)>) -> (String, u64) {
        if self.msg.is_none() {
            let oi = self.next_index();
            let item_id = format!("msg_{oi}");
            let added = json!({
                "output_index": oi,
                "item": {"type": "message", "id": item_id, "status": "in_progress",
                         "role": "assistant", "content": []},
            });
            out.push(self.event("response.output_item.added", added));
            self.msg = Some(ResponsesMsgItem {
                output_index: oi,
                item_id,
                next_content_index: 0,
                text: None,
                refusal: None,
            });
        }
        let m = self.msg.as_ref().expect("message item opened above");
        (m.item_id.clone(), m.output_index)
    }

    /// Stamp `type` + a fresh `sequence_number` onto an event body.
    fn event(&mut self, name: &str, mut body: Value) -> (String, Value) {
        let seq = self.seq;
        self.seq += 1;
        if let Some(o) = body.as_object_mut() {
            o.insert("type".into(), json!(name));
            o.insert("sequence_number".into(), json!(seq));
        }
        (name.to_string(), body)
    }

    /// Map the accumulated `finish_reason` to a Responses terminal status and an
    /// optional `incomplete_details.reason`.
    fn terminal_status(&self) -> (&'static str, Option<&'static str>) {
        match self.finish_reason.as_deref() {
            Some("length") => ("incomplete", Some("max_output_tokens")),
            Some("content_filter") => ("incomplete", Some("content_filter")),
            // stop / tool_calls / unknown / absent → a normal completion.
            _ => ("completed", None),
        }
    }

    /// Translate the OpenAI chat `usage` shape to the Responses `usage` classes,
    /// including the cached-prompt and reasoning detail sub-objects when the chat
    /// usage carries them (parity with the unary Responses usage renderer).
    fn responses_usage(chat: &Value) -> Value {
        let mut u = serde_json::Map::new();
        for (chat_key, resp_key) in [
            ("prompt_tokens", "input_tokens"),
            ("completion_tokens", "output_tokens"),
            ("total_tokens", "total_tokens"),
        ] {
            if let Some(v) = chat.get(chat_key).and_then(Value::as_u64) {
                u.insert(resp_key.into(), json!(v));
            }
        }
        // Detail sub-objects: chat `prompt_tokens_details.cached_tokens` →
        // `input_tokens_details.cached_tokens`; `completion_tokens_details.
        // reasoning_tokens` → `output_tokens_details.reasoning_tokens`.
        if let Some(cached) = chat
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(Value::as_u64)
        {
            u.insert(
                "input_tokens_details".into(),
                json!({"cached_tokens": cached}),
            );
        }
        if let Some(reasoning) = chat
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(Value::as_u64)
        {
            u.insert(
                "output_tokens_details".into(),
                json!({"reasoning_tokens": reasoning}),
            );
        }
        Value::Object(u)
    }

    fn build_response(&self, status: &str, output: Value, incomplete: Option<&str>) -> Value {
        let mut r = json!({
            "id": self.id.clone().unwrap_or_default(),
            "object": "response",
            "model": self.model.clone().unwrap_or_default(),
            "status": status,
            "output": output,
        });
        if let Some(reason) = incomplete {
            r["incomplete_details"] = json!({ "reason": reason });
        }
        if let Some(usage) = &self.usage {
            r["usage"] = Self::responses_usage(usage);
        }
        r
    }

    /// Process one chat-completion-chunk, returning the Responses events it maps to
    /// (0..N). A usage-only chunk (`choices: []`) and the `[DONE]` sentinel yield no
    /// events but are still observed for the terminal `response.completed`.
    pub fn push(&mut self, chunk: &Value) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        if self.id.is_none() {
            if let Some(id) = str_field(chunk, "id").filter(|s| !s.is_empty()) {
                self.id = Some(id);
            }
        }
        if self.model.is_none() {
            if let Some(m) = str_field(chunk, "model").filter(|s| !s.is_empty()) {
                self.model = Some(m);
            }
        }
        if let Some(u) = chunk.get("usage").filter(|u| !u.is_null()) {
            self.usage = Some(u.clone());
        }
        let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        else {
            return out; // usage-only chunk, or the [DONE] string
        };
        if !self.created {
            self.created = true;
            let body = json!({ "response": self.build_response("in_progress", json!([]), None) });
            out.push(self.event("response.created", body));
        }
        if let Some(fr) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(fr.to_owned());
        }
        let delta = choice.get("delta");
        // Assistant text → output_text deltas (opening the message item + part lazily).
        if let Some(text) = delta
            .and_then(|d| d.get("content"))
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
        {
            let (item_id, oi) = self.ensure_message(&mut out);
            let (ci, newly) = {
                let m = self.msg.as_mut().expect("message item opened above");
                match &mut m.text {
                    Some(p) => {
                        p.text.push_str(text);
                        (p.content_index, false)
                    }
                    None => {
                        let ci = m.next_content_index;
                        m.next_content_index += 1;
                        m.text = Some(ResponsesContentPart {
                            content_index: ci,
                            text: text.to_string(),
                        });
                        (ci, true)
                    }
                }
            };
            if newly {
                out.push(self.event(
                    "response.content_part.added",
                    json!({"item_id": item_id, "output_index": oi, "content_index": ci,
                           "part": {"type": "output_text", "text": ""}}),
                ));
            }
            out.push(self.event(
                "response.output_text.delta",
                json!({"item_id": item_id, "output_index": oi, "content_index": ci, "delta": text}),
            ));
        }
        // Structured-output refusal → a `refusal` content part with refusal deltas.
        // (Parity with the unary OpenAI-chat → Responses projection, which surfaces
        // a non-empty `message.refusal` as a `refusal` content part.)
        if let Some(refusal) = delta
            .and_then(|d| d.get("refusal"))
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
        {
            let (item_id, oi) = self.ensure_message(&mut out);
            let (ci, newly) = {
                let m = self.msg.as_mut().expect("message item opened above");
                match &mut m.refusal {
                    Some(p) => {
                        p.text.push_str(refusal);
                        (p.content_index, false)
                    }
                    None => {
                        let ci = m.next_content_index;
                        m.next_content_index += 1;
                        m.refusal = Some(ResponsesContentPart {
                            content_index: ci,
                            text: refusal.to_string(),
                        });
                        (ci, true)
                    }
                }
            };
            if newly {
                out.push(self.event(
                    "response.content_part.added",
                    json!({"item_id": item_id, "output_index": oi, "content_index": ci,
                           "part": {"type": "refusal", "refusal": ""}}),
                ));
            }
            out.push(self.event(
                "response.refusal.delta",
                json!({"item_id": item_id, "output_index": oi, "content_index": ci, "delta": refusal}),
            ));
        }
        // Tool calls → function_call items + argument deltas.
        if let Some(tcs) = delta
            .and_then(|d| d.get("tool_calls"))
            .and_then(Value::as_array)
        {
            for tc in tcs {
                let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(0);
                if let Some(call_id) = str_field(tc, "id").filter(|s| !s.is_empty()) {
                    let oi = self.next_index();
                    let item_id = format!("fc_{oi}");
                    let name = tc
                        .get("function")
                        .and_then(|f| str_field(f, "name"))
                        .unwrap_or_default();
                    let added = json!({
                        "output_index": oi,
                        "item": {"type": "function_call", "id": item_id, "call_id": call_id,
                                 "name": name, "arguments": "", "status": "in_progress"},
                    });
                    out.push(self.event("response.output_item.added", added));
                    let pos = self.tools.len();
                    self.tools.push(ResponsesToolItem {
                        output_index: oi,
                        item_id,
                        call_id,
                        name,
                        args: String::new(),
                    });
                    self.tool_by_index.insert(idx, pos);
                }
                if let Some(args) = tc
                    .get("function")
                    .and_then(|f| str_field(f, "arguments"))
                    .filter(|s| !s.is_empty())
                {
                    if let Some(&pos) = self.tool_by_index.get(&idx) {
                        let (item_id, oi) = {
                            let t = &mut self.tools[pos];
                            t.args.push_str(&args);
                            (t.item_id.clone(), t.output_index)
                        };
                        let d = json!({ "item_id": item_id, "output_index": oi, "delta": args });
                        out.push(self.event("response.function_call_arguments.delta", d));
                    }
                }
            }
        }
        out
    }

    /// Close every open item and emit the terminal `response.completed` /
    /// `response.incomplete` (carrying the assembled `output` + `usage`). Called
    /// once, when the underlying translator reports the logical end.
    ///
    /// `fallback_usage` is an OpenAI-chat-shaped usage object derived from the
    /// translator record, used when no usage-bearing chat chunk was seen — Anthropic
    /// and Gemini fold usage into the record rather than emitting a usage chunk, so
    /// without it their terminal Responses event would omit usage. A usage chunk the
    /// lifter already captured (the OpenAI-chat `include_usage` path) takes
    /// precedence.
    pub fn finish(&mut self, fallback_usage: Option<Value>) -> Vec<(String, Value)> {
        if self.usage.is_none() {
            self.usage = fallback_usage;
        }
        let mut out = Vec::new();
        let msg = self.msg.take();
        let tools = std::mem::take(&mut self.tools);
        // The message item's assembled content parts, in open order (text, refusal).
        let msg_content: Option<Value> = msg.as_ref().map(|m| {
            let mut parts = Vec::new();
            if let Some(t) = &m.text {
                parts.push(json!({"type": "output_text", "text": t.text}));
            }
            if let Some(r) = &m.refusal {
                parts.push(json!({"type": "refusal", "refusal": r.text}));
            }
            Value::Array(parts)
        });
        if let Some(m) = &msg {
            if let Some(t) = &m.text {
                out.push(self.event(
                    "response.output_text.done",
                    json!({"item_id": m.item_id, "output_index": m.output_index,
                           "content_index": t.content_index, "text": t.text}),
                ));
                out.push(self.event(
                    "response.content_part.done",
                    json!({"item_id": m.item_id, "output_index": m.output_index,
                           "content_index": t.content_index,
                           "part": {"type": "output_text", "text": t.text}}),
                ));
            }
            if let Some(r) = &m.refusal {
                out.push(self.event(
                    "response.refusal.done",
                    json!({"item_id": m.item_id, "output_index": m.output_index,
                           "content_index": r.content_index, "refusal": r.text}),
                ));
                out.push(self.event(
                    "response.content_part.done",
                    json!({"item_id": m.item_id, "output_index": m.output_index,
                           "content_index": r.content_index,
                           "part": {"type": "refusal", "refusal": r.text}}),
                ));
            }
            out.push(self.event(
                "response.output_item.done",
                json!({"output_index": m.output_index,
                       "item": {"type": "message", "id": m.item_id, "status": "completed",
                                "role": "assistant",
                                "content": msg_content.clone().unwrap_or_else(|| json!([]))}}),
            ));
        }
        for t in &tools {
            out.push(self.event(
                "response.function_call_arguments.done",
                json!({"item_id": t.item_id, "output_index": t.output_index, "arguments": t.args}),
            ));
            out.push(self.event(
                "response.output_item.done",
                json!({"output_index": t.output_index,
                       "item": {"type": "function_call", "id": t.item_id, "call_id": t.call_id,
                                "name": t.name, "arguments": t.args, "status": "completed"}}),
            ));
        }
        let mut output = Vec::new();
        if let Some(m) = &msg {
            output.push(
                json!({"type": "message", "id": m.item_id, "status": "completed",
                               "role": "assistant",
                               "content": msg_content.unwrap_or_else(|| json!([]))}),
            );
        }
        for t in &tools {
            output.push(
                json!({"type": "function_call", "id": t.item_id, "call_id": t.call_id,
                               "name": t.name, "arguments": t.args, "status": "completed"}),
            );
        }
        let (status, incomplete) = self.terminal_status();
        let response = self.build_response(status, Value::Array(output), incomplete);
        let name = if status == "completed" {
            "response.completed"
        } else {
            "response.incomplete"
        };
        out.push(self.event(name, json!({ "response": response })));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Surface;
    use crate::record::FinishReason;
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
    fn provider_accounting_matches_unary_streaming_and_client_totals() {
        use crate::response::*;
        use crate::response_canonical::*;
        for (read, written) in [(0_u64, 0_u64), (400, 0), (1000, 0), (400, 200)] {
            for protocol in [
                UpstreamProtocol::OpenAiChat,
                UpstreamProtocol::OpenAiResponses,
                UpstreamProtocol::AnthropicMessages,
                UpstreamProtocol::Gemini,
            ] {
                if protocol == UpstreamProtocol::Gemini && written != 0 {
                    continue;
                }
                let mut record = base();
                record.upstream_protocol = protocol;
                let (unary, frames, canonical) = match protocol {
                    UpstreamProtocol::OpenAiChat => {
                        let response = json!({"usage": {
                            "prompt_tokens": 1000, "completion_tokens": 50, "total_tokens": 1050,
                            "prompt_tokens_details": {"cached_tokens": read, "cache_write_tokens": written},
                            "completion_tokens_details": {"reasoning_tokens": 20}
                        }});
                        (
                            extract_openai_chat(record.clone(), &response),
                            vec![response.clone()],
                            openai_chat_to_canonical_response(&response),
                        )
                    }
                    UpstreamProtocol::OpenAiResponses => {
                        let response = json!({"status": "completed", "usage": {
                            "input_tokens": 1000, "output_tokens": 50, "total_tokens": 1050,
                            "input_tokens_details": {"cached_tokens": read, "cache_write_tokens": written},
                            "output_tokens_details": {"reasoning_tokens": 20}
                        }});
                        (
                            extract_openai_responses(record.clone(), &response),
                            vec![json!({"type": "response.completed", "response": response})],
                            openai_responses_to_canonical_response(&response),
                        )
                    }
                    UpstreamProtocol::AnthropicMessages => {
                        let response = json!({"usage": {
                            "input_tokens": 1000 - read - written, "output_tokens": 50,
                            "cache_read_input_tokens": read, "cache_creation_input_tokens": written
                        }});
                        let frames = vec![
                            json!({"type": "message_start", "message": response}),
                            json!({"type": "message_delta", "usage": {"output_tokens": 50}}),
                        ];
                        (
                            extract_anthropic_messages(record.clone(), &response),
                            frames,
                            anthropic_to_canonical_response(&response),
                        )
                    }
                    UpstreamProtocol::Gemini => {
                        let response = json!({"usageMetadata": {
                            "promptTokenCount": 1000, "candidatesTokenCount": 30,
                            "thoughtsTokenCount": 20, "cachedContentTokenCount": read,
                            "totalTokenCount": 1050
                        }});
                        (
                            extract_gemini(record.clone(), &response),
                            vec![response.clone()],
                            gemini_to_canonical_response(&response),
                        )
                    }
                };
                let mut streamed = StreamTranslator::for_record(record);
                for frame in frames {
                    streamed.push(&frame.to_string());
                }
                assert_eq!(
                    streamed.snapshot().usage,
                    unary.usage,
                    "{protocol:?}, read={read}, write={written}"
                );
                assert_eq!(unary.usage.input, Some(1000));
                assert_eq!(unary.usage.output, Some(50));
                assert_eq!(unary.usage.cached_read, Some(read));
                if protocol != UpstreamProtocol::Gemini {
                    assert_eq!(unary.usage.cache_write, Some(written));
                }
                let client = canonical_response_to_responses(&canonical);
                assert_eq!(client["usage"]["input_tokens"], 1000);
                assert_eq!(client["usage"]["output_tokens"], 50);
                assert_eq!(client["usage"]["total_tokens"], 1050);
                if protocol != UpstreamProtocol::Gemini {
                    assert_eq!(
                        client["usage"]["input_tokens_details"]["cache_write_tokens"],
                        written
                    );
                }
            }
        }
    }

    #[test]
    fn absent_usage_and_missing_primary_counts_remain_unknown_for_every_protocol() {
        use crate::response::*;
        for (protocol, response, frame) in [
            (
                UpstreamProtocol::OpenAiChat,
                json!({"usage": {}}),
                json!({"usage": {}}),
            ),
            (
                UpstreamProtocol::OpenAiResponses,
                json!({"usage": {}}),
                json!({"type": "response.completed", "response": {"usage": {}}}),
            ),
            (
                UpstreamProtocol::AnthropicMessages,
                json!({"usage": {}}),
                json!({"type": "message_start", "message": {"usage": {}}}),
            ),
            (
                UpstreamProtocol::Gemini,
                json!({"usageMetadata": {}}),
                json!({"usageMetadata": {}}),
            ),
        ] {
            let mut record = base();
            record.upstream_protocol = protocol;
            let unary = match protocol {
                UpstreamProtocol::OpenAiChat => extract_openai_chat(record.clone(), &response),
                UpstreamProtocol::OpenAiResponses => {
                    extract_openai_responses(record.clone(), &response)
                }
                UpstreamProtocol::AnthropicMessages => {
                    extract_anthropic_messages(record.clone(), &response)
                }
                UpstreamProtocol::Gemini => extract_gemini(record.clone(), &response),
            };
            let mut streamed = StreamTranslator::for_record(record);
            streamed.push(&frame.to_string());
            assert_eq!(streamed.snapshot().usage, unary.usage);
            assert_eq!(unary.usage, crate::TokenUsage::default());
        }
        assert_eq!(
            anthropic_token_usage_from(&json!({"cache_read_input_tokens": 10})).input,
            None
        );
        assert_eq!(
            gemini_token_usage_from(&json!({"thoughtsTokenCount": 10})).output,
            None
        );
        assert_eq!(
            anthropic_token_usage_from(
                &json!({"input_tokens": u64::MAX, "cache_read_input_tokens": 1})
            )
            .input,
            None
        );
        assert_eq!(
            gemini_token_usage_from(
                &json!({"candidatesTokenCount": u64::MAX, "thoughtsTokenCount": 1})
            )
            .output,
            None
        );
    }

    /// A representative stream: a role chunk (with identity + null usage),
    /// content deltas, a finish chunk, then the terminal usage chunk and
    /// `[DONE]`. The aggregator folds identity, finish reason, and usage.
    #[test]
    fn folds_identity_usage_and_finish_across_chunks() {
        let frames = [
            r#"{"id":"chatcmpl-9","model":"served-x","system_fingerprint":"fp_1","choices":[{"delta":{"role":"assistant"},"finish_reason":null}],"usage":null}"#,
            r#"{"id":"chatcmpl-9","model":"served-x","choices":[{"delta":{"content":"He"},"finish_reason":null}]}"#,
            r#"{"id":"chatcmpl-9","model":"served-x","choices":[{"delta":{"content":"llo"},"finish_reason":null}]}"#,
            r#"{"id":"chatcmpl-9","model":"served-x","choices":[{"delta":{},"finish_reason":"stop"}]}"#,
            r#"{"id":"chatcmpl-9","model":"served-x","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":3}}}"#,
            "[DONE]",
        ];
        let mut agg = OpenAiChatStreamAggregator::new(base());
        for f in frames {
            agg.observe_data(f);
        }
        let rec = agg.finish();
        assert_eq!(rec.model_served.as_deref(), Some("served-x"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("chatcmpl-9"));
        assert_eq!(rec.system_fingerprint.as_deref(), Some("fp_1"));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert_eq!(rec.usage.input, Some(7));
        assert_eq!(rec.usage.output, Some(2));
        assert_eq!(rec.usage.cached_read, Some(3));
        assert_eq!(rec.provider_prompt_cache, Some(true));
        assert!(!rec.refusal);
        // Identity from the base record is preserved.
        assert_eq!(rec.provider, LlmProvider::OpenRouter);
        assert_eq!(rec.model_requested, "alias");
    }

    #[test]
    fn done_blank_and_non_json_frames_are_ignored() {
        let mut agg = OpenAiChatStreamAggregator::new(base());
        agg.observe_data("[DONE]");
        agg.observe_data("");
        agg.observe_data("   ");
        agg.observe_data("not json at all");
        let rec = agg.finish();
        // Nothing was observed → all extracted fields stay unset (not fabricated).
        assert_eq!(rec.model_served, None);
        assert_eq!(rec.finish_reason, None);
        assert_eq!(rec.usage.input, None);
        assert!(!rec.refusal);
    }

    #[test]
    fn content_filter_finish_marks_refusal() {
        let mut agg = OpenAiChatStreamAggregator::new(base());
        agg.observe_data(
            r#"{"model":"m","choices":[{"delta":{},"finish_reason":"content_filter"}]}"#,
        );
        let rec = agg.finish();
        assert_eq!(rec.finish_reason, Some(FinishReason::ContentFilter));
        assert!(rec.refusal);
    }

    #[test]
    fn streamed_delta_refusal_marks_refusal_even_when_finish_is_stop() {
        let mut agg = OpenAiChatStreamAggregator::new(base());
        agg.observe_data(
            r#"{"model":"m","choices":[{"delta":{"refusal":"I can't help with that."},"finish_reason":"stop"}]}"#,
        );
        let rec = agg.finish();
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert!(rec.refusal);
    }

    #[test]
    fn earlier_null_usage_does_not_overwrite_terminal_usage() {
        // A null-usage chunk before the terminal usage chunk must not clobber
        // the real counts (regression guard for the `filter(!is_null)` check).
        let mut agg = OpenAiChatStreamAggregator::new(base());
        agg.observe_data(r#"{"model":"m","choices":[{"delta":{"content":"x"}}],"usage":null}"#);
        agg.observe_data(
            r#"{"model":"m","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1}}"#,
        );
        let rec = agg.finish();
        assert_eq!(rec.usage.input, Some(5));
        assert_eq!(rec.usage.output, Some(1));
    }

    // ---- StreamTranslator -------------------------------------------------

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
    fn openai_translator_passes_frames_through_and_folds_record() {
        let mut t = StreamTranslator::for_record(base());
        // A normal chunk forwards verbatim, not terminal.
        let step =
            t.push(r#"{"id":"c1","model":"served-x","choices":[{"delta":{"content":"hi"}}]}"#);
        assert!(!step.done);
        assert_eq!(step.chunks.len(), 1);
        assert_eq!(step.chunks[0]["choices"][0]["delta"]["content"], "hi");
        // The usage chunk folds tokens; [DONE] is terminal and forwarded.
        t.push(r#"{"model":"served-x","choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#);
        let done = t.push("[DONE]");
        assert!(done.done);
        assert_eq!(done.chunks[0], Value::String("[DONE]".to_string()));
        let rec = t.snapshot();
        assert_eq!(rec.model_served.as_deref(), Some("served-x"));
        assert_eq!(rec.usage.input, Some(3));
        assert_eq!(rec.usage.output, Some(2));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
    }

    #[test]
    fn anthropic_translator_maps_events_to_openai_chunks_and_record() {
        let mut t = StreamTranslator::for_record(anthropic_base());

        // message_start → role chunk; records id/model + prompt usage.
        let s = t.push(
            r#"{"type":"message_start","message":{"id":"msg_1","model":"claude-served-x","usage":{"input_tokens":12,"cache_read_input_tokens":4,"output_tokens":1}}}"#,
        );
        assert!(!s.done);
        assert_eq!(s.chunks.len(), 1);
        assert_eq!(s.chunks[0]["object"], "chat.completion.chunk");
        assert_eq!(s.chunks[0]["model"], "claude-served-x");
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["role"], "assistant");

        // content_block_start → no client frame.
        let s = t.push(
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        );
        assert!(s.chunks.is_empty() && !s.done);

        // text delta → content chunk; thinking/ping → nothing.
        let s = t.push(
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"He"}}"#,
        );
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["content"], "He");
        assert!(t.push(r#"{"type":"ping"}"#).chunks.is_empty());

        // message_delta → finish chunk; records stop_reason + output tokens.
        let s = t.push(
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}"#,
        );
        assert_eq!(s.chunks[0]["choices"][0]["finish_reason"], "stop");

        // message_stop → terminal [DONE].
        let s = t.push(r#"{"type":"message_stop"}"#);
        assert!(s.done);
        assert_eq!(s.chunks[0], Value::String("[DONE]".to_string()));

        // The aggregated record carries the Anthropic-mapped metadata.
        let rec = t.snapshot();
        assert_eq!(rec.upstream_protocol, UpstreamProtocol::AnthropicMessages);
        assert_eq!(rec.model_served.as_deref(), Some("claude-served-x"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("msg_1"));
        assert_eq!(rec.usage.input, Some(16));
        assert_eq!(rec.usage.cached_read, Some(4));
        assert_eq!(rec.usage.output, Some(7));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert_eq!(rec.provider_prompt_cache, Some(true));
    }

    #[test]
    fn anthropic_refusal_stop_reason_flags_record() {
        let mut t = StreamTranslator::for_record(anthropic_base());
        let s = t.push(r#"{"type":"message_delta","delta":{"stop_reason":"refusal"},"usage":{"output_tokens":1}}"#);
        assert_eq!(s.chunks[0]["choices"][0]["finish_reason"], "content_filter");
        assert!(t.snapshot().refusal);
    }

    // ---- Gemini StreamTranslator ------------------------------------------

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
    fn gemini_translator_maps_frames_to_openai_chunks_and_record() {
        let mut t = StreamTranslator::for_record(gemini_base());

        // First frame: identity + a text part. Emits a role chunk (Gemini has no
        // start event) THEN the content chunk; records modelVersion/responseId.
        let s = t.push(
            r#"{"responseId":"resp_1","modelVersion":"gemini-served-x","candidates":[{"content":{"role":"model","parts":[{"text":"He"}]}}]}"#,
        );
        assert!(!s.done);
        assert_eq!(s.chunks.len(), 2);
        assert_eq!(s.chunks[0]["object"], "chat.completion.chunk");
        assert_eq!(s.chunks[0]["model"], "gemini-served-x");
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(s.chunks[1]["choices"][0]["delta"]["content"], "He");

        // Second content frame: only a content chunk (role already emitted).
        let s = t.push(r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"llo"}]}}]}"#);
        assert_eq!(s.chunks.len(), 1);
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["content"], "llo");
        assert!(!s.done);

        // Final frame: finishReason + usageMetadata. Emits the trailing content,
        // a finish chunk, and the synthesized [DONE]; marks done.
        let s = t.push(
            r#"{"candidates":[{"finishReason":"STOP","content":{"role":"model","parts":[{"text":"!"}]}}],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3,"cachedContentTokenCount":2}}"#,
        );
        assert!(s.done);
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["content"], "!");
        assert_eq!(s.chunks[1]["choices"][0]["finish_reason"], "stop");
        assert_eq!(
            *s.chunks.last().unwrap(),
            Value::String("[DONE]".to_string())
        );

        let rec = t.snapshot();
        assert_eq!(rec.upstream_protocol, UpstreamProtocol::Gemini);
        assert_eq!(rec.model_served.as_deref(), Some("gemini-served-x"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("resp_1"));
        assert_eq!(rec.usage.input, Some(7));
        assert_eq!(rec.usage.output, Some(3));
        assert_eq!(rec.usage.cached_read, Some(2));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert_eq!(rec.provider_prompt_cache, Some(true));
        assert!(!rec.refusal);
    }

    #[test]
    fn gemini_safety_finish_flags_refusal_and_is_done() {
        // A SAFETY finish (no content) still emits role + finish + [DONE], marks
        // done, and flags refusal.
        let mut t = StreamTranslator::for_record(gemini_base());
        let s = t.push(r#"{"candidates":[{"finishReason":"SAFETY"}]}"#);
        assert!(s.done);
        assert_eq!(
            s.chunks[s.chunks.len() - 2]["choices"][0]["finish_reason"],
            "content_filter"
        );
        assert_eq!(
            *s.chunks.last().unwrap(),
            Value::String("[DONE]".to_string())
        );
        assert!(t.snapshot().refusal);
    }

    #[test]
    fn gemini_non_json_keepalive_is_ignored() {
        // A non-JSON data payload (keepalive) yields no client frame and is not
        // terminal — no fabrication from unparseable data.
        let mut t = StreamTranslator::for_record(gemini_base());
        let s = t.push(": keepalive");
        assert!(s.chunks.is_empty() && !s.done);
    }

    // ---- OpenAI Responses StreamTranslator --------------------------------

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
    fn responses_translator_maps_events_to_openai_chunks_and_record() {
        let mut t = StreamTranslator::for_record(responses_base());

        // response.created carries identity; first frame also emits the role chunk.
        let s = t.push(
            r#"{"type":"response.created","response":{"id":"resp_1","model":"gpt-5.4","status":"in_progress"}}"#,
        );
        assert!(!s.done);
        assert_eq!(s.chunks.len(), 1);
        assert_eq!(s.chunks[0]["object"], "chat.completion.chunk");
        assert_eq!(s.chunks[0]["model"], "gpt-5.4");
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["role"], "assistant");

        // output_item.added / content_part.added → no client frame.
        assert!(t
            .push(r#"{"type":"response.output_item.added","item":{"type":"message"}}"#)
            .chunks
            .is_empty());

        // output_text.delta → content; a reasoning-summary delta is NOT forwarded.
        let s = t.push(r#"{"type":"response.output_text.delta","delta":"He"}"#);
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["content"], "He");
        assert!(t
            .push(r#"{"type":"response.reasoning_summary_text.delta","delta":"thinking"}"#)
            .chunks
            .is_empty());
        let s = t.push(r#"{"type":"response.output_text.delta","delta":"llo"}"#);
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["content"], "llo");

        // response.completed → finish chunk + [DONE]; folds usage from response.usage.
        let s = t.push(
            r#"{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5.4","status":"completed","usage":{"input_tokens":7,"output_tokens":3,"input_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":1}}}}"#,
        );
        assert!(s.done);
        assert_eq!(s.chunks[0]["choices"][0]["finish_reason"], "stop");
        assert_eq!(
            *s.chunks.last().unwrap(),
            Value::String("[DONE]".to_string())
        );

        let rec = t.snapshot();
        assert_eq!(rec.upstream_protocol, UpstreamProtocol::OpenAiResponses);
        assert_eq!(rec.model_served.as_deref(), Some("gpt-5.4"));
        assert_eq!(rec.upstream_request_id.as_deref(), Some("resp_1"));
        assert_eq!(rec.usage.input, Some(7));
        assert_eq!(rec.usage.output, Some(3));
        assert_eq!(rec.usage.cached_read, Some(2));
        assert_eq!(rec.usage.reasoning, Some(1));
        assert_eq!(rec.finish_reason, Some(FinishReason::Stop));
        assert_eq!(rec.provider_prompt_cache, Some(true));
        assert!(!rec.refusal);
    }

    #[test]
    fn responses_incomplete_content_filter_flags_refusal_and_is_done() {
        let mut t = StreamTranslator::for_record(responses_base());
        let s = t.push(
            r#"{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"content_filter"}}}"#,
        );
        assert!(s.done);
        // role chunk (first frame) + finish chunk + [DONE].
        assert_eq!(
            s.chunks[s.chunks.len() - 2]["choices"][0]["finish_reason"],
            "content_filter"
        );
        assert_eq!(
            *s.chunks.last().unwrap(),
            Value::String("[DONE]".to_string())
        );
        assert!(t.snapshot().refusal);
    }

    #[test]
    fn responses_failed_is_not_terminal_so_egress_surfaces_truncation() {
        // A `response.failed` event is NOT a clean completion: it produces no
        // [DONE] and does not set done, so a subsequent stream close is surfaced
        // as a truncation by the egress rather than a masked success.
        let mut t = StreamTranslator::for_record(responses_base());
        let _role = t.push(r#"{"type":"response.created","response":{"id":"r","model":"m"}}"#);
        let s = t.push(r#"{"type":"response.failed","response":{"status":"failed"}}"#);
        assert!(!s.done);
        assert!(s.chunks.is_empty());
    }

    // ---- streaming tool calls ---------------------------------------------

    #[test]
    fn anthropic_streaming_tool_call_emits_delta_tool_calls() {
        let mut t = StreamTranslator::for_record(anthropic_base());
        t.push(
            r#"{"type":"message_start","message":{"id":"m1","model":"claude-x","usage":{"input_tokens":5}}}"#,
        );
        // A tool_use block opens → the OpenAI tool_call header.
        let s = t.push(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"get_weather"}}"#);
        let tc = &s.chunks[0]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["id"], "tu_1");
        assert_eq!(tc["function"]["name"], "get_weather");
        // input_json_delta → arguments delta.
        let s = t.push(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}"#);
        let tc = &s.chunks[0]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["function"]["arguments"], "{\"city\":");
        // tool_use stop → tool_calls finish (client + record).
        let s = t.push(r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":2}}"#);
        assert_eq!(s.chunks[0]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(t.snapshot().finish_reason, Some(FinishReason::ToolUse));
    }

    #[test]
    fn anthropic_streaming_emulation_routes_args_to_content() {
        let mut t = StreamTranslator::for_record(anthropic_base());
        t.push(r#"{"type":"message_start","message":{"id":"m1","model":"claude-x"}}"#);
        // The sentinel tool_use block emits NO tool_call header.
        let s = t.push(&format!(
            r#"{{"type":"content_block_start","index":0,"content_block":{{"type":"tool_use","id":"tu_1","name":"{STRUCTURED_OUTPUT_TOOL_NAME}"}}}}"#
        ));
        assert!(s.chunks.is_empty());
        // Its input_json_delta streams to the client as content (the JSON answer).
        let s = t.push(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"k\":1}"}}"#);
        assert_eq!(s.chunks[0]["choices"][0]["delta"]["content"], "{\"k\":1}");
        assert!(s.chunks[0]["choices"][0]["delta"]
            .get("tool_calls")
            .is_none());
        // Finishes as a normal stop (client received content, not a tool call).
        let s = t.push(r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"}}"#);
        assert_eq!(s.chunks[0]["choices"][0]["finish_reason"], "stop");
        assert_eq!(t.snapshot().finish_reason, Some(FinishReason::Stop));
    }

    #[test]
    fn gemini_streaming_function_call_emits_tool_calls() {
        let mut t = StreamTranslator::for_record(gemini_base());
        // A frame with a functionCall part → a whole tool_call chunk.
        let s = t.push(r#"{"responseId":"r1","modelVersion":"g-x","candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"SF"}}}]}}]}"#);
        let tc = s
            .chunks
            .iter()
            .find_map(|c| c["choices"][0]["delta"].get("tool_calls"))
            .expect("a tool_calls chunk");
        assert_eq!(tc[0]["function"]["name"], "get_weather");
        assert_eq!(tc[0]["id"], "call_0");
        assert_eq!(
            serde_json::from_str::<Value>(tc[0]["function"]["arguments"].as_str().unwrap())
                .unwrap(),
            json!({"city": "SF"})
        );
        // STOP + a tool call → tool_calls finish.
        let s = t.push(r#"{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":2}}"#);
        assert_eq!(
            s.chunks
                .iter()
                .find_map(|c| c["choices"][0]["finish_reason"].as_str()),
            Some("tool_calls")
        );
        assert_eq!(t.snapshot().finish_reason, Some(FinishReason::ToolUse));
    }

    #[test]
    fn responses_streaming_function_call_emits_tool_calls() {
        let mut t = StreamTranslator::for_record(responses_base());
        t.push(r#"{"type":"response.created","response":{"id":"r1","model":"gpt-x"}}"#);
        // output_item.added function_call → the tool_call header (id = call_id).
        let s = t.push(r#"{"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","call_id":"c1","name":"get_weather"}}"#);
        let tc = &s.chunks[0]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["id"], "c1");
        assert_eq!(tc["function"]["name"], "get_weather");
        // function_call_arguments.delta (keyed by item_id) → arguments delta.
        let s = t.push(r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"city\":\"SF\"}"}"#);
        let tc = &s.chunks[0]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["function"]["arguments"], "{\"city\":\"SF\"}");
        // completed + a tool call → tool_calls finish.
        let s = t.push(r#"{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":5,"output_tokens":2}}}"#);
        assert_eq!(
            s.chunks
                .iter()
                .find_map(|c| c["choices"][0]["finish_reason"].as_str()),
            Some("tool_calls")
        );
        assert_eq!(t.snapshot().finish_reason, Some(FinishReason::ToolUse));
    }

    #[test]
    fn chat_lift_text_emits_responses_event_sequence() {
        let mut lift = ChatStreamToResponses::new();
        let mut evs: Vec<(String, Value)> = Vec::new();
        evs.extend(
            lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"role":"assistant"}}]})),
        );
        evs.extend(
            lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"content":"He"}}]})),
        );
        evs.extend(
            lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"content":"llo"}}]})),
        );
        evs.extend(
            lift.push(
                &json!({"id":"c1","model":"m","choices":[{"delta":{},"finish_reason":"stop"}]}),
            ),
        );
        // A usage-only chunk is captured but emits no event.
        evs.extend(lift.push(
            &json!({"id":"c1","model":"m","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}),
        ));
        evs.extend(lift.finish(None));

        let names: Vec<&str> = evs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        // `sequence_number` is monotonic from 0.
        for (i, (_, e)) in evs.iter().enumerate() {
            assert_eq!(e["sequence_number"], i as u64);
        }
        // `response.created` carries id / model / in_progress.
        assert_eq!(evs[0].1["response"]["id"], "c1");
        assert_eq!(evs[0].1["response"]["model"], "m");
        assert_eq!(evs[0].1["response"]["status"], "in_progress");
        // The text deltas carry the content.
        assert_eq!(evs[3].1["delta"], "He");
        assert_eq!(evs[4].1["delta"], "llo");
        // `response.completed` carries the assembled message + converted usage.
        let completed = &evs.last().unwrap().1["response"];
        assert_eq!(completed["status"], "completed");
        assert_eq!(completed["output"][0]["type"], "message");
        assert_eq!(completed["output"][0]["content"][0]["text"], "Hello");
        assert_eq!(completed["usage"]["input_tokens"], 3);
        assert_eq!(completed["usage"]["output_tokens"], 2);
        assert_eq!(completed["usage"]["total_tokens"], 5);
    }

    #[test]
    fn chat_lift_tool_calls_emits_function_call_events() {
        let mut lift = ChatStreamToResponses::new();
        let mut evs: Vec<(String, Value)> = Vec::new();
        evs.extend(
            lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"role":"assistant"}}]})),
        );
        evs.extend(lift.push(
            &json!({"id":"c1","model":"m","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"f","arguments":""}}]}}]}),
        ));
        evs.extend(lift.push(
            &json!({"id":"c1","model":"m","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":"}}]}}]}),
        ));
        evs.extend(lift.push(
            &json!({"id":"c1","model":"m","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}),
        ));
        evs.extend(lift.push(
            &json!({"id":"c1","model":"m","choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
        ));
        evs.extend(lift.finish(None));

        let names: Vec<&str> = evs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.output_item.added",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        // The added item is a function_call carrying call_id + name.
        assert_eq!(evs[1].1["item"]["type"], "function_call");
        assert_eq!(evs[1].1["item"]["call_id"], "call_1");
        assert_eq!(evs[1].1["item"]["name"], "f");
        // The argument fragments accumulate into the final function_call.
        let completed = &evs.last().unwrap().1["response"];
        assert_eq!(completed["status"], "completed");
        assert_eq!(completed["output"][0]["type"], "function_call");
        assert_eq!(completed["output"][0]["call_id"], "call_1");
        assert_eq!(completed["output"][0]["arguments"], "{\"a\":1}");
    }

    #[test]
    fn chat_lift_length_finish_emits_incomplete() {
        let mut lift = ChatStreamToResponses::new();
        let _ = lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"content":"x"}}]}));
        let _ = lift.push(
            &json!({"id":"c1","model":"m","choices":[{"delta":{},"finish_reason":"length"}]}),
        );
        let fin = lift.finish(None);
        let (name, ev) = fin.last().unwrap();
        assert_eq!(name, "response.incomplete");
        assert_eq!(ev["response"]["status"], "incomplete");
        assert_eq!(
            ev["response"]["incomplete_details"]["reason"],
            "max_output_tokens"
        );
    }

    #[test]
    fn chat_lift_refusal_emits_refusal_part() {
        // A streamed structured-output refusal from an OpenAI-chat upstream carries
        // `delta.refusal` (no content). The lifter surfaces it as a `refusal`
        // content part with refusal.delta/done events, so the completed message
        // content is the refusal — not an empty turn (parity with unary Responses).
        let mut lift = ChatStreamToResponses::new();
        let mut evs: Vec<(String, Value)> = Vec::new();
        evs.extend(
            lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"role":"assistant"}}]})),
        );
        evs.extend(
            lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"refusal":"I can't "}}]})),
        );
        evs.extend(
            lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"refusal":"help."}}]})),
        );
        evs.extend(
            lift.push(
                &json!({"id":"c1","model":"m","choices":[{"delta":{},"finish_reason":"stop"}]}),
            ),
        );
        evs.extend(lift.finish(None));

        let names: Vec<&str> = evs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.output_item.added",
                "response.content_part.added",
                "response.refusal.delta",
                "response.refusal.delta",
                "response.refusal.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        // The opened content part is a `refusal` part.
        assert_eq!(evs[2].1["part"]["type"], "refusal");
        // The refusal text accumulates into the completed message content.
        let completed = &evs.last().unwrap().1["response"];
        assert_eq!(completed["status"], "completed");
        assert_eq!(completed["output"][0]["content"][0]["type"], "refusal");
        assert_eq!(
            completed["output"][0]["content"][0]["refusal"],
            "I can't help."
        );
    }

    #[test]
    fn chat_lift_usage_carries_cached_and_reasoning_details() {
        // The terminal usage object preserves the cached-prompt and reasoning detail
        // sub-objects (parity with the unary Responses usage renderer).
        let mut lift = ChatStreamToResponses::new();
        let _ = lift.push(&json!({"id":"c1","model":"m","choices":[{"delta":{"content":"x"}}]}));
        let _ = lift
            .push(&json!({"id":"c1","model":"m","choices":[{"delta":{},"finish_reason":"stop"}]}));
        let _ = lift.push(&json!({"id":"c1","model":"m","choices":[],"usage":{
            "prompt_tokens":10,"completion_tokens":5,"total_tokens":15,
            "prompt_tokens_details":{"cached_tokens":4},
            "completion_tokens_details":{"reasoning_tokens":2}
        }}));
        let fin = lift.finish(None);
        let usage = &fin.last().unwrap().1["response"]["usage"];
        assert_eq!(usage["input_tokens"], 10);
        assert_eq!(usage["output_tokens"], 5);
        assert_eq!(usage["total_tokens"], 15);
        assert_eq!(usage["input_tokens_details"]["cached_tokens"], 4);
        assert_eq!(usage["output_tokens_details"]["reasoning_tokens"], 2);
    }
}
