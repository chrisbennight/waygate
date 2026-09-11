//! The typed canonical **response** model — the egress counterpart to the
//! canonical *request* model ([`crate::canonical::LlmRequest`]). A provider's
//! native response is folded into a [`CanonicalResponse`] (modeled on the OpenAI
//! Responses *superset* — the most expressive client surface), and each client
//! surface renders *from* it: `/v1/chat/completions` via the
//! [`canonical_response_to_openai_chat`] downcast, and `/v1/responses` via
//! [`canonical_response_to_responses`] (near-identity). One hub both directions,
//! symmetric with the request side, so the lossy chat *wire* shape is no longer an
//! implicit response hub.
//!
//! **Opacity (design I-superset).** The hub carries provider-opaque material
//! losslessly so a Responses→Responses round-trip preserves it: `reasoning` items
//! (which may hold `encrypted_content`), unrecognized output-item / content-part
//! types ([`OutputItem::Unknown`] / [`OutputContentPart::Unknown`]), and a top-level
//! `extra` catch-all. The chat downcast deliberately drops what chat cannot carry
//! (reasoning, annotations, built-in-tool items) — which is exactly why the
//! existing `*_to_openai_chat` translators are the byte-for-byte golden oracle for
//! the downcast (they already omit the same material).
//!
//! Both egress directions are implemented: the four provider `→ canonical` folds
//! (incl. [`openai_chat_to_canonical_response`], for a Responses client whose call
//! routed to a Chat-Completions upstream), the chat downcast, and the Responses
//! egress. The OpenAI-chat upstream stays a pure passthrough *for a chat client*
//! (a typed hub cannot byte-preserve every chat field — logprobs,
//! `system_fingerprint`, multiple choices); a Responses client lifts it into the
//! hub.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::outbound::STRUCTURED_OUTPUT_TOOL_NAME;
use crate::response::{str_field, u64_field};

/// A provider's response, folded into the canonical (Responses-superset) shape.
/// Identity fields are `None` when the provider omitted them — never fabricated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CanonicalResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    pub status: ResponseStatus,
    /// Whether the turn was a safety refusal (sets the chat `content_filter`
    /// finish and the `InferenceRecord` refusal flag).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refusal: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output: Vec<OutputItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Opaque top-level fields the hub does not model, preserved verbatim so a
    /// Responses→Responses round-trip is lossless (the chat downcast ignores them).
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

/// Terminal disposition of a response, in Responses-native terms. The chat
/// downcast maps it to the `finish_reason` vocabulary; a tool-call turn overrides
/// to `tool_calls` regardless (every provider reports a "normal" stop on a
/// tool-call turn).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResponseStatus {
    #[default]
    Completed,
    Incomplete {
        reason: IncompleteReason,
    },
    InProgress,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    MaxOutputTokens,
    ContentFilter,
    Other,
}

/// One item in a response's `output[]`. `Reasoning` and `Unknown` are opaque
/// passthrough (carried for Responses fidelity; dropped by the chat downcast).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutputItem {
    Message {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        content: Vec<OutputContentPart>,
        /// Unmodeled item-level fields (e.g. `status`) preserved verbatim so a
        /// Responses→Responses round-trip is lossless. Dropped by the chat downcast.
        #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
        extra: Map<String, Value>,
    },
    FunctionCall {
        call_id: String,
        name: String,
        /// OpenAI's JSON *string* arguments, kept verbatim.
        arguments: String,
        /// Unmodeled item-level fields (the output-item `id` — distinct from
        /// `call_id` — and `status`) preserved verbatim for a lossless round-trip.
        #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
        extra: Map<String, Value>,
    },
    /// A reasoning item — carried verbatim (it may hold `encrypted_content`).
    Reasoning { raw: Value },
    /// Any output-item type the hub does not model — re-emitted verbatim on the
    /// Responses surface, dropped on chat.
    Unknown(Value),
}

/// One content part of a `Message` output item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutputContentPart {
    OutputText {
        text: String,
        /// Unmodeled `output_text` part fields (e.g. `annotations`, `logprobs`)
        /// preserved verbatim so a Responses→Responses round-trip is lossless.
        /// The chat downcast ignores them (it reads only `text`).
        #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
        extra: Map<String, Value>,
    },
    Unknown(Value),
}

/// Token usage, in the canonical (Responses-superset) classes. Unreported classes
/// stay `None` — never fabricated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Usage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_read: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<u64>,
}

impl CanonicalResponse {
    /// Concatenate the `output_text` of every `Message` item — the assistant text
    /// the chat surface shows. Matches the existing translators, which join all
    /// text blocks into one `content` string.
    fn content_text(&self) -> String {
        let mut s = String::new();
        for item in &self.output {
            if let OutputItem::Message { content, .. } = item {
                for part in content {
                    if let OutputContentPart::OutputText { text, .. } = part {
                        s.push_str(text);
                    }
                }
            }
        }
        s
    }

    /// Collect `FunctionCall` items into OpenAI `tool_calls`
    /// (`[{id, type:function, function:{name, arguments}}]`).
    fn tool_calls(&self) -> Vec<Value> {
        self.output
            .iter()
            .filter_map(|item| match item {
                OutputItem::FunctionCall {
                    call_id,
                    name,
                    arguments,
                    ..
                } => Some(json!({
                    "id": call_id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments },
                })),
                _ => None,
            })
            .collect()
    }
}

/// Map a [`ResponseStatus`] to the OpenAI Chat `finish_reason` (before the
/// tool-call override). `None` ⇒ the provider reported no terminal reason, which
/// the chat body carries as `finish_reason: null` — matching the legacy
/// translators, which `.map()` an absent provider finish field to `None`.
fn status_to_finish_reason(status: &ResponseStatus) -> Option<&'static str> {
    match status {
        ResponseStatus::Completed => Some("stop"),
        ResponseStatus::Incomplete { reason } => Some(match reason {
            IncompleteReason::MaxOutputTokens => "length",
            IncompleteReason::ContentFilter => "content_filter",
            IncompleteReason::Other => "stop",
        }),
        ResponseStatus::InProgress | ResponseStatus::Failed => None,
    }
}

/// Render a [`CanonicalResponse`] into the OpenAI Chat Completions response shape
/// — the downcast the gateway's `/v1/chat/completions` route serves regardless of
/// which provider (Anthropic / Gemini / OpenAI-Responses) served the call. It
/// reproduces, byte-for-byte, what the per-provider `*_to_openai_chat` translators
/// produced; the existing translators are the golden oracle (this module's tests
/// assert the equivalence). Reasoning items, annotations, and unknown items have
/// no chat representation and are dropped — exactly as the legacy translators did.
pub fn canonical_response_to_openai_chat(resp: &CanonicalResponse) -> Value {
    let content_text = resp.content_text();
    let tool_calls = resp.tool_calls();

    let mut message = Map::new();
    message.insert("role".into(), Value::from("assistant"));
    // OpenAI's canonical no-text-but-tool-calls form is `content: null`.
    if content_text.is_empty() && !tool_calls.is_empty() {
        message.insert("content".into(), Value::Null);
    } else {
        message.insert("content".into(), Value::from(content_text));
    }
    let mut finish_reason = status_to_finish_reason(&resp.status);
    if !tool_calls.is_empty() {
        // A tool-call turn always finishes `tool_calls`, even if the provider
        // reported a "normal" stop (or none at all).
        finish_reason = Some("tool_calls");
        message.insert("tool_calls".into(), Value::Array(tool_calls));
    }

    let mut obj = Map::new();
    if let Some(id) = &resp.id {
        obj.insert("id".into(), json!(id));
    }
    obj.insert("object".into(), Value::from("chat.completion"));
    if let Some(model) = &resp.model {
        obj.insert("model".into(), json!(model));
    }
    obj.insert(
        "choices".into(),
        json!([{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }]),
    );
    if let Some(usage) = &resp.usage {
        if usage.input.is_some() || usage.output.is_some() {
            obj.insert(
                "usage".into(),
                json!({
                    "prompt_tokens": usage.input,
                    "completion_tokens": usage.output,
                    "total_tokens": usage.total,
                }),
            );
        }
    }
    Value::Object(obj)
}

/// Fold an **Anthropic Messages** response body into a [`CanonicalResponse`].
/// Text blocks → an assistant `Message` item's `output_text` parts; `tool_use`
/// blocks → `FunctionCall` items; `stop_reason` → [`ResponseStatus`]. The
/// structured-output emulation (a `tool_use` named [`STRUCTURED_OUTPUT_TOOL_NAME`])
/// is unwound here into a `Message` whose text is the serialized tool input, with
/// a `Completed` status — to the client it is a structured *answer*, not a call.
pub fn anthropic_to_canonical_response(resp: &Value) -> CanonicalResponse {
    let blocks = resp.get("content").and_then(Value::as_array);
    // An absent `stop_reason` maps to `InProgress` (no terminal reason) so the
    // chat downcast emits `finish_reason: null`, matching the legacy translator.
    let mut status = resp
        .get("stop_reason")
        .and_then(Value::as_str)
        .map(anthropic_stop_reason_to_status)
        .unwrap_or(ResponseStatus::InProgress);
    let refusal = resp.get("stop_reason").and_then(Value::as_str) == Some("refusal");

    let emulated = blocks.and_then(|bs| {
        bs.iter().find(|b| {
            b.get("type").and_then(Value::as_str) == Some("tool_use")
                && b.get("name").and_then(Value::as_str) == Some(STRUCTURED_OUTPUT_TOOL_NAME)
        })
    });

    let mut output: Vec<OutputItem> = Vec::new();
    if let Some(b) = emulated {
        // Unwind the forced tool into a normal structured answer.
        let input = b.get("input").cloned().unwrap_or_else(|| json!({}));
        let text = serde_json::to_string(&input).unwrap_or_default();
        output.push(OutputItem::Message {
            id: None,
            content: vec![OutputContentPart::OutputText {
                text,
                extra: Map::new(),
            }],
            extra: Map::new(),
        });
        status = ResponseStatus::Completed;
    } else if let Some(bs) = blocks {
        // Text blocks join into one message item; tool_use blocks become
        // function_call items (in source order, after the message).
        let content: Vec<OutputContentPart> = bs
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .map(|t| OutputContentPart::OutputText {
                text: t.to_string(),
                extra: Map::new(),
            })
            .collect();
        if !content.is_empty() {
            output.push(OutputItem::Message {
                id: None,
                content,
                extra: Map::new(),
            });
        }
        for b in bs
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
        {
            output.push(OutputItem::FunctionCall {
                call_id: b
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                name: b
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: b
                    .get("input")
                    .map(|i| serde_json::to_string(i).unwrap_or_default())
                    .unwrap_or_else(|| "{}".to_string()),
                extra: Map::new(),
            });
        }
    }

    CanonicalResponse {
        id: str_field(resp, "id"),
        model: str_field(resp, "model"),
        created_at: None,
        status,
        refusal,
        output,
        usage: resp.get("usage").map(|u| Usage {
            input: u64_field(u, "input_tokens"),
            output: u64_field(u, "output_tokens"),
            total: match (u64_field(u, "input_tokens"), u64_field(u, "output_tokens")) {
                (Some(p), Some(c)) => Some(p + c),
                _ => None,
            },
            cached_read: u64_field(u, "cache_read_input_tokens"),
            reasoning: None,
        }),
        // Empty: Anthropic is *translated*, not round-tripped — its native
        // top-level fields have no place in a Responses-shaped egress body.
        extra: Map::new(),
    }
}

/// Map an Anthropic `stop_reason` to the canonical [`ResponseStatus`]. The chat
/// `finish_reason` it downcasts to matches `anthropic_stop_reason_to_openai` (the
/// legacy translator's mapping), asserted by the golden-oracle test.
fn anthropic_stop_reason_to_status(s: &str) -> ResponseStatus {
    match s {
        "max_tokens" => ResponseStatus::Incomplete {
            reason: IncompleteReason::MaxOutputTokens,
        },
        "refusal" => ResponseStatus::Incomplete {
            reason: IncompleteReason::ContentFilter,
        },
        // end_turn / stop_sequence / tool_use / unknown → a normal completion (a
        // tool-call turn is overridden to `tool_calls` by the downcast from the
        // presence of FunctionCall items, matching the legacy translator).
        _ => ResponseStatus::Completed,
    }
}

/// Fold a **Gemini `generateContent`** response body into a [`CanonicalResponse`].
/// `candidates[0].content.parts` text → an assistant `Message`'s `output_text`;
/// `functionCall` parts → `FunctionCall` items (Gemini emits no call id, so a
/// synthetic `call_N` is minted, matching the legacy translator); `finishReason`
/// → [`ResponseStatus`].
pub fn gemini_to_canonical_response(resp: &Value) -> CanonicalResponse {
    let candidate = resp
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|c| c.first());
    let parts = candidate
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(Value::as_array);

    let mut output: Vec<OutputItem> = Vec::new();
    // All text parts join into one message item (Gemini has no per-block id).
    let content: Vec<OutputContentPart> = parts
        .map(|ps| {
            ps.iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .map(|t| OutputContentPart::OutputText {
                    text: t.to_string(),
                    extra: Map::new(),
                })
                .collect()
        })
        .unwrap_or_default();
    if !content.is_empty() {
        output.push(OutputItem::Message {
            id: None,
            content,
            extra: Map::new(),
        });
    }
    // functionCall parts → function_call items with synthetic `call_N` ids.
    if let Some(ps) = parts {
        for (i, fc) in ps.iter().filter_map(|p| p.get("functionCall")).enumerate() {
            output.push(OutputItem::FunctionCall {
                call_id: format!("call_{i}"),
                name: fc
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: fc
                    .get("args")
                    .map(|a| serde_json::to_string(a).unwrap_or_default())
                    .unwrap_or_else(|| "{}".to_string()),
                extra: Map::new(),
            });
        }
    }

    let finish = candidate.and_then(|c| str_field(c, "finishReason"));
    let status = finish
        .as_deref()
        .map(gemini_finish_reason_to_status)
        .unwrap_or(ResponseStatus::InProgress);
    let refusal = matches!(
        finish.as_deref(),
        Some("SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII")
    );

    CanonicalResponse {
        id: str_field(resp, "responseId"),
        model: str_field(resp, "modelVersion"),
        created_at: None,
        status,
        refusal,
        output,
        usage: resp.get("usageMetadata").map(|um| {
            let input = u64_field(um, "promptTokenCount");
            let output = u64_field(um, "candidatesTokenCount");
            Usage {
                input,
                output,
                // Gemini reports `totalTokenCount`; fall back to the sum (matching
                // the legacy translator) only when it is absent and both are known.
                total: u64_field(um, "totalTokenCount").or(match (input, output) {
                    (Some(p), Some(c)) => Some(p + c),
                    _ => None,
                }),
                cached_read: u64_field(um, "cachedContentTokenCount"),
                reasoning: u64_field(um, "thoughtsTokenCount"),
            }
        }),
        // Empty: Gemini is *translated*, not round-tripped (see the Anthropic fold).
        extra: Map::new(),
    }
}

/// Map a Gemini `finishReason` to the canonical [`ResponseStatus`]. The chat
/// `finish_reason` it downcasts to matches `gemini_finish_reason_to_openai` (the
/// legacy translator's mapping — `STOP`/unknown → stop), asserted by the golden
/// oracle.
fn gemini_finish_reason_to_status(s: &str) -> ResponseStatus {
    match s {
        "MAX_TOKENS" => ResponseStatus::Incomplete {
            reason: IncompleteReason::MaxOutputTokens,
        },
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => {
            ResponseStatus::Incomplete {
                reason: IncompleteReason::ContentFilter,
            }
        }
        _ => ResponseStatus::Completed,
    }
}

/// Fold an **OpenAI Responses** (`/responses`) response body into a
/// [`CanonicalResponse`] — a near-identity typed fold (the hub is modeled on this
/// shape). `output[]` `message` items keep their `output_text` parts; other
/// content parts and unrecognized output items are carried opaquely
/// ([`OutputContentPart::Unknown`] / [`OutputItem::Unknown`] / [`OutputItem::Reasoning`])
/// so a Responses→Responses round-trip is lossless. `status` (+
/// `incomplete_details`) → [`ResponseStatus`].
pub fn openai_responses_to_canonical_response(resp: &Value) -> CanonicalResponse {
    let status = responses_status_to_canonical(resp);
    let refusal = matches!(
        status,
        ResponseStatus::Incomplete {
            reason: IncompleteReason::ContentFilter
        }
    );

    let output = resp
        .get("output")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(responses_output_item).collect())
        .unwrap_or_default();

    CanonicalResponse {
        id: str_field(resp, "id"),
        model: str_field(resp, "model"),
        created_at: resp.get("created_at").and_then(Value::as_u64),
        status,
        refusal,
        output,
        usage: resp.get("usage").map(|u| {
            let input = u64_field(u, "input_tokens");
            let output = u64_field(u, "output_tokens");
            Usage {
                input,
                output,
                total: u64_field(u, "total_tokens").or(match (input, output) {
                    (Some(p), Some(c)) => Some(p + c),
                    _ => None,
                }),
                cached_read: u
                    .get("input_tokens_details")
                    .and_then(|d| u64_field(d, "cached_tokens")),
                reasoning: u
                    .get("output_tokens_details")
                    .and_then(|d| u64_field(d, "reasoning_tokens")),
            }
        }),
        // Preserve every unmodeled top-level Responses field (`object`,
        // `instructions`, `tools`, `metadata`, `service_tier`, `error`, …) so a
        // Responses→canonical→Responses round-trip is lossless — the whole point
        // of a Responses-superset hub. `incomplete_details` is folded into
        // `status` (and reconstructed on the Responses egress), so it is consumed,
        // not carried here.
        extra: unmodeled_fields(
            resp,
            &[
                "id",
                "model",
                "created_at",
                "status",
                "incomplete_details",
                "output",
                "usage",
            ],
        ),
    }
}

/// Collect a response object's top-level fields that the hub does not model into
/// the opaque `extra` map (verbatim), so they survive a same-shape round-trip.
/// Only meaningful for the OpenAI-Responses fold: the Anthropic / Gemini folds
/// *translate* (their native top-level fields have no place in a Responses body),
/// so they carry an empty `extra`.
fn unmodeled_fields(resp: &Value, consumed: &[&str]) -> Map<String, Value> {
    resp.as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| !consumed.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Convert one Responses `output[]` item. `message` keeps its content parts;
/// `function_call` → [`OutputItem::FunctionCall`]; `reasoning` is carried verbatim;
/// any other type is opaque ([`OutputItem::Unknown`]).
fn responses_output_item(item: &Value) -> OutputItem {
    match item.get("type").and_then(Value::as_str) {
        Some("message") => OutputItem::Message {
            id: str_field(item, "id"),
            content: item
                .get("content")
                .and_then(Value::as_array)
                .map(|parts| parts.iter().map(responses_content_part).collect())
                .unwrap_or_default(),
            // Preserve item-level fields (e.g. `status`) for the round-trip.
            extra: unmodeled_fields(item, &["type", "id", "role", "content"]),
        },
        Some("function_call") => OutputItem::FunctionCall {
            call_id: str_field(item, "call_id").unwrap_or_default(),
            name: str_field(item, "name").unwrap_or_default(),
            arguments: str_field(item, "arguments").unwrap_or_default(),
            // Preserve the output-item `id` (distinct from `call_id`) and `status`.
            extra: unmodeled_fields(item, &["type", "call_id", "name", "arguments"]),
        },
        Some("reasoning") => OutputItem::Reasoning { raw: item.clone() },
        _ => OutputItem::Unknown(item.clone()),
    }
}

/// Convert one Responses content part: `output_text` → text; anything else is
/// carried opaquely (it has no chat representation but is preserved for the
/// Responses surface).
fn responses_content_part(part: &Value) -> OutputContentPart {
    match part.get("type").and_then(Value::as_str) {
        Some("output_text") => OutputContentPart::OutputText {
            text: str_field(part, "text").unwrap_or_default(),
            // Preserve `annotations`, `logprobs`, and any other part metadata so a
            // Responses round-trip keeps them (the chat downcast ignores them).
            extra: unmodeled_fields(part, &["type", "text"]),
        },
        _ => OutputContentPart::Unknown(part.clone()),
    }
}

/// Map a Responses object's `status` (+ `incomplete_details.reason`) to the
/// canonical [`ResponseStatus`]. `completed` → `Completed`; `incomplete` → the
/// mapped reason; `failed` → `Failed` (so the egress can round-trip it — both
/// `InProgress` and `Failed` downcast to `finish_reason: null`, matching the
/// legacy `response::responses_finish`, so the chat golden oracle is unaffected);
/// any other / absent status → `InProgress`.
fn responses_status_to_canonical(resp: &Value) -> ResponseStatus {
    match str_field(resp, "status").as_deref() {
        Some("completed") => ResponseStatus::Completed,
        Some("failed") => ResponseStatus::Failed,
        Some("incomplete") => ResponseStatus::Incomplete {
            reason: match resp
                .get("incomplete_details")
                .and_then(|d| str_field(d, "reason"))
                .as_deref()
            {
                Some("max_output_tokens") => IncompleteReason::MaxOutputTokens,
                Some("content_filter") => IncompleteReason::ContentFilter,
                _ => IncompleteReason::Other,
            },
        },
        _ => ResponseStatus::InProgress,
    }
}

// ===========================================================================
// Egress: CanonicalResponse → the client surfaces
// ===========================================================================

/// Render a [`CanonicalResponse`] into an OpenAI **Responses**-shaped body — the
/// `/v1/responses` egress. The opaque `extra` fields are flattened back first;
/// the modeled fields (id / model / status / output / usage) overlay them
/// (authoritative on any collision). `status` reconstructs `incomplete_details`.
/// For an OpenAI-Responses upstream this is a near-identity round-trip (the
/// preserved `extra` makes it lossless); for a translated provider (Anthropic /
/// Gemini / chat upstream) it is the faithful Responses projection of the call.
pub fn canonical_response_to_responses(resp: &CanonicalResponse) -> Value {
    let mut obj = Map::new();
    // Opaque passthrough first; modeled fields overlay (their value is authoritative).
    for (k, v) in &resp.extra {
        obj.insert(k.clone(), v.clone());
    }
    if let Some(id) = &resp.id {
        obj.insert("id".into(), json!(id));
    }
    obj.insert("object".into(), json!("response"));
    if let Some(ca) = resp.created_at {
        obj.insert("created_at".into(), json!(ca));
    }
    if let Some(model) = &resp.model {
        obj.insert("model".into(), json!(model));
    }
    let (status, incomplete_reason) = match &resp.status {
        ResponseStatus::Completed => ("completed", None),
        ResponseStatus::InProgress => ("in_progress", None),
        ResponseStatus::Failed => ("failed", None),
        ResponseStatus::Incomplete { reason } => (
            "incomplete",
            Some(match reason {
                IncompleteReason::MaxOutputTokens => "max_output_tokens",
                IncompleteReason::ContentFilter => "content_filter",
                IncompleteReason::Other => "other",
            }),
        ),
    };
    obj.insert("status".into(), json!(status));
    if let Some(reason) = incomplete_reason {
        obj.insert("incomplete_details".into(), json!({ "reason": reason }));
    }
    obj.insert(
        "output".into(),
        Value::Array(resp.output.iter().map(output_item_to_responses).collect()),
    );
    if let Some(u) = &resp.usage {
        obj.insert("usage".into(), usage_to_responses(u));
    }
    Value::Object(obj)
}

/// Render one [`OutputItem`] as a Responses `output[]` entry. Opaque items
/// (`Reasoning` / `Unknown`) are re-emitted verbatim.
fn output_item_to_responses(item: &OutputItem) -> Value {
    match item {
        OutputItem::Message { id, content, extra } => {
            // Opaque item metadata (e.g. `status`) first; modeled fields overlay.
            let mut m = extra.clone();
            m.insert("type".into(), json!("message"));
            if let Some(id) = id {
                m.insert("id".into(), json!(id));
            }
            m.insert("role".into(), json!("assistant"));
            m.insert(
                "content".into(),
                Value::Array(content.iter().map(content_part_to_responses).collect()),
            );
            Value::Object(m)
        }
        OutputItem::FunctionCall {
            call_id,
            name,
            arguments,
            extra,
        } => {
            // Opaque item metadata (output-item `id`, `status`) first; modeled overlay.
            let mut o = extra.clone();
            o.insert("type".into(), json!("function_call"));
            o.insert("call_id".into(), json!(call_id));
            o.insert("name".into(), json!(name));
            o.insert("arguments".into(), json!(arguments));
            Value::Object(o)
        }
        OutputItem::Reasoning { raw } => raw.clone(),
        OutputItem::Unknown(v) => v.clone(),
    }
}

/// Render one content part as a Responses content part. Opaque parts are verbatim.
fn content_part_to_responses(part: &OutputContentPart) -> Value {
    match part {
        OutputContentPart::OutputText { text, extra } => {
            // Opaque part metadata first; `type`/`text` overlay (authoritative).
            let mut o = extra.clone();
            o.insert("type".into(), json!("output_text"));
            o.insert("text".into(), json!(text));
            Value::Object(o)
        }
        OutputContentPart::Unknown(v) => v.clone(),
    }
}

/// Render canonical [`Usage`] in the Responses shape (`input_tokens` /
/// `output_tokens` / `total_tokens` + `*_tokens_details`). Unreported classes are
/// omitted.
fn usage_to_responses(u: &Usage) -> Value {
    let mut usage = Map::new();
    if let Some(i) = u.input {
        usage.insert("input_tokens".into(), json!(i));
    }
    if let Some(o) = u.output {
        usage.insert("output_tokens".into(), json!(o));
    }
    if let Some(t) = u.total {
        usage.insert("total_tokens".into(), json!(t));
    }
    if let Some(c) = u.cached_read {
        usage.insert("input_tokens_details".into(), json!({ "cached_tokens": c }));
    }
    if let Some(r) = u.reasoning {
        usage.insert(
            "output_tokens_details".into(),
            json!({ "reasoning_tokens": r }),
        );
    }
    Value::Object(usage)
}

/// Fold an **OpenAI Chat Completions** response body into a [`CanonicalResponse`].
/// Used for a Responses-surface client whose call routed to a Chat-Completions
/// upstream (the one provider R2a left as a chat passthrough): the chat body must
/// be lifted into the hub so the Responses egress can render it. `choices[0]`'s
/// message text → an assistant `Message` item; its `tool_calls` → `FunctionCall`
/// items; `finish_reason` → [`ResponseStatus`].
pub fn openai_chat_to_canonical_response(resp: &Value) -> CanonicalResponse {
    let choice = resp
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first());
    let message = choice.and_then(|c| c.get("message"));

    let mut output: Vec<OutputItem> = Vec::new();
    // Assemble the assistant message item's content parts: output text, then a
    // refusal part if the chat upstream reported one.
    let mut content_parts: Vec<OutputContentPart> = Vec::new();
    if let Some(t) = message
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    {
        content_parts.push(OutputContentPart::OutputText {
            text: t.to_string(),
            extra: Map::new(),
        });
    }
    // OpenAI structured outputs report a refusal in `message.refusal` (a non-empty
    // string) even when `finish_reason` is "stop". Surface it as a Responses
    // `refusal` content part (carried opaquely) so a Responses client sees the
    // refusal text instead of an empty completed turn, mirroring the legacy chat
    // extractor that flags `message.refusal` (`response::extract_openai_chat`).
    let message_refusal = message
        .and_then(|m| m.get("refusal"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if let Some(r) = message_refusal {
        content_parts.push(OutputContentPart::Unknown(
            json!({ "type": "refusal", "refusal": r }),
        ));
    }
    if !content_parts.is_empty() {
        output.push(OutputItem::Message {
            id: None,
            content: content_parts,
            extra: Map::new(),
        });
    }
    if let Some(tcs) = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(Value::as_array)
    {
        for tc in tcs {
            let func = tc.get("function");
            output.push(OutputItem::FunctionCall {
                call_id: str_field(tc, "id").unwrap_or_default(),
                name: func.and_then(|f| str_field(f, "name")).unwrap_or_default(),
                arguments: func
                    .and_then(|f| str_field(f, "arguments"))
                    .unwrap_or_default(),
                extra: Map::new(),
            });
        }
    }

    let (status, finish_refusal) =
        chat_finish_to_status(choice.and_then(|c| str_field(c, "finish_reason")));
    // A `content_filter` finish OR a non-empty `message.refusal` is a refusal.
    let refusal = finish_refusal || message_refusal.is_some();

    CanonicalResponse {
        id: str_field(resp, "id"),
        model: str_field(resp, "model"),
        created_at: resp.get("created").and_then(Value::as_u64),
        status,
        refusal,
        output,
        usage: resp.get("usage").map(|u| Usage {
            input: u64_field(u, "prompt_tokens"),
            output: u64_field(u, "completion_tokens"),
            total: u64_field(u, "total_tokens"),
            cached_read: u
                .get("prompt_tokens_details")
                .and_then(|d| u64_field(d, "cached_tokens")),
            reasoning: u
                .get("completion_tokens_details")
                .and_then(|d| u64_field(d, "reasoning_tokens")),
        }),
        extra: Map::new(),
    }
}

/// Map an OpenAI Chat `finish_reason` to a canonical [`ResponseStatus`] + refusal
/// flag. `stop` / `tool_calls` → completed; `length` → incomplete/max-tokens;
/// `content_filter` → incomplete/content-filter (refusal); absent / unknown →
/// in-progress (no terminal reason).
fn chat_finish_to_status(finish: Option<String>) -> (ResponseStatus, bool) {
    match finish.as_deref() {
        Some("stop") | Some("tool_calls") => (ResponseStatus::Completed, false),
        Some("length") => (
            ResponseStatus::Incomplete {
                reason: IncompleteReason::MaxOutputTokens,
            },
            false,
        ),
        Some("content_filter") => (
            ResponseStatus::Incomplete {
                reason: IncompleteReason::ContentFilter,
            },
            true,
        ),
        _ => (ResponseStatus::InProgress, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::{
        anthropic_response_to_openai_chat, gemini_response_to_openai_chat,
        openai_responses_to_openai_chat,
    };

    /// The golden oracle: for a representative corpus of Anthropic response
    /// bodies, the new `anthropic → canonical → chat` path must reproduce the
    /// shipped `anthropic_response_to_openai_chat` output **byte-for-byte**, so
    /// switching the dispatch egress through the canonical hub cannot regress the
    /// live `/v1/chat/completions` surface.
    fn assert_anthropic_golden(resp: Value) {
        let via_canonical =
            canonical_response_to_openai_chat(&anthropic_to_canonical_response(&resp));
        let legacy = anthropic_response_to_openai_chat(&resp);
        assert_eq!(
            via_canonical, legacy,
            "canonical downcast diverged from the legacy translator for {resp}"
        );
    }

    #[test]
    fn anthropic_chat_downcast_matches_legacy_translator() {
        // Plain text completion with usage.
        assert_anthropic_golden(json!({
            "id": "msg_1", "model": "claude-x", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "Hel"}, {"type": "text", "text": "lo"}],
            "usage": {"input_tokens": 12, "output_tokens": 4}
        }));
        // Text + a tool call.
        assert_anthropic_golden(json!({
            "id": "msg_2", "model": "claude-x", "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "let me check"},
                {"type": "tool_use", "id": "tu_1", "name": "get_weather", "input": {"city": "SF"}}
            ],
            "usage": {"input_tokens": 9, "output_tokens": 3}
        }));
        // Tool-call-only (content: null).
        assert_anthropic_golden(json!({
            "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "t", "name": "f", "input": {}}]
        }));
        // Length cap.
        assert_anthropic_golden(json!({
            "id": "m", "model": "c", "stop_reason": "max_tokens",
            "content": [{"type": "text", "text": "truncat"}],
            "usage": {"input_tokens": 5, "output_tokens": 2}
        }));
        // Refusal → content_filter.
        assert_anthropic_golden(json!({
            "stop_reason": "refusal", "content": [{"type": "text", "text": "no"}]
        }));
        // The structured-output emulation unwinds to content with a `stop` finish.
        assert_anthropic_golden(json!({
            "id": "m", "model": "c", "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "tu", "name": STRUCTURED_OUTPUT_TOOL_NAME,
                "input": {"answer": 42}}]
        }));
        // No usage object ⇒ no usage key.
        assert_anthropic_golden(json!({
            "stop_reason": "end_turn", "content": [{"type": "text", "text": "hi"}]
        }));
        // Unknown stop_reason defaults to stop.
        assert_anthropic_golden(json!({
            "stop_reason": "something_new", "content": [{"type": "text", "text": "x"}]
        }));
        // Absent stop_reason → finish_reason: null (no terminal reason reported).
        assert_anthropic_golden(json!({
            "content": [{"type": "text", "text": "partial"}]
        }));
        // Absent stop_reason but with a tool call → still `tool_calls`.
        assert_anthropic_golden(json!({
            "content": [{"type": "tool_use", "id": "t", "name": "f", "input": {"a": 1}}]
        }));
    }

    fn assert_gemini_golden(resp: Value) {
        let via_canonical = canonical_response_to_openai_chat(&gemini_to_canonical_response(&resp));
        let legacy = gemini_response_to_openai_chat(&resp);
        assert_eq!(
            via_canonical, legacy,
            "gemini canonical downcast diverged from the legacy translator for {resp}"
        );
    }

    #[test]
    fn gemini_chat_downcast_matches_legacy_translator() {
        // Plain text with usage (totalTokenCount present, used verbatim).
        assert_gemini_golden(json!({
            "responseId": "r1", "modelVersion": "gemini-x",
            "candidates": [{"finishReason": "STOP", "content": {"role": "model",
                "parts": [{"text": "He"}, {"text": "llo"}]}}],
            "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 6, "totalTokenCount": 17}
        }));
        // A function call (synthetic call_0 id); STOP overridden to tool_calls.
        assert_gemini_golden(json!({
            "responseId": "r2", "modelVersion": "gemini-x",
            "candidates": [{"finishReason": "STOP", "content": {"role": "model",
                "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}]}}],
            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2}
        }));
        // MAX_TOKENS → length; no totalTokenCount → computed sum.
        assert_gemini_golden(json!({
            "candidates": [{"finishReason": "MAX_TOKENS", "content": {"role": "model",
                "parts": [{"text": "trunc"}]}}],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1}
        }));
        // SAFETY → content_filter (no content parts).
        assert_gemini_golden(json!({"candidates": [{"finishReason": "SAFETY"}]}));
        // Absent finishReason → finish_reason: null.
        assert_gemini_golden(json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "partial"}]}}]
        }));
        // Unknown finishReason → stop; no usageMetadata → no usage key.
        assert_gemini_golden(json!({
            "candidates": [{"finishReason": "WHATEVER",
                "content": {"role": "model", "parts": [{"text": "x"}]}}]
        }));
        // Empty candidates → a bare body.
        assert_gemini_golden(json!({"candidates": []}));
    }

    fn assert_responses_golden(resp: Value) {
        let via_canonical =
            canonical_response_to_openai_chat(&openai_responses_to_canonical_response(&resp));
        let legacy = openai_responses_to_openai_chat(&resp);
        assert_eq!(
            via_canonical, legacy,
            "responses canonical downcast diverged from the legacy translator for {resp}"
        );
    }

    #[test]
    fn responses_chat_downcast_matches_legacy_translator() {
        // Text completion (the reasoning item is dropped by the chat downcast).
        assert_responses_golden(json!({
            "id": "resp_1", "model": "gpt-x", "status": "completed",
            "output": [
                {"type": "reasoning", "summary": []},
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "Hel"}, {"type": "output_text", "text": "lo"}]}
            ],
            "usage": {"input_tokens": 11, "output_tokens": 4}
        }));
        // A function call (call_id-keyed; arguments verbatim).
        assert_responses_golden(json!({
            "id": "resp_2", "model": "gpt-x", "status": "completed",
            "output": [{"type": "function_call", "call_id": "c1", "name": "get_weather",
                "arguments": "{\"city\":\"SF\"}"}]
        }));
        // incomplete + max_output_tokens → length.
        assert_responses_golden(json!({
            "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"},
            "output": [{"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "t"}]}]
        }));
        // incomplete + content_filter.
        assert_responses_golden(json!({
            "status": "incomplete", "incomplete_details": {"reason": "content_filter"}, "output": []
        }));
        // in_progress / absent status → finish_reason: null.
        assert_responses_golden(json!({"status": "in_progress", "output": []}));
        assert_responses_golden(json!({"output": []}));
        // total_tokens present is used verbatim.
        assert_responses_golden(json!({
            "id": "r", "model": "m", "status": "completed",
            "output": [{"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "x"}]}],
            "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5}
        }));
    }

    #[test]
    fn responses_fold_preserves_unmodeled_top_level_fields() {
        // The Responses-superset hub carries unmodeled top-level fields verbatim in
        // `extra` (the lossless substrate the Responses egress reuses); modeled
        // fields and the consumed `incomplete_details` are NOT duplicated there.
        let canonical = openai_responses_to_canonical_response(&json!({
            "id": "resp_1", "model": "gpt-x", "object": "response", "status": "completed",
            "service_tier": "default", "metadata": {"k": "v"}, "incomplete_details": null,
            "output": [], "usage": {"input_tokens": 1, "output_tokens": 1}
        }));
        assert_eq!(canonical.extra.get("object"), Some(&json!("response")));
        assert_eq!(canonical.extra.get("service_tier"), Some(&json!("default")));
        assert_eq!(canonical.extra.get("metadata"), Some(&json!({"k": "v"})));
        for k in [
            "id",
            "model",
            "status",
            "output",
            "usage",
            "incomplete_details",
        ] {
            assert!(
                !canonical.extra.contains_key(k),
                "{k} is modeled/consumed and must not be duplicated into extra"
            );
        }
        // The translating folds (Anthropic/Gemini) carry an empty `extra` — their
        // native top-level fields are not round-tripped into a Responses body.
        assert!(anthropic_to_canonical_response(&json!({
            "id": "m", "type": "message", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "hi"}]
        }))
        .extra
        .is_empty());
    }

    #[test]
    fn responses_round_trip_is_faithful() {
        // A Responses body folded to canonical and rendered back preserves the
        // modeled content, status, usage, opaque reasoning/unknown items, the
        // unmodeled top-level fields, AND item-level metadata (a message /
        // function_call `status`, a function_call output-item `id` distinct from
        // `call_id`) — all carried opaquely so the round-trip is lossless.
        let original = json!({
            "id": "resp_1", "object": "response", "model": "gpt-x",
            "status": "completed", "service_tier": "default", "metadata": {"k": "v"},
            "output": [
                {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "Z"},
                {"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                    "content": [{"type": "output_text", "text": "hello"}]},
                {"type": "function_call", "id": "fc_1", "status": "completed",
                    "call_id": "c1", "name": "f", "arguments": "{\"a\":1}"},
                {"type": "web_search_call", "id": "ws_1", "status": "completed"}
            ],
            "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8,
                "input_tokens_details": {"cached_tokens": 2}}
        });
        let round =
            canonical_response_to_responses(&openai_responses_to_canonical_response(&original));
        assert_eq!(round, original, "responses round-trip diverged");
    }

    #[test]
    fn responses_round_trip_reconstructs_incomplete_details() {
        let original = json!({
            "id": "r", "object": "response", "model": "m",
            "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"},
            "output": [{"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "trunc"}]}]
        });
        let round =
            canonical_response_to_responses(&openai_responses_to_canonical_response(&original));
        assert_eq!(round, original);
    }

    #[test]
    fn responses_round_trip_preserves_failed_status() {
        // Regression: a `failed` upstream status must round-trip as `failed`, not
        // be flattened to `in_progress`. The unmodeled `error` object rides along
        // in `extra` and is re-emitted verbatim.
        let original = json!({
            "id": "r", "object": "response", "model": "m",
            "status": "failed",
            "error": {"code": "server_error", "message": "boom"},
            "output": []
        });
        let canonical = openai_responses_to_canonical_response(&original);
        assert!(matches!(canonical.status, ResponseStatus::Failed));
        let round = canonical_response_to_responses(&canonical);
        assert_eq!(round, original);
    }

    #[test]
    fn responses_round_trip_preserves_output_text_metadata() {
        // Regression: `output_text` annotations / logprobs (and any other part
        // metadata) must survive a Responses→canonical→Responses round-trip; the
        // opaque part-level `extra` carries them.
        let original = json!({
            "id": "r", "object": "response", "model": "m", "status": "completed",
            "output": [{"type": "message", "role": "assistant", "content": [{
                "type": "output_text",
                "text": "see source",
                "annotations": [{
                    "type": "url_citation",
                    "url": "https://example.com",
                    "title": "Example",
                    "start_index": 0,
                    "end_index": 3
                }],
                "logprobs": []
            }]}]
        });
        let round =
            canonical_response_to_responses(&openai_responses_to_canonical_response(&original));
        assert_eq!(round, original);
    }

    #[test]
    fn chat_to_responses_egress_lifts_a_chat_body() {
        // A Responses-surface client routed to a Chat-Completions upstream: the
        // chat body is lifted into the hub and rendered as a Responses body.
        let chat = json!({
            "id": "chatcmpl-1", "object": "chat.completion", "model": "m", "created": 123,
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": "ok",
                "tool_calls": [{"id": "c1", "type": "function",
                    "function": {"name": "f", "arguments": "{}"}}]
            }}],
            "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}
        });
        let r = canonical_response_to_responses(&openai_chat_to_canonical_response(&chat));
        assert_eq!(r["object"], "response");
        assert_eq!(r["id"], "chatcmpl-1");
        assert_eq!(r["model"], "m");
        assert_eq!(r["created_at"], 123);
        assert_eq!(r["status"], "completed");
        let output = r["output"].as_array().unwrap();
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[0]["role"], "assistant");
        assert_eq!(output[0]["content"][0]["type"], "output_text");
        assert_eq!(output[0]["content"][0]["text"], "ok");
        assert_eq!(output[1]["type"], "function_call");
        assert_eq!(output[1]["call_id"], "c1");
        assert_eq!(output[1]["name"], "f");
        assert_eq!(output[1]["arguments"], "{}");
        assert_eq!(r["usage"]["input_tokens"], 4);
        assert_eq!(r["usage"]["output_tokens"], 2);
        assert_eq!(r["usage"]["total_tokens"], 6);

        // finish_reason `length` reconstructs incomplete_details on egress.
        let len = canonical_response_to_responses(&openai_chat_to_canonical_response(&json!({
            "choices": [{"finish_reason": "length",
                "message": {"role": "assistant", "content": "x"}}]
        })));
        assert_eq!(len["status"], "incomplete");
        assert_eq!(len["incomplete_details"]["reason"], "max_output_tokens");
    }

    #[test]
    fn chat_refusal_surfaces_on_responses_egress() {
        // A structured-output refusal from a chat upstream: finish_reason is "stop"
        // and content is null, but message.refusal carries the text. The Responses
        // client must see a `refusal` content part, not an empty completed turn.
        let chat = json!({
            "id": "chatcmpl-2", "object": "chat.completion", "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": null,
                "refusal": "I can't help with that."
            }}]
        });
        let r = canonical_response_to_responses(&openai_chat_to_canonical_response(&chat));
        assert_eq!(r["status"], "completed");
        let output = r["output"].as_array().unwrap();
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[0]["content"][0]["type"], "refusal");
        assert_eq!(
            output[0]["content"][0]["refusal"],
            "I can't help with that."
        );
    }
}
