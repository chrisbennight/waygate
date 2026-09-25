//! Embeddings translation: the OpenAI-shaped `/v1/embeddings` client surface ↔
//! a provider-neutral canonical request, plus the OpenAI-compatible outbound
//! adapter and response→[`InferenceRecord`] extraction.
//!
//! Embeddings are a second *operation* alongside chat (design §4): a far simpler
//! shape — `input → vectors`, unary only, no messages/tools/streaming — so it
//! gets its own canonical type and adapters rather than threading through the
//! chat [`LlmRequest`](crate::LlmRequest). It still shares everything below the
//! translation seam (credentials, transport, failover, the unified pipeline
//! gates, usage/cost): provider framing stays here and never leaks into the
//! generic pipeline (invariant I6).
//!
//! Only the OpenAI-compatible `/embeddings` wire shape is wired today, which is a
//! near-passthrough and covers OpenAI, OpenRouter, Together, Voyage, Mistral,
//! Jina, Cohere-compat, and self-hosted TEI/vLLM/Ollama. Native non-OpenAI
//! shapes (Gemini `:embedContent`, Cohere `/v1/embed`) are reserved for
//! follow-ups via [`EmbeddingsProtocol`] — mirroring how chat grew from one
//! protocol to four.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::inbound::TranslateError;
use crate::record::InferenceRecord;
use crate::response::{str_field, token_usage_from};

/// The provider-native protocol an embeddings request is rendered into. Each
/// embeddings-capable route declares its outbound shape; today only the
/// OpenAI-compatible `/embeddings` body is wired. Reserved variants
/// (Gemini `:embedContent`, Cohere `/v1/embed`) land with their adapters — the
/// embeddings analog of the chat [`UpstreamProtocol`](crate::UpstreamProtocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingsProtocol {
    /// The OpenAI-compatible `POST {base}/embeddings` shape.
    OpenAi,
}

impl EmbeddingsProtocol {
    /// Stable name of the upstream wire API this protocol speaks — the value the
    /// model catalog records in `llm_models.upstream_api`. The OpenAI-compatible
    /// embeddings shape is `embeddings`.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::OpenAi => "embeddings",
        }
    }
}

/// Canonical inbound embeddings request, normalized from the OpenAI
/// `/v1/embeddings` surface. `input` is kept as opaque JSON so every OpenAI
/// input form round-trips losslessly: a string, an array of strings, an array
/// of token ids, or an array of token-id arrays — the gateway does not
/// interpret it, only forwards it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    /// The model alias the client asked for.
    pub model_requested: String,
    /// The text/token input to embed (string | array). Forwarded verbatim.
    pub input: Value,
    /// `float` (default) | `base64`. `None` ⇒ provider default. Forwarded
    /// verbatim — the provider is the authority on accepted values.
    pub encoding_format: Option<String>,
    /// Output dimensionality (e.g. OpenAI `text-embedding-3*`). `None` ⇒ provider
    /// default. Forwarded where the provider supports it.
    pub dimensions: Option<u64>,
    /// Opaque end-user identifier for provider-side abuse monitoring. Forwarded
    /// verbatim where present.
    pub user: Option<String>,
    /// Retrieval task hint (`search_query` / `search_document` / `classification`
    /// / …). A widely-supported OpenAI-**compatible** extension (OpenRouter,
    /// Voyage, Cohere, Jina) that materially improves retrieval quality; it is not
    /// part of OpenAI's own spec, so it is forwarded verbatim only when the client
    /// sends it — the provider is the authority on accepted values.
    pub input_type: Option<String>,
    /// Optional backend prompt policy (for example raw or auto).
    pub prompt_mode: Option<String>,
    /// Optional backend request deadline in seconds.
    pub timeout_seconds: Option<f64>,
}

/// The typed Chat-style request struct: every translated embeddings field is
/// named, and `rest` captures anything else so an untranslated field rejects
/// rather than being silently dropped (I6) — the same pattern as the chat parser.
#[derive(Deserialize)]
struct EmbeddingsReq {
    model: String,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    encoding_format: Option<String>,
    #[serde(default)]
    dimensions: Option<u64>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    input_type: Option<String>,
    #[serde(default)]
    prompt_mode: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<f64>,
    /// Typed so a `stream: true` rejects with a clear message (the embeddings
    /// endpoint has no streaming form) rather than the generic unsupported-field
    /// error, and a `stream: false` is accepted as the no-op it is.
    #[serde(default)]
    stream: Option<bool>,
    /// Any embeddings field this slice does not translate. Rejected with
    /// `Unsupported` rather than silently stripped (I6).
    #[serde(flatten)]
    rest: Map<String, Value>,
}

/// Parse an OpenAI `/v1/embeddings` request body into the canonical model,
/// fail-closed: a structurally-bad request or an untranslated field is rejected
/// **before any cost** (no quota, no provider contact) rather than degraded.
pub fn parse_embeddings(body: &Value) -> Result<EmbeddingsRequest, TranslateError> {
    let req: EmbeddingsReq =
        serde_json::from_value(body.clone()).map_err(|e| TranslateError::Invalid(e.to_string()))?;
    if req.model.trim().is_empty() {
        return Err(TranslateError::Invalid("`model` must not be empty".into()));
    }
    if !input_is_nonempty(&req.input) {
        return Err(TranslateError::Invalid(
            "`input` must be a non-empty string or array".into(),
        ));
    }
    // Streaming has no embeddings form: a single response carries the whole
    // vector set. Reject `stream: true` with a clear message; `stream: false`
    // (and absent) is the no-op default.
    if req.stream == Some(true) {
        return Err(TranslateError::Unsupported {
            surface: "embeddings",
            param: "stream (the embeddings endpoint has no streaming form)".into(),
        });
    }
    // Reject — never silently drop — fields this surface cannot translate
    // faithfully (I6). The key list is sorted for a stable error.
    if !req.rest.is_empty() {
        let mut params: Vec<&str> = req.rest.keys().map(String::as_str).collect();
        params.sort_unstable();
        return Err(TranslateError::Unsupported {
            surface: "embeddings",
            param: params.join(", "),
        });
    }
    Ok(EmbeddingsRequest {
        model_requested: req.model,
        input: req.input,
        encoding_format: req.encoding_format,
        dimensions: req.dimensions,
        user: req.user,
        input_type: req.input_type,
        prompt_mode: req.prompt_mode,
        timeout_seconds: req.timeout_seconds,
    })
}

/// Whether an `input` value is a usable embeddings input: a non-empty string, or
/// a non-empty array (of strings / token ids / token-id arrays — not inspected).
/// An absent `input` deserializes to `Value::Null` and is rejected here.
fn input_is_nonempty(input: &Value) -> bool {
    match input {
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => false,
    }
}

/// Render a canonical embeddings request into the OpenAI-compatible `/embeddings`
/// body. A near-passthrough: the upstream model name is substituted and only the
/// translated fields are emitted (so a field the parser rejected can never reach
/// the provider). `encoding_format` / `dimensions` / `user` are forwarded
/// verbatim where present — the provider is the authority on accepted values.
/// Infallible (unlike the chat renderers): an embeddings request has no
/// feature combination that cannot be expressed on the OpenAI shape.
/// `encoding_format` / `dimensions` / `user` / `input_type` are forwarded
/// verbatim where present — the provider is the authority on accepted values.
pub fn render_openai_embeddings(req: &EmbeddingsRequest, model: &str) -> Value {
    let mut body = Map::new();
    body.insert("model".into(), json!(model));
    body.insert("input".into(), req.input.clone());
    if let Some(ef) = &req.encoding_format {
        body.insert("encoding_format".into(), json!(ef));
    }
    if let Some(d) = req.dimensions {
        body.insert("dimensions".into(), json!(d));
    }
    if let Some(u) = &req.user {
        body.insert("user".into(), json!(u));
    }
    if let Some(it) = &req.input_type {
        body.insert("input_type".into(), json!(it));
    }
    if let Some(mode) = &req.prompt_mode {
        body.insert("prompt_mode".into(), json!(mode));
    }
    if let Some(deadline) = req.timeout_seconds {
        body.insert("timeout_seconds".into(), json!(deadline));
    }
    Value::Object(body)
}

/// Fold an OpenAI-compatible embeddings response into the `InferenceRecord`
/// started before dispatch (`base` carries provider / credential / requested
/// model / surface). Embeddings report usage as `{prompt_tokens, total_tokens}`
/// — an input-token class only, no output/completion — and the served model as
/// `model`; there is no finish reason (an embeddings call does not "stop"), so it
/// stays `None`. The usage-ledger projection records zero completion tokens
/// when input is known, so catalog costing prices that input alone. Missing
/// provider fields stay `None` here.
///
/// `base.upstream_protocol` is left untouched: it names a *chat* protocol (it
/// selects the streaming chat translator), which an embeddings call never uses,
/// so it is inert on this path — the durable usage row keys off
/// `inbound_surface` (`embeddings`), not the protocol.
pub fn extract_openai_embeddings(mut base: InferenceRecord, response: &Value) -> InferenceRecord {
    base.model_served = str_field(response, "model");
    if let Some(usage) = response.get("usage") {
        // `token_usage_from` reads `prompt_tokens` → input; an embeddings body
        // carries no `completion_tokens`, so `output` stays `None` and the
        // cached/reasoning classes (also absent) stay `None` too.
        base.usage = token_usage_from(usage);
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{Surface, UpstreamProtocol};
    use waygate_llm_credentials::LlmProvider;

    fn base_record() -> InferenceRecord {
        // The chat `upstream_protocol` is a benign placeholder on the embeddings
        // path (it is never read); `Surface::Embeddings` is the meaningful field.
        InferenceRecord::new(
            LlmProvider::OpenAi,
            "MAIN",
            "text-embedding-3-small",
            Surface::Embeddings,
            UpstreamProtocol::OpenAiChat,
        )
    }

    #[test]
    fn parses_a_string_input_request() {
        let req = parse_embeddings(&json!({
            "model": "text-embedding-3-small",
            "input": "hello world"
        }))
        .expect("valid");
        assert_eq!(req.model_requested, "text-embedding-3-small");
        assert_eq!(req.input, json!("hello world"));
        assert_eq!(req.encoding_format, None);
        assert_eq!(req.dimensions, None);
        assert_eq!(req.user, None);
        assert_eq!(req.input_type, None);
    }

    #[test]
    fn parses_array_and_token_inputs_losslessly() {
        // Array of strings.
        let r = parse_embeddings(&json!({"model":"m","input":["a","b"]})).unwrap();
        assert_eq!(r.input, json!(["a", "b"]));
        // Array of token ids.
        let r = parse_embeddings(&json!({"model":"m","input":[1,2,3]})).unwrap();
        assert_eq!(r.input, json!([1, 2, 3]));
        // Array of token-id arrays (batched, pre-tokenized).
        let r = parse_embeddings(&json!({"model":"m","input":[[1,2],[3,4]]})).unwrap();
        assert_eq!(r.input, json!([[1, 2], [3, 4]]));
    }

    #[test]
    fn parses_optional_fields() {
        let req = parse_embeddings(&json!({
            "model": "text-embedding-3-large",
            "input": "x",
            "encoding_format": "base64",
            "dimensions": 256,
            "user": "u-123",
            "input_type": "search_document"
        }))
        .expect("valid");
        assert_eq!(req.encoding_format.as_deref(), Some("base64"));
        assert_eq!(req.dimensions, Some(256));
        assert_eq!(req.user.as_deref(), Some("u-123"));
        assert_eq!(req.input_type.as_deref(), Some("search_document"));
    }

    #[test]
    fn rejects_missing_or_empty_model() {
        assert!(matches!(
            parse_embeddings(&json!({"input": "x"})),
            Err(TranslateError::Invalid(_))
        ));
        assert!(matches!(
            parse_embeddings(&json!({"model": "  ", "input": "x"})),
            Err(TranslateError::Invalid(msg)) if msg.contains("model")
        ));
    }

    #[test]
    fn rejects_missing_empty_or_wrongly_typed_input() {
        // Absent input.
        assert!(matches!(
            parse_embeddings(&json!({"model": "m"})),
            Err(TranslateError::Invalid(msg)) if msg.contains("input")
        ));
        // Empty string.
        assert!(matches!(
            parse_embeddings(&json!({"model": "m", "input": ""})),
            Err(TranslateError::Invalid(_))
        ));
        // Empty array.
        assert!(matches!(
            parse_embeddings(&json!({"model": "m", "input": []})),
            Err(TranslateError::Invalid(_))
        ));
        // Wrong type (object).
        assert!(matches!(
            parse_embeddings(&json!({"model": "m", "input": {"a": 1}})),
            Err(TranslateError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_streaming_with_a_clear_message() {
        let err = parse_embeddings(&json!({"model":"m","input":"x","stream":true}))
            .expect_err("streaming has no embeddings form");
        assert!(matches!(
            err,
            TranslateError::Unsupported { surface: "embeddings", param } if param.contains("stream")
        ));
        // `stream: false` is the no-op default and is accepted.
        assert!(parse_embeddings(&json!({"model":"m","input":"x","stream":false})).is_ok());
    }

    #[test]
    fn rejects_untranslated_fields_rather_than_dropping_them() {
        // An unknown field must surface as Unsupported (I6), not be ignored.
        let err = parse_embeddings(&json!({
            "model": "m", "input": "x", "fancy": 1, "another": 2
        }))
        .expect_err("unknown fields reject");
        match err {
            TranslateError::Unsupported { surface, param } => {
                assert_eq!(surface, "embeddings");
                // Sorted, stable list.
                assert_eq!(param, "another, fancy");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn renders_a_passthrough_body_substituting_the_upstream_model() {
        let req = parse_embeddings(&json!({"model":"alias","input":"hi"})).unwrap();
        let body = render_openai_embeddings(&req, "openai/text-embedding-3-small");
        assert_eq!(
            body,
            json!({"model": "openai/text-embedding-3-small", "input": "hi"})
        );
        // Absent optionals are omitted entirely (not sent as null).
        assert!(body.get("encoding_format").is_none());
        assert!(body.get("dimensions").is_none());
        assert!(body.get("user").is_none());
        assert!(body.get("input_type").is_none());
    }

    #[test]
    fn renders_present_optionals_verbatim() {
        let req = EmbeddingsRequest {
            model_requested: "alias".into(),
            input: json!(["a", "b"]),
            encoding_format: Some("base64".into()),
            dimensions: Some(512),
            user: Some("u".into()),
            input_type: Some("search_query".into()),
            prompt_mode: None,
            timeout_seconds: None,
        };
        let body = render_openai_embeddings(&req, "up/model");
        assert_eq!(
            body,
            json!({
                "model": "up/model",
                "input": ["a", "b"],
                "encoding_format": "base64",
                "dimensions": 512,
                "user": "u",
                "input_type": "search_query"
            })
        );
    }

    #[test]
    fn extracts_served_model_and_input_only_usage() {
        let resp = json!({
            "object": "list",
            "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
            "model": "text-embedding-3-small",
            "usage": {"prompt_tokens": 8, "total_tokens": 8}
        });
        let rec = extract_openai_embeddings(base_record(), &resp);
        assert_eq!(rec.model_served.as_deref(), Some("text-embedding-3-small"));
        assert_eq!(rec.usage.input, Some(8));
        // The provider metadata omits output; the usage-ledger projection knows
        // embeddings have no completion tokens and supplies its applicable zero.
        assert_eq!(rec.usage.output, None);
        assert_eq!(rec.usage.cached_read, None);
        assert_eq!(rec.usage.reasoning, None);
        // No finish reason on an embeddings call.
        assert_eq!(rec.finish_reason, None);
    }

    #[test]
    fn extraction_does_not_fabricate_absent_fields() {
        // A response missing usage/model leaves those fields None, never invented.
        let rec = extract_openai_embeddings(base_record(), &json!({"object": "list", "data": []}));
        assert_eq!(rec.model_served, None);
        assert_eq!(rec.usage.input, None);
        assert_eq!(rec.usage.output, None);
    }

    #[test]
    fn protocol_wire_name_is_embeddings() {
        assert_eq!(EmbeddingsProtocol::OpenAi.wire_name(), "embeddings");
    }
}
