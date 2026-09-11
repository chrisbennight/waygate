//! `waygate-llm-translate` — translation between the OpenAI-shaped client
//! surfaces and a provider-neutral canonical model, plus the
//! [`InferenceRecord`] response-metadata contract.
//!
//! The crate is the inference plane's translation seam (design §4): inbound
//! adapters normalize a client request (`/v1/chat/completions` and
//! `/v1/responses`) into a [`LlmRequest`]; per-provider outbound
//! adapters render that into the provider's native protocol; and an
//! [`InferenceRecord`] is extracted from each response. Provider-specific
//! framing stays here, never leaking into the generic invocation pipeline
//! (invariant I6). The crate covers the canonical model (messages with tool
//! calls/results, `tools`/`tool_choice`, and `response_format`), the
//! `InferenceRecord`, the Chat Completions and Responses inbound parsers, the OpenAI-chat,
//! Anthropic-Messages, Gemini, and OpenAI-Responses outbound renderers
//! (including tool calling and the Anthropic structured-output emulation), unary
//! response→record extraction (plus the Anthropic→OpenAI, Gemini→OpenAI, and
//! OpenAI-Responses→OpenAI response translations), a protocol-aware
//! [`StreamTranslator`] that folds streamed frames into the terminal
//! `InferenceRecord` while emitting OpenAI chat chunks — incl. streamed
//! `delta.tool_calls` — to the client (OpenAI 1:1; Anthropic, Gemini, and
//! OpenAI-Responses events translated), and a pre-dispatch
//! [`check_provider_support`] capability gate. All four provider protocols are
//! supported unary and streaming.
//!
//! Alongside chat, the crate also covers the **embeddings** operation
//! (`/v1/embeddings`): its own canonical [`EmbeddingsRequest`], the OpenAI-compatible
//! [`parse_embeddings`] / [`render_openai_embeddings`] / [`extract_openai_embeddings`]
//! adapter, and an [`EmbeddingsProtocol`] reserved for future non-OpenAI shapes.
//! Embeddings are unary-only and reuse the shared [`InferenceRecord`] (input-token
//! usage only); they do not flow through the chat [`LlmRequest`] model.

mod canonical;
mod capability;
mod embeddings;
pub mod images;
mod inbound;
mod outbound;
mod record;
mod response;
mod response_canonical;
mod stream;

pub use canonical::{
    CanonicalMessage, CanonicalTool, ContentPart, LlmRequest, ResponseFormat, Role, Sampling,
    Surface, ToolChoice, UpstreamProtocol,
};
pub use capability::check_provider_support;
pub use embeddings::{
    extract_openai_embeddings, parse_embeddings, render_openai_embeddings, EmbeddingsProtocol,
    EmbeddingsRequest,
};
pub use inbound::{parse_chat_completions, parse_responses, TranslateError};
pub use outbound::{
    finalize_codex_responses_body, render_anthropic_messages, render_gemini, render_openai_chat,
    render_openai_responses, DEFAULT_ANTHROPIC_MAX_TOKENS,
};
pub use record::{FinishReason, InferenceRecord, TokenUsage};
pub use response::{
    anthropic_response_to_openai_chat, extract_anthropic_messages, extract_gemini,
    extract_openai_chat, extract_openai_responses, gemini_response_to_openai_chat,
    openai_responses_to_openai_chat,
};
pub use response_canonical::{
    anthropic_to_canonical_response, canonical_response_to_openai_chat,
    canonical_response_to_responses, gemini_to_canonical_response,
    openai_chat_to_canonical_response, openai_responses_to_canonical_response, CanonicalResponse,
    IncompleteReason, OutputContentPart, OutputItem, ResponseStatus, Usage,
};
pub use stream::{
    AnthropicStreamTranslator, ChatStreamToResponses, GeminiStreamTranslator,
    OpenAiChatStreamAggregator, ResponsesStreamTranslator, StreamStep, StreamTranslator,
};

// Re-export the provider enum so consumers have a single import surface for
// the inference-plane vocabulary.
pub use waygate_llm_credentials::LlmProvider;
