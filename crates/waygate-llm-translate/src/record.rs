//! The `InferenceRecord` — canonical response metadata extracted from a
//! provider's response and its terminal streaming frame. It is the single
//! record that feeds audit, OTel `gen_ai.*`, usage rollups, and
//! per-user budgets. It carries **metadata only** — never prompt or
//! completion content (design invariant I9).
//!
//! Cost fields are intentionally *not* here yet: cost is computed from the
//! model catalog's per-token pricing, not stored on the record. Adding them
//! later is a non-breaking extension.

use serde::{Deserialize, Serialize};
use waygate_llm_credentials::LlmProvider;

use crate::canonical::{Surface, UpstreamProtocol};

/// Normalized finish reason across providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural stop / end of turn.
    Stop,
    /// Hit the max output-token limit.
    Length,
    /// Stopped to emit a tool/function call.
    ToolUse,
    /// Stopped by a content filter / safety policy.
    ContentFilter,
    /// Upstream signalled an error mid-generation.
    Error,
    /// Provider-specific reason that doesn't map to the above.
    Other,
}

impl FinishReason {
    /// Stable lowercase token (matches the serde `snake_case` form). Used for
    /// the `llm_usage.finish_reason` column and any other string surface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Length => "length",
            Self::ToolUse => "tool_use",
            Self::ContentFilter => "content_filter",
            Self::Error => "error",
            Self::Other => "other",
        }
    }
}

/// Token usage by class. `None` distinguishes "not reported by this provider"
/// from a reported zero — important for budget accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input: Option<u64>,
    pub output: Option<u64>,
    /// Prompt-cache read hits (Anthropic `cache_read_input_tokens`,
    /// OpenAI/Gemini cached prompt tokens).
    pub cached_read: Option<u64>,
    /// Prompt-cache creation (Anthropic `cache_creation_input_tokens`).
    pub cache_write: Option<u64>,
    /// Reasoning / "thinking" tokens (o-series, Gemini thoughts).
    pub reasoning: Option<u64>,
}

/// Canonical response metadata for one inference, produced at stream close
/// (or sync collection). See module docs for the no-content / no-cost-yet
/// contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceRecord {
    // identity / routing
    pub provider: LlmProvider,
    /// Which pooled credential served the call (e.g. `PRIMARY`).
    pub credential_label: String,
    /// Trusted provider account paired with the dispatched credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_account_id: Option<String>,
    /// What the client asked for (alias).
    pub model_requested: String,
    /// What the upstream actually ran — can differ from `model_requested`
    /// (aliasing, fallback, OpenRouter auto-routing). `None` if unreported.
    pub model_served: Option<String>,
    pub inbound_surface: Surface,
    pub upstream_protocol: UpstreamProtocol,

    // usage
    pub usage: TokenUsage,

    // outcome
    pub finish_reason: Option<FinishReason>,
    pub refusal: bool,

    // timing
    /// Time to first token (streaming only).
    pub ttft_ms: Option<u32>,
    pub total_ms: Option<u32>,

    // cache
    /// Our exact-match cache served this.
    pub gateway_cache_hit: bool,
    /// The provider reported a prompt-cache hit.
    pub provider_prompt_cache: Option<bool>,

    // upstream correlation
    pub upstream_request_id: Option<String>,
    pub system_fingerprint: Option<String>,
}

impl InferenceRecord {
    /// A baseline record stamped with the routing identity, before the
    /// response is observed. The dispatch/inspection path fills in usage,
    /// finish reason, timing, and upstream refs as the response streams.
    pub fn new(
        provider: LlmProvider,
        credential_label: impl Into<String>,
        model_requested: impl Into<String>,
        inbound_surface: Surface,
        upstream_protocol: UpstreamProtocol,
    ) -> Self {
        Self {
            provider,
            credential_label: credential_label.into(),
            provider_account_id: None,
            model_requested: model_requested.into(),
            model_served: None,
            inbound_surface,
            upstream_protocol,
            usage: TokenUsage::default(),
            finish_reason: None,
            refusal: false,
            ttft_ms: None,
            total_ms: None,
            gateway_cache_hit: false,
            provider_prompt_cache: None,
            upstream_request_id: None,
            system_fingerprint: None,
        }
    }
}
