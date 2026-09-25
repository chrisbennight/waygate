//! The inference usage sink.
//!
//! Mirrors the audit [`EvidenceRecorder`](crate::audit::EvidenceRecorder)
//! pattern — `waygate-evidence` defines the trait and the row shape, a storage
//! crate provides the Postgres implementation, and the invocation pipeline
//! holds a `dyn` handle wired by the composition root. Keeping the trait here
//! means the MCP layer does not grow a `sqlx` / `waygate-storage` dependency.
//!
//! The pipeline's `record_outcome` stage builds an [`LlmUsageRow`] from a
//! completed call's `InferenceRecord` and hands it to the recorder. Recording
//! is **best-effort** (returns `()`, never blocks the response): a usage-ledger
//! write must not fail a call the user already paid for. The implementation
//! logs and drops on error.
//!
//! Invariant I9: the row carries token counts, the served model, finish
//! reason, latency, and (later) cost — **never** prompt or completion content.

use async_trait::async_trait;

/// One per-call usage record, written at stream close / unary collection.
/// Token counts are `Option<u64>`: `None` = the provider did not report that
/// class (distinct from a reported zero — load-bearing for budget accounting).
/// Cost is intentionally absent here: it is computed from the `llm_models`
/// catalog at insert time by the storage sink, which is where the
/// rates live.
#[derive(Debug, Clone)]
pub struct LlmUsageRow {
    pub tenant_id: String,
    /// `None` for anonymous / auth-disabled calls.
    pub principal_sub: Option<String>,
    /// Client-facing model name (the `model` the caller sent).
    pub model_alias: String,
    pub provider: String,
    /// Trusted account metadata for live metrics; not persisted in the usage ledger.
    pub provider_account_id: Option<String>,
    /// What the upstream actually ran; may differ from the alias.
    pub model_served: Option<String>,
    pub inbound_surface: String,
    /// Inclusive input total; cached reads and cache creation are subsets.
    pub input_tokens: Option<u64>,
    /// Inclusive output total; reasoning is a subset. Embeddings have zero output.
    pub output_tokens: Option<u64>,
    pub cached_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub finish_reason: Option<String>,
    pub refusal: bool,
    /// Total call latency in milliseconds (`i64` to match the audit/pipeline
    /// latency convention; the `llm_usage.latency_ms` column is `BIGINT`).
    pub latency_ms: Option<i64>,
    /// `true` when this row records a gateway cache hit (a free, zero-token
    /// replay) rather than a real provider call — lets cost/volume analytics
    /// separate hits from upstream calls. `false` for every provider call.
    pub gateway_cache_hit: bool,
}

/// Sink for per-call inference usage records. Implemented by the storage layer
/// (`waygate_storage::PgLlmUsageSink`); `None` on the pipeline ⇒ usage is not
/// persisted (DB-less / inference-disabled deployments behave as before).
#[async_trait]
pub trait LlmUsageRecorder: Send + Sync + 'static {
    /// Persist one usage row. Best-effort: implementations log and drop on
    /// error rather than propagate — never fail the caller's already-served
    /// response on a ledger write.
    async fn record_usage(&self, row: LlmUsageRow);
}

/// Shared, cheaply-cloneable handle to the usage sink.
pub type SharedLlmUsage = std::sync::Arc<dyn LlmUsageRecorder>;
