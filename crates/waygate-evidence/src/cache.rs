//! The per-principal completion cache sink.
//!
//! Mirrors the usage / audit recorder pattern — `waygate-evidence` defines the
//! trait and DTOs, a storage crate provides the Postgres implementation
//! (`waygate_storage::PgLlmCache`), and the invocation pipeline holds a `dyn`
//! handle wired by the composition root. The trait takes the canonical request
//! and principal as raw inputs and computes the per-principal cache key
//! internally, so the seam needs no hashing / `sqlx` dependency and the
//! no-cross-principal guarantee lives in one place (the key construction).
//!
//! Caching is opt-in per model (a model's configured TTL). A hit replays the
//! stored response and is **free** — it never contacts the provider, so it
//! incurs no token usage or cost.

use async_trait::async_trait;

/// A cache hit: the stored client-facing response body plus the identity to
/// stamp into the hit's `InferenceRecord` — the served model and the provider
/// that actually produced it on the original miss.
#[derive(Debug, Clone)]
pub struct CachedCompletion {
    pub model_served: Option<String>,
    /// The canonical provider identifier (`LlmProvider::as_str`) that served the
    /// original miss, so a hit attributes to the route that produced the content
    /// rather than the model's current primary (which may differ after a §7
    /// failover). `None` for a legacy row written before the column existed ⇒
    /// the caller falls back to the current route.
    pub provider: Option<String>,
    pub body: serde_json::Value,
}

/// A completion to store after a cache miss.
#[derive(Debug, Clone)]
pub struct CacheStoreRequest {
    /// The canonical request (a serialized `LlmRequest`) — hashed together with
    /// the principal into the per-principal key by the implementation.
    pub canonical_request: String,
    pub tenant_id: String,
    pub principal_sub: Option<String>,
    pub model_alias: String,
    pub model_served: Option<String>,
    /// The canonical provider identifier (`LlmProvider::as_str`) that actually
    /// served this miss — recorded so a later hit attributes to it.
    pub provider: String,
    pub body: serde_json::Value,
    pub ttl: std::time::Duration,
}

/// Per-principal exact-match completion cache. Implemented by the storage layer
/// (`waygate_storage::PgLlmCache`); `None` on the pipeline ⇒ caching is off
/// (the LLM path runs exactly as before).
#[async_trait]
pub trait LlmCache: Send + Sync + 'static {
    /// Look up a fresh cached completion for `(canonical_request, principal)`.
    /// The implementation computes the per-principal key, so a different
    /// principal can never hit another's entry. Best-effort: a lookup error
    /// returns `None` — a cache miss must never fail the call.
    async fn get(
        &self,
        canonical_request: &str,
        tenant_id: &str,
        principal_sub: Option<&str>,
    ) -> Option<CachedCompletion>;

    /// Store a completion after a miss. Best-effort: returns `()` and logs/drops
    /// on error — a cache write must not fail a response the user already got.
    async fn put(&self, entry: CacheStoreRequest);
}

/// Shared, cheaply-cloneable handle to the completion cache.
pub type SharedLlmCache = std::sync::Arc<dyn LlmCache>;
