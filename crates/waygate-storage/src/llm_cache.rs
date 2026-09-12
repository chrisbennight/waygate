//! Postgres store + key for the per-principal exact-match
//! completion cache (`migrations/0050_llm_cache.sql`).
//!
//! The cache is keyed by a BLAKE3 hash over the canonical request PLUS the
//! principal, so an entry is per-principal scoped — a cross-principal hit is
//! structurally impossible because the principal is part of the key. Unlike the
//! audit / usage ledgers (metadata only), the cache stores response content
//! (a hit replays it); the per-principal key is what keeps that safe.
//!
//! This module implements storage and cache keys. The invocation pipeline
//! checks the cache before dispatch and stores eligible responses after a miss.

use std::time::Duration;

use serde_json::Value;

/// A cache hit: the cached client-facing response, the served model, and the
/// provider that served it — all replayed into the hit's `InferenceRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedResponse {
    pub model_served: Option<String>,
    /// Canonical provider identifier (`LlmProvider::as_str`) that served the
    /// original miss; `None` when the entry has no recorded provider.
    pub provider: Option<String>,
    pub response_body: Value,
}

/// A new cache entry to store after a cache miss.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub cache_key: String,
    pub tenant_id: String,
    pub principal_sub: Option<String>,
    pub model_alias: String,
    pub model_served: Option<String>,
    /// Canonical provider identifier (`LlmProvider::as_str`) that served this
    /// miss — replayed to attribute a later hit to the right provider.
    pub provider: String,
    pub response_body: Value,
    /// Time-to-live; `expires_at` is stored as `now + ttl`.
    pub ttl: Duration,
}

/// Compute the per-principal cache key (design §9): a BLAKE3 hash over the
/// canonical request JSON PLUS the principal identity (tenant + subject). The
/// principal is part of the hashed input, so a request from one principal can
/// never produce the same key as another's — the cache's no-cross-principal
/// guarantee is structural, not a runtime check.
///
/// The three inputs are serialized as a JSON array before hashing so their
/// boundaries are unambiguous: serde escapes each element, so distinct
/// `(tenant, principal, request)` triples can never serialize to the same bytes
/// (no separator-collision forging a different framing).
pub fn cache_key(
    canonical_request_json: &str,
    tenant_id: &str,
    principal_sub: Option<&str>,
) -> String {
    let framed = serde_json::to_vec(&(tenant_id, principal_sub, canonical_request_json))
        .expect("serializing cache-key inputs (strings) cannot fail");
    blake3::hash(&framed).to_hex().to_string()
}

/// Look up a fresh cache entry by key. Returns `None` for a miss OR an expired
/// row — the freshness filter is in SQL, so an expired-but-unswept row is never
/// served.
pub async fn get_cached<'e, E>(
    executor: E,
    cache_key: &str,
) -> Result<Option<CachedResponse>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query_as::<_, (Option<String>, Option<String>, Value)>(
        "SELECT model_served, provider, response_body FROM llm_cache \
         WHERE cache_key = $1 AND expires_at > now()",
    )
    .bind(cache_key)
    .fetch_optional(executor)
    .await?;
    Ok(
        row.map(|(model_served, provider, response_body)| CachedResponse {
            model_served,
            provider,
            response_body,
        }),
    )
}

/// Store (or refresh) a cache entry. On a key conflict the body / served model /
/// expiry are updated, so a re-computed entry extends its TTL rather than
/// erroring.
///
/// `expires_at` is computed **database-side** as `now() + ttl` so it shares the
/// single Postgres clock that [`get_cached`]'s `expires_at > now()` freshness
/// filter uses. Computing it from the gateway's clock would make a short-TTL
/// row's freshness depend on gateway↔DB clock skew; deriving both from `now()`
/// keeps the expiry guarantee strict.
pub async fn put_cached<'e, E>(executor: E, entry: &CacheEntry) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO llm_cache \
           (cache_key, tenant_id, principal_sub, model_alias, model_served, provider, response_body, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8)) \
         ON CONFLICT (cache_key) DO UPDATE SET \
           response_body = EXCLUDED.response_body, \
           model_served  = EXCLUDED.model_served, \
           provider      = EXCLUDED.provider, \
           expires_at    = EXCLUDED.expires_at",
    )
    .bind(&entry.cache_key)
    .bind(&entry.tenant_id)
    .bind(&entry.principal_sub)
    .bind(&entry.model_alias)
    .bind(&entry.model_served)
    .bind(&entry.provider)
    .bind(&entry.response_body)
    .bind(entry.ttl.as_secs_f64())
    .execute(executor)
    .await?;
    Ok(())
}

/// Reclaim expired cache rows, deleting in batches of `batch` and returning the
/// total removed. Reads already filter `expires_at > now()`, so an expired row
/// is invisible to lookups before it is swept — this only reclaims its disk
/// (design §9). Batched by `ctid` so a large backlog never holds one
/// long lock; loops until a batch deletes fewer than `batch` rows.
pub async fn sweep_expired_llm_cache(pool: &sqlx::PgPool, batch: i64) -> Result<u64, sqlx::Error> {
    // A non-positive batch is meaningless and would never make progress: `LIMIT
    // 0` deletes nothing, so `affected < batch` (`0 < 0`) would loop forever.
    // Clamp to at least 1 so the loop always terminates regardless of caller.
    let batch = batch.max(1);
    let mut total: u64 = 0;
    loop {
        let affected = sqlx::query(
            "DELETE FROM llm_cache WHERE ctid IN \
               (SELECT ctid FROM llm_cache WHERE expires_at <= now() LIMIT $1)",
        )
        .bind(batch)
        .execute(pool)
        .await?
        .rows_affected();
        total += affected;
        // A short batch means the backlog is drained.
        if affected < batch as u64 {
            break;
        }
    }
    Ok(total)
}

/// Run the periodic TTL sweep until `shutdown` resolves. Mirrors
/// [`run_retention_scheduler`](crate::run_retention_scheduler): skip the t=0
/// tick, then every `interval_period` reclaim expired rows. Best-effort — a
/// sweep error is logged and the loop continues (the next tick retries); the
/// read-time freshness filter means a failed sweep only delays disk reclaim, it
/// never serves a stale row.
pub async fn run_llm_cache_sweep_scheduler(
    pool: sqlx::PgPool,
    interval_period: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    use tokio::pin;
    use tokio::time::interval;
    // Batch size per DELETE; fixed (not an operator knob) — large enough to
    // drain a backlog in few statements, small enough to keep each lock brief.
    const SWEEP_BATCH: i64 = 1000;
    pin!(shutdown);
    let mut ticker = interval(interval_period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate t=0 tick (the table is empty at boot).
    ticker.tick().await;
    tracing::info!(
        interval_secs = interval_period.as_secs(),
        "llm cache TTL sweep scheduler started",
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("llm cache TTL sweep scheduler shutting down");
                return;
            }
            _ = ticker.tick() => {
                match sweep_expired_llm_cache(&pool, SWEEP_BATCH).await {
                    Ok(n) if n > 0 => {
                        tracing::debug!(deleted = n, "llm cache TTL sweep reclaimed expired rows");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        error = %e,
                        "llm cache TTL sweep failed; retrying next interval",
                    ),
                }
            }
        }
    }
}

/// Bound a tenant's cache to at most `max_rows` entries, evicting the oldest (by
/// `created_at`) beyond that. Run after a `put` so a high request-diversity burst
/// can't balloon the table *within* a TTL window — the TTL sweep only reclaims
/// rows that have actually expired, whereas this caps *live* ones (design
/// §9). The delete is scoped to `tenant_id`, so it can never touch another
/// tenant's entries. `max_rows` is clamped to `>= 1` (a cap of 0 would evict the
/// entire tenant — the `NOT IN (empty set)` would match every row). Returns the
/// number of rows evicted.
pub async fn enforce_tenant_cap(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    max_rows: i64,
) -> Result<u64, sqlx::Error> {
    let max_rows = max_rows.max(1);
    let affected = sqlx::query(
        "DELETE FROM llm_cache WHERE tenant_id = $1 AND cache_key NOT IN \
           (SELECT cache_key FROM llm_cache WHERE tenant_id = $1 \
            ORDER BY created_at DESC, cache_key DESC LIMIT $2)",
    )
    .bind(tenant_id)
    .bind(max_rows)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected)
}

/// Postgres-backed per-principal completion cache — the runtime implementation
/// of [`waygate_evidence::cache::LlmCache`] the invocation pipeline holds. It computes
/// the per-principal key internally (the pipeline only passes the canonical
/// request + principal), so the no-cross-principal guarantee lives here. Both
/// methods are best-effort: a lookup error is a miss and a store error is
/// dropped, so a cache fault never fails the user's call.
#[derive(Clone)]
pub struct PgLlmCache {
    pool: sqlx::PgPool,
    /// Optional per-tenant row cap, enforced (evict-oldest) after each `put`.
    /// `None` ⇒ unbounded by count (the cache is then bounded only by TTL + the
    /// background sweep).
    max_rows_per_tenant: Option<i64>,
}

impl PgLlmCache {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            max_rows_per_tenant: None,
        }
    }

    /// Set the per-tenant row cap. `Some(n)` evicts the oldest beyond `n` after
    /// each store; `None` leaves the cache bounded only by TTL + the sweep.
    #[must_use]
    pub fn with_max_rows_per_tenant(mut self, max_rows: Option<i64>) -> Self {
        self.max_rows_per_tenant = max_rows;
        self
    }
}

#[async_trait::async_trait]
impl waygate_evidence::cache::LlmCache for PgLlmCache {
    async fn get(
        &self,
        canonical_request: &str,
        tenant_id: &str,
        principal_sub: Option<&str>,
    ) -> Option<waygate_evidence::cache::CachedCompletion> {
        let key = cache_key(canonical_request, tenant_id, principal_sub);
        match get_cached(&self.pool, &key).await {
            Ok(Some(c)) => Some(waygate_evidence::cache::CachedCompletion {
                model_served: c.model_served,
                provider: c.provider,
                body: c.response_body,
            }),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "llm cache lookup failed; treating as a miss");
                None
            }
        }
    }

    async fn put(&self, entry: waygate_evidence::cache::CacheStoreRequest) {
        let key = cache_key(
            &entry.canonical_request,
            &entry.tenant_id,
            entry.principal_sub.as_deref(),
        );
        let row = CacheEntry {
            cache_key: key,
            tenant_id: entry.tenant_id,
            principal_sub: entry.principal_sub,
            model_alias: entry.model_alias,
            model_served: entry.model_served,
            provider: entry.provider,
            response_body: entry.body,
            ttl: entry.ttl,
        };
        match put_cached(&self.pool, &row).await {
            Ok(()) => {
                // Bound the tenant's footprint (evict-oldest) so a within-TTL
                // diversity burst can't balloon the table. Best-effort: a cap
                // failure leaves the just-stored entry in place — the TTL sweep
                // still reclaims eventually.
                if let Some(max_rows) = self.max_rows_per_tenant {
                    if let Err(e) = enforce_tenant_cap(&self.pool, &row.tenant_id, max_rows).await {
                        tracing::warn!(
                            error = %e,
                            "llm cache tenant-cap eviction failed (best-effort)",
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "llm cache store failed; dropping (best-effort)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_per_principal_and_deterministic() {
        let req = r#"{"model":"alias","messages":[{"role":"user","content":"hi"}]}"#;
        let alice_1 = cache_key(req, "default", Some("alice"));
        let alice_2 = cache_key(req, "default", Some("alice"));
        let bob = cache_key(req, "default", Some("bob"));
        let anon = cache_key(req, "default", None);

        // Deterministic for identical inputs.
        assert_eq!(alice_1, alice_2);
        // Different principals → different keys: a cross-principal hit is
        // structurally impossible (the security invariant).
        assert_ne!(alice_1, bob);
        assert_ne!(alice_1, anon);
        // A different tenant is also a different key.
        assert_ne!(alice_1, cache_key(req, "other", Some("alice")));
        // A different request → a different key.
        assert_ne!(
            alice_1,
            cache_key(
                r#"{"model":"alias","messages":[]}"#,
                "default",
                Some("alice")
            )
        );
        // BLAKE3 hex is 64 chars.
        assert_eq!(alice_1.len(), 64);
    }
}
