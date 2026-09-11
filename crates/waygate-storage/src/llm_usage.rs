//! Postgres sink for the inference usage ledger
//! (`migrations/0048_llm_usage.sql`).
//!
//! Implements `waygate_evidence::usage::LlmUsageRecorder` — the storage-side
//! counterpart of the trait, mirroring how `PgAuditSink` implements
//! `EvidenceRecorder`. The invocation pipeline's record_outcome stage builds an
//! `LlmUsageRow` (tokens + identity, no cost — waygate-mcp has no rates) and
//! hands it here; the sink looks up the model's catalog costing, computes the
//! call's cost, and appends one row.
//!
//! Best-effort by contract: `record_usage` returns `()` and a failed insert is
//! logged and dropped — a usage-ledger write must never fail a call the user
//! already paid for.

use async_trait::async_trait;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use uuid::Uuid;

use waygate_evidence::usage::{LlmUsageRecorder, LlmUsageRow};

use crate::llm_catalog::{get_llm_model, get_llm_model_by_served, LlmModelRow};

/// Where a usage row's cost came from (design §4.2). Stored as the
/// `llm_usage.cost_source` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CostSource {
    /// The provider returned an authoritative cost (e.g. OpenRouter usage
    /// accounting). No provider exposes this through the gateway yet.
    ProviderReported,
    /// Computed here as rate x tokens from the `llm_models` catalog costing.
    ComputedFromCatalog,
    /// No costing configured for the model (or the model row was absent):
    /// tokens are recorded, cost is left NULL, cost budgets skip.
    #[default]
    Unknown,
}

impl CostSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderReported => "provider_reported",
            Self::ComputedFromCatalog => "computed_from_catalog",
            Self::Unknown => "unknown",
        }
    }
}

/// The computed cost for one call. `None` line items = that class had no rate
/// and/or no token count. `total_cost` is `None` only when no class could be
/// priced at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CostBreakdown {
    pub input_cost: Option<Decimal>,
    pub output_cost: Option<Decimal>,
    pub total_cost: Option<Decimal>,
    pub source: CostSource,
}

/// Compute a call's cost from the model's catalog rates and the call's token
/// counts: `cost(class) = rate_per_mtok x tokens / 1_000_000`. A class is
/// priced only when BOTH its rate and its token count are present.
///
/// `total_cost` sums every priced class (input, output, cached-read,
/// cache-write); cached/cache-write costs fold into the total (the ledger has
/// no separate columns for them). `source` is `ComputedFromCatalog` when the
/// model carries ANY rate, else `Unknown` (tokens still recorded, cost NULL).
/// There is no provider-reported path yet.
pub fn compute_cost(
    model: &LlmModelRow,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cached_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
) -> CostBreakdown {
    let million = Decimal::from(1_000_000u64);
    let line = |rate: Option<Decimal>, tokens: Option<u64>| -> Option<Decimal> {
        match (rate, tokens) {
            (Some(r), Some(t)) => Some(r * Decimal::from(t) / million),
            _ => None,
        }
    };
    let input_cost = line(model.input_cost_per_mtok, input_tokens);
    let output_cost = line(model.output_cost_per_mtok, output_tokens);
    let cached_cost = line(model.cached_read_cost_per_mtok, cached_read_tokens);
    let write_cost = line(model.cache_write_cost_per_mtok, cache_write_tokens);

    let parts = [input_cost, output_cost, cached_cost, write_cost];
    let total_cost = if parts.iter().any(Option::is_some) {
        Some(parts.into_iter().flatten().sum::<Decimal>())
    } else {
        None
    };

    let any_rate = model.input_cost_per_mtok.is_some()
        || model.output_cost_per_mtok.is_some()
        || model.cached_read_cost_per_mtok.is_some()
        || model.cache_write_cost_per_mtok.is_some();
    let source = if any_rate {
        CostSource::ComputedFromCatalog
    } else {
        CostSource::Unknown
    };

    CostBreakdown {
        input_cost,
        output_cost,
        total_cost,
        source,
    }
}

/// Postgres-backed inference usage sink. Cheap to clone (wraps a pooled
/// `PgPool`); construct once and share.
#[derive(Clone)]
pub struct PgLlmUsageSink {
    pool: sqlx::PgPool,
}

impl PgLlmUsageSink {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LlmUsageRecorder for PgLlmUsageSink {
    async fn record_usage(&self, row: LlmUsageRow) {
        // Price by model_served — what was actually billed — not the requested
        // alias (design §4.2). When the provider reported a served model we
        // price the catalog row that routes to it (Unknown if none is
        // cataloged — we will not bill a different model's rates). When the
        // provider did NOT report a served model, fall back to the requested
        // alias's configured route as the best available estimate. A lookup
        // error degrades to Unknown. Tokens are recorded regardless (cost is
        // best-effort metadata, not a gate).
        let lookup = match row.model_served.as_deref() {
            Some(served) => {
                get_llm_model_by_served(&self.pool, &row.tenant_id, &row.provider, served).await
            }
            None => get_llm_model(&self.pool, &row.tenant_id, &row.model_alias).await,
        };
        // Currency is the priced model's catalog currency; default to USD when
        // there is no model row (cost is then Unknown / NULL anyway, so the
        // currency label is never actually attached to a cost increment).
        let (cost, currency) = match lookup {
            Ok(Some(model)) => {
                let breakdown = compute_cost(
                    &model,
                    row.input_tokens,
                    row.output_tokens,
                    row.cached_read_tokens,
                    row.cache_write_tokens,
                );
                let currency = model.currency.clone();
                (breakdown, currency)
            }
            Ok(None) => (CostBreakdown::default(), "USD".to_string()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    model = %row.model_alias,
                    served = ?row.model_served,
                    "llm_usage cost lookup failed; recording tokens with unknown cost",
                );
                (CostBreakdown::default(), "USD".to_string())
            }
        };

        // Emit gen_ai.* metrics before the (best-effort) ledger
        // insert, so a dropped ledger write still surfaces the call in
        // dashboards. The ledger is the durable record; these counters are the
        // live view. Tokens label by request alias (bounded catalog cardinality).
        waygate_telemetry::metrics::record_llm_usage(waygate_telemetry::metrics::LlmUsageMetric {
            provider: &row.provider,
            provider_account_id: row.provider_account_id.as_deref(),
            duration_seconds: row.latency_ms.map(|value| value as f64 / 1000.0),
            gateway_cache_hit: row.gateway_cache_hit,
            model: &row.model_alias,
            finish_reason: row.finish_reason.as_deref(),
            input_tokens: row.input_tokens,
            output_tokens: row.output_tokens,
            cached_read_tokens: row.cached_read_tokens,
            cache_write_tokens: row.cache_write_tokens,
            reasoning_tokens: row.reasoning_tokens,
            cost: cost.total_cost.and_then(|d| d.to_f64()),
            currency: &currency,
        });

        if let Err(e) = insert_llm_usage(&self.pool, &row, &cost).await {
            // The call already succeeded and was audited; the usage ledger is
            // best-effort. Log and drop rather than propagate.
            tracing::warn!(
                error = %e,
                model = %row.model_alias,
                "failed to record llm_usage row (dropped; the call already succeeded)",
            );
        }
    }
}

/// Append one usage row with its computed cost. Generic over `sqlx::Executor`
/// (pool or transaction), mirroring the other storage helpers. `id` is a
/// caller-assigned UUIDv7 (time-ordered); `ts` defaults to `now()` server-side.
/// Token counts are `u64` in the domain and bind as `BIGINT` (`i64`) — counts
/// never approach `i64::MAX`, so the cast is lossless in practice.
pub async fn insert_llm_usage<'e, E>(
    executor: E,
    row: &LlmUsageRow,
    cost: &CostBreakdown,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let as_i64 = |v: Option<u64>| v.map(|n| n as i64);
    sqlx::query(
        r#"
        INSERT INTO llm_usage
            (id, tenant_id, principal_sub, model_alias, provider, model_served,
             inbound_surface, input_tokens, output_tokens, cached_read_tokens,
             cache_write_tokens, reasoning_tokens, finish_reason, refusal, latency_ms,
             input_cost, output_cost, total_cost, cost_source, gateway_cache_hit)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(&row.tenant_id)
    .bind(&row.principal_sub)
    .bind(&row.model_alias)
    .bind(&row.provider)
    .bind(&row.model_served)
    .bind(&row.inbound_surface)
    .bind(as_i64(row.input_tokens))
    .bind(as_i64(row.output_tokens))
    .bind(as_i64(row.cached_read_tokens))
    .bind(as_i64(row.cache_write_tokens))
    .bind(as_i64(row.reasoning_tokens))
    .bind(&row.finish_reason)
    .bind(row.refusal)
    .bind(row.latency_ms)
    .bind(cost.input_cost)
    .bind(cost.output_cost)
    .bind(cost.total_cost)
    .bind(cost.source.as_str())
    .bind(row.gateway_cache_hit)
    .execute(executor)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    fn model_with_rates(input: Option<&str>, output: Option<&str>) -> LlmModelRow {
        use std::str::FromStr;
        LlmModelRow {
            tenant_id: "default".into(),
            alias: "gpt-x".into(),
            provider: "openrouter".into(),
            credential_label: "MAIN".into(),
            upstream_model: "openai/gpt-x".into(),
            base_url: "https://x".into(),
            path: "chat/completions".into(),
            upstream_api: "chat_completions".into(),
            openai_chatgpt: false,
            risk: "high".into(),
            requires_approval: false,
            description: None,
            input_cost_per_mtok: input.map(|s| Decimal::from_str(s).unwrap()),
            output_cost_per_mtok: output.map(|s| Decimal::from_str(s).unwrap()),
            cached_read_cost_per_mtok: None,
            cache_write_cost_per_mtok: None,
            currency: "USD".into(),
            enabled: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn computes_cost_as_rate_times_tokens_over_a_million() {
        use std::str::FromStr;
        // $3 / Mtok input, $6 / Mtok output; 1_000_000 in, 500_000 out.
        let m = model_with_rates(Some("3"), Some("6"));
        let c = compute_cost(&m, Some(1_000_000), Some(500_000), None, None);
        assert_eq!(c.input_cost, Some(Decimal::from_str("3").unwrap()));
        assert_eq!(c.output_cost, Some(Decimal::from_str("3").unwrap()));
        assert_eq!(c.total_cost, Some(Decimal::from_str("6").unwrap()));
        assert_eq!(c.source, CostSource::ComputedFromCatalog);
    }

    #[test]
    fn no_rates_yields_unknown_and_null_total() {
        let m = model_with_rates(None, None);
        let c = compute_cost(&m, Some(1000), Some(1000), None, None);
        assert_eq!(c.total_cost, None);
        assert_eq!(c.input_cost, None);
        assert_eq!(c.source, CostSource::Unknown);
    }

    #[test]
    fn missing_token_class_is_not_priced_but_others_are() {
        use std::str::FromStr;
        // Output rate set but the provider did not report output tokens →
        // output_cost is None; input still prices and the source is computed.
        let m = model_with_rates(Some("2"), Some("8"));
        let c = compute_cost(&m, Some(1_000_000), None, None, None);
        assert_eq!(c.input_cost, Some(Decimal::from_str("2").unwrap()));
        assert_eq!(c.output_cost, None);
        assert_eq!(c.total_cost, Some(Decimal::from_str("2").unwrap()));
        assert_eq!(c.source, CostSource::ComputedFromCatalog);
    }
}
