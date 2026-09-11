//! Lagging LLM budget enforcement
//! (`migrations/0049_llm_budgets.sql`).
//!
//! The LLM path's check_quota stage calls [`check_llm_budget`] before the
//! irreversible provider call. It reads RECORDED usage (the `llm_usage` ledger)
//! against the configured `llm_budgets` and reports the first exhausted limit,
//! if any — invariant I3: reject the next call iff the principal is ALREADY
//! at/over a limit, with no estimation of the in-flight call (bounded ~1-request
//! overrun).
//!
//! A budget applies to a call when its scope matches: `tenant_id` equal,
//! `principal_sub` NULL (tenant-wide) or equal, `model_alias` NULL (all models)
//! or equal. Every applicable enabled budget must pass; the first exhausted one
//! refuses the call. Each budget sums `llm_usage` over its own rolling window
//! and scope.

use async_trait::async_trait;
use rust_decimal::Decimal;
use time::OffsetDateTime;

use waygate_evidence::budget::{BudgetRejection, LlmBudgetGate};

/// One configured budget row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmBudgetRow {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    /// `None` = tenant-wide.
    pub principal_sub: Option<String>,
    /// `None` = all models.
    pub model_alias: Option<String>,
    pub window_seconds: i64,
    pub max_total_tokens: Option<i64>,
    pub max_total_cost: Option<Decimal>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for LlmBudgetRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            principal_sub: row.try_get("principal_sub")?,
            model_alias: row.try_get("model_alias")?,
            window_seconds: row.try_get("window_seconds")?,
            max_total_tokens: row.try_get("max_total_tokens")?,
            max_total_cost: row.try_get("max_total_cost")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// The dimension a budget exhaustion tripped on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDimension {
    Tokens,
    Cost,
}

impl BudgetDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tokens => "tokens",
            Self::Cost => "cost",
        }
    }
}

/// A tripped budget: which dimension, and an operator-readable detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetExceedance {
    pub dimension: BudgetDimension,
    pub detail: String,
}

/// Insert or update a budget, keyed on its `(tenant, principal_sub, model_alias)`
/// scope. Used by the admin surface (and tests) to configure budgets.
pub async fn upsert_llm_budget<'e, E>(executor: E, row: &LlmBudgetRow) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO llm_budgets
            (id, tenant_id, principal_sub, model_alias, window_seconds,
             max_total_tokens, max_total_cost, enabled, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
        ON CONFLICT (tenant_id, principal_sub, model_alias) DO UPDATE SET
            window_seconds   = EXCLUDED.window_seconds,
            max_total_tokens = EXCLUDED.max_total_tokens,
            max_total_cost   = EXCLUDED.max_total_cost,
            enabled          = EXCLUDED.enabled,
            updated_at       = now()
        "#,
    )
    .bind(row.id)
    .bind(&row.tenant_id)
    .bind(&row.principal_sub)
    .bind(&row.model_alias)
    .bind(row.window_seconds)
    .bind(row.max_total_tokens)
    .bind(row.max_total_cost)
    .bind(row.enabled)
    .execute(executor)
    .await
    .map(|_| ())
}

/// Lagging budget check (I3). Returns `Some(exceedance)` when the principal is
/// already at/over an applicable limit (refuse the next call), `None` when
/// within budget (or no budget configured).
///
/// `pool` (not a bare executor) because the check runs two queries: the
/// applicable-budget lookup, then a per-budget usage SUM scoped to that
/// budget's own window + principal/model scope.
pub async fn check_llm_budget(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    principal_sub: Option<&str>,
    model_alias: &str,
) -> Result<Option<BudgetExceedance>, sqlx::Error> {
    // Budgets that apply to this call: tenant match, and scope columns either
    // wildcard (NULL) or equal to the call's principal / model.
    let budgets = sqlx::query_as::<_, LlmBudgetRow>(
        r#"
        SELECT id, tenant_id, principal_sub, model_alias, window_seconds,
               max_total_tokens, max_total_cost, enabled, created_at, updated_at
          FROM llm_budgets
         WHERE tenant_id = $1
           AND enabled
           AND (principal_sub IS NULL OR principal_sub = $2)
           AND (model_alias IS NULL OR model_alias = $3)
        "#,
    )
    .bind(tenant_id)
    .bind(principal_sub)
    .bind(model_alias)
    .fetch_all(pool)
    .await?;

    for b in &budgets {
        // Sum recorded usage over THIS budget's rolling window and scope. A
        // wildcard (NULL) scope column sums across all principals / models.
        let row = sqlx::query(
            r#"
            SELECT
                COALESCE(SUM(COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0)), 0)::BIGINT
                    AS tokens,
                COALESCE(SUM(COALESCE(total_cost, 0)), 0) AS cost
              FROM llm_usage
             WHERE tenant_id = $1
               AND ts >= now() - make_interval(secs => $2)
               AND ($3::text IS NULL OR principal_sub = $3)
               AND ($4::text IS NULL OR model_alias = $4)
            "#,
        )
        .bind(tenant_id)
        .bind(b.window_seconds as f64)
        .bind(&b.principal_sub)
        .bind(&b.model_alias)
        .fetch_one(pool)
        .await?;
        use sqlx::Row;
        let used_tokens: i64 = row.try_get("tokens")?;
        let used_cost: Decimal = row.try_get("cost")?;

        if let Some(max) = b.max_total_tokens {
            if used_tokens >= max {
                return Ok(Some(BudgetExceedance {
                    dimension: BudgetDimension::Tokens,
                    detail: format!(
                        "{used_tokens} tokens used >= {max} limit over the last {}s",
                        b.window_seconds
                    ),
                }));
            }
        }
        if let Some(max) = b.max_total_cost {
            if used_cost >= max {
                return Ok(Some(BudgetExceedance {
                    dimension: BudgetDimension::Cost,
                    detail: format!(
                        "{used_cost} cost used >= {max} limit over the last {}s",
                        b.window_seconds
                    ),
                }));
            }
        }
    }

    Ok(None)
}

/// Postgres-backed [`LlmBudgetGate`]. Cheap to clone (wraps a pooled `PgPool`).
#[derive(Clone)]
pub struct PgLlmBudgetGate {
    pool: sqlx::PgPool,
}

impl PgLlmBudgetGate {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LlmBudgetGate for PgLlmBudgetGate {
    async fn check(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        model_alias: &str,
    ) -> Option<BudgetRejection> {
        match check_llm_budget(&self.pool, tenant_id, principal_sub, model_alias).await {
            Ok(Some(exc)) => Some(BudgetRejection {
                dimension: exc.dimension.as_str().to_owned(),
                reason: exc.detail,
            }),
            Ok(None) => None,
            Err(e) => {
                // Fail OPEN: a budget is cost-control (bounded-overrun), not a
                // security boundary, so a transient budget-store error must not
                // take all inference offline. Log and allow.
                tracing::warn!(
                    error = %e,
                    tenant = %tenant_id,
                    "llm budget check failed; allowing the call (fail-open)",
                );
                None
            }
        }
    }
}
