//! Audit row selection and deadline-bounded observer reads.

use std::sync::LazyLock;
use std::time::Duration;

use sqlx::pool::PoolConnection;
use sqlx::{Acquire, PgExecutor, PgPool, Postgres};
use tokio::time::Instant;
use uuid::Uuid;

use super::{AuditQuery, AuditReadError, AuditRow};

// Every caller uses the same predicates and bindings, including the ID cursor.
// strpos preserves literal substring semantics, including '%' and '_'.
const FILTERED_SQL: &str = r#"
SELECT id, ts, category, tenant_id, action, outcome,
       principal_sub, principal_email, principal_groups, issuer,
       server, tool, operation, risk_level, pii,
       policy_ids, reason, trace_id, latency_ms,
       scim_active, scim_groups, target,
       req_scopes, auth_method, req_roles, side_effects,
       parent_execution_id, execution_step,
       execution_call_id, execution_attempt
FROM audit_log
WHERE ($1::TEXT IS NULL OR server = $1)
  AND ($2::TEXT IS NULL OR outcome = $2)
  AND ($12::TEXT IS NULL OR outcome <> $12)
  AND ($3::TEXT IS NULL OR risk_level = $3)
  AND ($4::TEXT IS NULL
       OR category = $4
       OR (category IS NULL AND $4 = 'invocation'))
  AND ($5::TEXT IS NULL
       OR strpos(principal_sub, $5) > 0
       OR strpos(principal_email, $5) > 0)
  AND ($6::BOOLEAN IS NULL OR pii = $6)
  AND ($7::TIMESTAMPTZ IS NULL OR ts >= $7)
  AND ($8::TIMESTAMPTZ IS NULL OR ts <= $8)
  AND ($9::UUID IS NULL OR id < $9)
  AND ($11::TEXT IS NULL OR tenant_id = $11)
  AND ($13::TEXT IS NULL OR policy_ids @> ARRAY[$13])
  AND (cardinality($14::TEXT[]) = 0
       OR category = ANY($14)
       OR (category IS NULL AND 'invocation' = ANY($14)))
  AND ($15::TEXT IS NULL OR reason IS DISTINCT FROM $15)
  AND ($16::TEXT IS NULL OR tool = $16)
  AND ($17::TEXT IS NULL OR reason = $17)
  AND ($18::TEXT IS NULL OR trace_id = $18)
"#;

static ORDERED_SQL: LazyLock<String> =
    LazyLock::new(|| format!("{FILTERED_SQL} ORDER BY id DESC LIMIT $10"));
static WINDOWED_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "WITH matches AS MATERIALIZED ({FILTERED_SQL}) \
         SELECT * FROM matches ORDER BY id DESC LIMIT $10"
    )
});

fn sql(query: &AuditQuery, bounded: bool) -> &'static str {
    if bounded
        && query.tenant_id.is_some()
        && query.since.is_some()
        && query.principal_substr.is_some()
    {
        // LIMIT must not encourage a full-history ID scan on the assumption
        // that a rare substring will quickly produce a complete page.
        &WINDOWED_SQL
    } else {
        &ORDERED_SQL
    }
}

pub(super) async fn fetch<'e>(
    executor: impl PgExecutor<'e>,
    query: &AuditQuery,
    limit: i64,
    after_id: Option<Uuid>,
    bounded: bool,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(sql(query, bounded))
        .bind(query.server.as_deref())
        .bind(query.outcome.as_deref())
        .bind(query.risk_level.as_deref())
        .bind(query.category.as_deref())
        .bind(query.principal_substr.as_deref())
        .bind(query.pii)
        .bind(query.since)
        .bind(query.until)
        .bind(after_id)
        .bind(limit.max(1))
        .bind(query.tenant_id.as_deref())
        .bind(query.outcome_ne.as_deref())
        .bind(query.policy_id.as_deref())
        .bind(query.categories.as_slice())
        .bind(query.reason_ne.as_deref())
        .bind(query.tool.as_deref())
        .bind(query.reason.as_deref())
        .bind(query.trace_id.as_deref())
        .fetch_all(executor)
        .await
}

// A canceled future must not return a connection with unfinished SQL to the
// shared pool. Successful rollback disarms the guard and permits normal reuse.
struct ReadConnection(Option<PoolConnection<Postgres>>);

impl Drop for ReadConnection {
    fn drop(&mut self) {
        if let Some(connection) = self.0.as_mut() {
            connection.close_on_drop();
        }
    }
}

pub(super) async fn fetch_bounded(
    pool: &PgPool,
    query: &AuditQuery,
    limit: i64,
    after_id: Option<Uuid>,
    budget: Duration,
) -> Result<Vec<AuditRow>, AuditReadError> {
    let deadline = Instant::now() + budget;
    tokio::time::timeout_at(deadline, async {
        let mut connection = ReadConnection(Some(pool.acquire().await?));
        let mut tx = connection
            .0
            .as_mut()
            .expect("acquired connection")
            .begin()
            .await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        let remaining_ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, i32::MAX as u128);
        // Transaction-local settings also cover the fallback control pool and
        // cannot leak a timeout or plan policy into an unrelated pooled read.
        sqlx::query(
            "SELECT set_config('statement_timeout', $1, true), \
             set_config('plan_cache_mode', 'force_custom_plan', true)",
        )
        .bind(format!("{remaining_ms}ms"))
        .execute(&mut *tx)
        .await?;
        let rows = fetch(&mut *tx, query, limit, after_id, true).await?;
        tx.rollback().await?;
        drop(connection.0.take());
        Ok(rows)
    })
    .await
    .map_err(|_| AuditReadError::DeadlineExceeded)?
}

#[cfg(test)]
mod tests;
