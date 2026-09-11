//! Tier-2: incremental maintenance of the `audit_rollup_hourly` pre-aggregate.
//!
//! The dashboard's wide-window aggregates (30d / "all time" volume, deny-rate,
//! per-tool totals) would full-scan the unboundedly-growing `audit_log`. This
//! worker keeps an hourly rollup current so those reads hit a small table
//! instead. It mirrors the [`crate::drain`] worker shape: an interval ticker
//! that calls [`rollup_once`] each tick and a shutdown branch for clean drain.
//!
//! Correctness model:
//! - Each tick RECOMPUTES every bucket newer than a finalized-hour watermark
//!   (`audit_rollup_state.finalized_hour`) directly from `audit_log`: DELETE
//!   the window's rollup rows, then re-aggregate. This recompute is
//!   IDEMPOTENT, so it is correct regardless of commit order, non-UUIDv7 ids
//!   (the retention-sweep markers use `Uuid::new_v4()`), or rows that arrive
//!   late within the window — there is no monotonic-id cursor that could skip a
//!   row forever. DELETE + INSERT + watermark-advance commit together, so a
//!   crash rolls back.
//! - The watermark advances only to `now() - SAFETY_LAG_HOURS` (truncated to
//!   the hour). Older buckets are closed (every row in them has certainly
//!   committed) and never recomputed again; the current hour stays in-window so
//!   it is refreshed every tick.
//! - The fold excludes `reason = 'pre_call'` intent rows, matching the live
//!   histogram / tool-stats semantics (those rows pair with a later real
//!   outcome row; counting both would double the volume).
//! - p95 latency is NOT rolled up (not additive across buckets); the dashboard
//!   computes it live over the bounded window.
//! - Retention: frozen buckets are an independent long-term aggregate — if a
//!   retention policy later sweeps the raw rows, the rollup keeps the counts by
//!   design (see the migration's retention note). With unbounded retention (the
//!   default) the rollup and raw always agree.

use std::future::Future;
use std::time::Duration;

use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use tokio::pin;
use tokio::time::{interval, MissedTickBehavior};

use crate::audit::{AuditFacets, HistogramBucket, ToolStat};

/// Safety lag: the worker freezes (stops recomputing) a bucket only once it is
/// at least this old, by which point every row that will ever land in it has
/// certainly committed. Generous on purpose — audit rows are written
/// synchronously on the request path, so the real producer→commit gap is
/// sub-second; this guards against a slow/retried audit transaction or modest
/// clock skew. The cost of a larger lag is only that each tick re-aggregates a
/// few more recent hours.
const SAFETY_LAG_HOURS: i32 = 2;

/// Recompute every rollup bucket newer than the finalized watermark directly
/// from `audit_log`, then advance the watermark — all in one transaction.
/// Returns the number of rollup rows (re)written.
///
/// The recompute is idempotent (DELETE the window + re-aggregate), so it cannot
/// skip or double-count rows the way a monotonic-id cursor could; see the
/// module docs. `FOR UPDATE` on the singleton serializes concurrent workers.
pub async fn rollup_once(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Serialize workers and read the recompute floor. NULL ⇒ recompute the
    // whole table (initial backfill of all historical hours).
    let finalized_hour: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT finalized_hour FROM audit_rollup_state WHERE id FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;

    // Drop the window's existing rollup rows, then re-aggregate them from
    // audit_log. Two separate statements (not a DELETE+INSERT data-modifying
    // CTE) so the INSERT observes the DELETE's effect and can't trip the unique
    // constraint on a row the same statement is removing.
    sqlx::query(
        "DELETE FROM audit_rollup_hourly WHERE $1::TIMESTAMPTZ IS NULL OR bucket_hour >= $1",
    )
    .bind(finalized_hour)
    .execute(&mut *tx)
    .await?;

    let rewritten = sqlx::query(
        r#"
        INSERT INTO audit_rollup_hourly
            (tenant_id, bucket_hour, server, tool, outcome, category, risk_level, pii, n)
        SELECT tenant_id,
               date_trunc('hour', ts),
               server, tool, outcome,
               COALESCE(category, 'invocation'),
               risk_level, pii,
               count(*)
        FROM audit_log
        WHERE ($1::TIMESTAMPTZ IS NULL OR ts >= $1)
          AND reason IS DISTINCT FROM 'pre_call'
        GROUP BY tenant_id, date_trunc('hour', ts), server, tool, outcome,
                 COALESCE(category, 'invocation'), risk_level, pii
        "#,
    )
    .bind(finalized_hour)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    // Advance the freeze boundary to now() - lag. Buckets older than this are
    // closed and won't be recomputed again; the current hour stays in-window.
    sqlx::query(
        "UPDATE audit_rollup_state
            SET finalized_hour = date_trunc('hour', now() - make_interval(hours => $1::INT)),
                updated_at = now()
          WHERE id",
    )
    .bind(SAFETY_LAG_HOURS)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(rewritten)
}

/// Periodic rollup worker. Calls [`rollup_once`] every `interval_period`; a
/// fold error is logged and retried on the next tick (the watermark only
/// advances on a committed fold, so a transient failure never loses rows).
pub async fn run_rollup_maintenance(
    pool: PgPool,
    interval_period: Duration,
    shutdown: impl Future<Output = ()>,
) {
    pin!(shutdown);
    let mut ticker = interval(interval_period);
    // Skip the immediate t=0 tick; first fold happens after one interval.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;
    tracing::info!(
        interval_secs = interval_period.as_secs(),
        "audit rollup maintenance started"
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("audit rollup maintenance shutting down");
                return;
            }
            _ = ticker.tick() => {
                match rollup_once(&pool).await {
                    Ok(n) if n > 0 => tracing::debug!(rollup_rows = n, "audit rollup folded"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        error = %e,
                        "audit rollup fold failed; retrying next tick"
                    ),
                }
            }
        }
    }
}

/// Wide-window volume histogram read from the rollup. Re-buckets the hourly
/// rollup into `bucket_seconds`-wide buckets (must be >= 3600 for the rollup
/// granularity to be meaningful) and stacks counts by outcome — the same
/// `HistogramBucket` shape the live `AuditReader::histogram` returns, so the
/// dashboard can swap the source by window width.
///
/// Applies the same categorical filters the live histogram does for every
/// dimension the rollup carries (`server` / `risk_level` / `category` / `pii`),
/// so a filtered wide-window read matches the live semantics. `category` is
/// stored COALESCE'd to `'invocation'` at fold time, so a plain equality here
/// already covers the NULL-counts-as-invocation case. The fold also excluded
/// `pre_call` rows, matching the live reader.
///
/// NOT supported: `principal` substring filtering — the rollup has no principal
/// dimension (it would explode cardinality). Callers MUST fall back to the live
/// reader when a principal filter is active; this signature has no principal
/// parameter so that contract is structural, not a silent drop.
///
/// Granularity: the rollup buckets by hour, so `since`/`until` are honoured at
/// hour resolution (`since` is floored to the hour to keep its partial bucket).
/// This reader is for WIDE windows (7d/30d/all), whose histogram bars are an
/// hour or coarser — hour-edge fuzz is immaterial there. Narrow, sub-hour-
/// precise windows (15m/1h/24h) must use the live `AuditReader::histogram`,
/// which the dashboard already does for those window widths.
#[allow(clippy::too_many_arguments)]
pub async fn rollup_histogram(
    pool: &PgPool,
    tenant: Option<&str>,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
    server: Option<&str>,
    risk_level: Option<&str>,
    category: Option<&str>,
    pii: Option<bool>,
    bucket_seconds: i64,
) -> Result<Vec<HistogramBucket>, sqlx::Error> {
    let bucket_seconds = bucket_seconds.max(3600);
    let rows = sqlx::query_as::<_, (i64, String, i64)>(
        r#"
        SELECT (floor(extract(epoch FROM bucket_hour) / $8) * $8)::BIGINT AS bucket_epoch,
               outcome,
               sum(n)::BIGINT AS n
        FROM audit_rollup_hourly
        WHERE ($1::TEXT IS NULL OR tenant_id = $1)
          -- Floor `since` to the hour so the bucket that *contains* `since`
          -- (e.g. since=14:30 → the 14:00 bucket) is INCLUDED rather than
          -- dropped — the rollup is hour-granular, so this is the closest it
          -- can come to the live reader's `ts >= since` without losing the
          -- first partial hour's rows.
          AND ($2::TIMESTAMPTZ IS NULL OR bucket_hour >= date_trunc('hour', $2))
          AND ($3::TIMESTAMPTZ IS NULL OR bucket_hour <= $3)
          AND ($4::TEXT IS NULL OR server = $4)
          AND ($5::TEXT IS NULL OR risk_level = $5)
          AND ($6::TEXT IS NULL OR category = $6)
          AND ($7::BOOLEAN IS NULL OR pii = $7)
        GROUP BY bucket_epoch, outcome
        ORDER BY bucket_epoch, outcome
        "#,
    )
    .bind(tenant)
    .bind(since)
    .bind(until)
    .bind(server)
    .bind(risk_level)
    .bind(category)
    .bind(pii)
    .bind(bucket_seconds as f64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(bucket_epoch, outcome, count)| HistogramBucket {
            bucket_epoch,
            outcome,
            count,
        })
        .collect())
}

/// Wide-window per-(server, tool) reliability from the rollup — call volume and
/// execution-error / denial counts. Mirrors `AuditReader::tool_stats` for every
/// dimension the rollup carries (server/risk/category/pii; outcome is summed
/// across, since the FILTERs derive errors/denied). `p95_latency_ms` is always
/// `None`: latency is not additive across buckets and is not rolled up — the
/// caller shows live p95 only for narrow windows. `since` is floored to the
/// hour (see `rollup_histogram`). Principal filtering is unsupported (no
/// principal dimension); callers fall back to the live reader when it is set.
#[allow(clippy::too_many_arguments)]
pub async fn rollup_tool_stats(
    pool: &PgPool,
    tenant: Option<&str>,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
    server: Option<&str>,
    risk_level: Option<&str>,
    category: Option<&str>,
    pii: Option<bool>,
    limit: i64,
) -> Result<Vec<ToolStat>, sqlx::Error> {
    let limit = limit.clamp(1, 200);
    let rows = sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        r#"
        SELECT server, tool,
               sum(n)::BIGINT AS total,
               -- COALESCE: `sum(...) FILTER` is NULL (not 0) when no row matches
               -- the filter; the live tool_stats uses count(*), which never is.
               COALESCE(sum(n) FILTER (WHERE outcome = 'execution_error'), 0)::BIGINT AS errors,
               COALESCE(sum(n) FILTER (WHERE outcome = 'denied'), 0)::BIGINT AS denied
        FROM audit_rollup_hourly
        WHERE ($1::TEXT IS NULL OR tenant_id = $1)
          AND ($2::TIMESTAMPTZ IS NULL OR bucket_hour >= date_trunc('hour', $2))
          AND ($3::TIMESTAMPTZ IS NULL OR bucket_hour <= $3)
          AND ($4::TEXT IS NULL OR server = $4)
          AND ($5::TEXT IS NULL OR risk_level = $5)
          AND ($6::TEXT IS NULL OR category = $6)
          AND ($7::BOOLEAN IS NULL OR pii = $7)
          AND server IS NOT NULL
          AND tool IS NOT NULL
        GROUP BY server, tool
        ORDER BY total DESC, server, tool
        LIMIT $8
        "#,
    )
    .bind(tenant)
    .bind(since)
    .bind(until)
    .bind(server)
    .bind(risk_level)
    .bind(category)
    .bind(pii)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(server, tool, total, errors, denied)| ToolStat {
            server,
            tool,
            total,
            errors,
            denied,
            p95_latency_ms: None,
        })
        .collect())
}

/// Wide-window facet rail from the rollup. Like `AuditReader::facet_counts`, a
/// table-wide aggregate within the time window ONLY (categorical filters do not
/// narrow the rail), summed per dimension from the rollup in one scan. NULL
/// risk/server/pii carry no chip; `category` is stored non-NULL (COALESCE'd at
/// fold). No principal concern — facets never filter by principal. `since` is
/// floored to the hour.
pub async fn rollup_facets(
    pool: &PgPool,
    tenant: Option<&str>,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
) -> Result<AuditFacets, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        r#"
        WITH scoped AS MATERIALIZED (
            SELECT server, outcome, category, risk_level, pii, n
            FROM audit_rollup_hourly
            WHERE ($1::TEXT IS NULL OR tenant_id = $1)
              AND ($2::TIMESTAMPTZ IS NULL OR bucket_hour >= date_trunc('hour', $2))
              AND ($3::TIMESTAMPTZ IS NULL OR bucket_hour <= $3)
        )
        SELECT 'outcome' AS dim, outcome AS val, sum(n)::BIGINT AS n
          FROM scoped GROUP BY outcome
        UNION ALL
        SELECT 'risk', risk_level, sum(n)::BIGINT
          FROM scoped WHERE risk_level IS NOT NULL GROUP BY risk_level
        UNION ALL
        SELECT 'category', category, sum(n)::BIGINT
          FROM scoped GROUP BY category
        UNION ALL
        SELECT 'server', server, sum(n)::BIGINT
          FROM scoped WHERE server IS NOT NULL GROUP BY server
        UNION ALL
        SELECT 'pii', CASE WHEN pii THEN 'true' ELSE 'false' END, sum(n)::BIGINT
          FROM scoped WHERE pii IS NOT NULL GROUP BY pii
        "#,
    )
    .bind(tenant)
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await?;
    let mut facets = AuditFacets::default();
    for (dim, val, n) in rows {
        match dim.as_str() {
            "outcome" => facets.outcome.push((val, n)),
            "risk" => facets.risk.push((val, n)),
            "category" => facets.category.push((val, n)),
            "server" => facets.server.push((val, n)),
            "pii" => facets.pii.push((val, n)),
            _ => {}
        }
    }
    Ok(facets)
}
