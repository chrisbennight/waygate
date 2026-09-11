//! Tuned connection-pool construction for the audit store.
//!
//! Two roles share one Postgres database but get different session tuning,
//! applied via `after_connect` so it is code-defined, idempotent, and
//! re-applied on every fresh connection (hence every fresh deploy/bootstrap) —
//! no hand-run `ALTER SYSTEM` or `postgresql.conf` edit required. Every GUC set
//! here is `USERSET` context, so no superuser privilege is needed.
//!
//! - [`PoolRole::Writer`] — write-capable audit or control-plane pools.
//!   Callers may create separate pools with this tuning so those workloads do
//!   not share connection permits. Resource GUCs only.
//! - [`PoolRole::Reader`] — the admin dashboard's read path. Adds
//!   `plan_cache_mode = force_custom_plan` so the dashboard's optional-filter
//!   queries are re-planned per call and never settle on a generic seq-scan
//!   plan after Postgres' prepared-statement custom→generic switch (which fires
//!   after five executions).

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};

use crate::audit::StorageError;

/// Which workload a pool serves. Selects the session tuning applied on connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolRole {
    /// Write-capable audit or control-plane path.
    Writer,
    /// Admin dashboard read path.
    Reader,
}

impl PoolRole {
    /// The `SET` block applied to every connection of a pool with this role.
    /// Kept as a function (not a closure capture) so it is unit-testable and
    /// the exact SQL is reviewable in one place.
    fn session_tuning_sql(self) -> &'static str {
        match self {
            // Resource GUCs only. `random_page_cost` trusts indexes on
            // SSD-class storage; `work_mem` keeps dashboard sorts/percentiles
            // in memory instead of spilling to temp files; `jit` off because
            // this OLTP/dashboard workload never amortises JIT compile cost.
            PoolRole::Writer => "SET random_page_cost = 1.1; SET work_mem = '64MB'; SET jit = off;",
            // Same resource GUCs plus force_custom_plan: the reader runs the
            // optional-filter `($N IS NULL OR col = $N)` dashboard queries, and
            // a cached generic plan for those degrades to a sequential scan.
            PoolRole::Reader => {
                "SET random_page_cost = 1.1; SET work_mem = '64MB'; SET jit = off; \
                 SET plan_cache_mode = 'force_custom_plan';"
            }
        }
    }
}

/// Build a Postgres pool with role-appropriate session tuning applied on every
/// connection. Does NOT run migrations — the caller runs those once against the
/// writer pool.
pub async fn build_pool(
    database_url: &str,
    role: PoolRole,
    max_connections: u32,
) -> Result<PgPool, StorageError> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute(role.session_tuning_sql()).await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
        .map_err(StorageError::Connect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_pins_custom_plan_writer_does_not() {
        // Contract: only the reader forces custom plans; both roles set the
        // shared resource GUCs. Pins the role→tuning mapping, not exact SQL
        // spacing, so a future GUC tweak only updates the asserted substring.
        let reader = PoolRole::Reader.session_tuning_sql();
        let writer = PoolRole::Writer.session_tuning_sql();
        assert!(reader.contains("plan_cache_mode"));
        assert!(!writer.contains("plan_cache_mode"));
        for guc in ["random_page_cost", "work_mem", "jit"] {
            assert!(reader.contains(guc), "reader missing {guc}");
            assert!(writer.contains(guc), "writer missing {guc}");
        }
    }
}
