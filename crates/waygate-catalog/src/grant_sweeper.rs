//! Periodic prune of consumed / expired
//! `approval_grants` rows. Without this, the hot-path
//! `(tenant_id, principal_sub, tool_id, argument_hash)` index
//! grows monotonically — most rows are dead (consumed at first
//! claim) but still walked by the index.
//!
//! Mirrors the shape of the AS / Tier-A re-encrypt sweepers in
//! `waygate-as`: a `tokio::time::interval`-driven loop that
//! awaits `shutdown` on every tick so the gateway can drain
//! cleanly.
//!
//! Retention is operator-tunable. The default
//! (`GATEWAY_GRANT_RETENTION_DAYS=7`) keeps a week of dead grants
//! around for the admin "history" view (`?include_consumed=true`)
//! before pruning. The sweep interval default
//! (`GATEWAY_GRANT_SWEEP_INTERVAL_SECONDS=3600`) is once per hour;
//! `0` disables the sweeper entirely.

use std::future::Future;
use std::time::Duration;

use time::OffsetDateTime;
use tokio::pin;
use tokio::time::interval;

use crate::store::SharedCatalogStore;

/// Run the grant sweeper until `shutdown` fires.
///
/// `interval_period` is the cadence between ticks; `retention`
/// is the minimum age a dead-grant row must reach before the
/// sweep deletes it (so very recently consumed grants stay
/// visible to the admin "history" view for the retention
/// window).
///
/// Each tick computes `older_than = now() - retention` and
/// passes it to
/// [`crate::store::CatalogStore::sweep_grants`]; the count is
/// recorded as the
/// `mcp_grant_sweep_rows_deleted` Prometheus counter and
/// emitted as an INFO log when non-zero (so silent steady-state
/// doesn't spam journald).
///
/// On store error: log a WARN, increment the
/// `mcp_grant_sweep_errors_total` counter, and keep going on
/// the next tick. The sweeper is hygiene, not load-bearing —
/// the only consequence of a missed tick is the table grows
/// for an hour longer than intended.
pub async fn run_grant_sweeper(
    catalog: SharedCatalogStore,
    interval_period: Duration,
    retention: Duration,
    shutdown: impl Future<Output = ()>,
) {
    pin!(shutdown);
    let mut ticker = interval(interval_period);
    // Skip the first immediate tick — tokio::interval fires
    // once at t=0 and that's not useful at boot (the table is
    // empty or near-empty; the operator hasn't had time to mint
    // grants that could be due for pruning).
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("grant sweeper shutting down");
                return;
            }
            _ = ticker.tick() => {
                let older_than = OffsetDateTime::now_utc()
                    - time::Duration::seconds(retention.as_secs() as i64);
                match catalog.sweep_grants(older_than).await {
                    Ok(0) => {
                        tracing::debug!("grant sweep: no rows to delete");
                    }
                    Ok(n) => {
                        tracing::info!(
                            deleted = n,
                            retention_secs = retention.as_secs(),
                            "approval-grant sweep deleted dead rows",
                        );
                        waygate_telemetry::metrics::record_grant_sweep_deleted(n);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "grant sweep failed; will retry on next tick");
                        waygate_telemetry::metrics::record_grant_sweep_error();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::CatalogStore;
    use crate::types::{
        ApprovalAction, ApprovalGrant, CatalogError, CatalogServerStatus, CatalogServerSummary,
        DriftEvent, DriftObservation, GrantFilter, GrantLookup, NewApprovalGrant, ResolvedTool,
    };
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Catalog fake: counts `sweep_grants` calls and returns the
    /// configured per-call delete count. Lets the sweeper test
    /// assert the loop ticked and called the store with the
    /// expected `older_than` window.
    struct SweepCatalog {
        sweep_calls: AtomicU64,
        delete_count: u64,
        /// Most recent `older_than` value the sweeper passed in.
        /// We pin it via `Mutex<Option<OffsetDateTime>>` so the
        /// test thread can read it after shutting down.
        last_older_than: std::sync::Mutex<Option<OffsetDateTime>>,
    }

    #[async_trait]
    impl CatalogStore for SweepCatalog {
        async fn approved_servers(
            &self,
            _t: &str,
        ) -> Result<Vec<CatalogServerSummary>, CatalogError> {
            Ok(vec![])
        }
        async fn resolve_tool(&self, _t: &str, _fq: &str) -> Result<ResolvedTool, CatalogError> {
            Ok(ResolvedTool::NotFound)
        }
        async fn record_drift(&self, _o: DriftObservation<'_>) -> Result<(), CatalogError> {
            Ok(())
        }
        async fn record_approval(&self, _a: ApprovalAction<'_>) -> Result<(), CatalogError> {
            Ok(())
        }
        async fn list_drift_events(
            &self,
            _t: &str,
            _s: OffsetDateTime,
            _l: u32,
        ) -> Result<Vec<DriftEvent>, CatalogError> {
            Ok(vec![])
        }
        async fn set_server_status(
            &self,
            _t: &str,
            _id: Uuid,
            _s: CatalogServerStatus,
            _a: &str,
            _r: Option<&str>,
        ) -> Result<bool, CatalogError> {
            Ok(true)
        }
        async fn last_approve_actor(
            &self,
            _t: &str,
            _id: Uuid,
        ) -> Result<Option<String>, CatalogError> {
            Ok(None)
        }
        async fn find_grant<'a>(
            &self,
            _l: GrantLookup<'a>,
        ) -> Result<Option<ApprovalGrant>, CatalogError> {
            Ok(None)
        }
        async fn claim_grant<'a>(
            &self,
            _l: GrantLookup<'a>,
        ) -> Result<Option<ApprovalGrant>, CatalogError> {
            Ok(None)
        }
        async fn create_grant<'a>(
            &self,
            _g: NewApprovalGrant<'a>,
        ) -> Result<ApprovalGrant, CatalogError> {
            Err(CatalogError::Unknown("not used"))
        }
        async fn list_grants<'a>(
            &self,
            _t: &'a str,
            _f: GrantFilter<'a>,
        ) -> Result<Vec<ApprovalGrant>, CatalogError> {
            Ok(vec![])
        }
        async fn revoke_grant(&self, _t: &str, _id: Uuid) -> Result<bool, CatalogError> {
            Ok(false)
        }
        async fn revoke_execution_grants(
            &self,
            _t: &str,
            _execution_id: Uuid,
        ) -> Result<u64, CatalogError> {
            Ok(0)
        }
        async fn sweep_grants(&self, older_than: OffsetDateTime) -> Result<u64, CatalogError> {
            self.sweep_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_older_than.lock().unwrap() = Some(older_than);
            Ok(self.delete_count)
        }
    }

    /// The sweeper MUST tick after the initial throwaway tick and
    /// MUST pass an `older_than` value approximately equal to
    /// `now() - retention`. Uses a very short interval (50ms) so
    /// the test runs in well under a second on real time without
    /// needing tokio's `test-util` paused-time feature.
    #[tokio::test(flavor = "current_thread")]
    async fn sweeper_ticks_and_passes_retention_window() {
        let inspect = Arc::new(SweepCatalog {
            sweep_calls: AtomicU64::new(0),
            delete_count: 3,
            last_older_than: std::sync::Mutex::new(None),
        });
        let catalog: SharedCatalogStore = inspect.clone();
        let shutdown_tx = Arc::new(tokio::sync::Notify::new());
        let shutdown_rx = shutdown_tx.clone();
        let retention = Duration::from_secs(7 * 24 * 3600);
        let sweep_handle = tokio::spawn(async move {
            run_grant_sweeper(catalog, Duration::from_millis(50), retention, async move {
                shutdown_rx.notified().await
            })
            .await
        });
        // Wait long enough for the initial throwaway tick + at
        // least one real tick.
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown_tx.notify_waiters();
        sweep_handle.await.unwrap();

        let calls = inspect.sweep_calls.load(Ordering::SeqCst);
        assert!(
            calls >= 1,
            "sweeper should have ticked at least once; got {calls}",
        );
        let older_than = inspect
            .last_older_than
            .lock()
            .unwrap()
            .expect("sweep_grants should have been invoked");
        let now = OffsetDateTime::now_utc();
        let delta_secs = (now - older_than).whole_seconds();
        assert!(
            (delta_secs - retention.as_secs() as i64).abs() < 5,
            "older_than should be ~retention behind now; got {delta_secs}s vs {}s",
            retention.as_secs(),
        );
    }
}
