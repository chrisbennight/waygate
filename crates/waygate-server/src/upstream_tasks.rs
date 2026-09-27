//! Composition of durable task routing and expired-metadata cleanup.

use std::sync::Arc;
use waygate_mcp::tasks::{PgTaskRouteStore, TaskRouter};

pub fn build(
    pool: Option<&sqlx::PgPool>,
    retention_seconds: u64,
    shutdown: tokio_util::sync::CancellationToken,
) -> Option<Arc<TaskRouter>> {
    let Some(pool) = pool else {
        tracing::info!("upstream Tasks disabled: routing database is not configured");
        return None;
    };
    let store = Arc::new(PgTaskRouteStore::new(pool.clone()));
    let sweeper = store.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tick.tick() => {
                    if sweeper.sweep_expired().await.is_err() {
                        tracing::warn!("upstream task routing cleanup failed; will retry next interval");
                    }
                }
            }
        }
    });
    Some(Arc::new(TaskRouter::new(store, retention_seconds)))
}
