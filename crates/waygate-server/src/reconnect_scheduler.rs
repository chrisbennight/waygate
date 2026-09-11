use std::{future::Future, sync::Arc};

use tokio_util::sync::CancellationToken;
use waygate_upstream::pool::UpstreamPool;

#[derive(Debug, PartialEq, Eq)]
enum ShutdownRace<T> {
    Completed(T),
    Shutdown,
}

async fn await_or_shutdown<T>(
    shutdown: &CancellationToken,
    future: impl Future<Output = T>,
) -> ShutdownRace<T> {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => ShutdownRace::Shutdown,
        value = future => ShutdownRace::Completed(value),
    }
}

pub(crate) async fn run(pool: Arc<UpstreamPool>, shutdown: CancellationToken) {
    let mut attempts = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = attempts.join_next(), if !attempts.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::error!(error = %error, "upstream reconnect task failed");
                }
            },
            _ = pool.wait_for_reconnect_due() => {
                match await_or_shutdown(&shutdown, pool.reconnect_due_task()).await {
                    ShutdownRace::Completed(Some(attempt)) => {
                        attempts.spawn(attempt);
                    }
                    ShutdownRace::Completed(None) => {}
                    ShutdownRace::Shutdown => break,
                }
            }
        }
    }
    attempts.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn shutdown_cancels_scheduler_waiting_without_upstreams() {
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(pool, shutdown.clone()));

        tokio::task::yield_now().await;
        shutdown.cancel();

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("reconnect scheduler ignored shutdown")
            .expect("reconnect scheduler panicked");
    }

    #[tokio::test]
    async fn shutdown_cancels_a_pending_claim_wait() {
        let shutdown = CancellationToken::new();
        let waiting_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            await_or_shutdown(&waiting_shutdown, std::future::pending::<()>()).await
        });

        tokio::task::yield_now().await;
        shutdown.cancel();

        let outcome = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("claim wait ignored shutdown")
            .expect("claim wait panicked");
        assert_eq!(outcome, ShutdownRace::Shutdown);
    }
}
