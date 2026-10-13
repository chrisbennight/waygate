//! Wakes a running Code Mode program's cancellation check when a cancellation
//! for it commits, on whichever replica requested it, so running programs do
//! not have to poll their rows to notice one.
//!
//! The store announces a request for a run with a live claim on
//! [`waygate_codemode::CANCELLATION_CHANNEL`]. One listener per process wakes
//! the matching watch, and wakes every watch whenever its connection may have
//! missed an announcement. A woken run confirms the request with one narrow
//! read before acting on it, so a spurious wake costs only that read.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Wait before reconnecting a listener whose connection failed.
const LISTENER_RETRY: Duration = Duration::from_secs(2);

/// Process-wide registry of running programs waiting to hear about their
/// cancellation.
#[derive(Clone, Default)]
pub struct CancellationWatch {
    waiters: Arc<Mutex<HashMap<Uuid, Weak<Notify>>>>,
}

/// One running program's registration; dropping it ends the watch.
pub struct CancellationWaiter {
    id: Uuid,
    notify: Arc<Notify>,
    watch: CancellationWatch,
}

impl CancellationWatch {
    /// Watch `id` for the life of the returned registration. Its first wait
    /// returns at once, so a request that committed before the watch began is
    /// still checked.
    pub fn watch(&self, id: Uuid) -> CancellationWaiter {
        let notify = Arc::new(Notify::new());
        notify.notify_one();
        self.waiters
            .lock()
            .expect("cancellation watch registry poisoned")
            .insert(id, Arc::downgrade(&notify));
        CancellationWaiter {
            id,
            notify,
            watch: self.clone(),
        }
    }

    fn wake(&self, id: Uuid) {
        let waiter = self
            .waiters
            .lock()
            .expect("cancellation watch registry poisoned")
            .get(&id)
            .and_then(Weak::upgrade);
        if let Some(waiter) = waiter {
            waiter.notify_one();
        }
    }

    fn wake_all(&self) {
        let waiters: Vec<Arc<Notify>> = self
            .waiters
            .lock()
            .expect("cancellation watch registry poisoned")
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for waiter in waiters {
            waiter.notify_one();
        }
    }

    /// Listen for cancellations committed on any replica until `shutdown`.
    pub fn spawn_listener(&self, pool: sqlx::PgPool, shutdown: CancellationToken) {
        tokio::spawn(listen(self.clone(), pool, shutdown));
    }
}

impl CancellationWaiter {
    /// Resolves when a cancellation for this run may have been requested.
    pub async fn notified(&self) {
        self.notify.notified().await;
    }
}

impl Drop for CancellationWaiter {
    fn drop(&mut self) {
        let mut waiters = self
            .watch
            .waiters
            .lock()
            .expect("cancellation watch registry poisoned");
        if waiters
            .get(&self.id)
            .is_some_and(|registered| registered.ptr_eq(&Arc::downgrade(&self.notify)))
        {
            waiters.remove(&self.id);
        }
    }
}

async fn listen(watch: CancellationWatch, pool: sqlx::PgPool, shutdown: CancellationToken) {
    loop {
        let listener = async {
            let mut listener = sqlx::postgres::PgListener::connect_with(&pool).await?;
            listener
                .listen(waygate_codemode::CANCELLATION_CHANNEL)
                .await?;
            Ok::<_, sqlx::Error>(listener)
        };
        let mut listener = tokio::select! {
            () = shutdown.cancelled() => return,
            listener = listener => match listener {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::warn!(%error, "Code Mode cancellation listener could not connect; retrying");
                    if sleep_or_shutdown(&shutdown).await {
                        return;
                    }
                    continue;
                }
            },
        };
        loop {
            // Anything announced while this connection was not listening is
            // caught by checking every watched run once it listens again.
            watch.wake_all();
            loop {
                let notification = tokio::select! {
                    () = shutdown.cancelled() => return,
                    notification = listener.try_recv() => notification,
                };
                match notification {
                    Ok(Some(notification)) => match notification.payload().parse::<Uuid>() {
                        Ok(id) => watch.wake(id),
                        Err(_) => tracing::warn!(
                            payload = notification.payload(),
                            "ignoring a malformed Code Mode cancellation announcement"
                        ),
                    },
                    // The connection dropped; the next receive reconnects and
                    // listens again.
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(%error, "Code Mode cancellation listener failed; reconnecting");
                        if sleep_or_shutdown(&shutdown).await {
                            return;
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Wait out the retry delay; returns `true` when shutdown arrived first.
async fn sleep_or_shutdown(shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => true,
        () = tokio::time::sleep(LISTENER_RETRY) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_watch_wakes_only_its_own_run_and_ends_with_its_registration() {
        let watch = CancellationWatch::default();
        let first = watch.watch(Uuid::now_v7());
        let second = watch.watch(Uuid::now_v7());
        // Each watch checks once as it begins.
        first.notified().await;
        second.notified().await;

        watch.wake(first.id);
        tokio::time::timeout(Duration::from_secs(1), first.notified())
            .await
            .expect("the named run is woken");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), second.notified())
                .await
                .is_err(),
            "another run is not woken"
        );

        watch.wake_all();
        tokio::time::timeout(Duration::from_secs(1), second.notified())
            .await
            .expect("a possibly missed announcement wakes every run");

        drop(first);
        drop(second);
        assert!(watch.waiters.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancellation_requested_on_another_replica_wakes_the_running_one() {
        let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
            return;
        };
        let tenant = waygate_test_support::pg::create_tenant(&pool).await;
        let store = waygate_codemode::PgExecutionStore::new(pool.clone());
        let id = Uuid::now_v7();
        let source = "return 1;";
        waygate_codemode::ExecutionStore::submit(
            &store,
            waygate_codemode::NewExecution {
                program_input: None,
                id,
                tenant_id: tenant.clone(),
                principal_sub: "alice".to_owned(),
                principal_issuer: "https://issuer.test".to_owned(),
                source: None,
                source_digest: waygate_codemode::source_digest(source),
                execution_profile: serde_json::json!({"name": "direct"}),
                sdk_contract_version: 1,
                runner_contract_version: 3,
                retention_until: time::OffsetDateTime::now_utc() + time::Duration::days(1),
            },
        )
        .await
        .expect("submit");
        waygate_codemode::ExecutionStore::claim(
            &store,
            &tenant,
            id,
            Uuid::now_v7(),
            Duration::from_secs(300),
            source.to_owned(),
            serde_json::json!({}),
        )
        .await
        .expect("claim")
        .expect("claim succeeds");

        // The replica running the program listens; the request comes from a
        // different replica, which shares only the database.
        let shutdown = CancellationToken::new();
        let running_replica = CancellationWatch::default();
        let waiter = running_replica.watch(id);
        waiter.notified().await;
        running_replica.spawn_listener(pool.clone(), shutdown.clone());
        // The listener wakes every run once it is listening.
        tokio::time::timeout(Duration::from_secs(10), waiter.notified())
            .await
            .expect("the listener starts");

        let requesting_replica = waygate_codemode::PgExecutionStore::new(pool.clone());
        waygate_codemode::ExecutionStore::request_cancellation(
            &requesting_replica,
            &tenant,
            "alice",
            "https://issuer.test",
            id,
        )
        .await
        .expect("request cancellation")
        .expect("execution exists");

        tokio::time::timeout(Duration::from_secs(10), waiter.notified())
            .await
            .expect("the running replica hears the cancellation");
        shutdown.cancel();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }
}
