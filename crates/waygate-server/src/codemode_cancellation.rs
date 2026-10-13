//! Wakes a running Code Mode program's cancellation check when a cancellation
//! for it commits, on whichever replica requested it, so running programs do
//! not have to poll their rows to notice one.
//!
//! The store announces a request for a run with a live claim on
//! [`waygate_codemode::CANCELLATION_CHANNEL`]. The fleet listener that already
//! serves configuration reloads routes each announcement to the matching
//! watch, and wakes every watch whenever it starts listening, in case an
//! announcement was missed. A woken run confirms the request with one narrow
//! read before acting on it, so a spurious wake costs only that read.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;
use uuid::Uuid;

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

    pub(crate) fn wake(&self, id: Uuid) {
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

    pub(crate) fn wake_all(&self) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
}
