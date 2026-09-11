//! Process-wide upstream tool-catalog change signaling.
//!
//! Each downstream MCP session subscribes when its `GatewayServer` is built.
//! Successful upstream publications advance the shared epoch; initialized
//! sessions then receive `notifications/tools/list_changed` and can refetch
//! the current catalog. A watch channel deliberately coalesces bursts because
//! the notification means "refetch current state", not "replay every change".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmcp::service::{Peer, RoleServer};
use tokio::sync::watch;

/// How often a dormant per-session watcher checks whether its transport has
/// closed. The catalog sender is process-wide and normally never closes, so a
/// bounded transport check prevents disconnected sessions from retaining a
/// watcher forever when no later catalog change occurs.
const SESSION_CLOSE_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Shared monotonic signal for changes to the downstream-visible tool catalog.
#[derive(Clone, Debug)]
pub struct ToolCatalogEpoch {
    sender: watch::Sender<u64>,
    active_changes: Arc<AtomicUsize>,
}

impl Default for ToolCatalogEpoch {
    fn default() -> Self {
        let (sender, receiver) = watch::channel(0);
        drop(receiver);
        Self {
            sender,
            active_changes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// A synchronous catalog publication in progress.
///
/// The guard must bracket only the non-awaiting state publication. Dropping it
/// without [`Self::commit`] cancels the publication marker without advancing
/// the externally visible generation.
#[must_use = "commit a successful catalog publication or drop the guard to cancel it"]
pub struct ToolCatalogChange<'a> {
    epoch: &'a ToolCatalogEpoch,
    finished: bool,
}

impl ToolCatalogChange<'_> {
    /// Publish the completed change and make stable readers retry.
    pub fn commit(mut self) {
        self.epoch.mark_changed();
        self.finish();
    }

    fn finish(&mut self) {
        self.epoch.active_changes.fetch_sub(1, Ordering::Release);
        self.finished = true;
    }
}

impl Drop for ToolCatalogChange<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.finish();
        }
    }
}

impl ToolCatalogEpoch {
    /// Create a catalog epoch at generation zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the epoch after a successful catalog publication.
    pub fn mark_changed(&self) {
        self.sender
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }

    /// Mark the start of a synchronous catalog publication.
    ///
    /// Readers refuse snapshots while any publication is active. Callers must
    /// not hold the returned guard across an `.await`; prepare slow work first,
    /// then bracket only the atomic serving-state mutation.
    pub fn begin_change(&self) -> ToolCatalogChange<'_> {
        self.active_changes.fetch_add(1, Ordering::AcqRel);
        ToolCatalogChange {
            epoch: self,
            finished: false,
        }
    }

    /// Start an optimistic read when no publication is currently active.
    pub fn stable_generation(&self) -> Option<u64> {
        if self.active_changes.load(Ordering::Acquire) != 0 {
            return None;
        }
        let generation = self.current();
        (self.active_changes.load(Ordering::Acquire) == 0).then_some(generation)
    }

    /// Return whether a read completed within one stable catalog generation.
    pub fn is_stable(&self, generation: u64) -> bool {
        if self.active_changes.load(Ordering::Acquire) != 0 {
            return false;
        }
        let unchanged = self.current() == generation;
        unchanged && self.active_changes.load(Ordering::Acquire) == 0
    }

    /// Subscribe at the current generation. Changes that happened before this
    /// call are the session's baseline and do not produce a notification.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.sender.subscribe()
    }

    /// Return the currently published generation.
    pub fn current(&self) -> u64 {
        *self.sender.borrow()
    }
}

pub(crate) fn spawn_tool_list_change_loop(
    mut receiver: watch::Receiver<u64>,
    peer: Peer<RoleServer>,
    notify_prompts: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut close_poll = tokio::time::interval(SESSION_CLOSE_POLL_INTERVAL);
        close_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = receiver.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    if let Err(error) = peer.notify_tool_list_changed().await {
                        tracing::debug!(%error, "tool catalog change watcher exiting: session closed");
                        return;
                    }
                    if notify_prompts && peer.notify_prompt_list_changed().await.is_err() {
                        return;
                    }
                }
                _ = close_poll.tick() => {
                    if peer.is_transport_closed() {
                        return;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriber_baseline_excludes_earlier_changes() {
        let epoch = ToolCatalogEpoch::new();
        assert_eq!(epoch.current(), 0);
        epoch.mark_changed();

        let receiver = epoch.subscribe();

        assert_eq!(*receiver.borrow(), 1);
        assert!(matches!(receiver.has_changed(), Ok(false)));
    }

    #[test]
    fn readers_reject_in_progress_and_completed_publications() {
        let epoch = ToolCatalogEpoch::new();
        let before = epoch.stable_generation().expect("initial state is stable");

        let change = epoch.begin_change();
        assert!(epoch.stable_generation().is_none());
        assert!(!epoch.is_stable(before));
        change.commit();

        assert!(!epoch.is_stable(before));
        assert_eq!(epoch.stable_generation(), Some(1));
    }

    #[test]
    fn cancelled_publication_does_not_notify_or_advance() {
        let epoch = ToolCatalogEpoch::new();
        let receiver = epoch.subscribe();

        drop(epoch.begin_change());

        assert_eq!(epoch.current(), 0);
        assert!(matches!(receiver.has_changed(), Ok(false)));
        assert_eq!(epoch.stable_generation(), Some(0));
    }

    #[tokio::test]
    async fn one_publication_wakes_every_subscriber() {
        let epoch = ToolCatalogEpoch::new();
        let mut first = epoch.subscribe();
        let mut second = epoch.subscribe();

        epoch.mark_changed();

        tokio::time::timeout(Duration::from_secs(1), first.changed())
            .await
            .expect("first subscriber wakes promptly")
            .expect("epoch sender remains live");
        tokio::time::timeout(Duration::from_secs(1), second.changed())
            .await
            .expect("second subscriber wakes promptly")
            .expect("epoch sender remains live");
        assert_eq!(*first.borrow(), 1);
        assert_eq!(*second.borrow(), 1);
        assert_eq!(epoch.current(), 1);

        epoch.mark_changed();
        tokio::time::timeout(Duration::from_secs(1), first.changed())
            .await
            .expect("subscriber wakes for a later generation")
            .expect("epoch sender remains live");
        assert_eq!(*first.borrow(), 2);
        assert_eq!(epoch.current(), 2);
    }
}
