//! Per-session record of tools revealed via `<server>.searchTools`.
//!
//! SEP #1888-aware clients invoke discovered tools directly — they do not
//! require the tool to appear in `tools/list` first. Stricter clients
//! (current Claude Code) refuse to call any tool that was not in the most
//! recent `tools/list` response. To keep both kinds of client working with
//! the same gateway we remember which fully-qualified tool names each
//! session has already discovered, add them to that session's `tools/list`
//! output, and emit `notifications/tools/list_changed` when the set grows.
//!
//! Nothing here bakes in authorization: callers re-check policy at list time
//! so a tool whose ACL changed after disclosure is not re-exposed. The
//! store below holds tool *names only*; `list_visible_tools` re-runs
//! profile, Cedar, and admission filters on every request, so a policy flip
//! after disclosure still hides the tool.
//!
//! Per-session `DisclosedTools` instances are created by the
//! [`StreamableHttpService`] factory and naturally dropped on disconnect; no
//! explicit eviction is needed. Stateless 2026-07-28 requests use a stable
//! full projection and never touch disclosure memory.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Shared, thread-safe record of tools that `searchTools` has disclosed to the
/// current session. Cloning a `DisclosedTools` hands back an `Arc`-equivalent
/// view so internal clones made by the rmcp runtime within a single session
/// share state; different sessions get different instances via the service
/// factory.
#[derive(Clone, Debug, Default)]
pub struct DisclosedTools {
    names: Arc<Mutex<NameRecord>>,
    pending_notify: Arc<AtomicBool>,
}

/// Insertion-ordered name set: the deque provides deterministic snapshot
/// order, and the set provides O(1) membership.
#[derive(Default, Debug)]
struct NameRecord {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl DisclosedTools {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record fully-qualified tool names (`<server>.<tool>`) as disclosed.
    /// If any name was newly added, arms the notify flag so the next call to
    /// [`Self::take_pending_notify`] returns `true` once.
    pub fn record<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut added = false;
        {
            let mut guard = self
                .names
                .lock()
                .expect("DisclosedTools mutex poisoned — a prior panic corrupted shared state");
            for name in names {
                let name: String = name.into();
                if guard.set.contains(&name) {
                    continue;
                }
                guard.set.insert(name.clone());
                guard.order.push_back(name);
                added = true;
            }
        }
        if added {
            self.pending_notify.store(true, Ordering::Release);
        }
    }

    /// Return a copy of every disclosed tool name, in disclosure order.
    pub fn snapshot(&self) -> Vec<String> {
        self.names
            .lock()
            .expect("DisclosedTools mutex poisoned")
            .order
            .iter()
            .cloned()
            .collect()
    }

    /// Atomically consume the "new disclosures to notify about" flag. The flag
    /// is single-shot: callers are expected to emit one
    /// `notifications/tools/list_changed` per `true` reading.
    pub fn take_pending_notify(&self) -> bool {
        self.pending_notify.swap(false, Ordering::AcqRel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_sets_pending_notify_only_on_new_names() {
        let d = DisclosedTools::new();
        d.record(["example-messages.send"]);
        assert!(d.take_pending_notify());
        assert!(!d.take_pending_notify());

        // Re-adding the same name must not re-arm the flag.
        d.record(["example-messages.send"]);
        assert!(!d.take_pending_notify());

        // Mixing known + new names arms it.
        d.record(["example-messages.send", "example-messages.list"]);
        assert!(d.take_pending_notify());
    }

    #[test]
    fn snapshot_returns_all_disclosed_names() {
        let d = DisclosedTools::new();
        d.record(["a.one", "a.two"]);
        d.record(["a.two", "b.three"]);
        let mut snap = d.snapshot();
        snap.sort();
        assert_eq!(snap, vec!["a.one", "a.two", "b.three"]);
    }

    #[test]
    fn clones_share_state() {
        let a = DisclosedTools::new();
        let b = a.clone();
        a.record(["x.y"]);
        assert_eq!(b.snapshot(), vec!["x.y".to_string()]);
        assert!(b.take_pending_notify());
        assert!(!a.take_pending_notify());
    }
}
