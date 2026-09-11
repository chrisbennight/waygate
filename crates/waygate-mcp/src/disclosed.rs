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
//! full projection and never touch disclosure memory. [`DisclosedStore`] is a
//! transitional, unwired remnant retained only until composition cleanup.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

/// Shared, thread-safe record of tools that `searchTools` has disclosed to the
/// current session. Cloning a `DisclosedTools` hands back an `Arc`-equivalent
/// view so internal clones made by the rmcp runtime within a single session
/// share state; different sessions get different instances via the service
/// factory.
#[derive(Clone, Debug)]
pub struct DisclosedTools {
    names: Arc<Mutex<NameRecord>>,
    pending_notify: Arc<AtomicBool>,
    /// Transitional broadcast twin of `pending_notify`, retained with the
    /// obsolete process-wide store until the compatibility cleanup removes
    /// it. The `AtomicBool` is the single-consumer flag the legacy session
    /// path consumes with `swap(false)`. Both are armed by the same
    /// `record()` sites; the watch coalesces bursts because the notification
    /// means "refetch current state".
    changes: Arc<watch::Sender<u64>>,
    /// Maximum number of remembered names. `None` for per-session records
    /// (dropped with the session); `Some` for store-held records, where the
    /// memory must be bounded because nothing drops it but TTL. At the cap
    /// the OLDEST disclosure is evicted in favour of the new one: a strict
    /// client acts on its recent `searchTools` results, so the recent
    /// working set must stay listable, and a long-evicted tool becomes
    /// listable again the moment any `searchTools` re-reveals it (which
    /// re-records it).
    capacity: Option<usize>,
    eviction_warned: Arc<AtomicBool>,
}

impl Default for DisclosedTools {
    fn default() -> Self {
        let (changes, receiver) = watch::channel(0);
        drop(receiver);
        Self {
            names: Arc::default(),
            pending_notify: Arc::default(),
            changes: Arc::new(changes),
            capacity: None,
            eviction_warned: Arc::default(),
        }
    }
}

/// Insertion-ordered name set: the deque provides eviction order (and a
/// deterministic snapshot order), the set provides O(1) membership.
#[derive(Default, Debug)]
struct NameRecord {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl DisclosedTools {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: Some(capacity),
            ..Self::default()
        }
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
        let mut evicted = false;
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
                if let Some(cap) = self.capacity {
                    while guard.order.len() >= cap {
                        if let Some(oldest) = guard.order.pop_front() {
                            guard.set.remove(&oldest);
                            evicted = true;
                        } else {
                            break;
                        }
                    }
                }
                guard.set.insert(name.clone());
                guard.order.push_back(name);
                added = true;
            }
        }
        if evicted && !self.eviction_warned.swap(true, Ordering::AcqRel) {
            tracing::warn!(
                "disclosure record reached its per-principal capacity; oldest \
                 disclosures are evicted first — a strict client can re-reveal \
                 an evicted tool with another searchTools call"
            );
        }
        if added {
            self.pending_notify.store(true, Ordering::Release);
            self.changes
                .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        }
    }

    /// Subscribe to this record's disclosure changes at the current
    /// generation (multi-subscriber; earlier disclosures are the baseline).
    /// Unlike [`Self::take_pending_notify`] this consumes nothing, so any
    /// number of `subscriptions/listen` streams for one principal can wake
    /// on the same record.
    pub fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Whether `other` is a view of the same underlying record. The bounded
    /// store REPLACES a principal's record on TTL expiry or eviction, so a
    /// long-lived subscriber must detect that its record is no longer the
    /// one new disclosures land in and re-subscribe to the replacement.
    pub fn same_record(&self, other: &DisclosedTools) -> bool {
        Arc::ptr_eq(&self.changes, &other.changes)
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

/// Former ceiling on distinct principals with live disclosure memory.
/// Reaching it evicts the least-recently-touched principal; reachable only by
/// authenticated principals, so the bound is a memory cap, not a DoS door.
pub const DISCLOSED_STORE_MAX_PRINCIPALS: usize = 10_000;

/// Former TTL for principal-keyed stateless disclosure memory.
pub const DISCLOSED_STORE_TTL: Duration = Duration::from_secs(30 * 60);

/// Ceiling on remembered names per principal (see
/// [`DisclosedTools::record`]'s overflow behaviour).
pub const MAX_DISCLOSED_PER_PRINCIPAL: usize = 2_000;

/// Identity the retained stateless store implementation keys by. The tenant
/// component is the isolation boundary the rest of the gateway enforces,
/// and the issuer component is mandatory because OAuth subject identifiers
/// are issuer-scoped: two accepted issuers may both mint `sub = "alice"`
/// for different people, and sharing disclosure memory across them would
/// expose one identity's discovery activity to the other. Never key by
/// bearer token (rotates) or transport.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct PrincipalKey {
    tenant: String,
    issuer: String,
    subject: String,
}

impl PrincipalKey {
    fn resolve(principal: Option<&waygate_oidc::Principal>) -> Self {
        match principal {
            Some(p) => Self {
                tenant: p.tenant.to_string(),
                issuer: p.issuer.clone(),
                subject: p.sub.clone(),
            },
            // Auth-disabled dev mode has one synthetic caller; a single
            // shared bucket matches how authorization treats it.
            None => Self {
                tenant: waygate_core::TenantId::DEFAULT.to_string(),
                issuer: String::new(),
                subject: "anonymous".to_string(),
            },
        }
    }
}

struct StoreEntry {
    tools: DisclosedTools,
    last_seen: Instant,
}

/// Retained implementation of the former process-wide, principal-keyed
/// stateless disclosure memory. No 2026 request uses it; legacy sessions keep
/// their independent per-session [`DisclosedTools`]. A follow-up removes this
/// dead compatibility surface after the stable projection has shipped.
#[derive(Default)]
pub struct DisclosedStore {
    inner: Mutex<HashMap<PrincipalKey, StoreEntry>>,
    max_principals: Option<usize>,
    ttl: Option<Duration>,
    per_principal_cap: Option<usize>,
}

impl DisclosedStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test seam: shrink the bounds without waiting on wall clock.
    #[cfg(test)]
    fn with_limits(max_principals: usize, ttl: Duration, per_principal_cap: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_principals: Some(max_principals),
            ttl: Some(ttl),
            per_principal_cap: Some(per_principal_cap),
        }
    }

    fn max_principals(&self) -> usize {
        self.max_principals
            .unwrap_or(DISCLOSED_STORE_MAX_PRINCIPALS)
    }

    fn ttl(&self) -> Duration {
        self.ttl.unwrap_or(DISCLOSED_STORE_TTL)
    }

    fn per_principal_cap(&self) -> usize {
        self.per_principal_cap
            .unwrap_or(MAX_DISCLOSED_PER_PRINCIPAL)
    }

    /// Fetch (creating if needed) the disclosure record for the request's
    /// principal, refreshing its TTL. Expired entries encountered on the
    /// way are dropped; at capacity, the least-recently-touched principal
    /// is evicted.
    pub fn for_principal(&self, principal: Option<&waygate_oidc::Principal>) -> DisclosedTools {
        let key = PrincipalKey::resolve(principal);
        let now = Instant::now();
        let ttl = self.ttl();
        let mut inner = self
            .inner
            .lock()
            .expect("DisclosedStore mutex poisoned — a prior panic corrupted shared state");

        // Reclamation is lazy by design: the touched key expires on access
        // (below) and capacity eviction reclaims the least-recently-seen
        // entry — expired or not — at the ceiling, so memory stays bounded
        // by `max_principals` without ever walking the map on the hot path.
        // (A filter-based sweep here would traverse until it *found*
        // expired entries, i.e. O(n) under the process-wide lock exactly
        // when nothing is expired.)
        if let Some(entry) = inner.get_mut(&key) {
            if now.duration_since(entry.last_seen) < ttl {
                entry.last_seen = now;
                return entry.tools.clone();
            }
            inner.remove(&key);
        }

        // Capacity eviction before insert: drop the least-recently-touched
        // principal. O(n) scan, paid only at the ceiling.
        if inner.len() >= self.max_principals() {
            if let Some(oldest) = inner
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| key.clone())
            {
                inner.remove(&oldest);
            }
        }

        let tools = DisclosedTools::with_capacity(self.per_principal_cap());
        inner.insert(
            key,
            StoreEntry {
                tools: tools.clone(),
                last_seen: now,
            },
        );
        tools
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    fn principal(tenant: &str, sub: &str) -> waygate_oidc::Principal {
        waygate_oidc::Principal {
            sub: sub.into(),
            email: None,
            groups: Vec::new(),
            issuer: "local-test".into(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::parse(tenant).expect("valid test tenant"),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: Vec::new(),
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn disclosure_persists_across_accesses_for_one_principal() {
        let store = DisclosedStore::new();
        let alice = principal("default", "alice");
        store
            .for_principal(Some(&alice))
            .record(["example-messages.send"]);
        assert_eq!(
            store.for_principal(Some(&alice)).snapshot(),
            vec!["example-messages.send".to_string()]
        );
    }

    #[test]
    fn issuers_are_isolated_for_the_same_tenant_and_subject() {
        // OAuth subjects are issuer-scoped: `sub = "alice"` from two
        // accepted issuers can be two different people, so their
        // disclosure memory must never merge.
        let store = DisclosedStore::new();
        let mut alice_a = principal("default", "alice");
        alice_a.issuer = "https://issuer-a.test".into();
        let mut alice_b = principal("default", "alice");
        alice_b.issuer = "https://issuer-b.test".into();
        store
            .for_principal(Some(&alice_a))
            .record(["example-messages.send"]);
        assert!(store.for_principal(Some(&alice_b)).snapshot().is_empty());
    }

    #[test]
    fn principals_and_tenants_are_isolated() {
        let store = DisclosedStore::new();
        let alice = principal("default", "alice");
        let bob = principal("default", "bob");
        let alice_other_tenant = principal("acme", "alice");
        store
            .for_principal(Some(&alice))
            .record(["example-messages.send"]);
        assert!(store.for_principal(Some(&bob)).snapshot().is_empty());
        assert!(store
            .for_principal(Some(&alice_other_tenant))
            .snapshot()
            .is_empty());
    }

    #[test]
    fn expired_entries_are_dropped_on_access() {
        let store = DisclosedStore::with_limits(16, Duration::ZERO, 16);
        let alice = principal("default", "alice");
        store
            .for_principal(Some(&alice))
            .record(["example-messages.send"]);
        // Zero TTL: the next access must see a fresh, empty record.
        assert!(store.for_principal(Some(&alice)).snapshot().is_empty());
    }

    #[test]
    fn capacity_evicts_the_least_recently_touched_principal() {
        let store = DisclosedStore::with_limits(2, Duration::from_secs(3600), 16);
        let a = principal("default", "a");
        let b = principal("default", "b");
        let c = principal("default", "c");
        store.for_principal(Some(&a)).record(["t.a"]);
        store.for_principal(Some(&b)).record(["t.b"]);
        // Touch `a` so `b` is the least-recently-seen when `c` arrives.
        let _ = store.for_principal(Some(&a));
        store.for_principal(Some(&c)).record(["t.c"]);
        assert_eq!(
            store.for_principal(Some(&a)).snapshot(),
            vec!["t.a".to_string()]
        );
        assert!(store.for_principal(Some(&b)).snapshot().is_empty());
    }

    #[test]
    fn per_principal_cap_evicts_oldest_disclosures_first() {
        let store = DisclosedStore::with_limits(16, Duration::from_secs(3600), 2);
        let alice = principal("default", "alice");
        let record = store.for_principal(Some(&alice));
        record.record(["a.one", "a.two", "a.three"]);
        // Newest-wins: the recent working set stays listable for strict
        // clients; the oldest name is what falls off.
        assert_eq!(
            record.snapshot(),
            vec!["a.two".to_string(), "a.three".to_string()],
            "cap must evict oldest-first and keep the record bounded"
        );
        // A re-reveal restores an evicted name.
        record.record(["a.one"]);
        assert_eq!(
            record.snapshot(),
            vec!["a.three".to_string(), "a.one".to_string()],
        );
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

    /// The root cause the subscription stream's periodic re-resolve exists
    /// for: a TTL replacement mints a NEW record with a NEW change channel,
    /// so a subscriber still watching the old record sleeps through every
    /// disclosure landing in the replacement. `same_record` is the
    /// detector; the new record's channel carries the new disclosures.
    #[tokio::test]
    async fn ttl_replacement_changes_record_identity_and_channel() {
        let store = DisclosedStore::with_limits(16, Duration::from_millis(10), 16);
        let stale = store.for_principal(None);
        let stale_changes = stale.subscribe_changes();

        std::thread::sleep(Duration::from_millis(25));
        let fresh = store.for_principal(None);
        assert!(
            !fresh.same_record(&stale),
            "TTL expiry must replace the record",
        );

        fresh.record(["demo.echo"]);
        assert!(
            matches!(stale_changes.has_changed(), Ok(false)),
            "the stale record's channel must not see the replacement's disclosures",
        );
        let mut fresh_changes = fresh.subscribe_changes();
        // Baseline excludes the earlier record() — record again and observe.
        fresh.record(["demo.other"]);
        tokio::time::timeout(Duration::from_secs(1), fresh_changes.changed())
            .await
            .expect("the replacement's channel wakes")
            .expect("sender alive");
    }
}
