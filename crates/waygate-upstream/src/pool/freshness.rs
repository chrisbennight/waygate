//! Catalog freshness: turning upstream `tools/list` `ttlMs` hints and the
//! operator's maximum catalog age into a refresh schedule.
//!
//! Each connection lane records the strictest `ttlMs` hint its dial-time
//! listing carried (`Connection::ttl_hint_ms`, anchored at
//! `Connection::dialed_at`). This module derives from those per-lane facts
//! the set of upstreams whose catalog is past due, for a periodic driver in
//! `waygate-server` that calls the one existing refresh path,
//! [`UpstreamPool::refresh_server_catalog`] — there is deliberately no
//! second refresh mechanism.
//!
//! Invariants:
//!
//! - **A hint can only shorten, never extend.** An absent hint uses the
//!   caller's ceiling as its fallback interval; a present hint is clamped
//!   between the caller's floor and ceiling, so a hostile `ttlMs: 1` cannot
//!   force a redial storm and a huge hint cannot postpone a refresh past the
//!   same maximum age.
//! - **The listing is only as fresh as its stalest lane.** Lanes may
//!   disagree during partial heals; the earliest deadline across connected
//!   lanes wins.
//! - **Down or tripped upstreams are not candidates.** A disconnected
//!   upstream is the reconnect scheduler's job (its next dial re-lists anyway),
//!   and an open breaker means the upstream needs recovery, not extra
//!   catalog traffic.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use waygate_oidc::Principal;

use super::{BreakerState, CatalogRefreshReport, UpstreamEntry, UpstreamPool};

/// Why a scheduled catalog refresh became due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogFreshnessTrigger {
    /// The upstream supplied a `ttlMs` hint whose clamped deadline expired.
    TtlHint,
    /// The upstream supplied no hint and reached the operator's maximum age.
    UnhintedFallback,
}

impl CatalogFreshnessTrigger {
    /// Stable low-cardinality value for logs and audit attribution.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TtlHint => "ttl_hint",
            Self::UnhintedFallback => "unhinted_fallback",
        }
    }
}

#[derive(Clone, Copy)]
struct CatalogFreshnessDeadline {
    at: Instant,
    trigger: CatalogFreshnessTrigger,
}

/// Outcome of one scheduled catalog refresh attempt.
#[derive(Debug)]
pub enum ScheduledCatalogRefresh {
    /// The upstream was still due and eligible under the session guard;
    /// the refresh ran and produced this report.
    Refreshed {
        report: CatalogRefreshReport,
        trigger: CatalogFreshnessTrigger,
    },
    /// Under the session guard the upstream was no longer due or eligible
    /// (re-anchored by a concurrent refresh, disconnected, breaker open,
    /// or tombstoned) — no refresh traffic was sent.
    NotDue,
    /// The server is not registered in the pool.
    Unknown,
}

impl UpstreamEntry {
    /// Earliest catalog-freshness deadline across this entry's connected
    /// lanes. A hinted lane uses its floor/ceiling-clamped hint; an unhinted
    /// lane uses the ceiling, so every connected catalog has a bounded age.
    async fn catalog_freshness_deadline(
        &self,
        floor: Duration,
        ceiling: Duration,
    ) -> Option<CatalogFreshnessDeadline> {
        let mut earliest: Option<CatalogFreshnessDeadline> = None;
        for slot in &self.slots {
            if let Some(conn) = slot.conn.read().await.as_ref() {
                let (effective_ttl, trigger) = match conn.ttl_hint_ms {
                    Some(ttl_ms) => (
                        Duration::from_millis(ttl_ms).clamp(floor, ceiling),
                        CatalogFreshnessTrigger::TtlHint,
                    ),
                    None => (ceiling, CatalogFreshnessTrigger::UnhintedFallback),
                };
                let ttl = if floor.is_zero() {
                    effective_ttl
                } else {
                    self.reconnect
                        .lock()
                        .expect("upstream reconnect lock poisoned")
                        .jitter_catalog_interval(floor, effective_ttl)
                };
                // Checked: a deadline beyond the platform's representable
                // Instant range can never arrive — treat the lane as
                // unscheduled rather than panicking the detached driver task
                // (whose JoinHandle nobody observes).
                let Some(at) = conn.dialed_at.checked_add(ttl) else {
                    continue;
                };
                let candidate = CatalogFreshnessDeadline { at, trigger };
                earliest = Some(match earliest {
                    Some(current)
                        if current.at < candidate.at
                            || (current.at == candidate.at
                                && current.trigger == CatalogFreshnessTrigger::TtlHint) =>
                    {
                        current
                    }
                    _ => candidate,
                });
            }
        }
        earliest
    }

    /// Whether this entry is a due refresh candidate under the shared
    /// eligibility rules: not tombstoned, breaker not open, and a
    /// connected lane's hinted or fallback deadline has passed.
    async fn catalog_refresh_trigger_if_due(
        &self,
        floor: Duration,
        ceiling: Duration,
        now: Instant,
    ) -> Option<CatalogFreshnessTrigger> {
        if self.removed.load(Ordering::Acquire) {
            return None;
        }
        if self.breaker.state() == BreakerState::Open {
            return None;
        }
        match self.catalog_freshness_deadline(floor, ceiling).await {
            Some(deadline) if deadline.at <= now => Some(deadline.trigger),
            Some(_) | None => None,
        }
    }
}

impl UpstreamPool {
    /// Names of upstreams whose freshest listing has aged past its clamped
    /// `ttlMs` hint or, without a hint, the ceiling as of `now`, sorted for
    /// deterministic iteration. Tombstoned entries, fully disconnected
    /// entries, and open-breaker entries are never returned.
    ///
    /// The caller (the `waygate-server` freshness task) is expected to run
    /// [`UpstreamPool::refresh_server_catalog`] for each returned name; a
    /// successful refresh re-dials every lane, which re-anchors the hint and
    /// moves the deadline forward. A failed refresh keeps the old catalog
    /// and the past-due deadline, so the next tick retries — bounded by the
    /// driver's tick cadence.
    pub async fn catalog_refresh_due(
        &self,
        floor: Duration,
        ceiling: Duration,
        now: Instant,
    ) -> Vec<String> {
        let map = self.entries.load_full();
        let mut due = Vec::new();
        for (name, entry) in map.iter() {
            if entry
                .catalog_refresh_trigger_if_due(floor, ceiling, now)
                .await
                .is_some()
            {
                due.push(name.clone());
            }
        }
        due.sort();
        due
    }

    /// Run one scheduled refresh with its eligibility precondition
    /// evaluated **under the entry's `session_mutation` guard** — the same
    /// guard the redial itself runs under. A queue built at tick time can
    /// take many refreshes' worth of time to drain, and a pre-check taken
    /// before the guard could go stale while an admin refresh or
    /// reconnect held it; checking under the guard closes that window, so
    /// an upstream that disconnected, tripped its breaker, was
    /// tombstoned, or was already re-anchored by a concurrent refresh
    /// receives no scheduled catalog traffic. (An eligibility change
    /// while the redial itself is in flight is inherent — the redial *is*
    /// the traffic — and a redial that succeeds has demonstrated the
    /// upstream healthy.) `now` is caller-supplied so the deadline rule
    /// stays deterministic under test.
    pub async fn scheduled_catalog_refresh(
        &self,
        server: &str,
        floor: Duration,
        ceiling: Duration,
        now: Instant,
        actor: &Principal,
    ) -> ScheduledCatalogRefresh {
        let Some(entry) = self.entries.load().get(server).cloned() else {
            return ScheduledCatalogRefresh::Unknown;
        };
        let session_guard = entry.session_mutation.lock().await;
        let Some(trigger) = entry
            .catalog_refresh_trigger_if_due(floor, ceiling, now)
            .await
        else {
            return ScheduledCatalogRefresh::NotDue;
        };
        match self
            .refresh_catalog_under_guard(server, &entry, session_guard, actor, Some(trigger))
            .await
        {
            Some(report) => ScheduledCatalogRefresh::Refreshed { report, trigger },
            None => ScheduledCatalogRefresh::Unknown,
        }
    }
}
