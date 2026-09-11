//! Upstream `subscriptions/listen` fan-in (MCP 2026-07-28): one background
//! listener per eligible upstream consumes the upstream's
//! `tools/list_changed` stream and drives the ONE existing refresh path
//! ([`UpstreamPool::refresh_server_catalog`]) as push invalidation. Events
//! augment the SEP-2549 freshness schedule; they never replace it — a
//! silent or unsupported upstream keeps exactly the pre-listen behavior.
//!
//! Hazard contracts (from the adoption plan's review):
//!
//! - The listener owns its OWN connection with the catalog probe identity —
//!   pooled lanes' identity cells belong to caller dispatch, and sharing
//!   one would race caller identity.
//! - A healthy silent stream never returns from its receive, so lifecycle
//!   checks (hot remove, manifest change) run on a timer arm of the same
//!   `select!`, never between receives.
//! - The listener exits on the same manifest-shape changes that would
//!   redial the lanes, but the catalog refreshes its own events trigger
//!   change no connection shape — so it never cancels itself.
//! - Events are untrusted upstream input to a refresh path: their rate is
//!   bounded by `min_refresh_interval`, with one trailing refresh for a
//!   burst (coalesced, never dropped).

use std::sync::atomic::Ordering;
use std::time::Duration;

use rmcp::model::{ServerNotification, SubscriptionFilter};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use waygate_oidc::Principal;

use super::reload::redial_committed_fields_eq;
use super::session_identity::install_catalog_probe_identity;
use super::{dispatch, transport, IdentityCell, UpstreamPool};
use crate::{Transport, UpstreamProtocol};

/// How often a listener re-checks lifecycle conditions (hot remove,
/// manifest shape) and flushes a rate-bounded trailing refresh. A healthy
/// silent stream pends on its receive forever, so this arm is the only
/// place those checks are guaranteed to run.
const LIFECYCLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on `subscriptions/listen` establishment. The streaming HTTP
/// client deliberately has no total receive timeout (a healthy stream is
/// idle), so an upstream that accepts the connection but never
/// acknowledges the subscription would otherwise pin this task — and the
/// reconciler's view of it — forever, unobservable by shutdown or reloads.
const LISTEN_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// A finished listener: why it returned, and the manifest shape it
/// actually evaluated/dialed. The reconciler scopes its respawn cooldown
/// to `shape` — recording the shape at harvest time instead would let a
/// reload that lands between exit and harvest be mistaken for the
/// configuration that failed and be suppressed for the whole cooldown.
#[derive(Debug, Clone)]
pub struct CatalogListenerOutcome {
    pub exit: CatalogListenerExit,
    /// The manifest the listener ran against; `None` only when the server
    /// was unregistered before a snapshot existed.
    pub shape: Option<crate::UpstreamManifest>,
}

/// Why a catalog listener returned. The reconciler maps these to respawn
/// timing: `Removed` drops the server, `ManifestChanged` respawns
/// immediately (the shape it dialed no longer exists), the rest respawn
/// after a backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogListenerExit {
    /// The upstream cannot serve this listener: wrong transport/protocol
    /// configuration, no 2026 negotiation, a failed dial, or a
    /// `subscriptions/listen` the upstream refused or acknowledged without
    /// `tools/list_changed`.
    Unsupported,
    /// The stream ended (gracefully or abruptly) after being established.
    Ended,
    /// The upstream was hot-removed from the catalog.
    Removed,
    /// A reload committed a connection-shape change; the listener's dial
    /// no longer matches the manifest and a fresh listener should dial it.
    ManifestChanged,
    /// Gateway shutdown.
    Shutdown,
}

/// Whether two manifests share the connection shape a reload's redial
/// commits under — the reconciler's cooldown is scoped to this shape, so a
/// reload that changes it re-qualifies the server immediately instead of
/// waiting out a cooldown recorded against configuration that no longer
/// exists.
pub fn manifest_connection_shape_eq(
    a: &crate::UpstreamManifest,
    b: &crate::UpstreamManifest,
) -> bool {
    redial_committed_fields_eq(a, b)
}

impl UpstreamPool {
    /// The named upstream's current manifest snapshot, for the reconciler's
    /// shape-scoped cooldown. `None` when the server is unregistered or
    /// hot-removed.
    pub fn listener_manifest(&self, server: &str) -> Option<crate::UpstreamManifest> {
        let entries = self.entries.load();
        let entry = entries.get(server)?;
        if entry.removed.load(Ordering::Acquire) {
            return None;
        }
        Some(entry.manifest_snapshot())
    }

    /// Servers currently worth a catalog-change listener: registered, not
    /// removed, HTTP transport, a manifest that permits 2026-07-28, and at
    /// least one lane that actually negotiated it. The list is a candidate
    /// set for the reconciler — every condition is re-checked inside
    /// [`Self::run_catalog_listener`].
    pub async fn catalog_listener_candidates(&self) -> Vec<String> {
        let entries = self.entries.load();
        let mut candidates = Vec::new();
        for (name, entry) in entries.iter() {
            if entry.removed.load(Ordering::Acquire) {
                continue;
            }
            let manifest = entry.manifest_snapshot();
            if !matches!(manifest.transport, Transport::Http)
                || manifest.protocol == UpstreamProtocol::Legacy
            {
                continue;
            }
            let mut negotiated_2026 = false;
            for slot in &entry.slots {
                let guard = slot.conn.read().await;
                if guard.as_ref().is_some_and(|conn| {
                    conn.negotiated_protocol.as_deref().is_some_and(|version| {
                        version >= rmcp::model::ProtocolVersion::V_2026_07_28.as_str()
                    })
                }) {
                    negotiated_2026 = true;
                    break;
                }
            }
            if negotiated_2026 {
                candidates.push(name.clone());
            }
        }
        candidates
    }

    /// Run one upstream catalog listener to completion.
    ///
    /// `min_refresh_interval` bounds how often the upstream's events may
    /// drive a refresh; a burst inside the window coalesces into one
    /// trailing refresh at the next lifecycle tick. `actor` attributes every
    /// event-driven refresh in the audit trail.
    pub async fn run_catalog_listener(
        &self,
        server: &str,
        min_refresh_interval: Duration,
        actor: &Principal,
        shutdown: CancellationToken,
    ) -> CatalogListenerOutcome {
        let Some(entry) = self.entries.load().get(server).cloned() else {
            return CatalogListenerOutcome {
                exit: CatalogListenerExit::Removed,
                shape: None,
            };
        };
        let dialed_manifest = entry.manifest_snapshot();
        let outcome = |exit: CatalogListenerExit| CatalogListenerOutcome {
            exit,
            shape: Some(dialed_manifest.clone()),
        };
        if entry.removed.load(Ordering::Acquire) {
            return outcome(CatalogListenerExit::Removed);
        }
        if !matches!(dialed_manifest.transport, Transport::Http)
            || dialed_manifest.protocol == UpstreamProtocol::Legacy
        {
            return outcome(CatalogListenerExit::Unsupported);
        }

        // Own connection, own probe identity: the dial and the listen
        // request run under the verified group-less gateway identity (plus
        // any manifest catalog-probe groups), exactly like the boot
        // discovery dial — never a caller's identity. The dial is pinned to
        // the 2026 generation: a listener has no meaning on a legacy leg,
        // so an upstream that rolled back fails the dial loud instead of
        // holding a session channel open.
        let identity_cell = self.issuer.as_ref().map(|_| IdentityCell::new());
        let probe_guard = match install_catalog_probe_identity(
            &dialed_manifest,
            self.issuer.as_ref(),
            identity_cell.as_ref(),
        ) {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(%server, %error, "catalog listener probe identity unavailable");
                return outcome(CatalogListenerExit::Unsupported);
            }
        };
        let client = match transport::connect(
            &dispatch::pinned_2026_manifest(&dialed_manifest),
            self.issuer.as_ref(),
            identity_cell.as_ref(),
            self.exchange.as_ref(),
        )
        .await
        {
            Ok(client) => client,
            Err(error) => {
                tracing::debug!(%server, %error, "catalog listener dial failed");
                return outcome(CatalogListenerExit::Unsupported);
            }
        };
        let mut filter = SubscriptionFilter::new();
        filter.tools_list_changed = Some(true);
        // Establishment is bounded and shutdown-observable BEFORE the main
        // select exists: an upstream that accepts the connection but never
        // acknowledges must not pin this task.
        let establish = tokio::select! {
            _ = shutdown.cancelled() => return outcome(CatalogListenerExit::Shutdown),
            result = tokio::time::timeout(LISTEN_ESTABLISH_TIMEOUT, client.listen(filter)) => result,
        };
        let mut subscription = match establish {
            Ok(Ok(subscription)) => subscription,
            Ok(Err(error)) => {
                tracing::debug!(%server, %error, "upstream refused subscriptions/listen");
                return outcome(CatalogListenerExit::Unsupported);
            }
            Err(_) => {
                tracing::debug!(%server, "subscriptions/listen acknowledgment timed out");
                return outcome(CatalogListenerExit::Unsupported);
            }
        };
        if subscription.acknowledged().tools_list_changed != Some(true) {
            tracing::debug!(%server, "upstream acknowledged no tools/list_changed category");
            return outcome(CatalogListenerExit::Unsupported);
        }
        // Establishment is done; nothing else goes out on this connection,
        // so the probe identity is cleared now rather than lingering for
        // the listener's lifetime.
        drop(probe_guard);
        tracing::info!(%server, "upstream catalog listener established");

        let mut lifecycle = tokio::time::interval(LIFECYCLE_CHECK_INTERVAL);
        lifecycle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        lifecycle.tick().await;
        let mut last_refresh: Option<Instant> = None;
        let mut pending_refresh = false;
        loop {
            // One trailing refresh per bounded burst: an event that arrived
            // inside the window is flushed here once the window passes, so
            // the catalog converges to the upstream's final state even when
            // events stop.
            if pending_refresh
                && !last_refresh.is_some_and(|at| at.elapsed() < min_refresh_interval)
            {
                pending_refresh = false;
                last_refresh = Some(Instant::now());
                let report = self.refresh_server_catalog(server, actor).await;
                tracing::debug!(
                    %server,
                    refreshed = report.is_some(),
                    "event-driven catalog refresh"
                );
            }
            // Precise trailing flush: when an event was coalesced inside
            // the window, wake exactly when the window ends (the loop-top
            // flush then runs) instead of waiting for the lifecycle tick.
            let flush_at = last_refresh
                .map(|at| at + min_refresh_interval)
                .filter(|_| pending_refresh);
            tokio::select! {
                _ = shutdown.cancelled() => return outcome(CatalogListenerExit::Shutdown),
                _ = async {
                    match flush_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {}
                _ = lifecycle.tick() => {
                    let Some(entry_now) = self.entries.load().get(server).cloned() else {
                        return outcome(CatalogListenerExit::Removed);
                    };
                    if entry_now.removed.load(Ordering::Acquire) {
                        return outcome(CatalogListenerExit::Removed);
                    }
                    // The same connection-shape predicate a reload's redial
                    // commits under: catalog refreshes (including the ones
                    // this listener triggers) change none of these fields,
                    // so the listener never cancels itself.
                    if !redial_committed_fields_eq(&dialed_manifest, &entry_now.manifest_snapshot())
                    {
                        return outcome(CatalogListenerExit::ManifestChanged);
                    }
                }
                next = subscription.next() => match next {
                    Ok(Some(notification)) => {
                        if matches!(
                            notification,
                            ServerNotification::ToolListChangedNotification(_)
                        ) {
                            // Untrusted upstream hint: mark and let the
                            // rate-bounded flush above decide when it may
                            // drive the refresh path.
                            pending_refresh = true;
                        }
                    }
                    Ok(None) => return outcome(CatalogListenerExit::Ended),
                    Err(error) => {
                        tracing::debug!(%server, %error, "catalog listener stream error");
                        return outcome(CatalogListenerExit::Ended);
                    }
                },
            }
        }
    }
}
