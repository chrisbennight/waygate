//! Per-upstream lane-shape resolution: how many connection slots an
//! upstream gets and which session-isolation mode governs its calls. Both
//! derive purely from the manifest, so they live apart from the pool's
//! runtime state.

use super::*;

/// RAII handle to a checked-out [`super::ConnectionSlot`]. Holds the
/// slot's `in_use` lock for the duration of a call, so the slot's
/// connection and identity cell are this call's alone.
pub(super) struct SlotCheckout<'a> {
    pub(super) slot: &'a super::ConnectionSlot,
    pub(super) _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl super::UpstreamPool {
    /// Mark a slot's connection down so the per-upstream scheduler
    /// re-dials it. Used by the dispatch error paths and the breaker-open
    /// recovery dial-failure path — a transport error or a failed re-dial
    /// means the slot's stored client is suspect, and leaving it as
    /// `Some` would keep routing traffic to a wedged lane while the
    /// shared breaker stays closed thanks to successes on other lanes.
    ///
    /// Republishes the protocol-generation gauge as part of the
    /// transition (liveness-guarded, so a retired entry cannot overwrite
    /// its successor's series): a lane that faults out of dispatch stops
    /// counting toward its generation immediately, instead of latching
    /// its last value until a successful re-probe — which a persistently
    /// down upstream never gets.
    pub(super) async fn mark_slot_down(
        &self,
        server: &str,
        entry: &std::sync::Arc<super::UpstreamEntry>,
        slot: &super::ConnectionSlot,
        error_class: super::health::UpstreamErrorClass,
    ) {
        {
            let mut g = slot.conn.write().await;
            *g = None;
        }
        entry.record_runtime_failure(error_class);
        self.arm_reconnect(server, entry).await;
        self.refresh_protocol_generation_gauge(server, entry).await;
    }

    /// Arm recovery only when `entry` is still the concrete registry identity
    /// that owns `server`'s schedule metrics. Same-name replacements leave the
    /// old entry alive while calls drain, so its removal flag alone is not a
    /// sufficient publication fence.
    pub(super) async fn arm_reconnect(
        &self,
        server: &str,
        entry: &std::sync::Arc<super::UpstreamEntry>,
    ) {
        let _structural_guard = self.reload_lock.lock().await;
        if entry.removed.load(Ordering::Acquire)
            || !self
                .entries
                .load()
                .get(server)
                .is_some_and(|current| std::sync::Arc::ptr_eq(current, entry))
        {
            return;
        }
        let mut state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        state.observe_runtime_failure();
        super::reconnect::publish_schedule(server, &state);
        drop(state);
        entry.reconnect_notify.notify_waiters();
    }
}

/// Dial a fresh pool of [`ConnectionSlot`]s for `manifest`. Each slot dials
/// independently. Once every boot dial has settled, the exact catalog common
/// to every connected lane is classified, published, and installed on each
/// lane. Failures remain empty and are healed by the per-upstream reconnect
/// scheduler.
pub(super) async fn dial_slots(
    name: &str,
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    exchange: Option<&ExchangeBundle>,
    index: Option<&SearchIndex>,
    pool_size: usize,
    dial_timeout: Duration,
) -> (Vec<ConnectionSlot>, Option<health::UpstreamErrorClass>) {
    let n = slot_count(manifest, pool_size);
    let mut connections = Vec::with_capacity(n);
    let mut last_error_class = None;
    for i in 0..n {
        let conn = match tokio::time::timeout(dial_timeout, dial(manifest, issuer, exchange)).await
        {
            Ok(Ok(connection)) => Some(connection),
            Ok(Err(error)) => {
                last_error_class = Some(health::UpstreamErrorClass::from_dial_error(&error));
                tracing::warn!(server = %name, slot = i, error = %error, "upstream connect failed");
                None
            }
            Err(_) => {
                last_error_class = Some(health::UpstreamErrorClass::Timeout);
                tracing::warn!(
                    server = %name,
                    slot = i,
                    timeout_s = dial_timeout.as_secs(),
                    "upstream boot dial timed out — marking it Disconnected and continuing boot; \
                     the reconnect scheduler will heal it. A hung upstream no longer deadlocks \
                     gateway startup.",
                );
                while connections.len() < n {
                    connections.push(None);
                }
                break;
            }
        };
        connections.push(conn);
    }

    if let Some(publish_index) = connections.iter().position(Option::is_some) {
        let common_live_tools = {
            let catalogs: Vec<&[Tool]> = connections
                .iter()
                .filter_map(Option::as_ref)
                .map(|connection| connection.live_tools.as_slice())
                .collect();
            super::reload::common_tool_catalog(&catalogs, manifest.classification_mode)
        };
        let publication = publish_classified_tools(
            name,
            &manifest.tools,
            manifest.classification_mode,
            &common_live_tools,
            "boot",
            |tools| {
                index
                    .map(|idx| idx.replace_server(name, tools))
                    .transpose()
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            },
        );
        match publication {
            Ok(published_tools) => {
                super::reload::synchronize_published_catalogs(
                    connections
                        .iter_mut()
                        .filter_map(Option::as_mut)
                        .map(|connection| &mut connection.tools),
                    &published_tools,
                );
                for connection in connections.iter_mut().filter_map(Option::as_mut) {
                    tool_listing::normalize_connection(name, connection);
                }
                if connections
                    .iter()
                    .filter_map(Option::as_ref)
                    .any(|connection| connection.live_tools != common_live_tools)
                {
                    tracing::warn!(
                        server = %name,
                        common_tools = common_live_tools.len(),
                        "boot lanes advertised different tool catalogs — publishing only their exact intersection",
                    );
                }
            }
            Err(error) => {
                last_error_class = Some(health::UpstreamErrorClass::Catalog);
                tracing::warn!(
                    server = %name,
                    slot = publish_index,
                    error = %error,
                    "search index populate failed — keeping upstream disconnected",
                );
                connections.fill_with(|| None);
            }
        }
    }

    let slots = connections
        .into_iter()
        .map(|connection| ConnectionSlot {
            conn: RwLock::new(connection),
            in_use: Mutex::new(()),
        })
        .collect();
    (slots, last_error_class)
}

impl super::UpstreamEntry {
    pub(super) fn record_runtime_failure(&self, error_class: super::health::UpstreamErrorClass) {
        self.recovery
            .write()
            .expect("upstream recovery lock poisoned")
            .record_failure(error_class);
    }

    pub(super) fn retire_reconnect(&self, server: &str) {
        let mut state = self
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        debug_assert!(self.removed.load(Ordering::Acquire));
        state.record_success(false);
        super::reconnect::publish_schedule(server, &state);
        drop(state);
        self.reconnect_notify.notify_waiters();
    }

    pub(super) fn manifest_snapshot(&self) -> crate::UpstreamManifest {
        self.manifest
            .read()
            .expect("manifest lock poisoned")
            .clone()
    }

    /// Check out a connection slot for exclusive use. Prefers a free
    /// *connected* slot (first pass), then any free slot (second pass —
    /// the caller gets a not-connected error if it's down, which feeds
    /// the breaker and the re-probe heals it), and finally waits on slot
    /// 0 if every slot is busy. The returned guard releases the slot on
    /// drop, so the slot's connection + identity cell are this call's
    /// alone for the dispatch.
    pub(super) async fn checkout(&self) -> SlotCheckout<'_> {
        // Pass 1: free AND connected.
        for slot in &self.slots {
            if let Ok(guard) = slot.in_use.try_lock() {
                if slot.conn.read().await.is_some() {
                    return SlotCheckout {
                        slot,
                        _guard: guard,
                    };
                }
                drop(guard); // free but down — keep looking
            }
        }
        // Pass 2: any free slot (may be down).
        for slot in &self.slots {
            if let Ok(guard) = slot.in_use.try_lock() {
                return SlotCheckout {
                    slot,
                    _guard: guard,
                };
            }
        }
        // All busy — queue behind slot 0. (Per-waiter round-robin
        // fairness isn't worth the complexity; under sustained
        // saturation every lane is equally hot.)
        let slot = &self.slots[0];
        let guard = slot.in_use.lock().await;
        SlotCheckout {
            slot,
            _guard: guard,
        }
    }
}

/// Connection-slot count for an upstream: stdio is always a single child
/// process; network transports get `pool_size` lanes so concurrent calls
/// to one upstream parallelize.
///
/// A per-upstream `session.concurrency` overrides the global `pool_size`
/// (the `GATEWAY_UPSTREAM_POOL_SIZE`-derived default) for HTTP/SSE — both
/// directions: raise it for a hot upstream, or lower it (e.g. `1`) to
/// throttle concurrent load onto a weak one. The override is clamped to
/// ≥ 1, so an explicit `concurrency: 0` still yields a single live
/// session rather than zero. Stdio ignores it entirely (a manifest can't
/// fan one child process into multiple sessions).
pub(super) fn slot_count(manifest: &UpstreamManifest, pool_size: usize) -> usize {
    match manifest.transport {
        Transport::Stdio => 1,
        Transport::Http | Transport::Sse => manifest
            .session
            .as_ref()
            .and_then(|s| s.concurrency)
            .unwrap_or(pool_size)
            .max(1),
    }
}

/// Resolve the session-isolation mode for an upstream.
///
/// The safe default is paranoid: HTTP/SSE upstreams default to
/// [`SessionIsolation::PerCall`] (a fresh upstream session per call, so no
/// cross-call or cross-principal state can leak through a reused session —
/// behavior MCP does not guarantee), and only reuse when the operator
/// explicitly opts in. stdio is **forced** to [`SessionIsolation::Reuse`]
/// regardless of the manifest: a child process is a single long-lived
/// session, and "per-call" would mean respawning the process on every
/// call. Mirrors `slot_count`'s stdio clamp.
/// The session isolation that actually governs this upstream: the manifest's
/// `session.isolation` for HTTP/SSE (defaulting to the paranoid
/// [`SessionIsolation::PerCall`]), and always [`SessionIsolation::Reuse`] for
/// stdio (a child process is one long-lived session). Exposed `pub` so the
/// admin dashboard's read-only server Overview can show the *resolved* value
/// without re-deriving — and drifting from — this defaulting rule.
pub fn resolve_isolation(manifest: &UpstreamManifest) -> SessionIsolation {
    match manifest.transport {
        Transport::Stdio => SessionIsolation::Reuse,
        Transport::Http | Transport::Sse => manifest
            .session
            .as_ref()
            .and_then(|s| s.isolation)
            .unwrap_or(SessionIsolation::PerCall),
    }
}
