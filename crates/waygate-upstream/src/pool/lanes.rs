//! Per-upstream lane-shape resolution: how many connection slots an
//! upstream gets and which session-isolation mode governs its calls. Both
//! derive purely from the manifest, so they live apart from the pool's
//! runtime state.

use super::*;

/// An upstream's connection slots and the queue for checking one out. There
/// is one permit per slot and only a checkout locks a slot's `in_use`. A call
/// that holds a permit without a slot never locks one, so a caller holding a
/// permit is owed a free slot. Permits are granted in request order, so a
/// waiting call takes whichever slot frees first.
pub(super) struct ConnectionSlots {
    slots: Vec<super::ConnectionSlot>,
    permits: tokio::sync::Semaphore,
    /// Whether every call holds a permit, so the slot count is the most calls
    /// in flight to this upstream. Otherwise only a call that needs a slot
    /// exclusively takes a permit, and one that finds none free runs on its
    /// own session instead of waiting.
    bounded: bool,
}

impl ConnectionSlots {
    pub(super) fn new(slots: Vec<super::ConnectionSlot>, bounded: bool) -> Self {
        let permits = tokio::sync::Semaphore::new(slots.len());
        Self {
            slots,
            permits,
            bounded,
        }
    }

    /// A slot for a call that only reads its connection: the first whose
    /// connection is live and not being replaced, else the first slot. Such a
    /// call holds the connection for reading, which a reconnect or re-dial
    /// must wait out before replacing it.
    fn shared(&self) -> &super::ConnectionSlot {
        self.slots
            .iter()
            .find(|slot| slot.conn.try_read().is_ok_and(|conn| conn.is_some()))
            .unwrap_or(&self.slots[0])
    }
}

/// Whether `manifest` limits the calls in flight to its upstream. A stdio
/// child process serves one call at a time. A network upstream is limited
/// only by an explicit `session.concurrency`, which also sets its slot count.
pub(super) fn calls_bounded(manifest: &UpstreamManifest) -> bool {
    match manifest.transport {
        Transport::Stdio => true,
        Transport::Http | Transport::Sse => manifest
            .session
            .as_ref()
            .is_some_and(|session| session.concurrency.is_some()),
    }
}

impl std::ops::Deref for ConnectionSlots {
    type Target = [super::ConnectionSlot];

    fn deref(&self) -> &Self::Target {
        &self.slots
    }
}

impl<'a> IntoIterator for &'a ConnectionSlots {
    type Item = &'a super::ConnectionSlot;
    type IntoIter = std::slice::Iter<'a, super::ConnectionSlot>;

    fn into_iter(self) -> Self::IntoIter {
        self.slots.iter()
    }
}

/// RAII handle to a checked-out [`super::ConnectionSlot`]. Holds the
/// slot's `in_use` lock for the duration of a call, so the slot's
/// connection and identity cell are this call's alone.
pub(super) struct SlotCheckout<'a> {
    pub(super) slot: &'a super::ConnectionSlot,
    pub(super) _guard: tokio::sync::MutexGuard<'a, ()>,
    /// Declared after the guard so the slot is free before the next waiter
    /// is admitted.
    _permit: tokio::sync::SemaphorePermit<'a>,
}

/// One admitted call's hold on its upstream for the dispatch.
pub(super) struct CallLane<'a> {
    /// The slot whose connection the call reads. A `Reuse` call runs on it
    /// and holds it exclusively; a `PerCall` call reads its tool view and
    /// negotiated protocol and dials its own session.
    pub(super) slot: &'a super::ConnectionSlot,
    /// The isolation the call runs under. A `Reuse` call that found every
    /// slot busy on an unbounded upstream runs `PerCall`.
    pub(super) isolation: SessionIsolation,
    /// Held by a call that runs on the slot's session.
    _checkout: Option<SlotCheckout<'a>>,
    /// Held by a call that shares the slot on a bounded upstream.
    _permit: Option<tokio::sync::SemaphorePermit<'a>>,
}

impl super::UpstreamPool {
    /// End every pooled upstream session and return how many lanes were open.
    ///
    /// A stateful upstream keeps a lane's session until the client deletes it
    /// or the upstream's own idle expiry ends it, and an upstream with a fixed
    /// session table refuses new sessions while it is full. A process that
    /// exits without closing its lanes leaves their sessions in that table, so
    /// the next gateway process can be refused until they expire. Closing a
    /// lane's client ends its session with the upstream.
    ///
    /// Every entry is retired, so the pool serves no upstream afterwards. Each
    /// entry's session guard is taken first: a reconnect or catalog refresh
    /// already dialing finishes installing its lanes and they are closed here,
    /// and one still waiting for the guard finds the entry retired and does not
    /// dial. Call this only once nothing can check out a lane.
    pub async fn close_sessions(&self) -> usize {
        let entries = self.entries.load_full();
        let closing = entries.iter().map(|(name, entry)| async move {
            let _session = entry.session_mutation.lock().await;
            entry.removed.store(true, Ordering::Release);
            let lanes = entry.slots.iter().map(|slot| async move {
                let connection = slot.conn.write().await.take()?;
                if let Err(error) = connection.client.cancel().await {
                    tracing::warn!(server = %name, %error, "upstream lane did not close cleanly");
                }
                Some(())
            });
            futures::future::join_all(lanes)
                .await
                .into_iter()
                .flatten()
                .count()
        });
        futures::future::join_all(closing).await.into_iter().sum()
    }

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
    pool_size: usize,
    dial_timeout: Duration,
) -> (ConnectionSlots, Option<health::UpstreamErrorClass>) {
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

    if connections.iter().any(Option::is_some) {
        let common_live_tools = {
            let catalogs: Vec<&[Tool]> = connections
                .iter()
                .filter_map(Option::as_ref)
                .map(|connection| connection.live_tools.as_slice())
                .collect();
            super::reload::common_tool_catalog(&catalogs, manifest.classification_mode)
        };
        let published_tools = publish_classified_tools(
            name,
            &manifest.tools,
            manifest.classification_mode,
            &common_live_tools,
            "boot",
        );
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

    let slots = connections
        .into_iter()
        .map(|connection| ConnectionSlot {
            conn: RwLock::new(connection),
            in_use: Mutex::new(()),
        })
        .collect();
    (
        ConnectionSlots::new(slots, calls_bounded(manifest)),
        last_error_class,
    )
}

impl super::UpstreamEntry {
    /// Waiting for capacity spends the same deadline as dispatch. Dropping
    /// admission releases any partially acquired permit or slot guard.
    pub(super) async fn admit_with_budget(
        &self,
        server: &str,
        isolation: SessionIsolation,
        deadline: Option<tokio::time::Instant>,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<CallLane<'_>, McpError> {
        let expires = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(McpError::internal_error(
                format!("upstream `{server}` call was cancelled while waiting for capacity"),
                Some(serde_json::json!({
                    "error": "upstream_call_cancelled", "phase": "pre_dispatch", "retryable": false,
                })),
            )),
            () = expires => Err(McpError::internal_error(
                format!("upstream `{server}` call timed out while waiting for capacity"),
                Some(serde_json::json!({
                    "error": "upstream_admission_timeout", "phase": "pre_dispatch", "retryable": true,
                })),
            )),
            lane = self.admit(isolation) => Ok(lane),
        }
    }

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

    /// Admit one call configured with `isolation`.
    ///
    /// A `PerCall` call dials its own session and only reads a slot's
    /// connection, so it shares a slot. A `Reuse` call runs on a slot's
    /// session, so it checks one out exclusively. On a bounded upstream (see
    /// [`calls_bounded`]) every call waits in request order for a permit,
    /// which caps the calls in flight. On an unbounded one nothing waits: a
    /// `Reuse` call that finds every slot busy runs on its own fresh session,
    /// which no other call or caller has used.
    pub(super) async fn admit(&self, isolation: SessionIsolation) -> CallLane<'_> {
        match isolation {
            SessionIsolation::Reuse => {
                let checkout = if self.slots.bounded {
                    Some(self.checkout().await)
                } else if let Ok(permit) = self.slots.permits.try_acquire() {
                    Some(self.claim_slot(permit).await)
                } else {
                    None
                };
                match checkout {
                    Some(checkout) => CallLane {
                        slot: checkout.slot,
                        isolation,
                        _checkout: Some(checkout),
                        _permit: None,
                    },
                    None => CallLane {
                        slot: self.slots.shared(),
                        isolation: SessionIsolation::PerCall,
                        _checkout: None,
                        _permit: None,
                    },
                }
            }
            SessionIsolation::PerCall => {
                let permit = if self.slots.bounded {
                    Some(
                        self.slots
                            .permits
                            .acquire()
                            .await
                            .expect("connection slot permits are never closed"),
                    )
                } else {
                    None
                };
                CallLane {
                    slot: self.slots.shared(),
                    isolation,
                    _checkout: None,
                    _permit: permit,
                }
            }
        }
    }

    /// Check out a connection slot for exclusive use. Waits for a permit,
    /// then prefers a free *connected* slot, then any free slot (the caller
    /// gets a not-connected error if it's down, which feeds the breaker and
    /// the re-probe heals it). The returned guard releases the slot on drop,
    /// so the slot's connection + identity cell are this call's alone for the
    /// dispatch.
    pub(super) async fn checkout(&self) -> SlotCheckout<'_> {
        let permit = self
            .slots
            .permits
            .acquire()
            .await
            .expect("connection slot permits are never closed");
        self.claim_slot(permit).await
    }

    /// Lock a free slot for the holder of `permit`, which is owed one.
    async fn claim_slot<'a>(
        &'a self,
        permit: tokio::sync::SemaphorePermit<'a>,
    ) -> SlotCheckout<'a> {
        loop {
            // Nothing in the scan waits. A busy slot is skipped before its
            // connection is read, since its call holds that lock for reading
            // and a queued reconnect writer would hold this read behind it.
            // Pass 1: free AND connected; a connection being replaced is
            // not known to be connected.
            for slot in &self.slots {
                if let Ok(guard) = slot.in_use.try_lock() {
                    if slot.conn.try_read().is_ok_and(|conn| conn.is_some()) {
                        return SlotCheckout {
                            slot,
                            _guard: guard,
                            _permit: permit,
                        };
                    }
                }
            }
            // Pass 2: any free slot (may be down).
            for slot in &self.slots {
                if let Ok(guard) = slot.in_use.try_lock() {
                    return SlotCheckout {
                        slot,
                        _guard: guard,
                        _permit: permit,
                    };
                }
            }
            // A slot is free at every instant, but one can be released behind
            // this scan while the slot ahead of it is taken; scan again.
            tokio::task::yield_now().await;
        }
    }
}

/// Connection-slot count for an upstream: stdio is always a single child
/// process; network transports get `pool_size` long-lived lanes, which
/// `Reuse` calls run on and `PerCall` calls read their tool view from.
///
/// A per-upstream `session.concurrency` replaces the global `pool_size`
/// (the `GATEWAY_UPSTREAM_POOL_SIZE`-derived default) for HTTP/SSE, and
/// [`calls_bounded`] makes it the most calls in flight to that upstream. It
/// is clamped to ≥ 1, so an explicit `concurrency: 0` still yields a single
/// live session rather than zero. Stdio ignores it entirely (a manifest
/// can't fan one child process into multiple sessions).
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
