//! Health/breaker/quarantine read surface for the pool — split out of
//! `pool/mod.rs`. Child module of [`super`], so no visibility changes.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Operator-facing availability state derived from the same lane and breaker
/// snapshot used for dispatch health. This is deliberately separate from the
/// durable catalog lifecycle (`live`, `quarantined`, and so on): a catalog-live
/// server can still be runtime-disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamRuntimeState {
    /// Every configured lane is connected and the circuit breaker is closed.
    Connected,
    /// Some capacity remains, but lanes are missing or the breaker is not
    /// closed. Operators should investigate without treating the transport as
    /// wholly absent.
    Degraded,
    /// No configured lane currently holds a connection, or the open circuit
    /// breaker makes retained sessions unavailable to dispatch.
    Disconnected,
}

impl UpstreamRuntimeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Degraded => "degraded",
            Self::Disconnected => "disconnected",
        }
    }
}

/// Stable, bounded classification of the most recent runtime failure. Raw
/// transport errors remain in protected logs/audit; operator APIs expose only
/// this closed vocabulary so credentials, private headers, and unbounded error
/// chains cannot cross the health boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamErrorClass {
    Authentication,
    Catalog,
    Configuration,
    Dns,
    Protocol,
    Timeout,
    Transport,
}

impl UpstreamErrorClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Catalog => "catalog",
            Self::Configuration => "configuration",
            Self::Dns => "dns",
            Self::Protocol => "protocol",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
        }
    }

    pub(super) fn from_dial_error(error: &DialError) -> Self {
        match error {
            DialError::ResolveNetwork { .. } | DialError::NoNetworkAddresses { .. } => Self::Dns,
            DialError::HandshakeTimeout(_) => Self::Timeout,
            DialError::MissingAuthEnv { .. }
            | DialError::AuthFileRead { .. }
            | DialError::AuthFileTooLarge { .. }
            | DialError::AuthFileNotRegular { .. }
            | DialError::AuthFileInvalidUtf8 { .. }
            | DialError::AuthFileEmpty { .. }
            | DialError::EmptyAuth
            | DialError::MtlsReadFailed { .. }
            | DialError::MtlsFileNotRegular { .. }
            | DialError::MtlsFileTooLarge { .. }
            | DialError::MtlsInvalidPem { .. } => Self::Authentication,
            DialError::Init(_) | DialError::ListTools(_) => Self::Protocol,
            DialError::Connect(_) | DialError::Spawn(_) => Self::Transport,
            DialError::MissingUrl
            | DialError::InvalidNetworkUrl { .. }
            | DialError::MissingCommand
            | DialError::UnsupportedAuthForTransport { .. }
            | DialError::CatalogProbeGroupsRequireIdentity { .. }
            | DialError::CatalogProbeGroupsRequirePerCall { .. }
            | DialError::MtlsMissingField
            | DialError::MtlsUnsupportedForTransport { .. }
            | DialError::MtlsClientBuild(_)
            | DialError::HttpClientBuild(_)
            | DialError::MtlsRequiresHttps { .. } => Self::Configuration,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct UpstreamRecovery {
    last_success_at: Option<time::OffsetDateTime>,
    last_error_class: Option<UpstreamErrorClass>,
}

impl UpstreamRecovery {
    pub(super) fn after_boot(
        connected_lanes: usize,
        total_lanes: usize,
        last_error_class: Option<UpstreamErrorClass>,
    ) -> Self {
        Self {
            last_success_at: (connected_lanes > 0).then(time::OffsetDateTime::now_utc),
            last_error_class: if connected_lanes == total_lanes {
                None
            } else {
                last_error_class
            },
        }
    }

    pub(super) fn record_reconnect(
        &mut self,
        connected_lanes: usize,
        total_lanes: usize,
        last_error_class: Option<UpstreamErrorClass>,
    ) {
        if connected_lanes > 0 {
            self.last_success_at = Some(time::OffsetDateTime::now_utc());
        }
        self.last_error_class = if connected_lanes == total_lanes {
            None
        } else {
            last_error_class.or(self.last_error_class)
        };
    }

    pub(super) fn record_failure(&mut self, error_class: UpstreamErrorClass) {
        self.last_error_class = Some(error_class);
    }

    pub(super) fn snapshot(&self) -> (Option<time::OffsetDateTime>, Option<UpstreamErrorClass>) {
        (self.last_success_at, self.last_error_class)
    }
}

/// Per-server health snapshot consumed by `/readyz` and the admin overview.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UpstreamHealth {
    pub name: String,
    /// Authoritative operator-facing runtime state. Consumers should render
    /// this rather than independently interpreting lane and breaker fields.
    pub runtime_state: UpstreamRuntimeState,
    /// Most recent successful connection/catalog handshake on any lane.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_success_at: Option<time::OffsetDateTime>,
    /// Bounded classification only; raw upstream errors never enter this
    /// operator-facing snapshot.
    pub last_error_class: Option<UpstreamErrorClass>,
    /// This upstream's independently-jittered next reconnect deadline.
    /// Absent while no recovery is scheduled.
    #[serde(with = "time::serde::rfc3339::option")]
    pub next_retry_at: Option<time::OffsetDateTime>,
    /// Compatibility transport signal: true when at least one lane is
    /// connected. It does not imply full capacity or a closed breaker; use
    /// [`Self::runtime_state`] for the complete availability state.
    pub connected: bool,
    /// Stringified for JSON — enum layout is a private concern of this crate.
    #[serde(serialize_with = "serialize_breaker_state")]
    pub breaker: BreakerState,
    /// Reusable MCP session slots that currently hold a connection.
    pub connected_lanes: usize,
    /// Configured reusable session lanes for this upstream.
    pub total_lanes: usize,
    /// Manifest-classified tools currently published to clients after the
    /// multi-lane catalog intersection and drift quarantine are applied.
    pub published_tool_count: usize,
    /// Tools currently blocked by mode-specific contract-drift quarantine.
    pub quarantined_tool_count: usize,
    /// Tools published WITHOUT the output schema this upstream advertised,
    /// because that schema's root was not `type: "object"`. The tools are
    /// still callable; the upstream is emitting definitions a strict MCP
    /// client would reject the whole catalog over. Non-zero is an operator
    /// signal to fix the upstream, not a gateway fault.
    pub rejected_output_schema_count: usize,
    /// Distinct MCP protocol generations negotiated by this upstream's
    /// connected lanes, sorted. Usually one entry; two while a partial
    /// heal straddles the upstream's own migration; empty when every lane
    /// is down. The fleet-migration view an operator reads before the
    /// legacy-removal decision.
    pub protocol_versions: Vec<String>,
}

/// What an upstream is publishing with a refused output schema, taken under
/// the lane guards, together with whether that view carries any information
/// about publication at all.
pub(super) struct ServedRefusals {
    /// Refusals currently published by at least one connected lane.
    pub(super) served: Vec<super::tool_listing::RejectedOutputSchema>,
    /// Whether any lane held a connection when this was taken.
    ///
    /// An entry with every lane down publishes nothing, but that silence is
    /// the transport being gone rather than a decision to withhold the tool.
    /// Recording it as the refusal having STOPPED would make a transport blip
    /// end the serving interval, so a reconnect would report the same
    /// unchanged refusal again — and only when a refresh happened to land
    /// during the outage, making the audit trail depend on unrelated timing.
    /// The refusal record therefore ignores a view taken with no live lane;
    /// the current-state gauge still follows reachability.
    pub(super) live: bool,
}

/// One registry-generation view of an upstream's manifest metadata and
/// runtime health. Admin surfaces consume this instead of joining separate
/// manifest and health reads across a possible structural reload.
#[derive(Debug, Clone)]
pub struct UpstreamStatus {
    pub manifest: UpstreamManifest,
    pub health: UpstreamHealth,
}

fn serialize_breaker_state<S: serde::Serializer>(
    s: &BreakerState,
    ser: S,
) -> Result<S::Ok, S::Error> {
    ser.serialize_str(s.as_str())
}

fn runtime_state(
    connected_lanes: usize,
    total_lanes: usize,
    breaker: BreakerState,
) -> UpstreamRuntimeState {
    if connected_lanes == 0 || breaker == BreakerState::Open {
        UpstreamRuntimeState::Disconnected
    } else if connected_lanes < total_lanes || breaker != BreakerState::Closed {
        UpstreamRuntimeState::Degraded
    } else {
        UpstreamRuntimeState::Connected
    }
}

impl UpstreamPool {
    /// Expose the manifest list (used by the admin API).
    pub fn manifests(&self) -> Vec<UpstreamManifest> {
        self.entries
            .load()
            .values()
            .map(|e| e.manifest_snapshot())
            .collect()
    }

    /// Return the currently-quarantined tool names for
    /// `server`, sorted, or `None` if the upstream is unknown. Used by
    /// the admin API to show operators which tools are being refused at
    /// dispatch and why (paired with structured drift logs).
    pub async fn quarantined_tools(&self, server: &str) -> Option<Vec<String>> {
        let entry = self.entries.load().get(server).cloned()?;
        let q = entry
            .quarantined
            .read()
            .expect("upstream quarantine lock poisoned");
        let mut out: Vec<String> = q.iter().cloned().collect();
        out.sort();
        Some(out)
    }

    /// Clear process-local quarantines and return the count released. Durable
    /// contract reviews remain blocked until their exact replacement is accepted.
    /// Returns `None` if the upstream is unknown or durable state cannot be read.
    /// The schema baseline is retained and the gauge reflects remaining blocks.
    pub async fn clear_quarantine(&self, server: &str) -> Option<usize> {
        let entry = self.entries.load().get(server).cloned()?;
        let durable = match self.tool_reviews.as_ref() {
            Some(store) => match store
                .quarantined_names(waygate_core::TenantId::DEFAULT, server)
                .await
            {
                Ok(names) => names,
                Err(_) => return None,
            },
            None => Vec::new(),
        };
        // Scoped so the guards are provably released before the republish
        // below awaits — a blocking lock must not straddle a suspension.
        // Lanes then quarantine, the order every refusal path uses.
        let (count, at, served, catalog_change, remaining) = {
            let mut lanes = Vec::with_capacity(entry.slots.len());
            for slot in &entry.slots {
                lanes.push(slot.conn.read().await);
            }
            let mut q = entry
                .quarantined
                .write()
                .expect("upstream quarantine lock poisoned");
            let before = q.len();
            q.retain(|name| durable.contains(name));
            q.extend(durable.iter().cloned());
            let count = before.saturating_sub(q.len());
            let catalog_change = (count > 0).then(|| self.tool_catalog_epoch.begin_change());
            // Sampled while the release is still guaranteed to be what is
            // served. Sampling after the guards drop would let a concurrent
            // reload withhold the tool again in the gap, and the interval in
            // which clients could see it would go unrecorded.
            // Stamped here, under the guards that make the release visible.
            let at = self.audited_refusals.observe();
            let served = rejected_union(&lanes, &q);
            (count, at, served, catalog_change, q.len())
        };
        waygate_telemetry::metrics::set_tool_quarantined(server, remaining as i64);
        if count > 0 {
            catalog_change
                .expect("non-empty quarantine starts a catalog publication")
                .commit();
            // Un-quarantining can put a refused tool back into the served set,
            // which starts serving it without an output contract — the row
            // says so, and the refresh brings the gauge to current state.
            self.record_new_refusals(server, &entry, at, &served).await;
            self.refresh_rejected_output_schemas(server).await;
        }
        Some(count)
    }

    /// `true` iff we currently hold a live rmcp session for this upstream.
    /// Used by the admin dashboard overview to show ok/down without a live
    /// ping — the stored `Connection` is the authoritative health signal.
    pub async fn is_connected(&self, server: &str) -> bool {
        // `let-else` drops the load() guard at the statement end (before the
        // await), and `cloned()` hands back an owned `Arc` — so unlike `if let`
        // this never holds the guard across the suspension point.
        let Some(entry) = self.entries.load().get(server).cloned() else {
            return false;
        };
        entry.any_connected().await
    }

    /// Current breaker state for a server, or `None` if the server is unknown.
    /// Fed into `/readyz` — an `Open` breaker means the upstream is down.
    pub fn breaker_state(&self, server: &str) -> Option<BreakerState> {
        self.entries.load().get(server).map(|e| e.breaker.state())
    }

    /// Snapshot manifest metadata and runtime health from one loaded registry
    /// generation. Stable ordering (alphabetical by name) keeps REST,
    /// dashboard, and readiness output diff-able.
    pub async fn status_snapshot(&self) -> Vec<UpstreamStatus> {
        // Snapshot the map once (owned `Arc<HashMap>`) so the borrowed `&String`
        // keys and `&Arc` values stay valid across the per-entry awaits below.
        let map = self.entries.load_full();
        let mut names: Vec<&String> = map.keys().collect();
        names.sort();
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let entry = &map[name];
            // Retain every lane read guard until the snapshot is assembled.
            // Refresh/reconnect commits require every write lock in the same
            // slot order, so the counts and representative published catalog
            // cannot straddle two catalog generations.
            let mut guards = Vec::with_capacity(entry.slots.len());
            for slot in &entry.slots {
                guards.push(slot.conn.read().await);
            }
            let connected_lanes = guards.iter().filter(|guard| guard.is_some()).count();
            // Match the write-side order exactly: slots -> manifest ->
            // quarantine. A redial publishes classifications and may update
            // quarantine while holding the manifest write guard, so taking
            // quarantine first here would create a lock cycle.
            let manifest = entry.manifest.read().expect("manifest lock poisoned");
            let quarantined = entry
                .quarantined
                .read()
                .expect("upstream quarantine lock poisoned");
            let published_tool_count = guards
                .iter()
                .find_map(|guard| guard.as_ref())
                .map(|conn| {
                    conn.tools
                        .iter()
                        .filter(|tool| !quarantined.contains(tool.name.as_ref()))
                        .count()
                })
                .unwrap_or_default();
            // Union across every connected lane, NOT the first lane's set.
            // A partial heal re-dials only the down lanes, and lanes are
            // allowed to diverge, so if the upstream started or stopped
            // advertising a malformed schema between dials the lanes hold
            // different sets. Reading one lane could then under-report a
            // live refusal — and silently under-reporting is the one
            // failure mode this whole surface exists to prevent.
            let rejected_output_schema_count = rejected_union(&guards, &quarantined).served.len();
            let mut protocol_versions: Vec<String> = guards
                .iter()
                .filter_map(|guard| guard.as_ref())
                .filter_map(|conn| conn.negotiated_protocol.clone())
                .collect();
            protocol_versions.sort();
            protocol_versions.dedup();
            let breaker = entry.breaker.state();
            let state = runtime_state(connected_lanes, guards.len(), breaker);
            let (last_success_at, last_error_class) = entry
                .recovery
                .read()
                .expect("upstream recovery lock poisoned")
                .snapshot();
            let next_retry_at = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .snapshot()
                .1;
            let health = UpstreamHealth {
                name: name.clone(),
                runtime_state: state,
                last_success_at,
                last_error_class,
                next_retry_at,
                connected: connected_lanes > 0,
                breaker,
                connected_lanes,
                total_lanes: guards.len(),
                published_tool_count,
                quarantined_tool_count: quarantined.len(),
                rejected_output_schema_count,
                protocol_versions,
            };
            out.push(UpstreamStatus {
                manifest: manifest.clone(),
                health,
            });
        }
        out
    }

    /// Runtime-only projection used by `/readyz` and health callers. See
    /// [`Self::status_snapshot`] for the atomic metadata pairing.
    pub async fn health_snapshot(&self) -> Vec<UpstreamHealth> {
        self.status_snapshot()
            .await
            .into_iter()
            .map(|status| status.health)
            .collect()
    }

    /// `UpstreamHealth`-category audit emission for reconnect outcomes.
    /// `record_best_effort` matches the gateway-wide posture: a botched
    /// audit write must not block a recovery that just succeeded.
    /// No-op when `self.evidence` is `None` (test pools, the
    /// disconnected fixture).
    pub(super) async fn record_upstream_health(
        &self,
        action: &'static str,
        outcome: waygate_mcp::AuditOutcome,
        reason: String,
    ) {
        let Some(evidence) = self.evidence.as_ref() else {
            return;
        };
        evidence
            .record_best_effort(
                waygate_mcp::AuditEvent::new(action, outcome)
                    .with_category(waygate_mcp::EvidenceCategory::UpstreamHealth)
                    .with_reason(reason),
            )
            .await;
    }

    /// Whether `entry` is still the registry's live entry for `name` — not
    /// tombstoned, and not superseded by a replacement under the same key.
    fn is_published_entry(&self, name: &str, entry: &Arc<UpstreamEntry>) -> bool {
        if entry.removed.load(Ordering::Acquire) {
            return false;
        }
        self.entries
            .load()
            .get(name)
            .is_some_and(|live| Arc::ptr_eq(live, entry))
    }

    /// Record what the BOOT dials refused, now that there is a sink. Rows
    /// ONLY — the boot gauge is published synchronously by `connect_inner`
    /// before the registry is shared, so nothing detached ever writes the
    /// gauge and a stale snapshot cannot clobber a newer value. An audit
    /// row is an event record rather than current state, so a slightly
    /// late one is harmless. Detached because attaching a recorder must not
    /// become an await point, and a failed audit write must never hold up
    /// boot.
    pub(super) fn spawn_boot_rejected_output_schema_publish(&self) {
        let Some(evidence) = self.evidence.clone() else {
            return;
        };
        // The LIVE registry, not a snapshot of it: this task can be scheduled
        // after a resize has already replaced an entry it would otherwise
        // report from, and the replacement reports for itself. It samples what
        // is served when it runs rather than what boot dialed, so a refusal
        // that boot saw and a re-dial cleared before this task acquires the
        // lane guards goes unreported — a window that has already closed, on
        // the one path that cannot sample under the guards that opened it,
        // because the recorder does not exist until after boot.
        tokio::spawn(emit_rejected_output_schema_rows(
            Arc::clone(&self.entries),
            Arc::clone(&self.audited_refusals),
            evidence,
            None,
        ));
    }
}

/// Publish the refusal gauge for every entry in `map`.
///
/// Callers must hold a registry view that cannot be superseded before the
/// write — either the pre-publication boot map, or a live load performed
/// inside the same install path. Nothing detached calls this.
pub(super) async fn set_rejected_gauges(map: &HashMap<String, Arc<UpstreamEntry>>) {
    for (name, entry) in map {
        let count = union_for(entry).await.len();
        waygate_telemetry::metrics::set_rejected_output_schemas(name, count as i64);
        // Published here too, not only on the runtime refresh path: an
        // upstream already serving a root union at startup would otherwise
        // have no series at all until something forced a re-dial, leaving the
        // steady state — the state an operator alerts on — silent.
        waygate_telemetry::metrics::set_unregisterable_input_schemas(
            name,
            unregisterable_union(entry).await,
        );
        set_protocol_generation_gauge(name, entry).await;
    }
}

/// Publish `gateway_upstream_protocol_generation{server, generation}` from
/// `entry`'s live lanes, WITHOUT a registry-liveness check. Only for the
/// boot path (the pre-publication map has no registry to check — the same
/// exemption `set_rejected_gauges` documents). Every runtime transition
/// goes through [`UpstreamPool::refresh_protocol_generation_gauge`], which
/// refuses to let a retired entry overwrite the live one's series.
///
/// Every label in the closed generation set is written on every call, so a
/// migration zeroes the departed generation's series instead of latching
/// it. Version strings outside the served set collapse to `other` — the
/// label vocabulary is gateway-owned, never upstream-supplied.
pub(super) async fn set_protocol_generation_gauge(name: &str, entry: &Arc<UpstreamEntry>) {
    let mut counts: Vec<(&str, i64)> = waygate_telemetry::metrics::UPSTREAM_PROTOCOL_GENERATIONS
        .iter()
        .map(|generation| (*generation, 0i64))
        .collect();
    for slot in &entry.slots {
        if let Some(conn) = slot.conn.read().await.as_ref() {
            let Some(negotiated) = conn.negotiated_protocol.as_deref() else {
                continue;
            };
            let label = counts
                .iter_mut()
                .find(|(generation, _)| *generation == negotiated)
                .map(|entry| &mut entry.1);
            match label {
                Some(lanes) => *lanes += 1,
                None => {
                    if let Some((_, lanes)) = counts
                        .iter_mut()
                        .find(|(generation, _)| *generation == "other")
                    {
                        *lanes += 1;
                    }
                }
            }
        }
    }
    waygate_telemetry::metrics::set_upstream_protocol_generations(name, &counts);
}

impl UpstreamPool {
    /// Runtime republication of the protocol-generation gauge: count the
    /// entry's lanes, then re-check that `entry` is still the registry's
    /// live entry before writing — a retired entry sampled just before a
    /// structural replacement or removal must not overwrite the successor's
    /// counts (or the removal's zeroes). Same check-after-the-lane-locks
    /// shape as `refresh_rejected_output_schemas`, except that this gauge's
    /// writers are fully serialized: `protocol_gauge_publish` (below) is a
    /// total order over every publisher and the removal-zero path, so the
    /// last writer always sampled last and no interleave or stale-last-write
    /// window exists.
    /// Zero every generation label for a removed server, under the same
    /// total-order lock as the entry publishers — a retired entry's late
    /// publication can therefore never resurrect a removed server's
    /// series (its in-lock liveness check fails once the registry no
    /// longer carries the entry).
    pub(super) async fn zero_protocol_generation_gauge(&self, server: &str) {
        let _publish_guard = self.protocol_gauge_publish.lock().await;
        let zeroes: Vec<(&str, i64)> = waygate_telemetry::metrics::UPSTREAM_PROTOCOL_GENERATIONS
            .iter()
            .map(|generation| (*generation, 0i64))
            .collect();
        waygate_telemetry::metrics::set_upstream_protocol_generations(server, &zeroes);
        waygate_telemetry::metrics::set_upstream_runtime_state(server, None);
    }

    pub(super) async fn refresh_protocol_generation_gauge(
        &self,
        server: &str,
        entry: &Arc<UpstreamEntry>,
    ) {
        // Total order over every writer of this gauge (see the pool
        // field's docs): whoever writes last sampled last, the liveness
        // check happens inside the lock, and the removal-zero path holds
        // the same lock — so a retired publisher can never overwrite its
        // successor's publication or a removal's zeroes.
        let _publish_guard = self.protocol_gauge_publish.lock().await;
        let mut counts: Vec<(&str, i64)> =
            waygate_telemetry::metrics::UPSTREAM_PROTOCOL_GENERATIONS
                .iter()
                .map(|generation| (*generation, 0i64))
                .collect();
        for slot in &entry.slots {
            if let Some(conn) = slot.conn.read().await.as_ref() {
                let Some(negotiated) = conn.negotiated_protocol.as_deref() else {
                    continue;
                };
                let idx = counts
                    .iter()
                    .position(|(generation, _)| *generation == negotiated)
                    .or_else(|| {
                        counts
                            .iter()
                            .position(|(generation, _)| *generation == "other")
                    });
                if let Some(idx) = idx {
                    counts[idx].1 += 1;
                }
            }
        }
        if !self.is_published_entry(server, entry) {
            return;
        }
        waygate_telemetry::metrics::set_upstream_protocol_generations(server, &counts);
    }
}

impl UpstreamPool {
    /// Drop everything recorded for `server`, so the next refusal it serves
    /// is reported as newly observed. Called when the server leaves the
    /// registry: the record describes an upstream, and a re-added name is a
    /// different arrangement that has told the operator nothing yet.
    pub(super) async fn forget_audited_refusals(&self, server: &str) {
        self.audited_refusals.forget(server).await;
    }

    /// Record a row for each refusal in `served` that has none yet.
    ///
    /// `served` must be sampled while holding the guards that make it the
    /// served set — that is the point of this entry point. A transition that
    /// samples after releasing them can be overtaken by one that withholds
    /// the tool again, and the interval in which clients could see a tool
    /// with no output contract would then go unrecorded. Pair it with
    /// [`Self::refresh_rejected_output_schemas`], which owns the gauge and is
    /// the only path allowed to forget a refusal that has cleared.
    ///
    /// `entry` is the entry the sample came from, used only to decide whether
    /// this server still has a record to add to — not whether the rows are
    /// written. An event stays true after the entry that served it retires.
    pub(super) async fn record_new_refusals(
        &self,
        server: &str,
        entry: &Arc<UpstreamEntry>,
        at: super::refusal_record::Observation,
        observed: &ServedRefusals,
    ) {
        let Some(evidence) = self.evidence.as_ref() else {
            return;
        };
        // A view taken with every lane down says nothing about what this server
        // publishes, so it must not be mistaken for the refusals having stopped
        // being served. See [`ServedRefusals::live`].
        if !observed.live {
            return;
        }
        // A server that has left the registry had its record pruned so a
        // re-added name reports afresh; the observation may not reopen it. The
        // rows are owed either way — the interval it served them was real.
        // Checked inside `apply`, under the lock retirement erases through, so
        // a removal cannot slip between the check and the record's recreation.
        let owed = self
            .audited_refusals
            .apply(server, at, &observed.served, || {
                self.is_published_entry(server, entry)
            })
            .await;
        for rejected in owed {
            record_rejected_output_schema_row(evidence, server, &rejected).await;
        }
    }

    /// Bring every refusal surface for one upstream up to date with what it
    /// is serving RIGHT NOW.
    ///
    /// Use this wherever the served set can change — a dial, a heal, a
    /// classification promotion, a quarantine release. The gauge is
    /// current state, so it is always rewritten. Rows are events, so only
    /// refusals not already recorded produce one; that is what lets a
    /// non-dial transition surface a newly-served refusal without
    /// re-dating the observations an earlier dial already wrote.
    ///
    /// The identity fence below narrows the gauge's write window; it does not
    /// close it. The check and the write are separate operations on a
    /// process-global gauge, so a replacement landing between them still
    /// decides the value by write order and the series can sit stale until the
    /// next publication. Deliberate: the gauge is a best-effort alerting
    /// signal, and the AUTHORITATIVE count is the one the Servers page and
    /// admin API compute from the live registry on every read. Serializing
    /// publishers to close it would add cross-task locking to a reload path in
    /// exchange for a metric that self-corrects at the next install. The rows
    /// have no such window — they are gated on the shared record, under lock.
    pub(super) async fn refresh_rejected_output_schemas(&self, server: &str) {
        let map = self.entries.load_full();
        let Some(entry) = map.get(server) else {
            return;
        };
        let (rejected, at) = observed_union(&self.audited_refusals, entry).await;
        // Re-read AFTER the lane locks: `entry` may have been retired or
        // replaced while this task was parked acquiring them.
        if !self.is_published_entry(server, entry) {
            return;
        }
        waygate_telemetry::metrics::set_rejected_output_schemas(
            server,
            rejected.served.len() as i64,
        );
        self.refresh_unregisterable_input_schema_gauge(server, entry)
            .await;
        self.refresh_protocol_generation_gauge(server, entry).await;
        self.record_new_refusals(server, entry, at, &rejected).await;
    }

    /// Republish the unregisterable-input-schema gauge from the across-lane
    /// union, re-checking after the lane locks that `entry` is still the
    /// registry's live entry — a retired entry sampled just before a
    /// replacement must not overwrite its successor's count. This shares
    /// [`Self::refresh_rejected_output_schemas`]'s best-effort contract: the
    /// check and the write are separate operations on a process-global
    /// gauge, so the value self-corrects at the next install rather than
    /// being serialized against every other publisher.
    pub(super) async fn refresh_unregisterable_input_schema_gauge(
        &self,
        server: &str,
        entry: &Arc<UpstreamEntry>,
    ) {
        let count = unregisterable_union(entry).await;
        if !self.is_published_entry(server, entry) {
            return;
        }
        waygate_telemetry::metrics::set_unregisterable_input_schemas(server, count);
    }
}

/// Across-lane refusal union for one entry, taking every lane read guard
/// before computing so the result reflects a single catalog generation.
/// Count the entry's client-visible tools whose input schema no strict
/// tool-calling client can register, across every lane.
///
/// Applies the same two withholding gates as [`rejected_union`]: a name this
/// lane does not publish, and a drift quarantine, both hide the tool from
/// `tools/list`. Counting either would report a client-visible incompatibility
/// for a tool no client is offered — and drift can quarantine a tool after its
/// unregisterable set was recorded at the dial, so the quarantine set must be
/// consulted here rather than trusted from that snapshot.
async fn unregisterable_union(entry: &Arc<UpstreamEntry>) -> i64 {
    let mut guards = Vec::with_capacity(entry.slots.len());
    for slot in &entry.slots {
        guards.push(slot.conn.read().await);
    }
    // Same lock order as the snapshot path: slots, then quarantine.
    let quarantined = entry
        .quarantined
        .read()
        .expect("upstream quarantine lock poisoned");
    let mut seen = std::collections::BTreeSet::new();
    for guard in &guards {
        let Some(conn) = guard.as_ref() else {
            continue;
        };
        for unregisterable in &conn.unregisterable_input_schemas {
            if !conn
                .tools
                .iter()
                .any(|tool| tool.name == unregisterable.tool)
                || quarantined.contains(unregisterable.tool.as_str())
            {
                continue;
            }
            seen.insert(unregisterable.tool.clone());
        }
    }
    seen.len() as i64
}

async fn union_for(entry: &Arc<UpstreamEntry>) -> Vec<super::tool_listing::RejectedOutputSchema> {
    let mut guards = Vec::with_capacity(entry.slots.len());
    for slot in &entry.slots {
        guards.push(slot.conn.read().await);
    }
    // Same lock order as the snapshot path: slots, then quarantine.
    let quarantined = entry
        .quarantined
        .read()
        .expect("upstream quarantine lock poisoned");
    rejected_union(&guards, &quarantined).served
}

/// The served refusals for `entry`, stamped with the observation that produced
/// them. The stamp is taken UNDER the lane guards, which is what orders it
/// against every other transition to the same server.
async fn observed_union(
    record: &super::refusal_record::RefusalRecord,
    entry: &Arc<UpstreamEntry>,
) -> (ServedRefusals, super::refusal_record::Observation) {
    let mut guards = Vec::with_capacity(entry.slots.len());
    for slot in &entry.slots {
        guards.push(slot.conn.read().await);
    }
    let quarantined = entry
        .quarantined
        .read()
        .expect("upstream quarantine lock poisoned");
    let at = record.observe();
    (rejected_union(&guards, &quarantined), at)
}

/// Every output-schema refusal held by any connected lane, deduplicated by
/// tool name and ordered deterministically so the admin count, the audit
/// rows, and two successive reads agree.
///
/// Lanes are permitted to diverge (a partial heal re-dials only the down
/// ones), so this unions rather than sampling a single lane: a refusal on
/// any live lane is one the operator has to see. When lanes disagree about
/// the root a tool advertised, the first lane's observation wins — the
/// identity of the offending tool is what the operator acts on.
pub(super) fn rejected_union<G>(
    guards: &[G],
    quarantined: &std::collections::HashSet<String>,
) -> ServedRefusals
where
    G: std::ops::Deref<Target = Option<super::Connection>>,
{
    let mut seen = std::collections::BTreeMap::new();
    for guard in guards {
        let Some(conn) = guard.as_ref() else {
            continue;
        };
        for rejected in &conn.rejected_output_schemas {
            // Stripping happens at the dial, before manifest classification,
            // so a refused schema can belong to a tool the gateway then
            // withholds (unclassified, or quarantined out of the published
            // view). Reporting that as "published without an output contract"
            // would overstate the serving inventory, so count only what this
            // lane actually publishes. Classification and drift quarantine are
            // two separate gates and both withhold the tool, so both are
            // applied here — the same pair `published_tools` applies.
            if !conn.tools.iter().any(|tool| tool.name == rejected.tool)
                || quarantined.contains(rejected.tool.as_str())
            {
                continue;
            }
            seen.entry(rejected.tool.clone())
                .or_insert_with(|| rejected.clone());
        }
    }
    ServedRefusals {
        served: seen.into_values().collect(),
        live: guards.iter().any(|guard| guard.is_some()),
    }
}

/// Audit rows only, for the detached boot replay. Writes no gauge, so a
/// stale snapshot here cannot clobber a newer current-state value; an entry
/// already tombstoned when this runs is skipped, so a removed upstream stops
/// producing rows. A retirement that lands after the sample was taken may
/// still emit the rows it observed — that interval was real — but it never
/// reopens the pruned record, which is what would silence a later re-add.
async fn emit_rejected_output_schema_rows(
    entries: Arc<ArcSwap<HashMap<String, Arc<UpstreamEntry>>>>,
    audited_refusals: Arc<super::refusal_record::RefusalRecord>,
    evidence: waygate_mcp::audit::SharedEvidence,
    server: Option<String>,
) {
    let names: Vec<String> = match server {
        Some(name) => vec![name],
        None => entries.load().keys().cloned().collect(),
    };
    for name in names {
        let Some(entry) = entries.load().get(&name).cloned() else {
            continue;
        };
        // The same record as every publish path, so a boot replay racing a
        // redial writes one row rather than two, and the stamps decide which
        // of them is describing the later state.
        let (rejected, at) = observed_union(&audited_refusals, &entry).await;
        // Re-read AFTER the lane locks: an entry retired or replaced while
        // this task was parked is no longer what clients are served from, and
        // the replacement reports for itself.
        if entry.removed.load(Ordering::Acquire)
            || !entries
                .load()
                .get(&name)
                .is_some_and(|live| Arc::ptr_eq(live, &entry))
        {
            continue;
        }
        // No lane was up, so this view says nothing about what is published.
        if !rejected.live {
            continue;
        }
        // Retirement erases the record under the same lock `apply` takes, so the
        // publication check has to happen there rather than out here: the skip
        // above can only be a shortcut, never the guarantee.
        let sampled = Arc::clone(&entry);
        let owed = audited_refusals
            .apply(&name, at, &rejected.served, || {
                !sampled.removed.load(Ordering::Acquire)
                    && entries
                        .load()
                        .get(&name)
                        .is_some_and(|current| Arc::ptr_eq(current, &sampled))
            })
            .await;
        for rejected in owed {
            record_rejected_output_schema_row(&evidence, &name, &rejected).await;
        }
    }
}

async fn record_rejected_output_schema_row(
    evidence: &waygate_mcp::audit::SharedEvidence,
    server: &str,
    rejected: &super::tool_listing::RejectedOutputSchema,
) {
    evidence
        .record_best_effort(
            waygate_mcp::AuditEvent::new(
                "UpstreamOutputSchemaRejected",
                waygate_mcp::AuditOutcome::ExecutionError,
            )
            .with_category(waygate_mcp::EvidenceCategory::UpstreamHealth)
            .with_tool(server, rejected.tool.clone())
            .with_reason(format!(
                "advertised output schema root is `{}`, not `object`; \
                 tool published without an output contract. A strict MCP \
                 client rejects the entire tools/list response over one \
                 such tool — fix the upstream definition.",
                rejected.observed_type
            )),
        )
        .await;
}

/// One live tool's observed behavior contract — the facts annotation-native
/// admission evaluates when a manifest with
/// `classification_mode: mcp-annotations` goes live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedToolContract {
    /// Tool name as the upstream advertises it (no gateway prefix).
    pub name: String,
    /// Canonical behavior hash ([`crate::tool_behavior_hash`]) when every
    /// connected lane advertises the name and every descriptor under it
    /// hashes identically; `None` when the descriptors disagree. Admission
    /// fails closed on that disagreement, so no single approved hash could
    /// make an ambiguous name admissible.
    pub behavior_hash: Option<String>,
    /// Why annotation-native admission would refuse this tool even with a
    /// matching approved hash: its advertised security metadata does not
    /// normalize (missing or malformed annotations / action metadata).
    pub metadata_error: Option<String>,
}

/// The live behavior contracts observed on one upstream's connected lanes.
#[derive(Debug, Clone)]
pub struct ObservedContracts {
    /// Whether at least one lane currently holds a connection. With every
    /// lane down `tools` is empty because observation is unavailable, not
    /// because the upstream has no tools.
    pub connected: bool,
    /// Union of live tool names across connected lanes, sorted by name.
    pub tools: Vec<ObservedToolContract>,
}

impl UpstreamPool {
    /// Whether `candidate` keeps the connection shape the pool currently
    /// holds for `candidate.name` — the same committed-field comparison the
    /// reload path uses to decide a re-dial (transport, url, command, auth,
    /// mTLS, session, exchange, identity tiers). `None` when the server is
    /// unknown. A `false` means a publish would re-dial a NEW endpoint, so
    /// facts observed on the current sessions cannot predict the redialed
    /// catalog.
    pub fn connection_shape_is_current(&self, candidate: &UpstreamManifest) -> Option<bool> {
        let entry = self.entries.load().get(candidate.name.as_str()).cloned()?;
        let current = entry.manifest_snapshot();
        Some(super::reload::redial_committed_fields_eq(
            &current, candidate,
        ))
    }

    /// Shape-check `candidate` and observe live contracts against ONE entry
    /// generation, or `None` if the server is unknown. Loading the registry
    /// twice — once for the shape check, once for the contracts — would let
    /// a concurrent structural reload swap the entry in between; comparing
    /// the manifest before taking the lane guards would let a same-shape
    /// redial (which advances the manifest and swaps sessions under the
    /// lane write locks) pair the OLD shape verdict with the NEW sessions'
    /// hashes. Both reads therefore resolve inside one guarded pass over
    /// one cloned `Arc` entry.
    pub async fn observe_candidate_contracts(
        &self,
        candidate: &UpstreamManifest,
    ) -> Option<CandidateObservation> {
        let entry = self.entries.load().get(candidate.name.as_str()).cloned()?;
        Some(
            match entry_observed_contracts(&entry, Some(candidate)).await {
                Some(observed) => CandidateObservation::Observed(observed),
                None => CandidateObservation::ShapeChanged,
            },
        )
    }

    /// Observe the live per-tool behavior contracts for `server`, or `None`
    /// if the upstream is unknown. Read-only: no dial, no publication or
    /// quarantine change.
    ///
    /// Hashes come from the same function annotation-native admission
    /// compares `approved_behavior_hash` against, computed over the raw
    /// live catalog (`live_tools`, not the currently-published subset) —
    /// exactly the view a `classification_mode: mcp-annotations` manifest
    /// would be admitted on. This is what lets an operator or proposer
    /// obtain correct approved hashes from the gateway without direct
    /// network reach to the upstream.
    pub async fn observed_tool_contracts(&self, server: &str) -> Option<ObservedContracts> {
        let entry = self.entries.load().get(server).cloned()?;
        let observed = entry_observed_contracts(&entry, None)
            .await
            .expect("no candidate means no shape refusal");
        Some(observed)
    }
}

/// Whether a candidate manifest can be judged against the currently
/// connected sessions, resolved on one entry generation.
#[derive(Debug, Clone)]
pub enum CandidateObservation {
    /// The candidate changes the committed connection shape, so publishing
    /// re-dials a new endpoint and the current sessions predict nothing.
    ShapeChanged,
    /// The candidate keeps the current shape; these are its live contracts.
    Observed(ObservedContracts),
}

/// Observe one entry's live contracts under its lane guards, optionally
/// shape-gated: with a `candidate`, returns `None` when it changes the
/// committed connection shape (and never `None` without one). The manifest
/// comparison happens INSIDE the guards: a same-shape redial advances the
/// manifest and swaps the sessions while holding the lane write locks, so
/// only a guarded read pins the shape verdict and the catalogs to one
/// entry generation.
async fn entry_observed_contracts(
    entry: &UpstreamEntry,
    candidate: Option<&UpstreamManifest>,
) -> Option<ObservedContracts> {
    // Take EVERY lane's read guard before reading any catalog — the
    // same all-lanes discipline `clear_quarantine` uses. A reconnect /
    // redial commits the replacement session under the lane locks, so a
    // per-lane acquire could combine catalogs from two generations and
    // report an agreement or ambiguity that neither generation had.
    let mut lane_guards = Vec::with_capacity(entry.slots.len());
    for slot in &entry.slots {
        lane_guards.push(slot.conn.read().await);
    }
    if let Some(candidate) = candidate {
        let current = entry.manifest_snapshot();
        if !super::reload::redial_committed_fields_eq(&current, candidate) {
            return None;
        }
    }
    // Per-lane view: name -> (distinct behavior hashes, first metadata
    // error). Hashing is CPU-only, so doing it under the lane read locks
    // cannot stall a dispatch write for longer than a catalog scan.
    type LaneView = BTreeMap<String, (BTreeSet<String>, Option<String>)>;
    let mut lanes: Vec<LaneView> = Vec::new();
    for guard in &lane_guards {
        let Some(conn) = guard.as_ref() else {
            continue;
        };
        let mut lane = LaneView::new();
        for tool in &conn.live_tools {
            let hash = crate::security_metadata::behavior_hash(tool);
            let error = crate::security_metadata::normalize_tool(tool)
                .err()
                .map(|e| e.to_string());
            let (hashes, first_error) = lane.entry(tool.name.as_ref().to_owned()).or_default();
            hashes.insert(hash);
            if first_error.is_none() {
                *first_error = error;
            }
        }
        lanes.push(lane);
    }
    drop(lane_guards);
    if lanes.is_empty() {
        return Some(ObservedContracts {
            connected: false,
            tools: Vec::new(),
        });
    }
    let names: BTreeSet<&String> = lanes.iter().flat_map(|lane| lane.keys()).collect();
    let tools = names
        .into_iter()
        .map(|name| {
            let mut hashes: BTreeSet<&String> = BTreeSet::new();
            let mut in_every_lane = true;
            let mut metadata_error = None;
            for lane in &lanes {
                match lane.get(name) {
                    Some((lane_hashes, error)) => {
                        hashes.extend(lane_hashes);
                        if metadata_error.is_none() {
                            metadata_error.clone_from(error);
                        }
                    }
                    None => in_every_lane = false,
                }
            }
            // Publication intersects lanes, so a name absent from any
            // connected lane has no executable contract to hash.
            let behavior_hash = (in_every_lane && hashes.len() == 1)
                .then(|| hashes.into_iter().next().cloned())
                .flatten();
            ObservedToolContract {
                name: name.clone(),
                behavior_hash,
                metadata_error,
            }
        })
        .collect();
    Some(ObservedContracts {
        connected: true,
        tools,
    })
}

#[cfg(test)]
mod runtime_state_tests {
    use super::*;

    #[test]
    fn runtime_state_distinguishes_capacity_from_catalog_lifecycle() {
        assert_eq!(
            runtime_state(0, 4, BreakerState::Closed),
            UpstreamRuntimeState::Disconnected,
            "no live lane is disconnected even before the breaker opens",
        );
        assert_eq!(
            runtime_state(2, 4, BreakerState::Closed),
            UpstreamRuntimeState::Degraded,
            "partial capacity must not render as fully connected",
        );
        assert_eq!(
            runtime_state(4, 4, BreakerState::Open),
            UpstreamRuntimeState::Disconnected,
            "stored sessions behind an open breaker have no usable dispatch capacity",
        );
        assert_eq!(
            runtime_state(4, 4, BreakerState::Closed),
            UpstreamRuntimeState::Connected,
        );
    }
}
