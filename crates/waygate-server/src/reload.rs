//! Manifest/policy reload subsystem — SIGHUP + doorbell + poll driven,
//! plus the boot-time resolvers it shares with `main()`. Split from
//! `main.rs`; bodies moved verbatim. Opens with
//! `use super::*;` so the crate root's imports keep resolving.

use super::*;

/// The owned, long-lived boot handles the SIGHUP reload task needs:
/// the two config dirs plus the policy/manifest recovery-ledger stores, the
/// reloadable Cedar engine, the upstream pool, and the audit sink.
/// Grouped into a struct because threading all of them as positional
/// args trips clippy's `too_many_arguments` — and named fields read
/// better than a seven-arg call besides.
#[cfg(unix)]
pub(crate) struct ReloadDeps {
    pub(crate) policies_dir: std::path::PathBuf,
    pub(crate) servers_dir: std::path::PathBuf,
    pub(crate) cedar: Option<Arc<ReloadableCedar>>,
    pub(crate) policy_store: Option<waygate_policy::SharedPolicyStore>,
    pub(crate) manifest_store: Option<waygate_manifest_store::SharedManifestStore>,
    pub(crate) pool: Arc<UpstreamPool>,
    pub(crate) audit: SharedEvidence,
    /// Carried so the SIGHUP reload applies the same prod manifest-safety
    /// gate boot does — a DB-sourced active bundle must not
    /// activate a prod-forbidden `transport: stdio` upstream via reload.
    pub(crate) deployment_profile: DeploymentProfile,
    /// Config-health signal: set healthy on a successful reload,
    /// degraded when a reload is refused (the previous set stays live). The
    /// dashboard reads the same handle for its banner.
    pub(crate) config_health: waygate_upstream::SharedConfigHealth,
    /// Policy config-health signal (mirrors the manifest signal above):
    /// [`reload_policies_only`]
    /// sets it healthy on a clean policy reload, degraded on a ledger recovery or
    /// a refused reload. Separate handle from `config_health` so the policy and
    /// manifest banners never clobber each other; the Policies page reads it.
    pub(crate) policy_config_health: waygate_upstream::SharedConfigHealth,
    /// This replica's fleet id, stamped into per-replica activation
    /// audit events so an operator can see which config each replica is serving.
    pub(crate) replica_id: String,
    /// Raw Postgres pool for the doorbell `LISTEN` (manifest and policy
    /// channels). `None` when no DB is wired ⇒ no doorbell; the poll
    /// backstop is the only cross-replica propagation path. The trait-object
    /// stores can't hand back a `PgPool` for a `PgListener`, so the pool is
    /// threaded here. Both doorbell channels share this one pool.
    pub(crate) db_pool: Option<PgPool>,
    /// Hash of the policy set this replica last loaded. The
    /// doorbell/poll policy reload ([`reload_policies_only`]) compares the live
    /// on-disk hash against this to no-op an idle tick without a Cedar rebuild or
    /// a `PolicyReload` audit row (the manifest pool's `is_noop` analogue, which
    /// the Cedar engine can't provide on its own). Seeded at boot with the
    /// just-loaded on-disk hash; only [`reload_policies_only`] touches it, and the
    /// reload task runs it serially, so the `Mutex` never actually contends.
    pub(crate) last_policy_hash: std::sync::Mutex<Option<String>>,
    /// Signature of the complete non-default active policy-bundle set this
    /// replica last compiled. Kept separately from `last_policy_hash` because
    /// tenant bundles are ledger-backed and do not change `policies/*.cedar`.
    pub(crate) last_tenant_policy_hash: std::sync::Mutex<Option<String>>,
}

/// Generation-fenced latch: a catalog reconcile is owed whenever state newer
/// than the last settled generation may exist. `arm` bumps the owed
/// generation — every dashboard-reload reconcile attempt arms (success
/// included), as does a failed doorbell/SIGHUP reconcile. A doorbell/SIGHUP
/// tick `observe`s the generation BEFORE it reads the disk set it will
/// import, and `settle`s that observation only on success — so a stale
/// reconcile that raced a newer arm cannot clear the newer obligation, and
/// the next tick re-imports from current disk truth. A static because one
/// reload task serves the process and the dashboard's reconcile callback
/// must reach the same latch.
pub(crate) struct ReconcileLatch {
    armed: std::sync::atomic::AtomicU64,
    settled: std::sync::atomic::AtomicU64,
}

impl ReconcileLatch {
    pub(crate) const fn new() -> Self {
        Self {
            armed: std::sync::atomic::AtomicU64::new(0),
            settled: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// A reconcile is owed for state newer than anything settled so far.
    pub(crate) fn arm(&self) {
        self.armed.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// The generation a beginning reconcile may later `settle`. Take it
    /// BEFORE reading the manifest set the reconcile will import: an arm
    /// that lands after this observation — a dashboard reload with newer
    /// disk state — must survive this reconcile's success.
    pub(crate) fn observe(&self) -> u64 {
        self.armed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Settle a successful reconcile's observed generation. Monotonic: a
    /// stale observation can never regress the settled generation.
    pub(crate) fn settle(&self, observed: u64) {
        self.settled
            .fetch_max(observed, std::sync::atomic::Ordering::AcqRel);
    }

    pub(crate) fn due(&self) -> bool {
        self.settled.load(std::sync::atomic::Ordering::Acquire)
            < self.armed.load(std::sync::atomic::Ordering::Acquire)
    }
}

pub(crate) static CATALOG_RECONCILE_LATCH: ReconcileLatch = ReconcileLatch::new();

/// Background task that reloads on-disk policies + upstream manifests on
/// SIGHUP. Errors during reload are logged and the previous state is kept
/// — a botched policy file must never lock the operator out of the gateway.
/// The task exits when the main cancellation token fires.
/// Poll-backstop cadence for the manifest reload task. The doorbell
/// (`LISTEN/NOTIFY`) is the fast path; this poll catches a missed
/// notification (dropped listener, coalesced burst) or an out-of-band edit to
/// the shared dir. A few-second window is fine for a rarely-edited config set;
/// the reload no-ops when nothing changed.
#[cfg(unix)]
pub(crate) const MANIFEST_POLL_SECS: u64 = 20;

#[cfg(unix)]
pub(crate) fn spawn_reload_task(
    deps: ReloadDeps,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cannot install SIGHUP handler; hot-reload disabled");
                return;
            }
        };
        // Doorbells: one PgListener subscribes to every channel so hot reload
        // consumes one process-lifetime control-pool permit regardless of how
        // many independently handled configuration planes exist. Keep a sender
        // alive for each here so the receiver never closes when there is no DB /
        // no forwarder (a closed channel would busy-spin the arm). Separate
        // receivers ensure a manifest write only re-dials upstreams and a policy
        // write only rebuilds Cedar.
        let (manifest_tx, mut manifest_rx) = tokio::sync::mpsc::channel::<()>(8);
        let (policy_tx, mut policy_rx) = tokio::sync::mpsc::channel::<()>(8);
        if let Some(pool) = deps.db_pool.clone() {
            tokio::spawn(fleet_doorbell_forwarder(
                pool,
                manifest_tx.clone(),
                policy_tx.clone(),
                deps.pool.tool_catalog_epoch(),
                shutdown.clone(),
            ));
        }
        let _manifest_tx_keepalive = manifest_tx;
        let _policy_tx_keepalive = policy_tx;
        // Poll backstop. Both `reload_*_only` no-op when nothing changed, so an
        // idle tick is cheap. Skip missed ticks rather than bursting.
        let mut poll = tokio::time::interval(std::time::Duration::from_secs(MANIFEST_POLL_SECS));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        poll.tick().await; // consume the immediate first tick (boot already loaded)
        tracing::info!(
            poll_secs = MANIFEST_POLL_SECS,
            "reload task ready: SIGHUP + doorbell + poll (policies + manifests)",
        );
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::debug!("reload task exiting");
                    return;
                }
                maybe = sighup.recv() => {
                    if maybe.is_none() {
                        return;
                    }
                    tracing::info!("SIGHUP received — reloading policies and manifests");
                    reload_once(&deps).await;
                }
                // Manifest doorbell: a peer (or this replica) wrote servers/*.yaml.
                Some(()) = manifest_rx.recv() => {
                    tracing::debug!("doorbell: manifest change notified — reloading");
                    reload_manifests_only(&deps).await;
                }
                // Policy doorbell: a peer (or this replica) wrote policies/*.cedar
                // — rebuild Cedar only (no manifest re-dial).
                Some(()) = policy_rx.recv() => {
                    tracing::debug!("doorbell: policy change notified — reloading");
                    reload_policies_only(&deps).await;
                }
                _ = poll.tick() => {
                    // Backstop both sets: catches a missed notification or an
                    // out-of-band edit to either shared dir.
                    reload_policies_only(&deps).await;
                    reload_manifests_only(&deps).await;
                }
            }
        }
    })
}

/// Fleet-wide manifest, policy, and governed-catalog invalidation.
///
/// One listener owns every doorbell subscription so supported small control
/// pools retain a permit for the stores and the catalog-generation read. The
/// catalog database generation is authoritative; its notification only prompts
/// a fast read. Establishing every `LISTEN` before the baseline query follows
/// the PostgreSQL setup contract and closes the listener-start race. A periodic
/// generation read catches a disconnected listener or a coalesced burst.
#[cfg(unix)]
pub(crate) async fn fleet_doorbell_forwarder(
    pool: PgPool,
    manifest_tx: tokio::sync::mpsc::Sender<()>,
    policy_tx: tokio::sync::mpsc::Sender<()>,
    epoch: waygate_mcp::ToolCatalogEpoch,
    shutdown: CancellationToken,
) {
    let mut observed_generation = None;
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "fleet doorbell connect failed; polling durable catalog generation before retry",
                );
                observe_catalog_generation(&pool, &epoch, &mut observed_generation).await;
                if sleep_or_shutdown(&shutdown, 5).await {
                    return;
                }
                continue;
            }
        };
        if let Err((channel, error)) = listen_for_fleet_changes(&mut listener).await {
            tracing::warn!(
                error = %error,
                %channel,
                "fleet doorbell LISTEN failed; polling durable catalog generation before retry",
            );
            observe_catalog_generation(&pool, &epoch, &mut observed_generation).await;
            if sleep_or_shutdown(&shutdown, 5).await {
                return;
            }
            continue;
        }

        // LISTEN is active before this query. A commit on either side of the
        // setup boundary is therefore represented by this baseline or by a
        // subsequently received notification (possibly both, which is safe).
        observe_catalog_generation(&pool, &epoch, &mut observed_generation).await;
        tracing::info!(
            channels = ?FLEET_RELOAD_CHANNELS,
            "fleet doorbell: LISTEN active",
        );

        let mut poll = tokio::time::interval(std::time::Duration::from_secs(MANIFEST_POLL_SECS));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        poll.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = poll.tick() => {
                    observe_catalog_generation(&pool, &epoch, &mut observed_generation).await;
                }
                notification = listener.recv() => match notification {
                    Ok(notification) => match FleetDoorbell::from_channel(notification.channel()) {
                        Some(FleetDoorbell::Manifest) => {
                            let _ = manifest_tx.try_send(());
                        }
                        Some(FleetDoorbell::Policy) => {
                            let _ = policy_tx.try_send(());
                        }
                        Some(FleetDoorbell::Catalog) => {
                            observe_catalog_generation(&pool, &epoch, &mut observed_generation).await;
                        }
                        None => {
                            tracing::warn!(channel = notification.channel(), "unexpected fleet doorbell channel");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "fleet doorbell listener dropped; reconnecting",
                        );
                        break;
                    }
                }
            }
        }
        if sleep_or_shutdown(&shutdown, 2).await {
            return;
        }
    }
}

#[cfg(unix)]
const FLEET_RELOAD_CHANNELS: [&str; 3] = [
    waygate_manifest_store::MANIFEST_RELOAD_CHANNEL,
    waygate_policy::POLICY_RELOAD_CHANNEL,
    waygate_catalog::CATALOG_RELOAD_CHANNEL,
];

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FleetDoorbell {
    Manifest,
    Policy,
    Catalog,
}

#[cfg(unix)]
impl FleetDoorbell {
    fn from_channel(channel: &str) -> Option<Self> {
        match channel {
            waygate_manifest_store::MANIFEST_RELOAD_CHANNEL => Some(Self::Manifest),
            waygate_policy::POLICY_RELOAD_CHANNEL => Some(Self::Policy),
            waygate_catalog::CATALOG_RELOAD_CHANNEL => Some(Self::Catalog),
            _ => None,
        }
    }
}

#[cfg(unix)]
async fn listen_for_fleet_changes(
    listener: &mut sqlx::postgres::PgListener,
) -> Result<(), (&'static str, sqlx::Error)> {
    for channel in FLEET_RELOAD_CHANNELS {
        if let Err(error) = listener.listen(channel).await {
            return Err((channel, error));
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod fleet_doorbell_tests {
    use super::{FleetDoorbell, FLEET_RELOAD_CHANNELS};

    #[test]
    fn every_subscribed_channel_routes_to_one_distinct_plane() {
        let routes = FLEET_RELOAD_CHANNELS.map(FleetDoorbell::from_channel);

        assert_eq!(
            routes,
            [
                Some(FleetDoorbell::Manifest),
                Some(FleetDoorbell::Policy),
                Some(FleetDoorbell::Catalog),
            ]
        );
        assert_eq!(FleetDoorbell::from_channel("unregistered"), None);
    }
}

#[cfg(unix)]
async fn observe_catalog_generation(
    pool: &PgPool,
    epoch: &waygate_mcp::ToolCatalogEpoch,
    observed_generation: &mut Option<i64>,
) {
    use waygate_catalog::CatalogStore as _;

    let store = waygate_catalog::PgCatalogStore::new(pool.clone());
    match store.discovery_generation().await {
        Ok(Some(current)) => {
            if observed_generation.is_none_or(|previous| previous != current) {
                epoch.mark_changed();
            }
            *observed_generation = Some(current);
        }
        Ok(None) => {
            tracing::warn!("catalog discovery generation row is missing; retrying on next poll");
        }
        Err(error) => {
            tracing::warn!(%error, "catalog discovery generation read failed; retrying on next poll");
        }
    }
}

/// Sleep up to `secs`, returning `true` if shutdown fired first.
#[cfg(unix)]
pub(crate) async fn sleep_or_shutdown(shutdown: &CancellationToken, secs: u64) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => true,
        _ = tokio::time::sleep(std::time::Duration::from_secs(secs)) => false,
    }
}

/// Reconcile the turnstile pointer to the actual on-disk hash. Called
/// from boot (clean disk load), the doorbell/poll reload, and
/// the dashboard Reload. An out-of-band edit to `servers/*.yaml` otherwise
/// leaves the pointer stale, so every later `cas_pointer` from the current disk
/// hash loses and dashboard saves permanently fail. Best-effort:
/// every failure is logged, never fails boot/reload; the next reload retries.
/// Emits a `ManifestReload` audit row only when the pointer actually advanced
/// (i.e. an out-of-band edit was detected), so a steady-state reload is silent.
pub(crate) async fn reconcile_manifest_pointer(
    store: &waygate_manifest_store::SharedManifestStore,
    manifests: &BTreeMap<String, UpstreamManifest>,
    audit: &SharedEvidence,
    actor: &str,
) {
    // The pointer tracks the CANONICAL on-disk hash:
    // `content_hash(serialize_manifest_set(load_manifests(dir)))`. `manifests`
    // here is exactly `load_manifests(dir)` for a clean load, so this matches
    // what `read_manifest_set_from_disk` and the write-path CAS compute.
    let disk_hash = match waygate_upstream::serialize_manifest_set(manifests) {
        Ok(content) => waygate_manifest_store::content_hash(&content),
        Err(e) => {
            tracing::warn!(error = %e, "pointer reconcile: could not serialize the on-disk set; skipping");
            return;
        }
    };
    match store
        .reconcile_pointer(waygate_core::TenantId::DEFAULT, &disk_hash, actor)
        .await
    {
        Ok(waygate_manifest_store::PointerReconcile::Advanced { from }) => {
            tracing::warn!(
                from = %from,
                to = %disk_hash,
                %actor,
                "turnstile pointer reconciled to the on-disk hash (out-of-band servers/*.yaml edit detected)",
            );
            audit
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "server_manifest.pointer_reconciled",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::ManifestReload)
                    .with_reason(format!(
                        "reconciled turnstile pointer {from} -> {disk_hash} ({actor}); \
                         out-of-band servers/*.yaml edit",
                    )),
                )
                .await;
        }
        Ok(other) => {
            tracing::debug!(?other, "turnstile pointer reconcile: no advance needed");
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "turnstile pointer reconcile failed (non-fatal; the next reload retries)",
            );
        }
    }
}

/// Whether a coordinated write appears to be in flight, for the out-of-band
/// snapshot guard. A publish/rollback CASes the turnstile pointer at
/// its start, then mirrors disk, then transitions the ledger — so a pointer
/// advanced within [`RECONCILE_GRACE`](waygate_manifest_store::RECONCILE_GRACE)
/// means a write is mid-flight and the disk/ledger drift it produced must NOT be
/// recorded as a `filesystem` row (it's the operator's about-to-land publish,
/// not an out-of-band edit). An absent pointer (fresh deploy) is not in-flight.
pub(crate) fn write_in_flight(
    pointer: Option<&waygate_manifest_store::ManifestPointer>,
    now: time::OffsetDateTime,
) -> bool {
    pointer.is_some_and(|p| now - p.updated_at < waygate_manifest_store::RECONCILE_GRACE)
}

/// Refuse to activate a manifest snapshot captured while a coordinated writer
/// is between its pointer CAS and its completed filesystem commit.
///
/// The writer advances the shared pointer to the target hash before touching
/// `servers/*.yaml`. A reader that observes a different disk hash while that
/// pointer is fresh may have caught the bounded multi-file commit in progress.
/// Keeping the prior in-memory set and retrying on the next doorbell or poll
/// prevents a replica from hot-removing upstreams from that transient view.
pub(crate) async fn manifest_reload_should_defer(
    store: Option<&waygate_manifest_store::SharedManifestStore>,
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> bool {
    let Some(store) = store else { return false };
    let content = match waygate_upstream::serialize_manifest_set(manifests) {
        Ok(content) => content,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "manifest reload: could not hash the candidate set; keeping the previous set",
            );
            return true;
        }
    };
    let disk_hash = waygate_manifest_store::content_hash(&content);
    match store.read_pointer(waygate_core::TenantId::DEFAULT).await {
        Ok(pointer) => {
            let in_flight = pointer.as_ref().is_some_and(|pointer| {
                pointer.current_hash != disk_hash
                    && write_in_flight(Some(pointer), time::OffsetDateTime::now_utc())
            });
            if in_flight {
                tracing::debug!(
                    "manifest reload: candidate differs from a freshly advanced turnstile \
                     pointer; keeping the previous set until the coordinated write settles",
                );
            }
            in_flight
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "manifest reload: turnstile read failed; keeping the previous set because an \
                 in-flight coordinated write cannot be ruled out",
            );
            true
        }
    }
}

/// Boot cannot retain a prior complete set, so a transient snapshot must make
/// the process retry before it starts serving.
pub(crate) async fn ensure_manifest_snapshot_ready_for_boot(
    store: Option<&waygate_manifest_store::SharedManifestStore>,
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> anyhow::Result<()> {
    if manifest_reload_should_defer(store, manifests).await {
        anyhow::bail!(
            "manifest snapshot differs from a freshly advanced turnstile pointer; \
             a coordinated write may be in progress, retry boot"
        );
    }
    Ok(())
}

/// Whether the on-disk set (`disk_hash` = its canonical content hash) has
/// drifted from the active ledger bundle's content. Canonicalizes
/// `active_content` the same way disk is hashed
/// (`content_hash(serialize_manifest_set(parse_manifest_set(_)))`) so a
/// published row that stored a *non-canonical* raw serialization doesn't read as
/// drift on every reload — the same canonical subtlety as the turnstile.
/// Returns `false` when the active content can't parse: don't synthesize
/// a convergence row off an unparseable ledger row.
pub(crate) fn disk_drifted_from_active(active_content: &str, disk_hash: &str) -> bool {
    match waygate_upstream::parse_manifest_set(active_content)
        .and_then(|s| waygate_upstream::serialize_manifest_set(&s))
    {
        Ok(c) => waygate_manifest_store::content_hash(&c) != disk_hash,
        Err(_) => false,
    }
}

/// Record the current on-disk set as a `filesystem`-attributed ledger bundle
/// when it has drifted from the latest published snapshot —
/// i.e. an out-of-band edit to `servers/*.yaml` that bypassed the dashboard.
/// Capturing it closes the bypass (the out-of-band state is now in history and
/// rollback-able) and gives free convergence monitoring. Best-effort: every
/// failure is logged, never fails boot/reload.
///
/// Detection lives here (not in the store) because it needs the canonical
/// comparison: disk's canonical hash vs the *canonical* hash of the active
/// bundle's content (the active row may store a non-canonical raw serialization;
/// comparing raw hashes would mis-fire on every reload — the same canonical
/// subtlety as the turnstile). A genuine match ⇒ nothing to record.
pub(crate) async fn record_out_of_band_snapshot(
    store: &waygate_manifest_store::SharedManifestStore,
    manifests: &BTreeMap<String, UpstreamManifest>,
    audit: &SharedEvidence,
) {
    let content = match waygate_upstream::serialize_manifest_set(manifests) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "out-of-band snapshot: could not serialize the on-disk set; skipping");
            return;
        }
    };
    let disk_hash = waygate_manifest_store::content_hash(&content);
    let active = match store.active_bundle(waygate_core::TenantId::DEFAULT).await {
        Ok(b) => b,
        // No published bundle yet (fresh deploy): the import/first-publish path
        // establishes the initial ledger, not this convergence recorder.
        Err(waygate_manifest_store::ManifestError::NotFound(_)) => return,
        Err(e) => {
            tracing::warn!(error = %e, "out-of-band snapshot: active-bundle read failed; skipping");
            return;
        }
    };
    if !disk_drifted_from_active(&active.content, &disk_hash) {
        return; // disk matches the latest published set — nothing out-of-band.
    }
    // In-flight-write guard: a coordinated admin publish/rollback
    // mirrors disk to the new content BEFORE its ledger transition, so during
    // that window disk is legitimately ahead of the ledger and this "drift" is a
    // dashboard write mid-flight, NOT an out-of-band edit. Recording it would
    // create a spurious `filesystem` row duplicating the operator's about-to-land
    // publish. The write CASes the turnstile pointer at its START, so a pointer
    // advanced within the grace window means a write is in flight — defer. An
    // out-of-band edit bypasses the turnstile, so the pointer still carries the
    // last *coordinated* write's (older) timestamp. (This recorder runs BEFORE
    // the pointer reconcile at each site, so the timestamp read here is the
    // pre-reconcile one, not one reconcile just refreshed.)
    match store.read_pointer(waygate_core::TenantId::DEFAULT).await {
        Ok(pointer) => {
            if write_in_flight(pointer.as_ref(), time::OffsetDateTime::now_utc()) {
                tracing::debug!(
                    "out-of-band snapshot: pointer advanced within the grace window; deferring \
                     (a coordinated write may be mid mirror-to-ledger)",
                );
                return;
            }
        }
        // Fail safe: a pointer read failure means we cannot rule out
        // a coordinated write mid mirror-to-ledger, and recording its content as
        // a `filesystem` row is exactly the harm this guard prevents. Defer (and
        // log, per the best-effort contract) rather than risk a spurious row;
        // the next reload retries once the read recovers.
        Err(e) => {
            tracing::warn!(
                error = %e,
                "out-of-band snapshot: pointer read failed; deferring (cannot rule out an in-flight write)",
            );
            return;
        }
    }
    match store
        .record_filesystem_snapshot(waygate_core::TenantId::DEFAULT, &content)
        .await
    {
        Ok(Some(bundle)) => {
            tracing::warn!(
                version = bundle.version,
                hash = %disk_hash,
                "recorded an out-of-band servers/*.yaml edit as a filesystem ledger snapshot",
            );
            audit
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "server_manifest.filesystem_snapshot",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::ManifestReload)
                    .with_reason(format!(
                        "recorded out-of-band servers/*.yaml edit as ledger v{} hash={} \
                         (filesystem)",
                        bundle.version, disk_hash
                    )),
                )
                .await;
        }
        Ok(None) => {} // already recorded (idempotent / another replica won).
        Err(e) => tracing::warn!(
            error = %e,
            "out-of-band snapshot record failed (non-fatal; the next reload retries)",
        ),
    }
}

/// Pick this replica's stable identifier for fleet observability: an
/// explicit `GATEWAY_REPLICA_ID` wins, else the container/pod
/// `HOSTNAME` (set by k8s/docker, unique per replica), else a process-scoped
/// fallback for local/dev. Pure (env reads live in [`derive_replica_id`]) so the
/// precedence is unit-testable.
pub(crate) fn pick_replica_id(explicit: Option<&str>, hostname: Option<&str>, pid: u32) -> String {
    explicit
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| hostname.map(str::trim).filter(|s| !s.is_empty()))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("replica-pid{pid}"))
}

/// This replica's identifier, read from the environment once at boot.
pub(crate) fn derive_replica_id() -> String {
    let explicit = std::env::var("GATEWAY_REPLICA_ID").ok();
    let hostname = std::env::var("HOSTNAME").ok();
    pick_replica_id(explicit.as_deref(), hostname.as_deref(), std::process::id())
}

/// Emit a per-replica activation audit event: "replica R
/// activated config <version|uncommitted> hash H (N upstreams)". Fired at boot
/// and on a reload that applied a change (NOT on no-op polls, per the no-spam
/// contract), so an operator can see, per replica, which config each is serving
/// — the audit-trail foundation for the fleet roll-up. Best-effort.
///
/// The version is the active ledger bundle's when disk matches it (after the
/// reconcile/synthesis that run first have converged the ledger to disk), else
/// `uncommitted` — an uncommitted/in-flight on-disk set with no committed
/// ledger version yet.
///
/// `fully_applied` distinguishes a real activation from a partial one: the
/// hot-reload path applies classification / identity changes AND
/// add/remove of upstreams in place (a newly-listed server is dialed and
/// published; a delisted one is drained and dropped). Only a slot-count-changing
/// shape edit (a stdio↔network flip or a `session.concurrency` change) or a
/// re-dial that failed on every lane still needs a restart. When `false`, the
/// replica is NOT yet serving the new config, so the event says "hot-applied …
/// RESTART required" rather than falsely claiming activation. Boot is always a
/// full activation (the pool is built fresh from the whole config).
/// Build (but do NOT record) the per-replica activation event, while
/// `manifests` is still in hand. Boot builds it here and records it only AFTER
/// the listener binds (the serving point), so a boot that fails between manifest
/// resolution and serving never persists a false "activated" claim; the
/// reload paths build+record adjacently via [`record_activation`] because
/// the pool is already live there. `None` if the on-disk set can't serialize.
pub(crate) async fn build_activation_event(
    store: Option<&waygate_manifest_store::SharedManifestStore>,
    replica_id: &str,
    manifests: &BTreeMap<String, UpstreamManifest>,
    fully_applied: bool,
) -> Option<waygate_mcp::AuditEvent> {
    let content = match waygate_upstream::serialize_manifest_set(manifests) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "activation audit: could not serialize the on-disk set; skipping");
            return None;
        }
    };
    let disk_hash = waygate_manifest_store::content_hash(&content);
    let version_label = match store {
        Some(s) => match s.active_bundle(waygate_core::TenantId::DEFAULT).await {
            Ok(active) if !disk_drifted_from_active(&active.content, &disk_hash) => {
                format!("v{}", active.version)
            }
            _ => "uncommitted".to_owned(),
        },
        None => "uncommitted".to_owned(),
    };
    let (verb, restart_note) = if fully_applied {
        ("activated", "")
    } else {
        (
            "hot-applied",
            " — a RESTART is required to serve the connection-shape changes",
        )
    };
    Some(
        waygate_mcp::AuditEvent::new(
            "server_manifest.activated",
            waygate_mcp::AuditOutcome::Success,
        )
        .with_category(waygate_mcp::EvidenceCategory::ManifestReload)
        .with_reason(format!(
            "replica {replica_id} {verb} config {version_label} hash={disk_hash} \
                 ({} upstream(s)){restart_note}",
            manifests.len()
        )),
    )
}

/// Record a per-replica activation event now — for the reload paths, where the
/// pool is already live so the build point IS the serving point. Best-effort.
pub(crate) async fn record_activation(
    store: Option<&waygate_manifest_store::SharedManifestStore>,
    audit: &SharedEvidence,
    replica_id: &str,
    manifests: &BTreeMap<String, UpstreamManifest>,
    fully_applied: bool,
) {
    if let Some(event) = build_activation_event(store, replica_id, manifests, fully_applied).await {
        audit.record_best_effort(event).await;
    }
}

/// The canonical on-disk hash of `manifests` plus the committed ledger version
/// it corresponds to (the active bundle's, when disk matches it after the
/// reconcile/synthesis have converged the ledger; `None` for an uncommitted /
/// out-of-band set). `None` overall if the set can't serialize. Shared by the
/// fleet heartbeat.
pub(crate) async fn disk_hash_and_version(
    store: Option<&waygate_manifest_store::SharedManifestStore>,
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> Option<(String, Option<i32>)> {
    let content = waygate_upstream::serialize_manifest_set(manifests).ok()?;
    let disk_hash = waygate_manifest_store::content_hash(&content);
    let version = match store {
        Some(s) => match s.active_bundle(waygate_core::TenantId::DEFAULT).await {
            Ok(active) if !disk_drifted_from_active(&active.content, &disk_hash) => {
                Some(active.version)
            }
            _ => None,
        },
        None => None,
    };
    Some((disk_hash, version))
}

/// Upsert this replica's fleet heartbeat: the disk hash + ledger
/// version it has loaded. Called on every reload tick (the doorbell/poll/SIGHUP
/// loop) so the dashboard roll-up sees a fresh check-in even when nothing
/// changed. No-op without a store (no heartbeat table); best-effort otherwise.
pub(crate) async fn record_heartbeat(
    store: Option<&waygate_manifest_store::SharedManifestStore>,
    replica_id: &str,
    manifests: &BTreeMap<String, UpstreamManifest>,
) {
    let Some(store) = store else { return };
    let Some((disk_hash, version)) = disk_hash_and_version(Some(store), manifests).await else {
        tracing::warn!("fleet heartbeat: could not serialize the on-disk set; skipping");
        return;
    };
    if let Err(e) = store
        .upsert_replica_heartbeat(
            replica_id,
            waygate_core::TenantId::DEFAULT,
            version,
            &disk_hash,
        )
        .await
    {
        tracing::warn!(error = %e, "fleet heartbeat upsert failed (non-fatal; the next reload retries)");
    }
}

/// Refresh ONLY this replica's heartbeat timestamp on a FAILED reload: the
/// replica is still alive and serving the previous set, so its
/// liveness must keep ticking even though there's no new config to record —
/// otherwise the fleet row ages stale during a prolonged broken-disk state.
/// Best-effort; no-op without a store.
pub(crate) async fn touch_heartbeat(
    store: Option<&waygate_manifest_store::SharedManifestStore>,
    replica_id: &str,
) {
    if let Some(store) = store {
        if let Err(e) = store.touch_replica_heartbeat(replica_id).await {
            tracing::warn!(error = %e, "fleet heartbeat touch failed (non-fatal)");
        }
    }
}

/// Manifest-only reload for the doorbell + poll backstop:
/// re-read the shared servers dir and swap the live pool, WITHOUT the Cedar
/// rebuild or the per-reload audit event that the SIGHUP [`reload_once`] emits.
/// Cheap enough for a poll tick (the pool diff no-ops when nothing changed),
/// and the dashboard write that triggered a doorbell NOTIFY is already audited
/// at its source — so a poll that finds no change must not spam the audit log.
/// Same fail-closed contract as `reload_once`: an unreadable live dir keeps the
/// previous in-memory set and marks config-health degraded.
#[cfg(unix)]
pub(crate) async fn reload_manifests_only(deps: &ReloadDeps) {
    // Latch fence: observed BEFORE this tick reads the disk set it may
    // import, so a dashboard arm landing after this point survives this
    // tick's successful settle (see `ReconcileLatch`).
    let reconcile_observed = CATALOG_RECONCILE_LATCH.observe();
    let resolved = match resolve_manifests(&deps.servers_dir, deps.manifest_store.as_ref()).await {
        Ok(ResolvedManifests {
            manifests,
            recovered,
        }) => crate::config::enforce_prod_manifest_safety_for_profile(
            deps.deployment_profile,
            &manifests,
        )
        .map(|()| (manifests, recovered)),
        Err(e) => Err(e),
    };
    match resolved {
        Ok((manifests, recovered)) => {
            if manifest_reload_should_defer(deps.manifest_store.as_ref(), &manifests).await {
                return;
            }
            let report = deps.pool.reload_manifests(&manifests).await;
            if !report.is_noop() {
                tracing::info!(
                    added = ?report.added,
                    removed = ?report.removed,
                    redialed = ?report.redialed,
                    redial_failed = ?report.redial_failed,
                    resource_shape_restart_required = ?report.resource_shape_restart_required,
                    classifications_updated = ?report.classifications_updated,
                    "manifest reload applied (doorbell/poll)",
                );
                if !report.redial_failed.is_empty() {
                    tracing::warn!(
                        servers = ?report.redial_failed,
                        "live re-dial failed on every lane — these upstreams kept the previous \
                         connection shape; fix the new target or restart to apply",
                    );
                }
                if !report.resource_shape_restart_required.is_empty() {
                    tracing::warn!(
                        servers = ?report.resource_shape_restart_required,
                        "manifest reload refused before mutation because resource ownership and \
                         connection shape changed together; restart to apply the complete set",
                    );
                }
            }
            // A superseded reload lost the live registry to a
            // newer concurrent reload, so `manifests` is NOT the set now serving.
            // Skip ALL of its control-plane side-effects — the config-health
            // banner, the catalog reconcile, the out-of-band snapshot +
            // turnstile-pointer reconcile (reconcile could CAS the pointer
            // BACKWARD to the losing set), the activation event, and the heartbeat
            // — so the catalog, ledger, pointer, and fleet/audit state only ever
            // reflect the WINNING reload, whose own tick records them.
            if !report.superseded && report.resource_shape_restart_required.is_empty() {
                let disk_loaded_cleanly = recovered.is_none();
                match recovered {
                    None => deps.config_health.set_healthy(format!(
                        "{} upstream(s) live from servers/*.yaml",
                        manifests.len()
                    )),
                    Some(detail) => deps.config_health.set_degraded(detail),
                }
                // Reconcile the tool-facts catalog from the served set on a
                // change-detected doorbell/poll reload, so a classification
                // change written to the live NFS dir takes effect
                // without a restart (authz reads catalog facts ahead of the
                // manifest fallback). Non-fatal + DB-pool-gated + change-gated,
                // where a prior failed reconcile keeps the gate open until a
                // retry succeeds — identical to the SIGHUP path.
                if !report.is_noop()
                    || CATALOG_RECONCILE_LATCH.due()
                    || deps.pool.catalog_reconcile_pending()
                {
                    if let Some(catalog_pool) = deps.db_pool.as_ref() {
                        match import_cmd::reconcile_catalog_from_manifests(catalog_pool, &manifests)
                            .await
                        {
                            Ok(stats) => {
                                deps.pool.settle_catalog_reconcile(&report);
                                CATALOG_RECONCILE_LATCH.settle(reconcile_observed);
                                tracing::info!(
                                    servers = stats.servers,
                                    tools = stats.tools,
                                    "catalog reconciled from reloaded manifest set (doorbell/poll)",
                                )
                            }
                            Err(e) => {
                                CATALOG_RECONCILE_LATCH.arm();
                                tracing::error!(
                                    error = %e,
                                    "catalog reconcile on reload FAILED (existing catalog preserved; \
                                     the next tick retries even without a manifest change)",
                                )
                            }
                        }
                    }
                }
                // Re-sync the turnstile pointer to disk after a clean
                // reload, so an out-of-band servers/*.yaml edit this replica just
                // picked up (via the doorbell/poll) doesn't leave the pointer
                // stale and CAS-fail later dashboard saves.
                if disk_loaded_cleanly {
                    if let Some(store) = deps.manifest_store.as_ref() {
                        // Snapshot BEFORE reconcile (see boot path).
                        record_out_of_band_snapshot(store, &manifests, &deps.audit).await;
                        reconcile_manifest_pointer(
                            store,
                            &manifests,
                            &deps.audit,
                            "filesystem-reload",
                        )
                        .await;
                    }
                }
                // A per-replica activation event when this reload
                // actually changed the live set — NOT on a no-op poll tick (the
                // no-spam contract this lean reload path is built around).
                // A failed re-dial may have applied independent hot fields;
                // a coupled resource/shape refusal never reaches this branch.
                if !report.is_noop() {
                    record_activation(
                        deps.manifest_store.as_ref(),
                        &deps.audit,
                        &deps.replica_id,
                        &manifests,
                        !report.requires_restart(),
                    )
                    .await;
                }
                // Refresh the fleet heartbeat (liveness + current
                // config), distinct from the no-spam activation audit above.
                record_heartbeat(deps.manifest_store.as_ref(), &deps.replica_id, &manifests).await;
            } else if !report.resource_shape_restart_required.is_empty() {
                deps.config_health.set_degraded(format!(
                    "reload refused — resource ownership and connection shape changed together \
                     for {}; restart required",
                    report.resource_shape_restart_required.join(", ")
                ));
                touch_heartbeat(deps.manifest_store.as_ref(), &deps.replica_id).await;
            }
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "manifest reload (doorbell/poll) failed or refused; keeping previous set",
            );
            deps.config_health
                .set_degraded(format!("reload refused — serving the previous set: {e}"));
            // The reload failed but the replica is still up and
            // serving the previous set — keep its liveness ticking.
            touch_heartbeat(deps.manifest_store.as_ref(), &deps.replica_id).await;
        }
    }
}

/// Policy-only reload for the doorbell + poll backstop (and the SIGHUP
/// path, which delegates here). Two concerns, separately gated:
///
/// 1. **Engine swap + `PolicyReload` audit** — gated on a change since the last
///    load (`last_policy_hash`), so an idle poll tick or a doorbell for a write
///    this replica already serves doesn't rebuild Cedar or spam the audit (the
///    `reload_manifests_only` `is_noop` analogue; the Cedar engine can't
///    self-report a no-change).
/// 2. **Ledger/pointer convergence** (out-of-band capture + pointer
///    reconcile) — runs on EVERY tick where disk is a usable Cedar set,
///    NOT gated on the hash. Both helpers are best-effort and idempotent
///    (`Ok(None)` / `AlreadyInSync` once converged), so a reconcile that FAILED or
///    DEFERRED on an earlier tick retries until it converges — exactly as the
///    manifest path reconciles every clean tick. Gating convergence on the hash
///    left a transient reconcile failure permanently un-retried for unchanged
///    disk, blocking later dashboard writes on a stale pointer. Idempotent
///    steady state is two cheap no-op DB reads per tick, no audit.
///
/// Fail-closed throughout: an unreadable/broken live set keeps the previous
/// engine and never installs an empty deny-all set. Ledger recovery remains a
/// boot path when no live engine exists; a running gateway never replaces its
/// current last-known-good engine with a possibly older recovery snapshot. The
/// convergence parse-guard ensures the pointer is only reconciled to a disk the
/// gate is actually running.
#[cfg(unix)]
pub(crate) async fn reload_policies_only(deps: &ReloadDeps) {
    let Some(engine) = deps.cedar.as_ref() else {
        return; // auth disabled (allow-all gate) — no Cedar engine to reload
    };
    // Non-default tenant bundles are ledger-backed, so refresh them even when
    // the default tenant's policy directory is unchanged or temporarily
    // unreadable. A failed read/compile keeps the previous registry intact and
    // leaves its signature due for the next poll.
    let tenant_refresh_error = match refresh_tenant_policy_engines(deps).await {
        Ok(Some(count)) => {
            tracing::info!(tenants = count, "tenant cedar policies reloaded");
            let policy_scopes: Vec<String> = engine.referenced_scopes().into_iter().collect();
            reconcile_policy_scopes(&deps.db_pool, &policy_scopes).await;
            deps.audit
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "PolicyReload",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::PolicyReload)
                    .with_reason(format!(
                        "reloaded policy engines for {count} non-default tenant(s)"
                    )),
                )
                .await;
            None
        }
        Ok(None) => None,
        Err(error) => {
            tracing::error!(%error, "tenant cedar reload failed; keeping previous tenant policy set");
            Some(error.to_string())
        }
    };
    // `read_policy_dir` reads file BYTES (a broken `.cedar` still reads), so a
    // genuine Err here is a missing / unreadable dir — keep the previous engine
    // and let the next tick retry rather than thrash.
    let source = match waygate_policy::read_policy_dir(&deps.policies_dir) {
        Ok(c) => c.source,
        Err(e) => {
            tracing::warn!(error = %e, "policy reload (doorbell/poll): policies dir unreadable; keeping previous set");
            // A refused reload must surface LOUDLY. The
            // gate keeps serving the previous Cedar set (fail-closed), but the
            // operator must see that policies/*.cedar is unreadable — set the
            // banner degraded before returning, exactly as reload_manifests_only
            // does for an unreadable servers dir.
            deps.policy_config_health.set_degraded(format!(
                "policies/*.cedar unreadable ({e}) — serving the previous set"
            ));
            return;
        }
    };
    let disk_hash = waygate_policy::content_hash(&source);
    let changed = deps
        .last_policy_hash
        .lock()
        .expect("last_policy_hash mutex poisoned")
        .as_deref()
        != Some(disk_hash.as_str());

    // (1) Engine swap + audit — only on a real change.
    if changed {
        match compile_policy_source(&deps.policies_dir, &source) {
            Ok(reloaded) => {
                let count = reloaded.list_policies().len();
                // Capture the new policy set's referenced
                // scopes BEFORE the move, reconcile into the registry AFTER
                // the swap. Best-effort — never gates the reload.
                let epoch = deps.pool.tool_catalog_epoch();
                let change = epoch.begin_change();
                engine.reload(reloaded);
                change.commit();
                let policy_scopes: Vec<String> = engine.referenced_scopes().into_iter().collect();
                reconcile_policy_scopes(&deps.db_pool, &policy_scopes).await;
                tracing::info!(policies = count, "cedar policies reloaded (doorbell/poll)");
                deps.audit
                    .record_best_effort(
                        waygate_mcp::AuditEvent::new(
                            "PolicyReload",
                            waygate_mcp::AuditOutcome::Success,
                        )
                        .with_category(waygate_mcp::EvidenceCategory::PolicyReload)
                        .with_reason(format!("reloaded {count} policies (doorbell/poll)")),
                    )
                    .await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cedar reload failed (doorbell/poll); keeping previous policy set");
                deps.audit
                    .record_best_effort(
                        waygate_mcp::AuditEvent::new(
                            "PolicyReload",
                            waygate_mcp::AuditOutcome::ExecutionError,
                        )
                        .with_category(waygate_mcp::EvidenceCategory::PolicyReload)
                        .with_reason(format!("reload failed: {e}")),
                    )
                    .await;
            }
        }
        // Mark this disk state processed for the swap/audit gate, regardless of
        // success: a stuck-broken disk must not re-resolve + re-log every tick. A
        // disk FIX changes the hash and re-triggers; the convergence below still
        // retries every tick independent of this gate.
        *deps
            .last_policy_hash
            .lock()
            .expect("last_policy_hash mutex poisoned") = Some(disk_hash);
    }

    // (2) Policy config-health + convergence — driven EVERY tick from the current
    // on-disk set, NOT gated on `changed`. `policy_source_is_recordable` (parses +
    // non-empty — the publish turnstile's guard) is the authoritative discriminator:
    // it is true iff `resolve_policies` would load disk cleanly, so the running
    // engine is serving a valid disk set. Computing health here (not in the
    // change-gated block above) is what lets a transient unreadable/broken blip
    // that recovers with UNCHANGED bytes clear a stale banner — `changed` is false
    // then, but the on-disk set is healthy again. The read-Err path
    // already set degraded + returned, so this only runs when disk read OK.
    let default_source_healthy = policy_source_is_recordable(&source);
    if default_source_healthy {
        match tenant_refresh_error.as_deref() {
            None => deps.policy_config_health.set_healthy(format!(
                "{} default policy/policies and {} tenant policy set(s) live",
                engine.list_policies().len(),
                engine.tenant_count()
            )),
            Some(error) => deps.policy_config_health.set_degraded(format!(
                "tenant policy reload failed ({error}) — serving the previous tenant policy set"
            )),
        }
        // Convergence on a clean disk: capture an out-of-band edit + reconcile the
        // pointer every tick (idempotent → no-op once converged), so a prior
        // failed/deferred reconcile retries. The parse-guard keeps us
        // from reconciling the pointer to a disk the gate isn't actually running.
        // Snapshot BEFORE reconcile.
        if let Some(store) = deps.policy_store.as_ref() {
            record_out_of_band_policy_snapshot(store, &deps.policies_dir, &deps.audit).await;
            reconcile_policy_pointer(store, &deps.policies_dir, &deps.audit, "filesystem-reload")
                .await;
        }
    } else {
        // Disk read OK but the set is broken (unparseable) or empty: the engine is
        // serving a ledger recovery or the previous set — degraded, even if the
        // bytes are unchanged since the last tick (so a degraded banner persists
        // until disk is fixed).
        deps.policy_config_health.set_degraded(
            "policies/*.cedar is broken or empty — serving a ledger recovery or the previous set"
                .to_owned(),
        );
    }
}

#[cfg(unix)]
pub(crate) async fn reload_once(deps: &ReloadDeps) {
    // Latch fence: observed BEFORE this tick reads the disk set it may
    // import, so a dashboard arm landing after this point survives this
    // tick's successful settle (see `ReconcileLatch`).
    let reconcile_observed = CATALOG_RECONCILE_LATCH.observe();
    // Borrow the fields by name (match ergonomics: each binding is a
    // reference into `deps`). Single `&ReloadDeps` arg keeps the
    // function under clippy's argument-count limit now that the prod
    // safety profile is threaded too.
    // Policy reload: delegate to the single change-detected policy path
    // the policy doorbell + poll backstop also use, so SIGHUP, the doorbell, and
    // the poll converge to identical behavior — and a SIGHUP that changed nothing
    // no longer writes a spurious PolicyReload row. The policy reload, its
    // clean-load out-of-band snapshot, and the pointer reconcile all live in
    // `reload_policies_only`.
    reload_policies_only(deps).await;

    // Manifest reload (SIGHUP path): verbose logging + always-audit (even on a
    // no-op), distinct from the quiet `reload_manifests_only` the doorbell/poll
    // use. Borrow the manifest fields by name; the policy fields and the doorbell
    // pool are handled elsewhere.
    let ReloadDeps {
        servers_dir,
        manifest_store,
        pool,
        audit,
        deployment_profile,
        config_health,
        replica_id,
        ..
    } = deps;

    // Same file-as-truth load as boot (see `resolve_manifests`): a SIGHUP
    // re-reads `servers/*.yaml` directly so an out-of-band edit takes
    // effect without a restart, recovering from the newest ledger snapshot
    // only when the on-disk set is unreadable. `recovered` carries that
    // recovery detail so the config-health signal stays degraded when the
    // running set is a stale recovery rather than a clean on-disk load.
    //
    // Gate the resolved set at activation time too.
    // Boot and `--import-server-bundle` both apply this, but a
    // ledger-recovered set (or a profile that changed to prod after the
    // snapshot was seeded) must not activate a prod-forbidden
    // `transport: stdio` upstream via SIGHUP. Chaining the gate with `map`
    // routes a violation into the same fail-closed `Err` arm as a
    // filesystem failure: log, audit, keep the previous set.
    let resolved = match resolve_manifests(servers_dir, manifest_store.as_ref()).await {
        Ok(ResolvedManifests {
            manifests,
            recovered,
        }) => {
            crate::config::enforce_prod_manifest_safety_for_profile(*deployment_profile, &manifests)
                .map(|()| (manifests, recovered))
        }
        Err(e) => Err(e),
    };
    match resolved {
        Ok((manifests, recovered)) => {
            if manifest_reload_should_defer(manifest_store.as_ref(), &manifests).await {
                return;
            }
            let report = pool.reload_manifests(&manifests).await;
            if report.is_noop() {
                tracing::info!("manifest reload: no changes");
            } else {
                tracing::info!(
                    updated = ?report.classifications_updated,
                    identity_updated = ?report.identity_updated,
                    session_policy_updated = ?report.session_policy_updated,
                    redialed = ?report.redialed,
                    redial_failed = ?report.redial_failed,
                    resource_shape_restart_required = ?report.resource_shape_restart_required,
                    added = ?report.added,
                    removed = ?report.removed,
                    "manifest reload applied",
                );
                if !report.added.is_empty() {
                    tracing::info!(
                        servers = ?report.added,
                        "new upstreams dialed and published live — no restart needed",
                    );
                }
                if !report.removed.is_empty() {
                    tracing::info!(
                        servers = ?report.removed,
                        "removed upstreams drained and dropped from the registry live — no restart needed",
                    );
                }
                if !report.redialed.is_empty() {
                    tracing::info!(
                        servers = ?report.redialed,
                        "connection-shape changes re-dialed or rebuilt live — no restart needed",
                    );
                }
                if !report.redial_failed.is_empty() {
                    tracing::warn!(
                        servers = ?report.redial_failed,
                        "live re-dial/rebuild failed on every lane — these upstreams kept the \
                         previous connection shape; fix the new target or restart to apply",
                    );
                }
                if !report.resource_shape_restart_required.is_empty() {
                    tracing::warn!(
                        servers = ?report.resource_shape_restart_required,
                        "manifest reload refused before mutation because resource ownership and \
                         connection shape changed together; restart to apply the complete set",
                    );
                }
            }
            // ManifestReload evidence event so the activity log records
            // every SIGHUP that touched the manifest set, mirroring the
            // PolicyReload pattern above. Recorded even on no-op so an
            // operator can see "reload fired, nothing changed". Reason
            // carries a compact summary of what shifted; the full
            // payload stays in `tracing` for log-aggregation pipelines.
            // Source-neutral: the resolved set is normally the on-disk
            // `servers/*.yaml` but may be a ledger recovery when that set
            // was unreadable (see `resolve_manifests`), so the reason
            // summarises the diff without claiming a source. The `tracing`
            // line in `resolve_manifests` records which source actually
            // won, and `recovered` drives the config-health signal below.
            let reason = if report.is_noop() {
                "no changes".to_owned()
            } else {
                format!(
                    "added={} removed={} redialed={} redial_failed={} resource_shape_restart_required={} classifications_updated={} identity_updated={} session_policy_updated={}",
                    report.added.len(),
                    report.removed.len(),
                    report.redialed.len(),
                    report.redial_failed.len(),
                    report.resource_shape_restart_required.len(),
                    report.classifications_updated.len(),
                    report.identity_updated.len(),
                    report.session_policy_updated.len(),
                )
            };
            audit
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "ManifestReload",
                        if report.resource_shape_restart_required.is_empty() {
                            waygate_mcp::AuditOutcome::Success
                        } else {
                            waygate_mcp::AuditOutcome::ExecutionError
                        },
                    )
                    .with_category(waygate_mcp::EvidenceCategory::ManifestReload)
                    .with_reason(reason),
                )
                .await;
            // A superseded reload lost the live registry to a
            // newer concurrent reload, so `manifests` is NOT the set now serving.
            // Skip ALL of its control-plane side-effects — the config-health
            // banner, the catalog reconcile, the out-of-band snapshot +
            // turnstile-pointer reconcile (reconcile could CAS the pointer
            // BACKWARD to the losing set), the activation event, and the heartbeat
            // — so the catalog, ledger, pointer, and fleet/audit state only ever
            // reflect the WINNING reload.
            if !report.superseded && report.resource_shape_restart_required.is_empty() {
                // Refresh the config-health signal from the resolved source: a
                // clean on-disk reload is healthy and clears any prior stale
                // banner; a ledger recovery (on-disk set unreadable) stays
                // DEGRADED even though the reload applied — the running set may be
                // stale until servers/*.yaml is fixed.
                let disk_loaded_cleanly = recovered.is_none();
                match recovered {
                    None => config_health.set_healthy(format!(
                        "{} upstream(s) live from servers/*.yaml",
                        manifests.len()
                    )),
                    Some(detail) => config_health.set_degraded(detail),
                }
                // The tool-facts catalog tracks the served set on a CHANGE-detected
                // reload, not only at boot, so a classification change written to
                // the live NFS servers dir takes
                // effect without a restart (authz reads catalog facts ahead of the
                // manifest fallback). Non-fatal: a failed reconcile keeps the
                // existing catalog and arms the pending flag, so the NEXT tick
                // retries even when its pool reload reports no change. Gated on
                // the DB pool and on change-or-pending (no per-tick DB churn).
                if !report.is_noop()
                    || CATALOG_RECONCILE_LATCH.due()
                    || pool.catalog_reconcile_pending()
                {
                    if let Some(catalog_pool) = deps.db_pool.as_ref() {
                        match import_cmd::reconcile_catalog_from_manifests(catalog_pool, &manifests)
                            .await
                        {
                            Ok(stats) => {
                                pool.settle_catalog_reconcile(&report);
                                CATALOG_RECONCILE_LATCH.settle(reconcile_observed);
                                tracing::info!(
                                    servers = stats.servers,
                                    tools = stats.tools,
                                    "catalog reconciled from reloaded manifest set (SIGHUP)",
                                )
                            }
                            Err(e) => {
                                CATALOG_RECONCILE_LATCH.arm();
                                tracing::error!(
                                    error = %e,
                                    "catalog reconcile on reload FAILED (existing catalog preserved; \
                                     the next tick retries even without a manifest change)",
                                )
                            }
                        }
                    }
                }
                // Reconcile the turnstile pointer on a clean SIGHUP reload
                // too — SIGHUP is exactly how an operator applies an
                // out-of-band servers/*.yaml edit, so the pointer must re-sync
                // here, not only on the doorbell/poll backstop or a dashboard
                // Reload.
                if disk_loaded_cleanly {
                    if let Some(store) = manifest_store.as_ref() {
                        // Snapshot BEFORE reconcile (see boot path).
                        record_out_of_band_snapshot(store, &manifests, audit).await;
                        reconcile_manifest_pointer(store, &manifests, audit, "filesystem-sighup")
                            .await;
                    }
                }
                // Per-replica activation event when SIGHUP changed the
                // live set (not on a no-op reload); honest about partial
                // application.
                if !report.is_noop() {
                    record_activation(
                        manifest_store.as_ref(),
                        audit,
                        replica_id,
                        &manifests,
                        !report.requires_restart(),
                    )
                    .await;
                }
                // Refresh the fleet heartbeat on every SIGHUP reload.
                record_heartbeat(manifest_store.as_ref(), replica_id, &manifests).await;
            } else if !report.resource_shape_restart_required.is_empty() {
                config_health.set_degraded(format!(
                    "reload refused — resource ownership and connection shape changed together \
                     for {}; restart required",
                    report.resource_shape_restart_required.join(", ")
                ));
                touch_heartbeat(manifest_store.as_ref(), replica_id).await;
            }
        }
        Err(e) => {
            // Covers a genuine filesystem failure (servers dir) AND a
            // prod safety-gate refusal of a DB-sourced bundle; `{e}`
            // carries the specific cause, so the message stays
            // source-neutral. Either way: keep the previous set.
            tracing::error!(
                error = %e,
                "manifest reload failed or refused; keeping previous manifests",
            );
            audit
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "ManifestReload",
                        waygate_mcp::AuditOutcome::ExecutionError,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::ManifestReload)
                    .with_reason(format!("reload failed or refused: {e}")),
                )
                .await;
            config_health.set_degraded(format!("reload refused — serving the previous set: {e}"));
            // Keep liveness ticking on a failed SIGHUP reload too.
            touch_heartbeat(manifest_store.as_ref(), replica_id).await;
        }
    }

    // Best-effort reconnect for any upstream still disconnected. Reuses the
    // same dial routine as the periodic re-probe task; no-op for entries that
    // are already connected. Gives operators a manual "kick" to recheck right
    // now rather than wait for the next probe tick.
    pool.try_reconnect_disconnected().await;
}

pub(crate) async fn build_authz_gate(
    cfg: &Config,
    policy_store: Option<&waygate_policy::SharedPolicyStore>,
    audit: &SharedEvidence,
    policy_health: &waygate_upstream::SharedConfigHealth,
) -> anyhow::Result<(SharedAuthz, Option<Arc<ReloadableCedar>>, Option<String>)> {
    if matches!(cfg.auth_mode, AuthMode::Disabled) {
        tracing::warn!("auth disabled — authz gate is allow-all. Do not run this in production.");
        // No Cedar set is loaded in allow-all mode; report healthy so the
        // dashboard doesn't show a spurious policy banner.
        policy_health.set_healthy("auth disabled — allow-all gate (no policy set)");
        return Ok((Arc::new(AllowAllGate), None, None));
    }

    // File-as-truth: the on-disk `policies/*.cedar` is the source of
    // truth; the ledger only recovers a broken on-disk set. The `?` is a
    // DELIBERATE fail-closed boot: if disk is unreadable AND the ledger has no
    // recoverable bundle, boot fails. An unreadable live set without a usable
    // ledger must never serve an unrelated configuration source.
    let resolved = resolve_policies(&cfg.policies_dir, policy_store).await?;
    // Drive the policy config-health signal from the
    // load's recovered status — a clean on-disk load is healthy; a ledger
    // recovery is DEGRADED even though resolve_policies returned Ok, because the
    // running set may be stale until policies/*.cedar is fixed.
    match &resolved.recovered {
        None => policy_health.set_healthy(format!(
            "{} policy/policies live from policies/*.cedar",
            resolved.engine.list_policies().len()
        )),
        Some(detail) => {
            tracing::warn!(%detail, "policy set RECOVERED from ledger at boot — fix policies/*.cedar; the running set may be stale");
            policy_health.set_degraded(format!(
                "policies/*.cedar unreadable — serving a ledger recovery: {detail}"
            ));
        }
    }
    // Reconcile the cross-replica turnstile pointer to the live on-disk
    // hash on a CLEAN boot load (seeds it if absent, re-syncs it if an
    // out-of-band edit left it stale), so the publish/rollback CAS has an
    // accurate base and writes don't permanently block. A recovered
    // (broken-disk) boot must
    // NOT reconcile to an unparseable disk's hash — the gate is running the
    // ledger set, not disk; a publish then repairs disk via the turnstile.
    if resolved.recovered.is_none() {
        if let Some(store) = policy_store {
            // Capture an out-of-band `policies/*.cedar` edit (or the
            // disk-wins residue of a ledger-failure / published_at race) as a
            // `filesystem`-attributed ledger row, so the ledger converges to disk.
            // BEFORE the reconcile so its in-flight guard reads the pre-reconcile
            // pointer timestamp.
            record_out_of_band_policy_snapshot(store, &cfg.policies_dir, audit).await;
            reconcile_policy_pointer(store, &cfg.policies_dir, audit, "filesystem-boot").await;
        }
    }
    let engine = resolved.engine;
    let tenant_policies = compile_tenant_policy_engines(policy_store).await?;
    let tenant_signature = tenant_policies.signature.clone();
    let tenant_count = tenant_policies.engines.len();
    // Wrap in ReloadableCedar so SIGHUP can swap the inner engine without
    // rebuilding the gate or the admin state. One Arc, two consumers: the
    // runtime authz gate (via `AuthzEngine` trait) and the admin diagnostics
    // (via tenant-selecting methods on the concrete wrapper).
    let reloadable = Arc::new(ReloadableCedar::new(engine));
    reloadable.replace_tenants_with_fingerprints(tenant_policies.engines);
    if tenant_count > 0 {
        tracing::info!(tenants = tenant_count, "tenant cedar policies loaded");
    }
    let engine_trait: Arc<dyn AuthzEngine> = reloadable.clone();
    Ok((
        Arc::new(CedarGate::new(engine_trait)),
        Some(reloadable),
        Some(tenant_signature),
    ))
}

pub(crate) struct CompiledTenantPolicies {
    pub(crate) signature: String,
    pub(crate) engines: std::collections::HashMap<String, (CedarEngine, String)>,
}

fn tenant_policy_signature(bundles: &[waygate_policy::ActivePolicyBundleSignature]) -> String {
    let mut bundles: Vec<_> = bundles
        .iter()
        .filter(|bundle| bundle.tenant_id != waygate_core::TenantId::DEFAULT)
        .collect();
    bundles.sort_by(|left, right| left.tenant_id.cmp(&right.tenant_id));

    let mut source = String::new();
    for bundle in bundles {
        source.push_str(&bundle.tenant_id);
        source.push('\0');
        source.push_str(&bundle.content_hash);
        source.push('\n');
    }
    waygate_policy::content_hash(&source)
}

fn tenant_policy_ids(bundles: &[waygate_policy::ActivePolicyBundleSignature]) -> Vec<String> {
    let mut ids: Vec<_> = bundles
        .iter()
        .filter(|bundle| bundle.tenant_id != waygate_core::TenantId::DEFAULT)
        .map(|bundle| bundle.tenant_id.clone())
        .collect();
    ids.sort();
    ids
}

fn tenant_policy_fingerprints(
    bundles: &[waygate_policy::ActivePolicyBundleSignature],
) -> Vec<(String, String)> {
    let mut fingerprints: Vec<_> = bundles
        .iter()
        .filter(|bundle| bundle.tenant_id != waygate_core::TenantId::DEFAULT)
        .map(|bundle| (bundle.tenant_id.clone(), bundle.content_hash.clone()))
        .collect();
    fingerprints.sort_by(|left, right| left.0.cmp(&right.0));
    fingerprints
}

pub(crate) async fn compile_tenant_policy_engines(
    policy_store: Option<&waygate_policy::SharedPolicyStore>,
) -> anyhow::Result<CompiledTenantPolicies> {
    let Some(store) = policy_store else {
        return Ok(CompiledTenantPolicies {
            signature: waygate_policy::content_hash(""),
            engines: std::collections::HashMap::new(),
        });
    };

    let mut bundles = store
        .active_bundles()
        .await
        .context("read active tenant policy bundles")?;
    bundles.retain(|bundle| bundle.tenant_id != waygate_core::TenantId::DEFAULT);
    bundles.sort_by(|left, right| left.tenant_id.cmp(&right.tenant_id));

    let mut signature_source = String::new();
    let mut engines = std::collections::HashMap::with_capacity(bundles.len());
    for bundle in bundles {
        let tenant =
            waygate_core::TenantId::parse(bundle.tenant_id.clone()).with_context(|| {
                format!(
                    "invalid tenant id in active policy bundle: {}",
                    bundle.tenant_id
                )
            })?;
        let actual_hash = waygate_policy::content_hash(&bundle.content);
        if actual_hash != bundle.content_hash {
            anyhow::bail!(
                "active policy bundle hash mismatch for tenant {} version {}",
                tenant,
                bundle.version
            );
        }
        let engine = CedarEngine::from_source(&bundle.content).with_context(|| {
            format!(
                "compile active policy bundle for tenant {} version {}",
                tenant, bundle.version
            )
        })?;
        if engine.list_policies().is_empty() {
            anyhow::bail!(
                "active policy bundle for tenant {} version {} contains zero policies",
                tenant,
                bundle.version
            );
        }
        signature_source.push_str(tenant.as_str());
        signature_source.push('\0');
        signature_source.push_str(&actual_hash);
        signature_source.push('\n');
        if engines
            .insert(tenant.to_string(), (engine, actual_hash))
            .is_some()
        {
            anyhow::bail!("multiple active policy bundles returned for tenant {tenant}");
        }
    }

    Ok(CompiledTenantPolicies {
        signature: waygate_policy::content_hash(&signature_source),
        engines,
    })
}

#[cfg(unix)]
pub(crate) async fn refresh_tenant_policy_engines(
    deps: &ReloadDeps,
) -> anyhow::Result<Option<usize>> {
    if deps.policy_store.is_none() {
        return Ok(None);
    }
    let engine = deps
        .cedar
        .as_ref()
        .expect("tenant policy refresh requires a Cedar registry");
    let tenant_generation = engine.tenant_generation();
    let candidate_bundles = deps
        .policy_store
        .as_ref()
        .expect("policy store checked above")
        .active_bundle_signatures()
        .await
        .context("read active tenant policy bundle signatures")?;
    let candidate_signature = tenant_policy_signature(&candidate_bundles);
    let candidate_tenants = tenant_policy_ids(&candidate_bundles);
    let candidate_fingerprints = tenant_policy_fingerprints(&candidate_bundles);
    let live_fingerprints = engine.tenant_policy_fingerprints();
    let live_matches_candidate = live_fingerprints
        .as_ref()
        .is_some_and(|live| live == &candidate_fingerprints);
    let legacy_live_matches_candidate = live_fingerprints.is_none()
        && deps
            .last_tenant_policy_hash
            .lock()
            .expect("last tenant policy hash mutex poisoned")
            .as_deref()
            == Some(candidate_signature.as_str())
        && engine.tenant_ids() == candidate_tenants;
    if live_matches_candidate || legacy_live_matches_candidate {
        // The exact engines currently served already match durable truth. This
        // includes a process-local tenant removal, whose handler has already
        // advanced the catalog epoch; adopting its exact content signature
        // here prevents the doorbell echo from emitting a second change.
        *deps
            .last_tenant_policy_hash
            .lock()
            .expect("last tenant policy hash mutex poisoned") = Some(candidate_signature);
        return Ok(None);
    }

    let compiled = compile_tenant_policy_engines(deps.policy_store.as_ref()).await?;
    // A publish can race the metadata projection and full snapshot reads. Use
    // the full snapshot's verified signature as authority and avoid swapping
    // if it converged back to the engine already being served.
    let mut compiled_fingerprints: Vec<_> = compiled
        .engines
        .iter()
        .map(|(tenant, (_, hash))| (tenant.clone(), hash.clone()))
        .collect();
    compiled_fingerprints.sort_by(|left, right| left.0.cmp(&right.0));
    if engine
        .tenant_policy_fingerprints()
        .is_some_and(|live| live == compiled_fingerprints)
    {
        *deps
            .last_tenant_policy_hash
            .lock()
            .expect("last tenant policy hash mutex poisoned") = Some(compiled.signature);
        return Ok(None);
    }

    let count = compiled.engines.len();
    let epoch = deps.pool.tool_catalog_epoch();
    let change = epoch.begin_change();
    if !engine.replace_tenants_with_fingerprints_if_generation(tenant_generation, compiled.engines)
    {
        return Ok(None);
    }
    change.commit();
    *deps
        .last_tenant_policy_hash
        .lock()
        .expect("last tenant policy hash mutex poisoned") = Some(compiled.signature);
    Ok(Some(count))
}

/// Outcome of [`resolve_manifests`]: the resolved upstream set plus
/// whether it came from the on-disk source of truth or was recovered
/// from the ledger because the on-disk set was unreadable. The caller
/// drives the config-health signal from `recovered`:
/// a clean on-disk load is healthy; a ledger recovery is degraded even
/// though `resolve_manifests` returns `Ok` — the running set may be
/// stale and the operator must fix `servers/*.yaml`.
pub(crate) struct ResolvedManifests {
    pub(crate) manifests: BTreeMap<String, UpstreamManifest>,
    /// `None` ⇒ loaded cleanly from `servers/*.yaml`.
    /// `Some(detail)` ⇒ the on-disk set was unreadable and the running
    /// set was recovered from the newest ledger snapshot; `detail` names
    /// the fault for the operator-facing stale-config banner.
    pub(crate) recovered: Option<String>,
}

/// File-as-truth manifest load (server-config redesign, see
/// `docs/server-config-source-of-truth.md`): the on-disk `servers_dir`
/// is the source of truth. Boot and the SIGHUP reload ([`reload_once`])
/// load it directly. The durable manifest store is no longer consulted
/// for *what to load* — it is the history/rollback ledger and a
/// last-resort recovery source.
///
/// Precedence (inverted from the old store-first dual-read, which had the
/// store win):
/// - the on-disk set loads cleanly ⇒ use it, full stop; the store is
///   not read. An empty dir is a valid zero-upstream set, not a fallback
///   trigger;
/// - the on-disk set is unreadable (a malformed file, or a read error)
///   ⇒ recover from the newest ledger snapshot if one exists, logged
///   loud (the recovered set may be stale — fix the file). This
///   preserves the no-lockout invariant in the new direction: a single
///   broken `*.yaml` never blanks the running upstream set;
/// - unreadable on-disk set AND no usable snapshot (no store, none
///   published, a store error, or a snapshot that won't parse) ⇒
///   propagate the filesystem error so boot fails loud rather than
///   silently serving nothing.
pub(crate) async fn resolve_manifests(
    servers_dir: &std::path::Path,
    manifest_store: Option<&waygate_manifest_store::SharedManifestStore>,
) -> anyhow::Result<ResolvedManifests> {
    // A dir that EXISTS and loads — even to an empty set — is
    // authoritative. A *missing* or non-directory `servers_dir` (an NFS
    // mount that didn't come up, a typoed path) is NOT: `load_manifests`
    // treats a non-existent dir as Ok(empty), which would silently serve
    // zero upstreams, so guard that here and route a missing dir to ledger
    // recovery / fail-loud exactly like a malformed file.
    let fs_result: Result<BTreeMap<String, UpstreamManifest>, String> = if servers_dir.is_dir() {
        match waygate_upstream::manifest_write_in_progress(servers_dir) {
            Ok(false) => load_manifests(servers_dir).map_err(|e| e.to_string()),
            Ok(true) => Err(
                "a coordinated manifest write is in progress or was interrupted; refusing the \
                 incomplete live directory"
                    .to_owned(),
            ),
            Err(error) => Err(format!("could not inspect manifest write marker: {error}")),
        }
    } else {
        Err(format!(
            "manifest dir {} is missing or not a directory (unmounted? typoed?)",
            servers_dir.display()
        ))
    };
    let fs_err = match fs_result {
        Ok(manifests) => {
            tracing::info!(
                count = manifests.len(),
                dir = %servers_dir.display(),
                "loaded upstream manifests from filesystem (source of truth)",
            );
            return Ok(ResolvedManifests {
                manifests,
                recovered: None,
            });
        }
        Err(e) => e,
    };

    // The on-disk set is unreadable. Recover from the ledger snapshot
    // rather than blank the upstream set.
    if let Some(store) = manifest_store {
        match store.active_bundle(waygate_core::TenantId::DEFAULT).await {
            Ok(bundle) => match parse_manifest_set(&bundle.content) {
                Ok(manifests) => {
                    tracing::error!(
                        dir = %servers_dir.display(),
                        fs_error = %fs_err,
                        recovered_version = bundle.version,
                        count = manifests.len(),
                        "on-disk manifest set is unreadable; RECOVERED from ledger \
                         snapshot — fix servers/*.yaml; the recovered set may be stale",
                    );
                    return Ok(ResolvedManifests {
                        manifests,
                        recovered: Some(format!(
                            "on-disk servers/*.yaml is unreadable ({fs_err}); \
                             recovered ledger snapshot v{} — the running set may be stale",
                            bundle.version
                        )),
                    });
                }
                Err(e) => tracing::error!(
                    fs_error = %fs_err,
                    snapshot_error = %e,
                    "on-disk manifest set is unreadable AND the ledger snapshot won't parse",
                ),
            },
            Err(waygate_manifest_store::ManifestError::NotFound(_)) => tracing::error!(
                fs_error = %fs_err,
                "on-disk manifest set is unreadable and no ledger snapshot exists to recover from",
            ),
            Err(e) => tracing::error!(
                fs_error = %fs_err,
                store_error = %e,
                "on-disk manifest set is unreadable and the ledger read failed",
            ),
        }
    }

    Err(anyhow::anyhow!(
        "load manifests from {} (source of truth): {fs_err} — and no usable ledger snapshot to recover from",
        servers_dir.display()
    ))
}

/// Whether a coordinated policy write appears in flight, for the out-of-band
/// capture guard. A publish/rollback CASes the turnstile pointer at
/// its START, so a pointer advanced within [`RECONCILE_GRACE`](waygate_policy::RECONCILE_GRACE)
/// means a write is mid-flight and the disk/ledger drift it produced must NOT be
/// captured as a `filesystem` row. An absent pointer (fresh deploy) is not
/// in-flight. Mirrors `write_in_flight`.
pub(crate) fn policy_write_in_flight(
    pointer: Option<&waygate_policy::PolicyPointer>,
    now: time::OffsetDateTime,
) -> bool {
    pointer.is_some_and(|p| now - p.updated_at < waygate_policy::RECONCILE_GRACE)
}

/// Whether the on-disk policy set (`disk_source` = `read_policy_dir(dir).source`)
/// has drifted from the active ledger bundle's content. Compares the
/// two Cedar sources on a **trailing-newline-insensitive** basis, because the
/// stored bundle `content` carries a *different number* of trailing newlines
/// depending on which path produced it, while disk source always carries
/// `read_policy_dir`'s per-file newline(s):
///
/// - a dashboard publish/rollback stores the submitted bytes (no trailing `\n`);
/// - this recorder's `capture_content` strips exactly one trailing `\n`;
/// - `--import-policies` stores `read_policy_dir(...).source` **verbatim** —
///   already carrying the per-file `\n` (and `\n\n` when a source file ended in
///   its own newline).
///
/// Hashing `canonical_policy_disk_hash(active.content)` (which *appends* one `\n`)
/// against the raw disk hash double-counted the newline for an imported bundle
/// whose bytes already equalled disk, so every imported deploy's first clean
/// boot/SIGHUP recorded a spurious `filesystem` snapshot even though
/// `policies/*.cedar` had not changed. Cedar ignores trailing
/// whitespace, so trimming trailing `\n` from both sides is the
/// representation-agnostic comparison: it still flags any real byte change to the
/// source tree (correct under disk-is-truth) while ignoring storage-layer newline
/// noise. Returns `false` when the active content can't parse as Cedar — don't
/// synthesize a convergence row off an unparseable ledger row.
pub(crate) fn policy_disk_drifted_from_active(active_content: &str, disk_source: &str) -> bool {
    if CedarEngine::from_source(active_content).is_err() {
        return false;
    }
    !waygate_policy::policy_sources_equivalent(active_content, disk_source)
}

/// Whether a freshly-read on-disk policy source is safe to record into the
/// ledger as the active set: it must parse as Cedar AND contain at
/// least one policy. The out-of-band recorder re-reads disk independently of the
/// boot/SIGHUP load it was gated behind, so a concurrent out-of-band edit could
/// have made disk unparseable or empty between the two reads — recording
/// that would poison recovery. Same guard the publish turnstile applies before
/// it accepts a disk set (`waygate-admin`'s `policy_turnstile_claim`).
pub(crate) fn policy_source_is_recordable(source: &str) -> bool {
    CedarEngine::from_source(source).is_ok_and(|engine| !engine.list_policies().is_empty())
}

/// Probe whether the policies directory accepts writes — a dashboard publish
/// mirrors the bundle onto `policies/*.cedar`, so a read-only mount (the
/// live volume mounted read-only) can't be edited. True iff a probe
/// file can be created + removed. Used at boot to disable policy editing cleanly
/// rather than letting a publish fail at the disk mirror.
pub(crate) fn policies_dir_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(format!(".mcpgw-write-probe-{}", std::process::id()));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Converge the policy ledger to the current on-disk set (disk is the source of
/// truth), as a `filesystem`-attributed bundle. Two cases:
///
/// - **No active bundle yet** (fresh deploy, never `--import-policies`'d) — SEED
///   the initial ledger v1 from disk, so the dashboard editor (which gates on an
///   active bundle existing) works out of the box rather than waiting on a manual
///   import. This fills the documented first-publish gap.
/// - **Active bundle exists, disk drifted** — an out-of-band git edit to
///   `policies/*.cedar`, OR the disk-wins residue of a ledger-failure /
///   `published_at` race — capture it as a new version so the state is
///   visible in history and rollback-able.
///
/// Best-effort: every failure is logged, never fails boot/reload. The caller
/// gates on a CLEAN load (`recovered.is_none()`), but this is a SECOND,
/// independent read of disk, so the re-read source is itself re-validated
/// before it can reach the ledger. The drift CHECK only applies when
/// there's already an active bundle (nothing to compare against otherwise), but
/// the in-flight-write guard runs in BOTH cases — a first dashboard
/// publish claims the turnstile + mirrors disk before its ledger row, so even the
/// seed path must defer to it rather than racing it into a duplicate `filesystem`
/// row. Mirrors `record_out_of_band_snapshot`.
pub(crate) async fn record_out_of_band_policy_snapshot(
    store: &waygate_policy::SharedPolicyStore,
    policies_dir: &std::path::Path,
    audit: &SharedEvidence,
) {
    let source = match waygate_policy::read_policy_dir(policies_dir) {
        Ok(c) => c.source,
        Err(e) => {
            tracing::warn!(error = %e, "out-of-band policy snapshot: policies dir unreadable; skipping");
            return;
        }
    };
    // Re-validate the just-read disk source. The caller gated on a
    // clean `resolve_policies` load, but that was an EARLIER read; this recorder
    // re-reads disk independently, and a concurrent out-of-band edit landing
    // between the two reads could leave disk unparseable or empty.
    // Recording that as the active `filesystem` bundle would poison recovery
    // (the gate runs disk, but a later reader recovering from a broken disk would
    // get this empty/broken set) until a valid snapshot overwrites it — so skip,
    // exactly as the publish turnstile refuses a broken/empty disk.
    if !policy_source_is_recordable(&source) {
        tracing::warn!(
            "out-of-band policy snapshot: re-read policies/*.cedar is empty or does not parse; \
             skipping capture (a concurrent edit may be racing boot/reload)"
        );
        return;
    }
    let active = match store.active_bundle(waygate_core::TenantId::DEFAULT).await {
        Ok(b) => Some(b),
        // No published bundle yet (fresh deploy / never imported): seed the
        // initial ledger from disk below. `record_filesystem_snapshot` publishes
        // v1 when there's no active bundle.
        Err(waygate_policy::PolicyError::NotFound(_)) => None,
        Err(e) => {
            tracing::warn!(error = %e, "policy ledger convergence: active-bundle read failed; skipping");
            return;
        }
    };
    // The DRIFT check needs an active bundle to compare against; with none, we
    // skip straight to the in-flight guard + seed.
    if let Some(active) = active.as_ref() {
        if !policy_disk_drifted_from_active(&active.content, &source) {
            return; // disk matches the latest published set — nothing out-of-band.
        }
    }
    // In-flight-write guard — also covers the seed path (no active bundle yet):
    // a coordinated publish/rollback mirrors disk to the new content BEFORE its
    // ledger transition, so during that window disk is legitimately ahead of the
    // ledger and this "drift" is a dashboard write mid-flight, NOT an out-of-band
    // edit. The write CASes the pointer at its START, so a pointer advanced within
    // the grace window means a write is in flight — defer. This applies EVEN with
    // no active bundle: the FIRST dashboard publish also claims the turnstile +
    // mirrors disk before `store.publish`, so a reload racing that window would
    // otherwise seed the in-flight publish's content as a `filesystem` row,
    // duplicating / misattributing the first publish. An out-of-band edit bypasses
    // the turnstile, so the pointer carries the last coordinated write's (older)
    // timestamp; a fresh deploy's pointer is absent (not in flight). (Runs BEFORE
    // the reconcile at each site, so the timestamp is pre-reconcile.)
    match store.read_pointer(waygate_core::TenantId::DEFAULT).await {
        Ok(pointer) => {
            if policy_write_in_flight(pointer.as_ref(), time::OffsetDateTime::now_utc()) {
                tracing::debug!("policy ledger convergence: pointer advanced within the grace window; deferring (a coordinated write may be mid mirror-to-ledger)");
                return;
            }
        }
        // Fail safe: a pointer read failure means we cannot rule out a
        // coordinated write mid mirror-to-ledger; recording its content as a
        // `filesystem` row is exactly the harm this guard prevents. Defer.
        Err(e) => {
            tracing::warn!(error = %e, "policy ledger convergence: pointer read failed; deferring (cannot rule out an in-flight write)");
            return;
        }
    }
    // Record the disk source MINUS its trailing newline: `read_policy_dir`
    // re-appends one newline per file, so a later rollback/mirror of this row
    // reproduces disk exactly — no re-drift, no newline accumulation across
    // capture cycles.
    let capture_content = source.strip_suffix('\n').unwrap_or(&source);
    match store
        .record_filesystem_snapshot(waygate_core::TenantId::DEFAULT, capture_content)
        .await
    {
        Ok(Some(bundle)) => {
            // Distinguish the initial SEED (no prior active bundle — a normal first
            // boot, INFO) from CONVERGENCE (disk drifted from an existing bundle —
            // an out-of-band change worth surfacing, WARN) in the log + audit.
            let reason = if active.is_none() {
                tracing::info!(
                    version = bundle.version,
                    hash = %bundle.content_hash,
                    "seeded the initial policy ledger from policies/*.cedar on boot \
                     (the dashboard editor is now available)",
                );
                format!(
                    "seeded initial policy ledger v{} from policies/*.cedar (filesystem) — \
                     disk is the source of truth",
                    bundle.version
                )
            } else {
                tracing::warn!(
                    version = bundle.version,
                    hash = %bundle.content_hash,
                    "captured an out-of-band policies/*.cedar edit as a filesystem ledger row \
                     (converged the ledger to disk)",
                );
                format!(
                    "captured out-of-band policies/*.cedar edit as v{} (filesystem) — \
                     converged the ledger to disk",
                    bundle.version
                )
            };
            audit
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "policy.filesystem_snapshot",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::PolicyReload)
                    .with_reason(reason),
                )
                .await;
        }
        Ok(None) => {
            tracing::debug!("policy ledger convergence: disk already matches the active ledger bundle; nothing to record")
        }
        Err(e) => {
            tracing::warn!(error = %e, "policy ledger convergence: record failed (non-fatal; the next reload retries)")
        }
    }
}

/// Reconcile the policy turnstile pointer to the CURRENT on-disk
/// hash. Subsumes the boot seed: `reconcile_pointer` seeds an absent
/// pointer, leaves an in-sync one, defers a recently-advanced (mid-write) one,
/// and re-syncs a STALE one (an out-of-band `policies/*.cedar` edit, or a git
/// deploy + restart where the persisted pointer survived but disk changed and
/// `seed_pointer`'s `ON CONFLICT DO NOTHING` left it stale). Without this re-sync
/// every later `cas_pointer` loses and dashboard/API policy writes permanently
/// block — the same footgun the manifest turnstile pointer guards against.
/// Callers run it on boot (clean load), SIGHUP/doorbell reload, and dashboard
/// Reload.
///
/// Best-effort: a DB hiccup logs a `WARN` and never fails boot/reload (the gate
/// already loaded the policies from disk; the pointer is coordination state, not
/// the boot source). The disk hash is `content_hash(read_policy_dir(dir).source)`
/// — the SAME value a writer's CAS target (`canonical_policy_disk_hash`) computes,
/// so they agree. Mirrors [`reconcile_manifest_pointer`].
pub(crate) async fn reconcile_policy_pointer(
    store: &waygate_policy::SharedPolicyStore,
    policies_dir: &std::path::Path,
    audit: &SharedEvidence,
    actor: &str,
) {
    let source = match waygate_policy::read_policy_dir(policies_dir) {
        Ok(c) => c.source,
        Err(e) => {
            tracing::debug!(error = %e, dir = %policies_dir.display(), "policy pointer reconcile skipped: policies dir unreadable");
            return;
        }
    };
    let disk_hash = waygate_policy::content_hash(&source);
    match store
        .reconcile_pointer(waygate_core::TenantId::DEFAULT, &disk_hash, actor)
        .await
    {
        Ok(waygate_policy::PointerReconcile::Advanced { from }) => {
            tracing::warn!(
                from = %from,
                to = %disk_hash,
                %actor,
                "policy turnstile pointer reconciled to the on-disk hash (out-of-band policies/*.cedar edit detected)",
            );
            audit
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "policy.pointer_reconciled",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::PolicyReload)
                    .with_reason(format!(
                        "reconciled policy turnstile pointer {from} -> {disk_hash} ({actor}); \
                         out-of-band policies/*.cedar edit",
                    )),
                )
                .await;
        }
        Ok(other) => {
            tracing::debug!(
                ?other,
                "policy turnstile pointer reconcile: no advance needed"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "policy turnstile pointer reconcile failed (non-fatal; the next reload retries)");
        }
    }
}

/// Outcome of [`resolve_policies`] — the live Cedar engine plus whether it came
/// from disk (the source of truth) or had to be recovered from the ledger.
pub(crate) struct ResolvedPolicies {
    pub(crate) engine: CedarEngine,
    /// `None` ⇒ loaded cleanly from `policies/*.cedar`.
    /// `Some(detail)` ⇒ the on-disk set was unreadable and the policy set was
    /// recovered from the newest ledger bundle; `detail` names the fault for
    /// the operator-facing policy config-health banner
    /// (`build_authz_gate` / `reload_policies_only` drive `policy_config_health`
    /// from this field).
    pub(crate) recovered: Option<String>,
}

/// Register every scope a loaded Cedar policy
/// references (`source='policy'`) in the scope registry, so the catalog —
/// and the catalog-only mint check — knows about it even when no key or
/// built-in carries it. Best-effort and non-blocking: a DB error is logged
/// and dropped (it must never gate a policy reload, per the "a botched
/// policy must not lock out" invariant). No-op when the DB / scope store
/// isn't wired, or when the policy set references no scopes.
///
/// Deliberately NOT `#[cfg(unix)]`: the boot reconcile calls it on every
/// platform. The Unix-only reload path (`reload_policies_only`) calls it
/// too, but that call is compiled out with the reload fn on non-Unix.
pub(crate) async fn reconcile_policy_scopes(db_pool: &Option<PgPool>, scope_names: &[String]) {
    use waygate_apikeys::ScopeStore as _;
    let Some(pool) = db_pool.as_ref() else {
        return;
    };
    if scope_names.is_empty() {
        return;
    }
    let store = waygate_apikeys::PgScopeStore::new(pool.clone());
    match store.upsert_policy_scopes(scope_names).await {
        Ok(n) if n > 0 => {
            tracing::info!(
                count = n,
                "scope registry: registered policy-referenced scope(s)"
            )
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(
            error = %e,
            "scope registry: policy-scope reconcile failed (non-fatal; catalog may lag policies)",
        ),
    }
}

/// File-as-truth Cedar load (see `docs/server-config-source-of-truth.md`): the
/// on-disk `policies_dir`
/// is the SOURCE OF TRUTH. Boot ([`build_authz_gate`]) and the SIGHUP reload
/// ([`reload_once`]) load it directly. The durable policy store
/// (`policy_bundles`) is consulted ONLY to RECOVER when the on-disk set is
/// unreadable — it is the history / rollback ledger, no longer the boot source.
///
/// This inverts the old store-first dual-read so an operator editing
/// `policies/*.cedar` by hand — or a git-PR deploy that drops new `.cedar`
/// files — is authoritative, matching the manifest model ([`resolve_manifests`]).
/// The no-lockout invariant is preserved: a broken on-disk set never blanks the
/// policy engine; it recovers from the ledger snapshot (or, with no usable
/// snapshot, boot fails loud rather than serving an empty — deny-nothing or
/// allow-nothing — policy set).
pub(crate) async fn resolve_policies(
    policies_dir: &std::path::Path,
    policy_store: Option<&waygate_policy::SharedPolicyStore>,
) -> anyhow::Result<ResolvedPolicies> {
    // Read and compile one owned snapshot. A writer may replace files at any
    // time, so re-reading during compilation could install bytes that do not
    // match the hash and lifecycle generation attributed to this load.
    let fs_err = match waygate_policy::read_policy_dir(policies_dir) {
        Ok(contents) => match compile_policy_source(policies_dir, &contents.source) {
            Ok(engine) => {
                tracing::info!(dir = %policies_dir.display(), "loaded Cedar policy set from filesystem (source of truth)");
                return Ok(ResolvedPolicies {
                    engine,
                    recovered: None,
                });
            }
            Err(error) => error.to_string(),
        },
        Err(error) => error.to_string(),
    };

    // A missing, unreadable, malformed, empty, or comment-only directory is
    // treated as unusable. It must not win over a valid ledger bundle because
    // installing a zero-policy engine would create an unintended deny-all set.
    // This mirrors the `--import-policies` empty guard.

    // The on-disk policy set is unreadable. Recover from the ledger bundle
    // rather than lock the operator out of a running gateway.
    if let Some(store) = policy_store {
        match store.active_bundle(waygate_core::TenantId::DEFAULT).await {
            // A recovered bundle must ALSO be non-empty: the publish / import
            // write paths only reject blank text + parse errors, so a
            // zero-policy (comment-only) bundle can exist in the ledger.
            // Installing it on a broken-disk boot would be the same empty
            // deny-all hazard as the disk path. Treat an empty
            // recovered bundle as "no usable snapshot" and fall through to the
            // hard error.
            Ok(bundle) => match CedarEngine::from_source(&bundle.content) {
                Ok(engine) if !engine.list_policies().is_empty() => {
                    tracing::error!(
                        dir = %policies_dir.display(),
                        fs_error = %fs_err,
                        recovered_version = bundle.version,
                        "on-disk policies/*.cedar is unreadable; RECOVERED from ledger \
                         bundle — fix the policies dir; the recovered set may be stale",
                    );
                    return Ok(ResolvedPolicies {
                        engine,
                        recovered: Some(format!(
                            "on-disk policies/*.cedar is unreadable ({fs_err}); recovered \
                             ledger bundle v{} — the running policy set may be stale",
                            bundle.version
                        )),
                    });
                }
                Ok(_empty) => tracing::error!(
                    fs_error = %fs_err,
                    recovered_version = bundle.version,
                    "on-disk policies unreadable AND the ledger bundle is empty (zero policies) \
                     — refusing to install an empty deny-all set",
                ),
                Err(e) => tracing::error!(
                    fs_error = %fs_err,
                    snapshot_error = %e,
                    "on-disk policies unreadable AND the ledger bundle won't parse",
                ),
            },
            Err(waygate_policy::PolicyError::NotFound(_)) => tracing::error!(
                fs_error = %fs_err,
                "on-disk policies unreadable and no ledger bundle exists to recover from",
            ),
            Err(e) => tracing::error!(
                fs_error = %fs_err,
                store_error = %e,
                "on-disk policies unreadable and the ledger read failed",
            ),
        }
    }

    Err(anyhow::anyhow!(
        "load Cedar policies from {} (source of truth): {fs_err} — and no usable ledger \
         bundle to recover from",
        policies_dir.display()
    ))
}

/// Compile one already-read policy snapshot without consulting the filesystem
/// again. A reload hashes this same source before calling here, so the engine,
/// stored hash, cursor invalidation, and list-change notification all describe
/// one policy generation even when an operator writes a newer set concurrently.
pub(crate) fn compile_policy_source(
    policies_dir: &std::path::Path,
    source: &str,
) -> anyhow::Result<CedarEngine> {
    let engine = CedarEngine::from_source(source)
        .with_context(|| format!("load Cedar policies from {}", policies_dir.display()))?;
    if engine.list_policies().is_empty() {
        anyhow::bail!(
            "policies dir {} loaded ZERO policies (empty or comment-only — mis-mounted / \
             empty volume?); refusing to install an empty deny-all set",
            policies_dir.display()
        );
    }
    Ok(engine)
}

/// Filesystem Cedar load used by tests that exercise the current disk state.
/// A missing dir is an ERROR (not an empty allow/deny-nothing set), so an
/// unmounted / typoed `GATEWAY_POLICIES_DIR` cannot be mistaken for a valid
/// empty policy set.
#[cfg(test)]
pub(crate) fn load_cedar_from_dir(policies_dir: &std::path::Path) -> anyhow::Result<CedarEngine> {
    if !policies_dir.exists() {
        anyhow::bail!(
            "GATEWAY_POLICIES_DIR does not exist: {} (unmounted? typoed? \
             set GATEWAY_AUTH_MODE=disabled for dev)",
            policies_dir.display()
        );
    }
    let engine = CedarEngine::load_dir(policies_dir)
        .with_context(|| format!("load Cedar policies from {}", policies_dir.display()))?;
    tracing::info!(dir = %policies_dir.display(), "loaded Cedar policy set from filesystem (source of truth)");
    Ok(engine)
}

#[cfg(test)]
mod policies_dir_writable_tests {
    use super::policies_dir_writable;

    #[test]
    fn true_for_a_writable_dir_and_cleans_up_the_probe() {
        let dir = std::env::temp_dir().join(format!("polwrite-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            policies_dir_writable(&dir),
            "a freshly-created tmp dir must report writable",
        );
        // The probe file is removed — the check leaves no stray files behind.
        let leftover: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(
            leftover.is_empty(),
            "write-probe must be cleaned up, found {} entries",
            leftover.len(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn false_for_a_nonexistent_dir() {
        // A missing / unmounted policies dir can't accept the probe write, so
        // editing is disabled cleanly instead of crash-looping at the first
        // publish. Portable and root-safe (no chmod): writing into a missing dir
        // always fails, even as root — unlike a 0o555 chmod that root bypasses.
        let dir = std::env::temp_dir().join(format!("polmissing-{}", uuid::Uuid::now_v7()));
        assert!(!dir.exists(), "precondition: dir must not exist");
        assert!(
            !policies_dir_writable(&dir),
            "a non-existent dir must report not-writable",
        );
    }
}
