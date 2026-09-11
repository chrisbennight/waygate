//! Manifest reload, reconnect, and drift detection for the pool — split out
//! of `pool/mod.rs`. Child module of [`super`], so no visibility changes.

use super::*;

/// What changed during a [`UpstreamPool::reload_manifests`] call.
/// `added` / `removed` are now hot-applied (the entry is dialed-and-published or
/// drained-and-dropped live), and every connection-shape change is re-dialed or
/// REBUILT live, landing in `redialed` / `redial_failed`. A shape change coupled
/// to a resource-ownership change is refused before either field mutates and
/// lands in `resource_shape_restart_required`. See
/// [`requires_restart`](ReloadReport::requires_restart).
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ReloadReport {
    /// Internal fence token for the manifest generation this report applied.
    /// Kept off the serialized operator surface; callers pass the report back
    /// to `settle_catalog_reconcile` after the matching full-set import.
    #[serde(skip)]
    pub(super) catalog_generation: u64,
    pub classifications_updated: Vec<String>,
    /// Upstreams whose hot-reloadable identity-chaining fields changed
    /// (`exchange` / `tier_a_required` / `tier_c_peer`). These are applied
    /// in place like classifications. Tracked separately so a bundle that
    /// touches only these is not mis-reported as a no-op.
    pub identity_updated: Vec<String>,
    /// Upstreams whose request-path setup-recovery policy changed without a
    /// connection replacement. Kept separate from connection shape so a
    /// policy-only reload is observable and never misreported as a no-op.
    pub session_policy_updated: Vec<String>,
    /// Upstreams whose connection-shape changed (transport / url / command /
    /// auth / mtls / session) and were re-dialed or REBUILT live (no restart),
    /// adopting the new shape with a fresh identity cell, a re-resolved bearer,
    /// and freshly read mTLS material. Two mechanisms land here:
    ///
    ///   - same slot count ⇒ the existing session(s) are torn down and
    ///     re-dialed in place (`redial_entry`), and
    ///   - a slot-count-changing edit (stdio↔network flip or `session.concurrency`
    ///     change) ⇒ a fresh entry with the new slot count is dialed and swapped
    ///     into the registry under the structural fence, the old entry draining
    ///     via its `Arc`. This retired the old restart-required
    ///     `transport_changed` bucket.
    ///
    /// At least one lane adopted the new shape; a same-count redial whose lane
    /// failed was marked down for the re-probe to heal from the now-advanced
    /// manifest.
    pub redialed: Vec<String>,
    /// Upstreams whose connection-shape changed but EVERY new-shape dial failed —
    /// so the OLD entry was kept whole and keeps serving (availability preserved,
    /// old/old self-consistent). Covers both a failed same-count redial (stored
    /// manifest left on the old shape) and a failed slot-resize rebuild (the
    /// fresh entry was discarded, the old one never replaced). The change is NOT
    /// applied, so this counts as restart-required: the activation audit must not
    /// claim it landed.
    pub redial_failed: Vec<String>,
    /// Existing upstreams whose connection shape and resource ownership changed
    /// in the same manifest set. The complete reload is refused before dialing or
    /// mutation, because routing claims must become visible atomically with the
    /// backend that serves them. Apply the set through a process restart instead.
    pub resource_shape_restart_required: Vec<String>,
    /// Upstreams newly listed in the fresh set and dialed-and-published into the
    /// live registry + search index by this reload (hot add — no restart). A
    /// failed initial dial still adds the entry (slots down); the re-probe heals
    /// it, exactly like a boot-time dial failure. A re-add of a previously
    /// hot-removed server also lands here (it is built fresh).
    pub added: Vec<String>,
    /// Upstreams dropped from the fresh set and tombstoned, drained, removed
    /// from the registry map, and pulled from the search index by this reload
    /// (hot remove — no restart). In-flight callers hold their own `Arc` and
    /// drain naturally; new lookups miss immediately.
    pub removed: Vec<String>,
    /// True when this reload's manifest set is NOT the one now live, so its
    /// callers MUST skip ALL control-plane writes (activation, heartbeat,
    /// turnstile-pointer reconcile, out-of-band snapshot, config-health) — fleet /
    /// audit / ledger state must never claim the replica is serving a set that
    /// isn't live. Two causes, both concurrent-reload races:
    ///   - SUPERSEDED at the structural commit by a newer reload (its generation
    ///     was below `applied_reload_gen`): it abandoned its structural
    ///     changes.
    ///   - a kept upstream was concurrently REMOVED before this reload could
    ///     restore it (a fresh key absent from both its dialed adds and the live
    ///     map): the registry can't match `fresh` this tick, and the poll /
    ///     doorbell backstop converges it.
    ///
    /// The in-place fields above may still be non-empty (work attempted in stage 1,
    /// some of which a newer reload overwrote), so this is checked SEPARATELY from
    /// `is_noop`.
    pub superseded: bool,
}

/// Result of forcing a healthy upstream through a fresh MCP initialization and
/// republishing the manifest-classified tool inventory from its new session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CatalogRefreshReport {
    pub server: String,
    pub outcome: CatalogRefreshOutcome,
    pub session_replaced: bool,
    pub before_tool_count: usize,
    pub after_tool_count: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Existing tool names whose advertised descriptor changed, including
    /// input/output schemas and other MCP Tool metadata.
    pub schema_changed: Vec<String>,
}

/// Whether a forced upstream catalog refresh changed the published inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogRefreshOutcome {
    Updated,
    Unchanged,
    Failed,
    Superseded,
    Removed,
}

impl CatalogRefreshOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
            Self::Removed => "removed",
        }
    }
}

impl ReloadReport {
    pub fn is_noop(&self) -> bool {
        self.classifications_updated.is_empty()
            && self.identity_updated.is_empty()
            && self.session_policy_updated.is_empty()
            && self.redialed.is_empty()
            && self.redial_failed.is_empty()
            && self.resource_shape_restart_required.is_empty()
            && self.added.is_empty()
            && self.removed.is_empty()
    }

    /// Whether this reload changed something the hot path CANNOT apply, so the
    /// replica is NOT yet serving the new config and a restart is required.
    /// Two cases are restart-required:
    ///   - `redial_failed` — a connection-shape change whose every new-shape dial
    ///     failed (a same-count redial OR a slot-resize rebuild), so the OLD
    ///     shape is still serving and the new one never landed.
    ///   - `resource_shape_restart_required` — connection shape and resource
    ///     ownership changed together, so the complete manifest-set reload was
    ///     refused before mutation to preserve backend/routing atomicity.
    ///
    /// `classifications_updated`, `identity_updated`, `session_policy_updated`,
    /// `redialed` (including the
    /// slot-resize rebuilds that retired the old `transport_changed` bucket), AND
    /// `added` / `removed` are all applied in place / live, so a reload touching
    /// only those is fully active. Used so the per-replica activation audit
    /// doesn't claim a replica activated a config whose
    /// connection-shape it hasn't applied.
    pub fn requires_restart(&self) -> bool {
        !self.redial_failed.is_empty() || !self.resource_shape_restart_required.is_empty()
    }
}

impl UpstreamPool {
    /// Whether a live authorization-input transition is waiting for its
    /// full-set catalog reconcile. Reload callers include this in their retry
    /// condition so a superseded/failed attempt cannot strand the fence.
    pub fn catalog_reconcile_pending(&self) -> bool {
        self.catalog_transitions
            .read()
            .expect("catalog transition lock poisoned")
            .values()
            .any(|transition| transition.pending)
    }

    /// Clear transitions covered by a successful full-set reconcile for this
    /// reload generation. A newer concurrent reload carries a higher token and
    /// remains fenced until its own manifest set reaches the catalog.
    pub fn settle_catalog_reconcile(&self, report: &ReloadReport) {
        let change = self.tool_catalog_epoch.begin_change();
        let mut settled = false;
        for transition in self
            .catalog_transitions
            .write()
            .expect("catalog transition lock poisoned")
            .values_mut()
        {
            if transition.pending && transition.generation <= report.catalog_generation {
                transition.pending = false;
                settled = true;
            }
        }
        if settled {
            change.commit();
        }
    }

    pub(super) fn catalog_transition_state(
        &self,
        server: &str,
        tool: &str,
    ) -> Option<CatalogTransition> {
        self.catalog_transitions
            .read()
            .expect("catalog transition lock poisoned")
            .get(&(server.to_owned(), tool.to_owned()))
            .copied()
    }

    fn mark_catalog_transitions(
        &self,
        server: &str,
        tools: impl IntoIterator<Item = String>,
        generation: u64,
    ) {
        if self.catalog.is_none() {
            return;
        }
        let mut pending = self
            .catalog_transitions
            .write()
            .expect("catalog transition lock poisoned");
        for tool in tools {
            pending
                .entry((server.to_owned(), tool))
                .and_modify(|current| {
                    if generation >= current.generation {
                        *current = CatalogTransition {
                            generation,
                            pending: true,
                        };
                    }
                })
                .or_insert(CatalogTransition {
                    generation,
                    pending: true,
                });
        }
    }
}

/// Tools present in the target manifest whose authorization-bearing manifest
/// declaration changes. Removed tools stop being published by the pool; the
/// fence covers calls that can become newly or differently authorized.
fn changed_classified_tools(current: &UpstreamManifest, target: &UpstreamManifest) -> Vec<String> {
    if current.classification_mode != target.classification_mode
        || current.approval_mode != target.approval_mode
    {
        return target.tools.iter().map(|tool| tool.name.clone()).collect();
    }
    let current_by_name: HashMap<&str, &crate::ToolClassification> = current
        .tools
        .iter()
        .map(|tool| (tool.name.as_str(), tool))
        .collect();
    target
        .tools
        .iter()
        .filter(|tool| current_by_name.get(tool.name.as_str()).copied() != Some(*tool))
        .map(|tool| tool.name.clone())
        .collect()
}

/// Outcome of a live [`UpstreamPool::redial_entry`].
#[derive(Clone, Copy)]
enum RedialOutcome {
    /// ≥1 lane adopted the new shape and the stored manifest advanced — the
    /// change is live (no restart).
    Redialed,
    /// Every new-shape dial failed; the old shape was kept and is still serving.
    /// The change has NOT landed (restart-required).
    Failed,
    /// A concurrent reload tombstoned the entry mid-redial; the dialed sessions
    /// were dropped. Nothing to report — the entry is being retired.
    Tombstoned,
    /// A newer concurrent re-dial committed a different connection shape while
    /// this one was dialing, so the commit-time CAS failed. The stale dial was
    /// discarded rather than rolling the shape back. Reported
    /// as neither `redialed` nor `redial_failed` — the concurrent winner owns
    /// the current shape and its reload reports the outcome.
    Superseded,
}

#[derive(Clone, Copy)]
enum RedialSource {
    ConnectionShape,
    CatalogRefresh,
}

struct RedialFailure {
    class: UpstreamErrorClass,
    detail: String,
}

fn partial_redial_error_class(
    down_lanes: usize,
    last_failure: Option<&RedialFailure>,
) -> Option<UpstreamErrorClass> {
    if down_lanes == 0 {
        None
    } else {
        last_failure.map(|failure| failure.class)
    }
}

impl RedialSource {
    fn publish_label(self) -> &'static str {
        match self {
            Self::ConnectionShape => "redial",
            Self::CatalogRefresh => "catalog_refresh",
        }
    }
}

struct CatalogPublication<'a> {
    source: &'static str,
    classifications: &'a [crate::ToolClassification],
    classification_mode: crate::ClassificationMode,
    previous_tools: &'a [Tool],
    live_tools: Option<&'a [Tool]>,
}

/// Whether two manifests agree on EVERY field a [`UpstreamPool::redial_entry`]
/// commit writes: the connection-shape fields (transport / url / command / auth
/// / mtls / session) AND the coupled identity fields (exchange /
/// tier_a_required / tier_c_peer) that a re-dial now advances atomically with
/// the shape. Used as the commit-time CAS: a re-dial advances the stored
/// manifest only if every field it is about to write still equals what it
/// dialed FROM, so a slow older re-dial can neither roll back a newer one's
/// shape NOR clobber a newer reload's identity / Authorization posture.
/// Classification (`tools`) is deliberately excluded — it is not
/// written here and is allowed to drift in the same reload set.
fn connection_shape_eq(a: &UpstreamManifest, b: &UpstreamManifest) -> bool {
    matches_transport(&a.transport, &b.transport)
        && a.protocol == b.protocol
        && a.url == b.url
        && a.command == b.command
        && auth_eq(a.auth.as_ref(), b.auth.as_ref())
        && a.mtls == b.mtls
        && session_connection_shape_eq(a.session.as_ref(), b.session.as_ref())
}

/// Compare only the session fields that shape live connections. Setup-retry
/// policy is read per invocation and hot-applies without replacing healthy
/// sessions.
fn session_connection_shape_eq(
    a: Option<&crate::SessionConfig>,
    b: Option<&crate::SessionConfig>,
) -> bool {
    let mut a = a.cloned().unwrap_or_default();
    let mut b = b.cloned().unwrap_or_default();
    a.retry_on_setup_failure = None;
    b.retry_on_setup_failure = None;
    a == b
}

fn setup_retry_policy_eq(a: &UpstreamManifest, b: &UpstreamManifest) -> bool {
    a.session
        .as_ref()
        .and_then(|session| session.retry_on_setup_failure)
        == b.session
            .as_ref()
            .and_then(|session| session.retry_on_setup_failure)
}

/// Whether live reload must refuse this existing-server edit so resource
/// ownership cannot advance independently of the backend shape that serves it.
pub fn resource_shape_change_requires_restart(
    current: &UpstreamManifest,
    candidate: &UpstreamManifest,
) -> bool {
    current.resources != candidate.resources && !connection_shape_eq(current, candidate)
}

/// Whether a reload changes declared ownership or whether an existing server
/// may participate in native resource operations. Eligibility is part of the
/// routing table even for undeclared legacy servers because enumeration can
/// make one newly eligible server an additional owner of an exact URI.
fn resource_routing_changed(
    current: &HashMap<String, Arc<UpstreamEntry>>,
    fresh: &BTreeMap<String, UpstreamManifest>,
) -> bool {
    current.iter().any(|(name, entry)| {
        let removed = entry.removed.load(Ordering::Acquire);
        let old_manifest = entry.manifest_snapshot();
        let old_resources = if removed {
            Vec::new()
        } else {
            old_manifest.resources.clone()
        };
        fresh
            .get(name)
            .map_or(!old_resources.is_empty(), |manifest| {
                old_resources != manifest.resources
                    || (!removed
                        && super::resources::manifest_supports_resource_operations(&old_manifest)
                            != super::resources::manifest_supports_resource_operations(manifest))
            })
    }) || fresh
        .iter()
        .any(|(name, manifest)| !current.contains_key(name) && !manifest.resources.is_empty())
}

fn resource_topology_changed(
    current: &HashMap<String, Arc<UpstreamEntry>>,
    fresh: &BTreeMap<String, UpstreamManifest>,
) -> bool {
    current
        .iter()
        .any(|(name, entry)| !entry.removed.load(Ordering::Acquire) && !fresh.contains_key(name))
        || fresh.keys().any(|name| {
            current
                .get(name)
                .is_none_or(|entry| entry.removed.load(Ordering::Acquire))
        })
}

pub(super) fn redial_committed_fields_eq(a: &UpstreamManifest, b: &UpstreamManifest) -> bool {
    connection_shape_eq(a, b)
        && setup_retry_policy_eq(a, b)
        && a.exchange == b.exchange
        && a.tier_a_required == b.tier_a_required
        && a.tier_c_peer == b.tier_c_peer
}

fn descriptors_by_name(tools: &[Tool]) -> BTreeMap<&str, &Tool> {
    tools
        .iter()
        .map(|tool| (tool.name.as_ref(), tool))
        .collect()
}

/// Compare catalogs as name-keyed descriptor sets. MCP tool order carries no
/// meaning, so an upstream that returns the same descriptors in a different
/// order must not trigger a downstream list-changed notification.
fn tool_catalogs_equal(before: &[Tool], after: &[Tool]) -> bool {
    descriptors_by_name(before) == descriptors_by_name(after)
}

fn tool_inventory_diff(before: &[Tool], after: &[Tool]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let before = descriptors_by_name(before);
    let after = descriptors_by_name(after);
    let added = after
        .keys()
        .filter(|name| !before.contains_key(*name))
        .map(|name| (*name).to_owned())
        .collect();
    let removed = before
        .keys()
        .filter(|name| !after.contains_key(*name))
        .map(|name| (*name).to_owned())
        .collect();
    let schema_changed = after
        .iter()
        .filter_map(|(name, descriptor)| {
            before
                .get(name)
                .filter(|previous| *previous != descriptor)
                .map(|_| (*name).to_owned())
        })
        .collect();
    (added, removed, schema_changed)
}

/// Tool descriptors advertised by every successful replacement lane. A
/// multi-lane commit publishes this conservative intersection so discovery
/// never promises a tool or schema that one of the serving sessions lacks.
///
/// Manifest governance may omit a disputed optional output schema because the
/// manifest remains the authority for admission. Annotation governance instead
/// treats the complete reviewed behavior hash as the authority, including the
/// output schema, so a disagreement withholds the tool until lanes converge.
pub(super) fn common_tool_catalog(
    catalogs: &[&[Tool]],
    mode: crate::ClassificationMode,
) -> Vec<Tool> {
    let Some(first) = catalogs.first() else {
        return Vec::new();
    };
    let later: Vec<HashMap<String, Option<Arc<rmcp::model::JsonObject>>>> = catalogs[1..]
        .iter()
        .map(|catalog| {
            catalog
                .iter()
                .map(|tool| {
                    (
                        lane_catalog_identity_hash(tool, mode),
                        tool.output_schema.clone(),
                    )
                })
                .collect()
        })
        .collect();
    first
        .iter()
        .filter_map(|candidate| {
            let hash = lane_catalog_identity_hash(candidate, mode);
            let mut output_agrees = true;
            for catalog in &later {
                let peer_output = catalog.get(&hash)?;
                output_agrees &= *peer_output == candidate.output_schema;
            }
            let mut tool = candidate.clone();
            if mode == crate::ClassificationMode::Manifest && !output_agrees {
                tool.output_schema = None;
            }
            Some(tool)
        })
        .collect()
}

fn lane_catalog_identity_hash(tool: &Tool, mode: crate::ClassificationMode) -> String {
    match mode {
        crate::ClassificationMode::Manifest => behavior_hash_sans_output_schema(tool),
        crate::ClassificationMode::McpAnnotations => crate::security_metadata::behavior_hash(tool),
    }
}

/// The reviewed behavior hash with the output schema excluded.
///
/// Lane identity for the published intersection has to ignore the output
/// schema, because a partial heal legitimately leaves lanes holding
/// different catalog generations and the conservative answer to that
/// disagreement is to withhold the CONTRACT, not the tool. Everything else
/// the hash covers — name, description, input schema, annotations, and the
/// namespaced metadata — still has to match on every lane.
fn behavior_hash_sans_output_schema(tool: &Tool) -> String {
    let mut tool = tool.clone();
    tool.output_schema = None;
    crate::security_metadata::behavior_hash(&tool)
}

pub(super) fn synchronize_published_catalogs<'a>(
    catalogs: impl IntoIterator<Item = &'a mut Vec<Tool>>,
    published: &[Tool],
) {
    for catalog in catalogs {
        catalog.clear();
        catalog.extend_from_slice(published);
    }
}

fn synchronize_reconnect_catalogs<'a>(
    breaker_open: bool,
    existing: impl IntoIterator<Item = Option<&'a mut Vec<Tool>>>,
    replacements: impl IntoIterator<Item = (bool, Option<&'a mut Vec<Tool>>)>,
    published: &[Tool],
) {
    let existing = existing
        .into_iter()
        .filter_map(|catalog| if breaker_open { None } else { catalog });
    let replacements = replacements.into_iter().filter_map(
        |(install, catalog)| {
            if install {
                catalog
            } else {
                None
            }
        },
    );
    synchronize_published_catalogs(existing.chain(replacements), published);
}

fn matches_transport(a: &Transport, b: &Transport) -> bool {
    matches!(
        (a, b),
        (Transport::Http, Transport::Http)
            | (Transport::Sse, Transport::Sse)
            | (Transport::Stdio, Transport::Stdio)
    )
}

/// Whether two manifests resolve to the SAME number of connection slots, so a
/// connection-shape change between them can be re-dialed live in place
/// rather than requiring a restart to resize the slot `Vec`.
///
/// Slot count is `1` for stdio and `session.concurrency` (else the global pool
/// size) for HTTP/SSE — see [`slot_count`]. So the count is provably unchanged
/// when either both manifests are stdio (always one slot), or both are network
/// AND their `session.concurrency` is identical. A stdio↔network flip (1↔N) or
/// a concurrency change is NOT stable.
///
/// Deliberately conservative without the global pool size in scope: a
/// `concurrency: None`→`Some(global_default)` edit is reported unstable
/// (restart-required) even though the numeric count is unchanged. That is the
/// safe direction — it never lets an in-place re-dial run against a slot `Vec`
/// that is actually the wrong size.
pub(super) fn slot_count_stable(old: &UpstreamManifest, new: &UpstreamManifest) -> bool {
    let old_net = matches!(old.transport, Transport::Http | Transport::Sse);
    let new_net = matches!(new.transport, Transport::Http | Transport::Sse);
    if old_net != new_net {
        // stdio↔network flips the count between 1 and N.
        return false;
    }
    if !new_net {
        // Both stdio: always exactly one slot, regardless of session config.
        return true;
    }
    // Both network: count = concurrency.or(pool_size); stable iff the explicit
    // concurrency override is identical (see the conservative-direction note).
    let old_c = old.session.as_ref().and_then(|s| s.concurrency);
    let new_c = new.session.as_ref().and_then(|s| s.concurrency);
    old_c == new_c
}

/// Compare two `Option<&UpstreamAuth>` for reload purposes. Pulled out so
/// `reload_manifests` doesn't need to derive `PartialEq` on the whole auth
/// struct (future variants may carry non-`PartialEq` material like signing
/// keys). Both the static bearer and catalog-probe groups are dial-time
/// inputs, so changing either requires a fresh connection and tool catalog.
fn auth_eq(a: Option<&UpstreamAuth>, b: Option<&UpstreamAuth>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.bearer_env == b.bearer_env && a.catalog_probe_groups == b.catalog_probe_groups
        }
        _ => false,
    }
}

/// Decide whether an entry should be re-dialed by the periodic / SIGHUP /
/// admin reconnect paths. An entry needs reconnection if it has no stored
/// session, or if its breaker has tripped `Open` — the latter is the dead-
/// session case where the rmcp client object is still in memory but the
/// underlying transport is gone.
///
/// Tombstoned entries (removed via `reload_manifests`) always return false
/// regardless of conn/breaker state — auto-rediscover must not silently
/// resurrect a server the operator just retired.
pub(super) async fn entry_needs_reconnect(entry: &Arc<UpstreamEntry>) -> bool {
    if entry.removed.load(Ordering::Acquire) {
        return false;
    }
    // Any down slot warrants a re-probe (the pool tries to keep every
    // lane live), as does a tripped breaker (the dead-session case where
    // the rmcp client is in memory but its transport is gone).
    for slot in &entry.slots {
        if slot.conn.read().await.is_none() {
            return true;
        }
    }
    entry.breaker.state() == BreakerState::Open
}

/// Release and publish one current entry's claim. The caller must hold the
/// pool's structural reload fence across its final identity check and this
/// call; server-labelled gauges cannot distinguish same-name entry versions.
fn release_reconnect_claim(
    name: &str,
    entry: &Arc<UpstreamEntry>,
    claim: u64,
    needs_recovery: bool,
) {
    let state = {
        let mut state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        if !state.release_claim(claim, needs_recovery) {
            return;
        }
        state.clone()
    };
    super::reconnect::publish_schedule(name, &state);
    entry.reconnect_notify.notify_waiters();
}

/// Settle a claim owned by an entry that is no longer published. Its successor
/// owns the server-labelled schedule gauge, so the retired entry must not
/// publish while releasing its private claim state.
fn discard_reconnect_claim(entry: &Arc<UpstreamEntry>, claim: u64) {
    entry
        .reconnect
        .lock()
        .expect("upstream reconnect lock poisoned")
        .release_claim(claim, false);
}

/// Ensures an attempt claim cannot strand an upstream if its task is cancelled
/// or panics before the reconnect body records an outcome.
struct ReconnectClaimGuard {
    pool: std::sync::Weak<UpstreamPool>,
    name: String,
    entry: Arc<UpstreamEntry>,
    claim: u64,
}

impl ReconnectClaimGuard {
    fn new(pool: &Arc<UpstreamPool>, name: String, entry: Arc<UpstreamEntry>, claim: u64) -> Self {
        Self {
            pool: Arc::downgrade(pool),
            name,
            entry,
            claim,
        }
    }
}

impl Drop for ReconnectClaimGuard {
    fn drop(&mut self) {
        let Some(pool) = self.pool.upgrade() else {
            discard_reconnect_claim(&self.entry, self.claim);
            return;
        };

        // Metric labels are keyed only by server name. Commit fallback state
        // under the same structural fence as replacement so a retired entry
        // can never overwrite its successor's gauges after an earlier identity
        // check. Usually the fence is immediately available; cancellation in
        // the middle of reload defers settlement without blocking `Drop`.
        if let Ok(_structural_guard) = pool.reload_lock.try_lock() {
            if self.entry.removed.load(Ordering::Acquire)
                || !pool.entry_is_current(&self.name, &self.entry)
            {
                discard_reconnect_claim(&self.entry, self.claim);
            } else {
                release_reconnect_claim(&self.name, &self.entry, self.claim, true);
            }
            return;
        }

        let name = self.name.clone();
        let entry = Arc::clone(&self.entry);
        let claim = self.claim;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // A future can be dropped while its runtime is shutting down. No
            // scheduler can consume a rearmed claim then, and private cleanup
            // is safer than panicking from `Drop` or publishing without the
            // structural fence.
            discard_reconnect_claim(&entry, claim);
            return;
        };
        runtime.spawn(async move {
            let _structural_guard = pool.reload_lock.lock().await;
            if entry.removed.load(Ordering::Acquire) || !pool.entry_is_current(&name, &entry) {
                discard_reconnect_claim(&entry, claim);
            } else {
                release_reconnect_claim(&name, &entry, claim, true);
            }
        });
    }
}

impl UpstreamPool {
    fn entry_is_current(&self, name: &str, entry: &Arc<UpstreamEntry>) -> bool {
        self.entries
            .load()
            .get(name)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
    }

    /// Converge retry state after a successful half-open application call.
    /// Reconnect and reload attempts own the same state while they hold the
    /// session-mutation guard, so a racing call leaves their cancellation-safe
    /// fallback untouched. The structural fence then makes the entry identity,
    /// remaining lane health, and server-labelled metric publication one
    /// atomic decision with respect to replacement and removal.
    pub(super) async fn settle_probe_recovery(
        &self,
        name: &str,
        entry: &Arc<UpstreamEntry>,
        recovered: bool,
    ) {
        if !recovered {
            return;
        }
        let Ok(_session_guard) = entry.session_mutation.try_lock() else {
            return;
        };
        let _structural_guard = self.reload_lock.lock().await;
        if entry.removed.load(Ordering::Acquire)
            || !self.entry_is_current(name, entry)
            || entry_needs_reconnect(entry).await
        {
            return;
        }
        let state = {
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            state.record_success(false);
            state.clone()
        };
        super::reconnect::publish_schedule(name, &state);
        entry.reconnect_notify.notify_waiters();
    }

    /// Walk every upstream and re-dial the ones currently disconnected after
    /// a configuration reload. The scheduler handles ordinary automatic
    /// retries; this path gives an operator an immediate recheck after
    /// manifests or referenced credentials may have changed. It preserves the
    /// existing failure episode after a no-op or refused reload, but starts one
    /// fresh episode when dial-time credential material actually changes.
    /// Relevant entry replacement/reconfiguration and targeted
    /// [`Self::reconnect_one`] calls also own fresh-episode resets.
    ///
    /// "Disconnected" covers two cases: no stored `Connection` at all, and a
    /// stored `Connection` whose breaker has tripped `Open` from repeated
    /// RPC failures. The latter is the dead-session case (rmcp client object
    /// still in memory, transport gone) — without that branch the periodic
    /// task would silently skip the very upstream that needs recovery.
    pub async fn try_reconnect_disconnected(&self) {
        let map = self.entries.load_full();
        let mut due = Vec::new();
        for (name, entry) in map.iter() {
            if entry_needs_reconnect(entry).await {
                due.push((name.clone(), entry.clone()));
            }
        }
        futures::future::join_all(
            due.iter()
                .map(|(name, entry)| self.reconnect_entry_preserving_episode(name, entry)),
        )
        .await;
    }

    /// Claim all currently due upstreams and return their owned attempt future.
    /// Each schedule is independent entry state, so claiming it must not wait
    /// behind an unrelated upstream's structural commit. The post-claim
    /// identity check rejects a retired entry; every eventual commit repeats
    /// that check under the structural fence.
    pub async fn reconnect_due_task(
        self: &Arc<Self>,
    ) -> Option<impl std::future::Future<Output = ()> + Send + 'static> {
        let map = self.entries.load_full();
        let now = std::time::Instant::now();
        let mut due = Vec::new();
        for (name, entry) in map.iter() {
            let claimed = {
                let mut state = entry
                    .reconnect
                    .lock()
                    .expect("upstream reconnect lock poisoned");
                state.claim_due(now).map(|claim| (claim, state.clone()))
            };
            if let Some((claim, state)) = claimed {
                if entry.removed.load(Ordering::Acquire) || !self.entry_is_current(name, entry) {
                    discard_reconnect_claim(entry, claim);
                    continue;
                }
                // Keep server-labelled publication ordered with replacement
                // when the fence is immediately available. If a structural
                // commit owns it, launching recovery is more important than
                // clearing an in-flight schedule timestamp; the reconnect
                // outcome republishes the authoritative state under the fence.
                if let Ok(_structural_guard) = self.reload_lock.try_lock() {
                    if entry.removed.load(Ordering::Acquire) || !self.entry_is_current(name, entry)
                    {
                        discard_reconnect_claim(entry, claim);
                        continue;
                    }
                    super::reconnect::publish_schedule(name, &state);
                }
                due.push((
                    name.clone(),
                    entry.clone(),
                    ReconnectClaimGuard::new(self, name.clone(), entry.clone(), claim),
                ));
            }
        }
        if due.is_empty() {
            return None;
        }

        let pool = Arc::clone(self);
        Some(async move {
            futures::future::join_all(due.into_iter().map(|(name, entry, claim)| {
                let pool = Arc::clone(&pool);
                async move {
                    let claim_guard = claim;
                    pool.reconnect_claimed_entry(&name, &entry, claim_guard.claim)
                        .await;
                }
            }))
            .await;
        })
    }

    /// Re-dial a single upstream by name. Returns the new connection state
    /// (`true` ⇒ now connected, `false` ⇒ still down or retired). Used by
    /// the admin `POST /upstreams/{name}/reconnect` endpoint to give an
    /// operator a targeted lever after fixing a misbehaving upstream.
    /// Unknown server names return `false` — callers map that to a 404.
    /// Tombstoned servers (removed via `reload_manifests`) also return
    /// `false`: a SIGHUP-removed upstream must not be silently revived by
    /// an admin reconnect.
    ///
    /// Forces a fresh dial whenever the entry needs recovery (no conn or
    /// breaker open). A healthy connected entry is a no-op; this is a
    /// recovery lever, not a "force-restart this upstream" verb.
    pub async fn reconnect_one(&self, server: &str) -> bool {
        let Some(entry) = self.entries.load().get(server).cloned() else {
            return false;
        };
        let session_guard = entry.session_mutation.lock().await;
        let needs_reconnect = entry_needs_reconnect(&entry).await;
        {
            let _structural_guard = self.reload_lock.lock().await;
            if entry.removed.load(Ordering::Acquire) || !self.entry_is_current(server, &entry) {
                return false;
            }
            if !needs_reconnect {
                return true;
            }
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            // The base-delay fallback makes this request cancel-safe: a
            // dropped admin handler leaves bounded automatic recovery work,
            // while a completed outcome replaces the fallback below.
            state.reset_for_operator();
            super::reconnect::publish_schedule(server, &state);
        }
        entry.reconnect_notify.notify_waiters();
        self.reconnect_entry_under_guard(server, &entry, None, session_guard)
            .await;
        entry.any_connected().await && entry.breaker.state() != BreakerState::Open
    }

    /// Force a fresh MCP session for one upstream even when its current
    /// connection is healthy, then atomically republish the classified tool
    /// inventory discovered by the replacement session. The old session keeps
    /// serving until every replacement dial has completed; a total dial failure
    /// leaves the old session and catalog untouched. The initiating principal is
    /// mandatory: its attributed evidence event is submitted to the bounded
    /// recorder after the session commit and after the session guard is
    /// released.
    pub async fn refresh_server_catalog(
        &self,
        server: &str,
        actor: &Principal,
    ) -> Option<CatalogRefreshReport> {
        let entry = self.entries.load().get(server).cloned()?;
        let session_guard = entry.session_mutation.lock().await;
        self.refresh_catalog_under_guard(server, &entry, session_guard, actor, None)
            .await
    }

    /// The body of [`Self::refresh_server_catalog`], entered with the
    /// entry's `session_mutation` guard already held. Split so the
    /// scheduled-freshness path can evaluate its eligibility preconditions
    /// under the same guard the redial runs under — a pre-check taken
    /// before this lock could go stale while an admin refresh or reconnect
    /// held it.
    pub(super) async fn refresh_catalog_under_guard(
        &self,
        server: &str,
        entry: &Arc<UpstreamEntry>,
        session_guard: tokio::sync::MutexGuard<'_, ()>,
        actor: &Principal,
        freshness_trigger: Option<super::CatalogFreshnessTrigger>,
    ) -> Option<CatalogRefreshReport> {
        if entry.removed.load(Ordering::Acquire) {
            return None;
        }

        let before = entry.published_tools().await;
        let manifest = entry.manifest_snapshot();
        let redial = self
            .redial_entry(
                server,
                entry,
                &manifest,
                &manifest,
                RedialSource::CatalogRefresh,
            )
            .await;
        // A total dial/index failure returns before `redial_entry` reaches its
        // successful-commit registry fence. Classify that outcome against the
        // live registry under the structural lock before claiming the prior
        // inventory is still current: an overlapping reload may have replaced
        // or removed this entry while the failed dial was in flight.
        let (redial, after) = if matches!(redial, RedialOutcome::Failed) {
            let _structural_guard = self.reload_lock.lock().await;
            let effective = if entry.removed.load(Ordering::Acquire) {
                RedialOutcome::Tombstoned
            } else if !self.entry_is_current(server, entry) {
                RedialOutcome::Superseded
            } else {
                RedialOutcome::Failed
            };
            (effective, entry.published_tools().await)
        } else {
            (redial, entry.published_tools().await)
        };
        let (added, removed, schema_changed) = tool_inventory_diff(&before, &after);
        let session_replaced = matches!(redial, RedialOutcome::Redialed);
        let outcome = match redial {
            RedialOutcome::Redialed
                if added.is_empty() && removed.is_empty() && schema_changed.is_empty() =>
            {
                CatalogRefreshOutcome::Unchanged
            }
            RedialOutcome::Redialed => CatalogRefreshOutcome::Updated,
            RedialOutcome::Failed => CatalogRefreshOutcome::Failed,
            RedialOutcome::Superseded => CatalogRefreshOutcome::Superseded,
            RedialOutcome::Tombstoned => CatalogRefreshOutcome::Removed,
        };

        let report = CatalogRefreshReport {
            server: server.to_owned(),
            outcome,
            session_replaced,
            before_tool_count: before.len(),
            after_tool_count: after.len(),
            added,
            removed,
            schema_changed,
        };
        drop(session_guard);
        self.record_catalog_refresh_attribution(server, actor, redial, freshness_trigger)
            .await;
        Some(report)
    }

    async fn record_catalog_refresh_attribution(
        &self,
        server: &str,
        actor: &Principal,
        outcome: RedialOutcome,
        freshness_trigger: Option<super::CatalogFreshnessTrigger>,
    ) {
        let Some(evidence) = self.evidence.as_ref() else {
            return;
        };
        let audit_outcome = match outcome {
            RedialOutcome::Redialed => waygate_mcp::AuditOutcome::Success,
            RedialOutcome::Failed | RedialOutcome::Superseded | RedialOutcome::Tombstoned => {
                waygate_mcp::AuditOutcome::ExecutionError
            }
        };
        let outcome_reason = match outcome {
            RedialOutcome::Redialed => "outcome=redialed",
            RedialOutcome::Failed => "outcome=failed",
            RedialOutcome::Superseded => "outcome=superseded",
            RedialOutcome::Tombstoned => "outcome=removed",
        };
        let reason = match freshness_trigger {
            Some(trigger) => format!("{outcome_reason} trigger={}", trigger.as_str()),
            None => outcome_reason.to_owned(),
        };
        let event = waygate_mcp::AuditEvent::new("UpstreamCatalogRefresh", audit_outcome)
            .with_category(waygate_mcp::EvidenceCategory::UpstreamHealth)
            .with_principal(Some(actor))
            .with_tenant(actor.tenant.clone())
            .with_target(server.to_owned())
            .with_reason(reason);
        evidence.record_best_effort(event).await;
    }

    /// Shared reconnect path. Replaces any stored `Connection` (the prior
    /// one is presumed dead — that's why the entry needed re-probing) and
    /// resets the breaker so the freshly-dialed session isn't immediately
    /// rejected by stale failure counts.
    ///
    /// The dial itself happens *outside* the write lock so concurrent RPCs
    /// through `call_tool_inner` aren't blocked for the duration of a TCP
    /// handshake. After the dial succeeds we acquire the write lock and
    /// re-check the predicate. Session replacement attempts are serialized per
    /// upstream, but a concurrent manifest reload can still advance identity
    /// fields or tombstone the entry while the dial is in flight. In either
    /// case we drop our just-dialed `Connection`; rmcp shuts the session down
    /// cleanly on drop.
    /// Apply the shared reconnect path after a fleet reload without treating a
    /// generic SIGHUP as evidence that this entry's failure cause changed.
    async fn reconnect_entry_preserving_episode(&self, name: &str, entry: &Arc<UpstreamEntry>) {
        let session_guard = entry.session_mutation.lock().await;
        if !entry_needs_reconnect(entry).await {
            return;
        }
        let credential_version = transport::credential_material_version(
            &entry.manifest_snapshot(),
            self.reconnect_policy.credential_key(),
        );
        {
            // Serialize the cancellation fallback with entry
            // replacement/removal. `observe_runtime_failure` arms a missing
            // schedule without clearing attempt aggregation or reducing an
            // existing backoff.
            let _structural_guard = self.reload_lock.lock().await;
            if entry.removed.load(Ordering::Acquire) || !self.entry_is_current(name, entry) {
                return;
            }
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            // A changed credential payload is a new actionable dial-input
            // episode even when its manifest path is unchanged. Repeated
            // SIGHUPs against identical material preserve aggregation.
            if state.update_credential_version(credential_version) {
                state.reset_for_operator();
            } else {
                state.observe_runtime_failure();
            }
            super::reconnect::publish_schedule(name, &state);
        }
        entry.reconnect_notify.notify_waiters();
        self.reconnect_entry_under_guard(name, entry, None, session_guard)
            .await;
    }

    async fn reconnect_claimed_entry(&self, name: &str, entry: &Arc<UpstreamEntry>, claim: u64) {
        let session_guard = entry.session_mutation.lock().await;
        let claim_is_active = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .claim_is_active(claim);
        if !claim_is_active {
            return;
        }
        if !entry_needs_reconnect(entry).await {
            let _structural_guard = self.reload_lock.lock().await;
            if entry.removed.load(Ordering::Acquire) || !self.entry_is_current(name, entry) {
                discard_reconnect_claim(entry, claim);
                return;
            }
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            state.record_success(false);
            super::reconnect::publish_schedule(name, &state);
            return;
        }
        self.reconnect_entry_under_guard(name, entry, Some(claim), session_guard)
            .await;
    }

    async fn reconnect_entry_under_guard(
        &self,
        name: &str,
        entry: &Arc<UpstreamEntry>,
        claim: Option<u64>,
        _session_guard: tokio::sync::MutexGuard<'_, ()>,
    ) {
        // Re-dial every slot that needs it. The dials happen *outside*
        // each slot's write lock so concurrent RPCs through other (live)
        // slots aren't blocked for the duration of a TCP handshake. After the
        // dials settle we take every slot's write lock and re-check because
        // `reload_manifests` may have advanced identity fields or tombstoned the
        // entry while the dials were in flight. In either case we drop the
        // just-dialed `Connection`s; rmcp shuts the sessions down cleanly on
        // drop.
        //
        // **Dead-session recovery.** When the breaker
        // is `Open`, every populated slot's client is presumed dead — the
        // rmcp `RunningService` object is still in memory but its
        // transport is gone (the very state the breaker exists to detect).
        // Under that condition we re-dial ALL slots (replacing populated
        // ones too) so scheduled + admin reconnect actually
        // recover the upstream, restoring the original entry-level
        // reconnect semantics. With the breaker closed / half-open,
        // only `None` slots are re-dialed (the steady-state recovery
        // path).
        let dial_manifest = entry.manifest_snapshot();
        let attempt_credential_version = transport::credential_material_version(
            &dial_manifest,
            self.reconnect_policy.credential_key(),
        );
        let breaker_open_at_start = entry.breaker.state() == BreakerState::Open;
        let should_dial = futures::future::join_all(
            entry
                .slots
                .iter()
                .map(|slot| async { breaker_open_at_start || slot.conn.read().await.is_none() }),
        )
        .await;
        if should_dial.iter().any(|should_dial| *should_dial) {
            waygate_telemetry::metrics::record_upstream_reconnect_attempt(name);
        }
        let timeout = self.redial_dial_timeout;
        let issuer = self.issuer.as_ref();
        let exchange = self.exchange.as_ref();
        let results = futures::future::join_all(should_dial.iter().map(|should_dial| {
            let should_dial = *should_dial;
            let dial_manifest = &dial_manifest;
            async move {
                if !should_dial {
                    return None;
                }
                Some(
                    match tokio::time::timeout(timeout, dial(dial_manifest, issuer, exchange)).await
                    {
                        Ok(Ok(conn)) => Ok(conn),
                        Ok(Err(error)) => Err((
                            UpstreamErrorClass::from_dial_error(&error),
                            error.to_string(),
                        )),
                        Err(_) => Err((
                            UpstreamErrorClass::Timeout,
                            format!("dial timed out after {timeout:?}"),
                        )),
                    },
                )
            }
        }))
        .await;
        let mut dialed = Vec::with_capacity(results.len());
        let mut last_err: Option<(UpstreamErrorClass, String)> = None;
        for result in results {
            match result {
                Some(Ok(conn)) => dialed.push(Some(conn)),
                Some(Err(error)) => {
                    last_err = Some(error);
                    dialed.push(None);
                }
                None => dialed.push(None),
            }
        }

        if !should_dial.iter().any(|should_dial| *should_dial) {
            let _structural_guard = self.reload_lock.lock().await;
            if entry.removed.load(Ordering::Acquire) || !self.entry_is_current(name, entry) {
                if let Some(claim) = claim {
                    discard_reconnect_claim(entry, claim);
                }
                return;
            }
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            state.update_credential_version(attempt_credential_version);
            state.record_success(false);
            super::reconnect::publish_schedule(name, &state);
            return;
        }

        #[cfg(test)]
        self.pause_before_reconnect_commit().await;

        // A reconnect changes one upstream-wide catalog, even when it only
        // heals one lane. Commit every prospective lane under one structural
        // fence so the search index and every connected Connection expose the
        // exact descriptor intersection advertised by all serving lanes.
        // Never hold the fleet structural fence while waiting for this
        // upstream's active calls to release their lane readers. Taking the
        // lane writers first is safe only with a non-blocking structural
        // acquisition: if a reload already owns the fence and is waiting for
        // these lanes, release them, wait for that mutation to finish, and
        // retry without an inverted-lock deadlock.
        let (_structural_guard, mut guards) = loop {
            let mut guards: Vec<_> = Vec::with_capacity(entry.slots.len());
            for slot in &entry.slots {
                guards.push(slot.conn.write().await);
            }
            if let Ok(structural_guard) = self.reload_lock.try_lock() {
                break (structural_guard, guards);
            }
            drop(guards);
            let structural_guard = self.reload_lock.lock().await;
            drop(structural_guard);
        };
        if !self.entry_is_current(name, entry) {
            if let Some(claim) = claim {
                discard_reconnect_claim(entry, claim);
            }
            return;
        }
        if entry.removed.load(Ordering::Acquire) {
            if let Some(claim) = claim {
                discard_reconnect_claim(entry, claim);
            }
            return;
        }
        if !redial_committed_fields_eq(&entry.manifest_snapshot(), &dial_manifest) {
            tracing::info!(
                server = %name,
                "discarding reconnect dials whose connection shape was superseded by a live re-dial",
            );
            if let Some(claim) = claim {
                release_reconnect_claim(name, entry, claim, true);
            }
            return;
        }

        // A half-open application probe can recover the breaker while these
        // dials are in flight. Its breaker disposition happens before it
        // releases the lane read lock, so after acquiring every lane's write
        // lock this is the commit-time health truth. Never let the stale
        // pre-dial snapshot erase a lane that just proved healthy.
        let breaker_open = entry.breaker.state() == BreakerState::Open;
        let recovered_by_probe = breaker_open_at_start && !breaker_open;

        let installable: Vec<bool> = guards
            .iter()
            .zip(&should_dial)
            .zip(&dialed)
            .map(|((guard, should_dial), conn)| {
                *should_dial && conn.is_some() && (breaker_open || guard.is_none())
            })
            .collect();
        let candidate_healed = installable.iter().filter(|install| **install).count();
        let mut healed = 0usize;
        let mut tool_count = guards
            .iter()
            .find_map(|guard| guard.as_ref().map(|conn| conn.tools.len()))
            .unwrap_or_default();

        if candidate_healed > 0 {
            let previous_tools = guards
                .iter()
                .find_map(|guard| guard.as_ref().map(|conn| conn.tools.clone()))
                .unwrap_or_default();
            let manifest = entry.manifest_snapshot();
            let classifications = manifest.tools;
            let classification_mode = manifest.classification_mode;
            let publish_index = installable
                .iter()
                .position(|install| *install)
                .expect("at least one reconnect dial is installable");
            let common_live_tools = {
                let mut catalogs: Vec<&[Tool]> = Vec::with_capacity(guards.len());
                for (index, guard) in guards.iter().enumerate() {
                    if installable[index] {
                        catalogs.push(
                            dialed[index]
                                .as_ref()
                                .expect("installable reconnect dial exists")
                                .live_tools
                                .as_slice(),
                        );
                    } else if !breaker_open {
                        if let Some(conn) = guard.as_ref() {
                            catalogs.push(conn.live_tools.as_slice());
                        }
                    }
                }
                common_tool_catalog(&catalogs, classification_mode)
            };
            if let Err(error) = self.publish_classifications_to(
                entry,
                dialed[publish_index]
                    .as_mut()
                    .expect("selected reconnect connection exists"),
                name,
                CatalogPublication {
                    source: "reconnect",
                    classifications: &classifications,
                    classification_mode,
                    previous_tools: &previous_tools,
                    live_tools: Some(&common_live_tools),
                },
                None,
            ) {
                last_err = Some((
                    UpstreamErrorClass::Catalog,
                    format!("search index publish failed: {error}"),
                ));
            } else {
                let published_tools = dialed[publish_index]
                    .as_ref()
                    .expect("selected reconnect connection exists")
                    .tools
                    .clone();
                synchronize_reconnect_catalogs(
                    breaker_open,
                    guards
                        .iter_mut()
                        .map(|guard| guard.as_mut().map(|conn| &mut conn.tools)),
                    dialed.iter_mut().zip(&installable).map(|(conn, install)| {
                        (*install, conn.as_mut().map(|conn| &mut conn.tools))
                    }),
                    &published_tools,
                );
                // Same per-lane rule as the redial commit: a refusal on any
                // live lane has to reach the operator, and only the
                // publishing lane was normalized during publication.
                for conn in guards.iter_mut().filter_map(|guard| guard.as_mut()) {
                    super::tool_listing::normalize_connection(name, conn);
                }
                for conn in dialed.iter_mut().filter_map(Option::as_mut) {
                    super::tool_listing::normalize_connection(name, conn);
                }
                if guards
                    .iter()
                    .filter_map(|guard| match (breaker_open, guard.as_ref()) {
                        (false, Some(conn)) => Some(conn),
                        _ => None,
                    })
                    .map(|conn| &conn.live_tools)
                    .chain(
                        dialed
                            .iter()
                            .zip(&installable)
                            .filter_map(
                                |(conn, install)| {
                                    if *install {
                                        conn.as_ref()
                                    } else {
                                        None
                                    }
                                },
                            )
                            .map(|conn| &conn.live_tools),
                    )
                    .any(|tools| *tools != common_live_tools)
                {
                    tracing::warn!(
                        server = %name,
                        common_tools = common_live_tools.len(),
                        "connected lanes advertised different tool catalogs — publishing only their exact intersection",
                    );
                }
                tool_count = published_tools.len();
                healed = candidate_healed;
                for ((guard, conn), install) in
                    guards.iter_mut().zip(dialed.iter_mut()).zip(&installable)
                {
                    if *install {
                        **guard = conn.take();
                    }
                }
            }
        }

        if breaker_open {
            for ((guard, should_dial), install) in
                guards.iter_mut().zip(&should_dial).zip(&installable)
            {
                if *should_dial && !install {
                    **guard = None;
                }
            }
        }
        // Sampled under the guards that installed the healed lanes, for the
        // same reason as the re-dial path.
        let (served_at_install, install_at) = {
            let quarantined = entry
                .quarantined
                .read()
                .expect("upstream quarantine lock poisoned");
            let at = self.audited_refusals.observe();
            (super::health::rejected_union(&guards, &quarantined), at)
        };
        let connected_after = guards.iter().filter(|guard| guard.is_some()).count();
        if healed > 0 {
            // Linearize the breaker reset with the lane installation. Once
            // these writers release, any application failure is necessarily
            // newer and must own the breaker transition.
            entry.breaker.reset();
        }
        let reconnect_revision_at_install = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .revision();
        drop(guards);
        drop(_structural_guard);

        // Republished on BOTH outcomes: a recovery that failed every dial
        // just cleared its lanes, and the generation gauge must fall with
        // them — the healed>0 branch republishes again via the refusal
        // refresh, which is an idempotent set.
        self.refresh_protocol_generation_gauge(name, entry).await;

        #[cfg(test)]
        self.pause_before_reconnect_outcome().await;

        // The gauge refresh is deliberately awaited without the structural
        // fence. Revalidate immediately afterward and linearize every outcome
        // publication under that fence: a removal or slot-resize that won the
        // gap owns the server-labelled metrics and operator evidence now.
        let outcome_guard = self.reload_lock.lock().await;
        if entry.removed.load(Ordering::Acquire) || !self.entry_is_current(name, entry) {
            if let Some(claim) = claim {
                discard_reconnect_claim(entry, claim);
            }
            return;
        }

        if healed > 0 {
            let converged = {
                let mut state = entry
                    .reconnect
                    .lock()
                    .expect("upstream reconnect lock poisoned");
                let failed_attempts = state.episode_attempts();
                state
                    .record_success_if_revision(
                        reconnect_revision_at_install,
                        connected_after < entry.slots.len(),
                        attempt_credential_version,
                    )
                    .then(|| (failed_attempts, state.clone()))
            };
            let Some((failed_attempts, state)) = converged else {
                // A newer lane failure owns recovery state. The scheduler's
                // claim guard rearms a claimed attempt on return; an operator
                // attempt retains the schedule armed before it started.
                drop(outcome_guard);
                return;
            };
            super::reconnect::publish_schedule(name, &state);
            entry.reconnect_notify.notify_waiters();
            entry
                .recovery
                .write()
                .expect("upstream recovery lock poisoned")
                .record_reconnect(
                    connected_after,
                    entry.slots.len(),
                    last_err.as_ref().map(|(class, _)| *class),
                );
            tracing::info!(server = %name, slots = healed, tools = tool_count, failed_attempts, "upstream reconnected");
            drop(outcome_guard);
            self.record_upstream_health(
                "UpstreamReconnected",
                waygate_mcp::AuditOutcome::Success,
                format!("server={name} tools={tool_count} slots={healed} failed_attempts={failed_attempts}"),
            )
            .await;
            // An upstream that was down at boot and auto-recovers here would
            // otherwise have malformed schemas stripped and counted but never
            // reported to the operator's error log.
            self.record_new_refusals(name, entry, install_at, &served_at_install)
                .await;
            self.refresh_rejected_output_schemas(name).await;
        } else if recovered_by_probe && entry.breaker.state() != BreakerState::Open {
            // The application probe, rather than this reconnect's dials,
            // restored service. Settle the stale claim without reporting its
            // failed dials as a new outage. Missing lanes remain scheduled at
            // the base delay so partial recovery still converges.
            let state = {
                let mut state = entry
                    .reconnect
                    .lock()
                    .expect("upstream reconnect lock poisoned");
                state
                    .record_success_if_revision(
                        reconnect_revision_at_install,
                        connected_after < entry.slots.len(),
                        attempt_credential_version,
                    )
                    .then(|| state.clone())
            };
            let Some(state) = state else {
                drop(outcome_guard);
                return;
            };
            super::reconnect::publish_schedule(name, &state);
            entry.reconnect_notify.notify_waiters();
            drop(outcome_guard);
        } else if let Some((error_class, e)) = last_err {
            let failure = {
                let mut state = entry
                    .reconnect
                    .lock()
                    .expect("upstream reconnect lock poisoned");
                let Some(failure) = state.record_failure_if_revision(
                    reconnect_revision_at_install,
                    attempt_credential_version,
                ) else {
                    drop(outcome_guard);
                    return;
                };
                super::reconnect::publish_schedule(name, &state);
                failure
            };
            entry.reconnect_notify.notify_waiters();
            entry
                .recovery
                .write()
                .expect("upstream recovery lock poisoned")
                .record_failure(error_class);
            if failure.episode_started {
                waygate_telemetry::metrics::record_upstream_reconnect_failure_episode(name);
                tracing::warn!(server = %name, error = %e, next_retry_ms = failure.backoff.as_millis(), "upstream reconnect failure episode started");
                drop(outcome_guard);
                self.record_upstream_health(
                    "UpstreamReconnectFailed",
                    waygate_mcp::AuditOutcome::ExecutionError,
                    format!(
                        "server={name} error={e} episode_attempt=1 next_retry_ms={}",
                        failure.backoff.as_millis()
                    ),
                )
                .await;
            } else if failure.episode_attempt.is_power_of_two() {
                tracing::warn!(
                    server = %name,
                    error_class = error_class.as_str(),
                    repeated_failures = failure.episode_attempt - 1,
                    next_retry_ms = failure.backoff.as_millis(),
                    "upstream reconnect failure episode continues",
                );
                drop(outcome_guard);
            } else {
                drop(outcome_guard);
            }
        } else {
            if let Some(claim) = claim {
                release_reconnect_claim(
                    name,
                    entry,
                    claim,
                    connected_after < entry.slots.len()
                        || entry.breaker.state() == BreakerState::Open,
                );
            }
            drop(outcome_guard);
        }
        // healed == 0 && last_err == None ⇒ every down slot was a race-loser
        // (already healed / tombstoned); nothing to report.
    }

    #[cfg(test)]
    async fn pause_before_reconnect_commit(&self) {
        let hook = self
            .reconnect_commit_hook
            .lock()
            .expect("reconnect commit hook lock poisoned")
            .clone();
        if let Some((reached, resume)) = hook {
            reached.notify_one();
            resume.notified().await;
        }
    }

    #[cfg(test)]
    async fn pause_before_reconnect_outcome(&self) {
        let hook = self
            .reconnect_outcome_hook
            .lock()
            .expect("reconnect outcome hook lock poisoned")
            .clone();
        if let Some((reached, resume)) = hook {
            reached.notify_one();
            resume.notified().await;
        }
    }

    /// Live re-dial. The connection-shape (transport / url / command /
    /// auth / mtls / session) of `name` changed on reload, and the change keeps
    /// the same slot count (see [`slot_count_stable`]), so we tear down the old
    /// session(s) and re-dial in place with the new shape — applying it live
    /// (no restart), picking up a fresh identity cell, a re-resolved bearer,
    /// and freshly read mTLS material (the three things baked at dial time that
    /// a reload otherwise cannot touch).
    ///
    /// Ordering is the whole reason this isn't a naive in-place swap:
    ///   1. Dial EVERY lane from the new shape FIRST, outside the slot locks,
    ///      while the old session(s) keep serving — zero-downtime, and the old
    ///      shape is never abandoned before a new-shape session exists.
    ///   2. If no lane dialed, abort: leave the stored manifest AND the live
    ///      session(s) on the OLD shape (self-consistent, still serving) and
    ///      report [`RedialOutcome::Failed`]. A bad shape push never blacks out
    ///      a working upstream.
    ///   3. Only once ≥1 new-shape session exists, commit ATOMICALLY: acquire
    ///      EVERY slot's conn write lock, then **compare-and-swap** the stored
    ///      shape (commit only if it still equals the shape we dialed FROM —
    ///      else a newer concurrent re-dial won, so abort as
    ///      [`RedialOutcome::Superseded`] rather than roll it back),
    ///      advance the shape fields, and swap the dialed lanes in / mark
    ///      any failed lane down — all under the held locks. The bearer / cert /
    ///      endpoint live in the `Connection` (baked at dial), so holding the
    ///      conn locks across the manifest advance is what guarantees no
    ///      `call_tool` can pair a new-manifest snapshot with a still-old
    ///      `Connection`, and no racing
    ///      [`reconnect_entry_under_guard`](Self::reconnect_entry_under_guard)
    ///      can slip an old-shape dial
    ///      into a slot mid-swap. Acquiring the write locks also drains any
    ///      in-flight call on each lane first.
    ///
    /// A forced catalog refresh reuses this transaction with identical `new`
    /// and `from_shape` manifests. It still replaces the live MCP session and
    /// publishes the freshly classified inventory atomically, without claiming
    /// that any connection settings changed.
    ///
    /// `removed` is re-checked before dialing, and again UNDER the held locks
    /// immediately before the manifest advance — which gates the advance AND the
    /// lane swaps as one all-or-nothing step. If the entry was tombstoned by the
    /// time of that gate, we bail without advancing (old manifest + old
    /// connections, self-consistent — the retirement semantic keeps a removed
    /// entry's live sessions serving until restart). If it was not, we advance
    /// and install EVERY lane, so the live manifest and the live connections
    /// agree. A lock-free `removed` store landing during the install leaves a
    /// consistent NEW-shape entry (reported `Tombstoned`) — never the
    /// advanced-manifest-over-old-connections hybrid that a per-lane skip would
    /// produce.
    async fn redial_entry(
        &self,
        name: &str,
        entry: &Arc<UpstreamEntry>,
        new: &UpstreamManifest,
        from_shape: &UpstreamManifest,
        source: RedialSource,
    ) -> RedialOutcome {
        let new_credential_version =
            transport::credential_material_version(new, self.reconnect_policy.credential_key());
        // `from_shape` is the connection-shape + identity this reload transitions
        // FROM, captured by `reload_manifests` UNDER the same manifest lock that
        // decided this reload needs a re-dial. Independent
        // reload call sites (doorbell/poll, SIGHUP, dashboard) can invoke
        // `reload_manifests` — and thus this method — concurrently, each having
        // read a possibly-different on-disk config. A slow older re-dial that
        // finishes after a newer one already committed must NOT roll the stored
        // manifest and live connections back to its (now stale) config.
        // We compare-and-swap against `from_shape` under the commit
        // locks below: commit only if every field we are about to write still
        // equals what we started from; otherwise a concurrent reload won, abort.
        // Capturing the baseline in the caller (not here) is essential — a fresh
        // snapshot taken at this point, after the decision lock was dropped,
        // could already reflect a newer reload and we would overwrite it.

        // Stage 1 — dial every lane from the new shape, outside the slot locks,
        // CONCURRENTLY and each under `redial_dial_timeout`. The old session(s)
        // stay live throughout, so calls keep flowing on the previous shape
        // until we have a replacement in hand. The per-lane timeout + the
        // concurrency are what make an unresponsive new target surface as
        // `redial_failed` *promptly* (~one timeout) instead of wedging the
        // awaited `reload_manifests` for N sequential hangs.
        let timeout = self.redial_dial_timeout;
        let dials = (0..entry.slots.len()).map(|_| async move {
            match tokio::time::timeout(
                timeout,
                dial(new, self.issuer.as_ref(), self.exchange.as_ref()),
            )
            .await
            {
                Ok(Ok(c)) => Ok(c),
                Ok(Err(e)) => Err(RedialFailure {
                    class: UpstreamErrorClass::from_dial_error(&e),
                    detail: e.to_string(),
                }),
                Err(_elapsed) => Err(RedialFailure {
                    class: UpstreamErrorClass::Timeout,
                    detail: format!("dial timed out after {timeout:?}"),
                }),
            }
        });
        let mut dialed: Vec<Option<Connection>> = Vec::with_capacity(entry.slots.len());
        let mut last_err: Option<RedialFailure> = None;
        for result in futures::future::join_all(dials).await {
            match result {
                Ok(c) => dialed.push(Some(c)),
                Err(e) => {
                    last_err = Some(e);
                    dialed.push(None);
                }
            }
        }

        if dialed.iter().all(Option::is_none) {
            // Publish this failed attempt only while this is still the live
            // entry and still has the shape we dialed from. A newer redial may
            // have committed while these dials were in flight; recording this
            // older failure after that success would make the authoritative
            // recovery snapshot run backwards. The same structural fence used
            // by the successful commit gives the failure path a total order
            // with replacement, removal, and competing redials.
            let _structural_guard = self.reload_lock.lock().await;
            if entry.removed.load(Ordering::Acquire) {
                return RedialOutcome::Tombstoned;
            }
            if !self.entry_is_current(name, entry)
                || !redial_committed_fields_eq(&entry.manifest_snapshot(), from_shape)
            {
                return RedialOutcome::Superseded;
            }
            if let Some(failure) = last_err.as_ref() {
                entry.record_runtime_failure(failure.class);
            }
            drop(_structural_guard);

            // No lane adopted the new shape. Leave the stored manifest and the
            // live session(s) untouched on the OLD shape — the upstream keeps
            // serving and stays self-consistent. The operator's change has NOT
            // landed; the caller reports it restart-required.
            if let Some(e) = last_err.as_ref() {
                tracing::warn!(
                    server = %name,
                    error = %e.detail,
                    "live re-dial failed on every lane — keeping the previous connection shape",
                );
            }
            if matches!(source, RedialSource::ConnectionShape) {
                self.record_upstream_health(
                    "UpstreamRedialFailed",
                    waygate_mcp::AuditOutcome::ExecutionError,
                    format!(
                        "server={name} error={}",
                        last_err
                            .as_ref()
                            .map(|failure| failure.detail.as_str())
                            .unwrap_or("unknown")
                    ),
                )
                .await;
            }
            return RedialOutcome::Failed;
        }

        // A racing reload may have retired the entry while we dialed. Drop the
        // fresh sessions rather than resurrect a tombstoned upstream.
        if entry.removed.load(Ordering::Acquire) {
            return RedialOutcome::Tombstoned;
        }

        // Serialize the commit with registry replacement. A slot-count-changing
        // reload swaps a different `Arc<UpstreamEntry>` under this same lock and
        // republishes its index before releasing it. The identity check prevents
        // a slow refresh/redial holding the retired entry from publishing after
        // that structural commit.
        let _structural_guard = self.reload_lock.lock().await;
        if !self.entry_is_current(name, entry) {
            return RedialOutcome::Superseded;
        }

        // Commit the swap ATOMICALLY with respect to `call_tool` and
        // the reconnect path. The bearer / client cert / endpoint live inside the
        // dialed `Connection` (baked at dial time); the stored manifest is only
        // the metadata that says which shape is "live". If we advanced the
        // manifest while any slot still held the old `Connection`, a concurrent
        // reuse-mode dispatch could snapshot the NEW manifest and then run on
        // the OLD bearer / cert / url. To prevent that we
        // hold EVERY slot's conn write lock across the manifest advance AND all
        // swaps, so no call can pair a new-manifest snapshot with a stale
        // connection, and no reconnect can slip an old-shape dial into a slot
        // mid-swap.
        //
        // Acquiring the write locks also serializes behind any in-flight call on
        // each slot (a dispatch holds the conn read lock), so an active request
        // drains before its lane is swapped rather than being yanked. No
        // deadlock: structural commits take `reload_lock` before any slot lock,
        // and both this path and reconnect take every slot lock in slot
        // order. Other paths lock at most one slot conn at a time, so taking
        // them all in slot order can only wait, never cycle; and
        // `publish_classifications_to` takes the `Connection` by `&mut` and
        // never re-locks a slot conn (it already runs under one in
        // reconnect).
        let mut guards: Vec<_> = Vec::with_capacity(entry.slots.len());
        for slot in &entry.slots {
            guards.push(slot.conn.write().await);
        }
        // Re-check the tombstone under the locks: a concurrent reload may have
        // retired the entry between the dial and acquiring the locks. (Its
        // drain at the bottom of `reload_manifests` takes these same conn write
        // locks, so it cannot complete the teardown while we hold them — but it
        // sets `removed` first, so honour it and bail.)
        if entry.removed.load(Ordering::Acquire) {
            // Guards + freshly-dialed sessions drop here; don't resurrect.
            return RedialOutcome::Tombstoned;
        }
        // Compare-and-swap under the held locks, then advance. We hold every
        // slot conn write lock, so no concurrent re-dial can be mid-commit. The
        // CAS compares EVERY field this commit writes — the connection-shape
        // fields AND the coupled identity fields (exchange / tier_a_required /
        // tier_c_peer) — against what we dialed FROM. If any of them no longer
        // match, a newer reload already moved past us: committing would roll the
        // shape (and live bearer / cert) back to our stale shape
        // OR clobber a newer reload's identity / Authorization posture with our
        // stale identity. Either way, abort — our dialed sessions
        // drop with `dialed`, the slot guards release on return. (The
        // doorbell/poll backstop re-converges any genuinely-newer on-disk config
        // on its next tick.) A concurrent IN-PLACE identity-only reload
        // (`!needs_redial`) also moves these fields, so it too trips the CAS and
        // we defer to it rather than overwrite it.
        {
            let mut manifest_guard = entry.manifest.write().expect("manifest lock poisoned");
            if !redial_committed_fields_eq(&manifest_guard, from_shape) {
                tracing::info!(
                    server = %name,
                    "live re-dial superseded by a concurrent reload — discarding the stale dial \
                     rather than rolling back the connection shape or identity posture",
                );
                return RedialOutcome::Superseded;
            }
            // Final tombstone gate, taken UNDER the manifest write lock and the
            // held slot conn locks, immediately before the irreversible advance.
            // The manifest advance and the lane swaps below MUST be all-or-
            // nothing with respect to a concurrent removal: if we advanced the
            // shape/identity here but then skipped the swaps because `removed`
            // raced in, the entry would be left with the NEW manifest over the
            // OLD connections — and since a tombstoned entry is still callable
            // (the retirement semantic keeps its live sessions until restart),
            // calls would serve old dial-time credentials under the new auth /
            // identity policy. So: if removed, bail WITHOUT
            // advancing — old manifest + old connections, self-consistent. If
            // NOT removed, advance and install EVERY lane below (no per-lane
            // removed skip): either way the live manifest and the live
            // connections agree.
            if entry.removed.load(Ordering::Acquire) {
                return RedialOutcome::Tombstoned;
            }

            // Publish the replacement inventory before advancing the manifest or
            // installing any session. Search-index failure is transaction failure:
            // restore the prior index slice and leave the old manifest + sessions
            // serving. This runs synchronously under all commit locks, so
            // cancellation cannot observe an index/session split.
            let previous_tools = guards
                .iter()
                .find_map(|guard| guard.as_ref().map(|conn| conn.tools.clone()))
                .unwrap_or_default();
            let classifications = manifest_guard.tools.clone();
            let classification_mode = manifest_guard.classification_mode;
            let publish_index = dialed
                .iter()
                .position(Option::is_some)
                .expect("at least one replacement dial succeeded");
            let common_live_tools = {
                let catalogs: Vec<&[Tool]> = dialed
                    .iter()
                    .filter_map(Option::as_ref)
                    .map(|conn| conn.live_tools.as_slice())
                    .collect();
                common_tool_catalog(&catalogs, classification_mode)
            };
            if let Err(error) = self.publish_classifications_to(
                entry,
                dialed[publish_index]
                    .as_mut()
                    .expect("selected replacement connection exists"),
                name,
                CatalogPublication {
                    source: source.publish_label(),
                    classifications: &classifications,
                    classification_mode,
                    previous_tools: &previous_tools,
                    live_tools: Some(&common_live_tools),
                },
                None,
            ) {
                tracing::error!(
                    server = %name,
                    error = %error,
                    "live re-dial aborted because search-index publication failed",
                );
                return RedialOutcome::Failed;
            }
            let published_tools = dialed[publish_index]
                .as_ref()
                .expect("selected replacement connection exists")
                .tools
                .clone();
            synchronize_published_catalogs(
                dialed
                    .iter_mut()
                    .filter_map(Option::as_mut)
                    .map(|conn| &mut conn.tools),
                &published_tools,
            );
            // Every lane records the refusals ITS OWN dial observed. Only the
            // publishing lane went through publication, and lanes may
            // advertise different schemas, so without this a malformed
            // sibling reports nothing anywhere.
            for conn in dialed.iter_mut().filter_map(Option::as_mut) {
                super::tool_listing::normalize_connection(name, conn);
            }
            if dialed
                .iter()
                .filter_map(Option::as_ref)
                .any(|conn| conn.live_tools != common_live_tools)
            {
                tracing::warn!(
                    server = %name,
                    common_tools = common_live_tools.len(),
                    "replacement lanes advertised different tool catalogs — publishing only their exact intersection",
                );
            }

            // Every conn lock is held, so the advance + the swaps below are a
            // single indivisible step from any caller's view. Tool classification
            // fields were already copied in place by `reload_manifests`; resource
            // claims advance here because they route to this exact backend. We
            // mirror those claims, the connection-shape fields, AND the coupled
            // hot-reloadable identity fields. `exchange` / `tier_c_peer` are mutually exclusive
            // with `auth.bearer_env` (a loader rule) and `tier_a_required` needs
            // `exchange`, so they must land TOGETHER with the auth shape —
            // `reload_manifests` deferred them to us precisely so a failed
            // re-dial can't leave the new identity applied over the old
            // bearer. On the failure / supersede / tombstone paths we
            // never reach here, so none of these advance.
            manifest_guard.transport = new.transport.clone();
            manifest_guard.protocol = new.protocol;
            manifest_guard.url = new.url.clone();
            manifest_guard.command = new.command.clone();
            manifest_guard.auth = new.auth.clone();
            manifest_guard.mtls = new.mtls.clone();
            manifest_guard.session = new.session.clone();
            manifest_guard.resources = new.resources.clone();
            manifest_guard.exchange = new.exchange.clone();
            manifest_guard.tier_a_required = new.tier_a_required;
            manifest_guard.tier_c_peer = new.tier_c_peer;
        }

        let mut redialed = 0usize;
        let mut down = 0usize;
        for (guard, conn) in guards.iter_mut().zip(dialed) {
            // No per-lane `removed` skip here — that is what would create the
            // advanced-manifest-over-old-connections hybrid.
            // We already gated the manifest advance on `removed` above, under the
            // same held locks, so reaching this loop means we committed to the
            // new shape/identity — install EVERY lane so the live connections
            // match the advanced manifest. A removal that lands during this loop
            // (the lock-free `removed` store) is observed by the post-loop check
            // and reported `Tombstoned`, but the connections it installed are the
            // NEW shape, consistent with the NEW manifest — never a torn posture.
            match conn {
                Some(conn) => {
                    **guard = Some(conn); // install the new shape; old session dropped
                    redialed += 1;
                }
                None => {
                    // This lane's new-shape dial failed. Clear it (dropping the
                    // old-shape session) so nothing serves the old bearer / cert
                    // under the now-advanced manifest; the re-probe re-dials it
                    // from the new shape.
                    **guard = None;
                    down += 1;
                }
            }
        }
        // Linearize recovery of the shared failure budget with the lane swap.
        // A call cannot fail on a newly installed lane until its writer drops,
        // so no post-commit breaker transition can be erased here.
        entry.breaker.reset();
        // Sampled while the installed connections are still guaranteed to be
        // what is served. Sampling after the guards drop would let a
        // concurrent classification or quarantine withhold the tool in the
        // gap, and the interval in which the dial served a refused schema
        // would go unrecorded.
        let (served_at_install, install_at) = {
            let quarantined = entry
                .quarantined
                .read()
                .expect("upstream quarantine lock poisoned");
            let at = self.audited_refusals.observe();
            (super::health::rejected_union(&guards, &quarantined), at)
        };
        let reconnect_revision_at_install = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .revision();
        drop(guards);
        drop(_structural_guard);

        // Before the tombstone check, because the sample is about connections
        // this call installed and published. A removal landing afterwards ends
        // that interval; it does not unmake it, and the outcome reported to the
        // caller has no bearing on what clients could reach in the meantime.
        self.record_new_refusals(name, entry, install_at, &served_at_install)
            .await;

        // A removal that landed AFTER the pre-advance gate (the lock-free
        // `removed` store) means we advanced + installed the new shape on an
        // entry that is now retiring. The live manifest and the live connections
        // still AGREE (both new) — no torn posture — but report `Tombstoned`
        // rather than claiming a live re-dial of an entry being retired; the
        // concurrent removal's reload owns the removal report.
        let outcome_guard = self.reload_lock.lock().await;
        if entry.removed.load(Ordering::Acquire) {
            return RedialOutcome::Tombstoned;
        }
        if !self.entry_is_current(name, entry) {
            return RedialOutcome::Superseded;
        }

        let converged = {
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            if state.record_success_if_revision(
                reconnect_revision_at_install,
                down > 0,
                new_credential_version,
            ) {
                super::reconnect::publish_schedule(name, &state);
                true
            } else {
                false
            }
        };
        if converged {
            entry
                .recovery
                .write()
                .expect("upstream recovery lock poisoned")
                .record_reconnect(
                    redialed,
                    entry.slots.len(),
                    partial_redial_error_class(down, last_err.as_ref()),
                );
            entry.reconnect_notify.notify_waiters();
        }
        drop(outcome_guard);
        match source {
            RedialSource::ConnectionShape => tracing::info!(
                server = %name,
                redialed,
                down,
                "live re-dialed upstream to the new connection shape (no restart)",
            ),
            RedialSource::CatalogRefresh => tracing::info!(
                server = %name,
                redialed,
                down,
                "upstream session replaced and tool catalog refreshed",
            ),
        }
        if matches!(source, RedialSource::ConnectionShape) {
            self.record_upstream_health(
                "UpstreamRedialed",
                waygate_mcp::AuditOutcome::Success,
                format!("server={name} redialed={redialed} down={down}"),
            )
            .await;
        }
        // The rows were written from the install-time sample above; the gauge
        // is sampled fresh, because a row is an event that was true while the
        // gauge is state a newer transition may already have changed.
        self.refresh_rejected_output_schemas(name).await;
        RedialOutcome::Redialed
    }

    /// Emit one `CatalogDrift` audit row per detected drift event so
    /// behavior drift / quarantine — previously metric/log-only and thus
    /// invisible in the activity feed — becomes a first-class audit row. A
    /// quarantined drift is recorded as `Denied` (the tool is now blocked) so
    /// it stands out from an informational drift (`Success`).
    ///
    /// The caller captures the active trace before a detached handoff. Events
    /// are built one at a time with that captured ID, so the submission task
    /// never needs request-span context or a second in-memory batch.
    pub(super) async fn emit_drift_audit(
        evidence: &waygate_mcp::audit::SharedEvidence,
        server: &str,
        drift: &[DriftReport],
        trace_id: Option<String>,
    ) {
        for d in drift {
            let outcome = if d.quarantined {
                waygate_mcp::AuditOutcome::Denied
            } else {
                waygate_mcp::AuditOutcome::Success
            };
            let reason = if d.quarantined {
                let risk = d
                    .risk
                    .map_or_else(|| "unclassified".to_string(), |r| format!("{r:?}"));
                // Name BOTH axes: the threshold covers `risk OR side_effects`, so
                // a low-risk side-effecting tool quarantines on `side_effects` —
                // the reason must say so or the audit row looks inconsistent.
                format!(
                    "behavior drift on {risk}-risk tool (side_effects={}) → quarantined \
                     (live schemas or security metadata diverged from the last observation)",
                    d.side_effects
                )
            } else {
                "behavior drift detected (live schemas or security metadata diverged from last observation)"
                    .to_string()
            };
            let mut event = waygate_mcp::AuditEvent::new("ToolDrift", outcome)
                .with_category(waygate_mcp::EvidenceCategory::CatalogDrift)
                .with_tool(server.to_string(), d.tool.clone())
                .with_reason(reason);
            event.trace_id.clone_from(&trace_id);
            evidence.record_chained_best_effort(event).await;
        }
    }

    /// Publish invariant: every write to `Connection.tools` and the per-server
    /// slice of the search index goes through this helper, and the caller MUST
    /// hold every connection lock whose session participates in the atomic
    /// replacement. The helper never yields: once the shared index changes,
    /// cancellation cannot interrupt the caller before it installs the matching
    /// replacement session(s). Callers pass the classification slice protected
    /// by their manifest commit guard, so filtering and publication use the
    /// exact view that the transaction validated.
    ///
    /// Boot is exempt because `connect_inner` builds entries before the pool is
    /// observable to any other task — its initial publish uses the dial-time
    /// owned manifest and there is no concurrent writer to race against.
    ///
    /// `source` is forwarded to the drift warnings so an operator can tell
    /// which path triggered a publish ("boot" / "reconnect" / "reload"). A
    /// multi-lane transaction passes `CatalogPublication::live_tools` as the
    /// exact intersection advertised by every successful lane; other callers
    /// use the supplied connection's own live catalog.
    fn publish_classifications_to(
        &self,
        entry: &UpstreamEntry,
        conn: &mut Connection,
        name: &str,
        publication: CatalogPublication<'_>,
        external_catalog_change: Option<&waygate_mcp::catalog_changes::ToolCatalogChange<'_>>,
    ) -> Result<(), String> {
        let CatalogPublication {
            source,
            classifications,
            classification_mode,
            previous_tools,
            live_tools,
        } = publication;
        let live_tools = live_tools.unwrap_or(&conn.live_tools);
        // Index and serving-session replacement form one synchronous catalog
        // publication. Stable discovery readers retry until both agree.
        let catalog_change = external_catalog_change
            .is_none()
            .then(|| self.tool_catalog_epoch.begin_change());
        let tools = publish_classified_tools(
            name,
            classifications,
            classification_mode,
            live_tools,
            source,
            |tools| {
                self.index
                    .as_ref()
                    .map(|idx| idx.replace_server(name, tools))
                    .transpose()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            },
        );
        let tools = match tools {
            Ok(tools) => tools,
            Err(error) => {
                if let Some(index) = self.index.as_ref() {
                    if let Err(rollback_error) = index.replace_server(name, previous_tools) {
                        tracing::error!(
                            server = %name,
                            error = %error,
                            rollback_error = %rollback_error,
                            "search index publish and rollback failed",
                        );
                    }
                }
                return Err(error);
            }
        };
        conn.tools = tools;
        super::tool_listing::normalize_connection(name, conn);
        let catalog_changed = !tool_catalogs_equal(&conn.tools, previous_tools);
        // Record per-tool behavior-hash drift
        // against the entry's in-process baseline, with auto-quarantine
        // applied per the pool's `quarantine_threshold`. Live
        // `tools/list` is the source of truth (we hash what the
        // upstream advertised, not the manifest-filtered subset) so a
        // drift on a quarantined / unclassified tool still surfaces.
        // Per-upstream — the first slot of a multi-slot publication records
        // the observation so sibling slots do not double-count it.
        let drift = entry.record_observed_schemas_against(
            name,
            &conn.live_tools,
            source,
            self.quarantine_threshold,
            classifications,
            classification_mode,
        );
        let quarantine_changed = drift.iter().any(|report| report.quarantined);
        if catalog_changed || quarantine_changed {
            if let Some(catalog_change) = catalog_change {
                catalog_change.commit();
            }
        }
        // Surface behavior drift / quarantine as `CatalogDrift` audit rows in the
        // activity feed. Capture the originating trace while its span is still
        // active, then hand the batch and trace snapshot to one task so this
        // synchronous lock-holding path never polls an arbitrary recorder
        // implementation. Production recording only submits to the bounded
        // chained queue; database latency stays in its workers. Empty on the
        // boot pass and when nothing drifted.
        if !drift.is_empty() {
            if let Some(evidence) = self.evidence.clone() {
                let server = name.to_string();
                let trace_id = waygate_telemetry::correlation::current_trace_id();
                tokio::spawn(async move {
                    Self::emit_drift_audit(&evidence, &server, &drift, trace_id).await;
                });
            }
        }
        Ok(())
    }

    /// After a live slot-resize rebuild inherits the
    /// replaced entry's behavior baseline, run behavior-drift detection on the
    /// freshly-dialed connection so a tool whose contract CHANGED on the new
    /// connection is audited (`ToolDrift`) and auto-quarantined (per
    /// `quarantine_threshold`) BEFORE the rebuilt entry serves traffic. A
    /// rebuild's fresh dial otherwise bypasses the drift check that a same-count
    /// redial / reconnect publish runs, so a resize that lands on an upstream
    /// whose behavior drifted would accept traffic on the unverified tool. Records
    /// against the inherited baseline only — NO index write, since the BM25
    /// publish is deferred to the stage-2 commit — mirroring the boot seed's
    /// "first connected slot observes for the whole entry" pattern.
    async fn detect_drift_on_rebuilt_entry(&self, entry: &UpstreamEntry, name: &str) {
        for slot in &entry.slots {
            if let Some(conn) = slot.conn.read().await.as_ref() {
                let drift = entry.record_observed_schemas(
                    name,
                    &conn.live_tools,
                    "rebuild",
                    self.quarantine_threshold,
                );
                if !drift.is_empty() {
                    if let Some(evidence) = self.evidence.clone() {
                        let server = name.to_string();
                        let trace_id = waygate_telemetry::correlation::current_trace_id();
                        tokio::spawn(async move {
                            Self::emit_drift_audit(&evidence, &server, &drift, trace_id).await;
                        });
                    }
                }
                return;
            }
        }
    }

    /// Apply a fresh on-disk manifest set to the live pool. Add/remove of
    /// upstreams is HOT: a newly-listed server is dialed and published into the
    /// registry map + search index, and a delisted server is tombstoned,
    /// drained, dropped from the map, and pulled from the index — all without a
    /// restart. In-place edits to an EXISTING entry (tool classifications,
    /// identity-chaining fields, a same-slot-count live re-dial) mutate through
    /// the shared `Arc` and need no map swap. A slot-count-changing shape edit
    /// (a stdio↔network flip or a `session.concurrency` change) is REBUILT
    /// live: a fresh entry with the new slot count is dialed and swapped into
    /// the registry under the structural fence, the old entry draining via its
    /// `Arc` — landing in [`ReloadReport::redialed`], or in
    /// [`ReloadReport::redial_failed`] if every new-shape dial fails (old kept,
    /// restart-required). An existing server edit that changes resource
    /// ownership and connection shape together is refused as a complete set
    /// before mutation and lands in
    /// [`ReloadReport::resource_shape_restart_required`]. Returns a
    /// [`ReloadReport`] of what changed so the
    /// SIGHUP / doorbell / dashboard paths can log it and drive the per-replica
    /// activation audit.
    pub async fn reload_manifests(
        &self,
        fresh: &BTreeMap<String, UpstreamManifest>,
    ) -> ReloadReport {
        // Monotonic generation for this reload attempt. The highest generation to
        // reach the structural commit wins; a slower, staler reload that arrives
        // at the commit later is fenced out so it can neither resurrect a server a
        // newer reload omitted nor tombstone one a newer reload kept.
        // Handed out before any dialing so it reflects reload-start order.
        let my_gen = self.next_reload_gen.fetch_add(1, Ordering::AcqRel);
        let mut report = ReloadReport {
            catalog_generation: my_gen,
            ..ReloadReport::default()
        };

        // Every reload holds the read side of the fleet routing fence unless it
        // changes resource ownership, in which case it upgrades to the write
        // side and refreshes its registry snapshot. That makes a resource-set
        // transaction exclusive with concurrent shape-only reloads too: a
        // shape edit cannot slip between the coupled-change preflight and the
        // per-entry commits below. Ordinary shape/tool reloads remain mutually
        // concurrent, and resource resolvers remain concurrent with read-side
        // reloads.
        let resource_routing_read_guard = self.resource_routing.read().await;
        let mut current = self.entries.load_full();
        let resource_routing_change_requested = resource_routing_changed(&current, fresh);
        let mut resource_routing_write_guard = None;
        let resource_routing_read_guard = if resource_routing_change_requested {
            drop(resource_routing_read_guard);
            resource_routing_write_guard = Some(self.resource_routing.write().await);
            // A resource-changing reload may have completed while this attempt
            // waited to upgrade. Decide and mutate from one snapshot protected
            // by the acquired write side.
            current = self.entries.load_full();
            None
        } else {
            Some(resource_routing_read_guard)
        };
        let mut resource_routing_read_guard = resource_routing_read_guard;
        let resource_routing_write_guard = resource_routing_write_guard;
        let resource_topology_change_requested = resource_topology_changed(&current, fresh);

        // One owned snapshot of the live registry for DECIDING what to dial /
        // update. The structural commit (stage 2) re-reads the live map under the
        // `reload_lock` and reconciles it to exactly `fresh`; removals are drained
        // there too, so a fenced reload never mutates a live entry. In-place
        // updates below mutate the shared `Arc<UpstreamEntry>` objects (visible
        // immediately) and need no lock — the per-entry redial CAS already
        // serializes concurrent same-entry shape changes.
        // A resource claim is meaningful only together with the backend that
        // serves it. Refuse the complete manifest set before any mutation when
        // an existing live server changes both in one edit. Otherwise a failed
        // or partially successful redial could expose old claims with a new
        // backend, new claims with an old backend, or a half-applied prefix move
        // involving another server. Resource-only edits still advance under the
        // fleet routing fence below; shape-only edits keep their live-redial path.
        for (name, entry) in current.iter() {
            if entry.removed.load(Ordering::Acquire) {
                continue;
            }
            let Some(new_manifest) = fresh.get(name) else {
                continue;
            };
            let old_manifest = entry.manifest_snapshot();
            if resource_shape_change_requires_restart(&old_manifest, new_manifest) {
                report.resource_shape_restart_required.push(name.clone());
            }
        }
        if !report.resource_shape_restart_required.is_empty() {
            report.resource_shape_restart_required.sort();
            return report;
        }
        // Resource ownership is a fleet-wide routing table, so every manifest
        // participating in one reload must advance behind one write-side
        // fence. In particular, moving a prefix between two existing servers
        // must never expose the per-entry intermediate state (old owner already
        // cleared, or both owners present) to a resolver. The guard is held
        // through the structural commit below; readers therefore observe the
        // complete old set or the complete admitted fresh set.
        let resource_routing_change_requested = resource_routing_changed(&current, fresh);
        if resource_routing_change_requested {
            // Advance only after every admitted read from the previous
            // generation has released the read side. A resolution that already
            // finished carries the old value and will be refused before
            // dispatch; a new snapshot waits for this complete activation.
            self.resource_routing_generation
                .fetch_add(1, Ordering::AcqRel);
        }
        // Freshly-built (dialed) entries to publish in stage 2.
        let mut to_add: Vec<(String, Arc<UpstreamEntry>)> = Vec::new();

        for (name, new_manifest) in fresh {
            let existing = current.get(name).cloned();
            // ADD / hot re-add: the name is absent, OR its entry was tombstoned
            // by a removal (in-flight holders may still reference it, but it is
            // leaving the map). Build a fresh, dialed entry — bounded by
            // `redial_dial_timeout` so a black-hole new target can't wedge this
            // awaited reload (the same bound the live re-dial path accepts).
            // The index publish is DEFERRED (index = None here): a superseded add
            // must not leave orphaned BM25 docs, so the fenced commit (stage 2)
            // publishes the tools only for entries it actually commits. Like boot,
            // the entry is inserted even when its dial fails (slots down) — the
            // re-probe heals it from the manifest. `my_gen` stamps the new entry's
            // `last_reload_gen` so an OLDER concurrent reload that finds it is
            // fenced from rolling its fields back.
            let rebuild = existing
                .as_ref()
                .is_none_or(|e| e.removed.load(Ordering::Acquire));
            if rebuild {
                let entry = Self::build_entry(
                    name,
                    new_manifest.clone(),
                    self.issuer.as_ref(),
                    self.exchange.as_ref(),
                    None,
                    pool_size_from_env(),
                    self.redial_dial_timeout,
                    my_gen,
                    self.reconnect_policy,
                    self.reconnect_notify.clone(),
                )
                .await;
                // Reported as `added` only if the fenced commit (stage 2)
                // actually publishes it — a superseded reload adds nothing.
                to_add.push((name.clone(), entry));
                continue;
            }
            // Existing, live entry → in-place update. Re-borrow as `&Arc` so the
            // block below is byte-for-byte the pre-hot-swap update path.
            let entry_owned = existing.expect("rebuild=false ⇒ existing is Some");
            let entry = &entry_owned;
            // Classification and lane publication are one observable commit.
            // Take every lane before the manifest so status readers either see
            // the old classification generation or the fully-republished new
            // one, never a manifest from one generation and lane catalogs from
            // another. The locks are released before any slow replacement dial.
            let mut classification_guards = Vec::with_capacity(entry.slots.len());
            for slot in &entry.slots {
                classification_guards.push(slot.conn.write().await);
            }
            let (
                needs_redial,
                identity_changed,
                from_shape,
                resize,
                tool_classification_changed,
                resource_classification_changed,
            ) = {
                let mut guard = entry.manifest.write().expect("manifest lock poisoned");
                // Per-entry generation fence: if a newer reload has
                // already applied an in-place update to this entry, ours is stale —
                // apply NOTHING (no classification, identity, or redial), so a
                // reload delayed in a slow hot-add dial can't roll back a kept
                // entry's classifications/identity after a newer reload advanced
                // them. The check + the field writes below are atomic under this
                // manifest write lock, which already serializes per-entry mutation.
                if my_gen < entry.last_reload_gen.load(Ordering::Acquire) {
                    (false, false, None, false, false, false)
                } else {
                    entry.last_reload_gen.store(my_gen, Ordering::Release);
                    let transport_changed =
                        !matches_transport(&guard.transport, &new_manifest.transport)
                            || guard.protocol != new_manifest.protocol
                            || guard.url != new_manifest.url
                            || guard.command != new_manifest.command
                            || !auth_eq(guard.auth.as_ref(), new_manifest.auth.as_ref())
                            || guard.mtls != new_manifest.mtls
                            || !session_connection_shape_eq(
                                guard.session.as_ref(),
                                new_manifest.session.as_ref(),
                            );
                    // A connection-shape change that keeps the same slot count is
                    // re-dialed live below — the old session is torn down
                    // and re-dialed in place with the new shape (fresh identity
                    // cell, re-resolved bearer, freshly read mTLS material).
                    let needs_redial = transport_changed && slot_count_stable(&guard, new_manifest);
                    // A connection-shape change that RESIZES the slot pool (a
                    // stdio↔network flip, or a `session.concurrency` change) can't
                    // re-dial the existing slots — the `Vec` is sized once per entry.
                    // It is REBUILT live instead: the block below dials a fresh
                    // entry with the new slot count and replaces this one under the
                    // structural fence (reported `redialed`), or keeps this entry on
                    // a failed dial (reported `redial_failed`). NOT restart-required
                    // (the old `transport_changed` bucket is retired). We skip ALL
                    // in-place mutation of THIS entry: the fresh entry carries the
                    // new shape + classification + identity together (atomic, no
                    // exclusivity-violating bearer/exchange hybrid), and a failed
                    // rebuild leaves this old entry whole.
                    let resize = transport_changed && !needs_redial;
                    // Capture the CAS baseline for `redial_entry` HERE — under the
                    // same lock that decided `needs_redial`, and before any in-place
                    // edits below — so it is the exact shape + identity this reload
                    // transitions FROM. Capturing it later (inside `redial_entry`,
                    // after this lock is dropped) would risk snapshotting a
                    // concurrent newer reload's state as the baseline and then
                    // overwriting it past a shape-only-looking CAS.
                    let from_shape = needs_redial.then(|| guard.clone());
                    // Apply the tool classification in place for ALL paths,
                    // including a resize. Classification is a
                    // hot, catalog-cataloged field that is NOT coupled to the
                    // connection shape: the SIGHUP/doorbell handler reconciles the
                    // governed catalog from the fresh manifests on every non-noop
                    // reload, and `resolve_invocation_tool` treats the catalog (and this
                    // manifest fallback) as authoritative for authz. If a resize
                    // skipped this apply while the catalog still advanced, a failed
                    // rebuild that KEEPS the old entry would leave the entry serving
                    // old tools while authz reads the new (possibly downgraded) risk
                    // / side_effects / requires_approval — a security desync. So the
                    // classification advances on the kept entry regardless of whether
                    // the SHAPE rebuild lands; on a successful rebuild the fresh
                    // entry carries the same new tools and replaces this one (the
                    // in-place apply is then moot but harmless).
                    let tool_classification_changed = guard.tools != new_manifest.tools
                        || guard.classification_mode != new_manifest.classification_mode
                        || guard.approval_mode != new_manifest.approval_mode;
                    let resource_classification_changed = guard.resources != new_manifest.resources;
                    if tool_classification_changed
                        || (resource_classification_changed && !transport_changed)
                    {
                        report.classifications_updated.push(name.clone());
                    }
                    if resource_classification_changed && !transport_changed {
                        // A resources-only edit is hot. When the connection
                        // shape also changes, routing must advance atomically
                        // with the backend it names, so the redial/rebuild
                        // success paths below commit the complete new manifest
                        // and a failure keeps these old claims.
                        guard.resources = new_manifest.resources.clone();
                    }
                    if tool_classification_changed {
                        let catalog_change = self.tool_catalog_epoch.begin_change();
                        // Arm before publishing the new manifest fields. A
                        // resolver that observes the new fields must therefore
                        // also observe the fence and cannot combine them with
                        // the previous catalog generation.
                        self.mark_catalog_transitions(
                            name,
                            changed_classified_tools(&guard, new_manifest),
                            my_gen,
                        );
                        guard.tools = new_manifest.tools.clone();
                        guard.classification_mode = new_manifest.classification_mode;
                        guard.approval_mode = new_manifest.approval_mode;
                        let common_live_tools = {
                            let catalogs = classification_guards
                                .iter()
                                .filter_map(|conn_guard| {
                                    conn_guard.as_ref().map(|conn| conn.live_tools.as_slice())
                                })
                                .collect::<Vec<_>>();
                            common_tool_catalog(&catalogs, new_manifest.classification_mode)
                        };
                        let mut published_tools = None;
                        for conn_guard in &mut classification_guards {
                            let Some(conn) = conn_guard.as_mut() else {
                                continue;
                            };
                            if published_tools.is_none() {
                                let previous_tools = conn.tools.clone();
                                match self.publish_classifications_to(
                                    entry,
                                    conn,
                                    name,
                                    CatalogPublication {
                                        source: "reload",
                                        classifications: &guard.tools,
                                        classification_mode: guard.classification_mode,
                                        previous_tools: &previous_tools,
                                        live_tools: Some(&common_live_tools),
                                    },
                                    Some(&catalog_change),
                                ) {
                                    Ok(()) => published_tools = Some(conn.tools.clone()),
                                    Err(error) => tracing::error!(
                                        server = %name,
                                        error = %error,
                                        "classification reload kept the prior serving and search inventory because search-index publication failed",
                                    ),
                                }
                            }
                        }
                        if let Some(published_tools) = published_tools.as_deref() {
                            synchronize_published_catalogs(
                                classification_guards.iter_mut().filter_map(|conn_guard| {
                                    conn_guard.as_mut().map(|conn| &mut conn.tools)
                                }),
                                published_tools,
                            );
                        }
                        // The transition fence, manifest fields, serving
                        // inventory, drift quarantine, and every lane's
                        // filtered catalog are one complete publication. A
                        // failed index replacement still leaves the governance
                        // fence visible, so it also invalidates cached lists.
                        catalog_change.commit();
                    }
                    // The hot-reloadable identity-chaining fields (exchange /
                    // tier_a_required / tier_c_peer) are runtime-tunable per-call
                    // reads — BUT they are COUPLED to the auth shape: the loader
                    // makes `exchange` and `tier_c_peer` mutually exclusive with
                    // `auth.bearer_env`, and `tier_a_required` needs `exchange`. A
                    // reload that moves between bearer_env and exchange/tier_c
                    // changes the (shape) auth field AND these identity fields. If
                    // we applied identity here but the coupled auth shape did NOT
                    // land in the same step, the stored manifest would hold the new
                    // exchange/tier_c alongside the OLD bearer_env — an exclusivity-
                    // violating hybrid where the surviving old connection serves the
                    // baked static bearer AND new per-call Authorization.
                    // The auth shape lands together with these identity
                    // fields ONLY when there is NO shape change at all, so gate the
                    // in-place apply on `!transport_changed`:
                    //   - no shape change at all ⇒ apply in place here (the pure
                    //     runtime-tunable identity update — auth unchanged, so no
                    //     coupling hazard), but
                    //   - shape change re-dialed live ⇒ DEFER to `redial_entry`'s
                    //     commit so identity advances ATOMICALLY with the auth shape
                    //     (on a failed re-dial neither lands), and
                    //   - shape change that RESIZES the pool (`resize`: a stdio↔network
                    //     flip or `session.concurrency` change) ⇒ apply NEITHER here —
                    //     the rebuild block below dials a fresh entry that carries the
                    //     new auth shape AND new identity together (atomic, no
                    //     bearer/exchange hybrid), and a failed rebuild keeps this old
                    //     entry's posture whole.
                    //
                    // `resize` already implies `transport_changed`, so the
                    // `!transport_changed` gate below also excludes it.
                    let identity_changed = guard.exchange != new_manifest.exchange
                        || guard.tier_a_required != new_manifest.tier_a_required
                        || guard.tier_c_peer != new_manifest.tier_c_peer;
                    if !transport_changed {
                        // Retry policy is request-path configuration, not
                        // connection shape. Apply the exact session block in
                        // place when its shape fields are unchanged, avoiding
                        // a needless replacement of healthy sessions.
                        if !setup_retry_policy_eq(&guard, new_manifest) {
                            report.session_policy_updated.push(name.clone());
                        }
                        guard.session = new_manifest.session.clone();
                        if identity_changed {
                            report.identity_updated.push(name.clone());
                        }
                        guard.exchange = new_manifest.exchange.clone();
                        guard.tier_a_required = new_manifest.tier_a_required;
                        guard.tier_c_peer = new_manifest.tier_c_peer;
                    }
                    (
                        needs_redial,
                        identity_changed,
                        from_shape,
                        resize,
                        tool_classification_changed,
                        resource_classification_changed,
                    )
                }
            };
            // A classification-only edit changes which tools are served
            // without dialing, and a refusal is reported only for a tool the
            // gateway actually serves — so promoting a tool whose schema was
            // stripped starts serving it without an output contract, with no
            // dial to say so. Sample that while the guards still hold the
            // promotion: `reload_manifests` permits concurrent in-place
            // updates, and one that demotes the tool again before this task
            // resumes would otherwise erase the evidence that clients could
            // see it at all.
            let served_at_commit = report
                .classifications_updated
                .iter()
                .any(|n| n == name)
                .then(|| {
                    let quarantined = entry
                        .quarantined
                        .read()
                        .expect("upstream quarantine lock poisoned");
                    let at = self.audited_refusals.observe();
                    (
                        super::health::rejected_union(&classification_guards, &quarantined),
                        at,
                    )
                });
            drop(classification_guards);

            if let Some((served, commit_at)) = served_at_commit {
                self.record_new_refusals(name, entry, commit_at, &served)
                    .await;
                // The gauge is current state, so it is sampled fresh rather
                // than from the commit — a demotion that overtook this one is
                // the truth about what is served now.
                self.refresh_rejected_output_schemas(name).await;
            }

            // A slot-count-changing shape edit is REBUILT live. Build a fresh
            // entry with the new shape (new slot count), dialed lock-free here just
            // like a hot add — `index = None` defers the BM25 publish to the stage-2
            // commit so a superseded / failed rebuild never pollutes the index, and
            // `initial_gen = my_gen` fences the fresh entry as of THIS reload.
            //
            //   - ≥1 lane dials ⇒ stage it in `to_add`; the stage-2 reconcile prefers
            //     a freshly-built entry over the live one, so it REPLACES the old
            //     entry under the structural fence. The old entry is NOT tombstoned —
            //     in-flight calls on the old shape complete; it drains when its last
            //     Arc holder finishes. Reported `redialed`.
            //   - every lane fails ⇒ discard the fresh entry, KEEP the old entry
            //     serving, and report `redial_failed` (restart-required), exactly like
            //     the same-slot-count redial's failed path.
            //
            // `continue` past the same-count redial below: `resize` and
            // `needs_redial` are mutually exclusive, and classification was
            // already published atomically to the old entry above while the
            // rebuilt entry carries the same new classification.
            if resize {
                let new_entry = Self::build_entry(
                    name,
                    new_manifest.clone(),
                    self.issuer.as_ref(),
                    self.exchange.as_ref(),
                    None,
                    pool_size_from_env(),
                    self.redial_dial_timeout,
                    my_gen,
                    self.reconnect_policy,
                    self.reconnect_notify.clone(),
                )
                .await;
                if new_entry.any_connected().await {
                    // The fresh entry would otherwise start with an EMPTY drift
                    // quarantine and a fresh schema baseline, silently clearing an
                    // active quarantine and re-baselining schema history without an
                    // operator `clear_quarantine` or a process restart.
                    // Inherit both from the entry it replaces so the dispatch
                    // BLOCK and the observation baseline survive the rebuild; a later
                    // reconnect re-measures drift against the carried baseline.
                    new_entry.inherit_drift_state_from(entry).await;
                    // Drift-check the freshly-dialed connection against the inherited
                    // baseline so a behavior-contract change on the new connection is audited +
                    // auto-quarantined before the rebuilt entry serves traffic — the
                    // rebuild's fresh dial otherwise bypasses the drift detection that
                    // a same-count redial / reconnect publish runs.
                    self.detect_drift_on_rebuilt_entry(&new_entry, name).await;
                    if resource_classification_changed && !tool_classification_changed {
                        report.classifications_updated.push(name.clone());
                    }
                    report.redialed.push(name.clone());
                    to_add.push((name.clone(), new_entry));
                    continue;
                }
                // Every new-shape lane failed: discard the fresh entry and KEEP the
                // old one serving (restart-required). Tool classifications were
                // already republished atomically above because their catalog
                // authority advanced independently; resource claims stay old
                // with the old backend because the new routing never activated.
                report.redial_failed.push(name.clone());
                continue;
            }

            // Connection-shape changed with a stable slot count —
            // tear down + re-dial live. The dial happens here, outside the
            // manifest and lane locks dropped just above. Tool classification
            // was already committed to every old lane; resource routing commits
            // only with a successful re-dial. A failed re-dial therefore leaves
            // the old backend and its old resource claims together.
            if needs_redial {
                let from_shape = from_shape
                    .as_ref()
                    .expect("from_shape is captured under the lock whenever needs_redial");
                match self
                    .redial_entry(
                        name,
                        entry,
                        new_manifest,
                        from_shape,
                        RedialSource::ConnectionShape,
                    )
                    .await
                {
                    RedialOutcome::Redialed => {
                        if resource_classification_changed && !tool_classification_changed {
                            report.classifications_updated.push(name.clone());
                        }
                        report.redialed.push(name.clone());
                        // The coupled identity fields were deferred from the sync
                        // block and advanced ATOMICALLY with the shape inside
                        // redial_entry; report them now that they actually landed.
                        if identity_changed {
                            report.identity_updated.push(name.clone());
                        }
                    }
                    RedialOutcome::Failed => {
                        report.redial_failed.push(name.clone());
                        // Neither shape nor identity advanced — the old auth
                        // posture is preserved. Do NOT report identity_updated:
                        // it was not applied (no exclusivity-violating hybrid).
                    }
                    // Tombstoned by a concurrent overlapping reload mid-redial;
                    // that reload owns the removal report, not this one.
                    RedialOutcome::Tombstoned => {}
                    // Superseded by a newer concurrent re-dial that committed a
                    // different shape; reported by neither bucket here (the
                    // winner's reload owns the outcome).
                    RedialOutcome::Superseded => {}
                }
            }
        }

        // An undeclared legacy resource server has no routing-table row, but
        // adding or removing it can still change enumeration ownership and
        // ambiguity. Its potentially slow dial ran concurrently under the read
        // side above. Upgrade only now, immediately before structural publish,
        // so an admitted old-generation read drains before the topology and
        // generation become observable without serializing independent dials.
        let mut late_resource_routing_write_guard = None;
        if resource_topology_change_requested && resource_routing_write_guard.is_none() {
            drop(resource_routing_read_guard.take());
            late_resource_routing_write_guard = Some(self.resource_routing.write().await);
            // A resource-changing reload may have been queued ahead of this
            // late upgrade and committed while this attempt waited. Stage 1
            // was decided against the earlier claims, so publishing its newer
            // topology now could claim convergence while preserving that
            // intervening routing set. Refuse this attempt as superseded; the
            // reload backstop retries from one write-protected snapshot.
            let protected_current = self.entries.load_full();
            if resource_routing_changed(&protected_current, fresh) {
                report.superseded = true;
                return report;
            }
        }
        let _resource_routing_read_guard = resource_routing_read_guard;
        let _resource_routing_write_guard = resource_routing_write_guard;
        let _late_resource_routing_write_guard = late_resource_routing_write_guard;

        // STAGE 2 — commit the structural change under `reload_lock`, generation-
        // fenced. Dialing and other slow work above ran without this pool-level
        // lock; only short registry and session/index commit sections serialize.
        // The fence makes the NEWEST reload
        // authoritative: a stale reload whose slow dial lands it here after a
        // newer reload already committed is abandoned — it must not publish its
        // (superseded) view, or it could resurrect a server the newer reload
        // omitted. Removals are drained HERE too, under the lock,
        // ONLY by the winning reload, so a fenced reload never tombstones a live
        // entry that a newer reload kept.
        {
            let _commit_guard = self.reload_lock.lock().await;
            if my_gen >= self.applied_reload_gen.load(Ordering::Acquire) {
                self.applied_reload_gen.store(my_gen, Ordering::Release);
                if resource_topology_change_requested && !resource_routing_change_requested {
                    self.resource_routing_generation
                        .fetch_add(1, Ordering::AcqRel);
                }
                let live = self.entries.load_full();
                // Live entries the desired set omits — the removals for this reload.
                let dropped: Vec<String> = live
                    .keys()
                    .filter(|n| !fresh.contains_key(*n))
                    .cloned()
                    .collect();
                // Missing-fresh-key race: a fresh key our pre-lock
                // snapshot had (so we never dialed it — it went through the in-place
                // update branch, not the rebuild branch) but that a concurrent
                // reload REMOVED from the live map before our commit. We can't
                // materialize it here without a dial, and we deliberately don't dial
                // under `reload_lock` (it would block every other reload behind a
                // bounded-but-real dial — the whole point of the narrow lock). So we
                // mark this reload as NOT fully live: the callers skip its activation
                // / heartbeat / turnstile-pointer writes (the registry doesn't match
                // `fresh`), and the poll / doorbell backstop re-adds the key from
                // disk on the next tick. `built` is consumed by the reconcile below,
                // so check membership against `to_add` here.
                let materializable = |name: &String| {
                    to_add.iter().any(|(n, _)| n == name)
                        || live
                            .get(name)
                            .is_some_and(|e| !e.removed.load(Ordering::Acquire))
                };
                if !fresh.keys().all(materializable) {
                    report.superseded = true;
                }
                // A topology change is adds-to-publish OR drops. A pure in-place
                // reload (classifications / identity / redial only) leaves the map
                // untouched — those entries were mutated through their shared Arcs.
                if !to_add.is_empty() || !dropped.is_empty() {
                    let mut catalog_changed = !dropped.is_empty();
                    // Drain every dropped entry before starting publication, while
                    // the old map and its dispatch contract remain live. Retaining
                    // every slot guard prevents a reconnect from publishing between
                    // this barrier and the later tombstone/index/map commit.
                    let mut dropped_slot_guards = Vec::new();
                    for name in &dropped {
                        let entry = &live[name];
                        for slot in &entry.slots {
                            dropped_slot_guards.push(slot.conn.write().await);
                        }
                    }
                    // Reconcile the published map to EXACTLY `fresh`: prefer this
                    // reload's freshly-dialed entry, else keep the currently-live
                    // one. Reconciling (rather than applying a stale add/remove
                    // delta) means the published map is always one reload's COMPLETE
                    // view, never a merge of two divergent reloads.
                    // Slow entry reads and reconnect drains complete before the
                    // synchronous publication. The BM25 batch and map swap are then
                    // fenced as one discovery-visible generation.
                    let mut built: HashMap<&str, Arc<UpstreamEntry>> = to_add
                        .iter()
                        .map(|(n, e)| (n.as_str(), e.clone()))
                        .collect();
                    let mut added = Vec::new();
                    let mut next: HashMap<String, Arc<UpstreamEntry>> =
                        HashMap::with_capacity(fresh.len());
                    for name in fresh.keys() {
                        let built_entry = built.remove(name.as_str());
                        let live_entry = live.get(name);
                        // Prefer this reload's freshly-built (rebuild / add) entry,
                        // EXCEPT when a NEWER reload already updated the live entry in
                        // place after we built ours. A rebuild's fresh entry carries
                        // THIS reload's (possibly older) manifest; the
                        // `applied_reload_gen` fence only blocks us if a higher gen
                        // already COMMITTED, so an older resize that reaches the commit
                        // first would otherwise replace a live entry a newer in-place
                        // reload just mutated — discarding that newer reload's
                        // classification / identity, which it has no built replacement
                        // to reapply. Generation-fence the swap here
                        // too: if the live entry's `last_reload_gen` exceeds `my_gen`,
                        // keep it and mark this reload superseded (its set is not the
                        // one now live); the poll / doorbell backstop re-converges on
                        // the newest set.
                        let entry = match (built_entry, live_entry) {
                            (Some(_stale), Some(live))
                                if live.last_reload_gen.load(Ordering::Acquire) > my_gen =>
                            {
                                report.superseded = true;
                                Some(live.clone())
                            }
                            (Some(built), _) => Some(built),
                            (None, live) => live.cloned(),
                        };
                        if let Some(entry) = entry {
                            // Reported `added` iff the live map lacked it (or held
                            // only a tombstone) — the honest add count after the
                            // fence, computed from the actual map transition.
                            if live_entry.is_none_or(|e| e.removed.load(Ordering::Acquire)) {
                                added.push(name.clone());
                            }
                            next.insert(name.clone(), entry);
                        }
                    }
                    let next_arc = Arc::new(next);
                    // A structural rebuild can replace an existing entry without
                    // being an add/remove. Compare the exact published descriptor
                    // views before exposing the new map so a rebuild that changes
                    // tools notifies downstream sessions, while a shape-only
                    // rebuild with identical tools remains quiet. A stale built
                    // entry rejected by the generation fence leaves the same Arc
                    // in `next` and therefore is not a change.
                    for (name, _) in &to_add {
                        let Some(next_entry) = next_arc.get(name) else {
                            continue;
                        };
                        match live.get(name) {
                            None => catalog_changed = true,
                            Some(previous) if previous.removed.load(Ordering::Acquire) => {
                                catalog_changed = true;
                            }
                            Some(previous) if !Arc::ptr_eq(previous, next_entry) => {
                                if !tool_catalogs_equal(
                                    &previous.published_tools().await,
                                    &next_entry.published_tools().await,
                                ) {
                                    catalog_changed = true;
                                }
                            }
                            Some(_) => {}
                        }
                    }
                    // Prepare the complete next BM25 snapshot before entering
                    // the non-awaiting publication section. Structural reload
                    // is the recovery boundary for a prior index error: only a
                    // full rebuild can prove no committed-but-unpublished slice
                    // survives from a failed reader handoff.
                    let mut index_slices = Vec::new();
                    if catalog_changed && self.index.is_some() {
                        for (name, entry) in next_arc.iter() {
                            index_slices.push((name.clone(), entry.published_tools().await));
                        }
                    }

                    let published = if catalog_changed {
                        let change = self.tool_catalog_epoch.begin_change();
                        let index_result = self.index.as_ref().map_or(Ok(()), |idx| {
                            idx.replace_all_servers(
                                index_slices
                                    .iter()
                                    .map(|(name, tools)| (name.as_str(), tools.as_slice())),
                            )
                        });
                        if let Err(error) = index_result {
                            tracing::warn!(
                                error = %error,
                                "structural reload kept the prior topology because search-index publication failed",
                            );
                            report.superseded = true;
                            false
                        } else {
                            for name in &dropped {
                                let entry = &live[name];
                                entry.removed.store(true, Ordering::Release);
                                entry.retire_reconnect(name);
                            }
                            for name in &added {
                                if let Some(manifest) = fresh.get(name) {
                                    self.mark_catalog_transitions(
                                        name,
                                        manifest.tools.iter().map(|tool| tool.name.clone()),
                                        my_gen,
                                    );
                                }
                            }
                            self.entries.store(next_arc.clone());
                            report.added.extend(added.iter().cloned());
                            report.removed.extend(dropped.iter().cloned());
                            change.commit();
                            true
                        }
                    } else {
                        self.entries.store(next_arc.clone());
                        true
                    };
                    drop(dropped_slot_guards);

                    if published {
                        for name in &dropped {
                            // A removed upstream publishes nothing, so its
                            // server-labelled gauges must not retain stale facts.
                            waygate_telemetry::metrics::set_rejected_output_schemas(name, 0);
                            waygate_telemetry::metrics::set_unregisterable_input_schemas(name, 0);
                            self.zero_protocol_generation_gauge(name).await;
                            self.forget_audited_refusals(name).await;
                        }
                        // Hot-added and slot-resized entries were dialed above and
                        // are only now the committed topology, so this is the
                        // first point their rejection sets can be attributed to a
                        // live upstream. Without it, a server added or resized at
                        // runtime strips malformed schemas silently.
                        for (name, _) in &to_add {
                            self.refresh_rejected_output_schemas(name).await;
                            if let Some(entry) = next_arc.get(name) {
                                let state = entry
                                    .reconnect
                                    .lock()
                                    .expect("upstream reconnect lock poisoned");
                                super::reconnect::publish_schedule(name, &state);
                            }
                        }
                        self.reconnect_notify.notify_waiters();
                    }
                }
            } else {
                // Superseded by a newer reload — abandon the structural commit
                // (the dialed `to_add` entries just drop, and they never published
                // to the index). Flag it so the doorbell / SIGHUP callers skip the
                // activation + heartbeat audit: this reload's manifest set is NOT
                // the one now live, and recording it would claim the replica is
                // serving a config that didn't win. The in-place
                // stage-1 work that landed is the newer reload's concern now.
                report.superseded = true;
            }
        }

        report.added.sort();
        report.removed.sort();
        report.redialed.sort();
        report.redial_failed.sort();
        report.resource_shape_restart_required.sort();
        report.classifications_updated.sort();
        report.identity_updated.sort();
        report.session_policy_updated.sort();
        report
    }
}

#[cfg(test)]
mod catalog_refresh_tests {
    use std::sync::Arc;

    use rmcp::model::Tool;
    use serde_json::json;

    use super::{
        common_tool_catalog, partial_redial_error_class, synchronize_published_catalogs,
        synchronize_reconnect_catalogs, CatalogRefreshOutcome, RedialFailure,
    };
    use crate::UpstreamErrorClass;

    fn tool(name: &str, schema_property: Option<&str>) -> Tool {
        let mut properties = serde_json::Map::new();
        if let Some(property) = schema_property {
            properties.insert(property.to_owned(), json!({"type": "string"}));
        }
        let schema = json!({"type": "object", "properties": properties})
            .as_object()
            .expect("schema object")
            .clone();
        Tool::new(
            name.to_owned(),
            format!("{name} description"),
            Arc::new(schema),
        )
    }

    #[test]
    fn catalog_refresh_outcome_strings_are_stable() {
        assert_eq!(CatalogRefreshOutcome::Updated.as_str(), "updated");
        assert_eq!(CatalogRefreshOutcome::Unchanged.as_str(), "unchanged");
        assert_eq!(CatalogRefreshOutcome::Failed.as_str(), "failed");
        assert_eq!(CatalogRefreshOutcome::Superseded.as_str(), "superseded");
        assert_eq!(CatalogRefreshOutcome::Removed.as_str(), "removed");
    }

    #[test]
    fn partial_redial_preserves_the_failed_lanes_bounded_class() {
        let timeout = RedialFailure {
            class: UpstreamErrorClass::Timeout,
            detail: "private timeout detail".to_owned(),
        };
        assert_eq!(
            partial_redial_error_class(1, Some(&timeout)),
            Some(UpstreamErrorClass::Timeout),
        );
        assert_eq!(
            partial_redial_error_class(0, Some(&timeout)),
            None,
            "a fully healed batch must clear the prior error class",
        );
    }

    #[test]
    fn common_catalog_requires_exact_descriptor_on_every_lane() {
        let shared = tool("shared", None);
        let first = vec![
            shared.clone(),
            tool("first_only", None),
            tool("schema_drift", Some("old")),
        ];
        let second = vec![
            shared.clone(),
            tool("second_only", None),
            tool("schema_drift", Some("new")),
        ];

        assert_eq!(
            common_tool_catalog(&[&first, &second], crate::ClassificationMode::Manifest),
            vec![shared],
            "a published descriptor must be callable with that schema on every lane",
        );
    }

    /// The display title is excluded from the reviewed behavior hash, so a
    /// rolling deployment whose lanes differ only in `ToolAnnotations.title`
    /// must keep the tool published rather than dropping it from the
    /// intersection (which annotation mode would then quarantine).
    #[test]
    fn common_catalog_ignores_display_title_differences() {
        let mut titled = tool("shared", None);
        titled.annotations = Some(rmcp::model::ToolAnnotations::from_raw(
            Some("Renamed in the newer build".to_owned()),
            Some(true),
            Some(false),
            Some(true),
            Some(false),
        ));
        let mut untitled = tool("shared", None);
        untitled.annotations = Some(rmcp::model::ToolAnnotations::from_raw(
            None,
            Some(true),
            Some(false),
            Some(true),
            Some(false),
        ));
        let first = vec![titled.clone()];
        let second = vec![untitled];

        assert_eq!(
            common_tool_catalog(
                &[&first, &second],
                crate::ClassificationMode::McpAnnotations,
            ),
            vec![titled],
            "a title-only lane difference must not drop the shared tool",
        );
    }

    #[test]
    fn output_schema_disagreement_respects_the_classification_authority() {
        let with_output_schema = |property: &str| {
            let mut tool = tool("shared", None);
            tool.output_schema = Some(Arc::new(
                json!({
                    "type": "object",
                    "properties": {property: {"type": "string"}}
                })
                .as_object()
                .expect("output schema object")
                .clone(),
            ));
            tool
        };
        let first = vec![with_output_schema("old")];
        let second = vec![with_output_schema("new")];

        let manifest_catalog =
            common_tool_catalog(&[&first, &second], crate::ClassificationMode::Manifest);
        assert_eq!(manifest_catalog.len(), 1);
        assert_eq!(manifest_catalog[0].output_schema, None);

        assert!(common_tool_catalog(
            &[&first, &second],
            crate::ClassificationMode::McpAnnotations,
        )
        .is_empty());
    }

    #[test]
    fn canonical_catalog_is_installed_on_every_lane() {
        let published = vec![tool("shared", None)];
        let mut first = vec![tool("first_only", None)];
        let mut second = vec![tool("second_only", None)];

        synchronize_published_catalogs([&mut first, &mut second], &published);

        assert_eq!(first, published);
        assert_eq!(second, published);
    }

    #[test]
    fn reconnect_synchronizes_surviving_and_replacement_lanes() {
        let published = vec![tool("shared", None)];
        let mut surviving = vec![tool("surviving_only", None)];
        let mut replaced = vec![tool("replacement_only", None)];
        let mut failed = vec![tool("failed_only", None)];

        synchronize_reconnect_catalogs(
            false,
            [Some(&mut surviving)],
            [(true, Some(&mut replaced)), (false, Some(&mut failed))],
            &published,
        );

        assert_eq!(surviving, published);
        assert_eq!(replaced, published);
        assert_eq!(failed, vec![tool("failed_only", None)]);
    }
}
