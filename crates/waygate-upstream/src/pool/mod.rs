//! `UpstreamPool` — one connected rmcp client per configured upstream.
//!
//! Three transports are supported:
//! - `http` — streamable HTTP via rmcp's `StreamableHttpClientTransport`.
//! - `sse`  — legacy two-endpoint MCP SSE (long-lived GET + POST messages
//!   URL announced via `event: endpoint`). Implemented in
//!   [`crate::sse_client`]; rmcp ships no SSE client transport of its
//!   own.
//! - `stdio` — spawns the configured `command` and speaks rmcp over its
//!   stdin/stdout via `TokioChildProcess`. The child inherits the gateway's
//!   stderr for logging. No auto-restart: a child that exits stays
//!   disconnected until the operator restarts the gateway; the breaker
//!   trips after the configured failure budget.
//!
//! Identity forwarding (`X-MCP-Identity`) and RFC 8693 token exchange are
//! HTTP-only (http + sse). Stdio upstreams run inside the gateway's own
//! security boundary and do not receive per-caller identity; a stdio
//! manifest with an `exchange:` block logs a warning and the field is
//! ignored.
//!
//! On startup every manifest is dialed and its `tools/list` cached; a
//! failure is logged but does not abort boot — the upstream stays in the
//! pool as `Disconnected` and is surfaced by `list_tools` as an empty list.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use rmcp::model::{
    CallToolResponse, CallToolResult, ClientInfo, ListResourceTemplatesResult, ListResourcesResult,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult, Tool,
};
use rmcp::service::RunningService;
use rmcp::{ErrorData as McpError, RoleClient};
use serde_json::{Map, Value};
use tokio::sync::{Mutex, Notify, RwLock};

use waygate_mcp::authz::ToolFacts;
use waygate_mcp::catalog::{
    AdmittedResourceReadError, CallToolResultProcessing, InvocationContractIdentity,
    InvocationToolSnapshot, ResolvedInvocationTool, ResourceClaim, ResourceReadAdmission,
    ResourceRoutingSnapshot, ToolCallMrtr, UpstreamCatalog,
};
use waygate_mcp::files::{
    AuthorizeDownloadParams, AuthorizeDownloadResult, AuthorizeUploadParams, AuthorizeUploadResult,
    AuthorizedFileDownload, AuthorizedFileUpload,
};
use waygate_mcp::index::SearchIndex;
use waygate_mcp::protocol::RiskTier;
use waygate_mcp::ToolCatalogEpoch;
use waygate_oidc::upstream_crypto::UpstreamCrypto;
use waygate_oidc::upstream_session::{
    RefreshError, SharedSessionRefresher, SharedUpstreamSessionStore, UpstreamTokens,
};
use waygate_oidc::{Principal, SharedIdentityIssuer, TokenCache, TokenExchangeClient};

use crate::breaker::{Breaker, BreakerConfig, BreakerError, BreakerState};
use crate::identity_client::{ExchangeSettings, IdentityCell, IdentityContext};
use crate::transport::{self, DialError};
use crate::{SessionIsolation, Transport, UpstreamAuth, UpstreamManifest};

/// Bundles a shared RFC 8693 client with its token cache so the pool can be
/// constructed in one argument rather than three scattered ones.
#[derive(Clone)]
pub struct ExchangeBundle {
    pub client: Arc<TokenExchangeClient>,
    pub cache: Arc<TokenCache>,
}

impl ExchangeBundle {
    pub fn new(client: Arc<TokenExchangeClient>) -> Self {
        Self {
            client,
            cache: Arc::new(TokenCache::default()),
        }
    }
}

/// A single configured upstream and its (optional) live client.
///
/// `identity_cell` is `Some` only when the pool was built with an issuer and
/// the transport is HTTP — it's the mailbox the `IdentityForwardingClient`
/// reads from before each HTTP request. `call_serializer` gates concurrent
/// `call_tool` invocations for the same upstream so two callers can't race on
/// writing the cell.
/// One independently-dialed connection lane to an upstream. An
/// entry holds a small pool of these so concurrent calls to
/// the same upstream run in parallel instead of serializing on a single
/// connection. Each slot owns its **own** [`IdentityCell`], so a call
/// that has checked out a slot can write the cell without racing any
/// other call — the per-slot `in_use` mutex grants that exclusivity for
/// the duration of the dispatch, replacing the old per-entry
/// `call_serializer`.
struct ConnectionSlot {
    conn: RwLock<Option<Connection>>,
    /// Held for a call's exclusive use of the slot. Acquiring it is the
    /// "checkout"; while held, no other call touches this slot's
    /// connection or its identity cell. At pool size 1 this is exactly
    /// the old per-upstream `call_serializer`.
    in_use: Mutex<()>,
}

struct UpstreamEntry {
    /// Manifest is behind a std RwLock so SIGHUP can swap tool classifications
    /// (risk tier, side_effects) without touching the live rmcp connection.
    /// Connection-shape fields (transport, url, command) are read once at
    /// dial time — a reload that changes those logs a warning and is ignored;
    /// a restart is still required to re-dial with a new transport.
    manifest: StdRwLock<UpstreamManifest>,
    /// Connection pool for this upstream. Always ≥ 1 slot. Network
    /// transports (HTTP/SSE) get `pool_size` slots so calls parallelize;
    /// stdio is forced to 1 (a single child process). All slots dial the
    /// same upstream and carry identical tool lists.
    slots: Vec<ConnectionSlot>,
    /// Serializes reconnect and forced catalog refresh for this upstream. Calls
    /// keep using the current slot connections while a replacement dials, but
    /// these identical-shape operations need a guard because the manifest CAS
    /// cannot distinguish an older session from a newer one. Manifest-shape
    /// redials remain concurrent and use their existing shape CAS fence.
    session_mutation: Mutex<()>,
    /// Whether this upstream forwards caller identity (the pool has an
    /// issuer AND the transport is HTTP/SSE). Fixed at construction —
    /// every slot's connection carries its own [`IdentityCell`] iff this
    /// is true. Read by the `tier_a_required` / context-build gates,
    /// which need the answer even when all slots are momentarily down.
    forwards_identity: bool,
    /// Shared across slots: an upstream that's failing is failing
    /// regardless of which lane a call took, so the failure budget is
    /// per-upstream, not per-slot.
    breaker: Breaker,
    recovery: StdRwLock<health::UpstreamRecovery>,
    reconnect: StdMutex<reconnect::ReconnectState>,
    reconnect_notify: Arc<Notify>,
    /// Tombstone flag set by `reload_manifests` when the operator removed
    /// this server from the on-disk catalog. The entry stays in `entries`
    /// (the pool's HashMap is post-boot immutable so existing in-flight
    /// callers don't trip a None-not-found mid-call), but the periodic
    /// re-probe / SIGHUP / admin reconnect paths all skip it — otherwise
    /// auto-rediscover would silently re-dial a retired upstream and
    /// re-populate the search index a SIGHUP just cleared.
    removed: AtomicBool,
    /// In-process behavior-hash baseline keyed by tool name.
    /// Populated by [`record_observed_schemas`] at the publish
    /// points (boot, reconnect, reload). On a subsequent publish where
    /// a known tool's schemas or security annotations differ from its
    /// baseline, drift is
    /// recorded (Prometheus + WARN log) and the baseline is updated.
    /// First observation is silent — drift is "this tool changed since
    /// the last time we looked," not "the manifest disagrees with the
    /// live schema." A synchronous mutex is required because catalog
    /// publication must not yield after updating the shared search index but
    /// before installing its replacement session; contention is trivially low
    /// (one short acquire per publish pass).
    observed_schemas: StdMutex<HashMap<String, String>>,
    /// Process-local quarantine decisions when no durable review store is
    /// attached; otherwise a cache for runtime status and metrics. Durable
    /// discovery and dispatch read the database so another replica's exact
    /// acceptance can take effect without a restart.
    quarantined: StdRwLock<HashSet<String>>,
    /// Generation of the most recent reload that applied an IN-PLACE update to
    /// this entry (tool classifications / identity-chaining fields). A reload
    /// applies its in-place changes under the manifest write lock only if its
    /// generation is ≥ this; otherwise it has been superseded for this entry by a
    /// newer reload and applies nothing — so a stale reload delayed in a slow
    /// hot-add dial can't roll back a kept entry's classifications or identity
    /// after a newer reload already advanced them. Pairs with the
    /// pool-level `applied_reload_gen` (which fences the structural map commit):
    /// together they make every reload effect generation-ordered.
    last_reload_gen: AtomicU64,
}

/// One detected behavior-contract drift event, returned by
/// [`UpstreamEntry::record_observed_schemas`] so the owning [`UpstreamPool`]
/// (which holds the evidence sink) can emit a `CatalogDrift` audit row. Drift
/// and quarantine would otherwise be metric/log-only — invisible in the
/// activity feed; surfacing them as audit rows is why this type exists.
struct DriftReport {
    /// The tool whose live behavior hash diverged from the last observation.
    tool: String,
    /// Manifest risk tier of that tool, if classified (drives the outcome +,
    /// together with `side_effects`, whether it was quarantined).
    risk: Option<waygate_core::RiskTier>,
    /// Whether the tool is side-effecting. Recorded alongside `risk` because the
    /// quarantine threshold covers `risk OR side_effects` (campaign decouple),
    /// so the drift-audit reason can explain WHY a low-risk tool quarantined.
    side_effects: bool,
    /// Whether this drift tripped the pool's quarantine threshold.
    quarantined: bool,
}

/// Last manifest/catalog transition observed for one tool. Settled entries are
/// retained as generation witnesses so a resolver can detect a transition that
/// begins and completes while its catalog lookup is awaiting the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CatalogTransition {
    generation: u64,
    pending: bool,
}

impl UpstreamEntry {
    /// `true` iff at least one slot currently holds a live connection.
    async fn any_connected(&self) -> bool {
        for slot in &self.slots {
            if slot.conn.read().await.is_some() {
                return true;
            }
        }
        false
    }

    /// The published (manifest-classified) tool view for this upstream,
    /// from the first connected slot. Filter the local quarantine only when
    /// it is authoritative; callers with durable storage apply its decision. All
    /// connected slots carry identical tool lists, so any one is
    /// representative; empty when all are down.
    async fn published_tools(&self, local_quarantine_authoritative: bool) -> Vec<Tool> {
        for slot in &self.slots {
            if let Some(conn) = slot.conn.read().await.as_ref() {
                let q = self
                    .quarantined
                    .read()
                    .expect("upstream quarantine lock poisoned");
                if !local_quarantine_authoritative || q.is_empty() {
                    return conn.tools.clone();
                }
                return conn
                    .tools
                    .iter()
                    .filter(|t| !q.contains(t.name.as_ref()))
                    .cloned()
                    .collect();
            }
        }
        Vec::new()
    }

    /// Record an observation pass against `tools` (the live
    /// `tools/list` for this upstream). For each tool, compute its
    /// legacy schema hash or annotation-native behavior hash and compare to
    /// the per-entry baseline. A known tool with a different hash → drift:
    /// bump `mcp_tool_drift_total{server=name}` and WARN with the
    /// before/after hashes. First observation of a tool is silent (no
    /// baseline to drift from). The baseline is then updated in-place.
    ///
    /// `source` is the publish path label ("boot" / "reconnect" /
    /// "reload"), forwarded to the WARN log so an operator can tell
    /// which observation triggered drift. `threshold` is the pool's
    /// quarantine policy: a known tool that drifts AND meets `threshold`
    /// (by risk tier OR `side_effects`) is added to [`UpstreamEntry::quarantined`],
    /// and a structured WARN tagged `quarantined=true` is emitted so
    /// alerting can distinguish observe-only drift from auto-blocked
    /// drift. Called from [`UpstreamPool::publish_classifications_to`]
    /// (and the boot seeding loop) under the slot `conn` lock that
    /// already brackets each publish.
    ///
    /// Returns the drift events it detected so the caller (the pool,
    /// which owns the evidence sink) can emit `CatalogDrift` audit rows. Empty
    /// on first observation (baseline seed) and when nothing drifted.
    fn record_observed_schemas(
        &self,
        name: &str,
        tools: &[Tool],
        source: &'static str,
        threshold: QuarantineThreshold,
    ) -> Vec<DriftReport> {
        let manifest = self.manifest_snapshot();
        self.record_observed_schemas_against(
            name,
            tools,
            source,
            threshold,
            &manifest.tools,
            manifest.classification_mode,
        )
    }

    /// `true` iff `tool_name` is currently quarantined on this upstream.
    /// Hot-path read used by [`UpstreamPool::resolve_invocation_tool`] to gate
    /// dispatch before the catalog / manifest classification lookup.
    async fn is_quarantined(&self, tool_name: &str) -> bool {
        self.quarantined
            .read()
            .expect("upstream quarantine lock poisoned")
            .contains(tool_name)
    }
}

struct Connection {
    client: RunningService<RoleClient, ClientInfo>,
    /// Address set resolved and pinned when this network connection was
    /// created. File downloads on the same upstream host reuse this set so a
    /// second DNS answer cannot redirect the gateway to another service.
    network_destination: Option<transport::PinnedNetworkDestination>,
    /// Whether every network leg used by this live MCP connection was
    /// observed in cleartext. Legacy SSE learns this only after its endpoint
    /// handshake, so it cannot be reconstructed safely from the manifest.
    cleartext_control_plane: bool,
    /// Identity cell wired into `client`'s transport at dial time
    /// (`Some` for identity-forwarding upstreams). Co-located with the
    /// client it feeds so a reconnect swaps cell + client atomically
    /// under the slot's `conn` write lock — a dispatch reading the slot
    /// always sees a cell that matches the live client.
    identity_cell: Option<IdentityCell>,
    /// Manifest-classified subset of `live_tools`. This is the published view —
    /// `list_tools` returns it and the search index is populated from it.
    tools: Vec<Tool>,
    /// Raw `tools/list` response retained from the dial. Held so a SIGHUP that
    /// only edits classifications can re-filter against the existing live view
    /// without an upstream round-trip — newly classified live tools become
    /// discoverable, newly unclassified ones are quarantined out of search and
    /// `call_tool`, all without a reconnect or restart.
    live_tools: Vec<Tool>,
    /// Protocol generation this lane's dial negotiated (the version string
    /// from the service's peer info). Per-lane state, fresh as of the dial:
    /// lanes may legitimately diverge during a partial heal while the
    /// upstream migrates. `None` only if the SDK exposed no peer info.
    negotiated_protocol: Option<String>,
    /// Whether this lane's initialize result advertised MCP Resources.
    resource_capability_advertised: bool,
    /// SEP-2549 `ttlMs` hint observed on this lane's dial-time `tools/list`
    /// (strictest page; `None` = the upstream offered none). Per-lane state,
    /// fresh as of `dialed_at` — lanes may legitimately disagree during
    /// partial heals. Consumed by [`freshness`] to schedule catalog
    /// refreshes; never extends reuse (an absent hint uses the operator's
    /// configured freshness ceiling).
    ttl_hint_ms: Option<u64>,
    /// When this lane's `tools/list` read *began* — the anchor its
    /// freshness hint counts down from. Taken before the first page
    /// request, so time spent fetching later pages cannot extend an
    /// earlier page's deadline.
    dialed_at: std::time::Instant,
    rejected_output_schemas: Vec<tool_listing::RejectedOutputSchema>,
    /// Published tools this lane serves whose input schema a strict
    /// tool-calling client cannot register. Observed only — unlike a refused
    /// output schema, nothing is stripped, because the schema conforms and
    /// altering it would rewrite a contract the upstream owns.
    unregisterable_input_schemas: Vec<tool_listing::UnregisterableInputSchema>,
}

pub struct UpstreamPool {
    /// The upstream registry, swapped atomically on a structural reload
    /// (hot add/remove). Reads on the dispatch hot path take a lock-free
    /// `load()` and clone out the `Arc<UpstreamEntry>` they need — so an
    /// in-flight call holds its own `Arc` and is unaffected when a
    /// concurrent reload publishes a map that no longer contains it (the
    /// entry drains and its connections close when the last holder drops
    /// it). In-place edits to an EXISTING entry (tool classifications,
    /// identity-chaining fields, a same-slot-count live re-dial) mutate
    /// through the shared `Arc` and need no map swap; only add/remove
    /// publish a new map. The whole map is cheap to clone for a swap —
    /// the values are `Arc`s and the cardinality is dozens.
    entries: Arc<ArcSwap<HashMap<String, Arc<UpstreamEntry>>>>,
    /// What the operator has already been told about refused output schemas,
    /// keyed by server so a resize that replaces the entry keeps the history.
    /// Ordering and the event-vs-repeat rule live in [`refusal_record`].
    audited_refusals: Arc<refusal_record::RefusalRecord>,
    /// Total order over every writer of
    /// `gateway_upstream_protocol_generation` — entry publishers AND the
    /// removal-zero path — held across sample → liveness check → write.
    /// The serialization domain is the gauge itself (server names survive
    /// entry replacement, so a per-entry lock cannot order a retired
    /// publisher against its successor or against removal zeroes).
    /// Contended only on lane transitions and reloads, never on dispatch.
    protocol_gauge_publish: Mutex<()>,
    /// Serializes structural map commits and the short session/index commit
    /// sections that must prove their `UpstreamEntry` is still current. Dialing
    /// and other slow work stay outside this lock, so a slow target cannot block
    /// unrelated reload work. A structural commit re-reads the live map under
    /// the lock, while a session commit checks `Arc` identity under the same
    /// lock; this makes the last committed registry entry authoritative over the
    /// shared search index.
    reload_lock: Mutex<()>,
    /// Hands out a monotonic generation to each `reload_manifests` call (before
    /// it dials), so the structural commit can fence out a stale reload. Without
    /// it, a reload whose slow dial lands at the commit AFTER a newer reload
    /// already committed could resurrect a server the newer reload omitted, or
    /// tombstone one it kept.
    next_reload_gen: AtomicU64,
    /// The highest reload generation that has reached the structural commit.
    /// Checked under `reload_lock`: a reload whose generation is below this has
    /// been superseded and must abandon its commit. Advanced by every reload that
    /// reaches the commit — including a structural no-op — so a newer no-op reload
    /// still fences an older stale one.
    applied_reload_gen: AtomicU64,
    /// Fleet-wide fence for resource ownership and risk. Resolution snapshots
    /// a generation under a read guard; admitted reads reacquire that guard,
    /// verify the generation, and retain it across the upstream RPC. A reload
    /// that changes topology or resource claims takes the write side for its
    /// activation, so authorization can never straddle routing generations.
    resource_routing: RwLock<()>,
    resource_routing_generation: AtomicU64,
    /// Tools whose live manifest authorization inputs have advanced beyond the
    /// catalog generation. Each value is the reload generation that introduced
    /// the transition. The resolver refuses only these tools until a full-set
    /// catalog reconcile for that generation succeeds; catalog-owned overrides
    /// remain authoritative outside the transition window.
    catalog_transitions: StdRwLock<HashMap<(String, String), CatalogTransition>>,
    /// BM25 index shared with the MCP handler. Populated from each upstream's
    /// `tools/list` at connect time and refreshed on manifest reload. `None`
    /// in the disconnected-test constructor so unit tests don't need tantivy.
    index: Option<SearchIndex>,
    /// Process-wide signal advanced after successful changes to the
    /// downstream-visible tool descriptors or upstream topology. Downstream
    /// MCP sessions subscribe through `waygate-server` and refetch tools when
    /// the epoch changes. Independent of the optional BM25 index so degraded
    /// search mode preserves catalog-change notifications.
    tool_catalog_epoch: ToolCatalogEpoch,
    reconnect_policy: reconnect::ReconnectPolicy,
    reconnect_notify: Arc<Notify>,
    #[cfg(test)]
    reconnect_commit_hook: StdMutex<Option<(Arc<Notify>, Arc<Notify>)>>,
    #[cfg(test)]
    reconnect_outcome_hook: StdMutex<Option<(Arc<Notify>, Arc<Notify>)>>,
    /// Retained from `connect_inner` so the scheduler, configuration-reload,
    /// and admin reconnect paths re-dial with the same identity /
    /// token-exchange wiring used at boot. `None` for pools built without
    /// identity forwarding.
    issuer: Option<SharedIdentityIssuer>,
    exchange: Option<ExchangeBundle>,
    /// Per-call timeout applied to every `call_tool` invocation. Without this,
    /// a wedged upstream stream (e.g. a long-idle HTTP/2 connection that
    /// silently half-closed) keeps the per-server `call_serializer` mutex
    /// held forever and blocks every subsequent call to that upstream until
    /// the gateway restarts. `None` disables the timeout. Defaults to 300s
    /// (5 minutes) in [`connect`](Self::connect) /
    /// [`connect_with_identity`](Self::connect_with_identity) /
    /// [`connect_with_identity_and_exchange`](Self::connect_with_identity_and_exchange);
    /// operators override via
    /// [`with_call_timeout`](Self::with_call_timeout) (wired to
    /// `GATEWAY_UPSTREAM_CALL_TIMEOUT_SECONDS` in `waygate-server`).
    call_timeout: Option<Duration>,
    /// Per-lane timeout for a live re-dial's connect + `tools/list`,
    /// so an unresponsive new target surfaces as `redial_failed` instead of
    /// wedging the awaited `reload_manifests`. Always set;
    /// defaults to [`DEFAULT_REDIAL_DIAL_TIMEOUT`] (15s). Tests shorten it via
    /// [`with_redial_dial_timeout`](Self::with_redial_dial_timeout).
    redial_dial_timeout: Duration,
    /// Write-side `EvidenceRecorder` for unchained `UpstreamHealth` rows and
    /// chained-best-effort `CatalogDrift` rows. `None` when the pool was built
    /// without one (tests, the disconnected fixture); `Some` after
    /// `waygate-server` chains `.with_evidence(audit_sink.clone())`. Neither
    /// posture lets an evidence failure block reconnect or republish.
    evidence: Option<waygate_mcp::audit::SharedEvidence>,
    /// Tier-A subject-token resolver. When `Some`, every identity-
    /// forwarding `call_tool` consults
    /// `sessions.get(principal.sub, upstream_issuer)` before populating
    /// the per-call [`IdentityCell`], decrypts the envelope with
    /// `crypto`, and threads the upstream access token into
    /// `IdentityContext.stored_upstream_subject_token`. The
    /// `IdentityAugmenter` prefers it over `principal.raw_token` as the
    /// subject for RFC 8693 exchange — that's the right actor for
    /// downscoping (the upstream IdP knows the user; the gateway-issued
    /// bearer is a different identity layer).
    ///
    /// `None` when:
    ///   - the gateway isn't running its own AS (no upstream IdP to
    ///     have sessions against),
    ///   - `waygate-server` hasn't called `with_upstream_sessions`
    ///     (the disconnected-test pool, classify CLI),
    ///   - or the `cfg.as_server` block is absent.
    ///
    /// On `None`, the existing `principal.raw_token` fallback path
    /// stays intact — Tier-A keeps working in legacy / dev modes.
    upstream_sessions: Option<UpstreamSessionBundle>,
    /// Governed-catalog read handle. When `Some`,
    /// [`resolve_invocation_tool`](UpstreamPool::resolve_invocation_tool)
    /// consults `CatalogStore::resolve_tool` first. `None` means pure manifest
    /// behavior (no DB, classify CLI, disconnected-test pool).
    /// [`Self::with_catalog`] retains transitional fallback on a miss,
    /// `PendingApproval`, or DB error; production uses
    /// [`Self::with_authoritative_catalog`] after its fail-closed boot
    /// reconcile so a miss or error refuses dispatch.
    catalog: Option<waygate_catalog::SharedCatalogStore>,
    tool_reviews: Option<Arc<waygate_catalog::tool_reviews::PgCatalogStore>>,
    /// Whether the attached catalog is the serving authority rather than a
    /// transitional dual-read aid. The production composition sets this only
    /// after boot has atomically reconciled the accepted manifest generation;
    /// catalog misses and read failures then refuse dispatch instead of
    /// reviving a withdrawn tool through manifest fallback.
    catalog_authoritative: bool,
    /// Monotonic signal for authoritative catalog read failures. Discovery
    /// samples it around multi-await projections so a silently skipped failed
    /// tool can never be accepted as a complete snapshot or cursor basis.
    catalog_read_error_generation: AtomicU64,
    /// When an observed-drift event fires for a tool that meets
    /// this threshold (by risk tier OR `side_effects`), the tool is added to the
    /// per-entry quarantine set and subsequent `resolve_invocation_tool`
    /// returns `ResolvedInvocationTool::Quarantined`. `Off` (default) leaves
    /// drift recorded but never auto-blocking.
    /// Read at construction from `GATEWAY_QUARANTINE_ON_DRIFT_RISK`.
    quarantine_threshold: QuarantineThreshold,
    /// Strict mode for catalog `PendingApproval`. When
    /// `false` (default), a `PendingApproval` result from the catalog
    /// triggers the transitional manifest fallback — operators get a
    /// WARN but calls proceed against the manifest-classified facts.
    /// When `true`, `PendingApproval` is treated as a hard refusal
    /// (returns `ResolvedInvocationTool::Quarantined`) — the right behavior
    /// once the catalog is reliably populated and an un-approved
    /// schema means "do not dispatch." Read at construction from
    /// `GATEWAY_CATALOG_STRICT_PENDING_APPROVAL`. Transitional catalog
    /// attachments keep the manifest fallback for `NotFound` and store
    /// errors; an authoritative attachment refuses both independently of this
    /// pending-approval setting.
    catalog_strict_pending_approval: bool,
    /// Peer JWKS cache used to resolve a manifest's
    /// `tier_c_peer: <peer_id>` to the peer's canonical issuer
    /// URL at per-call IdentityContext build time. The cached
    /// entry's `issuer` field becomes the `aud` claim on the
    /// minted identity JWT, which lets the remote MCP gateway's
    /// `PeerJwtValidator` accept it as a peer assertion from
    /// this gateway. `None` ⇒
    /// `tier_c_peer:` is not resolvable; manifests that set it
    /// on a pool without this wired refuse dispatch loud at
    /// call time (better than silently downgrading the aud
    /// and 401-ing at the remote peer).
    peer_jwks_cache: Option<waygate_federation::jwks::SharedPeerJwksCache>,
}

/// Risk-tier threshold at which observed tool-behavior drift triggers automatic
/// in-process quarantine of the affected tool. Off (default) leaves
/// drift recorded as a counter + WARN log but with no call-time
/// enforcement. Other levels are increasingly aggressive
/// auto-blocking. Operators opt in via `GATEWAY_QUARANTINE_ON_DRIFT_RISK`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QuarantineThreshold {
    /// Never auto-quarantine. Drift is observed-only.
    Off,
    /// Quarantine on drift when the tool's manifest risk is `High` OR the tool
    /// is `side_effects: true`. (The catalog tier `critical` also maps to `High`
    /// at the runtime, so `critical` tools are covered. The `side_effects` half
    /// is the campaign decouple — a destructive tool reclassified
    /// `high -> low + side_effects` is still quarantined.)
    High,
    /// Quarantine on drift when risk is `Medium`/`High` OR `side_effects: true`.
    Medium,
    /// Quarantine on every observed drift, regardless of risk or side_effects.
    All,
}

impl QuarantineThreshold {
    /// Should a tool be quarantined on drift under the current threshold?
    ///
    /// Keys on `side_effects` as well as the risk tier: after the campaign
    /// decoupled the operational controls from `risk == High`, the dangerous
    /// surface worth quarantining on drift is "administrative (`high`) OR
    /// side-effecting", so a destructive tool reclassified `high -> low +
    /// side_effects` stays covered at the `high`/`medium` thresholds. `off`
    /// still never quarantines and `all` always does.
    fn covers(self, risk: RiskTier, side_effects: bool) -> bool {
        match self {
            QuarantineThreshold::Off => false,
            QuarantineThreshold::High => matches!(risk, RiskTier::High) || side_effects,
            QuarantineThreshold::Medium => {
                matches!(risk, RiskTier::Medium | RiskTier::High) || side_effects
            }
            QuarantineThreshold::All => true,
        }
    }
}

/// Parse the strict-mode flag for catalog `PendingApproval` from
/// `GATEWAY_CATALOG_STRICT_PENDING_APPROVAL`. Returns `true` only on
/// `true` / `1` (case-insensitive); everything else (unset, `false`,
/// `0`, unknown) returns `false` so the documented default — the
/// transitional manifest fallback — is preserved.
fn catalog_strict_pending_approval_from_env() -> bool {
    matches!(
        std::env::var("GATEWAY_CATALOG_STRICT_PENDING_APPROVAL")
            .ok()
            .as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("true") | Some("1"),
    )
}

/// Parse the quarantine threshold from `GATEWAY_QUARANTINE_ON_DRIFT_RISK`.
/// Unset / unparseable falls back to [`QuarantineThreshold::Off`] — the
/// safe default (drift recorded, never auto-blocking). Recognized values
/// (case-insensitive): `off`, `high`, `medium`, `all`.
fn quarantine_threshold_from_env() -> QuarantineThreshold {
    match std::env::var("GATEWAY_QUARANTINE_ON_DRIFT_RISK")
        .ok()
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("off") | None => QuarantineThreshold::Off,
        Some("high") => QuarantineThreshold::High,
        Some("medium") => QuarantineThreshold::Medium,
        Some("all") => QuarantineThreshold::All,
        Some(other) => {
            tracing::warn!(
                value = %other,
                "unrecognized GATEWAY_QUARANTINE_ON_DRIFT_RISK; falling back to off",
            );
            QuarantineThreshold::Off
        }
    }
}

/// Default per-upstream connection-pool size for network transports.
/// Four lanes covers typical concurrent-user fan-out to one upstream
/// without opening an unreasonable number of sockets per server.
const DEFAULT_UPSTREAM_POOL_SIZE: usize = 4;

/// Default per-upstream `call_tool` timeout. Long enough to absorb a slow
/// legitimate upstream operation (agentic-reflect-style tools that chain
/// several LLM calls + tool fetches can take 60–120s end-to-end on warm
/// hardware; 300s leaves headroom for cold-cache and multi-step reasoning);
/// short enough that a wedged stream releases the serializer mutex before
/// the operator's troubleshooting attention is on something else.
const DEFAULT_UPSTREAM_CALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Per-lane timeout for a live re-dial's connect + `tools/list`. Unlike
/// boot / background reconnect, a re-dial runs *synchronously inside*
/// `reload_manifests`, which the SIGHUP / dashboard Reload / doorbell paths
/// `await` — so an unresponsive new target (one that accepts the TCP connection
/// then stalls the MCP handshake) must time out promptly and surface as
/// `redial_failed` (old session kept) rather than wedging the whole reload.
/// The lanes are dialed concurrently, so the wall
/// time of a re-dial against a black-hole target is ~this bound, not N× it.
/// 15s leaves ample headroom for a healthy TCP + TLS + initialize + list
/// round-trip on a slow link. Override per-pool via
/// [`with_redial_dial_timeout`](UpstreamPool::with_redial_dial_timeout).
const DEFAULT_REDIAL_DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-lane timeout for the INITIAL boot dial (connect + MCP `initialize` +
/// `tools/list` + classify) in [`dial_slots`]. The boot dial loop runs
/// synchronously in `UpstreamPool::connect`, which the gateway `await`s before
/// it binds its listener — so an unresponsive upstream (one that accepts the
/// connection then stalls the handshake) would wedge the *entire* sequential
/// boot and the gateway would never bind its port. This is the same hazard
/// `DEFAULT_REDIAL_DIAL_TIMEOUT` guards on the re-dial path, but the boot
/// path was missed — and it caused a prod boot deadlock
/// (2026-06-10: one upstream wedged after `initialize`, startup hung forever).
/// On timeout the lane is marked Disconnected and boot continues; the
/// reconnect scheduler heals the upstream once it recovers. Generous
/// (well above a healthy connect/handshake) so a slow-but-live upstream is not
/// dropped, while still bounding a true hang.
const DEFAULT_BOOT_DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// Resolve the per-upstream pool size from `GATEWAY_UPSTREAM_POOL_SIZE`,
/// falling back to [`DEFAULT_UPSTREAM_POOL_SIZE`] when unset, unparseable,
/// or < 1. Read at pool construction because the value determines how
/// many connection slots are dialed up front.
fn pool_size_from_env() -> usize {
    std::env::var("GATEWAY_UPSTREAM_POOL_SIZE")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        // Clamp parseable values to ≥ 1 (a zero env-set value means "as
        // little as possible", not "fall through to the default"); only
        // unset / unparseable falls back to the default. This matches
        // the README's documented "values < 1 clamp to 1" contract.
        .map(|n| n.max(1))
        .unwrap_or(DEFAULT_UPSTREAM_POOL_SIZE)
}

impl UpstreamPool {
    /// Dial every HTTP upstream and cache its initial tool list. Connection
    /// failures are logged but keep the upstream in the pool as disconnected.
    /// Does not mint identity tokens — use [`Self::connect_with_identity`] to
    /// stamp `X-MCP-Identity` on each upstream call.
    pub async fn connect(manifests: BTreeMap<String, UpstreamManifest>) -> Self {
        Self::connect_inner(manifests, None, None).await
    }

    /// Connect every upstream with an `IdentityForwardingClient` wrapping the
    /// underlying reqwest transport. Each HTTP upstream gets its own
    /// [`IdentityCell`]; the pool uses an unprivileged service identity for
    /// connection initialization and tool discovery, then replaces it with
    /// the caller identity before every `call_tool` invocation and clears it
    /// afterward.
    pub async fn connect_with_identity(
        manifests: BTreeMap<String, UpstreamManifest>,
        issuer: SharedIdentityIssuer,
    ) -> Self {
        Self::connect_inner(manifests, Some(issuer), None).await
    }

    /// Same as [`Self::connect_with_identity`] but also attaches an RFC 8693
    /// token-exchange client (Tier A). Upstreams opt in via `exchange:` in
    /// their manifest — upstreams without it still get Tier B identity JWTs.
    pub async fn connect_with_identity_and_exchange(
        manifests: BTreeMap<String, UpstreamManifest>,
        issuer: SharedIdentityIssuer,
        exchange: ExchangeBundle,
    ) -> Self {
        Self::connect_inner(manifests, Some(issuer), Some(exchange)).await
    }

    async fn connect_inner(
        manifests: BTreeMap<String, UpstreamManifest>,
        issuer: Option<SharedIdentityIssuer>,
        exchange: Option<ExchangeBundle>,
    ) -> Self {
        let index = match SearchIndex::new() {
            Ok(idx) => Some(idx),
            Err(e) => {
                // Falling back to the substring scan keeps the gateway usable
                // even if tantivy fails to initialize — logged at error level
                // so an operator can see the degradation.
                tracing::error!(error = %e, "failed to initialize search index; BM25 disabled");
                None
            }
        };
        // Per-upstream connection-pool size. Read from the env
        // at construction because it determines how many slots we dial
        // here — unlike `call_timeout`, it can't be a post-construction
        // builder. `GATEWAY_UPSTREAM_POOL_SIZE` overrides the default;
        // anything unparseable / < 1 falls back to the default.
        let pool_size = pool_size_from_env();
        let reconnect_policy = reconnect::ReconnectPolicy::random();
        let reconnect_notify = Arc::new(Notify::new());
        let mut entries = HashMap::with_capacity(manifests.len());
        for (name, manifest) in manifests {
            let entry = Self::build_entry(
                &name,
                manifest,
                issuer.as_ref(),
                exchange.as_ref(),
                index.as_ref(),
                pool_size,
                DEFAULT_BOOT_DIAL_TIMEOUT,
                // Boot is generation 0; it publishes each entry's tools into the
                // index during the dial (no concurrent reload races boot).
                0,
                reconnect_policy,
                reconnect_notify.clone(),
            )
            .await;
            entries.insert(name, entry);
        }
        health::set_rejected_gauges(&entries).await;
        Self {
            entries: Arc::new(ArcSwap::from_pointee(entries)),
            audited_refusals: Arc::new(refusal_record::RefusalRecord::default()),
            protocol_gauge_publish: Mutex::new(()),
            reload_lock: Mutex::new(()),
            next_reload_gen: AtomicU64::new(0),
            applied_reload_gen: AtomicU64::new(0),
            resource_routing: RwLock::new(()),
            resource_routing_generation: AtomicU64::new(0),
            catalog_transitions: StdRwLock::new(HashMap::new()),
            index,
            tool_catalog_epoch: ToolCatalogEpoch::new(),
            reconnect_policy,
            reconnect_notify,
            #[cfg(test)]
            reconnect_commit_hook: StdMutex::new(None),
            #[cfg(test)]
            reconnect_outcome_hook: StdMutex::new(None),
            issuer,
            exchange,
            call_timeout: Some(DEFAULT_UPSTREAM_CALL_TIMEOUT),
            redial_dial_timeout: DEFAULT_REDIAL_DIAL_TIMEOUT,
            evidence: None,
            upstream_sessions: None,
            catalog: None,
            tool_reviews: None,
            catalog_authoritative: false,
            catalog_read_error_generation: AtomicU64::new(0),
            quarantine_threshold: quarantine_threshold_from_env(),
            catalog_strict_pending_approval: catalog_strict_pending_approval_from_env(),
            peer_jwks_cache: None,
        }
    }

    /// Build (and dial) a single upstream entry from its manifest, reusing the
    /// pool's boot-identical wiring (`issuer` / `exchange` / search `index` /
    /// `pool_size`). Used by boot ([`connect_inner`], `initial_gen = 0`, index
    /// published during the dial) and by the hot-add path in [`reload_manifests`]
    /// (`initial_gen = my_gen`, `index = None` so the index publish is DEFERRED to
    /// the fenced commit — a superseded add never pollutes the index). Like boot,
    /// the entry is returned even when its dial fails — the slots are allocated
    /// and marked down, and the reconnect scheduler heals them from the now-current
    /// manifest.
    ///
    /// `initial_gen` seeds `last_reload_gen` so a newly-added entry is fenced as
    /// of the reload that built it: an OLDER concurrent reload that finds this
    /// entry must see `older_gen < initial_gen` and skip its in-place update,
    /// rather than passing the fence against a `0` baseline and rolling the new
    /// entry's classifications/identity back.
    // Ten params, all irreducible dial wiring (identity issuer, exchange,
    // search index, pool size, dial timeout, generation, reconnect policy)
    // the entry needs at
    // construction; bundling them into a struct would just move the list, not
    // shorten it.
    #[allow(clippy::too_many_arguments)]
    async fn build_entry(
        name: &str,
        manifest: UpstreamManifest,
        issuer: Option<&SharedIdentityIssuer>,
        exchange: Option<&ExchangeBundle>,
        index: Option<&SearchIndex>,
        pool_size: usize,
        dial_timeout: Duration,
        initial_gen: u64,
        reconnect_policy: reconnect::ReconnectPolicy,
        reconnect_notify: Arc<Notify>,
    ) -> Arc<UpstreamEntry> {
        let forwards_identity =
            issuer.is_some() && matches!(manifest.transport, Transport::Http | Transport::Sse);
        let (slots, last_error_class) = dial_slots(
            name,
            &manifest,
            issuer,
            exchange,
            index,
            pool_size,
            dial_timeout,
        )
        .await;
        let mut connected_lanes = 0;
        for slot in &slots {
            connected_lanes += usize::from(slot.conn.read().await.is_some());
        }
        let total_lanes = slots.len();
        let entry = Arc::new(UpstreamEntry {
            slots,
            session_mutation: Mutex::new(()),
            forwards_identity,
            breaker: Breaker::new_with_open_notify(
                BreakerConfig::default(),
                reconnect_notify.clone(),
            ),
            recovery: StdRwLock::new(health::UpstreamRecovery::after_boot(
                connected_lanes,
                total_lanes,
                last_error_class,
            )),
            reconnect: StdMutex::new(reconnect::ReconnectState::after_boot_manifest(
                reconnect_policy,
                name,
                connected_lanes < total_lanes,
                &manifest,
            )),
            manifest: StdRwLock::new(manifest),
            reconnect_notify,
            removed: AtomicBool::new(false),
            observed_schemas: StdMutex::new(HashMap::new()),
            quarantined: StdRwLock::new(HashSet::new()),
            last_reload_gen: AtomicU64::new(initial_gen),
        });
        // Seed the per-entry behavior-hash baseline from the first connected
        // slot's live tools. No drift recorded — the map is empty so every
        // tool is a first observation. Subsequent publishes (reconnect /
        // reload) compare against this baseline. If no slot connected, the
        // baseline stays empty and the first reconnect populates it instead.
        // First observation can't be drift, so `QuarantineThreshold::Off`.
        for slot in &entry.slots {
            if let Some(conn) = slot.conn.read().await.as_ref() {
                entry.record_observed_schemas(
                    name,
                    &conn.live_tools,
                    "boot",
                    QuarantineThreshold::Off,
                );
                break;
            }
        }
        entry
    }
    /// Build a pool without dialing anything. Intended for tests that want to
    /// exercise catalog metadata (`tool_facts`, manifest lookup) without a
    /// real MCP upstream. No search index is wired up — that requires live
    /// tool lists, which disconnected entries don't have.
    pub fn from_manifests_disconnected(manifests: BTreeMap<String, UpstreamManifest>) -> Self {
        let reconnect_policy = reconnect::ReconnectPolicy::random();
        let reconnect_notify = Arc::new(Notify::new());
        let entries = manifests
            .into_iter()
            .map(|(name, manifest)| {
                let entry = Arc::new(UpstreamEntry {
                    // One empty slot — disconnected fixtures never dial,
                    // and the pool size is irrelevant with no issuer.
                    slots: vec![ConnectionSlot {
                        conn: RwLock::new(None),
                        in_use: Mutex::new(()),
                    }],
                    session_mutation: Mutex::new(()),
                    forwards_identity: false,
                    breaker: Breaker::new_with_open_notify(
                        BreakerConfig::default(),
                        reconnect_notify.clone(),
                    ),
                    recovery: StdRwLock::new(health::UpstreamRecovery::default()),
                    reconnect: StdMutex::new(reconnect::ReconnectState::after_boot_manifest(
                        reconnect_policy,
                        &name,
                        true,
                        &manifest,
                    )),
                    manifest: StdRwLock::new(manifest),
                    reconnect_notify: reconnect_notify.clone(),
                    removed: AtomicBool::new(false),
                    observed_schemas: StdMutex::new(HashMap::new()),
                    quarantined: StdRwLock::new(HashSet::new()),
                    last_reload_gen: AtomicU64::new(0),
                });
                (name, entry)
            })
            .collect();
        Self {
            entries: Arc::new(ArcSwap::from_pointee(entries)),
            audited_refusals: Arc::new(refusal_record::RefusalRecord::default()),
            protocol_gauge_publish: Mutex::new(()),
            reload_lock: Mutex::new(()),
            next_reload_gen: AtomicU64::new(0),
            applied_reload_gen: AtomicU64::new(0),
            resource_routing: RwLock::new(()),
            resource_routing_generation: AtomicU64::new(0),
            catalog_transitions: StdRwLock::new(HashMap::new()),
            index: None,
            tool_catalog_epoch: ToolCatalogEpoch::new(),
            reconnect_policy,
            reconnect_notify,
            #[cfg(test)]
            reconnect_commit_hook: StdMutex::new(None),
            #[cfg(test)]
            reconnect_outcome_hook: StdMutex::new(None),
            issuer: None,
            exchange: None,
            call_timeout: Some(DEFAULT_UPSTREAM_CALL_TIMEOUT),
            redial_dial_timeout: DEFAULT_REDIAL_DIAL_TIMEOUT,
            evidence: None,
            upstream_sessions: None,
            catalog: None,
            tool_reviews: None,
            catalog_authoritative: false,
            catalog_read_error_generation: AtomicU64::new(0),
            // Disconnected fixtures don't observe live tools so they
            // can't trigger drift; keep quarantine off regardless of
            // env to avoid env-leak into unit tests.
            quarantine_threshold: QuarantineThreshold::Off,
            // Same reasoning: tests opt into strict mode explicitly
            // via the builder below; never inherit it from env.
            catalog_strict_pending_approval: false,
            // No peer cache wired in disconnected mode. Tests
            // exercising `tier_c_peer:` use the public builder
            // `with_peer_jwks_cache` to attach a fake.
            peer_jwks_cache: None,
        }
    }

    /// Attach an `EvidenceRecorder` so reconnect outcomes produce
    /// `UpstreamHealth`-category audit rows. `waygate-server` chains
    /// this with the shared `audit_sink` (the same `SharedEvidence` the
    /// MCP dispatch path and `waygate-as` use) so every category lands
    /// in the same `audit_log` table.
    ///
    /// Boot-time dial outcomes are NOT recorded here — `connect_inner`
    /// runs before this builder method can be chained. The intent is
    /// captured by reconnect events: every disconnected upstream is scheduled
    /// independently, so a boot-failed upstream surfaces as the next
    /// `UpstreamReconnectFailed` event its retry records.
    pub fn with_evidence(mut self, evidence: waygate_mcp::audit::SharedEvidence) -> Self {
        self.evidence = Some(evidence);
        self.spawn_boot_rejected_output_schema_publish();
        self
    }

    /// Configure bounded per-upstream reconnect backoff. Existing boot-failed
    /// entries are re-armed from the new base immediately; each server keeps
    /// an independent jitter stream and failure episode.
    pub fn with_reconnect_policy(mut self, base: Duration, ceiling: Duration) -> Self {
        assert!(!base.is_zero(), "reconnect base must be non-zero");
        assert!(ceiling >= base, "reconnect ceiling must be >= base");
        self.reconnect_policy = self.reconnect_policy.configured(base, ceiling);
        let map = self.entries.load_full();
        for (name, entry) in map.iter() {
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            let needs_recovery = state.is_scheduled();
            state.reconfigure(self.reconnect_policy, name, needs_recovery);
            reconnect::publish_schedule(name, &state);
        }
        self.reconnect_notify.notify_waiters();
        self
    }

    /// Attach the governed-catalog read handle. When
    /// set, `resolve_invocation_tool` consults `CatalogStore::resolve_tool`
    /// first and falls back to the manifest on a miss / error.
    /// `waygate-server` wires this only when a Postgres pool exists;
    /// without it the pool keeps pure manifest behaviour.
    pub fn with_catalog(mut self, catalog: waygate_catalog::SharedCatalogStore) -> Self {
        self.catalog = Some(catalog);
        self
    }

    /// Attach a catalog that has already been reconciled from the exact
    /// accepted serving configuration. Missing rows and store failures are
    /// authoritative unavailability on this path; they never fall through to
    /// manifest admission.
    pub fn with_authoritative_catalog(
        mut self,
        catalog: waygate_catalog::SharedCatalogStore,
    ) -> Self {
        self.catalog = Some(catalog);
        self.catalog_authoritative = true;
        self
    }

    /// Opt into strict mode for catalog `PendingApproval`.
    /// When enabled, `resolve_invocation_tool` returns
    /// `ResolvedInvocationTool::Quarantined` on a `PendingApproval` instead of
    /// falling back to the manifest classification (the transitional
    /// behavior, kept for `false`). Tests use this to exercise the
    /// strict-mode branch without setting the
    /// `GATEWAY_CATALOG_STRICT_PENDING_APPROVAL` env (which would
    /// leak across the suite). Production is gated through the env
    /// parser at construction.
    pub fn with_catalog_strict_pending_approval(mut self, strict: bool) -> Self {
        self.catalog_strict_pending_approval = strict;
        self
    }

    /// Wire the peer JWKS cache so manifests that opt into
    /// Tier-C peer assertion via `tier_c_peer:` can resolve a
    /// peer id into its canonical issuer URL at per-call
    /// IdentityContext build time. The issuer becomes the `aud`
    /// claim on the gateway-minted identity JWT so the remote
    /// MCP gateway's `PeerJwtValidator` accepts it. Without this
    /// wired, manifests that set `tier_c_peer:` are detected at
    /// call time and refuse dispatch loud — better than silently
    /// downgrading to a Tier-B audience the remote can't match.
    /// `waygate-server` wires the same `Arc` that backs the peer
    /// JWKS refresh task and the inbound peer-assertion validator.
    pub fn with_peer_jwks_cache(
        mut self,
        cache: waygate_federation::jwks::SharedPeerJwksCache,
    ) -> Self {
        self.peer_jwks_cache = Some(cache);
        self
    }

    /// Expose the search index so `waygate-server` can clone it into the
    /// `GatewayServer`. Returns `None` when the pool was built disconnected
    /// or tantivy failed to initialize — callers fall back to substring
    /// search in that case.
    pub fn search_index(&self) -> Option<&SearchIndex> {
        self.index.as_ref()
    }

    /// Clone the process-wide signal used to notify downstream MCP sessions
    /// after successful changes to the published upstream tool catalog.
    pub fn tool_catalog_epoch(&self) -> ToolCatalogEpoch {
        self.tool_catalog_epoch.clone()
    }

    /// Look up an upstream, returning an OWNED `Arc<UpstreamEntry>` (not a
    /// borrow into the map). The dispatch hot path clones the `Arc` out under a
    /// lock-free `load()` so it holds its own handle for the whole call — a
    /// concurrent reload that publishes a map without this entry can't pull it
    /// out from under an in-flight dispatch.
    fn entry(&self, server: &str) -> Result<Arc<UpstreamEntry>, McpError> {
        self.entries
            .load()
            .get(server)
            .cloned()
            .ok_or_else(|| McpError::invalid_params(format!("unknown upstream: {server}"), None))
    }
}

/// Split a freshly-fetched `tools/list` response into:
/// 1. the subset present in the manifest's classification list (kept),
/// 2. names present upstream but not in the manifest (`unclassified`),
/// 3. names in the manifest but not advertised by the upstream (`ghosts`).
///
/// Fail-closed Tier-A enforcement, split into two refuse
/// points around the pool's RFC 8693 pre-flight. A single
/// post-pre-flight gate is bypassable because
/// `preflight_exchange` falls back to `principal.raw_token` as the
/// subject token when no durable session is present — meaning an
/// OAuth caller who never completed `/oauth/callback` could still
/// reach a `tier_a_required: true` upstream by having the gateway
/// exchange the *gateway-issued bearer*. These refuse points exist
/// to refuse exactly that posture.
///
/// Refuse point 1 ([`refuse_when_no_durable_session`]) runs BEFORE
/// pre-flight: it inspects whether the per-call resolver produced a
/// stored subject token (initial login or refresh-on-demand
/// recovered). If absent under `tier_a_required: true`, refuse
/// dispatch — never let the pool's pre-flight reach
/// `raw_token` fallback.
///
/// Refuse point 2 ([`refuse_when_exchange_failed`]) runs AFTER pre-
/// flight: a stored token was present but the RFC 8693 exchange
/// itself failed (IdP unreachable, scope mismatch, refresh died).
/// Distinguishing the two error texts lets the operator log identify
/// whether to investigate the IdP or have the user re-login.
fn refuse_when_no_durable_session(
    snapshot: &UpstreamManifest,
    stored: Option<&str>,
    server: &str,
    principal_sub: &str,
) -> Result<(), McpError> {
    if snapshot.tier_a_required && stored.is_none() {
        tracing::warn!(
            %server,
            user = %principal_sub,
            "tier_a_required=true but no durable upstream session resolved; refusing dispatch",
        );
        return Err(McpError::internal_error(
            format!(
                "upstream `{server}` requires Tier-A (durable upstream session); \
                 no session available for principal `{principal_sub}`. Have the user \
                 complete an OAuth login (waygate-as) before retrying."
            ),
            None,
        ));
    }
    Ok(())
}

fn refuse_when_exchange_failed(
    snapshot: &UpstreamManifest,
    exchanged_bearer: Option<&str>,
    server: &str,
    principal_sub: &str,
) -> Result<(), McpError> {
    if snapshot.tier_a_required && exchanged_bearer.is_none() {
        tracing::warn!(
            %server,
            user = %principal_sub,
            "tier_a_required=true but RFC 8693 pre-flight produced no exchanged bearer; refusing dispatch",
        );
        return Err(McpError::internal_error(
            format!(
                "upstream `{server}` requires Tier-A but the RFC 8693 token exchange \
                 failed for principal `{principal_sub}`. The durable session is present; \
                 check the IdP token-exchange endpoint, audience configuration, and \
                 upstream issuer reachability."
            ),
            None,
        ));
    }
    Ok(())
}

/// Tier-A gate: should the per-call pipeline consult
/// `user_upstream_sessions` for an upstream-token subject?
///
/// ALL three must be true:
///
/// 1. The upstream opted into the RFC 8693 exchange (the existing
///    `exchange:` manifest block). No exchange → no subject token
///    needed at all, so no point fetching a stored one.
/// 2. The caller authenticated via OAuth. **Privilege-escalation
///    guard**: `user_upstream_sessions` rows
///    are written exclusively by `/oauth/callback`, which only runs
///    for OAuth principals. An API-key principal happens to share
///    the same `sub` field but its `auth_method` is `ApiKey`. Without
///    this check, an operator-minted API key whose `sub` matches an
///    OAuth user (e.g. `alice@example.com`) would borrow that user's
///    stored IdP access token for downscoped Tier-A exchange — a
///    long-lived API-key holder → user-IdP-token escalation. Restrict
///    the read path to the same auth method that produced the write.
///
/// (The third gate — "the pool was wired with a session store" — is
/// enforced inside [`UpstreamPool::resolve_tier_a_subject_token`] so
/// every caller of that helper benefits.)
fn should_consult_tier_a_session(
    principal: &Principal,
    exchange: Option<&ExchangeSettings>,
) -> bool {
    exchange.is_some() && matches!(principal.auth_method, waygate_oidc::AuthMethod::Oauth)
}

// Helpers above this line are reused by tests; helpers below are
// pool-internal.

async fn dial(
    manifest: &UpstreamManifest,
    issuer: Option<&SharedIdentityIssuer>,
    exchange: Option<&ExchangeBundle>,
) -> Result<Connection, DialError> {
    // Identity-forwarding upstreams (HTTP/SSE with an issuer) get a fresh
    // cell wired into THIS connection's transport. It travels back in the
    // returned Connection so the cell and the client it feeds stay
    // together — a reconnect replaces both atomically. Stdio is excluded:
    // no HTTP header to stamp, and stdio runs inside the gateway's own
    // boundary.
    let identity_cell = match (issuer, &manifest.transport) {
        (Some(_), Transport::Http | Transport::Sse) => Some(IdentityCell::new()),
        _ => None,
    };
    // Initializing a connection and discovering its tool schema are gateway
    // service operations, not anonymous user calls. Give those requests a
    // verified identity, then clear it before the connection can serve a
    // caller. The default identity is group-less. A manifest may opt into
    // catalog-only groups when its upstream hides tool definitions by role;
    // those groups exist only for initialize/tools-list and never survive into
    // caller dispatch.
    let _probe_identity_guard =
        install_catalog_probe_identity(manifest, issuer, identity_cell.as_ref())?;
    // Per-transport construction lives in the transport factory; the
    // common post-connect tail (tools/list + Connection) stays here.
    let connected =
        transport::connect_with_destination(manifest, issuer, identity_cell.as_ref(), exchange)
            .await?;
    let listed = list_all_tools(&connected.service)
        .await
        .map_err(DialError::ListTools)?;
    let peer_info = connected.service.peer_info();
    let negotiated_protocol = peer_info.as_ref().map(|i| i.protocol_version.to_string());
    let resource_capability_advertised =
        peer_info.is_some_and(|i| i.capabilities.resources.is_some());
    Ok(Connection {
        client: connected.service,
        network_destination: connected.network_destination,
        cleartext_control_plane: connected.cleartext_control_plane,
        negotiated_protocol,
        resource_capability_advertised,
        identity_cell,
        // `tools` is the manifest-filtered, published view; the caller
        // fills it via `publish_classified_tools` against `live_tools`
        // before installing the connection. Empty here is the
        // pre-publish placeholder, never observed by readers.
        tools: Vec::new(),
        live_tools: listed.tools,
        ttl_hint_ms: listed.ttl_hint_ms,
        dialed_at: listed.listed_at,
        rejected_output_schemas: Vec::new(),
        unregisterable_input_schemas: Vec::new(),
    })
}

use lanes::dial_slots;
pub use lanes::resolve_isolation;
#[cfg(test)]
use lanes::slot_count;

#[async_trait]
impl UpstreamCatalog for UpstreamPool {
    async fn list_servers(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.load().keys().cloned().collect();
        names.sort();
        names
    }

    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
        let entry = self.entry(server)?;
        let tools = entry.published_tools(self.tool_reviews.is_none()).await;
        if self.tool_reviews.is_none() {
            return Ok(tools);
        }
        let mut admitted = Vec::with_capacity(tools.len());
        for tool in tools {
            if matches!(
                self.resolve_invocation_tool(
                    waygate_core::TenantId::DEFAULT,
                    server,
                    tool.name.as_ref()
                )
                .await,
                ResolvedInvocationTool::Ready(_)
            ) {
                admitted.push(tool);
            }
        }
        Ok(admitted)
    }

    async fn discovery_generation(&self) -> Result<Option<i64>, McpError> {
        let Some(catalog) = self.catalog.as_ref() else {
            return Ok(None);
        };
        catalog.discovery_generation().await.map_err(|error| {
            tracing::warn!(%error, "durable catalog discovery generation unavailable");
            McpError::internal_error(
                "the governed tool catalog generation is unavailable; retry the request",
                Some(serde_json::json!({
                    "error": "catalog_generation_unavailable",
                    "retryable": true,
                })),
            )
        })
    }

    fn discovery_error_generation(&self) -> u64 {
        self.catalog_read_error_generation.load(Ordering::Acquire)
    }
    fn resource_claims(&self, server: &str) -> Vec<waygate_mcp::catalog::ResourceClaim> {
        self.declared_resource_claims(server)
    }
    fn admitted_resource_routing_claims(&self) -> Vec<(String, ResourceClaim)> {
        self.admitted_resource_routing_claims_inner()
    }
    async fn resource_routing_snapshot(&self) -> ResourceRoutingSnapshot {
        self.resource_routing_snapshot_inner().await
    }

    async fn list_resources(
        &self,
        server: &str,
        params: Option<PaginatedRequestParams>,
        principal: Option<&Principal>,
    ) -> Result<ListResourcesResult, McpError> {
        match self
            .request_resource_inner(server, ResourceRequest::List(params), principal)
            .await?
        {
            ResourceResponse::List(result) => Ok(result),
            ResourceResponse::ListTemplates(_) => {
                unreachable!("list request returned a template-list response")
            }
            ResourceResponse::Read(_) => unreachable!("list request returned a read response"),
        }
    }

    async fn list_resource_templates(
        &self,
        server: &str,
        params: Option<PaginatedRequestParams>,
        principal: Option<&Principal>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        self.request_resource_templates_inner(server, params, principal)
            .await
    }

    async fn read_resource(
        &self,
        server: &str,
        params: ReadResourceRequestParams,
        principal: Option<&Principal>,
    ) -> Result<ReadResourceResult, McpError> {
        match self
            .request_resource_inner(server, ResourceRequest::Read(params), principal)
            .await?
        {
            ResourceResponse::Read(result) => Ok(result),
            ResourceResponse::ListTemplates(_) => {
                unreachable!("read request returned a template-list response")
            }
            ResourceResponse::List(_) => unreachable!("read request returned a list response"),
        }
    }

    async fn read_resource_admitted(
        &self,
        server: &str,
        params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        admitted: &ResourceReadAdmission,
    ) -> Result<ReadResourceResult, AdmittedResourceReadError> {
        self.read_resource_admitted_inner(server, params, principal, admitted)
            .await
    }

    fn resource_operations_supported(&self, server: &str) -> bool {
        self.resource_operations_supported_inner(server)
    }

    async fn resource_capability_advertised(&self, server: &str) -> bool {
        self.resource_capability_advertised_inner(server).await
    }
    async fn authorize_file_download(
        &self,
        server: &str,
        params: AuthorizeDownloadParams,
        principal: Option<&Principal>,
    ) -> Result<AuthorizedFileDownload, McpError> {
        self.authorize_download(server, params, principal).await
    }
    async fn authorize_file_upload(
        &self,
        server: &str,
        tool_name: &str,
        params: AuthorizeUploadParams,
        principal: Option<&Principal>,
        admitted: &InvocationContractIdentity,
    ) -> Result<AuthorizedFileUpload, McpError> {
        self.authorize_upload(server, tool_name, params, principal, admitted)
            .await
    }
    async fn call_tool(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError> {
        // Narrow legacy entry point: no retry payload, no caller input
        // capabilities; `require_complete` refuses non-final variants.
        let response = self
            .call_tool_traced(
                server,
                tool_name,
                args,
                principal,
                admitted,
                ToolCallMrtr::default(),
            )
            .await?;
        dispatch::require_complete(response, server, tool_name)
    }

    async fn call_tool_response(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        mrtr: ToolCallMrtr,
    ) -> Result<CallToolResponse, McpError> {
        self.call_tool_traced(server, tool_name, args, principal, admitted, mrtr)
            .await
    }

    async fn call_tool_response_processed(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        processing: CallToolResultProcessing<'_>,
    ) -> Result<CallToolResponse, waygate_mcp::catalog::InvocationError> {
        self.call_tool_response_processed_with_resource_routing(
            server, tool_name, args, principal, admitted, processing,
        )
        .await
    }

    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        // Unknown server / unknown tool falls through to the safe default
        // (Low / no-side-effects / no-pii). For any *live* upstream this
        // branch is unreachable for unclassified tools: they're filtered
        // out of `Connection.tools` and the search index at publish
        // time, and `call_tool_inner` rejects unclassified by-name calls
        // before they reach the upstream. The fallback exists for
        // catalog queries that bypass the pool's call path (e.g. authz
        // precomputing facts for a tool name lifted from a stale client
        // cache) and must stay conservative.
        let manifest = self
            .entries
            .load()
            .get(server)
            .map(|e| e.manifest_snapshot());
        contract_binding::manifest_tool_facts(manifest.as_ref(), server, tool_name)
    }

    /// Governed-catalog read with manifest fallback.
    ///
    /// When a `CatalogStore` is wired, consult
    /// `resolve_tool(tenant, "server.tool")` first:
    /// - `Live` → retain the catalog identity, admitted schemas, and classification.
    /// - `Quarantined` → return `ResolvedInvocationTool::Quarantined`, an
    ///   authoritative block. The caller refuses dispatch / hides the
    ///   tool and does **not** fall back to the manifest — otherwise an
    ///   operator's quarantine would have no effect on a
    ///   manifest-backed upstream.
    /// - `PendingApproval` follows the configured strict-mode contract.
    /// - `NotFound` / DB error fall back only for a transitional catalog
    ///   attachment. An authoritative attachment refuses them because boot
    ///   already reconciled the exact serving set and absence or unreadability
    ///   cannot safely be distinguished from withdrawal.
    ///
    /// When no `CatalogStore` is wired, this is just `tool_facts`.
    async fn resolve_invocation_tool(
        &self,
        tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        // Without durable review storage, the in-process quarantine is the
        // authority. With storage, resolve_snapshot_from checks the durable
        // decision so an acceptance on another replica can take effect.
        // Clone the entry out from under the lock-free `load()` BEFORE the
        // `.await` — an `if let` scrutinee's temporary (the arc-swap guard)
        // would otherwise live across the await, holding the guard over a
        // suspension point.
        let entry = self.entries.load().get(server).cloned();
        // ONE manifest snapshot governs admission, mode, hash, and facts;
        // the separately read published contract is bound to this generation
        // inside the resolver (published behavior hash == approved hash).
        let manifest = entry.as_ref().map(|entry| entry.manifest_snapshot());
        if let (Some(entry), Some(manifest)) = (entry.as_ref(), manifest.as_ref()) {
            if self.tool_reviews.is_none() && entry.is_quarantined(tool_name).await {
                tracing::info!(
                    %tenant, %server, tool = %tool_name,
                    "tool is in-process quarantined (drift-triggered); refusing dispatch",
                );
                return ResolvedInvocationTool::Quarantined {
                    server: server.to_owned(),
                    tool: tool_name.to_owned(),
                };
            }
            if !admission::entry_tool_is_admitted(entry, manifest, tool_name).await {
                tracing::info!(
                    %tenant, %server, tool = %tool_name,
                    "tool is not admitted by the current classification mode and behavior hash",
                );
                return ResolvedInvocationTool::Quarantined {
                    server: server.to_owned(),
                    tool: tool_name.to_owned(),
                };
            }
        }
        let published =
            schema_admission::published_tool_contract(entry.as_deref(), tool_name).await;
        self.resolve_snapshot_from(
            tenant,
            server,
            tool_name,
            contract_binding::snapshot_inputs_for(manifest.as_ref(), server, tool_name, published),
        )
        .await
    }
}

impl UpstreamPool {
    async fn call_tool_inner(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        options: dispatch::ToolCallDispatchOptions<'_>,
    ) -> Result<dispatch::ProcessedCallToolResponse, McpError> {
        let dispatch::ToolCallDispatchOptions { mrtr, processor } = options;
        let entry = self.entry(server)?;

        // Refuse a call to a tombstoned upstream. A hot remove
        // (`reload_manifests`) sets `removed` and drains the slots BEFORE it
        // publishes the map without this entry; a dispatch that loaded the OLD
        // map during that window holds a cloned `Arc` to the tombstoned entry.
        // Without this check it could start a NEW upstream RPC after the drain,
        // so the removed upstream would not actually stop serving.
        // Calls already past this point hold the `Arc` and run to completion;
        // only new dispatches that observe the tombstone are refused.
        if entry.removed.load(Ordering::Acquire) {
            return Err(McpError::invalid_params(
                format!("upstream `{server}` is being removed"),
                None,
            ));
        }

        // Reject calls to tools the operator hasn't classified. Unclassified
        // tools are filtered out of `Connection.tools` and the search index
        // at publish time, so an explicit by-name call is the only way to
        // reach them — usually a hardcoded client or a stale prompt.
        // Without this check the catalog default (Low risk, no side-effects)
        // would silently apply to upstream tools the operator never audited.
        // Runs before the breaker so a flood of calls to a typo'd tool name
        // can't drain the failure budget on a healthy upstream.
        if !admission::entry_tool_is_admitted(&entry, &entry.manifest_snapshot(), tool_name).await {
            return Err(McpError::invalid_params(
                format!("upstream `{server}` has no admitted tool `{tool_name}`"),
                None,
            ));
        }

        // Build the per-call IdentityContext *before* acquiring the
        // per-upstream `call_serializer`: the
        // refresh-on-demand path can issue a network round-trip to
        // the upstream IdP, and holding the serializer across that
        // network call would block every concurrent call to the same
        // upstream until the refresh's 10s timeout fires. The
        // serializer's only job is to prevent concurrent writes to
        // the shared `IdentityCell` and the rmcp `RunningService`'s
        // session state — both of which are O(1) after the context
        // is built. Building the context (which may call refresh) is
        // therefore safe to do without the serializer; the
        // serializer wraps `cell.set` + dispatch only.
        //
        // Three gates on the Tier-A subject-token lookup, ALL must pass:
        //
        // 1. The upstream opted into the exchange (the existing
        //    `exchange:` manifest block).
        // 2. The pool was wired with a session store (handled inside
        //    `resolve_tier_a_subject_token`).
        // 3. **The caller is an OAuth principal.** A
        //    privilege-escalation guard:
        //    `user_upstream_sessions` is written exclusively by
        //    `/oauth/callback`, which only runs for OAuth principals;
        //    the read path enforces the same invariant by
        //    `auth_method` check. Otherwise an operator-minted API
        //    key whose `sub` matches an OAuth user
        //    (e.g. `alice@example.com`) would borrow that user's
        //    stored IdP access token for downscoped Tier-A exchange.
        //    Keep the gate co-located with the lookup so every future
        //    caller has to walk past it.
        // The fail-closed gate runs regardless of whether
        // this pool wires identity forwarding. The `(None, _)` /
        // `(_, None)` arms below mean a pool built via `connect()`
        // (no identity issuer, no per-upstream identity cell) or a
        // call without a principal (dev mode); both are
        // misconfigurations for `tier_a_required: true`. Refuse
        // dispatch with the same error the populated arm would
        // produce — operator gets a single clear signal instead of a
        // silent Tier-B dispatch.
        let snapshot = entry.manifest_snapshot();

        // MRTR continuations are generation-bound (contracts in
        // `pool::dispatch`): a manifest that can never negotiate 2026
        // cannot have issued the pause a continuation answers — refuse
        // before any breaker/identity/dial cost. The reuse arm adds the
        // lane-level half for a post-reconnect rollback.
        let has_continuation = mrtr.input_responses.is_some() || mrtr.request_state.is_some();
        if let Some(err) =
            dispatch::manifest_continuation_refusal(server, has_continuation, &snapshot)
        {
            return Err(err);
        }

        // Tier-A / Tier-C identity-forwarding refusal gates (moved verbatim
        // to `session_identity::refuse_identityless_tiers`): a manifest that
        // demands identity minting the pool cannot perform must refuse loud
        // before any breaker or dial cost.
        refuse_identityless_tiers(server, &snapshot, entry.forwards_identity, principal)?;

        // Build the per-call IdentityContext *before* acquiring the
        // per-upstream `call_serializer`: the
        // refresh-on-demand path can issue a network round-trip to
        // the upstream IdP, and holding the serializer across that
        // network call would block every concurrent call to the same
        // upstream until the refresh's 10s timeout fires.
        //
        // Subject-token + pre-flight gates:
        // 1. The upstream opted into the exchange (`exchange:`
        //    manifest block).
        // 2. The pool was wired with a session store (handled inside
        //    `resolve_tier_a_subject_token`).
        // 3. The caller is an OAuth principal (privilege-escalation
        //    guard).
        // 4. Pre-flight the RFC 8693 exchange in the pool, not at
        //    `headers()` time: doing the exchange inside the
        //    augmenter meant exchange failures silently dropped the
        //    Authorization header, bypassing `tier_a_required`. The
        //    pre-flight populates `IdentityContext.exchanged_bearer`
        //    that the augmenter stamps directly.
        let prebuilt_context = match (entry.forwards_identity, principal) {
            (true, Some(principal)) => {
                let exchange = snapshot.exchange.as_ref().map(|cfg| ExchangeSettings {
                    audience: cfg.audience.clone(),
                    scope: cfg.scope.clone(),
                });
                let stored_upstream_subject_token =
                    if should_consult_tier_a_session(principal, exchange.as_ref()) {
                        self.resolve_tier_a_subject_token(server, &principal.sub)
                            .await
                    } else {
                        None
                    };
                // Refuse point 1: under
                // `tier_a_required: true`, refuse BEFORE pre-flight
                // when no durable session resolved. `preflight_exchange`
                // falls back to `principal.raw_token` when stored is
                // None — that fallback is exactly the posture the flag
                // exists to refuse (gateway-issued bearer, not the
                // user's IdP token).
                refuse_when_no_durable_session(
                    &snapshot,
                    stored_upstream_subject_token.as_deref(),
                    server,
                    &principal.sub,
                )?;
                // Pre-flight the RFC 8693 exchange so the augmenter
                // doesn't have to do it (and so an exchange failure
                // surfaces here, where we can refuse dispatch under
                // `tier_a_required` with an operator-meaningful error).
                let exchanged_bearer = self
                    .preflight_exchange(
                        server,
                        principal,
                        exchange.as_ref(),
                        stored_upstream_subject_token.as_deref(),
                    )
                    .await;
                // Refuse point 2: the durable session was present but
                // the RFC 8693 exchange itself failed. Distinguishing
                // this from refuse point 1 lets the operator's log
                // identify whether to investigate the IdP or have the
                // user re-login.
                refuse_when_exchange_failed(
                    &snapshot,
                    exchanged_bearer.as_deref(),
                    server,
                    &principal.sub,
                )?;
                // When this manifest opts into Tier-C peer
                // assertion, the minted identity JWT must carry
                // `aud = <peer's issuer URL>` so the remote
                // gateway's PeerJwtValidator accepts it.
                // Fail-closed if the peer isn't in the cache —
                // silently downgrading to the Tier-B server-name
                // audience would just produce a 401 at the remote,
                // with a confusing error path. The peer is looked
                // up by id only; the cache spans tenants, so
                // per-tenant gating happens elsewhere (admin CRUD
                // enforces tenant-scoped registration). The
                // gateway-minted JWT goes on Authorization: Bearer
                // (NOT just X-MCP-Identity) so the remote gateway's
                // PeerJwtValidator actually sees it. Resolve the
                // peer's issuer URL once, pass it as both the mint
                // audience AND the tier_c_audience marker on
                // IdentityContext.
                let tier_c_audience = match snapshot.tier_c_peer {
                    Some(peer_id) => Some(
                        self.resolve_tier_c_audience(server, peer_id, &principal.sub)
                            .await?,
                    ),
                    None => None,
                };
                let audience = tier_c_audience.clone().unwrap_or_else(|| server.to_owned());
                Some(IdentityContext {
                    principal: principal.clone(),
                    audience,
                    exchange,
                    stored_upstream_subject_token,
                    exchanged_bearer,
                    tier_c_audience,
                })
            }
            _ => None,
        };

        // Acquire the breaker permit AFTER all gateway-side refusal
        // gates: acquiring earlier
        // meant Tier-A refusals dropped an unreported permit
        // (counted as upstream failure by `Permit::drop`),
        // potentially tripping the breaker on a healthy upstream
        // just because callers without a durable session retried.
        //
        // `acquire()` is also where the Open → HalfOpen timeout
        // transition lives (see `breaker.rs:86-99`), so it must run
        // on every call — a pre-acquire short-circuit on
        // `breaker.state() == Open` would block recovery forever
        // until a reconnect path called `breaker.reset()`.
        // The cost of paying for a Tier-A
        // pre-flight while the breaker is Open is bounded
        // (`open_duration` is 30s by default), and the alternative
        // (broken recovery) is worse.
        let permit = match entry.breaker.acquire() {
            Ok(p) => p,
            Err(BreakerError::Open) => {
                tracing::warn!(
                    %server,
                    "upstream circuit breaker is open; rejecting call",
                );
                return Err(McpError::internal_error(
                    format!("upstream `{server}` circuit open"),
                    None,
                ));
            }
            Err(BreakerError::ProbeInFlight) => {
                return Err(McpError::internal_error(
                    format!("upstream `{server}` circuit probing recovery"),
                    None,
                ));
            }
        };

        // Check out a connection slot for this call. Holding the
        // checkout's `in_use` lock makes the slot's connection AND its
        // identity cell this call's alone for the dispatch — so concurrent
        // calls to the same upstream run on different slots in parallel
        // instead of serializing on one connection (the old per-upstream
        // `call_serializer`). The cell lives inside the slot's `Connection`,
        // so it always matches the live client and is never shared across
        // slots — no cross-caller identity clobbering.
        //
        // The metrics measure the checkout: `wait` is the time to get
        // a free slot (≈0 when a lane is idle), `queue_depth` the number of
        // calls contending on this upstream's pool (> pool_size ⇒ saturated).
        waygate_telemetry::metrics::identity_cell_queue_inc(server);
        let _depth_guard = SerializerDepthGuard {
            server: server.to_owned(),
        };
        let wait_start = std::time::Instant::now();
        let checkout = entry.checkout().await;
        waygate_telemetry::metrics::record_identity_cell_wait(
            server,
            wait_start.elapsed().as_secs_f64(),
        );

        // The `snapshot` above — and the Tier-A/Tier-C gates
        // + per-call IdentityContext built from it — predate this checkout. A
        // live re-dial commits its new shape AND identity atomically under the
        // slot conn write locks, so a call that snapshotted before the swap and
        // dispatched after it could otherwise run on the freshly-installed
        // connection (Reuse) or dial the stale shape (PerCall) with the OLD
        // isolation / identity / auth posture — e.g. missing a newly-enabled
        // `tier_a_required`. Each branch checks while holding the slot conn read
        // lock. A re-dial needs the WRITE lock, so under it the connection
        // and the manifest cannot move, and `redial_committed_fields_eq` against
        // `snapshot` is exact. If anything a re-dial commits changed, we refuse
        // retryably and the caller rebuilds a context consistent with the new
        // connection.

        let params =
            dispatch::build_call_params(tool_name, args, mrtr.input_responses, mrtr.request_state);

        // Tenant for the dispatch-time contract re-resolution: the same
        // derivation the pipeline's Stage 1 uses (anonymous ⇒ default
        // tenant), so both reads resolve through identical catalog scoping.
        let tenant = principal
            .map(|p| p.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);

        // Resolve session isolation for this upstream. `PerCall` (the
        // HTTP/SSE default) dials a FRESH upstream session for this call and
        // drops it afterwards, so no state from a prior call — or a different
        // principal — can survive on a reused session (a property MCP does
        // not guarantee). `Reuse` runs the call on the checked-out slot's
        // long-lived session. Either way the checkout's `in_use` lock bounds
        // this upstream's concurrency.
        let isolation = resolve_isolation(&snapshot);
        let call_deadline = self
            .call_timeout
            .and_then(|duration| tokio::time::Instant::now().checked_add(duration));
        let trace_id = dispatch::call_trace_id();
        let mut attempts = 1_usize;
        let (inner_result, conn_guard) = match isolation {
            SessionIsolation::PerCall => {
                // Initialize-only dial (no tools/list — the boot slot already
                // published the tool view); a fresh identity cell carries this
                // call's principal so even the initialize handshake is scoped
                // to the caller. The boot-dialed `slot.conn` is left as the
                // tools/health connection and is NOT used for the call.
                //
                // Hold the boot slot's conn READ lock across the health check,
                // the consistency re-check, AND the ephemeral dial + RPC: a
                // re-dial needs the WRITE lock to commit its new shape/identity,
                // so while we hold this read lock the manifest cannot move under
                // us and the `snapshot` we dial + gate from stays current.
                // The ephemeral session itself does not use this
                // connection — the lock is purely the re-dial barrier.
                let conn_guard = checkout.slot.conn.read().await;
                // First honor the boot slot's health: if no free slot holds a
                // live connection, the upstream was unreachable at the last
                // probe — report "not connected" (as `Reuse` does, counting
                // against the breaker) instead of attempting a doomed
                // ephemeral dial and surfacing a noisier transport error.
                let Some(conn) = conn_guard.as_ref() else {
                    permit.failure();
                    entry.record_runtime_failure(UpstreamErrorClass::Transport);
                    return Err(McpError::internal_error(
                        format!("upstream `{server}` is not connected"),
                        None,
                    ));
                };
                // Re-check the tombstone AFTER the per-call setup awaits
                // (identity/session build + slot checkout): a hot remove may have
                // tombstoned this entry since the early check in `call_tool_inner`.
                // We hold the slot's conn READ lock here, which the remove drain's
                // WRITE-lock barrier must wait on — so if `removed` is set we refuse
                // before any RPC, and if it isn't, the drain can't complete until we
                // release. Either way a removed upstream never receives a racing
                // call. Breaker-neutral: a local removal race, not
                // an upstream-health signal.
                if entry.removed.load(Ordering::Acquire) {
                    permit.neutral();
                    return Err(McpError::invalid_params(
                        format!("upstream `{server}` is being removed"),
                        None,
                    ));
                }
                let current_manifest = entry.manifest_snapshot();
                if !dispatch_contract_is_current(
                    &entry,
                    &snapshot,
                    &current_manifest,
                    &conn.live_tools,
                    tool_name,
                    self.tool_reviews.is_none(),
                ) {
                    permit.neutral();
                    return Err(contract_changed_error(server, tool_name));
                }
                // Bind this dispatch to the exact contract identity Stage 1
                // admitted: a reload that swapped in a different APPROVED
                // contract since the pipeline validated/authorized would pass
                // the current-state admission above while executing claims
                // the earlier stages never saw. Breaker-neutral: a local
                // configuration race, not an upstream-health signal.
                let raw_contract = conn
                    .live_tools
                    .iter()
                    .find(|tool| tool.name.as_ref() == tool_name);
                if self
                    .observe_tool_reviews(
                        &entry,
                        server,
                        &current_manifest,
                        raw_contract.map(std::slice::from_ref).unwrap_or_default(),
                    )
                    .await
                    .is_err()
                {
                    permit.neutral();
                    return Err(contract_changed_error(server, tool_name));
                }
                if !self
                    .review_allows(
                        server,
                        tool_name,
                        raw_contract,
                        current_manifest.classification_mode,
                    )
                    .await
                {
                    permit.neutral();
                    return Err(contract_changed_error(server, tool_name));
                }
                if let Some(admitted) = admitted {
                    if !self
                        .admitted_contract_is_current(
                            tenant,
                            server,
                            tool_name,
                            &current_manifest,
                            conn,
                            admitted,
                        )
                        .await
                    {
                        permit.neutral();
                        return Err(contract_changed_error(server, tool_name));
                    }
                }
                // The recovery module owns the complete pre-dispatch attempt:
                // dial, annotation contract read, and request handoff. It may
                // repeat that sequence once only while dispatch is proven
                // absent and the admitted contract proves replay safe.
                let execution = recovery::execute_per_call(recovery::PerCallExecution {
                    pool: self,
                    snapshot: &snapshot,
                    current_manifest: &current_manifest,
                    entry: &entry,
                    issuer: self.issuer.as_ref(),
                    exchange: self.exchange.as_ref(),
                    prebuilt_context: prebuilt_context.as_ref(),
                    caller_capabilities: mrtr.caller_capabilities.as_ref(),
                    negotiated_protocol: conn.negotiated_protocol.as_deref(),
                    admitted,
                    has_continuation,
                    approval_gated: mrtr.approval_gated,
                    deadline: call_deadline,
                    timeout: self.call_timeout,
                    server,
                    tool_name,
                    advertised_tool: raw_contract,
                    trace_id: &trace_id,
                    params,
                    processor,
                })
                .await;
                match execution {
                    recovery::PerCallExecutionOutcome::Finished {
                        result,
                        attempts: completed_attempts,
                    } => {
                        attempts = completed_attempts;
                        (result, conn_guard)
                    }
                    recovery::PerCallExecutionOutcome::Failed { error, error_class } => {
                        permit.failure();
                        entry.record_runtime_failure(error_class);
                        return Err(error);
                    }
                }
            }
            SessionIsolation::Reuse => {
                let conn_guard = checkout.slot.conn.read().await;
                let Some(conn) = conn_guard.as_ref() else {
                    // Not-connected counts against the breaker so a
                    // persistently down upstream trips open instead of
                    // returning "not connected" forever. (Checkout prefers a
                    // connected slot; reaching here means every free slot was
                    // down — the reconnect scheduler heals them.)
                    permit.failure();
                    entry.record_runtime_failure(UpstreamErrorClass::Transport);
                    return Err(McpError::internal_error(
                        format!("upstream `{server}` is not connected"),
                        None,
                    ));
                };
                // Re-check the tombstone after the setup awaits + slot checkout —
                // the conn READ lock (held across the RPC below) is the same barrier
                // the remove drain's WRITE lock must wait on, so a hot remove that
                // raced our early check is caught here before any RPC.
                // Breaker-neutral: a local removal race.
                if entry.removed.load(Ordering::Acquire) {
                    permit.neutral();
                    return Err(McpError::invalid_params(
                        format!("upstream `{server}` is being removed"),
                        None,
                    ));
                }
                let current_manifest = entry.manifest_snapshot();
                if !dispatch_contract_is_current(
                    &entry,
                    &snapshot,
                    &current_manifest,
                    &conn.live_tools,
                    tool_name,
                    self.tool_reviews.is_none(),
                ) {
                    permit.neutral();
                    return Err(contract_changed_error(server, tool_name));
                }
                // Bind this dispatch to the exact contract identity Stage 1
                // admitted (see the PerCall branch's twin check): the RPC
                // below runs on this connection while we hold its read lock,
                // so a mismatch here is the last point the race can be
                // refused. Breaker-neutral: a local configuration race.
                let raw_contract = conn
                    .live_tools
                    .iter()
                    .find(|tool| tool.name.as_ref() == tool_name);
                if !self
                    .review_allows(
                        server,
                        tool_name,
                        raw_contract,
                        current_manifest.classification_mode,
                    )
                    .await
                {
                    permit.neutral();
                    return Err(contract_changed_error(server, tool_name));
                }
                if let Some(admitted) = admitted {
                    if !self
                        .admitted_contract_is_current(
                            tenant,
                            server,
                            tool_name,
                            &current_manifest,
                            conn,
                            admitted,
                        )
                        .await
                    {
                        permit.neutral();
                        return Err(contract_changed_error(server, tool_name));
                    }
                }
                // Populate THIS slot's identity cell (if identity-forwarding)
                // with a drop-guard so an early return / panic / cancellation
                // still clears it before the slot is handed to the next caller.
                let _cell_guard = match (conn.identity_cell.as_ref(), prebuilt_context) {
                    (Some(cell), Some(ctx)) => {
                        cell.set(ctx);
                        Some(CellClearGuard { cell: cell.clone() })
                    }
                    _ => None,
                };
                // Bind the approved annotation contract to the session that
                // executes the RPC — the long-lived pooled session. The
                // admission above checked `conn.live_tools`, which was read
                // when this connection DIALED, and the pool handles no
                // `notifications/tools/list_changed` — so a reuse session
                // (or forced-reuse stdio) that changed its descriptors after
                // dial would otherwise keep executing under the stale
                // approved view until a reconnect. Read the session's
                // current `tools/list` (under the caller's identity, exactly
                // as the per-call ephemeral dial carries it) and require
                // admission on what it advertises NOW. Manifest mode is
                // exempt: its classification authority is the operator's
                // manifest, and the legacy dispatch path stays unchanged.
                if matches!(
                    current_manifest.classification_mode,
                    crate::ClassificationMode::McpAnnotations
                ) {
                    let session_tools = match self
                        .session_tools_bounded(&conn.client, recovery::remaining(call_deadline))
                        .await
                    {
                        Ok(tools) => tools,
                        Err(e) => {
                            // A transport failure on the session makes this
                            // lane suspect, same as a failed RPC below.
                            let error_class = e.error_class();
                            dispatch::record_failure(
                                server,
                                dispatch::ToolCallFailurePhase::PreDispatch,
                            );
                            tracing::warn!(
                                %server,
                                %tool_name,
                                %trace_id,
                                phase = dispatch::ToolCallFailurePhase::PreDispatch.as_str(),
                                error = %e,
                                "reuse session contract read failed",
                            );
                            permit.failure();
                            drop(conn_guard);
                            self.mark_slot_down(server, &entry, checkout.slot, error_class)
                                .await;
                            return Err(dispatch::bounded_upstream_error(
                                server,
                                dispatch::ToolCallFailurePhase::PreDispatch,
                                false,
                                1,
                                &trace_id,
                            ));
                        }
                    };
                    let current_tool = session_tools
                        .iter()
                        .find(|tool| tool.name.as_ref() == tool_name);
                    if self
                        .observe_tool_reviews(
                            &entry,
                            server,
                            &current_manifest,
                            current_tool.map(std::slice::from_ref).unwrap_or_default(),
                        )
                        .await
                        .is_err()
                    {
                        permit.neutral();
                        return Err(contract_changed_error(server, tool_name));
                    }
                    if !self
                        .review_allows(
                            server,
                            tool_name,
                            current_tool,
                            current_manifest.classification_mode,
                        )
                        .await
                    {
                        permit.neutral();
                        return Err(contract_changed_error(server, tool_name));
                    }
                    if !admission::tool_is_admitted_in_catalog(
                        &current_manifest,
                        &session_tools,
                        tool_name,
                    ) {
                        // The executing session advertises a contract the
                        // operator never approved — upstream behavior drift,
                        // counted against the breaker (persistent drift trips
                        // it and the re-probe redials + re-publishes, which
                        // quarantines the drifted tool).
                        permit.failure();
                        entry.record_runtime_failure(UpstreamErrorClass::Protocol);
                        waygate_telemetry::metrics::record_tool_drift(server);
                        tracing::warn!(
                            %server,
                            %tool_name,
                            "reuse session advertises a contract that does not match \
                             the approved behavior hash; refusing dispatch",
                        );
                        return Err(McpError::internal_error(
                            format!(
                                "upstream `{server}` session advertises a different \
                                 contract for `{tool_name}` than the approved behavior"
                            ),
                            None,
                        ));
                    }
                }
                // Bound the upstream call with a hard timeout. Without it a
                // wedged stream (long-idle HTTP/2 that silently half-closed)
                // holds the checked-out slot and blocks every other call
                // routed to it. On timeout we drop the in-flight future
                // (releasing the slot) and fault the slot so repeated hangs
                // trip the breaker and the re-probe rebuilds it.
                // Contract in `dispatch::legacy_continuation_refusal`.
                // Breaker-neutral: a local generation mismatch, not an
                // upstream-health signal.
                if let Some(err) = dispatch::legacy_continuation_refusal(
                    server,
                    has_continuation,
                    conn.negotiated_protocol.as_deref(),
                ) {
                    permit.neutral();
                    return Err(err);
                }
                // Raw `call_tool_once` for the same reason as the per-call
                // arm: a pause must pass through, not be driven locally. A
                // reuse-lane dial advertises no capabilities, so a conforming
                // 2026 upstream never pauses here; the pipeline's
                // answerability check fails closed if one does anyway.
                let response = dispatch::call_tool_once_classified(
                    &conn.client,
                    params,
                    recovery::remaining(call_deadline),
                )
                .await;
                let reader = resources::SessionResourceReader {
                    server,
                    client: &conn.client,
                    timeout: recovery::remaining(call_deadline),
                    bounded_reads_supported: matches!(snapshot.transport, crate::Transport::Http),
                };
                (
                    dispatch::process_call_response(response, processor, &reader).await,
                    conn_guard,
                )
            }
        };
        dispatch::finish_call_response(
            self,
            server,
            &entry,
            dispatch::CallLaneGuard::new(checkout.slot, isolation, conn_guard),
            permit,
            inner_result,
            dispatch::CallAttemptContext {
                attempts,
                trace_id: &trace_id,
            },
        )
        .await
    }
}

mod admission;
mod catalog;
mod configuration;
mod contract_binding;
mod dispatch;
mod file_transfers;
mod freshness;
pub mod health;
mod lanes;
pub mod listen;
mod reconnect;
mod recovery;
mod refusal_record;
pub(crate) mod reload;
mod resources;
mod schema_admission;
mod session_identity;
mod tool_listing;
mod tool_reviews;

#[cfg(test)]
use admission::partition_live_tools;
use admission::publish_classified_tools;
use admission::{contract_changed_error, dispatch_contract_is_current};
use catalog::risk_to_tier as catalog_risk_to_tier;
pub use contract_binding::{list_all_tools, ListedCatalog};
pub use freshness::{CatalogFreshnessTrigger, ScheduledCatalogRefresh};
pub use health::{
    ObservedContracts, ObservedToolContract, UpstreamErrorClass, UpstreamHealth, UpstreamStatus,
};
use reload::redial_committed_fields_eq;
pub use reload::{CatalogRefreshOutcome, CatalogRefreshReport, ReloadReport};
use resources::{ResourceRequest, ResourceResponse};
use session_identity::{
    install_catalog_probe_identity, refuse_identityless_tiers, CellClearGuard,
    SerializerDepthGuard, UpstreamSessionBundle,
};

#[cfg(test)]
mod tests;
