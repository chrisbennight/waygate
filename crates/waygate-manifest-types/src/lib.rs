//! Upstream-manifest types, parsers, and load-time validation.
//!
//! The manifest *domain* types live in this crate, separate from
//! `waygate-upstream`, so that consumers which only need the types — the
//! bundle store, admin editors, importers — no longer link the whole
//! connection pool. `waygate-upstream` depends on this crate and re-exports
//! every item at its old paths, so existing `waygate_upstream::…` imports
//! keep resolving; the canonical home is here.
//!
//! Each upstream is declared by a YAML manifest (`servers/*.yaml` on disk,
//! or the one-document set form stored in a `server_manifests` bundle).
//! [`validate_manifest_invariants`] is the single source of truth every
//! load path funnels through; [`Transport`]'s capability predicates are
//! what the dashboard identity form and the validator both consume.
//! Foundation-tier crate per `docs/architecture.md` §1: depends on
//! `waygate-core` only (reserved-namespace constants, `RiskTier`).

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use waygate_core::RiskTier;

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("no upstream named {0}")]
    UnknownUpstream(String),
    /// A manifest combines mutually exclusive identity fields (e.g.
    /// `tier_c_peer:` + `exchange:`) or another invariant
    /// [`validate_manifest_invariants`] enforces. Surfaced at
    /// `load_manifests` time so an operator's typo doesn't reach the
    /// dispatch path.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    /// A manifest *set* (the YAML sequence stored in a
    /// `server_manifests` bundle) named the same upstream twice.
    /// Per-file `load_manifests` can't hit this — each file is one
    /// manifest keyed into a `BTreeMap` by name, so a dup silently
    /// overwrites. The whole-set form CAN, so `parse_manifest_set`
    /// rejects it: two entries for one name make the active set
    /// ambiguous (which `url`/`tools` win?).
    #[error("duplicate upstream name in manifest set: {0}")]
    DuplicateName(String),
    /// A conditional manifest-directory write found a different live set at
    /// the filesystem commit boundary. The concurrent live edit is preserved.
    #[error("the live manifest set changed during the filesystem commit")]
    StaleBase,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Http,
    Sse,
    Stdio,
}

/// Which MCP client lifecycle the gateway runs when dialing this upstream.
///
/// `auto` (the default) probes with `server/discover` and falls back to the
/// legacy `initialize` handshake only when the upstream proves it is legacy
/// (`METHOD_NOT_FOUND`); any other discovery error fails the dial rather
/// than silently downgrading. `legacy` skips discovery entirely — the
/// operator escape hatch for an upstream whose non-conforming discovery
/// response would otherwise fail the dial. `2026-07-28` requires the new
/// lifecycle and never falls back. SSE-transport upstreams are legacy by
/// definition: `auto` resolves to the legacy handshake there, and an
/// explicit `2026-07-28` is rejected at manifest validation.
///
/// Every dial runs the configured mode — the negotiated generation is
/// per-connection state observed fresh at each dial, never cached across
/// dials.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum UpstreamProtocol {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "legacy")]
    Legacy,
    #[serde(rename = "2026-07-28")]
    V20260728,
}

impl UpstreamProtocol {
    /// Serialized manifest spelling, for error messages and admin views.
    pub const fn as_str(self) -> &'static str {
        match self {
            UpstreamProtocol::Auto => "auto",
            UpstreamProtocol::Legacy => "legacy",
            UpstreamProtocol::V20260728 => "2026-07-28",
        }
    }

    /// `true` for the default, so serialization can omit it.
    pub const fn is_auto(&self) -> bool {
        matches!(self, UpstreamProtocol::Auto)
    }
}

impl Transport {
    /// Does this transport carry a static per-upstream bearer
    /// (`auth.bearer_env`)? HTTP and SSE both send `Authorization: Bearer` on
    /// the wire (HTTP via the streamable transport; SSE on the GET + every
    /// message POST). stdio speaks over a child process and has no HTTP request
    /// to carry it. **Single source of truth**: `validate_manifest_invariants`
    /// and the dashboard identity form both consume this, so the per-transport
    /// rule can't drift between enforcement and UI.
    pub fn supports_static_bearer(&self) -> bool {
        matches!(self, Transport::Http | Transport::Sse)
    }

    /// Does this transport support mutual TLS (`mtls`)? HTTP only — the SSE
    /// client dials through a bare `reqwest` client with no per-upstream cert
    /// wiring, and stdio has no TLS handshake.
    pub fn supports_mtls(&self) -> bool {
        matches!(self, Transport::Http)
    }

    /// Does this transport forward per-caller identity (Tier-A `exchange`,
    /// Tier-C `tier_c_peer`, Tier-B `X-MCP-Identity`)? The network transports
    /// HTTP and SSE; stdio forwards no network identity.
    pub fn supports_identity_forwarding(&self) -> bool {
        matches!(self, Transport::Http | Transport::Sse)
    }
}

/// Authority for behavior and sensitivity claims on an upstream's tools.
///
/// Risk and role requirements remain gateway-owned catalog policy. This
/// setting chooses only where the gateway reads the tool's behavior and
/// data-handling claims; [`ApprovalMode`] separately selects whether an
/// upstream review claim participates in approval enforcement.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationMode {
    /// Read the legacy `side_effects` and `pii` compatibility fields from each
    /// manifest tool entry.
    #[default]
    Manifest,
    /// Read behavior from standard MCP annotations and the experimental
    /// action-metadata namespace. The manifest/catalog tool entry still owns
    /// risk and admission. Missing or malformed claims quarantine the tool.
    McpAnnotations,
}

impl ClassificationMode {
    fn is_manifest(&self) -> bool {
        matches!(self, Self::Manifest)
    }
}

/// Which authority can require a live per-call approval grant for an
/// upstream's tools.
///
/// The default honors both annotation-native `requiresReview` claims and the
/// governed catalog flag. Deployments whose Cedar policy fully governs an
/// upstream's side-effecting surface may explicitly opt out of those two
/// ordinary approval sources while retaining any approval overlay expressed
/// by Cedar itself.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Honor annotation and catalog per-call approval requirements.
    #[default]
    PerCall,
    /// Ignore annotation and catalog approval requirements; Cedar remains
    /// authoritative and may still require an approval grant through policy.
    PolicyOnly,
}

impl ApprovalMode {
    fn is_per_call(&self) -> bool {
        matches!(self, Self::PerCall)
    }

    /// Whether upstream claims and catalog flags participate in the ordinary
    /// per-call approval requirement.
    pub const fn uses_per_call_requirements(self) -> bool {
        matches!(self, Self::PerCall)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpstreamManifest {
    pub name: String,
    pub transport: Transport,
    /// MCP client lifecycle for dialing this upstream. Defaults to
    /// [`UpstreamProtocol::Auto`]; see the enum for the exact semantics
    /// and the SSE clamp. A change re-dials: this is a connection-shape
    /// field in the reload predicate.
    #[serde(default, skip_serializing_if = "UpstreamProtocol::is_auto")]
    pub protocol: UpstreamProtocol,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub tools: Vec<ToolClassification>,
    /// URI-prefix claims owned by this upstream. These declarations are both
    /// the routing table for dynamic `resources/read` requests and the source
    /// of the resource risk presented to Cedar. An empty list preserves the
    /// legacy discovery-by-enumeration path for existing resource servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceClassification>,
    /// Select whether behavior and sensitivity are supplied by legacy
    /// manifest fields or by the upstream's MCP annotations. Defaults to
    /// [`ClassificationMode::Manifest`] for compatibility.
    #[serde(default, skip_serializing_if = "ClassificationMode::is_manifest")]
    pub classification_mode: ClassificationMode,
    /// Select which authority supplies ordinary per-call approval
    /// requirements. Defaults to [`ApprovalMode::PerCall`], which honors
    /// annotation-native `requiresReview` claims and governed catalog flags.
    /// [`ApprovalMode::PolicyOnly`] is an explicit deployment opt-in for an
    /// upstream whose entire authorization contract is enforced in Cedar.
    #[serde(default, skip_serializing_if = "ApprovalMode::is_per_call")]
    pub approval_mode: ApprovalMode,
    /// Opt-in RFC 8693 token exchange. When set, the gateway swaps the
    /// caller's access token for a downscoped one audienced at this upstream
    /// (Tier A identity chaining). Absence = Tier B (gateway-minted identity
    /// JWT in `X-MCP-Identity`).
    #[serde(default)]
    pub exchange: Option<ExchangeConfig>,
    /// Opt-in fail-closed Tier-A invariant. When
    /// `true`, the per-call path refuses to dispatch unless a
    /// durable upstream session (or its successful
    /// refresh-on-demand result) yields a `stored_upstream_subject_token`.
    /// Manifests that set this MUST also set `exchange:` — without it
    /// the Tier-A path is never consulted, and the fail-closed
    /// check would block every call. Falling back to
    /// `principal.raw_token` is the *opt-out* posture; setting
    /// `tier_a_required: true` says "this upstream rejects gateway-
    /// issued bearers, only the user's IdP-minted access token is
    /// acceptable upstream." Absence/`false` keeps the existing
    /// graceful-fallback behaviour.
    #[serde(default)]
    pub tier_a_required: bool,
    /// Static, per-upstream auth applied at dial time. Supported on HTTP and
    /// SSE — sent as `Authorization: Bearer` (on the streamable-HTTP request,
    /// or on the SSE GET + every message POST); stdio rejects this field at
    /// dial time (no HTTP request to carry it). The secret is resolved from
    /// process env so it never lives in the YAML or git. Used for upstreams
    /// reached over the public internet, where the underlying MCP server has
    /// no docker-network isolation to fall back on.
    #[serde(default)]
    pub auth: Option<UpstreamAuth>,
    /// Opt-in mutual TLS. When set, the
    /// gateway presents the configured client certificate
    /// when dialing this upstream. HTTP-only — SSE and stdio
    /// reject this field loud at dial time. Compatible with
    /// `auth.bearer_env`: an upstream may require BOTH a
    /// bearer header AND a client cert (the cert authenticates
    /// the gateway as a trusted infrastructure peer; the
    /// bearer carries the per-user identity). Cert + key are
    /// read from disk at dial time; rotating without a
    /// gateway restart needs the upstream connection to be
    /// reconnected (a file-watcher reload lands in a
    /// follow-up).
    #[serde(default)]
    pub mtls: Option<MtlsConfig>,
    /// Opt into Tier-C peer assertion
    /// for this upstream. When `Some(peer_id)`, the gateway-
    /// minted identity JWT carries `aud = <peer's issuer URL>`
    /// instead of the default local server name, so the
    /// remote MCP gateway's bearer chain (running its own
    /// `PeerJwtValidator`) can verify it as a peer assertion
    /// from THIS gateway. The peer record is looked up at
    /// per-call IdentityContext build time via the in-memory
    /// `PeerJwksCache` — fail-closed: if the peer isn't in
    /// the cache (peer record was deleted, JWKS fetch is
    /// failing, refresh hasn't completed yet), the call is
    /// refused with a structured error rather than silently
    /// downgrading to a Tier-B aud that the remote can't
    /// match. Mutually exclusive with `exchange:` (Tier-A) and
    /// with `auth.bearer_env:` — all three write
    /// `Authorization: Bearer`, so `validate_manifest_invariants`
    /// refuses any pair (the operator picks one Authorization
    /// writer).
    #[serde(default)]
    pub tier_c_peer: Option<Uuid>,
    /// Per-upstream session / connection-pool policy. Absent ⇒ the
    /// gateway-wide defaults apply: pool size from
    /// `GATEWAY_UPSTREAM_POOL_SIZE`, one in-flight request per session.
    /// See [`SessionConfig`]. Connection-shape (read once at dial time,
    /// like `transport`/`url`), applied live on Reload: a change that keeps
    /// the slot count is re-dialed in place, and a `concurrency` change that
    /// resizes the pool is rebuilt live (a fresh entry with the new slot count
    /// is dialed and swapped in) — restart-required only if every new-shape
    /// dial fails.
    #[serde(default)]
    pub session: Option<SessionConfig>,
}

/// One upstream-owned resource URI space and its gateway classification.
///
/// Prefixes are literal, verbatim URI prefixes rather than wildcard patterns.
/// The manifest-set validator refuses overlapping prefixes, so a read can be
/// routed without probing the fleet and without choosing between owners.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema, schemars::JsonSchema,
)]
pub struct ResourceClassification {
    pub uri_prefix: String,
    #[schemars(with = "String")]
    pub risk: RiskTier,
}

/// Per-upstream session / connection-pool policy.
///
/// The gateway dials a pool of independent upstream sessions per server
/// and serves at most one in-flight request per session (see
/// `waygate_upstream::pool`).
/// This block tunes that pool per upstream; every field is optional and
/// falls back to the gateway-wide default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SessionConfig {
    /// Number of independent upstream sessions dialed for this server —
    /// the per-upstream override of the global
    /// `GATEWAY_UPSTREAM_POOL_SIZE`. Higher ⇒ more calls run in parallel
    /// (each on its own session); lower throttles concurrent load on a
    /// weak upstream. `None` inherits the global default. Clamped to
    /// ≥ 1, and ignored for `stdio` (always one child process). Read at
    /// dial time; a change resizes the pool and is rebuilt live on Reload
    /// (restart-required only if every new-shape dial fails).
    #[serde(default)]
    pub concurrency: Option<usize>,
    /// How upstream sessions are reused across calls. `None` selects the
    /// safe default: [`SessionIsolation::PerCall`] for HTTP/SSE (a fresh
    /// session per call — so no cross-call or cross-principal state can
    /// leak), and [`SessionIsolation::Reuse`] for stdio (a child process
    /// is a single long-lived session). Set `reuse` on an HTTP/SSE
    /// upstream you trust to drain per-session state between calls, to
    /// save the per-call initialize round-trip. See [`SessionIsolation`].
    #[serde(default)]
    pub isolation: Option<SessionIsolation>,
    /// Whether a reused session may be shared across *different callers*.
    /// Whether a reused session may be shared across *different callers*.
    /// Required (as `shared`) to set `isolation: reuse` on an HTTP/SSE
    /// upstream: the pooled session is shared across callers and the gateway
    /// may forward per-caller identity to network upstreams, so reuse there
    /// needs a conscious acknowledgement. Inert for the default `per_call`
    /// and for stdio. `None` ⇒ [`SessionScope::PerPrincipal`] (the safe
    /// default). See [`SessionScope`] and `validate_manifest_invariants`.
    #[serde(default)]
    pub scope: Option<SessionScope>,
    /// Whether the gateway may automatically repeat one replay-safe HTTP
    /// setup attempt after a proven pre-dispatch failure. `None`/`true`
    /// preserves the bounded default; `false` suppresses automatic recovery
    /// for an upstream whose latency, load, or provider policy requires a
    /// single attempt. This never permits mutation replay or more than two
    /// total attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_on_setup_failure: Option<bool>,
}

impl SessionConfig {
    /// Whether this upstream permits the gateway's one safe setup recovery.
    pub fn retries_safe_setup_failures(&self) -> bool {
        self.retry_on_setup_failure.unwrap_or(true)
    }
}

/// How a per-upstream connection pool reuses sessions across calls.
///
/// MCP does not guarantee that a server isolates state between sequential
/// requests on one session — that is an unspecified implementation
/// detail. Reuse is therefore a trust decision: the gateway defaults
/// HTTP/SSE upstreams to [`PerCall`](Self::PerCall) (safe by
/// construction) and only reuses a session when the operator opts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionIsolation {
    /// Dial a fresh upstream session for every call (initialize → call →
    /// close). Maximum isolation: no state from a prior call — or a
    /// different caller — can survive on the session. Costs one
    /// initialize round-trip per call. The default for HTTP/SSE.
    PerCall,
    /// Reuse a pooled session across calls (still one in-flight request
    /// per session). Avoids the per-call initialize, at the cost of
    /// trusting the upstream to fully reset per-session state between
    /// requests. The default — and only mode — for stdio.
    Reuse,
}

/// Whether a *reused* upstream session may be shared across different
/// callers of an HTTP/SSE upstream.
///
/// The gateway's slot pool is shared across all callers, so `isolation:
/// reuse` on a network upstream runs one caller's call on a session a
/// *different* caller previously used. When the gateway forwards per-caller
/// identity to that upstream — Tier-B `X-MCP-Identity` for any issuer-wired
/// HTTP/SSE upstream, plus a downscoped bearer under `exchange` /
/// `tier_c_peer` — that leaks identity across callers if the upstream binds
/// anything to the session (unspecified by MCP). This is the cross-caller
/// hazard the `per_call` default avoids. Whether identity forwarding is
/// wired is a runtime property the manifest can't see, so `scope` is a
/// conservative validation gate at manifest-load time, NOT a dispatch knob:
/// the gateway does not implement per-principal session *pooling*, because
/// the `per_call` default already provides per-caller isolation with
/// negligible perf difference for the low-QPS upstreams that forward
/// identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionScope {
    /// Do not share a reused session across callers (the safe default).
    /// Combined with `isolation: reuse` on an HTTP/SSE upstream this is
    /// refused at load time: use the default `isolation: per_call` (which
    /// gives per-caller isolation), or consciously opt into `scope: shared`.
    PerPrincipal,
    /// Explicitly allow a reused session to be shared across all callers of
    /// this upstream. The conscious acknowledgement required to run
    /// `isolation: reuse` on an HTTP/SSE upstream — only safe when you know
    /// the upstream treats any forwarded identity as strictly per-request
    /// and binds no per-caller state to the session.
    Shared,
}

/// Per-upstream RFC 8693 token exchange settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExchangeConfig {
    /// Value passed as `audience` on the exchange request. Typically the
    /// canonical URI the upstream registered with the IdP.
    pub audience: String,
    /// Optional scope string to include on the exchange. Omit to let the IdP
    /// default-downscope.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Application-layer authentication attached to one network upstream.
///
/// `mtls` lives on `UpstreamManifest` directly (not here) — it's
/// orthogonal to the application-layer bearer (an upstream may demand
/// both: mTLS as the transport-layer "this is a trusted infrastructure
/// peer" check, plus a bearer for per-user identity), so a single
/// struct conflating them would invite "only one at a time" thinking.
/// Future application-layer auth methods (basic, signed-JWT) land here
/// as additional optional fields with an exactly-one-of check at dial
/// time, rather than as enum variants — serde-yaml requires YAML tags
/// for externally-tagged enums in this shape, which is awkward in
/// hand-edited manifests.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpstreamAuth {
    /// Name of the process env var holding a bearer token. Sent as
    /// `Authorization: Bearer <value>` on every upstream request. When that
    /// variable is unset or empty, the transport reads the bounded token file
    /// named by the conventional `<NAME>_FILE` companion variable instead.
    /// Missing or empty sources fail the dial loud — silent fallthrough would
    /// leak unauthenticated requests to a public endpoint, which is the failure
    /// mode this field exists to prevent.
    #[serde(default)]
    pub bearer_env: Option<String>,
    /// Optional groups carried only by the gateway's short-lived catalog-probe
    /// identity while it initializes the upstream and reads `tools/list`.
    /// The identity cell is cleared before the connection can serve a caller,
    /// so these groups can reveal a role-filtered catalog without granting the
    /// synthetic probe authority on later tool calls. Empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub catalog_probe_groups: Vec<String>,
}

/// Per-upstream mutual TLS configuration.
///
/// All paths are resolved at DIAL time, not at manifest load
/// or at `--import-manifests`. The importer (`to_import_server`)
/// only stores the paths in the catalog's `runtime_target`
/// JSONB; it never reads them, and never surfaces a bad-cert
/// error. Reading at dial keeps the load
/// path filesystem-free — the same manifest can be validated
/// in CI / test without requiring the cert files to exist, and
/// `--import-manifests` succeeds even when the cert files
/// haven't been provisioned yet. A missing or invalid file
/// surfaces as a structured `DialError`
/// (`MtlsReadFailed` / `MtlsInvalidPem` / `MtlsClientBuild`)
/// at the moment the gateway actually tries to dial.
///
/// The cert + key MUST be PEM-encoded. Concatenated cert+key in
/// a single file is supported (call `cert_path` and `key_path`
/// the same path) because `reqwest::Identity::from_pem` accepts
/// either a single PEM blob with both or a cert-only blob with
/// the key inlined. Today the contract is explicit: separate
/// files. Operators with single-file PEMs can point both fields
/// at the same path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MtlsConfig {
    /// Path to the PEM-encoded client certificate (and chain).
    /// Required.
    #[serde(default)]
    pub cert_path: Option<std::path::PathBuf>,
    /// Path to the PEM-encoded private key matching `cert_path`.
    /// Required.
    #[serde(default)]
    pub key_path: Option<std::path::PathBuf>,
    /// Optional CA bundle to ADD to the gateway's trust store
    /// when verifying the upstream's server certificate. Each
    /// CA in the bundle becomes an additional root that the
    /// platform's default trust store accepts; existing
    /// platform roots remain in effect. Use this to introduce
    /// a private CA that issues the upstream's cert without
    /// disabling default trust. Omit when the upstream's cert
    /// chains to a publicly-trusted root.
    ///
    /// Strict pin-only mode (reject anything not chaining to
    /// the configured CA) is a stricter posture we can add
    /// later behind a `tls_verify: strict` flag; today `ca_path`
    /// only ADDS a trusted root — it does not restrict trust to
    /// ONLY this CA.
    #[serde(default)]
    pub ca_path: Option<std::path::PathBuf>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema, schemars::JsonSchema,
)]
pub struct ToolClassification {
    pub name: String,
    /// Reviewed live behavior hash required by annotation-native mode. This is
    /// an approval witness, not an upstream-provided risk classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_behavior_hash: Option<String>,
    #[schemars(with = "String")]
    pub risk: RiskTier,
    #[serde(default)]
    pub side_effects: bool,
    #[serde(default)]
    pub pii: bool,
    /// Argument field whose value selects which operation a call performs.
    ///
    /// A tool carrying many operations behind one name cannot be classified by
    /// name alone: the gateway sees the same tool whether the caller asked for
    /// the harmless operation or the dangerous one. Naming the field here lets
    /// `operations` refine the classification per value.
    ///
    /// `None` keeps the tool classified by name alone, which is every tool
    /// that does not opt in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<String>,
    /// Per-operation classifications, keyed by discriminator value.
    ///
    /// A value with no entry here is classified by the tool's own entry, so an
    /// unrecognized operation is never weaker than the tool it arrived
    /// through. A named value carries the classification an operator reviewed
    /// for it, which may be narrower than the tool's — that is the point: an
    /// executor whose tool-level entry has to cover its most sensitive
    /// operation can admit the harmless ones individually.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<OperationClassification>,
}

impl ToolClassification {
    /// A tool classified by name alone: no operation refinements and no
    /// approval witness.
    ///
    /// This is the shape of every classification whose operator has not opted
    /// into per-operation review, so it is what a caller building one almost
    /// always wants. Use struct-update syntax against it to set the fields it
    /// leaves empty.
    #[must_use]
    pub fn new(name: impl Into<String>, risk: RiskTier, side_effects: bool, pii: bool) -> Self {
        Self {
            name: name.into(),
            approved_behavior_hash: None,
            risk,
            side_effects,
            pii,
            discriminator: None,
            operations: Vec::new(),
        }
    }
}

/// Classification for one discriminator value of a tool.
///
/// Replaces the owning [`ToolClassification`]'s risk and flags for calls whose
/// discriminator argument carries [`value`](Self::value). Operator-reviewed
/// state, like the tool-level entry it refines.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema, schemars::JsonSchema,
)]
pub struct OperationClassification {
    /// Exact discriminator value this entry classifies.
    pub value: String,
    #[schemars(with = "String")]
    pub risk: RiskTier,
    #[serde(default)]
    pub side_effects: bool,
    #[serde(default)]
    pub pii: bool,
}

/// Load all `*.yaml` upstream manifests from a directory.
pub fn load_manifests(
    dir: &std::path::Path,
) -> Result<BTreeMap<String, UpstreamManifest>, UpstreamError> {
    let mut out = BTreeMap::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let m: UpstreamManifest = serde_yaml::from_slice(&bytes)?;
        validate_manifest_invariants(&m)?;
        out.insert(m.name.clone(), m);
    }
    validate_resource_claim_set(&out)?;
    Ok(out)
}

fn valid_uri_prefix(prefix: &str) -> bool {
    let Some((scheme, _rest)) = prefix.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !prefix.chars().any(char::is_control)
        && prefix.trim() == prefix
}

/// Validate the literal routing table as a set. Prefix overlap is rejected
/// even when the two declarations carry the same risk: otherwise ownership
/// would depend on longest-prefix conventions that the manifest never states.
fn validate_resource_claim_set(
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> Result<(), UpstreamError> {
    let claims: Vec<(&str, &ResourceClassification)> = manifests
        .values()
        .flat_map(|manifest| {
            manifest
                .resources
                .iter()
                .map(move |claim| (manifest.name.as_str(), claim))
        })
        .collect();
    for (index, (left_server, left)) in claims.iter().enumerate() {
        for (right_server, right) in &claims[index + 1..] {
            if left.uri_prefix.starts_with(&right.uri_prefix)
                || right.uri_prefix.starts_with(&left.uri_prefix)
            {
                return Err(UpstreamError::InvalidManifest(format!(
                    "resource URI claims overlap: upstream `{left_server}` prefix `{}` and \
                     upstream `{right_server}` prefix `{}`; every URI must have exactly one \
                     declared owner",
                    left.uri_prefix, right.uri_prefix,
                )));
            }
        }
    }
    Ok(())
}

/// Map an upstream `name` to its canonical manifest filename
/// (`<name>.yaml`), refusing any name that isn't a single safe path
/// component. Centralised so the write path (and any future reader that
/// cares about the on-disk filename) agree on the convention, and so a
/// crafted name like `../../etc/cron.d/x` is rejected *before* any
/// filesystem write rather than escaping the manifest dir.
fn manifest_filename(name: &str) -> Result<String, UpstreamError> {
    let unsafe_name = name.is_empty()
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0');
    if unsafe_name {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream name `{name}` is not a safe filename (must be non-empty, must \
             not start with `.`, and must contain no `/`, `\\`, or NUL) — refusing \
             to write it to the manifest dir",
        )));
    }
    Ok(format!("{name}.yaml"))
}

/// Write a whole upstream-manifest *set* to `dir` as the canonical
/// one-file-per-upstream form [`load_manifests`] reads back: each manifest
/// is serialized to `<name>.yaml`, and every other `*.yaml` already in
/// `dir` is removed so the directory exactly mirrors `set`.
///
/// File-as-truth write path (see
/// `docs/server-config-source-of-truth.md`): the admin surfaces call this
/// to make the on-disk `servers_dir` — the boot/SIGHUP source of truth —
/// reflect an edit. The directory is gateway-owned once dashboard editing
/// is on: a removed upstream's file is deleted (not left to be re-loaded),
/// and a hand-named `example-messages-prod.yaml` is replaced by the canonical
/// `example-messages.yaml`, which also removes the duplicate-name ambiguity
/// `load_manifests`'s last-writer-wins insert would otherwise hide.
///
/// Each file write is atomic — a temp file in the same dir, fsync'd, then
/// `rename`d over the target — so a concurrent reader (another replica on
/// a shared volume, or this process re-reading on reload) never sees a
/// torn file: the `rename` is the only externally-visible step, and a
/// cross-filesystem rename can't happen because the temp file is a sibling
/// of the target. The caller is responsible for serializing concurrent
/// *writers* (an in-process lock or a DB turnstile); this function does
/// not lock.
///
/// NFS-awareness invariants (ADR §6 — the
/// live dir is a shared NFS volume in the target deploy). These are the rules
/// for this write path and the coordination layer around it; keep them if you
/// touch either:
/// - **temp + rename on the same mount** (above): the only atomic primitive
///   that holds for multiple NFS readers — never an in-place rewrite, and the
///   temp must be a sibling of the target so the rename can't cross a mount.
///   Enforced here today.
/// - **no `flock` / POSIX file lock**: NFS advisory locking is unreliable;
///   the cross-replica writer lock is the Postgres turnstile
///   (`ManifestStore::cas_pointer`), not the filesystem.
/// - **no `inotify` / file-watcher**: inotify does not observe writes from
///   another NFS client, so cross-replica change *propagation* must not use
///   it. The mechanism is the Postgres doorbell (`LISTEN/NOTIFY`, the fast
///   path) plus a hash-recheck poll backstop (`waygate-server`'s reload
///   task, `MANIFEST_POLL_SECS`, the slow path that catches a missed
///   notification or an out-of-band edit): every replica reloads on
///   doorbell notify or poll tick, in addition to SIGHUP or the dashboard
///   Reload button.
/// - **content-hash, never mtime**: NFS attribute caching makes mtime
///   unreliable, so any "did the shared dir change?" check must compare the
///   content hash — as the turnstile pointer and boot ledger-recovery already
///   do — not timestamps. (The poll backstop hash-rechecks on this basis;
///   `reload_manifests` itself diffs manifest fields, not the hash.)
///
/// Every name is validated up front (validate-before-irreversible): if any
/// is not a safe filename the whole write is refused before a single file
/// is touched, so a partial set is never written and a crafted name can't
/// escape `dir`.
pub fn write_manifest_set_to_dir(
    dir: &std::path::Path,
    set: &BTreeMap<String, UpstreamManifest>,
) -> Result<(), UpstreamError> {
    write_manifest_set_to_dir_inner(dir, set, None, || {}, || {})
}

/// Write `set` only when the live manifest directory still has
/// `expected_base_hash` at the filesystem commit boundary.
///
/// Replacement files are staged and synced before the final base check. The
/// previous set is then quarantined, the new files are installed without
/// replacing any concurrently-created path, and both sides are verified. An
/// out-of-band edit during that boundary is preserved and returns
/// [`UpstreamError::StaleBase`].
pub fn write_manifest_set_to_dir_from_base(
    dir: &std::path::Path,
    set: &BTreeMap<String, UpstreamManifest>,
    expected_base_hash: &str,
) -> Result<(), UpstreamError> {
    write_manifest_set_to_dir_inner(dir, set, Some(expected_base_hash), || {}, || {})
}

fn write_manifest_set_to_dir_inner(
    dir: &std::path::Path,
    set: &BTreeMap<String, UpstreamManifest>,
    expected_base_hash: Option<&str>,
    after_base_check: impl FnOnce(),
    after_quarantine: impl FnOnce(),
) -> Result<(), UpstreamError> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Per-process monotonic counter so each temp file gets a unique name.
    // Combined with `create_new` below, this makes the temp open refuse a
    // pre-existing path (including a planted symlink) and avoids colliding
    // with a stale temp from a crashed prior write.
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    std::fs::create_dir_all(dir)?;

    // Pass 1 — plan: validate every name and serialize every manifest, with
    // NO filesystem writes. An unsafe name or a serialize error aborts here,
    // before any temp exists, so a bad entry anywhere in the set can't leave
    // earlier temps behind (and a crafted name can't escape `dir`).
    let mut keep: std::collections::BTreeSet<std::ffi::OsString> =
        std::collections::BTreeSet::new();
    // (tmp_path, final_path, serialized_yaml)
    let mut planned: Vec<(std::path::PathBuf, std::path::PathBuf, String)> = Vec::new();
    for (name, manifest) in set {
        let fname = manifest_filename(name)?;
        keep.insert(std::ffi::OsString::from(&fname));
        let final_path = dir.join(&fname);
        let tmp_path = dir.join(format!(
            ".{fname}.{}.{}.tmp",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let yaml = serde_yaml::to_string(manifest)?;
        planned.push((tmp_path, final_path, yaml));
    }

    // Pass 2 — write ALL temp files before any rename, so a write failure
    // (disk-full) still aborts before the live dir is mutated. Each temp is
    // fsync'd so a later rename can't expose an empty/partial file after a
    // crash. On failure, clean up the temps written so far (the live dir
    // hasn't been touched yet).
    for (idx, (tmp, _final, yaml)) in planned.iter().enumerate() {
        let write_tmp = (|| -> std::io::Result<()> {
            // create_new (O_CREAT|O_EXCL) refuses to open an existing path,
            // so a planted `.<name>.yaml.*.tmp` symlink can't redirect this
            // write outside `dir`. If the name DOES already exist it's a
            // stale temp from a crashed prior write — e.g. a container
            // restart that reused this PID (commonly PID 1) and reset the
            // counter. Unlink it (remove_file drops the entry itself, NOT a
            // symlink's target, so this stays symlink-safe) and create
            // fresh; a symlink re-planted between the two calls just fails
            // the second create_new, so there's still no redirect.
            let open = |p: &std::path::Path| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(p)
            };
            let mut f = match open(tmp) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::fs::remove_file(tmp)?;
                    open(tmp)?
                }
                Err(e) => return Err(e),
            };
            f.write_all(yaml.as_bytes())?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_tmp {
            for (t, _, _) in &planned[..=idx] {
                let _ = std::fs::remove_file(t);
            }
            return Err(e.into());
        }
    }

    if let Some(expected) = expected_base_hash {
        let result = commit_manifest_set_from_base(
            dir,
            set,
            &planned,
            &keep,
            expected,
            after_base_check,
            after_quarantine,
        );
        for (tmp, _, _) in &planned {
            let _ = std::fs::remove_file(tmp);
        }
        if result.is_ok() {
            sync_dir_best_effort(dir);
        }
        return result;
    }

    // Pass 3 — rename each temp into place. Each rename is atomic and
    // same-filesystem (the temp is a sibling of the target), so a reader
    // never sees a torn file. On a mid-batch failure, clean up the
    // not-yet-renamed temps; already-renamed files stay — each is a
    // complete, valid manifest, so the dir is at worst a mix of new and
    // previous *versions*, never a corrupt file.
    for (i, (tmp, final_path, _)) in planned.iter().enumerate() {
        if let Err(e) = std::fs::rename(tmp, final_path) {
            for (t, _, _) in &planned[i..] {
                let _ = std::fs::remove_file(t);
            }
            return Err(e.into());
        }
    }

    // Pass 4 — reconcile: drop any *.yaml in `dir` that isn't part of
    // `set`, so a removed upstream stops being loaded and a stray
    // non-canonical filename can't shadow or duplicate a canonical one.
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let is_kept = path.file_name().is_some_and(|f| keep.contains(f));
        if !is_kept {
            std::fs::remove_file(&path)?;
        }
    }

    // Pass 5 — best-effort directory fsync. The temp files were `sync_all`'d
    // before being renamed, but a `rename` / `remove_file` only becomes
    // crash-durable once the DIRECTORY's own metadata is flushed. Best-effort
    // by design: the new content is already written and atomically in place,
    // so a dir-fsync failure (a filesystem that doesn't support fsync on a
    // directory fd) must NOT fail the write — it only weakens durability, not
    // correctness, and the atomicity guarantee above is unaffected.
    sync_dir_best_effort(dir);
    if manifest_write_in_progress(dir)? {
        if manifest_dir_hash(dir)? != manifest_set_hash(set)? {
            return Err(UpstreamError::StaleBase);
        }
        clear_manifest_commit_marker(dir, &dir.join(MANIFEST_WRITE_MARKER))?;
        remove_abandoned_manifest_archives(dir);
    }
    Ok(())
}

const MANIFEST_ARCHIVE_PREFIX: &str = ".manifest-write-archive.";
pub const MANIFEST_WRITE_MARKER: &str = ".manifest-write-in-progress";

/// Whether a conditional whole-set commit started its destructive phase but
/// has not yet made a complete replacement visible.
///
/// Readers use this marker to reject the live directory and fall back to the
/// last complete ledger snapshot. The marker is synced before any live YAML is
/// moved and removed only after either the replacement or the rollback is
/// verified.
pub fn manifest_write_in_progress(dir: &std::path::Path) -> Result<bool, UpstreamError> {
    match std::fs::symlink_metadata(dir.join(MANIFEST_WRITE_MARKER)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn commit_manifest_set_from_base(
    dir: &std::path::Path,
    set: &BTreeMap<String, UpstreamManifest>,
    planned: &[(std::path::PathBuf, std::path::PathBuf, String)],
    keep: &std::collections::BTreeSet<std::ffi::OsString>,
    expected_base_hash: &str,
    after_base_check: impl FnOnce(),
    after_quarantine: impl FnOnce(),
) -> Result<(), UpstreamError> {
    if manifest_dir_hash(dir)? != expected_base_hash {
        return Err(UpstreamError::StaleBase);
    }
    after_base_check();

    let archive_dir = dir.join(format!("{MANIFEST_ARCHIVE_PREFIX}{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&archive_dir)?;
    let marker = match begin_manifest_commit(dir) {
        Ok(marker) => marker,
        Err(error) => {
            let _ = std::fs::remove_dir(&archive_dir);
            return Err(error);
        }
    };
    let mut installed = std::collections::BTreeSet::new();

    let transaction = (|| -> Result<(), UpstreamError> {
        for entry in yaml_entries(dir)? {
            std::fs::rename(entry.path(), archive_dir.join(entry.file_name()))?;
        }
        after_quarantine();

        for (tmp, final_path, _) in planned {
            match std::fs::hard_link(tmp, final_path) {
                Ok(()) => {
                    installed.insert(
                        final_path
                            .file_name()
                            .expect("planned manifest has a filename")
                            .to_os_string(),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(UpstreamError::StaleBase);
                }
                Err(error) => return Err(error.into()),
            }
        }

        if manifest_dir_hash(&archive_dir)? != expected_base_hash
            || manifest_dir_hash(dir)? != manifest_set_hash(set)?
            || yaml_file_names(dir)? != *keep
        {
            return Err(UpstreamError::StaleBase);
        }
        Ok(())
    })();

    match transaction {
        Ok(()) => {
            clear_manifest_commit_marker(dir, &marker)?;
            // The archive is hidden from the loader and only retains the
            // replaced set. Cleanup is best-effort because the live commit is
            // already verified; failing the operation now would roll back the
            // database pointer away from the actual disk state.
            let _ = std::fs::remove_dir_all(&archive_dir);
            Ok(())
        }
        Err(error) => {
            rollback_conditional_manifest_write(dir, &archive_dir, planned, &installed)?;
            clear_manifest_commit_marker(dir, &marker)?;
            Err(error)
        }
    }
}

fn begin_manifest_commit(dir: &std::path::Path) -> Result<std::path::PathBuf, UpstreamError> {
    use std::io::Write as _;

    let marker = dir.join(MANIFEST_WRITE_MARKER);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)?;
    file.write_all(b"manifest write in progress\n")?;
    file.sync_all()?;
    sync_dir(dir)?;
    Ok(marker)
}

fn clear_manifest_commit_marker(
    dir: &std::path::Path,
    marker: &std::path::Path,
) -> Result<(), UpstreamError> {
    std::fs::remove_file(marker)?;
    sync_dir(dir)?;
    Ok(())
}

fn remove_abandoned_manifest_archives(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let is_internal_archive = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(MANIFEST_ARCHIVE_PREFIX));
        if is_internal_archive && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn sync_dir(dir: &std::path::Path) -> Result<(), UpstreamError> {
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn rollback_conditional_manifest_write(
    dir: &std::path::Path,
    archive_dir: &std::path::Path,
    planned: &[(std::path::PathBuf, std::path::PathBuf, String)],
    installed: &std::collections::BTreeSet<std::ffi::OsString>,
) -> Result<(), UpstreamError> {
    let mut preserve_deletions = std::collections::BTreeSet::new();
    for (tmp, final_path, yaml) in planned {
        let Some(name) = final_path.file_name() else {
            continue;
        };
        if !installed.contains(name) {
            continue;
        }
        if !final_path.exists() {
            preserve_deletions.insert(name.to_os_string());
            continue;
        }
        if same_file(tmp, final_path)? && std::fs::read(final_path)? == yaml.as_bytes() {
            std::fs::remove_file(final_path)?;
        }
    }

    if archive_dir.exists() {
        for entry in yaml_entries(archive_dir)? {
            let name = entry.file_name();
            if preserve_deletions.contains(&name) {
                continue;
            }
            let target = dir.join(&name);
            match std::fs::hard_link(entry.path(), &target) {
                Ok(()) => {
                    std::fs::remove_file(entry.path())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        if std::fs::read_dir(archive_dir)?.next().is_none() {
            std::fs::remove_dir(archive_dir)?;
        }
    }
    sync_dir_best_effort(dir);
    Ok(())
}

fn manifest_dir_hash(dir: &std::path::Path) -> Result<String, UpstreamError> {
    manifest_set_hash(&load_manifests(dir)?)
}

fn manifest_set_hash(set: &BTreeMap<String, UpstreamManifest>) -> Result<String, UpstreamError> {
    use sha2::{Digest, Sha256};

    let canonical = serialize_manifest_set(set)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(out)
}

fn yaml_entries(dir: &std::path::Path) -> std::io::Result<Vec<std::fs::DirEntry>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("yaml") {
            entries.push(entry);
        }
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    Ok(entries)
}

fn yaml_file_names(
    dir: &std::path::Path,
) -> Result<std::collections::BTreeSet<std::ffi::OsString>, UpstreamError> {
    Ok(yaml_entries(dir)?
        .into_iter()
        .map(|entry| entry.file_name())
        .collect())
}

#[cfg(unix)]
fn same_file(left: &std::path::Path, right: &std::path::Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let left = std::fs::metadata(left)?;
    let right = std::fs::metadata(right)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_file(left: &std::path::Path, right: &std::path::Path) -> std::io::Result<bool> {
    Ok(std::fs::canonicalize(left)? == std::fs::canonicalize(right)?)
}

fn sync_dir_best_effort(dir: &std::path::Path) {
    if let Ok(file) = std::fs::File::open(dir) {
        let _ = file.sync_all();
    }
}

/// `tier_c_peer:`
/// stamps the gateway-minted JWT onto `Authorization:
/// Bearer` so the remote gateway's `PeerJwtValidator` reads
/// it. Tier-A's `exchange:` ALSO stamps Authorization (with
/// the RFC 8693 downscoped bearer). The two paths can't both
/// claim the header; refusing the manifest at load time is
/// the right error stage (vs silently letting one win at
/// call time and leaving the operator's intent ambiguous).
/// Longest `discriminator` the catalog column accepts.
///
/// Matches the `tool_classifications.discriminator` CHECK, so a manifest that
/// loads is one the catalog can also hold.
const MAX_DISCRIMINATOR_LEN: usize = 128;

/// Longest operation value the catalog column accepts.
///
/// Matches the `tool_operation_classifications.operation` CHECK.
const MAX_OPERATION_VALUE_LEN: usize = 256;

/// True when a name carries a character an operation name may not contain.
///
/// An allowlist rather than a list of rejects. Enumerating the Unicode format
/// and bidirectional code points is a set that grows with every release, and
/// one missed entry means a name that renders as another name reaching the
/// catalog and the audit trail. Naming what is permitted cannot fall behind.
///
/// PostgreSQL `TEXT` cannot hold a NUL, so a manifest carrying one would pass
/// validation and then fail to persist. Everything else excluded here is
/// excluded because a name that is compared exactly and read by a person should
/// look like what it is.
///
/// This is the same set the invocation path admits when a caller selects an
/// operation, so an operator cannot classify a value no call could ever select.
fn has_inadmissible_char(s: &str) -> bool {
    !s.chars().all(|c| c.is_ascii_graphic())
}

/// Reject per-operation classifications that could not be resolved or stored.
///
/// The tool-level entry classifies any value this list does not name, so it is
/// what an unrecognized or unresolvable operation receives. That gives the one
/// substantive rule here: the tool entry must be at least as severe as every
/// operation it names, or an unnamed value would be treated more leniently
/// than one someone already assessed as dangerous.
///
/// Within that ceiling a named operation may be narrower, and that is the
/// point of naming it. An executor whose tool-level entry has to cover its most
/// sensitive operation can then admit the harmless ones individually.
///
/// The remaining checks are structural: entries nothing could select, values
/// storage could not hold, and duplicates.
///
/// Annotation-native mode needs no clause of its own. It already forces the
/// tool-level behavior and sensitivity flags clear, and the ceiling then
/// forbids an operation from declaring either, so an operation cannot become a
/// second behavior authority.
fn validate_operation_classifications(m: &UpstreamManifest) -> Result<(), UpstreamError> {
    for tool in &m.tools {
        if tool.discriminator.is_none() && !tool.operations.is_empty() {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}` tool `{}` classifies operations without naming a `discriminator`; \
                 nothing would select between them",
                m.name, tool.name,
            )));
        }
        if tool
            .discriminator
            .as_deref()
            .is_some_and(|d| !(1..=MAX_DISCRIMINATOR_LEN).contains(&d.chars().count()))
        {
            let discriminator = tool.discriminator.as_deref().unwrap_or_default();
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}` tool `{}` has a `discriminator` of {} characters; name the \
                 argument field selecting the operation in 1 to {MAX_DISCRIMINATOR_LEN}",
                m.name,
                tool.name,
                discriminator.chars().count(),
            )));
        }
        if tool
            .discriminator
            .as_deref()
            .is_some_and(has_inadmissible_char)
        {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}` tool `{}` has a `discriminator` outside the characters an \
                 operation name may use: printable ASCII, no spaces. The value is not repeated \
                 here because a name is refused precisely when it may not render as itself",
                m.name, tool.name,
            )));
        }

        let mut values = HashSet::new();
        for (index, operation) in tool.operations.iter().enumerate() {
            if !(1..=MAX_OPERATION_VALUE_LEN).contains(&operation.value.chars().count()) {
                return Err(UpstreamError::InvalidManifest(format!(
                    "upstream `{}` tool `{}` has an operation value of {} characters; a value \
                     must be 1 to {MAX_OPERATION_VALUE_LEN}",
                    m.name,
                    tool.name,
                    operation.value.chars().count(),
                )));
            }
            if has_inadmissible_char(&operation.value) {
                return Err(UpstreamError::InvalidManifest(format!(
                    "upstream `{}` tool `{}` operation at position {index} has a value outside \
                     the characters an operation name may use: printable ASCII, no spaces. The \
                     value is not repeated here because a name is refused precisely when it may \
                     not render as itself",
                    m.name, tool.name,
                )));
            }
            if !values.insert(operation.value.as_str()) {
                return Err(UpstreamError::InvalidManifest(format!(
                    "upstream `{}` tool `{}` repeats operation `{}`; each value must have exactly \
                     one classification",
                    m.name, tool.name, operation.value,
                )));
            }
            if !tool.risk.covers(operation.risk) {
                return Err(UpstreamError::InvalidManifest(format!(
                    "upstream `{}` tool `{}` operation `{}` is `{}` risk, above the tool's `{}`; \
                     the tool-level entry classifies every value it does not name, so it must be \
                     at least as severe as every value it does",
                    m.name,
                    tool.name,
                    operation.value,
                    operation.risk.as_str(),
                    tool.risk.as_str(),
                )));
            }
            if operation.side_effects && !tool.side_effects {
                return Err(UpstreamError::InvalidManifest(format!(
                    "upstream `{}` tool `{}` operation `{}` declares `side_effects` the tool does \
                     not; an unnamed value would then be treated more leniently than this one",
                    m.name, tool.name, operation.value,
                )));
            }
            if operation.pii && !tool.pii {
                return Err(UpstreamError::InvalidManifest(format!(
                    "upstream `{}` tool `{}` operation `{}` declares `pii` the tool does not; an \
                     unnamed value would then be treated more leniently than this one",
                    m.name, tool.name, operation.value,
                )));
            }
        }
    }
    Ok(())
}

pub fn validate_manifest_invariants(m: &UpstreamManifest) -> Result<(), UpstreamError> {
    // SSE predates the stateless protocol: the transport is legacy by
    // definition, `protocol: auto` resolves to the legacy handshake at
    // dial time, and an explicit `2026-07-28` is a contradiction the
    // operator must resolve rather than a value to silently downgrade.
    if matches!(m.transport, Transport::Sse) && m.protocol == UpstreamProtocol::V20260728 {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `protocol: 2026-07-28` is not possible over `transport: sse` — the \
             SSE transport exists only in the legacy protocol; use `transport: http` or drop the \
             `protocol:` override",
            m.name,
        )));
    }
    let mut tool_names = HashSet::new();
    if let Some(tool) = m
        .tools
        .iter()
        .find(|tool| !tool_names.insert(tool.name.as_str()))
    {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}` repeats tool classification `{}`; each tool must have exactly one \
             admission and policy entry",
            m.name, tool.name,
        )));
    }
    for resource in &m.resources {
        if !valid_uri_prefix(&resource.uri_prefix) {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}` resource prefix must be a non-empty absolute URI prefix with a \
                 valid scheme and no surrounding whitespace or control characters",
                m.name,
            )));
        }
        if resource
            .uri_prefix
            .split_once(':')
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("mcp-file"))
        {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}` resource prefix `{}` collides with the file-transfer URI \
                 namespace; file handles are resolved through files/authorizeDownload, not \
                 resources/read",
                m.name, resource.uri_prefix,
            )));
        }
    }
    let singleton = BTreeMap::from([(m.name.clone(), m.clone())]);
    validate_resource_claim_set(&singleton)?;
    validate_operation_classifications(m)?;
    if matches!(m.classification_mode, ClassificationMode::McpAnnotations) {
        if m.tools.iter().any(|tool| tool.side_effects || tool.pii) {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}`: `classification_mode: mcp_annotations` makes MCP annotations the \
                 sole behavior and sensitivity claim source; omit legacy `side_effects: true` and \
                 `pii: true` values to avoid conflicting authorities",
                m.name,
            )));
        }
        if let Some(tool) = m.tools.iter().find(|tool| {
            !tool
                .approved_behavior_hash
                .as_deref()
                .is_some_and(is_sha256_hex)
        }) {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}` tool `{}`: annotation mode requires an approved 64-character \
                 lowercase hexadecimal behavior hash",
                m.name, tool.name,
            )));
        }
    }
    // The built-in `gateway-admin.*` MCP namespace
    // (`waygate_mcp::BuiltinTools`) is dispatched BEFORE the `<server>.<tool>`
    // upstream split, so an upstream that collides with it would be silently
    // shadowed — every call diverted to the gateway's own change-request
    // tools. Refuse the name at load so the collision is a loud config error
    // rather than a silent black hole. Every load path (boot `load_manifests`,
    // bundle/SIGHUP `parse_manifest_set`, the `import` command's lenient
    // loader) funnels through this function, so the guard covers them all.
    //
    // The dispatcher intercepts ANY tool name starting
    // with `<reserved>.`, not just the exact name. An upstream named `S`
    // advertises tools `S.<tool>`, so `S` collides iff `S == reserved` OR `S`
    // itself begins with `reserved.` (e.g. `gateway-admin.foo`, tools
    // `gateway-admin.foo.*`). Match that exactly — but NOT a mere literal
    // prefix like `gateway-adminX`, which the dispatcher does not intercept.
    // The complete set of reserved built-in namespaces is the single source
    // of truth in `waygate-core`; optional surfaces stay reserved even when
    // disabled so a later configuration change cannot shadow an upstream.
    if let Some(reserved) = waygate_core::RESERVED_BUILTIN_NAMESPACES
        .iter()
        .copied()
        .find(|reserved| {
            m.name == *reserved
                || m.name
                    .strip_prefix(*reserved)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream name `{}` is reserved for (or collides with) the built-in `{reserved}` \
             MCP namespace; rename the upstream",
            m.name,
        )));
    }
    // Downstream MCP tool names are routed as `<server>.<tool>` by splitting
    // on the first dot. Tool names may themselves contain dots, so the server
    // component must not: permitting one would make two distinct source
    // identities render as the same public name, and one call could dispatch
    // to a different tool than the client selected. Keep the more specific
    // built-in collision error above for reserved dotted prefixes.
    if m.name.contains('.') {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream name `{}` contains `.`; server names cannot contain dots because MCP tool \
             calls use `<server>.<tool>` qualification",
            m.name,
        )));
    }
    // The inference plane's `llm` namespace is owned by the LLM model resolver
    // whenever the LLM path is active. An upstream named exactly `llm` would have
    // its tools rejected as unknown LLM models (a dead namespace) — reject it at
    // load instead. EXACT match only: the resolver intercepts `llm`, not `llm.*`.
    if m.name == waygate_core::LLM_RESERVED_NAMESPACE {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream name `{}` is reserved for the inference plane's LLM model \
             namespace; rename the upstream",
            m.name,
        )));
    }
    let catalog_probe_groups = m
        .auth
        .as_ref()
        .map(|auth| auth.catalog_probe_groups.as_slice())
        .unwrap_or_default();
    if !catalog_probe_groups.is_empty() && !m.transport.supports_identity_forwarding() {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `auth.catalog_probe_groups` requires an HTTP or SSE transport that \
             forwards the gateway identity; stdio has no identity header to carry these groups",
            m.name,
        )));
    }
    if catalog_probe_groups.len() > 32 {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `auth.catalog_probe_groups` accepts at most 32 groups",
            m.name,
        )));
    }
    let mut distinct_probe_groups = HashSet::with_capacity(catalog_probe_groups.len());
    for group in catalog_probe_groups {
        if group.is_empty()
            || group.len() > 128
            || group.trim() != group
            || group.chars().any(char::is_control)
        {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}`: every `auth.catalog_probe_groups` entry must be non-empty, at \
                 most 128 bytes, unpadded, and free of control characters",
                m.name,
            )));
        }
        if !distinct_probe_groups.insert(group) {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}`: `auth.catalog_probe_groups` contains duplicate group `{group}`",
                m.name,
            )));
        }
    }
    if m.tier_c_peer.is_some() && m.exchange.is_some() {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `tier_c_peer:` and `exchange:` are mutually exclusive — both \
             write Authorization: Bearer. Pick the gateway-to-gateway federation path \
             (tier_c_peer) OR the user-via-IdP path (exchange / Tier-A).",
            m.name,
        )));
    }
    // `auth.bearer_env` also
    // writes `Authorization: Bearer`. Same conflict shape as
    // `exchange:` — the operator must choose the static
    // per-upstream bearer OR the per-call peer-minted JWT.
    if m.tier_c_peer.is_some() && m.auth.as_ref().is_some_and(|a| a.bearer_env.is_some()) {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `tier_c_peer:` and `auth.bearer_env:` are mutually exclusive — both \
             write Authorization: Bearer. Pick the gateway-to-gateway federation path \
             (tier_c_peer) OR the static per-upstream bearer (auth.bearer_env).",
            m.name,
        )));
    }
    // `exchange:` (Tier-A) and `auth.bearer_env:` both
    // write `Authorization: Bearer`. On a per-call request with an exchange
    // context the exchanged (per-user) token wins, so the static bearer is
    // silently shadowed on every call. Same conflict shape as the two tier_c
    // guards above — refuse the combo rather than ship a manifest where the
    // static bearer is inert.
    if m.exchange.is_some() && m.auth.as_ref().is_some_and(|a| a.bearer_env.is_some()) {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `exchange:` and `auth.bearer_env:` are mutually exclusive — both write \
             Authorization: Bearer, and the exchanged per-user token shadows the static bearer on \
             every call. Pick Tier-A exchange OR the static per-upstream bearer.",
            m.name,
        )));
    }
    // Security guardrail. `session.isolation: reuse` runs calls on a
    // pooled session that is SHARED across all callers of this upstream. On
    // an HTTP/SSE upstream the gateway forwards per-caller identity — Tier-B
    // `X-MCP-Identity` for ANY issuer-wired upstream (`pool/mod.rs`'s
    // `forwards_identity`), plus a downscoped `Authorization` bearer under
    // `exchange` / `tier_c_peer` — so a reused session can carry one caller's
    // identity into a later caller's call if the upstream binds any
    // per-session state. Whether identity forwarding is actually wired is a
    // runtime property (`GATEWAY_IDENTITY_*`) the manifest can't see, so the
    // guard is conservative: refuse network-upstream reuse unless the
    // operator consciously acknowledges cross-caller sharing via
    // `scope: shared`. stdio is exempt (a child process is a single
    // long-lived session, not a shared HTTP session pool); a static
    // `auth.bearer_env` is irrelevant (same bearer for every caller, no
    // per-caller identity).
    let reuse = matches!(
        m.session.as_ref().and_then(|s| s.isolation),
        Some(SessionIsolation::Reuse)
    );
    if m.session
        .as_ref()
        .is_some_and(|session| session.retry_on_setup_failure.is_some())
        && !matches!(m.transport, Transport::Http)
    {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `session.retry_on_setup_failure` applies only to streamable HTTP \
             per-call recovery; omit it for SSE or stdio transports.",
            m.name,
        )));
    }
    if !catalog_probe_groups.is_empty() && reuse {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `auth.catalog_probe_groups` cannot be combined with \
             `session.isolation: reuse` because an upstream may retain the privileged catalog \
             identity in MCP session state. Use the default `session.isolation: per_call`.",
            m.name,
        )));
    }
    let shared = matches!(
        m.session.as_ref().and_then(|s| s.scope),
        Some(SessionScope::Shared)
    );
    let http_like = m.transport.supports_identity_forwarding();
    if http_like && reuse && !shared {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `session.isolation: reuse` reuses one upstream session across all \
             callers of this server, but an HTTP/SSE upstream may have per-caller identity \
             forwarded to it (X-MCP-Identity / a downscoped bearer) — so a reused session can \
             carry one caller's identity into another's call. Use the default \
             `session.isolation: per_call`, or set `session.scope: shared` to consciously \
             accept cross-caller session reuse.",
            m.name,
        )));
    }
    // `tier_a_required: true` is fail-closed: it refuses
    // every call that can't produce an exchanged subject token. But the Tier-A
    // path is only consulted when `exchange:` is set (`should_consult_tier_a_*`
    // in `pool`), so `tier_a_required` WITHOUT `exchange` refuses every call —
    // an unusable upstream. The field's doc states the dependency; enforce it
    // at load so a dashboard publish / SIGHUP can't ship the broken combo.
    if m.tier_a_required && m.exchange.is_none() {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `tier_a_required: true` requires `exchange:`. Without it the Tier-A \
             path is never consulted, so `tier_a_required` refuses every call. Set `exchange:` \
             (the audience this upstream accepts), or clear `tier_a_required`.",
            m.name,
        )));
    }
    // `mtls` is HTTP-only. The SSE client (`sse_client::connect`) dials through
    // a bare reqwest client with no per-upstream cert wiring, and stdio speaks
    // over a child process with no TLS. A manifest that sets `mtls:` on a
    // non-HTTP upstream validates but breaks at dial, so refuse it at load.
    if m.mtls.is_some() && !m.transport.supports_mtls() {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `mtls:` is HTTP-only — the SSE and stdio transports reject it at \
             dial. Use `transport: http`, or remove the `mtls:` block.",
            m.name,
        )));
    }
    // `auth.bearer_env` is supported on HTTP *and* SSE — both send
    // `Authorization: Bearer` on the wire (HTTP via the streamable transport;
    // SSE on the GET + every message POST, see `sse_client::connect`). Only
    // stdio rejects it: a child process over stdin/stdout has no HTTP request to
    // carry a bearer, so a configured one would be silently inert. Refuse that
    // combo at load. (Supersedes the earlier HTTP-only-for-auth rule now that
    // the SSE client actually honors the field instead of dropping it.)
    let has_static_auth = m.auth.as_ref().is_some_and(|a| a.bearer_env.is_some());
    if has_static_auth && !m.transport.supports_static_bearer() {
        return Err(UpstreamError::InvalidManifest(format!(
            "upstream `{}`: `auth.bearer_env:` is not supported for `transport: stdio` — a stdio \
             child process has no HTTP request to carry `Authorization: Bearer`. Use `transport: \
             http` or `sse`, or remove the `auth:` block.",
            m.name,
        )));
    }
    // The HTTP mTLS builder requires BOTH a client
    // cert and its key (`transport.rs` `MtlsMissingField`); a cert-only or
    // CA-only block validates but fails at dial. Require the pair at load.
    if let Some(mtls) = m.mtls.as_ref() {
        if mtls.cert_path.is_none() || mtls.key_path.is_none() {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}`: `mtls:` requires both `cert_path` and `key_path` (the CA bundle \
                 is optional). Provide both, or remove the `mtls:` block.",
                m.name,
            )));
        }
        // A client cert is only presented over TLS — the
        // transport refuses `mtls:` unless the upstream URL is `https://`. A
        // manifest pairing `mtls:` with an `http://` url validates but fails to
        // dial after the required restart, so reject it at load.
        let https = m.url.as_deref().is_some_and(|u| u.starts_with("https://"));
        if !https {
            return Err(UpstreamError::InvalidManifest(format!(
                "upstream `{}`: `mtls:` requires an `https://` url — the client certificate is \
                 only presented over TLS. Use an `https://` url, or remove the `mtls:` block.",
                m.name,
            )));
        }
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Serialize a whole manifest *set* to ONE YAML document (a sequence of
/// `UpstreamManifest`), the form stored in a `server_manifests` bundle's
/// `content`. The inverse of [`parse_manifest_set`].
///
/// Iteration is over a `BTreeMap`, so output ordering is by upstream
/// name and therefore **deterministic** — the same set always serializes
/// to the same bytes, which keeps `content_hash` stable and makes the
/// import round-trip self-check meaningful. The on-disk per-file layout
/// (`servers/*.yaml`, one manifest per file) is NOT reproduced; the
/// bundle is the set as a unit.
pub fn serialize_manifest_set(
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> Result<String, UpstreamError> {
    // Serialize the values as a sequence. `&UpstreamManifest` serializes
    // identically to the owned form, so no clone is needed.
    let seq: Vec<&UpstreamManifest> = manifests.values().collect();
    Ok(serde_yaml::to_string(&seq)?)
}

/// Parse a whole manifest *set* from the YAML-sequence form stored in a
/// bundle's `content`, validating each entry and rejecting duplicate
/// names. The inverse of [`serialize_manifest_set`]; the DB-overlay
/// counterpart to [`load_manifests`] (which reads one manifest per file
/// from a directory).
///
/// Same validation posture as `load_manifests`: every entry must pass
/// [`validate_manifest_invariants`], and the whole parse fails loud on
/// the first bad entry rather than silently dropping it — a bundle that
/// can't fully parse must NOT become the active set (boot/SIGHUP fall
/// back to the YAML dir instead). Duplicate names are rejected because,
/// unlike the per-file path where a `BTreeMap` insert silently
/// last-writer-wins, a set with two entries for one name is genuinely
/// ambiguous about which definition is active.
pub fn parse_manifest_set(
    content: &str,
) -> Result<BTreeMap<String, UpstreamManifest>, UpstreamError> {
    let seq: Vec<UpstreamManifest> = serde_yaml::from_str(content)?;
    let mut out = BTreeMap::new();
    for m in seq {
        validate_manifest_invariants(&m)?;
        if out.contains_key(&m.name) {
            return Err(UpstreamError::DuplicateName(m.name));
        }
        out.insert(m.name.clone(), m);
    }
    validate_resource_claim_set(&out)?;
    Ok(out)
}

/// Prod-profile manifest safety gate, shared by the gateway's boot/SIGHUP
/// activation path (`waygate-server`'s
/// `enforce_prod_manifest_safety_for_profile`) and the admin dashboard's
/// in-place "Reload manifests" action. In the `prod` deployment profile the
/// gateway refuses any upstream using `transport: stdio` — local subprocess
/// MCP needs a sandbox this proxy-only gateway does not provide. Returns the
/// operator-facing refusal message (naming the offending upstreams) on
/// violation; `Ok(())` when not prod or when no stdio upstream is present.
///
/// Centralised here — where [`UpstreamManifest`] and [`Transport`] live — so
/// the dashboard reload path applies exactly the same gate as boot/SIGHUP
/// without a `waygate-admin → waygate-server` dependency and without the
/// security check drifting between two copies. The dev-profile operator
/// nudge (a `tracing::warn!` flagging stdio for migration) stays in the
/// `waygate-server` wrapper: it is a boot/SIGHUP concern, not a per-reload
/// one.
pub fn enforce_no_prod_stdio(
    is_prod: bool,
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> Result<(), String> {
    if !is_prod {
        return Ok(());
    }
    let stdio_names: Vec<&str> = manifests
        .values()
        .filter(|m| matches!(m.transport, Transport::Stdio))
        .map(|m| m.name.as_str())
        .collect();
    if stdio_names.is_empty() {
        return Ok(());
    }
    Err(format!(
        "GATEWAY_DEPLOYMENT_PROFILE=prod refuses upstream manifests with \
         `transport: stdio` — local subprocess MCP requires sandboxing this \
         gateway does not provide (proxy-only deployment model). \
         Offending manifest(s): {}. Migrate to HTTP/SSE, or set \
         GATEWAY_DEPLOYMENT_PROFILE=dev for local.",
        stdio_names.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tool classification with per-operation refinements.
    fn tool_with_operations(
        risk: RiskTier,
        side_effects: bool,
        pii: bool,
        operations: Vec<OperationClassification>,
    ) -> ToolClassification {
        ToolClassification {
            approved_behavior_hash: None,
            name: "example-secrets.read".into(),
            risk,
            side_effects,
            pii,
            discriminator: Some("operation".into()),
            operations,
        }
    }

    fn operation(
        value: &str,
        risk: RiskTier,
        side_effects: bool,
        pii: bool,
    ) -> OperationClassification {
        OperationClassification {
            value: value.into(),
            risk,
            side_effects,
            pii,
        }
    }

    fn resource(prefix: &str, risk: RiskTier) -> ResourceClassification {
        ResourceClassification {
            uri_prefix: prefix.to_owned(),
            risk,
        }
    }

    #[test]
    fn resource_claims_are_literal_absolute_uri_prefixes() {
        let mut manifest = base_manifest();
        manifest.resources = vec![resource("browser://screenshot/", RiskTier::High)];
        validate_manifest_invariants(&manifest).expect("a literal absolute URI prefix is valid");

        for invalid in [
            "browser/*",
            " browser://screenshot/",
            "mcp-file://gateway/",
            "MCP-FILE://gateway/",
        ] {
            manifest.resources = vec![resource(invalid, RiskTier::High)];
            validate_manifest_invariants(&manifest)
                .expect_err("invalid and file-handle prefixes must be refused");
        }
    }

    #[test]
    fn manifest_set_refuses_overlapping_resource_owners() {
        let mut browser = base_manifest();
        browser.name = "browser".to_owned();
        browser.resources = vec![resource("browser://screenshot/", RiskTier::High)];
        let mut shadow = base_manifest();
        shadow.name = "shadow".to_owned();
        shadow.resources = vec![resource("browser://screenshot/private/", RiskTier::Low)];
        let content = serde_yaml::to_string(&vec![browser, shadow]).unwrap();

        let error = parse_manifest_set(&content).expect_err("overlapping routes are ambiguous");
        assert!(error.to_string().contains("claims overlap"), "{error}");
    }

    #[test]
    fn the_tool_entry_must_cover_every_operation_it_names() {
        // It is the classification an unnamed value receives. If a named
        // operation were more severe, an unrecognized one would be treated
        // more leniently than a value someone already assessed as dangerous.
        let cases: [(&str, RiskTier, bool, bool, OperationClassification); 3] = [
            (
                "above the tool's",
                RiskTier::Low,
                true,
                true,
                operation("secrets.reveal", RiskTier::High, true, true),
            ),
            (
                "declares `side_effects` the tool does not",
                RiskTier::High,
                false,
                true,
                operation("secrets.reveal", RiskTier::High, true, true),
            ),
            (
                "declares `pii` the tool does not",
                RiskTier::High,
                true,
                false,
                operation("secrets.reveal", RiskTier::High, true, true),
            ),
        ];

        for (expected, risk, side_effects, pii, op) in cases {
            let mut m = base_manifest();
            m.tools
                .push(tool_with_operations(risk, side_effects, pii, vec![op]));
            let error = validate_manifest_invariants(&m)
                .expect_err("an operation may not exceed the entry that covers unnamed values");
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in: {error}"
            );
        }
    }

    #[test]
    fn an_operation_may_be_narrower_than_the_tool_it_classifies() {
        // The reason the field exists. An executor's tool-level entry has to
        // cover its most sensitive operation, so the harmless ones are only
        // expressible by naming them.
        let mut m = base_manifest();
        m.tools.push(tool_with_operations(
            RiskTier::High,
            true,
            true,
            vec![
                operation("projects.list", RiskTier::Low, false, false),
                operation("secrets.reveal", RiskTier::High, false, true),
            ],
        ));

        validate_manifest_invariants(&m)
            .expect("an operator may classify a named operation below its tool");
    }

    #[test]
    fn operations_require_a_discriminator_to_select_them() {
        let mut m = base_manifest();
        let mut tool = tool_with_operations(
            RiskTier::Low,
            false,
            false,
            vec![operation("projects.list", RiskTier::High, false, false)],
        );
        tool.discriminator = None;
        m.tools.push(tool);

        let error = validate_manifest_invariants(&m)
            .expect_err("operations without a discriminator cannot be selected");
        assert!(error.to_string().contains("without naming a"), "{error}");
    }

    /// The loader admits the same names the invocation path admits.
    ///
    /// Only the refusals were pinned here, so narrowing this predicate back to
    /// a separator allowlist would have left this crate green while making
    /// every classification naming one of these values fail to load — the
    /// operator-facing half of the same rule, unprotected.
    #[test]
    fn a_legible_name_loads_whatever_it_is_made_of() {
        for name in [
            "cafe@v2",
            "secrets/reveal",
            "op[1]",
            "read+write",
            "v1::secrets",
        ] {
            let mut m = base_manifest();
            let mut tool = tool_with_operations(
                RiskTier::High,
                true,
                true,
                vec![operation(name, RiskTier::Low, false, false)],
            );
            tool.discriminator = Some(name.to_owned());
            m.tools.push(tool);

            validate_manifest_invariants(&m)
                .unwrap_or_else(|e| panic!("`{name}` renders as itself and must load: {e}"));
        }
    }

    #[test]
    fn a_name_the_catalog_could_not_store_is_refused() {
        // A manifest that loads must be one the catalog can hold. PostgreSQL
        // TEXT cannot store a NUL, so accepting one here would defer the
        // failure to the write that persists it.
        let cases: [(&str, &str); 10] = [
            ("discriminator", "oper\0ation"),
            ("discriminator", "oper\nation"),
            ("operation at position 0", "secrets\0reveal"),
            ("operation at position 0", "secrets\treveal"),
            // Refused for a second reason: these render as nothing or reorder
            // the text around them, so an operator could classify a name that
            // displays as another one — and the invocation path refuses the
            // same values, so an entry naming one could never be selected.
            ("discriminator", "oper\u{200b}ation"),
            ("operation at position 0", "secrets.\u{202e}laever"),
            // Format controls a hand-written blocklist had missed.
            ("discriminator", "oper\u{0890}ation"),
            ("operation at position 0", "secrets\u{13430}reveal"),
            // The rule is an allowlist, so a printable character outside it is
            // refused too — the loader and the invocation path agree on which
            // names exist rather than on a list of banned code points.
            // Whitespace is invisible where these names are compared and shown.
            ("discriminator", "oper ation"),
            ("operation at position 0", "secrets reveal"),
        ];

        for (expected, name) in cases {
            let mut m = base_manifest();
            let mut tool = tool_with_operations(
                RiskTier::High,
                true,
                true,
                vec![operation("projects.list", RiskTier::Low, false, false)],
            );
            if expected == "discriminator" {
                tool.discriminator = Some(name.into());
            } else {
                tool.operations = vec![operation(name, RiskTier::Low, false, false)];
            }
            m.tools.push(tool);

            let error = validate_manifest_invariants(&m)
                .expect_err("a name outside the admissible characters is refused");
            let message = error.to_string();
            assert!(
                message.contains(expected) && message.contains("an operation name may use"),
                "expected `{expected}` and the admissible-character rule in: {error}"
            );
            assert!(
                !message.contains(name),
                "the offending value must not be echoed into a log line: {error}"
            );
        }
    }

    #[test]
    fn a_repeated_operation_value_is_refused() {
        let mut m = base_manifest();
        m.tools.push(tool_with_operations(
            RiskTier::High,
            false,
            true,
            vec![
                operation("secrets.reveal", RiskTier::High, false, true),
                operation("secrets.reveal", RiskTier::High, false, true),
            ],
        ));

        let error = validate_manifest_invariants(&m)
            .expect_err("one value must have exactly one classification");
        assert!(error.to_string().contains("repeats operation"), "{error}");
    }

    #[test]
    fn a_manifest_that_loads_is_one_the_catalog_can_store() {
        // The column CHECKs and this validation have to agree, or a manifest
        // would validate and then fail to persist.
        let mut m = base_manifest();
        let mut tool = tool_with_operations(RiskTier::Low, false, false, Vec::new());
        tool.discriminator = Some("d".repeat(MAX_DISCRIMINATOR_LEN + 1));
        m.tools.push(tool);
        let error = validate_manifest_invariants(&m)
            .expect_err("a discriminator longer than storage allows must not load");
        assert!(error.to_string().contains("characters"), "{error}");

        let mut m = base_manifest();
        m.tools.push(tool_with_operations(
            RiskTier::Low,
            false,
            false,
            vec![operation(
                &"v".repeat(MAX_OPERATION_VALUE_LEN + 1),
                RiskTier::Low,
                false,
                false,
            )],
        ));
        let error = validate_manifest_invariants(&m)
            .expect_err("an operation value longer than storage allows must not load");
        assert!(error.to_string().contains("characters"), "{error}");

        let mut m = base_manifest();
        m.tools.push(tool_with_operations(
            RiskTier::Low,
            false,
            false,
            vec![operation("", RiskTier::Low, false, false)],
        ));
        validate_manifest_invariants(&m).expect_err("an empty operation value must not load");
    }

    #[test]
    fn annotation_mode_cannot_gain_a_second_behavior_authority() {
        // Annotation-native mode clears the tool-level behavior and
        // sensitivity flags, and the ceiling forbids an operation from
        // declaring what its tool does not, so operations cannot reintroduce a
        // manifest-side claim. Asserted because the two rules only combine to
        // this effect; neither states it alone.
        let mut m = base_manifest();
        m.classification_mode = ClassificationMode::McpAnnotations;
        let mut tool = tool_with_operations(
            RiskTier::High,
            false,
            false,
            vec![operation("secrets.reveal", RiskTier::High, true, false)],
        );
        tool.approved_behavior_hash = Some("a".repeat(64));
        m.tools.push(tool);

        let error = validate_manifest_invariants(&m)
            .expect_err("an operation must not claim behavior its tool does not");
        assert!(
            error
                .to_string()
                .contains("declares `side_effects` the tool does not"),
            "{error}"
        );
    }

    #[test]
    fn a_manifest_written_before_operations_still_parses() {
        // Constructing a manifest in Rust exercises the struct defaults, not
        // the serde ones. A manifest on disk predating these fields has to
        // deserialize with the discriminator absent and the list empty.
        let yaml = r#"
name: example-messages
transport: http
url: http://example-messages/mcp
tools:
  - name: send
    risk: high
    side_effects: true
"#;
        let m: UpstreamManifest = serde_yaml::from_str(yaml).expect("a pre-operations manifest");

        assert_eq!(m.tools.len(), 1);
        assert_eq!(m.tools[0].discriminator, None);
        assert!(m.tools[0].operations.is_empty());
        validate_manifest_invariants(&m).expect("manifests without operations still load");
    }

    fn base_manifest() -> UpstreamManifest {
        UpstreamManifest {
            name: "example-messages".into(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some("http://example-messages/mcp".into()),
            command: None,
            tools: vec![],
            resources: vec![],
            classification_mode: ClassificationMode::Manifest,
            approval_mode: ApprovalMode::PerCall,
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        }
    }

    fn manifest_set(manifests: Vec<UpstreamManifest>) -> BTreeMap<String, UpstreamManifest> {
        manifests.into_iter().map(|m| (m.name.clone(), m)).collect()
    }

    #[test]
    fn classification_mode_defaults_to_legacy_and_rejects_mixed_authority() {
        let parsed: UpstreamManifest = serde_yaml::from_str(
            "name: example-messages\ntransport: http\nurl: http://example-messages/mcp\ntools: []\n",
        )
        .unwrap();
        assert_eq!(parsed.classification_mode, ClassificationMode::Manifest);

        let mut annotation_native = base_manifest();
        annotation_native.classification_mode = ClassificationMode::McpAnnotations;
        annotation_native
            .tools
            .push(ToolClassification::new("send", RiskTier::High, true, false));
        let error = validate_manifest_invariants(&annotation_native).unwrap_err();
        assert!(
            error.to_string().contains("conflicting authorities"),
            "{error}"
        );

        annotation_native.tools[0].side_effects = false;
        let error = validate_manifest_invariants(&annotation_native).unwrap_err();
        assert!(
            error.to_string().contains("approved 64-character"),
            "{error}"
        );

        annotation_native.tools[0].approved_behavior_hash = Some("a".repeat(64));
        validate_manifest_invariants(&annotation_native)
            .expect("annotation-native mode with a reviewed behavior hash is valid");
    }

    #[test]
    fn approval_mode_defaults_to_per_call_and_policy_only_is_explicit() {
        let parsed: UpstreamManifest = serde_yaml::from_str(
            "name: ordinary\ntransport: http\nurl: http://ordinary.test/mcp\ntools: []\n",
        )
        .unwrap();
        assert_eq!(parsed.approval_mode, ApprovalMode::PerCall);
        assert!(
            !serde_yaml::to_string(&parsed)
                .expect("serialize default approval mode")
                .contains("approval_mode"),
            "the fail-closed default should not add noise to existing manifests",
        );

        let mut policy_governed = parsed;
        policy_governed.approval_mode = ApprovalMode::PolicyOnly;
        let yaml = serde_yaml::to_string(&policy_governed).expect("serialize explicit mode");
        assert!(yaml.contains("approval_mode: policy_only"), "{yaml}");
        let reparsed: UpstreamManifest = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(reparsed.approval_mode, ApprovalMode::PolicyOnly);
    }

    #[test]
    fn duplicate_tool_classifications_are_rejected_before_selection_can_diverge() {
        let mut duplicate = base_manifest();
        let tool = ToolClassification::new("send", RiskTier::High, true, false);
        duplicate.tools = vec![tool.clone(), tool];

        let error = validate_manifest_invariants(&duplicate).unwrap_err();
        assert!(error.to_string().contains("repeats tool classification"));
    }

    /// Unique temp dir removed on drop, for the file-as-truth write tests.
    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("upwrite-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn yaml_files(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.0)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".yaml"))
                .collect();
            names.sort();
            names
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn named(name: &str) -> UpstreamManifest {
        let mut m = base_manifest();
        m.name = name.into();
        m.url = Some(format!("http://{name}/mcp"));
        m
    }

    #[test]
    fn manifest_filename_accepts_identifiers_rejects_traversal() {
        assert_eq!(
            manifest_filename("example-messages").unwrap(),
            "example-messages.yaml"
        );
        assert_eq!(
            manifest_filename("example_archive").unwrap(),
            "example_archive.yaml"
        );
        for bad in ["", ".", "..", ".hidden", "a/b", "../evil", "a\\b"] {
            assert!(
                manifest_filename(bad).is_err(),
                "name `{bad}` must be refused as an unsafe filename",
            );
        }
    }

    #[test]
    fn write_set_round_trips_through_load() {
        let dir = TmpDir::new();
        let set = manifest_set(vec![named("example-messages"), named("gamma")]);
        write_manifest_set_to_dir(&dir.0, &set).unwrap();
        assert_eq!(
            dir.yaml_files(),
            vec!["example-messages.yaml", "gamma.yaml"]
        );
        let loaded = load_manifests(&dir.0).unwrap();
        // UpstreamManifest isn't PartialEq, so check the round-trip by keys
        // + a representative field rather than whole-map equality.
        assert_eq!(
            loaded.keys().collect::<Vec<_>>(),
            set.keys().collect::<Vec<_>>()
        );
        for (name, m) in &set {
            assert_eq!(loaded[name].url, m.url, "url for `{name}` must round-trip");
        }
    }

    #[test]
    fn conditional_write_from_live_base_round_trips() {
        let dir = TmpDir::new();
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a")])).unwrap();
        let expected = manifest_dir_hash(&dir.0).unwrap();
        let replacement = manifest_set(vec![named("b")]);

        write_manifest_set_to_dir_from_base(&dir.0, &replacement, &expected).unwrap();

        assert_eq!(dir.yaml_files(), vec!["b.yaml"]);
        assert!(
            !manifest_write_in_progress(&dir.0).unwrap(),
            "a verified replacement must clear the reader safety marker",
        );
        assert_eq!(
            load_manifests(&dir.0).unwrap()["b"].url,
            replacement["b"].url
        );
    }

    #[test]
    fn interrupted_conditional_write_leaves_the_reader_safety_marker() {
        let dir = TmpDir::new();
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a")])).unwrap();
        let expected = manifest_dir_hash(&dir.0).unwrap();

        let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = write_manifest_set_to_dir_inner(
                &dir.0,
                &manifest_set(vec![named("replacement")]),
                Some(&expected),
                || {},
                || panic!("simulate process abort after quarantining the live set"),
            );
        }));

        assert!(aborted.is_err(), "the injected abort must leave the commit");
        assert!(
            manifest_write_in_progress(&dir.0).unwrap(),
            "readers need a durable signal that the visible directory is incomplete",
        );
        assert!(
            dir.yaml_files().is_empty(),
            "the injection point models the destructive empty-directory window",
        );

        let recovered = manifest_set(vec![named("recovered")]);
        write_manifest_set_to_dir(&dir.0, &recovered)
            .expect("a complete rollback-style rewrite must repair the marked directory");
        assert!(!manifest_write_in_progress(&dir.0).unwrap());
        assert!(load_manifests(&dir.0).unwrap().contains_key("recovered"));
        assert!(
            std::fs::read_dir(&dir.0).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(MANIFEST_ARCHIVE_PREFIX)
            }),
            "a verified repair must remove the abandoned internal archive",
        );
    }

    #[test]
    fn conditional_write_refuses_a_stale_base_without_touching_live() {
        let dir = TmpDir::new();
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a")])).unwrap();
        let stale = manifest_dir_hash(&dir.0).unwrap();
        let concurrent = manifest_set(vec![named("concurrent")]);
        write_manifest_set_to_dir(&dir.0, &concurrent).unwrap();

        let error =
            write_manifest_set_to_dir_from_base(&dir.0, &manifest_set(vec![named("b")]), &stale)
                .unwrap_err();

        assert!(matches!(error, UpstreamError::StaleBase));
        assert_eq!(dir.yaml_files(), vec!["concurrent.yaml"]);
        assert_eq!(
            load_manifests(&dir.0).unwrap()["concurrent"].url,
            concurrent["concurrent"].url
        );
    }

    #[test]
    fn conditional_write_preserves_an_edit_after_the_final_base_check() {
        let dir = TmpDir::new();
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a")])).unwrap();
        let expected = manifest_dir_hash(&dir.0).unwrap();
        let mut concurrent = named("a");
        concurrent.url = Some("http://concurrent/mcp".to_owned());
        let concurrent_yaml = serde_yaml::to_string(&concurrent).unwrap();

        let error = write_manifest_set_to_dir_inner(
            &dir.0,
            &manifest_set(vec![named("replacement")]),
            Some(&expected),
            || std::fs::write(dir.0.join("a.yaml"), &concurrent_yaml).unwrap(),
            || {},
        )
        .unwrap_err();

        assert!(matches!(error, UpstreamError::StaleBase));
        let live = load_manifests(&dir.0).unwrap();
        assert_eq!(live.keys().collect::<Vec<_>>(), vec!["a"]);
        assert_eq!(live["a"].url.as_deref(), Some("http://concurrent/mcp"));
    }

    #[test]
    fn write_set_reconciles_removed_upstream() {
        let dir = TmpDir::new();
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a"), named("b")])).unwrap();
        // A later write that drops `b` must delete b.yaml, not leave it to
        // be re-loaded — removal is a real edit under file-as-truth.
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a")])).unwrap();
        assert_eq!(dir.yaml_files(), vec!["a.yaml"]);
        let loaded = load_manifests(&dir.0).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key("a") && !loaded.contains_key("b"));
    }

    #[test]
    fn write_set_canonicalizes_noncanonical_filename() {
        let dir = TmpDir::new();
        // A human-authored, non-canonical filename for upstream `example-messages`.
        std::fs::write(
            dir.0.join("example-messages-prod.yaml"),
            "name: example-messages\ntransport: http\nurl: http://example-messages/mcp\n",
        )
        .unwrap();
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("example-messages")])).unwrap();
        // The write canonicalizes to example-messages.yaml and drops the stray file,
        // so load_manifests can't hit a duplicate `name: example-messages`.
        assert_eq!(dir.yaml_files(), vec!["example-messages.yaml"]);
        assert!(load_manifests(&dir.0)
            .unwrap()
            .contains_key("example-messages"));
    }

    #[test]
    fn write_set_leaves_no_orphan_temp_files() {
        // The temp+rename invariant (ADR §6 NFS rule): after a successful
        // write every temp must be renamed into place — no `.tmp` sibling may
        // linger to confuse an NFS reader or accrete across writes. `yaml_files`
        // ignores dotfiles, so assert directly against the raw dir listing.
        let dir = TmpDir::new();
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a"), named("b")])).unwrap();
        // A second write re-exercises the create_new / rename path.
        write_manifest_set_to_dir(&dir.0, &manifest_set(vec![named("a"), named("c")])).unwrap();
        let leftovers: Vec<String> = std::fs::read_dir(&dir.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp files may linger after a write, found: {leftovers:?}",
        );
    }

    #[test]
    fn write_set_refuses_unsafe_name_without_writing() {
        let dir = TmpDir::new();
        let set = manifest_set(vec![named("../evil")]);
        let err = write_manifest_set_to_dir(&dir.0, &set).unwrap_err();
        assert!(matches!(err, UpstreamError::InvalidManifest(_)));
        // Names are validated before any write, so nothing landed.
        assert!(
            dir.yaml_files().is_empty(),
            "no file may be written for a refused set"
        );
    }

    #[test]
    fn write_set_refuses_unsafe_name_after_safe_leaves_no_temp() {
        let dir = TmpDir::new();
        // "example-messages" sorts before "z/evil", so the safe entry is planned
        // first; the unsafe name must still abort the whole write in Pass 1,
        // leaving NO file — temp or yaml — behind.
        let set = manifest_set(vec![named("example-messages"), named("z/evil")]);
        let err = write_manifest_set_to_dir(&dir.0, &set).unwrap_err();
        assert!(matches!(err, UpstreamError::InvalidManifest(_)));
        let left: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            left.is_empty(),
            "a refused write must leave the dir empty, found: {left:?}"
        );
    }

    #[test]
    fn enforce_no_prod_stdio_refuses_stdio_in_prod() {
        let mut stdio = base_manifest();
        stdio.name = "local".into();
        stdio.transport = Transport::Stdio;
        stdio.url = None;
        stdio.command = Some(vec!["echo".into()]);
        let set = manifest_set(vec![base_manifest(), stdio]);
        let err = enforce_no_prod_stdio(true, &set).unwrap_err();
        assert!(
            err.contains("transport: stdio") && err.contains("local"),
            "prod refusal must name the offending stdio upstream: {err}"
        );
    }

    #[test]
    fn enforce_no_prod_stdio_allows_stdio_in_dev_and_http_in_prod() {
        let mut stdio = base_manifest();
        stdio.name = "local".into();
        stdio.transport = Transport::Stdio;
        stdio.url = None;
        stdio.command = Some(vec!["echo".into()]);
        // dev profile: stdio allowed.
        assert!(enforce_no_prod_stdio(false, &manifest_set(vec![stdio])).is_ok());
        // prod profile, HTTP-only set: allowed.
        assert!(enforce_no_prod_stdio(true, &manifest_set(vec![base_manifest()])).is_ok());
    }

    /// Refuse an upstream name that collides with a reserved built-in MCP
    /// namespace, both on the exact name and on a `reserved.`-prefixed name.
    #[test]
    fn validate_refuses_reserved_builtin_namespace() {
        assert!(
            waygate_core::RESERVED_BUILTIN_NAMESPACES
                .contains(&waygate_core::SKILLS_SERVER_NAMESPACE),
            "the gateway-owned skill policy identity must stay reserved from upstreams"
        );
        // An upstream that collides with the built-in
        // `gateway-admin` MCP namespace would be silently shadowed at
        // dispatch, so it's refused at load. Every load path funnels through
        // validate_manifest_invariants, so this guard covers boot /
        // SIGHUP-bundle / import alike.
        // Every reserved namespace collides on both the exact name AND a
        // `reserved.`-prefixed name (the dispatcher intercepts any `<ns>.*`
        // tool call before the `<server>.<tool>` split) — the second case
        // is exercised below.
        for reserved in waygate_core::RESERVED_BUILTIN_NAMESPACES {
            for bad in [(*reserved).to_owned(), format!("{reserved}.foo")] {
                let mut m = base_manifest();
                m.name = bad.clone();
                match validate_manifest_invariants(&m) {
                    Err(UpstreamError::InvalidManifest(msg)) => assert!(
                        msg.contains("reserved"),
                        "error must explain the reserved-name collision for `{bad}`: {msg}",
                    ),
                    other => panic!("expected InvalidManifest for `{bad}`, got {other:?}"),
                }
            }
            // A mere literal-prefix lookalike (`gateway-adminX`, no dot) is NOT
            // over-rejected — the dispatcher wouldn't intercept it, so neither
            // should the guard.
            let mut lookalike = base_manifest();
            lookalike.name = format!("{reserved}X");
            assert!(
                validate_manifest_invariants(&lookalike).is_ok(),
                "`{reserved}X` does not collide and must not be rejected"
            );
        }
        // A normal name still validates.
        assert!(validate_manifest_invariants(&base_manifest()).is_ok());
    }

    #[test]
    fn validate_refuses_dotted_server_name_that_cannot_round_trip_through_dispatch() {
        let mut manifest = base_manifest();
        manifest.name = "alpha.beta".to_owned();

        let error = validate_manifest_invariants(&manifest)
            .expect_err("a dotted server name makes qualified tool identity ambiguous");
        match error {
            UpstreamError::InvalidManifest(message) => {
                assert!(message.contains("cannot contain dots"), "{message}");
                assert!(message.contains("<server>.<tool>"), "{message}");
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn validate_refuses_reserved_llm_namespace_exact_only() {
        // The inference plane owns the `llm` server: an upstream named exactly
        // `llm` would be a dead namespace (its tools rejected as unknown models),
        // so it's refused at load.
        let mut m = base_manifest();
        m.name = waygate_core::LLM_RESERVED_NAMESPACE.to_owned();
        match validate_manifest_invariants(&m) {
            Err(UpstreamError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("reserved"),
                    "must explain the reservation: {msg}"
                )
            }
            other => panic!("expected InvalidManifest for `llm`, got {other:?}"),
        }
        // Exact reservation does not reject ordinary lookalikes. Dotted names
        // are independently invalid because public tool routing reserves the
        // first dot as the server/tool boundary.
        for ok in ["llmX", "my-llm"] {
            let mut m = base_manifest();
            m.name = ok.to_owned();
            assert!(
                validate_manifest_invariants(&m).is_ok(),
                "`{ok}` does not collide with the exact `llm` reservation"
            );
        }
    }

    #[test]
    fn parse_manifest_set_rejects_reserved_builtin_namespace() {
        // The whole-set path (bundle publish / SIGHUP) must reject it too.
        let doc = format!(
            "- name: {}\n  transport: http\n  url: http://x/mcp\n",
            waygate_core::RESERVED_BUILTIN_NAMESPACE,
        );
        match parse_manifest_set(&doc) {
            Err(UpstreamError::InvalidManifest(msg)) => {
                assert!(msg.contains("reserved"), "got: {msg}")
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    /// Refuse a manifest that combines `tier_c_peer:` (Tier-C) with
    /// `exchange:` (Tier-A) — they both want to write
    /// Authorization: Bearer and the operator must pick one.
    #[test]
    fn validate_refuses_tier_c_plus_exchange() {
        let mut m = base_manifest();
        m.tier_c_peer = Some(uuid::Uuid::new_v4());
        m.exchange = Some(ExchangeConfig {
            audience: "https://idp/upstream".into(),
            scope: None,
        });
        let err = validate_manifest_invariants(&m).unwrap_err();
        match err {
            UpstreamError::InvalidManifest(msg) => {
                assert!(
                    msg.contains("tier_c_peer") && msg.contains("exchange"),
                    "error must name both fields: {msg}",
                );
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_tier_c_alone() {
        let mut m = base_manifest();
        m.tier_c_peer = Some(uuid::Uuid::new_v4());
        validate_manifest_invariants(&m).expect("tier_c alone must pass");
    }

    #[test]
    fn validate_accepts_exchange_alone() {
        let mut m = base_manifest();
        m.exchange = Some(ExchangeConfig {
            audience: "https://idp/upstream".into(),
            scope: None,
        });
        validate_manifest_invariants(&m).expect("exchange alone must pass");
    }

    /// `tier_a_required` without `exchange` refuses every
    /// call (the Tier-A path is never consulted), so it's rejected at load.
    #[test]
    fn validate_refuses_tier_a_required_without_exchange() {
        let mut m = base_manifest();
        m.tier_a_required = true;
        match validate_manifest_invariants(&m).unwrap_err() {
            UpstreamError::InvalidManifest(msg) => assert!(
                msg.contains("tier_a_required") && msg.contains("exchange"),
                "got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
        m.exchange = Some(ExchangeConfig {
            audience: "https://idp/upstream".into(),
            scope: None,
        });
        validate_manifest_invariants(&m).expect("tier_a_required + exchange must pass");
    }

    /// SSE bearer support: `auth.bearer_env` is honored on SSE (stamped on the
    /// SSE GET + every message POST), so an SSE upstream may carry it. `mtls`
    /// stays HTTP-only, and stdio rejects `auth.bearer_env` (no HTTP request to
    /// carry a bearer).
    #[test]
    fn validate_bearer_and_mtls_transport_rules() {
        // SSE + auth.bearer_env: ACCEPTED (the new capability).
        let mut m = base_manifest();
        m.transport = Transport::Sse;
        m.auth = Some(UpstreamAuth {
            bearer_env: Some("UP_BEARER".into()),
            ..Default::default()
        });
        validate_manifest_invariants(&m).expect("auth.bearer_env on sse must pass");

        // stdio + auth.bearer_env: REFUSED (no HTTP request to carry it).
        m.transport = Transport::Stdio;
        match validate_manifest_invariants(&m).unwrap_err() {
            UpstreamError::InvalidManifest(msg) => assert!(
                msg.contains("stdio") && msg.contains("auth.bearer_env"),
                "got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }

        // mtls on a non-HTTP upstream: still REFUSED (HTTP-only).
        m.auth = None;
        m.transport = Transport::Sse;
        m.mtls = Some(MtlsConfig {
            cert_path: Some("/c.pem".into()),
            key_path: Some("/k.pem".into()),
            ca_path: None,
        });
        match validate_manifest_invariants(&m).unwrap_err() {
            UpstreamError::InvalidManifest(msg) => {
                assert!(
                    msg.contains("mtls") && msg.contains("HTTP-only"),
                    "got: {msg}"
                )
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }

        // Both fine on an https HTTP upstream (mTLS needs TLS).
        m.transport = Transport::Http;
        m.url = Some("https://example-messages/mcp".into());
        m.auth = Some(UpstreamAuth {
            bearer_env: Some("UP_BEARER".into()),
            ..Default::default()
        });
        validate_manifest_invariants(&m).expect("auth + mtls on https http must pass");
    }

    #[test]
    fn catalog_probe_groups_round_trip_and_default_to_empty() {
        let yaml = "\
name: komodo
transport: http
url: http://komodo-mcp:3000/mcp
auth:
  bearer_env: KOMODO_BEARER
  catalog_probe_groups:
    - service-operators
";
        let manifest: UpstreamManifest = serde_yaml::from_str(yaml).expect("parse manifest");
        let auth = manifest.auth.as_ref().expect("auth block");
        assert_eq!(auth.catalog_probe_groups, ["service-operators"]);

        let encoded = serde_yaml::to_string(&manifest).expect("serialize manifest");
        let decoded: UpstreamManifest = serde_yaml::from_str(&encoded).expect("round trip");
        assert_eq!(
            decoded.auth.unwrap().catalog_probe_groups,
            ["service-operators"]
        );

        let without_groups = "\
name: komodo
transport: http
url: http://komodo-mcp:3000/mcp
auth:
  bearer_env: KOMODO_BEARER
";
        let manifest: UpstreamManifest =
            serde_yaml::from_str(without_groups).expect("parse manifest without groups");
        assert!(manifest.auth.unwrap().catalog_probe_groups.is_empty());
        assert!(
            !serde_yaml::to_string(&UpstreamAuth::default())
                .expect("serialize default auth")
                .contains("catalog_probe_groups"),
            "the default must remain absent from generated manifests",
        );
    }

    #[test]
    fn validate_catalog_probe_groups_contract() {
        fn manifest_with(groups: Vec<String>) -> UpstreamManifest {
            let mut manifest = base_manifest();
            manifest.auth = Some(UpstreamAuth {
                catalog_probe_groups: groups,
                ..Default::default()
            });
            manifest
        }

        for transport in [Transport::Http, Transport::Sse] {
            let mut manifest = manifest_with(vec!["service-operators".into()]);
            manifest.transport = transport;
            validate_manifest_invariants(&manifest)
                .expect("a bounded network catalog role must pass");
        }

        validate_manifest_invariants(&manifest_with(vec!["x".repeat(128)]))
            .expect("the 128-byte entry limit is inclusive");
        validate_manifest_invariants(&manifest_with(
            (0..32).map(|index| format!("group-{index}")).collect(),
        ))
        .expect("the 32-group limit is inclusive");

        let mut stdio = manifest_with(vec!["service-operators".into()]);
        stdio.transport = Transport::Stdio;
        let err = validate_manifest_invariants(&stdio).expect_err("stdio must reject probe groups");
        assert!(err
            .to_string()
            .contains("requires an HTTP or SSE transport"));

        for (case, groups) in [
            ("empty", vec![String::new()]),
            ("leading space", vec![" service-operators".into()]),
            ("trailing space", vec!["service-operators ".into()]),
            ("control", vec!["komodo\nadmin".into()]),
            ("too long", vec!["x".repeat(129)]),
        ] {
            let err = validate_manifest_invariants(&manifest_with(groups))
                .expect_err("invalid catalog-probe group must fail");
            assert!(
                err.to_string()
                    .contains("every `auth.catalog_probe_groups` entry"),
                "{case}: {err}",
            );
        }

        let duplicate = manifest_with(vec!["service-operators".into(), "service-operators".into()]);
        let err = validate_manifest_invariants(&duplicate).expect_err("duplicates must fail");
        assert!(err
            .to_string()
            .contains("duplicate group `service-operators`"));

        let too_many = manifest_with((0..33).map(|index| format!("group-{index}")).collect());
        let err = validate_manifest_invariants(&too_many).expect_err("too many groups must fail");
        assert!(err.to_string().contains("at most 32 groups"));

        let mut reused = manifest_with(vec!["service-operators".into()]);
        reused.session = Some(SessionConfig {
            isolation: Some(SessionIsolation::Reuse),
            scope: Some(SessionScope::Shared),
            ..Default::default()
        });
        let err = validate_manifest_invariants(&reused)
            .expect_err("catalog privileges must not enter a caller-reused MCP session");
        assert!(err.to_string().contains("cannot be combined"));

        reused.session.as_mut().unwrap().isolation = Some(SessionIsolation::PerCall);
        validate_manifest_invariants(&reused)
            .expect("per-call sessions isolate catalog discovery from caller sessions");
    }

    /// The `Transport` capability predicates are the single source of truth the
    /// dashboard identity form consumes; pin that they agree with what
    /// `validate_manifest_invariants` actually accepts, so a future change to
    /// one without the other fails CI.
    #[test]
    fn transport_capability_predicates_match_validator() {
        for t in [Transport::Http, Transport::Sse, Transport::Stdio] {
            // Static bearer.
            let mut m = base_manifest();
            m.transport = t.clone();
            m.url = Some("https://up/mcp".into());
            m.auth = Some(UpstreamAuth {
                bearer_env: Some("UP_BEARER".into()),
                ..Default::default()
            });
            assert_eq!(
                validate_manifest_invariants(&m).is_ok(),
                t.supports_static_bearer(),
                "bearer accept/reject disagrees with supports_static_bearer for {t:?}",
            );

            // mTLS (complete cert+key on an https url — so only the transport
            // gate decides accept vs reject).
            let mut m = base_manifest();
            m.transport = t.clone();
            m.url = Some("https://up/mcp".into());
            m.mtls = Some(MtlsConfig {
                cert_path: Some("/c.pem".into()),
                key_path: Some("/k.pem".into()),
                ca_path: None,
            });
            assert_eq!(
                validate_manifest_invariants(&m).is_ok(),
                t.supports_mtls(),
                "mtls accept/reject disagrees with supports_mtls for {t:?}",
            );
        }
    }

    /// The HTTP mTLS builder needs both cert and key;
    /// a cert-only / CA-only block is rejected at load.
    #[test]
    fn validate_refuses_incomplete_mtls() {
        let mut m = base_manifest();
        m.mtls = Some(MtlsConfig {
            cert_path: Some("/c.pem".into()),
            key_path: None,
            ca_path: None,
        });
        match validate_manifest_invariants(&m).unwrap_err() {
            UpstreamError::InvalidManifest(msg) => assert!(
                msg.contains("cert_path") && msg.contains("key_path"),
                "got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
        m.mtls = Some(MtlsConfig {
            cert_path: Some("/c.pem".into()),
            key_path: Some("/k.pem".into()),
            ca_path: None,
        });
        // mTLS needs an https url (the cert is only presented over TLS).
        m.url = Some("https://example-messages/mcp".into());
        validate_manifest_invariants(&m).expect("complete mtls on https must pass");
    }

    /// `mtls:` requires an `https://` url — the client
    /// cert is only presented over TLS, so an `http://` upstream is rejected.
    #[test]
    fn validate_refuses_mtls_without_https() {
        let mut m = base_manifest(); // base_manifest uses an http:// url
        m.mtls = Some(MtlsConfig {
            cert_path: Some("/c.pem".into()),
            key_path: Some("/k.pem".into()),
            ca_path: None,
        });
        match validate_manifest_invariants(&m).unwrap_err() {
            UpstreamError::InvalidManifest(msg) => {
                assert!(msg.contains("https://"), "got: {msg}")
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
        m.url = Some("https://example-messages/mcp".into());
        validate_manifest_invariants(&m).expect("mtls on https must pass");
    }

    /// `exchange:` and `auth.bearer_env:` both write
    /// Authorization: Bearer — the exchanged token shadows the static bearer
    /// per call, so the combo is refused (same shape as the tier_c guards).
    #[test]
    fn validate_refuses_exchange_plus_auth_bearer_env() {
        let mut m = base_manifest();
        m.exchange = Some(ExchangeConfig {
            audience: "https://idp/upstream".into(),
            scope: None,
        });
        m.auth = Some(UpstreamAuth {
            bearer_env: Some("UP_BEARER".into()),
            ..Default::default()
        });
        match validate_manifest_invariants(&m).unwrap_err() {
            UpstreamError::InvalidManifest(msg) => assert!(
                msg.contains("exchange") && msg.contains("auth.bearer_env"),
                "got: {msg}"
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    /// `auth.bearer_env`
    /// also writes Authorization: Bearer, so it conflicts with
    /// `tier_c_peer:` the same way `exchange:` does.
    #[test]
    fn validate_refuses_tier_c_plus_auth_bearer_env() {
        let mut m = base_manifest();
        m.tier_c_peer = Some(uuid::Uuid::new_v4());
        m.auth = Some(UpstreamAuth {
            bearer_env: Some("UPSTREAM_BEARER".into()),
            ..Default::default()
        });
        let err = validate_manifest_invariants(&m).unwrap_err();
        match err {
            UpstreamError::InvalidManifest(msg) => assert!(
                msg.contains("tier_c_peer") && msg.contains("auth.bearer_env"),
                "error must name both fields: {msg}",
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    /// Bearer-env without tier_c is still fine.
    #[test]
    fn validate_accepts_auth_bearer_env_alone() {
        let mut m = base_manifest();
        m.auth = Some(UpstreamAuth {
            bearer_env: Some("UPSTREAM_BEARER".into()),
            ..Default::default()
        });
        validate_manifest_invariants(&m).expect("bearer_env alone must pass");
    }

    /// The optional `session:` block deserializes its `concurrency`
    /// override, and a manifest without it leaves `session` as `None`
    /// (so existing manifests keep the gateway-wide pool default).
    #[test]
    fn session_concurrency_parses_and_defaults() {
        let with = "\
name: searxng
transport: http
url: http://searxng/mcp
session:
  concurrency: 2
";
        let m: UpstreamManifest = serde_yaml::from_str(with).expect("parse with session");
        assert_eq!(
            m.session.and_then(|s| s.concurrency),
            Some(2),
            "concurrency must round-trip from YAML",
        );

        let without = "\
name: searxng
transport: http
url: http://searxng/mcp
";
        let m: UpstreamManifest = serde_yaml::from_str(without).expect("parse without session");
        assert!(
            m.session.is_none(),
            "absent session block ⇒ None ⇒ inherit the global pool size",
        );
    }

    /// `session.isolation` deserializes the snake_case variants and is
    /// `None` (⇒ transport-defaulted) when the field is omitted.
    #[test]
    fn session_isolation_parses_from_yaml() {
        let per_call = "\
name: searxng
transport: http
url: http://searxng/mcp
session:
  isolation: per_call
";
        let m: UpstreamManifest = serde_yaml::from_str(per_call).expect("parse per_call");
        assert_eq!(
            m.session.and_then(|s| s.isolation),
            Some(SessionIsolation::PerCall),
        );

        let reuse = "\
name: searxng
transport: http
url: http://searxng/mcp
session:
  isolation: reuse
";
        let m: UpstreamManifest = serde_yaml::from_str(reuse).expect("parse reuse");
        assert_eq!(
            m.session.and_then(|s| s.isolation),
            Some(SessionIsolation::Reuse),
        );

        // concurrency-only block leaves isolation unset (transport-defaulted).
        let conc_only = "\
name: searxng
transport: http
url: http://searxng/mcp
session:
  concurrency: 1
";
        let m: UpstreamManifest = serde_yaml::from_str(conc_only).expect("parse conc-only");
        assert!(m.session.unwrap().isolation.is_none());
    }

    /// `session.scope` deserializes its snake_case variants.
    #[test]
    fn session_scope_parses_from_yaml() {
        let shared = "\
name: example-messages
transport: http
url: http://example-messages/mcp
session:
  isolation: reuse
  scope: shared
";
        let m: UpstreamManifest = serde_yaml::from_str(shared).expect("parse scope: shared");
        let s = m.session.unwrap();
        assert_eq!(s.isolation, Some(SessionIsolation::Reuse));
        assert_eq!(s.scope, Some(SessionScope::Shared));
    }

    #[test]
    fn setup_retry_policy_is_http_only() {
        let mut manifest = base_manifest();
        manifest.session = Some(SessionConfig {
            retry_on_setup_failure: Some(false),
            ..Default::default()
        });
        validate_manifest_invariants(&manifest).expect("HTTP supports safe setup recovery policy");

        manifest.transport = Transport::Sse;
        let error = validate_manifest_invariants(&manifest)
            .expect_err("SSE has no automatic setup recovery to configure");
        assert!(error.to_string().contains("session.retry_on_setup_failure"));
    }

    /// Security guardrail: `isolation: reuse` on ANY HTTP/SSE upstream is refused
    /// unless `scope: shared` consciously accepts cross-caller session
    /// sharing. The guard is conservative because identity forwarding to a
    /// network upstream is a runtime property the manifest can't see
    /// (Tier-B `X-MCP-Identity` is emitted for any issuer-wired HTTP/SSE
    /// upstream). `per_call` and stdio are unaffected.
    #[test]
    fn validate_refuses_http_reuse_unless_scope_shared() {
        let reuse_session = |scope| {
            Some(SessionConfig {
                concurrency: None,
                isolation: Some(SessionIsolation::Reuse),
                scope,
                retry_on_setup_failure: None,
            })
        };

        // reuse on HTTP + no scope → refused, even with no identity fields
        // set (Tier-B identity may still be forwarded at runtime).
        let mut m = base_manifest();
        m.session = reuse_session(None);
        match validate_manifest_invariants(&m).unwrap_err() {
            UpstreamError::InvalidManifest(msg) => assert!(
                msg.contains("session.isolation: reuse") && msg.contains("session.scope: shared"),
                "error must name the hazard and the opt-in: {msg}",
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }

        // reuse + scope: shared → accepted (conscious opt-in).
        m.session = reuse_session(Some(SessionScope::Shared));
        validate_manifest_invariants(&m).expect("scope: shared acknowledges the reuse hazard");

        // Explicit identity fields don't change the verdict — still refused
        // without scope: shared (subsumed by the HTTP+reuse rule).
        let mut ident = base_manifest();
        ident.exchange = Some(ExchangeConfig {
            audience: "https://idp/upstream".into(),
            scope: None,
        });
        ident.session = reuse_session(None);
        validate_manifest_invariants(&ident)
            .expect_err("reuse + exchange must refuse without scope: shared");

        // per_call (the safe default) → accepted, no scope needed.
        m.session = Some(SessionConfig {
            concurrency: None,
            isolation: Some(SessionIsolation::PerCall),
            scope: None,
            retry_on_setup_failure: None,
        });
        validate_manifest_invariants(&m).expect("per_call is the safe default");

        // stdio is exempt (not a shared HTTP session pool): reuse needs no
        // scope: shared.
        let mut stdio = base_manifest();
        stdio.transport = Transport::Stdio;
        stdio.url = None;
        stdio.command = Some(vec!["/bin/true".into()]);
        stdio.session = reuse_session(None);
        validate_manifest_invariants(&stdio).expect("stdio reuse needs no scope: shared");
    }

    fn set_with(names: &[&str]) -> BTreeMap<String, UpstreamManifest> {
        let mut out = BTreeMap::new();
        for n in names {
            let mut m = base_manifest();
            m.name = (*n).to_owned();
            out.insert(m.name.clone(), m);
        }
        out
    }

    /// serialize → parse → serialize must yield byte-identical YAML.
    /// `UpstreamManifest` has no `PartialEq`, so the set equality is
    /// asserted by re-serializing the parsed set and comparing to the
    /// original document.
    #[test]
    fn manifest_set_round_trips() {
        let original = set_with(&["alpha", "beta", "gamma"]);
        let doc = serialize_manifest_set(&original).expect("serialize");
        let parsed = parse_manifest_set(&doc).expect("parse");
        assert_eq!(
            parsed.keys().collect::<Vec<_>>(),
            original.keys().collect::<Vec<_>>(),
            "same names survive the round-trip",
        );
        let redoc = serialize_manifest_set(&parsed).expect("re-serialize");
        assert_eq!(doc, redoc, "round-trip is byte-stable");
    }

    /// Adding resource declarations must not rewrite the canonical form of
    /// legacy manifests that declare none. Mixed-version replicas compare the
    /// serialized set hash, so an emitted `resources: []` would create a false
    /// configuration conflict during rollout.
    #[test]
    fn empty_resource_claims_preserve_legacy_canonical_form() {
        let doc = serialize_manifest_set(&set_with(&["legacy"])).expect("serialize");
        assert!(
            !doc.lines()
                .any(|line| line.trim_start().starts_with("resources:")),
            "empty resource declarations must remain absent: {doc}",
        );
    }

    /// BTreeMap ordering makes serialization independent of insertion
    /// order — the hash of the set must not depend on how it was built.
    #[test]
    fn manifest_set_serialization_is_deterministic() {
        let mut a = BTreeMap::new();
        for n in ["zeta", "alpha", "mu"] {
            let mut m = base_manifest();
            m.name = n.to_owned();
            a.insert(m.name.clone(), m);
        }
        let mut b = BTreeMap::new();
        for n in ["mu", "zeta", "alpha"] {
            let mut m = base_manifest();
            m.name = n.to_owned();
            b.insert(m.name.clone(), m);
        }
        assert_eq!(
            serialize_manifest_set(&a).unwrap(),
            serialize_manifest_set(&b).unwrap(),
            "insertion order must not affect serialized bytes",
        );
    }

    /// An empty set is a legitimate ("no upstreams") configuration, not
    /// an error — it round-trips to an empty sequence and back.
    #[test]
    fn manifest_set_empty_round_trips() {
        let empty = BTreeMap::new();
        let doc = serialize_manifest_set(&empty).expect("serialize empty");
        let parsed = parse_manifest_set(&doc).expect("parse empty");
        assert!(parsed.is_empty(), "empty set survives the round-trip");
    }

    /// A set naming the same upstream twice is ambiguous — reject it
    /// (the per-file `load_manifests` path can't express this).
    #[test]
    fn parse_manifest_set_rejects_duplicate_names() {
        // Build the document by hand: BTreeMap can't hold a dup, so the
        // serialize helper can't produce one.
        let doc = "\
- name: dup
  transport: http
  url: http://a/mcp
- name: dup
  transport: http
  url: http://b/mcp
";
        match parse_manifest_set(doc) {
            Err(UpstreamError::DuplicateName(n)) => assert_eq!(n, "dup"),
            other => panic!("expected DuplicateName, got {other:?}"),
        }
    }

    /// Each entry is validated, so a set containing a mutually-exclusive
    /// manifest (tier_c_peer + exchange) is rejected at parse time — the
    /// whole set fails rather than admitting a bad upstream.
    #[test]
    fn parse_manifest_set_rejects_invalid_entry() {
        let doc = format!(
            "\
- name: ok
  transport: http
  url: http://ok/mcp
- name: bad
  transport: http
  url: http://bad/mcp
  tier_c_peer: {}
  exchange:
    audience: https://idp/upstream
",
            uuid::Uuid::new_v4(),
        );
        match parse_manifest_set(&doc) {
            Err(UpstreamError::InvalidManifest(msg)) => assert!(
                msg.contains("bad") && msg.contains("tier_c_peer"),
                "error must identify the bad entry: {msg}",
            ),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod protocol_field_tests {
    use super::*;

    /// Operator-facing YAML contract for the `protocol:` field: absent
    /// defaults to auto and is omitted on re-serialization; the three
    /// spellings round-trip; and the SSE + 2026-07-28 contradiction is
    /// refused at validation, not silently downgraded at dial time.
    #[test]
    fn protocol_field_round_trips_and_validates() {
        let absent: UpstreamManifest =
            serde_yaml::from_str("name: a\ntransport: http\nurl: http://u/mcp\n").expect("parse");
        assert_eq!(absent.protocol, UpstreamProtocol::Auto);
        assert!(
            !serde_yaml::to_string(&absent)
                .expect("serialize")
                .contains("protocol"),
            "the default stays out of scaffolded and re-written manifests"
        );

        for (spelling, expected) in [
            ("auto", UpstreamProtocol::Auto),
            ("legacy", UpstreamProtocol::Legacy),
            ("\"2026-07-28\"", UpstreamProtocol::V20260728),
        ] {
            let m: UpstreamManifest = serde_yaml::from_str(&format!(
                "name: a\ntransport: http\nurl: http://u/mcp\nprotocol: {spelling}\n"
            ))
            .expect("parse");
            assert_eq!(m.protocol, expected, "{spelling}");
            // The full round trip: what serializes must parse back to the
            // same selection (the default is omitted; the overrides keep
            // their spelling).
            let reparsed: UpstreamManifest =
                serde_yaml::from_str(&serde_yaml::to_string(&m).expect("serialize"))
                    .expect("reparse");
            assert_eq!(reparsed.protocol, expected, "{spelling} round trip");
        }

        let sse_modern: UpstreamManifest = serde_yaml::from_str(
            "name: a\ntransport: sse\nurl: http://u/mcp\nprotocol: \"2026-07-28\"\n",
        )
        .expect("parse");
        let err = validate_manifest_invariants(&sse_modern)
            .expect_err("sse cannot speak the stateless protocol");
        assert!(
            err.to_string().contains("sse"),
            "the refusal names the contradiction: {err}"
        );

        let sse_auto: UpstreamManifest =
            serde_yaml::from_str("name: a\ntransport: sse\nurl: http://u/mcp\n").expect("parse");
        validate_manifest_invariants(&sse_auto)
            .expect("auto on sse is fine — it resolves to the legacy handshake");
    }
}
