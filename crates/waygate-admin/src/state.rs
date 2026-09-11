//! Shared state the admin API handlers pull from. Built once at startup.
//!
//! Fields are grouped into per-plane sub-structs — identity,
//! policy, observability, servers, llm, hitl, agent, federation, dashboard —
//! so a handler reads `state.identity.tenants`, `state.policy.cedar`, etc.
//! Each plane struct's doc says what belongs there; a new store handle goes
//! into exactly one plane. Root keeps only the cross-cutting always-present
//! handles (`upstreams`, `evidence`, `public_url`, `system`). The `with_*`
//! builders keep their flat signatures and write through, so the composition
//! root is unaffected by the grouping.
//!
//! Optionally-wired store/service handles are [`Capability`] fields: the
//! capability wraps the optional handle plus its canonical
//! operator-facing unavailable-message, declared once in [`AdminState::new`].
//! Handlers guard via `require()` / `get()` / `enabled()` — never an inline
//! `ServiceUnavailable` literal (`scripts/check-capability-guards.sh`
//! enforces this). Field docs below phrase wiredness as "`Some` ⇒ … /
//! `None` ⇒ …": that refers to the wrapped optional state (`get()`), which
//! `waygate-server` populates per the stated gating.
//!
//! `audit` can legitimately be absent: production can run with no database
//! configured (audit writes go to `NullSink`); the admin audit endpoint then
//! serves an empty list rather than 500ing. `cedar` likewise: dev mode runs
//! without Cedar (auth disabled → `AllowAllGate`) — `/policies` returns
//! empty and `/policies/simulate` returns 503 with a clear message.

use std::sync::Arc;

use crate::capability::{Capability, Feature};

use waygate_apikeys::ApiKeyStore;
use waygate_as::clients::SharedConfidentialClientStore;
use waygate_as::consent::SharedConsentStore;
use waygate_as::sessions::SharedUpstreamSessionStore;
use waygate_as::store::OauthStore;
use waygate_authz::ReloadableCedar;
use waygate_catalog::SharedCatalogStore;
use waygate_manifest_store::SharedManifestStore;
use waygate_mcp::audit::{NullSink, SharedEvidence};
use waygate_policy::SharedPolicyStore;
use waygate_scim::{ScimGroupStore, ScimUserStore};
use waygate_storage::{AuditReader, BundleSigner, RetentionStore, RoutingStore, Sweeper};
use waygate_upstream::UpstreamPool;

/// The on-disk manifest set plus its canonical content hash — the success
/// payload of [`AdminState::read_manifest_set_from_disk`]. Factored out so
/// the nested return type stays under clippy's complexity threshold.
pub type DiskManifestSet = (
    std::collections::BTreeMap<String, waygate_upstream::UpstreamManifest>,
    String,
);

/// Failure outcome of [`AdminState::mirror_then`] (the atomic policy
/// mirror-then-ledger commit). Separates the safe-to-report failures — where
/// disk and ledger are left CONSISTENT — from the rare double fault that needs
/// a loud, operator-actionable error.
#[derive(Debug)]
pub enum PolicyCommitError {
    /// The on-disk mirror (validate / write) failed BEFORE the ledger was
    /// touched, so nothing was half-applied. Carries the mirror error string.
    Mirror(String),
    /// The ledger write failed; the disk mirror was rolled back (or never
    /// happened for a no-dir / non-default-tenant case), so disk + ledger are
    /// consistent. Carries the typed `PolicyError` so callers can preserve the
    /// status mapping (e.g. `NotFound` → 404).
    Ledger(waygate_policy::PolicyError),
    /// The bundle was applied to disk (the source of truth) but the LEDGER
    /// transition failed. Under file-as-truth the on-disk set WINS — the gate
    /// loads it on the next reload and the ledger reconciles to disk;
    /// disk is NOT rolled back (that would treat the ledger as authoritative and,
    /// across replicas, clobber a concurrent writer). Carries an
    /// operator-actionable message; surface it loudly so the operator knows the
    /// ledger lagged.
    DiskAhead(String),
    /// The cross-replica write turnstile was LOST: another replica
    /// advanced the on-disk policy set since this edit's base was read. Nothing
    /// was written (the CAS precedes the mirror). The caller's edit is stale —
    /// reload and retry (HTTP 409). Carries the human-readable reason.
    Conflict(String),
    /// The bundle's content already equals the live on-disk policy set, so there
    /// is nothing to apply — and a competing ledger row published from the
    /// already-current state could race a concurrent cross-replica writer
    /// (it cannot own the turnstile, since a no-op `cas(base,base)` does not
    /// advance the pointer to exclude a real `base -> H2` writer). So
    /// the write is refused as a no-op rather than recorded. Carries the reason.
    NoChange(String),
}

/// Outcome of a policy turnstile claim ([`AdminState::policy_turnstile_claim`]).
/// The `Err(PolicyCommitError::Conflict)` arm is the LOST case. The policy
/// analogue of `dashboard_server_manifests::TurnstileClaim`.
enum PolicyTurnstileClaim {
    /// Won: the pointer advanced `base -> new_hash`. The caller mirrors and, on a
    /// mirror/ledger failure, rolls the pointer back to `base`.
    Won { base: String },
    /// No turnstile ran — no policy store, or an unreadable on-disk set being
    /// repaired. The caller mirrors (a repair); nothing to roll back.
    NoTurnstile,
    /// The on-disk set ALREADY equals the target. The caller must NOT mirror
    /// (writing identical content does not advance the pointer, so a no-op CAS
    /// "wins" without claiming the slot and a concurrent real write would be
    /// clobbered); the operation is refused without a ledger transition.
    AlreadyCurrent,
}

/// Default allowlist for the Overview "What changed" feed's `admin_mutation`
/// rows: the change-request ceremony actions. The `admin_mutation` category is
/// broad (it also carries secret-retrievals, oauth/session revokes, …), so the
/// feed surfaces only these by default — the propose → approve → execute
/// lifecycle the operator actually wants visible alongside the resulting mint.
/// Operators override the set via `GATEWAY_OVERVIEW_CHANGE_FEED_ACTIONS`
/// (comma-separated); the effective list is shown read-only on the Settings
/// page. Match is exact against `audit_log.action`.
pub const DEFAULT_OVERVIEW_CHANGE_FEED_ACTIONS: &[&str] = &[
    "ChangeRequestPropose",
    "ChangeRequestApprove",
    "ChangeRequestExecute",
    "ChangeRequestDeny",
];

/// Who is calling and what they may hold: API keys/profiles/scopes/groups,
/// OAuth sessions + consent, SCIM users/groups + resolver + provisioning log,
/// RBAC, tenants, and the bearer-chain invalidation side-channels.
pub struct IdentityPlane {
    /// API-key store. `Some` ⇒ admin operations (tenant DELETE
    /// cleanup, the API-key admin REST surface when
    /// `api_keys_enabled` is also true) can read/mutate the
    /// `api_keys` table. Wired
    /// whenever a Postgres pool exists (NOT gated on the
    /// `GATEWAY_API_KEYS_ENABLED` flag), so tenant-DELETE
    /// cleanup can revoke before bulk-deleting api_key
    /// profiles even when runtime API-key auth is off. The
    /// runtime auth path (bearer chain validator) and the
    /// UI feature flag are gated separately via
    /// [`Self::api_keys_feature`].
    pub api_keys: Capability<ApiKeyStore>,
    /// Feature flag for the API-key
    /// admin REST surface and onboarding SCIM key minting.
    /// `true` only when `GATEWAY_API_KEYS_ENABLED=true` AND
    /// the bearer chain actually installs the API-key
    /// validator. Decoupled from `api_keys.is_some()` so that
    /// admin cleanup paths (which need the store) can run
    /// without exposing mint/list endpoints that would
    /// produce unusable keys (a key minted while the
    /// validator is absent cannot authenticate). Without this
    /// flag, a deployment with API-key auth temporarily
    /// disabled could mint SCIM API keys during tenant
    /// onboarding that appear usable but 401 every request
    /// until the flag is re-enabled.
    pub api_keys_feature: Feature,
    /// API-key mint profile store backing
    /// `/api/v1/admin/api_key_profiles/*`. Same DB-pool gating
    /// pattern as the other admin stores.
    pub api_key_profiles: Capability<Arc<dyn waygate_apikeys::ProfileStore>>,
    /// The same `ApiKeyValidator` instance the bearer middleware uses.
    /// The tenant DELETE cleanup path calls `invalidate_all()`
    /// on it after the cascade revoke so freshly-revoked keys
    /// cannot still authenticate against the in-memory cache for
    /// the remainder of its TTL. Pass the same Arc the bearer
    /// chain consumes — both surfaces must see the invalidation
    /// for it to bite.
    pub api_key_validator: Option<Arc<waygate_apikeys::ApiKeyValidator>>,
    /// OAuth refresh-token store. `Some` ⇒ `/admin/identities` shows the
    /// live OAuth-session list with chain-revoke; `None` ⇒ the OAuth
    /// section is hidden. Constructed by `waygate-server` only when the
    /// built-in AS is enabled (`GATEWAY_AS_ENABLED=true`).
    pub oauth: Capability<OauthStore>,
    /// Tier-A durable upstream-session store. `Some` ⇒ the admin
    /// `/api/v1/admin/upstream_sessions` list + revoke endpoints
    /// are live; `None` ⇒ both 503 with a message
    /// matching the audit-endpoint pattern. Constructed by
    /// `waygate-server` only when the built-in AS is enabled AND a
    /// Postgres pool exists AND `GATEWAY_AUTHENTIK_ISSUER` is set,
    /// matching the same gating the per-call Tier-A read path uses.
    pub upstream_sessions: Capability<SharedUpstreamSessionStore>,
    /// OAuth consent grant store backing
    /// `/api/v1/admin/oauth_consent/*`. Same DB-pool gating
    /// as `upstream_sessions` — `Some` when a Postgres pool
    /// exists, `None` ⇒ endpoints 503. Pass the same
    /// `SharedConsentStore` the AS callback writes through
    /// so the admin read surface and the callback writer
    /// observe the same rows; admin revoke + callback
    /// re-consent therefore share a single source of
    /// truth.
    pub consent: Capability<SharedConsentStore>,
    /// EMA confidential-client registry. `Some` ⇒ the
    /// `/api/v1/admin/confidential-clients` endpoints register/list/delete the
    /// clients allowed to redeem ID-JAGs; `None` ⇒ they 503. Same store handle
    /// the redeem path authenticates against.
    pub confidential_clients: Capability<SharedConfidentialClientStore>,
    /// SCIM 2.0 Users store backing
    /// `/scim/v2/Users`. `Some` ⇒ the SCIM endpoints serve
    /// from Postgres; `None` ⇒ they 503 with a "SCIM store
    /// not configured" message. Set via
    /// [`AdminState::with_scim_users`]. `waygate-server`
    /// constructs whenever a Postgres pool exists.
    pub scim_users: Capability<Arc<dyn ScimUserStore>>,
    /// SCIM 2.0 Groups store backing
    /// `/scim/v2/Groups`. Same DB-pool gating as
    /// `scim_users`. Set via
    /// [`AdminState::with_scim_groups`].
    pub scim_groups: Capability<Arc<dyn ScimGroupStore>>,
    /// SCIM `(tenant, sub) → ResolvedPrincipal` resolver
    /// for the dashboard's "effective permissions for subject"
    /// query. Same Arc the bearer-middleware `PgScimEnricher`
    /// uses internally, so the admin lookup sees exactly what
    /// the runtime would see for the same sub (including the
    /// fail-closed ambiguous-match path). `None` ⇒ the lookup
    /// form renders a "SCIM resolver not configured" empty
    /// state; same DB-pool gating pattern as the other SCIM
    /// fields. Set via [`AdminState::with_scim_resolver`].
    pub scim_resolver: Capability<Arc<dyn waygate_scim::ScimResolver>>,
    /// The same `PgScimEnricher`
    /// instance the bearer middleware uses. SCIM user handlers invalidate
    /// affected subjects, while group handlers invalidate all entries after a
    /// successful mutation because membership changes may affect many
    /// principals. Pass the same Arc the chained enricher consumes — both
    /// surfaces must see the invalidation for it to be effective.
    pub scim_enricher: Option<Arc<waygate_scim::PgScimEnricher>>,
    /// SCIM provisioning-log timeline store. `Some` ⇒
    /// the SCIM REST handlers append structured event rows on
    /// every successful mutation (best-effort — failure logs
    /// and the SCIM mutation still commits), and the dashboard
    /// SCIM page renders a "Provisioning log" timeline + per-
    /// row drawer fed from this same store. `None` ⇒ both
    /// surfaces are absent; the existing `audit_log` writes
    /// stay in place. Same DB-pool gating as the other admin
    /// stores; set via
    /// [`AdminState::with_scim_provisioning_log`].
    pub scim_provisioning_log: Capability<
        Arc<dyn waygate_dashboard_stores::scim_provisioning_log::ScimProvisioningLogStore>,
    >,
    /// RBAC store backing
    /// `/api/v1/admin/rbac/*`. Same DB-pool gating as
    /// `scim_users` / `scim_groups`. Set via
    /// [`AdminState::with_rbac_store`]. `waygate-server`
    /// constructs whenever a Postgres pool exists.
    pub rbac: Capability<Arc<dyn waygate_rbac::RbacStore>>,
    /// The same
    /// `RbacEnricher` instance the bearer middleware uses.
    /// Admin RBAC and group-catalog handlers call `invalidate_all()` on it
    /// after a successful mutation for prompt process-local convergence of
    /// ordinary roles. Control-plane role resolutions are never cached and
    /// recheck durable SCIM membership in Postgres on every request.
    pub rbac_enricher: Option<Arc<waygate_rbac::RbacEnricher>>,
    /// Canonical tenants registry backing
    /// `/api/v1/admin/tenants/*`. Same DB-pool gating as
    /// `scim_users` / `rbac`. Set via
    /// [`AdminState::with_tenant_store`]. `waygate-server`
    /// constructs whenever a Postgres pool exists.
    pub tenants: Capability<Arc<dyn waygate_tenants::TenantStore>>,
    /// Cross-domain tenant deletion transaction spanning the registry row and
    /// policy-bundle ledger. Kept separate from the registry store so the two
    /// domain crates retain their table ownership.
    pub tenant_lifecycle: Capability<Arc<dyn crate::tenants::TenantLifecycleStore>>,
    /// The same `PgTenantEnricher` instance the
    /// bearer middleware uses. Tenant admin handlers call
    /// `invalidate(id)` after a successful mutation so a freshly
    /// suspended or deleted tenant takes effect on the next
    /// request instead of after the 60s TTL. Pass the same Arc the
    /// chained enricher consumes — both surfaces must see the
    /// invalidation for it to be effective.
    pub tenant_enricher: Option<Arc<waygate_tenants::PgTenantEnricher>>,
    /// Scope registry store backing the
    /// read-only Scopes page (`/scopes`). Same DB-pool gating as the
    /// other admin stores: `None` ⇒ the page renders its
    /// "store not configured" state.
    pub scopes: Capability<Arc<dyn waygate_apikeys::ScopeStore>>,
    /// Group catalog read-view backing the
    /// read-only Groups page (`/groups`). Reads the unified
    /// `scim_groups` table (SCIM + local groups). Distinct from
    /// [`Self::scim_groups`] (the SCIM 2.0 CRUD store). Same DB-pool
    /// gating: `None` ⇒ the page renders its "store not configured"
    /// state.
    pub groups: Capability<Arc<dyn waygate_apikeys::GroupStore>>,
}

/// What is allowed: the Cedar engine, the policy-bundle ledger + on-disk
/// mirror machinery, break-glass overrides, inspection rules, and rate-limit
/// policies.
pub struct PolicyPlane {
    /// Reloadable Cedar wrapper so tenant-selected policy diagnostics and
    /// simulation reflect the latest file-backed default and ledger-backed
    /// tenant engines after reload, without restarting.
    pub cedar: Capability<Arc<ReloadableCedar>>,
    /// Durable policy-bundle store. `Some` ⇒ the
    /// `/api/v1/policy_bundles` admin endpoints serve from the
    /// Postgres `policy_bundles` table; `None` ⇒ they 503 (no DB
    /// configured), matching the catalog/audit pattern. Set via
    /// [`AdminState::with_policy_store`] (a builder rather than a
    /// `new` arg to avoid churning the existing call sites).
    pub policy_store: Capability<SharedPolicyStore>,
    /// Whether the dashboard / REST may MUTATE policy bundles. Enabled by
    /// default; disabled (with the operator-facing reason surfaced in the UI
    /// and 403 bodies) when `GATEWAY_POLICY_EDITING=off` (another governed
    /// operator path owns the live volume and the dashboard is a window), or
    /// when the policies directory is not writable (a publish would fail at the
    /// disk mirror, so editing is refused cleanly rather than appearing then
    /// erroring). Set via [`AdminState::with_policy_editing_off_reason`].
    pub policy_editing: Feature,
    /// On-disk Cedar policy directory (`GATEWAY_POLICIES_DIR`) — the source
    /// of truth under the server-config redesign (file-as-truth, see
    /// `docs/server-config-source-of-truth.md` and `resolve_policies`
    /// in `waygate-server`). `Some` ⇒ a dashboard / REST policy publish or
    /// rollback mirrors the chosen bundle onto disk (the boot/SIGHUP/Reload
    /// source) before recording the ledger transition; `None` ⇒ test/dev
    /// composition with no on-disk surface, so the mirror step is skipped.
    /// Set via [`AdminState::with_policies_dir`]. The policy analogue of
    /// [`ServersPlane::servers_dir`].
    pub policies_dir: Option<std::path::PathBuf>,
    /// The policy analogue of [`ServersPlane::manifest_write_lock`]: serializes
    /// dashboard / REST policy publish + rollback within this process so the
    /// mirror-to-disk and ledger transition stay atomic per replica. Separate
    /// from the manifest lock so a policy edit and a manifest edit don't
    /// serialize against each other needlessly. Always present (cheap).
    pub policy_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Policy config-health signal. `Some` ⇒ the Policies
    /// page reads it for a prominent banner when the on-disk `policies/*.cedar`
    /// set is broken / ledger-recovered and the gateway is serving a stale policy
    /// set. A SEPARATE handle from [`ServersPlane::config_health`] (manifests) so the two
    /// banners never clobber each other. `None` in tests / compositions that
    /// don't wire it.
    pub policy_config_health: Option<waygate_upstream::SharedConfigHealth>,
    /// Break-glass override store backing
    /// `/api/v1/admin/break_glass/*` (mint/list/revoke) AND
    /// consulted on Deny by the `BreakGlassGate` wrapper
    /// around the Cedar gate. Same `SharedBreakGlassStore`
    /// is handed to both surfaces from `waygate-server::main`
    /// when a Postgres pool exists; admin reads, mints, and
    /// revokes the same rows the runtime claims at use-time.
    /// `None` ⇒ admin endpoints 503 AND no override path —
    /// Deny is final.
    pub break_glass: Capability<waygate_authz::SharedBreakGlassStore>,
    /// Per-tenant inspection-rules store
    /// backing `/api/v1/admin/inspection_rules/*`. Same
    /// DB-pool gating — `Some` ⇒ admin CRUD is live;
    /// `None` ⇒ endpoints 503. The runtime
    /// consumer reads from this same store.
    pub inspection_rules: Capability<waygate_dashboard_stores::inspection_rules::SharedRulesStore>,
    /// Rate-limit policies CRUD store backing
    /// `/api/v1/admin/rate_limit_policies/*`. Distinct from the
    /// hot-path `QuotaService` (which only consumes tokens) — the
    /// admin handler navigates the policies table by id + writes,
    /// the consumer only reads-and-debits. Same DB-pool gating as
    /// the other admin stores: `None` ⇒ endpoints return 503.
    pub rate_limit_policies: Capability<Arc<dyn waygate_quota::RateLimitPolicyStore>>,
}

/// What happened: the audit reader, evidence routing/retention/sweep, the
/// signed-bundle exporter, and the trace-link template.
pub struct ObservabilityPlane {
    pub audit: Capability<Arc<dyn AuditReader>>,
    /// Per-tenant evidence routing store.
    /// `Some` ⇒ the `/api/v1/audit/routing` GET/PUT/DELETE
    /// endpoints serve from the `tenant_evidence_routing`
    /// table; `None` ⇒ they 503 (no DB configured), matching
    /// the audit/catalog/policy pattern. Set via
    /// [`AdminState::with_routing_store`].
    pub routing: Capability<Arc<dyn RoutingStore>>,
    /// Per-tenant retention policy store. `Some` ⇒
    /// the `/api/v1/audit/retention` GET/PUT/DELETE endpoints serve
    /// from the `evidence_retention_policy` table; `None` ⇒ they
    /// 503, matching the audit/catalog/policy/routing pattern.
    /// Set via [`AdminState::with_retention_store`].
    pub retention: Capability<Arc<dyn RetentionStore>>,
    /// Pool-bound retention sweeper. `Some` ⇒ the
    /// `/api/v1/audit/sweep` admin endpoint can run a sweep on
    /// demand against the configured Postgres pool; `None` ⇒ the
    /// endpoint 503s. Set via [`AdminState::with_sweeper`].
    /// DB-level authorisation is gated by migration 0018's
    /// SECURITY DEFINER wrapper + marker-coverage check.
    pub sweeper: Capability<Arc<dyn Sweeper>>,
    /// Ed25519 signing config for the
    /// `/api/v1/audit/bundle` admin endpoint. `Some` ⇒ the
    /// endpoint signs and serves bundles; `None` ⇒ it
    /// 503s with a "signing key not configured" message.
    /// Loaded from `GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM`
    /// at boot via [`AdminState::with_bundle_signer`].
    pub bundle_signer: Capability<Arc<BundleSigner>>,
    /// Optional Grafana Explore → Tempo URL template for the
    /// activity-drawer "View trace" link. Contains a `{trace_id}` placeholder
    /// the drawer substitutes with the row's trace_id. `None` (unset) hides the
    /// link entirely. Set via [`AdminState::with_trace_url_template`] from the
    /// `GATEWAY_TRACE_URL_TEMPLATE` env var.
    pub trace_url_template: Option<String>,
}

/// What is served: the governed catalog, the server-manifest ledger + its
/// on-disk file-as-truth machinery, and the built-in surface descriptors.
pub struct ServersPlane {
    /// Governed-catalog store. `Some` ⇒ the `/api/v1/catalog/*`
    /// read endpoints serve from the Postgres catalog tables;
    /// `None` ⇒ they 503 (no DB configured), matching the
    /// audit-endpoint pattern. Constructed by `waygate-server`
    /// whenever a Postgres pool exists.
    pub catalog: Capability<SharedCatalogStore>,
    /// Durable server-manifest store. `Some` ⇒ the
    /// `/api/v1/server_manifests` admin endpoints (and the
    /// dashboard editor) serve from the Postgres `server_manifests`
    /// table; `None` ⇒ they 503 (no DB configured), matching
    /// `policy_store`. Set via [`AdminState::with_manifest_store`].
    pub manifest_store: Capability<SharedManifestStore>,
    /// On-disk upstream-manifest directory (`GATEWAY_SERVERS_DIR`) — the
    /// source of truth under the server-config redesign (file-as-truth,
    /// see `docs/server-config-source-of-truth.md`). `Some` ⇒ the admin
    /// write surfaces mirror an edit onto disk (the boot/SIGHUP/Reload
    /// source) before recording the ledger snapshot; `None` ⇒ test/dev
    /// composition with no on-disk surface, so the file-write step is
    /// skipped. Set via [`AdminState::with_servers_dir`].
    pub servers_dir: Option<std::path::PathBuf>,
    /// Serializes dashboard manifest writes within this process so the
    /// dual-write (DB ledger + on-disk mirror) is atomic per replica —
    /// two concurrent admin edits can't interleave and leave disk
    /// reflecting an older version than the ledger's newest published.
    /// Always present (cheap). Multi-replica serialization is handled
    /// separately by the DB turnstile (`dashboard_server_manifests::turnstile_cas`);
    /// this lock covers the single-replica case within this process.
    pub manifest_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Config-health signal. `Some` ⇒ the Servers page reads it for a
    /// prominent banner when a load/reload was refused and the gateway is
    /// serving a stale set. The same handle `waygate-server` hands the SIGHUP
    /// reload task, so the dashboard reflects boot/SIGHUP health. `None` in
    /// tests / compositions that don't wire it.
    pub config_health: Option<waygate_upstream::SharedConfigHealth>,
    /// Static descriptors of the gateway's built-in MCP namespaces
    /// (`gateway-admin.*`, `gateway-observe.*`, `gateway-control.*`) — the
    /// gateway's OWN tool surfaces, answered locally rather than proxied to an
    /// upstream, so they never appear in the manifest/catalog server lists.
    /// Injected at boot via [`AdminState::with_builtin_surfaces`] for the
    /// read-only "Built-in surfaces" operator view; empty in tests/dev. No
    /// secrets — safe to render in HTML / return over the read API.
    pub builtin_surfaces: Vec<waygate_mcp::BuiltinSurfaceDescriptor>,
    /// Reconciles the governed catalog from a manifest set the dashboard
    /// just applied to the live pool. `Some` ⇒ `waygate-server` wired the
    /// same catalog import the doorbell/SIGHUP reload path runs, so a
    /// dashboard Reload cannot leave the pool and the catalog on different
    /// classification modes or approved behavior versions (the later
    /// doorbell tick observes a no-op pool reload and skips its own
    /// import). `None` ⇒ no catalog database configured; the reconcile is
    /// skipped exactly like the doorbell path's pool gate.
    pub catalog_reconcile: Option<SharedCatalogReconcile>,
}

/// Callback that reconciles the governed catalog from the manifest set the
/// caller just applied to the live pool. Returns `(servers, tools)` counts
/// imported; errors are strings because the caller only logs them
/// (non-fatal — the existing catalog is preserved).
pub type SharedCatalogReconcile = Arc<
    dyn Fn(
            std::collections::BTreeMap<String, waygate_upstream::UpstreamManifest>,
        ) -> futures_util::future::BoxFuture<'static, Result<(u64, u64), String>>
        + Send
        + Sync,
>;

/// The inference plane: model catalog, credential pool health, and the
/// routing resolver (present only when /v1/chat/completions is mounted).
pub struct LlmPlane {
    /// Inference-plane LLM model catalog. `Some` ⇒ the
    /// read-only `/llm_models` dashboard page lists the caller's tenant's
    /// configured models from the Postgres `llm_models` table; `None` ⇒
    /// the page renders the "store not configured" card, matching the
    /// catalog/audit pattern. Set via
    /// [`AdminState::with_llm_model_catalog`] (a builder rather than a
    /// `new` arg to avoid churning the existing call sites).
    pub llm_models: Capability<waygate_storage::SharedLlmModelCatalog>,
    /// The shared in-process LLM credential store (the SAME
    /// `Arc` the dispatcher resolves bearers from). `Some` ⇒ the read-only
    /// `/llm_credentials` dashboard panel shows live per-(provider, label) pool
    /// health; `None` ⇒ the panel renders the "not configured" card (no LLM
    /// path / dispatcher). Set via [`AdminState::with_llm_credentials`].
    pub llm_credentials: Capability<std::sync::Arc<waygate_llm_credentials::LlmCredentialStore>>,
    /// The LLM routing resolver — the SAME `Arc<dyn LlmModelResolver>` the
    /// `/v1/chat/completions` + `/v1/models` routes use, present ONLY when the
    /// inference plane is actually mounted (`llm_deps` exists). `None` in an
    /// MCP-only deployment, even though `try_invocation` is always wired for the
    /// MCP try-it path — so the `/chat` page uses THIS (not `try_invocation`) as
    /// its "inference configured" signal, and filters its model picker to models
    /// the resolver can dispatch (parity with `/v1/models`). Defaults `None`.
    pub llm_resolver: Option<std::sync::Arc<dyn waygate_llm_dispatch::LlmModelResolver>>,
}

/// Human-in-the-loop control-plane changes: the change-request store,
/// out-of-band notifier, secret-return crypto, the approvals WebSocket hub,
/// and the two-approver knob.
pub struct HitlPlane {
    /// Durable Code Mode execution journal used to list and resolve
    /// approval-bound data-plane mutations.
    pub codemode_executions: Capability<waygate_codemode::SharedExecutionStore>,
    /// Active skill catalog used by distribution review.
    pub skills: Capability<std::sync::Arc<waygate_skills::ReloadableSkillCatalog>>,
    pub reviewed_skills: Capability<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
    /// Change-request store backing
    /// `/api/v1/admin/change_requests/*` (propose + poll). `Some`
    /// when a Postgres pool exists; `None` ⇒ the propose/status
    /// endpoints 503.
    pub change_requests: Capability<waygate_changeset::SharedChangeRequestStore>,
    /// Out-of-band notifier fired when a change is
    /// proposed (so a human away from the dashboard learns a decision is
    /// waiting). `None` ⇒ no out-of-band push (the dashboard review queue
    /// still surfaces the change). Shared with the built-in MCP tools so both
    /// propose surfaces notify.
    pub change_notifier: Option<crate::change_notify::SharedChangeNotifier>,
    /// HITL secret-return channel: AES-256-GCM keyring used to encrypt an
    /// executor-produced secret (e.g. a freshly minted API key) at rest in
    /// `change_request_secrets`, and to decrypt it on the maker's single
    /// burn-on-read retrieve. `None` ⇒ no `GATEWAY_CHANGE_SECRET_KEY`
    /// configured, so secret-producing executors (`api_key.mint`) fail
    /// closed at execute (`ExecError::Unavailable`) rather than persist a
    /// plaintext secret. Reuses `waygate_as`'s proven token-envelope crypto.
    pub change_secret_crypto: Capability<waygate_as::UpstreamCrypto>,
    /// Reads a document a maker uploaded through the governed file plane so it
    /// can be submitted as a change request's `content` / `statement` /
    /// `instructions` param instead of riding inline through MCP JSON-RPC.
    /// `None` ⇒ the gateway has no file storage, and a submission naming a
    /// file is refused with that message while inline submission still works.
    /// See [`crate::param_files`].
    pub proposal_files: Capability<Arc<dyn crate::param_files::ProposalFileReader>>,
    /// In-process HITL approval fan-out
    /// hub backing the WebSocket route
    /// `/api/v1/admin/approval_grants/subscribe`. Always
    /// constructed — the hub is in-memory, zero-cost
    /// when no subscribers attach, and lets the
    /// invocation pipeline publish without a None-check.
    /// `waygate-server` also wires the same `Arc` into
    /// `DefaultInvocationService` via the
    /// `HitlNotifier` trait.
    pub hitl_hub: Arc<crate::hitl_ws::ApprovalHub>,
    /// Two-approver rule for catalog server promotion.
    /// When `true`, `POST /api/v1/catalog/servers/{id}/approve` refuses
    /// (409 Conflict) when the calling actor is the same as the most
    /// recent `approved`-action actor for this server. Default `false`
    /// preserves existing single-actor approval. Set via
    /// [`AdminState::with_two_approver_mode`]; `waygate-server` reads
    /// `GATEWAY_REQUIRE_TWO_APPROVALS` at boot.
    pub require_two_approvals: bool,
    /// 30s TTL cache for the sidebar Decisions badge, keyed by tenant:
    /// `(computed_at, pending_count)`. Internal — initialized empty, no
    /// constructor argument; see `dashboard::decisions_badge`.
    pub decisions_badge_cache:
        tokio::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, String)>>,
}

/// The dashboard's chat agent: per-tenant agent configs, conversation
/// persistence, in-chat approval rendezvous, and the governed read-tool
/// caller.
pub struct AgentPlane {
    /// Per-tenant agent-config store backing the
    /// "Gateway Agents" dashboard tab (and, later, read by the agent runtime
    /// loop). Same DB-pool gating as the other admin stores — `Some` ⇒ the tab
    /// can list/create/edit/delete agents; `None` ⇒ the tab shows the "store
    /// not configured" card. Set via [`AdminState::with_agent_configs`].
    pub agent_configs: Capability<waygate_dashboard_stores::agent_config::SharedAgentConfigStore>,
    /// Per-operator agent **conversation** persistence
    /// (owner-scoped on `tenant_id` + `user_sub`). `Some` ⇒ the agent-chat page
    /// can store/list/replay conversations; `None` (no DB pool) ⇒ chat still
    /// works for a single turn but nothing is persisted. Set via
    /// [`AdminState::with_conversations`].
    pub conversations: Capability<waygate_storage::SharedConversationStore>,
    /// In-chat side-effects approval rendezvous. The agent
    /// loop parks a side-effecting tool call here and blocks; the operator's
    /// `POST /agent_chat/approve` resolves it. In-memory + always present (no DB
    /// gating) — a process restart simply drops parked approvals, which the
    /// gate's timeout turns into rejections.
    pub chat_approvals: waygate_agent_runtime::chat_approvals::SharedChatApprovals,
    /// The governed read-built-in caller the chat
    /// agent dispatches a `gateway-observe.*` allowlist entry through. `Some` ⇒
    /// the agent can reach the gateway's own read tools (audit, resources, policy
    /// simulation) under the SAME Cedar overlay + scope floor a direct MCP call
    /// gets; `None` ⇒ the agent stays upstream-only. Injected at the composition
    /// root via [`AdminState::with_assist_read`].
    pub assist_read: Option<waygate_mcp::SharedAssistReadTools>,
}

/// Tier-C gateway-to-gateway federation: the peer registry and the JWKS
/// cache invalidated on peer rotation.
pub struct FederationPlane {
    /// Federated gateway peer registry
    /// backing `/api/v1/admin/federated_peers/*`. Same
    /// DB-pool gating — `Some` ⇒ admin CRUD is live;
    /// `None` ⇒ endpoints 503. The JWKS
    /// fetcher + peer-assertion validator consume
    /// this same store on the dispatch path.
    pub federated_peers: Capability<waygate_federation::SharedPeersStore>,
    /// The JWKS cache the
    /// per-call `PeerJwtValidator` reads from. Held on
    /// `AdminState` so the PATCH and DELETE handlers can
    /// `cache.forget(peer_id)` immediately after a
    /// successful store mutation. Without this, an
    /// operator rotating away from a compromised peer
    /// `issuer` / `jwks_url` would leave the OLD cached
    /// entry trusted indefinitely if the NEW JWKS URL
    /// happens to be unreachable — the refresher
    /// deliberately retains the previous entry on fetch
    /// failure. Forgetting on mutation forces the next
    /// refresh cycle to start from a clean slate.
    /// `None` ⇒ admin endpoints still work but the cache
    /// is not invalidated on rotation; used in tests that
    /// don't wire a cache.
    pub federated_peers_cache: Option<waygate_federation::jwks::SharedPeerJwksCache>,
}

/// Dashboard-page persistence and affordances that belong to no domain
/// plane: playground scenarios, activity saved views, MCP task rows, the
/// try-it invocation handle, and the Overview change-feed filter.
pub struct DashboardPlane {
    /// Per-tenant Cedar playground saved-scenarios
    /// store. `Some` ⇒ the playground page renders the Saved
    /// scenarios sidebar + Save/Delete affordances; `None` ⇒
    /// the page hides the affordances and the playground stays
    /// stateless. Same DB-pool gating as the
    /// other admin stores; `waygate-server` constructs a
    /// `PgPlaygroundScenarioStore` whenever a Postgres pool
    /// exists. Set via [`AdminState::with_playground_scenarios`].
    pub playground_scenarios: Capability<
        Arc<dyn waygate_dashboard_stores::playground_scenarios::PlaygroundScenarioStore>,
    >,
    /// Per-tenant activity-page saved-views store.
    /// `Some` ⇒ the activity page renders a Saved-views sidebar
    /// section and accepts Save / Delete / Load actions for named
    /// filter combinations. `None` ⇒ the saved-views section is
    /// hidden entirely; the rest of the activity page (facets,
    /// filter form, results) is unaffected. Same DB-pool gating
    /// as the other admin stores; `waygate-server` constructs a
    /// `PgActivitySavedViewStore` whenever a Postgres pool
    /// exists. Set via [`AdminState::with_activity_saved_views`].
    pub activity_saved_views:
        Capability<Arc<dyn waygate_dashboard_stores::activity_saved_views::ActivitySavedViewStore>>,
    /// MCP Tasks store backing
    /// `/api/v1/admin/tasks/*`. Same DB-pool gating as
    /// the other admin stores — `Some` when a Postgres
    /// pool exists, `None` ⇒ endpoints 503.
    pub tasks: Capability<waygate_dashboard_stores::tasks::SharedTaskStore>,
    /// Governed "Try this tool" invocation handle. `Some` ⇒ the
    /// dashboard's per-tool try-it surface routes a real call through the
    /// **same** `authorize → step-up → quota → HITL → audit → redact`
    /// pipeline an MCP client hits — built by the shared
    /// `waygate_mcp::build_default_invocation_service`, so it can never
    /// diverge into a weaker-governance bypass. `None` ⇒ the try-it
    /// endpoint returns a "not available in this deployment" fragment and
    /// renders no invoke form. Set via [`AdminState::with_try_invocation`].
    ///
    /// The production composition root (`waygate-server`) **always** wires
    /// this — the invocation pipeline runs fine with no database (audit /
    /// quota / HITL stages just no-op), so try-it is not DB-gated. `None`
    /// is therefore the default for the test/`new()` `AdminState` and any
    /// future composition that omits the setter; it is a defensive
    /// graceful-degradation path, not a normal runtime posture.
    pub try_invocation: Option<waygate_mcp::SharedInvocation>,
    /// Allowlist of `audit_log.action` values surfaced from the broad
    /// `admin_mutation` category on the Overview "What changed" feed —
    /// the change-request ceremony (propose / approve / execute / deny) by
    /// default. Without this filter the feed would show every admin
    /// mutation (secret-retrievals, oauth/session revokes, …). Always
    /// populated — `new()` defaults to
    /// [`DEFAULT_OVERVIEW_CHANGE_FEED_ACTIONS`]; `waygate-server` overrides
    /// from `GATEWAY_OVERVIEW_CHANGE_FEED_ACTIONS` via
    /// [`AdminState::with_overview_change_feed_actions`]. Shown read-only on
    /// the Settings page.
    pub overview_change_feed_actions: Vec<String>,
}

pub struct AdminState {
    pub upstreams: Arc<UpstreamPool>,
    /// Write-side `EvidenceRecorder` so mutating admin handlers (API-key
    /// mint / rename / revoke, and every `AdminMutation`-emitting handler
    /// more broadly) can persist lifecycle events to `audit_log` rather than
    /// just `tracing`. Always populated — `waygate-server` passes
    /// `NullSink` when no DB is configured, and `NullSink`'s
    /// `record_best_effort` is a log-and-drop noop so callers don't
    /// need to guard.
    pub evidence: SharedEvidence,
    /// Gateway's canonical external URL (e.g. `https://mcp.example.com`).
    /// Templates that render copy-pasteable client config (Codex's
    /// `[mcp_servers.<name>].url`) substitute this at render time so the
    /// operator never sees a `<gateway-public-url>` placeholder.
    pub public_url: String,
    /// Frozen-at-boot system info snapshot for the
    /// `/admin/t/{tenant}/settings` page (JWKS lifecycle,
    /// introspection config, capability flags, MCP spec
    /// version). Always populated — `new()` defaults to
    /// [`SystemInfo::unknown()`], `waygate-server` overrides via
    /// [`AdminState::with_system_info`] from `Config` + the
    /// constructed `IdentityKeyring`. The struct never carries
    /// secrets (introspection client_secret is elided), so
    /// every field is safe to render in HTML.
    pub system: Arc<SystemInfo>,
    /// See [`IdentityPlane`].
    pub identity: IdentityPlane,
    /// See [`PolicyPlane`].
    pub policy: PolicyPlane,
    /// See [`ObservabilityPlane`].
    pub observability: ObservabilityPlane,
    /// See [`ServersPlane`].
    pub servers: ServersPlane,
    /// See [`LlmPlane`].
    pub llm: LlmPlane,
    /// See [`HitlPlane`].
    pub hitl: HitlPlane,
    /// See [`AgentPlane`].
    pub agent: AgentPlane,
    /// See [`FederationPlane`].
    pub federation: FederationPlane,
    /// See [`DashboardPlane`].
    pub dashboard: DashboardPlane,
}

/// Frozen-at-boot system info snapshot rendered on the
/// dashboard Settings page. All fields are safe to
/// surface — no secrets, no live mutable state. Boot
/// constructs once from [`crate::AdminState::with_system_info`].
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// `"dev"` or `"prod"` — from `GATEWAY_DEPLOYMENT_PROFILE`.
    pub deployment_profile: &'static str,
    /// `"enforce"` or `"disabled"` — from `GATEWAY_AUTH_MODE`.
    /// `"disabled"` is the dev-only synthetic-admin path.
    pub auth_mode: &'static str,
    /// `waygate_mcp::MCP_SPEC_VERSION` — the primary (newest) MCP spec
    /// version the gateway serves.
    pub mcp_spec_version: &'static str,
    /// `waygate_mcp::SUPPORTED_MCP_SPEC_VERSIONS` — every spec version the
    /// gateway serves, newest first (2026-07-28 statelessly, earlier
    /// revisions on sessions).
    pub mcp_spec_versions: &'static [&'static str],
    /// `env!("CARGO_PKG_VERSION")` of the running binary.
    pub gateway_version: &'static str,
    /// Gateway-as-AS status: `true` when the built-in OAuth
    /// Authorization Server is enabled
    /// (`GATEWAY_AS_ENABLED=true`).
    pub as_enabled: bool,
    /// `true` when `GATEWAY_ACCEPT_UPSTREAM_TOKENS=true`.
    /// Deprecated upstream-bearer passthrough; the Settings
    /// page surfaces a warning when on.
    pub accept_upstream_tokens: bool,
    /// JWKS lifecycle snapshot. `None` only when the gateway
    /// boots without an identity issuer (auth-disabled dev
    /// path); production deployments always have it.
    pub jwks: Option<JwksSummary>,
    /// RFC 7662 token-introspection summary. `Some` when the
    /// `GATEWAY_INTROSPECTION_*` env vars are set; `None`
    /// otherwise. Never carries `client_secret`.
    pub introspection: Option<IntrospectionSummary>,
    /// Per-mint TTL for gateway-issued identity tokens
    /// (`IdentityConfig.ttl`). `None` when no identity issuer
    /// is configured.
    pub identity_token_ttl_secs: Option<u64>,
}

impl SystemInfo {
    /// Boot-default for tests and dev paths that don't supply
    /// a real snapshot. `waygate-server` always overrides via
    /// [`AdminState::with_system_info`].
    pub fn unknown() -> Self {
        Self {
            deployment_profile: "unknown",
            auth_mode: "unknown",
            mcp_spec_version: "unknown",
            mcp_spec_versions: &[],
            gateway_version: "unknown",
            as_enabled: false,
            accept_upstream_tokens: false,
            jwks: None,
            introspection: None,
            identity_token_ttl_secs: None,
        }
    }
}

/// JWKS lifecycle snapshot for the Settings page. Reflects
/// `IdentityKeyring` state captured once at boot — kid
/// rotation requires a restart, so a single snapshot is
/// authoritative.
#[derive(Debug, Clone)]
pub struct JwksSummary {
    /// The `kid` of the active signing key.
    pub active_kid: String,
    /// All `kid`s in published JWKS order — active first, then
    /// verify-only kids in ascending order (matches
    /// `IdentityKeyring::kids()`).
    pub all_kids: Vec<String>,
    /// Fully-qualified URL where the JWKS document is served
    /// (e.g. `https://mcp.example.com/.well-known/jwks.json`).
    pub jwks_url: String,
}

/// Token-introspection summary. Subset of
/// `waygate_oidc::IntrospectionConfig` with the
/// secret-bearing `client_secret` deliberately omitted.
///
/// `active` distinguishes "env-vars
/// set and the validator IS on the bearer chain" from
/// "env-vars set but the bearer chain skipped wiring it
/// because the AS-mode / upstream-tokens gate is closed".
/// Without this flag the Settings page mis-reports the
/// second case as enabled, which contradicts the actual
/// dispatch posture.
#[derive(Debug, Clone)]
pub struct IntrospectionSummary {
    pub introspection_url: String,
    pub client_id: String,
    pub max_positive_ttl_secs: u64,
    pub negative_ttl_secs: u64,
    /// `true` when the bearer chain installed the
    /// `OpaqueTokenValidator`. `false` when the env triple is
    /// set but the boot logic gated the validator off
    /// (`GATEWAY_AS_ENABLED=true` AND
    /// `GATEWAY_ACCEPT_UPSTREAM_TOKENS!=true`), matching the
    /// boot-time WARN at `waygate-server::main`.
    pub active: bool,
}

impl AdminState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstreams: Arc<UpstreamPool>,
        cedar: Option<Arc<ReloadableCedar>>,
        audit: Option<Arc<dyn AuditReader>>,
        evidence: SharedEvidence,
        api_keys: Option<ApiKeyStore>,
        oauth: Option<OauthStore>,
        upstream_sessions: Option<SharedUpstreamSessionStore>,
        catalog: Option<SharedCatalogStore>,
        public_url: String,
    ) -> Self {
        Self {
            upstreams,
            evidence,
            public_url,
            // SystemInfo is a Settings-page rendering
            // detail; default to the "unknown" snapshot so
            // tests and dev paths boot without churning the
            // `new()` arg list. `waygate-server` always
            // overrides via `.with_system_info(...)`.
            system: Arc::new(SystemInfo::unknown()),
            identity: IdentityPlane {
                api_keys: Capability::new("api-key store not configured", api_keys),
                // Default OFF; main.rs enables via
                // `.with_api_keys_enabled(true)` only when
                // GATEWAY_API_KEYS_ENABLED is set AND the bearer
                // chain installed the API-key validator. Test
                // builders that don't set it stay in the safe
                // "feature off; admin/onboarding minting hidden"
                // posture.
                api_keys_feature: Feature::disabled(
                    "api-key feature disabled (GATEWAY_API_KEYS_ENABLED=false)",
                    "GATEWAY_API_KEYS_ENABLED is off or the bearer chain has no API-key validator",
                ),
                api_key_profiles: Capability::absent("profile store not configured"),
                api_key_validator: None,
                oauth: Capability::new("oauth sessions disabled", oauth),
                upstream_sessions: Capability::new(
                    "tier-a upstream session store not configured",
                    upstream_sessions,
                ),
                consent: Capability::absent("oauth consent store not configured"),
                confidential_clients: Capability::absent("confidential-client store not configured"),
                scim_users: Capability::absent("SCIM store not configured"),
                scim_groups: Capability::absent("SCIM group store not configured"),
                scim_resolver: Capability::absent("SCIM resolver not configured"),
                scim_enricher: None,
                scim_provisioning_log: Capability::absent("SCIM provisioning log store not configured"),
                rbac: Capability::absent("RBAC store not configured"),
                rbac_enricher: None,
                tenants: Capability::absent("tenants store not configured"),
                tenant_lifecycle: Capability::absent(
                    "tenant lifecycle store not configured",
                ),
                tenant_enricher: None,
                scopes: Capability::absent("scope store not configured"),
                groups: Capability::absent("group store not configured"),
            },
            policy: PolicyPlane {
                cedar: Capability::new("no cedar engine configured", cedar),
                policy_store: Capability::absent("policy store not configured"),
                // Editing-on is the default (set by GATEWAY_POLICY_EDITING, default
                // on); waygate-server sets the off-reason when the flag is off or
                // the policies dir isn't writable. Test builders that don't call
                // `with_policy_editing_off_reason` get the permissive default,
                // matching prior behavior where the editor was always offered.
                policy_editing: Feature::enabled_with("policy editing is disabled"),
                policies_dir: None,
                policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
                policy_config_health: None,
                break_glass: Capability::absent("break-glass store not configured"),
                inspection_rules: Capability::absent("inspection rules store not configured"),
                rate_limit_policies: Capability::absent("rate-limit store not configured"),
            },
            observability: ObservabilityPlane {
                audit: Capability::new("audit store not configured", audit),
                routing: Capability::absent("routing store not configured"),
                retention: Capability::absent("retention store not configured"),
                sweeper: Capability::absent("sweep runner not configured"),
                bundle_signer: Capability::absent(
                    "bundle signing key not configured (set GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM)",
                ),
                trace_url_template: None,
            },
            servers: ServersPlane {
                catalog: Capability::new("catalog store not configured", catalog),
                manifest_store: Capability::absent("manifest store not configured"),
                servers_dir: None,
                manifest_write_lock: Arc::new(tokio::sync::Mutex::new(())),
                config_health: None,
                builtin_surfaces: Vec::new(),
                catalog_reconcile: None,
            },
            llm: LlmPlane {
                llm_models: Capability::absent("llm model catalog not configured"),
                llm_credentials: Capability::absent("llm credential store not configured"),
                llm_resolver: None,
            },
            hitl: HitlPlane {
                codemode_executions: Capability::absent(
                    "Code Mode execution store not configured",
                ),
                skills: Capability::absent("Agent Skills catalog or indexed Git resource unavailable"),
                reviewed_skills: Capability::absent("Skill distribution reviews are unavailable"),
                change_requests: Capability::absent("change-request store not configured"),
                change_notifier: None,
                change_secret_crypto: Capability::absent(
                    "change-request secret channel not configured (set GATEWAY_CHANGE_SECRET_KEY)",
                ),
                proposal_files: Capability::absent(
                    "file uploads are not configured (set GATEWAY_FILE_STORAGE_DIR); submit the \
                     document inline instead",
                ),
                hitl_hub: Arc::new(crate::hitl_ws::ApprovalHub::default()),
                require_two_approvals: false,
                decisions_badge_cache: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            },
            agent: AgentPlane {
                agent_configs: Capability::absent("agent config store not configured"),
                conversations: Capability::absent("conversation store not configured"),
                chat_approvals: std::sync::Arc::new(waygate_agent_runtime::chat_approvals::ChatApprovalRegistry::new()),
                assist_read: None,
            },
            federation: FederationPlane {
                federated_peers: Capability::absent("federated peers store not configured"),
                federated_peers_cache: None,
            },
            dashboard: DashboardPlane {
                playground_scenarios: Capability::absent("playground scenario store not configured"),
                activity_saved_views: Capability::absent("activity saved-views store not configured"),
                tasks: Capability::absent("tasks store not configured"),
                try_invocation: None,
                overview_change_feed_actions: DEFAULT_OVERVIEW_CHANGE_FEED_ACTIONS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
            },
        }
    }

    /// Attach the on-disk manifest directory (`GATEWAY_SERVERS_DIR`).
    /// Same post-`new()` builder reasoning as `with_manifest_store`.
    /// `waygate-server` calls this at boot so the dashboard write
    /// surfaces can mirror an edit onto the file-as-truth source before
    /// recording the ledger snapshot. Absent (tests/dev) ⇒ the file-write
    /// step is skipped.
    #[must_use]
    pub fn with_servers_dir(mut self, servers_dir: std::path::PathBuf) -> Self {
        self.servers.servers_dir = Some(servers_dir);
        self
    }

    /// Attach the on-disk Cedar policy directory (`GATEWAY_POLICIES_DIR`).
    /// The policy analogue of [`Self::with_servers_dir`]: `waygate-server`
    /// calls this at boot so a dashboard / REST policy publish or rollback can
    /// mirror the chosen bundle onto the file-as-truth source before recording
    /// the ledger transition. Absent (tests/dev) ⇒ the mirror step is skipped.
    #[must_use]
    pub fn with_policies_dir(mut self, policies_dir: std::path::PathBuf) -> Self {
        self.policy.policies_dir = Some(policies_dir);
        self
    }

    /// Set the policy-editing posture. `waygate-server` passes `None`
    /// (enabled) when `GATEWAY_POLICY_EDITING` is on AND the policies dir is
    /// writable, else `Some(reason)` — the operator-facing why, surfaced in
    /// the UI and 403 bodies.
    #[must_use]
    pub fn with_policy_editing_off_reason(mut self, off_reason: Option<String>) -> Self {
        self.policy.policy_editing.set_off_reason(off_reason);
        self
    }

    /// Attach the config-health signal. `waygate-server` hands the
    /// same handle to the SIGHUP reload task, so the Servers page banner
    /// reflects boot/SIGHUP config health.
    #[must_use]
    pub fn with_config_health(
        mut self,
        config_health: waygate_upstream::SharedConfigHealth,
    ) -> Self {
        self.servers.config_health = Some(config_health);
        self
    }

    /// Attach the governed-catalog reconcile callback the dashboard Reload
    /// handler runs after applying a changed manifest set to the live pool.
    /// `None` (no catalog database) leaves the reconcile skipped, matching
    /// the doorbell path's pool gate. See
    /// [`ServersPlane::catalog_reconcile`].
    pub fn with_catalog_reconcile(mut self, reconcile: Option<SharedCatalogReconcile>) -> Self {
        self.servers.catalog_reconcile = reconcile;
        self
    }

    /// Attach the policy config-health signal.
    /// `waygate-server` hands the same handle to `build_authz_gate` (boot) and
    /// the reload task (SIGHUP / doorbell / poll), so the Policies page banner
    /// reflects boot/reload policy health. Separate from [`Self::with_config_health`].
    #[must_use]
    pub fn with_policy_config_health(
        mut self,
        policy_config_health: waygate_upstream::SharedConfigHealth,
    ) -> Self {
        self.policy.policy_config_health = Some(policy_config_health);
        self
    }

    /// Write a bundle's manifest-set `content` onto the on-disk source of
    /// truth (file-as-truth server-config redesign). Shared by
    /// the dashboard and REST publish/rollback paths so both keep disk in
    /// sync with the ledger. No-op when no `servers_dir` is wired
    /// (tests / dev). The caller must hold [`ServersPlane::manifest_write_lock`]
    /// and maps the returned error string to its own response shape (a
    /// flash redirect for the dashboard, a 500 for the REST surface).
    pub fn mirror_manifest_set_to_disk(&self, tenant: &str, content: &str) -> Result<(), String> {
        // Disk is the GLOBAL upstream set that resolve_manifests reads for
        // the DEFAULT tenant (upstreams are gateway-wide today). A
        // non-default tenant's publish/rollback stages in its own DB ledger
        // but must NOT mutate the single global on-disk source of truth.
        if tenant != waygate_core::TenantId::DEFAULT {
            return Ok(());
        }
        let Some(dir) = self.servers.servers_dir.as_ref() else {
            return Ok(());
        };
        let set = waygate_upstream::parse_manifest_set(content).map_err(|e| format!("{e}"))?;
        // Validate-before-write: disk is the boot/SIGHUP source of truth, so
        // a prod-forbidden set (transport: stdio under
        // GATEWAY_DEPLOYMENT_PROFILE=prod) must never reach it — boot loads
        // disk first and would then refuse it and fail to start. Every caller
        // runs this mirror BEFORE its ledger transition, so this
        // refusal returns ahead of the publish / rollback_to / create_draft
        // write: the prod-unsafe version is refused outright, not recorded —
        // "an unsafe publish fails, it does not break prod".
        let is_prod = self.system.deployment_profile == "prod";
        waygate_upstream::enforce_no_prod_stdio(is_prod, &set)?;
        waygate_upstream::write_manifest_set_to_dir(dir, &set).map_err(|e| format!("{e}"))
    }

    /// Mirror a derived manifest set only when disk still matches the exact
    /// source hash the maker inspected.
    ///
    /// The conditional filesystem writer stages first, then verifies and
    /// quarantines the prior set at commit. A raw NFS edit that bypasses the
    /// database turnstile is preserved and returned as
    /// [`waygate_upstream::UpstreamError::StaleBase`].
    pub(crate) fn mirror_manifest_set_to_disk_from_base(
        &self,
        tenant: &str,
        content: &str,
        expected_base: &str,
    ) -> Result<(), waygate_upstream::UpstreamError> {
        if tenant != waygate_core::TenantId::DEFAULT {
            return Ok(());
        }
        let Some(dir) = self.servers.servers_dir.as_ref() else {
            return Ok(());
        };
        let set = waygate_upstream::parse_manifest_set(content)?;
        let is_prod = self.system.deployment_profile == "prod";
        waygate_upstream::enforce_no_prod_stdio(is_prod, &set)
            .map_err(waygate_upstream::UpstreamError::InvalidManifest)?;
        waygate_upstream::write_manifest_set_to_dir_from_base(dir, &set, expected_base)
    }

    /// Mirror a policy bundle's concatenated Cedar `content` onto the on-disk
    /// source of truth (file-as-truth, server-config redesign §7.7). The policy
    /// analogue of [`Self::mirror_manifest_set_to_disk`]: shared by the
    /// dashboard and REST publish/rollback paths so both keep `policies/*.cedar`
    /// in sync with the ledger. No-op when no `policies_dir` is wired
    /// (tests / dev). The caller must hold [`PolicyPlane::policy_write_lock`] and maps
    /// the returned error string to its own response shape.
    pub fn mirror_policy_bundle_to_disk(&self, tenant: &str, content: &str) -> Result<(), String> {
        let Some(dir) = self.policy_mirror_target(tenant, content)? else {
            return Ok(());
        };
        waygate_policy::write_policy_bundle_to_dir(dir, content).map_err(|e| format!("{e}"))
    }

    fn policy_mirror_target<'a>(
        &'a self,
        tenant: &str,
        content: &str,
    ) -> Result<Option<&'a std::path::Path>, String> {
        Self::validate_policy_bundle_content(content)?;
        // Disk is the source of truth `resolve_policies` reads for the DEFAULT
        // tenant. Non-default tenants are live from their own DB ledger bundle,
        // so their publish/rollback must not mutate the default tenant's disk.
        if tenant != waygate_core::TenantId::DEFAULT {
            return Ok(None);
        }
        let Some(dir) = self.policy.policies_dir.as_ref() else {
            return Ok(None);
        };
        Ok(Some(dir))
    }

    /// Validate the same parseable, non-empty invariant enforced by boot and
    /// tenant-registry refresh. This runs before either the default disk mirror
    /// or a non-default ledger transition, so one tenant cannot publish a
    /// bundle that poisons the complete-registry refresh.
    fn validate_policy_bundle_content(content: &str) -> Result<(), String> {
        let engine =
            waygate_authz::CedarEngine::from_source(content).map_err(|e| format!("{e}"))?;
        if engine.list_policies().is_empty() {
            return Err(
                "refusing to publish an empty policy bundle; include at least one policy"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn mirror_policy_bundle_to_disk_from_base(
        &self,
        tenant: &str,
        content: &str,
        expected_base: Option<&str>,
    ) -> Result<(), PolicyCommitError> {
        let Some(dir) = self
            .policy_mirror_target(tenant, content)
            .map_err(PolicyCommitError::Mirror)?
        else {
            return Ok(());
        };
        match expected_base {
            Some(base) => {
                match waygate_policy::write_policy_bundle_to_dir_from_base(dir, content, base) {
                    Ok(()) => Ok(()),
                    Err(waygate_policy::PolicyDirWriteError::StaleBase) => {
                        Err(PolicyCommitError::Conflict(
                            "the live policy set changed after the write turnstile was claimed — re-propose against the current source"
                                .to_owned(),
                        ))
                    }
                    Err(waygate_policy::PolicyDirWriteError::Io(error)) => {
                        Err(PolicyCommitError::Mirror(error.to_string()))
                    }
                }
            }
            None => waygate_policy::write_policy_bundle_to_dir(dir, content)
                .map_err(|error| PolicyCommitError::Mirror(error.to_string())),
        }
    }

    /// Apply a policy `content` change under the cross-replica turnstile, on the
    /// file-as-truth **disk-wins** model (mirroring `dashboard_server_manifests`):
    /// claim the turnstile (CAS the pointer), mirror onto the on-disk source of
    /// truth, then run the `ledger` transition. The on-disk set is authoritative:
    /// - a **mirror** failure rolls the turnstile back (the write never landed; a
    ///   broken/empty dir is recovered from the ledger on the next reload) and
    ///   returns [`PolicyCommitError::Mirror`];
    /// - a **ledger** failure does NOT roll back or restore disk — disk wins, the
    ///   gate loads it on the next reload, and the ledger reconciles to disk via
    ///   the capture slice. It returns [`PolicyCommitError::DiskAhead`]
    ///   (a loud "applied to disk but the ledger record failed"). Restoring would
    ///   treat the ledger as authoritative and, across replicas, clobber a
    ///   concurrent writer's committed disk.
    ///
    /// Centralized here so every publish / rollback call site (REST + dashboard)
    /// shares one path. The caller must hold [`PolicyPlane::policy_write_lock`];
    /// pre-checks (draft / rollback-target) and content resolution happen BEFORE
    /// this.
    pub async fn mirror_then<F, Fut>(
        &self,
        tenant: &str,
        content: &str,
        actor: &str,
        ledger: F,
    ) -> Result<waygate_policy::PolicyBundle, PolicyCommitError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<
            Output = Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError>,
        >,
    {
        self.mirror_then_from_base(tenant, content, actor, None, ledger)
            .await
    }

    /// The [`Self::mirror_then`] body with an optional exact on-disk merge base.
    /// Derived writes pass the hash they read before reconstructing a full policy
    /// set; if disk has changed since that read, the turnstile refuses before any
    /// mirror or ledger write. Full-set publish and rollback pass `None` and use
    /// the current on-disk hash as their CAS base.
    pub(crate) async fn mirror_then_from_base<F, Fut>(
        &self,
        tenant: &str,
        content: &str,
        actor: &str,
        expected_base: Option<&str>,
        ledger: F,
    ) -> Result<waygate_policy::PolicyBundle, PolicyCommitError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<
            Output = Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError>,
        >,
    {
        Self::validate_policy_bundle_content(content).map_err(PolicyCommitError::Mirror)?;
        // A mirror only happens for the DEFAULT tenant with a wired dir;
        // otherwise disk is untouched and a ledger failure is inherently
        // consistent (nothing to compensate).
        let dir = if tenant == waygate_core::TenantId::DEFAULT {
            self.policy.policies_dir.clone()
        } else {
            None
        };
        let Some(dir) = dir else {
            let bundle = ledger().await.map_err(PolicyCommitError::Ledger)?;
            if let Some(store) = self.policy.policy_store.get() {
                if let Err(error) = store.notify_reload(&bundle.content_hash).await {
                    tracing::warn!(%error, tenant, "tenant policy doorbell notify failed (poll backstop active)");
                }
            }
            return Ok(bundle);
        };

        // Claim the cross-replica write turnstile BEFORE the mirror, so
        // only the CAS winner ever renames `policies/*.cedar` — preventing the
        // lost update, not just detecting it. The CAS target is the canonical
        // hash disk WILL have after mirroring `content`.
        let new_hash = waygate_policy::canonical_policy_disk_hash(content);
        let claim = self
            .policy_turnstile_claim(&dir, &new_hash, actor, expected_base)
            .await?;

        // AlreadyCurrent: disk already holds this exact content. We must NOT
        // record a ledger row from here: it cannot own the turnstile (a no-op
        // `cas(base,base)` does not advance the pointer, so it can't exclude a
        // concurrent cross-replica `base -> H2` writer), so a competing publish
        // could become the latest-published-active while disk has moved to H2 —
        // a disk/ledger divergence. Mirroring the manifest precedent
        // (`turnstile_cas` AlreadyCurrent), refuse it as a no-op. Nothing was
        // written.
        if matches!(claim, PolicyTurnstileClaim::AlreadyCurrent) {
            return Err(PolicyCommitError::NoChange(
                "the bundle's content already matches the live on-disk policy set — \
                 nothing to apply"
                    .to_owned(),
            ));
        }
        // On Won we hold the turnstile and roll it back if the MIRROR fails (so
        // the pointer doesn't advertise a version that never reached disk); on
        // NoTurnstile there is nothing to roll back.
        let won_base = match &claim {
            PolicyTurnstileClaim::Won { base } => Some(base.clone()),
            _ => None,
        };

        // Mirror the bundle onto the on-disk SOURCE OF TRUTH. A Won claim passes
        // its exact base into the synchronous filesystem commit, which re-reads
        // the complete directory after all async turnstile work and temp-file
        // staging but before removing any Cedar file.
        if let Err(commit_err) =
            self.mirror_policy_bundle_to_disk_from_base(tenant, content, won_base.as_deref())
        {
            // The write did not land. Roll the turnstile back (best-effort) so the
            // pointer doesn't advertise content that never reached disk. We do NOT
            // try to "restore" a prior set: the writer clears before renaming, so a
            // partial failure may leave `policies/` empty — which `resolve_policies`
            // treats as unreadable and RECOVERS from the ledger on the next reload
            // (the running gate is unaffected — it reloads only on boot/SIGHUP).
            // The reconcile then re-syncs the pointer. Mirrors the manifest model:
            // disk is the source of truth, recovery/reconcile converge it — never
            // a cross-replica disk restore.
            self.policy_turnstile_rollback(won_base.as_deref(), &new_hash, actor)
                .await;
            return Err(commit_err);
        }

        // Ledger transition LAST — disk now holds the content.
        match ledger().await {
            Ok(bundle) => {
                // Doorbell: the write + ledger append landed — tell the
                // fleet to reload policies/*.cedar. Fire AFTER the ledger append
                // (per the doorbell contract: a ledger failure must never tell
                // peers to reload an unrecorded change) and carry the canonical
                // on-disk hash (matches the pointer/disk, not the raw bundle hash).
                // Best-effort: a notify failure is logged, never fails
                // the publish — the poll backstop still converges.
                if let Some(store) = self.policy.policy_store.get() {
                    if let Err(e) = store.notify_reload(&new_hash).await {
                        tracing::warn!(
                            error = %e,
                            "policy doorbell notify failed (poll backstop active)",
                        );
                    }
                }
                Ok(bundle)
            }
            Err(ledger_err) => {
                // Disk (the source of truth) was applied, but recording the
                // transition in the ledger failed. We do NOT restore disk or roll
                // the turnstile back: under file-as-truth the on-disk set WINS — the
                // gate loads it on the next reload and the ledger/dashboard view
                // converges to disk via the reconcile + out-of-band capture.
                // Restoring would treat the LEDGER as authoritative (it
                // is not) and, across replicas, clobber a concurrent writer that has
                // since advanced the pointer and mirrored its own content.
                // This matches `dashboard_server_manifests`'s
                // ledger-failure handling. Surfaced loudly so the operator knows
                // the ledger lagged.
                Err(PolicyCommitError::DiskAhead(format!(
                    "the policy was applied to policies/*.cedar (the source of truth) but \
                     recording it in the ledger failed ({ledger_err}); the gate loads the \
                     on-disk set on the next reload and the ledger reconciles to disk — no \
                     manual action needed unless this recurs"
                )))
            }
        }
    }

    /// Claim the cross-replica write turnstile for a policy mirror,
    /// before the disk write, mirroring `dashboard_server_manifests::turnstile_cas`.
    /// The CAS base is the CURRENT on-disk hash (the set being replaced). Returns:
    /// - `Won { base }` — this writer advanced the pointer `base -> new_hash` and
    ///   must mirror; roll the pointer back to `base` if the mirror/ledger fails.
    /// - `AlreadyCurrent` — disk already equals `new_hash`; the caller must NOT
    ///   mirror AND must NOT record a ledger row (a no-op `cas(base,base)` does
    ///   not advance the pointer to exclude a concurrent `base -> H2` writer, so
    ///   a competing publish would race). It is a no-op refusal.
    /// - `NoTurnstile` — no policy store wired, or the on-disk set is UNUSABLE
    ///   (an I/O error, OR a readable-but-broken set: unparseable Cedar or
    ///   empty/comment-only). A publish/rollback REPAIRS such a set, so skip the
    ///   CAS and let it overwrite; the boot/SIGHUP reconcile re-syncs the pointer
    ///   afterward.
    ///
    /// `Err(PolicyCommitError::Conflict)` when the CAS LOST — another replica
    /// advanced the on-disk set since this edit's base; nothing was written.
    async fn policy_turnstile_claim(
        &self,
        dir: &std::path::Path,
        new_hash: &str,
        actor: &str,
        expected_base: Option<&str>,
    ) -> Result<PolicyTurnstileClaim, PolicyCommitError> {
        let Some(store) = self.policy.policy_store.get() else {
            return Ok(PolicyTurnstileClaim::NoTurnstile);
        };
        let source = match waygate_policy::read_policy_dir(dir) {
            Ok(c) => c.source,
            // An I/O error: no usable CAS base, and a publish/rollback REPAIRS it.
            Err(e) => {
                if expected_base.is_some() {
                    return Err(PolicyCommitError::Conflict(format!(
                        "the live policy set could not be re-read to verify this fragment's merge base ({e}) — retry after the policy source is healthy"
                    )));
                }
                tracing::warn!(error = %e, "policy turnstile: on-disk set unreadable; skipping CAS so the write can repair it");
                return Ok(PolicyTurnstileClaim::NoTurnstile);
            }
        };
        // `read_policy_dir` returns Ok for a readable-but-BROKEN set (unparseable
        // Cedar, or empty/comment-only) — but `resolve_policies` treats exactly
        // those as "unreadable" and RECOVERS from the ledger, and it skips the
        // pointer reconcile on a recovered load, leaving the pointer at the
        // previous-good hash (NOT this broken disk's hash). So a CAS keyed on the
        // broken disk's bytes would lose against that stale pointer and 409 the
        // very publish meant to REPAIR the source of truth. Detect a broken set
        // with the SAME usable=parses-and-non-empty test `resolve_policies` uses,
        // and skip the CAS so the repair overwrites it (the next reconcile
        // re-syncs the pointer).
        let usable = matches!(
            waygate_authz::CedarEngine::from_source(&source),
            Ok(engine) if !engine.list_policies().is_empty()
        );
        if !usable {
            if expected_base.is_some() {
                return Err(PolicyCommitError::Conflict(
                    "the live policy set is unparseable or empty, so this fragment's merge base cannot be verified — repair the policy source and re-propose"
                        .to_owned(),
                ));
            }
            tracing::warn!("policy turnstile: on-disk set is unparseable or empty (recovered state); skipping CAS so the write can repair it");
            return Ok(PolicyTurnstileClaim::NoTurnstile);
        }
        let base = waygate_policy::content_hash(&source);
        if expected_base.is_some_and(|expected| expected != base) {
            return Err(PolicyCommitError::Conflict(
                "another replica changed the policy set after this fragment was merged — re-propose against the current live set"
                    .to_owned(),
            ));
        }
        // No-op guard: `cas_pointer(base, base)` would match its own
        // WHERE and report Won WITHOUT advancing — admitting a concurrent
        // clobber. Nothing to write; report AlreadyCurrent before any CAS.
        if new_hash == base {
            return Ok(PolicyTurnstileClaim::AlreadyCurrent);
        }
        let t = waygate_core::TenantId::DEFAULT;
        // Seed the base if absent so the CAS has a row to match (a fresh deploy
        // before the boot reconcile ran); never clobbers an advanced pointer.
        store
            .seed_pointer(t, &base)
            .await
            .map_err(|e| PolicyCommitError::Mirror(format!("policy turnstile seed failed: {e}")))?;
        match store
            .cas_pointer(t, &base, new_hash, actor)
            .await
            .map_err(|e| PolicyCommitError::Mirror(format!("policy turnstile check failed: {e}")))?
        {
            waygate_policy::TurnstileOutcome::Won => Ok(PolicyTurnstileClaim::Won { base }),
            waygate_policy::TurnstileOutcome::Lost => Err(PolicyCommitError::Conflict(
                "another replica changed the policy set since this page loaded — reload and retry"
                    .to_owned(),
            )),
        }
    }

    /// Best-effort undo of a turnstile advance when the subsequent MIRROR failed,
    /// so the pointer never advertises a version that never reached disk.
    /// `None` ⇒ the CAS was skipped (AlreadyCurrent / NoTurnstile),
    /// nothing to undo. Used ONLY on a mirror failure — where no concurrent writer
    /// can have advanced past us (the pointer is at `new_hash` while disk is not,
    /// so any other writer's CAS from the on-disk hash loses). A failed/lost undo
    /// is harmless: the next boot/SIGHUP reconcile re-syncs the pointer to disk.
    /// On a LEDGER failure the caller does NOT roll back — disk wins (file-as-truth)
    /// and the ledger converges to it.
    async fn policy_turnstile_rollback(
        &self,
        won_from_base: Option<&str>,
        new_hash: &str,
        actor: &str,
    ) {
        if let (Some(store), Some(base)) = (self.policy.policy_store.get(), won_from_base) {
            let _ = store
                .cas_pointer(waygate_core::TenantId::DEFAULT, new_hash, base, actor)
                .await;
        }
    }

    /// Read the on-disk manifest set (the source of truth) plus its
    /// canonical content hash — the read-side counterpart to
    /// [`Self::mirror_manifest_set_to_disk`]. The dashboard render tabs
    /// pre-fill from this and stamp `base_hash` from the hash, and the
    /// write path's stale-edit guard compares against it, so render and
    /// write agree on "what is currently on disk" (an out-of-band edit to
    /// `servers/*.yaml` is therefore the edit base, not something a later
    /// dashboard publish silently clobbers). The hash is computed exactly
    /// as a ledger bundle's is (`content_hash(serialize_manifest_set(..))`),
    /// so a disk set that matches a published snapshot hashes identically.
    /// `None` when no `servers_dir` is wired (tests / dev).
    pub fn read_manifest_set_from_disk(&self) -> Option<Result<DiskManifestSet, String>> {
        let dir = self.servers.servers_dir.as_ref()?;
        Some((|| {
            // Mirror `resolve_manifests`: a missing / non-directory path is an
            // error, NOT an authoritative empty set (`load_manifests` returns
            // Ok(empty) for a non-existent dir), so the dashboard reads fail
            // consistently with boot/SIGHUP instead of silently showing zero
            // upstreams for an unmounted or typoed `servers_dir`.
            if !dir.is_dir() {
                return Err(format!(
                    "manifest dir {} is missing or not a directory",
                    dir.display()
                ));
            }
            if waygate_upstream::manifest_write_in_progress(dir).map_err(|e| format!("{e}"))? {
                return Err(
                    "a coordinated manifest write is in progress or was interrupted; the live \
                     directory is not a safe proposal base"
                        .to_owned(),
                );
            }
            let set = waygate_upstream::load_manifests(dir).map_err(|e| format!("{e}"))?;
            let content =
                waygate_upstream::serialize_manifest_set(&set).map_err(|e| format!("{e}"))?;
            let hash = waygate_manifest_store::content_hash(&content);
            Ok((set, hash))
        })())
    }

    /// Replace the default HITL hub with
    /// a custom one (typically a hub the composition
    /// root also handed to `DefaultInvocationService` as
    /// the `HitlNotifier`, so a single broadcast channel
    /// feeds both sides). The default suffices for
    /// tests / dev paths that don't run the full server.
    #[must_use]
    pub fn with_hitl_hub(mut self, hub: Arc<crate::hitl_ws::ApprovalHub>) -> Self {
        self.hitl.hitl_hub = hub;
        self
    }

    /// Attach the governed "Try this tool" invocation handle.
    /// `waygate-server` passes the same `build_default_invocation_service`
    /// output the per-session MCP dispatch path uses, so the dashboard
    /// try-it surface and a real client share one governance pipeline by
    /// construction. `waygate-server` always calls this (try-it is not
    /// DB-gated). Omitting it leaves `try_invocation = None`, which disables
    /// the try-it form — the default for tests and any composition that
    /// doesn't run the full server wiring.
    pub fn with_try_invocation(mut self, invocation: waygate_mcp::SharedInvocation) -> Self {
        self.dashboard.try_invocation = Some(invocation);
        self
    }

    /// Attach the LLM routing resolver (only when the inference plane is
    /// mounted). The `/chat` page treats its presence as "inference configured"
    /// and filters its model picker through it, matching `/v1/models`. `None`
    /// (MCP-only deployment) ⇒ the page shows the "not configured" card.
    pub fn with_llm_resolver(
        mut self,
        resolver: Option<std::sync::Arc<dyn waygate_llm_dispatch::LlmModelResolver>>,
    ) -> Self {
        self.llm.llm_resolver = resolver;
        self
    }

    /// Attach the per-tenant routing store. Same builder
    /// reasoning as `with_policy_store`: a post-`new()` opt-in
    /// keeps existing call sites unchanged. `waygate-server`
    /// calls this when a Postgres pool exists.
    #[must_use]
    pub fn with_routing_store(mut self, routing: Option<Arc<dyn RoutingStore>>) -> Self {
        self.observability.routing.set(routing);
        self
    }

    /// Attach the per-tenant retention policy store.
    /// Same builder pattern as `with_routing_store`. `waygate-server`
    /// calls this when a Postgres pool exists; absence ⇒ admin
    /// endpoints return 503.
    #[must_use]
    pub fn with_retention_store(mut self, retention: Option<Arc<dyn RetentionStore>>) -> Self {
        self.observability.retention.set(retention);
        self
    }

    /// Attach the pool-bound sweep runner. Same
    /// builder pattern as `with_retention_store`. `waygate-server`
    /// calls this when a Postgres pool exists; absence ⇒ the
    /// sweep endpoint returns 503.
    #[must_use]
    pub fn with_sweeper(mut self, sweeper: Option<Arc<dyn Sweeper>>) -> Self {
        self.observability.sweeper.set(sweeper);
        self
    }

    /// Attach the bundle signing config.
    /// `waygate-server` constructs from
    /// `GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM` +
    /// `..._KEY_ID`; absence ⇒ `POST /api/v1/audit/bundle`
    /// returns 503 with a clear "key not configured"
    /// message.
    #[must_use]
    pub fn with_bundle_signer(mut self, signer: Option<Arc<BundleSigner>>) -> Self {
        self.observability.bundle_signer.set(signer);
        self
    }

    /// Attach the OAuth consent store.
    /// Same pattern as the other admin store builders —
    /// `waygate-server` passes the same `SharedConsentStore`
    /// the AS callback writes through whenever a Postgres
    /// pool exists; absence ⇒
    /// `/api/v1/admin/oauth_consent/*` returns 503.
    #[must_use]
    pub fn with_consent_store(mut self, store: Option<SharedConsentStore>) -> Self {
        self.identity.consent.set(store);
        self
    }

    /// Attach the confidential-client registry. `waygate-server`
    /// calls this when a Postgres pool exists; absence ⇒
    /// `/api/v1/admin/confidential-clients` returns 503.
    #[must_use]
    pub fn with_confidential_clients(
        mut self,
        store: Option<SharedConfidentialClientStore>,
    ) -> Self {
        self.identity.confidential_clients.set(store);
        self
    }

    /// Attach the SCIM Users store.
    /// `waygate-server` calls this when a Postgres pool
    /// exists; absence ⇒ `/scim/v2/Users` returns 503.
    #[must_use]
    pub fn with_scim_users(mut self, store: Option<Arc<dyn ScimUserStore>>) -> Self {
        self.identity.scim_users.set(store);
        self
    }

    /// Attach the SCIM Groups store. Same
    /// pattern as `with_scim_users`.
    #[must_use]
    pub fn with_scim_groups(mut self, store: Option<Arc<dyn ScimGroupStore>>) -> Self {
        self.identity.scim_groups.set(store);
        self
    }

    /// Attach the RBAC store. Same pattern as
    /// `with_scim_users` — `waygate-server` calls this when a
    /// Postgres pool exists; absence ⇒ `/api/v1/admin/rbac/*`
    /// endpoints return 503.
    #[must_use]
    pub fn with_rbac_store(mut self, store: Option<Arc<dyn waygate_rbac::RbacStore>>) -> Self {
        self.identity.rbac.set(store);
        self
    }

    /// Attach the per-tenant Cedar playground saved-
    /// scenarios store. `waygate-server` constructs a
    /// `PgPlaygroundScenarioStore` whenever a Postgres pool
    /// exists; absence ⇒ the playground page hides the Save +
    /// Load + Delete affordances and the page stays stateless.
    #[must_use]
    pub fn with_playground_scenarios(
        mut self,
        store: Option<
            Arc<dyn waygate_dashboard_stores::playground_scenarios::PlaygroundScenarioStore>,
        >,
    ) -> Self {
        self.dashboard.playground_scenarios.set(store);
        self
    }

    /// Attach the SCIM provisioning-log store used by
    /// the SCIM REST writer hooks + the dashboard timeline.
    /// `waygate-server` constructs a
    /// `PgScimProvisioningLogStore` whenever a Postgres pool
    /// exists; absence ⇒ the SCIM handlers skip the structured
    /// append (the `audit_log` writes already in place are
    /// unaffected) and the dashboard timeline section hides
    /// itself.
    #[must_use]
    pub fn with_scim_provisioning_log(
        mut self,
        store: Option<
            Arc<dyn waygate_dashboard_stores::scim_provisioning_log::ScimProvisioningLogStore>,
        >,
    ) -> Self {
        self.identity.scim_provisioning_log.set(store);
        self
    }

    /// Attach the activity-page saved-views store used by
    /// the Saved-views sidebar + Save / Delete / Load actions on
    /// `/admin/t/<tenant>/activity`. `waygate-server` constructs
    /// a `PgActivitySavedViewStore` whenever a Postgres pool
    /// exists; absence ⇒ the activity page hides its Saved-views
    /// section entirely (facets + filter form + results
    /// unaffected). Same builder-style addition as
    /// `with_playground_scenarios` and
    /// `with_scim_provisioning_log` so the existing
    /// `AdminState::new` call sites don't churn.
    #[must_use]
    pub fn with_activity_saved_views(
        mut self,
        store: Option<
            Arc<dyn waygate_dashboard_stores::activity_saved_views::ActivitySavedViewStore>,
        >,
    ) -> Self {
        self.dashboard.activity_saved_views.set(store);
        self
    }

    /// Set the Grafana Explore → Tempo URL template for the
    /// activity-drawer "View trace" link (a string containing a `{trace_id}`
    /// placeholder). Builder rather than a `new()` arg so the existing
    /// `AdminState::new` call sites don't churn.
    #[must_use]
    pub fn with_trace_url_template(mut self, template: Option<String>) -> Self {
        self.observability.trace_url_template = template;
        self
    }

    /// Attach the SCIM `(tenant, sub) → ResolvedPrincipal`
    /// resolver used by the dashboard's "effective permissions for
    /// subject" query. Pass the same `Arc` the bearer middleware's
    /// `PgScimEnricher` uses internally so the admin view sees
    /// exactly what the runtime would see for the same sub
    /// (including the fail-closed ambiguous-match path). Same
    /// DB-pool gating pattern as the other admin stores.
    #[must_use]
    pub fn with_scim_resolver(
        mut self,
        resolver: Option<Arc<dyn waygate_scim::ScimResolver>>,
    ) -> Self {
        self.identity.scim_resolver.set(resolver);
        self
    }

    /// Attach the `RbacEnricher` so admin handlers can call
    /// `invalidate_all()` after mutations. Pass the same Arc
    /// the bearer middleware uses — both must see invalidation
    /// for it to take effect on the hot path.
    #[must_use]
    pub fn with_rbac_enricher(mut self, enricher: Option<Arc<waygate_rbac::RbacEnricher>>) -> Self {
        self.identity.rbac_enricher = enricher;
        self
    }

    /// Attach the canonical tenants registry.
    /// Same pattern as the other admin stores — `waygate-server`
    /// calls this when a Postgres pool exists; absence ⇒
    /// `/api/v1/admin/tenants/*` endpoints return 503.
    #[must_use]
    pub fn with_tenant_store(
        mut self,
        store: Option<Arc<dyn waygate_tenants::TenantStore>>,
    ) -> Self {
        self.identity.tenants.set(store);
        self
    }

    /// Attach the atomic tenant lifecycle store used by DELETE surfaces.
    #[must_use]
    pub fn with_tenant_lifecycle_store(
        mut self,
        store: Option<Arc<dyn crate::tenants::TenantLifecycleStore>>,
    ) -> Self {
        self.identity.tenant_lifecycle.set(store);
        self
    }

    /// Attach the `PgTenantEnricher` shared with
    /// the bearer middleware so admin tenant mutations invalidate
    /// the cache. Same wiring discipline as
    /// [`Self::with_rbac_enricher`].
    #[must_use]
    pub fn with_tenant_enricher(
        mut self,
        enricher: Option<Arc<waygate_tenants::PgTenantEnricher>>,
    ) -> Self {
        self.identity.tenant_enricher = enricher;
        self
    }

    /// Attach the `PgScimEnricher`
    /// shared with the bearer middleware so a SCIM user DELETE evicts
    /// the cached active enrichment immediately instead of after the
    /// 60s TTL. Same wiring discipline as [`Self::with_tenant_enricher`].
    #[must_use]
    pub fn with_scim_enricher(
        mut self,
        enricher: Option<Arc<waygate_scim::PgScimEnricher>>,
    ) -> Self {
        self.identity.scim_enricher = enricher;
        self
    }

    /// Attach the `ApiKeyValidator` shared with the bearer middleware so
    /// the tenant DELETE cleanup can flush its principal cache
    /// after revoking the underlying rows. Without this hook,
    /// a freshly-revoked SCIM key remains valid for the
    /// validator's TTL window and a re-created tenant id could
    /// briefly resurrect the prior bearer.
    #[must_use]
    pub fn with_api_key_validator(
        mut self,
        validator: Option<Arc<waygate_apikeys::ApiKeyValidator>>,
    ) -> Self {
        self.identity.api_key_validator = validator;
        self
    }

    /// Attach the rate-limit-policies CRUD
    /// store backing `/api/v1/admin/rate_limit_policies/*`.
    /// Same pattern as the other admin store builders.
    #[must_use]
    pub fn with_rate_limit_policy_store(
        mut self,
        store: Option<Arc<dyn waygate_quota::RateLimitPolicyStore>>,
    ) -> Self {
        self.policy.rate_limit_policies.set(store);
        self
    }

    /// Attach the API-key profile store backing
    /// `/api/v1/admin/api_key_profiles/*`.
    #[must_use]
    pub fn with_api_key_profile_store(
        mut self,
        store: Option<Arc<dyn waygate_apikeys::ProfileStore>>,
    ) -> Self {
        self.identity.api_key_profiles.set(store);
        self
    }

    /// Attach the scope-registry store backing
    /// the read-only Scopes page. Same `Option<Arc<dyn …>>` DB-pool
    /// gating as [`Self::with_api_key_profile_store`]; `None` ⇒ the
    /// page renders its "store not configured" card.
    #[must_use]
    pub fn with_scope_store(mut self, store: Option<Arc<dyn waygate_apikeys::ScopeStore>>) -> Self {
        self.identity.scopes.set(store);
        self
    }

    /// Attach the group catalog read-view store
    /// backing the read-only Groups page. Same `Option<Arc<dyn …>>`
    /// DB-pool gating as [`Self::with_scope_store`]; `None` ⇒ the page
    /// renders its "store not configured" card.
    #[must_use]
    pub fn with_group_store(mut self, store: Option<Arc<dyn waygate_apikeys::GroupStore>>) -> Self {
        self.identity.groups.set(store);
        self
    }

    /// Attach the break-glass override store.
    /// Same `SharedBreakGlassStore` is also wrapped around the
    /// Cedar gate by `waygate-server::main` so admin and
    /// runtime see the same rows. `None` ⇒ admin endpoints
    /// 503 AND no override path (Deny is final).
    #[must_use]
    pub fn with_break_glass_store(
        mut self,
        store: Option<waygate_authz::SharedBreakGlassStore>,
    ) -> Self {
        self.policy.break_glass.set(store);
        self
    }

    /// Attach the change-request store backing
    /// the `mcp:propose` maker surface. `waygate-server` calls this when
    /// a Postgres pool exists; absence ⇒ `/api/v1/admin/change_requests/*`
    /// returns 503.
    #[must_use]
    pub fn with_change_request_store(
        mut self,
        store: Option<waygate_changeset::SharedChangeRequestStore>,
    ) -> Self {
        self.hitl.change_requests.set(store);
        self
    }

    /// Attach the durable Code Mode execution journal that owns pending
    /// data-plane mutation decisions.
    #[must_use]
    pub fn with_codemode_execution_store(
        mut self,
        store: Option<waygate_codemode::SharedExecutionStore>,
    ) -> Self {
        self.hitl.codemode_executions.set(store);
        self
    }

    /// Attach the active catalog used by the distribution review surface.
    #[must_use]
    pub fn with_skill_catalog(
        mut self,
        skills: Option<std::sync::Arc<waygate_skills::ReloadableSkillCatalog>>,
    ) -> Self {
        self.hitl.skills.set(skills);
        self
    }

    #[must_use]
    pub fn with_skill_distribution(
        mut self,
        catalog: Option<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
    ) -> Self {
        self.hitl.reviewed_skills.set(catalog);
        self
    }

    /// Attach the out-of-band change-request
    /// notifier. `waygate-server` builds it from `GATEWAY_HITL_WEBHOOK_URL`
    /// and shares the same Arc with the built-in MCP tools; absence ⇒ no
    /// out-of-band push.
    #[must_use]
    pub fn with_change_notifier(
        mut self,
        notifier: Option<crate::change_notify::SharedChangeNotifier>,
    ) -> Self {
        self.hitl.change_notifier = notifier;
        self
    }

    /// HITL secret-return channel: attach the AES-256-GCM keyring used to
    /// encrypt executor-produced secrets at rest and decrypt them on the
    /// maker's burn-on-read retrieve. `waygate-server` builds it from
    /// `GATEWAY_CHANGE_SECRET_KEY`; absence ⇒ secret-producing executors
    /// fail closed rather than persist plaintext.
    #[must_use]
    pub fn with_change_secret_crypto(mut self, crypto: Option<waygate_as::UpstreamCrypto>) -> Self {
        self.hitl.change_secret_crypto.set(crypto);
        self
    }

    /// Attach the reader that turns an uploaded document into a change
    /// request's text param. `waygate-server` calls this when file storage is
    /// configured; absence ⇒ a submission naming a file is refused and inline
    /// submission is unaffected.
    #[must_use]
    pub fn with_proposal_file_reader(
        mut self,
        reader: Option<Arc<dyn crate::param_files::ProposalFileReader>>,
    ) -> Self {
        self.hitl.proposal_files.set(reader);
        self
    }

    /// Attach the MCP Tasks store.
    /// Same pattern as the other admin stores —
    /// `waygate-server` calls this when a Postgres
    /// pool exists; absence ⇒ `/api/v1/admin/tasks/*`
    /// returns 503.
    #[must_use]
    pub fn with_tasks_store(
        mut self,
        store: Option<waygate_dashboard_stores::tasks::SharedTaskStore>,
    ) -> Self {
        self.dashboard.tasks.set(store);
        self
    }

    /// Attach the per-tenant
    /// inspection-rules store. Same DB-pool gating as the
    /// other admin stores — `waygate-server` passes
    /// `Some` when a Postgres pool exists; `None` ⇒
    /// `/api/v1/admin/inspection_rules/*` returns 503.
    #[must_use]
    pub fn with_inspection_rules_store(
        mut self,
        store: Option<waygate_dashboard_stores::inspection_rules::SharedRulesStore>,
    ) -> Self {
        self.policy.inspection_rules.set(store);
        self
    }

    /// Attach the per-tenant agent-config store backing
    /// the "Gateway Agents" tab. Same DB-pool gating as the other admin stores
    /// — `waygate-server` passes `Some` when a Postgres pool exists; `None` ⇒
    /// the tab shows the "store not configured" card.
    #[must_use]
    pub fn with_agent_configs(
        mut self,
        store: Option<waygate_dashboard_stores::agent_config::SharedAgentConfigStore>,
    ) -> Self {
        self.agent.agent_configs.set(store);
        self
    }

    /// Attach the agent-conversation store backing the
    /// agent-chat page's history persistence. DB-pool-gated like the other
    /// stores — `waygate-server` passes `Some` when a Postgres pool exists.
    #[must_use]
    pub fn with_conversations(
        mut self,
        store: Option<waygate_storage::SharedConversationStore>,
    ) -> Self {
        self.agent.conversations.set(store);
        self
    }

    /// Attach the governed read-built-in caller so the
    /// chat agent can reach the gateway's own read tools (`gateway-observe.*`)
    /// under the same Cedar overlay + scope floor as a direct MCP call.
    /// `waygate-server` passes `Some` once the observe built-in + authz gate
    /// exist.
    #[must_use]
    pub fn with_assist_read(mut self, caller: Option<waygate_mcp::SharedAssistReadTools>) -> Self {
        self.agent.assist_read = caller;
        self
    }

    /// Attach the federated peers store
    /// backing the `/api/v1/admin/federated_peers/*` CRUD.
    /// Same DB-pool gating — `waygate-server` passes `Some`
    /// when a Postgres pool exists; `None` ⇒ endpoints 503.
    #[must_use]
    pub fn with_federated_peers_store(
        mut self,
        store: Option<waygate_federation::SharedPeersStore>,
    ) -> Self {
        self.federation.federated_peers.set(store);
        self
    }

    /// Wire the same `Arc` the
    /// refresher writes to and the bearer chain's
    /// `PeerJwtValidator` reads from, so admin PATCH
    /// and DELETE can immediately evict the cached entry on a
    /// metadata rotation or removal. Without this, an
    /// `issuer` / `jwks_url` / `trust_tier` change leaves the
    /// old cached entry trusted until the next refresh —
    /// indefinitely, if the new JWKS URL is unreachable
    /// (the refresher deliberately retains the previous entry
    /// on fetch failure).
    #[must_use]
    pub fn with_federated_peers_cache(
        mut self,
        cache: Option<waygate_federation::jwks::SharedPeerJwksCache>,
    ) -> Self {
        self.federation.federated_peers_cache = cache;
        self
    }

    /// Gate the API-key admin REST
    /// surface and onboarding SCIM key minting separately
    /// from the `api_keys` store. `waygate-server` sets this
    /// to true only when `GATEWAY_API_KEYS_ENABLED=true` AND
    /// the bearer chain actually installed the API-key
    /// validator. Without this flag, a deployment with auth
    /// off but a DB pool would expose the mint endpoints
    /// and onboarding would mint SCIM API keys that can't
    /// authenticate (no validator on the chain).
    #[must_use]
    pub fn with_api_keys_enabled(mut self, enabled: bool) -> Self {
        if enabled {
            self.identity.api_keys_feature.set_off_reason(None);
        } else {
            // Explicit rather than relying on the constructor default, so a
            // future enable-then-disable call sequence behaves.
            self.identity.api_keys_feature.set_off_reason(Some(
                "GATEWAY_API_KEYS_ENABLED is off or the bearer chain has no API-key validator"
                    .into(),
            ));
        }
        self
    }

    /// Attach the durable policy-bundle store. Builder rather than a
    /// `new` argument so the existing 11 `AdminState::new` call sites
    /// don't churn; `waygate-server` calls this when a Postgres pool
    /// exists, leaving it `None` (⇒ 503) otherwise.
    #[must_use]
    pub fn with_policy_store(mut self, policy_store: Option<SharedPolicyStore>) -> Self {
        self.policy.policy_store.set(policy_store);
        self
    }

    /// Attach the inference-plane LLM model catalog. Same builder
    /// reasoning as [`AdminState::with_policy_store`]: `waygate-server`
    /// calls this when a Postgres pool exists, leaving it `None` (⇒ the
    /// `/llm_models` page shows the "store not configured" card) otherwise,
    /// so the existing `new()` call sites don't churn.
    #[must_use]
    pub fn with_llm_model_catalog(
        mut self,
        store: Option<waygate_storage::SharedLlmModelCatalog>,
    ) -> Self {
        self.llm.llm_models.set(store);
        self
    }

    /// Attach the shared LLM credential store for the `/llm_credentials` panel.
    /// `waygate-server` passes the SAME `Arc` the dispatcher holds when
    /// an LLM path is configured, leaving it `None` (⇒ the panel shows the "not
    /// configured" card) otherwise.
    #[must_use]
    pub fn with_llm_credentials(
        mut self,
        store: Option<std::sync::Arc<waygate_llm_credentials::LlmCredentialStore>>,
    ) -> Self {
        self.llm.llm_credentials.set(store);
        self
    }

    /// Attach the durable server-manifest store. Same builder
    /// reasoning as [`AdminState::with_policy_store`]: `waygate-server`
    /// calls this when a Postgres pool exists, leaving it `None` (⇒ 503)
    /// otherwise, so the existing `new()` call sites don't churn.
    #[must_use]
    pub fn with_manifest_store(mut self, manifest_store: Option<SharedManifestStore>) -> Self {
        self.servers.manifest_store.set(manifest_store);
        self
    }

    /// Inject the gateway's built-in MCP namespace descriptors for the
    /// read-only "Built-in surfaces" operator view (REST + dashboard). A
    /// post-`new()` opt-in like the other stores; static and secret-free.
    #[must_use]
    pub fn with_builtin_surfaces(
        mut self,
        surfaces: Vec<waygate_mcp::BuiltinSurfaceDescriptor>,
    ) -> Self {
        self.servers.builtin_surfaces = surfaces;
        self
    }

    /// Enable the legacy two-approver rule for direct catalog server
    /// promotion. Same builder reasoning as `with_policy_store`: a
    /// post-`new()` opt-in keeps the existing call sites unchanged.
    #[must_use]
    pub fn with_two_approver_mode(mut self, enabled: bool) -> Self {
        self.hitl.require_two_approvals = enabled;
        self
    }

    /// Override the Overview change-feed allowlist (see
    /// [`DashboardPlane::overview_change_feed_actions`]). `waygate-server` calls this
    /// with the parsed `GATEWAY_OVERVIEW_CHANGE_FEED_ACTIONS` value; an empty
    /// vec is ignored so a blank/whitespace-only env var can't silently blank
    /// the feed (the `new()` default stands instead).
    #[must_use]
    pub fn with_overview_change_feed_actions(mut self, actions: Vec<String>) -> Self {
        if !actions.is_empty() {
            self.dashboard.overview_change_feed_actions = actions;
        }
        self
    }

    /// Attach the frozen-at-boot system info snapshot
    /// rendered on the Settings page. `waygate-server`
    /// builds the snapshot from its `Config` plus the
    /// constructed `IdentityKeyring` and passes it via this
    /// builder; tests can override per-fixture, or omit
    /// entirely and accept the [`SystemInfo::unknown()`]
    /// default `new()` plants.
    #[must_use]
    pub fn with_system_info(mut self, info: Arc<SystemInfo>) -> Self {
        self.system = info;
        self
    }

    /// Sentinel `SharedEvidence` for tests / dev paths that don't care
    /// about evidence emission. `NullSink::record_best_effort` is a
    /// log-and-drop noop so handlers can always record unconditionally.
    pub fn null_evidence() -> SharedEvidence {
        Arc::new(NullSink)
    }
}
