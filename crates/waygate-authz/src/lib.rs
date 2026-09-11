//! Cedar-backed authorization.
//!
//! The `AuthzEngine` trait lets the MCP layer hold any authorization backend
//! — the real Cedar engine in production, an allow-all stub in tests, a
//! deny-all when policy is misconfigured. Decisions are always
//! deterministic: no policy set means deny-by-default (baseline forbid).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use waygate_core::Facts;
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;

pub mod break_glass;
pub mod break_glass_gate;
pub mod cedar;
pub mod gate;
pub mod segment;

pub use break_glass::{
    amr_subset_satisfied, scope_pattern_matches, BreakGlassError, BreakGlassLifecycle,
    BreakGlassStore, BreakGlassToken, NewBreakGlassToken, PgBreakGlassStore, SharedBreakGlassStore,
    MAX_LIST_LIMIT,
};
pub use break_glass_gate::BreakGlassGate;
pub use cedar::{
    cross_app_facts, simulation_facts, validate_diagnostics, CedarDiagnostic, CedarEngine,
    CedarError, PolicySnapshot, ResourceSpec, SkillSpec, ToolSpec,
};
pub use gate::CedarGate;
pub use segment::{
    append_policy, ensure_single_policy, policy_statement, remove_policy, replace_policy,
    segment_verified, PolicyFragment, SegmentError,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    StepUpRequired,
    /// An approval-overlay `forbid` (one conditioned on
    /// `!context.approval_present`) is the only thing standing between this
    /// call and an allow: the call may proceed once a live per-call approval
    /// grant is claimed. A caller without the underlying permit still gets a
    /// flat `Deny`.
    ApprovalRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    ListTools,
    SearchTools,
    CallTool {
        name: String,
        risk: RiskTier,
    },
    ListResources,
    ReadResource {
        uri: String,
    },
    ListSkills,
    FetchSkillResource {
        uri: String,
    },
    ReadSkill {
        uri: String,
    },
    AdminManagePolicies,
    AdminManageServers,
    AdminViewTelemetry,
    /// Enterprise-Managed Authorization: obtain an ID-JAG (cross-app
    /// access grant) for a `resource` (an MCP server), acting through a
    /// client. Evaluated against a `Server` resource entity with the
    /// requesting OAuth `client_id` available as `context.client_id`, so
    /// a policy can gate on "is this group allowed to use this client
    /// against this resource". See `crates/waygate-authz/tests/fixtures/policies/40-cross-app-access.cedar`
    /// and `docs/agents/ema.md`.
    GrantCrossAppAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzResult {
    pub decision: Decision,
    /// Per-policy HUMAN-READABLE explanations pulled from each fired
    /// policy's `@reason("...")` Cedar annotation. Surfaced
    /// to the MCP client + admin UI via `InvocationError::
    /// Forbidden { reasons }`. NEVER carry engine diagnostic
    /// messages here — those are operator-internal and would
    /// leak Cedar internals to a denied caller. Empty when no
    /// fired policy carries the annotation.
    pub reasons: Vec<String>,
    /// Cedar `diagnostics().reason()`: the policy IDs of
    /// every policy that contributed to the decision.
    /// Machine-readable identifier; `reasons` is the
    /// parallel human-readable list.
    pub policy_ids: Vec<String>,
}

impl AuthzResult {
    pub fn is_allow(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }
}

/// Error-preserving outcome of [`AuthzEngine::try_evaluate_facts`].
///
/// The plain [`evaluate_facts`](AuthzEngine::evaluate_facts) collapses an
/// engine/build error into a baseline `Deny` (fail closed) — correct for the
/// upstream tool plane, which treats every `Deny` as a denial. But the
/// built-in **forbid-overlay** distinguishes a *clean* baseline deny (no policy
/// governs the built-in → proceed; the scope self-gate is the authoritative
/// floor) from a deny it should NOT trust (an engine error). Those two are
/// byte-identical at the `AuthzResult` level (`Deny` with empty `policy_ids`),
/// so this variant carries the distinction the overlay needs to fail closed on
/// the error path instead of waving the call through.
#[derive(Debug, Clone)]
pub enum AuthzOutcome {
    /// The engine reached a decision (possibly `Deny`).
    Decided(AuthzResult),
    /// The engine could not reach a decision — a misbuilt request/entities or a
    /// Cedar evaluation error. Callers governing a side effect MUST fail closed.
    EngineError,
}

/// Policy-engine-agnostic interface used by the MCP handler.
///
/// The decision is made over the typed [`Facts`]
/// ([`evaluate_facts`](AuthzEngine::evaluate_facts)). The
/// `(Principal, Action, ResourceSpec)` [`evaluate`](AuthzEngine::evaluate)
/// is a provided adapter for the discovery path that still holds those
/// inputs — it bridges to `evaluate_facts` via the gate's PIP.
pub trait AuthzEngine: Send + Sync + 'static {
    /// Evaluate a decision over the assembled [`Facts`].
    fn evaluate_facts(&self, facts: &Facts) -> AuthzResult;

    /// Like [`evaluate_facts`](AuthzEngine::evaluate_facts) but surfaces an
    /// engine/build error as [`AuthzOutcome::EngineError`] instead of
    /// collapsing it into a baseline `Deny`. The built-in forbid-overlay uses
    /// this so it can fail closed on an error while still proceeding on a clean
    /// baseline deny (the two are indistinguishable through `evaluate_facts`).
    ///
    /// Default: engines that cannot fail (allow-all / deny-all stubs) reuse
    /// their infallible `evaluate_facts`. The Cedar-backed engines override
    /// this to report the error.
    fn try_evaluate_facts(&self, facts: &Facts) -> AuthzOutcome {
        AuthzOutcome::Decided(self.evaluate_facts(facts))
    }

    /// Adapter for callers that hold `(Principal, Action, ResourceSpec)`.
    /// Builds `Facts` from those inputs and delegates to
    /// [`evaluate_facts`](AuthzEngine::evaluate_facts).
    fn evaluate(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &ResourceSpec,
    ) -> AuthzResult {
        self.evaluate_facts(&crate::cedar::facts_from(principal, action, resource))
    }
}

impl AuthzEngine for CedarEngine {
    fn evaluate_facts(&self, facts: &Facts) -> AuthzResult {
        match CedarEngine::evaluate_facts(self, facts) {
            Ok(r) => r,
            Err(e) => {
                // Fail closed on engine error; a misbuilt request or entity
                // must not quietly allow. The error message stays in the
                // server log — do NOT route it through `reasons`, which
                // gets surfaced to denied clients and would leak Cedar
                // internals (entity shape, attr names, policy syntax) to
                // a caller who shouldn't see how the engine failed.
                tracing::error!(error = %e, "cedar evaluate errored; denying");
                AuthzResult {
                    decision: Decision::Deny,
                    reasons: Vec::new(),
                    policy_ids: Vec::new(),
                }
            }
        }
    }

    fn try_evaluate_facts(&self, facts: &Facts) -> AuthzOutcome {
        // Surface the engine error instead of collapsing it into a baseline
        // Deny. `evaluate_facts_strict` reports BOTH a build error (Result::Err)
        // AND a request-time Cedar evaluation error (diagnostics().errors()) —
        // both are fail-closed cases for the built-in overlay, which cannot tell
        // a dropped policy from "no governance authored". The lenient
        // `evaluate_facts` above also refuses an erroring `forbid` (it maps the
        // error to Deny), and differs only in skipping an erroring `permit`,
        // which cannot widen access.
        match CedarEngine::evaluate_facts_strict(self, facts) {
            Ok(r) => AuthzOutcome::Decided(r),
            Err(e) => {
                tracing::error!(error = %e, "cedar evaluate errored; failing closed");
                AuthzOutcome::EngineError
            }
        }
    }
}

/// Tenant-selected Cedar engine registry that can be swapped atomically on
/// SIGHUP or the policy doorbell.
///
/// The whole point is to let an operator edit policies and reload without
/// restarting the gateway (and dropping live MCP sessions). The default tenant
/// is file-backed; published non-default tenant engines override it. Readers
/// grab the engine selected by `Facts.tenant` before each evaluation — swap
/// semantics are: in-flight evaluations complete against the old engine, new
/// evaluations start against the new engine, no locking on the hot path beyond
/// a one-shot `Arc::clone`.
///
/// Implementation: one `RwLock<CedarRegistry>` whose entries hold `Arc`s. An
/// `ArcSwap` would be more idiomatic but this crate would like to stay
/// zero-deps beyond Cedar itself; writes happen only on reload, never per call.
struct CedarRegistry {
    default: Arc<CedarEngine>,
    tenants: HashMap<String, TenantCedar>,
}

struct TenantCedar {
    engine: Arc<CedarEngine>,
    /// Hash of the source compiled into `engine`. Older/test-only callers may
    /// omit it; production reload paths always publish it so convergence can
    /// compare policy content rather than tenant identifiers alone.
    content_hash: Option<String>,
}

pub struct ReloadableCedar {
    inner: RwLock<CedarRegistry>,
    tenant_generation: std::sync::atomic::AtomicU64,
}

impl ReloadableCedar {
    pub fn new(engine: CedarEngine) -> Self {
        Self {
            inner: RwLock::new(CedarRegistry {
                default: Arc::new(engine),
                tenants: HashMap::new(),
            }),
            tenant_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Current file-backed default engine for boot, reload, and health paths.
    /// Caller-facing diagnostics must use [`Self::snapshot_for_tenant`].
    pub fn snapshot(&self) -> Arc<CedarEngine> {
        self.inner
            .read()
            .expect("reloadable cedar lock poisoned")
            .default
            .clone()
    }

    /// Return the policy engine for `tenant_id`, falling back to the
    /// file-backed default engine only when the tenant has no published bundle.
    pub fn snapshot_for_tenant(&self, tenant_id: &str) -> Arc<CedarEngine> {
        let registry = self.inner.read().expect("reloadable cedar lock poisoned");
        registry
            .tenants
            .get(tenant_id)
            .map(|tenant| tenant.engine.clone())
            .unwrap_or_else(|| registry.default.clone())
    }

    /// Install a fresh engine. Called from the SIGHUP handler after a
    /// successful `CedarEngine::load_dir`.
    pub fn reload(&self, engine: CedarEngine) {
        self.inner
            .write()
            .expect("reloadable cedar lock poisoned")
            .default = Arc::new(engine);
    }

    /// Atomically replace the complete non-default tenant policy registry.
    /// Callers compile every candidate before invoking this method, so a broken
    /// bundle never partially updates the live tenant set.
    pub fn replace_tenants(&self, engines: HashMap<String, CedarEngine>) {
        let tenants = engines
            .into_iter()
            .map(|(tenant, engine)| {
                (
                    tenant,
                    TenantCedar {
                        engine: Arc::new(engine),
                        content_hash: None,
                    },
                )
            })
            .collect();
        let mut registry = self.inner.write().expect("reloadable cedar lock poisoned");
        registry.tenants = tenants;
        self.tenant_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Replace the tenant registry only if no local lifecycle mutation landed
    /// after `expected_generation` was observed. The generation check and swap
    /// share the registry write lock, closing the window between an async
    /// database read and installation of its snapshot.
    pub fn replace_tenants_if_generation(
        &self,
        expected_generation: u64,
        engines: HashMap<String, CedarEngine>,
    ) -> bool {
        let tenants = engines
            .into_iter()
            .map(|(tenant, engine)| {
                (
                    tenant,
                    TenantCedar {
                        engine: Arc::new(engine),
                        content_hash: None,
                    },
                )
            })
            .collect();
        let mut registry = self.inner.write().expect("reloadable cedar lock poisoned");
        if self
            .tenant_generation
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_generation
        {
            return false;
        }
        registry.tenants = tenants;
        self.tenant_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        true
    }

    /// Atomically replace the complete non-default tenant registry together
    /// with the source hash compiled into each engine.
    pub fn replace_tenants_with_fingerprints(
        &self,
        engines: HashMap<String, (CedarEngine, String)>,
    ) {
        let tenants = tenant_entries_with_fingerprints(engines);
        let mut registry = self.inner.write().expect("reloadable cedar lock poisoned");
        registry.tenants = tenants;
        self.tenant_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Generation-fenced variant of [`Self::replace_tenants_with_fingerprints`].
    pub fn replace_tenants_with_fingerprints_if_generation(
        &self,
        expected_generation: u64,
        engines: HashMap<String, (CedarEngine, String)>,
    ) -> bool {
        let tenants = tenant_entries_with_fingerprints(engines);
        let mut registry = self.inner.write().expect("reloadable cedar lock poisoned");
        if self
            .tenant_generation
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_generation
        {
            return false;
        }
        registry.tenants = tenants;
        self.tenant_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        true
    }

    /// Remove one tenant override immediately on this replica. The default
    /// engine becomes the fallback for subsequent evaluations while the
    /// cross-replica reload signal converges the rest of the fleet.
    pub fn remove_tenant(&self, tenant_id: &str) -> bool {
        let mut registry = self.inner.write().expect("reloadable cedar lock poisoned");
        let removed = registry.tenants.remove(tenant_id).is_some();
        if removed {
            self.tenant_generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        removed
    }

    /// Sorted tenant identifiers currently carrying an override. Reload uses
    /// this with the durable signature: equal content hashes alone are not an
    /// unchanged state when a lifecycle mutation removed a live entry.
    pub fn tenant_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self
            .inner
            .read()
            .expect("reloadable cedar lock poisoned")
            .tenants
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    /// Sorted `(tenant_id, policy_content_hash)` entries for the exact tenant
    /// engines currently served. `None` means a caller installed at least one
    /// engine without a source fingerprint, so content equality cannot be
    /// established safely from this snapshot.
    pub fn tenant_policy_fingerprints(&self) -> Option<Vec<(String, String)>> {
        let registry = self.inner.read().expect("reloadable cedar lock poisoned");
        let mut fingerprints = Vec::with_capacity(registry.tenants.len());
        for (tenant_id, tenant) in &registry.tenants {
            fingerprints.push((tenant_id.clone(), tenant.content_hash.clone()?));
        }
        fingerprints.sort_by(|left, right| left.0.cmp(&right.0));
        Some(fingerprints)
    }

    /// Monotonic generation for tenant-registry mutations on this replica.
    /// A reload that awaited database work must not overwrite a newer local
    /// lifecycle mutation with its older snapshot.
    pub fn tenant_generation(&self) -> u64 {
        self.tenant_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn tenant_count(&self) -> usize {
        self.inner
            .read()
            .expect("reloadable cedar lock poisoned")
            .tenants
            .len()
    }

    /// Loaded policies for the selected tenant. This is the diagnostic
    /// counterpart to runtime evaluation and must use the same fallback rule;
    /// returning the default snapshot unconditionally would expose another
    /// tenant's policy source and produce misleading traces.
    pub fn list_policies_for_tenant(&self, tenant_id: &str) -> Vec<PolicySnapshot> {
        self.snapshot_for_tenant(tenant_id).list_policies()
    }

    /// Union every scope referenced by the serving default and tenant policy
    /// engines. The scope registry is a name catalog, so reconciliation is
    /// intentionally global even though authorization remains tenant-selected.
    pub fn referenced_scopes(&self) -> std::collections::BTreeSet<String> {
        let registry = self.inner.read().expect("reloadable cedar lock poisoned");
        let mut scopes = registry.default.referenced_scopes();
        for tenant in registry.tenants.values() {
            scopes.extend(tenant.engine.referenced_scopes());
        }
        scopes
    }

    /// Loaded policies for the file-backed default tenant.
    ///
    /// Prefer [`Self::list_policies_for_tenant`] for caller-facing diagnostics.
    pub fn list_policies(&self) -> Vec<PolicySnapshot> {
        self.snapshot().list_policies()
    }
}

fn tenant_entries_with_fingerprints(
    engines: HashMap<String, (CedarEngine, String)>,
) -> HashMap<String, TenantCedar> {
    engines
        .into_iter()
        .map(|(tenant, (engine, content_hash))| {
            (
                tenant,
                TenantCedar {
                    engine: Arc::new(engine),
                    content_hash: Some(content_hash),
                },
            )
        })
        .collect()
}

impl AuthzEngine for ReloadableCedar {
    fn evaluate_facts(&self, facts: &Facts) -> AuthzResult {
        // Take a cheap Arc clone so the RwLock doesn't serialize concurrent
        // evaluates. The clone outlives the drop of the read guard.
        let engine = self.snapshot_for_tenant(facts.tenant.tenant_id.as_str());
        <CedarEngine as AuthzEngine>::evaluate_facts(engine.as_ref(), facts)
    }

    fn try_evaluate_facts(&self, facts: &Facts) -> AuthzOutcome {
        let engine = self.snapshot_for_tenant(facts.tenant.tenant_id.as_str());
        <CedarEngine as AuthzEngine>::try_evaluate_facts(engine.as_ref(), facts)
    }
}

/// Open-door engine for dev / unit tests. Never ship this in production.
pub struct AllowAll;

impl AuthzEngine for AllowAll {
    fn evaluate_facts(&self, _facts: &Facts) -> AuthzResult {
        AuthzResult {
            decision: Decision::Allow,
            reasons: vec!["allow-all engine".into()],
            policy_ids: Vec::new(),
        }
    }
}

/// Fail-closed engine. Useful as a safety default when policy loading fails.
pub struct DenyAll;

impl AuthzEngine for DenyAll {
    fn evaluate_facts(&self, _facts: &Facts) -> AuthzResult {
        AuthzResult {
            decision: Decision::Deny,
            reasons: vec!["deny-all engine".into()],
            policy_ids: Vec::new(),
        }
    }
}
