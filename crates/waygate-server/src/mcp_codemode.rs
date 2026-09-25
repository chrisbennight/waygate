//! Gateway-native Code Mode discovery and execution surface.
//!
//! Search and describe expose the runtime-neutral connector contract. Execute
//! starts a fresh external JavaScript runtime whose connector calls re-enter the
//! ordinary governed invocation pipeline under the original principal.

use crate::codemode_limits::limits;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, JsonObject, Task, TaskStatus, Tool, ToolAnnotations};
use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
#[cfg(test)]
use waygate_codemode::DetachedExecutionSlot;
use waygate_codemode::{
    source_digest, ExecutionArtifact, ExecutionArtifactContent, ExecutionClaim, ExecutionEventKind,
    ExecutionStatus, ExecutionTransition, NewExecution, NewExecutionEvent, ResumeExecution,
    RetryEquivalence, SharedExecutionStore, SharedSourceArtifactStore, SourceArtifactOwner,
    StartExecution, StartExecutionResult, MAX_SOURCE_LOCATORS_PER_OWNER,
    MAX_SOURCE_LOCATORS_PER_TENANT,
};
use waygate_invocation::{
    InvocationContractIdentity, InvocationHierarchy, InvocationRequest, InvocationResponse,
    InvocationRisk, SharedInvocation,
};

use waygate_core::RiskTier;
use waygate_mcp::authz::{profile_blocks_server, profile_blocks_tool};
use waygate_mcp::catalog::{InvocationToolSnapshot, ResolutionAuthority};
use waygate_mcp::tool_schema::input_schema_value_has_object_root;
use waygate_mcp::{
    rank_visible_tools, AuditEvent, AuditOutcome, AuthorizedCatalog, BuiltinCatalog,
    BuiltinProfileScope, BuiltinRegistry, BuiltinSurfaceDescriptor, BuiltinTools,
    CatalogAuthorization, CatalogChannel, CatalogTool, CatalogToolSource, SharedAuthz,
    SharedBuiltinTools, SharedCatalog, SharedEvidence, ToolCatalogEpoch,
};
use waygate_oidc::session::HasExp;
use waygate_oidc::{Principal, Scope};

use crate::config::CodeModeCapacityLimits;
use crate::mcp_builtin::{schema_obj, structured};
#[cfg(test)]
use crate::process_mode::codemode_protocol::encode_frame;
use crate::process_mode::codemode_protocol::{
    bounded_failure_message, encode_parent_frame, ConnectorCallResult, ParentFrame, RunnerBinding,
    RunnerFailureCode, RunnerFrame, RunnerResumeContext, CONFINEMENT_PROFILE, RUNNER_FLAG,
    RUNNER_SPOOL_FLAG,
};

pub const NAMESPACE: &str = waygate_core::CODEMODE_BUILTIN_NAMESPACE;
const DEFAULT_SEARCH_LIMIT: u16 = 50;
const MAX_SEARCH_LIMIT: u16 = 100;
const DEFAULT_ARTIFACT_LIMIT: u16 = 50;
const MAX_ARTIFACT_LIMIT: u16 = 100;
const MAX_ARTIFACT_CURSOR_LENGTH: usize = 20;
const DEFAULT_EXECUTION_LIST_LIMIT: u16 = 50;
const MAX_EXECUTION_LIST_LIMIT: u16 = 100;
// A nanosecond keyset timestamp, a UUID, and the separator fit well inside
// this; anything longer is not a cursor this surface issued.
const MAX_EXECUTION_LIST_CURSOR_LENGTH: usize = 80;
const MAX_SELECTOR_LENGTH: usize = 512;
const MAX_CURSOR_LENGTH: usize = 1_024;
const SEARCH_CURSOR_KIND: &str = "codemode-search-v2";
const SEARCH_CURSOR_LIFETIME_SECONDS: i64 = 5 * 60;
const MAX_STABLE_CATALOG_READ_ATTEMPTS: usize = 3;
/// Supported range for the runner budget.
///
/// The floor keeps a misconfiguration from making every program fail before
/// it can do anything; the ceiling bounds how long one caller can hold a
/// runner slot, which is a resource decision rather than a correctness one.
#[cfg(test)]
const DEFAULT_EXECUTION_LIMIT: Duration =
    Duration::from_millis(crate::process_mode::codemode_protocol::default_execution_limit_ms());
const MIN_EXECUTION_LIMIT: Duration = Duration::from_secs(1);
#[cfg(test)]
const MAX_EXECUTION_LIMIT: Duration = Duration::from_secs(86_400);

/// What the parent allows for everything that precedes a program running.
///
/// The parent's clock starts before binding discovery, claiming, process
/// spawn, readiness and start-frame I/O, while the runner's own budget only
/// begins once that frame arrives. Those are different starting points, so the
/// parent must allow for the gap explicitly. Left implicit, a near-limit
/// program would be cut off by the parent before consuming the budget it was
/// granted — and a call timeout would become indistinguishable from budget
/// exhaustion, which is the distinction callers branch on.
///
/// Bounded rather than unbounded so a wedged setup still fails rather than
/// hanging: this is the allowance for setup, not a licence for it.
fn execution_setup_allowance() -> Duration {
    Duration::from_secs(limits().setup_seconds)
}
/// Headroom for the runner's own teardown and final frame after its budget
/// expires, so the parent does not race the runner's precise timeout report.
const EXECUTION_TIMEOUT_HEADROOM: Duration = Duration::from_secs(1);
/// Floor for the durable worker claim lease.
///
/// The lease fences one runner against another claiming the same execution,
/// and the store refuses a terminal write once it has passed. It must
/// therefore outlast the work it fences: an ordinary durable run has
/// no renewal loop, so a lease shorter than the budget would let a program
/// finish and then fail to record its own result.
const EXECUTION_CLAIM_LEASE_FLOOR: Duration = Duration::from_secs(30);
const EXECUTION_RETENTION: time::Duration = time::Duration::days(7);
const MIN_SOURCE_RETENTION_SECONDS: u32 = 60;
const MAX_SOURCE_RETENTION_SECONDS: u32 = 24 * 60 * 60;
/// How long `codemode.cancel` waits for a requested cancellation to settle
/// before reporting whatever status the execution holds. Bounded so the tool
/// stays a quick control-plane call: a runner that has not observed the
/// request within this window is reported as still running rather than waited
/// on, and the caller polls `codemode.status` for the transition.
const EXECUTION_CANCEL_SETTLE_ATTEMPTS: u8 = 20;
const EXECUTION_CANCEL_SETTLE_INTERVAL: Duration = Duration::from_millis(25);
/// Rolling window of program-facing contracts a binary will continue. Both
/// stamps advance together whenever the sandbox surface changes, because a
/// continuation replays the whole program: a binary that does not offer what
/// the program was submitted against must refuse the row rather than run it
/// degraded. `execution.input` is such a change — a runner that does not
/// install it would replay an input-dependent program with no input and take
/// a different path — so an older binary, which knows nothing of these
/// numbers, fails the compatibility check instead.
const LEGACY_SDK_CONTRACT_VERSION: i32 = 2;
const PREVIOUS_SDK_CONTRACT_VERSION: i32 = 3;
const SDK_CONTRACT_VERSION: i32 = 4;
const LEGACY_RUNNER_CONTRACT_VERSION: i32 = 5;
const PREVIOUS_RUNNER_CONTRACT_VERSION: i32 = 6;
const RUNNER_CONTRACT_VERSION: i32 = 7;

/// Process-wide Code Mode admission shared by every MCP session.
///
/// Detached work consumes the detached pool in addition to the ordinary
/// tenant and global pools, so it can never expand total runner concurrency.
pub struct CodeModeExecutionCapacity {
    limits: CodeModeCapacityLimits,
    global: Arc<Semaphore>,
    detached: Arc<Semaphore>,
    tenants: Mutex<HashMap<String, Weak<Semaphore>>>,
    detached_starts: Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
}

impl CodeModeExecutionCapacity {
    pub(crate) fn new(limits: CodeModeCapacityLimits) -> Self {
        Self {
            limits,
            global: Arc::new(Semaphore::new(limits.global)),
            detached: Arc::new(Semaphore::new(limits.detached)),
            tenants: Mutex::new(HashMap::new()),
            detached_starts: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn shared(limits: CodeModeCapacityLimits) -> Arc<Self> {
        Arc::new(Self::new(limits))
    }

    fn tenant(&self, tenant: &str) -> Arc<Semaphore> {
        let mut capacities = self
            .tenants
            .lock()
            .expect("tenant execution capacity registry poisoned");
        capacities.retain(|_, capacity| capacity.strong_count() > 0);
        if let Some(capacity) = capacities.get(tenant).and_then(Weak::upgrade) {
            return capacity;
        }
        let capacity = Arc::new(Semaphore::new(self.limits.per_tenant));
        capacities.insert(tenant.to_owned(), Arc::downgrade(&capacity));
        capacity
    }

    fn acquire_execution(
        &self,
        principal: &Principal,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), McpError> {
        let tenant = self
            .tenant(principal.tenant.as_str())
            .try_acquire_owned()
            .map_err(|_| tenant_execution_capacity())?;
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| execution_capacity())?;
        Ok((tenant, global))
    }

    fn acquire_detached(&self) -> Result<OwnedSemaphorePermit, McpError> {
        self.detached
            .clone()
            .try_acquire_owned()
            .map_err(|_| detached_execution_capacity())
    }

    fn detached_start(&self, dedupe_key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut starts = self
            .detached_starts
            .lock()
            .expect("detached start registry poisoned");
        starts.retain(|_, start| start.strong_count() > 0);
        if let Some(start) = starts.get(dedupe_key).and_then(Weak::upgrade) {
            return start;
        }
        let start = Arc::new(tokio::sync::Mutex::new(()));
        starts.insert(dedupe_key.to_owned(), Arc::downgrade(&start));
        start
    }
}
#[cfg(test)]
#[derive(Default)]
struct AttemptBarrier {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

/// Code Mode facade over the governed upstream catalog and invocation service.
#[derive(Clone)]
pub struct CodeModeTools {
    authorized_catalog: AuthorizedCatalog,
    authz: SharedAuthz,
    audit: SharedEvidence,
    /// Strong ownership for gateway-local handlers that detached executions
    /// may invoke after their request-scoped server has been dropped. This set
    /// excludes Code Mode itself, so it cannot form an ownership cycle.
    builtin_handlers: Arc<[SharedBuiltinTools]>,
    tool_catalog_epoch: ToolCatalogEpoch,
    search_cursor_sealer: Arc<crate::mcp_discovery::DiscoveryCursorSealer>,
    invocation: SharedInvocation,
    execution_store: Option<SharedExecutionStore>,
    source_artifact_store: Option<SharedSourceArtifactStore>,
    source_file_reader: Option<crate::file_transfer::SharedStoredTextReader>,
    skill_catalog: Option<Arc<waygate_skills::ReloadableSkillCatalog>>,
    reviewed_skills: Option<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
    /// Grant store used to revoke execution-bound approvals whenever an
    /// execution's pending request is replaced — an approval minted for an
    /// earlier request must never authorize a later, different effect.
    grant_store: Option<waygate_catalog::SharedCatalogStore>,
    quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    result_persistence_allowed: bool,
    execution_capacity: Arc<CodeModeExecutionCapacity>,
    /// Wall-clock budget granted to each runner, decided here rather than in
    /// the runner so operator policy is enforced on the side that holds it.
    execution_limit: Duration,
    #[cfg(test)]
    attempt_barrier: Option<Arc<AttemptBarrier>>,
}

impl CodeModeTools {
    fn with_call_timeout(&self, tool: &str, arguments: &mut JsonObject) -> Result<Self, McpError> {
        let mut narrowed = self.clone();
        if matches!(tool, "execute" | "start" | "resume" | "start_resume") {
            if let Some(value) = arguments.remove("timeout_seconds") {
                let timeout: ExecutionTimeout =
                    serde_json::from_value(serde_json::json!({"timeout_seconds": value})).map_err(
                        |_| McpError::invalid_params("timeout_seconds must be an integer", None),
                    )?;
                let seconds = timeout
                    .timeout_seconds
                    .unwrap_or(self.execution_limit.as_secs());
                if seconds == 0 || seconds > self.execution_limit.as_secs() {
                    return Err(McpError::invalid_params(
                        "timeout_seconds must be a positive integer no greater than the configured execution default; omit it to use the default",
                        Some(serde_json::json!({"max_seconds": self.execution_limit.as_secs()})),
                    ));
                }
                narrowed.execution_limit = Duration::from_secs(seconds);
            }
        }
        Ok(narrowed)
    }

    pub fn new(catalog: SharedCatalog, authz: SharedAuthz, invocation: SharedInvocation) -> Self {
        Self {
            authorized_catalog: AuthorizedCatalog::new(
                catalog.clone(),
                authz.clone(),
                BuiltinRegistry::default(),
            ),
            authz,
            audit: Arc::new(waygate_mcp::audit::NullSink),
            builtin_handlers: Arc::from([]),
            tool_catalog_epoch: ToolCatalogEpoch::new(),
            search_cursor_sealer: Arc::new(
                crate::mcp_discovery::DiscoveryCursorSealer::process_local(),
            ),
            invocation,
            execution_store: None,
            source_artifact_store: None,
            source_file_reader: None,
            skill_catalog: None,
            reviewed_skills: None,
            grant_store: None,
            quota: None,
            result_persistence_allowed: false,
            execution_capacity: Arc::new(CodeModeExecutionCapacity::new(
                CodeModeCapacityLimits::default(),
            )),
            execution_limit: Duration::from_secs(limits().execution_seconds),
            #[cfg(test)]
            attempt_barrier: None,
        }
    }

    pub fn with_tool_catalog_epoch(mut self, tool_catalog_epoch: ToolCatalogEpoch) -> Self {
        self.tool_catalog_epoch = tool_catalog_epoch;
        self
    }

    pub fn with_builtin_registry(mut self, builtins: BuiltinRegistry) -> Self {
        self.authorized_catalog = self.authorized_catalog.with_builtin_registry(builtins);
        self
    }

    pub fn with_builtin_handlers(mut self, builtins: Vec<SharedBuiltinTools>) -> Self {
        self.builtin_handlers = builtins.into();
        self
    }

    pub fn with_audit(mut self, audit: SharedEvidence) -> Self {
        self.audit = audit;
        self
    }

    pub(crate) fn with_search_cursor_sealer(
        mut self,
        sealer: Arc<crate::mcp_discovery::DiscoveryCursorSealer>,
    ) -> Self {
        self.search_cursor_sealer = sealer;
        self
    }

    async fn stable_visible_codemode_tools(
        &self,
        principal: &Principal,
        channel: CatalogChannel,
    ) -> Result<Vec<CatalogTool>, McpError> {
        for _ in 0..MAX_STABLE_CATALOG_READ_ATTEMPTS {
            let durable_generation = self.authorized_catalog.discovery_generation().await?;
            let error_generation = self.authorized_catalog.discovery_error_generation();
            let Some(local_generation) = self.tool_catalog_epoch.stable_generation() else {
                tokio::task::yield_now().await;
                continue;
            };
            let mut visible = self
                .authorized_catalog
                .visible_tools(Some(principal), channel, true)
                .await;
            let durable_after = self.authorized_catalog.discovery_generation().await?;
            let errors_after = self.authorized_catalog.discovery_error_generation();
            if crate::mcp_discovery::catalog_read_is_stable(
                &self.tool_catalog_epoch,
                local_generation,
                durable_generation,
                durable_after,
                error_generation,
                errors_after,
            ) {
                visible.retain(|candidate| match &candidate.identity.source {
                    CatalogToolSource::Builtin(namespace) => {
                        channel == CatalogChannel::Direct
                            && namespace != NAMESPACE
                            && input_schema_value_has_object_root(&Value::Object(
                                candidate.definition.input_schema.as_ref().clone(),
                            ))
                    }
                    CatalogToolSource::Upstream(_) => {
                        candidate.invocation_snapshot().is_some_and(|snapshot| {
                            snapshot
                                .input_schema()
                                .is_some_and(input_schema_value_has_object_root)
                                && !matches!(
                                    snapshot.authority(),
                                    ResolutionAuthority::SyntheticModel
                                )
                        })
                    }
                });
                return Ok(visible);
            }
            tokio::task::yield_now().await;
        }
        Err(crate::mcp_discovery::catalog_changing())
    }

    pub fn with_execution_store(mut self, execution_store: SharedExecutionStore) -> Self {
        self.execution_store = Some(execution_store);
        self
    }

    pub fn with_source_artifact_store(
        mut self,
        source_artifact_store: SharedSourceArtifactStore,
    ) -> Self {
        self.source_artifact_store = Some(source_artifact_store);
        self
    }

    pub(crate) fn with_source_file_reader(
        mut self,
        source_file_reader: Option<crate::file_transfer::SharedStoredTextReader>,
    ) -> Self {
        self.source_file_reader = source_file_reader;
        self
    }

    pub fn with_skill_script_execution(
        mut self,
        skill_catalog: Option<Arc<waygate_skills::ReloadableSkillCatalog>>,
    ) -> Self {
        self.skill_catalog = skill_catalog;
        self
    }

    pub fn with_reviewed_skills(
        mut self,
        catalog: Option<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
    ) -> Self {
        self.reviewed_skills = catalog;
        self
    }

    pub fn with_grant_store(mut self, grant_store: waygate_catalog::SharedCatalogStore) -> Self {
        self.grant_store = Some(grant_store);
        self
    }

    pub fn with_quota(mut self, quota: Option<Arc<dyn waygate_quota::QuotaService>>) -> Self {
        self.quota = quota;
        self
    }

    pub fn with_result_persistence_allowed(mut self, allowed: bool) -> Self {
        self.result_persistence_allowed = allowed;
        self
    }

    pub fn with_execution_capacity(mut self, capacity: Arc<CodeModeExecutionCapacity>) -> Self {
        self.execution_capacity = capacity;
        self
    }

    #[cfg(test)]
    fn with_attempt_barrier(mut self, barrier: Arc<AttemptBarrier>) -> Self {
        self.attempt_barrier = Some(barrier);
        self
    }

    /// Set the wall-clock budget granted to each runner.
    ///
    /// Clamped defensively for programmatic callers. The operator path does
    /// not rely on this: centralized configuration rejects an out-of-range
    /// value at boot, like every other bounded knob here, so a mistyped
    /// budget fails loudly instead of being silently reinterpreted.
    pub fn with_execution_limit(mut self, limit: Duration) -> Self {
        self.execution_limit = limit.clamp(
            MIN_EXECUTION_LIMIT,
            Duration::from_secs(limits().execution_max_seconds),
        );
        self
    }

    /// Backstop for a whole attempt: setup, the program, and teardown.
    ///
    /// Wide enough that a slow setup never charges the program for time it did
    /// not get, which is why it spans both phases. It is deliberately not the
    /// bound on the program itself — see `program_phase_timeout`.
    fn call_timeout(&self) -> Duration {
        execution_setup_allowance() + self.program_phase_timeout()
    }

    /// Bound on the program phase alone, measured from the start frame.
    ///
    /// The runner arms the same budget when that frame arrives, so ordinarily
    /// it stops itself and reports a precise reason; this is the backstop for
    /// the window where it cannot. A connector call blocks the runner on a
    /// synchronous read, and QuickJS cannot invoke the interrupt handler while
    /// it is blocked, so a program waiting on a connector result overruns its
    /// budget until the result arrives.
    ///
    /// Bounding the phase rather than the attempt is what keeps the operator's
    /// budget meaningful. Under a single attempt-wide bound, allowance that
    /// setup did not spend would stay available to the program, so a fast
    /// setup would silently grant it the whole setup allowance on top of its
    /// budget.
    fn program_phase_timeout(&self) -> Duration {
        self.execution_limit + EXECUTION_TIMEOUT_HEADROOM
    }

    /// Program-phase deadline enforced by the broker for every profile.
    ///
    /// A mutation must never be aborted mid-future, since that
    /// could abandon an effect already in flight upstream while the
    /// journal records a plain timeout. It carries this deadline into the
    /// broker and is checked at fenced journal boundaries instead.
    ///
    /// Call this at the start frame and nowhere earlier. An instant taken
    /// before binding discovery and claiming would charge that setup to the
    /// program, which is how the two profiles come to grant different amounts
    /// of running time for one configured budget.
    fn program_phase_deadline(
        &self,
        profile: CodeExecutionProfile,
    ) -> Option<tokio::time::Instant> {
        match profile {
            CodeExecutionProfile::Direct | CodeExecutionProfile::LegacyApprovalBound => {
                Some(tokio::time::Instant::now() + self.program_phase_timeout())
            }
        }
    }

    /// Lease granted when claiming a durable execution.
    ///
    /// Derived from the budget rather than fixed, because the store refuses a
    /// terminal write once the claim has expired: a lease shorter than the
    /// work it fences would let a long program finish and then be unable to
    /// record its own result.
    fn claim_lease(&self) -> Duration {
        EXECUTION_CLAIM_LEASE_FLOOR.max(self.call_timeout())
    }

    fn acquire_detached_execution_slot(&self) -> Result<OwnedSemaphorePermit, McpError> {
        self.execution_capacity.acquire_detached()
    }
    /// Whether profile confinement withholds a tool that commits durable
    /// background work from this caller.
    ///
    /// This namespace is a delegated data plane, so the router skips its
    /// namespace and tool profile checks and the implementation applies the
    /// caller's profile itself — which it does on every nested connector
    /// decision. That argument covers data reach, and it is why a program can
    /// touch nothing its caller could not touch directly.
    ///
    /// It does not cover a commitment that outlives the call. Starting or
    /// continuing a detached execution creates or advances a durable journal
    /// row and holds tenant and global capacity after returning, which is a
    /// resource the caller spends rather than data it reads. This repository already fails
    /// closed for a tool-confined profile on surfaces that are not the exact
    /// tools it granted, so the same rule applies here: a profile that
    /// enumerates tools must name these to spend that resource.
    ///
    /// Only an enumerated tool grant applies. A profile with no restrictions
    /// is unaffected, and so is one that confines upstream servers without
    /// listing tools: server confinement bounds which connectors a program may
    /// reach, which the nested decisions already enforce, and it is not a
    /// statement about this facade.
    fn profile_withholds_detached(&self, principal: &Principal, tool: &str) -> bool {
        profile_blocks_tool(principal, NAMESPACE, tool)
    }

    fn durable_continuation_available(&self) -> bool {
        self.execution_store.is_some() && self.result_persistence_allowed
    }

    fn source_owner(principal: &Principal) -> SourceArtifactOwner {
        SourceArtifactOwner {
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: principal.issuer.clone(),
        }
    }

    async fn resolve_source(
        &self,
        principal: &Principal,
        selector: SourceSelector,
        retain_for_seconds: Option<u32>,
    ) -> Result<ResolvedSource, McpError> {
        if retain_for_seconds.is_some_and(|seconds| {
            !(MIN_SOURCE_RETENTION_SECONDS..=MAX_SOURCE_RETENTION_SECONDS).contains(&seconds)
        }) {
            return Err(invalid_source_retention());
        }

        let owner = Self::source_owner(principal);
        let (source, requested_digest, source_authority) = match selector {
            SourceSelector::Inline(source) => (source, None, None),
            SourceSelector::File(uri) => {
                let reader = self
                    .source_file_reader
                    .as_ref()
                    .ok_or_else(source_file_unavailable)?;
                let file = reader
                    .read_text(principal, &uri, limits().source_bytes)
                    .await
                    .map_err(source_file_error)?;
                (file.text, Some(file.sha256), None)
            }
            SourceSelector::Retained(digest) => {
                if !valid_source_digest(&digest) {
                    return Err(invalid_source_digest());
                }
                let store = self
                    .source_artifact_store
                    .as_ref()
                    .ok_or_else(source_artifact_unavailable)?;
                let artifact = store
                    .resolve_source(&owner, &digest)
                    .await
                    .map_err(|error| {
                        tracing::error!(%error, "could not resolve retained Code Mode source");
                        source_artifact_unavailable()
                    })?
                    .ok_or_else(source_artifact_not_found)?;
                (artifact.source, Some(digest), None)
            }
            SourceSelector::SkillScript(uri, revision) => {
                self.resolve_skill_script(principal, &uri, revision.as_deref())
                    .await?
            }
        };
        validate_source(&source)?;
        let digest = source_digest(&source);
        if requested_digest
            .as_deref()
            .is_some_and(|expected| expected != digest)
        {
            tracing::error!("resolved Code Mode source did not match its recorded digest");
            return Err(source_artifact_unavailable());
        }

        Ok(ResolvedSource {
            source,
            digest,
            retention: retain_for_seconds.map(|seconds| Duration::from_secs(u64::from(seconds))),
            source_authority,
        })
    }

    async fn resolve_skill_script(
        &self,
        principal: &Principal,
        resource_uri: &str,
        requested_revision: Option<&str>,
    ) -> Result<(String, Option<String>, Option<Value>), McpError> {
        let catalog = self
            .skill_catalog
            .as_ref()
            .ok_or_else(skill_script_catalog_unavailable)?;
        let reviewed = self
            .reviewed_skills
            .as_ref()
            .ok_or_else(skill_script_catalog_unavailable)?;
        let snapshot = reviewed
            .resolve(principal.tenant.as_str(), resource_uri, requested_revision)
            .await
            .map_err(|_| skill_script_catalog_unavailable())?;
        let descriptor = snapshot
            .resource(resource_uri)
            .ok_or_else(skill_script_not_found)?;
        let access = waygate_mcp::server::SkillResourceAccess::new(&self.authz, &self.audit);
        access
            .authorize_fetch(principal, &snapshot, resource_uri)
            .await?;
        if descriptor.size > limits().source_bytes as u64 {
            return Err(McpError::invalid_params(
                format!(
                    "skill Code Mode source exceeds the {}-byte source limit",
                    limits().source_bytes
                ),
                Some(
                    serde_json::json!({"error": "source_too_large", "max_bytes": limits().source_bytes}),
                ),
            ));
        }
        let loaded = catalog
            .load_resource(&snapshot, resource_uri)
            .await
            .map_err(|_| skill_script_catalog_unavailable())?
            .expect("resource membership was checked in the same snapshot");
        let resource_identity = snapshot
            .resource_identity(resource_uri, loaded.content_digest)
            .expect("verified catalog resource has an identity");
        let policies = access
            .authorize_gateway_skill_read(Some(principal), &resource_identity)
            .await?
            .expect("skill source loading has a principal");
        // Recheck distribution access after loading the source.
        let current_access = async {
            let current = reviewed
                .resolve(principal.tenant.as_str(), resource_uri, requested_revision)
                .await
                .map_err(|_| skill_script_catalog_changed())?;
            let current_identity = current
                .resource_identity(resource_uri, resource_identity.resource_digest.clone())
                .ok_or_else(skill_script_catalog_changed)?;
            if current_identity != resource_identity {
                return Err(skill_script_catalog_changed());
            }
            Ok(())
        }
        .await;
        access
            .record_gateway_skill_read(
                principal,
                &resource_identity,
                &policies,
                if current_access.is_ok() {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Denied
                },
                current_access
                    .as_ref()
                    .err()
                    .map(|error| error.message.as_ref()),
            )
            .await;
        current_access?;
        let source = std::str::from_utf8(&loaded.bytes)
            .map_err(|_| skill_script_incompatible())?
            .to_owned();

        let revision = &resource_identity.revision;
        Ok((
            source,
            Some(
                resource_identity
                    .resource_digest
                    .strip_prefix("sha256:")
                    .expect("verified resource digest has sha256 prefix")
                    .to_owned(),
            ),
            Some(serde_json::json!({
                "kind": "skill_script",
                "source_origin": revision.source_origin,
                "artifact_digest": revision.artifact_digest,
                "source_tree_digest": revision.source_tree_digest,
                "skill_uri": revision.skill_uri,
                "revision_digest": revision.revision_digest,
                // Keep the persisted retry identity compatible with older binaries.
                "approval_digest": revision.legacy_script_execution_digest(),
                "resource_uri": resource_identity.resource_uri,
                "source_path": resource_identity.source_path,
                "source_object": resource_identity.source_object,
                "resource_digest": resource_identity.resource_digest,
                "execution_profile": CodeExecutionProfile::Direct.as_str(),
            })),
        ))
    }

    async fn retain_resolved_source(
        &self,
        principal: &Principal,
        source: &mut ResolvedSource,
    ) -> Result<(), McpError> {
        let Some(retention) = source.retention.take() else {
            return Ok(());
        };
        let store = self
            .source_artifact_store
            .as_ref()
            .ok_or_else(source_artifact_unavailable)?;
        store
            .retain_source(
                &Self::source_owner(principal),
                &source.source,
                &source.digest,
                retention,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, "could not retain Code Mode source");
                match error {
                    waygate_core::store::StoreError::Conflict => source_artifact_capacity(),
                    _ => source_artifact_unavailable(),
                }
            })?;
        Ok(())
    }

    async fn live_source_reference(
        &self,
        principal: &Principal,
        source_digest: &str,
    ) -> SourceReference {
        let mut reference = SourceReference {
            sha256: source_digest.to_owned(),
            expires_at: None,
            retention_state: SourceRetentionState::NotRetained,
        };
        let Some(store) = self.source_artifact_store.as_ref() else {
            return reference;
        };
        match store
            .resolve_source_expiry(&Self::source_owner(principal), source_digest)
            .await
        {
            Ok(Some(expires_at)) => {
                reference.expires_at = Some(waygate_core::fmt::format_ts_rfc3339(expires_at));
                reference.retention_state = SourceRetentionState::Live;
            }
            Ok(None) => {}
            Err(error) => {
                reference.retention_state = SourceRetentionState::Unavailable;
                tracing::warn!(
                    %error,
                    source_digest,
                    "could not read retained Code Mode source expiry"
                );
            }
        }
        reference
    }

    async fn execution_status_response(
        &self,
        principal: &Principal,
        execution: &waygate_codemode::Execution,
    ) -> ExecutionStatusResponse {
        let mut response = execution_status_projection(execution);
        response.source_ref = Some(
            self.live_source_reference(principal, &execution.source_digest)
                .await,
        );
        response
    }

    async fn search(
        &self,
        principal: &Principal,
        params: SearchParams,
    ) -> Result<CallToolResult, McpError> {
        let cursor_supplied = params.cursor.is_some();
        if params
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_CURSOR_LENGTH)
        {
            waygate_telemetry::metrics::record_discovery_cursor(
                waygate_telemetry::metrics::DiscoverySurface::CodeMode,
                false,
            );
            return Err(McpError::invalid_params(
                format!("`cursor` must be at most {MAX_CURSOR_LENGTH} bytes"),
                None,
            ));
        }
        validate_search_params(&params)?;
        let limit = params.limit.unwrap_or(DEFAULT_SEARCH_LIMIT);
        let limit = usize::from(limit);
        let query = params
            .query
            .as_deref()
            .map(str::trim)
            .filter(|query| !query.is_empty())
            .map(str::to_owned);
        let mut candidates = self
            .stable_visible_codemode_tools(principal, CatalogChannel::Direct)
            .await?;
        candidates.retain(|candidate| {
            selector_admitted(candidate.identity.source.name(), &candidate.identity.name)
        });
        if let Some(query) = query.as_deref() {
            candidates = rank_visible_tools(query, candidates);
        }
        let principal_binding = crate::mcp_discovery::principal_binding(principal)?;
        let query_binding = crate::mcp_discovery::digest_field(
            b"codemode-search-query-v2\0",
            query.as_deref().unwrap_or_default().as_bytes(),
        );
        let view_binding = crate::mcp_discovery::search_view_binding(&candidates)?;
        let start = search_cursor_offset(
            params.cursor.as_deref(),
            &principal_binding,
            &query_binding,
            &view_binding,
            candidates.len(),
            &self.search_cursor_sealer,
        );
        if cursor_supplied {
            waygate_telemetry::metrics::record_discovery_cursor(
                waygate_telemetry::metrics::DiscoverySurface::CodeMode,
                start.is_ok(),
            );
        }
        let start = start?;
        let end = start.saturating_add(limit).min(candidates.len());
        let has_more = end < candidates.len();

        let mut tools = Vec::with_capacity(end.saturating_sub(start));
        for tool in candidates.into_iter().skip(start).take(end - start) {
            let fully_qualified = tool.identity.qualified_name();
            tools.push(
                summary(&fully_qualified, &tool)
                    .expect("stable Code Mode catalog retains only callable contracts"),
            );
        }

        let next_cursor = has_more
            .then(|| {
                search_cursor(
                    end,
                    &principal_binding,
                    &query_binding,
                    &view_binding,
                    &self.search_cursor_sealer,
                )
            })
            .transpose()?;
        Ok(structured(&SearchResponse {
            contract_version: ContractVersion::V1,
            tools,
            next_cursor,
        }))
    }

    async fn describe(
        &self,
        principal: &Principal,
        params: DescribeParams,
    ) -> Result<CallToolResult, McpError> {
        let admitted = self
            .resolve_describe_target(principal, &params)
            .await?
            .ok_or_else(|| unknown_tool(""))?;
        let contract = connector_contract_for_tool(&admitted).ok_or_else(|| unknown_tool(""))?;
        Ok(structured(&contract))
    }

    async fn resolve_describe_target(
        &self,
        principal: &Principal,
        params: &DescribeParams,
    ) -> Result<Option<CatalogTool>, McpError> {
        let visible = self
            .stable_visible_codemode_tools(principal, CatalogChannel::Direct)
            .await?;
        let selected = match (&params.name, &params.connector, &params.operation) {
            (None, Some(server), Some(tool)) if selector_admitted(server, tool) => {
                visible.into_iter().find(|candidate| {
                    candidate.identity.source.name() == server && candidate.identity.name == *tool
                })
            }
            (Some(name), None, None) if name.len() <= MAX_SELECTOR_LENGTH => {
                let mut matches = visible
                    .into_iter()
                    .filter(|candidate| candidate.identity.qualified_name() == *name);
                let selected = matches.next();
                if matches.next().is_some() {
                    return Ok(None);
                }
                selected
            }
            _ => None,
        };
        Ok(selected)
    }

    async fn execute(
        &self,
        principal: &Principal,
        params: StartParams,
    ) -> Result<CallToolResult, McpError> {
        // One published schema serves both consumption shapes of this tool,
        // but only the task-augmented shape creates a retained handle that
        // `repeat_after` could name; the blocking shape refuses it rather
        // than silently ignoring a repetition request.
        let (selector, retain_for_seconds, repeat_after, input) = params.into_parts()?;
        if repeat_after.is_some() {
            return Err(McpError::invalid_params(
                "`repeat_after` applies only to detached starts (`codemode.start` and \
                 task-augmented `execute`); a blocking `codemode.execute` runs \
                 unconditionally and returns its result directly",
                Some(serde_json::json!({"error": "execution_repeat_requires_detached_start"})),
            ));
        }
        let remote_skill_script = matches!(&selector, SourceSelector::SkillScript(..));
        let profile = CodeExecutionProfile::Direct;
        let mut permits = if remote_skill_script {
            self.check_execution_quota(principal, "execute").await?;
            Some(self.execution_capacity.acquire_execution(principal)?)
        } else {
            None
        };
        let source = self
            .resolve_source(principal, selector, retain_for_seconds)
            .await?;
        if !remote_skill_script {
            self.check_execution_quota(principal, "execute").await?;
            permits = Some(self.execution_capacity.acquire_execution(principal)?);
        }
        let permits = permits.expect("source admission acquires execution capacity");
        match self.execution_store.as_ref() {
            Some(store) => {
                self.execute_durable(store, principal, source, input, profile, permits)
                    .await
            }
            None => {
                self.execute_ephemeral(principal, source, input, profile, permits)
                    .await
            }
        }
    }

    async fn resume(
        &self,
        principal: &Principal,
        params: ResumeParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(resume_storage_unavailable());
        }
        self.check_execution_quota(principal, "resume").await?;
        let result = self.resume_durable(principal, params).await?;
        Ok(structured(&result))
    }

    async fn stored_result(
        &self,
        principal: &Principal,
        params: ExecutionReferenceParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(result_storage_unavailable());
        }
        let execution = self
            .task_execution(&params.execution_id, Some(principal))
            .await?
            .ok_or_else(stored_result_unavailable)?;
        let execution_id = execution.id;
        let payload = execution_result_payload(execution)?;
        let result = payload
            .get("result")
            .cloned()
            .ok_or_else(stored_result_unavailable)?;
        Ok(structured(&StoredResultResponse {
            contract_version: ContractVersion::V1,
            reference: ExecutionResultReference { execution_id },
            result,
        }))
    }

    /// Admit and fence an execution, then run it with no caller.
    ///
    /// Admission and the fenced claim both complete before this returns, so a
    /// handle is only ever issued for an execution that was actually accepted;
    /// a caller is never told its work was taken when capacity refused it.
    /// Runner work begins after that, on a task with nobody awaiting it: the
    /// journal, not the response, is where the outcome lands.
    ///
    /// Both consumption shapes route through here. A client using the MCP
    /// Tasks extension and a caller polling the ordinary tool surface must not
    /// be able to observe different lifecycles for the same program, and one
    /// path is the only way to guarantee that.
    async fn start_detached(
        &self,
        principal: &Principal,
        quota_tool: &str,
        params: StartParams,
    ) -> Result<waygate_codemode::Execution, McpError> {
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let (selector, retain_for_seconds, repeat_after, input) = params.into_parts()?;
        let repeat_after = repeat_after
            .as_deref()
            .map(|raw| uuid::Uuid::parse_str(raw).map_err(|_| execution_repeat_unavailable()))
            .transpose()?;
        if retain_for_seconds.is_some_and(|seconds| {
            !(MIN_SOURCE_RETENTION_SECONDS..=MAX_SOURCE_RETENTION_SECONDS).contains(&seconds)
        }) {
            return Err(invalid_source_retention());
        }
        let mut remote_source_admission = if matches!(&selector, SourceSelector::SkillScript(..)) {
            self.check_execution_quota(principal, quota_tool).await?;
            let detached = self.acquire_detached_execution_slot()?;
            let permits = self.execution_capacity.acquire_execution(principal)?;
            Some((detached, permits))
        } else {
            None
        };
        let profile = CodeExecutionProfile::Direct;
        let owner = Self::source_owner(principal);
        let source_locator = detached_source_locator(&selector);
        let mapped_digest = match source_locator.as_deref() {
            Some(locator) => store
                .resolve_source_locator(&owner, locator)
                .await
                .map_err(|error| {
                    tracing::error!(%error, "could not resolve Code Mode source locator");
                    execution_unavailable()
                })?,
            None => None,
        };
        let locator_needs_binding = source_locator.is_some() && mapped_digest.is_none();
        let mut selector = Some(selector);
        let mut resolved = None;
        let digest =
            match detached_known_source_digest(selector.as_ref().expect("source selector"))?
                .or(mapped_digest)
            {
                Some(digest) => digest,
                None => {
                    let source = self
                        .resolve_source(
                            principal,
                            selector.take().expect("unresolved source selector"),
                            retain_for_seconds,
                        )
                        .await?;
                    let digest = source.digest.clone();
                    resolved = Some(source);
                    digest
                }
            };
        let source_authority = resolved
            .as_ref()
            .and_then(|source| source.source_authority.clone());
        let probe = RetryEquivalence {
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: principal.issuer.clone(),
            dedupe_key: detached_start_dedupe_key(
                principal,
                &digest,
                &input,
                source_authority.as_ref(),
            ),
            source_digest: digest.clone(),
            execution_profile: self.durable_execution_profile(
                principal,
                true,
                profile,
                source_authority,
            ),
        };
        // Serialize retry-equivalent starts through their optimistic lookup and
        // durable arbitration. Without this process-local single flight, two
        // callers can both miss below and compete for permits even though only
        // one execution can survive `start_or_reuse`.
        let detached_start = self.execution_capacity.detached_start(&probe.dedupe_key);
        let _detached_start = detached_start.lock().await;
        // The common retry converges here, before any admission cost, and a
        // hit is durable truth. A miss proves nothing: uniqueness is enforced
        // inside `start_or_reuse`, atomically with claiming the execution.
        let latest = store
            .find_retry_equivalent(&probe, None)
            .await
            .map_err(|error| {
                tracing::error!(%error, "could not probe for a retry-equivalent Code Mode start");
                execution_unavailable()
            })?;
        match (&latest, repeat_after) {
            (Some(latest), None) => {
                if locator_needs_binding || retain_for_seconds.is_some() {
                    if remote_source_admission.is_none() {
                        self.check_execution_quota(principal, quota_tool).await?;
                    }
                    if let Some(locator) =
                        source_locator.as_deref().filter(|_| locator_needs_binding)
                    {
                        store
                            .bind_source_locator(&owner, locator, &digest, latest.retention_until)
                            .await
                            .map_err(|error| {
                                tracing::error!(%error, "could not bind Code Mode source locator");
                                source_locator_store_error(error)
                            })?;
                    }
                    if retain_for_seconds.is_some() && resolved.is_none() {
                        resolved = Some(
                            self.resolve_source(
                                principal,
                                selector.take().expect("unresolved source selector"),
                                retain_for_seconds,
                            )
                            .await?,
                        );
                    }
                    let mut retention_source = match resolved.take() {
                        Some(source) => source,
                        None => resolved_execution_source(latest, retain_for_seconds)?,
                    };
                    self.retain_resolved_source(principal, &mut retention_source)
                        .await?;
                }
                return Ok(latest.clone());
            }
            (Some(latest), Some(repeat)) if latest.id != repeat => {
                // The chain already moved past the named handle. When that
                // handle is a retained member of this retry-equivalence
                // chain — under exactly the store's dedupe-key and retention
                // predicate, so a NULL-keyed blocking execution or an
                // expired row is refused — the requested repetition already
                // happened and a lost-response retry converges on it, even
                // while it still runs, which is why this cannot wait for
                // slot admission.
                let member = store
                    .find_retry_equivalent(&probe, Some(repeat))
                    .await
                    .map_err(|error| {
                        tracing::error!(%error, "could not read the repeat_after execution");
                        execution_unavailable()
                    })?
                    .is_some();
                if member {
                    if locator_needs_binding || retain_for_seconds.is_some() {
                        if remote_source_admission.is_none() {
                            self.check_execution_quota(principal, quota_tool).await?;
                        }
                        if let Some(locator) =
                            source_locator.as_deref().filter(|_| locator_needs_binding)
                        {
                            store
                                .bind_source_locator(
                                    &owner,
                                    locator,
                                    &digest,
                                    latest.retention_until,
                                )
                                .await
                                .map_err(|error| {
                                    tracing::error!(
                                        %error,
                                        "could not bind Code Mode source locator"
                                    );
                                    source_locator_store_error(error)
                                })?;
                        }
                        if retain_for_seconds.is_some() && resolved.is_none() {
                            resolved = Some(
                                self.resolve_source(
                                    principal,
                                    selector.take().expect("unresolved source selector"),
                                    retain_for_seconds,
                                )
                                .await?,
                            );
                        }
                        let mut retention_source = match resolved.take() {
                            Some(source) => source,
                            None => resolved_execution_source(latest, retain_for_seconds)?,
                        };
                        self.retain_resolved_source(principal, &mut retention_source)
                            .await?;
                    }
                    return Ok(latest.clone());
                }
                return Err(execution_repeat_unavailable());
            }
            (Some(latest), Some(_)) => {
                if !latest.status.is_terminal() {
                    return Err(execution_repeat_not_terminal(latest));
                }
                // A locator binding proves only how a prior admitted upload
                // resolved. It can recover a lost response, but deliberate
                // new work must still present a live source selector.
                if resolved.is_none() {
                    resolved = Some(
                        self.resolve_source(
                            principal,
                            selector.take().expect("unresolved source selector"),
                            retain_for_seconds,
                        )
                        .await?,
                    );
                }
                // The caller named the latest matching terminal execution:
                // a deliberate repetition, admitted and inserted below.
            }
            (None, Some(_)) => return Err(execution_repeat_unavailable()),
            (None, None) => {}
        }
        let mut resolved = match (resolved, latest.as_ref()) {
            (Some(resolved), _) => resolved,
            (None, Some(latest)) => resolved_execution_source(latest, retain_for_seconds)?,
            (None, None) => {
                self.resolve_source(
                    principal,
                    selector.take().expect("unresolved source selector"),
                    retain_for_seconds,
                )
                .await?
            }
        };
        // A retry whose digest is known without source I/O consumes no quota.
        // A remote skill script cannot know its content digest until the one
        // selected blob is read, so it is admitted before that read and reuses
        // the same permits here if this becomes new work.
        let (detached_slot, (tenant_permit, capacity_permit)) = match remote_source_admission.take()
        {
            Some(admission) => admission,
            None => {
                self.check_execution_quota(principal, quota_tool).await?;
                let detached = self.acquire_detached_execution_slot()?;
                let permits = self.execution_capacity.acquire_execution(principal)?;
                (detached, permits)
            }
        };
        self.retain_resolved_source(principal, &mut resolved)
            .await?;
        let source = resolved.source;
        let deadline = tokio::time::Instant::now() + self.call_timeout();
        let bindings =
            tokio::time::timeout_at(deadline, self.execution_bindings(principal, profile))
                .await
                .map_err(|_| execution_timeout())??;
        let (admitted_calls, runner_bindings, tool_snapshot) = admit_execution_bindings(bindings);
        let worker = uuid::Uuid::now_v7();
        let started = store
            .start_or_reuse(StartExecution {
                execution: NewExecution {
                    id: uuid::Uuid::now_v7(),
                    tenant_id: probe.tenant_id.clone(),
                    principal_sub: probe.principal_sub.clone(),
                    principal_issuer: probe.principal_issuer.clone(),
                    source: Some(source.clone()),
                    source_digest: digest,
                    program_input: Some(input.clone()),
                    execution_profile: probe.execution_profile.clone(),
                    sdk_contract_version: SDK_CONTRACT_VERSION,
                    runner_contract_version: RUNNER_CONTRACT_VERSION,
                    retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
                },
                dedupe_key: probe.dedupe_key,
                source_locator,
                repeat_after,
                owner: worker,
                lease: self.claim_lease(),
                source: source.clone(),
                tool_snapshot,
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, "could not start-or-reuse a Code Mode execution");
                source_locator_store_error(error)
            })?;
        let (execution, claim) = match started {
            StartExecutionResult::Claimed { execution, claim } => (execution, claim),
            StartExecutionResult::Existing(execution) => {
                return Ok(execution);
            }
            StartExecutionResult::RepeatUnavailable => {
                return Err(execution_repeat_unavailable());
            }
            StartExecutionResult::RepeatNotTerminal(execution) => {
                return Err(execution_repeat_not_terminal(&execution));
            }
        };
        let claimed = ClaimedProgram {
            execution: execution.clone(),
            store: store.clone(),
            claim,
            program: ExecutionProgram {
                source,
                admitted_calls,
                runner_bindings,
                resume: None,
                input,
                profile,
            },
            deadline,
            persist_result: true,
            _tenant_permit: tenant_permit,
            _detached_slot: Some(detached_slot),
            _capacity_permit: capacity_permit,
        };
        let execution_id = execution.id;
        let tools = self.clone();
        let principal = principal.clone();
        tokio::spawn(async move {
            if let Err(error) = tools.run_claimed_program(&principal, claimed).await {
                // There is no caller left to return this to, and the terminal
                // state is journaled regardless. This is for an operator
                // reading logs, not for the poller.
                tracing::debug!(
                    %execution_id,
                    error_code = %error.code.0,
                    "detached Code Mode execution finished without a successful result"
                );
            }
        });
        Ok(execution)
    }

    /// Continue a paused execution without waiting for what follows.
    ///
    /// The detached lifecycle has to survive a pause, or it stops being a
    /// lifecycle: a program that checkpoints would otherwise force the caller
    /// back into the long blocking call it started detached to avoid, which is
    /// the situation this surface exists to remove.
    ///
    /// Claiming happens before this returns, so a resume that cannot be
    /// claimed is refused rather than acknowledged and lost.
    async fn resume_detached(
        &self,
        principal: &Principal,
        params: ResumeParams,
    ) -> Result<waygate_codemode::Execution, McpError> {
        self.execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let detached_slot = self.acquire_detached_execution_slot()?;
        let mut claimed = self.claim_resume(principal, params).await?;
        claimed._detached_slot = Some(detached_slot);
        let handle = claimed.execution.clone();
        let execution_id = handle.id;

        let tools = self.clone();
        let principal = principal.clone();
        tokio::spawn(async move {
            if let Err(error) = tools.run_claimed_program(&principal, claimed).await {
                tracing::debug!(
                    %execution_id,
                    error_code = %error.code.0,
                    "detached Code Mode resume finished without a successful result"
                );
            }
        });
        Ok(handle)
    }

    /// Resume a paused execution and return its handle without waiting.
    ///
    /// The continuation half of the detached surface. It answers the
    /// checkpoint `codemode.status` reported and hands back the same
    /// projection, so a caller alternates between this and status for as many
    /// pauses as the program takes.
    async fn start_resume_execution(
        &self,
        principal: &Principal,
        params: ResumeParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(execution_start_unavailable());
        }
        if self.profile_withholds_detached(principal, "start_resume") {
            return Err(detached_execution_withheld("start_resume"));
        }
        self.check_execution_quota(principal, "start_resume")
            .await?;
        let execution = self.resume_detached(principal, params).await?;
        let response = self.execution_status_response(principal, &execution).await;
        Ok(structured(&response))
    }

    /// Start one durable execution and return its handle without waiting.
    ///
    /// This is the submit half of the submit/poll/cancel surface, for a caller
    /// whose client will not hold a long call open for it. The response is the
    /// same projection `codemode.status` returns, so the first poll and every
    /// later one have one shape.
    ///
    /// Durable storage is required rather than optional here. A handle whose
    /// result cannot be stored is not a handle, so a deployment that cannot
    /// honour one refuses it instead of quietly running the program to nowhere.
    async fn start_execution(
        &self,
        principal: &Principal,
        params: StartParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(execution_start_unavailable());
        }
        if self.profile_withholds_detached(principal, "start") {
            return Err(detached_execution_withheld("start"));
        }
        let execution = self.start_detached(principal, "start", params).await?;
        let response = self.execution_status_response(principal, &execution).await;
        Ok(structured(&response))
    }

    /// Report one durable execution's lifecycle status without its result.
    ///
    /// This is the poll half of the submit/poll/cancel surface. It reads the
    /// same execution journal the MCP Task projection reads, so a caller that
    /// polls here and a client that polls `tasks/get` observe the same status
    /// and the same terminal state for the same execution.
    async fn execution_status(
        &self,
        principal: &Principal,
        params: ExecutionReferenceParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(execution_poll_unavailable());
        }
        let execution = self
            .task_execution(&params.execution_id, Some(principal))
            .await?
            .ok_or_else(execution_status_unavailable)?;
        let response = self.execution_status_response(principal, &execution).await;
        Ok(structured(&response))
    }

    /// List the caller's own in-flight executions, newest first.
    ///
    /// This is the recovery half of retry-safe starting: convergence prevents
    /// an orphan, and this listing finds one that already exists — work whose
    /// handle was garbled or lost with the context that held it. The scoping
    /// is the by-id read's (tenant, subject, issuer, effective profile), so
    /// enumeration hands out only identifiers the caller could already use.
    /// Rows are listed as stored, without reconciliation; polling a
    /// discovered identifier reconciles it, so the listing stays as cheap as
    /// a status poll.
    async fn list_executions(
        &self,
        principal: &Principal,
        params: ExecutionListParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(execution_poll_unavailable());
        }
        validate_execution_list_params(&params)?;
        let before = params
            .cursor
            .as_deref()
            .map(parse_execution_list_cursor)
            .transpose()?;
        let limit = params.limit.unwrap_or(DEFAULT_EXECUTION_LIST_LIMIT);
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let owner = waygate_codemode::OwnedInFlight {
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: principal.issuer.clone(),
            profile_confinement: task_profile_confinement(principal),
        };
        let mut executions = store
            .list_owned_in_flight(&owner, before, limit.saturating_add(1))
            .await
            .map_err(|error| {
                tracing::error!(%error, "could not list Code Mode executions");
                execution_unavailable()
            })?;
        let next_cursor = if executions.len() > usize::from(limit) {
            executions.pop();
            executions.last().map(execution_list_cursor)
        } else {
            None
        };
        Ok(structured(&ExecutionListResponse {
            contract_version: ContractVersion::V1,
            executions: executions.iter().map(in_flight_status_projection).collect(),
            next_cursor,
        }))
    }

    /// Request cancellation of one durable execution.
    ///
    /// Requesting cancellation is not itself terminal: the execution reaches
    /// `cancelled` once it observes the request. This waits briefly for that
    /// transition so the common case returns a settled status, then reports
    /// whatever status the execution actually holds rather than asserting one.
    async fn cancel_execution(
        &self,
        principal: &Principal,
        params: ExecutionReferenceParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(execution_poll_unavailable());
        }
        let execution = self
            .task_execution(&params.execution_id, Some(principal))
            .await?
            .ok_or_else(execution_status_unavailable)?;
        let id = execution.id;
        if execution.status.is_terminal() {
            let response = self.execution_status_response(principal, &execution).await;
            return Ok(structured(&response));
        }
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let mut execution = store
            .request_cancellation(
                principal.tenant.as_str(),
                &principal.sub,
                &principal.issuer,
                id,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, %id, "could not request Code Mode execution cancellation");
                execution_unavailable()
            })?
            .ok_or_else(execution_status_unavailable)?;
        for _ in 0..EXECUTION_CANCEL_SETTLE_ATTEMPTS {
            if execution.status.is_terminal() {
                break;
            }
            tokio::time::sleep(EXECUTION_CANCEL_SETTLE_INTERVAL).await;
            execution = store
                .get(principal.tenant.as_str(), id)
                .await
                .map_err(|error| {
                    tracing::error!(%error, %id, "could not confirm Code Mode execution cancellation");
                    execution_unavailable()
                })?
                .ok_or_else(execution_status_unavailable)?;
            if !execution_owned_by(&execution, principal) {
                return Err(execution_status_unavailable());
            }
        }
        let response = self.execution_status_response(principal, &execution).await;
        Ok(structured(&response))
    }

    async fn artifacts(
        &self,
        principal: &Principal,
        params: ArtifactListParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(artifact_unavailable());
        }
        validate_artifact_list_params(&params)?;
        let after_event_id = params
            .cursor
            .as_deref()
            .map(parse_artifact_cursor)
            .transpose()?;
        let limit = params.limit.unwrap_or(DEFAULT_ARTIFACT_LIMIT);
        let execution = self
            .task_execution(&params.execution_id, Some(principal))
            .await?
            .ok_or_else(stored_artifact_unavailable)?;
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let mut artifacts = store
            .list_artifacts(
                principal.tenant.as_str(),
                execution.id,
                after_event_id,
                limit.saturating_add(1),
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %execution.id,
                    "could not list Code Mode artifacts"
                );
                execution_unavailable()
            })?;
        let next_cursor = if artifacts.len() > usize::from(limit) {
            artifacts.pop();
            artifacts.last().map(artifact_cursor)
        } else {
            None
        };
        Ok(structured(&ArtifactListResponse {
            contract_version: ContractVersion::V1,
            execution_id: execution.id,
            artifacts: artifacts.into_iter().map(artifact_summary).collect(),
            next_cursor,
        }))
    }

    async fn artifact(
        &self,
        principal: &Principal,
        params: ArtifactParams,
    ) -> Result<CallToolResult, McpError> {
        if !self.durable_continuation_available() {
            return Err(artifact_unavailable());
        }
        let artifact_id = uuid::Uuid::parse_str(&params.artifact_id)
            .map_err(|_| stored_artifact_unavailable())?;
        let execution = self
            .task_execution(&params.execution_id, Some(principal))
            .await?
            .ok_or_else(stored_artifact_unavailable)?;
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let artifact = store
            .get_artifact(principal.tenant.as_str(), execution.id, artifact_id)
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %execution.id,
                    "could not read Code Mode artifact"
                );
                execution_unavailable()
            })?
            .ok_or_else(stored_artifact_unavailable)?;
        Ok(structured(&artifact_response(artifact)))
    }

    async fn resume_durable(
        &self,
        principal: &Principal,
        params: ResumeParams,
    ) -> Result<ExecuteResponse, McpError> {
        let claimed = self.claim_resume(principal, params).await?;
        self.run_claimed_program(principal, claimed).await
    }

    async fn claim_resume(
        &self,
        principal: &Principal,
        params: ResumeParams,
    ) -> Result<ClaimedProgram, McpError> {
        if params.input.as_ref().is_some_and(|input| {
            serde_json::to_vec(input)
                .map(|encoded| encoded.len() > limits().input_bytes)
                .unwrap_or(true)
        }) {
            return Err(McpError::invalid_params(
                "Code Mode resume input exceeds the configured input limit",
                Some(serde_json::json!({
                    "error": "execution_resume_input_too_large",
                    "max_bytes": limits().input_bytes,
                })),
            ));
        }
        let id = uuid::Uuid::parse_str(&params.execution_id).map_err(|_| {
            McpError::invalid_params(
                "`execution_id` must be the durable identifier returned by a paused Code Mode \
                 execution",
                Some(serde_json::json!({"error": "execution_resume_unavailable"})),
            )
        })?;
        let execution = self
            .task_execution(&params.execution_id, Some(principal))
            .await?
            .ok_or_else(execution_resume_unavailable)?;
        debug_assert_eq!(id, execution.id);
        if execution.status != ExecutionStatus::WaitingForResume {
            return Err(execution_resume_unavailable());
        }
        if execution
            .execution_profile
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(|name| name != "direct")
        {
            return Err(execution_resume_unavailable());
        }
        let source = execution
            .source
            .clone()
            .ok_or_else(|| execution_resume_incompatible("source_unavailable"))?;
        if source_digest(&source) != execution.source_digest {
            return Err(execution_resume_incompatible("source_changed"));
        }
        let supported_contracts = matches!(
            (
                execution.sdk_contract_version,
                execution.runner_contract_version,
            ),
            (LEGACY_SDK_CONTRACT_VERSION, LEGACY_RUNNER_CONTRACT_VERSION)
                | (
                    PREVIOUS_SDK_CONTRACT_VERSION,
                    PREVIOUS_RUNNER_CONTRACT_VERSION
                )
                | (SDK_CONTRACT_VERSION, PREVIOUS_RUNNER_CONTRACT_VERSION)
                | (PREVIOUS_SDK_CONTRACT_VERSION, RUNNER_CONTRACT_VERSION)
                | (SDK_CONTRACT_VERSION, RUNNER_CONTRACT_VERSION)
        );
        if !supported_contracts {
            let reason = if !matches!(
                execution.sdk_contract_version,
                LEGACY_SDK_CONTRACT_VERSION | PREVIOUS_SDK_CONTRACT_VERSION | SDK_CONTRACT_VERSION
            ) {
                "sdk_contract_changed"
            } else {
                "runner_contract_changed"
            };
            return Err(execution_resume_incompatible(reason));
        }

        let expected_resume_context = execution.resume_context.clone();
        let mut resume_context = expected_resume_context
            .clone()
            .unwrap_or_else(|| serde_json::json!({"checkpoint": null}));
        let Some(context) = resume_context.as_object_mut() else {
            return Err(execution_resume_incompatible("checkpoint_invalid"));
        };
        let effective_input = match context.get("input") {
            Some(bound) => {
                if params.input.as_ref().is_some_and(|input| input != bound) {
                    return Err(execution_resume_incompatible("input_already_bound"));
                }
                bound.clone()
            }
            None => {
                let input = params.input.unwrap_or(Value::Null);
                context.insert("input".to_owned(), input.clone());
                input
            }
        };
        let checkpoint = context.get("checkpoint").cloned().unwrap_or(Value::Null);

        self.claim_waiting_program(
            principal,
            execution,
            WaitingProgram {
                expected_status: ExecutionStatus::WaitingForResume,
                profile: CodeExecutionProfile::Direct,
                source,
                resume_context,
                runner_resume: Some(RunnerResumeContext {
                    checkpoint,
                    input: effective_input,
                }),
            },
        )
        .await
    }

    async fn claim_waiting_program(
        &self,
        principal: &Principal,
        execution: waygate_codemode::Execution,
        waiting: WaitingProgram,
    ) -> Result<ClaimedProgram, McpError> {
        let WaitingProgram {
            expected_status,
            profile,
            source,
            resume_context,
            runner_resume,
        } = waiting;
        let (tenant_permit, capacity_permit) =
            self.execution_capacity.acquire_execution(principal)?;
        let deadline = tokio::time::Instant::now() + self.call_timeout();
        let bindings =
            tokio::time::timeout_at(deadline, self.execution_bindings(principal, profile))
                .await
                .map_err(|_| execution_timeout())??;
        let expected_tool_snapshot = execution
            .tool_snapshot
            .as_ref()
            .ok_or_else(|| execution_resume_incompatible("tool_snapshot_unavailable"))?;
        let bindings = compatible_resume_bindings(bindings, expected_tool_snapshot)
            .map_err(execution_resume_incompatible)?;
        let (admitted_calls, runner_bindings, tool_snapshot) = admit_execution_bindings(bindings);
        debug_assert_eq!(&tool_snapshot, expected_tool_snapshot);

        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let worker = uuid::Uuid::now_v7();
        let id = execution.id;
        let expected_resume_context = execution.resume_context.clone();
        let (execution, claim) = store
            .resume(ResumeExecution {
                tenant_id: principal.tenant.to_string(),
                principal_sub: principal.sub.clone(),
                principal_issuer: principal.issuer.clone(),
                id,
                owner: worker,
                lease: self.claim_lease(),
                expected_status,
                resume_context,
                expected_claim_epoch: execution.claim_epoch,
                expected_resume_context,
                expected_source_digest: execution.source_digest.clone(),
                expected_tool_snapshot: tool_snapshot.clone(),
                expected_sdk_contract_version: execution.sdk_contract_version,
                expected_runner_contract_version: execution.runner_contract_version,
                next_sdk_contract_version: SDK_CONTRACT_VERSION,
                next_runner_contract_version: RUNNER_CONTRACT_VERSION,
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, %id, "could not claim Code Mode continuation");
                execution_unavailable()
            })?
            .ok_or_else(execution_resume_unavailable)?;
        // A continuation replays the program from the top, so it must be given
        // the input its execution was submitted with. Reading it from the
        // durable row rather than the request is what keeps a resumed attempt
        // on the same path as the attempt it continues.
        let input = execution.program_input.clone().unwrap_or(Value::Null);
        Ok(ClaimedProgram {
            execution,
            store: store.clone(),
            claim,
            program: ExecutionProgram {
                source,
                admitted_calls,
                runner_bindings,
                resume: runner_resume,
                input,
                profile,
            },
            deadline,
            persist_result: true,
            _tenant_permit: tenant_permit,
            _detached_slot: None,
            _capacity_permit: capacity_permit,
        })
    }

    async fn run_claimed_program(
        &self,
        principal: &Principal,
        claimed: ClaimedProgram,
    ) -> Result<ExecuteResponse, McpError> {
        let ClaimedProgram {
            store,
            claim,
            program,
            deadline,
            persist_result,
            _tenant_permit,
            _detached_slot,
            _capacity_permit,
            ..
        } = claimed;
        let work = async {
            #[cfg(test)]
            if let Some(barrier) = self.attempt_barrier.as_ref() {
                barrier.entered.notify_one();
                barrier.release.notified().await;
                return Err(execution_timeout());
            }
            self.run_claimed_durable(
                ClaimedExecution {
                    store: &store,
                    principal,
                    claim: &claim,
                    persist_result,
                    deadline,
                },
                program,
            )
            .await
        };
        hold_execution_permits_until(
            ExecutionPermits {
                tenant: _tenant_permit,
                detached: _detached_slot,
                global: _capacity_permit,
            },
            work,
        )
        .await
    }

    async fn check_execution_quota(
        &self,
        principal: &Principal,
        tool: &str,
    ) -> Result<(), McpError> {
        let Some(quota) = self.quota.as_ref() else {
            return Ok(());
        };
        let context = waygate_quota::QuotaContext {
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: Some(principal.sub.clone()),
            client_id: None,
            server: NAMESPACE.to_owned(),
            fq_tool: format!("{NAMESPACE}.{tool}"),
        };
        match quota
            .check_and_consume(&context, &[waygate_quota::QuotaAction::Call])
            .await
        {
            Ok(()) => Ok(()),
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id,
                name,
                retry_after_seconds,
            }) => Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!("rate-limited by policy `{name}`; retry after {retry_after_seconds}s"),
                Some(serde_json::json!({
                    "error": "rate_limited",
                    "policy_id": policy_id.to_string(),
                    "policy_name": name,
                    "retry_after_seconds": retry_after_seconds,
                })),
            )),
            Err(waygate_quota::QuotaError::Sqlx(error)) => {
                tracing::warn!(
                    tenant = %principal.tenant.as_str(),
                    %error,
                    "Code Mode quota store error; allowing execution"
                );
                Ok(())
            }
        }
    }

    async fn execute_ephemeral(
        &self,
        principal: &Principal,
        mut source: ResolvedSource,
        input: Value,
        profile: CodeExecutionProfile,
        permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
    ) -> Result<CallToolResult, McpError> {
        // The attempt clock and the setup allowance share this instant, so the
        // allowance bounds everything before the program rather than restarting
        // once part of that work is already done.
        let started = tokio::time::Instant::now();
        let (_tenant_capacity, _capacity) = permits;
        let bindings = tokio::time::timeout_at(started + execution_setup_allowance(), async {
            self.retain_resolved_source(principal, &mut source).await?;
            self.execution_bindings(principal, profile).await
        })
        .await
        .map_err(|_| execution_timeout())??;
        let source_digest = source.digest;
        let source = source.source;
        let execution_id = uuid::Uuid::now_v7();
        let (admitted_calls, runner_bindings, _) = admit_execution_bindings(bindings);
        let result = self
            .run_external_program(
                RunnerAttempt {
                    principal,
                    execution_id,
                    claim: None,
                    persist_content: false,
                    profile,
                    source_digest,
                    deadline: None,
                },
                ExecutionProgram {
                    source,
                    admitted_calls,
                    runner_bindings,
                    resume: None,
                    input,
                    profile,
                },
                started + execution_setup_allowance(),
            )
            .await?;
        Ok(structured(&result))
    }

    async fn execute_durable(
        &self,
        store: &SharedExecutionStore,
        principal: &Principal,
        mut source: ResolvedSource,
        input: Value,
        profile: CodeExecutionProfile,
        permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
    ) -> Result<CallToolResult, McpError> {
        let persist_content = self.result_persistence_allowed;
        self.retain_resolved_source(principal, &mut source).await?;
        let execution = self
            .submit_durable(store, principal, &source, &input, persist_content, profile)
            .await?;
        let execution_id = execution.id;
        let claimed = self
            .claim_submitted_durable(
                store,
                principal,
                SubmittedProgram {
                    execution_id,
                    source: source.source,
                    input,
                    persist_result: persist_content,
                    profile,
                    permits,
                },
            )
            .await
            .map_err(|error| execution_error_with_id(error, execution_id))?;
        let result = self
            .run_claimed_program(principal, claimed)
            .await
            .map_err(|error| execution_error_with_id(error, execution_id))?;
        Ok(structured(&result))
    }

    /// One builder for the durable execution-profile document. Retry
    /// convergence compares this value for equality, so every durable
    /// submission path must produce it from the same place or identical
    /// requests silently stop being retry-equivalent.
    fn durable_execution_profile(
        &self,
        principal: &Principal,
        persist_result: bool,
        profile: CodeExecutionProfile,
        source_authority: Option<Value>,
    ) -> Value {
        let mut execution_profile = serde_json::json!({
            "name": profile.as_str(),
            "timeout_seconds": self.execution_limit.as_secs(),
            "confinement_profile": CONFINEMENT_PROFILE,
            "profile_confinement": task_profile_confinement(principal),
            // An execution with direct authority must not replay effects after
            // losing its worker. Explicit checkpoints are handled separately.
            "resumable": false,
            "result_storage": if persist_result {
                "allow"
            } else {
                "disabled"
            },
        });
        // Existing executions predate governed skill-script sources. Omitting
        // this optional field for every other source preserves their durable
        // retry-equivalence document across a rolling deployment.
        if let Some(source_authority) = source_authority {
            execution_profile
                .as_object_mut()
                .expect("execution profile is an object")
                .insert("source_authority".into(), source_authority);
        }
        execution_profile
    }

    async fn submit_durable(
        &self,
        store: &SharedExecutionStore,
        principal: &Principal,
        source: &ResolvedSource,
        input: &Value,
        persist_result: bool,
        profile: CodeExecutionProfile,
    ) -> Result<waygate_codemode::Execution, McpError> {
        let execution_id = uuid::Uuid::now_v7();
        store
            .submit(NewExecution {
                id: execution_id,
                tenant_id: principal.tenant.as_str().to_owned(),
                principal_sub: principal.sub.clone(),
                principal_issuer: principal.issuer.clone(),
                source: persist_result.then(|| source.source.clone()),
                source_digest: source.digest.clone(),
                // Bound on exactly the condition the source is: a row that
                // cannot replay its program has no use for the input that
                // program would have read.
                program_input: persist_result.then(|| input.clone()),
                execution_profile: self.durable_execution_profile(
                    principal,
                    persist_result,
                    profile,
                    source.source_authority.clone(),
                ),
                sdk_contract_version: SDK_CONTRACT_VERSION,
                runner_contract_version: RUNNER_CONTRACT_VERSION,
                retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, %execution_id, "could not persist Code Mode execution");
                execution_unavailable()
            })
    }

    async fn claim_submitted_durable(
        &self,
        store: &SharedExecutionStore,
        principal: &Principal,
        submitted: SubmittedProgram,
    ) -> Result<ClaimedProgram, McpError> {
        let SubmittedProgram {
            execution_id,
            source,
            input,
            persist_result,
            profile,
            permits,
        } = submitted;
        let (tenant_permit, capacity_permit) = permits;

        let deadline = tokio::time::Instant::now() + self.call_timeout();
        let bindings =
            match tokio::time::timeout_at(deadline, self.execution_bindings(principal, profile))
                .await
            {
                Ok(Ok(bindings)) => bindings,
                Ok(Err(error)) => {
                    self.persist_pre_claim_failure(store, principal, execution_id, &error)
                        .await?;
                    return Err(error);
                }
                Err(_) => {
                    let error = execution_timeout();
                    self.persist_pre_claim_failure(store, principal, execution_id, &error)
                        .await?;
                    return Err(error);
                }
            };
        let (admitted_calls, runner_bindings, tool_snapshot) = admit_execution_bindings(bindings);
        let worker = uuid::Uuid::now_v7();
        let (execution, claim) = store
            .claim(
                principal.tenant.as_str(),
                execution_id,
                worker,
                self.claim_lease(),
                source.clone(),
                tool_snapshot,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, %execution_id, "could not claim Code Mode execution");
                execution_unavailable()
            })?
            .ok_or_else(execution_unavailable)?;

        Ok(ClaimedProgram {
            execution,
            store: store.clone(),
            claim,
            program: ExecutionProgram {
                source,
                admitted_calls,
                runner_bindings,
                resume: None,
                input,
                profile,
            },
            deadline,
            persist_result,
            _tenant_permit: tenant_permit,
            _detached_slot: None,
            _capacity_permit: capacity_permit,
        })
    }

    async fn run_claimed_durable(
        &self,
        claimed: ClaimedExecution<'_>,
        program: ExecutionProgram,
    ) -> Result<ExecuteResponse, McpError> {
        let profile = program.profile;
        let run = self.run_external_program(
            RunnerAttempt {
                principal: claimed.principal,
                execution_id: claimed.claim.execution_id,
                claim: Some(claimed.claim),
                persist_content: claimed.persist_result,
                profile,
                source_digest: source_digest(&program.source),
                // The program-phase deadline is assigned at the start frame,
                // not here: an instant taken before binding discovery and
                // claiming would charge that setup to the program.
                deadline: None,
            },
            program,
            // The same origin as the attempt deadline: that is
            // `origin + setup allowance + program phase`, so subtracting the
            // program phase recovers the instant the allowance runs out.
            claimed.deadline - self.program_phase_timeout(),
        );
        // All programs can dispatch effects. The broker observes cancellation
        // and deadlines between calls, after an in-flight outcome is journaled.
        let result = match run.await {
            Err(error) => {
                self.persist_claimed_failure(claimed.store, claimed.claim, &error)
                    .await?;
                return Err(error);
            }
            Ok(result) => result,
        };
        if result.status.leaves_execution_waiting() {
            return Ok(result);
        }
        let result_payload = if claimed.persist_result {
            Some(serde_json::to_value(&result).map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claimed.claim.execution_id,
                    "could not encode Code Mode result"
                );
                execution_unavailable()
            })?)
        } else {
            None
        };
        let persisted = claimed
            .store
            .transition(
                claimed.claim,
                ExecutionTransition {
                    from: vec![ExecutionStatus::Running],
                    to: ExecutionStatus::Succeeded,
                    event: execution_event(
                        ExecutionEventKind::Succeeded,
                        None,
                        None,
                        serde_json::json!({
                            "connector_calls": result.connector_calls,
                            "artifacts": result.artifacts.len(),
                        }),
                    ),
                    terminal_reason_code: None,
                    result_metadata: Some(serde_json::json!({
                        "connector_calls": result.connector_calls,
                        "artifacts": result.artifacts.len(),
                    })),
                    result_payload,
                    resume_context: None,
                },
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claimed.claim.execution_id,
                    "could not advance Code Mode journal"
                );
                execution_unavailable()
            })?;
        if persisted.is_none() {
            if self
                .finish_requested_cancellation(claimed.store, claimed.claim)
                .await?
            {
                return Err(execution_cancelled());
            }
            tracing::error!(
                execution_id = %claimed.claim.execution_id,
                "Code Mode execution claim was lost before transition"
            );
            return Err(execution_unavailable());
        }
        Ok(result)
    }

    async fn finish_requested_cancellation(
        &self,
        store: &SharedExecutionStore,
        claim: &ExecutionClaim,
    ) -> Result<bool, McpError> {
        let execution = store
            .get(&claim.tenant_id, claim.execution_id)
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claim.execution_id,
                    "could not resolve Code Mode transition fence"
                );
                execution_unavailable()
            })?
            .ok_or_else(execution_unavailable)?;
        if execution.cancellation_requested_at.is_none() {
            return Ok(false);
        }
        if !execution.status.is_terminal() {
            self.persist_claimed_cancellation(store, claim).await?;
        }
        Ok(true)
    }

    async fn wait_for_cancellation(
        &self,
        store: &SharedExecutionStore,
        principal: &Principal,
        execution_id: uuid::Uuid,
    ) -> Result<(), McpError> {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let execution = store
                .get(principal.tenant.as_str(), execution_id)
                .await
                .map_err(|error| {
                    tracing::error!(
                        %error,
                        %execution_id,
                        "could not observe Code Mode cancellation state"
                    );
                    execution_unavailable()
                })?
                .ok_or_else(execution_unavailable)?;
            if execution.cancellation_requested_at.is_some() {
                return Ok(());
            }
        }
    }

    async fn persist_claimed_cancellation(
        &self,
        store: &SharedExecutionStore,
        claim: &ExecutionClaim,
    ) -> Result<(), McpError> {
        // The requester is no longer on the call path here: this
        // finalization runs when the runner observes a pending request. The
        // row's recorded provenance says whether the owner or an operator
        // asked, so the terminal reason attributes the cancellation to its
        // actual cause; a request that predates the provenance column
        // finalizes under the historical client reason.
        let reason = store
            .get(&claim.tenant_id, claim.execution_id)
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claim.execution_id,
                    "could not read Code Mode cancellation provenance"
                );
                execution_unavailable()
            })?
            .and_then(|execution| execution.cancellation_reason_code)
            .unwrap_or_else(|| "cancelled_by_client".to_owned());
        let persisted = store
            .transition(
                claim,
                ExecutionTransition {
                    from: vec![ExecutionStatus::Running],
                    to: ExecutionStatus::Cancelled,
                    event: execution_event(
                        ExecutionEventKind::Cancelled,
                        None,
                        None,
                        serde_json::json!({"reason_code": reason.as_str()}),
                    ),
                    terminal_reason_code: Some(reason),
                    result_metadata: None,
                    result_payload: None,
                    resume_context: None,
                },
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claim.execution_id,
                    "could not persist Code Mode cancellation"
                );
                execution_unavailable()
            })?;
        if persisted.is_none() {
            tracing::error!(
                execution_id = %claim.execution_id,
                "Code Mode cancellation lost its worker claim"
            );
            return Err(execution_unavailable());
        }
        Ok(())
    }

    async fn persist_pre_claim_failure(
        &self,
        store: &SharedExecutionStore,
        principal: &Principal,
        execution_id: uuid::Uuid,
        error: &McpError,
    ) -> Result<(), McpError> {
        let reason_code = execution_failure_code(error);
        let persisted = store
            .fail_submission(
                principal.tenant.as_str(),
                execution_id,
                execution_event(
                    ExecutionEventKind::Failed,
                    None,
                    None,
                    serde_json::json!({"reason_code": reason_code}),
                ),
                reason_code,
            )
            .await
            .map_err(|store_error| {
                tracing::error!(%store_error, %execution_id, "could not persist Code Mode rejection");
                execution_unavailable()
            })?;
        if persisted.is_none() {
            tracing::error!(%execution_id, "Code Mode rejection lost its submitted-state claim");
            return Err(execution_unavailable());
        }
        Ok(())
    }

    async fn persist_claimed_failure(
        &self,
        store: &SharedExecutionStore,
        claim: &ExecutionClaim,
        error: &McpError,
    ) -> Result<(), McpError> {
        let reason_code = execution_failure_code(error);
        let persisted = store
            .transition(
                claim,
                ExecutionTransition {
                    from: vec![ExecutionStatus::Running],
                    to: ExecutionStatus::Failed,
                    event: execution_event(
                        ExecutionEventKind::Failed,
                        None,
                        None,
                        serde_json::json!({"reason_code": reason_code}),
                    ),
                    terminal_reason_code: Some(reason_code),
                    result_metadata: None,
                    result_payload: None,
                    resume_context: None,
                },
            )
            .await
            .map_err(|store_error| {
                tracing::error!(
                    %store_error,
                    execution_id = %claim.execution_id,
                    "could not persist Code Mode failure"
                );
                execution_unavailable()
            })?;
        if persisted.is_none() {
            if self.finish_requested_cancellation(store, claim).await? {
                return Err(execution_cancelled());
            }
            tracing::error!(
                execution_id = %claim.execution_id,
                "Code Mode execution claim was lost before failure attribution"
            );
            return Err(execution_unavailable());
        }
        Ok(())
    }

    async fn append_claimed_event(
        &self,
        claim: &ExecutionClaim,
        event: NewExecutionEvent,
    ) -> Result<(), McpError> {
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let appended = store.append_event(claim, event).await.map_err(|error| {
            tracing::error!(
                %error,
                execution_id = %claim.execution_id,
                "could not append Code Mode execution event"
            );
            execution_unavailable()
        })?;
        if !appended {
            // The append fence refuses once cancellation is requested: that
            // refusal is the pre-dispatch cancellation boundary, so finalize
            // the cancellation here rather than reporting a broken store.
            if self.finish_requested_cancellation(store, claim).await? {
                return Err(execution_cancelled());
            }
            tracing::error!(
                execution_id = %claim.execution_id,
                "Code Mode execution event rejected by the claim fence"
            );
            return Err(execution_unavailable());
        }
        Ok(())
    }

    /// Await an in-flight effect while keeping the durable worker claim
    /// alive. The effect is exempt from the execution deadline, and a
    /// spec-permitted upstream call can far outlive the claim lease; without
    /// renewal the outcome would lose its journal fence and abandonment
    /// reconciliation could terminalize a still-dispatching row. A refused
    /// renewal (cancellation requested, claim stolen) is logged and dispatch
    /// continues — an in-flight effect is never aborted; the owner/epoch
    /// fence on the outcome append decides whether the journal write lands.
    async fn await_effect_with_claim_renewal<T>(
        &self,
        claim: Option<&ExecutionClaim>,
        dispatch: impl std::future::Future<Output = T>,
    ) -> T {
        let Some(claim) = claim else {
            return dispatch.await;
        };
        tokio::pin!(dispatch);
        loop {
            tokio::select! {
                result = &mut dispatch => break result,
                _ = tokio::time::sleep(self.claim_lease() / 3) => {
                    let Some(store) = self.execution_store.as_ref() else {
                        continue;
                    };
                    // Cancellation-tolerant on purpose: a cancellation
                    // requested mid-flight must not let the lease lapse and
                    // reconciliation terminalize the row before the effect's
                    // outcome is journaled. Cancellation finalizes at the
                    // next journal boundary instead.
                    match store.renew_effect_lease(claim, self.claim_lease()).await {
                        Ok(true) => {}
                        Ok(false) => tracing::warn!(
                            execution_id = %claim.execution_id,
                            "Code Mode effect dispatch continuing without a renewable claim"
                        ),
                        Err(error) => tracing::warn!(
                            %error,
                            execution_id = %claim.execution_id,
                            "Code Mode claim renewal failed during effect dispatch"
                        ),
                    }
                }
            }
        }
    }

    /// Journal the observed outcome of a side-effecting call. Unlike
    /// [`Self::append_claimed_event`], a cancellation requested while the
    /// effect was in flight does not refuse the write — the journal must
    /// record what was actually dispatched before the cancellation
    /// terminalizes the execution.
    async fn append_claimed_effect_outcome(
        &self,
        claim: &ExecutionClaim,
        event: NewExecutionEvent,
    ) -> Result<(), McpError> {
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let appended = store
            .append_effect_outcome(claim, event)
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claim.execution_id,
                    "could not append Code Mode effect outcome"
                );
                execution_unavailable()
            })?;
        if !appended {
            tracing::error!(
                execution_id = %claim.execution_id,
                "Code Mode effect outcome rejected by the claim fence"
            );
            return Err(execution_unavailable());
        }
        Ok(())
    }

    async fn persist_claimed_pause(
        &self,
        claim: &ExecutionClaim,
        checkpoint: Value,
        connector_calls: usize,
        artifact_count: usize,
    ) -> Result<(), McpError> {
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let persisted = store
            .transition(
                claim,
                ExecutionTransition {
                    from: vec![ExecutionStatus::Running],
                    to: ExecutionStatus::WaitingForResume,
                    event: execution_event(
                        ExecutionEventKind::WaitingForResume,
                        None,
                        None,
                        serde_json::json!({
                            "connector_calls": connector_calls,
                            "artifacts": artifact_count,
                        }),
                    ),
                    terminal_reason_code: None,
                    result_metadata: Some(serde_json::json!({
                        "connector_calls": connector_calls,
                        "artifacts": artifact_count,
                    })),
                    result_payload: None,
                    resume_context: Some(serde_json::json!({"checkpoint": checkpoint})),
                },
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claim.execution_id,
                    "could not persist Code Mode pause"
                );
                execution_unavailable()
            })?;
        if persisted.is_none() {
            if self.finish_requested_cancellation(store, claim).await? {
                return Err(execution_cancelled());
            }
            tracing::error!(
                execution_id = %claim.execution_id,
                "Code Mode execution claim was lost before checkpoint commit"
            );
            return Err(execution_unavailable());
        }
        Ok(())
    }

    async fn persist_claimed_approval(
        &self,
        claim: &ExecutionClaim,
        approval: &MutationApprovalRequest,
        connector_calls: usize,
        artifact_count: usize,
    ) -> Result<(), McpError> {
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        // Persisting a (possibly different) pending request invalidates every
        // live grant bound to this execution first: an approval minted for an
        // earlier request must never authorize a later effect, and revoking
        // before the new request commits keeps the failure mode fail-closed —
        // a revocation without a replacement only forces a fresh approval.
        if let Some(grants) = self.grant_store.as_ref() {
            let revoked = grants
                .revoke_execution_grants(&claim.tenant_id, claim.execution_id)
                .await
                .map_err(|error| {
                    tracing::error!(
                        %error,
                        execution_id = %claim.execution_id,
                        "could not revoke superseded Code Mode approval grants"
                    );
                    execution_approval_unavailable()
                })?;
            if revoked > 0 {
                tracing::info!(
                    execution_id = %claim.execution_id,
                    revoked,
                    "superseded Code Mode approval grants revoked before new request"
                );
            }
        }
        let persisted = store
            .transition(
                claim,
                ExecutionTransition {
                    from: vec![ExecutionStatus::Running],
                    to: ExecutionStatus::WaitingForApproval,
                    event: execution_event_with_attempt(
                        ExecutionEventKind::WaitingForApproval,
                        Some(
                            usize::try_from(approval.step)
                                .expect("approval step fits the execution event type"),
                        ),
                        Some(approval.call_id),
                        u32::try_from(claim.epoch).ok(),
                        serde_json::json!({
                            "connector": approval.connector,
                            "operation": approval.operation,
                            "argument_hash": approval.argument_hash,
                            "risk": approval.risk,
                        }),
                    ),
                    terminal_reason_code: None,
                    result_metadata: Some(serde_json::json!({
                        "connector_calls": connector_calls,
                        "artifacts": artifact_count,
                    })),
                    result_payload: None,
                    resume_context: Some(serde_json::json!({"approval": approval})),
                },
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    %error,
                    execution_id = %claim.execution_id,
                    "could not persist Code Mode approval request"
                );
                execution_unavailable()
            })?;
        if persisted.is_none() {
            if self.finish_requested_cancellation(store, claim).await? {
                return Err(execution_cancelled());
            }
            tracing::error!(
                execution_id = %claim.execution_id,
                "Code Mode execution claim was lost before approval request commit"
            );
            return Err(execution_unavailable());
        }
        Ok(())
    }

    /// The start frame that carries this deployment's granted budget.
    ///
    /// The runner applies whatever arrives here and chooses nothing, so this
    /// is the point where an operator's configured value becomes the deadline
    /// a program runs under.
    fn start_frame(
        &self,
        source: String,
        bindings: Vec<RunnerBinding>,
        resume: Option<RunnerResumeContext>,
        input: Value,
        artifacts_available: bool,
    ) -> ParentFrame {
        ParentFrame::Start {
            source,
            bindings,
            resume,
            input,
            artifacts_available,
            execution_limit_ms: u64::try_from(self.execution_limit.as_millis()).unwrap_or(u64::MAX),
        }
    }

    async fn run_external_program(
        &self,
        mut attempt: RunnerAttempt<'_>,
        program: ExecutionProgram,
        setup_deadline: tokio::time::Instant,
    ) -> Result<ExecuteResponse, McpError> {
        let ExecutionProgram {
            source,
            admitted_calls,
            runner_bindings,
            resume,
            input,
            ..
        } = program;
        let executable = std::env::current_exe().map_err(|error| {
            tracing::error!(%error, "could not resolve Code Mode runner executable");
            execution_unavailable()
        })?;
        let mut connector_spool = tempfile::NamedTempFile::new().map_err(|error| {
            tracing::error!(%error, "could not create Code Mode result spool");
            execution_unavailable()
        })?;
        let mut command = Command::new(executable);
        command
            .arg(RUNNER_FLAG)
            .arg(RUNNER_SPOOL_FLAG)
            .arg(connector_spool.path())
            .arg(serde_json::to_string(crate::codemode_limits::limits()).expect("limits serialize"))
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| {
            tracing::error!(%error, "could not start Code Mode runner");
            execution_unavailable()
        })?;
        let mut child_stdin = child.stdin.take().ok_or_else(execution_unavailable)?;
        let child_stdout = child.stdout.take().ok_or_else(execution_unavailable)?;
        let mut child_stdout = BufReader::new(child_stdout);

        complete_runner_setup(
            &mut child_stdin,
            &mut child_stdout,
            self.start_frame(
                source,
                runner_bindings,
                resume,
                input,
                attempt.persist_content,
            ),
            setup_deadline,
        )
        .await?;
        // Ready proves the child opened the private file before seccomp. Drop
        // its directory entry now: only the two already-open process handles
        // can reach the bytes, and normal RAII still closes both on failure.
        std::fs::remove_file(connector_spool.path()).map_err(|error| {
            tracing::error!(%error, "could not unlink Code Mode result spool");
            execution_unavailable()
        })?;
        // Setup ends here, so the program phase is bounded from here rather
        // than sharing the attempt-wide backstop with everything before it.
        //
        // Every profile carries its deadline into the broker so in-flight
        // effects finish and are journaled before a timeout can stop the run.
        attempt.deadline = self.program_phase_deadline(attempt.profile);
        let brokered = self.broker_runner_frames_with_spool(
            attempt.clone(),
            &admitted_calls,
            &mut child_stdin,
            &mut child_stdout,
            connector_spool.as_file_mut(),
        );
        let outcome = match attempt.deadline {
            Some(_) => brokered.await?,
            None => tokio::time::timeout(self.program_phase_timeout(), brokered)
                .await
                .map_err(|_| execution_timeout())??,
        };
        let outcome = match outcome {
            RunnerProgramOutcome::Paused {
                checkpoint,
                calls,
                artifacts,
            } => {
                let claim = attempt.claim.ok_or_else(execution_unavailable)?;
                // The runner remains blocked on its inherited input until the
                // checkpoint commit succeeds; only then may this attempt exit.
                self.persist_claimed_pause(claim, checkpoint.clone(), calls, artifacts.len())
                    .await?;
                drop(child_stdin);
                drop(child);
                let source_ref = self
                    .live_source_reference(attempt.principal, &attempt.source_digest)
                    .await;
                return Ok(ExecuteResponse {
                    contract_version: ContractVersion::V1,
                    sdk_contract_version: SdkContractVersion::V4,
                    runner_contract_version: RunnerContractVersion::V7,
                    execution_id: attempt.execution_id,
                    source_ref,
                    status: ExecutionResponseStatus::WaitingForResume,
                    result: Value::Null,
                    checkpoint: Some(checkpoint),
                    approval: None,
                    connector_calls: calls,
                    result_ref: None,
                    artifacts,
                });
            }
            RunnerProgramOutcome::WaitingForApproval {
                approval,
                calls,
                artifacts,
            } => {
                let claim = attempt.claim.ok_or_else(execution_unavailable)?;
                self.persist_claimed_approval(claim, &approval, calls, artifacts.len())
                    .await?;
                drop(child_stdin);
                drop(child);
                let source_ref = self
                    .live_source_reference(attempt.principal, &attempt.source_digest)
                    .await;
                return Ok(ExecuteResponse {
                    contract_version: ContractVersion::V1,
                    sdk_contract_version: SdkContractVersion::V4,
                    runner_contract_version: RunnerContractVersion::V7,
                    execution_id: attempt.execution_id,
                    source_ref,
                    status: ExecutionResponseStatus::WaitingForApproval,
                    result: Value::Null,
                    checkpoint: None,
                    approval: Some(*approval),
                    connector_calls: calls,
                    result_ref: None,
                    artifacts,
                });
            }
            completed @ RunnerProgramOutcome::Completed { .. } => completed,
        };
        drop(child_stdin);
        let status = child.wait().await.map_err(|error| {
            tracing::error!(%error, "Code Mode runner wait failed");
            execution_unavailable()
        })?;
        if !status.success() {
            return Err(runner_crashed());
        }
        let RunnerProgramOutcome::Completed {
            result,
            calls,
            artifacts,
        } = outcome
        else {
            unreachable!("paused runner returned before process wait")
        };
        let source_ref = self
            .live_source_reference(attempt.principal, &attempt.source_digest)
            .await;
        Ok(ExecuteResponse {
            contract_version: ContractVersion::V1,
            sdk_contract_version: SdkContractVersion::V4,
            runner_contract_version: RunnerContractVersion::V7,
            execution_id: attempt.execution_id,
            source_ref,
            status: ExecutionResponseStatus::Completed,
            result,
            checkpoint: None,
            approval: None,
            connector_calls: calls,
            result_ref: attempt.persist_content.then_some(ExecutionResultReference {
                execution_id: attempt.execution_id,
            }),
            artifacts,
        })
    }

    async fn broker_runner_frames_with_spool(
        &self,
        attempt: RunnerAttempt<'_>,
        admitted_calls: &HashMap<String, AdmittedCall>,
        child_stdin: &mut (impl AsyncWrite + Unpin),
        child_stdout: &mut (impl AsyncBufRead + Unpin),
        connector_spool: &mut std::fs::File,
    ) -> Result<RunnerProgramOutcome, McpError> {
        let mut calls = 0usize;
        let mut mutation_calls = 0usize;
        let mut artifacts = Vec::new();
        let mut artifact_bytes = 0usize;
        let result = loop {
            match bounded_by_deadline(attempt.deadline, async {
                let read = read_runner_frame(&mut *child_stdout);
                if let (Some(claim), Some(store)) = (attempt.claim, self.execution_store.as_ref()) {
                    tokio::select! {
                        frame = read => frame.map_err(runner_frame_failure),
                        cancelled = self.wait_for_cancellation(store, attempt.principal, claim.execution_id) => {
                            cancelled?;
                            self.persist_claimed_cancellation(store, claim).await?;
                            Err(execution_cancelled())
                        }
                    }
                } else {
                    read.await.map_err(runner_frame_failure)
                }
            })
            .await?
            {
                RunnerFrame::Call {
                    id,
                    call_id,
                    arguments,
                } => {
                    calls += 1;
                    let hierarchy = nested_invocation_hierarchy(&attempt, calls)?;
                    let admitted = admitted_call(admitted_calls, &call_id);
                    let event_detail = match admitted.as_ref() {
                        Ok(admitted) => serde_json::json!({
                            "server": admitted.server,
                            "tool": admitted.tool,
                        }),
                        Err(_) => serde_json::json!({"binding_refused": true}),
                    };
                    // The fenced start append is the pre-dispatch cancellation
                    // boundary: once cancellation is requested it refuses, the
                    // execution finalizes as cancelled, and no dispatch occurs.
                    if let Some(claim) = attempt.claim {
                        self.append_claimed_event(
                            claim,
                            execution_event_with_attempt(
                                ExecutionEventKind::ConnectorCallStarted,
                                Some(calls),
                                Some(hierarchy.call_id),
                                Some(hierarchy.attempt.get()),
                                event_detail.clone(),
                            ),
                        )
                        .await?;
                    }
                    let dispatches_effect = admitted
                        .as_ref()
                        .is_ok_and(|admitted| admitted.contract.side_effects());
                    let result = match admitted {
                        Ok(admitted)
                            if admitted.contract.side_effects()
                                && attempt.profile == CodeExecutionProfile::Direct =>
                        {
                            let dispatch = self.invoke_connector(
                                attempt.principal, &admitted, arguments, hierarchy,
                                CodeExecutionProfile::Direct, None,
                            );
                            self.await_effect_with_claim_renewal(attempt.claim, dispatch)
                                .await.map_err(|error| connector_error(error.kind(), &error))
                        }
                        Ok(admitted) if admitted.contract.side_effects() => {
                            mutation_calls += 1;
                            if attempt.profile != CodeExecutionProfile::LegacyApprovalBound {
                                Err(connector_error(
                                    "execution_profile",
                                    "side-effecting connector is outside this execution profile",
                                ))
                            } else if mutation_calls > 1 {
                                Err(connector_error(
                                    "mutation_call_limit",
                                    "Code Mode mutation executions admit one side-effecting call",
                                ))
                            } else if serde_json::to_vec(&arguments)
                                .map(|encoded| encoded.len() > limits().request_bytes)
                                .unwrap_or(true)
                            {
                                // The approval binds the hash of the complete
                                // arguments, so an administrator must be able
                                // to review them completely: an effect too
                                // large for exact review is refused, never
                                // partially previewed.
                                Err(connector_error(
                                    "mutation_arguments_too_large",
                                    format!(
                                        "Code Mode mutation arguments exceed the \
                                         {}-byte argument limit; \
                                         reduce the effect payload so an administrator can \
                                         review the complete arguments the approval would \
                                         authorize", limits().request_bytes
                                    ),
                                ))
                            } else {
                                // Pre-dispatch cancellation fence: renewal is
                                // atomic with the cancellation flag, so a
                                // cancellation accepted after the start append
                                // is observed here, before dispatch. The bound
                                // grant claim repeats the same refusal
                                // atomically with authority consumption.
                                if let Some(claim) = attempt.claim {
                                    let store = self
                                        .execution_store
                                        .as_ref()
                                        .ok_or_else(execution_unavailable)?;
                                    let renewed = store
                                        .renew(claim, self.claim_lease())
                                        .await
                                        .map_err(|error| {
                                            tracing::error!(
                                                %error,
                                                execution_id = %claim.execution_id,
                                                "could not confirm the Code Mode claim before \
                                                 effect dispatch"
                                            );
                                            execution_unavailable()
                                        })?;
                                    if !renewed {
                                        if self.finish_requested_cancellation(store, claim).await? {
                                            return Err(execution_cancelled());
                                        }
                                        return Err(execution_unavailable());
                                    }
                                }
                                let approval = mutation_approval_request(
                                    &attempt, &admitted, &arguments, hierarchy,
                                );
                                let dispatch = self.invoke_connector(
                                    attempt.principal,
                                    &admitted,
                                    arguments,
                                    hierarchy,
                                    attempt.profile,
                                    Some(waygate_invocation::InvocationApprovalBinding {
                                        execution_id: attempt.execution_id,
                                        source_digest: attempt.source_digest.clone(),
                                        call_id: hierarchy.call_id,
                                    }),
                                );
                                match self
                                    .await_effect_with_claim_renewal(attempt.claim, dispatch)
                                    .await
                                {
                                    Ok(value) => Ok(value),
                                    Err(
                                        waygate_invocation::InvocationError::ApprovalRequired {
                                            ..
                                        },
                                    ) => {
                                        break RunnerProgramOutcome::WaitingForApproval {
                                            approval: Box::new(approval),
                                            calls,
                                            artifacts,
                                        };
                                    }
                                    Err(error) => Err(connector_error(error.kind(), &error)),
                                }
                            }
                        }
                        Ok(admitted) => {
                            // Reads are recomputable, so a deadline may cut
                            // them off. In-flight effects finish before the
                            // broker enforces the deadline.
                            bounded_by_deadline(attempt.deadline, async {
                                Ok(self
                                    .invoke_connector(
                                        attempt.principal,
                                        &admitted,
                                        arguments,
                                        hierarchy,
                                        attempt.profile,
                                        None,
                                    )
                                    .await
                                    .map_err(|error| connector_error(error.kind(), &error)))
                            })
                            .await?
                        }
                        Err(error) => Err(error),
                    };
                    let event_kind = if result.is_ok() {
                        ExecutionEventKind::ConnectorCallSucceeded
                    } else {
                        ExecutionEventKind::ConnectorCallFailed
                    };
                    if let Some(claim) = attempt.claim {
                        let event = execution_event_with_attempt(
                            event_kind,
                            Some(calls),
                            Some(hierarchy.call_id),
                            Some(hierarchy.attempt.get()),
                            event_detail,
                        );
                        if dispatches_effect {
                            self.append_claimed_effect_outcome(claim, event).await?;
                        } else {
                            self.append_claimed_event(claim, event).await?;
                        }
                    }
                    write_connector_result(&mut *child_stdin, connector_spool, id, result, limits().connector_response_bytes).await?;
                }
                RunnerFrame::Complete { result } => {
                    break RunnerProgramOutcome::Completed {
                        result,
                        calls,
                        artifacts,
                    }
                }
                RunnerFrame::Pause { checkpoint } => {
                    if !attempt.persist_content {
                        return Err(pause_unavailable());
                    }
                    if attempt.profile != CodeExecutionProfile::Direct {
                        return Err(mutation_pause_unavailable());
                    }
                    break RunnerProgramOutcome::Paused {
                        checkpoint,
                        calls,
                        artifacts,
                    };
                }
                RunnerFrame::Artifact { id, value } => {
                    if !attempt.persist_content {
                        return Err(artifact_unavailable());
                    }
                    let bytes = serde_json::to_vec(&value).map_err(|_| artifact_too_large())?.len();
                    artifact_bytes = artifact_bytes.checked_add(bytes).ok_or_else(artifact_too_large)?;
                    if bytes > limits().artifact_bytes || artifact_bytes > limits().artifact_total_bytes {
                        return Err(artifact_too_large());
                    }
                    if artifacts.len() >= limits().artifacts_per_attempt {
                        return Err(artifact_limit_exceeded());
                    }
                    let claim = attempt.claim.ok_or_else(artifact_unavailable)?;
                    let reference = ArtifactReference {
                        execution_id: attempt.execution_id,
                        artifact_id: uuid::Uuid::now_v7(),
                    };
                    self.append_claimed_event(
                        claim,
                        execution_event(
                            ExecutionEventKind::ArtifactEmitted,
                            None,
                            None,
                            serde_json::json!({
                                "artifact_id": reference.artifact_id,
                                "value": value,
                            }),
                        ),
                    )
                    .await?;
                    write_parent_frame(
                        &mut *child_stdin,
                        &ParentFrame::ArtifactResult {
                            id,
                            result: Ok(serde_json::to_value(&reference)
                                .expect("artifact references contain only serializable values")),
                        },
                    )
                    .await?;
                    artifacts.push(reference);
                }
                RunnerFrame::Failed { code, message } => {
                    tracing::debug!(?code, "Code Mode runner reported execution failure");
                    return Err(runner_reported_failure(code, &message));
                }
                RunnerFrame::Ready { .. } => return Err(runner_protocol_failure()),
            }
        };
        Ok(result)
    }

    #[cfg(test)]
    async fn broker_runner_frames(
        &self,
        attempt: RunnerAttempt<'_>,
        admitted_calls: &HashMap<String, AdmittedCall>,
        child_stdin: &mut (impl AsyncWrite + Unpin),
        child_stdout: &mut (impl AsyncBufRead + Unpin),
    ) -> Result<RunnerProgramOutcome, McpError> {
        let mut spool = tempfile::tempfile().map_err(|_| execution_unavailable())?;
        self.broker_runner_frames_with_spool(
            attempt,
            admitted_calls,
            child_stdin,
            child_stdout,
            &mut spool,
        )
        .await
    }

    #[cfg(test)]
    async fn invoke_direct(
        &self,
        principal: &Principal,
        server: &str,
        tool: &str,
        arguments: Value,
        expected_contract: InvocationContractIdentity,
        hierarchy: InvocationHierarchy,
    ) -> Result<Value, waygate_invocation::InvocationError> {
        self.invoke_connector(
            principal,
            &AdmittedCall {
                approval_context: None,
                server: server.to_owned(),
                tool: tool.to_owned(),
                contract: ExecutionContract::Upstream {
                    identity: expected_contract,
                },
            },
            arguments,
            hierarchy,
            CodeExecutionProfile::Direct,
            None,
        )
        .await
    }

    async fn invoke_connector(
        &self,
        principal: &Principal,
        admitted: &AdmittedCall,
        arguments: Value,
        hierarchy: InvocationHierarchy,
        profile: CodeExecutionProfile,
        approval_binding: Option<waygate_invocation::InvocationApprovalBinding>,
    ) -> Result<Value, waygate_invocation::InvocationError> {
        let Some(arguments) = arguments.as_object().cloned() else {
            return Err(waygate_invocation::InvocationError::InvalidArguments(
                "connector arguments must be a JSON object".to_owned(),
            ));
        };

        if let ExecutionContract::Builtin { behavior_hash, .. } = &admitted.contract {
            let builtin = self
                .builtin_handlers
                .iter()
                .find(|builtin| builtin.namespace() == admitted.server)
                .ok_or_else(|| builtin_contract_changed(admitted))?;
            let catalog = builtin.catalog();
            catalog
                .tools
                .iter()
                .find(|tool| tool.identity.name == admitted.tool)
                .filter(|tool| builtin_behavior_hash(tool) == *behavior_hash)
                .ok_or_else(|| builtin_contract_changed(admitted))?;
            let governance_tool = builtin.governance_tool(&admitted.tool);
            if builtin.profile_scope() == BuiltinProfileScope::Namespace
                && (profile_blocks_server(principal, &admitted.server)
                    || profile_blocks_tool(principal, &admitted.server, governance_tool))
            {
                return Err(builtin_contract_changed(admitted));
            }
            waygate_mcp::server::authorize_builtin_call(
                &self.authz,
                &self.audit,
                &catalog,
                governance_tool,
                Some(principal),
                Some(hierarchy),
            )
            .await
            .map_err(waygate_invocation::InvocationError::Upstream)?;
            let result = builtin
                .call(&admitted.tool, Some(arguments), Some(principal))
                .await;
            let outcome = if result.is_ok() {
                AuditOutcome::Success
            } else {
                AuditOutcome::ExecutionError
            };
            self.audit
                .record_chained_best_effort(
                    AuditEvent::new("CallTool", outcome)
                        .with_principal(Some(principal))
                        .with_tool(&admitted.server, &admitted.tool)
                        .with_risk(admitted.contract.risk_tier())
                        .with_pii(admitted.contract.pii())
                        .with_invocation_hierarchy(Some(hierarchy)),
                )
                .await;
            let result = result.map_err(waygate_invocation::InvocationError::Upstream)?;
            return connector_result_value(result);
        }

        let ExecutionContract::Upstream { identity } = &admitted.contract else {
            unreachable!("built-in contracts return before upstream dispatch");
        };
        let mut request = InvocationRequest::new(&admitted.server, &admitted.tool)
            .with_arguments(Some(arguments))
            .with_expected_contract(identity.clone())
            .with_hierarchy(hierarchy)
            .with_response_delivery(waygate_invocation::ResponseDelivery::Materialize)
            .with_response_materialization_limit(limits().connector_response_bytes);
        match profile {
            CodeExecutionProfile::Direct => {}
            CodeExecutionProfile::LegacyApprovalBound => {
                if admitted.contract.side_effects() {
                    let binding = approval_binding.ok_or_else(|| {
                        waygate_invocation::InvocationError::ReadOnlyRequired {
                            tool: format!("{}.{}", admitted.server, admitted.tool),
                        }
                    })?;
                    request = request.with_approval_binding(binding);
                }
            }
        }
        match self.invocation.invoke(Some(principal), request).await? {
            InvocationResponse::Unary(result) => connector_result_value(result),
            // Code Mode declares no input capabilities, so the pipeline
            // fails an MRTR pause closed before it can surface here; its own
            // pauses ride the approval-gate/task model instead.
            InvocationResponse::Stream(_)
            | InvocationResponse::UnaryValue(_)
            | InvocationResponse::InputRequired(_) => Err(
                waygate_invocation::InvocationError::Upstream(McpError::internal_error(
                    "connector returned an unsupported response shape",
                    None,
                )),
            ),
        }
    }

    async fn execution_bindings(
        &self,
        principal: &Principal,
        profile: CodeExecutionProfile,
    ) -> Result<Vec<ExecutionBinding>, McpError> {
        let channel = CatalogChannel::Direct;
        let visible = self
            .stable_visible_codemode_tools(principal, channel)
            .await?;
        let mut bindings = Vec::new();
        for tool in visible {
            let server = tool.identity.source.name();
            if !selector_admitted(server, &tool.identity.name) {
                continue;
            }
            if !profile.admits(&tool.facts) {
                continue;
            }
            let Some(contract) = connector_contract_for_tool(&tool) else {
                continue;
            };
            let execution_contract = match &tool.identity.source {
                CatalogToolSource::Upstream(_) => ExecutionContract::Upstream {
                    identity: tool
                        .invocation_snapshot()
                        .expect("upstream Code Mode binding has a snapshot")
                        .contract_identity(),
                },
                CatalogToolSource::Builtin(_) => ExecutionContract::Builtin {
                    behavior_hash: builtin_behavior_hash(&tool),
                    risk: match tool.facts.risk {
                        RiskTier::Low => InvocationRisk::Low,
                        RiskTier::Medium => InvocationRisk::Medium,
                        RiskTier::High => InvocationRisk::High,
                    },
                    side_effects: tool.facts.side_effects,
                    pii: tool.facts.pii,
                },
            };
            let public_binding = contract.binding;
            let call_id = runner_call_id(server, &tool.identity.name);
            bindings.push(ExecutionBinding {
                approval_context: Some(ApprovalContext::from_tool(&tool)),
                contract: execution_contract,
                runner: RunnerBinding {
                    connector: public_binding.connector.clone(),
                    operation: public_binding.operation.clone(),
                    call_id,
                },
                server: server.to_owned(),
                tool: tool.identity.name,
            });
        }
        bindings.sort_by(|left, right| left.runner.call_id.cmp(&right.runner.call_id));
        bindings.dedup_by(|left, right| left.runner.call_id == right.runner.call_id);
        Ok(bindings)
    }
}

/// Optional Postgres-backed durable execution store. One construction
/// shape shared by the MCP tool surface and the admin approval endpoints,
/// so both always read the same rows.
fn configured_execution_store(pool: sqlx::PgPool) -> waygate_codemode::PgExecutionStore {
    waygate_codemode::PgExecutionStore::new(pool)
        .with_source_limits(waygate_codemode::SourceRetentionLimits {
            owner_bytes: limits().retained_owner_bytes as i64,
            tenant_bytes: limits().retained_tenant_bytes as i64,
            owner_count: limits().retained_owner_count as i64,
            tenant_count: limits().retained_tenant_count as i64,
        })
        .expect("boot validated retained source limits")
}

pub fn shared_execution_store(db_pool: Option<sqlx::PgPool>) -> Option<SharedExecutionStore> {
    db_pool
        .map(|pool| Arc::new(waygate_codemode::PgExecutionStore::new(pool)) as SharedExecutionStore)
}

/// Operator-controlled Code Mode settings, resolved from configuration.
///
/// Grouped rather than passed individually because they travel together and
/// come from one place: every field here is a deployment decision the caller
/// cannot influence.
pub struct CodeModeSettings {
    pub result_storage: crate::config::CodeModeResultStorage,
    /// Wall-clock budget granted to each runner.
    pub execution_limit: Duration,
    pub execution_capacity: Arc<CodeModeExecutionCapacity>,
    pub tool_catalog_epoch: ToolCatalogEpoch,
    pub(crate) search_cursor_sealer: Arc<crate::mcp_discovery::DiscoveryCursorSealer>,
}

/// External source handles shared by the Code Mode composition root.
pub struct CodeModeSourceProviders {
    pub builtins: BuiltinRegistry,
    pub builtin_handlers: Vec<SharedBuiltinTools>,
    pub audit: SharedEvidence,
    pub source_file_reader: Option<crate::file_transfer::SharedStoredTextReader>,
    pub skill_catalog: Option<Arc<waygate_skills::ReloadableSkillCatalog>>,
    pub reviewed_skills: Option<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
}

/// The boot-resolved budget shared with the runner.
pub fn execution_limit_from_env() -> anyhow::Result<Duration> {
    Ok(Duration::from_secs(limits().execution_seconds))
}

pub fn configured_tools(
    catalog: SharedCatalog,
    authz: SharedAuthz,
    invocation: SharedInvocation,
    db_pool: Option<sqlx::PgPool>,
    sources: CodeModeSourceProviders,
    quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    settings: CodeModeSettings,
) -> SharedBuiltinTools {
    // The grant store shares the pool: revoke-on-replace must reach the same
    // approval_grants rows the invocation pipeline claims from.
    let grant_store = db_pool.clone().map(|pool| {
        Arc::new(waygate_catalog::PgCatalogStore::new(pool)) as waygate_catalog::SharedCatalogStore
    });
    let codemode_store = db_pool.map(|pool| Arc::new(configured_execution_store(pool)));
    let execution_store = codemode_store
        .clone()
        .map(|store| store as SharedExecutionStore);
    let result_persistence_allowed = settings.result_storage.allows_persistence();
    let source_artifact_store =
        configured_source_artifact_store(codemode_store.clone(), result_persistence_allowed);
    let mut tools = CodeModeTools::new(catalog, authz, invocation)
        .with_builtin_registry(sources.builtins)
        .with_builtin_handlers(sources.builtin_handlers)
        .with_audit(sources.audit)
        .with_tool_catalog_epoch(settings.tool_catalog_epoch)
        .with_search_cursor_sealer(settings.search_cursor_sealer)
        .with_source_file_reader(sources.source_file_reader)
        .with_skill_script_execution(sources.skill_catalog)
        .with_reviewed_skills(sources.reviewed_skills)
        .with_quota(quota)
        .with_result_persistence_allowed(result_persistence_allowed)
        .with_execution_capacity(settings.execution_capacity)
        .with_execution_limit(settings.execution_limit);
    if let Some(grants) = grant_store {
        tools = tools.with_grant_store(grants);
    }
    if let Some(store) = source_artifact_store {
        tools = tools.with_source_artifact_store(store);
    }
    Arc::new(match execution_store {
        Some(store) => tools.with_execution_store(store),
        None => tools,
    })
}

fn configured_source_artifact_store(
    store: Option<Arc<waygate_codemode::PgExecutionStore>>,
    result_persistence_allowed: bool,
) -> Option<SharedSourceArtifactStore> {
    if result_persistence_allowed {
        store.map(|store| store as SharedSourceArtifactStore)
    } else {
        None
    }
}

#[async_trait]
impl BuiltinTools for CodeModeTools {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn profile_scope(&self) -> BuiltinProfileScope {
        BuiltinProfileScope::DelegatedDataPlane
    }

    fn catalog(&self) -> BuiltinCatalog {
        surface_catalog()
    }

    fn governance_tool<'a>(&self, tool: &'a str) -> &'a str {
        if matches!(
            tool,
            "resume" | "result" | "artifacts" | "artifact" | "status" | "executions"
        ) {
            "execute"
        } else {
            tool
        }
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        let Some(principal) = principal else {
            return Vec::new();
        };
        let supports_tasks = self.supports_tasks();
        self.catalog()
            .definitions()
            .into_iter()
            .filter(|tool| {
                if matches!(
                    tool.name.as_ref(),
                    "codemode.resume"
                        | "codemode.result"
                        | "codemode.artifacts"
                        | "codemode.artifact"
                        | "codemode.start"
                        | "codemode.start_resume"
                        | "codemode.status"
                        | "codemode.executions"
                        | "codemode.cancel"
                ) && !supports_tasks
                {
                    return false;
                }
                if matches!(
                    tool.name.as_ref(),
                    "codemode.execute"
                        | "codemode.resume"
                        | "codemode.result"
                        | "codemode.artifacts"
                        | "codemode.artifact"
                        | "codemode.start"
                        | "codemode.start_resume"
                        | "codemode.status"
                        | "codemode.executions"
                        | "codemode.cancel"
                ) {
                    // A tool this caller's profile withholds must not be
                    // advertised, or the listing would promise a call that
                    // refuses.
                    if matches!(
                        tool.name.as_ref(),
                        "codemode.start" | "codemode.start_resume"
                    ) && tool
                        .name
                        .strip_prefix("codemode.")
                        .is_some_and(|bare| self.profile_withholds_detached(principal, bare))
                    {
                        return false;
                    }
                    may_invoke(principal)
                } else {
                    may_read(principal)
                }
            })
            .collect()
    }

    async fn call(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        let principal = principal.ok_or_else(|| insufficient_scope(Scope::McpRead.as_str()))?;
        let requires_invoke = matches!(
            tool,
            "execute"
                | "resume"
                | "result"
                | "artifacts"
                | "artifact"
                | "start"
                | "start_resume"
                | "status"
                | "executions"
                | "cancel"
        );
        let required_scope = if requires_invoke {
            Scope::McpInvoke.as_str()
        } else {
            Scope::McpRead.as_str()
        };
        let admitted = if requires_invoke {
            may_invoke(principal)
        } else {
            may_read(principal)
        };
        if !admitted {
            return Err(insufficient_scope(required_scope));
        }
        let mut arguments = arguments.unwrap_or_default();
        let narrowed = self.with_call_timeout(tool, &mut arguments)?;
        let this = &narrowed;
        match tool {
            "limits" => {
                let _: LimitsParams = parse_args(&arguments, "limits")?;
                Ok(structured(&LimitsResponse {
                    resources: limits().clone(),
                    global_concurrency: self.execution_capacity.limits.global,
                    tenant_concurrency: self.execution_capacity.limits.per_tenant,
                    detached_concurrency: self.execution_capacity.limits.detached,
                }))
            }
            "search" => {
                let started = Instant::now();
                let result = match parse_args(&arguments, "search") {
                    Ok(params) => self.search(principal, params).await,
                    Err(error) => Err(error),
                };
                record_discovery_operation(
                    waygate_telemetry::metrics::DiscoveryOperation::CodeModeSearch,
                    &result,
                    started,
                );
                result
            }
            "describe" => {
                let started = Instant::now();
                let result = match parse_args(&arguments, "describe") {
                    Ok(params) => self.describe(principal, params).await,
                    Err(error) => Err(error),
                };
                record_discovery_operation(
                    waygate_telemetry::metrics::DiscoveryOperation::CodeModeDescribe,
                    &result,
                    started,
                );
                result
            }
            "execute" => {
                this.execute(principal, parse_args(&arguments, "execute")?)
                    .await
            }
            "resume" => {
                this.resume(principal, parse_args(&arguments, "resume")?)
                    .await
            }
            "result" => {
                self.stored_result(principal, parse_args(&arguments, "result")?)
                    .await
            }
            "artifacts" => {
                self.artifacts(principal, parse_args(&arguments, "artifacts")?)
                    .await
            }
            "artifact" => {
                self.artifact(principal, parse_args(&arguments, "artifact")?)
                    .await
            }
            "start" => {
                this.start_execution(principal, parse_args(&arguments, "start")?)
                    .await
            }
            "start_resume" => {
                this.start_resume_execution(principal, parse_args(&arguments, "start_resume")?)
                    .await
            }
            "status" => {
                self.execution_status(principal, parse_args(&arguments, "status")?)
                    .await
            }
            "executions" => {
                self.list_executions(principal, parse_args(&arguments, "executions")?)
                    .await
            }
            "cancel" => {
                self.cancel_execution(principal, parse_args(&arguments, "cancel")?)
                    .await
            }
            other => Err(McpError::invalid_params(
                format!(
                    "unknown {NAMESPACE} tool: {other}; use `{NAMESPACE}.search`, \
                     `{NAMESPACE}.describe`, `{NAMESPACE}.execute`, or \
                     `{NAMESPACE}.resume`; persisted executions also expose \
                     `{NAMESPACE}.result`, `{NAMESPACE}.artifacts`, \
                     `{NAMESPACE}.artifact`, `{NAMESPACE}.start`, \
                     `{NAMESPACE}.start_resume`, `{NAMESPACE}.status`, \
                     `{NAMESPACE}.executions`, and `{NAMESPACE}.cancel`"
                ),
                None,
            )),
        }
    }

    fn supports_tasks(&self) -> bool {
        self.durable_continuation_available()
    }

    fn task_tool(&self) -> Option<&str> {
        self.supports_tasks().then_some("execute")
    }

    fn cancel_task_tool(&self) -> Option<&str> {
        self.supports_tasks().then_some("cancel")
    }

    async fn enqueue_task(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<Option<Task>, McpError> {
        if !matches!(tool, "execute" | "resume") || !self.supports_tasks() {
            return Ok(None);
        }
        let principal = principal.ok_or_else(|| insufficient_scope(Scope::McpInvoke.as_str()))?;
        if !may_invoke(principal) {
            return Err(insufficient_scope(Scope::McpInvoke.as_str()));
        }
        if self.profile_withholds_detached(principal, tool) {
            return Err(detached_execution_withheld(tool));
        }
        let mut arguments = arguments.unwrap_or_default();
        let narrowed = self.with_call_timeout(tool, &mut arguments)?;
        if tool == "resume" {
            let params: ResumeParams = parse_args(&arguments, "resume")?;
            narrowed.check_execution_quota(principal, "resume").await?;
            let execution = narrowed.resume_detached(principal, params).await?;
            return Ok(Some(task_projection(&execution)));
        }
        // Task augmentation is the detached shape of `execute`, so it takes
        // the start surface's parameters: retries converge and `repeat_after`
        // names a deliberate repetition. The blocking tool keeps refusing
        // `repeat_after`, which only means anything for a retained handle.
        let params: StartParams = parse_args(&arguments, "execute")?;
        let execution = narrowed
            .start_detached(principal, "execute", params)
            .await?;
        Ok(Some(task_projection(&execution)))
    }

    async fn get_task(
        &self,
        task_id: &str,
        principal: Option<&Principal>,
    ) -> Result<Option<Task>, McpError> {
        if !self.supports_tasks() {
            return Ok(None);
        }
        let Some(execution) = self.task_execution(task_id, principal).await? else {
            return Ok(None);
        };
        Ok(Some(task_projection(&execution)))
    }

    async fn get_task_result(
        &self,
        task_id: &str,
        principal: Option<&Principal>,
    ) -> Result<Option<CallToolResult>, McpError> {
        if !self.supports_tasks() {
            return Ok(None);
        }
        let Some(execution) = self.task_execution(task_id, principal).await? else {
            return Ok(None);
        };
        match execution.status {
            ExecutionStatus::Succeeded
            | ExecutionStatus::Compensated
            | ExecutionStatus::ReconciledApplied
            | ExecutionStatus::ReconciledNotApplied => {
                let mut payload = execution
                    .result_payload
                    .ok_or_else(task_result_unavailable)?;
                if let Some(source_ref) = payload.get_mut("source_ref") {
                    let principal =
                        principal.ok_or_else(|| insufficient_scope(Scope::McpInvoke.as_str()))?;
                    *source_ref = serde_json::to_value(
                        self.live_source_reference(principal, &execution.source_digest)
                            .await,
                    )
                    .expect("SourceReference always serializes");
                }
                Ok(Some(structured(&payload)))
            }
            ExecutionStatus::Failed | ExecutionStatus::Expired => Err(McpError::invalid_request(
                "Code Mode task did not complete successfully",
                Some(serde_json::json!({
                    "error": execution
                        .terminal_reason_code
                        .unwrap_or_else(|| "execution_failed".to_owned())
                })),
            )),
            ExecutionStatus::Cancelled => Err(execution_cancelled()),
            _ => Err(McpError::invalid_request(
                "Code Mode task result is not ready",
                Some(serde_json::json!({"error": "task_not_ready"})),
            )),
        }
    }

    async fn cancel_task(
        &self,
        task_id: &str,
        principal: Option<&Principal>,
    ) -> Result<Option<Task>, McpError> {
        if !self.supports_tasks() {
            return Ok(None);
        }
        let principal = principal.ok_or_else(|| insufficient_scope(Scope::McpInvoke.as_str()))?;
        if !may_invoke(principal) {
            return Err(insufficient_scope(Scope::McpInvoke.as_str()));
        }
        let id = match uuid::Uuid::parse_str(task_id) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };
        if self
            .task_execution(task_id, Some(principal))
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let mut execution = match store
            .request_cancellation(
                principal.tenant.as_str(),
                &principal.sub,
                &principal.issuer,
                id,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, %id, "could not request Code Mode task cancellation");
                execution_unavailable()
            })? {
            Some(execution) => execution,
            None => return Ok(None),
        };
        for _ in 0..20 {
            if execution.status.is_terminal() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            execution = store
                .get(principal.tenant.as_str(), id)
                .await
                .map_err(|error| {
                    tracing::error!(%error, %id, "could not confirm Code Mode task cancellation");
                    execution_unavailable()
                })?
                .ok_or_else(execution_unavailable)?;
            if !execution_owned_by(&execution, principal) {
                return Ok(None);
            }
        }
        Ok(Some(task_projection(&execution)))
    }

    async fn update_task_continuation(
        &self,
        task_id: &str,
        principal: Option<&Principal>,
    ) -> Result<Option<&'static str>, McpError> {
        if !self.supports_tasks() {
            return Ok(None);
        }
        let Some(execution) = self.task_execution(task_id, principal).await? else {
            return Ok(None);
        };
        match execution.status {
            ExecutionStatus::WaitingForResume => Ok(Some("resume")),
            ExecutionStatus::WaitingForApproval => {
                Err(execution_resume_incompatible("legacy_execution_profile"))
            }
            // Ambiguous projects as `input_required` on the task surface,
            // but the side effect may already have applied and it must
            // never grow a retry path — name that instead of falling into
            // a generic not-awaiting-input error.
            ExecutionStatus::Ambiguous => Err(McpError::invalid_request(
                "Code Mode execution outcome is ambiguous (the side effect may already have \
                 applied); there is no retry path — inspect `codemode.result` or wait for \
                 operator reconciliation",
                None,
            )),
            _ => Err(McpError::invalid_request(
                "Code Mode task is not awaiting client input; poll tasks/get for its status",
                None,
            )),
        }
    }

    async fn update_task(
        &self,
        task_id: &str,
        input_responses: rmcp::model::InputResponses,
        principal: Option<&Principal>,
    ) -> Result<(), McpError> {
        let principal = principal.ok_or_else(|| insufficient_scope(Scope::McpInvoke.as_str()))?;
        if !may_invoke(principal) {
            return Err(insufficient_scope(Scope::McpInvoke.as_str()));
        }
        // Exactly one recognized response key selects the continuation;
        // the claim below re-verifies the execution is in that
        // continuation's waiting state, so a key/state mismatch surfaces
        // as the claim's own expected-status refusal.
        let mut entries = input_responses.into_iter();
        let (key, value) = match (entries.next(), entries.next()) {
            (Some(entry), None) => entry,
            _ => {
                return Err(McpError::invalid_params(
                    "tasks/update for a Code Mode task carries exactly one response: key \
                     `resume` with the checkpoint input (JSON; null for none) for a \
                     waiting_for_resume execution",
                    None,
                ));
            }
        };
        let claimed = match key.as_str() {
            "resume" => {
                if self.profile_withholds_detached(principal, "resume") {
                    return Err(detached_execution_withheld("resume"));
                }
                self.execution_store
                    .as_ref()
                    .ok_or_else(execution_unavailable)?;
                let detached_slot = self.acquire_detached_execution_slot()?;
                let input = match value {
                    Value::Null => None,
                    other => Some(other),
                };
                self.check_execution_quota(principal, "resume").await?;
                let mut claimed = self
                    .claim_resume(
                        principal,
                        ResumeParams {
                            execution_id: task_id.to_owned(),
                            input,
                        },
                    )
                    .await?;
                claimed._detached_slot = Some(detached_slot);
                claimed
            }
            other => {
                return Err(McpError::invalid_params(
                    format!(
                        "unknown tasks/update response key `{other}` for a Code Mode task; \
                         use `resume` (waiting_for_resume)"
                    ),
                    None,
                ));
            }
        };
        // The acknowledgement is eventually consistent: the continuation
        // runs detached exactly like a task-augmented `codemode.resume`,
        // and the client observes progress via `tasks/get`.
        let execution_id = claimed.execution.id;
        let tools = self.clone();
        let principal = principal.clone();
        tokio::spawn(async move {
            if let Err(error) = tools.run_claimed_program(&principal, claimed).await {
                tracing::debug!(
                    %execution_id,
                    error_code = %error.code.0,
                    "Code Mode tasks/update continuation finished without a successful result"
                );
            }
        });
        Ok(())
    }
}

impl CodeModeTools {
    async fn task_execution(
        &self,
        task_id: &str,
        principal: Option<&Principal>,
    ) -> Result<Option<waygate_codemode::Execution>, McpError> {
        let principal = principal.ok_or_else(|| insufficient_scope(Scope::McpInvoke.as_str()))?;
        if !may_invoke(principal) {
            return Err(insufficient_scope(Scope::McpInvoke.as_str()));
        }
        let id = match uuid::Uuid::parse_str(task_id) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };
        let store = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?;
        let Some(execution) = store
            .get(principal.tenant.as_str(), id)
            .await
            .map_err(|error| {
                tracing::error!(%error, %id, "could not read Code Mode task");
                execution_unavailable()
            })?
        else {
            return Ok(None);
        };
        if !execution_owned_by(&execution, principal)
            || execution.execution_profile.get("profile_confinement")
                != Some(&task_profile_confinement(principal))
        {
            return Ok(None);
        }
        if execution.status.is_terminal()
            && execution.retention_until <= time::OffsetDateTime::now_utc()
        {
            return Ok(None);
        }
        let reconciled = store
            .reconcile_abandoned(
                principal.tenant.as_str(),
                &principal.sub,
                &principal.issuer,
                id,
                self.claim_lease(),
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, %id, "could not reconcile abandoned Code Mode task");
                execution_unavailable()
            })?;
        Ok(reconciled.filter(|execution| {
            !execution.status.is_terminal()
                || execution.retention_until > time::OffsetDateTime::now_utc()
        }))
    }
}

fn task_profile_confinement(principal: &Principal) -> Value {
    let Some(restrictions) = principal.api_key_profile_restrictions.as_ref() else {
        return Value::Null;
    };
    let mut servers = restrictions.allowed_servers.clone().unwrap_or_default();
    servers.sort();
    servers.dedup();
    let mut tools = restrictions.allowed_tools.clone().unwrap_or_default();
    tools.sort();
    tools.dedup();
    if servers.is_empty() && tools.is_empty() {
        Value::Null
    } else {
        serde_json::json!({
            "allowed_servers": servers,
            "allowed_tools": tools,
        })
    }
}

/// Full-identity ownership check: tenant scoping happened at the store
/// read; here subject AND issuer must both match, and a pre-upgrade row
/// with no recorded issuer is owned by no one (fail closed) — two issuers
/// may mint the same `sub` for different people.
fn execution_owned_by(execution: &waygate_codemode::Execution, principal: &Principal) -> bool {
    execution.principal_sub == principal.sub
        && execution.principal_issuer.as_deref() == Some(principal.issuer.as_str())
}

/// Map a journal status onto the lifecycle status a caller observes.
///
/// Shared by the MCP Task projection and the ordinary poll surface so the two
/// consumption shapes cannot drift. A caller polling `codemode.status` and a
/// client polling `tasks/get` must not have to handle different vocabularies
/// for one execution; keeping the mapping in one place is what makes that a
/// property of the code rather than a convention.
fn lifecycle_status(status: ExecutionStatus) -> TaskStatus {
    match status {
        ExecutionStatus::WaitingForApproval
        | ExecutionStatus::WaitingForResume
        | ExecutionStatus::Ambiguous => TaskStatus::InputRequired,
        ExecutionStatus::Succeeded
        | ExecutionStatus::Compensated
        | ExecutionStatus::ReconciledApplied
        | ExecutionStatus::ReconciledNotApplied => TaskStatus::Completed,
        ExecutionStatus::Failed | ExecutionStatus::Expired => TaskStatus::Failed,
        ExecutionStatus::Cancelled => TaskStatus::Cancelled,
        _ => TaskStatus::Working,
    }
}

/// Render a lifecycle status as the value that crosses the wire.
///
/// Derived from the same serialization the Tasks projection uses, so the
/// string a poller reads is the string a Tasks client reads rather than a
/// second hand-maintained table that could disagree.
fn lifecycle_status_str(status: TaskStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "working".to_owned())
}

fn task_projection(execution: &waygate_codemode::Execution) -> Task {
    let status = lifecycle_status(execution.status);
    let mut task = Task::new(
        execution.id.to_string(),
        status,
        waygate_core::fmt::format_ts_rfc3339(execution.submitted_at),
        waygate_core::fmt::format_ts_rfc3339(execution.updated_at),
    );
    task.poll_interval_ms = Some(100);
    let ttl = (execution.retention_until - execution.submitted_at)
        .whole_milliseconds()
        .max(0);
    task.ttl_ms = u64::try_from(ttl).ok();
    task.status_message =
        if execution.cancellation_requested_at.is_some() && !execution.status.is_terminal() {
            Some("Cancellation requested".to_owned())
        } else if execution.status == ExecutionStatus::WaitingForResume {
            execution
                .resume_context
                .as_ref()
                .and_then(|context| context.get("checkpoint"))
                .and_then(|checkpoint| checkpoint.get("prompt"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| Some("Execution is waiting for resume".to_owned()))
        } else if execution.status == ExecutionStatus::WaitingForApproval {
            Some("Execution is waiting for mutation approval".to_owned())
        } else {
            execution.terminal_reason_code.clone()
        };
    task
}

fn execution_result_payload(execution: waygate_codemode::Execution) -> Result<Value, McpError> {
    match execution.status {
        ExecutionStatus::Succeeded
        | ExecutionStatus::Compensated
        | ExecutionStatus::ReconciledApplied
        | ExecutionStatus::ReconciledNotApplied => execution
            .result_payload
            .ok_or_else(stored_result_unavailable),
        ExecutionStatus::Failed | ExecutionStatus::Expired => Err(McpError::invalid_request(
            "Code Mode execution did not complete successfully",
            Some(serde_json::json!({
                "error": execution
                    .terminal_reason_code
                    .unwrap_or_else(|| "execution_failed".to_owned())
            })),
        )),
        ExecutionStatus::Cancelled => Err(execution_cancelled()),
        _ => Err(McpError::invalid_request(
            "Code Mode execution result is not ready",
            Some(serde_json::json!({"error": "execution_result_not_ready"})),
        )),
    }
}

fn artifact_reference(artifact: &ExecutionArtifact) -> ArtifactReference {
    ArtifactReference {
        execution_id: artifact.execution_id,
        artifact_id: artifact.artifact_id,
    }
}

fn artifact_summary(artifact: ExecutionArtifact) -> ArtifactSummary {
    ArtifactSummary {
        reference: artifact_reference(&artifact),
        created_at: waygate_core::fmt::format_ts_rfc3339(artifact.created_at),
    }
}

fn artifact_response(content: ExecutionArtifactContent) -> ArtifactResponse {
    ArtifactResponse {
        contract_version: ContractVersion::V1,
        reference: artifact_reference(&content.artifact),
        value: content.value,
        created_at: waygate_core::fmt::format_ts_rfc3339(content.artifact.created_at),
    }
}

fn artifact_cursor(artifact: &ExecutionArtifact) -> String {
    artifact.event_id.to_string()
}

fn parse_artifact_cursor(cursor: &str) -> Result<i64, McpError> {
    cursor
        .parse::<i64>()
        .ok()
        .filter(|cursor| *cursor > 0)
        .ok_or_else(|| {
            McpError::invalid_params(
                "invalid Code Mode artifact cursor; pass `next_cursor` unchanged from the prior response",
                None,
            )
        })
}

/// Keyset cursor over `(submitted_at, id)`, the listing's sort key. The
/// timestamp travels as unix nanoseconds so the round trip is exact: an
/// equal-timestamp tie is broken by the identifier, and a lossy encoding
/// would skip or repeat rows at page boundaries.
fn execution_list_cursor(entry: &waygate_codemode::InFlightExecution) -> String {
    format!("{}.{}", entry.submitted_at.unix_timestamp_nanos(), entry.id)
}

/// Status projection for one listed entry, from the store's decision-shaped
/// subset. It shares the by-id vocabulary but never carries a checkpoint:
/// checkpoints are caller-controlled payloads, so a page that included them
/// would grow with what the listed programs stored rather than with its row
/// count. The by-id poll reports the checkpoint for a discovered identifier.
fn in_flight_status_projection(
    entry: &waygate_codemode::InFlightExecution,
) -> ExecutionStatusResponse {
    ExecutionStatusResponse {
        contract_version: ContractVersion::V1,
        execution_id: entry.id,
        source_ref: None,
        status: lifecycle_status_str(lifecycle_status(entry.status)),
        terminal: entry.status.is_terminal(),
        terminal_reason_code: entry.terminal_reason_code.clone(),
        result_available: entry.result_available,
        cancellation_requested: entry.cancellation_requested,
        submitted_at: waygate_core::fmt::format_ts_rfc3339(entry.submitted_at),
        updated_at: waygate_core::fmt::format_ts_rfc3339(entry.updated_at),
        completed_at: entry.completed_at.map(waygate_core::fmt::format_ts_rfc3339),
        retention_until: waygate_core::fmt::format_ts_rfc3339(entry.retention_until),
        checkpoint: None,
    }
}

fn parse_execution_list_cursor(
    cursor: &str,
) -> Result<(time::OffsetDateTime, uuid::Uuid), McpError> {
    let invalid = || {
        McpError::invalid_params(
            "invalid Code Mode execution cursor; pass `next_cursor` unchanged from the prior \
             response",
            None,
        )
    };
    let (nanos, id) = cursor.split_once('.').ok_or_else(invalid)?;
    let submitted_at = nanos
        .parse::<i128>()
        .ok()
        .and_then(|nanos| time::OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .ok_or_else(invalid)?;
    let id = uuid::Uuid::parse_str(id).map_err(|_| invalid())?;
    Ok((submitted_at, id))
}

fn validate_execution_list_params(params: &ExecutionListParams) -> Result<(), McpError> {
    if params
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_EXECUTION_LIST_LIMIT)
    {
        return Err(McpError::invalid_params(
            format!("`limit` must be between 1 and {MAX_EXECUTION_LIST_LIMIT}"),
            None,
        ));
    }
    if params
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_EXECUTION_LIST_CURSOR_LENGTH)
    {
        return Err(McpError::invalid_params(
            format!("`cursor` must be at most {MAX_EXECUTION_LIST_CURSOR_LENGTH} bytes"),
            None,
        ));
    }
    Ok(())
}

fn validate_artifact_list_params(params: &ArtifactListParams) -> Result<(), McpError> {
    if params
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_ARTIFACT_LIMIT)
    {
        return Err(McpError::invalid_params(
            format!("`limit` must be between 1 and {MAX_ARTIFACT_LIMIT}"),
            None,
        ));
    }
    if params
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_ARTIFACT_CURSOR_LENGTH)
    {
        return Err(McpError::invalid_params(
            format!("`cursor` must be at most {MAX_ARTIFACT_CURSOR_LENGTH} bytes"),
            None,
        ));
    }
    Ok(())
}

fn may_read(principal: &Principal) -> bool {
    principal.has_scope(Scope::McpRead.as_str()) || principal.has_scope(Scope::McpAdmin.as_str())
}

fn may_invoke(principal: &Principal) -> bool {
    principal.has_scope(Scope::McpInvoke.as_str()) || principal.has_scope(Scope::McpAdmin.as_str())
}

fn record_discovery_operation(
    operation: waygate_telemetry::metrics::DiscoveryOperation,
    result: &Result<CallToolResult, McpError>,
    started: Instant,
) {
    let outcome = discovery_outcome(operation, result);
    waygate_telemetry::metrics::record_discovery_operation(
        operation,
        outcome,
        started.elapsed().as_secs_f64(),
    );
}

fn discovery_outcome(
    _operation: waygate_telemetry::metrics::DiscoveryOperation,
    result: &Result<CallToolResult, McpError>,
) -> waygate_telemetry::metrics::DiscoveryOutcome {
    use waygate_telemetry::metrics::DiscoveryOutcome;

    let error_kind = result.as_ref().err().and_then(|error| {
        error
            .data
            .as_ref()
            .and_then(|data| data.get("error"))
            .and_then(Value::as_str)
    });
    match result {
        Ok(_) => DiscoveryOutcome::Ok,
        Err(error) => match error_kind {
            Some(
                "catalog_changing"
                | "catalog_unavailable"
                | "skill_script_catalog_unavailable"
                | "tool_unavailable",
            ) => DiscoveryOutcome::Unavailable,
            Some("search_cursor_encoding_failed") => DiscoveryOutcome::Error,
            _ if error.code == rmcp::model::ErrorCode::INVALID_PARAMS => DiscoveryOutcome::Invalid,
            _ => DiscoveryOutcome::Error,
        },
    }
}

fn insufficient_scope(required_scope: &str) -> McpError {
    McpError::invalid_request(
        format!(
            "insufficient scope: the requested {NAMESPACE} operation requires `{required_scope}`"
        ),
        Some(serde_json::json!({
            "error": "insufficient_scope",
            "required_scope": required_scope,
        })),
    )
}

fn unknown_tool(_name: &str) -> McpError {
    McpError::invalid_params(
        format!(
            "unknown, ambiguous, or unavailable Code Mode tool; call `{NAMESPACE}.search` and \
             pass one returned `binding.connector` plus `binding.operation` pair"
        ),
        Some(serde_json::json!({"error": "tool_unavailable"})),
    )
}

fn admitted_call(
    admitted_calls: &HashMap<String, AdmittedCall>,
    call_id: &str,
) -> Result<AdmittedCall, String> {
    admitted_calls.get(call_id).cloned().ok_or_else(|| {
        connector_error(
            "binding_unavailable",
            "connector is not available in this execution",
        )
    })
}

/// The stable in-code error contract for a refused or failed connector
/// call: `"<code>: <message>"`, where `<code>` is a lowercase snake_case
/// discriminator stable across message-text changes. The runner SDK splits
/// this prefix into the thrown `Error`'s `code` property, so program code
/// branches on `error.code` — never on message text. Pipeline refusals use
/// `InvocationError::kind()` (`forbidden`, `approval_required`,
/// `input_schema_violation`, `rate_limited`,
/// `response_inspection_blocked`, …); broker-level refusals use the codes
/// authored at their sites.
fn connector_error(code: &str, message: impl std::fmt::Display) -> String {
    format!("{code}: {message}")
}

fn connector_result_value(
    result: CallToolResult,
) -> Result<Value, waygate_invocation::InvocationError> {
    if result.is_error.unwrap_or(false) {
        return Err(waygate_invocation::InvocationError::Upstream(
            McpError::internal_error(
                "connector reported a tool error",
                result.structured_content.clone(),
            ),
        ));
    }
    let delivery = result
        .meta
        .as_ref()
        .and_then(|meta| meta.get(waygate_mcp::files::RETAINED_DELIVERY_META_KEY))
        .cloned();
    if let Some(delivery) = delivery {
        let mut value = result
            .structured_content
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(object) = value.as_object_mut() {
            object.insert("_gateway_delivery".to_owned(), delivery);
            return Ok(value);
        }
        return Ok(serde_json::json!({"data":value, "_gateway_delivery":delivery}));
    }
    match result.structured_content.as_ref() {
        Some(structured) if structured.get("_gateway_delivery").is_some() => {
            // Only gateway metadata may populate the top-level delivery field.
            // Preserve a colliding upstream object as ordinary nested data.
            Ok(serde_json::json!({"data": structured}))
        }
        Some(structured) => Ok(structured.clone()),
        None => serde_json::to_value(&result).map_err(|_| {
            waygate_invocation::InvocationError::Upstream(McpError::internal_error(
                "connector result could not be encoded",
                None,
            ))
        }),
    }
}

fn builtin_contract_changed(admitted: &AdmittedCall) -> waygate_invocation::InvocationError {
    waygate_invocation::InvocationError::Upstream(McpError::invalid_params(
        format!(
            "connector contract changed for `{}.{}`; discover the current tool before retrying",
            admitted.server, admitted.tool
        ),
        Some(serde_json::json!({"error": "connector_contract_changed"})),
    ))
}

fn admit_execution_bindings(
    bindings: Vec<ExecutionBinding>,
) -> (HashMap<String, AdmittedCall>, Vec<RunnerBinding>, Value) {
    let mut admitted_calls = HashMap::with_capacity(bindings.len());
    let mut runner_bindings = Vec::with_capacity(bindings.len());
    let mut snapshot = Vec::with_capacity(bindings.len());
    for mut binding in bindings {
        // The durable snapshot keeps the stable connector identity used for
        // compatibility checks. Only the per-attempt runner binding receives
        // a fresh opaque capability handle.
        snapshot.push(
            serde_json::to_value(&binding)
                .expect("Code Mode execution bindings contain only serializable values"),
        );
        // Capability handles are fresh for each attempt. A handle observed by
        // one runner cannot name a connector in any later runner process.
        let call_id = loop {
            let candidate = uuid::Uuid::now_v7().to_string();
            if !admitted_calls.contains_key(&candidate) {
                break candidate;
            }
        };
        binding.runner.call_id = call_id.clone();
        admitted_calls.insert(
            call_id,
            AdmittedCall {
                approval_context: binding.approval_context,
                server: binding.server,
                tool: binding.tool,
                contract: binding.contract,
            },
        );
        runner_bindings.push(binding.runner);
    }
    (
        admitted_calls,
        runner_bindings,
        serde_json::json!({
            "contract_version": 1,
            "bindings": snapshot,
        }),
    )
}

fn compatible_resume_bindings(
    current: Vec<ExecutionBinding>,
    expected_snapshot: &Value,
) -> Result<Vec<ExecutionBinding>, &'static str> {
    let expected = expected_snapshot
        .as_object()
        .ok_or("tool_snapshot_invalid")?;
    if expected.get("contract_version").and_then(Value::as_u64) != Some(1) {
        return Err("tool_snapshot_invalid");
    }
    let expected_bindings = expected
        .get("bindings")
        .and_then(Value::as_array)
        .ok_or("tool_snapshot_invalid")?;

    let mut current_by_id = HashMap::with_capacity(current.len());
    for binding in current {
        let call_id = binding.runner.call_id.clone();
        let serialized = serde_json::to_value(&binding)
            .expect("Code Mode execution bindings contain only serializable values");
        if current_by_id
            .insert(call_id, (binding, serialized))
            .is_some()
        {
            return Err("tool_snapshot_invalid");
        }
    }

    let mut resumed = Vec::with_capacity(expected_bindings.len());
    for expected_binding in expected_bindings {
        let call_id = expected_binding
            .pointer("/runner/call_id")
            .and_then(Value::as_str)
            .ok_or("tool_snapshot_invalid")?;
        let Some((binding, serialized)) = current_by_id.remove(call_id) else {
            return Err("tool_snapshot_changed");
        };
        if serialized != *expected_binding {
            return Err("tool_snapshot_changed");
        }
        resumed.push(binding);
    }
    Ok(resumed)
}

fn runner_call_id(server: &str, tool: &str) -> String {
    format!("{}:{server}{}:{tool}", server.len(), tool.len())
}

fn selector_admitted(server: &str, tool: &str) -> bool {
    !server.is_empty()
        && !tool.is_empty()
        && server.len().saturating_add(tool.len()) <= MAX_SELECTOR_LENGTH
}

#[derive(Serialize, Deserialize)]
struct SearchCursorClaims {
    kind: String,
    exp: i64,
    offset: u64,
    principal: String,
    query: String,
    view: String,
}

impl HasExp for SearchCursorClaims {
    fn exp(&self) -> i64 {
        self.exp
    }
}

fn search_cursor(
    offset: usize,
    principal: &str,
    query: &str,
    view: &str,
    sealer: &crate::mcp_discovery::DiscoveryCursorSealer,
) -> Result<String, McpError> {
    let offset = u64::try_from(offset).map_err(|_| search_cursor_encoding_error())?;
    sealer
        .seal_claims(&SearchCursorClaims {
            kind: SEARCH_CURSOR_KIND.to_owned(),
            exp: time::OffsetDateTime::now_utc()
                .unix_timestamp()
                .saturating_add(SEARCH_CURSOR_LIFETIME_SECONDS),
            offset,
            principal: principal.to_owned(),
            query: query.to_owned(),
            view: view.to_owned(),
        })
        .map_err(|_| search_cursor_encoding_error())
}

fn search_cursor_offset(
    cursor: Option<&str>,
    principal: &str,
    query: &str,
    view: &str,
    result_count: usize,
    sealer: &crate::mcp_discovery::DiscoveryCursorSealer,
) -> Result<usize, McpError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let claims: SearchCursorClaims = sealer
        .open_claims(cursor)
        .map_err(|_| invalid_search_cursor())?;
    let offset = usize::try_from(claims.offset).map_err(|_| invalid_search_cursor())?;
    if claims.kind != SEARCH_CURSOR_KIND
        || claims.principal != principal
        || claims.query != query
        || claims.view != view
        || offset == 0
        || offset >= result_count
    {
        return Err(invalid_search_cursor());
    }
    Ok(offset)
}

fn search_cursor_encoding_error() -> McpError {
    McpError::internal_error(
        "Code Mode search continuation could not be encoded",
        Some(serde_json::json!({"error": "search_cursor_encoding_failed"})),
    )
}

fn invalid_search_cursor() -> McpError {
    McpError::invalid_params(
        "invalid Code Mode search cursor; pass `next_cursor` unchanged from the prior response",
        None,
    )
}

fn execution_unavailable() -> McpError {
    McpError::internal_error(
        "Code Mode execution is unavailable",
        Some(serde_json::json!({"error": "execution_unavailable"})),
    )
}

fn invalid_source_retention() -> McpError {
    McpError::invalid_params(
        format!(
            "`retain_for_seconds` must be between {MIN_SOURCE_RETENTION_SECONDS} and \
             {MAX_SOURCE_RETENTION_SECONDS}; omit it when submitting `source_sha256`"
        ),
        Some(serde_json::json!({"error": "invalid_source_retention"})),
    )
}

fn invalid_source_selector(
    source: bool,
    source_file: bool,
    source_sha256: bool,
    skill_script: bool,
    include_skill_script_in_guidance: bool,
) -> McpError {
    let mut supplied = Vec::new();
    if source {
        supplied.push("`source`");
    }
    if source_file {
        supplied.push("`source_file`");
    }
    if source_sha256 {
        supplied.push("`source_sha256`");
    }
    if skill_script {
        supplied.push("`skill_script`");
    }
    // Only none-supplied and more-than-one-supplied reach this error, so the
    // list never names a single field the caller got right.
    let detail = if supplied.is_empty() {
        "none was supplied".to_string()
    } else {
        format!("{} were supplied together", supplied.join(" and "))
    };
    let choices = if include_skill_script_in_guidance {
        "`source` (inline JavaScript), `source_file` (an uploaded `mcp-file://gateway/...` URI), \
         `source_sha256` (a live retained digest), or `skill_script` (an approved resource in \
         the active Agent Skills catalog)"
    } else {
        "`source` (inline JavaScript), `source_file` (an uploaded `mcp-file://gateway/...` URI), \
         or `source_sha256` (a live retained digest)"
    };
    McpError::invalid_params(
        format!("supply exactly one of {choices}; {detail}"),
        Some(serde_json::json!({"error": "invalid_source_selector"})),
    )
}

fn skill_script_catalog_unavailable() -> McpError {
    McpError::invalid_request(
        "Agent Skills script execution is unavailable because no verified catalog snapshot is active; ask the operator to configure or refresh the external Git skill source",
        Some(serde_json::json!({"error": "skill_script_catalog_unavailable"})),
    )
}

fn skill_script_not_found() -> McpError {
    McpError::invalid_params(
        "`skill_script` is not a static resource in the active verified Agent Skills catalog; refresh discovery and pass its exact resource URI",
        Some(serde_json::json!({"error": "skill_script_not_found"})),
    )
}

fn skill_script_incompatible() -> McpError {
    McpError::invalid_request(
        "the skill resource must contain UTF-8 JavaScript supported by the Code Mode runtime",
        Some(serde_json::json!({"error": "skill_script_incompatible"})),
    )
}

fn skill_script_catalog_changed() -> McpError {
    McpError::invalid_request(
        "the served skill changed while its source was loaded; rediscover the current skill",
        Some(serde_json::json!({"error": "skill_script_catalog_changed"})),
    )
}

fn valid_source_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn invalid_source_digest() -> McpError {
    McpError::invalid_params(
        "`source_sha256` must be the 64-character lowercase SHA-256 returned in `source_ref.sha256`",
        Some(serde_json::json!({"error": "invalid_source_digest"})),
    )
}

fn source_artifact_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode retained-source storage requires a configured database and \
         `GATEWAY_CODEMODE_RESULT_STORAGE=allow`; omit retention or ask the operator to enable \
         durable content storage",
        Some(serde_json::json!({"error": "source_artifact_unavailable"})),
    )
}

fn source_locator_store_error(error: waygate_core::store::StoreError) -> McpError {
    match error {
        waygate_core::store::StoreError::Conflict => source_locator_capacity(),
        _ => execution_unavailable(),
    }
}

fn source_locator_capacity() -> McpError {
    McpError::invalid_request(
        "Code Mode uploaded-source retry capacity is exhausted for this owner or tenant; reuse \
         an existing upload handle or allow prior execution retention windows to expire",
        Some(serde_json::json!({
            "error": "source_locator_capacity",
            "max_locators_per_owner": MAX_SOURCE_LOCATORS_PER_OWNER,
            "max_locators_per_tenant": MAX_SOURCE_LOCATORS_PER_TENANT,
        })),
    )
}

fn source_artifact_capacity() -> McpError {
    McpError::invalid_request(
        "Code Mode retained-source capacity is exhausted; reuse or allow existing source hashes to expire before retaining new source",
        Some(serde_json::json!({
            "error": "source_artifact_capacity",
            "max_sources_per_owner": limits().retained_owner_count,
            "max_source_bytes_per_owner": limits().retained_owner_bytes,
            "max_sources_per_tenant": limits().retained_tenant_count,
            "max_source_bytes_per_tenant": limits().retained_tenant_bytes,
        })),
    )
}

fn source_artifact_not_found() -> McpError {
    McpError::invalid_request(
        "retained Code Mode source is unavailable or expired; resubmit `source` or upload a fresh `source_file`",
        Some(serde_json::json!({"error": "source_artifact_not_found"})),
    )
}

fn source_file_unavailable() -> McpError {
    McpError::internal_error(
        "Code Mode uploaded-source reading is unavailable on this deployment",
        Some(serde_json::json!({"error": "source_file_unavailable"})),
    )
}

fn source_file_error(error: crate::file_transfer::StoredTextFileError) -> McpError {
    use crate::file_transfer::StoredTextFileError;

    match error {
        StoredTextFileError::InvalidUri => McpError::invalid_params(
            format!(
                "`source_file` must be an owner-scoped `{}<id>` URI returned after upload",
                waygate_core::GATEWAY_FILE_URI_PREFIX
            ),
            Some(serde_json::json!({"error": "invalid_source_file"})),
        ),
        StoredTextFileError::NotFound => McpError::invalid_request(
            "uploaded Code Mode source is unavailable or expired; upload it again and submit the fresh URI",
            Some(serde_json::json!({"error": "source_file_not_found"})),
        ),
        StoredTextFileError::TooLarge { size, max_bytes } => McpError::invalid_params(
            format!("uploaded Code Mode source is {size} bytes; maximum is {max_bytes} bytes"),
            Some(serde_json::json!({"error": "source_too_large", "max_bytes": max_bytes})),
        ),
        StoredTextFileError::InvalidUtf8 => McpError::invalid_params(
            "uploaded Code Mode source must be valid UTF-8 JavaScript",
            Some(serde_json::json!({"error": "source_not_utf8"})),
        ),
        StoredTextFileError::Unavailable => source_file_unavailable(),
    }
}

fn execution_error_with_id(mut error: McpError, execution_id: uuid::Uuid) -> McpError {
    let mut data = error.data.take().unwrap_or_else(|| serde_json::json!({}));
    if let Some(fields) = data.as_object_mut() {
        fields.insert(
            "execution_id".to_owned(),
            Value::String(execution_id.to_string()),
        );
    } else {
        data = serde_json::json!({
            "execution_id": execution_id,
            "detail": data,
        });
    }
    error.data = Some(data);
    error
}

fn execution_setup_timeout() -> McpError {
    McpError::invalid_request(
        "Code Mode runner did not become ready within its setup allowance",
        Some(serde_json::json!({"error": "execution_setup_timeout"})),
    )
}

fn execution_timeout() -> McpError {
    McpError::invalid_request(
        "Code Mode execution exceeded its time limit",
        Some(serde_json::json!({"error": "execution_timeout"})),
    )
}

fn execution_cancelled() -> McpError {
    McpError::invalid_request(
        "Code Mode execution was cancelled",
        Some(serde_json::json!({"error": "execution_cancelled"})),
    )
}

fn pause_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode pause requires durable storage with result persistence enabled; configure \
         `GATEWAY_DATABASE_URL` and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`, then run the \
         execution again",
        Some(serde_json::json!({"error": "execution_pause_unavailable"})),
    )
}

fn mutation_pause_unavailable() -> McpError {
    McpError::invalid_request(
        "Direct-authority Code Mode executions cannot pause or replay; \
         `execution.pause(checkpoint)` is available only when durable result storage is available",
        Some(serde_json::json!({"error": "execution_pause_unavailable"})),
    )
}

fn resume_storage_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode resume requires durable storage with result persistence enabled; configure \
         `GATEWAY_DATABASE_URL` and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`",
        Some(serde_json::json!({"error": "execution_resume_unavailable"})),
    )
}

fn result_storage_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode result references require durable storage with result persistence enabled; \
         configure `GATEWAY_DATABASE_URL` and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`",
        Some(serde_json::json!({"error": "execution_result_unavailable"})),
    )
}

fn stored_result_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode execution result is unavailable to this caller or past its retention window",
        Some(serde_json::json!({"error": "execution_result_unavailable"})),
    )
}

/// Precondition failure for the poll surface.
///
/// Distinct from the result-reference error because the caller's mistake is
/// different: nothing is wrong with their handle, the deployment simply keeps
/// no executions to poll.
fn detached_execution_withheld(tool: &str) -> McpError {
    McpError::invalid_request(
        format!(
            "profile confinement does not grant `{NAMESPACE}.{tool}`; a profile that enumerates \
             tools must name it to start durable background work"
        ),
        Some(serde_json::json!({"error": "detached_execution_withheld"})),
    )
}

fn execution_start_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode detached execution requires durable storage with result persistence enabled; \
         configure `GATEWAY_DATABASE_URL` and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`, or call \
         `codemode.execute` and let the call block",
        Some(serde_json::json!({"error": "execution_start_unavailable"})),
    )
}

fn execution_poll_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode execution polling requires durable storage with result persistence enabled; \
         configure `GATEWAY_DATABASE_URL` and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`",
        Some(serde_json::json!({"error": "execution_poll_unavailable"})),
    )
}

/// One shape for unknown, unowned, and expired executions.
///
/// A caller that does not own an execution learns nothing about whether the
/// identifier exists, which is what keeps a handle from being usable by
/// possession alone.
fn execution_status_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode execution is unknown, not owned by this caller, or past its retention window",
        Some(serde_json::json!({"error": "execution_unavailable"})),
    )
}

fn artifact_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode artifacts require durable storage with result persistence enabled; configure \
         `GATEWAY_DATABASE_URL` and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`",
        Some(serde_json::json!({"error": "execution_artifact_unavailable"})),
    )
}

fn artifact_limit_exceeded() -> McpError {
    McpError::invalid_request(
        "Code Mode execution exceeded the intermediate artifact limit for one runner attempt",
        Some(serde_json::json!({
            "error": "execution_artifact_limit_exceeded",
            "max_artifacts": limits().artifacts_per_attempt,
        })),
    )
}

fn artifact_too_large() -> McpError {
    McpError::invalid_request(
        "Code Mode artifact exceeded its size limit",
        Some(serde_json::json!({
            "error": "execution_artifact_too_large",
            "max_bytes": limits().artifact_bytes,
        })),
    )
}

fn stored_artifact_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode artifact is unavailable to this caller or past its retention window",
        Some(serde_json::json!({"error": "execution_artifact_unavailable"})),
    )
}

fn execution_resume_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode execution is not waiting for resume, is already owned by another worker, or \
         is unavailable to this caller",
        Some(serde_json::json!({"error": "execution_resume_unavailable"})),
    )
}

fn execution_approval_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode mutation is not waiting for approval, is already owned by another worker, or \
         is unavailable to this caller",
        Some(serde_json::json!({"error": "execution_approval_unavailable"})),
    )
}

fn execution_resume_incompatible(reason: &str) -> McpError {
    McpError::invalid_request(
        "Code Mode execution cannot resume because its immutable execution context is no longer \
         compatible; start a new execution",
        Some(serde_json::json!({
            "error": "execution_resume_incompatible",
            "reason": reason,
        })),
    )
}

fn task_result_unavailable() -> McpError {
    McpError::invalid_request(
        "Code Mode task result is no longer available; run the task again",
        Some(serde_json::json!({"error": "task_result_unavailable"})),
    )
}

fn execution_failure_code(error: &McpError) -> String {
    match error
        .data
        .as_ref()
        .and_then(|data| data.get("error"))
        .and_then(Value::as_str)
    {
        Some(
            code @ ("tenant_execution_capacity"
            | "detached_execution_capacity"
            | "execution_capacity"
            | "execution_unavailable"
            | "execution_timeout"
            | "execution_setup_timeout"
            | "execution_result_too_large"
            | "execution_result_not_json"
            | "execution_artifact_unavailable"
            | "execution_artifact_limit_exceeded"
            | "execution_artifact_too_large"
            | "runner_failed"
            | "runner_frame_too_large"
            | "runner_frame_unterminated"
            | "runner_frame_malformed"
            | "runner_crashed"
            | "runner_protocol_error"
            | "runner_transport_error"),
        ) => code.to_owned(),
        _ => "execution_failed".to_owned(),
    }
}

fn execution_event(
    kind: ExecutionEventKind,
    step: Option<usize>,
    call_id: Option<uuid::Uuid>,
    detail: Value,
) -> NewExecutionEvent {
    execution_event_with_attempt(kind, step, call_id, step.map(|_| 1), detail)
}

fn execution_event_with_attempt(
    kind: ExecutionEventKind,
    step: Option<usize>,
    call_id: Option<uuid::Uuid>,
    attempt: Option<u32>,
    detail: Value,
) -> NewExecutionEvent {
    NewExecutionEvent {
        kind,
        step_number: step.and_then(|value| i32::try_from(value).ok()),
        call_id,
        attempt: attempt.and_then(|value| i32::try_from(value).ok()),
        detail,
    }
}

fn nested_invocation_hierarchy(
    attempt: &RunnerAttempt<'_>,
    calls: usize,
) -> Result<InvocationHierarchy, McpError> {
    let step = u32::try_from(calls)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(execution_unavailable)?;
    let claim_epoch = attempt.claim.map_or(1, |claim| claim.epoch);
    let attempt_number = u32::try_from(claim_epoch)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(execution_unavailable)?;
    let call_id = uuid::Uuid::new_v5(&attempt.execution_id, &step.get().to_be_bytes());
    Ok(InvocationHierarchy::new(
        attempt.execution_id,
        step,
        call_id,
        attempt_number,
    ))
}

fn mutation_approval_request(
    attempt: &RunnerAttempt<'_>,
    admitted: &AdmittedCall,
    arguments: &Value,
    hierarchy: InvocationHierarchy,
) -> MutationApprovalRequest {
    MutationApprovalRequest {
        connector: admitted.server.clone(),
        operation: admitted.tool.clone(),
        argument_hash: waygate_catalog::argument_hash(arguments.as_object()),
        arguments_preview: admitted.approval_context.as_ref().map_or_else(
            || approval_arguments_preview(arguments),
            |context| context.arguments_preview(arguments),
        ),
        description: admitted
            .approval_context
            .as_ref()
            .map(|context| context.description.clone()),
        risk: match admitted.contract.risk() {
            InvocationRisk::Low => Risk::Low,
            InvocationRisk::Medium => Risk::Medium,
            InvocationRisk::High => Risk::High,
        },
        source_digest: attempt.source_digest.clone(),
        call_id: hierarchy.call_id,
        step: hierarchy.step.get(),
        contract: serde_json::to_value(&admitted.contract)
            .expect("invocation contract identity is serializable"),
        prior_effects: 0,
    }
}

/// Approval presentation derived from the admitted, reviewed tool definition.
/// Raw arguments remain inside the invocation boundary; this projection does
/// not change what is authorized, hashed, or submitted upstream.
#[derive(Debug, Clone)]
struct ApprovalContext {
    description: String,
    sensitive_input: bool,
    input_fields: Vec<String>,
}

impl ApprovalContext {
    fn from_tool(tool: &CatalogTool) -> Self {
        let sensitive_input = tool
            .invocation_snapshot()
            .and_then(|snapshot| {
                Some(
                    waygate_upstream::security_metadata::behavior_claims(
                        snapshot.tool_annotations()?,
                        snapshot.action_metadata()?,
                    )
                    .map_or(true, |claims| claims.input_sensitive),
                )
            })
            // Legacy aggregate PII can describe output alone. Preserve its
            // existing credential-redacted preview without inferring that
            // an effect destination is secret input.
            .unwrap_or(false);
        let input_fields = tool
            .definition
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|fields| fields.keys().cloned().collect())
            .unwrap_or_default();
        Self {
            description: tool
                .definition
                .description
                .as_deref()
                .unwrap_or_default()
                .to_owned(),
            sensitive_input,
            input_fields,
        }
    }

    fn arguments_preview(&self, arguments: &Value) -> Value {
        if !self.sensitive_input {
            return approval_arguments_preview(arguments);
        }
        // Use schema-owned names, not arbitrary user-controlled object keys.
        Value::Object(
            self.input_fields
                .iter()
                .filter(|name| arguments.get(name.as_str()).is_some())
                .map(|name| {
                    (
                        name.clone(),
                        Value::String("[REDACTED:SENSITIVE_INPUT]".to_owned()),
                    )
                })
                .collect(),
        )
    }
}

/// Produce the complete approval argument view with explicit credential redaction.
fn approval_arguments_preview(arguments: &Value) -> Value {
    // The approver must see effect destinations and payload content to make
    // the decision — including PII-shaped values, since an unintended
    // recipient or an exfiltrated value is exactly what a human review
    // exists to catch. Every value the approval hash covers is shown in
    // full; only recognized credential material and sensitive key names are
    // replaced, and each replacement is an explicit labeled marker, never a
    // silent omission. Oversized arguments never reach preview generation —
    // they are refused at admission by `limits().request_bytes`.
    let (without_secrets, _) = waygate_mcp::inspection::secrets::redact_json_value(arguments);
    redact_sensitive_argument_keys(without_secrets)
}

/// Normalize a field name to lower snake_case before sensitive-marker
/// matching, so `clientSecret`, `client-secret`, `client.secret`, and
/// `client_secret` all reach the same comparison form. Camel boundaries
/// (a lowercase letter or digit followed by an uppercase letter) become
/// underscores; consecutive capitals collapse (`APIKey` → `apikey`).
fn normalize_argument_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len() + 4);
    let mut previous_lower_or_digit = false;
    for ch in key.chars() {
        if ch == '-' || ch == '.' {
            normalized.push('_');
            previous_lower_or_digit = false;
            continue;
        }
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            normalized.push('_');
        }
        previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        normalized.push(ch.to_ascii_lowercase());
    }
    normalized
}

fn redact_sensitive_argument_keys(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(redact_sensitive_argument_keys)
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    // Match markers as whole underscore-delimited segments
                    // anywhere in the key, so `aws_secret_access_key` and
                    // `secretAccessKey` redact the same as `secret` — a
                    // credential-bearing word buried mid-key must not slip
                    // past an exact/suffix comparison.
                    let padded = format!("_{}_", normalize_argument_key(&key));
                    let sensitive = [
                        "authorization",
                        "password",
                        "passwd",
                        "secret",
                        "token",
                        "api_key",
                        "apikey",
                        "credential",
                        "private_key",
                    ]
                    .iter()
                    .any(|marker| padded.contains(&format!("_{marker}_")));
                    (
                        key,
                        if sensitive {
                            Value::String("[REDACTED:SENSITIVE_FIELD]".to_owned())
                        } else {
                            redact_sensitive_argument_keys(value)
                        },
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

fn runner_reported_failure(code: RunnerFailureCode, runner_message: &str) -> McpError {
    if code == RunnerFailureCode::RunnerInternal {
        return McpError::internal_error(
            "Code Mode runner could not complete the execution",
            Some(serde_json::json!({"error": "runner_failed"})),
        );
    }
    let (error, message) = match code {
        RunnerFailureCode::ExecutionTimeout => (
            "execution_timeout",
            "Code Mode execution exceeded its time limit".to_owned(),
        ),
        RunnerFailureCode::ProgramFailed => {
            ("execution_failed", bounded_failure_message(runner_message))
        }
        RunnerFailureCode::ConnectorResultTooLarge => (
            "connector_result_too_large",
            "Code Mode connector result exceeded runtime materialization capacity".to_owned(),
        ),
        RunnerFailureCode::ResultTooLarge => (
            "execution_result_too_large",
            "Code Mode execution result exceeded its size limit".to_owned(),
        ),
        RunnerFailureCode::ResultNotJson => (
            "execution_result_not_json",
            "Code Mode program must return a JSON-compatible value".to_owned(),
        ),
        RunnerFailureCode::ArtifactTooLarge => (
            "execution_artifact_too_large",
            "Code Mode artifact exceeded its size limit".to_owned(),
        ),
        RunnerFailureCode::RunnerInternal => unreachable!("handled above"),
    };
    McpError::invalid_request(message, Some(serde_json::json!({"error": error})))
}

/// Bring a spawned runner to the point where its program can begin.
///
/// Bounded, and safe to bound on every profile. Nothing has been dispatched
/// before the start frame is written, so there is no in-flight effect to
/// abandon — which is the reason an approval-bound mutation's *program* phase
/// must never be dropped, and the reason this phase may be. Without a bound
/// here a runner that never reaches readiness holds its capacity permits and
/// its durable claim indefinitely, with nothing to release them.
///
/// The timeout reports its own reason rather than the program's. A caller that
/// cannot tell a runner that never started from a program that ran out of
/// budget cannot tell a broken deployment from a slow program.
async fn complete_runner_setup(
    stdin: &mut (impl AsyncWrite + Unpin),
    stdout: &mut (impl AsyncBufRead + Unpin),
    start: ParentFrame,
    setup_deadline: tokio::time::Instant,
) -> Result<(), McpError> {
    tokio::time::timeout_at(setup_deadline, async {
        let readiness = read_runner_frame(stdout)
            .await
            .map_err(runner_frame_failure)?;
        validate_runner_ready(readiness)?;
        write_parent_frame(stdin, &start).await
    })
    .await
    .map_err(|_| execution_setup_timeout())?
}

fn validate_runner_ready(frame: RunnerFrame) -> Result<(), McpError> {
    match frame {
        RunnerFrame::Ready {
            confinement_profile,
        } if confinement_profile == CONFINEMENT_PROFILE => Ok(()),
        _ => Err(runner_protocol_failure()),
    }
}

fn runner_frame_failure(failure: RunnerFrameReadFailure) -> McpError {
    match failure {
        RunnerFrameReadFailure::Closed => runner_crashed(),
        RunnerFrameReadFailure::TooLarge => McpError::internal_error(
            "Code Mode runner emitted an oversized protocol frame",
            Some(serde_json::json!({"error": "runner_frame_too_large"})),
        ),
        RunnerFrameReadFailure::Unterminated => McpError::internal_error(
            "Code Mode runner emitted an unterminated protocol frame",
            Some(serde_json::json!({"error": "runner_frame_unterminated"})),
        ),
        RunnerFrameReadFailure::Malformed => McpError::internal_error(
            "Code Mode runner emitted a malformed protocol frame",
            Some(serde_json::json!({"error": "runner_frame_malformed"})),
        ),
        RunnerFrameReadFailure::Transport => runner_transport_failure(),
    }
}

fn runner_crashed() -> McpError {
    McpError::internal_error(
        "Code Mode runner terminated before completing the execution",
        Some(serde_json::json!({"error": "runner_crashed"})),
    )
}

fn runner_protocol_failure() -> McpError {
    McpError::internal_error(
        "Code Mode runner violated its protocol contract",
        Some(serde_json::json!({"error": "runner_protocol_error"})),
    )
}

fn runner_transport_failure() -> McpError {
    McpError::internal_error(
        "Code Mode runner transport failed",
        Some(serde_json::json!({"error": "runner_transport_error"})),
    )
}

fn tenant_execution_capacity() -> McpError {
    McpError::invalid_request(
        "Code Mode execution capacity for this tenant is currently exhausted",
        Some(serde_json::json!({"error": "tenant_execution_capacity"})),
    )
}

fn execution_capacity() -> McpError {
    McpError::invalid_request(
        "Code Mode execution capacity is currently exhausted",
        Some(serde_json::json!({"error": "execution_capacity"})),
    )
}

fn detached_execution_capacity() -> McpError {
    McpError::invalid_request(
        "Code Mode detached execution capacity is currently exhausted",
        Some(serde_json::json!({"error": "detached_execution_capacity"})),
    )
}

fn execution_repeat_unavailable() -> McpError {
    McpError::invalid_request(
        "`repeat_after` does not name a retained execution with this exact source, profile, \
         and owner; call `codemode.start` without `repeat_after` to converge on the current \
         matching execution or create one",
        Some(serde_json::json!({"error": "execution_repeat_unavailable"})),
    )
}

fn execution_repeat_not_terminal(execution: &waygate_codemode::Execution) -> McpError {
    McpError::invalid_request(
        "the `repeat_after` execution has not finished; poll `codemode.status` until it is \
         terminal before deliberately repeating it",
        Some(serde_json::json!({
            "error": "execution_repeat_not_terminal",
            "execution_id": execution.id,
            "status": lifecycle_status_str(lifecycle_status(execution.status)),
        })),
    )
}

/// Return the exact content digest when the selector carries enough bytes or
/// hash material to do so without an external read.
fn detached_known_source_digest(selector: &SourceSelector) -> Result<Option<String>, McpError> {
    match selector {
        SourceSelector::Inline(source) => {
            validate_source(source)?;
            Ok(Some(source_digest(source)))
        }
        SourceSelector::Retained(digest) => {
            if !valid_source_digest(digest) {
                return Err(invalid_source_digest());
            }
            // Knowing a hash is not enough to use it after the private source
            // artifact expires; resolve it through the artifact lifecycle.
            Ok(None)
        }
        SourceSelector::File(_) | SourceSelector::SkillScript(..) => Ok(None),
    }
}

fn detached_source_locator(selector: &SourceSelector) -> Option<String> {
    match selector {
        SourceSelector::File(uri) => Some(source_digest(&format!("mcp-file\u{1f}{uri}"))),
        SourceSelector::Inline(_)
        | SourceSelector::Retained(_)
        | SourceSelector::SkillScript(..) => None,
    }
}

fn resolved_execution_source(
    execution: &waygate_codemode::Execution,
    retain_for_seconds: Option<u32>,
) -> Result<ResolvedSource, McpError> {
    Ok(ResolvedSource {
        source: execution.source.clone().ok_or_else(execution_unavailable)?,
        digest: execution.source_digest.clone(),
        retention: retain_for_seconds.map(|seconds| Duration::from_secs(u64::from(seconds))),
        source_authority: execution
            .execution_profile
            .get("source_authority")
            .filter(|authority| !authority.is_null())
            .cloned(),
    })
}

/// One retry-equivalence class per principal identity, exact source bytes, and
/// exact input on the detached start surface. Input participates because the
/// source digest deliberately does not: the same program run against different
/// input does different work, and without input here those starts would
/// converge and the second would be served the first one's result. Fixed width
/// is deliberate: identity claims have no length bound, and repeating them
/// verbatim in an indexed column can exceed PostgreSQL's index-row limit for
/// identities the rest of the schema accepts.
fn detached_start_dedupe_key(
    principal: &Principal,
    program_digest: &str,
    input: &Value,
    source_authority: Option<&Value>,
) -> String {
    let identity = format!(
        "start\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        principal.tenant.as_str(),
        principal.issuer,
        principal.sub,
        program_digest,
    );
    let identity = match source_authority {
        Some(authority) => format!(
            "{identity}\u{1f}{}",
            serde_json::to_string(authority).expect("source authority serializes")
        ),
        None => identity,
    };
    // A start carrying no input keys exactly as it did before the input
    // channel existed. Executions outlive a deployment, so appending a digest
    // of "no input" would strand every retained no-input start: an identical
    // retry would miss its own class and duplicate the work, and `repeat_after`
    // could not name an execution submitted by the previous binary. An omitted
    // input and an explicit null are one class because the program cannot tell
    // them apart either.
    if input.is_null() {
        return source_digest(&identity);
    }
    // Keyed on the parsed input, re-serialized here; the caller's original
    // bytes are already gone by this point. Which encoding distinctions
    // survive that round trip is deliberately not relied on, because neither
    // outcome is a correctness risk: two submissions that converge carried the
    // same values, and two that separate cost an extra run rather than one
    // being served the other's result. Canonicalizing would mean recursively
    // sorting arbitrary caller JSON on every start to buy neither of those.
    let input_digest = source_digest(&serde_json::to_string(input).unwrap_or_default());
    source_digest(&format!("{identity}\u{1f}{input_digest}"))
}

async fn write_parent_frame(
    output: &mut (impl AsyncWrite + Unpin),
    frame: &ParentFrame,
) -> Result<(), McpError> {
    let encoded = encode_parent_frame(frame).map_err(|_| runner_protocol_failure())?;
    output
        .write_all(&encoded)
        .await
        .map_err(|_| runner_transport_failure())?;
    output
        .write_all(b"\n")
        .await
        .map_err(|_| runner_transport_failure())?;
    output.flush().await.map_err(|_| runner_transport_failure())
}

async fn write_connector_result(
    output: &mut (impl AsyncWrite + Unpin),
    spool: &mut std::fs::File,
    id: u32,
    result: Result<Value, String>,
    materialization_limit: usize,
) -> Result<(), McpError> {
    let result = match result {
        Ok(value) => match crate::codemode_spool::check_value(&value, materialization_limit) {
            Ok(()) => Ok(value),
            Err(crate::codemode_spool::WriteValueError::TooLarge) => Err(connector_error(
                "connector_result_too_large",
                "connector result exceeds the Code Mode runtime materialization budget",
            )),
            Err(crate::codemode_spool::WriteValueError::Failed(error)) => {
                tracing::error!(%error, "could not measure Code Mode connector result");
                return Err(runner_transport_failure());
            }
        },
        Err(error) => Err(error),
    };
    let inline = ParentFrame::CallResult {
        id,
        result: result.map(|value| ConnectorCallResult::Inline { value }),
    };
    if encode_parent_frame(&inline).is_ok() {
        return write_parent_frame(output, &inline).await;
    }
    let ParentFrame::CallResult {
        result: Ok(ConnectorCallResult::Inline { value }),
        ..
    } = inline
    else {
        return Err(runner_protocol_failure());
    };
    let mut file = spool.try_clone().map_err(|_| runner_transport_failure())?;
    let result =
        tokio::task::spawn_blocking(move || crate::codemode_spool::write_value(&mut file, &value))
            .await
            .map_err(|_| runner_transport_failure())?;
    let result = match result {
        Ok(bytes) => Ok(ConnectorCallResult::Spool { bytes }),
        Err(crate::codemode_spool::WriteValueError::TooLarge) => Err(connector_error(
            "connector_result_too_large",
            "connector result exceeds the Code Mode runtime materialization budget",
        )),
        Err(crate::codemode_spool::WriteValueError::Failed(error)) => {
            tracing::error!(%error, "could not write Code Mode result spool");
            return Err(runner_transport_failure());
        }
    };
    write_parent_frame(output, &ParentFrame::CallResult { id, result }).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerFrameReadFailure {
    Closed,
    TooLarge,
    Unterminated,
    Malformed,
    Transport,
}

async fn read_runner_frame(
    input: &mut (impl AsyncBufRead + Unpin),
) -> Result<RunnerFrame, RunnerFrameReadFailure> {
    let mut encoded = Vec::new();
    let bytes = (&mut *input)
        .take((limits().frame_bytes + 1) as u64)
        .read_until(b'\n', &mut encoded)
        .await
        .map_err(|_| RunnerFrameReadFailure::Transport)?;
    if bytes == 0 {
        return Err(RunnerFrameReadFailure::Closed);
    }
    if bytes > limits().frame_bytes {
        return Err(RunnerFrameReadFailure::TooLarge);
    }
    if !encoded.ends_with(b"\n") {
        return Err(RunnerFrameReadFailure::Unterminated);
    }
    serde_json::from_slice(&encoded).map_err(|_| RunnerFrameReadFailure::Malformed)
}

fn parse_args<T: DeserializeOwned>(arguments: &JsonObject, action: &str) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(arguments.clone())).map_err(|error| {
        let example = match action {
            "search" => r#"{"query":"email","limit":20}"#,
            "describe" => r#"{"name":"email.read"}"#,
            "execute" | "start" => {
                r#"{"source":"return connectors.email.read({value: \"inbox\"});","retain_for_seconds":3600}"#
            }
            "resume" => r#"{"execution_id":"019c...","input":{"choice":"west"}}"#,
            _ => "{}",
        };
        McpError::invalid_params(
            format!(
                "invalid `{NAMESPACE}.{action}` arguments: {error}; inspect this tool's \
                 inputSchema for the accepted fields; example: {example}"
            ),
            None,
        )
    })
}

fn validate_search_params(params: &SearchParams) -> Result<(), McpError> {
    if params
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_SEARCH_LIMIT)
    {
        return Err(McpError::invalid_params(
            format!("`limit` must be between 1 and {MAX_SEARCH_LIMIT}"),
            None,
        ));
    }
    if params
        .query
        .as_ref()
        .is_some_and(|query| query.len() > limits().query_bytes)
    {
        return Err(McpError::invalid_params(
            format!("`query` must be at most {} bytes", limits().query_bytes),
            None,
        ));
    }
    Ok(())
}

fn summary(name: &str, tool: &CatalogTool) -> Option<ConnectorSummary> {
    Some(ConnectorSummary {
        name: name.to_owned(),
        binding: ConnectorBinding {
            connector: tool.identity.source.name().to_owned(),
            operation: tool.identity.name.clone(),
            name: name.to_owned(),
        },
        description: tool.definition.description.as_deref().map(str::to_owned),
        identity: catalog_identity(tool)?,
        governance: Governance::from_admission(&tool.facts, Some(&tool.authorization)),
    })
}

fn catalog_identity(tool: &CatalogTool) -> Option<SnapshotIdentity> {
    match &tool.identity.source {
        CatalogToolSource::Upstream(_) => tool.invocation_snapshot().map(identity),
        CatalogToolSource::Builtin(_) => Some(SnapshotIdentity::Builtin {
            behavior_hash: builtin_behavior_hash(tool),
            input_schema_hash: waygate_catalog::validator_schema_hash(&Value::Object(
                tool.definition.input_schema.as_ref().clone(),
            )),
            output_schema_hash: tool.definition.output_schema.as_ref().map(|schema| {
                waygate_catalog::validator_schema_hash(&Value::Object(schema.as_ref().clone()))
            }),
        }),
    }
}

fn builtin_behavior_hash(tool: &CatalogTool) -> String {
    let annotations = tool
        .definition
        .annotations
        .as_ref()
        .and_then(|annotations| serde_json::to_value(annotations).ok());
    let metadata = tool
        .definition
        .meta
        .as_ref()
        .map(|meta| Value::Object(meta.0.clone()));
    waygate_catalog::behavior_hash(
        &tool.identity.qualified_name(),
        tool.definition.description.as_deref(),
        tool.definition.input_schema.as_ref(),
        tool.definition.output_schema.as_deref(),
        annotations.as_ref(),
        metadata.as_ref(),
    )
}

fn identity(snapshot: &InvocationToolSnapshot) -> SnapshotIdentity {
    let input_schema_hash = snapshot
        .input_schema()
        .map(waygate_catalog::validator_schema_hash)
        .expect("Code Mode only identifies snapshots with an admitted input schema");
    let output_schema_hash = snapshot
        .described_output_schema()
        .as_ref()
        .map(waygate_catalog::validator_schema_hash);
    let tool_annotations_hash = snapshot
        .tool_annotations()
        .map(waygate_catalog::validator_schema_hash);
    let action_metadata_hash = snapshot
        .action_metadata()
        .map(waygate_catalog::validator_schema_hash);
    let operations_hash = snapshot.operations_hash();
    match snapshot.authority() {
        ResolutionAuthority::Catalog {
            tool_id,
            schema_hash,
        } => SnapshotIdentity::Catalog {
            tool_id: tool_id.to_string(),
            catalog_schema_hash: schema_hash.clone(),
            input_schema_hash,
            output_schema_hash,
            tool_annotations_hash,
            action_metadata_hash,
            operations_hash,
        },
        ResolutionAuthority::ManifestFallback {
            approval_requirements_known,
            approved_behavior_hash,
        } => SnapshotIdentity::ManifestFallback {
            approved_behavior_hash: approved_behavior_hash.clone(),
            input_schema_hash,
            output_schema_hash,
            tool_annotations_hash,
            action_metadata_hash,
            operations_hash,
            approval_requirements_known: *approval_requirements_known,
        },
        ResolutionAuthority::SyntheticModel => {
            unreachable!("synthetic model identities are not admitted as MCP connectors")
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Risk {
    Low,
    Medium,
    High,
}

impl From<RiskTier> for Risk {
    fn from(risk: RiskTier) -> Self {
        match risk {
            RiskTier::Low => Self::Low,
            RiskTier::Medium => Self::Medium,
            RiskTier::High => Self::High,
        }
    }
}

fn validate_source(source: &str) -> Result<(), McpError> {
    let max_source_bytes = limits().source_bytes;
    if source.trim().is_empty() || source.len() > limits().source_bytes {
        return Err(McpError::invalid_params(
            format!(
                "`source` must contain between 1 and {max_source_bytes} UTF-8 bytes, including at \
                 least one non-whitespace character; example: \
                 {{\"source\":\"return {{ok: true}};\"}}"
            ),
            None,
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchParams {
    /// Natural-language or keyword query ranked across fully-qualified names,
    /// source names, titles, and descriptions. Omit to enumerate admitted
    /// tools in canonical order.
    #[schemars(length(max = limits().query_bytes))]
    query: Option<String>,
    /// Exclusive cursor returned by a prior search response.
    #[schemars(length(max = MAX_CURSOR_LENGTH))]
    cursor: Option<String>,
    /// Maximum returned tools. Defaults to 50; maximum 100.
    #[schemars(range(min = 1, max = MAX_SEARCH_LIMIT))]
    limit: Option<u16>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DescribeParams {
    /// Conventional display name returned by `codemode.search`. Use only when
    /// it identifies exactly one connector/operation pair.
    #[schemars(length(min = 3, max = MAX_SELECTOR_LENGTH))]
    name: Option<String>,
    /// Exact connector namespace from `codemode.search.tools[].binding`.
    #[schemars(length(min = 1, max = MAX_SELECTOR_LENGTH))]
    connector: Option<String>,
    /// Exact operation name from `codemode.search.tools[].binding`.
    #[schemars(length(min = 1, max = MAX_SELECTOR_LENGTH))]
    operation: Option<String>,
}

// The source forms are independent optional properties rather than a
// root-level union of one-variant-per-form. A schema root carrying
// `anyOf`/`oneOf`/`allOf` is valid JSON Schema and valid MCP, but the
// tool-calling APIs that consume `tools/list` refuse such a tool definition, so
// a published union costs the tool its place in the client's catalog entirely.
// `select_source` enforces mutual exclusion and reports conflicting fields.

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StartParams {
    /// JavaScript function body, exactly as `codemode.execute` accepts it.
    /// Supply exactly one source field. The source limit counts UTF-8 bytes;
    /// read `codemode.limits` for the effective budget.
    #[schemars(length(min = 1, max = limits().source_bytes), regex(pattern = r"\S"))]
    source: Option<String>,
    /// Owner-scoped `mcp-file://gateway/...` URI containing UTF-8 JavaScript.
    /// Supply exactly one source field.
    #[schemars(length(min = 1, max = MAX_SELECTOR_LENGTH))]
    source_file: Option<String>,
    /// Lowercase SHA-256 returned by an earlier retained Code Mode source
    /// submission. Looking it up never extends its expiry. Supply exactly one
    /// source field.
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    source_sha256: Option<String>,
    /// Exact `skill://...` URI of a JavaScript file available to this tenant.
    /// The gateway fetches it directly without source in the client's context.
    /// No compatibility hint or separate execution grant is required; ordinary
    /// Code Mode and tool permissions apply. Supply exactly one source field.
    #[schemars(length(min = 1, max = MAX_SELECTOR_LENGTH))]
    skill_script: Option<String>,
    /// Optional catalog revision returned by gateway-skills.load. Valid only
    /// with skill_script. Pins the helper to the loaded workflow revision;
    /// unavailable or unapproved revisions fail rather than using newer bytes.
    /// Omit to select the currently approved serving revision.
    #[schemars(length(equal = 71), regex(pattern = r"^sha256:[0-9a-f]{64}$"))]
    skill_revision: Option<String>,
    /// Keep these exact UTF-8 source bytes for private reuse by SHA-256 for
    /// this many seconds. Omit to execute without creating a reusable source.
    /// Valid with `source`, `source_file`, or `skill_script`; omit with `source_sha256`.
    #[schemars(range(min = MIN_SOURCE_RETENTION_SECONDS, max = MAX_SOURCE_RETENTION_SECONDS))]
    retain_for_seconds: Option<u32>,
    /// Any JSON-compatible value the program reads as `execution.input`. Put
    /// arguments here rather than editing them into the source: a program is
    /// identified by its exact bytes, so an edited-in value makes a different
    /// program that cannot reuse a retained source. Two starts of the same
    /// source with different input are distinct executions.
    input: Option<Value>,
    /// Deliberate repetition of the latest retained terminal execution with
    /// the same resolved source, input, and profile.
    #[serde(default)]
    repeat_after: Option<String>,
}

/// Resolve the one admitted source form from the independent optional fields
/// the published schema carries, rejecting a request that names none or more
/// than one.
fn select_source(
    source: Option<String>,
    source_file: Option<String>,
    source_sha256: Option<String>,
    skill_script: Option<String>,
    skill_revision: Option<String>,
    retain_for_seconds: Option<u32>,
    include_skill_script_in_guidance: bool,
) -> Result<(SourceSelector, Option<u32>), McpError> {
    if skill_revision.is_some() && skill_script.is_none() {
        return Err(McpError::invalid_params(
            "skill_revision requires skill_script; omit it for other source forms",
            Some(serde_json::json!({"error": "invalid_skill_revision_selector"})),
        ));
    }
    match (source, source_file, source_sha256, skill_script) {
        (Some(source), None, None, None) => {
            Ok((SourceSelector::Inline(source), retain_for_seconds))
        }
        (None, Some(uri), None, None) => Ok((SourceSelector::File(uri), retain_for_seconds)),
        (None, None, Some(digest), None) => {
            // Resolving a retained artifact never extends its expiry, so a
            // retention request here would silently do nothing.
            if retain_for_seconds.is_some() {
                return Err(invalid_source_retention());
            }
            Ok((SourceSelector::Retained(digest), None))
        }
        (None, None, None, Some(uri)) => Ok((
            SourceSelector::SkillScript(uri, skill_revision),
            retain_for_seconds,
        )),
        (source, source_file, source_sha256, skill_script) => Err(invalid_source_selector(
            source.is_some(),
            source_file.is_some(),
            source_sha256.is_some(),
            skill_script.is_some(),
            include_skill_script_in_guidance,
        )),
    }
}

#[derive(Debug)]
enum SourceSelector {
    Inline(String),
    File(String),
    Retained(String),
    SkillScript(String, Option<String>),
}

#[derive(Debug)]
struct ResolvedSource {
    source: String,
    digest: String,
    retention: Option<Duration>,
    source_authority: Option<Value>,
}

/// Caller-supplied data a program reads, admitted against the same bound as a
/// resume's input. `None` and an explicit JSON null are the same absence of
/// input, so a program can test `execution.input` without distinguishing them.
fn admit_program_input(input: Option<Value>) -> Result<Value, McpError> {
    let input = input.unwrap_or(Value::Null);
    let oversized = serde_json::to_vec(&input)
        .map(|encoded| encoded.len() > limits().input_bytes)
        .unwrap_or(true);
    if oversized {
        return Err(McpError::invalid_params(
            "Code Mode program input exceeds the bounded input limit",
            Some(serde_json::json!({
                "error": "execution_input_too_large",
                "max_bytes": limits().input_bytes,
            })),
        ));
    }
    Ok(input)
}

impl StartParams {
    fn into_parts(self) -> Result<(SourceSelector, Option<u32>, Option<String>, Value), McpError> {
        let (selector, retain_for_seconds) = select_source(
            self.source,
            self.source_file,
            self.source_sha256,
            self.skill_script,
            self.skill_revision,
            self.retain_for_seconds,
            true,
        )?;
        Ok((
            selector,
            retain_for_seconds,
            self.repeat_after,
            admit_program_input(self.input)?,
        ))
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ResumeParams {
    /// Durable identifier returned by a Code Mode execution whose status is
    /// `waiting_for_resume`.
    #[schemars(length(min = 1, max = 64))]
    execution_id: String,
    /// Any JSON-compatible value requested by the checkpoint. Omit when
    /// retrying an interrupted attempt whose input is already durably bound.
    input: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExecutionReferenceParams {
    /// Durable execution identifier returned by `codemode.execute`,
    /// `codemode.resume`, or MCP Task augmentation.
    #[schemars(length(min = 1, max = 64))]
    execution_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ArtifactListParams {
    /// Durable execution identifier returned by `codemode.execute`,
    /// `codemode.resume`, or MCP Task augmentation.
    #[schemars(length(min = 1, max = 64))]
    execution_id: String,
    /// Exclusive cursor returned by a prior artifact-list response.
    #[schemars(length(max = MAX_ARTIFACT_CURSOR_LENGTH))]
    cursor: Option<String>,
    /// Maximum returned references. Defaults to 50; maximum 100.
    #[schemars(range(min = 1, max = MAX_ARTIFACT_LIMIT))]
    limit: Option<u16>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExecutionListParams {
    /// Exclusive cursor returned by a prior execution-list response.
    #[schemars(length(max = MAX_EXECUTION_LIST_CURSOR_LENGTH))]
    cursor: Option<String>,
    /// Maximum returned executions. Defaults to 50; maximum 100.
    #[schemars(range(min = 1, max = MAX_EXECUTION_LIST_LIMIT))]
    limit: Option<u16>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ArtifactParams {
    /// Durable execution identifier from the artifact reference.
    #[schemars(length(min = 1, max = 64))]
    execution_id: String,
    /// Opaque artifact identifier returned by `execution.emitArtifact(...)`
    /// or `codemode.artifacts`.
    #[schemars(length(min = 1, max = 64))]
    artifact_id: String,
}

#[derive(Debug, Serialize)]
struct ExecutionBinding {
    // Reconstructed from the same hash-bound catalog definition on resume.
    #[serde(skip)]
    approval_context: Option<ApprovalContext>,
    runner: RunnerBinding,
    server: String,
    tool: String,
    contract: ExecutionContract,
}

#[derive(Debug, Clone)]
struct AdmittedCall {
    approval_context: Option<ApprovalContext>,
    server: String,
    tool: String,
    contract: ExecutionContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExecutionContract {
    Upstream {
        identity: InvocationContractIdentity,
    },
    Builtin {
        behavior_hash: String,
        risk: InvocationRisk,
        side_effects: bool,
        pii: bool,
    },
}

impl Serialize for ExecutionContract {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            // Preserve the established durable shape for upstream bindings so
            // executions created before this release remain comparable.
            Self::Upstream { identity } => identity.serialize(serializer),
            Self::Builtin {
                behavior_hash,
                risk,
                side_effects,
                pii,
            } => serde_json::json!({
                "source": "builtin",
                "behavior_hash": behavior_hash,
                "risk": risk,
                "side_effects": side_effects,
                "pii": pii,
            })
            .serialize(serializer),
        }
    }
}

impl ExecutionContract {
    fn risk(&self) -> InvocationRisk {
        match self {
            Self::Upstream { identity } => identity.risk,
            Self::Builtin { risk, .. } => *risk,
        }
    }

    fn risk_tier(&self) -> RiskTier {
        match self.risk() {
            InvocationRisk::Low => RiskTier::Low,
            InvocationRisk::Medium => RiskTier::Medium,
            InvocationRisk::High => RiskTier::High,
        }
    }

    fn side_effects(&self) -> bool {
        match self {
            Self::Upstream { identity } => identity.side_effects,
            Self::Builtin { side_effects, .. } => *side_effects,
        }
    }

    fn pii(&self) -> bool {
        match self {
            Self::Upstream { identity } => identity.pii,
            Self::Builtin { pii, .. } => *pii,
        }
    }

    #[cfg(test)]
    fn upstream_identity(&self) -> Option<&InvocationContractIdentity> {
        match self {
            Self::Upstream { identity } => Some(identity),
            Self::Builtin { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct MutationApprovalRequest {
    /// Exact connector namespace.
    connector: String,
    /// Exact operation name.
    operation: String,
    /// Canonical hash of the original arguments consumed by the approval gate.
    argument_hash: String,
    /// Argument preview with credentials redacted. For classified sensitive
    /// inputs, only submitted schema field names are shown, with value markers.
    /// The protocol binding still covers the complete original arguments.
    arguments_preview: Value,
    /// Reviewed tool description explaining consequences and limitations.
    /// Absent on approval requests captured before description support.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Governed risk classification.
    risk: Risk,
    /// Digest of the exact JavaScript source.
    source_digest: String,
    /// Stable connector-call identity.
    call_id: uuid::Uuid,
    /// One-based connector-call order.
    step: u32,
    /// Immutable admitted connector contract.
    contract: Value,
    /// Side effects already completed by this execution.
    prior_effects: u32,
}

struct ExecutionProgram {
    source: String,
    admitted_calls: HashMap<String, AdmittedCall>,
    runner_bindings: Vec<RunnerBinding>,
    resume: Option<RunnerResumeContext>,
    /// Caller-supplied data the program reads. Carried per attempt from the
    /// durable row, so a resumed or retried attempt replays the input its
    /// execution was submitted with rather than starting from nothing.
    input: Value,
    profile: CodeExecutionProfile,
}

struct SubmittedProgram {
    execution_id: uuid::Uuid,
    source: String,
    input: Value,
    persist_result: bool,
    profile: CodeExecutionProfile,
    permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
}

struct WaitingProgram {
    expected_status: ExecutionStatus,
    profile: CodeExecutionProfile,
    source: String,
    resume_context: Value,
    runner_resume: Option<RunnerResumeContext>,
}

struct ClaimedProgram {
    execution: waygate_codemode::Execution,
    store: SharedExecutionStore,
    claim: ExecutionClaim,
    program: ExecutionProgram,
    deadline: tokio::time::Instant,
    persist_result: bool,
    _tenant_permit: OwnedSemaphorePermit,
    _detached_slot: Option<OwnedSemaphorePermit>,
    _capacity_permit: OwnedSemaphorePermit,
}

struct ExecutionPermits {
    tenant: OwnedSemaphorePermit,
    detached: Option<OwnedSemaphorePermit>,
    global: OwnedSemaphorePermit,
}

/// Hold every permit for the whole attempt future.
async fn hold_execution_permits_until<T>(
    permits: ExecutionPermits,
    work: impl std::future::Future<Output = T>,
) -> T {
    let ExecutionPermits {
        tenant,
        detached,
        global,
    } = permits;
    let result = work.await;
    drop((tenant, detached, global));
    result
}

#[derive(Clone)]
struct RunnerAttempt<'a> {
    principal: &'a Principal,
    execution_id: uuid::Uuid,
    claim: Option<&'a ExecutionClaim>,
    persist_content: bool,
    profile: CodeExecutionProfile,
    source_digest: String,
    /// Deadline enforced *inside* the broker at journal-safe boundaries
    /// (frame reads and read dispatches) instead of by dropping the attempt
    /// future. Set for mutation attempts, whose one approved effect must
    /// never be abandoned mid-flight: once its dispatch begins it is awaited
    /// to completion — bounded by the invocation pipeline's own upstream
    /// timeout — and its outcome journaled before a deadline failure can
    /// terminalize the attempt.
    deadline: Option<tokio::time::Instant>,
}

/// Await `future` under the attempt's journal-safe deadline, converting
/// expiry into the ordinary timeout failure. `None` leaves the future
/// unbounded (the caller enforces an outer deadline instead).
async fn bounded_by_deadline<T>(
    deadline: Option<tokio::time::Instant>,
    future: impl std::future::Future<Output = Result<T, McpError>>,
) -> Result<T, McpError> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| execution_timeout())?,
        None => future.await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeExecutionProfile {
    Direct,
    /// Historical journal profile. Public execution and resume entry points
    /// never select it; persisted records using it cannot be resumed.
    LegacyApprovalBound,
}

impl CodeExecutionProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::LegacyApprovalBound => "approval_bound_mutation",
        }
    }

    fn admits(self, _facts: &waygate_mcp::authz::ToolFacts) -> bool {
        match self {
            // Direct execution carries no authority of its own. Discovery is
            // a projection; every call re-enters the caller's ordinary direct
            // authorization path at dispatch time.
            Self::Direct | Self::LegacyApprovalBound => true,
        }
    }
}

struct ClaimedExecution<'a> {
    store: &'a SharedExecutionStore,
    principal: &'a Principal,
    claim: &'a ExecutionClaim,
    persist_result: bool,
    deadline: tokio::time::Instant,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
enum ContractVersion {
    #[serde(rename = "1")]
    V1,
}

/// The caller-facing spelling of the stamps a row carries. These are the same
/// two numbers as `SDK_CONTRACT_VERSION` and `RUNNER_CONTRACT_VERSION` and must
/// advance with them: a response that advertised the previous contract while
/// the sandbox offered a new one would tell a client the program surface is
/// something other than what it ran against.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
enum SdkContractVersion {
    #[serde(rename = "4")]
    V4,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
enum RunnerContractVersion {
    #[serde(rename = "7")]
    V7,
}

#[derive(Debug)]
enum RunnerProgramOutcome {
    Completed {
        result: Value,
        calls: usize,
        artifacts: Vec<ArtifactReference>,
    },
    Paused {
        checkpoint: Value,
        calls: usize,
        artifacts: Vec<ArtifactReference>,
    },
    WaitingForApproval {
        approval: Box<MutationApprovalRequest>,
        calls: usize,
        artifacts: Vec<ArtifactReference>,
    },
}

#[derive(Debug, Serialize, JsonSchema)]
struct SearchResponse {
    /// Version of the runtime-neutral connector contract.
    contract_version: ContractVersion,
    /// Governed tools admitted for this caller.
    tools: Vec<ConnectorSummary>,
    /// Exclusive cursor for the next page, or absent on the final page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ConnectorSummary {
    /// Fully-qualified `<connector>.<operation>` identity.
    name: String,
    /// Unambiguous connector and operation selector for `codemode.describe`.
    binding: ConnectorBinding,
    /// Published operation description.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Immutable authority and schema-version identity.
    identity: SnapshotIdentity,
    /// Governance facts admitted with this tool snapshot.
    governance: Governance,
}

#[derive(Debug, Serialize, JsonSchema)]
struct DescribeResponse {
    /// Version of the runtime-neutral connector contract.
    contract_version: ContractVersion,
    /// Stable raw names used by generated connector bindings.
    binding: ConnectorBinding,
    /// Immutable authority and schema-version identity.
    identity: SnapshotIdentity,
    /// Exact admitted JSON Schema for connector input.
    input_schema: Value,
    /// Response schema supplied by the governed catalog or upstream declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    output_schema: Option<Value>,
    /// Governance facts admitted with this tool snapshot.
    governance: Governance,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ConnectorBinding {
    /// Exact upstream or gateway-local connector namespace.
    connector: String,
    /// Exact operation name within the connector.
    operation: String,
    /// Conventional display identity. Use `connector` plus `operation` as the
    /// unambiguous selector because either component may contain dots.
    name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ExecuteResponse {
    /// Version of the Code Mode execution contract.
    contract_version: ContractVersion,
    /// Version of the `connectors[server][operation]` binding contract.
    sdk_contract_version: SdkContractVersion,
    /// Version of the parent/runner capability protocol.
    runner_contract_version: RunnerContractVersion,
    /// Parent identity stamped onto every governed nested invocation and its
    /// evidence rows.
    execution_id: uuid::Uuid,
    /// Content-addressed identity of the exact UTF-8 JavaScript bytes that
    /// ran, plus the private reuse deadline when those bytes were retained.
    source_ref: SourceReference,
    /// Whether the fresh runner completed or released its resources at a
    /// durable checkpoint.
    status: ExecutionResponseStatus,
    /// JSON-compatible value returned by the program. This is JSON `null`
    /// while `status` is `waiting_for_resume`.
    result: Value,
    /// Bounded checkpoint emitted by `execution.pause(...)`. Present only
    /// while the execution is waiting for caller input or another resume.
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint: Option<Value>,
    /// Exact side effect awaiting a human decision. Its argument preview is
    /// size-bounded and best-effort redacted; the canonical hash, not the
    /// preview, binds the approval to the actual arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<MutationApprovalRequest>,
    /// Number of connector calls attempted by the program.
    connector_calls: usize,
    /// Stable reference for repeated retrieval through `codemode.result`.
    /// Present only when content persistence is enabled and execution
    /// completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    result_ref: Option<ExecutionResultReference>,
    /// Stable references for artifacts emitted during this runner attempt.
    artifacts: Vec<ArtifactReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SourceRetentionState {
    /// No live private source artifact exists for this caller and digest.
    NotRetained,
    /// The artifact is reusable until `expires_at`.
    Live,
    /// Retention truth could not be read; retry status before deciding that
    /// the artifact is absent.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
struct SourceReference {
    /// Lowercase SHA-256 accepted later as `source_sha256` while retained.
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    sha256: String,
    /// Exact deadline for hash reuse. Absent when no live retained artifact
    /// backs this reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    /// Whether the owner-scoped retained artifact is live, absent, or could
    /// not be checked. `live` always carries `expires_at`.
    retention_state: SourceRetentionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
struct ExecutionResultReference {
    /// Durable execution whose stored final result this reference resolves.
    execution_id: uuid::Uuid,
}

#[derive(Debug, Serialize, JsonSchema)]
struct StoredResultResponse {
    /// Version of the Code Mode stored-result contract.
    contract_version: ContractVersion,
    /// Stable reference used for this retrieval.
    reference: ExecutionResultReference,
    /// Original JSON-compatible value returned by the program.
    result: Value,
}

/// Decision-shaped projection of one durable execution.
///
/// Deliberately excludes the stored result and any artifact content. This is
/// the shape a caller polls in a loop, so its size must not grow with the work
/// the program did; retrieval stays with `codemode.result` and the artifact
/// tools, which a caller reaches for once, after this reports there is
/// something to fetch.
#[derive(Debug, Serialize, JsonSchema)]
struct ExecutionStatusResponse {
    /// Version of the Code Mode execution-status contract.
    contract_version: ContractVersion,
    /// Durable execution this status describes.
    execution_id: uuid::Uuid,
    /// Digest of the exact admitted source. A live retained-artifact expiry is
    /// included when one still exists for this caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ref: Option<SourceReference>,
    /// Lifecycle status at the moment of this read, in the same vocabulary the
    /// MCP Tasks projection reports for this execution.
    status: String,
    /// Whether `status` is terminal, so further polling cannot change it.
    terminal: bool,
    /// Stable reason code accompanying a terminal status, where one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_reason_code: Option<String>,
    /// Whether a stored final result is retrievable through `codemode.result`.
    /// False on a non-terminal execution and on one that stored no result.
    result_available: bool,
    /// Whether cancellation has been requested. A request is not itself
    /// terminal; the execution reaches `cancelled` once it observes one.
    cancellation_requested: bool,
    /// When the execution was submitted.
    submitted_at: String,
    /// When the execution row last advanced.
    updated_at: String,
    /// When the execution reached a terminal status, where it has.
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    /// When this execution, its stored result, and its artifacts stop being
    /// retrievable. Past this the identifier resolves to nothing.
    retention_until: String,
    /// Checkpoint a paused program published, present only while the execution
    /// is waiting to be resumed.
    ///
    /// A caller that started the execution detached never saw the response
    /// carrying this, and cannot choose resume input without it. It is absent
    /// in every other state, so an ordinary poll stays decision-shaped.
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint: Option<Value>,
}

/// Checkpoint to report for an execution, or `None` when it has none to report.
///
/// Read-only pause is the only state with a checkpoint a caller may act on.
/// Approval-bound waiting also stores a resume context, but that context holds
/// the approval binding rather than a checkpoint, and it is reviewed and
/// redacted on its own surface. Selecting the state first, then the one key,
/// keeps that binding out of a poll response by construction rather than by a
/// reader's care.
fn reportable_checkpoint(execution: &waygate_codemode::Execution) -> Option<Value> {
    if execution.status != ExecutionStatus::WaitingForResume {
        return None;
    }
    execution
        .resume_context
        .as_ref()
        .and_then(|context| context.get("checkpoint"))
        .cloned()
}

fn execution_status_projection(execution: &waygate_codemode::Execution) -> ExecutionStatusResponse {
    ExecutionStatusResponse {
        contract_version: ContractVersion::V1,
        execution_id: execution.id,
        source_ref: Some(SourceReference {
            sha256: execution.source_digest.clone(),
            expires_at: None,
            retention_state: SourceRetentionState::NotRetained,
        }),
        status: lifecycle_status_str(lifecycle_status(execution.status)),
        terminal: execution.status.is_terminal(),
        terminal_reason_code: execution.terminal_reason_code.clone(),
        result_available: execution.result_payload.is_some(),
        cancellation_requested: execution.cancellation_requested_at.is_some(),
        submitted_at: waygate_core::fmt::format_ts_rfc3339(execution.submitted_at),
        updated_at: waygate_core::fmt::format_ts_rfc3339(execution.updated_at),
        completed_at: execution
            .completed_at
            .map(waygate_core::fmt::format_ts_rfc3339),
        retention_until: waygate_core::fmt::format_ts_rfc3339(execution.retention_until),
        checkpoint: reportable_checkpoint(execution),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
struct ArtifactReference {
    /// Durable execution that owns the artifact.
    execution_id: uuid::Uuid,
    /// Opaque append-only journal identifier for this artifact.
    artifact_id: uuid::Uuid,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ArtifactSummary {
    /// Stable reference accepted by `codemode.artifact`.
    reference: ArtifactReference,
    /// Journal timestamp for the durable emission.
    created_at: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ArtifactListResponse {
    /// Version of the Code Mode artifact contract.
    contract_version: ContractVersion,
    /// Durable execution that owns every returned artifact.
    execution_id: uuid::Uuid,
    /// Artifacts in append order. Content is retrieved individually through
    /// `codemode.artifact`.
    artifacts: Vec<ArtifactSummary>,
    /// Exclusive cursor for the next reference page, or absent on the final
    /// page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ExecutionListResponse {
    /// Version of the Code Mode execution contract.
    contract_version: ContractVersion,
    /// The caller's own in-flight executions, newest submission first, in
    /// the status poll's vocabulary. Entries never carry a checkpoint — a
    /// page's size is bounded by its row count, not by what the listed
    /// programs stored — so poll a discovered identifier with
    /// `codemode.status` to read its checkpoint.
    executions: Vec<ExecutionStatusResponse>,
    /// Exclusive cursor for the next page, or absent on the final page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ArtifactResponse {
    /// Version of the Code Mode artifact contract.
    contract_version: ContractVersion,
    /// Stable reference used for this retrieval.
    reference: ArtifactReference,
    /// JSON-compatible content emitted by the program.
    value: Value,
    /// Journal timestamp for the durable emission.
    created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ExecutionResponseStatus {
    Completed,
    WaitingForApproval,
    WaitingForResume,
}

impl ExecutionResponseStatus {
    fn leaves_execution_waiting(self) -> bool {
        matches!(self, Self::WaitingForApproval | Self::WaitingForResume)
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "authority", rename_all = "snake_case")]
enum SnapshotIdentity {
    /// Gateway-owned built-in definition, versioned by its complete published
    /// behavior contract and exact schemas.
    Builtin {
        behavior_hash: String,
        input_schema_hash: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        output_schema_hash: Option<String>,
    },
    /// Governed catalog identity plus hashes of the exact admitted schemas.
    Catalog {
        tool_id: String,
        /// Historical catalog-version discriminator. This is provenance, not
        /// the connector contract hash: imported catalog rows can use a
        /// classification-only value.
        catalog_schema_hash: String,
        /// Canonical hash of the exact admitted input schema returned here.
        input_schema_hash: String,
        /// Canonical hash of the exact admitted output schema returned here.
        #[serde(skip_serializing_if = "Option::is_none")]
        output_schema_hash: Option<String>,
        /// Canonical hash of standard MCP behavior annotations.
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_annotations_hash: Option<String>,
        /// Canonical hash of the namespaced action metadata.
        #[serde(skip_serializing_if = "Option::is_none")]
        action_metadata_hash: Option<String>,
        /// Canonical hash of the reviewed per-operation definition — the
        /// discriminator and the classifications keyed by its values. Absent
        /// when the tool is classified by name alone.
        #[serde(skip_serializing_if = "Option::is_none")]
        operations_hash: Option<String>,
    },
    /// Transitional manifest authority with exact admitted schema hashes.
    ManifestFallback {
        /// The manifest-approved behavior hash bound at admission for an
        /// annotation-native upstream (`None` in legacy manifest mode) —
        /// keeps separately approved generations distinguishable even when
        /// they differ only outside the four schema hashes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approved_behavior_hash: Option<String>,
        /// Canonical hash of the exact admitted input schema returned here.
        input_schema_hash: String,
        /// Canonical hash of the exact admitted output schema returned here.
        #[serde(skip_serializing_if = "Option::is_none")]
        output_schema_hash: Option<String>,
        /// Canonical hash of standard MCP behavior annotations.
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_annotations_hash: Option<String>,
        /// Canonical hash of the namespaced action metadata.
        #[serde(skip_serializing_if = "Option::is_none")]
        action_metadata_hash: Option<String>,
        /// Canonical hash of the reviewed per-operation definition — the
        /// discriminator and the classifications keyed by its values. Absent
        /// when the tool is classified by name alone.
        #[serde(skip_serializing_if = "Option::is_none")]
        operations_hash: Option<String>,
        approval_requirements_known: bool,
    },
}

#[derive(Debug, Serialize, JsonSchema)]
struct Governance {
    /// Admitted risk tier.
    risk: Risk,
    /// Whether the operation can cause an external effect.
    side_effects: bool,
    /// Whether the operator classified the operation as handling PII.
    pii: bool,
    /// Whether a live per-call approval grant is required.
    requires_approval: bool,
    /// Whether the authority supplying `requires_approval` was available and
    /// trustworthy when this snapshot was admitted.
    requires_approval_known: bool,
    /// Scope required to make the tool callable when current Code Mode policy
    /// requires step-up authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    required_step_up_scope: Option<String>,
}

impl Governance {
    fn from_admission(
        facts: &waygate_mcp::ToolFacts,
        authorization: Option<&CatalogAuthorization>,
    ) -> Self {
        let approval_required =
            matches!(authorization, Some(CatalogAuthorization::ApprovalRequired));
        let required_step_up_scope = match authorization {
            Some(CatalogAuthorization::StepUpRequired { required_scope }) => {
                Some(required_scope.clone())
            }
            Some(CatalogAuthorization::Allowed | CatalogAuthorization::ApprovalRequired) | None => {
                None
            }
        };
        Self {
            risk: Risk::from(facts.risk),
            side_effects: facts.side_effects,
            pii: facts.pii,
            requires_approval: approval_required || facts.requires_approval,
            requires_approval_known: approval_required || facts.requires_approval_known,
            required_step_up_scope,
        }
    }
}

fn connector_contract_with_authorization(
    server: &str,
    tool_name: &str,
    snapshot: &InvocationToolSnapshot,
    authorization: Option<&CatalogAuthorization>,
) -> Option<DescribeResponse> {
    let input_schema = snapshot.input_schema().cloned()?;
    let facts = snapshot.facts();
    Some(DescribeResponse {
        contract_version: ContractVersion::V1,
        binding: ConnectorBinding {
            connector: server.to_owned(),
            operation: tool_name.to_owned(),
            name: format!("{server}.{tool_name}"),
        },
        identity: identity(snapshot),
        input_schema,
        output_schema: snapshot
            .described_output_schema()
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .map(|schema| {
                serde_json::Value::Object(waygate_mcp::retained_delivery::output_schema(schema))
            }),
        governance: Governance::from_admission(facts, authorization),
    })
}

fn connector_contract_for_tool(tool: &CatalogTool) -> Option<DescribeResponse> {
    match &tool.identity.source {
        CatalogToolSource::Upstream(server) => connector_contract_with_authorization(
            server,
            &tool.identity.name,
            tool.invocation_snapshot()?,
            Some(&tool.authorization),
        ),
        CatalogToolSource::Builtin(namespace) => Some(DescribeResponse {
            contract_version: ContractVersion::V1,
            binding: ConnectorBinding {
                connector: namespace.clone(),
                operation: tool.identity.name.clone(),
                name: tool.identity.qualified_name(),
            },
            identity: catalog_identity(tool)?,
            input_schema: Value::Object(tool.definition.input_schema.as_ref().clone()),
            output_schema: tool
                .definition
                .output_schema
                .as_ref()
                .map(|schema| Value::Object(schema.as_ref().clone())),
            governance: Governance::from_admission(&tool.facts, Some(&tool.authorization)),
        }),
    }
}

fn input_schema<T: JsonSchema>() -> Arc<JsonObject> {
    let mut schema =
        serde_json::to_value(schemars::schema_for!(T)).expect("input schema serializes");
    if std::any::type_name::<T>() == std::any::type_name::<ResumeParams>() {
        annotate_timeout(&mut schema);
    }
    schema_obj(schema)
}

fn source_input_schema<T: JsonSchema>() -> Arc<JsonObject> {
    schema_obj(generated_source_input_schema::<T>())
}

fn generated_source_input_schema<T: JsonSchema>() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(T))
        .expect("schemars source input schema serializes to JSON");
    annotate_source_file_properties(&mut schema);
    annotate_timeout(&mut schema);
    schema
}

fn annotate_timeout(schema: &mut Value) {
    let timeout = serde_json::to_value(schemars::schema_for!(ExecutionTimeout))
        .expect("timeout schema serializes");
    schema["properties"]["timeout_seconds"] = timeout["properties"]["timeout_seconds"].clone();
}

#[derive(Deserialize, JsonSchema)]
struct ExecutionTimeout {
    /// Optional shorter execution budget in seconds. Omit to use the operator default.
    #[schemars(range(min = 1, max = limits().execution_seconds))]
    timeout_seconds: Option<u64>,
}

fn annotate_source_file_properties(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if let Some(Value::Object(properties)) = object.get_mut("properties") {
                if let Some(source_file) = properties.get_mut("source_file") {
                    waygate_mcp::files::annotate_file_input(
                        source_file,
                        &waygate_mcp::files::FileInputDescriptor {
                            accept: None,
                            max_size: Some(limits().source_bytes as u64),
                            transfer_modes: Some(vec![
                                waygate_mcp::files::FileTransferMode::Upload,
                            ]),
                        },
                    )
                    .expect("source_file is a string schema");
                }
            }
            for value in object.values_mut() {
                annotate_source_file_properties(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                annotate_source_file_properties(value);
            }
        }
        _ => {}
    }
}

fn with_status_projection_guidance(description: &str) -> String {
    format!(
        "{description} The authoritative machine result is \
         `CallToolResult.structuredContent`; text `content` mirrors it only for MCP \
         compatibility. In a programmatic caller, keep intermediate status envelopes inside \
         the runtime, bound polling by a deadline or attempt limit, and expose only the \
         structured fields needed when `terminal` is true or `status` is `input_required`, \
         rather than serializing the whole `CallToolResult`."
    )
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct LimitsParams {}

#[derive(Serialize, JsonSchema)]
struct LimitsResponse {
    /// Effective process resource budgets; byte sizes refer to UTF-8 or serialized JSON.
    resources: crate::codemode_limits::CodeModeLimits,
    /// Maximum active runners in this gateway process.
    global_concurrency: usize,
    /// Maximum active runners for one tenant in this process.
    tenant_concurrency: usize,
    /// Maximum detached runners, sharing global and tenant permits.
    detached_concurrency: usize,
}

pub(crate) fn tool_defs() -> Vec<Tool> {
    vec![
        Tool::new(format!("{NAMESPACE}.limits"),
            "Read effective Code Mode source, payload, memory, storage, execution-time, file, and concurrency limits before planning a program. Values are operator configuration for this gateway process. The authoritative result is CallToolResult.structuredContent.",
            input_schema::<LimitsParams>())
            .with_title("Read Code Mode limits")
            .with_output_schema::<LimitsResponse>()
            .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.search"),
            "Search the governed direct catalog across upstream and gateway-local connectors. Returns only tools this \
             caller may discover after profile restrictions, quarantine state, and Cedar \
             decisions. Results carry immutable snapshot identity and governance facts; use \
             `codemode.describe` with a returned binding connector/operation pair for the exact \
             connector schemas.",
            input_schema::<SearchParams>(),
        )
        .with_title("Search Code Mode connectors")
        .with_output_schema::<SearchResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.describe"),
            "Describe one tool returned by `codemode.search` as a runtime-neutral, versioned \
             connector contract. Pass `connector` and `operation` from the returned `binding` for \
             an unambiguous lookup; `name` remains accepted only when it identifies one exact pair. \
             Returns exact admitted input/output schemas, raw connector binding names, governance \
             classification, and catalog or manifest snapshot identity. Denied, restricted, \
             quarantined, ambiguous, and unknown selectors share one unavailable error shape.",
            input_schema::<DescribeParams>(),
        )
        .with_title("Describe a Code Mode connector")
        .with_output_schema::<DescribeResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.execute"),
            "Requires `mcp:invoke`. Execute JavaScript in a fresh external runtime and return its \
             JSON-compatible result. Provide exactly one of inline `source`, an uploaded \
             `source_file`, a private retained `source_sha256`, or a `skill_script` \
             URI from the active verified Agent Skills catalog. Inline, uploaded, and skill source may \
             set `retain_for_seconds` for bounded hash reuse; the response always returns the \
             resolved digest and `retention_state` in `source_ref`, with the exact expiry when \
             retained. `unavailable` means retention state could not be checked and is distinct \
             from `not_retained`. Retention requires a configured database and \
             `GATEWAY_CODEMODE_RESULT_STORAGE=allow`. An \
             uploaded source is copied before execution, so later upload expiry cannot interrupt \
             admitted work. An unavailable retained hash returns `source_artifact_not_found` and \
             must be resubmitted inline or as a fresh upload. Pass arguments as `input` rather \
             than editing them into the program; the runtime exposes the submitted value as \
             `execution.input` as data it never evaluates. A program is identified by its exact \
             bytes, so an edited-in value makes a different program that cannot reuse a retained \
             source, while `input` leaves the digest and its retention untouched. The runtime installs only concrete synchronous \
             `connectors[server][operation]({...})` bindings generated from the caller's currently \
             admitted direct `codemode.describe` contracts; unavailable operations are absent. \
             The exact described contract is required again during each nested call's governed \
             tool resolution, so same-name catalog drift is refused before dispatch. Each nested \
             call re-enters the ordinary direct gateway invocation path under the same principal, \
             including its current authorization, approval, validation, quota, inspection, and \
             audit decisions. All source forms, including skill scripts, use this same \
             authority and have no Code Mode-only call-count or mutation admission gate. Denied, \
             quarantined, and credential-profile-restricted operations remain unavailable. The runtime exposes no filesystem, network, process, \
             environment, module-loader, or credential APIs. Execution fails closed unless the \
             child installs and reports the required Linux syscall-confinement profile. \
             Programs may call `execution.wait(milliseconds)` with a finite, non-negative \
             duration to pace polling without spinning; elapsed waiting spends the same operator \
             execution budget as computation, and exhausting it returns `execution_timeout`. With \
             durable result storage enabled, a program may call \
             `execution.emitArtifact(value)` to durably publish bounded intermediate JSON and \
             receive a stable reference before continuing. Programs may explicitly checkpoint using \
             `execution.pause(checkpoint)` and continue through `codemode.resume`. A lost worker \
             never causes automatic replay of a direct-authority execution. Clients may invoke this tool as an MCP Task to receive a durable task identifier \
             after bounded admission and its fenced claim, before runner work begins; they can \
             poll status, retrieve the completed result during the execution retention window, \
             or request cancellation. Task augmentation is advertised only \
             when the operator explicitly allows result storage. \
             Failures return stable machine-readable `data.error` codes that distinguish timeouts, program \
             errors, invalid or oversized results, runner termination, protocol violations, and \
             transport failures. Defined codes are `execution_failed`, `execution_timeout`, \
             `execution_setup_timeout`, \
             `execution_result_not_json`, `execution_result_too_large`, `execution_capacity`, \
             `tenant_execution_capacity`, `detached_execution_capacity`, \
             `execution_unavailable`, \
             `runner_failed`, `runner_crashed`, `runner_frame_too_large`, \
             `runner_frame_unterminated`, `runner_frame_malformed`, `runner_protocol_error`, and \
             `runner_transport_error`; pause can additionally return \
             `execution_pause_unavailable`, while artifact emission can return \
             `execution_artifact_unavailable`, `execution_artifact_too_large`, or \
             `execution_artifact_limit_exceeded`. Source resolution additionally uses \
             `invalid_source_selector`, \
             `invalid_source_digest`, `invalid_source_retention`, `invalid_source_file`, \
             `source_file_not_found`, `source_file_unavailable`, `source_not_utf8`, \
             `source_too_large`, `source_artifact_not_found`, `source_artifact_capacity`, \
             `source_artifact_unavailable`, and `source_locator_capacity`. Skill-script admission \
             additionally uses `skill_script_catalog_unavailable`, `skill_script_not_found`, \
             `skill_script_incompatible`, and `skill_script_catalog_changed`. Oversized `input` \
             returns `execution_input_too_large`. `repeat_after` is meaningful only on the \
             task-augmented shape, where starts are retried by converging on the retained \
             execution and a deliberate repetition names the latest terminal one; the blocking \
             shape refuses it with `execution_repeat_requires_detached_start`.",
            source_input_schema::<StartParams>(),
        )
        .with_title("Execute Code Mode JavaScript with direct authority")
        .with_output_schema::<ExecuteResponse>()
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.resume"),
            "Requires `mcp:invoke`. Resume one durable Code Mode execution that returned \
             `waiting_for_resume`. Pass the original `execution_id` and any JSON-compatible \
             `input` requested by its checkpoint. The gateway starts a fresh confined runner, \
             supplies the immutable checkpoint and bound input as `execution.resume`, and \
             rechecks the original source digest, execution profile, SDK/runner contracts, \
             current governed connector snapshot, authorization, and worker fence before any \
             new dispatch. The resumed program may complete or call `execution.pause(...)` \
             again. Invoke normally to wait for the next boundary, or use MCP task augmentation \
             to atomically claim the continuation before returning and then continue polling the \
             same execution id. Failures use \
             `execution_resume_unavailable`, `execution_resume_incompatible`, or \
             `execution_resume_input_too_large` with structured details.",
            input_schema::<ResumeParams>(),
        )
        .with_title("Resume a paused Code Mode execution")
        .with_output_schema::<ExecuteResponse>()
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.result"),
            "Requires `mcp:invoke`. Resolve the stable final-result reference returned by a \
             completed persisted `codemode.execute` or `codemode.resume` call. The lookup is \
             tenant-, principal-, and effective-profile scoped, re-enters current `codemode.execute` \
             governance, and remains available only through the execution retention window. \
             Returns the original bounded JSON-compatible program result. When already \
             following a task-augmented call, poll MCP `tasks/get` instead: a completed \
             task inlines the result.",
            input_schema::<ExecutionReferenceParams>(),
        )
        .with_title("Retrieve a persisted Code Mode result")
        .with_output_schema::<StoredResultResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.start"),
            with_status_projection_guidance(
                "Requires `mcp:invoke`. Start a program and return a handle immediately \
             instead of waiting for it. Use this when the client cannot hold a long tool call \
             open -- a subagent, a headless run, or any client without automatic backgrounding -- \
             and poll `codemode.status` with the returned identifier, retrieve the result with \
             `codemode.result` once status reports one is available, and stop it early with \
             `codemode.cancel`. The program is admitted, quota-checked and durably claimed before \
             this returns, so a returned handle means the work was accepted rather than merely \
             queued; exhausted capacity is refused here rather than discovered later. The \
             stable `detached_execution_capacity` refusal means this gateway process has no \
             detached runner slot available; poll or cancel active work before retrying. The \
             response is the same projection `codemode.status` returns, so the first poll and \
             every later one have one shape. The program runs under the same governed pipeline, \
             confinement, connector admission and operator execution budget as `codemode.execute` \
             and reaches the same terminal states: this changes who waits, not what is allowed. \
             Requires durable result storage and refuses without it, rather than running a \
             program whose result nothing could retrieve. Client-authored source can invoke the \
             same direct operations as blocking `codemode.execute`; skill scripts keep \
             the invoking caller's authority. Starting is safe to retry: while an identical \
             submission (same resolved source, profile, and principal) is retained, calling start again \
             returns that execution's handle instead of running the work twice, so a caller \
             that timed out or lost the response converges by retrying. To deliberately run \
             identical work again, pass `repeat_after` naming the latest retained terminal \
             execution; retrying a repetition whose response was lost converges on the newer \
             handle. `repeat_after` failures return `execution_repeat_unavailable` or \
             `execution_repeat_not_terminal`. Source may be inline, an uploaded `source_file`, \
             a live private `source_sha256`, or a `skill_script`; \
             `retain_for_seconds` on inline/uploaded/skill source keeps \
             it reusable for up to 24 hours, and the returned `source_ref` reports the digest and \
             explicit retention state, plus the exact expiry while live. A retention request \
             requires the deployment's durable-content posture; one over the intrinsic owner or \
             tenant budget returns `source_artifact_capacity`. An expired upload URI can recover \
             an already-started handle, but cannot extend retention or authorize deliberate new \
             work; upload retry bindings over their own intrinsic budget return \
             `source_locator_capacity`.",
            ),
            source_input_schema::<StartParams>(),
        )
        .with_title("Start a Code Mode execution without waiting")
        .with_output_schema::<ExecutionStatusResponse>()
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.start_resume"),
            with_status_projection_guidance(
                "Requires `mcp:invoke`. Answer the checkpoint of a paused execution and return its \
             handle immediately instead of waiting for what follows. This is the continuation \
             half of the detached surface: `codemode.status` reports the checkpoint while an \
             execution waits to be resumed, this supplies the input it asked for, and the \
             response is the same projection status returns, so a caller alternates between the \
             two for as many pauses as the program takes. Without it a detached caller would be \
             forced back into a long blocking `codemode.resume` at the first pause, which is the \
             situation this surface exists to remove. The execution is claimed before this \
             returns, so a resume that cannot be claimed is refused rather than acknowledged and \
             lost. A `detached_execution_capacity` refusal means this gateway process has no \
             detached runner slot available; poll or cancel active work before retrying. The \
             capacity check happens before the execution row is read or claimed. Omit the input \
             when retrying an attempt whose input is already durably bound. \
             The lookup is tenant-, principal- and effective-profile scoped, and this governs \
             under its own name rather than borrowing the authority of the call that started the \
             execution.",
            ),
            input_schema::<ResumeParams>(),
        )
        .with_title("Resume a paused Code Mode execution without waiting")
        .with_output_schema::<ExecutionStatusResponse>()
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.status"),
            with_status_projection_guidance(
                "Requires `mcp:invoke`. Report the lifecycle status of a persisted execution without \
             returning its result. This is the poll half of the submit/poll/cancel surface and is \
             the tool to call in a loop: the response is decision-shaped and does not grow with \
             the work the program did, so polling stays cheap. It reports the current status, \
             whether that status is terminal, whether a stored result is retrievable, whether \
             cancellation has been requested, and the retention deadline after which the \
             identifier resolves to nothing. It also reports the admitted source SHA-256 and the \
             retained-source state and expiry while that private artifact remains reusable. An \
             `unavailable` retention state tells the caller to retry rather than infer absence. \
             Retrieve the result itself with `codemode.result` \
             once this reports one is available, and artifacts with `codemode.artifacts`. The \
             lookup is tenant-, principal-, and effective-profile scoped; unknown, unowned, and \
             expired executions share one response so a handle is not usable by possession alone. \
             It reads the same execution journal as MCP `tasks/get`, so a polling caller and a \
             task-augmented client observe the same status for the same execution.",
            ),
            input_schema::<ExecutionReferenceParams>(),
        )
        .with_title("Poll a persisted Code Mode execution")
        .with_output_schema::<ExecutionStatusResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.executions"),
            "Requires `mcp:invoke`. List the caller's own in-flight persisted executions, newest \
             submission first, so detached work whose handle was lost can be found again instead \
             of running unreachable until expiry. Use it when a handle was garbled or lost with \
             the context that held it, or to check for an existing attempt before starting \
             another. Entries use the same status vocabulary `codemode.status` reports but never \
             carry a checkpoint, so a page stays bounded by its row count no matter what the \
             listed programs stored; a discovered identifier is immediately usable with \
             `codemode.status` (which reports a paused execution's checkpoint), \
             `codemode.result`, `codemode.artifacts`, and `codemode.cancel`. The listing is \
             tenant-, principal-, and effective-profile scoped and returns exactly the \
             executions those tools would serve: it reveals nothing about work belonging to any \
             other principal, and an empty page means nothing of the caller's is in flight, not \
             that a given identifier is invalid. Terminal executions are not listed; a known \
             handle's outcome stays retrievable through `codemode.status` and `codemode.result` \
             until retention expires. Pass `next_cursor` unchanged to continue a bounded page \
             walk.",
            input_schema::<ExecutionListParams>(),
        )
        .with_title("List the caller's in-flight Code Mode executions")
        .with_output_schema::<ExecutionListResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.cancel"),
            "Requires `mcp:invoke`. Request cancellation of a persisted execution and report its \
             resulting status. Requesting cancellation is not itself terminal: the execution \
             reaches `cancelled` once its runner observes the request, so this waits briefly for \
             that transition and then reports whatever status the execution actually holds rather \
             than asserting one. A caller that sees a non-terminal status should poll \
             `codemode.status` for the transition. Cancelling an already-terminal execution is \
             accepted and returns its existing status unchanged, so a retry after a lost response \
             is safe. The lookup is tenant-, principal-, and effective-profile scoped; unknown, \
             unowned, and expired executions share one response with the status tool.",
            input_schema::<ExecutionReferenceParams>(),
        )
        .with_title("Cancel a persisted Code Mode execution")
        .with_output_schema::<ExecutionStatusResponse>()
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.artifacts"),
            "Requires `mcp:invoke`. Page through stable references for bounded intermediate JSON artifacts \
             already emitted by one durable Code Mode execution. Listing works while the execution \
             is running, paused, failed, cancelled, or completed, subject to the same owner, \
             effective-profile, current-governance, and retention checks as result retrieval. \
             Artifact content is never materialized by this listing; pass one returned reference \
             to `codemode.artifact` and pass `next_cursor` unchanged to continue.",
            input_schema::<ArtifactListParams>(),
        )
        .with_title("List Code Mode execution artifacts")
        .with_output_schema::<ArtifactListResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.artifact"),
            "Requires `mcp:invoke`. Retrieve one bounded JSON artifact using the exact \
             `execution_id` and opaque `artifact_id` returned by `execution.emitArtifact(...)` \
             or `codemode.artifacts`. Cross-execution, cross-tenant, cross-principal, expired, and \
             effective-profile-conflicting references share one unavailable error shape.",
            input_schema::<ArtifactParams>(),
        )
        .with_title("Retrieve a Code Mode artifact")
        .with_output_schema::<ArtifactResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
    ]
}

pub(crate) fn surface_descriptor() -> BuiltinSurfaceDescriptor {
    surface_catalog().descriptor()
}

pub(crate) fn surface_catalog() -> BuiltinCatalog {
    let prefix = format!("{NAMESPACE}.");
    let tools = tool_defs()
        .into_iter()
        .map(|tool| {
            let name = tool
                .name
                .strip_prefix(&prefix)
                .unwrap_or(tool.name.as_ref())
                .to_owned();
            let effect_capable = matches!(name.as_str(), "execute" | "start");
            // Cancellation changes durable execution state and can stop work
            // already in flight, so it is not side-effect free. It is not an
            // approval-bound external effect either, so it does not carry the
            // mutation tools' risk: its blast radius is this gateway's own
            // execution, not an upstream system. Starting an execution
            // detached is the same class: it leaves durable work running after
            // the call returns, which the blocking tool never does.
            let state_changing =
                effect_capable || matches!(name.as_str(), "cancel" | "start_resume");
            let risk = if effect_capable {
                RiskTier::High
            } else if state_changing {
                RiskTier::Medium
            } else {
                RiskTier::Low
            };
            CatalogTool::builtin(NAMESPACE, tool, risk, state_changing, false)
        })
        .collect();
    BuiltinCatalog::new(
        NAMESPACE,
        Scope::McpInvoke.as_str(),
        "Code Mode connector discovery and JavaScript composition. Search and describe expose \
         the caller's directly governed contracts, and client-authored executions can invoke the \
         same operations through the ordinary direct governance path. Skill scripts \
         use the invoking caller's authority. Every connector call is gateway-dispatched from \
         a fresh external runtime that has no ambient authority and fails closed without attested \
         Linux syscall confinement.",
        tools,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::num::NonZeroU32;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use rmcp::model::CallToolRequestParams;
    use serde_json::{json, Map};
    use uuid::Uuid;
    use waygate_codemode::{
        Execution, ExecutionEvent, ExecutionStore, InFlightExecution, OwnedInFlight,
        RetainedSource, SourceArtifactStore,
    };
    use waygate_core::store::StoreError;
    use waygate_mcp::audit::NullSink;
    use waygate_mcp::authz::{AuthzGate, AuthzVerdict, ToolFacts};
    use waygate_mcp::catalog::{OperationClassification, ResolvedInvocationTool, UpstreamCatalog};
    use waygate_mcp::{DefaultInvocationService, GatewayServer, SharedCatalog};
    use waygate_oidc::{ApiKeyProfileRestrictions, AuthMethod};

    use crate::process_mode::codemode_protocol::MAX_FAILURE_MESSAGE_CHARS;
    use waygate_invocation::InvocationContractAuthority;

    use super::*;

    #[test]
    fn malformed_describe_arguments_are_invalid_not_unavailable() {
        let result: Result<CallToolResult, McpError> =
            Err(McpError::invalid_params("malformed arguments", None));

        assert_eq!(
            discovery_outcome(
                waygate_telemetry::metrics::DiscoveryOperation::CodeModeDescribe,
                &result,
            ),
            waygate_telemetry::metrics::DiscoveryOutcome::Invalid
        );
    }

    #[test]
    fn hidden_describe_target_is_unavailable_not_invalid() {
        let result: Result<CallToolResult, McpError> = Err(unknown_tool("hidden"));

        assert_eq!(
            discovery_outcome(
                waygate_telemetry::metrics::DiscoveryOperation::CodeModeDescribe,
                &result,
            ),
            waygate_telemetry::metrics::DiscoveryOutcome::Unavailable
        );
    }

    #[test]
    fn unrecognized_discovery_failure_is_error_not_invalid() {
        let result: Result<CallToolResult, McpError> = Err(McpError::internal_error(
            "catalog generation lookup failed",
            Some(json!({"error": "catalog_generation_unavailable"})),
        ));

        assert_eq!(
            discovery_outcome(
                waygate_telemetry::metrics::DiscoveryOperation::CodeModeDescribe,
                &result,
            ),
            waygate_telemetry::metrics::DiscoveryOutcome::Error
        );
    }

    struct StaticSkillSource(waygate_skills::SkillCatalogSnapshot);

    #[async_trait]
    impl waygate_skills::SkillCatalogSource for StaticSkillSource {
        async fn load(
            &self,
        ) -> Result<waygate_skills::SkillCatalogSnapshot, waygate_skills::SkillSourceError>
        {
            Ok(self.0.clone())
        }
    }

    struct CountingSkillLoader {
        resources: BTreeMap<String, Vec<u8>>,
        loads: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl waygate_skills::SkillResourceLoader for CountingSkillLoader {
        async fn load(
            &self,
            descriptor: &waygate_skills::SkillResourceDescriptor,
        ) -> Result<Vec<u8>, waygate_skills::SkillResourceLoadError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.resources.get(&descriptor.uri).cloned().ok_or_else(|| {
                waygate_skills::SkillResourceLoadError::Unavailable(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test resource missing",
                )))
            })
        }
    }

    fn sha256_prefixed(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        let mut encoded = String::from("sha256:");
        for byte in sha2::Sha256::digest(bytes) {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }

    async fn skill_script_catalog_with_load_count(
        script: &[u8],
        metadata: Option<&str>,
    ) -> (
        Arc<waygate_skills::ReloadableSkillCatalog>,
        Arc<AtomicUsize>,
    ) {
        let root_uri = "skill://homelab/pr-and-monitor/SKILL.md";
        let script_uri = "skill://homelab/pr-and-monitor/scripts/pr-wait.js";
        let metadata_yaml = metadata
            .map(|value| {
                format!(
                    "metadata:\n  io.cacahuate.mcp-gateway.code-mode: '{}'\n",
                    value.replace('\'', "''")
                )
            })
            .unwrap_or_default();
        let skill_md = format!(
            "---\nname: pr-and-monitor\ndescription: Ship and monitor a pull request\n{metadata_yaml}---\n# PR and monitor\n"
        );
        let mut frontmatter = serde_json::from_value::<Map<String, Value>>(serde_json::json!({
            "name": "pr-and-monitor",
            "description": "Ship and monitor a pull request"
        }))
        .expect("frontmatter object");
        if let Some(metadata) = metadata {
            frontmatter.insert(
                "metadata".into(),
                json!({(waygate_skills::CODE_MODE_METADATA_KEY): metadata}),
            );
        }
        let manifest = waygate_skills::CatalogManifest {
            schema_version: waygate_skills::CATALOG_SCHEMA_VERSION,
            skills: vec![waygate_skills::CatalogSkill {
                uri: root_uri.into(),
                frontmatter,
                resources: vec![
                    waygate_skills::SkillResourceDescriptor {
                        uri: root_uri.into(),
                        source_path: "pr-and-monitor/SKILL.md".into(),
                        source_object: sha256_prefixed(skill_md.as_bytes()),
                        size: skill_md.len() as u64,
                        media_type: "text/markdown".into(),
                    },
                    waygate_skills::SkillResourceDescriptor {
                        uri: script_uri.into(),
                        source_path: "pr-and-monitor/scripts/pr-wait.js".into(),
                        source_object: sha256_prefixed(script),
                        size: script.len() as u64,
                        media_type: "text/javascript".into(),
                    },
                ],
            }],
        };
        let loads = Arc::new(AtomicUsize::new(0));
        let snapshot = waygate_skills::verify_catalog_snapshot(
            waygate_skills::CatalogSourceIdentity {
                origin: "git+https://git.example/team/skills".into(),
                reference: "main".into(),
                resolved_digest: format!("git-sha1:{}", "a".repeat(40)),
                resolved_tree_digest: format!("git-sha1:{}", "b".repeat(40)),
            },
            manifest,
            BTreeMap::from([(root_uri.into(), skill_md.clone().into_bytes())]),
            Arc::new(CountingSkillLoader {
                resources: BTreeMap::from([
                    (root_uri.into(), skill_md.into_bytes()),
                    (script_uri.into(), script.to_vec()),
                ]),
                loads: loads.clone(),
            }),
        )
        .expect("valid skill catalog");
        let catalog = Arc::new(waygate_skills::ReloadableSkillCatalog::default());
        catalog
            .refresh(&StaticSkillSource(snapshot))
            .await
            .expect("publish skill snapshot");
        (catalog, loads)
    }

    #[tokio::test]
    async fn oversized_connector_value_reaches_javascript_as_a_stable_refusal() {
        let (mut parent_output, runner_input) = tokio::io::duplex(4096);
        let mut runner_input = BufReader::new(runner_input);
        let mut spool = tempfile::tempfile().expect("temporary result spool");
        let value = Value::String("x".repeat(limits().connector_response_bytes));

        let (written, line) = tokio::join!(
            write_connector_result(
                &mut parent_output,
                &mut spool,
                7,
                Ok(value),
                limits().connector_response_bytes
            ),
            async {
                let mut line = String::new();
                runner_input
                    .read_line(&mut line)
                    .await
                    .expect("read parent frame");
                line
            }
        );
        written.expect("write refusal frame");
        let frame: ParentFrame = serde_json::from_str(&line).expect("decode parent frame");

        assert!(matches!(
            frame,
            ParentFrame::CallResult {
                id: 7,
                result: Err(message),
            } if message.starts_with("connector_result_too_large:")
        ));
    }

    #[tokio::test]
    async fn inline_connector_result_obeys_a_smaller_materialization_limit() {
        for (length, accepted) in [(1022, true), (1023, false)] {
            let (mut output, input) = tokio::io::duplex(4096);
            let mut input = BufReader::new(input);
            let mut spool = tempfile::tempfile().expect("spool");
            let value = Value::String("x".repeat(length));
            write_connector_result(&mut output, &mut spool, 1, Ok(value.clone()), 1024)
                .await
                .expect("write bounded response");
            let mut line = String::new();
            input.read_line(&mut line).await.expect("read frame");
            let ParentFrame::CallResult { result, .. } =
                serde_json::from_str(&line).expect("frame")
            else {
                panic!("call result");
            };
            if accepted {
                assert!(
                    matches!(result, Ok(ConnectorCallResult::Inline { value: actual }) if actual == value)
                );
            } else {
                assert!(
                    matches!(result, Err(message) if message.starts_with("connector_result_too_large:"))
                );
            }
        }
    }

    #[test]
    fn retained_recovery_identity_survives_the_runner_error_boundary() {
        const URI: &str = "connector-response:/downloadLog/0";
        let error = waygate_invocation::InvocationError::Upstream(McpError::internal_error(
            format!(
                "retained connector response for operation `downloadLog` at `{URI}` could not be recovered"
            ),
            Some(json!({
                "error": "retained_response_recovery_failed",
                "operation_id": "downloadLog",
                "resource_uri": URI,
            })),
        ));

        let runner_error = connector_error(error.kind(), &error);
        assert!(runner_error.contains("downloadLog"));
        assert!(runner_error.contains(URI));
    }

    fn test_hierarchy(step: u32) -> InvocationHierarchy {
        InvocationHierarchy::new(
            Uuid::now_v7(),
            NonZeroU32::new(step).expect("test step is one-based"),
            Uuid::now_v7(),
            NonZeroU32::MIN,
        )
    }

    #[derive(Clone)]
    struct FakeCatalog {
        tools: Arc<BTreeMap<String, Vec<Tool>>>,
        snapshots: Arc<BTreeMap<(String, String), ResolvedInvocationTool>>,
        server_lists: Arc<AtomicUsize>,
        resolve_calls: Arc<AtomicUsize>,
        error_generation: Arc<AtomicU64>,
        retained_body: Option<Arc<str>>,
    }

    impl FakeCatalog {
        /// `(server, tool, side_effects)`; the catalog classification flags
        /// side-effecting tools as requiring approval, the common shape.
        fn with_tools(specs: &[(&str, &str, bool)]) -> Self {
            let classified: Vec<(&str, &str, bool, bool)> = specs
                .iter()
                .map(|(server, name, side_effects)| (*server, *name, *side_effects, *side_effects))
                .collect();
            Self::with_classified(&classified)
        }

        /// `(server, tool, side_effects, requires_approval)` — the explicit
        /// shape for policy-gated tools whose catalog flag is off.
        fn with_classified(specs: &[(&str, &str, bool, bool)]) -> Self {
            let mut tools: BTreeMap<String, Vec<Tool>> = BTreeMap::new();
            let mut snapshots = BTreeMap::new();
            for (server, name, side_effects, requires_approval) in specs {
                let input = json!({
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"}
                    },
                    "required": ["value"]
                });
                let output = json!({
                    "type": "object",
                    "properties": {
                        "result": {"type": "string"}
                    },
                    "required": ["result"]
                });
                let mut published = Tool::new(
                    (*name).to_owned(),
                    format!("{server} {name} operation"),
                    Arc::new(input.as_object().expect("input object").clone()),
                );
                published.output_schema =
                    Some(Arc::new(output.as_object().expect("output object").clone()));
                tools
                    .entry((*server).to_owned())
                    .or_default()
                    .push(published);
                snapshots.insert(
                    ((*server).to_owned(), (*name).to_owned()),
                    ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog(
                        ToolFacts {
                            server: (*server).to_owned(),
                            name: (*name).to_owned(),
                            risk: RiskTier::Low,
                            side_effects: *side_effects,
                            pii: false,
                            requires_approval: *requires_approval,
                            requires_approval_known: true,
                        },
                        Uuid::new_v4(),
                        format!("hash-{server}-{name}"),
                        Some(input),
                        Some(output),
                    )),
                );
            }
            Self {
                tools: Arc::new(tools),
                snapshots: Arc::new(snapshots),
                server_lists: Arc::new(AtomicUsize::new(0)),
                resolve_calls: Arc::new(AtomicUsize::new(0)),
                error_generation: Arc::new(AtomicU64::new(0)),
                retained_body: None,
            }
        }

        fn quarantine(&mut self, server: &str, tool: &str) {
            Arc::make_mut(&mut self.snapshots).insert(
                (server.to_owned(), tool.to_owned()),
                ResolvedInvocationTool::Quarantined {
                    server: server.to_owned(),
                    tool: tool.to_owned(),
                },
            );
        }

        fn unavailable(&mut self, server: &str, tool: &str) {
            Arc::make_mut(&mut self.snapshots).insert(
                (server.to_owned(), tool.to_owned()),
                ResolvedInvocationTool::Unavailable {
                    server: server.to_owned(),
                    tool: tool.to_owned(),
                },
            );
        }

        fn use_manifest_fallback(&mut self, server: &str, tool: &str) {
            let input_schema = self.tools[server]
                .iter()
                .find(|candidate| candidate.name == tool)
                .map(|candidate| Value::Object((*candidate.input_schema).clone()))
                .expect("published tool");
            Arc::make_mut(&mut self.snapshots).insert(
                (server.to_owned(), tool.to_owned()),
                ResolvedInvocationTool::Ready(
                    InvocationToolSnapshot::manifest_fallback_with_input_schema(
                        ToolFacts {
                            server: server.to_owned(),
                            name: tool.to_owned(),
                            risk: RiskTier::Low,
                            side_effects: false,
                            pii: false,
                            requires_approval: false,
                            requires_approval_known: false,
                        },
                        false,
                        Some(input_schema),
                    ),
                ),
            );
        }

        fn replace_input_schema(&mut self, server: &str, tool: &str, input_schema: Value) {
            let key = (server.to_owned(), tool.to_owned());
            let ResolvedInvocationTool::Ready(existing) = &self.snapshots[&key] else {
                panic!("test tool must be admitted");
            };
            let facts = existing.facts().clone();
            let output_schema = existing.output_schema().cloned();
            let input_object = input_schema
                .as_object()
                .cloned()
                .expect("test input schema must be an object");
            let published = Arc::make_mut(&mut self.tools)
                .get_mut(server)
                .and_then(|tools| tools.iter_mut().find(|candidate| candidate.name == tool))
                .expect("published test tool");
            published.input_schema = Arc::new(input_object);
            Arc::make_mut(&mut self.snapshots).insert(
                key,
                ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog(
                    facts,
                    Uuid::new_v4(),
                    format!("hash-{server}-{tool}-replacement"),
                    Some(input_schema),
                    output_schema,
                )),
            );
        }

        fn contract_identity(&self, server: &str, tool: &str) -> InvocationContractIdentity {
            match &self.snapshots[&(server.to_owned(), tool.to_owned())] {
                ResolvedInvocationTool::Ready(snapshot) => snapshot.contract_identity(),
                ResolvedInvocationTool::Quarantined { .. } => {
                    panic!("test contract must be admitted")
                }
                ResolvedInvocationTool::Unavailable { .. } => {
                    panic!("test catalog must be available")
                }
            }
        }

        /// Attach a reviewed per-operation definition to an already-admitted
        /// tool — the shape a dispatch-lane upstream publishes, where one
        /// argument selects which reviewed classification governs the call.
        ///
        /// Entries inherit the tool's risk and side-effect flags so they stay
        /// within the ceiling a real resolver enforces; `values` names the
        /// reviewed set the discriminator can select.
        fn refine_operations(
            &mut self,
            server: &str,
            tool: &str,
            discriminator: &str,
            values: &[&str],
        ) {
            let key = (server.to_owned(), tool.to_owned());
            let ResolvedInvocationTool::Ready(existing) = self.snapshots[&key].clone() else {
                panic!("a tool must be admitted before it is refined");
            };
            let ResolutionAuthority::Catalog {
                tool_id,
                schema_hash,
            } = existing.authority().clone()
            else {
                panic!("test refinement expects a catalog authority");
            };
            let facts = existing.facts().clone();
            let operations = values
                .iter()
                .map(|value| OperationClassification {
                    value: (*value).to_owned(),
                    risk: facts.risk,
                    side_effects: facts.side_effects,
                    pii: facts.pii,
                })
                .collect();
            let refined = InvocationToolSnapshot::catalog(
                facts,
                tool_id,
                schema_hash,
                existing.input_schema().cloned(),
                existing.output_schema().cloned(),
            )
            .with_operation_classifications(Some(discriminator.to_owned()), operations);
            Arc::make_mut(&mut self.snapshots).insert(key, ResolvedInvocationTool::Ready(refined));
        }

        fn server_list_count(&self) -> usize {
            self.server_lists.load(Ordering::SeqCst)
        }

        fn resolve_call_count(&self) -> usize {
            self.resolve_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl UpstreamCatalog for FakeCatalog {
        async fn list_servers(&self) -> Vec<String> {
            self.server_lists.fetch_add(1, Ordering::SeqCst);
            self.tools.keys().cloned().collect()
        }

        async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
            self.tools
                .get(server)
                .cloned()
                .ok_or_else(|| McpError::invalid_params("unknown upstream", None))
        }

        async fn call_tool(
            &self,
            server: &str,
            tool_name: &str,
            args: Option<Map<String, Value>>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            if let Some(body) = &self.retained_body {
                return Ok(CallToolResult::structured(json!({
                    "result":"retained", "success":true, "status":200,
                    "content_type":"text/plain", "headers":{}, "operation_id":tool_name,
                    "payload":{"bytes":body.len(), "media_type":"text/plain", "retained":true,
                        "inlined":false, "resource_uri":"test-response:/body",
                        "preview":"preview only", "context_ceiling_bytes":65536, "reason":"above inline ceiling"}
                })));
            }
            let value = args
                .as_ref()
                .and_then(|args| args.get("value"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            Ok(CallToolResult::structured(json!({
                "result": format!("{server}.{tool_name}:{value}")
            })))
        }

        async fn read_resource(
            &self,
            _server: &str,
            params: rmcp::model::ReadResourceRequestParams,
            _principal: Option<&Principal>,
        ) -> Result<rmcp::model::ReadResourceResult, McpError> {
            let body = self
                .retained_body
                .as_ref()
                .expect("retained response fixture");
            assert_eq!(params.uri, "test-response:/body");
            Ok(rmcp::model::ReadResourceResult::new(vec![
                rmcp::model::ResourceContents::text(body.to_string(), params.uri),
            ]))
        }

        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> ResolvedInvocationTool {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            let resolved = self
                .snapshots
                .get(&(server.to_owned(), tool_name.to_owned()))
                .cloned()
                .unwrap_or_else(|| ResolvedInvocationTool::Quarantined {
                    server: server.to_owned(),
                    tool: tool_name.to_owned(),
                });
            if matches!(&resolved, ResolvedInvocationTool::Unavailable { .. }) {
                self.error_generation.fetch_add(1, Ordering::AcqRel);
            }
            resolved
        }

        fn discovery_error_generation(&self) -> u64 {
            self.error_generation.load(Ordering::Acquire)
        }
    }

    struct SelectiveAuthz;

    struct SkillAccessGate {
        allow_fetch: bool,
        read: AuthzVerdict,
    }

    #[async_trait]
    impl AuthzGate for SkillAccessGate {
        async fn may_discover_server(&self, _: &Principal, _: &str) -> bool {
            true
        }

        async fn authorize_tool_call(&self, _: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow { policy_ids: vec![] }
        }

        async fn authorize_skill_fetch(
            &self,
            _: &Principal,
            facts: &waygate_mcp::authz::SkillAccessFacts,
        ) -> AuthzVerdict {
            assert!(facts.content_digest.is_none());
            if self.allow_fetch {
                AuthzVerdict::Allow {
                    policy_ids: vec!["skill-fetch".into()],
                }
            } else {
                AuthzVerdict::Deny {
                    reason: "skill fetch denied".into(),
                    policy_ids: vec!["skill-fetch".into()],
                    reasons: vec![],
                }
            }
        }

        async fn authorize_skill_read(
            &self,
            _: &Principal,
            facts: &waygate_mcp::authz::SkillAccessFacts,
        ) -> AuthzVerdict {
            assert!(facts
                .content_digest
                .as_ref()
                .unwrap()
                .starts_with("sha256:"));
            self.read.clone()
        }
    }

    #[async_trait]
    impl AuthzGate for SelectiveAuthz {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
            if facts.resource.tool == "hidden" {
                AuthzVerdict::Deny {
                    reason: "hidden by policy".to_owned(),
                    policy_ids: vec!["hide-tool".to_owned()],
                    reasons: vec![],
                }
            } else {
                AuthzVerdict::Allow { policy_ids: vec![] }
            }
        }
    }

    /// Gate that forbids `send` only on the Code Mode channel and reports
    /// `paused` as approval-gated — the fake analog of a
    /// `context.channel == "codemode"` availability forbid plus the shipped
    /// approval overlay.
    struct ChannelSelectiveAuthz;

    #[async_trait]
    impl AuthzGate for ChannelSelectiveAuthz {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
            let codemode = facts.context.channel == waygate_core::InvocationChannelFact::CodeMode;
            if !codemode && facts.resource.tool == "confined" {
                AuthzVerdict::Deny {
                    reason: "available only to confined Code Mode by policy".to_owned(),
                    policy_ids: vec!["codemode-only".to_owned()],
                    reasons: vec![],
                }
            } else if codemode && facts.resource.tool == "send" {
                AuthzVerdict::Deny {
                    reason: "unavailable to Code Mode by policy".to_owned(),
                    policy_ids: vec!["codemode-availability".to_owned()],
                    reasons: vec![],
                }
            } else if codemode && facts.resource.tool == "paused" {
                AuthzVerdict::ApprovalRequired {
                    reason: "approval-gated by policy".to_owned(),
                    policy_ids: vec!["codemode-mutation-approval".to_owned()],
                }
            } else if codemode && facts.resource.tool == "elevated" {
                AuthzVerdict::StepUpRequired {
                    reason: "step-up required by policy".to_owned(),
                    policy_ids: vec!["codemode-step-up".to_owned()],
                    required_scope: "mcp:elevated".to_owned(),
                }
            } else {
                AuthzVerdict::Allow { policy_ids: vec![] }
            }
        }
    }

    struct ToolErrorInvocation;

    #[async_trait]
    impl waygate_invocation::InvocationService for ToolErrorInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            _request: InvocationRequest,
        ) -> Result<InvocationResponse, waygate_invocation::InvocationError> {
            let mut result = CallToolResult::structured(json!({"reason": "upstream refused"}));
            result.is_error = Some(true);
            Ok(InvocationResponse::Unary(result))
        }
    }

    #[derive(Default)]
    struct RecordingInvocation {
        requests: tokio::sync::Mutex<Vec<InvocationRequest>>,
    }

    #[async_trait]
    impl waygate_invocation::InvocationService for RecordingInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse, waygate_invocation::InvocationError> {
            self.requests.lock().await.push(request);
            Ok(InvocationResponse::Unary(CallToolResult::structured(
                json!({"result": "ok"}),
            )))
        }
    }

    /// Invocation whose dispatch outlives the worker-claim lease, standing in
    /// for a slow but spec-permitted upstream mutation.
    struct SlowInvocation {
        delay: Duration,
        requests: tokio::sync::Mutex<Vec<InvocationRequest>>,
    }

    #[async_trait]
    impl waygate_invocation::InvocationService for SlowInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse, waygate_invocation::InvocationError> {
            self.requests.lock().await.push(request);
            tokio::time::sleep(self.delay).await;
            Ok(InvocationResponse::Unary(CallToolResult::structured(
                json!({"result": "ok"}),
            )))
        }
    }

    #[derive(Default)]
    struct ApprovalRequiredInvocation {
        requests: tokio::sync::Mutex<Vec<InvocationRequest>>,
    }

    #[async_trait]
    impl waygate_invocation::InvocationService for ApprovalRequiredInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse, waygate_invocation::InvocationError> {
            self.requests.lock().await.push(request);
            Err(waygate_invocation::InvocationError::ApprovalRequired {
                tool: "email.send".to_owned(),
                reason: "tool requires human approval; no matching grant".to_owned(),
                satisfiable: true,
            })
        }
    }

    type SourceLocatorKey = (String, String, String, String);
    type SourceLocatorValue = (String, time::OffsetDateTime);

    #[derive(Default)]
    struct RecordingExecutionStore {
        submitted: tokio::sync::Mutex<Option<NewExecution>>,
        current: tokio::sync::Mutex<Option<Execution>>,
        terminal_reason_codes: tokio::sync::Mutex<Vec<String>>,
        events: tokio::sync::Mutex<Vec<NewExecutionEvent>>,
        /// When set, the first successful `append_event` also marks the
        /// current execution cancellation-requested — simulating a
        /// `tasks/cancel` arriving between the fenced call-start append and
        /// the effect dispatch.
        cancel_on_first_append: std::sync::atomic::AtomicBool,
        /// Lease renewals observed while an effect dispatch was in flight.
        renewals: tokio::sync::Mutex<Vec<Duration>>,
        detached_slots: tokio::sync::Mutex<HashMap<(String, String, String), uuid::Uuid>>,
        /// Detached-slot lease renewals observed while runner work was held.
        slot_renewals: tokio::sync::Mutex<Vec<Duration>>,
        /// Executions created through `start_or_reuse`, oldest first, keyed
        /// by their dedupe key.
        started: tokio::sync::Mutex<Vec<(String, Execution)>>,
        /// One-shot test barrier taken by the next `start_or_reuse` call.
        start_or_reuse_barrier: Mutex<Option<Arc<AttemptBarrier>>>,
        /// Immutable uploaded-file locator bindings, scoped by full owner.
        source_locators: tokio::sync::Mutex<HashMap<SourceLocatorKey, SourceLocatorValue>>,
        /// Rows served to `list_owned_in_flight`, in any order; the fake
        /// applies the keyset bound and ordering itself.
        in_flight: tokio::sync::Mutex<Vec<Execution>>,
        /// Owner identities each listing call was scoped by, so a test can
        /// assert what the handler passed down.
        list_owners: tokio::sync::Mutex<Vec<OwnedInFlight>>,
    }

    impl RecordingExecutionStore {
        async fn bind_start_locator(
            &self,
            start: &StartExecution,
            expires_at: time::OffsetDateTime,
        ) -> Result<(), StoreError> {
            let Some(source_locator) = start.source_locator.as_deref() else {
                return Ok(());
            };
            self.bind_source_locator(
                &SourceArtifactOwner {
                    tenant_id: start.execution.tenant_id.clone(),
                    principal_sub: start.execution.principal_sub.clone(),
                    principal_issuer: start.execution.principal_issuer.clone(),
                },
                source_locator,
                &start.execution.source_digest,
                expires_at,
            )
            .await
        }
    }

    fn recorded_execution(
        execution: &NewExecution,
        status: ExecutionStatus,
        transition: Option<&ExecutionTransition>,
    ) -> Execution {
        let now = time::OffsetDateTime::now_utc();
        Execution {
            program_input: execution.program_input.clone(),
            id: execution.id,
            tenant_id: execution.tenant_id.clone(),
            principal_sub: execution.principal_sub.clone(),
            principal_issuer: Some(execution.principal_issuer.clone()),
            source: execution.source.clone(),
            source_digest: execution.source_digest.clone(),
            execution_profile: execution.execution_profile.clone(),
            tool_snapshot: None,
            sdk_contract_version: execution.sdk_contract_version,
            runner_contract_version: execution.runner_contract_version,
            status,
            terminal_reason_code: transition.and_then(|value| value.terminal_reason_code.clone()),
            result_metadata: transition.and_then(|value| value.result_metadata.clone()),
            result_payload: transition.and_then(|value| value.result_payload.clone()),
            resume_context: transition.and_then(|value| value.resume_context.clone()),
            claim_owner: None,
            claim_epoch: 0,
            claim_expires_at: None,
            cancellation_requested_at: None,
            cancellation_reason_code: None,
            submitted_at: now,
            updated_at: now,
            completed_at: status.is_terminal().then_some(now),
            retention_until: execution.retention_until,
        }
    }
    #[async_trait]
    impl ExecutionStore for RecordingExecutionStore {
        async fn list_owned_in_flight(
            &self,
            owner: &OwnedInFlight,
            before: Option<(time::OffsetDateTime, Uuid)>,
            limit: u16,
        ) -> Result<Vec<InFlightExecution>, StoreError> {
            self.list_owners.lock().await.push(owner.clone());
            let mut page: Vec<InFlightExecution> = self
                .in_flight
                .lock()
                .await
                .iter()
                .filter(|row| before.is_none_or(|bound| (row.submitted_at, row.id) < bound))
                .map(|row| InFlightExecution {
                    id: row.id,
                    status: row.status,
                    terminal_reason_code: row.terminal_reason_code.clone(),
                    result_available: row.result_payload.is_some(),
                    cancellation_requested: row.cancellation_requested_at.is_some(),
                    submitted_at: row.submitted_at,
                    updated_at: row.updated_at,
                    completed_at: row.completed_at,
                    retention_until: row.retention_until,
                })
                .collect();
            page.sort_by_key(|row| std::cmp::Reverse((row.submitted_at, row.id)));
            page.truncate(usize::from(limit));
            Ok(page)
        }

        async fn acquire_detached_slot(
            &self,
            slot: &DetachedExecutionSlot,
            _lease: Duration,
        ) -> Result<bool, StoreError> {
            let key = (
                slot.tenant_id.clone(),
                slot.principal_issuer.clone(),
                slot.principal_sub.clone(),
            );
            let mut slots = self.detached_slots.lock().await;
            if slots.get(&key).is_some_and(|holder| *holder != slot.holder) {
                return Ok(false);
            }
            slots.insert(key, slot.holder);
            Ok(true)
        }

        async fn release_detached_slot(
            &self,
            slot: &DetachedExecutionSlot,
        ) -> Result<bool, StoreError> {
            let key = (
                slot.tenant_id.clone(),
                slot.principal_issuer.clone(),
                slot.principal_sub.clone(),
            );
            let mut slots = self.detached_slots.lock().await;
            if !slots.get(&key).is_some_and(|holder| *holder == slot.holder) {
                return Ok(false);
            }
            slots.remove(&key);
            Ok(true)
        }

        async fn renew_detached_slot(
            &self,
            slot: &DetachedExecutionSlot,
            lease: Duration,
        ) -> Result<bool, StoreError> {
            let key = (
                slot.tenant_id.clone(),
                slot.principal_issuer.clone(),
                slot.principal_sub.clone(),
            );
            let slots = self.detached_slots.lock().await;
            if !slots.get(&key).is_some_and(|holder| *holder == slot.holder) {
                return Ok(false);
            }
            self.slot_renewals.lock().await.push(lease);
            Ok(true)
        }

        async fn start_or_reuse(
            &self,
            start: StartExecution,
        ) -> Result<StartExecutionResult, StoreError> {
            let barrier = self
                .start_or_reuse_barrier
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            if let Some(barrier) = barrier {
                barrier.entered.notify_one();
                barrier.release.notified().await;
            }
            let mut started = self.started.lock().await;
            let latest = started
                .iter()
                .rev()
                .find(|(key, execution)| {
                    *key == start.dedupe_key
                        && execution.source_digest == start.execution.source_digest
                        && execution.execution_profile == start.execution.execution_profile
                })
                .map(|(_, execution)| execution.clone());
            if let Some(latest) = latest {
                match start.repeat_after {
                    None => {
                        self.bind_start_locator(&start, latest.retention_until)
                            .await?;
                        return Ok(StartExecutionResult::Existing(latest));
                    }
                    Some(repeat_after) if latest.id == repeat_after => {
                        if !latest.status.is_terminal() {
                            return Ok(StartExecutionResult::RepeatNotTerminal(latest));
                        }
                    }
                    Some(repeat_after) => {
                        let known = started
                            .iter()
                            .any(|(key, e)| *key == start.dedupe_key && e.id == repeat_after);
                        if !known {
                            return Ok(StartExecutionResult::RepeatUnavailable);
                        }
                        self.bind_start_locator(&start, latest.retention_until)
                            .await?;
                        return Ok(StartExecutionResult::Existing(latest));
                    }
                }
            } else if start.repeat_after.is_some() {
                return Ok(StartExecutionResult::RepeatUnavailable);
            }
            let mut execution =
                recorded_execution(&start.execution, ExecutionStatus::Running, None);
            // `start_or_reuse` IS the durable submission and persists the
            // admission snapshot; the fake must show both or acknowledgment
            // tests would pass against a row production never writes.
            execution.tool_snapshot = Some(start.tool_snapshot.clone());
            execution.claim_owner = Some(start.owner);
            execution.claim_epoch = 1;
            *self.submitted.lock().await = Some(start.execution.clone());
            let claim = ExecutionClaim {
                execution_id: execution.id,
                tenant_id: execution.tenant_id.clone(),
                owner: start.owner,
                epoch: 1,
            };
            started.push((start.dedupe_key.clone(), execution.clone()));
            *self.current.lock().await = Some(execution.clone());
            self.bind_start_locator(&start, execution.retention_until)
                .await?;
            Ok(StartExecutionResult::Claimed { execution, claim })
        }

        async fn find_retry_equivalent(
            &self,
            probe: &RetryEquivalence,
            id: Option<Uuid>,
        ) -> Result<Option<Execution>, StoreError> {
            Ok(self
                .started
                .lock()
                .await
                .iter()
                .rev()
                .find(|(key, execution)| {
                    *key == probe.dedupe_key
                        && execution.source_digest == probe.source_digest
                        && execution.execution_profile == probe.execution_profile
                        && id.is_none_or(|id| execution.id == id)
                })
                .map(|(_, execution)| execution.clone()))
        }
        async fn resolve_source_locator(
            &self,
            owner: &SourceArtifactOwner,
            source_locator: &str,
        ) -> Result<Option<String>, StoreError> {
            Ok(self
                .source_locators
                .lock()
                .await
                .get(&(
                    owner.tenant_id.clone(),
                    owner.principal_issuer.clone(),
                    owner.principal_sub.clone(),
                    source_locator.to_owned(),
                ))
                .filter(|(_, expires_at)| *expires_at > time::OffsetDateTime::now_utc())
                .map(|(digest, _)| digest.clone()))
        }
        async fn bind_source_locator(
            &self,
            owner: &SourceArtifactOwner,
            source_locator: &str,
            source_digest: &str,
            expires_at: time::OffsetDateTime,
        ) -> Result<(), StoreError> {
            let key = (
                owner.tenant_id.clone(),
                owner.principal_issuer.clone(),
                owner.principal_sub.clone(),
                source_locator.to_owned(),
            );
            let mut locators = self.source_locators.lock().await;
            match locators.get_mut(&key) {
                Some((bound_digest, bound_expiry)) if bound_digest == source_digest => {
                    *bound_expiry = (*bound_expiry).max(expires_at);
                }
                Some(_) => return Err(StoreError::Conflict),
                None => {
                    locators.insert(key, (source_digest.to_owned(), expires_at));
                }
            }
            Ok(())
        }
        async fn submit(&self, execution: NewExecution) -> Result<Execution, StoreError> {
            let record = recorded_execution(&execution, ExecutionStatus::Submitted, None);
            *self.submitted.lock().await = Some(execution);
            *self.current.lock().await = Some(record.clone());
            Ok(record)
        }

        async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Execution>, StoreError> {
            let current = self
                .current
                .lock()
                .await
                .clone()
                .filter(|execution| execution.tenant_id == tenant_id && execution.id == id);
            if current.is_some() {
                return Ok(current);
            }
            Ok(self
                .started
                .lock()
                .await
                .iter()
                .find(|(_, execution)| execution.tenant_id == tenant_id && execution.id == id)
                .map(|(_, execution)| execution.clone()))
        }

        async fn claim(
            &self,
            tenant_id: &str,
            id: Uuid,
            owner: Uuid,
            _lease: Duration,
            source: String,
            tool_snapshot: Value,
        ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError> {
            let mut current = self.current.lock().await;
            let Some(execution) = current.as_mut().filter(|execution| {
                execution.tenant_id == tenant_id
                    && execution.id == id
                    && execution.status == ExecutionStatus::Submitted
            }) else {
                return Ok(None);
            };
            execution.status = ExecutionStatus::Running;
            execution.source = Some(source);
            execution.tool_snapshot = Some(tool_snapshot);
            execution.claim_owner = Some(owner);
            execution.claim_epoch += 1;
            let claim = ExecutionClaim {
                execution_id: id,
                tenant_id: tenant_id.to_owned(),
                owner,
                epoch: execution.claim_epoch,
            };
            Ok(Some((execution.clone(), claim)))
        }

        async fn resume(
            &self,
            resume: ResumeExecution,
        ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError> {
            let ResumeExecution {
                tenant_id,
                principal_sub,
                principal_issuer,
                id,
                owner,
                lease: _,
                expected_status,
                resume_context,
                expected_claim_epoch,
                expected_resume_context,
                expected_source_digest,
                expected_tool_snapshot,
                expected_sdk_contract_version,
                expected_runner_contract_version,
                next_sdk_contract_version,
                next_runner_contract_version,
            } = resume;
            let mut current = self.current.lock().await;
            let Some(execution) = current.as_mut().filter(|execution| {
                execution.tenant_id == tenant_id
                    && execution.principal_sub == principal_sub
                    && execution.principal_issuer.as_deref() == Some(principal_issuer.as_str())
                    && execution.id == id
                    && execution.status == expected_status
                    && execution.claim_epoch == expected_claim_epoch
                    && execution.resume_context == expected_resume_context
                    && execution.source_digest == expected_source_digest
                    && execution.tool_snapshot.as_ref() == Some(&expected_tool_snapshot)
                    && execution.sdk_contract_version == expected_sdk_contract_version
                    && execution.runner_contract_version == expected_runner_contract_version
            }) else {
                return Ok(None);
            };
            execution.status = ExecutionStatus::Running;
            execution.resume_context = Some(resume_context);
            execution.sdk_contract_version = next_sdk_contract_version;
            execution.runner_contract_version = next_runner_contract_version;
            execution.claim_owner = Some(owner);
            execution.claim_epoch += 1;
            let claim = ExecutionClaim {
                execution_id: id,
                tenant_id,
                owner,
                epoch: execution.claim_epoch,
            };
            Ok(Some((execution.clone(), claim)))
        }

        async fn renew(&self, claim: &ExecutionClaim, lease: Duration) -> Result<bool, StoreError> {
            // Mirror the Pg fence: a pending cancellation refuses renewal,
            // which is the broker's pre-dispatch cancellation check.
            if self
                .current
                .lock()
                .await
                .as_ref()
                .filter(|execution| execution.id == claim.execution_id)
                .is_some_and(|execution| execution.cancellation_requested_at.is_some())
            {
                return Ok(false);
            }
            self.renewals.lock().await.push(lease);
            Ok(true)
        }

        async fn renew_effect_lease(
            &self,
            _claim: &ExecutionClaim,
            lease: Duration,
        ) -> Result<bool, StoreError> {
            // Mirror the Pg semantics: the in-flight effect keeps its lease
            // even while a cancellation request is pending.
            self.renewals.lock().await.push(lease);
            Ok(true)
        }

        async fn append_event(
            &self,
            claim: &ExecutionClaim,
            event: NewExecutionEvent,
        ) -> Result<bool, StoreError> {
            // Mirror the Pg fence: a pending cancellation refuses ordinary
            // appends, which is the broker's pre-dispatch boundary.
            let mut current = self.current.lock().await;
            if current
                .as_ref()
                .filter(|execution| execution.id == claim.execution_id)
                .is_some_and(|execution| execution.cancellation_requested_at.is_some())
            {
                return Ok(false);
            }
            if self
                .cancel_on_first_append
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                if let Some(execution) = current.as_mut() {
                    execution.cancellation_requested_at = Some(time::OffsetDateTime::now_utc());
                }
            }
            drop(current);
            self.events.lock().await.push(event);
            Ok(true)
        }

        async fn append_effect_outcome(
            &self,
            _claim: &ExecutionClaim,
            event: NewExecutionEvent,
        ) -> Result<bool, StoreError> {
            self.events.lock().await.push(event);
            Ok(true)
        }

        async fn transition(
            &self,
            claim: &ExecutionClaim,
            transition: ExecutionTransition,
        ) -> Result<Option<Execution>, StoreError> {
            if !matches!(
                transition.to,
                ExecutionStatus::WaitingForResume
                    | ExecutionStatus::WaitingForApproval
                    | ExecutionStatus::Cancelled
            ) {
                return Ok(None);
            }
            let mut current = self.current.lock().await;
            let Some(execution) = current.as_mut().filter(|execution| {
                execution.tenant_id == claim.tenant_id
                    && execution.id == claim.execution_id
                    && execution.claim_owner == Some(claim.owner)
                    && execution.claim_epoch == claim.epoch
                    && execution.status == ExecutionStatus::Running
            }) else {
                return Ok(None);
            };
            execution.status = transition.to;
            execution.result_metadata = transition.result_metadata;
            execution.resume_context = transition.resume_context;
            execution.terminal_reason_code = transition.terminal_reason_code;
            if transition.to.is_terminal() {
                execution.completed_at = Some(time::OffsetDateTime::now_utc());
            }
            execution.claim_owner = None;
            Ok(Some(execution.clone()))
        }

        async fn fail_submission(
            &self,
            _tenant_id: &str,
            _id: Uuid,
            event: NewExecutionEvent,
            reason_code: String,
        ) -> Result<Option<Execution>, StoreError> {
            self.terminal_reason_codes.lock().await.push(reason_code);
            self.events.lock().await.push(event);
            let submitted = self.submitted.lock().await;
            Ok(submitted
                .as_ref()
                .map(|execution| recorded_execution(execution, ExecutionStatus::Failed, None)))
        }

        async fn request_cancellation(
            &self,
            tenant_id: &str,
            principal_sub: &str,
            principal_issuer: &str,
            id: Uuid,
        ) -> Result<Option<Execution>, StoreError> {
            let mut current = self.current.lock().await;
            let Some(execution) = current.as_mut().filter(|execution| {
                execution.tenant_id == tenant_id
                    && execution.principal_sub == principal_sub
                    && execution.principal_issuer.as_deref() == Some(principal_issuer)
                    && execution.id == id
            }) else {
                return Ok(None);
            };
            execution.status = ExecutionStatus::Cancelled;
            execution.cancellation_requested_at = Some(time::OffsetDateTime::now_utc());
            execution.completed_at = execution.cancellation_requested_at;
            Ok(Some(execution.clone()))
        }

        async fn reconcile_abandoned(
            &self,
            tenant_id: &str,
            principal_sub: &str,
            principal_issuer: &str,
            id: Uuid,
            _submission_grace: Duration,
        ) -> Result<Option<Execution>, StoreError> {
            let mut current = self.current.lock().await;
            let Some(execution) = current.as_mut().filter(|execution| {
                execution.tenant_id == tenant_id
                    && execution.principal_sub == principal_sub
                    && execution.principal_issuer.as_deref() == Some(principal_issuer)
                    && execution.id == id
            }) else {
                return Ok(None);
            };
            if execution.status == ExecutionStatus::WaitingForResume
                && execution.retention_until <= time::OffsetDateTime::now_utc()
            {
                execution.status = ExecutionStatus::Expired;
                execution.completed_at = Some(time::OffsetDateTime::now_utc());
            }
            Ok(Some(execution.clone()))
        }

        async fn events(
            &self,
            tenant_id: &str,
            id: Uuid,
        ) -> Result<Vec<ExecutionEvent>, StoreError> {
            let now = time::OffsetDateTime::now_utc();
            Ok(self
                .events
                .lock()
                .await
                .iter()
                .enumerate()
                .map(|(index, event)| ExecutionEvent {
                    id: i64::try_from(index + 1).expect("test event count fits i64"),
                    execution_id: id,
                    tenant_id: tenant_id.to_owned(),
                    kind: event.kind.as_str().to_owned(),
                    step_number: event.step_number,
                    call_id: event.call_id,
                    attempt: event.attempt,
                    detail: event.detail.clone(),
                    created_at: now,
                })
                .collect())
        }

        async fn list_artifacts(
            &self,
            _tenant_id: &str,
            id: Uuid,
            after_event_id: Option<i64>,
            limit: u16,
        ) -> Result<Vec<ExecutionArtifact>, StoreError> {
            let now = time::OffsetDateTime::now_utc();
            Ok(self
                .events
                .lock()
                .await
                .iter()
                .enumerate()
                .filter_map(|(index, event)| {
                    let event_id = i64::try_from(index + 1).expect("test event count fits i64");
                    if event.kind != ExecutionEventKind::ArtifactEmitted
                        || after_event_id.is_some_and(|cursor| event_id <= cursor)
                    {
                        return None;
                    }
                    let artifact_id = event
                        .detail
                        .get("artifact_id")
                        .and_then(Value::as_str)
                        .and_then(|value| Uuid::parse_str(value).ok())?;
                    Some(ExecutionArtifact {
                        event_id,
                        execution_id: id,
                        artifact_id,
                        created_at: now,
                    })
                })
                .take(usize::from(limit))
                .collect())
        }

        async fn get_artifact(
            &self,
            tenant_id: &str,
            id: Uuid,
            artifact_id: Uuid,
        ) -> Result<Option<ExecutionArtifactContent>, StoreError> {
            let artifact = self
                .list_artifacts(tenant_id, id, None, u16::MAX)
                .await?
                .into_iter()
                .find(|artifact| artifact.artifact_id == artifact_id);
            let Some(artifact) = artifact else {
                return Ok(None);
            };
            let value = self
                .events
                .lock()
                .await
                .get(usize::try_from(artifact.event_id - 1).expect("positive test event id"))
                .and_then(|event| event.detail.get("value"))
                .cloned()
                .expect("artifact test event carries content");
            Ok(Some(ExecutionArtifactContent { artifact, value }))
        }
    }

    struct BlockingInvocation {
        calls: AtomicUsize,
        entered: tokio::sync::Notify,
    }

    /// Denies every execution-quota check without asserting the caller's
    /// identity, for tests whose principals are tenant-isolated.
    struct ExhaustedQuota;

    #[async_trait]
    impl waygate_quota::QuotaService for ExhaustedQuota {
        async fn check_and_consume(
            &self,
            _ctx: &waygate_quota::QuotaContext,
            _actions: &[waygate_quota::QuotaAction],
        ) -> Result<(), waygate_quota::QuotaError> {
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id: Uuid::from_u128(2),
                name: "Code Mode execution budget".to_owned(),
                retry_after_seconds: 4,
            })
        }
    }

    struct DenyExecutionQuota(&'static str);

    #[async_trait]
    impl waygate_quota::QuotaService for DenyExecutionQuota {
        async fn check_and_consume(
            &self,
            ctx: &waygate_quota::QuotaContext,
            actions: &[waygate_quota::QuotaAction],
        ) -> Result<(), waygate_quota::QuotaError> {
            assert_eq!(ctx.tenant_id, waygate_core::TenantId::default().as_str());
            assert_eq!(ctx.principal_sub.as_deref(), Some("reader"));
            assert_eq!(ctx.server, NAMESPACE);
            assert_eq!(ctx.fq_tool, format!("codemode.{}", self.0));
            assert_eq!(actions, [waygate_quota::QuotaAction::Call]);
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id: Uuid::from_u128(1),
                name: "Code Mode execution budget".to_owned(),
                retry_after_seconds: 4,
            })
        }
    }

    #[async_trait]
    impl waygate_invocation::InvocationService for BlockingInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            _request: InvocationRequest,
        ) -> Result<InvocationResponse, waygate_invocation::InvocationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    fn reader() -> Principal {
        Principal {
            sub: "reader".to_owned(),
            email: None,
            groups: vec![],
            issuer: "test".to_owned(),
            scopes: vec![Scope::McpRead.as_str().to_owned()],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn start_source(source: &str) -> StartParams {
        StartParams {
            input: None,
            source: Some(source.to_owned()),
            source_file: None,
            source_sha256: None,
            skill_script: None,
            skill_revision: None,
            retain_for_seconds: None,
            repeat_after: None,
        }
    }

    fn resolved_inline_source(source: &str) -> ResolvedSource {
        ResolvedSource {
            source: source.to_owned(),
            digest: source_digest(source),
            retention: None,
            source_authority: None,
        }
    }

    fn repeat_source(source: &str, execution_id: Uuid) -> StartParams {
        StartParams {
            repeat_after: Some(execution_id.to_string()),
            ..start_source(source)
        }
    }

    #[derive(Default)]
    struct MemorySourceArtifactStore {
        artifacts: tokio::sync::Mutex<
            HashMap<(String, String, String, String), waygate_codemode::RetainedSource>,
        >,
        fail_expiry_reads: std::sync::atomic::AtomicBool,
    }

    struct MemorySourceFileReader {
        uri: String,
        source: tokio::sync::Mutex<Option<String>>,
    }

    #[async_trait]
    impl crate::file_transfer::StoredTextReader for MemorySourceFileReader {
        async fn read_text(
            &self,
            _principal: &Principal,
            uri: &str,
            max_bytes: usize,
        ) -> Result<crate::file_transfer::StoredTextFile, crate::file_transfer::StoredTextFileError>
        {
            if uri != self.uri {
                return Err(crate::file_transfer::StoredTextFileError::NotFound);
            }
            let source = self
                .source
                .lock()
                .await
                .clone()
                .ok_or(crate::file_transfer::StoredTextFileError::NotFound)?;
            if source.len() > max_bytes {
                return Err(crate::file_transfer::StoredTextFileError::TooLarge {
                    size: source.len() as u64,
                    max_bytes,
                });
            }
            Ok(crate::file_transfer::StoredTextFile {
                sha256: source_digest(&source),
                size: source.len() as u64,
                text: source,
            })
        }
    }

    #[async_trait]
    impl SourceArtifactStore for MemorySourceArtifactStore {
        async fn retain_source(
            &self,
            owner: &SourceArtifactOwner,
            source: &str,
            source_digest: &str,
            retention: Duration,
        ) -> Result<RetainedSource, StoreError> {
            let retained = RetainedSource {
                source: source.to_owned(),
                source_digest: source_digest.to_owned(),
                expires_at: time::OffsetDateTime::now_utc()
                    + time::Duration::try_from(retention).expect("test retention fits"),
            };
            self.artifacts.lock().await.insert(
                (
                    owner.tenant_id.clone(),
                    owner.principal_issuer.clone(),
                    owner.principal_sub.clone(),
                    source_digest.to_owned(),
                ),
                retained.clone(),
            );
            Ok(retained)
        }

        async fn resolve_source(
            &self,
            owner: &SourceArtifactOwner,
            source_digest: &str,
        ) -> Result<Option<RetainedSource>, StoreError> {
            Ok(self
                .artifacts
                .lock()
                .await
                .get(&(
                    owner.tenant_id.clone(),
                    owner.principal_issuer.clone(),
                    owner.principal_sub.clone(),
                    source_digest.to_owned(),
                ))
                .filter(|artifact| artifact.expires_at > time::OffsetDateTime::now_utc())
                .cloned())
        }

        async fn resolve_source_expiry(
            &self,
            owner: &SourceArtifactOwner,
            source_digest: &str,
        ) -> Result<Option<time::OffsetDateTime>, StoreError> {
            if self
                .fail_expiry_reads
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err(StoreError::NotFound);
            }
            Ok(self
                .artifacts
                .lock()
                .await
                .get(&(
                    owner.tenant_id.clone(),
                    owner.principal_issuer.clone(),
                    owner.principal_sub.clone(),
                    source_digest.to_owned(),
                ))
                .filter(|artifact| artifact.expires_at > time::OffsetDateTime::now_utc())
                .map(|artifact| artifact.expires_at))
        }
    }

    #[tokio::test]
    async fn inline_source_can_be_retained_and_reused_privately_by_hash() {
        let source_store = Arc::new(MemorySourceArtifactStore::default());
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_source_artifact_store(source_store.clone());
        let principal = reader();
        let source = "return rows.filter(row => row.enabled);";

        let mut retained = tools
            .resolve_source(
                &principal,
                SourceSelector::Inline(source.to_owned()),
                Some(3600),
            )
            .await
            .expect("retain inline source");
        assert_eq!(retained.source, source);
        assert_eq!(retained.digest, source_digest(source));
        assert!(retained.retention.is_some());
        tools
            .retain_resolved_source(&principal, &mut retained)
            .await
            .expect("retain resolved source");
        let reference = tools
            .live_source_reference(&principal, &retained.digest)
            .await;
        assert!(reference.expires_at.is_some());
        assert_eq!(reference.retention_state, SourceRetentionState::Live);
        source_store
            .fail_expiry_reads
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let unavailable = tools
            .live_source_reference(&principal, &retained.digest)
            .await;
        assert_eq!(
            unavailable.retention_state,
            SourceRetentionState::Unavailable
        );
        assert!(unavailable.expires_at.is_none());
        source_store
            .fail_expiry_reads
            .store(false, std::sync::atomic::Ordering::Relaxed);

        let reused = tools
            .resolve_source(
                &principal,
                SourceSelector::Retained(retained.digest.clone()),
                None,
            )
            .await
            .expect("reuse retained source");
        assert_eq!(reused.source, source);
        assert_eq!(reused.digest, retained.digest);

        let mut other_issuer = principal.clone();
        other_issuer.issuer = "https://other-issuer.test".to_owned();
        let error = tools
            .resolve_source(
                &other_issuer,
                SourceSelector::Retained(reused.digest.clone()),
                None,
            )
            .await
            .expect_err("another owner cannot resolve the hash");
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "source_artifact_not_found"
        );

        let key = (
            principal.tenant.as_str().to_owned(),
            principal.issuer.clone(),
            principal.sub.clone(),
            reused.digest.clone(),
        );
        source_store
            .artifacts
            .lock()
            .await
            .get_mut(&key)
            .expect("retained artifact")
            .expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let error = tools
            .resolve_source(&principal, SourceSelector::Retained(reused.digest), None)
            .await
            .expect_err("expired source is not reusable");
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "source_artifact_not_found"
        );
    }

    #[tokio::test]
    async fn uploaded_source_is_copied_before_its_file_lifecycle_ends() {
        let source_store = Arc::new(MemorySourceArtifactStore::default());
        let uri = "mcp-file://gateway/019c-source".to_owned();
        let source = format!(
            "/*{}*/return true;",
            "x".repeat(limits().source_bytes - "/* */return true;".len())
        );
        let file_reader = Arc::new(MemorySourceFileReader {
            uri: uri.clone(),
            source: tokio::sync::Mutex::new(Some(source.clone())),
        });
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_source_artifact_store(source_store)
        .with_source_file_reader(Some(file_reader.clone()));
        let principal = reader();

        let mut uploaded = tools
            .resolve_source(&principal, SourceSelector::File(uri), Some(3600))
            .await
            .expect("resolve uploaded source");
        tools
            .retain_resolved_source(&principal, &mut uploaded)
            .await
            .expect("retain uploaded source");
        *file_reader.source.lock().await = None;

        let reused = tools
            .resolve_source(
                &principal,
                SourceSelector::Retained(uploaded.digest.clone()),
                None,
            )
            .await
            .expect("reuse survives uploaded-file expiry");
        assert_eq!(reused.source, source);
        assert_eq!(reused.digest, uploaded.digest);
    }

    fn call(name: &str, arguments: Value) -> CallToolRequestParams {
        let mut request = CallToolRequestParams::new(name.to_owned());
        request.arguments = arguments.as_object().cloned();
        request
    }

    fn structured(result: &CallToolResult) -> &Value {
        result
            .structured_content
            .as_ref()
            .expect("Code Mode tools return structured content")
    }

    fn code_mode_tools(catalog: SharedCatalog, authz: SharedAuthz) -> CodeModeTools {
        let invocation = Arc::new(DefaultInvocationService::new(
            catalog.clone(),
            authz.clone(),
            Arc::new(NullSink),
        ));
        CodeModeTools::new(catalog, authz, invocation)
    }

    fn upstream_contract(identity: InvocationContractIdentity) -> ExecutionContract {
        ExecutionContract::Upstream { identity }
    }

    const TEST_BUILTIN_NAMESPACE: &str = "gateway-test";

    fn test_builtin_catalog() -> BuiltinCatalog {
        BuiltinCatalog::new(
            TEST_BUILTIN_NAMESPACE,
            Scope::McpInvoke.as_str(),
            "test built-in",
            vec![CatalogTool::builtin(
                TEST_BUILTIN_NAMESPACE,
                Tool::new(
                    format!("{TEST_BUILTIN_NAMESPACE}.write"),
                    "Record one test write",
                    schema_obj(json!({
                        "type": "object",
                        "properties": {"value": {"type": "string"}},
                        "required": ["value"],
                        "additionalProperties": false
                    })),
                ),
                RiskTier::High,
                true,
                false,
            )],
        )
    }

    #[derive(Default)]
    struct RecordingBuiltin {
        calls: AtomicUsize,
    }

    #[derive(Default)]
    struct RecordingEvidence {
        events: tokio::sync::Mutex<Vec<AuditEvent>>,
    }

    impl RecordingEvidence {
        async fn snapshot(&self) -> Vec<AuditEvent> {
            self.events.lock().await.clone()
        }
    }

    #[async_trait]
    impl waygate_mcp::EvidenceRecorder for RecordingEvidence {
        async fn record_required(
            &self,
            event: AuditEvent,
        ) -> Result<Uuid, waygate_mcp::EvidenceError> {
            let id = event.id;
            self.events.lock().await.push(event);
            Ok(id)
        }

        async fn record_chained_best_effort(&self, event: AuditEvent) {
            self.events.lock().await.push(event);
        }

        async fn record_best_effort(&self, event: AuditEvent) {
            self.events.lock().await.push(event);
        }
    }

    #[async_trait]
    impl BuiltinTools for RecordingBuiltin {
        fn namespace(&self) -> &str {
            TEST_BUILTIN_NAMESPACE
        }

        fn catalog(&self) -> BuiltinCatalog {
            test_builtin_catalog()
        }

        async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
            principal
                .is_some_and(may_invoke)
                .then(test_builtin_catalog)
                .map(|catalog| catalog.definitions())
                .unwrap_or_default()
        }

        async fn call(
            &self,
            tool: &str,
            arguments: Option<JsonObject>,
            principal: Option<&Principal>,
        ) -> Result<CallToolResult, McpError> {
            if tool != "write" || !principal.is_some_and(may_invoke) {
                return Err(McpError::invalid_params("unknown test tool", None));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(CallToolResult::structured(Value::Object(
                arguments.unwrap_or_default(),
            )))
        }
    }

    #[tokio::test]
    async fn search_and_describe_return_the_same_admitted_snapshot() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[
            ("email", "read", false),
            ("email", "send", true),
        ]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let server = GatewayServer::with_authz(catalog.clone(), authz.clone())
            .with_builtin_tools(Arc::new(code_mode_tools(catalog, authz)));
        let principal = reader();

        let search = server
            .dispatch_tool_call(
                call("codemode.search", json!({"query": "email.send"})),
                Some(&principal),
            )
            .await
            .expect("search succeeds");
        assert_eq!(structured(&search)["contract_version"], "1");
        assert_eq!(structured(&search)["tools"].as_array().unwrap().len(), 1);
        let found = &structured(&search)["tools"][0];
        assert_eq!(found["name"], "email.send");
        assert_eq!(found["identity"]["authority"], "catalog");
        assert_eq!(found["identity"]["catalog_schema_hash"], "hash-email-send");
        assert!(found["identity"]["input_schema_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()));
        assert!(found["identity"]["output_schema_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()));
        assert_eq!(found["governance"]["side_effects"], true);
        assert_eq!(found["governance"]["requires_approval"], true);

        let describe = server
            .dispatch_tool_call(
                call("codemode.describe", json!({"name": "email.send"})),
                Some(&principal),
            )
            .await
            .expect("describe succeeds");
        let described = structured(&describe);
        assert_eq!(described["identity"], found["identity"]);
        assert_eq!(described["binding"]["connector"], "email");
        assert_eq!(described["binding"]["operation"], "send");
        assert_eq!(described["input_schema"]["required"][0], "value");
        assert_eq!(
            described["output_schema"]["anyOf"][0]["required"][0],
            "result"
        );
    }

    #[tokio::test]
    async fn search_and_describe_project_live_direct_authorization() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_classified(&[
            ("email", "paused", true, false),
            ("email", "elevated", false, false),
        ]));
        let authz: SharedAuthz = Arc::new(ChannelSelectiveAuthz);
        let server = GatewayServer::with_authz(catalog.clone(), authz.clone())
            .with_builtin_tools(Arc::new(code_mode_tools(catalog, authz)));
        let principal = reader();

        let search = server
            .dispatch_tool_call(
                call("codemode.search", json!({"query": "email.paused"})),
                Some(&principal),
            )
            .await
            .expect("directly authorized tool remains discoverable");
        let governance = &structured(&search)["tools"][0]["governance"];
        assert_eq!(governance["requires_approval"], false);
        assert_eq!(governance["requires_approval_known"], true);

        let describe = server
            .dispatch_tool_call(
                call("codemode.describe", json!({"name": "email.elevated"})),
                Some(&principal),
            )
            .await
            .expect("directly authorized tool remains describable");
        assert!(structured(&describe)["governance"]
            .get("required_step_up_scope")
            .is_none());
    }

    #[tokio::test]
    async fn search_carries_one_admitted_snapshot_through_ranking_and_projection() {
        let catalog = Arc::new(FakeCatalog::with_tools(&[("email", "read", false)]));
        let tools = code_mode_tools(catalog.clone(), Arc::new(SelectiveAuthz));

        let result = tools
            .search(
                &reader(),
                SearchParams {
                    query: Some("email read".to_owned()),
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .expect("search succeeds");

        assert_eq!(catalog.resolve_call_count(), 1);
        let found = &structured(&result)["tools"][0];
        assert_eq!(found["description"], "email read operation");
        assert_eq!(found["identity"]["catalog_schema_hash"], "hash-email-read");
    }

    #[tokio::test]
    async fn all_execution_profiles_use_the_callers_direct_catalog() {
        let catalog: SharedCatalog =
            Arc::new(FakeCatalog::with_tools(&[("email", "confined", false)]));
        let tools = code_mode_tools(catalog, Arc::new(ChannelSelectiveAuthz));
        let principal = reader();

        let direct = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("direct catalog");
        assert!(direct.is_empty());

        for profile in [
            CodeExecutionProfile::Direct,
            CodeExecutionProfile::LegacyApprovalBound,
        ] {
            let confined = tools
                .execution_bindings(&principal, profile)
                .await
                .expect("confined Code Mode catalog");
            assert!(confined.is_empty());
        }
    }

    #[tokio::test]
    async fn direct_catalog_and_dispatch_include_builtins_but_exclude_codemode_recursion() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let registry = BuiltinRegistry::default();
        let builtin = Arc::new(RecordingBuiltin::default());
        let builtin_handle: SharedBuiltinTools = builtin.clone();
        let audit = Arc::new(RecordingEvidence::default());
        let tools = code_mode_tools(catalog, authz)
            .with_builtin_registry(registry.clone())
            .with_builtin_handlers(vec![builtin_handle.clone()])
            .with_audit(audit.clone());
        let codemode_handle: SharedBuiltinTools = Arc::new(tools.clone());
        registry.replace(&[builtin_handle, codemode_handle]);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        let search = tools
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .expect("direct built-in is discoverable");
        let names = structured(&search)["tools"]
            .as_array()
            .expect("search tools")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["gateway-test.write"]);

        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("direct bindings");
        let (admitted, runner, _) = admit_execution_bindings(bindings);
        let call = admitted
            .get(&runner[0].call_id)
            .expect("built-in capability binding");
        let hierarchy = test_hierarchy(1);
        let result = tools
            .invoke_connector(
                &principal,
                call,
                json!({"value": "written"}),
                hierarchy,
                CodeExecutionProfile::Direct,
                None,
            )
            .await
            .expect("built-in dispatch succeeds");
        assert_eq!(result, json!({"value": "written"}));
        assert_eq!(builtin.calls.load(Ordering::SeqCst), 1);
        let events = audit.snapshot().await;
        let completion = events
            .iter()
            .find(|event| {
                event.action == "CallTool"
                    && event.outcome == AuditOutcome::Success
                    && event.server.as_deref() == Some(TEST_BUILTIN_NAMESPACE)
                    && event.tool.as_deref() == Some("write")
            })
            .expect("successful nested built-in completion is audited");
        assert_eq!(completion.invocation_hierarchy, Some(hierarchy));
    }

    #[tokio::test]
    async fn catalog_read_error_refuses_every_codemode_catalog_consumer() {
        let mut fake =
            FakeCatalog::with_tools(&[("email", "broken", false), ("email", "healthy", false)]);
        fake.unavailable("email", "broken");
        let tools = code_mode_tools(Arc::new(fake), Arc::new(SelectiveAuthz));
        let principal = reader();

        let search_error = tools
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .expect_err("search must not return a partial catalog");
        assert_eq!(
            search_error.data.as_ref().expect("structured error")["error"],
            "catalog_changing"
        );

        let describe_error = tools
            .describe(
                &principal,
                DescribeParams {
                    name: None,
                    connector: Some("email".to_owned()),
                    operation: Some("healthy".to_owned()),
                },
            )
            .await
            .expect_err("describe must not trust a partial traversal");
        assert_eq!(
            describe_error.data.as_ref().expect("structured error")["error"],
            "catalog_changing"
        );

        let binding_error = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect_err("execution must not receive a partial connector set");
        assert_eq!(
            binding_error.data.as_ref().expect("structured error")["error"],
            "catalog_changing"
        );
    }

    #[tokio::test]
    async fn conditional_schema_remains_discoverable_and_enforced_through_codemode() {
        let mut fake = FakeCatalog::with_tools(&[("fixture", "conditional", false)]);
        let schema = serde_json::from_str::<Value>(include_str!(
            "../../waygate-mcp/tests/fixtures/client-schema-tools.json"
        ))
        .unwrap()[2]["inputSchema"]
            .clone();
        fake.replace_input_schema("fixture", "conditional", schema.clone());
        let tools = code_mode_tools(Arc::new(fake), Arc::new(SelectiveAuthz));
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let described = tools
            .describe(
                &principal,
                DescribeParams {
                    name: Some("fixture.conditional".to_owned()),
                    connector: None,
                    operation: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(structured(&described)["input_schema"], schema);
        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .unwrap();
        let (admitted, runner, _) = admit_execution_bindings(bindings);
        let call = admitted.get(&runner[0].call_id).unwrap();
        for (args, valid) in [
            (json!({"mode":"large","size":1500000000}), true),
            (json!({"mode":"small","size":1000000}), true),
            (json!({"mode":"small","size":1500000000}), false),
        ] {
            let result = tools
                .invoke_connector(
                    &principal,
                    call,
                    args,
                    test_hierarchy(1),
                    CodeExecutionProfile::Direct,
                    None,
                )
                .await;
            if valid {
                assert!(result.is_ok(), "{result:?}");
            } else {
                assert!(matches!(
                    result,
                    Err(waygate_invocation::InvocationError::InputSchemaViolation { .. })
                ));
            }
        }
    }

    #[tokio::test]
    async fn malformed_input_schema_is_absent_from_all_codemode_discovery() {
        let mut fake =
            FakeCatalog::with_tools(&[("email", "read", false), ("email", "malformed", false)]);
        fake.replace_input_schema(
            "email",
            "malformed",
            json!({"anyOf": [{"type": "object", "required": ["value"]}]}),
        );
        let tools = code_mode_tools(Arc::new(fake), Arc::new(SelectiveAuthz));
        let principal = reader();

        let search = tools
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .expect("search succeeds for healthy siblings");
        let names: Vec<&str> = structured(&search)["tools"]
            .as_array()
            .expect("search tools")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(names, ["email.read"]);

        tools
            .describe(
                &principal,
                DescribeParams {
                    name: Some("email.malformed".to_owned()),
                    connector: None,
                    operation: None,
                },
            )
            .await
            .expect_err("malformed connector must not be describable");

        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].tool, "read");
    }

    #[tokio::test]
    async fn execution_bindings_share_describe_contracts_without_a_read_only_ceiling() {
        let mut fake = FakeCatalog::with_tools(&[
            ("email", "read", false),
            ("email", "send", true),
            ("email", "hidden", false),
            ("email", "approval-unknown", false),
        ]);
        fake.use_manifest_fallback("email", "approval-unknown");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();

        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        assert_eq!(
            bindings
                .iter()
                .map(|binding| {
                    format!("{}.{}", binding.runner.connector, binding.runner.operation)
                })
                .collect::<Vec<_>>(),
            vec!["email.approval-unknown", "email.read", "email.send"]
        );
        let bindings: Vec<_> = bindings
            .into_iter()
            .filter(|binding| binding.tool == "read")
            .collect();

        let described = tools
            .describe(
                &principal,
                DescribeParams {
                    name: Some("email.read".to_owned()),
                    connector: None,
                    operation: None,
                },
            )
            .await
            .expect("read connector is describable");
        assert_eq!(
            structured(&described)["binding"]["connector"].as_str(),
            Some(bindings[0].runner.connector.as_str())
        );
        assert_eq!(
            structured(&described)["binding"]["operation"].as_str(),
            Some(bindings[0].runner.operation.as_str())
        );
        let expected = bindings[0]
            .contract
            .upstream_identity()
            .expect("upstream contract");
        assert_eq!(
            expected.input_schema_hash.as_deref(),
            structured(&described)["identity"]["input_schema_hash"].as_str()
        );
        assert_eq!(
            expected.output_schema_hash.as_deref(),
            structured(&described)["identity"]["output_schema_hash"].as_str()
        );
    }

    #[tokio::test]
    async fn direct_bindings_include_every_directly_authorized_operation() {
        let mut fake = FakeCatalog::with_tools(&[
            ("email", "read", false),
            ("email", "send", true),
            ("email", "hidden", true),
            ("email", "manifest-effect", true),
        ]);
        fake.use_manifest_fallback("email", "manifest-effect");
        let tools = code_mode_tools(Arc::new(fake), Arc::new(SelectiveAuthz));

        let bindings = tools
            .execution_bindings(&reader(), CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        assert_eq!(
            bindings
                .iter()
                .map(|binding| format!("{}.{}", binding.server, binding.tool))
                .collect::<Vec<_>>(),
            ["email.manifest-effect", "email.read", "email.send"]
        );
        let mutation = bindings
            .iter()
            .find(|binding| binding.tool == "send")
            .expect("approval-required mutation binding");
        let identity = mutation
            .contract
            .upstream_identity()
            .expect("upstream contract");
        assert!(mutation.contract.side_effects());
        assert!(identity.requires_approval);
        assert!(matches!(
            identity.authority,
            InvocationContractAuthority::Catalog { .. }
        ));
    }

    #[tokio::test]
    async fn codemode_only_policy_does_not_neuter_direct_bindings() {
        let fake = FakeCatalog::with_classified(&[
            ("email", "read", false, false),
            ("email", "send", true, false),
            ("email", "paused", true, false),
        ]);
        let authz: SharedAuthz = Arc::new(ChannelSelectiveAuthz);
        // The same gate allows a DIRECT call to the tool it hides from
        // Code Mode — availability diverges purely on the channel fact.
        let direct = authz
            .may_call_tool(
                &reader(),
                &waygate_mcp::authz::ToolFacts {
                    server: "email".to_owned(),
                    name: "send".to_owned(),
                    risk: waygate_mcp::protocol::RiskTier::Low,
                    side_effects: true,
                    pii: false,
                    requires_approval: false,
                    requires_approval_known: true,
                },
            )
            .await;
        assert!(direct.is_allow());

        let tools = code_mode_tools(Arc::new(fake), authz);
        let bindings = tools
            .execution_bindings(&reader(), CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        let mut admitted = bindings
            .iter()
            .map(|binding| format!("{}.{}", binding.server, binding.tool))
            .collect::<Vec<_>>();
        admitted.sort();
        assert_eq!(
            admitted,
            ["email.paused", "email.read", "email.send"],
            "Code Mode receives the same directly authorized catalog as its client",
        );
    }

    #[tokio::test]
    async fn direct_bindings_do_not_require_a_catalog_approval_flag() {
        let fake = FakeCatalog::with_classified(&[
            ("email", "read", false, false),
            ("email", "flagged", true, true),
            ("email", "unflagged", true, false),
        ]);
        let tools = code_mode_tools(Arc::new(fake), Arc::new(SelectiveAuthz));
        let bindings = tools
            .execution_bindings(&reader(), CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        let mut admitted = bindings
            .iter()
            .map(|binding| format!("{}.{}", binding.server, binding.tool))
            .collect::<Vec<_>>();
        admitted.sort();
        assert_eq!(
            admitted,
            ["email.flagged", "email.read", "email.unflagged"],
            "direct authorization, not a Code Mode admission flag, decides availability",
        );
    }

    #[tokio::test]
    async fn dotted_connector_names_remain_unambiguous_end_to_end() {
        let fake = FakeCatalog::with_tools(&[("llm.foo", "bar", false), ("llm", "foo.bar", false)]);
        let dotted_server_contract = fake.contract_identity("llm.foo", "bar");
        let dotted_tool_contract = fake.contract_identity("llm", "foo.bar");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();

        let search = tools
            .search(
                &principal,
                SearchParams {
                    query: Some("llm.foo.bar".to_owned()),
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .expect("search returns both structured bindings");
        let mut discovered_pairs = structured(&search)["tools"]
            .as_array()
            .expect("search tools")
            .iter()
            .map(|tool| {
                (
                    tool["binding"]["connector"]
                        .as_str()
                        .expect("connector")
                        .to_owned(),
                    tool["binding"]["operation"]
                        .as_str()
                        .expect("operation")
                        .to_owned(),
                )
            })
            .collect::<Vec<_>>();
        discovered_pairs.sort();
        assert_eq!(
            discovered_pairs,
            vec![
                ("llm".to_owned(), "foo.bar".to_owned()),
                ("llm.foo".to_owned(), "bar".to_owned())
            ]
        );

        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        assert_eq!(bindings.len(), 2);
        assert_ne!(bindings[0].runner.call_id, bindings[1].runner.call_id);
        assert!(bindings.iter().any(|binding| {
            binding.runner.connector == "llm.foo" && binding.runner.operation == "bar"
        }));
        assert!(bindings.iter().any(|binding| {
            binding.runner.connector == "llm" && binding.runner.operation == "foo.bar"
        }));

        let described = tools
            .describe(
                &principal,
                DescribeParams {
                    name: None,
                    connector: Some("llm.foo".to_owned()),
                    operation: Some("bar".to_owned()),
                },
            )
            .await
            .expect("structured selector describes dotted connector");
        assert_eq!(structured(&described)["binding"]["connector"], "llm.foo");
        assert_eq!(structured(&described)["binding"]["operation"], "bar");

        let ambiguous = tools
            .describe(
                &principal,
                DescribeParams {
                    name: Some("llm.foo.bar".to_owned()),
                    connector: None,
                    operation: None,
                },
            )
            .await
            .expect_err("flattened collision must not pick one contract");
        assert!(ambiguous.message.contains("ambiguous"));

        tools
            .invoke_direct(
                &principal,
                "llm.foo",
                "bar",
                json!({"value": "one"}),
                dotted_server_contract,
                test_hierarchy(1),
            )
            .await
            .expect("dotted connector dispatches exact operation");
        tools
            .invoke_direct(
                &principal,
                "llm",
                "foo.bar",
                json!({"value": "two"}),
                dotted_tool_contract,
                test_hierarchy(2),
            )
            .await
            .expect("dotted operation dispatches exact connector");
    }

    #[tokio::test]
    async fn raw_selector_admission_is_identical_for_search_describe_and_execution() {
        let oversized_server = "x".repeat((MAX_SELECTOR_LENGTH / 2) + 1);
        let oversized_tool = "y".repeat(MAX_SELECTOR_LENGTH / 2);
        let fake = FakeCatalog::with_tools(&[
            (" mail ", " read ", false),
            (&oversized_server, &oversized_tool, false),
        ]);
        let padded_contract = fake.contract_identity(" mail ", " read ");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();

        let search = tools
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .expect("raw admitted selector is discoverable");
        let discovered = structured(&search)["tools"]
            .as_array()
            .expect("search tools");
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0]["binding"]["connector"], " mail ");
        assert_eq!(discovered[0]["binding"]["operation"], " read ");

        let described = tools
            .describe(
                &principal,
                DescribeParams {
                    name: None,
                    connector: Some(" mail ".to_owned()),
                    operation: Some(" read ".to_owned()),
                },
            )
            .await
            .expect("structured describe preserves raw identifiers");
        assert_eq!(structured(&described)["binding"]["connector"], " mail ");
        assert_eq!(structured(&described)["binding"]["operation"], " read ");

        tools
            .describe(
                &principal,
                DescribeParams {
                    name: None,
                    connector: Some("mail".to_owned()),
                    operation: Some("read".to_owned()),
                },
            )
            .await
            .expect_err("describe must not normalize raw identifiers");
        tools
            .describe(
                &principal,
                DescribeParams {
                    name: None,
                    connector: Some(oversized_server),
                    operation: Some(oversized_tool),
                },
            )
            .await
            .expect_err("describe shares the selector admission bound");

        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].runner.connector, " mail ");
        assert_eq!(bindings[0].runner.operation, " read ");
        assert_eq!(bindings[0].contract, upstream_contract(padded_contract));
    }

    #[tokio::test]
    async fn ordinary_codemode_producer_recovers_beyond_preview_for_reads_and_mutations() {
        for side_effects in [false, true] {
            let mut catalog =
                FakeCatalog::with_classified(&[("logs", "download", side_effects, false)]);
            let body = format!("{}diagnostic-beyond-preview", "x".repeat(80_000));
            catalog.retained_body = Some(Arc::from(body.clone()));
            let identity = catalog.contract_identity("logs", "download");
            let tools = code_mode_tools(
                Arc::new(catalog),
                Arc::new(waygate_mcp::authz::AllowAllGate),
            );
            let result = tools
                .invoke_direct(
                    &reader(),
                    "logs",
                    "download",
                    json!({"value":"job"}),
                    identity,
                    test_hierarchy(1),
                )
                .await
                .expect("ordinary Code Mode recovers complete retained response");
            assert_eq!(result["data"].as_str(), Some(body.as_str()));
            assert!(result["data"]
                .as_str()
                .unwrap()
                .ends_with("diagnostic-beyond-preview"));
        }
    }

    #[tokio::test]
    async fn nested_broker_preserves_the_ordinary_approval_requirement() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false), ("email", "send", true)]);
        let read_contract = fake.contract_identity("email", "read");
        let send_contract = fake.contract_identity("email", "send");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();

        let read = tools
            .invoke_direct(
                &principal,
                "email",
                "read",
                json!({"value": "inbox"}),
                read_contract,
                test_hierarchy(1),
            )
            .await
            .expect("read connector dispatches");
        assert_eq!(read, json!({"result": "email.read:inbox"}));

        let error = tools
            .invoke_direct(
                &principal,
                "email",
                "send",
                json!({"value": "message"}),
                send_contract,
                test_hierarchy(2),
            )
            .await
            .expect_err("unknown approval authority must be refused by ordinary invocation");
        assert!(matches!(
            error,
            waygate_invocation::InvocationError::ApprovalRequired { ref tool, .. }
                if tool == "email.send"
        ));
    }

    /// A tool whose operations carry reviewed classifications stays callable
    /// from inside an execution. The identity Code Mode admits has to be the
    /// one the resolver produces: a binding that could not carry the reviewed
    /// per-operation definition would be refused as drift on every call, which
    /// is how a dispatch-lane connector goes silently dead.
    #[tokio::test]
    async fn per_operation_classified_tool_dispatches_from_an_execution() {
        let mut fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        fake.refine_operations("email", "read", "value", &["inbox"]);
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();

        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        let binding = bindings
            .iter()
            .find(|binding| binding.tool == "read")
            .expect("a refined tool stays admitted");
        assert!(
            binding
                .contract
                .upstream_identity()
                .expect("upstream contract")
                .operations_hash
                .is_some(),
            "the admitted contract must carry the reviewed per-operation definition"
        );

        let result = tools
            .invoke_direct(
                &principal,
                "email",
                "read",
                json!({"value": "inbox"}),
                binding
                    .contract
                    .upstream_identity()
                    .expect("upstream contract")
                    .clone(),
                test_hierarchy(1),
            )
            .await
            .expect("a per-operation classified tool dispatches from Code Mode");
        assert_eq!(result, json!({"result": "email.read:inbox"}));
    }

    /// Code Mode uses ordinary tool classification when a dispatcher argument
    /// has no more-specific operation classification.
    #[tokio::test]
    async fn execution_uses_the_ordinary_dispatch_tool_classification() {
        let mut fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        fake.refine_operations("email", "read", "value", &["inbox"]);
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();

        let bindings = tools
            .execution_bindings(&principal, CodeExecutionProfile::Direct)
            .await
            .expect("catalog snapshot is stable");
        let contract = bindings
            .iter()
            .find(|binding| binding.tool == "read")
            .expect("a refined tool stays admitted")
            .contract
            .clone();

        let result = tools
            .invoke_direct(
                &principal,
                "email",
                "read",
                json!({"value": "drafts"}),
                contract
                    .upstream_identity()
                    .expect("upstream contract")
                    .clone(),
                test_hierarchy(1),
            )
            .await
            .expect("ordinary caller-authorized dispatch remains available");
        assert_eq!(result, json!({"result":"email.read:drafts"}));
    }

    /// The drift guard still refuses a reviewed definition that changed under a
    /// running execution. These entries decide the risk, side-effect, and PII
    /// facts a call is authorized under, so dispatching against a reviewed set
    /// the execution never admitted is exactly the substitution the check
    /// exists to catch.
    #[tokio::test]
    async fn refuses_a_reviewed_operation_set_that_changed_under_the_execution() {
        let mut fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        fake.refine_operations("email", "read", "value", &["inbox"]);
        let admitted = fake.contract_identity("email", "read");

        fake.refine_operations("email", "read", "value", &["inbox", "drafts"]);
        assert_ne!(
            admitted.operations_hash,
            fake.contract_identity("email", "read").operations_hash,
            "a changed reviewed set must change the contract identity"
        );

        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);

        let error = tools
            .invoke_direct(
                &reader(),
                "email",
                "read",
                json!({"value": "inbox"}),
                admitted,
                test_hierarchy(1),
            )
            .await
            .expect_err("a changed reviewed definition must be refused");
        assert!(matches!(
            error,
            waygate_invocation::InvocationError::InvalidArguments(ref reason)
                if reason.contains("operation contract changed during execution")
        ));
    }

    /// Describe publishes the same reviewed definition the admitted contract
    /// binds, and omits the key entirely for a tool classified by name alone.
    /// An unrefined tool's stored binding has to stay byte-identical, or the
    /// deploy that adds the field fails every in-flight execution as changed.
    #[tokio::test]
    async fn describe_publishes_the_reviewed_operation_definition_only_when_one_exists() {
        let mut fake =
            FakeCatalog::with_tools(&[("email", "read", false), ("email", "list", false)]);
        fake.refine_operations("email", "read", "value", &["inbox"]);
        let refined_hash = fake
            .contract_identity("email", "read")
            .operations_hash
            .expect("a reviewed definition hashes");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();

        let describe = |tool: &'static str| {
            tools.describe(
                &principal,
                DescribeParams {
                    name: None,
                    connector: Some("email".to_owned()),
                    operation: Some(tool.to_owned()),
                },
            )
        };

        let refined = describe("read").await.expect("refined tool describes");
        assert_eq!(
            structured(&refined)["identity"]["operations_hash"],
            json!(refined_hash),
        );

        let plain = describe("list").await.expect("unrefined tool describes");
        assert!(
            structured(&plain)["identity"]
                .get("operations_hash")
                .is_none(),
            "a tool classified by name alone must not publish the key at all"
        );
    }

    #[test]
    fn durable_approval_pause_remains_resumable() {
        assert!(ExecutionResponseStatus::WaitingForApproval.leaves_execution_waiting());
        assert!(ExecutionResponseStatus::WaitingForResume.leaves_execution_waiting());
        assert!(!ExecutionResponseStatus::Completed.leaves_execution_waiting());
    }

    #[tokio::test]
    async fn direct_execution_allows_multiple_effects_beyond_the_legacy_call_limit() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let invocation = Arc::new(RecordingInvocation::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone());
        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(64 * 1024);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(limits().frame_bytes * 2);
        for id in 1..=17 {
            runner_parent_output
                .write_all(
                    &encode_frame(&RunnerFrame::Call {
                        id: u32::try_from(id).expect("test id fits u32"),
                        call_id: call_id.clone(),
                        arguments: json!({"value": id}),
                    })
                    .expect("encode connector call"),
                )
                .await
                .expect("write connector call");
            runner_parent_output.write_all(b"\n").await.unwrap();
        }
        runner_parent_output
            .write_all(
                &encode_frame(&RunnerFrame::Complete {
                    result: json!({"done": true}),
                })
                .expect("encode completion"),
            )
            .await
            .expect("write completion");
        runner_parent_output.write_all(b"\n").await.unwrap();

        let mut parent_stdout = BufReader::new(parent_stdout);
        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: Uuid::now_v7(),
                    claim: None,
                    persist_content: false,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest("return null;"),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("direct execution completes without a Code Mode call ceiling");
        let RunnerProgramOutcome::Completed { calls, .. } = outcome else {
            panic!("direct execution unexpectedly paused");
        };
        assert_eq!(calls, 17);
        let requests = invocation.requests.lock().await;
        assert_eq!(requests.len(), 17);
        assert!(requests.iter().all(|request| {
            request.channel == waygate_invocation::InvocationChannel::Direct
                && request.mode == waygate_invocation::InvocationMode::Unrestricted
                && request.approval_binding.is_none()
        }));
    }

    #[test]
    fn parent_refuses_runner_calls_outside_the_execution_binding_set() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let admitted = HashMap::from([(
            runner_call_id("email", "read"),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "read".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "read")),
            },
        )]);

        assert!(admitted_call(&admitted, &runner_call_id("email", "read")).is_ok());
        assert_eq!(
            admitted_call(&admitted, &runner_call_id("email", "send")).unwrap_err(),
            "binding_unavailable: connector is not available in this execution"
        );
    }

    fn execution_binding(catalog: &FakeCatalog, server: &str, tool: &str) -> ExecutionBinding {
        ExecutionBinding {
            approval_context: None,
            runner: RunnerBinding {
                connector: server.to_owned(),
                operation: tool.to_owned(),
                call_id: runner_call_id(server, tool),
            },
            server: server.to_owned(),
            tool: tool.to_owned(),
            contract: upstream_contract(catalog.contract_identity(server, tool)),
        }
    }

    fn read_execution_binding(catalog: &FakeCatalog) -> Vec<ExecutionBinding> {
        vec![execution_binding(catalog, "email", "read")]
    }

    #[test]
    fn capability_handles_are_fresh_while_compatibility_snapshot_is_stable() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);

        let (first_admitted, first_runner, first_snapshot) =
            admit_execution_bindings(read_execution_binding(&fake));
        let (second_admitted, second_runner, second_snapshot) =
            admit_execution_bindings(read_execution_binding(&fake));
        let first_handle = &first_runner[0].call_id;
        let second_handle = &second_runner[0].call_id;

        assert_ne!(first_handle, second_handle);
        assert_eq!(first_snapshot, second_snapshot);
        assert!(admitted_call(&first_admitted, first_handle).is_ok());
        assert!(admitted_call(&second_admitted, second_handle).is_ok());
        assert_eq!(
            admitted_call(&second_admitted, first_handle).unwrap_err(),
            "binding_unavailable: connector is not available in this execution"
        );
    }

    #[test]
    fn resume_keeps_its_original_tool_set_when_unrelated_tools_are_added() {
        let fake =
            FakeCatalog::with_tools(&[("email", "read", false), ("calendar", "list", false)]);
        let (_, _, original_snapshot) = admit_execution_bindings(read_execution_binding(&fake));
        let current = vec![
            execution_binding(&fake, "email", "read"),
            execution_binding(&fake, "calendar", "list"),
        ];

        let resumed = compatible_resume_bindings(current, &original_snapshot)
            .expect("an unrelated addition does not invalidate the original bindings");

        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].runner.connector, "email");
        assert_eq!(resumed[0].runner.operation, "read");
    }

    #[test]
    fn resume_keeps_a_binding_across_validation_equivalent_schema_projection() {
        let raw_input = json!({
            "type": "object",
            "properties": {
                "value": {"type": ["string", "null"]},
                "anything": true
            }
        });
        let snapshot = InvocationToolSnapshot::catalog(
            ToolFacts {
                server: "email".to_owned(),
                name: "read".to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            Uuid::from_u128(44),
            "catalog-v1".to_owned(),
            Some(raw_input.clone()),
            None,
        );
        let source_hash = waygate_catalog::validator_schema_hash(&raw_input);
        let projected_hash = waygate_catalog::validator_schema_hash(
            snapshot.input_schema().expect("portable input schema"),
        );
        assert_ne!(source_hash, projected_hash);

        let binding = || ExecutionBinding {
            approval_context: None,
            runner: RunnerBinding {
                connector: "email".to_owned(),
                operation: "read".to_owned(),
                call_id: runner_call_id("email", "read"),
            },
            server: "email".to_owned(),
            tool: "read".to_owned(),
            contract: upstream_contract(snapshot.contract_identity()),
        };
        let predeployment_binding = binding();
        assert_eq!(
            predeployment_binding
                .contract
                .upstream_identity()
                .expect("upstream contract")
                .input_schema_hash
                .as_deref(),
            Some(source_hash.as_str())
        );

        let (_, _, predeployment_snapshot) = admit_execution_bindings(vec![predeployment_binding]);
        let resumed = compatible_resume_bindings(vec![binding()], &predeployment_snapshot)
            .expect("wire-only schema projection preserves the durable binding");
        assert_eq!(resumed.len(), 1);
    }

    #[test]
    fn resume_refuses_a_changed_original_tool_contract() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let (_, _, original_snapshot) = admit_execution_bindings(read_execution_binding(&fake));
        let mut current = read_execution_binding(&fake);
        current[0].server = "changed-upstream".to_owned();

        assert!(matches!(
            compatible_resume_bindings(current, &original_snapshot),
            Err("tool_snapshot_changed")
        ));
    }

    #[tokio::test]
    async fn broker_refuses_a_capability_handle_replayed_from_another_execution() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let (_, stale_runner, _) = admit_execution_bindings(read_execution_binding(&fake));
        let (current_admitted, _, _) = admit_execution_bindings(read_execution_binding(&fake));
        let replayed_handle = stale_runner[0].call_id.clone();

        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let invocation = Arc::new(RecordingInvocation::default());
        let tools = CodeModeTools::new(catalog, authz, invocation.clone());
        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for frame in [
            RunnerFrame::Call {
                id: 1,
                call_id: replayed_handle,
                arguments: json!({"value": "inbox"}),
            },
            RunnerFrame::Complete {
                result: json!({"done": true}),
            },
        ] {
            runner_parent_output
                .write_all(&encode_frame(&frame).expect("encode runner frame"))
                .await
                .expect("write runner frame");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner frame");
        }
        let mut parent_stdout = BufReader::new(parent_stdout);

        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: Uuid::now_v7(),
                    claim: None,
                    persist_content: false,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest("return null;"),
                    deadline: None,
                },
                &current_admitted,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("broker refuses replay without terminating the execution");
        let RunnerProgramOutcome::Completed { result, calls, .. } = outcome else {
            panic!("broker unexpectedly paused");
        };

        assert_eq!(result, json!({"done": true}));
        assert_eq!(calls, 1);
        assert!(
            invocation.requests.lock().await.is_empty(),
            "a replayed handle must not reach the governed invocation service"
        );
    }

    #[tokio::test]
    async fn broker_stops_at_pause_without_dispatching_later_runner_frames() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let invocation = Arc::new(RecordingInvocation::default());
        let tools = CodeModeTools::new(catalog, authz, invocation.clone());
        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for frame in [
            RunnerFrame::Pause {
                checkpoint: json!({
                    "prompt": "Choose a region",
                    "state": {"candidate_ids": [1, 2]},
                }),
            },
            RunnerFrame::Call {
                id: 1,
                call_id: "must-not-dispatch".to_owned(),
                arguments: json!({}),
            },
        ] {
            runner_parent_output
                .write_all(&encode_frame(&frame).expect("encode runner frame"))
                .await
                .expect("write runner frame");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner frame");
        }
        let mut parent_stdout = BufReader::new(parent_stdout);

        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: Uuid::now_v7(),
                    claim: None,
                    persist_content: true,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest("return null;"),
                    deadline: None,
                },
                &HashMap::new(),
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("pause is a successful durable boundary");

        assert!(matches!(
            outcome,
            RunnerProgramOutcome::Paused {
                checkpoint,
                calls: 0,
                ..
            } if checkpoint["prompt"] == "Choose a region"
        ));
        assert!(
            invocation.requests.lock().await.is_empty(),
            "frames after a pause must not reach invocation"
        );
    }

    #[tokio::test]
    async fn mutation_broker_refuses_checkpoint_pause() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let invocation = Arc::new(RecordingInvocation::default());
        let tools = CodeModeTools::new(catalog, authz, invocation);
        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        let frame = RunnerFrame::Pause {
            checkpoint: json!({"state": "before-effect"}),
        };
        runner_parent_output
            .write_all(&encode_frame(&frame).expect("encode runner frame"))
            .await
            .expect("write runner frame");
        runner_parent_output
            .write_all(b"\n")
            .await
            .expect("terminate runner frame");
        let mut parent_stdout = BufReader::new(parent_stdout);

        // Historical mutation journal attempts cannot use checkpoint pauses.
        let error = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: Uuid::now_v7(),
                    claim: None,
                    persist_content: true,
                    profile: CodeExecutionProfile::LegacyApprovalBound,
                    source_digest: source_digest("return null;"),
                    deadline: None,
                },
                &HashMap::new(),
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect_err("mutation executions pause only at the approval boundary");
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("error")),
            Some(&json!("execution_pause_unavailable"))
        );
    }

    #[tokio::test]
    async fn mutation_broker_journals_effect_outcome_before_deadline_failure() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let invocation = Arc::new(RecordingInvocation::default());
        let store = Arc::new(RecordingExecutionStore::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;

        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        // Only the effect call is buffered; the runner then goes silent, so
        // the already-expired deadline fires at the next frame read.
        runner_parent_output
            .write_all(
                &encode_frame(&RunnerFrame::Call {
                    id: 1,
                    call_id,
                    arguments: json!({}),
                })
                .expect("encode effect call"),
            )
            .await
            .expect("write effect call");
        runner_parent_output
            .write_all(b"\n")
            .await
            .expect("terminate effect call");
        let mut parent_stdout = BufReader::new(parent_stdout);

        let error = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: claim.execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest(source),
                    deadline: Some(tokio::time::Instant::now()),
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect_err("a silent runner past the deadline fails the attempt");
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("error")),
            Some(&json!("execution_timeout"))
        );
        // The deadline must not abandon the approved effect: it dispatched
        // exactly once and its outcome reached the journal before the
        // timeout terminalized the attempt.
        {
            let requests = invocation.requests.lock().await;
            assert_eq!(requests.len(), 1);
            // Direct effects retain the caller's ordinary invocation channel.
            assert_eq!(
                requests[0].channel,
                waygate_invocation::InvocationChannel::Direct
            );
        }
        let kinds: Vec<ExecutionEventKind> = store
            .events
            .lock()
            .await
            .iter()
            .map(|event| event.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                ExecutionEventKind::ConnectorCallStarted,
                ExecutionEventKind::ConnectorCallSucceeded,
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_effect_dispatch_keeps_renewing_the_worker_claim() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        // Dispatch outlives the configured lease: the ticker must renew it so
        // the outcome append keeps its fence and reconciliation cannot steal
        // the still-dispatching row.
        let invocation = Arc::new(SlowInvocation {
            delay: Duration::from_secs(limits().execution_seconds) * 3,
            requests: tokio::sync::Mutex::new(Vec::new()),
        });
        let store = Arc::new(RecordingExecutionStore::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;

        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for frame in [
            RunnerFrame::Call {
                id: 1,
                call_id,
                arguments: json!({}),
            },
            RunnerFrame::Complete {
                result: json!({"sent": true}),
            },
        ] {
            runner_parent_output
                .write_all(&encode_frame(&frame).expect("encode runner frame"))
                .await
                .expect("write runner frame");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner frame");
        }
        let mut parent_stdout = BufReader::new(parent_stdout);

        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: claim.execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest(source),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("slow effect dispatch completes its attempt");
        assert!(matches!(
            outcome,
            RunnerProgramOutcome::Completed { calls: 1, .. }
        ));
        let renewals = store.renewals.lock().await;
        assert!(
            renewals.len() >= 2,
            "a dispatch spanning two leases renews more than once (saw {})",
            renewals.len()
        );
        // Each renewal grants the lease this configuration actually uses. That
        // is derived from the execution budget now rather than fixed, so
        // asserting a constant here would pin the old arithmetic instead of
        // the contract: a renewal must extend the fence by the same span a
        // fresh claim would.
        assert!(renewals.iter().all(|lease| *lease == tools.claim_lease()));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_effect_dispatch_survives_a_mid_flight_cancellation() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let store = Arc::new(RecordingExecutionStore::default());
        // Cancellation lands right after dispatch begins, and the dispatch
        // then outlives the lease: the effect-lease renewal must keep the
        // claim alive despite the pending cancellation so the outcome still
        // reaches the journal.
        let invocation = Arc::new(CancelDuringDispatchInvocation {
            store: store.clone(),
            delay: Duration::from_secs(limits().execution_seconds) * 3,
            requests: tokio::sync::Mutex::new(Vec::new()),
        });
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;

        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for frame in [
            RunnerFrame::Call {
                id: 1,
                call_id,
                arguments: json!({}),
            },
            RunnerFrame::Complete {
                result: json!({"sent": true}),
            },
        ] {
            runner_parent_output
                .write_all(&encode_frame(&frame).expect("encode runner frame"))
                .await
                .expect("write runner frame");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner frame");
        }
        let mut parent_stdout = BufReader::new(parent_stdout);

        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: claim.execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest(source),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("a cancelled in-flight effect still completes its attempt");
        assert!(matches!(
            outcome,
            RunnerProgramOutcome::Completed { calls: 1, .. }
        ));
        assert!(
            store.renewals.lock().await.len() >= 2,
            "the effect lease keeps renewing while cancellation is pending"
        );
        let kinds: Vec<ExecutionEventKind> = store
            .events
            .lock()
            .await
            .iter()
            .map(|event| event.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                ExecutionEventKind::ConnectorCallStarted,
                ExecutionEventKind::ConnectorCallSucceeded,
            ]
        );
    }

    #[tokio::test]
    async fn mutation_broker_refuses_arguments_too_large_for_exact_review() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let invocation = Arc::new(RecordingInvocation::default());
        let store = Arc::new(RecordingExecutionStore::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(64 * 1024);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(limits().frame_bytes * 2);
        for frame in [
            RunnerFrame::Call {
                id: 1,
                call_id,
                arguments: json!({"body": "b".repeat(limits().request_bytes)}),
            },
            RunnerFrame::Complete {
                result: json!({"done": true}),
            },
        ] {
            runner_parent_output
                .write_all(&encode_frame(&frame).expect("encode runner frame"))
                .await
                .expect("write runner frame");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner frame");
        }
        let execution_id = Uuid::now_v7();
        let claim = ExecutionClaim {
            execution_id,
            tenant_id: reader().tenant.to_string(),
            owner: Uuid::now_v7(),
            epoch: 1,
        };
        let mut parent_stdout = BufReader::new(parent_stdout);

        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::LegacyApprovalBound,
                    source_digest: source_digest("return null;"),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("an oversized effect fails its call, not the attempt");
        // The approval binds the hash of the complete arguments, so an effect
        // the administrator could not review completely must never reach a
        // pending request or dispatch.
        assert!(matches!(outcome, RunnerProgramOutcome::Completed { .. }));
        assert!(
            invocation.requests.lock().await.is_empty(),
            "an oversized effect must not dispatch"
        );
        let kinds: Vec<ExecutionEventKind> = store
            .events
            .lock()
            .await
            .iter()
            .map(|event| event.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                ExecutionEventKind::ConnectorCallStarted,
                ExecutionEventKind::ConnectorCallFailed,
            ]
        );
    }

    /// Grant store recording only the revocation seam the broker uses; every
    /// other catalog operation is out of scope for these tests.
    #[derive(Default)]
    struct RecordingGrantStore {
        revoked: tokio::sync::Mutex<Vec<(String, Uuid)>>,
    }

    #[async_trait]
    impl waygate_catalog::CatalogStore for RecordingGrantStore {
        async fn approved_servers(
            &self,
            _tenant: &str,
        ) -> Result<Vec<waygate_catalog::CatalogServerSummary>, waygate_catalog::CatalogError>
        {
            unreachable!("broker tests do not browse the catalog")
        }

        async fn resolve_tool(
            &self,
            _tenant: &str,
            _fq_name: &str,
        ) -> Result<waygate_catalog::ResolvedTool, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not resolve tools")
        }

        async fn record_drift(
            &self,
            _observation: waygate_catalog::DriftObservation<'_>,
        ) -> Result<(), waygate_catalog::CatalogError> {
            unreachable!("broker tests do not record drift")
        }

        async fn record_approval(
            &self,
            _action: waygate_catalog::ApprovalAction<'_>,
        ) -> Result<(), waygate_catalog::CatalogError> {
            unreachable!("broker tests do not record approvals")
        }

        async fn list_drift_events(
            &self,
            _tenant: &str,
            _since: time::OffsetDateTime,
            _limit: u32,
        ) -> Result<Vec<waygate_catalog::DriftEvent>, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not list drift")
        }

        async fn set_server_status(
            &self,
            _tenant: &str,
            _server_id: Uuid,
            _new_status: waygate_catalog::CatalogServerStatus,
            _actor: &str,
            _reason: Option<&str>,
        ) -> Result<bool, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not change server status")
        }

        async fn last_approve_actor(
            &self,
            _tenant: &str,
            _server_id: Uuid,
        ) -> Result<Option<String>, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not read approval actors")
        }

        async fn find_grant<'a>(
            &self,
            _lookup: waygate_catalog::GrantLookup<'a>,
        ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not look up grants")
        }

        async fn claim_grant<'a>(
            &self,
            _lookup: waygate_catalog::GrantLookup<'a>,
        ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not claim grants")
        }

        async fn create_grant<'a>(
            &self,
            _grant: waygate_catalog::NewApprovalGrant<'a>,
        ) -> Result<waygate_catalog::ApprovalGrant, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not mint grants")
        }

        async fn list_grants<'a>(
            &self,
            _tenant: &'a str,
            _filter: waygate_catalog::GrantFilter<'a>,
        ) -> Result<Vec<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not list grants")
        }

        async fn revoke_grant(
            &self,
            _tenant: &str,
            _id: Uuid,
        ) -> Result<bool, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not revoke by id")
        }

        async fn revoke_execution_grants(
            &self,
            tenant_id: &str,
            execution_id: Uuid,
        ) -> Result<u64, waygate_catalog::CatalogError> {
            self.revoked
                .lock()
                .await
                .push((tenant_id.to_owned(), execution_id));
            Ok(1)
        }

        async fn sweep_grants(
            &self,
            _older_than: time::OffsetDateTime,
        ) -> Result<u64, waygate_catalog::CatalogError> {
            unreachable!("broker tests do not sweep grants")
        }
    }

    #[tokio::test]
    async fn persisting_a_new_approval_request_revokes_superseded_grants() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let invocation = Arc::new(RecordingInvocation::default());
        let store = Arc::new(RecordingExecutionStore::default());
        let grants = Arc::new(RecordingGrantStore::default());
        let tools = CodeModeTools::new(catalog, authz, invocation)
            .with_execution_store(store.clone())
            .with_grant_store(grants.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;
        let approval = MutationApprovalRequest {
            connector: "email".to_owned(),
            operation: "send".to_owned(),
            argument_hash: "sha256:new-request".to_owned(),
            arguments_preview: json!({"value": "x"}),
            description: None,
            risk: Risk::High,
            source_digest: source_digest(source),
            call_id: Uuid::new_v5(&claim.execution_id, &1_u32.to_be_bytes()),
            step: 1,
            contract: json!({"authority": {"authority": "catalog"}}),
            prior_effects: 0,
        };

        tools
            .persist_claimed_approval(&claim, &approval, 1, 0)
            .await
            .expect("approval request persists");

        // Any earlier execution-bound grant must be dead before the new
        // request becomes approvable: one execution never holds live
        // authorizations for two different effects.
        assert_eq!(
            grants.revoked.lock().await.clone(),
            vec![(claim.tenant_id.clone(), claim.execution_id)]
        );
        let waiting = store.current.lock().await.clone().expect("execution");
        assert_eq!(waiting.status, ExecutionStatus::WaitingForApproval);
    }

    async fn claimed_mutation_fixture(
        store: &RecordingExecutionStore,
        source: &str,
    ) -> ExecutionClaim {
        let tenant = reader().tenant.to_string();
        let execution_id = Uuid::now_v7();
        store
            .submit(NewExecution {
                program_input: None,
                id: execution_id,
                tenant_id: tenant.clone(),
                principal_sub: reader().sub.clone(),
                principal_issuer: "test".to_owned(),
                source: Some(source.to_owned()),
                source_digest: source_digest(source),
                execution_profile: json!({
                    "name": "approval_bound_mutation",
                    "resumable": false,
                }),
                sdk_contract_version: SDK_CONTRACT_VERSION,
                runner_contract_version: RUNNER_CONTRACT_VERSION,
                retention_until: time::OffsetDateTime::now_utc() + time::Duration::days(1),
            })
            .await
            .expect("submit mutation execution");
        let (_, claim) = store
            .claim(
                &tenant,
                execution_id,
                Uuid::now_v7(),
                Duration::from_secs(30),
                source.to_owned(),
                json!({"contract_version": 1, "bindings": []}),
            )
            .await
            .expect("claim mutation execution")
            .expect("claim succeeds");
        claim
    }

    #[tokio::test]
    async fn mutation_broker_refuses_dispatch_after_cancellation_request() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let invocation = Arc::new(RecordingInvocation::default());
        let store = Arc::new(RecordingExecutionStore::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;
        // A tasks/cancel lands while the claim is live, before any dispatch.
        store
            .current
            .lock()
            .await
            .as_mut()
            .expect("claimed execution")
            .cancellation_requested_at = Some(time::OffsetDateTime::now_utc());

        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        runner_parent_output
            .write_all(
                &encode_frame(&RunnerFrame::Call {
                    id: 1,
                    call_id,
                    arguments: json!({}),
                })
                .expect("encode effect call"),
            )
            .await
            .expect("write effect call");
        runner_parent_output
            .write_all(b"\n")
            .await
            .expect("terminate effect call");
        let mut parent_stdout = BufReader::new(parent_stdout);

        let error = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: claim.execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::LegacyApprovalBound,
                    source_digest: source_digest(source),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect_err("an accepted cancellation closes later dispatch");
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("error")),
            Some(&json!("execution_cancelled"))
        );
        assert!(
            invocation.requests.lock().await.is_empty(),
            "no dispatch may follow an accepted cancellation"
        );
        let cancelled = store.current.lock().await.clone().expect("execution");
        assert_eq!(cancelled.status, ExecutionStatus::Cancelled);
        assert_eq!(
            cancelled.terminal_reason_code.as_deref(),
            Some("cancelled_by_client")
        );
    }

    /// The requester is off the call path when a live-claim cancellation
    /// finalizes, so the terminal reason must come from the row's recorded
    /// provenance: an operator's request finalizes as
    /// `cancelled_by_operator`, not the historical client reason.
    #[tokio::test]
    async fn claimed_cancellation_finalizes_under_the_recorded_operator_provenance() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let invocation = Arc::new(RecordingInvocation::default());
        let store = Arc::new(RecordingExecutionStore::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;
        {
            let mut current = store.current.lock().await;
            let execution = current.as_mut().expect("claimed execution");
            execution.cancellation_requested_at = Some(time::OffsetDateTime::now_utc());
            execution.cancellation_reason_code = Some("cancelled_by_operator".to_owned());
        }

        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        runner_parent_output
            .write_all(
                &encode_frame(&RunnerFrame::Call {
                    id: 1,
                    call_id,
                    arguments: json!({}),
                })
                .expect("encode effect call"),
            )
            .await
            .expect("write effect call");
        runner_parent_output
            .write_all(b"\n")
            .await
            .expect("terminate effect call");
        let mut parent_stdout = BufReader::new(parent_stdout);

        tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: claim.execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::LegacyApprovalBound,
                    source_digest: source_digest(source),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect_err("an accepted cancellation closes later dispatch");
        let cancelled = store.current.lock().await.clone().expect("execution");
        assert_eq!(cancelled.status, ExecutionStatus::Cancelled);
        assert_eq!(
            cancelled.terminal_reason_code.as_deref(),
            Some("cancelled_by_operator"),
            "finalization reports the recorded requester, not a hard-coded reason"
        );
    }

    #[tokio::test]
    async fn mutation_broker_refuses_dispatch_when_cancellation_lands_after_the_start_append() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let invocation = Arc::new(RecordingInvocation::default());
        let store = Arc::new(RecordingExecutionStore::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;
        // The cancellation request commits in the gap between the fenced
        // call-start append and the dispatch: the pre-dispatch renewal fence
        // must observe it and no upstream call may follow.
        store
            .cancel_on_first_append
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        let frame = RunnerFrame::Call {
            id: 1,
            call_id,
            arguments: json!({}),
        };
        runner_parent_output
            .write_all(&encode_frame(&frame).expect("encode runner frame"))
            .await
            .expect("write runner frame");
        runner_parent_output
            .write_all(b"\n")
            .await
            .expect("terminate runner frame");
        let mut parent_stdout = BufReader::new(parent_stdout);

        let error = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: claim.execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::LegacyApprovalBound,
                    source_digest: source_digest(source),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect_err("a cancellation accepted before dispatch closes the effect");
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("error")),
            Some(&json!("execution_cancelled"))
        );
        assert!(
            invocation.requests.lock().await.is_empty(),
            "no dispatch may follow an accepted cancellation"
        );
        let cancelled = store.current.lock().await.clone().expect("execution");
        assert_eq!(cancelled.status, ExecutionStatus::Cancelled);
    }

    /// Invocation that commits a cancellation request while the dispatch is
    /// in flight — after the pre-dispatch fence, before the outcome — and
    /// then optionally keeps the dispatch running past the claim lease.
    struct CancelDuringDispatchInvocation {
        store: Arc<RecordingExecutionStore>,
        delay: Duration,
        requests: tokio::sync::Mutex<Vec<InvocationRequest>>,
    }

    #[async_trait]
    impl waygate_invocation::InvocationService for CancelDuringDispatchInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse, waygate_invocation::InvocationError> {
            self.requests.lock().await.push(request);
            if let Some(execution) = self.store.current.lock().await.as_mut() {
                execution.cancellation_requested_at = Some(time::OffsetDateTime::now_utc());
            }
            tokio::time::sleep(self.delay).await;
            Ok(InvocationResponse::Unary(CallToolResult::structured(
                json!({"result": "ok"}),
            )))
        }
    }

    #[tokio::test]
    async fn mutation_broker_journals_effect_outcome_when_cancellation_arrives_mid_flight() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let store = Arc::new(RecordingExecutionStore::default());
        let invocation = Arc::new(CancelDuringDispatchInvocation {
            store: store.clone(),
            delay: Duration::ZERO,
            requests: tokio::sync::Mutex::new(Vec::new()),
        });
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(store.clone());
        let source = "return connectors.email.send({value: 'x'});";
        let claim = claimed_mutation_fixture(&store, source).await;

        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for frame in [
            RunnerFrame::Call {
                id: 1,
                call_id,
                arguments: json!({}),
            },
            RunnerFrame::Complete {
                result: json!({"sent": true}),
            },
        ] {
            runner_parent_output
                .write_all(&encode_frame(&frame).expect("encode runner frame"))
                .await
                .expect("write runner frame");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner frame");
        }
        let mut parent_stdout = BufReader::new(parent_stdout);

        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id: claim.execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::LegacyApprovalBound,
                    source_digest: source_digest(source),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("a dispatched effect completes its attempt");
        assert!(matches!(
            outcome,
            RunnerProgramOutcome::Completed { calls: 1, .. }
        ));
        assert_eq!(invocation.requests.lock().await.len(), 1);
        // The journal must record what was dispatched even though the
        // cancellation flag was set while the effect was in flight.
        let kinds: Vec<ExecutionEventKind> = store
            .events
            .lock()
            .await
            .iter()
            .map(|event| event.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                ExecutionEventKind::ConnectorCallStarted,
                ExecutionEventKind::ConnectorCallSucceeded,
            ]
        );
        let current = store.current.lock().await.clone().expect("execution");
        assert!(current.cancellation_requested_at.is_some());
    }

    #[tokio::test]
    async fn broker_persists_artifact_before_returning_its_stable_reference() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let invocation = Arc::new(RecordingInvocation::default());
        let execution_store = Arc::new(RecordingExecutionStore::default());
        let tools = CodeModeTools::new(catalog, authz, invocation)
            .with_execution_store(execution_store.clone())
            .with_result_persistence_allowed(true);
        let (mut parent_stdin, runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for frame in [
            RunnerFrame::Artifact {
                id: 1,
                value: json!({"kind": "preview", "rows": [1, 2]}),
            },
            RunnerFrame::Complete {
                result: json!({"done": true}),
            },
        ] {
            runner_parent_output
                .write_all(&encode_frame(&frame).expect("encode runner frame"))
                .await
                .expect("write runner frame");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner frame");
        }
        let execution_id = Uuid::now_v7();
        let claim = ExecutionClaim {
            execution_id,
            tenant_id: reader().tenant.to_string(),
            owner: Uuid::now_v7(),
            epoch: 1,
        };
        let mut parent_stdout = BufReader::new(parent_stdout);

        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest("return null;"),
                    deadline: None,
                },
                &HashMap::new(),
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("broker persists artifact and completes");
        let RunnerProgramOutcome::Completed { artifacts, .. } = outcome else {
            panic!("broker unexpectedly paused")
        };
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].execution_id, execution_id);

        let events = execution_store.events.lock().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, ExecutionEventKind::ArtifactEmitted);
        assert_eq!(
            events[0].detail["value"],
            json!({"kind": "preview", "rows": [1, 2]})
        );
        assert_eq!(
            events[0].detail["artifact_id"],
            artifacts[0].artifact_id.to_string()
        );
        drop(events);

        let mut runner_parent_input = BufReader::new(runner_parent_input);
        let mut response = String::new();
        runner_parent_input
            .read_line(&mut response)
            .await
            .expect("read artifact response");
        let response: ParentFrame =
            serde_json::from_str(&response).expect("decode artifact response");
        assert!(matches!(
            response,
            ParentFrame::ArtifactResult {
                id: 1,
                result: Ok(reference),
            } if reference["artifact_id"] == artifacts[0].artifact_id.to_string()
        ));
    }

    #[tokio::test]
    async fn nested_broker_preserves_upstream_tool_errors() {
        let fake = FakeCatalog::with_tools(&[("email", "fails", false)]);
        let contract = fake.contract_identity("email", "fails");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = CodeModeTools::new(catalog, authz, Arc::new(ToolErrorInvocation));

        let error = tools
            .invoke_direct(
                &reader(),
                "email",
                "fails",
                json!({"value": "inbox"}),
                contract,
                test_hierarchy(1),
            )
            .await
            .expect_err("upstream tool errors must remain failures");
        assert!(matches!(
            error,
            waygate_invocation::InvocationError::Upstream(ref error)
                if error.message == "connector reported a tool error"
                    && error.data.as_ref() == Some(&json!({"reason": "upstream refused"}))
        ));
    }

    #[test]
    fn aggregate_pii_does_not_hide_ordinary_effect_destinations() {
        let definition = Tool::new(
            "email.send",
            "Send a message",
            Arc::new(
                json!({"type": "object", "properties": {"recipient": {"type": "string"}}})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        );
        let tool = CatalogTool::builtin("email", definition, RiskTier::High, true, true);
        let preview = ApprovalContext::from_tool(&tool).arguments_preview(
            &json!({"recipient": "recipient@example.test", "password": "synthetic-password"}),
        );
        assert_eq!(preview["recipient"], "recipient@example.test");
        assert_eq!(preview["password"], "[REDACTED:SENSITIVE_FIELD]");
    }

    #[tokio::test]
    async fn sensitive_approval_uses_reviewed_consequences_and_field_names_only() {
        let mut catalog = FakeCatalog::with_tools(&[("komodo", "stacks.compose.write", true)]);
        let key = ("komodo".to_owned(), "stacks.compose.write".to_owned());
        let input = json!({"type": "object", "properties": {
            "selector": {"type": "string"}, "contents": {"type": "string"}
        }, "required": ["selector", "contents"], "additionalProperties": false});
        let description = "Replace inline Compose. Komodo may retain submitted values. Deploy separately; reconcile with stacks.compose.read.";
        let published = Tool::new(
            "stacks.compose.write",
            description,
            Arc::new(input.as_object().unwrap().clone()),
        );
        Arc::make_mut(&mut catalog.tools).insert("komodo".to_owned(), vec![published]);
        Arc::make_mut(&mut catalog.snapshots).insert(
            key,
            ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog_with_annotation_claims(
                ToolFacts {
                    server: "komodo".to_owned(),
                    name: "stacks.compose.write".to_owned(),
                    risk: RiskTier::High,
                    side_effects: true,
                    pii: true,
                    requires_approval: true,
                    requires_approval_known: true,
                },
                Uuid::new_v4(),
                "reviewed-compose-contract".to_owned(),
                false,
                Some(input),
                None,
                Some(json!({"readOnlyHint": false, "destructiveHint": true,
                    "idempotentHint": false, "openWorldHint": true})),
                Some(
                    json!({"inputMetadata": {"destination": "internal", "sensitivity": "sensitive"},
                    "returnMetadata": {"source": "first-party", "sensitivity": "operational"},
                    "outcome": "modify", "requiresReview": true}),
                ),
            )),
        );
        let tools = CodeModeTools::new(
            Arc::new(catalog),
            Arc::new(SelectiveAuthz),
            Arc::new(RecordingInvocation::default()),
        );
        let bindings = tools
            .execution_bindings(&reader(), CodeExecutionProfile::Direct)
            .await
            .unwrap();
        assert_eq!(bindings.len(), 1);
        let (admitted, _, snapshot) = admit_execution_bindings(bindings);
        let call = admitted.values().next().unwrap();
        let arguments = json!({"selector": "private-target", "contents": "opaque-secret-body"});
        let attempt = RunnerAttempt {
            principal: &reader(),
            execution_id: Uuid::now_v7(),
            claim: None,
            persist_content: true,
            profile: CodeExecutionProfile::Direct,
            source_digest: source_digest("synthetic program"),
            deadline: None,
        };
        let request = mutation_approval_request(&attempt, call, &arguments, test_hierarchy(1));
        assert_eq!(request.description.as_deref(), Some(description));
        assert_eq!(
            request.arguments_preview,
            json!({"selector": "[REDACTED:SENSITIVE_INPUT]",
            "contents": "[REDACTED:SENSITIVE_INPUT]"})
        );
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("private-target"));
        assert!(!encoded.contains("opaque-secret-body"));
        assert_eq!(
            request.argument_hash,
            waygate_catalog::argument_hash(arguments.as_object())
        );
        // Presentation is reconstructed from the contract on resume, preserving
        // compatibility with snapshots captured before summaries were available.
        let resumed = compatible_resume_bindings(
            tools
                .execution_bindings(&reader(), CodeExecutionProfile::Direct)
                .await
                .unwrap(),
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            resumed[0].approval_context.as_ref().unwrap().description,
            description
        );
        let context = call.approval_context.as_ref().unwrap();
        assert_eq!(
            context.arguments_preview(&json!({"untrusted-secret-key": "value"})),
            json!({})
        );
    }

    #[tokio::test]
    async fn mutation_broker_pauses_with_exact_redacted_approval_binding() {
        let fake = FakeCatalog::with_tools(&[("email", "send", true)]);
        let call_id = runner_call_id("email", "send");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "send".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "send")),
            },
        )]);
        let invocation = Arc::new(ApprovalRequiredInvocation::default());
        let execution_store = Arc::new(RecordingExecutionStore::default());
        let tools =
            CodeModeTools::new(Arc::new(fake), Arc::new(SelectiveAuthz), invocation.clone())
                .with_execution_store(execution_store.clone());
        let opaque_blob = "b".repeat(400);
        let arguments = json!({
            "value": "send summary",
            "password": "do-not-store",
            "recipient": "alice@example.com",
            "credential": "AKIAIOSFODNN7EXAMPLE",
            "clientSecret": "opaque-value-under-a-camel-case-key",
            "accessToken": "another-opaque-camel-case-value",
            "body": opaque_blob,
        });
        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        runner_parent_output
            .write_all(
                &encode_frame(&RunnerFrame::Call {
                    id: 1,
                    call_id,
                    arguments: arguments.clone(),
                })
                .expect("encode mutation call"),
            )
            .await
            .expect("write mutation call");
        runner_parent_output
            .write_all(b"\n")
            .await
            .expect("terminate mutation call");

        let execution_id = Uuid::now_v7();
        let claim = ExecutionClaim {
            execution_id,
            tenant_id: reader().tenant.to_string(),
            owner: Uuid::now_v7(),
            epoch: 2,
        };
        let source = "return connectors.email.send({value: 'send summary'});";
        let digest = source_digest(source);
        let mut parent_stdout = BufReader::new(parent_stdout);
        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id,
                    claim: Some(&claim),
                    persist_content: true,
                    profile: CodeExecutionProfile::LegacyApprovalBound,
                    source_digest: digest.clone(),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("approval requirement is a durable pause");
        let RunnerProgramOutcome::WaitingForApproval {
            approval, calls, ..
        } = outcome
        else {
            panic!("mutation did not pause for approval");
        };
        assert_eq!(calls, 1);
        assert_eq!(approval.connector, "email");
        assert_eq!(approval.operation, "send");
        assert_eq!(
            approval.argument_hash,
            waygate_catalog::argument_hash(arguments.as_object())
        );
        assert_eq!(
            approval.arguments_preview["password"],
            "[REDACTED:SENSITIVE_FIELD]"
        );
        assert_eq!(
            approval.arguments_preview["credential"],
            "[REDACTED:SENSITIVE_FIELD]"
        );
        // Camel-case credential fields normalize to the same markers as
        // snake_case ones.
        assert_eq!(
            approval.arguments_preview["clientSecret"],
            "[REDACTED:SENSITIVE_FIELD]"
        );
        assert_eq!(
            approval.arguments_preview["accessToken"],
            "[REDACTED:SENSITIVE_FIELD]"
        );
        // The effect destination stays visible: an approver cannot judge an
        // email send without seeing where it goes.
        assert_eq!(approval.arguments_preview["recipient"], "alice@example.com");
        assert_eq!(approval.arguments_preview["value"], "send summary");
        // Every hash-covered value is shown in full — the approval must not
        // bind content the administrator was never shown.
        assert_eq!(approval.arguments_preview["body"], opaque_blob);
        assert_eq!(approval.source_digest, digest);
        assert_eq!(approval.step, 1);
        assert_eq!(
            approval.call_id,
            Uuid::new_v5(&execution_id, &1_u32.to_be_bytes())
        );

        let requests = invocation.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].mode,
            waygate_invocation::InvocationMode::Unrestricted
        );
        assert_eq!(
            requests[0].approval_binding.as_ref().map(|binding| (
                binding.execution_id,
                binding.source_digest.as_str(),
                binding.call_id,
            )),
            Some((execution_id, digest.as_str(), approval.call_id))
        );
        assert_eq!(
            requests[0]
                .hierarchy
                .expect("mutation hierarchy")
                .attempt
                .get(),
            2
        );
        drop(requests);
        let events = execution_store.events.lock().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, ExecutionEventKind::ConnectorCallStarted);
        assert_eq!(events[0].attempt, Some(2));
    }

    #[tokio::test]
    async fn nested_broker_assigns_one_parent_and_ordered_stable_call_attempts() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let call_id = runner_call_id("email", "read");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "read".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "read")),
            },
        )]);
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let invocation = Arc::new(RecordingInvocation::default());
        let execution_store = Arc::new(RecordingExecutionStore::default());
        let shared_store: SharedExecutionStore = execution_store.clone();
        let tools = CodeModeTools::new(catalog, authz, invocation.clone())
            .with_execution_store(shared_store);
        let (mut parent_stdin, _runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for id in [1, 2] {
            let frame = encode_frame(&RunnerFrame::Call {
                id,
                call_id: call_id.clone(),
                arguments: json!({"value": id.to_string()}),
            })
            .expect("encode runner call");
            runner_parent_output
                .write_all(&frame)
                .await
                .expect("write runner call");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner call");
        }
        let complete = encode_frame(&RunnerFrame::Complete {
            result: json!({"done": true}),
        })
        .expect("encode completion");
        runner_parent_output
            .write_all(&complete)
            .await
            .expect("write completion");
        runner_parent_output
            .write_all(b"\n")
            .await
            .expect("terminate completion");

        let execution_id = Uuid::now_v7();
        let claim = ExecutionClaim {
            execution_id,
            tenant_id: reader().tenant.to_string(),
            owner: Uuid::now_v7(),
            epoch: 1,
        };
        let mut parent_stdout = BufReader::new(parent_stdout);
        let outcome = tools
            .broker_runner_frames(
                RunnerAttempt {
                    principal: &reader(),
                    execution_id,
                    claim: Some(&claim),
                    persist_content: false,
                    profile: CodeExecutionProfile::Direct,
                    source_digest: source_digest("return null;"),
                    deadline: None,
                },
                &admitted_calls,
                &mut parent_stdin,
                &mut parent_stdout,
            )
            .await
            .expect("broker completes");
        let RunnerProgramOutcome::Completed { result, calls, .. } = outcome else {
            panic!("broker unexpectedly paused");
        };

        assert_eq!(result, json!({"done": true}));
        assert_eq!(calls, 2);
        let requests = invocation.requests.lock().await;
        let hierarchies: Vec<_> = requests
            .iter()
            .map(|request| request.hierarchy.expect("nested hierarchy"))
            .collect();
        assert_eq!(hierarchies.len(), 2);
        assert!(hierarchies
            .iter()
            .all(|hierarchy| hierarchy.parent_execution_id == execution_id));
        assert_eq!(hierarchies[0].step.get(), 1);
        assert_eq!(hierarchies[1].step.get(), 2);
        assert_eq!(
            hierarchies[0].call_id,
            Uuid::new_v5(&execution_id, &1_u32.to_be_bytes())
        );
        assert_eq!(
            hierarchies[1].call_id,
            Uuid::new_v5(&execution_id, &2_u32.to_be_bytes())
        );
        assert!(hierarchies
            .iter()
            .all(|hierarchy| hierarchy.attempt == NonZeroU32::MIN));
        let events = execution_store.events.lock().await;
        assert_eq!(
            events.iter().map(|event| event.kind).collect::<Vec<_>>(),
            [
                ExecutionEventKind::ConnectorCallStarted,
                ExecutionEventKind::ConnectorCallSucceeded,
                ExecutionEventKind::ConnectorCallStarted,
                ExecutionEventKind::ConnectorCallSucceeded,
            ]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.step_number)
                .collect::<Vec<_>>(),
            [Some(1), Some(1), Some(2), Some(2)]
        );
    }

    #[tokio::test]
    async fn cancelling_broker_closes_capability_channel_before_later_dispatch() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let call_id = runner_call_id("email", "read");
        let admitted_calls = HashMap::from([(
            call_id.clone(),
            AdmittedCall {
                approval_context: None,
                server: "email".to_owned(),
                tool: "read".to_owned(),
                contract: upstream_contract(fake.contract_identity("email", "read")),
            },
        )]);
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let invocation = Arc::new(BlockingInvocation {
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        });
        let tools = Arc::new(CodeModeTools::new(catalog, authz, invocation.clone()));
        let (mut parent_stdin, mut runner_parent_input) = tokio::io::duplex(4096);
        let (mut runner_parent_output, parent_stdout) = tokio::io::duplex(4096);
        for id in [1, 2] {
            let frame = encode_frame(&RunnerFrame::Call {
                id,
                call_id: call_id.clone(),
                arguments: json!({"value": id.to_string()}),
            })
            .expect("encode runner call");
            runner_parent_output
                .write_all(&frame)
                .await
                .expect("write runner call");
            runner_parent_output
                .write_all(b"\n")
                .await
                .expect("terminate runner call");
        }
        let mut parent_stdout = BufReader::new(parent_stdout);
        let principal = reader();
        let broker = tokio::spawn(async move {
            tools
                .broker_runner_frames(
                    RunnerAttempt {
                        principal: &principal,
                        execution_id: uuid::Uuid::now_v7(),
                        claim: None,
                        persist_content: false,
                        profile: CodeExecutionProfile::Direct,
                        source_digest: source_digest("return null;"),
                        deadline: None,
                    },
                    &admitted_calls,
                    &mut parent_stdin,
                    &mut parent_stdout,
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), invocation.entered.notified())
            .await
            .expect("first nested dispatch starts");
        broker.abort();
        assert!(broker
            .await
            .expect_err("broker is cancelled")
            .is_cancelled());

        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), runner_parent_input.read(&mut byte))
                .await
                .expect("capability channel closes")
                .expect("read capability channel"),
            0
        );
        assert_eq!(
            invocation.calls.load(Ordering::SeqCst),
            1,
            "cancellation must drop the in-flight call and never begin the queued call"
        );
    }

    #[test]
    fn catalog_identity_versions_exact_input_and_output_schemas() {
        let tool_id = Uuid::new_v4();
        let facts = ToolFacts {
            server: "email".to_owned(),
            name: "send".to_owned(),
            risk: RiskTier::Low,
            side_effects: true,
            pii: false,
            requires_approval: true,
            requires_approval_known: true,
        };
        let input = json!({"type": "object", "properties": {"value": {"type": "string"}}});
        let string_output = json!({"type": "object", "properties": {"result": {"type": "string"}}});
        let integer_output =
            json!({"type": "object", "properties": {"result": {"type": "integer"}}});
        let first = InvocationToolSnapshot::catalog(
            facts.clone(),
            tool_id,
            "classification-only-hash".to_owned(),
            Some(input.clone()),
            Some(string_output),
        );
        let changed_output = InvocationToolSnapshot::catalog(
            facts.clone(),
            tool_id,
            "classification-only-hash".to_owned(),
            Some(input),
            Some(integer_output),
        );
        let changed_input = InvocationToolSnapshot::catalog(
            facts,
            tool_id,
            "classification-only-hash".to_owned(),
            Some(json!({
                "type": "object",
                "properties": {"value": {"type": "integer"}}
            })),
            changed_output.output_schema().cloned(),
        );

        let first = serde_json::to_value(identity(&first)).expect("identity serializes");
        let changed_output =
            serde_json::to_value(identity(&changed_output)).expect("identity serializes");
        let changed_input =
            serde_json::to_value(identity(&changed_input)).expect("identity serializes");

        assert_eq!(
            first["catalog_schema_hash"],
            changed_output["catalog_schema_hash"]
        );
        assert_eq!(
            first["input_schema_hash"],
            changed_output["input_schema_hash"]
        );
        assert_ne!(
            first["output_schema_hash"],
            changed_output["output_schema_hash"]
        );
        assert_ne!(
            changed_output["input_schema_hash"],
            changed_input["input_schema_hash"]
        );
    }

    #[test]
    fn declared_output_schema_is_discoverable_and_versions_code_mode_identity() {
        let snapshot = |kind| {
            let output = json!({"type":"object","properties":{"result":{"type":kind}}});
            let tool = rmcp::model::Tool::new(
                "read",
                "Read a record",
                Arc::new(json!({"type":"object"}).as_object().unwrap().clone()),
            )
            .with_raw_output_schema(Arc::new(output.as_object().unwrap().clone()));
            InvocationToolSnapshot::catalog(
                ToolFacts {
                    server: "records".into(),
                    name: "read".into(),
                    risk: RiskTier::Low,
                    side_effects: false,
                    pii: false,
                    requires_approval: false,
                    requires_approval_known: true,
                },
                Uuid::nil(),
                "classification-only".into(),
                Some(json!({"type":"object"})),
                None,
            )
            .with_published_definition(Some(tool))
        };
        let first = snapshot("string");
        let second = snapshot("integer");
        let contract =
            connector_contract_with_authorization("records", "read", &first, None).unwrap();
        assert!(contract.output_schema.is_some());
        assert!(first.output_schema().is_none());
        let before = serde_json::to_value(identity(&first)).unwrap();
        let after = serde_json::to_value(identity(&second)).unwrap();
        assert_ne!(before["output_schema_hash"], after["output_schema_hash"]);
        assert_eq!(before["catalog_schema_hash"], after["catalog_schema_hash"]);
    }

    #[tokio::test]
    async fn delegated_profile_keeps_facade_visible_and_filters_its_results() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[
            ("email", "read", false),
            ("weather", "forecast", false),
        ]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let server = GatewayServer::with_authz(catalog.clone(), authz.clone())
            .with_builtin_tools(Arc::new(code_mode_tools(catalog, authz)));
        let mut principal = reader();
        principal.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
            profile_id: "email-only".to_owned(),
            profile_name: "Email only".to_owned(),
            allowed_servers: Some(vec!["email".to_owned()]),
            allowed_tools: None,
        });

        let visible: Vec<String> = server
            .list_visible_tools(Some(&principal))
            .await
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(visible.contains(&"codemode.search".to_owned()));
        assert!(visible.contains(&"codemode.describe".to_owned()));
        assert!(!visible.contains(&"codemode.execute".to_owned()));
        assert!(visible.contains(&"email.searchTools".to_owned()));
        assert!(!visible.contains(&"weather.searchTools".to_owned()));

        let result = server
            .dispatch_tool_call(call("codemode.search", json!({})), Some(&principal))
            .await
            .expect("delegated facade is reachable");
        let names: Vec<&str> = structured(&result)["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["email.read"]);
    }

    #[tokio::test]
    async fn execute_visibility_and_dispatch_requires_invoke_scope() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[("email", "read", false)]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let execution_store: SharedExecutionStore = Arc::new(RecordingExecutionStore::default());
        let invocation = Arc::new(DefaultInvocationService::new(
            catalog.clone(),
            authz.clone(),
            Arc::new(NullSink),
        ));
        let server =
            GatewayServer::with_authz(catalog.clone(), authz.clone()).with_builtin_tools(Arc::new(
                CodeModeTools::new(catalog, authz, invocation)
                    .with_execution_store(execution_store)
                    .with_result_persistence_allowed(true),
            ));
        let reader = reader();

        let error = server
            .dispatch_tool_call(call("codemode.execute", json!({})), Some(&reader))
            .await
            .expect_err("discovery-only scope must not execute programs");
        assert_eq!(
            error.data.as_ref().unwrap()["required_scope"],
            Scope::McpInvoke.as_str()
        );
        let mut invoker = reader;
        invoker.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let visible: Vec<String> = server
            .list_visible_tools(Some(&invoker))
            .await
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(visible.contains(&"codemode.execute".to_owned()));
        let mutation_error = server
            .dispatch_tool_call(call("codemode.execute", json!({})), Some(&invoker))
            .await
            .expect_err("real mutation dispatch validates its source after authorization");
        assert_eq!(
            mutation_error.data.as_ref().unwrap()["error"],
            "invalid_source_selector"
        );
    }

    #[tokio::test]
    async fn search_cursor_follows_global_fully_qualified_order() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[
            ("a", "read", false),
            ("a-z", "read", false),
        ]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let server = GatewayServer::with_authz(catalog.clone(), authz.clone())
            .with_builtin_tools(Arc::new(code_mode_tools(catalog, authz)));
        let principal = reader();

        let first = server
            .dispatch_tool_call(
                call("codemode.search", json!({"limit": 1})),
                Some(&principal),
            )
            .await
            .expect("first page");
        assert_eq!(structured(&first)["tools"][0]["name"], "a-z.read");
        let cursor = structured(&first)["next_cursor"]
            .as_str()
            .expect("next cursor")
            .to_owned();

        let second = server
            .dispatch_tool_call(
                call("codemode.search", json!({"limit": 1, "cursor": cursor})),
                Some(&principal),
            )
            .await
            .expect("second page");
        assert_eq!(structured(&second)["tools"][0]["name"], "a.read");
        assert!(structured(&second).get("next_cursor").is_none());
    }

    #[test]
    fn search_cursor_is_bound_to_principal_query_and_exact_view() {
        let sealer = crate::mcp_discovery::DiscoveryCursorSealer::process_local();
        let principal = crate::mcp_discovery::principal_binding(&reader()).expect("principal");
        let query = crate::mcp_discovery::digest_field(b"codemode-search-query-v2\0", b"email");
        let cursor = search_cursor(1, &principal, &query, "view-a", &sealer).expect("cursor");

        assert_eq!(
            search_cursor_offset(Some(&cursor), &principal, &query, "view-a", 2, &sealer,)
                .expect("matching cursor"),
            1,
        );
        assert!(search_cursor_offset(
            Some(&cursor),
            &principal,
            "different-query",
            "view-a",
            2,
            &sealer,
        )
        .is_err());
        assert!(search_cursor_offset(
            Some(&cursor),
            "different-principal",
            &query,
            "view-a",
            2,
            &sealer,
        )
        .is_err());
        assert!(
            search_cursor_offset(Some(&cursor), &principal, &query, "view-b", 2, &sealer,).is_err()
        );
    }

    #[tokio::test]
    async fn search_cursor_rejects_when_the_authorized_view_changes() {
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let principal = reader();
        let sealer = Arc::new(crate::mcp_discovery::DiscoveryCursorSealer::process_local());
        let original_catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[
            ("a", "read", false),
            ("b", "read", false),
            ("c", "read", false),
        ]));
        let original = code_mode_tools(original_catalog, authz.clone())
            .with_search_cursor_sealer(sealer.clone());
        let first = original
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: None,
                    limit: Some(1),
                },
            )
            .await
            .expect("first page");
        let cursor = structured(&first)["next_cursor"]
            .as_str()
            .expect("next cursor")
            .to_owned();

        let changed_catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[
            ("b", "read", false),
            ("c", "read", false),
        ]));
        let changed = code_mode_tools(changed_catalog, authz).with_search_cursor_sealer(sealer);
        let error = changed
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: Some(cursor),
                    limit: Some(1),
                },
            )
            .await
            .expect_err("catalog removal invalidates the prior view");

        assert!(error.message.contains("next_cursor"));
    }

    #[tokio::test]
    async fn search_cursor_rejects_when_the_invocation_snapshot_changes() {
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let principal = reader();
        let sealer = Arc::new(crate::mcp_discovery::DiscoveryCursorSealer::process_local());
        let original_fake = FakeCatalog::with_tools(&[
            ("a", "read", false),
            ("b", "read", false),
            ("c", "read", false),
        ]);
        let mut changed_fake = original_fake.clone();
        changed_fake.refine_operations("b", "read", "mailbox", &["inbox", "archive"]);
        let original = code_mode_tools(Arc::new(original_fake), authz.clone())
            .with_search_cursor_sealer(sealer.clone());
        let first = original
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: None,
                    limit: Some(1),
                },
            )
            .await
            .expect("first page");
        let cursor = structured(&first)["next_cursor"]
            .as_str()
            .expect("next cursor")
            .to_owned();

        let changed =
            code_mode_tools(Arc::new(changed_fake), authz).with_search_cursor_sealer(sealer);
        let error = changed
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: Some(cursor),
                    limit: Some(1),
                },
            )
            .await
            .expect_err("operation-classification change invalidates the prior view");

        assert!(error.message.contains("next_cursor"));
    }

    #[tokio::test]
    async fn longest_admitted_selector_emits_a_reusable_cursor() {
        let server = "a".repeat(MAX_SELECTOR_LENGTH / 2);
        let tool = "b".repeat(MAX_SELECTOR_LENGTH / 2);
        let fake = FakeCatalog::with_tools(&[(&server, &tool, false), ("z", "read", false)]);
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let principal = reader();
        let first = tools
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: None,
                    limit: Some(1),
                },
            )
            .await
            .expect("first page");
        let cursor = structured(&first)["next_cursor"]
            .as_str()
            .expect("next cursor")
            .to_owned();
        assert!(cursor.len() <= MAX_CURSOR_LENGTH);

        let second = tools
            .search(
                &principal,
                SearchParams {
                    query: None,
                    cursor: Some(cursor),
                    limit: Some(1),
                },
            )
            .await
            .expect("emitted cursor is accepted");
        assert_eq!(structured(&second)["tools"][0]["name"], "z.read");
    }

    #[tokio::test]
    async fn describe_is_hermetic_for_unknown_denied_and_quarantined_tools() {
        let mut fake =
            FakeCatalog::with_tools(&[("email", "hidden", false), ("email", "quarantined", false)]);
        fake.quarantine("email", "quarantined");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let server = GatewayServer::with_authz(catalog.clone(), authz.clone())
            .with_builtin_tools(Arc::new(code_mode_tools(catalog, authz)));
        let principal = reader();

        let mut messages = Vec::new();
        for name in ["email.unknown", "email.hidden", "email.quarantined"] {
            let error = server
                .dispatch_tool_call(
                    call("codemode.describe", json!({"name": name})),
                    Some(&principal),
                )
                .await
                .expect_err("unavailable tool must be hidden");
            messages.push((error.code, error.message));
        }
        assert!(messages
            .windows(2)
            .all(|pair| pair[0].0 == pair[1].0 && pair[0].1 == pair[1].1));
    }

    #[tokio::test]
    async fn manifest_fallback_identity_cannot_be_mistaken_for_catalog_authority() {
        let mut fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        fake.use_manifest_fallback("email", "read");
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let server = GatewayServer::with_authz(catalog.clone(), authz.clone())
            .with_builtin_tools(Arc::new(code_mode_tools(catalog, authz)));

        let result = server
            .dispatch_tool_call(
                call("codemode.describe", json!({"name": "email.read"})),
                Some(&reader()),
            )
            .await
            .expect("manifest-backed tool is describable");
        let described = structured(&result);
        assert_eq!(described["identity"]["authority"], "manifest_fallback");
        assert!(described["identity"]["input_schema_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()));
        assert_eq!(described["identity"]["approval_requirements_known"], false);
        assert_eq!(described["governance"]["requires_approval_known"], false);
        assert!(described["identity"]["output_schema_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()));
        assert_eq!(
            described["output_schema"]["anyOf"][0]["required"][0],
            "result"
        );
    }

    #[tokio::test]
    async fn advertised_output_schemas_validate_real_results() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[("email", "read", false)]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let server = GatewayServer::with_authz(catalog.clone(), authz.clone())
            .with_builtin_tools(Arc::new(code_mode_tools(catalog, authz)));
        let principal = reader();

        for (name, args) in [
            ("codemode.limits", json!({})),
            ("codemode.search", json!({})),
            ("codemode.describe", json!({"name": "email.read"})),
        ] {
            let definition = tool_defs()
                .into_iter()
                .find(|tool| tool.name == name)
                .expect("tool definition");
            assert_eq!(
                definition
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.read_only_hint),
                Some(true)
            );
            let result = server
                .dispatch_tool_call(call(name, args), Some(&principal))
                .await
                .expect("tool call succeeds");
            let schema = Value::Object(
                definition
                    .output_schema
                    .as_ref()
                    .expect("output schema")
                    .as_ref()
                    .clone(),
            );
            let validator = jsonschema::validator_for(&schema).expect("schema compiles");
            let errors: Vec<String> = validator
                .iter_errors(structured(&result))
                .map(|error| error.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "{name} result violates schema: {errors:?}"
            );
        }

        let sample = super::structured(&ExecuteResponse {
            contract_version: ContractVersion::V1,
            sdk_contract_version: SdkContractVersion::V4,
            runner_contract_version: RunnerContractVersion::V7,
            execution_id: uuid::Uuid::now_v7(),
            source_ref: SourceReference {
                sha256: source_digest("return null;"),
                expires_at: None,
                retention_state: SourceRetentionState::NotRetained,
            },
            status: ExecutionResponseStatus::Completed,
            result: json!({"derived": true}),
            checkpoint: None,
            approval: None,
            connector_calls: 2,
            result_ref: Some(ExecutionResultReference {
                execution_id: uuid::Uuid::now_v7(),
            }),
            artifacts: Vec::new(),
        });
        assert_eq!(structured(&sample)["sdk_contract_version"], "4");
        assert_eq!(structured(&sample)["runner_contract_version"], "7");
        for name in ["codemode.execute", "codemode.resume"] {
            let definition = tool_defs()
                .into_iter()
                .find(|tool| tool.name == name)
                .expect("execution definition");
            let schema = Value::Object(
                definition
                    .output_schema
                    .as_ref()
                    .expect("output schema")
                    .as_ref()
                    .clone(),
            );
            let validator = jsonschema::validator_for(&schema).expect("schema compiles");
            let errors: Vec<String> = validator
                .iter_errors(structured(&sample))
                .map(|error| error.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "{name} sample violates schema: {errors:?}"
            );
        }
    }

    #[test]
    fn surface_descriptor_matches_the_wire_tools() {
        let descriptor = surface_descriptor();
        assert_eq!(descriptor.namespace, NAMESPACE);
        assert_eq!(descriptor.required_scope, Scope::McpInvoke.as_str());
        assert_eq!(descriptor.tools.len(), tool_defs().len());
        for tool in descriptor.tools {
            match tool.name.as_str() {
                // These operations can reach whatever direct tool the caller
                // is authorized to invoke, including external effects.
                "execute" | "start" => {
                    assert!(tool.side_effects);
                    assert_eq!(tool.risk, RiskTier::High);
                }
                // Cancellation writes durable execution state and can stop work
                // already in flight, so it is not side-effect free — but it acts
                // only on this gateway's own execution, never on an upstream, so
                // it does not carry the mutation tools' risk. Classifying it as
                // read-only would have the governance inventory disagree with
                // its wire annotation about whether it changes anything.
                "cancel" => {
                    assert!(tool.side_effects);
                    assert_eq!(tool.risk, RiskTier::Medium);
                }
                // A detached start leaves durable work running with no caller
                // attached, which the blocking tool never does, so the
                // inventory records it as changing something rather than as a
                // read.
                "start_resume" => {
                    assert!(tool.side_effects);
                    assert_eq!(tool.risk, RiskTier::Medium);
                }
                _ => {
                    assert!(!tool.side_effects, "{} claims side effects", tool.name);
                    assert_eq!(tool.risk, RiskTier::Low);
                }
            }
        }
    }

    #[test]
    fn unscoped_call_teaches_the_required_capability() {
        let error = insufficient_scope(Scope::McpRead.as_str());
        assert!(error.message.contains(Scope::McpRead.as_str()));
        assert_eq!(
            error.data.as_ref().unwrap()["required_scope"],
            Scope::McpRead.as_str()
        );
    }

    #[test]
    fn execute_source_schema_exposes_all_product_inputs() {
        let definition = tool_defs()
            .into_iter()
            .find(|tool| tool.name == "codemode.execute")
            .expect("execute tool");
        let schema = Value::Object(definition.input_schema.as_ref().clone());
        assert_eq!(schema["type"], "object");
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        assert!(!validator.is_valid(&json!({"source": " \n\t"})));
        assert!(validator.is_valid(&json!({
            "source_file": "mcp-file://gateway/019c-test",
            "retain_for_seconds": 3600
        })));
        assert!(validator.is_valid(&json!({"source_sha256": "a".repeat(64)})));
        assert!(validator.is_valid(&json!({
            "skill_script": "skill://homelab/pr-and-monitor/scripts/pr-wait.js"
        })));
        assert!(waygate_mcp::files::schema_declares_file_inputs(&schema));
        // The source forms are mutually exclusive, but the schema cannot say so
        // at its root without becoming unregisterable, so it publishes them as
        // independent optional properties and `select_source` owns the
        // exclusion. Both halves are asserted: the schema admits the
        // combinations, and the resolver refuses them.
        assert!(
            waygate_mcp::tool_schema::root_composition_keyword(&definition.input_schema).is_none()
        );
        assert!(validator.is_valid(&json!({
            "source": "return 1;",
            "source_sha256": "a".repeat(64)
        })));

        let multibyte = format!("/*{}*/", "é".repeat((limits().source_bytes - 4) / 2));
        assert_eq!(multibyte.len(), limits().source_bytes);
        assert!(validator.is_valid(&json!({"source": multibyte})));
        assert!(validate_source(&multibyte).is_ok());

        let over_limit = format!("{multibyte}x");
        // JSON Schema counts characters; admission enforces the advertised UTF-8 byte limit.
        assert!(validator.is_valid(&json!({"source": over_limit})));
        assert!(validate_source(&over_limit).is_err());
    }

    #[test]
    fn skill_script_is_advertised_for_every_source_tool() {
        let definitions = tool_defs();
        for tool_name in ["codemode.execute", "codemode.start"] {
            let definition = definitions
                .iter()
                .find(|tool| tool.name == tool_name)
                .expect("read-only source tool");
            assert!(definition.input_schema["properties"]["skill_script"].is_object());
        }
    }

    #[test]
    fn source_selection_admits_exactly_one_form() {
        let digest = "a".repeat(64);
        let uri = "mcp-file://gateway/019c-test".to_string();

        assert!(matches!(
            select_source(Some("return 1;".into()), None, None, None, None, None, true),
            Ok((SourceSelector::Inline(_), None))
        ));
        assert!(matches!(
            select_source(None, Some(uri.clone()), None, None, None, Some(3600), true),
            Ok((SourceSelector::File(_), Some(3600)))
        ));
        assert!(matches!(
            select_source(None, None, Some(digest.clone()), None, None, None, true),
            Ok((SourceSelector::Retained(_), None))
        ));

        for (source, source_file, source_sha256) in [
            (None, None, None),
            (Some("return 1;".to_string()), None, Some(digest.clone())),
            (Some("return 1;".to_string()), Some(uri.clone()), None),
            (None, Some(uri), Some(digest.clone())),
        ] {
            let error = select_source(source, source_file, source_sha256, None, None, None, true)
                .expect_err("a request naming none or several source forms is refused");
            assert_eq!(
                error.data.as_ref().expect("structured error")["error"],
                "invalid_source_selector"
            );
        }

        let source_error = select_source(None, None, None, None, None, None, true)
            .expect_err("execution requires one source form");
        assert!(source_error.message.contains("`skill_script`"));

        // Resolving a retained artifact never extends its expiry, so a
        // retention request alongside one is refused rather than ignored.
        let error = select_source(None, None, Some(digest), None, None, Some(3600), true)
            .expect_err("retention alongside a retained digest is refused");
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "invalid_source_retention"
        );
    }

    #[tokio::test]
    async fn skill_script_source_needs_no_execution_grant_and_preserves_verified_bytes() {
        let script = b"return { issue: execution.input.issue };\n";
        let (catalog, loads) = skill_script_catalog_with_load_count(script, None).await;
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(waygate_mcp::AllowAllGate),
        )
        .with_skill_script_execution(Some(catalog.clone()));
        let reviews = Arc::new(waygate_test_support::skills::SkillReviewFixture::default());
        let snapshot = catalog.current().unwrap();
        reviews.approve(reader().tenant.as_str(), &snapshot);
        let tools = tools.with_reviewed_skills(Some(
            waygate_test_support::skills::reviewed_catalog(catalog, reviews.clone()),
        ));
        let uri = "skill://homelab/pr-and-monitor/scripts/pr-wait.js";

        let resolved = tools
            .resolve_source(
                &reader(),
                SourceSelector::SkillScript(uri.into(), None),
                None,
            )
            .await
            .expect("the script is admitted without a separate execution grant");
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert_eq!(resolved.source.as_bytes(), script);
        assert_eq!(
            resolved.digest,
            source_digest(std::str::from_utf8(script).unwrap())
        );
        let authority = resolved.source_authority.expect("skill authority");
        let revision = snapshot.revision_identity(uri).unwrap();
        let descriptor = snapshot.resource(uri).unwrap();
        let persisted_authority = json!({
            "kind": "skill_script",
            "source_origin": revision.source_origin,
            "artifact_digest": revision.artifact_digest,
            "source_tree_digest": revision.source_tree_digest,
            "skill_uri": revision.skill_uri,
            "revision_digest": revision.revision_digest,
            "approval_digest": revision.legacy_script_execution_digest(),
            "resource_uri": uri,
            "source_path": descriptor.source_path,
            "source_object": descriptor.source_object,
            "resource_digest": format!("sha256:{}", resolved.digest),
            "execution_profile": "direct",
        });
        assert_eq!(authority, persisted_authority);
        assert_eq!(
            detached_start_dedupe_key(&reader(), &resolved.digest, &Value::Null, Some(&authority)),
            detached_start_dedupe_key(
                &reader(),
                &resolved.digest,
                &Value::Null,
                Some(&persisted_authority)
            ),
        );
        let root = &snapshot.skills()[0].uri;
        let candidate =
            waygate_skills::review::ReviewCandidate::from_snapshot(&snapshot, root).unwrap();
        reviews.quarantine(reader().tenant.as_str(), &candidate.source_key(), root);
        assert!(tools
            .resolve_source(
                &reader(),
                SourceSelector::SkillScript(uri.into(), None),
                None
            )
            .await
            .is_err());
        assert_eq!(
            loads.load(Ordering::SeqCst),
            1,
            "distribution quarantine blocks further source reads"
        );
    }

    #[tokio::test]
    async fn skill_revision_pin_never_substitutes_current_source() {
        let (old_catalog, _) = skill_script_catalog_with_load_count(b"return 1;", None).await;
        let old_revision = old_catalog.current().unwrap().revision().to_owned();
        let (catalog, loads) = skill_script_catalog_with_load_count(b"return 2;", None).await;
        let current = catalog.current().unwrap();
        assert_ne!(old_revision, current.revision());
        let reviews = Arc::new(waygate_test_support::skills::SkillReviewFixture::default());
        reviews.approve(reader().tenant.as_str(), &current);
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(waygate_mcp::AllowAllGate),
        )
        .with_skill_script_execution(Some(catalog.clone()))
        .with_reviewed_skills(Some(waygate_test_support::skills::reviewed_catalog(
            catalog, reviews,
        )));
        let uri = "skill://homelab/pr-and-monitor/scripts/pr-wait.js";
        let params: StartParams = serde_json::from_value(json!({
            "skill_script": uri, "skill_revision": old_revision,
        }))
        .unwrap();
        let (selector, retention, _, _) = params.into_parts().unwrap();
        assert!(tools
            .resolve_source(&reader(), selector, retention)
            .await
            .is_err());
        assert_eq!(loads.load(Ordering::SeqCst), 0);

        for revision in [Some(current.revision()), None] {
            let params: StartParams = serde_json::from_value(json!({
                "skill_script": uri, "skill_revision": revision,
            }))
            .unwrap();
            let (selector, retention, _, _) = params.into_parts().unwrap();
            let source = tools
                .resolve_source(&reader(), selector, retention)
                .await
                .unwrap();
            assert_eq!(source.source, "return 2;");
        }
        let unrelated: StartParams = serde_json::from_value(json!({
            "source": "return 2;", "skill_revision": current.revision(),
        }))
        .unwrap();
        assert!(unrelated.into_parts().is_err());
    }

    #[tokio::test]
    async fn oversized_skill_source_is_refused_before_download() {
        let script = vec![b' '; limits().source_bytes + 1];
        let (catalog, loads) = skill_script_catalog_with_load_count(&script, None).await;
        let reviews = Arc::new(waygate_test_support::skills::SkillReviewFixture::default());
        reviews.approve(reader().tenant.as_str(), &catalog.current().unwrap());
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(waygate_mcp::AllowAllGate),
        )
        .with_skill_script_execution(Some(catalog.clone()))
        .with_reviewed_skills(Some(waygate_test_support::skills::reviewed_catalog(
            catalog, reviews,
        )));
        let error = tools
            .resolve_source(
                &reader(),
                SourceSelector::SkillScript(
                    "skill://homelab/pr-and-monitor/scripts/pr-wait.js".into(),
                    None,
                ),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.data.as_ref().unwrap()["error"], "source_too_large");
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn skill_source_requires_principal_resource_access_and_audits_decisions() {
        for scenario in [
            "profile-server",
            "profile-tool",
            "fetch",
            "read",
            "step-up",
            "approval",
            "allow",
        ] {
            let (catalog, loads) = skill_script_catalog_with_load_count(b"return 42;", None).await;
            let reviews = Arc::new(waygate_test_support::skills::SkillReviewFixture::default());
            let mut principal = reader();
            reviews.approve(principal.tenant.as_str(), &catalog.current().unwrap());
            if scenario.starts_with("profile-") {
                principal.api_key_profile_restrictions =
                    Some(waygate_oidc::ApiKeyProfileRestrictions {
                        profile_id: "tools-only".into(),
                        profile_name: "tools only".into(),
                        allowed_servers: (scenario == "profile-server")
                            .then(|| vec!["codemode".into()]),
                        allowed_tools: (scenario == "profile-tool")
                            .then(|| vec!["codemode.execute".into()]),
                    });
            }
            let read = match scenario {
                "read" => AuthzVerdict::Deny {
                    reason: "skill read denied".into(),
                    policy_ids: vec!["skill-read".into()],
                    reasons: vec![],
                },
                "step-up" => AuthzVerdict::StepUpRequired {
                    required_scope: "mcp:elevated".into(),
                    reason: "elevation required".into(),
                    policy_ids: vec!["skill-read".into()],
                },
                "approval" => AuthzVerdict::ApprovalRequired {
                    reason: "approval required".into(),
                    policy_ids: vec!["skill-read".into()],
                },
                _ => AuthzVerdict::Allow {
                    policy_ids: vec!["skill-read".into()],
                },
            };
            let audit = Arc::new(RecordingEvidence::default());
            let tools = code_mode_tools(
                Arc::new(FakeCatalog::with_tools(&[])),
                Arc::new(SkillAccessGate {
                    allow_fetch: scenario != "fetch",
                    read,
                }),
            )
            .with_skill_script_execution(Some(catalog.clone()))
            .with_reviewed_skills(Some(waygate_test_support::skills::reviewed_catalog(
                catalog, reviews,
            )))
            .with_audit(audit.clone());
            let resolved = tools
                .resolve_source(
                    &principal,
                    SourceSelector::SkillScript(
                        "skill://homelab/pr-and-monitor/scripts/pr-wait.js".into(),
                        None,
                    ),
                    None,
                )
                .await;
            assert_eq!(resolved.is_ok(), scenario == "allow", "{scenario}");
            let fetched = !scenario.starts_with("profile-") && scenario != "fetch";
            assert_eq!(
                loads.load(Ordering::SeqCst),
                usize::from(fetched),
                "{scenario}"
            );
            let events = audit.snapshot().await;
            let fetch = events
                .iter()
                .find(|event| event.action == "FetchSkillResource")
                .unwrap();
            assert_eq!(
                fetch.outcome,
                if fetched {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Denied
                }
            );
            if scenario.starts_with("profile-") {
                assert_eq!(
                    fetch.reason.as_deref(),
                    Some(waygate_core::SKILL_PROFILE_REFUSAL_REASON)
                );
            }
            let read = events.iter().find(|event| event.action == "ReadSkill");
            assert_eq!(read.is_some(), fetched);
            if let Some(read) = read {
                assert_eq!(read.policy_ids, vec!["skill-read"]);
                assert_eq!(
                    read.outcome,
                    match scenario {
                        "allow" => AuditOutcome::Success,
                        "step-up" => AuditOutcome::StepUpRequired,
                        _ => AuditOutcome::Denied,
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn execute_refuses_skill_downloads_when_quota_or_capacity_is_exhausted() {
        for refusal in [
            "rate_limited",
            "tenant_execution_capacity",
            "execution_capacity",
        ] {
            let (catalog, loads) =
                skill_script_catalog_with_load_count(b"return execution.input;", None).await;
            let reviews = Arc::new(waygate_test_support::skills::SkillReviewFixture::default());
            reviews.approve(reader().tenant.as_str(), &catalog.current().unwrap());
            let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
                per_tenant: if refusal == "tenant_execution_capacity" {
                    0
                } else {
                    1
                },
                global: if refusal == "execution_capacity" {
                    0
                } else {
                    1
                },
                detached: 1,
            }));
            let mut tools = code_mode_tools(
                Arc::new(FakeCatalog::with_tools(&[])),
                Arc::new(SelectiveAuthz),
            )
            .with_skill_script_execution(Some(catalog.clone()))
            .with_reviewed_skills(Some(waygate_test_support::skills::reviewed_catalog(
                catalog, reviews,
            )))
            .with_execution_capacity(capacity);
            if refusal == "rate_limited" {
                tools = tools.with_quota(Some(Arc::new(DenyExecutionQuota("execute"))));
            }
            let params = serde_json::from_value(json!({
                "skill_script": "skill://homelab/pr-and-monitor/scripts/pr-wait.js"
            }))
            .unwrap();
            let error = tools.execute(&reader(), params).await.unwrap_err();
            assert_eq!(error.data.as_ref().unwrap()["error"], refusal);
            assert_eq!(loads.load(Ordering::SeqCst), 0, "{refusal}");
        }
    }

    #[tokio::test]
    async fn skill_uri_resolution_ignores_compatibility_metadata() {
        let script = b"return execution.input;";
        let uri = "skill://homelab/pr-and-monitor/scripts/pr-wait.js";
        for metadata in [
            None,
            Some(r#"{"version":2,"scripts":{"scripts/pr-wait.js":true}}"#),
            Some(r#"{"version":2,"scripts":{"scripts/pr-wait.js":false}}"#),
            Some(r#"{"version":2,"scripts":{"scripts/other.js":true}}"#),
            Some(r#"{"version":1,"scripts":{"scripts/pr-wait.js":"read_only"}}"#),
            Some(r#"{"version":1,"scripts":{"scripts/pr-wait.js":"direct"}}"#),
            Some(r#"{"version":99,"scripts":{"scripts/pr-wait.js":true}}"#),
            Some("invalid JSON"),
            Some("false"),
            Some("no"),
            Some("disabled"),
        ] {
            let (catalog, loads) = skill_script_catalog_with_load_count(script, metadata).await;
            let reviews = Arc::new(waygate_test_support::skills::SkillReviewFixture::default());
            reviews.approve(reader().tenant.as_str(), &catalog.current().unwrap());
            let tools = code_mode_tools(
                Arc::new(FakeCatalog::with_tools(&[])),
                Arc::new(waygate_mcp::AllowAllGate),
            )
            .with_skill_script_execution(Some(catalog.clone()))
            .with_reviewed_skills(Some(
                waygate_test_support::skills::reviewed_catalog(catalog, reviews),
            ));
            let params: StartParams = serde_json::from_value(json!({
                "skill_script": uri, "input": {"issue": 42}, "retain_for_seconds": 3600
            }))
            .unwrap();
            let (selector, retention, _, input) = params.into_parts().unwrap();
            let resolved = tools
                .resolve_source(&reader(), selector, retention)
                .await
                .unwrap();
            let inline = tools
                .resolve_source(
                    &reader(),
                    SourceSelector::Inline(String::from_utf8(script.to_vec()).unwrap()),
                    retention,
                )
                .await
                .unwrap();
            assert_eq!(resolved.source, inline.source, "metadata: {metadata:?}");
            assert_eq!(resolved.digest, inline.digest);
            assert_eq!(resolved.retention, inline.retention);
            assert_eq!(input, json!({"issue": 42}));
            assert_eq!(loads.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn skill_script_supports_retention_but_cannot_be_combined_with_other_source_forms() {
        let uri = "skill://homelab/pr-and-monitor/scripts/pr-wait.js".to_owned();
        let (selector, retention) =
            select_source(None, None, None, Some(uri.clone()), None, Some(3600), true)
                .expect("skill source uses ordinary retention");
        assert!(matches!(selector, SourceSelector::SkillScript(selected, None) if selected == uri));
        assert_eq!(retention, Some(3600));
        let combined = select_source(
            Some("return 1;".into()),
            None,
            None,
            Some(uri),
            None,
            None,
            true,
        )
        .expect_err("skill script and inline source cannot be combined");
        assert_eq!(
            combined.data.as_ref().expect("structured error")["error"],
            "invalid_source_selector"
        );
    }

    #[tokio::test]
    async fn runner_frame_reader_classifies_closed_oversized_and_malformed_channels() {
        let mut closed = &b""[..];
        assert_eq!(
            read_runner_frame(&mut closed).await.unwrap_err(),
            RunnerFrameReadFailure::Closed
        );

        let oversized = vec![b'x'; limits().frame_bytes + 1];
        let mut oversized = oversized.as_slice();
        assert_eq!(
            read_runner_frame(&mut oversized).await.unwrap_err(),
            RunnerFrameReadFailure::TooLarge
        );

        let mut unterminated = &b"{}"[..];
        assert_eq!(
            read_runner_frame(&mut unterminated).await.unwrap_err(),
            RunnerFrameReadFailure::Unterminated
        );

        let mut malformed = &b"{not-json}\n"[..];
        assert_eq!(
            read_runner_frame(&mut malformed).await.unwrap_err(),
            RunnerFrameReadFailure::Malformed
        );
    }

    #[test]
    fn runner_failures_have_stable_machine_readable_codes() {
        for (failure, expected) in [
            (RunnerFrameReadFailure::Closed, "runner_crashed"),
            (RunnerFrameReadFailure::TooLarge, "runner_frame_too_large"),
            (
                RunnerFrameReadFailure::Unterminated,
                "runner_frame_unterminated",
            ),
            (RunnerFrameReadFailure::Malformed, "runner_frame_malformed"),
            (RunnerFrameReadFailure::Transport, "runner_transport_error"),
        ] {
            assert_eq!(
                runner_frame_failure(failure).data.unwrap()["error"],
                expected
            );
        }

        for (failure, expected) in [
            (RunnerFailureCode::ExecutionTimeout, "execution_timeout"),
            (RunnerFailureCode::ProgramFailed, "execution_failed"),
            (
                RunnerFailureCode::ConnectorResultTooLarge,
                "connector_result_too_large",
            ),
            (
                RunnerFailureCode::ResultTooLarge,
                "execution_result_too_large",
            ),
            (
                RunnerFailureCode::ResultNotJson,
                "execution_result_not_json",
            ),
            (
                RunnerFailureCode::ArtifactTooLarge,
                "execution_artifact_too_large",
            ),
            (RunnerFailureCode::RunnerInternal, "runner_failed"),
        ] {
            assert_eq!(
                runner_reported_failure(failure, "connector refused the call")
                    .data
                    .unwrap()["error"],
                expected
            );
        }
        let program_error =
            runner_reported_failure(RunnerFailureCode::ProgramFailed, "connector returned PII");
        assert_eq!(program_error.message, "connector returned PII");
        assert_eq!(
            execution_failure_code(&program_error),
            "execution_failed",
            "the caller gets useful detail while the journal gets only a stable code",
        );
        for code in [
            "tenant_execution_capacity",
            "detached_execution_capacity",
            "execution_capacity",
            "execution_unavailable",
            "execution_timeout",
            "execution_result_too_large",
            "execution_result_not_json",
            "runner_failed",
            "runner_frame_too_large",
            "runner_frame_unterminated",
            "runner_frame_malformed",
            "runner_crashed",
            "runner_protocol_error",
            "runner_transport_error",
        ] {
            let error = McpError::invalid_request("caller detail", Some(json!({"error": code})));
            assert_eq!(execution_failure_code(&error), code);
        }
        let content_derived_code = McpError::invalid_request(
            "connector returned PII",
            Some(json!({"error": "customer@example.com"})),
        );
        assert_eq!(
            execution_failure_code(&content_derived_code),
            "execution_failed",
            "unknown error identifiers cannot become journal content",
        );
        let oversized_message = "é".repeat(MAX_FAILURE_MESSAGE_CHARS + 1);
        assert_eq!(
            runner_reported_failure(RunnerFailureCode::ProgramFailed, &oversized_message)
                .message
                .chars()
                .count(),
            MAX_FAILURE_MESSAGE_CHARS
        );
    }

    #[test]
    fn readiness_rejects_every_out_of_phase_frame_as_a_protocol_failure() {
        assert!(validate_runner_ready(RunnerFrame::Ready {
            confinement_profile: CONFINEMENT_PROFILE.to_owned(),
        })
        .is_ok());

        for frame in [
            RunnerFrame::Ready {
                confinement_profile: "unknown-profile".to_owned(),
            },
            RunnerFrame::Call {
                id: 1,
                call_id: "opaque".to_owned(),
                arguments: Value::Null,
            },
            RunnerFrame::Complete {
                result: Value::Null,
            },
            RunnerFrame::Pause {
                checkpoint: serde_json::json!({}),
            },
            RunnerFrame::Failed {
                code: RunnerFailureCode::RunnerInternal,
                message: "failed before readiness".to_owned(),
            },
        ] {
            assert_eq!(
                validate_runner_ready(frame).unwrap_err().data.unwrap()["error"],
                "runner_protocol_error"
            );
        }
    }

    #[test]
    fn execution_capacity_is_isolated_per_tenant() {
        let capacity = CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 4,
            per_tenant: 2,
            detached: 2,
        });
        let tenant_a = format!("tenant-a-{}", Uuid::new_v4());
        let tenant_b = format!("tenant-b-{}", Uuid::new_v4());
        let capacity_a = capacity.tenant(&tenant_a);
        let capacity_b = capacity.tenant(&tenant_b);

        let _a1 = capacity_a
            .clone()
            .try_acquire_owned()
            .expect("tenant A slot");
        let _a2 = capacity_a
            .clone()
            .try_acquire_owned()
            .expect("tenant A slot");
        assert!(capacity_a.try_acquire_owned().is_err());
        assert!(capacity_b.try_acquire_owned().is_ok());
    }

    #[test]
    fn global_execution_capacity_spans_tenants() {
        let capacity = CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 2,
            per_tenant: 2,
            detached: 1,
        });
        let mut tenant_a = reader();
        tenant_a.tenant = waygate_core::TenantId::parse("capacity-a").unwrap();
        let mut tenant_b = reader();
        tenant_b.tenant = waygate_core::TenantId::parse("capacity-b").unwrap();

        let _first = capacity.acquire_execution(&tenant_a).unwrap();
        let _second = capacity.acquire_execution(&tenant_b).unwrap();
        assert_eq!(
            capacity
                .acquire_execution(&tenant_b)
                .unwrap_err()
                .data
                .unwrap()["error"],
            "execution_capacity"
        );
    }

    #[tokio::test]
    async fn exhausted_detached_capacity_refuses_before_journal_or_catalog_work() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let observed = fake.clone();
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let execution_store = Arc::new(RecordingExecutionStore::default());
        let shared_store: SharedExecutionStore = execution_store.clone();
        let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 4,
            per_tenant: 4,
            detached: 1,
        }));
        let _held = capacity.acquire_detached().expect("hold detached slot");
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(shared_store)
            .with_result_persistence_allowed(true)
            .with_execution_capacity(capacity);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant =
            waygate_core::TenantId::parse(format!("detached-pressure-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = format!("issuer-{}", Uuid::new_v4());
        let error = tools
            .start_execution(&principal, start_source("return 1;"))
            .await
            .expect_err("exhausted detached capacity is refused");

        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "detached_execution_capacity"
        );
        assert!(
            execution_store.submitted.lock().await.is_none(),
            "detached admission happens before a durable row is submitted"
        );
        assert_eq!(
            observed.server_list_count(),
            0,
            "detached admission happens before catalog binding work"
        );
    }

    #[tokio::test]
    async fn execution_permit_wrapper_holds_every_permit_until_work_finishes() {
        let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 1,
            per_tenant: 1,
            detached: 1,
        }));
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_capacity(capacity.clone());
        let mut principal = reader();
        principal.tenant =
            waygate_core::TenantId::parse(format!("detached-lifecycle-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = format!("issuer-{}", Uuid::new_v4());
        let detached = tools
            .acquire_detached_execution_slot()
            .expect("detached slot");
        let (tenant, global) = capacity
            .acquire_execution(&principal)
            .expect("ordinary permits");
        let release = tokio::sync::Notify::new();
        let attempt = hold_execution_permits_until(
            ExecutionPermits {
                tenant,
                detached: Some(detached),
                global,
            },
            release.notified(),
        );
        tokio::pin!(attempt);

        tokio::select! {
            _ = &mut attempt => panic!("attempt cannot finish before release"),
            _ = tokio::task::yield_now() => {}
        }
        assert_eq!(
            capacity.acquire_detached().unwrap_err().data.unwrap()["error"],
            "detached_execution_capacity"
        );
        assert_eq!(
            capacity
                .acquire_execution(&principal)
                .unwrap_err()
                .data
                .unwrap()["error"],
            "tenant_execution_capacity"
        );

        release.notify_one();
        attempt.await;
        assert!(capacity.acquire_detached().is_ok());
        assert!(capacity.acquire_execution(&principal).is_ok());
    }

    #[tokio::test]
    async fn detached_start_holds_detached_and_ordinary_permits_through_runner_work() {
        let execution_store = Arc::new(RecordingExecutionStore::default());
        let shared_store: SharedExecutionStore = execution_store.clone();
        let barrier = Arc::new(AttemptBarrier::default());
        let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 2,
            per_tenant: 2,
            detached: 1,
        }));
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(shared_store)
        .with_result_persistence_allowed(true)
        .with_execution_capacity(capacity.clone())
        .with_attempt_barrier(barrier.clone());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant =
            waygate_core::TenantId::parse(format!("detached-production-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = format!("issuer-{}", Uuid::new_v4());

        tools
            .start_execution(&principal, start_source("return 1;"))
            .await
            .expect("start detached runner");
        tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
            .await
            .expect("run_claimed_program reached its attempt future");

        assert_eq!(capacity.detached.available_permits(), 0);
        let error = tools
            .start_execution(
                &principal,
                // A different program: an identical one would converge on
                // the running execution instead of probing the slot.
                start_source("return 2;"),
            )
            .await
            .expect_err("the active production runner keeps the detached slot");
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "detached_execution_capacity"
        );
        let tenant_capacity = capacity.tenant(principal.tenant.as_str());
        let remaining = tenant_capacity
            .clone()
            .try_acquire_owned()
            .expect("the tenant's other slot remains");
        assert!(
            tenant_capacity.try_acquire_owned().is_err(),
            "run_claimed_program retains its tenant permit during runner work"
        );
        drop(remaining);

        barrier.release.notify_one();
        for _ in 0..200 {
            if capacity.detached.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            capacity.detached.available_permits() == 1,
            "the detached slot releases after runner completion"
        );
    }

    #[tokio::test]
    async fn exhausted_tenant_capacity_refuses_before_journal_binding_or_source_retention() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let observed = fake.clone();
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let execution_store = Arc::new(RecordingExecutionStore::default());
        let shared_store: SharedExecutionStore = execution_store.clone();
        let source_store = Arc::new(MemorySourceArtifactStore::default());
        let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 4,
            per_tenant: 2,
            detached: 2,
        }));
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(shared_store)
            .with_source_artifact_store(source_store.clone())
            .with_execution_capacity(capacity.clone());
        let mut principal = reader();
        principal.tenant = waygate_core::TenantId::parse(format!("pressure-{}", Uuid::new_v4()))
            .expect("valid tenant");
        let tenant_capacity = capacity.tenant(principal.tenant.as_str());
        let _first = tenant_capacity
            .clone()
            .try_acquire_owned()
            .expect("first tenant slot");
        let _second = tenant_capacity
            .try_acquire_owned()
            .expect("second tenant slot");

        let error = tools
            .execute(
                &principal,
                StartParams {
                    input: None,
                    source: Some("return 1;".to_owned()),
                    source_file: None,
                    source_sha256: None,
                    skill_script: None,
                    skill_revision: None,
                    retain_for_seconds: Some(3600),
                    repeat_after: None,
                },
            )
            .await
            .expect_err("exhausted capacity is refused");

        assert_eq!(
            error.data.as_ref().unwrap()["error"],
            "tenant_execution_capacity"
        );
        assert!(error.data.as_ref().unwrap().get("execution_id").is_none());
        assert_eq!(
            observed.server_list_count(),
            0,
            "capacity must cover full-catalog binding admission"
        );
        assert!(execution_store.submitted.lock().await.is_none());
        assert!(
            execution_store
                .terminal_reason_codes
                .lock()
                .await
                .is_empty(),
            "there is no admitted execution to terminalize"
        );
        assert!(
            source_store.artifacts.lock().await.is_empty(),
            "capacity refusal must not create a retained source artifact"
        );
    }

    #[tokio::test]
    async fn execution_quota_refuses_before_journal_or_catalog_work() {
        let fake = FakeCatalog::with_tools(&[("email", "read", false)]);
        let observed = fake.clone();
        let catalog: SharedCatalog = Arc::new(fake);
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let execution_store = Arc::new(RecordingExecutionStore::default());
        let shared_store: SharedExecutionStore = execution_store.clone();
        let source_store = Arc::new(MemorySourceArtifactStore::default());
        let quota: Arc<dyn waygate_quota::QuotaService> = Arc::new(DenyExecutionQuota("execute"));
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(shared_store)
            .with_source_artifact_store(source_store.clone())
            .with_quota(Some(quota));

        let error = tools
            .execute(
                &reader(),
                StartParams {
                    input: None,
                    source: Some("return 1;".to_owned()),
                    source_file: None,
                    source_sha256: None,
                    skill_script: None,
                    skill_revision: None,
                    retain_for_seconds: Some(3600),
                    repeat_after: None,
                },
            )
            .await
            .expect_err("quota denial refuses execution");

        assert_eq!(error.data.as_ref().unwrap()["error"], "rate_limited");
        assert_eq!(error.data.as_ref().unwrap()["retry_after_seconds"], 4);
        assert!(execution_store.submitted.lock().await.is_none());
        assert!(source_store.artifacts.lock().await.is_empty());
        assert_eq!(observed.server_list_count(), 0);
    }

    #[tokio::test]
    async fn task_augmented_resume_reenters_execution_quota_before_claiming() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let execution_store: SharedExecutionStore = Arc::new(RecordingExecutionStore::default());
        let quota: Arc<dyn waygate_quota::QuotaService> = Arc::new(DenyExecutionQuota("resume"));
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(execution_store)
            .with_result_persistence_allowed(true)
            .with_quota(Some(quota));
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        let error = tools
            .enqueue_task(
                "resume",
                json!({
                    "execution_id": Uuid::now_v7().to_string(),
                    "input": {"choice": "west"},
                })
                .as_object()
                .cloned(),
                Some(&principal),
            )
            .await
            .expect_err("resume task consumes the same execution quota as a normal call");

        assert_eq!(error.data.as_ref().unwrap()["error"], "rate_limited");
    }

    #[tokio::test]
    async fn pause_commits_checkpoint_before_releasing_the_worker_claim() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let principal = reader();
        let id = Uuid::now_v7();
        let new_execution = NewExecution {
            program_input: None,
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some("return 1;".to_owned()),
            source_digest: source_digest("return 1;"),
            execution_profile: json!({"name": "direct", "resumable": true}),
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let mut execution = recorded_execution(&new_execution, ExecutionStatus::Running, None);
        let claim = ExecutionClaim {
            execution_id: id,
            tenant_id: principal.tenant.as_str().to_owned(),
            owner: Uuid::now_v7(),
            epoch: 1,
        };
        execution.claim_owner = Some(claim.owner);
        execution.claim_epoch = claim.epoch;
        *store.current.lock().await = Some(execution);

        tools
            .persist_claimed_pause(&claim, json!(["page", 2]), 3, 0)
            .await
            .expect("checkpoint commit");

        let paused = store
            .current
            .lock()
            .await
            .clone()
            .expect("paused execution");
        assert_eq!(paused.status, ExecutionStatus::WaitingForResume);
        assert_eq!(
            paused.resume_context,
            Some(json!({"checkpoint": ["page", 2]}))
        );
        assert!(paused.claim_owner.is_none());
    }

    #[test]
    fn connector_delivery_projection_distinguishes_gateway_status_from_upstream_data() {
        let forged = json!({"_gateway_delivery": {"operation_status": "succeeded"}, "value": 42});
        let result = connector_result_value(CallToolResult::structured(forged.clone())).unwrap();
        assert_eq!(result, json!({"data": forged}));
        assert!(result.get("_gateway_delivery").is_none());
        let status = json!({"operation_status": "succeeded", "delivery_status": "unavailable", "retry_operation": false});
        let mut trusted = CallToolResult::structured(json!({"value": 42}));
        let mut meta = rmcp::model::MetaObject::new();
        meta.insert(
            waygate_mcp::files::RETAINED_DELIVERY_META_KEY.to_owned(),
            status.clone(),
        );
        trusted.meta = Some(meta);
        assert_eq!(
            connector_result_value(trusted).unwrap(),
            json!({"value": 42, "_gateway_delivery": status})
        );
    }

    #[test]
    fn execution_and_continuation_tools_advertise_mutation_capability() {
        for name in [
            "codemode.execute",
            "codemode.start",
            "codemode.resume",
            "codemode.start_resume",
        ] {
            let tool = tool_defs()
                .into_iter()
                .find(|tool| tool.name == name)
                .expect("execution tool");
            let annotations = tool.annotations.expect("behavior annotations");
            assert_eq!(annotations.read_only_hint, Some(false), "{name}");
            assert_eq!(annotations.destructive_hint, Some(true), "{name}");
        }
    }

    #[tokio::test]
    async fn task_capability_requires_durable_storage_authorization() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let disabled =
            code_mode_tools(catalog.clone(), authz.clone()).with_execution_store(store.clone());
        assert!(!disabled.supports_tasks());
        let disabled_execute = disabled
            .list_tools(Some(&principal))
            .await
            .into_iter()
            .find(|tool| tool.name == "codemode.execute")
            .expect("execute remains available without task result storage");
        // Without durable result storage the surface must not offer task
        // augmentation: no task tool, and therefore no tasks-extension
        // advertisement (the per-tool task-support wire field no longer
        // exists to assert on).
        assert!(disabled.task_tool().is_none());
        let _ = disabled_execute;
        assert!(disabled
            .list_tools(Some(&principal))
            .await
            .into_iter()
            .all(|tool| {
                !matches!(
                    tool.name.as_ref(),
                    "codemode.resume" | "codemode.resume_mutation"
                )
            }));
        let mutation_error = disabled
            .execute(
                &principal,
                StartParams {
                    source: None,
                    source_file: None,
                    source_sha256: None,
                    skill_script: None,
                    skill_revision: None,
                    retain_for_seconds: None,
                    repeat_after: None,
                    input: None,
                },
            )
            .await
            .expect_err("ordinary argument validation runs without a storage prerequisite");
        assert_eq!(
            mutation_error.data.as_ref().expect("structured error")["error"],
            "invalid_source_selector"
        );
        let unavailable = disabled
            .resume(
                &principal,
                ResumeParams {
                    execution_id: Uuid::now_v7().to_string(),
                    input: None,
                },
            )
            .await
            .expect_err("resume requires explicit durable content storage");
        assert_eq!(
            unavailable.data.as_ref().expect("structured error")["error"],
            "execution_resume_unavailable"
        );

        let allowed = code_mode_tools(catalog, authz)
            .with_execution_store(store)
            .with_result_persistence_allowed(true);
        assert!(allowed.supports_tasks());
        let allowed_tools = allowed.list_tools(Some(&principal)).await;
        let _allowed_execute = allowed_tools
            .iter()
            .find(|tool| tool.name == "codemode.execute")
            .expect("execute tool");
        let _allowed_resume = allowed_tools
            .iter()
            .find(|tool| tool.name == "codemode.resume")
            .expect("resume tool");
        // With durable storage authorized, the task tool is advertised at
        // the capability level (supports_tasks above) and keyed to execute.
        assert_eq!(allowed.task_tool(), Some("execute"));
        assert_eq!(allowed.cancel_task_tool(), Some("cancel"));
        assert!(!allowed_tools
            .iter()
            .any(|tool| tool.name == "codemode.resume_mutation"));
    }

    /// The default budget is five minutes, and the parent always outlasts it.
    ///
    /// Existing deployments set nothing, so the default is what almost every
    /// program runs under. The parent must also outlast the runner, or an
    /// overrun would surface as the parent's generic call timeout instead of
    /// the runner's precise one — and callers branch on that difference.
    #[test]
    fn default_execution_budget_is_five_minutes_and_the_parent_outlasts_it() {
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
            Arc::new(SelectiveAuthz) as SharedAuthz,
        );
        assert_eq!(tools.execution_limit, DEFAULT_EXECUTION_LIMIT);
        assert_eq!(
            DEFAULT_EXECUTION_LIMIT.as_millis() as u64,
            crate::process_mode::codemode_protocol::default_execution_limit_ms(),
            "the parent default and the protocol default must not diverge"
        );
        assert!(
            tools.call_timeout() > tools.execution_limit + execution_setup_allowance(),
            "the parent must outlast setup plus the full granted budget, since \
             its clock starts before the runner's does"
        );
    }

    /// Setup allowance the attempt does not spend must not become extra
    /// running time for the program.
    ///
    /// The runner cannot always stop itself — a connector call blocks it on a
    /// synchronous read where the interrupt handler cannot run — so the phase
    /// bound is what holds a program to the operator's budget in that window.
    /// Folding the allowance into it would let a fast setup silently hand the
    /// program the whole allowance on top of its grant, which is the same
    /// defect whichever direction the arithmetic drifts.
    #[test]
    fn the_program_phase_bound_does_not_absorb_the_setup_allowance() {
        let build = |limit: Duration| {
            code_mode_tools(
                Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
                Arc::new(SelectiveAuthz) as SharedAuthz,
            )
            .with_execution_limit(limit)
        };

        for limit in [
            MIN_EXECUTION_LIMIT,
            DEFAULT_EXECUTION_LIMIT,
            Duration::from_secs(60),
            MAX_EXECUTION_LIMIT,
        ] {
            let tools = build(limit);
            assert!(
                tools.program_phase_timeout() > limit,
                "the phase bound must outlast the budget it backstops, so an \
                 overrun is still reported with the runner's precise reason"
            );
            assert!(
                tools.program_phase_timeout() < limit + execution_setup_allowance(),
                "the phase bound must not carry the setup allowance: unspent \
                 setup time is not the program's to spend"
            );
            assert_eq!(
                tools.call_timeout(),
                tools.program_phase_timeout() + execution_setup_allowance(),
                "the attempt backstop is the phase bound plus setup, so the \
                 two cannot drift apart"
            );
        }
    }

    /// One configured budget must buy the same running time on every profile.
    ///
    /// A profile that cannot be stopped by dropping its future carries its
    /// deadline into the broker instead, which is an enforcement difference
    /// and must not become a budget difference. It previously was one: the
    /// deadline was taken before binding discovery and claiming, so the whole
    /// setup allowance became program time on that path alone.
    #[tokio::test(start_paused = true)]
    async fn every_profile_grants_the_same_program_phase_from_the_start_frame() {
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
            Arc::new(SelectiveAuthz) as SharedAuthz,
        );

        assert!(tools
            .program_phase_deadline(CodeExecutionProfile::Direct)
            .is_some());

        // Setup has already elapsed by the time this is called, and none of it
        // may show up in the grant.
        let setup_elapsed = execution_setup_allowance() / 2;
        tokio::time::advance(setup_elapsed).await;
        let assigned_at = tokio::time::Instant::now();
        let deadline = tools
            .program_phase_deadline(CodeExecutionProfile::LegacyApprovalBound)
            .expect("a profile enforcing its own deadline is given one");

        assert_eq!(
            deadline - assigned_at,
            tools.program_phase_timeout(),
            "the grant is measured from the start frame, so elapsed setup \
             neither shortens nor extends it"
        );
    }

    /// A budget outside the supported range never reaches the runner.
    ///
    /// The operator path rejects at boot; this pins the defensive clamp that
    /// backs it for programmatic callers, so an out-of-range value cannot
    /// reach a runner by either route.
    #[test]
    fn execution_budget_outside_the_supported_range_never_reaches_a_runner() {
        let build = |limit: Duration| {
            code_mode_tools(
                Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
                Arc::new(SelectiveAuthz) as SharedAuthz,
            )
            .with_execution_limit(limit)
        };

        assert_eq!(
            build(Duration::from_millis(1)).execution_limit,
            MIN_EXECUTION_LIMIT
        );
        assert_eq!(
            build(Duration::from_secs(86_400)).execution_limit,
            MAX_EXECUTION_LIMIT
        );

        // An in-range budget is taken exactly, and the parent still outlasts it.
        let configured = build(Duration::from_secs(60));
        assert_eq!(configured.execution_limit, Duration::from_secs(60));
        assert!(configured.call_timeout() > Duration::from_secs(60));
    }

    /// The durable claim must outlast the work it fences.
    ///
    /// The store refuses a terminal write once the claim has expired, and an
    /// ordinary durable run has no renewal loop. A lease shorter
    /// than the budget would therefore let a long program finish and then be
    /// unable to record its own result — the failure raising the ceiling
    /// would otherwise have introduced on the durable, pollable path.
    #[test]
    fn claim_lease_outlasts_the_granted_budget() {
        let build = |limit: Duration| {
            code_mode_tools(
                Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
                Arc::new(SelectiveAuthz) as SharedAuthz,
            )
            .with_execution_limit(limit)
        };

        for limit in [
            MIN_EXECUTION_LIMIT,
            DEFAULT_EXECUTION_LIMIT,
            Duration::from_secs(60),
            MAX_EXECUTION_LIMIT,
        ] {
            let tools = build(limit);
            assert!(
                tools.claim_lease() > tools.execution_limit,
                "claim lease {:?} does not outlast budget {:?}",
                tools.claim_lease(),
                tools.execution_limit
            );
            assert!(
                tools.claim_lease() >= tools.call_timeout(),
                "claim lease must also cover the parent's wait"
            );
        }

        // The historical floor remains a lower bound, so no configuration can
        // shrink the window in which an abandoned execution is reclaimed below
        // what it has always been.
        assert!(build(MIN_EXECUTION_LIMIT).claim_lease() >= EXECUTION_CLAIM_LEASE_FLOOR);
    }

    /// The poll surface must appear and disappear with the rest of the durable
    /// tools. A deployment that has not authorized result storage has no
    /// execution to poll, so advertising a status or cancel tool there would
    /// promise a lifecycle that cannot exist.
    #[tokio::test]
    async fn poll_surface_is_gated_with_the_other_durable_tools() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        let disabled =
            code_mode_tools(catalog.clone(), authz.clone()).with_execution_store(store.clone());
        assert!(disabled
            .list_tools(Some(&principal))
            .await
            .into_iter()
            .all(|tool| !matches!(tool.name.as_ref(), "codemode.status" | "codemode.cancel")));
        let unavailable = disabled
            .execution_status(
                &principal,
                ExecutionReferenceParams {
                    execution_id: Uuid::now_v7().to_string(),
                },
            )
            .await
            .expect_err("status requires explicit durable content storage");
        assert_eq!(
            unavailable.data.as_ref().expect("structured error")["error"],
            "execution_poll_unavailable"
        );

        let allowed = code_mode_tools(catalog, authz)
            .with_execution_store(store)
            .with_result_persistence_allowed(true);
        let allowed_tools = allowed.list_tools(Some(&principal)).await;
        assert!(allowed_tools
            .iter()
            .any(|tool| tool.name == "codemode.status"));
        assert!(allowed_tools
            .iter()
            .any(|tool| tool.name == "codemode.cancel"));
    }

    #[test]
    fn detached_status_tools_teach_context_efficient_projection() {
        for name in ["codemode.start", "codemode.start_resume", "codemode.status"] {
            let definition = tool_defs()
                .into_iter()
                .find(|tool| tool.name == name)
                .expect("detached status tool definition");
            let description = definition.description.as_deref().expect("description");

            for required_guidance in [
                "CallToolResult.structuredContent",
                "text `content` mirrors it only for MCP compatibility",
                "deadline or attempt limit",
                "`status` is `input_required`",
                "rather than serializing the whole `CallToolResult`",
            ] {
                assert!(
                    description.contains(required_guidance),
                    "{name} omits `{required_guidance}` from its caller guidance"
                );
            }
        }
    }

    /// A status response is polled in a loop, so it must not carry the result.
    /// If it ever did, polling would cost what retrieval costs and the reason
    /// this surface exists would be gone.
    #[test]
    fn execution_status_projection_omits_the_result_payload() {
        let now = time::OffsetDateTime::now_utc();
        let execution = Execution {
            program_input: None,
            id: Uuid::now_v7(),
            tenant_id: "tenant".to_owned(),
            principal_sub: "sub".to_owned(),
            principal_issuer: Some("issuer".to_owned()),
            source: Some("return 1;".to_owned()),
            source_digest: "digest".to_owned(),
            execution_profile: serde_json::json!({}),
            tool_snapshot: None,
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            status: ExecutionStatus::Succeeded,
            terminal_reason_code: None,
            result_metadata: None,
            result_payload: Some(serde_json::json!({"result": "sensitive-and-large"})),
            resume_context: None,
            claim_owner: None,
            claim_epoch: 0,
            claim_expires_at: None,
            cancellation_requested_at: None,
            cancellation_reason_code: None,
            submitted_at: now,
            updated_at: now,
            completed_at: Some(now),
            retention_until: now + EXECUTION_RETENTION,
        };

        let projection = execution_status_projection(&execution);
        let encoded = serde_json::to_string(&projection).expect("status projection serializes");
        assert!(
            !encoded.contains("sensitive-and-large"),
            "status must not carry the stored result: {encoded}"
        );
        // It reports that a result exists so a caller knows to fetch it, which
        // is the whole signal a poll needs.
        assert!(projection.result_available);
        assert!(projection.terminal);
    }

    /// The two consumption shapes must agree about one execution.
    ///
    /// Asserted against the Tasks projection itself rather than against a
    /// literal, so this fails if either mapping is changed without the other —
    /// which is the drift the shared lifecycle status exists to prevent, and
    /// the seam #890 names as most worth protecting.
    #[test]
    fn poll_and_task_projections_report_the_same_lifecycle_status() {
        let now = time::OffsetDateTime::now_utc();
        let base = Execution {
            program_input: None,
            id: Uuid::now_v7(),
            tenant_id: "tenant".to_owned(),
            principal_sub: "sub".to_owned(),
            principal_issuer: Some("issuer".to_owned()),
            source: Some("return 1;".to_owned()),
            source_digest: "digest".to_owned(),
            execution_profile: serde_json::json!({}),
            tool_snapshot: None,
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            status: ExecutionStatus::Submitted,
            terminal_reason_code: None,
            result_metadata: None,
            result_payload: None,
            resume_context: None,
            claim_owner: None,
            claim_epoch: 0,
            claim_expires_at: None,
            cancellation_requested_at: None,
            cancellation_reason_code: None,
            submitted_at: now,
            updated_at: now,
            completed_at: None,
            retention_until: now + EXECUTION_RETENTION,
        };

        for status in [
            ExecutionStatus::Submitted,
            ExecutionStatus::Admitted,
            ExecutionStatus::Running,
            ExecutionStatus::WaitingForApproval,
            ExecutionStatus::WaitingForResume,
            ExecutionStatus::Compensating,
            ExecutionStatus::Compensated,
            ExecutionStatus::Succeeded,
            ExecutionStatus::Failed,
            ExecutionStatus::Cancelled,
            ExecutionStatus::Expired,
            ExecutionStatus::Ambiguous,
            ExecutionStatus::ReconciledApplied,
            ExecutionStatus::ReconciledNotApplied,
        ] {
            let execution = Execution {
                status,
                ..base.clone()
            };
            let polled = execution_status_projection(&execution).status;
            let task = task_projection(&execution);
            let via_task = serde_json::to_value(task.status)
                .expect("task status serializes")
                .as_str()
                .expect("task status is a string")
                .to_owned();
            assert_eq!(
                polled, via_task,
                "poll and task projections disagree for {status:?}"
            );
        }
    }

    /// A detached caller cannot resume a paused program without its
    /// checkpoint, and must never be handed an approval binding.
    ///
    /// Both waiting states carry a resume context, and only one of them holds
    /// something a poller may act on. The approval binding is reviewed and
    /// redacted on its own surface; a poll response is not that surface.
    #[test]
    fn status_reports_a_pause_checkpoint_and_never_an_approval_binding() {
        let now = time::OffsetDateTime::now_utc();
        let base = Execution {
            program_input: None,
            id: Uuid::now_v7(),
            tenant_id: "tenant".to_owned(),
            principal_sub: "sub".to_owned(),
            principal_issuer: Some("issuer".to_owned()),
            source: Some("return 1;".to_owned()),
            source_digest: "digest".to_owned(),
            execution_profile: serde_json::json!({}),
            tool_snapshot: None,
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            status: ExecutionStatus::Submitted,
            terminal_reason_code: None,
            result_metadata: None,
            result_payload: None,
            resume_context: None,
            claim_owner: None,
            claim_epoch: 0,
            claim_expires_at: None,
            cancellation_requested_at: None,
            cancellation_reason_code: None,
            submitted_at: now,
            updated_at: now,
            completed_at: None,
            retention_until: now + EXECUTION_RETENTION,
        };

        let checkpoint = serde_json::json!({"page": 3});
        let paused = Execution {
            status: ExecutionStatus::WaitingForResume,
            resume_context: Some(serde_json::json!({"checkpoint": checkpoint})),
            ..base.clone()
        };
        assert_eq!(
            execution_status_projection(&paused).checkpoint,
            Some(checkpoint),
            "a paused execution must report the checkpoint a resume input answers"
        );

        // The exact shape an approval wait stores. Selecting on state and then
        // on one key is what keeps it out; reading the context wholesale would
        // publish it.
        let awaiting_approval = Execution {
            status: ExecutionStatus::WaitingForApproval,
            resume_context: Some(serde_json::json!({
                "approval": {"binding": "email.send", "arguments_digest": "abc"},
            })),
            ..base.clone()
        };
        let projected = execution_status_projection(&awaiting_approval);
        assert_eq!(projected.checkpoint, None);
        let rendered = serde_json::to_string(&projected).expect("status serializes");
        assert!(
            !rendered.contains("approval") && !rendered.contains("email.send"),
            "an approval binding must not reach a poll response: {rendered}"
        );

        // Every other state, including one that ran to completion, is a plain
        // decision-shaped status with nothing extra to carry.
        for status in [
            ExecutionStatus::Submitted,
            ExecutionStatus::Running,
            ExecutionStatus::Succeeded,
            ExecutionStatus::Failed,
            ExecutionStatus::Cancelled,
        ] {
            let execution = Execution {
                status,
                resume_context: Some(serde_json::json!({"checkpoint": {"page": 9}})),
                ..base.clone()
            };
            assert_eq!(
                execution_status_projection(&execution).checkpoint,
                None,
                "{status:?} is not a state a caller resumes from"
            );
        }
    }

    /// The operator's configured budget is what reaches the runner.
    ///
    /// The runner applies the arriving value and chooses nothing, so this is
    /// the step where configuration becomes the deadline a program runs under.
    /// It is asserted against a value no default could produce, so a
    /// regression that dropped the plumbing and fell back to the compiled
    /// default would fail here rather than pass quietly.
    #[test]
    fn the_configured_budget_is_what_the_start_frame_carries() {
        let configured = Duration::from_secs(97);
        assert_ne!(
            configured, DEFAULT_EXECUTION_LIMIT,
            "a value equal to the default would pass even if nothing propagated"
        );
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
            Arc::new(SelectiveAuthz) as SharedAuthz,
        )
        .with_execution_limit(configured);

        let ParentFrame::Start {
            execution_limit_ms, ..
        } = tools.start_frame("return 1;".to_owned(), Vec::new(), None, Value::Null, false)
        else {
            panic!("start frame");
        };
        assert_eq!(execution_limit_ms, 97_000);
    }

    /// A runner that never becomes ready must not hold its permits forever.
    ///
    /// Setup is the one phase that is safe to bound on every profile: nothing
    /// has been dispatched before the start frame, so there is no in-flight
    /// effect a dropped future could abandon. That is why the approval-bound
    /// profile — whose program phase must never be dropped, and which
    /// therefore takes no outer timeout at all — is included here rather than
    /// excepted. Without this bound its runner would hold capacity and a
    /// durable claim with nothing to release them.
    #[tokio::test(start_paused = true)]
    async fn a_runner_that_never_becomes_ready_is_bounded() {
        let (mut parent_stdin, _runner_input) = tokio::io::duplex(4096);
        // Held open and silent: the runner exists but never announces itself,
        // which is the stall this bound exists for. A closed pipe would take
        // the read-failure path instead and prove nothing about the timeout.
        let (_runner_output, parent_stdout) = tokio::io::duplex(4096);
        let mut parent_stdout = BufReader::new(parent_stdout);

        // Setup is bounded by an instant the caller already owns, not by a
        // fresh allowance starting here. Binding discovery, claiming and spawn
        // have already spent part of it by the time this runs, and starting
        // over would let the whole pre-program phase outlast the allowance
        // that names it — and outlast the attempt deadline, which would report
        // its own generic reason instead of this one.
        let started = tokio::time::Instant::now();
        let remaining = Duration::from_secs(5);
        assert!(
            remaining < execution_setup_allowance(),
            "the point is that setup gets what is left, not a full allowance"
        );

        let error = complete_runner_setup(
            &mut parent_stdin,
            &mut parent_stdout,
            ParentFrame::Start {
                input: Value::Null,
                source: "return 1;".to_owned(),
                bindings: Vec::new(),
                resume: None,
                artifacts_available: false,
                execution_limit_ms: 1_000,
            },
            started + remaining,
        )
        .await
        .expect_err("a runner that never becomes ready is given up on");

        assert_eq!(
            tokio::time::Instant::now() - started,
            remaining,
            "setup must give up at the instant it was given, not a fresh allowance later"
        );

        // Distinct from budget exhaustion and from a call timeout: a caller
        // that cannot tell a runner which never started from a program that
        // ran out of time cannot tell a broken deployment from a slow program.
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "execution_setup_timeout"
        );
        assert_ne!(
            error.data.as_ref().expect("structured error")["error"],
            "execution_timeout"
        );
    }

    /// A tool-confined profile must name the detached tools to spend the
    /// durable resource they commit.
    ///
    /// The namespace skips the router's profile checks because it applies the
    /// caller's profile to every nested connector decision instead, which
    /// bounds what a program can *reach*. It says nothing about a commitment
    /// that outlives the call, and starting detached work writes a durable row
    /// and holds capacity after returning. So these two apply the same rule
    /// this repository already applies to other non-tool surfaces under a
    /// tool-confined profile: an enumerated grant is exact.
    #[tokio::test]
    async fn a_tool_confined_profile_must_name_the_detached_tools() {
        let store: SharedExecutionStore = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
            Arc::new(SelectiveAuthz) as SharedAuthz,
        )
        .with_execution_store(store)
        .with_result_persistence_allowed(true);

        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        // Enumerating tools without naming these withholds them, and the
        // listing must agree with the call rather than advertise a refusal.
        let mut confined = principal.clone();
        confined.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
            profile_id: "email-only".to_owned(),
            profile_name: "Email only".to_owned(),
            allowed_servers: None,
            allowed_tools: Some(vec!["email.send".to_owned()]),
        });
        let listed = tools.list_tools(Some(&confined)).await;
        for name in ["codemode.start", "codemode.start_resume"] {
            assert!(
                listed.iter().all(|tool| tool.name.as_ref() != name),
                "{name} must not be advertised to a profile that withholds it"
            );
        }
        let refused = tools
            .start_execution(&confined, start_source("return 1;"))
            .await
            .expect_err("a withheld start is refused");
        assert_eq!(
            refused.data.as_ref().expect("structured error")["error"],
            "detached_execution_withheld"
        );
        let refused_resume = tools
            .start_resume_execution(
                &confined,
                ResumeParams {
                    execution_id: Uuid::now_v7().to_string(),
                    input: None,
                },
            )
            .await
            .expect_err("a withheld resume is refused");
        assert_eq!(
            refused_resume.data.as_ref().expect("structured error")["error"],
            "detached_execution_withheld"
        );

        // Naming them grants them.
        let mut granted = principal.clone();
        granted.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
            profile_id: "detached".to_owned(),
            profile_name: "Detached".to_owned(),
            allowed_servers: None,
            allowed_tools: Some(vec![
                "codemode.start".to_owned(),
                "codemode.start_resume".to_owned(),
            ]),
        });
        let listed = tools.list_tools(Some(&granted)).await;
        for name in ["codemode.start", "codemode.start_resume"] {
            assert!(
                listed.iter().any(|tool| tool.name.as_ref() == name),
                "{name} must be advertised to a profile that names it"
            );
        }

        // A profile that confines servers without enumerating tools is
        // unaffected, and so is one with no restrictions at all.
        let mut server_confined = principal.clone();
        server_confined.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
            profile_id: "servers".to_owned(),
            profile_name: "Servers".to_owned(),
            // An upstream connector, which is what server confinement is for.
            // Naming this namespace here would pass whatever the predicate
            // did, and prove nothing about the case operators actually write.
            allowed_servers: Some(vec!["email".to_owned()]),
            allowed_tools: None,
        });
        for candidate in [&principal, &server_confined] {
            let listed = tools.list_tools(Some(candidate)).await;
            for name in ["codemode.start", "codemode.start_resume"] {
                assert!(
                    listed.iter().any(|tool| tool.name.as_ref() == name),
                    "{name} must stay available where no tool grant is enumerated"
                );
            }
        }

        // Blocking calls keep the namespace's existing behaviour. Their
        // detached task shape is checked at enqueue time because one static
        // tool listing cannot vary with a call's task augmentation.
        let listed = tools.list_tools(Some(&confined)).await;
        for name in [
            "codemode.execute",
            "codemode.status",
            "codemode.cancel",
            "codemode.result",
        ] {
            assert!(
                listed.iter().any(|tool| tool.name.as_ref() == name),
                "{name} must be unaffected by this change"
            );
        }
        for name in ["execute", "resume"] {
            let error = tools
                .enqueue_task(name, None, Some(&confined))
                .await
                .expect_err("task augmentation is a detached commitment");
            assert_eq!(
                error.data.as_ref().expect("structured error")["error"],
                "detached_execution_withheld",
                "task-augmented {name} must require its exact profile grant"
            );
        }

        let mut responses = rmcp::model::InputResponses::new();
        responses.insert("resume".to_owned(), Value::Null);
        let error = tools
            .update_task(&Uuid::now_v7().to_string(), responses, Some(&confined))
            .await
            .expect_err("tasks/update also leaves continuation work detached");
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "detached_execution_withheld",
            "the selected continuation must require its exact profile grant"
        );
    }

    /// State-changing detached controls must be governable as themselves.
    ///
    /// `governance_tool` exists so a continuation can carry the authority of
    /// the execution it advances. The Cedar overlay builds its facts from the
    /// descriptor that alias selects, so aliasing a state-changing tool to a
    /// read-only one hands the policy engine the wrong risk and side-effect
    /// facts, and a rule keyed to this operation could never match it. Starting,
    /// resuming, or cancelling durable background work must therefore govern
    /// under its own name.
    #[test]
    fn state_changing_detached_controls_use_their_own_names_and_facts() {
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
            Arc::new(SelectiveAuthz) as SharedAuthz,
        );
        let descriptor = surface_descriptor();
        let facts_for = |name: &str| {
            descriptor
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("{name} has a descriptor"))
        };

        for name in ["start", "start_resume", "cancel"] {
            assert_eq!(
                tools.governance_tool(name),
                name,
                "{name} must not borrow another tool's authority"
            );
            // These are the facts Cedar receives, selected by the name above.
            let facts = facts_for(name);
            assert!(facts.side_effects, "{name} changes durable execution state");
            assert_eq!(
                facts.risk,
                if name == "start" {
                    RiskTier::High
                } else {
                    RiskTier::Medium
                }
            );
        }

        // Read-only retrieval keeps carrying the authority of the execution
        // the caller already started.
        assert_eq!(tools.governance_tool("result"), "execute");
    }

    /// A handle whose result could never be stored is not a handle.
    ///
    /// The blocking tool can still serve a deployment without durable storage,
    /// because its caller receives the result directly. A detached start has
    /// nobody to return to, so it refuses rather than running a program whose
    /// output nothing could retrieve.
    #[tokio::test]
    async fn detached_tools_are_withheld_without_durable_result_storage() {
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let disabled = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
            Arc::new(SelectiveAuthz) as SharedAuthz,
        );
        assert!(
            disabled
                .list_tools(Some(&principal))
                .await
                .into_iter()
                .all(|tool| tool.name.as_ref() != "codemode.start"),
            "a tool the deployment cannot honour must not be advertised"
        );
        let refused = disabled
            .start_execution(&principal, start_source("return 1;"))
            .await
            .expect_err("a detached start requires durable result storage");
        assert_eq!(
            refused.data.as_ref().expect("structured error")["error"],
            "execution_start_unavailable"
        );

        // The continuation half is gated on the same posture. A deployment
        // that cannot hand back a handle cannot hand back a second one for the
        // same execution either, and advertising only one of the pair would
        // promise a lifecycle that stops at its first pause.
        assert!(
            disabled
                .list_tools(Some(&principal))
                .await
                .into_iter()
                .all(|tool| tool.name.as_ref() != "codemode.start_resume"),
            "the continuation half must be withheld with the half it continues"
        );
        let refused_resume = disabled
            .start_resume_execution(
                &principal,
                ResumeParams {
                    execution_id: Uuid::now_v7().to_string(),
                    input: None,
                },
            )
            .await
            .expect_err("a detached resume requires durable result storage");
        assert_eq!(
            refused_resume.data.as_ref().expect("structured error")["error"],
            "execution_start_unavailable"
        );

        let store: SharedExecutionStore = Arc::new(RecordingExecutionStore::default());
        let allowed = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])) as SharedCatalog,
            Arc::new(SelectiveAuthz) as SharedAuthz,
        )
        .with_execution_store(store)
        .with_result_persistence_allowed(true);
        let allowed_tools = allowed.list_tools(Some(&principal)).await;
        for name in ["codemode.start", "codemode.start_resume"] {
            assert!(
                allowed_tools.iter().any(|tool| tool.name == name),
                "{name} must appear alongside the poll half it pairs with"
            );
        }
    }

    #[tokio::test]
    async fn retained_source_store_obeys_the_operator_content_posture() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://codemode:codemode@127.0.0.1/codemode")
            .expect("syntactically valid lazy Pg pool");
        let store = Arc::new(waygate_codemode::PgExecutionStore::new(pool));

        assert!(
            configured_source_artifact_store(Some(store.clone()), false).is_none(),
            "the default no-content posture must not install retained-source persistence"
        );
        assert!(
            configured_source_artifact_store(Some(store), true).is_some(),
            "explicit durable-content admission installs the retained-source store"
        );
    }

    #[tokio::test]
    async fn journal_profile_records_per_execution_result_storage() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let shared_store: SharedExecutionStore = store.clone();
        let tools = code_mode_tools(catalog, authz).with_result_persistence_allowed(true);
        let principal = reader();

        tools
            .submit_durable(
                &shared_store,
                &principal,
                &resolved_inline_source("return 1;"),
                &Value::Null,
                false,
                CodeExecutionProfile::Direct,
            )
            .await
            .expect("synchronous durable submission");
        assert_eq!(
            store
                .submitted
                .lock()
                .await
                .as_ref()
                .expect("submission")
                .execution_profile["result_storage"],
            "disabled"
        );
        assert!(
            store
                .submitted
                .lock()
                .await
                .as_ref()
                .expect("submission")
                .execution_profile
                .get("source_authority")
                .is_none(),
            "ordinary sources retain their pre-skill durable profile shape"
        );

        tools
            .submit_durable(
                &shared_store,
                &principal,
                &resolved_inline_source("return 2;"),
                &Value::Null,
                true,
                CodeExecutionProfile::Direct,
            )
            .await
            .expect("task durable submission");
        assert_eq!(
            store
                .submitted
                .lock()
                .await
                .as_ref()
                .expect("submission")
                .execution_profile["result_storage"],
            "allow"
        );
        {
            let submitted = store.submitted.lock().await;
            let submitted = submitted.as_ref().expect("resumable submission");
            assert_eq!(submitted.source.as_deref(), Some("return 2;"));
            assert_eq!(submitted.execution_profile["resumable"], false);
        }

        tools
            .submit_durable(
                &shared_store,
                &principal,
                &resolved_inline_source("return 3;"),
                &Value::Null,
                true,
                CodeExecutionProfile::LegacyApprovalBound,
            )
            .await
            .expect("mutation durable submission");
        let submitted = store.submitted.lock().await;
        let submitted = submitted.as_ref().expect("mutation submission");
        // A mutation execution waits only at the approval boundary; marking it
        // ordinarily resumable would let abandonment reconciliation park it in
        // `waiting_for_resume`, which no continuation API accepts.
        assert_eq!(submitted.execution_profile["resumable"], false);
    }

    /// A later attempt replays the program from the top, so the input must be
    /// on the durable row rather than only in the request that started it —
    /// bound on exactly the condition the source is, since a row that cannot
    /// replay its program has no use for the input it would have read.
    #[tokio::test]
    async fn durable_submission_binds_the_input_wherever_it_binds_the_source() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let shared_store: SharedExecutionStore = store.clone();
        let tools = code_mode_tools(catalog, authz).with_result_persistence_allowed(true);
        let principal = reader();
        let input = serde_json::json!({"pr_number": 71});

        for persist in [true, false] {
            tools
                .submit_durable(
                    &shared_store,
                    &principal,
                    &resolved_inline_source("return execution.input.pr_number;"),
                    &input,
                    persist,
                    CodeExecutionProfile::Direct,
                )
                .await
                .expect("durable submission");
            let submitted = store.submitted.lock().await;
            let submitted = submitted.as_ref().expect("submission");
            assert_eq!(submitted.source.is_some(), persist);
            assert_eq!(
                submitted.program_input.as_ref(),
                persist.then_some(&input),
                "input must be durable exactly when the program is",
            );
        }
    }

    #[tokio::test]
    async fn task_enqueue_returns_a_durable_owner_scoped_execution_id() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let arguments = json!({"source": "return 42;", "timeout_seconds": 1})
            .as_object()
            .cloned()
            .expect("arguments object");

        let task = tools
            .enqueue_task("execute", Some(arguments), Some(&principal))
            .await
            .expect("enqueue task")
            .expect("execute supports tasks");

        assert_eq!(task.status, TaskStatus::Working);
        let id = Uuid::parse_str(&task.task_id).expect("task id is an execution UUID");
        let claimed = store
            .current
            .lock()
            .await
            .clone()
            .expect("acknowledged task has a journal row");
        assert_eq!(claimed.status, ExecutionStatus::Running);
        assert_eq!(claimed.execution_profile["timeout_seconds"], 1);
        assert!(
            claimed.tool_snapshot.is_some(),
            "task acknowledgment follows immutable admission and claim"
        );
        assert_eq!(
            store
                .submitted
                .lock()
                .await
                .as_ref()
                .expect("durable submission")
                .source_digest,
            source_digest("return 42;"),
        );
        let mut other = principal.clone();
        other.sub = "other-user".to_owned();
        assert!(tools
            .get_task(&id.to_string(), Some(&other))
            .await
            .expect("owner-scoped lookup")
            .is_none());
    }

    /// The stamp a row is written with and the stamp a response advertises are
    /// two spellings of one number, held in separate declarations that can
    /// drift apart. They did: advancing the durable constants for
    /// `execution.input` left responses advertising the previous contract.
    #[test]
    fn responses_advertise_the_contracts_executions_are_stamped_with() {
        assert_eq!(
            serde_json::to_value(SdkContractVersion::V4).expect("serialize sdk stamp"),
            Value::String(SDK_CONTRACT_VERSION.to_string()),
        );
        assert_eq!(
            serde_json::to_value(RunnerContractVersion::V7).expect("serialize runner stamp"),
            Value::String(RUNNER_CONTRACT_VERSION.to_string()),
        );
    }

    #[tokio::test]
    async fn previous_waitless_sdk_pause_resumes_under_current_runtime_contracts() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = Uuid::now_v7();
        let source = "return execution.resume.input;";
        let new_execution = NewExecution {
            program_input: None,
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some(source.to_owned()),
            source_digest: source_digest(source),
            execution_profile: json!({
                "name": "direct",
                "profile_confinement": task_profile_confinement(&principal),
                "resumable": true,
            }),
            sdk_contract_version: PREVIOUS_SDK_CONTRACT_VERSION,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let mut execution =
            recorded_execution(&new_execution, ExecutionStatus::WaitingForResume, None);
        execution.tool_snapshot = Some(json!({"contract_version": 1, "bindings": []}));
        execution.resume_context = Some(json!({"checkpoint": {"prompt": "Provide a value"}}));
        *store.current.lock().await = Some(execution);

        let claimed = tools
            .claim_resume(
                &principal,
                ResumeParams {
                    execution_id: id.to_string(),
                    input: Some(json!({"value": 42})),
                },
            )
            .await
            .expect("previous waitless SDK pause remains resumable");

        assert_eq!(claimed.execution.sdk_contract_version, SDK_CONTRACT_VERSION);
        assert_eq!(
            claimed.execution.runner_contract_version,
            RUNNER_CONTRACT_VERSION
        );
        let persisted = store
            .current
            .lock()
            .await
            .clone()
            .expect("claimed execution");
        assert_eq!(persisted.sdk_contract_version, SDK_CONTRACT_VERSION);
        assert_eq!(persisted.runner_contract_version, RUNNER_CONTRACT_VERSION);
    }

    /// A continuation replays the program from the top, so it must be handed
    /// the input its execution was submitted with, read back off the durable
    /// row. The resume input is a separate channel and must not stand in for
    /// it: a program reading `execution.input` on its second attempt would
    /// otherwise take a path its first attempt never took.
    #[tokio::test]
    async fn a_continuation_replays_with_the_input_its_execution_was_submitted_with() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = Uuid::now_v7();
        let source = "return [execution.input.pr_number, execution.resume.input.value];";
        let submitted_input = json!({"pr_number": 71});
        let new_execution = NewExecution {
            program_input: Some(submitted_input.clone()),
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some(source.to_owned()),
            source_digest: source_digest(source),
            execution_profile: json!({
                "name": "direct",
                "profile_confinement": task_profile_confinement(&principal),
                "resumable": true,
            }),
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let mut execution =
            recorded_execution(&new_execution, ExecutionStatus::WaitingForResume, None);
        execution.tool_snapshot = Some(json!({"contract_version": 1, "bindings": []}));
        execution.resume_context = Some(json!({"checkpoint": {"prompt": "Provide a value"}}));
        *store.current.lock().await = Some(execution);

        let claimed = tools
            .claim_resume(
                &principal,
                ResumeParams {
                    execution_id: id.to_string(),
                    input: Some(json!({"value": 42})),
                },
            )
            .await
            .expect("bound execution remains resumable");

        assert_eq!(
            claimed.program.input, submitted_input,
            "the continuation must read the input the execution was submitted with",
        );
    }

    #[tokio::test]
    async fn legacy_approval_pause_is_rejected_without_claiming_or_upgrading() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = Uuid::now_v7();
        let source = "return connectors.email.send({subject: 'ready'});";
        let new_execution = NewExecution {
            program_input: None,
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some(source.to_owned()),
            source_digest: source_digest(source),
            execution_profile: json!({
                "name": "approval_bound_mutation",
                "profile_confinement": task_profile_confinement(&principal),
                "resumable": false,
            }),
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: PREVIOUS_RUNNER_CONTRACT_VERSION,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let mut execution =
            recorded_execution(&new_execution, ExecutionStatus::WaitingForApproval, None);
        execution.tool_snapshot = Some(json!({"contract_version": 1, "bindings": []}));
        execution.resume_context = Some(json!({"approval": {"call_id": 1}}));
        *store.current.lock().await = Some(execution);

        let error = match tools
            .call(
                "resume_mutation",
                json!({"execution_id":id}).as_object().cloned(),
                Some(&principal),
            )
            .await
        {
            Ok(_) => panic!("legacy executions must not be replayed"),
            Err(error) => error,
        };
        assert!(error.message.contains("unknown codemode tool"));
        let persisted = store.current.lock().await.clone().unwrap();
        assert_eq!(persisted.status, ExecutionStatus::WaitingForApproval);
        assert_eq!(
            persisted.runner_contract_version,
            PREVIOUS_RUNNER_CONTRACT_VERSION
        );
        assert_eq!(
            persisted.execution_profile["name"],
            "approval_bound_mutation"
        );
    }

    #[tokio::test]
    async fn normal_resume_call_rejects_runtime_drift_before_starting_a_runner() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = Uuid::now_v7();
        let new_execution = NewExecution {
            program_input: None,
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some("return execution.resume.input;".to_owned()),
            source_digest: source_digest("return execution.resume.input;"),
            execution_profile: json!({
                "name": "direct",
                "profile_confinement": task_profile_confinement(&principal),
                "resumable": true,
            }),
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: LEGACY_RUNNER_CONTRACT_VERSION - 1,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let mut execution =
            recorded_execution(&new_execution, ExecutionStatus::WaitingForResume, None);
        execution.tool_snapshot = Some(json!({"contract_version": 1, "bindings": []}));
        execution.resume_context = Some(json!({"checkpoint": {"prompt": "Provide a value"}}));
        *store.current.lock().await = Some(execution);

        let error = tools
            .resume(
                &principal,
                ResumeParams {
                    execution_id: id.to_string(),
                    input: Some(json!({"value": 42})),
                },
            )
            .await
            .expect_err("stale runner contract must not resume");

        assert_eq!(
            error.data.as_ref().expect("structured incompatibility")["error"],
            "execution_resume_incompatible"
        );
        assert_eq!(
            error.data.as_ref().expect("structured incompatibility")["reason"],
            "runner_contract_changed"
        );
    }

    #[tokio::test]
    async fn task_augmented_resume_rejects_runtime_drift_before_acknowledging() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = Uuid::now_v7();
        let new_execution = NewExecution {
            program_input: None,
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some("return execution.resume.input;".to_owned()),
            source_digest: source_digest("return execution.resume.input;"),
            execution_profile: json!({
                "name": "direct",
                "profile_confinement": task_profile_confinement(&principal),
                "resumable": true,
            }),
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: LEGACY_RUNNER_CONTRACT_VERSION - 1,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let mut execution =
            recorded_execution(&new_execution, ExecutionStatus::WaitingForResume, None);
        execution.tool_snapshot = Some(json!({"contract_version": 1, "bindings": []}));
        execution.resume_context = Some(json!({"checkpoint": {"prompt": "Provide a value"}}));
        *store.current.lock().await = Some(execution);

        let error = tools
            .enqueue_task(
                "resume",
                json!({
                    "execution_id": id.to_string(),
                    "input": {"value": 42},
                })
                .as_object()
                .cloned(),
                Some(&principal),
            )
            .await
            .expect_err("task resume must reject stale runner contract before acknowledgment");

        assert_eq!(
            error.data.as_ref().expect("structured incompatibility")["error"],
            "execution_resume_incompatible"
        );
        assert_eq!(
            error.data.as_ref().expect("structured incompatibility")["reason"],
            "runner_contract_changed"
        );
    }

    #[tokio::test]
    async fn completed_task_returns_result_with_live_source_reference() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let source_store = Arc::new(MemorySourceArtifactStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_source_artifact_store(source_store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = Uuid::now_v7();
        let source = "return 42;";
        let digest = source_digest(source);
        let retained = source_store
            .retain_source(
                &CodeModeTools::source_owner(&principal),
                source,
                &digest,
                Duration::from_secs(3600),
            )
            .await
            .expect("retain task source");
        let new_execution = NewExecution {
            program_input: None,
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some(source.to_owned()),
            source_digest: digest.clone(),
            execution_profile: json!({
                "name": "direct",
                "profile_confinement": task_profile_confinement(&principal),
            }),
            sdk_contract_version: 1,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let transition = ExecutionTransition {
            from: vec![ExecutionStatus::Running],
            to: ExecutionStatus::Succeeded,
            event: execution_event(ExecutionEventKind::Succeeded, None, None, json!({})),
            terminal_reason_code: None,
            result_metadata: Some(json!({"connector_calls": 0})),
            result_payload: Some(json!({
                "execution_id": id,
                "result": 42,
                "connector_calls": 0,
                "source_ref": {
                    "sha256": digest,
                    "expires_at": "2000-01-01T00:00:00Z",
                },
            })),
            resume_context: None,
        };
        *store.current.lock().await = Some(recorded_execution(
            &new_execution,
            ExecutionStatus::Succeeded,
            Some(&transition),
        ));

        let result = tools
            .get_task_result(&id.to_string(), Some(&principal))
            .await
            .expect("read result")
            .expect("task exists");
        assert_eq!(structured(&result)["result"], 42);
        assert_eq!(structured(&result)["execution_id"], id.to_string());
        assert_eq!(
            structured(&result)["source_ref"]["expires_at"],
            waygate_core::fmt::format_ts_rfc3339(retained.expires_at)
        );
        assert_eq!(structured(&result)["source_ref"]["retention_state"], "live");
        let extended = source_store
            .retain_source(
                &CodeModeTools::source_owner(&principal),
                source,
                &new_execution.source_digest,
                Duration::from_secs(7200),
            )
            .await
            .expect("extend task source retention");
        let repeated = tools
            .get_task_result(&id.to_string(), Some(&principal))
            .await
            .expect("repeat read")
            .expect("durable task result remains available");
        assert_eq!(structured(&repeated)["result"], 42);
        assert_eq!(
            structured(&repeated)["source_ref"]["expires_at"],
            waygate_core::fmt::format_ts_rfc3339(extended.expires_at),
            "task retrieval projects the current reuse deadline"
        );
        let referenced = tools
            .call(
                "result",
                json!({"execution_id": id.to_string()}).as_object().cloned(),
                Some(&principal),
            )
            .await
            .expect("resolve stable result reference");
        assert_eq!(structured(&referenced)["result"], 42);

        let mut confined = principal.clone();
        confined.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
            profile_id: "email-only".to_owned(),
            profile_name: "Email only".to_owned(),
            allowed_servers: Some(vec!["email".to_owned()]),
            allowed_tools: None,
        });
        assert!(tools
            .get_task_result(&id.to_string(), Some(&confined))
            .await
            .expect("profile-confined lookup")
            .is_none());

        let mut expired = store
            .current
            .lock()
            .await
            .clone()
            .expect("completed execution");
        expired.retention_until = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        *store.current.lock().await = Some(expired);
        assert!(tools
            .get_task_result(&id.to_string(), Some(&principal))
            .await
            .expect("expired lookup")
            .is_none());
        assert_eq!(
            tools
                .call(
                    "result",
                    json!({"execution_id": id.to_string()}).as_object().cloned(),
                    Some(&principal),
                )
                .await
                .expect_err("expired result reference is unavailable")
                .data
                .expect("structured result error")["error"],
            "execution_result_unavailable"
        );
    }

    #[tokio::test]
    async fn emitted_artifacts_are_listable_and_retrievable_after_failure() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let execution_id = Uuid::now_v7();
        let artifact_id = Uuid::now_v7();
        let second_artifact_id = Uuid::now_v7();
        let new_execution = NewExecution {
            program_input: None,
            id: execution_id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some("return 1;".to_owned()),
            source_digest: source_digest("return 1;"),
            execution_profile: json!({
                "name": "direct",
                "profile_confinement": task_profile_confinement(&principal),
            }),
            sdk_contract_version: SDK_CONTRACT_VERSION,
            runner_contract_version: RUNNER_CONTRACT_VERSION,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let transition = ExecutionTransition {
            from: vec![ExecutionStatus::Running],
            to: ExecutionStatus::Failed,
            event: execution_event(ExecutionEventKind::Failed, None, None, json!({})),
            terminal_reason_code: Some("execution_failed".to_owned()),
            result_metadata: None,
            result_payload: None,
            resume_context: None,
        };
        *store.current.lock().await = Some(recorded_execution(
            &new_execution,
            ExecutionStatus::Failed,
            Some(&transition),
        ));
        store.events.lock().await.push(execution_event(
            ExecutionEventKind::ArtifactEmitted,
            None,
            None,
            json!({
                "artifact_id": artifact_id,
                "value": {"kind": "partial", "rows": [1, 2]},
            }),
        ));
        store.events.lock().await.push(execution_event(
            ExecutionEventKind::ArtifactEmitted,
            None,
            None,
            json!({
                "artifact_id": second_artifact_id,
                "value": {"kind": "partial", "rows": [3, 4]},
            }),
        ));

        let listed = tools
            .call(
                "artifacts",
                json!({
                    "execution_id": execution_id.to_string(),
                    "limit": 1,
                })
                .as_object()
                .cloned(),
                Some(&principal),
            )
            .await
            .expect("list failed execution artifacts");
        assert_eq!(
            structured(&listed)["artifacts"][0]["reference"]["artifact_id"],
            artifact_id.to_string()
        );
        let next_cursor = structured(&listed)["next_cursor"]
            .as_str()
            .expect("first artifact page has a cursor")
            .to_owned();
        let second_page = tools
            .call(
                "artifacts",
                json!({
                    "execution_id": execution_id.to_string(),
                    "cursor": next_cursor,
                    "limit": 1,
                })
                .as_object()
                .cloned(),
                Some(&principal),
            )
            .await
            .expect("continue artifact listing");
        assert_eq!(
            structured(&second_page)["artifacts"][0]["reference"]["artifact_id"],
            second_artifact_id.to_string()
        );
        assert!(structured(&second_page).get("next_cursor").is_none());

        let artifact = tools
            .call(
                "artifact",
                json!({
                    "execution_id": execution_id.to_string(),
                    "artifact_id": artifact_id.to_string(),
                })
                .as_object()
                .cloned(),
                Some(&principal),
            )
            .await
            .expect("retrieve failed execution artifact");
        assert_eq!(
            structured(&artifact)["value"],
            json!({"kind": "partial", "rows": [1, 2]})
        );

        let mut other = principal.clone();
        other.sub = "other".to_owned();
        assert_eq!(
            tools
                .call(
                    "artifact",
                    json!({
                        "execution_id": execution_id.to_string(),
                        "artifact_id": artifact_id.to_string(),
                    })
                    .as_object()
                    .cloned(),
                    Some(&other),
                )
                .await
                .expect_err("cross-principal artifact is hidden")
                .data
                .expect("structured artifact error")["error"],
            "execution_artifact_unavailable"
        );

        let mut expired_pause = store
            .current
            .lock()
            .await
            .clone()
            .expect("recorded execution");
        expired_pause.status = ExecutionStatus::WaitingForResume;
        expired_pause.completed_at = None;
        expired_pause.retention_until =
            time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        *store.current.lock().await = Some(expired_pause);
        assert_eq!(
            tools
                .call(
                    "artifact",
                    json!({
                        "execution_id": execution_id.to_string(),
                        "artifact_id": artifact_id.to_string(),
                    })
                    .as_object()
                    .cloned(),
                    Some(&principal),
                )
                .await
                .expect_err("reconciled expiration closes artifact retrieval")
                .data
                .expect("structured expired artifact error")["error"],
            "execution_artifact_unavailable"
        );
    }

    async fn waiting_execution(
        store: &RecordingExecutionStore,
        principal: &Principal,
        status: ExecutionStatus,
    ) -> Uuid {
        let id = Uuid::now_v7();
        let source = "return execution.resume.input;";
        let new_execution = NewExecution {
            program_input: None,
            id,
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: principal.sub.clone(),
            principal_issuer: "test".to_owned(),
            source: Some(source.to_owned()),
            source_digest: source_digest(source),
            execution_profile: json!({
                "name": "direct",
                "profile_confinement": task_profile_confinement(principal),
                "resumable": true,
            }),
            // Legacy contract versions on the planted row: the claim path
            // stamps the CURRENT versions, so a test asserting them proves
            // the claim genuinely ran instead of restating fixture state.
            sdk_contract_version: LEGACY_SDK_CONTRACT_VERSION,
            runner_contract_version: LEGACY_RUNNER_CONTRACT_VERSION,
            retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
        };
        let mut execution = recorded_execution(&new_execution, status, None);
        execution.tool_snapshot = Some(json!({"contract_version": 1, "bindings": []}));
        execution.resume_context = Some(json!({"checkpoint": {"prompt": "Provide a value"}}));
        *store.current.lock().await = Some(execution);
        id
    }

    /// The `tasks/update` alias reports exactly the continuation the paused
    /// execution supports, so the router applies that continuation's
    /// governance. Historical approval waits and ambiguous outcomes expose
    /// no continuation that could replay an effect.
    #[tokio::test]
    async fn tasks_update_continuation_matches_the_waiting_state() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        for (status, expected) in [(ExecutionStatus::WaitingForResume, Some("resume"))] {
            let id = waiting_execution(&store, &principal, status).await;
            let continuation = tools
                .update_task_continuation(&id.to_string(), Some(&principal))
                .await
                .expect("waiting execution names its continuation");
            assert_eq!(continuation, expected, "status {status:?}");
        }

        let id = waiting_execution(&store, &principal, ExecutionStatus::WaitingForApproval).await;
        assert!(tools
            .update_task_continuation(&id.to_string(), Some(&principal))
            .await
            .is_err());

        let id = waiting_execution(&store, &principal, ExecutionStatus::Ambiguous).await;
        let error = tools
            .update_task_continuation(&id.to_string(), Some(&principal))
            .await
            .expect_err("an ambiguous outcome has no retry path");
        assert!(
            error.message.contains("ambiguous"),
            "the refusal must name the ambiguity: {}",
            error.message,
        );

        let id = waiting_execution(&store, &principal, ExecutionStatus::Running).await;
        let error = tools
            .update_task_continuation(&id.to_string(), Some(&principal))
            .await
            .expect_err("a running execution is not awaiting input");
        assert!(error.message.contains("not awaiting"));

        assert!(tools
            .update_task_continuation(&Uuid::now_v7().to_string(), Some(&principal))
            .await
            .expect("unknown id is simply not owned here")
            .is_none());
    }

    /// The listing is the lost-handle recovery surface: it pages the
    /// caller's own in-flight work newest first, scopes every store read by
    /// the caller's full identity and effective profile, and projects each
    /// entry exactly as `codemode.status` would, so a discovered identifier
    /// is immediately actionable.
    #[tokio::test]
    async fn executions_lists_own_in_flight_work_newest_first_and_pages() {
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(store.clone())
        .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        let base = time::OffsetDateTime::now_utc();
        let mut rows = Vec::new();
        for minutes_ago in [3i64, 2, 1] {
            let source = "return 1;";
            let new = NewExecution {
                program_input: None,
                id: Uuid::now_v7(),
                tenant_id: principal.tenant.to_string(),
                principal_sub: principal.sub.clone(),
                principal_issuer: principal.issuer.clone(),
                source: Some(source.to_owned()),
                source_digest: source_digest(source),
                execution_profile: json!({"name": "direct"}),
                sdk_contract_version: SDK_CONTRACT_VERSION,
                runner_contract_version: RUNNER_CONTRACT_VERSION,
                retention_until: base + time::Duration::days(1),
            };
            let mut execution = recorded_execution(&new, ExecutionStatus::Running, None);
            execution.submitted_at = base - time::Duration::minutes(minutes_ago);
            rows.push(execution);
        }
        // A paused row carries a caller-controlled checkpoint the by-id poll
        // would report; the listing must stay bounded by row count and leave
        // that payload behind.
        rows[1].status = ExecutionStatus::WaitingForResume;
        rows[1].resume_context = Some(json!({"step": 7}));
        *store.in_flight.lock().await = rows.clone();

        let first = tools
            .list_executions(
                &principal,
                ExecutionListParams {
                    cursor: None,
                    limit: Some(2),
                },
            )
            .await
            .expect("first page");
        let first = structured(&first);
        let ids: Vec<&str> = first["executions"]
            .as_array()
            .expect("executions array")
            .iter()
            .map(|entry| entry["execution_id"].as_str().expect("execution id"))
            .collect();
        assert_eq!(
            ids,
            vec![rows[2].id.to_string(), rows[1].id.to_string()],
            "newest submissions come first"
        );
        assert_eq!(
            first["executions"][0]["status"], "working",
            "entries speak the status poll's vocabulary"
        );
        assert_eq!(
            first["executions"][1]["status"], "input_required",
            "a paused row reports the lifecycle the by-id poll would"
        );
        assert!(
            first["executions"][1].get("checkpoint").is_none(),
            "a listed entry never carries a checkpoint; the by-id poll reports it"
        );
        let cursor = first["next_cursor"]
            .as_str()
            .expect("a full page carries a continuation cursor")
            .to_owned();

        let second = tools
            .list_executions(
                &principal,
                ExecutionListParams {
                    cursor: Some(cursor),
                    limit: Some(2),
                },
            )
            .await
            .expect("second page");
        let second = structured(&second);
        assert_eq!(
            second["executions"]
                .as_array()
                .expect("executions array")
                .len(),
            1
        );
        assert_eq!(
            second["executions"][0]["execution_id"],
            rows[0].id.to_string(),
            "the cursor resumes exactly after the prior page"
        );
        assert!(
            second.get("next_cursor").is_none(),
            "the final page carries no cursor"
        );

        let owners = store.list_owners.lock().await;
        assert!(!owners.is_empty());
        assert!(
            owners.iter().all(|owner| {
                owner.tenant_id == principal.tenant.to_string()
                    && owner.principal_sub == principal.sub
                    && owner.principal_issuer == principal.issuer
                    && owner.profile_confinement == Value::Null
            }),
            "every store read is scoped by the caller's full identity"
        );
    }

    #[tokio::test]
    async fn executions_refuses_without_durable_continuation_and_teaches_cursor_misuse() {
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        let withheld = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        );
        let error = withheld
            .list_executions(
                &principal,
                ExecutionListParams {
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .expect_err("listing requires durable continuation");
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "execution_poll_unavailable"
        );

        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(Arc::new(RecordingExecutionStore::default()))
        .with_result_persistence_allowed(true);
        let error = tools
            .list_executions(
                &principal,
                ExecutionListParams {
                    cursor: Some("not-a-cursor".to_owned()),
                    limit: None,
                },
            )
            .await
            .expect_err("a garbled cursor cannot address a page");
        assert!(
            error.message.contains("next_cursor"),
            "the refusal teaches the caller where a cursor comes from"
        );
    }

    /// A `tasks/update` keyed `resume` claims the paused execution through
    /// the same claim path as the direct `codemode.resume` tool; the
    /// acknowledgement returns once the claim holds (the continuation runs
    /// detached).
    #[tokio::test]
    async fn tasks_update_resume_claims_the_waiting_execution() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = waiting_execution(&store, &principal, ExecutionStatus::WaitingForResume).await;

        let mut responses = rmcp::model::InputResponses::new();
        responses.insert("resume".to_owned(), json!({"value": 42}));
        tools
            .update_task(&id.to_string(), responses, Some(&principal))
            .await
            .expect("the update claims the waiting execution");

        // The claim ran: the fixture planted LEGACY contract versions, so
        // only the claim path can have stamped the current ones (they stay
        // stable regardless of how the detached continuation ends).
        let persisted = store
            .current
            .lock()
            .await
            .clone()
            .expect("claimed execution");
        assert_eq!(persisted.sdk_contract_version, SDK_CONTRACT_VERSION);
        assert_eq!(persisted.runner_contract_version, RUNNER_CONTRACT_VERSION);
    }

    #[tokio::test]
    async fn tasks_update_retains_the_detached_slot_through_runner_work() {
        let store = Arc::new(RecordingExecutionStore::default());
        let barrier = Arc::new(AttemptBarrier::default());
        let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 2,
            per_tenant: 2,
            detached: 1,
        }));
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(store.clone())
        .with_result_persistence_allowed(true)
        .with_execution_capacity(capacity.clone())
        .with_attempt_barrier(barrier.clone());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant =
            waygate_core::TenantId::parse(format!("task-update-pressure-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = "test".to_owned();

        let first = waiting_execution(&store, &principal, ExecutionStatus::WaitingForResume).await;
        let mut responses = rmcp::model::InputResponses::new();
        responses.insert("resume".to_owned(), Value::Null);
        tools
            .update_task(&first.to_string(), responses, Some(&principal))
            .await
            .expect("first task continuation is acknowledged");
        tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
            .await
            .expect("task continuation reached run_claimed_program");

        let second = waiting_execution(&store, &principal, ExecutionStatus::WaitingForResume).await;
        let mut responses = rmcp::model::InputResponses::new();
        responses.insert("resume".to_owned(), Value::Null);
        let error = tools
            .update_task(&second.to_string(), responses, Some(&principal))
            .await
            .expect_err("a second task continuation cannot bypass detached capacity");
        assert_eq!(
            error.data.as_ref().expect("structured error")["error"],
            "detached_execution_capacity"
        );
        assert_eq!(capacity.detached.available_permits(), 0);

        barrier.release.notify_one();
        for _ in 0..200 {
            if capacity.detached.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            capacity.detached.available_permits() == 1,
            "the task continuation releases its detached slot after work"
        );
    }

    #[tokio::test]
    async fn detached_admission_no_longer_writes_or_renews_principal_leases() {
        let store = Arc::new(RecordingExecutionStore::default());
        let barrier = Arc::new(AttemptBarrier::default());
        let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 2,
            per_tenant: 2,
            detached: 1,
        }));
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(store.clone())
        .with_result_persistence_allowed(true)
        .with_execution_capacity(capacity.clone())
        .with_attempt_barrier(barrier.clone());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant =
            waygate_core::TenantId::parse(format!("slot-renewal-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = "test".to_owned();

        let waiting =
            waiting_execution(&store, &principal, ExecutionStatus::WaitingForResume).await;
        let mut responses = rmcp::model::InputResponses::new();
        responses.insert("resume".to_owned(), Value::Null);
        tools
            .update_task(&waiting.to_string(), responses, Some(&principal))
            .await
            .expect("task continuation is acknowledged");
        tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
            .await
            .expect("task continuation reached run_claimed_program");

        assert!(store.detached_slots.lock().await.is_empty());
        assert!(store.slot_renewals.lock().await.is_empty());
        assert_eq!(capacity.detached.available_permits(), 0);

        barrier.release.notify_one();
        for _ in 0..200 {
            if capacity.detached.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            capacity.detached.available_permits() == 1,
            "the slot is released once the attempt future finishes"
        );
    }

    /// The retry-safe start contract's primary outcome: retrying an
    /// identical detached start converges on the retained execution — even
    /// while it runs and holds a detached slot — instead of being refused
    /// for capacity or starting duplicate work.
    #[tokio::test]
    async fn racing_detached_start_retries_single_flight_before_capacity() {
        let store = Arc::new(RecordingExecutionStore::default());
        let start_barrier = Arc::new(AttemptBarrier::default());
        *store
            .start_or_reuse_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(start_barrier.clone());
        let runner_barrier = Arc::new(AttemptBarrier::default());
        let capacity = Arc::new(CodeModeExecutionCapacity::new(CodeModeCapacityLimits {
            global: 2,
            per_tenant: 1,
            detached: 1,
        }));
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(store.clone())
        .with_result_persistence_allowed(true)
        .with_execution_capacity(capacity.clone())
        .with_attempt_barrier(runner_barrier.clone());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant =
            waygate_core::TenantId::parse(format!("racing-retry-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = format!("issuer-{}", Uuid::new_v4());

        let first_tools = tools.clone();
        let first_principal = principal.clone();
        let first = tokio::spawn(async move {
            first_tools
                .start_detached(&first_principal, "start", start_source("return 1;"))
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), start_barrier.entered.notified())
            .await
            .expect("first start reached durable arbitration");

        let second_tools = tools.clone();
        let second_principal = principal.clone();
        let second = tokio::spawn(async move {
            second_tools
                .start_detached(&second_principal, "start", start_source("return 1;"))
                .await
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !second.is_finished(),
            "the racing retry waits for the first durable arbitration instead of failing capacity"
        );

        start_barrier.release.notify_one();
        let first = first.await.unwrap().expect("first start is admitted");
        let second = second.await.unwrap().expect("racing retry converges");
        assert_eq!(second.id, first.id);
        assert_eq!(store.started.lock().await.len(), 1);
        assert_eq!(capacity.detached.available_permits(), 0);

        tokio::time::timeout(Duration::from_secs(2), runner_barrier.entered.notified())
            .await
            .expect("the one admitted execution reaches runner work");
        runner_barrier.release.notify_one();
        for _ in 0..200 {
            if capacity.detached.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(capacity.detached.available_permits(), 1);
    }

    #[tokio::test]
    async fn detached_start_retry_converges_on_the_retained_execution() {
        let store = Arc::new(RecordingExecutionStore::default());
        let shared: SharedExecutionStore = store.clone();
        let barrier = Arc::new(AttemptBarrier::default());
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(shared)
        .with_result_persistence_allowed(true)
        .with_attempt_barrier(barrier.clone());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant = waygate_core::TenantId::parse(format!("retry-start-{}", Uuid::new_v4()))
            .expect("valid tenant");
        principal.issuer = format!("issuer-{}", Uuid::new_v4());

        let first = tools
            .start_detached(&principal, "start", start_source("return 1;"))
            .await
            .expect("first start is admitted");
        tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
            .await
            .expect("first start reached run_claimed_program");

        let retry = tools
            .start_detached(&principal, "start", start_source("return 1;"))
            .await
            .expect("an identical retry converges instead of being refused");
        assert_eq!(retry.id, first.id, "the retry returns the original handle");
        assert_eq!(
            store.started.lock().await.len(),
            1,
            "no second execution is created for a retry"
        );
        assert_eq!(
            tools.execution_capacity.detached.available_permits(),
            CodeModeCapacityLimits::default().detached - 1,
            "the converged retry neither consumes nor disturbs the slot"
        );

        barrier.release.notify_one();
        for _ in 0..200 {
            if tools.execution_capacity.detached.available_permits()
                == CodeModeCapacityLimits::default().detached
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            tools.execution_capacity.detached.available_permits(),
            CodeModeCapacityLimits::default().detached
        );
    }

    #[tokio::test]
    async fn retained_skill_retries_consume_one_quota_token_per_request() {
        #[derive(Default)]
        struct CountingQuota(AtomicUsize);

        #[async_trait]
        impl waygate_quota::QuotaService for CountingQuota {
            async fn check_and_consume(
                &self,
                _ctx: &waygate_quota::QuotaContext,
                _actions: &[waygate_quota::QuotaAction],
            ) -> Result<(), waygate_quota::QuotaError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let (catalog, loads) = skill_script_catalog_with_load_count(b"return 1;", None).await;
        let reviews = Arc::new(waygate_test_support::skills::SkillReviewFixture::default());
        let principal = reader();
        reviews.approve(principal.tenant.as_str(), &catalog.current().unwrap());
        let store = Arc::new(RecordingExecutionStore::default());
        let quota = Arc::new(CountingQuota::default());
        let barrier = Arc::new(AttemptBarrier::default());
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(waygate_mcp::AllowAllGate),
        )
        .with_skill_script_execution(Some(catalog.clone()))
        .with_reviewed_skills(Some(waygate_test_support::skills::reviewed_catalog(
            catalog, reviews,
        )))
        .with_execution_store(store.clone())
        .with_result_persistence_allowed(true)
        .with_source_artifact_store(Arc::new(MemorySourceArtifactStore::default()))
        .with_quota(Some(quota.clone()))
        .with_attempt_barrier(barrier.clone());
        let start = |repeat: Option<Uuid>| {
            serde_json::from_value(json!({
                "skill_script": "skill://homelab/pr-and-monitor/scripts/pr-wait.js",
                "retain_for_seconds": 3600,
                "repeat_after": repeat.map(|id| id.to_string()),
            }))
            .unwrap()
        };

        let first = tools
            .start_detached(&principal, "start", start(None))
            .await
            .unwrap();
        barrier.entered.notified().await;
        assert_eq!(quota.0.load(Ordering::SeqCst), 1);
        let retry = tools
            .start_detached(&principal, "start", start(None))
            .await
            .unwrap();
        assert_eq!(retry.id, first.id);
        assert_eq!(quota.0.load(Ordering::SeqCst), 2);
        barrier.release.notify_one();
        // Acquiring every slot waits for the held runner to release its slot.
        let slots = tools
            .execution_capacity
            .detached
            .acquire_many(CodeModeCapacityLimits::default().detached as u32)
            .await
            .unwrap();
        drop(slots);
        store.started.lock().await[0].1.status = ExecutionStatus::Succeeded;

        let second = tools
            .start_detached(&principal, "start", start(Some(first.id)))
            .await
            .unwrap();
        barrier.entered.notified().await;
        assert_ne!(second.id, first.id);
        assert_eq!(quota.0.load(Ordering::SeqCst), 3);
        let retry = tools
            .start_detached(&principal, "start", start(Some(first.id)))
            .await
            .unwrap();
        assert_eq!(retry.id, second.id);
        assert_eq!(quota.0.load(Ordering::SeqCst), 4);
        assert_eq!(loads.load(Ordering::SeqCst), 4);
        assert_eq!(store.started.lock().await.len(), 2);
        barrier.release.notify_one();
    }

    #[tokio::test]
    async fn file_backed_start_retry_converges_after_upload_expiry() {
        let store = Arc::new(RecordingExecutionStore::default());
        let source_store = Arc::new(MemorySourceArtifactStore::default());
        let barrier = Arc::new(AttemptBarrier::default());
        let uri = "mcp-file://gateway/019c-retry-source".to_owned();
        let file_reader = Arc::new(MemorySourceFileReader {
            uri: uri.clone(),
            source: tokio::sync::Mutex::new(Some("return 1;".to_owned())),
        });
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(store.clone())
        .with_result_persistence_allowed(true)
        .with_source_artifact_store(source_store.clone())
        .with_source_file_reader(Some(file_reader.clone()))
        .with_attempt_barrier(barrier.clone());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant =
            waygate_core::TenantId::parse(format!("retry-file-start-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = format!("issuer-{}", Uuid::new_v4());
        source_store
            .retain_source(
                &CodeModeTools::source_owner(&principal),
                "return 1;",
                &source_digest("return 1;"),
                Duration::from_secs(3600),
            )
            .await
            .expect("retain source for the hash selector");
        let start = || StartParams {
            input: None,
            source: None,
            source_file: Some(uri.clone()),
            source_sha256: None,
            skill_script: None,
            skill_revision: None,
            retain_for_seconds: None,
            repeat_after: None,
        };

        let first = tools
            .start_detached(&principal, "start", start())
            .await
            .expect("file-backed start is admitted");
        tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
            .await
            .expect("first start reached run_claimed_program");
        let inline = tools
            .start_detached(&principal, "start", start_source("return 1;"))
            .await
            .expect("inline bytes converge with the uploaded source");
        assert_eq!(inline.id, first.id);
        let retained = tools
            .start_detached(
                &principal,
                "start",
                StartParams {
                    input: None,
                    source: None,
                    source_file: None,
                    source_sha256: Some(source_digest("return 1;")),
                    skill_script: None,
                    skill_revision: None,
                    retain_for_seconds: None,
                    repeat_after: None,
                },
            )
            .await
            .expect("the exact retained hash converges with the uploaded source");
        assert_eq!(retained.id, first.id);
        *file_reader.source.lock().await = None;

        let retry = tools
            .start_detached(&principal, "start", start())
            .await
            .expect("identical retry converges after the upload expires");
        assert_eq!(retry.id, first.id);
        assert_eq!(store.started.lock().await.len(), 1);

        let retention_error = tools
            .start_detached(
                &principal,
                "start",
                StartParams {
                    retain_for_seconds: Some(3600),
                    ..start()
                },
            )
            .await
            .expect_err("a dead upload locator cannot create fresh source retention");
        assert_eq!(
            retention_error.data.as_ref().expect("structured error")["error"],
            "source_file_not_found"
        );

        barrier.release.notify_one();
        for _ in 0..200 {
            if tools.execution_capacity.detached.available_permits()
                == CodeModeCapacityLimits::default().detached
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            tools.execution_capacity.detached.available_permits(),
            CodeModeCapacityLimits::default().detached
        );
        store.started.lock().await[0].1.status = ExecutionStatus::Succeeded;

        let repeat_error = tools
            .start_detached(
                &principal,
                "start",
                StartParams {
                    input: None,
                    source: None,
                    source_file: Some(uri),
                    source_sha256: None,
                    skill_script: None,
                    skill_revision: None,
                    retain_for_seconds: None,
                    repeat_after: Some(first.id.to_string()),
                },
            )
            .await
            .expect_err("a dead upload locator cannot authorize deliberate new work");
        assert_eq!(
            repeat_error.data.as_ref().expect("structured error")["error"],
            "source_file_not_found"
        );
        assert_eq!(store.started.lock().await.len(), 1);
    }

    /// Deliberate repetition is distinguishable from retry: it must name the
    /// latest retained terminal execution, a premature or unknown name is
    /// refused with a teach-through, and a repetition whose response was
    /// lost converges on the newer handle rather than repeating twice.
    #[tokio::test]
    async fn deliberate_repetition_names_the_terminal_handle_and_lost_retries_converge() {
        let store = Arc::new(RecordingExecutionStore::default());
        let shared: SharedExecutionStore = store.clone();
        let barrier = Arc::new(AttemptBarrier::default());
        let tools = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(shared)
        .with_result_persistence_allowed(true)
        .with_attempt_barrier(barrier.clone());
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        principal.tenant =
            waygate_core::TenantId::parse(format!("repeat-start-{}", Uuid::new_v4()))
                .expect("valid tenant");
        principal.issuer = format!("issuer-{}", Uuid::new_v4());
        let start = || start_source("return 1;");
        let repeat = |id: uuid::Uuid| repeat_source("return 1;", id);

        let first = tools
            .start_detached(&principal, "start", start())
            .await
            .expect("first start is admitted");
        tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
            .await
            .expect("first start reached run_claimed_program");

        let premature = tools
            .start_detached(&principal, "start", repeat(first.id))
            .await
            .expect_err("a repetition of a running execution is refused");
        assert_eq!(
            premature.data.as_ref().expect("structured error")["error"],
            "execution_repeat_not_terminal"
        );
        let unknown = tools
            .start_detached(&principal, "start", repeat(uuid::Uuid::now_v7()))
            .await
            .expect_err("an unknown repeat handle is refused");
        assert_eq!(
            unknown.data.as_ref().expect("structured error")["error"],
            "execution_repeat_unavailable"
        );

        barrier.release.notify_one();
        for _ in 0..200 {
            if tools.execution_capacity.detached.available_permits()
                == CodeModeCapacityLimits::default().detached
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        store.started.lock().await[0].1.status = ExecutionStatus::Succeeded;

        let second = tools
            .start_detached(&principal, "start", repeat(first.id))
            .await
            .expect("naming the latest terminal execution creates the next run");
        assert_ne!(second.id, first.id, "a deliberate repetition is new work");
        tokio::time::timeout(Duration::from_secs(2), barrier.entered.notified())
            .await
            .expect("the repetition reached run_claimed_program");

        let converged = tools
            .start_detached(&principal, "start", repeat(first.id))
            .await
            .expect("a lost-response repetition retry converges on the newer handle");
        assert_eq!(converged.id, second.id);
        assert_eq!(
            store.started.lock().await.len(),
            2,
            "retrying the repetition never creates a third execution"
        );

        let blocking = tools
            .execute(&principal, repeat_source("return 1;", first.id))
            .await
            .expect_err("the blocking shape refuses a repetition request");
        assert_eq!(
            blocking.data.as_ref().expect("structured error")["error"],
            "execution_repeat_requires_detached_start"
        );

        // Convergence must survive an exhausted allowance: the same failure
        // that forces a retry may have consumed the last quota unit.
        let denying: Arc<dyn waygate_quota::QuotaService> = Arc::new(ExhaustedQuota);
        let throttled = code_mode_tools(
            Arc::new(FakeCatalog::with_tools(&[])),
            Arc::new(SelectiveAuthz),
        )
        .with_execution_store(store.clone() as SharedExecutionStore)
        .with_result_persistence_allowed(true)
        .with_quota(Some(denying));
        let recovered = throttled
            .start_detached(&principal, "start", start())
            .await
            .expect("a retry converges without consuming quota");
        assert_eq!(recovered.id, second.id);
        let fresh = throttled
            .start_detached(&principal, "start", start_source("return 99;"))
            .await
            .expect_err("new work still pays quota");
        assert_eq!(
            fresh.data.as_ref().expect("structured error")["error"],
            "rate_limited"
        );

        barrier.release.notify_one();
        for _ in 0..200 {
            if tools.execution_capacity.detached.available_permits()
                == CodeModeCapacityLimits::default().detached
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            tools.execution_capacity.detached.available_permits(),
            CodeModeCapacityLimits::default().detached
        );
    }

    #[test]
    fn dedupe_key_width_is_independent_of_identity_length() {
        let mut short = reader();
        short.issuer = "i".to_owned();
        short.sub = "s".to_owned();
        let mut long = reader();
        long.issuer = "i".repeat(4096);
        long.sub = "s".repeat(4096);
        assert_eq!(
            detached_start_dedupe_key(&short, &source_digest("return 1;"), &Value::Null, None)
                .len(),
            detached_start_dedupe_key(&long, &source_digest("return 1;"), &Value::Null, None).len(),
            "indexed key width must not grow with identity claims"
        );
    }

    /// Input is what distinguishes two starts of the same program, because
    /// the source digest deliberately does not. Were it absent from the key,
    /// a start against one input would be served another start's result.
    #[test]
    fn retry_equivalence_separates_starts_that_differ_only_by_input() {
        let principal = reader();
        let digest = source_digest("return execution.input.pr;");
        let key_for = |input: Value| detached_start_dedupe_key(&principal, &digest, &input, None);

        assert_ne!(
            key_for(serde_json::json!({"pr": 71})),
            key_for(serde_json::json!({"pr": 72})),
        );
        assert_ne!(
            key_for(serde_json::json!({"pr": 71})),
            key_for(Value::Null),
            "supplying input must not converge with supplying none",
        );
        assert_eq!(
            key_for(serde_json::json!({"pr": 71})),
            key_for(serde_json::json!({"pr": 71})),
            "the same program and input stays one retry-equivalence class",
        );
    }

    /// Executions outlive the binary that submitted them, so adding the input
    /// channel must not renumber the class a no-input start already belongs
    /// to. The expected key is spelled out here rather than taken from the
    /// function, because the contract under test is the durable format retained
    /// rows were written with, not whatever the current code computes.
    #[test]
    fn a_start_without_input_keys_as_it_did_before_the_input_channel() {
        let principal = reader();
        let digest = source_digest("return 1;");
        let before_the_input_channel = source_digest(&format!(
            "start\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            principal.tenant.as_str(),
            principal.issuer,
            principal.sub,
            digest,
        ));

        assert_eq!(
            detached_start_dedupe_key(&principal, &digest, &Value::Null, None),
            before_the_input_channel,
            "a retained no-input start must stay findable across the upgrade",
        );
    }

    /// The update carries exactly one recognized continuation key; anything
    /// else is refused with a teach-through before any claim.
    #[tokio::test]
    async fn tasks_update_requires_exactly_one_recognized_key() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let tools = code_mode_tools(catalog, authz);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());

        let error = tools
            .update_task(
                &Uuid::now_v7().to_string(),
                rmcp::model::InputResponses::new(),
                Some(&principal),
            )
            .await
            .expect_err("an empty update advances nothing");
        assert!(error.message.contains("exactly one response"));

        let mut two = rmcp::model::InputResponses::new();
        two.insert("resume".to_owned(), json!(null));
        two.insert("resume_mutation".to_owned(), json!(true));
        assert!(tools
            .update_task(&Uuid::now_v7().to_string(), two, Some(&principal))
            .await
            .expect_err("two keys are ambiguous")
            .message
            .contains("exactly one response"));

        let mut unknown = rmcp::model::InputResponses::new();
        unknown.insert("continue".to_owned(), json!(true));
        let error = tools
            .update_task(&Uuid::now_v7().to_string(), unknown, Some(&principal))
            .await
            .expect_err("unrecognized keys are refused");
        assert!(
            error.message.contains("`resume`") && !error.message.contains("`resume_mutation`"),
            "the refusal must teach the valid keys: {}",
            error.message,
        );
    }

    /// Ownership binds tenant + issuer + subject: a caller whose issuer
    /// differs — or an execution that predates issuer recording — owns
    /// nothing, even with a matching `sub`.
    #[tokio::test]
    async fn execution_ownership_requires_the_matching_issuer() {
        let catalog: SharedCatalog = Arc::new(FakeCatalog::with_tools(&[]));
        let authz: SharedAuthz = Arc::new(SelectiveAuthz);
        let store = Arc::new(RecordingExecutionStore::default());
        let tools = code_mode_tools(catalog, authz)
            .with_execution_store(store.clone())
            .with_result_persistence_allowed(true);
        let mut principal = reader();
        principal.scopes.push(Scope::McpInvoke.as_str().to_owned());
        let id = waiting_execution(&store, &principal, ExecutionStatus::WaitingForResume).await;

        assert!(tools
            .get_task(&id.to_string(), Some(&principal))
            .await
            .expect("owner lookup")
            .is_some());

        let mut other_issuer = principal.clone();
        other_issuer.issuer = "https://other-issuer.test".to_owned();
        assert!(
            tools
                .get_task(&id.to_string(), Some(&other_issuer))
                .await
                .expect("cross-issuer lookup")
                .is_none(),
            "a same-sub principal from another issuer is a different person",
        );

        // A pre-upgrade row records no issuer: owned by no one.
        store
            .current
            .lock()
            .await
            .as_mut()
            .expect("planted execution")
            .principal_issuer = None;
        assert!(
            tools
                .get_task(&id.to_string(), Some(&principal))
                .await
                .expect("issuerless lookup")
                .is_none(),
            "an issuer-less pre-upgrade execution fails closed",
        );
    }
}
