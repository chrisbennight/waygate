//! Policy/manifest bundle change-executors — split from `change_executor.rs`.
//! Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;
use crate::dashboard_server_manifests::canonical_disk_hash;
use crate::manifest_bundles::{
    merge_upserts_into_live_set, publish_bundle_core_from_base as publish_manifest_core_from_base,
    remove_servers_core, remove_servers_from_live_set,
    rollback_bundle_core_from_base as rollback_manifest_core_from_base, stage_and_publish_core,
    upsert_servers_core,
};

/// Add the canonical on-disk fingerprint that gateway replicas report in
/// their heartbeats. The ledger's `content_hash` fingerprints the submitted
/// YAML, which can differ from the canonical serialization without changing
/// runtime content; activation verification must compare like with like.
fn manifest_execution_result(
    tenant_id: &str,
    bundle: &waygate_manifest_store::ManifestBundle,
    mut details: serde_json::Map<String, Value>,
) -> Value {
    details.insert("bundle_id".to_owned(), serde_json::json!(bundle.id));
    details.insert("version".to_owned(), serde_json::json!(bundle.version));
    details.insert(
        "content_hash".to_owned(),
        serde_json::json!(bundle.content_hash),
    );
    if tenant_id == waygate_core::TenantId::DEFAULT {
        match canonical_disk_hash(&bundle.content) {
            Ok(activation_hash) => {
                details.insert(
                    "activation_hash".to_owned(),
                    serde_json::json!(activation_hash),
                );
            }
            Err(error) => {
                // Publication already completed inside the shared core. Receipt
                // enrichment is observational and must not relabel that durable
                // success as failed; the dashboard will report verification as
                // unavailable when this fingerprint is absent.
                tracing::error!(
                    error = %error,
                    manifest_version = bundle.version,
                    "published manifest could not produce an activation fingerprint",
                );
            }
        }
    }
    Value::Object(details)
}

/// Params for `policy.publish`: the draft bundle id to mirror-and-publish.
/// Tenant-scoped through the approver's principal — `publish_bundle_core`
/// resolves tenant + publisher from it, so a maker can only publish a draft in
/// their own tenant.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct PolicyPublishParams {
    pub(super) bundle_id: Uuid,
}

pub(super) struct PolicyPublishExecutor;

#[async_trait]
impl ActionExecutor for PolicyPublishExecutor {
    fn action_type(&self) -> &'static str {
        "policy.publish"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: PolicyPublishParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Reuse the same core the REST publish handler calls: turnstile +
        // mirror-before-ledger (disk-wins) + AdminMutation audit. The approver
        // is the publisher, and the core derives the tenant from it (== the
        // change request's tenant), so a maker can't publish into another
        // tenant. map_core_error maps a lost turnstile / no-op / non-draft
        // (ApiError::Conflict) to Precondition (-> the change is durably
        // `failed`), and a DiskAhead / mirror double-fault
        // (InternalOperatorVisible) to Store (loud). The result is a non-secret
        // fingerprint of the now-active bundle.
        let bundle = publish_bundle_core(state, Some(actor), p.bundle_id)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "bundle_id": bundle.id,
            "version": bundle.version,
            "content_hash": bundle.content_hash,
        })))
    }
}

// ---- policy.rollback ----

/// Params for `policy.rollback`: the previously-published version to
/// re-activate (a roll-forward of that version's content). Tenant-scoped via
/// the approver's principal, like `policy.publish`.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct PolicyRollbackParams {
    pub(super) version: i32,
}

pub(super) struct PolicyRollbackExecutor;

#[async_trait]
impl ActionExecutor for PolicyRollbackExecutor {
    fn action_type(&self) -> &'static str {
        "policy.rollback"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: PolicyRollbackParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Same core the REST rollback handler calls. A missing target version
        // (ApiError::NotFoundDyn) or a never-published draft target / lost
        // turnstile / no-op (ApiError::Conflict) both map to Precondition
        // (-> failed); a DiskAhead / mirror double-fault maps to Store. The
        // result fingerprints the version rolled back to and the new active
        // version it was re-published as.
        let bundle = rollback_bundle_core(state, Some(actor), p.version)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "rolled_back_to_version": p.version,
            "new_version": bundle.version,
            "content_hash": bundle.content_hash,
        })))
    }
}

// ---- policy.upsert_fragment ----

/// Params for `policy.upsert_fragment`: exactly one Cedar policy statement,
/// addressed by its required `@id`, plus an optional author label. The gateway
/// merges it into the live on-disk set, requires an impact replay, stages the
/// reconstructed full bundle, and publishes it in the approved execution.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct PolicyUpsertFragmentParams {
    /// Exact `context.base_hash` returned by
    /// `gateway-admin.get_action_context` for this live policy snapshot.
    /// Proposing against any other current snapshot is refused.
    pub(super) base_hash: String,
    /// Exactly one complete Cedar policy statement with a unique `@id("…")`
    /// annotation. An existing id is replaced; a new id is appended. Unrelated
    /// live policies are preserved server-side.
    pub(super) statement: String,
    /// Optional author label recorded on the staged bundle.
    #[serde(default)]
    pub(super) author: Option<String>,
}

pub(super) struct PolicyUpsertFragmentExecutor;

#[async_trait]
impl ActionExecutor for PolicyUpsertFragmentExecutor {
    fn action_type(&self) -> &'static str {
        "policy.upsert_fragment"
    }

    fn file_params(&self) -> &'static [FileBackedParam] {
        &[FileBackedParam {
            pointer: "/statement",
            description: "UTF-8 Cedar source containing exactly one complete policy statement \
                          with a unique `@id(\"…\")` annotation",
        }]
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        if tenant_id != waygate_core::TenantId::DEFAULT {
            return Err(ExecError::BadParams(
                "policy fragment upsert currently supports only the default tenant".to_owned(),
            ));
        }
        let p: PolicyUpsertFragmentParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let merged =
            merge_policy_fragment_into_live_set(state, &p.statement).map_err(map_core_error)?;
        if merged.base_hash != p.base_hash {
            return Err(ExecError::Precondition(
                "the live policy set no longer matches params.base_hash; call \
                 gateway-admin.get_action_context again and re-prepare the proposal"
                    .to_owned(),
            ));
        }
        Ok(Some(merged.base_hash))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let target_etag = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, target_etag.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let p: PolicyUpsertFragmentParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let proposed_base = target_etag.ok_or_else(|| {
            ExecError::Precondition(
                "the proposal is missing its captured live-policy-set witness".to_owned(),
            )
        })?;
        let outcome = upsert_policy_fragment_core(
            state,
            Some(actor),
            &p.statement,
            p.author.as_deref(),
            proposed_base,
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "bundle_id": outcome.bundle.id,
            "version": outcome.bundle.version,
            "content_hash": outcome.bundle.content_hash,
            "policy_id": outcome.policy_id,
            "impact_previewed": true,
        })))
    }
}

// ---- manifest.publish ----

/// Params for `manifest.publish`: the draft server-manifest bundle id to
/// mirror-and-publish. Tenant-scoped through the approver's principal — a maker
/// publishes a draft in their own tenant. Symmetric with `policy.publish`.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ManifestPublishParams {
    pub(super) bundle_id: Uuid,
}

pub(super) struct ManifestPublishExecutor;

#[async_trait]
impl ActionExecutor for ManifestPublishExecutor {
    fn action_type(&self) -> &'static str {
        "manifest.publish"
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let p: ManifestPublishParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let store = state
            .servers
            .manifest_store
            .get()
            .ok_or_else(|| ExecError::Store("manifest store is not configured".to_owned()))?;
        let target = store
            .get(tenant_id, p.bundle_id)
            .await
            .map_err(|e| ExecError::Precondition(e.to_string()))?;
        if target.status != waygate_manifest_store::ManifestStatus::Draft {
            return Err(ExecError::Precondition(
                "manifest publish target is no longer a draft".to_owned(),
            ));
        }
        let witness = ManifestFullSetWitness {
            target_content_hash: target.content_hash,
            live_base_hash: optional_live_manifest_base_hash(state, tenant_id)?,
        };
        serde_json::to_string(&witness)
            .map(Some)
            .map_err(|e| ExecError::Store(format!("encode manifest publish witness: {e}")))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let target_etag = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, target_etag.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ManifestPublishParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let witness = parse_manifest_full_set_witness(target_etag)?;
        // Reuse the same core the REST publish handler calls: turnstile CAS +
        // mirror-before-ledger + doorbell + AdminMutation audit. The approver is
        // the publisher, and the core derives the tenant from it (== the change
        // request's tenant). map_core_error maps a non-draft / lost turnstile
        // (NotFound / Conflict) to Precondition, a no-op
        // (UnprocessableEntity: disk already current) to BadParams, and a mirror
        // failure (Internal) to Store (loud) — each marks the change `failed`
        // rather than reporting a phantom publish. Result is a non-secret
        // fingerprint of the now-active bundle.
        let bundle = publish_manifest_core_from_base(
            state,
            Some(actor),
            p.bundle_id,
            witness.live_base_hash.as_deref(),
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(manifest_execution_result(
            tenant_id,
            &bundle,
            serde_json::Map::new(),
        )))
    }
}

// ---- manifest.rollback ----

/// Params for `manifest.rollback`: the previously-published version to
/// re-activate (roll-forward of that version's content). Tenant-scoped via the
/// approver's principal, like `manifest.publish`.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ManifestRollbackParams {
    pub(super) version: i32,
}

pub(super) struct ManifestRollbackExecutor;

#[async_trait]
impl ActionExecutor for ManifestRollbackExecutor {
    fn action_type(&self) -> &'static str {
        "manifest.rollback"
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let p: ManifestRollbackParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let store = state
            .servers
            .manifest_store
            .get()
            .ok_or_else(|| ExecError::Store("manifest store is not configured".to_owned()))?;
        let target = store
            .get_by_version(tenant_id, p.version)
            .await
            .map_err(|e| ExecError::Precondition(e.to_string()))?;
        let witness = ManifestFullSetWitness {
            target_content_hash: target.content_hash,
            live_base_hash: optional_live_manifest_base_hash(state, tenant_id)?,
        };
        serde_json::to_string(&witness)
            .map(Some)
            .map_err(|e| ExecError::Store(format!("encode manifest rollback witness: {e}")))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let target_etag = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, target_etag.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ManifestRollbackParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let witness = parse_manifest_full_set_witness(target_etag)?;
        // Same core the REST rollback handler calls. A missing target version
        // (NotFound) or lost turnstile (Conflict) maps to Precondition; a no-op
        // (UnprocessableEntity) to BadParams; a mirror failure (Internal) to
        // Store. The result fingerprints the version rolled back to and the new
        // active version it was re-published as.
        let bundle = rollback_manifest_core_from_base(
            state,
            Some(actor),
            p.version,
            witness.live_base_hash.as_deref(),
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(manifest_execution_result(
            tenant_id,
            &bundle,
            serde_json::Map::from_iter([
                (
                    "rolled_back_to_version".to_owned(),
                    serde_json::json!(p.version),
                ),
                ("new_version".to_owned(), serde_json::json!(bundle.version)),
            ]),
        )))
    }
}

// ---- manifest.stage_and_publish ----

/// Params for `manifest.stage_and_publish`: the full manifest-set YAML to stage
/// as a draft and publish in one approved step, plus an optional author label.
/// Lets an agent author a manifest change through the HITL flow (propose → human
/// approves the previewed effect → server-side publish) instead of editing
/// `servers/*.yaml` on the NFS volume directly, which leaves the Postgres ledger
/// stale. Tenant-scoped through the approver's principal, like `manifest.publish`.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ManifestStageAndPublishParams {
    /// Exact `context.base_hash` returned by
    /// `gateway-admin.get_action_context` for the live manifest snapshot this
    /// replacement was prepared from.
    pub(super) base_hash: String,
    /// Full manifest-set source: a YAML sequence of upstream manifests (the same
    /// shape `POST /api/v1/server_manifests` accepts). Validated with
    /// `parse_manifest_set` before anything is staged.
    pub(super) content: String,
    /// Optional author label recorded on the bundle.
    #[serde(default)]
    pub(super) author: Option<String>,
}

pub(super) struct ManifestStageAndPublishExecutor;

#[async_trait]
impl ActionExecutor for ManifestStageAndPublishExecutor {
    fn action_type(&self) -> &'static str {
        "manifest.stage_and_publish"
    }

    fn file_params(&self) -> &'static [FileBackedParam] {
        &[FileBackedParam {
            pointer: "/content",
            description: "UTF-8 YAML sequence of complete upstream manifests — the whole live \
                          set, the same shape the inline `content` field takes",
        }]
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let p: ManifestStageAndPublishParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        waygate_upstream::parse_manifest_set(&p.content)
            .map_err(|e| ExecError::BadParams(format!("manifest set is not valid: {e}")))?;
        let current = live_manifest_base_hash(state, tenant_id)?;
        ensure_prepared_base_matches(&p.base_hash, &current)?;
        Ok(Some(current))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ManifestStageAndPublishParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Reuse the shared core: validate → stage draft → publish (turnstile CAS +
        // mirror-before-ledger + doorbell + AdminMutation audit), all in the
        // approver's tenant. map_core_error maps a bad/empty set (BadRequest) and a
        // no-op (UnprocessableEntity: content already live) to BadParams, a lost
        // turnstile (Conflict) to Precondition, and a mirror failure (Internal) to
        // Store — so the change is marked `failed` rather than reporting a phantom
        // publish. The result is a non-secret fingerprint of the now-active bundle.
        let bundle = stage_and_publish_core(
            state,
            Some(actor),
            &p.content,
            p.author.as_deref(),
            &p.base_hash,
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(manifest_execution_result(
            tenant_id,
            &bundle,
            serde_json::Map::new(),
        )))
    }
}

// ---- manifest.upsert_servers ----

/// Params for `manifest.upsert_servers`: a PARTIAL manifest set — only the
/// servers to add or replace (keyed by `name`) — plus an optional author label.
/// The servers are merged into the live on-disk set server-side and the
/// reconstructed full set is published. Because the params carry only the changed
/// servers (not the whole set), their size tracks the change rather than the
/// deployment — the path for large deployments and the common single-server edit,
/// where a full-set replacement would resend every unrelated manifest.
/// Add/replace only; use `manifest.remove_servers` for selected-name removal.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ManifestUpsertServersParams {
    /// Opaque `context.base_hash` returned by
    /// `gateway-admin.get_action_context` for the live manifest snapshot these
    /// additions or replacements were prepared from. Copy it verbatim; never
    /// calculate it.
    pub(super) base_hash: String,
    /// Partial manifest-set source: a YAML sequence of complete upstream
    /// manifests to add or replace by `name`, not a tool fragment. Validated with
    /// `parse_manifest_set`, then merged into the live set before publishing.
    pub(super) content: String,
    /// Optional author label recorded on the bundle.
    #[serde(default)]
    pub(super) author: Option<String>,
}

pub(super) struct ManifestUpsertServersExecutor;

#[async_trait]
impl ActionExecutor for ManifestUpsertServersExecutor {
    fn action_type(&self) -> &'static str {
        "manifest.upsert_servers"
    }

    fn file_params(&self) -> &'static [FileBackedParam] {
        &[FileBackedParam {
            pointer: "/content",
            description: "UTF-8 YAML sequence of the complete upstream manifests to add or \
                          replace by `name` — a partial set, not a tool fragment",
        }]
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        if tenant_id != waygate_core::TenantId::DEFAULT {
            return Err(ExecError::BadParams(
                "manifest server upsert currently supports only the default tenant because the \
                 live on-disk manifest set is gateway-wide"
                    .to_owned(),
            ));
        }
        let p: ManifestUpsertServersParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let (_, current) =
            merge_upserts_into_live_set(state, &p.content).map_err(map_core_error)?;
        ensure_prepared_base_matches(&p.base_hash, &current)?;
        Ok(Some(current))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ManifestUpsertServersParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Merge the upserts into the live on-disk set, then publish the
        // reconstructed full set through the shared core (turnstile CAS +
        // mirror-before-ledger + doorbell + AdminMutation audit) in the approver's
        // tenant. map_core_error maps a bad/empty upsert set or unreadable live set
        // to BadParams / Store, a lost turnstile to Precondition — so a failed
        // execute marks the change `failed` rather than reporting a phantom
        // publish. The result is a non-secret fingerprint of the now-active bundle.
        let bundle = upsert_servers_core(
            state,
            Some(actor),
            &p.content,
            p.author.as_deref(),
            &p.base_hash,
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(manifest_execution_result(
            tenant_id,
            &bundle,
            serde_json::Map::new(),
        )))
    }
}

// ---- manifest.remove_servers ----

/// Params for `manifest.remove_servers`: selected live server names plus the
/// manifest snapshot they were selected from. The gateway reconstructs the
/// full set server-side, so proposal size scales with the removal rather than
/// the deployment.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ManifestRemoveServersParams {
    /// Exact `context.base_hash` returned by
    /// `gateway-admin.get_action_context` for the live manifest snapshot.
    pub(super) base_hash: String,
    /// Exact server names to remove. Every name must exist in the inspected live
    /// set; unknown or duplicate names are rejected.
    #[schemars(length(min = 1))]
    pub(super) server_names: Vec<String>,
    /// Optional author label recorded on the bundle.
    #[serde(default)]
    pub(super) author: Option<String>,
}

pub(super) struct ManifestRemoveServersExecutor;

#[async_trait]
impl ActionExecutor for ManifestRemoveServersExecutor {
    fn action_type(&self) -> &'static str {
        "manifest.remove_servers"
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        if tenant_id != waygate_core::TenantId::DEFAULT {
            return Err(ExecError::BadParams(
                "manifest server removal currently supports only the default tenant because the \
                 live on-disk manifest set is gateway-wide"
                    .to_owned(),
            ));
        }
        let p: ManifestRemoveServersParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let (_, current) =
            remove_servers_from_live_set(state, &p.server_names, Some(p.base_hash.as_str()))
                .map_err(map_core_error)?;
        Ok(Some(current))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ManifestRemoveServersParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let bundle = remove_servers_core(
            state,
            Some(actor),
            &p.server_names,
            p.author.as_deref(),
            &p.base_hash,
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(manifest_execution_result(
            tenant_id,
            &bundle,
            serde_json::Map::from_iter([(
                "removed_servers".to_owned(),
                serde_json::json!(p.server_names),
            )]),
        )))
    }
}

fn live_manifest_base_hash(state: &AdminState, tenant_id: &str) -> Result<String, ExecError> {
    if tenant_id != waygate_core::TenantId::DEFAULT {
        return Err(ExecError::BadParams(
            "manifest replacement currently supports only the default tenant because the live \
             on-disk manifest set is gateway-wide"
                .to_owned(),
        ));
    }
    optional_live_manifest_base_hash(state, tenant_id)?.ok_or_else(|| {
        ExecError::Store(crate::manifest_bundles::MANIFEST_SERVERS_DIR_UNAVAILABLE.to_owned())
    })
}

fn optional_live_manifest_base_hash(
    state: &AdminState,
    tenant_id: &str,
) -> Result<Option<String>, ExecError> {
    if tenant_id != waygate_core::TenantId::DEFAULT {
        return Ok(None);
    }
    match state.read_manifest_set_from_disk() {
        Some(Ok((_, base_hash))) => Ok(Some(base_hash)),
        Some(Err(e)) => Err(ExecError::Store(format!(
            "could not read the live manifest set: {e}"
        ))),
        None => Ok(None),
    }
}

fn parse_manifest_full_set_witness(
    target_etag: Option<&str>,
) -> Result<ManifestFullSetWitness, ExecError> {
    let encoded = target_etag.ok_or_else(|| {
        ExecError::Precondition(
            "the proposal is missing its captured manifest target and live-set witness".to_owned(),
        )
    })?;
    serde_json::from_str(encoded).map_err(|e| {
        ExecError::Precondition(format!(
            "the proposal carries an invalid manifest target witness: {e}"
        ))
    })
}

fn ensure_prepared_base_matches(proposed: &str, current: &str) -> Result<(), ExecError> {
    if proposed == current {
        return Ok(());
    }
    Err(ExecError::Precondition(
        "the live manifest set no longer matches params.base_hash; call \
         gateway-admin.get_action_context again and re-prepare the proposal"
            .to_owned(),
    ))
}
