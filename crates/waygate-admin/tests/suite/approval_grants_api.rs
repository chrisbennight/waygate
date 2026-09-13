//! Route-level coverage for `/api/v1/admin/approval_grants`.
//!
//! Uses an in-memory `CatalogStore` fake that actually implements
//! create/list/revoke + a Live `resolve_tool` so the handlers'
//! tool-resolution + behavior-and-argument binding + lifetime-clamp logic
//! is exercised end-to-end without a Postgres dependency.
//!
//! Pins:
//! 1. POST mints a grant; the stored binding matches the live tool behavior
//!    hash plus `waygate_catalog::argument_hash` for the same args.
//! 2. POST requires exactly one of `arguments` / `argument_hash`.
//! 3. POST 404s when the qualified tool isn't Live in the catalog.
//! 4. POST clamps the lifetime to `[60s, 7d]` (a 1s request floor
//!    to 60s; a 10y request ceiling to 7d).
//! 5. GET returns the live grants in the caller's tenant.
//! 6. DELETE revokes a live grant (204); a second DELETE 404s.
//! 7. Scopes: missing → 401, mcp:read → 403, mcp:admin → through.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tower::util::ServiceExt;
use uuid::Uuid;

use waygate_admin::{api_router, AdminState};
use waygate_catalog::{
    ApprovalAction, ApprovalGrant, CatalogError, CatalogServerStatus, CatalogServerSummary,
    DriftEvent, DriftObservation, GrantFilter, GrantLookup, NewApprovalGrant, ResolvedTool,
    SharedCatalogStore, ToolDefinition,
};
use waygate_codemode::{
    DetachedExecutionSlot, Execution, ExecutionArtifact, ExecutionArtifactContent, ExecutionClaim,
    ExecutionEvent, ExecutionStatus, ExecutionStore, ExecutionTransition, NewExecution,
    NewExecutionEvent, ResumeExecution, RetryEquivalence, SharedExecutionStore,
    SourceArtifactOwner, StartExecution, StartExecutionResult,
};
use waygate_core::store::StoreError;
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;

mod email_policy;

/// In-memory grant store. `resolve_tool` returns a canned Live tool
/// (or NotFound for the "unknown" test); `create_grant` / `list_grants`
/// / `revoke_grant` operate on a `Vec<ApprovalGrant>` behind a
/// `std::sync::Mutex` (no contention in tests).
struct GrantFakeCatalog {
    tool_id: Uuid,
    server_id: Uuid,
    /// When false, `resolve_tool` returns NotFound — drives the 404
    /// branch of `create_grant`.
    tool_present: bool,
    /// When set, `resolve_live_tool_id` reports this schema hash instead of
    /// the reviewed `"h"` — simulating a tool-version change between listing
    /// and approval.
    live_schema_override: Option<String>,
    requires_approval: bool,
    /// When true, `tool()` reports the tool as annotation-native
    /// (`classification_mode = "mcp_annotations"`) with the legacy
    /// `side_effects` flag forced false, mirroring how annotation manifests are
    /// imported. Effectfulness for such tools comes from reviewed annotations at
    /// dispatch, not this flag.
    annotation_native: bool,
    grants: Mutex<Vec<ApprovalGrant>>,
}

impl GrantFakeCatalog {
    fn new(tool_present: bool) -> Self {
        Self {
            tool_id: Uuid::from_u128(0xAAAA),
            server_id: Uuid::from_u128(0xBBBB),
            tool_present,
            live_schema_override: None,
            requires_approval: true,
            annotation_native: false,
            grants: Mutex::new(Vec::new()),
        }
    }

    /// The Cedar-only shape: a live side-effecting tool whose catalog
    /// classification does NOT require approval — the pause came from an
    /// approval-overlay policy verdict instead of the per-tool flag.
    fn new_policy_gated() -> Self {
        Self {
            requires_approval: false,
            ..Self::new(true)
        }
    }

    /// An annotation-native tool: `classification_mode = "mcp_annotations"` with
    /// the legacy `side_effects` flag forced false (as annotation imports do).
    /// Its Code Mode mutations must still be approvable even though the flag is
    /// off, since effectfulness is derived from annotations at dispatch.
    fn new_annotation_native() -> Self {
        Self {
            annotation_native: true,
            ..Self::new(true)
        }
    }

    fn tool(&self) -> ToolDefinition {
        ToolDefinition {
            discriminator: None,
            operations: Vec::new(),
            tool_id: self.tool_id,
            server_id: self.server_id,
            server_name: "example-messages".into(),
            tool_name: "send".into(),
            schema_hash: "h".into(),
            description: "".into(),
            classification_mode: if self.annotation_native {
                "mcp_annotations".into()
            } else {
                "manifest".into()
            },
            input_schema: None,
            output_schema: None,
            tool_annotations: None,
            action_metadata: None,
            risk: "high".into(),
            // Annotation-native rows keep the legacy flag forced false; manifest
            // rows carry the real effectfulness.
            side_effects: !self.annotation_native,
            pii: false,
            data_classification: None,
            cost_class: None,
            requires_approval: self.requires_approval,
        }
    }
}

#[async_trait]
impl waygate_catalog::CatalogStore for GrantFakeCatalog {
    async fn approved_servers(
        &self,
        _tenant: &str,
    ) -> Result<Vec<CatalogServerSummary>, CatalogError> {
        Ok(vec![])
    }
    async fn resolve_tool(&self, _t: &str, _fq: &str) -> Result<ResolvedTool, CatalogError> {
        if !self.tool_present {
            return Ok(ResolvedTool::NotFound);
        }
        Ok(ResolvedTool::Live(Box::new(self.tool())))
    }
    async fn resolve_live_tool_id(
        &self,
        _tenant: &str,
        tool_id: Uuid,
    ) -> Result<Option<ToolDefinition>, CatalogError> {
        Ok((self.tool_present && tool_id == self.tool_id).then(|| {
            let mut tool = self.tool();
            if let Some(hash) = &self.live_schema_override {
                tool.schema_hash = hash.clone();
            }
            tool
        }))
    }
    async fn record_drift(&self, _o: DriftObservation<'_>) -> Result<(), CatalogError> {
        Ok(())
    }
    async fn record_approval(&self, _a: ApprovalAction<'_>) -> Result<(), CatalogError> {
        Ok(())
    }
    async fn list_drift_events(
        &self,
        _t: &str,
        _s: OffsetDateTime,
        _l: u32,
    ) -> Result<Vec<DriftEvent>, CatalogError> {
        Ok(vec![])
    }
    async fn set_server_status(
        &self,
        _t: &str,
        _id: Uuid,
        _s: CatalogServerStatus,
        _a: &str,
        _r: Option<&str>,
    ) -> Result<bool, CatalogError> {
        Ok(true)
    }
    async fn last_approve_actor(
        &self,
        _t: &str,
        _id: Uuid,
    ) -> Result<Option<String>, CatalogError> {
        Ok(None)
    }
    async fn find_grant<'a>(
        &self,
        _l: GrantLookup<'a>,
    ) -> Result<Option<ApprovalGrant>, CatalogError> {
        Ok(None)
    }
    async fn claim_grant<'a>(
        &self,
        lookup: GrantLookup<'a>,
    ) -> Result<Option<ApprovalGrant>, CatalogError> {
        let mut grants = self.grants.lock().unwrap();
        let now = OffsetDateTime::now_utc();
        let grant = grants.iter_mut().find(|grant| {
            grant.tenant_id == lookup.tenant_id
                && grant.principal_sub == lookup.principal_sub
                && grant.principal_issuer.as_deref() == Some(lookup.principal_issuer)
                && grant.tool_id == lookup.tool_id
                && grant.argument_hash == lookup.argument_hash
                && grant.execution_binding.is_none()
                && lookup.execution_binding.is_none()
                && grant.consumed_at.is_none()
                && grant.expires_at > now
        });
        Ok(grant.map(|grant| {
            grant.consumed_at = Some(now);
            grant.clone()
        }))
    }
    async fn create_grant<'a>(
        &self,
        g: NewApprovalGrant<'a>,
    ) -> Result<ApprovalGrant, CatalogError> {
        let stored = ApprovalGrant {
            id: Uuid::now_v7(),
            tenant_id: g.tenant_id.to_owned(),
            principal_sub: g.principal_sub.to_owned(),
            principal_issuer: Some("https://issuer.test".to_owned()),
            client_id: g.client_id.map(str::to_owned),
            server_id: g.server_id,
            tool_id: g.tool_id,
            argument_hash: g.argument_hash.to_owned(),
            execution_binding: g.execution_binding.map(|binding| {
                waygate_catalog::ApprovalGrantExecutionBinding {
                    execution_id: binding.execution_id,
                    source_digest: binding.source_digest.to_owned(),
                    call_id: binding.call_id,
                }
            }),
            expires_at: g.expires_at,
            consumed_at: None,
            approver: g.approver.to_owned(),
            reason: g.reason.map(str::to_owned),
            created_at: OffsetDateTime::now_utc(),
        };
        self.grants.lock().unwrap().push(stored.clone());
        Ok(stored)
    }
    async fn list_grants<'a>(
        &self,
        tenant_id: &'a str,
        filter: GrantFilter<'a>,
    ) -> Result<Vec<ApprovalGrant>, CatalogError> {
        let v = self.grants.lock().unwrap();
        let now = OffsetDateTime::now_utc();
        Ok(v.iter()
            .filter(|g| g.tenant_id == tenant_id)
            .filter(|g| {
                filter
                    .principal_sub
                    .map(|p| g.principal_sub == p)
                    .unwrap_or(true)
            })
            .filter(|g| filter.tool_id.map(|t| g.tool_id == t).unwrap_or(true))
            .filter(|g| filter.include_consumed || (g.consumed_at.is_none() && g.expires_at > now))
            .cloned()
            .collect())
    }
    async fn revoke_grant(&self, tenant_id: &str, id: Uuid) -> Result<bool, CatalogError> {
        let mut v = self.grants.lock().unwrap();
        let found = v
            .iter_mut()
            .find(|g| g.tenant_id == tenant_id && g.id == id && g.consumed_at.is_none());
        match found {
            Some(g) => {
                g.consumed_at = Some(OffsetDateTime::now_utc());
                Ok(true)
            }
            None => Ok(false),
        }
    }
    async fn revoke_execution_grants(
        &self,
        tenant_id: &str,
        execution_id: Uuid,
    ) -> Result<u64, CatalogError> {
        let mut v = self.grants.lock().unwrap();
        let mut revoked = 0;
        for grant in v.iter_mut().filter(|g| {
            g.tenant_id == tenant_id
                && g.consumed_at.is_none()
                && g.execution_binding
                    .as_ref()
                    .is_some_and(|binding| binding.execution_id == execution_id)
        }) {
            grant.consumed_at = Some(OffsetDateTime::now_utc());
            revoked += 1;
        }
        Ok(revoked)
    }
    async fn sweep_grants(&self, _older_than: OffsetDateTime) -> Result<u64, CatalogError> {
        Ok(0)
    }
}

struct GrantFakeExecutionStore {
    execution: Mutex<Execution>,
    /// When set, the next `get` swaps this in after returning the current
    /// execution — simulating a concurrent writer replacing the
    /// pending request between the approve handler's verify and its
    /// post-mint confirmation.
    replace_after_get: Mutex<Option<Execution>>,
}

impl GrantFakeExecutionStore {
    fn new(execution: Execution) -> Self {
        Self {
            execution: Mutex::new(execution),
            replace_after_get: Mutex::new(None),
        }
    }
}

#[async_trait]
impl ExecutionStore for GrantFakeExecutionStore {
    async fn acquire_detached_slot(
        &self,
        _slot: &DetachedExecutionSlot,
        _lease: std::time::Duration,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }

    async fn release_detached_slot(
        &self,
        _slot: &DetachedExecutionSlot,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }

    async fn renew_detached_slot(
        &self,
        _slot: &DetachedExecutionSlot,
        _lease: std::time::Duration,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }

    async fn start_or_reuse(
        &self,
        _start: StartExecution,
    ) -> Result<StartExecutionResult, StoreError> {
        unreachable!("approval route tests do not start executions")
    }

    async fn find_retry_equivalent(
        &self,
        _probe: &RetryEquivalence,
        _id: Option<Uuid>,
    ) -> Result<Option<Execution>, StoreError> {
        Ok(None)
    }

    async fn resolve_source_locator(
        &self,
        _owner: &SourceArtifactOwner,
        _source_locator: &str,
    ) -> Result<Option<String>, StoreError> {
        Ok(None)
    }

    async fn bind_source_locator(
        &self,
        _owner: &SourceArtifactOwner,
        _source_locator: &str,
        _source_digest: &str,
        _expires_at: time::OffsetDateTime,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    async fn submit(&self, _execution: NewExecution) -> Result<Execution, StoreError> {
        unreachable!("approval route tests do not submit executions")
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Execution>, StoreError> {
        let mut execution = self.execution.lock().unwrap();
        let result =
            (execution.tenant_id == tenant_id && execution.id == id).then(|| execution.clone());
        if let Some(next) = self.replace_after_get.lock().unwrap().take() {
            *execution = next;
        }
        Ok(result)
    }

    async fn list_waiting_approvals(
        &self,
        tenant_id: &str,
        limit: u16,
    ) -> Result<Vec<Execution>, StoreError> {
        let execution = self.execution.lock().unwrap();
        Ok((limit > 0
            && execution.tenant_id == tenant_id
            && execution.status == ExecutionStatus::WaitingForApproval)
            .then(|| execution.clone())
            .into_iter()
            .collect())
    }

    async fn deny_waiting_approval(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver: &str,
        reason: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut execution = self.execution.lock().unwrap();
        if execution.tenant_id != tenant_id
            || execution.id != id
            || execution.status != ExecutionStatus::WaitingForApproval
        {
            return Ok(false);
        }
        execution.status = ExecutionStatus::Failed;
        execution.terminal_reason_code = Some("approval_denied".to_owned());
        execution.result_metadata = Some(json!({
            "approver": approver,
            "reason": reason,
        }));
        execution.completed_at = Some(OffsetDateTime::now_utc());
        Ok(true)
    }

    async fn claim(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _owner: Uuid,
        _lease: std::time::Duration,
        _source: String,
        _tool_snapshot: Value,
    ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError> {
        unreachable!("approval route tests do not claim executions")
    }

    async fn resume(
        &self,
        _execution: ResumeExecution,
    ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError> {
        unreachable!("approval route tests do not resume executions")
    }

    async fn renew(
        &self,
        _claim: &ExecutionClaim,
        _lease: std::time::Duration,
    ) -> Result<bool, StoreError> {
        unreachable!("approval route tests do not renew claims")
    }

    async fn append_event(
        &self,
        _claim: &ExecutionClaim,
        _event: NewExecutionEvent,
    ) -> Result<bool, StoreError> {
        unreachable!("approval route tests do not append events")
    }

    async fn append_effect_outcome(
        &self,
        _claim: &ExecutionClaim,
        _event: NewExecutionEvent,
    ) -> Result<bool, StoreError> {
        unreachable!("approval route tests do not append effect outcomes")
    }

    async fn transition(
        &self,
        _claim: &ExecutionClaim,
        _transition: ExecutionTransition,
    ) -> Result<Option<Execution>, StoreError> {
        unreachable!("approval route tests do not transition executions")
    }

    async fn fail_submission(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _event: NewExecutionEvent,
        _reason_code: String,
    ) -> Result<Option<Execution>, StoreError> {
        unreachable!("approval route tests do not fail submissions")
    }

    async fn request_cancellation(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _principal_issuer: &str,
        _id: Uuid,
    ) -> Result<Option<Execution>, StoreError> {
        unreachable!("approval route tests do not cancel executions")
    }

    async fn reconcile_abandoned(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _principal_issuer: &str,
        _id: Uuid,
        _submission_grace: std::time::Duration,
    ) -> Result<Option<Execution>, StoreError> {
        unreachable!("approval route tests do not reconcile executions")
    }

    async fn events(&self, _tenant_id: &str, _id: Uuid) -> Result<Vec<ExecutionEvent>, StoreError> {
        unreachable!("approval route tests do not read execution events")
    }

    async fn list_artifacts(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _after_event_id: Option<i64>,
        _limit: u16,
    ) -> Result<Vec<ExecutionArtifact>, StoreError> {
        unreachable!("approval route tests do not list artifacts")
    }

    async fn get_artifact(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _artifact_id: Uuid,
    ) -> Result<Option<ExecutionArtifactContent>, StoreError> {
        unreachable!("approval route tests do not read artifacts")
    }
}

fn principal_with(scopes: &[&str]) -> Principal {
    Principal {
        sub: "admin@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn state_with(catalog: Option<SharedCatalogStore>) -> Arc<AdminState> {
    state_with_execution(catalog, None).await
}

async fn state_with_execution(
    catalog: Option<SharedCatalogStore>,
    executions: Option<SharedExecutionStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(
        AdminState::new(
            pool,
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            catalog,
            "http://127.0.0.1:0".into(),
        )
        .with_codemode_execution_store(executions),
    )
}

fn post_json(path: &str, body: &Value, scopes: &[&str]) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(principal_with(scopes));
    req
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn pending_mutation(tool_id: Uuid) -> Execution {
    let now = OffsetDateTime::now_utc();
    let id = Uuid::now_v7();
    let call_id = Uuid::new_v5(&id, &1_u32.to_be_bytes());
    Execution {
        program_input: None,
        id,
        tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
        principal_sub: "alice@example.com".to_owned(),
        principal_issuer: Some("https://issuer.test".to_owned()),
        source: Some("return connectors[\"example-messages\"].send({body: 'hello'});".to_owned()),
        source_digest: "source-digest".to_owned(),
        execution_profile: json!({"name": "approval_bound_mutation"}),
        tool_snapshot: Some(json!({"contract_version": 1, "bindings": []})),
        sdk_contract_version: 2,
        runner_contract_version: 5,
        status: ExecutionStatus::WaitingForApproval,
        terminal_reason_code: None,
        result_metadata: Some(json!({"connector_calls": 1, "artifacts": 0})),
        result_payload: None,
        resume_context: Some(json!({
            "approval": {
                "connector": "example-messages",
                "operation": "send",
                "argument_hash": "sha256:approved-arguments",
                "arguments_preview": {"to": "[REDACTED:PHONE]", "body": "hello"},
                "risk": "high",
                "source_digest": "source-digest",
                "call_id": call_id,
                "step": 1,
                "contract": {
                    "authority": {
                        "authority": "catalog",
                        "tool_id": tool_id,
                        "catalog_schema_hash": "h"
                    },
                    "input_schema_hash": "input-hash",
                    "output_schema_hash": null,
                    "risk": "high",
                    "side_effects": true,
                    "pii": false,
                    "requires_approval": true,
                    "requires_approval_known": true
                },
                "prior_effects": 0
            }
        })),
        claim_owner: None,
        claim_epoch: 1,
        claim_expires_at: None,
        cancellation_requested_at: None,
        cancellation_reason_code: None,
        submitted_at: now,
        updated_at: now,
        completed_at: None,
        retention_until: now + time::Duration::days(7),
    }
}

#[tokio::test]
async fn codemode_pending_request_can_be_listed_and_approved_exactly() {
    let catalog = Arc::new(GrantFakeCatalog::new(true));
    let execution = pending_mutation(catalog.tool_id);
    let execution_id = execution.id;
    let call_id = execution.resume_context.as_ref().unwrap()["approval"]["call_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let executions: SharedExecutionStore = Arc::new(GrantFakeExecutionStore::new(execution));
    let catalog_store: SharedCatalogStore = catalog.clone();
    let app = api_router(state_with_execution(Some(catalog_store), Some(executions)).await);

    let mut list = Request::builder()
        .uri("/api/v1/admin/codemode/approval_requests")
        .body(Body::empty())
        .unwrap();
    list.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    assert_eq!(listed["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(
        listed["approvals"][0]["request"]["arguments_preview"]["to"],
        "[REDACTED:PHONE]"
    );
    let request_digest = listed["approvals"][0]["request_digest"]
        .as_str()
        .expect("listing returns the reviewed request identity")
        .to_owned();

    // A decision that does not echo the reviewed request is refused before
    // any grant is minted.
    let response = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({"expires_in_seconds": 600, "reason": "operator approved"}),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "reason": "operator approved",
                "request_digest": "sha256:different-request",
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        catalog.grants.lock().unwrap().is_empty(),
        "a refused decision must not mint a grant"
    );

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "reason": "operator approved",
                "request_digest": request_digest,
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let approved = body_json(response).await;
    assert_eq!(approved["principal_sub"], "alice@example.com");
    // The Code Mode grant binds the reviewed behavior hash with the request's
    // argument hash, matching the invocation lookup — a raw argument hash
    // would never claim.
    assert_eq!(
        approved["argument_hash"],
        waygate_catalog::approval_binding_hash("h", "sha256:approved-arguments")
    );
    assert_eq!(
        approved["execution_binding"],
        json!({
            "execution_id": execution_id,
            "source_digest": "source-digest",
            "call_id": call_id,
        })
    );
    let grants = catalog.grants.lock().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0]
            .execution_binding
            .as_ref()
            .map(|binding| binding.execution_id),
        Some(execution_id)
    );
}

/// A pending request whose pause came from a Cedar approval-overlay verdict
/// — the catalog flag is off — must still be approvable: the waiting
/// request itself is the authority that approval was demanded.
#[tokio::test]
async fn codemode_policy_gated_request_approves_without_the_catalog_flag() {
    let catalog = Arc::new(GrantFakeCatalog::new_policy_gated());
    let mut execution = pending_mutation(catalog.tool_id);
    // The frozen contract mirrors the flag-off catalog classification.
    if let Some(context) = execution.resume_context.as_mut() {
        context["approval"]["contract"]["requires_approval"] = json!(false);
    }
    let execution_id = execution.id;
    let executions: SharedExecutionStore = Arc::new(GrantFakeExecutionStore::new(execution));
    let catalog_store: SharedCatalogStore = catalog.clone();
    let app = api_router(state_with_execution(Some(catalog_store), Some(executions)).await);

    let mut list = Request::builder()
        .uri("/api/v1/admin/codemode/approval_requests")
        .body(Body::empty())
        .unwrap();
    list.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    let request_digest = listed["approvals"][0]["request_digest"]
        .as_str()
        .expect("listing returns the reviewed request identity")
        .to_owned();

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "reason": "operator approved",
                "request_digest": request_digest,
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "a policy-gated pending request must mint its execution-bound grant",
    );
    let grants = catalog.grants.lock().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0]
            .execution_binding
            .as_ref()
            .map(|binding| binding.execution_id),
        Some(execution_id)
    );
}

/// Annotation-native tools keep the legacy catalog `side_effects` flag forced
/// false and derive effectfulness from reviewed annotations at dispatch. A
/// side-effecting annotation-native Code Mode mutation that reaches
/// waiting_for_approval must still mint its grant: the effectfulness re-check
/// applies only to manifest-mode rows, whose flag is authoritative. Without the
/// mode guard, the `!side_effects` check would reject every annotation-native
/// mutation and break the behavior-bound Code Mode approval flow.
#[tokio::test]
async fn codemode_annotation_native_request_approves_despite_forced_false_flag() {
    let catalog = Arc::new(GrantFakeCatalog::new_annotation_native());
    let execution = pending_mutation(catalog.tool_id);
    let execution_id = execution.id;
    let executions: SharedExecutionStore = Arc::new(GrantFakeExecutionStore::new(execution));
    let catalog_store: SharedCatalogStore = catalog.clone();
    let app = api_router(state_with_execution(Some(catalog_store), Some(executions)).await);

    let mut list = Request::builder()
        .uri("/api/v1/admin/codemode/approval_requests")
        .body(Body::empty())
        .unwrap();
    list.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    let request_digest = listed["approvals"][0]["request_digest"]
        .as_str()
        .expect("listing returns the reviewed request identity")
        .to_owned();

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "reason": "operator approved",
                "request_digest": request_digest,
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "an annotation-native side-effecting request must mint despite the forced-false flag",
    );
    assert_eq!(catalog.grants.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn codemode_approval_revokes_its_mint_when_the_request_changes_mid_decision() {
    let catalog = Arc::new(GrantFakeCatalog::new(true));
    let execution = pending_mutation(catalog.tool_id);
    let execution_id = execution.id;
    // The replacement request the concurrent resume persists: same
    // execution, different pending effect (a new argument hash).
    let mut replacement = execution.clone();
    replacement.resume_context.as_mut().unwrap()["approval"]["argument_hash"] =
        json!("sha256:replaced-arguments");
    let executions = Arc::new(GrantFakeExecutionStore::new(execution));
    *executions.replace_after_get.lock().unwrap() = Some(replacement);
    let shared_executions: SharedExecutionStore = executions.clone();
    let catalog_store: SharedCatalogStore = catalog.clone();
    let app = api_router(state_with_execution(Some(catalog_store), Some(shared_executions)).await);

    let mut list = Request::builder()
        .uri("/api/v1/admin/codemode/approval_requests")
        .body(Body::empty())
        .unwrap();
    list.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    let request_digest = listed["approvals"][0]["request_digest"]
        .as_str()
        .expect("listing returns the reviewed request identity")
        .to_owned();

    // The digest verifies against the snapshot the handler loads, but the
    // pending request is replaced before the post-mint confirmation — the
    // handler must revoke its own mint and refuse the decision.
    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "reason": "operator approved",
                "request_digest": request_digest,
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let grants = catalog.grants.lock().unwrap();
    assert_eq!(grants.len(), 1, "the racing mint is recorded");
    assert!(
        grants[0].consumed_at.is_some(),
        "a mint for a request that is no longer pending must be revoked"
    );
}

#[tokio::test]
async fn codemode_pending_request_denial_is_terminal() {
    let catalog = Arc::new(GrantFakeCatalog::new(true));
    let execution = pending_mutation(catalog.tool_id);
    let execution_id = execution.id;
    let executions = Arc::new(GrantFakeExecutionStore::new(execution));
    let shared_executions: SharedExecutionStore = executions.clone();
    let catalog_store: SharedCatalogStore = catalog;
    let app = api_router(state_with_execution(Some(catalog_store), Some(shared_executions)).await);

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/deny"),
            &json!({"reason": "recipient is incorrect"}),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let denied = executions.execution.lock().unwrap();
    assert_eq!(denied.status, ExecutionStatus::Failed);
    assert_eq!(
        denied.terminal_reason_code.as_deref(),
        Some("approval_denied")
    );
    assert_eq!(
        denied.result_metadata.as_ref().unwrap()["reason"],
        "recipient is incorrect"
    );
}

#[tokio::test]
async fn mint_grant_persists_and_argument_hash_matches() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog.clone())).await);
    let body = json!({
        "principal_sub": "alice@example.com",
        "principal_issuer": "https://issuer.test",
        "tool": "example-messages.send",
        "behavior_hash": "h",
        "arguments": {"to": "bob", "body": "hi"},
        "expires_in_seconds": 600,
        "reason": "ticket #42"
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    // The API accepts arguments but stores the invocation-time binding, so a
    // behavior change invalidates the grant even when the arguments match.
    let raw_argument_hash = waygate_catalog::argument_hash(Some(
        json!({"to": "bob", "body": "hi"}).as_object().unwrap(),
    ));
    let expected_binding = waygate_catalog::approval_binding_hash("h", &raw_argument_hash);
    assert_eq!(v["argument_hash"].as_str().unwrap(), expected_binding);
    assert_eq!(v["principal_sub"].as_str().unwrap(), "alice@example.com");
    assert_eq!(v["reason"].as_str().unwrap(), "ticket #42");
    assert!(v["consumed_at"].is_null());
}

#[tokio::test]
async fn mint_refuses_when_reviewed_behavior_hash_drifted() {
    // The approver reviewed behavior "old", but the tool's Live approved
    // behavior is "h". Minting must refuse rather than bind the human decision
    // to a version the approver never reviewed.
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);
    let body = json!({
        "principal_sub": "alice@example.com",
        "principal_issuer": "https://issuer.test",
        "tool": "example-messages.send",
        "behavior_hash": "old",
        "arguments": {"to": "bob"},
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn mint_rejects_both_arguments_and_argument_hash() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);
    let body = json!({
        "principal_sub": "alice@example.com",
        "principal_issuer": "https://issuer.test",
        "tool": "example-messages.send",
        "behavior_hash": "h",
        "arguments": {"to": "bob"},
        "argument_hash": "abc",
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mint_rejects_neither_arguments_nor_argument_hash() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);
    let body = json!({
        "principal_sub": "alice@example.com",
        "principal_issuer": "https://issuer.test",
        "tool": "example-messages.send",
        "behavior_hash": "h",
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// An operator script written against an older shape of this API
/// (or any future field this struct removes /
/// renames) sending an extra field MUST get a clean 400 from serde
/// rather than have its field silently dropped. Pins
/// `#[serde(deny_unknown_fields)]` on CreateGrantRequest.
#[tokio::test]
async fn mint_rejects_unknown_fields() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);
    // `client_id` was removed from this API in the round-2 fix.
    // A stale client that still sends it must NOT have the grant
    // minted as any-client (the previous silent-drop behavior).
    let body = json!({
        "principal_sub": "alice@example.com",
        "principal_issuer": "https://issuer.test",
        "tool": "example-messages.send",
        "behavior_hash": "h",
        "arguments": {},
        "client_id": "svc-account"
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    // Axum's `Json` extractor surfaces serde-rejected payloads as
    // `422 UNPROCESSABLE_ENTITY` (the JSON parsed but didn't match
    // the struct) — distinct from the `400 BAD_REQUEST` our handler
    // returns for handler-level validation (both/neither args). Both
    // are 4xx client errors; the operator can tell the difference
    // by the status code and the (serde-emitted) error body.
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn mint_404s_when_tool_not_live() {
    // tool_present=false → catalog returns NotFound for the
    // resolve_tool lookup; mint refuses with 404 rather than minting
    // a grant for a tool the gateway wouldn't dispatch.
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(false));
    let app = api_router(state_with(Some(catalog)).await);
    let body = json!({
        "principal_sub": "alice@example.com",
        "principal_issuer": "https://issuer.test",
        "tool": "example-messages.send",
        "behavior_hash": "h",
        "arguments": {}
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mint_clamps_lifetime_floor_and_ceiling() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog.clone())).await);

    // Floor: 1 second → must clamp UP to 60s.
    let now = OffsetDateTime::now_utc();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &json!({
                "principal_sub": "alice@example.com",
                "principal_issuer": "https://issuer.test",
                "tool": "example-messages.send",
                "behavior_hash": "h",
                "arguments": {},
                "expires_in_seconds": 1
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    let expires_at = OffsetDateTime::parse(
        v["expires_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let delta = expires_at - now;
    assert!(
        delta.whole_seconds() >= 55 && delta.whole_seconds() <= 65,
        "lifetime should clamp to ~60s; got {}s",
        delta.whole_seconds(),
    );

    // Ceiling: 10 years (315360000s) → must clamp DOWN to 7d.
    let now = OffsetDateTime::now_utc();
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &json!({
                "principal_sub": "alice@example.com",
                "principal_issuer": "https://issuer.test",
                "tool": "example-messages.send",
                "behavior_hash": "h",
                "arguments": {},
                "expires_in_seconds": 315_360_000u64
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    let expires_at = OffsetDateTime::parse(
        v["expires_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let week_secs = 7 * 24 * 60 * 60;
    let delta = expires_at - now;
    assert!(
        (delta.whole_seconds() - week_secs).abs() < 10,
        "lifetime should clamp to ~7d ({}s); got {}s",
        week_secs,
        delta.whole_seconds(),
    );
}

#[tokio::test]
async fn list_returns_live_grants_for_tenant() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog.clone())).await);
    // Mint two grants for different principals.
    for sub in ["alice@example.com", "bob@example.com"] {
        let body = json!({
            "principal_sub": sub,
            "principal_issuer": "https://issuer.test",
            "tool": "example-messages.send",
            "behavior_hash": "h",
            "arguments": {"to": "x"}
        });
        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/approval_grants",
                &body,
                &["mcp:admin"],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    // List unfiltered: both visible.
    let mut req = Request::builder()
        .uri("/api/v1/admin/approval_grants")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["grants"].as_array().unwrap().len(), 2);
    // List filtered by principal_sub: only alice.
    let mut req = Request::builder()
        .uri("/api/v1/admin/approval_grants?principal_sub=alice@example.com")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let grants = v["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0]["principal_sub"].as_str().unwrap(),
        "alice@example.com"
    );
}

#[tokio::test]
async fn revoke_204_then_404_on_second_revoke() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);
    // Mint.
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &json!({
                "principal_sub": "alice@example.com",
                "principal_issuer": "https://issuer.test",
                "tool": "example-messages.send",
                "behavior_hash": "h",
                "arguments": {}
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = body_json(resp).await["id"].as_str().unwrap().to_owned();
    // Revoke: 204.
    let path = format!("/api/v1/admin/approval_grants/{id}");
    let mut req = Request::builder()
        .method("DELETE")
        .uri(&path)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // Revoke again: 404 (already consumed).
    let mut req = Request::builder()
        .method("DELETE")
        .uri(&path)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn scope_enforcement() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);

    // No principal → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/approval_grants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // mcp:read insufficient.
    let mut req = Request::builder()
        .uri("/api/v1/admin/approval_grants")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_503s_without_catalog() {
    let app = api_router(state_with(None).await);
    let mut req = Request::builder()
        .uri("/api/v1/admin/approval_grants")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A tool-version change between listing and approval must refuse the mint:
/// the grant binds to the reviewed behavior hash, and a grant for a version
/// the operator never saw would be rejected at dispatch as unusable.
#[tokio::test]
async fn codemode_approval_refuses_when_tool_version_drifted() {
    let mut fake = GrantFakeCatalog::new(true);
    // The reviewed request carries catalog_schema_hash "h"; the live tool is
    // now on a different version.
    fake.live_schema_override = Some("h-next".to_owned());
    let catalog = Arc::new(fake);
    let execution = pending_mutation(catalog.tool_id);
    let execution_id = execution.id;
    let executions: SharedExecutionStore = Arc::new(GrantFakeExecutionStore::new(execution));
    let catalog_store: SharedCatalogStore = catalog.clone();
    let app = api_router(state_with_execution(Some(catalog_store), Some(executions)).await);

    let mut list = Request::builder()
        .uri("/api/v1/admin/codemode/approval_requests")
        .body(Body::empty())
        .unwrap();
    list.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let listed = body_json(app.clone().oneshot(list).await.unwrap()).await;
    let request_digest = listed["approvals"][0]["request_digest"].as_str().unwrap();

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "reason": "operator approved",
                "request_digest": request_digest,
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        catalog.grants.lock().unwrap().is_empty(),
        "a drifted tool version must not mint a grant",
    );
}

/// Separation of duty: the direct grant endpoint refuses to mint a grant
/// whose principal is the calling admin themselves — otherwise an mcp:admin
/// principal could self-authorize a protected write.
#[tokio::test]
async fn mint_refuses_self_approval() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);
    // `principal_with` (the caller) is "admin@example.com"; approving a grant
    // for that same principal is a self-approval.
    let body = json!({
        "principal_sub": "admin@example.com",
        "principal_issuer": "test",
        "tool": "example-messages.send",
        "behavior_hash": "h",
        "arguments": {"to": "bob"},
        "expires_in_seconds": 600,
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// Separation of duty on the Code Mode path: an admin may not approve a
/// mutation their own principal proposed.
#[tokio::test]
async fn codemode_approval_refuses_self_approval() {
    let catalog = Arc::new(GrantFakeCatalog::new(true));
    let mut execution = pending_mutation(catalog.tool_id);
    // The proposer is the same principal (issuer AND sub) as the
    // approving admin.
    execution.principal_sub = "admin@example.com".to_owned();
    execution.principal_issuer = Some("test".to_owned());
    let execution_id = execution.id;
    let executions: SharedExecutionStore = Arc::new(GrantFakeExecutionStore::new(execution));
    let catalog_store: SharedCatalogStore = catalog.clone();
    let app = api_router(state_with_execution(Some(catalog_store), Some(executions)).await);

    let mut list = Request::builder()
        .uri("/api/v1/admin/codemode/approval_requests")
        .body(Body::empty())
        .unwrap();
    list.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let listed = body_json(app.clone().oneshot(list).await.unwrap()).await;
    let request_digest = listed["approvals"][0]["request_digest"].as_str().unwrap();

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "reason": "self",
                "request_digest": request_digest,
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        catalog.grants.lock().unwrap().is_empty(),
        "a self-approval must not mint a grant",
    );
}

/// Separation of duty compares the FULL identity: two issuers may mint the
/// same `sub` for different people, so an approver whose `sub` collides
/// with the requester's under a different issuer is a different person and
/// must be allowed to approve.
#[tokio::test]
async fn mint_allows_cross_issuer_same_sub() {
    let catalog: SharedCatalogStore = Arc::new(GrantFakeCatalog::new(true));
    let app = api_router(state_with(Some(catalog)).await);
    // The approving admin is ("test", "admin@example.com"); the requester
    // shares the sub under ANOTHER issuer — a different person.
    let body = json!({
        "principal_sub": "admin@example.com",
        "principal_issuer": "https://other-issuer.test",
        "tool": "example-messages.send",
        "behavior_hash": "h",
        "arguments": {"to": "bob"},
        "expires_in_seconds": 600,
    });
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/approval_grants",
            &body,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// An execution that predates issuer-scoped ownership records no requester
/// issuer, so there is no trustworthy identity to bind a grant to: the
/// approve endpoint refuses instead of minting an unscoped grant.
#[tokio::test]
async fn codemode_approval_refuses_issuerless_pre_upgrade_execution() {
    let catalog = Arc::new(GrantFakeCatalog::new(true));
    let mut execution = pending_mutation(catalog.tool_id);
    execution.principal_issuer = None;
    let execution_id = execution.id;
    let executions: SharedExecutionStore = Arc::new(GrantFakeExecutionStore::new(execution));
    let catalog_store: SharedCatalogStore = catalog.clone();
    let app = api_router(state_with_execution(Some(catalog_store), Some(executions)).await);

    let mut list = Request::builder()
        .uri("/api/v1/admin/codemode/approval_requests")
        .body(Body::empty())
        .unwrap();
    list.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let listed = body_json(app.clone().oneshot(list).await.unwrap()).await;
    let request_digest = listed["approvals"][0]["request_digest"].as_str().unwrap();

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/codemode/approval_requests/{execution_id}/approve"),
            &json!({
                "expires_in_seconds": 600,
                "request_digest": request_digest,
            }),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = body_json(response).await;
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("records no requester issuer"),
        "the refusal must name the missing issuer: {body}",
    );
}
