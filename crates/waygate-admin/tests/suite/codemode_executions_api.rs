//! Route-level coverage for `/api/v1/admin/codemode/executions`.
//!
//! Uses an in-memory `ExecutionStore` fake that serves canned operator
//! rows and records what the handlers asked for, so the surface's
//! tenant-scoping, wire mapping, and cancellation plumbing are exercised
//! without a Postgres dependency (the journal SQL itself is pinned by
//! `waygate-codemode`'s Pg contract tests).
//!
//! Pins:
//! 1. GET lists in-flight rows mapped to the wire shape — status string,
//!    claim liveness, RFC3339 timestamps — with the clamped limit echoed,
//!    and scopes the query to the caller's tenant.
//! 2. The `principal_sub` filter reaches the store.
//! 3. POST `/{id}/cancel` passes the operator's subject through, returns
//!    the post-request status, and 404s for an unknown id.
//! 4. Both endpoints 503 when the execution store is absent.
//! 5. Scopes: missing principal → 401, `mcp:read` → 403, `mcp:admin` →
//!    through.

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
use waygate_codemode::{
    DetachedExecutionSlot, Execution, ExecutionArtifact, ExecutionArtifactContent, ExecutionClaim,
    ExecutionEvent, ExecutionStatus, ExecutionStore, ExecutionTransition, NewExecution,
    NewExecutionEvent, OperatorInFlightExecution, ResumeExecution, RetryEquivalence,
    SharedExecutionStore, SourceArtifactOwner, StartExecution, StartExecutionResult,
};
use waygate_core::store::StoreError;
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;

/// Arguments the list handler passed to the store: tenant, subject
/// filter, clamped limit, offset.
type ListCall = (String, Option<String>, u16, u32);

/// Serves canned operator rows and records the arguments the handlers
/// passed, so tenant scoping and filter plumbing are assertable.
struct OperatorFakeExecutionStore {
    rows: Vec<OperatorInFlightExecution>,
    cancellable: Mutex<Option<Execution>>,
    list_calls: Mutex<Vec<ListCall>>,
    cancel_calls: Mutex<Vec<(String, Uuid, String)>>,
}

impl OperatorFakeExecutionStore {
    fn new(rows: Vec<OperatorInFlightExecution>, cancellable: Option<Execution>) -> Self {
        Self {
            rows,
            cancellable: Mutex::new(cancellable),
            list_calls: Mutex::new(Vec::new()),
            cancel_calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ExecutionStore for OperatorFakeExecutionStore {
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
        unreachable!("operator route tests do not start executions")
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
        unreachable!("operator route tests do not submit executions")
    }
    async fn get(&self, _tenant_id: &str, _id: Uuid) -> Result<Option<Execution>, StoreError> {
        Ok(None)
    }
    async fn list_in_flight_for_operator(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<OperatorInFlightExecution>, StoreError> {
        self.list_calls.lock().unwrap().push((
            tenant_id.to_owned(),
            principal_sub.map(str::to_owned),
            limit,
            offset,
        ));
        Ok(self.rows.clone())
    }
    async fn request_cancellation_for_operator(
        &self,
        tenant_id: &str,
        id: Uuid,
        operator_sub: &str,
    ) -> Result<Option<Execution>, StoreError> {
        self.cancel_calls
            .lock()
            .unwrap()
            .push((tenant_id.to_owned(), id, operator_sub.to_owned()));
        let guard = self.cancellable.lock().unwrap();
        Ok(guard
            .as_ref()
            .filter(|execution| execution.tenant_id == tenant_id && execution.id == id)
            .cloned())
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
        unreachable!("operator route tests do not claim executions")
    }
    async fn resume(
        &self,
        _execution: ResumeExecution,
    ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError> {
        unreachable!("operator route tests do not resume executions")
    }
    async fn renew(
        &self,
        _claim: &ExecutionClaim,
        _lease: std::time::Duration,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }
    async fn append_event(
        &self,
        _claim: &ExecutionClaim,
        _event: NewExecutionEvent,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }
    async fn append_effect_outcome(
        &self,
        _claim: &ExecutionClaim,
        _event: NewExecutionEvent,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }
    async fn transition(
        &self,
        _claim: &ExecutionClaim,
        _transition: ExecutionTransition,
    ) -> Result<Option<Execution>, StoreError> {
        Ok(None)
    }
    async fn fail_submission(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _event: NewExecutionEvent,
        _reason_code: String,
    ) -> Result<Option<Execution>, StoreError> {
        Ok(None)
    }
    async fn request_cancellation(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _principal_issuer: &str,
        _id: Uuid,
    ) -> Result<Option<Execution>, StoreError> {
        unreachable!("the operator surface never uses the owner-scoped cancellation")
    }
    async fn reconcile_abandoned(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _principal_issuer: &str,
        _id: Uuid,
        _submission_grace: std::time::Duration,
    ) -> Result<Option<Execution>, StoreError> {
        Ok(None)
    }
    async fn events(&self, _tenant_id: &str, _id: Uuid) -> Result<Vec<ExecutionEvent>, StoreError> {
        Ok(Vec::new())
    }
    async fn list_artifacts(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _after_event_id: Option<i64>,
        _limit: u16,
    ) -> Result<Vec<ExecutionArtifact>, StoreError> {
        Ok(Vec::new())
    }
    async fn get_artifact(
        &self,
        _tenant_id: &str,
        _id: Uuid,
        _artifact_id: Uuid,
    ) -> Result<Option<ExecutionArtifactContent>, StoreError> {
        Ok(None)
    }
}

fn in_flight_row(id: Uuid, sub: &str, claimed: bool) -> OperatorInFlightExecution {
    let now = OffsetDateTime::now_utc();
    OperatorInFlightExecution {
        id,
        principal_sub: sub.to_owned(),
        principal_issuer: Some("https://issuer.test".to_owned()),
        status: if claimed {
            ExecutionStatus::Running
        } else {
            ExecutionStatus::Submitted
        },
        cancellation_requested: false,
        claimed,
        claim_expires_at: claimed.then(|| now + time::Duration::seconds(30)),
        submitted_at: now - time::Duration::minutes(5),
        updated_at: now,
        retention_until: now + time::Duration::days(7),
    }
}

fn cancelled_execution(id: Uuid) -> Execution {
    let now = OffsetDateTime::now_utc();
    Execution {
        program_input: None,
        id,
        tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
        principal_sub: "alice@example.com".to_owned(),
        principal_issuer: Some("https://issuer.test".to_owned()),
        source: None,
        source_digest: "source-digest".to_owned(),
        execution_profile: json!({"name": "read_only"}),
        tool_snapshot: None,
        sdk_contract_version: 1,
        runner_contract_version: 3,
        status: ExecutionStatus::Cancelled,
        terminal_reason_code: Some("cancelled_by_operator".to_owned()),
        result_metadata: None,
        result_payload: None,
        resume_context: None,
        claim_owner: None,
        claim_epoch: 0,
        claim_expires_at: None,
        cancellation_requested_at: Some(now),
        cancellation_reason_code: Some("cancelled_by_operator".to_owned()),
        submitted_at: now - time::Duration::minutes(5),
        updated_at: now,
        completed_at: Some(now),
        retention_until: now + time::Duration::days(7),
    }
}

fn principal_with(scopes: &[&str]) -> Principal {
    Principal {
        sub: "operator@example.com".into(),
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

async fn state_with(executions: Option<SharedExecutionStore>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Real in-memory sink: cancel uses the fail-closed record_required
    // evidence write, which NullSink rejects by design.
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    Arc::new(
        AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_codemode_execution_store(executions),
    )
}

fn get_request(path: &str, scopes: Option<&[&str]>) -> Request<Body> {
    let mut req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    if let Some(scopes) = scopes {
        req.extensions_mut().insert(principal_with(scopes));
    }
    req
}

fn post_request(path: &str, scopes: &[&str]) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(scopes));
    req
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("body is JSON")
}

#[tokio::test]
async fn listing_projects_the_journal_rows_into_the_wire_shape() {
    let claimed_id = Uuid::now_v7();
    let unclaimed_id = Uuid::now_v7();
    let store = Arc::new(OperatorFakeExecutionStore::new(
        vec![
            in_flight_row(claimed_id, "bob", true),
            in_flight_row(unclaimed_id, "alice", false),
        ],
        None,
    ));
    let app = api_router(state_with(Some(store.clone())).await);

    let resp = app
        .oneshot(get_request(
            "/api/v1/admin/codemode/executions?principal_sub=bob&limit=9999",
            Some(&["mcp:admin"]),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(
        body["limit"], 500,
        "the requested limit is clamped and echoed"
    );
    let executions = body["executions"].as_array().expect("executions array");
    assert_eq!(executions.len(), 2);
    assert_eq!(executions[0]["id"], json!(claimed_id));
    assert_eq!(executions[0]["principal_sub"], "bob");
    assert_eq!(executions[0]["status"], "running");
    assert_eq!(executions[0]["claimed"], true);
    assert!(executions[0]["claim_expires_at"].is_string());
    assert_eq!(executions[1]["status"], "submitted");
    assert_eq!(executions[1]["claimed"], false);
    assert!(executions[1]["claim_expires_at"].is_null());
    assert!(
        executions[0]["submitted_at"]
            .as_str()
            .unwrap()
            .contains('T'),
        "timestamps are RFC3339"
    );

    let calls = store.list_calls.lock().unwrap();
    assert_eq!(
        calls.as_slice(),
        &[(
            waygate_core::TenantId::DEFAULT.to_owned(),
            Some("bob".to_owned()),
            500,
            0,
        )],
        "the query is tenant-scoped from the principal and carries the filter"
    );
}

#[tokio::test]
async fn cancel_names_the_operator_and_404s_on_unknown_ids() {
    let id = Uuid::now_v7();
    let store = Arc::new(OperatorFakeExecutionStore::new(
        Vec::new(),
        Some(cancelled_execution(id)),
    ));
    let app = api_router(state_with(Some(store.clone())).await);

    let resp = app
        .clone()
        .oneshot(post_request(
            &format!("/api/v1/admin/codemode/executions/{id}/cancel"),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["execution_id"], json!(id));
    assert_eq!(body["status"], "cancelled");
    assert_eq!(body["cancellation_requested"], true);
    {
        let calls = store.cancel_calls.lock().unwrap();
        assert_eq!(
            calls.as_slice(),
            &[(
                waygate_core::TenantId::DEFAULT.to_owned(),
                id,
                "operator@example.com".to_owned(),
            )],
            "the journal records which operator intervened"
        );
    }

    let missing = Uuid::now_v7();
    let resp = app
        .oneshot(post_request(
            &format!("/api/v1/admin/codemode/executions/{missing}/cancel"),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn endpoints_fail_closed_without_a_store_and_enforce_admin_scope() {
    let app = api_router(state_with(None).await);
    let resp = app
        .clone()
        .oneshot(get_request(
            "/api/v1/admin/codemode/executions",
            Some(&["mcp:admin"]),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let resp = app
        .clone()
        .oneshot(post_request(
            &format!(
                "/api/v1/admin/codemode/executions/{}/cancel",
                Uuid::now_v7()
            ),
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let resp = app
        .clone()
        .oneshot(get_request("/api/v1/admin/codemode/executions", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = app
        .oneshot(get_request(
            "/api/v1/admin/codemode/executions",
            Some(&["mcp:read"]),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
