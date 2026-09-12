//! Route-level coverage for `/api/v1/admin/change_requests`, the
//! human-in-the-loop change request API.
//!
//! Uses the real `waygate_changeset::InMemoryChangeRequestStore` (no
//! Postgres) so the propose -> poll flow is exercised end-to-end.
//!
//! Pins:
//! 1. Scopes: missing principal -> 401, `mcp:read` -> 403, `mcp:propose`
//!    -> through (the maker scope gates the surface, not `mcp:admin`).
//! 2. POST captures a pending change and returns the id + binding_code.
//! 3. GET .../{id} reports `authorization_pending` (the CIBA poll).
//! 4. A maker can't poll another maker's request (404, not leaked).
//! 5. Unknown action_type / empty justification -> 400.
//! 6. Store absent -> 503.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Map, Value};
use time::{Duration, OffsetDateTime};
use tower::util::ServiceExt;
use uuid::Uuid;

use waygate_admin::change_executor::{registry, ExecError};
use waygate_admin::{api_router, dashboard_router, AdminState, DashboardAuth};
use waygate_apikeys::{
    GroupStore, GroupStoreError, GroupView, ProfileStore, ScopeStore, ScopeStoreError, ScopeView,
};
use waygate_as::consent::{ConsentGrant, ConsentStore, ConsentStoreError, NewConsentGrant};
use waygate_as::sessions::{
    NewSessionRow, OffKeyRow, SessionMetadata, SessionStoreError, StoredSessionRow,
    UpstreamSessionStore,
};
use waygate_as::UpstreamCrypto;
use waygate_authz::{
    BreakGlassError, BreakGlassLifecycle, BreakGlassStore, BreakGlassToken, CedarEngine,
    NewBreakGlassToken, ReloadableCedar,
};
use waygate_changeset::{
    ApprovalRequirement, ChangeRequestStore, InMemoryChangeRequestStore, NewChangeRequest,
    SharedChangeRequestStore,
};
use waygate_dashboard_stores::agent_config::{
    AgentConfigFields, AgentConfigStore, AgentKind, InMemoryAgentConfigStore,
};
use waygate_dashboard_stores::inspection_rules::{
    InspectionRule, InspectionRulesStore, InspectorKind, NewInspectionRule, RuleError, RuleFilter,
    RuleUpdate,
};
use waygate_federation::{
    FederatedPeer, FederatedPeersStore, NewFederatedPeer, PeerError, PeerFilter, PeerUpdate,
    TrustTier,
};
use waygate_manifest_store::{
    ManifestBundle, ManifestBundleSummary, ManifestError, ManifestPointer, ManifestStatus,
    ManifestStore, TurnstileOutcome as ManifestTurnstileOutcome,
};
use waygate_oidc::Principal;
use waygate_policy::{
    content_hash as policy_content_hash, PolicyBundle, PolicyBundleSummary, PolicyError,
    PolicyPointer, PolicyStatus, PolicyStore, TurnstileOutcome,
};
use waygate_quota::{
    QuotaAction, QuotaScope, RateLimitPolicy, RateLimitPolicyStore, RateLimitStoreError,
};
use waygate_rbac::{GroupRoleMapping, RbacError, RbacStore, ResolvedRoles, Role, RoleAssignment};
use waygate_storage::{RetentionPolicy, RetentionStore};
use waygate_test_support::mocks::InMemoryProfileStore;
use waygate_upstream::pool::UpstreamPool;

fn principal_with_sub(sub: &str, scopes: &[&str]) -> Principal {
    Principal {
        sub: sub.into(),
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

async fn state_with(store: Option<SharedChangeRequestStore>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // propose calls record_required, and NullSink fails that by design
    // (fail-closed audit). Use a real in-memory sink so the audited happy
    // path can succeed in tests — same fixture the other admin-mutation
    // route tests use.
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
        .with_change_request_store(store),
    )
}

async fn state_with_local_catalog(
    store: Option<SharedChangeRequestStore>,
    groups: Arc<dyn GroupStore>,
    scopes: Arc<dyn ScopeStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(store)
        .with_group_store(Some(groups))
        .with_scope_store(Some(scopes)),
    )
}

async fn state_with_agent_configs(
    store: Option<SharedChangeRequestStore>,
    agent_configs: Arc<dyn AgentConfigStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(store)
        .with_agent_configs(Some(agent_configs)),
    )
}

async fn state_with_api_key_profiles(
    store: Option<SharedChangeRequestStore>,
    profiles: Arc<dyn ProfileStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(store)
        .with_api_key_profile_store(Some(profiles)),
    )
}

fn mem_store() -> SharedChangeRequestStore {
    Arc::new(InMemoryChangeRequestStore::new())
}

async fn state_with_secret(
    store: SharedChangeRequestStore,
    crypto: UpstreamCrypto,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(Some(store))
        .with_change_secret_crypto(Some(crypto)),
    )
}

/// Drive a change request to `executed` with a stored encrypted secret via
/// the public store methods (no executor / ApiKeyStore needed), so the
/// maker-facing burn-on-read retrieve contract can be exercised without
/// Postgres — exactly the state a successful secret-producing
/// execute-on-approval leaves behind.
async fn executed_with_secret(
    store: &SharedChangeRequestStore,
    crypto: &UpstreamCrypto,
    maker: &str,
    secret: &[u8],
) -> Uuid {
    let tenant = waygate_core::TenantId::default();
    let t = tenant.as_str();
    let cr = store
        .propose(NewChangeRequest {
            tenant_id: t.to_owned(),
            requested_by: maker.to_owned(),
            client_id: None,
            action_type: "api_key.mint".into(),
            params: json!({}),
            preview: None,
            target_etag: None,
            justification: "provision a least-privilege triage key".into(),
            requirement: ApprovalRequirement::single("dashboard-admins"),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        })
        .await
        .unwrap();
    // eligible operator approves → claim → store encrypted
    // secret → mark executed.
    store
        .try_approve(t, cr.id, "operator")
        .await
        .unwrap()
        .unwrap();
    store.try_begin_execution(t, cr.id).await.unwrap().unwrap();
    let ct = crypto.encrypt(secret).unwrap();
    store
        .store_secret(t, cr.id, &ct, crypto.active_id())
        .await
        .unwrap();
    store
        .mark_executed(
            t,
            cr.id,
            json!({ "key_prefix": "mcpgw_AB", "secret_available": true }),
        )
        .await
        .unwrap()
        .unwrap();
    cr.id
}

fn valid_body() -> Value {
    json!({
        "action_type": "rate_limit.update",
        // Valid rate_limit.update params (params are validated at propose).
        "params": { "policy_id": "00000000-0000-0000-0000-000000000000", "bucket_capacity": 100 },
        "justification": "nightly sync job needs more headroom"
    })
}

fn post_req(path: &str, body: &Value, sub: &str, scopes: &[&str]) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(principal_with_sub(sub, scopes));
    req
}

fn get_req(path: &str, sub: &str, scopes: &[&str]) -> Request<Body> {
    let mut req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with_sub(sub, scopes));
    req
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn propose_scope_gating() {
    let app = api_router(state_with(Some(mem_store())).await);

    // No principal -> 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/change_requests")
                .header("content-type", "application/json")
                .body(Body::from(valid_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // mcp:read is insufficient -> 403.
    let resp = app
        .clone()
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &valid_body(),
            "agent",
            &["mcp:read"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // mcp:propose -> through (201).
    let resp = app
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &valid_body(),
            "agent",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn propose_captures_pending_with_binding_code() {
    let app = api_router(state_with(Some(mem_store())).await);
    let resp = app
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &valid_body(),
            "agent",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert!(v["change_request_id"].as_str().is_some());
    assert_eq!(v["status"].as_str().unwrap(), "pending");
    assert!(!v["binding_code"].as_str().unwrap().is_empty());
    assert!(v["poll_url"]
        .as_str()
        .unwrap()
        .contains("/change_requests/"));
    // approval_url must be a *routable* operator handoff: the review queue
    // (GET /admin/changes) selecting and deep-linking this change's row via
    // the `pending_id` query and `#change-{id}` fragment the queue renders. It must NOT be
    // `/admin/changes/{id}` — there is no per-id GET route, so that would
    // 404.
    let id = v["change_request_id"].as_str().unwrap();
    let approval_url = v["approval_url"].as_str().unwrap();
    assert!(
        approval_url.ends_with(&format!("/admin/changes?pending_id={id}#change-{id}")),
        "approval_url should deep-link the queue row, got: {approval_url}"
    );
}

#[tokio::test]
async fn poll_reports_authorization_pending() {
    let app = api_router(state_with(Some(mem_store())).await);
    let proposed = body_json(
        app.clone()
            .oneshot(post_req(
                "/api/v1/admin/change_requests",
                &valid_body(),
                "agent",
                &["mcp:propose"],
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = proposed["change_request_id"].as_str().unwrap();

    let resp = app
        .oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "agent",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["status"].as_str().unwrap(), "authorization_pending");
    assert_eq!(v["action_type"].as_str().unwrap(), "rate_limit.update");
}

#[tokio::test]
async fn maker_cannot_poll_another_makers_request() {
    let app = api_router(state_with(Some(mem_store())).await);
    let proposed = body_json(
        app.clone()
            .oneshot(post_req(
                "/api/v1/admin/change_requests",
                &valid_body(),
                "agent-a",
                &["mcp:propose"],
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = proposed["change_request_id"].as_str().unwrap();

    // A different maker (same tenant, also mcp:propose) must NOT see it.
    let resp = app
        .oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "agent-b",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn propose_rejects_unknown_action_and_empty_justification() {
    let app = api_router(state_with(Some(mem_store())).await);

    let unknown = json!({
        "action_type": "api_key.delete_everything",
        "params": {},
        "justification": "x"
    });
    let resp = app
        .clone()
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &unknown,
            "agent",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let empty_just = json!({
        "action_type": "rate_limit.update",
        "params": {},
        "justification": "   "
    });
    let resp = app
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &empty_just,
            "agent",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn propose_503_when_store_absent() {
    let app = api_router(state_with(None).await);
    let resp = app
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &valid_body(),
            "agent",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ---- approve / deny / execute ----

/// Minimal in-memory `RateLimitPolicyStore`: only `update` (what the
/// `rate_limit.update` executor calls) is real; the rest are stubs.
/// Seeded with one policy in the default tenant.
struct FakeRateLimitStore {
    policies: Mutex<Vec<RateLimitPolicy>>,
}

impl FakeRateLimitStore {
    fn seeded(id: Uuid) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            policies: Mutex::new(vec![RateLimitPolicy {
                id,
                tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
                name: "nightly".into(),
                scope: QuotaScope::Tenant,
                scope_value: None,
                bucket_capacity: 100,
                refill_per_second: 1.0,
                action: QuotaAction::Call,
                created_at: now,
                updated_at: now,
            }]),
        }
    }

    fn capacity(&self, id: Uuid) -> Option<i32> {
        self.policies
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.bucket_capacity)
    }

    fn find_named(&self, name: &str) -> Option<RateLimitPolicy> {
        self.policies
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.name == name)
            .cloned()
    }

    fn exists(&self, id: Uuid) -> bool {
        self.policies.lock().unwrap().iter().any(|p| p.id == id)
    }
}

#[async_trait]
impl RateLimitPolicyStore for FakeRateLimitStore {
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        scope: QuotaScope,
        scope_value: Option<&str>,
        bucket_capacity: i32,
        refill_per_second: f64,
        action: QuotaAction,
    ) -> Result<RateLimitPolicy, RateLimitStoreError> {
        let now = OffsetDateTime::now_utc();
        let p = RateLimitPolicy {
            id: Uuid::now_v7(),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            scope,
            scope_value: scope_value.map(str::to_owned),
            bucket_capacity,
            refill_per_second,
            action,
            created_at: now,
            updated_at: now,
        };
        self.policies.lock().unwrap().push(p.clone());
        Ok(p)
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<RateLimitPolicy>, RateLimitStoreError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.tenant_id == tenant_id && p.id == id)
            .cloned())
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<RateLimitPolicy>, RateLimitStoreError> {
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        bucket_capacity: Option<i32>,
        refill_per_second: Option<f64>,
    ) -> Result<Option<RateLimitPolicy>, RateLimitStoreError> {
        let mut g = self.policies.lock().unwrap();
        if let Some(p) = g
            .iter_mut()
            .find(|p| p.tenant_id == tenant_id && p.id == id)
        {
            if let Some(bc) = bucket_capacity {
                p.bucket_capacity = bc;
            }
            if let Some(rp) = refill_per_second {
                p.refill_per_second = rp;
            }
            Ok(Some(p.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, RateLimitStoreError> {
        let mut g = self.policies.lock().unwrap();
        let before = g.len();
        g.retain(|p| !(p.tenant_id == tenant_id && p.id == id));
        Ok(g.len() != before)
    }

    async fn delete_all_for_tenant(&self, _tenant_id: &str) -> Result<u64, RateLimitStoreError> {
        Ok(0)
    }
}

async fn state_full(
    cr: Option<SharedChangeRequestStore>,
    rl: Option<Arc<dyn RateLimitPolicyStore>>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    let st = AdminState::new(
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
    .with_change_request_store(cr)
    .with_rate_limit_policy_store(rl);
    Arc::new(st)
}

fn post_empty(path: &str, sub: &str, scopes: &[&str]) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with_sub(sub, scopes));
    req
}

fn rate_limit_update_body(policy_id: Uuid, bucket_capacity: i32) -> Value {
    json!({
        "action_type": "rate_limit.update",
        "params": { "policy_id": policy_id, "bucket_capacity": bucket_capacity },
        "justification": "raise the nightly ceiling for the sync job"
    })
}

async fn propose_as(app: &axum::Router, body: &Value, sub: &str) -> String {
    let v = body_json(
        app.clone()
            .oneshot(post_req(
                "/api/v1/admin/change_requests",
                body,
                sub,
                &["mcp:propose"],
            ))
            .await
            .unwrap(),
    )
    .await;
    v["change_request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("propose failed: {v}"))
        .to_owned()
}

#[tokio::test]
async fn approve_executes_rate_limit_update() {
    let policy_id = Uuid::from_u128(0x1234);
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    let app = api_router(
        state_full(
            Some(mem_store()),
            Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
        )
        .await,
    );
    let id = propose_as(&app, &rate_limit_update_body(policy_id, 250), "alice").await;

    // A DIFFERENT operator (mcp:admin) approves -> executes server-side.
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        v["execution_result"]["bucket_capacity"].as_i64().unwrap(),
        250
    );
    // The real store was actually mutated.
    assert_eq!(rl.capacity(policy_id), Some(250));

    // The MAKER's poll must also surface the execution outcome detail, not
    // just the `executed` status.
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "executed");
    assert_eq!(
        poll["execution_result"]["bucket_capacity"]
            .as_i64()
            .unwrap(),
        250
    );
}

#[tokio::test]
async fn approve_requires_admin_scope_not_propose() {
    let policy_id = Uuid::from_u128(0x1234);
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    let app =
        api_router(state_full(Some(mem_store()), Some(rl as Arc<dyn RateLimitPolicyStore>)).await);
    let id = propose_as(&app, &rate_limit_update_body(policy_id, 250), "alice").await;
    // mcp:propose is the maker scope; approving needs mcp:admin.
    let resp = app
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn single_approval_allows_eligible_proposer() {
    let policy_id = Uuid::from_u128(0x1234);
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    let app = api_router(
        state_full(
            Some(mem_store()),
            Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
        )
        .await,
    );
    // The same subject proposes with mcp:propose and independently reaches
    // the approval boundary with mcp:admin. One eligible approval satisfies
    // the captured quorum without an implicit second person.
    let id = propose_as(&app, &rate_limit_update_body(policy_id, 250), "alice").await;
    let resp = app
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "alice",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "executed");
    assert_eq!(rl.capacity(policy_id), Some(250));
}

#[tokio::test]
async fn deny_records_denied_with_reason() {
    let app = api_router(state_full(Some(mem_store()), None).await);
    let id = propose_as(&app, &valid_body(), "alice").await;
    let resp = app
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/deny"),
            &json!({ "reason": "scope too broad" }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["status"].as_str().unwrap(), "denied");
    assert_eq!(v["denied_reason"].as_str().unwrap(), "scope too broad");
}

#[tokio::test]
async fn approve_unknown_id_is_404() {
    let app = api_router(state_full(Some(mem_store()), None).await);
    let resp = app
        .oneshot(post_empty(
            &format!(
                "/api/v1/admin/change_requests/{}/approve",
                Uuid::from_u128(0xDEAD)
            ),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approve_execution_fails_loudly_when_dependency_absent() {
    // The rate-limit store is NOT configured -> the executor returns
    // Unavailable -> the change is marked `failed` (not tombstoned as done),
    // and approve surfaces 503.
    let app = api_router(state_full(Some(mem_store()), None).await);
    let policy_id = Uuid::from_u128(0x1234);
    let id = propose_as(&app, &rate_limit_update_body(policy_id, 250), "alice").await;
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    // The maker polls and sees the change durably `failed`.
    let status = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(status["status"].as_str().unwrap(), "failed");
}

#[tokio::test]
async fn approve_rejects_non_positive_capacity() {
    // A captured non-positive bucket_capacity is rejected at execute time
    // (422) BEFORE the store write, not pushed to the store as a raw error.
    // The change is marked failed; the store is untouched.
    let policy_id = Uuid::from_u128(0x1234);
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    let app = api_router(
        state_full(
            Some(mem_store()),
            Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
        )
        .await,
    );
    let id = propose_as(&app, &rate_limit_update_body(policy_id, -5), "alice").await;
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rl.capacity(policy_id), Some(100), "store must be untouched");
    let status = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(status["status"].as_str().unwrap(), "failed");
}

#[tokio::test]
async fn approve_resumes_already_approved_row() {
    // A row stranded in `approved` (e.g. the approval audit failed before
    // execution) is resumable — re-POSTing approve drives execution rather
    // than 409-ing on the non-pending row.
    let policy_id = Uuid::from_u128(0x1234);
    let cr = mem_store();
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    let app = api_router(
        state_full(
            Some(cr.clone()),
            Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
        )
        .await,
    );
    let id_str = propose_as(&app, &rate_limit_update_body(policy_id, 250), "alice").await;
    let id = Uuid::parse_str(&id_str).unwrap();
    let tenant = waygate_core::TenantId::default();
    // Commit the approval directly (status -> approved) without executing,
    // simulating the audit-failure strand.
    cr.try_approve(tenant.as_str(), id, "bob")
        .await
        .unwrap()
        .unwrap();
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "carol",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(rl.capacity(policy_id), Some(250));
}

async fn state_and_sink(
    cr: Option<SharedChangeRequestStore>,
    rl: Option<Arc<dyn RateLimitPolicyStore>>,
) -> (Arc<AdminState>, Arc<waygate_mcp::audit::InMemorySink>) {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let sink = Arc::new(waygate_mcp::audit::InMemorySink::default());
    let evidence: waygate_mcp::audit::SharedEvidence = sink.clone();
    let st = AdminState::new(
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
    .with_change_request_store(cr)
    .with_rate_limit_policy_store(rl);
    (Arc::new(st), sink)
}

#[tokio::test]
async fn resume_emits_approve_audit_before_execute() {
    // The resume path must record a ChangeRequestApprove BEFORE execution,
    // so a row stranded by an approval-audit failure never executes with
    // only an Execute audit.
    let policy_id = Uuid::from_u128(0x1234);
    let cr = mem_store();
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    let (state, sink) =
        state_and_sink(Some(cr.clone()), Some(rl as Arc<dyn RateLimitPolicyStore>)).await;
    let app = api_router(state);
    let id_str = propose_as(&app, &rate_limit_update_body(policy_id, 250), "alice").await;
    let id = Uuid::parse_str(&id_str).unwrap();
    // Strand it `approved` WITHOUT the handler -> no approve audit yet.
    cr.try_approve(waygate_core::TenantId::default().as_str(), id, "bob")
        .await
        .unwrap()
        .unwrap();
    let resp = app
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "carol",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let actions: Vec<String> = sink
        .snapshot()
        .await
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(
        actions.iter().any(|a| a == "ChangeRequestApprove"),
        "resume must emit ChangeRequestApprove before execute; got {actions:?}",
    );
    assert!(
        actions.iter().any(|a| a == "ChangeRequestExecute"),
        "resume must emit ChangeRequestExecute; got {actions:?}",
    );
}

// ---- secret-return channel (burn-on-read) ----

#[tokio::test]
async fn secret_retrieve_is_single_use_and_maker_scoped() {
    let store = mem_store();
    let crypto = UpstreamCrypto::from_key_bytes([7u8; 32]);
    let id = executed_with_secret(&store, &crypto, "maker", b"mcpgw_TESTSECRET").await;
    let app = api_router(state_with_secret(store, crypto).await);
    let path = format!("/api/v1/admin/change_requests/{id}/secret");

    // A DIFFERENT maker can't even see it — 404 (not 403), so the route
    // can't probe another maker's change ids. Checked BEFORE the burn, so it
    // leaves the secret intact for the rightful maker below.
    let resp = app
        .clone()
        .oneshot(get_req(&path, "intruder", &["mcp:propose"]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The rightful maker retrieves the secret exactly once.
    let resp = app
        .clone()
        .oneshot(get_req(&path, "maker", &["mcp:propose"]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Never cached — the "shown once" property (same headers as the api-key
    // reveal page).
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CACHE_CONTROL)
            .unwrap(),
        "no-store, no-cache, must-revalidate, private"
    );
    let v = body_json(resp).await;
    assert_eq!(v["secret"].as_str().unwrap(), "mcpgw_TESTSECRET");

    // A second retrieve is refused — single-use burn (409).
    let resp = app
        .clone()
        .oneshot(get_req(&path, "maker", &["mcp:propose"]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn secret_retrieve_requires_executed() {
    // A change that hasn't executed has no retrievable secret yet — 409,
    // not a leak or a 500.
    let store = mem_store();
    let crypto = UpstreamCrypto::from_key_bytes([7u8; 32]);
    let tenant = waygate_core::TenantId::default();
    let cr = store
        .propose(NewChangeRequest {
            tenant_id: tenant.as_str().to_owned(),
            requested_by: "maker".into(),
            client_id: None,
            action_type: "api_key.mint".into(),
            params: json!({}),
            preview: None,
            target_etag: None,
            justification: "pending change, not yet approved".into(),
            requirement: ApprovalRequirement::single("dashboard-admins"),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        })
        .await
        .unwrap();
    let app = api_router(state_with_secret(store, crypto).await);
    let resp = app
        .oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{}/secret", cr.id),
            "maker",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn api_key_mint_fails_closed_without_secret_channel() {
    // With no secret channel configured the executor refuses to mint at all,
    // so no orphan key is created (validate-before-irreversible). The crypto
    // pre-check fires before any store access, so a crypto-less, ApiKeyStore-
    // less state still yields Unavailable (not a store error).
    let state = state_with(Some(mem_store())).await;
    let actor = principal_with_sub("operator", &["mcp:admin"]);
    let params = json!({ "name": "triage", "sub": "svc-triage", "scopes": ["mcp:read"] });
    let exec = registry()
        .get("api_key.mint")
        .expect("api_key.mint must be registered");
    let err = exec
        .execute(&state, "default", &actor, &params)
        .await
        .expect_err("must fail closed without a secret channel");
    assert!(
        matches!(err, ExecError::Unavailable(_)),
        "expected Unavailable when the secret channel is absent, got {err:?}"
    );
}

#[tokio::test]
async fn api_key_revoke_fails_closed_without_store() {
    // With the api-keys runtime disabled, require_api_keys_runtime returns
    // ServiceUnavailable, so the executor fails closed (no store access) rather
    // than reporting a revoke that didn't happen. (A full propose -> approve ->
    // revoke needs a Postgres-backed ApiKeyStore — the store is a concrete Pg
    // type, not a trait — so it's covered by the Pg-backed dashboard revoke
    // tests; here we pin the executor's fail-closed wiring, matching the
    // api_key.mint fails-closed test above.)
    let state = state_with(Some(mem_store())).await;
    let actor = principal_with_sub("operator", &["mcp:admin"]);
    let params = json!({ "api_key_id": Uuid::nil() });
    let exec = registry()
        .get("api_key.revoke")
        .expect("api_key.revoke must be registered");
    let err = exec
        .execute(&state, "default", &actor, &params)
        .await
        .expect_err("must fail closed without an api-keys store");
    assert!(
        matches!(err, ExecError::Unavailable(_)),
        "expected Unavailable when the api-keys runtime is absent, got {err:?}"
    );
}

// ---- multi-approver (M-of-N) ----

#[tokio::test]
async fn multi_approver_executes_only_after_quorum() {
    let policy_id = Uuid::from_u128(0x5678);
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id)); // seeded capacity 100
    let cr_store = mem_store();
    // Seed a count=2 change request directly. No built-in executor declares
    // count>1 yet (propose_core resolves count=1 from the executor), so we
    // insert the M-of-N requirement straight into the store to exercise the
    // approve path.
    let tenant = waygate_core::TenantId::default();
    let cr = cr_store
        .propose(NewChangeRequest {
            tenant_id: tenant.as_str().to_owned(),
            requested_by: "alice".into(),
            client_id: None,
            action_type: "rate_limit.update".into(),
            params: json!({ "policy_id": policy_id, "bucket_capacity": 250 }),
            preview: None,
            target_etag: None,
            justification: "raise the nightly ceiling (two-person rule)".into(),
            requirement: ApprovalRequirement {
                required_approvals: 2,
                eligible_role: "dashboard-admins".into(),
                factors: vec![],
                cooldown_seconds: None,
            },
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        })
        .await
        .unwrap();
    let id = cr.id;
    let (state, sink) = state_and_sink(
        Some(cr_store as SharedChangeRequestStore),
        Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
    )
    .await;
    let app = api_router(state);
    let approve = |sub: &'static str| {
        post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            sub,
            &["mcp:admin"],
        )
    };

    // The eligible proposer supplies the first distinct approval. The quorum
    // is not met yet, so the change stays pending and the target is untouched.
    let resp = app.clone().oneshot(approve("alice")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await["status"].as_str().unwrap(),
        "pending",
        "1 of 2 approvals must not execute"
    );
    assert_eq!(
        rl.capacity(policy_id),
        Some(100),
        "no mutation before quorum"
    );

    // A repeat by the same proposer does not inflate the distinct tally.
    let resp = app.clone().oneshot(approve("alice")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"].as_str().unwrap(), "pending");
    assert_eq!(rl.capacity(policy_id), Some(100));

    // A second distinct eligible admin completes the quorum and executes once.
    let resp = app.clone().oneshot(approve("bob")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await["status"].as_str().unwrap(),
        "executed"
    );
    assert_eq!(
        rl.capacity(policy_id),
        Some(250),
        "quorum met -> the rate-limit store was mutated"
    );

    // The fail-closed execute audit attributes EVERY distinct approver that
    // counted toward the quorum. Even if a partial approval's
    // post-commit ChangeRequestApprove audit had failed, the execution record
    // still names the full set, so a counting approval can never contribute to
    // an execution that has no durable audit naming that approver.
    let exec_reason = sink
        .snapshot()
        .await
        .into_iter()
        .find(|e| e.action == "ChangeRequestExecute")
        .and_then(|e| e.reason)
        .expect("an executed M-of-N change must emit ChangeRequestExecute with a reason");
    assert!(
        exec_reason.contains("alice") && exec_reason.contains("bob"),
        "execute audit must name the proposer and second distinct approver; got {exec_reason:?}",
    );
}

#[tokio::test]
async fn protected_approval_without_dashboard_assurance_has_no_side_effect() {
    let policy_id = Uuid::from_u128(0x5679);
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    let cr_store = Arc::new(InMemoryChangeRequestStore::new());
    let tenant = waygate_core::TenantId::default();
    let cr = cr_store
        .propose(NewChangeRequest {
            tenant_id: tenant.as_str().to_owned(),
            requested_by: "alice".into(),
            client_id: None,
            action_type: "rate_limit.update".into(),
            params: json!({ "policy_id": policy_id, "bucket_capacity": 250 }),
            preview: None,
            target_etag: None,
            justification: "protected rate-limit change".into(),
            requirement: ApprovalRequirement {
                required_approvals: 1,
                eligible_role: "dashboard-admins".into(),
                factors: vec!["mfa".into()],
                cooldown_seconds: None,
            },
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        })
        .await
        .unwrap();
    let (state, _sink) = state_and_sink(
        Some(cr_store.clone() as SharedChangeRequestStore),
        Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
    )
    .await;
    let app = api_router(state);

    let response = app
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{}/approve", cr.id),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        rl.capacity(policy_id),
        Some(100),
        "factor refusal must happen before the governed mutation"
    );
    let stored = cr_store
        .get(tenant.as_str(), cr.id)
        .await
        .unwrap()
        .expect("change remains present");
    assert_eq!(
        stored.status,
        waygate_changeset::ChangeRequestStatus::Pending
    );
}

// ---- standard executors (rate_limit create/delete, inspection_rule
//      create/update, oauth_consent revoke) ----

/// In-memory `InspectionRulesStore` for the executor tests: real insert /
/// get / update / delete over a `Vec`, tenant-scoped, with the
/// `(tenant, inspector, name)` uniqueness the Pg store enforces.
struct FakeInspectionRulesStore {
    rules: Mutex<Vec<InspectionRule>>,
}

impl FakeInspectionRulesStore {
    fn seeded(rule: InspectionRule) -> Self {
        Self {
            rules: Mutex::new(vec![rule]),
        }
    }

    fn count(&self) -> usize {
        self.rules.lock().unwrap().len()
    }
}

#[async_trait]
impl InspectionRulesStore for FakeInspectionRulesStore {
    async fn insert(&self, rule: NewInspectionRule<'_>) -> Result<InspectionRule, RuleError> {
        let mut g = self.rules.lock().unwrap();
        if g.iter().any(|r| {
            r.tenant_id == rule.tenant_id && r.inspector == rule.inspector && r.name == rule.name
        }) {
            return Err(RuleError::DuplicateName);
        }
        let now = OffsetDateTime::now_utc();
        let r = InspectionRule {
            id: Uuid::now_v7(),
            tenant_id: rule.tenant_id.to_owned(),
            inspector: rule.inspector,
            name: rule.name.to_owned(),
            config: rule.config.clone(),
            applies_to: rule.applies_to.clone(),
            enabled: rule.enabled,
            created_at: now,
            updated_at: now,
        };
        g.push(r.clone());
        Ok(r)
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<InspectionRule>, RuleError> {
        Ok(self
            .rules
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
            .cloned())
    }

    async fn list(
        &self,
        tenant_id: &str,
        _filter: RuleFilter<'_>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<InspectionRule>, RuleError> {
        Ok(self
            .rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: RuleUpdate<'_>,
    ) -> Result<Option<InspectionRule>, RuleError> {
        let mut g = self.rules.lock().unwrap();
        let Some(r) = g
            .iter_mut()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
        else {
            return Ok(None);
        };
        if let Some(n) = update.name {
            r.name = n.to_owned();
        }
        if let Some(c) = update.config {
            r.config = c.clone();
        }
        if let Some(a) = update.applies_to {
            r.applies_to = a.clone();
        }
        if let Some(e) = update.enabled {
            r.enabled = e;
        }
        Ok(Some(r.clone()))
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, RuleError> {
        let mut g = self.rules.lock().unwrap();
        let before = g.len();
        g.retain(|r| !(r.tenant_id == tenant_id && r.id == id));
        Ok(g.len() != before)
    }
}

/// In-memory `ConsentStore` for the revoke executor test: real
/// tenant-scoped soft-revoke over a `Vec`. Only `revoke` / `list` are
/// exercised; `upsert` / `find_active` are not on this path.
struct FakeConsentStore {
    grants: Mutex<Vec<ConsentGrant>>,
}

impl FakeConsentStore {
    fn seeded(grant: ConsentGrant) -> Self {
        Self {
            grants: Mutex::new(vec![grant]),
        }
    }

    fn is_revoked(&self, principal_sub: &str, client_id: &str) -> bool {
        self.grants
            .lock()
            .unwrap()
            .iter()
            .find(|g| g.principal_sub == principal_sub && g.client_id == client_id)
            .map(|g| g.revoked_at.is_some())
            .unwrap_or(false)
    }
}

#[async_trait]
impl ConsentStore for FakeConsentStore {
    async fn upsert(&self, _grant: NewConsentGrant<'_>) -> Result<ConsentGrant, ConsentStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }

    async fn list(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<ConsentGrant>, ConsentStoreError> {
        Ok(self
            .grants
            .lock()
            .unwrap()
            .iter()
            .filter(|g| {
                g.tenant_id == tenant_id
                    && match principal_sub {
                        Some(s) => g.principal_sub == s,
                        None => true,
                    }
            })
            .cloned()
            .collect())
    }

    async fn revoke(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        client_id: &str,
    ) -> Result<bool, ConsentStoreError> {
        let mut g = self.grants.lock().unwrap();
        if let Some(row) = g.iter_mut().find(|r| {
            r.tenant_id == tenant_id
                && r.principal_sub == principal_sub
                && r.client_id == client_id
                && r.revoked_at.is_none()
        }) {
            row.revoked_at = Some(OffsetDateTime::now_utc());
            Ok(true)
        } else {
            // Absent or already-revoked: idempotent no-op.
            Ok(false)
        }
    }

    async fn find_active(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _client_id: &str,
    ) -> Result<Option<ConsentGrant>, ConsentStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }
}

async fn state_with_rules(
    cr: Option<SharedChangeRequestStore>,
    rules: waygate_dashboard_stores::inspection_rules::SharedRulesStore,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_inspection_rules_store(Some(rules)),
    )
}

async fn state_with_consent(
    cr: Option<SharedChangeRequestStore>,
    consent: waygate_as::consent::SharedConsentStore,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_consent_store(Some(consent)),
    )
}

/// Approve a pending change as an eligible operator, returning
/// the decision response JSON. Mirrors the inline pattern the rate_limit
/// tests use.
async fn approve_as(app: &axum::Router, id: &str, sub: &str) -> Value {
    let resp = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "effect_preview_acknowledged": true }),
            sub,
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "approve should be 200");
    body_json(resp).await
}

#[tokio::test]
async fn approve_executes_rate_limit_create() {
    let rl = Arc::new(FakeRateLimitStore::seeded(Uuid::from_u128(0x11)));
    let app = api_router(
        state_full(
            Some(mem_store()),
            Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
        )
        .await,
    );
    let body = json!({
        "action_type": "rate_limit.create",
        "params": {
            "name": "burst-cap",
            "scope": "tenant",
            "bucket_capacity": 500,
            "refill_per_second": 10.0,
            "action": "call"
        },
        "justification": "add a burst ceiling for the importer job"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(v["execution_result"]["name"].as_str().unwrap(), "burst-cap");
    // The policy was actually created in the store with the proposed fields.
    let created = rl.find_named("burst-cap").expect("policy persisted");
    assert_eq!(created.bucket_capacity, 500);
}

#[tokio::test]
async fn approve_executes_rate_limit_delete() {
    let policy_id = Uuid::from_u128(0x22);
    let rl = Arc::new(FakeRateLimitStore::seeded(policy_id));
    assert!(rl.exists(policy_id));
    let app = api_router(
        state_full(
            Some(mem_store()),
            Some(rl.clone() as Arc<dyn RateLimitPolicyStore>),
        )
        .await,
    );
    let body = json!({
        "action_type": "rate_limit.delete",
        "params": { "policy_id": policy_id },
        "justification": "retire the seeded nightly policy"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert!(!rl.exists(policy_id), "policy removed from the store");
}

#[tokio::test]
async fn approve_rate_limit_delete_missing_fails_precondition() {
    // The target policy doesn't exist (deleted between propose and approve):
    // delete_policy_core returns Ok(false) -> the executor raises a
    // Precondition -> the change is marked `failed` (409), not silently
    // "executed" with nothing done.
    let rl = Arc::new(FakeRateLimitStore::seeded(Uuid::from_u128(0x33)));
    let app =
        api_router(state_full(Some(mem_store()), Some(rl as Arc<dyn RateLimitPolicyStore>)).await);
    let body = json!({
        "action_type": "rate_limit.delete",
        "params": { "policy_id": Uuid::from_u128(0xdead) },
        "justification": "delete a policy that is already gone"
    });
    let id = propose_as(&app, &body, "alice").await;
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "failed");
}

#[tokio::test]
async fn approve_executes_oauth_consent_revoke() {
    let now = OffsetDateTime::now_utc();
    let grant = ConsentGrant {
        id: Uuid::from_u128(0x55),
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        principal_sub: "user-9".into(),
        client_id: "https://app.example/cimd.json".into(),
        scopes: vec!["mcp:read".into()],
        granted_at: now,
        expires_at: None,
        revoked_at: None,
    };
    let consent = Arc::new(FakeConsentStore::seeded(grant));
    let app = api_router(
        state_with_consent(
            Some(mem_store()),
            consent.clone() as waygate_as::consent::SharedConsentStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "oauth_consent.revoke",
        "params": {
            "principal_sub": "user-9",
            "client_id": "https://app.example/cimd.json"
        },
        "justification": "revoke a stale grant after offboarding"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert!(v["execution_result"]["removed"].as_bool().unwrap());
    assert!(
        consent.is_revoked("user-9", "https://app.example/cimd.json"),
        "grant soft-revoked in the store"
    );
}

// ---- elevated executors (inspection_rule.delete, peer
//      create/update/delete, rbac.role create/update) ----

/// In-memory `FederatedPeersStore` for the peer executor tests: real
/// tenant-scoped insert / get / update / delete over a `Vec`, with the
/// `(tenant, peer_name|issuer)` uniqueness the Pg store enforces.
struct FakeFederatedPeersStore {
    peers: Mutex<Vec<FederatedPeer>>,
}

impl FakeFederatedPeersStore {
    fn new() -> Self {
        Self {
            peers: Mutex::new(vec![]),
        }
    }

    fn seeded(peer: FederatedPeer) -> Self {
        Self {
            peers: Mutex::new(vec![peer]),
        }
    }

    fn count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    fn get_by_id(&self, id: Uuid) -> Option<FederatedPeer> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.id == id)
            .cloned()
    }
}

#[async_trait]
impl FederatedPeersStore for FakeFederatedPeersStore {
    async fn insert(&self, peer: NewFederatedPeer<'_>) -> Result<FederatedPeer, PeerError> {
        let mut g = self.peers.lock().unwrap();
        if g.iter().any(|p| {
            p.tenant_id == peer.tenant_id
                && (p.peer_name == peer.peer_name || p.issuer == peer.issuer)
        }) {
            return Err(PeerError::DuplicateName);
        }
        let now = OffsetDateTime::now_utc();
        let p = FederatedPeer {
            id: Uuid::now_v7(),
            tenant_id: peer.tenant_id.to_owned(),
            peer_name: peer.peer_name.to_owned(),
            issuer: peer.issuer.to_owned(),
            jwks_url: peer.jwks_url.to_owned(),
            trust_tier: peer.trust_tier,
            created_at: now,
            updated_at: now,
        };
        g.push(p.clone());
        Ok(p)
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<FederatedPeer>, PeerError> {
        Ok(self
            .peers
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.tenant_id == tenant_id && p.id == id)
            .cloned())
    }

    async fn list(
        &self,
        tenant_id: &str,
        _filter: PeerFilter<'_>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError> {
        Ok(self
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: PeerUpdate<'_>,
    ) -> Result<Option<FederatedPeer>, PeerError> {
        let mut g = self.peers.lock().unwrap();
        let Some(p) = g
            .iter_mut()
            .find(|p| p.tenant_id == tenant_id && p.id == id)
        else {
            return Ok(None);
        };
        if let Some(n) = update.peer_name {
            p.peer_name = n.to_owned();
        }
        if let Some(i) = update.issuer {
            p.issuer = i.to_owned();
        }
        if let Some(j) = update.jwks_url {
            p.jwks_url = j.to_owned();
        }
        if let Some(t) = update.trust_tier {
            p.trust_tier = t;
        }
        Ok(Some(p.clone()))
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, PeerError> {
        let mut g = self.peers.lock().unwrap();
        let before = g.len();
        g.retain(|p| !(p.tenant_id == tenant_id && p.id == id));
        Ok(g.len() != before)
    }

    async fn list_all_for_refresh(
        &self,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError> {
        Ok(self.peers.lock().unwrap().clone())
    }
}

/// In-memory `RbacStore` for the role executor tests. Only `create_role`
/// and `update_role` (what the executors reach through their cores) are
/// real; the assignment / group-mapping / resolver surface isn't on this
/// path, so those methods panic if a test ever wanders into them.
struct FakeRbacStore {
    roles: Mutex<Vec<Role>>,
    assignments: Mutex<Vec<RoleAssignment>>,
    mappings: Mutex<Vec<GroupRoleMapping>>,
}

impl FakeRbacStore {
    fn new() -> Self {
        Self {
            roles: Mutex::new(vec![]),
            assignments: Mutex::new(vec![]),
            mappings: Mutex::new(vec![]),
        }
    }

    fn seeded(role: Role) -> Self {
        Self {
            roles: Mutex::new(vec![role]),
            assignments: Mutex::new(vec![]),
            mappings: Mutex::new(vec![]),
        }
    }

    fn count(&self) -> usize {
        self.roles.lock().unwrap().len()
    }

    fn get_by_id(&self, id: Uuid) -> Option<Role> {
        self.roles
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    fn assignment_count(&self) -> usize {
        self.assignments.lock().unwrap().len()
    }

    fn mapping_count(&self) -> usize {
        self.mappings.lock().unwrap().len()
    }
}

#[async_trait]
impl RbacStore for FakeRbacStore {
    async fn resolve_for_subject(
        &self,
        _tenant_id: &str,
        _sub: &str,
        _scim_group_ids: &[Uuid],
    ) -> Result<ResolvedRoles, RbacError> {
        unimplemented!("not exercised by the role executor tests")
    }

    async fn create_role(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<Role, RbacError> {
        let mut g = self.roles.lock().unwrap();
        if g.iter().any(|r| r.tenant_id == tenant_id && r.name == name) {
            return Err(RbacError::Conflict(format!(
                "role name {name} already exists"
            )));
        }
        let now = OffsetDateTime::now_utc();
        let role = Role {
            id: Uuid::now_v7(),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            description: description.map(str::to_owned),
            scopes: scopes.to_vec(),
            created_at: now,
            updated_at: now,
        };
        g.push(role.clone());
        Ok(role)
    }

    async fn get_role(&self, tenant_id: &str, id: Uuid) -> Result<Option<Role>, RbacError> {
        Ok(self
            .roles
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
            .cloned())
    }

    async fn list_roles(&self, _tenant_id: &str) -> Result<Vec<Role>, RbacError> {
        unimplemented!("not exercised by the role executor tests")
    }

    async fn update_role(
        &self,
        tenant_id: &str,
        id: Uuid,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<Option<Role>, RbacError> {
        let mut g = self.roles.lock().unwrap();
        let Some(r) = g
            .iter_mut()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
        else {
            return Ok(None);
        };
        r.name = name.to_owned();
        r.description = description.map(str::to_owned);
        r.scopes = scopes.to_vec();
        r.updated_at += Duration::seconds(1);
        Ok(Some(r.clone()))
    }

    async fn delete_role(&self, tenant_id: &str, id: Uuid) -> Result<bool, RbacError> {
        let mut g = self.roles.lock().unwrap();
        let before = g.len();
        g.retain(|r| !(r.tenant_id == tenant_id && r.id == id));
        Ok(g.len() != before)
    }

    async fn delete_all_roles_for_tenant(&self, _tenant_id: &str) -> Result<u64, RbacError> {
        unimplemented!("not exercised by the role executor tests")
    }

    async fn create_assignment(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        subject_sub: &str,
    ) -> Result<RoleAssignment, RbacError> {
        let mut assignments = self.assignments.lock().unwrap();
        if assignments.iter().any(|assignment| {
            assignment.tenant_id == tenant_id
                && assignment.role_id == role_id
                && assignment.subject_sub == subject_sub
        }) {
            return Err(RbacError::Conflict("assignment already exists".into()));
        }
        let assignment = RoleAssignment {
            id: Uuid::now_v7(),
            tenant_id: tenant_id.to_owned(),
            role_id,
            subject_sub: subject_sub.to_owned(),
            created_at: OffsetDateTime::now_utc(),
        };
        assignments.push(assignment.clone());
        Ok(assignment)
    }

    async fn create_assignment_if_role_version(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        subject_sub: &str,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        let role_matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant_id
                && role.id == role_id
                && role.updated_at == expected_role_updated_at
        });
        if !role_matches {
            return Ok(None);
        }
        self.create_assignment(tenant_id, role_id, subject_sub)
            .await
            .map(Some)
    }

    async fn get_assignment(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        Ok(self
            .assignments
            .lock()
            .unwrap()
            .iter()
            .find(|assignment| assignment.tenant_id == tenant_id && assignment.id == id)
            .cloned())
    }

    async fn list_assignments(
        &self,
        tenant_id: &str,
        role_id: Option<Uuid>,
        subject_sub: Option<&str>,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        Ok(self
            .assignments
            .lock()
            .unwrap()
            .iter()
            .filter(|assignment| assignment.tenant_id == tenant_id)
            .filter(|assignment| role_id.is_none_or(|id| assignment.role_id == id))
            .filter(|assignment| {
                subject_sub.is_none_or(|sub| assignment.subject_sub.as_str() == sub)
            })
            .cloned()
            .collect())
    }

    async fn delete_assignment(&self, tenant_id: &str, id: Uuid) -> Result<bool, RbacError> {
        let mut assignments = self.assignments.lock().unwrap();
        let before = assignments.len();
        assignments
            .retain(|assignment| !(assignment.tenant_id == tenant_id && assignment.id == id));
        Ok(before != assignments.len())
    }

    async fn delete_assignment_if_role_version(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        let role_matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant_id
                && role.id == expected_role_id
                && role.updated_at == expected_role_updated_at
        });
        if !role_matches {
            return Ok(None);
        }
        let mut assignments = self.assignments.lock().unwrap();
        let Some(index) = assignments.iter().position(|assignment| {
            assignment.tenant_id == tenant_id
                && assignment.id == id
                && assignment.role_id == expected_role_id
        }) else {
            return Ok(None);
        };
        Ok(Some(assignments.remove(index)))
    }

    async fn create_group_mapping(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<GroupRoleMapping, RbacError> {
        let mut mappings = self.mappings.lock().unwrap();
        if mappings.iter().any(|mapping| {
            mapping.tenant_id == tenant_id
                && mapping.group_id == group_id
                && mapping.role_id == role_id
        }) {
            return Err(RbacError::Conflict("group mapping already exists".into()));
        }
        let mapping = GroupRoleMapping {
            tenant_id: tenant_id.to_owned(),
            group_id,
            role_id,
            created_at: OffsetDateTime::now_utc(),
        };
        mappings.push(mapping.clone());
        Ok(mapping)
    }

    async fn create_group_mapping_if_role_version(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<GroupRoleMapping>, RbacError> {
        let role_matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant_id
                && role.id == role_id
                && role.updated_at == expected_role_updated_at
        });
        if !role_matches {
            return Ok(None);
        }
        self.create_group_mapping(tenant_id, group_id, role_id)
            .await
            .map(Some)
    }

    async fn list_group_mappings(
        &self,
        tenant_id: &str,
        role_id: Option<Uuid>,
        group_id: Option<Uuid>,
    ) -> Result<Vec<GroupRoleMapping>, RbacError> {
        Ok(self
            .mappings
            .lock()
            .unwrap()
            .iter()
            .filter(|mapping| mapping.tenant_id == tenant_id)
            .filter(|mapping| role_id.is_none_or(|id| mapping.role_id == id))
            .filter(|mapping| group_id.is_none_or(|id| mapping.group_id == id))
            .cloned()
            .collect())
    }

    async fn delete_group_mapping(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, RbacError> {
        let mut mappings = self.mappings.lock().unwrap();
        let before = mappings.len();
        mappings.retain(|mapping| {
            !(mapping.tenant_id == tenant_id
                && mapping.group_id == group_id
                && mapping.role_id == role_id)
        });
        Ok(before != mappings.len())
    }

    async fn delete_group_mapping_if_versions(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_mapping_created_at: OffsetDateTime,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<GroupRoleMapping>, RbacError> {
        let role_matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant_id
                && role.id == role_id
                && role.updated_at == expected_role_updated_at
        });
        if !role_matches {
            return Ok(None);
        }
        let mut mappings = self.mappings.lock().unwrap();
        let Some(index) = mappings.iter().position(|mapping| {
            mapping.tenant_id == tenant_id
                && mapping.group_id == group_id
                && mapping.role_id == role_id
                && mapping.created_at == expected_mapping_created_at
        }) else {
            return Ok(None);
        };
        Ok(Some(mappings.remove(index)))
    }
}

async fn state_with_peers(
    cr: Option<SharedChangeRequestStore>,
    peers: waygate_federation::SharedPeersStore,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_federated_peers_store(Some(peers)),
    )
}

async fn state_with_rbac(
    cr: Option<SharedChangeRequestStore>,
    rbac: Arc<dyn RbacStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_rbac_store(Some(rbac)),
    )
}

async fn state_with_rbac_and_groups(
    cr: Option<SharedChangeRequestStore>,
    rbac: Arc<dyn RbacStore>,
    groups: Arc<dyn GroupStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_rbac_store(Some(rbac))
        .with_group_store(Some(groups)),
    )
}

fn seed_peer(id: Uuid, name: &str) -> FederatedPeer {
    let now = OffsetDateTime::now_utc();
    FederatedPeer {
        id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        peer_name: name.into(),
        issuer: "https://peer.example".into(),
        jwks_url: "https://peer.example/jwks".into(),
        trust_tier: TrustTier::Restricted,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn approve_executes_inspection_rule_delete() {
    let now = OffsetDateTime::now_utc();
    let rule_id = Uuid::from_u128(0x6001);
    let seed = InspectionRule {
        id: rule_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        inspector: InspectorKind::Pii,
        name: "mask-ssn".into(),
        config: json!({}),
        applies_to: json!({}),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    let rules = Arc::new(FakeInspectionRulesStore::seeded(seed));
    let app = api_router(
        state_with_rules(
            Some(mem_store()),
            rules.clone() as waygate_dashboard_stores::inspection_rules::SharedRulesStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "inspection_rule.delete",
        "params": { "id": rule_id },
        "justification": "retire the SSN-masking rule"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(rules.count(), 0, "rule removed from the store");
}

#[tokio::test]
async fn approve_executes_peer_create() {
    let peers = Arc::new(FakeFederatedPeersStore::new());
    let app = api_router(
        state_with_peers(
            Some(mem_store()),
            peers.clone() as waygate_federation::SharedPeersStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "peer.create",
        "params": {
            "peer_name": "east-gw",
            "issuer": "https://east.example",
            "jwks_url": "https://east.example/jwks"
        },
        "justification": "federate the east gateway"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        v["execution_result"]["peer_name"].as_str().unwrap(),
        "east-gw"
    );
    assert_eq!(
        v["execution_result"]["trust_tier"].as_str().unwrap(),
        "full"
    );
    assert_eq!(peers.count(), 1, "peer persisted");
}

#[tokio::test]
async fn approve_executes_peer_update() {
    let peer_id = Uuid::from_u128(0x6002);
    let peers = Arc::new(FakeFederatedPeersStore::seeded(seed_peer(
        peer_id, "west-gw",
    )));
    let app = api_router(
        state_with_peers(
            Some(mem_store()),
            peers.clone() as waygate_federation::SharedPeersStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "peer.update",
        "params": { "id": peer_id, "peer_name": "renamed-gw" },
        "justification": "rename west gateway"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        peers.get_by_id(peer_id).unwrap().trust_tier,
        TrustTier::Restricted,
        "existing stored label is preserved"
    );
}

#[tokio::test]
async fn approve_executes_peer_delete() {
    let peer_id = Uuid::from_u128(0x6003);
    let peers = Arc::new(FakeFederatedPeersStore::seeded(seed_peer(
        peer_id, "stale-gw",
    )));
    let app = api_router(
        state_with_peers(
            Some(mem_store()),
            peers.clone() as waygate_federation::SharedPeersStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "peer.delete",
        "params": { "id": peer_id },
        "justification": "decommission stale-gw"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(peers.count(), 0, "peer removed from the store");
}

#[tokio::test]
async fn approve_executes_rbac_role_create() {
    let rbac = Arc::new(FakeRbacStore::new());
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    let body = json!({
        "action_type": "rbac.role.create",
        "params": {
            "name": "triage",
            "scopes": ["mcp:read", "mcp:invoke"]
        },
        "justification": "least-privilege triage role for agents"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(v["execution_result"]["name"].as_str().unwrap(), "triage");
    assert_eq!(rbac.count(), 1, "role persisted");
}

#[tokio::test]
async fn ordinary_direct_and_group_membership_actions_execute_end_to_end() {
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x6010);
    let group_id = Uuid::from_u128(0x6011);
    let role = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "readers".into(),
        description: None,
        scopes: vec!["mcp:read".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(role));
    let groups = Arc::new(FakeGroupStore {
        rows: Mutex::new(vec![GroupView {
            id: group_id,
            tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
            display_name: "support".into(),
            source: "scim".into(),
            external_id: Some("idp-support".into()),
            created_at: now,
            updated_at: now,
            user_member_count: 1,
            key_member_count: 0,
            role_mapping_count: 0,
        }]),
    });
    let app = api_router(
        state_with_rbac_and_groups(
            Some(mem_store()),
            rbac.clone() as Arc<dyn RbacStore>,
            groups,
        )
        .await,
    );

    let direct_grant = json!({
        "action_type": "rbac.assignment.grant",
        "params": { "role_id": role_id, "subject_sub": "user-7" },
        "justification": "grant the reader role directly"
    });
    let id = propose_as(&app, &direct_grant, "alice").await;
    let executed = approve_as(&app, &id, "bob").await;
    assert_eq!(executed["status"], "executed");
    assert_eq!(rbac.assignment_count(), 1);
    let assignment_id = rbac.assignments.lock().unwrap()[0].id;

    let group_grant = json!({
        "action_type": "rbac.group_mapping.grant",
        "params": { "group_id": group_id, "role_id": role_id },
        "justification": "grant the reader role through the support group"
    });
    let id = propose_as(&app, &group_grant, "alice").await;
    let executed = approve_as(&app, &id, "bob").await;
    assert_eq!(executed["status"], "executed");
    assert_eq!(rbac.mapping_count(), 1);

    let direct_revoke = json!({
        "action_type": "rbac.assignment.revoke",
        "params": { "id": assignment_id },
        "justification": "remove the direct reader grant"
    });
    let id = propose_as(&app, &direct_revoke, "alice").await;
    let executed = approve_as(&app, &id, "bob").await;
    assert_eq!(executed["status"], "executed");
    assert_eq!(rbac.assignment_count(), 0);

    let group_revoke = json!({
        "action_type": "rbac.group_mapping.revoke",
        "params": { "group_id": group_id, "role_id": role_id },
        "justification": "remove the support-group reader grant"
    });
    let id = propose_as(&app, &group_revoke, "alice").await;
    let executed = approve_as(&app, &id, "bob").await;
    assert_eq!(executed["status"], "executed");
    assert_eq!(rbac.mapping_count(), 0);
}

#[tokio::test]
async fn local_group_cannot_receive_an_rbac_role_mapping() {
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x6018);
    let group_id = Uuid::from_u128(0x6019);
    let rbac = Arc::new(FakeRbacStore::seeded(Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "operators".into(),
        description: None,
        scopes: vec!["mcp:admin".into()],
        created_at: now,
        updated_at: now,
    }));
    let groups = Arc::new(FakeGroupStore {
        rows: Mutex::new(vec![GroupView {
            id: group_id,
            tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
            display_name: "api-key-operators".into(),
            source: "local".into(),
            external_id: None,
            created_at: now,
            updated_at: now,
            user_member_count: 0,
            key_member_count: 1,
            role_mapping_count: 0,
        }]),
    });
    let app = api_router(
        state_with_rbac_and_groups(
            Some(mem_store()),
            rbac.clone() as Arc<dyn RbacStore>,
            groups,
        )
        .await,
    );
    let proposal = json!({
        "action_type": "rbac.group_mapping.grant_privileged",
        "params": { "group_id": group_id, "role_id": role_id },
        "justification": "attempt to map an API-key catalog group to a privileged role"
    });
    let response = app
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &proposal,
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(rbac.mapping_count(), 0);
}

#[tokio::test]
async fn privileged_membership_requires_the_protected_action_and_stale_witness_refuses_write() {
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x6012);
    let role = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "operators".into(),
        description: None,
        scopes: vec!["mcp:read".into(), "mcp:admin".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(role));
    let changes = Arc::new(InMemoryChangeRequestStore::new());
    let app = api_router(
        state_with_rbac(
            Some(changes.clone() as SharedChangeRequestStore),
            rbac.clone() as Arc<dyn RbacStore>,
        )
        .await,
    );

    let ordinary = json!({
        "action_type": "rbac.assignment.grant",
        "params": { "role_id": role_id, "subject_sub": "user-7" },
        "justification": "attempt an under-classified operator grant"
    });
    let response = app
        .clone()
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &ordinary,
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(rbac.assignment_count(), 0);

    let privileged = json!({
        "action_type": "rbac.assignment.grant_privileged",
        "params": { "role_id": role_id, "subject_sub": "user-7" },
        "justification": "grant the operator role under the protected bar"
    });
    let id = propose_as(&app, &privileged, "alice").await;
    let request_id = Uuid::parse_str(&id).unwrap();
    let captured = changes
        .get(waygate_core::TenantId::default().as_str(), request_id)
        .await
        .unwrap()
        .expect("privileged proposal stored");
    assert!(captured.requirement().factors.is_empty());
    assert_eq!(captured.requirement().cooldown_seconds, Some(300));
    assert!(
        captured.target_etag.is_some(),
        "role witness must be frozen"
    );

    let executor = registry()
        .get("rbac.assignment.grant_privileged")
        .expect("privileged assignment executor");
    let actor = principal_with_sub("bob", &["mcp:admin"]);
    let params = privileged["params"].clone();
    executor
        .execute_with_target_etag(
            &state_with_rbac(None, rbac.clone() as Arc<dyn RbacStore>).await,
            waygate_core::TenantId::default().as_str(),
            &actor,
            &params,
            captured.target_etag.as_deref(),
        )
        .await
        .expect("current privileged witness executes");
    assert_eq!(rbac.assignment_count(), 1);

    let stale_token = executor
        .capture_etag(
            &state_with_rbac(None, rbac.clone() as Arc<dyn RbacStore>).await,
            waygate_core::TenantId::default().as_str(),
            &actor,
            &params,
        )
        .await
        .unwrap()
        .expect("capture current role witness");
    rbac.update_role(
        waygate_core::TenantId::default().as_str(),
        role_id,
        "operators",
        Some("changed after review"),
        &["mcp:read".into(), "mcp:admin".into()],
    )
    .await
    .unwrap();
    let stale_params = json!({ "role_id": role_id, "subject_sub": "user-8" });
    let error = executor
        .execute_with_target_etag(
            &state_with_rbac(None, rbac.clone() as Arc<dyn RbacStore>).await,
            waygate_core::TenantId::default().as_str(),
            &actor,
            &stale_params,
            Some(&stale_token),
        )
        .await
        .expect_err("stale role witness must refuse the grant");
    assert!(matches!(error, ExecError::Precondition(_)));
    assert_eq!(
        rbac.assignment_count(),
        1,
        "stale reviewed role version must not grant a second assignment",
    );
}

#[tokio::test]
async fn approve_executes_rbac_role_update() {
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x6004);
    let seed = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "triage".into(),
        description: None,
        scopes: vec!["mcp:read".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(seed));
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    let body = json!({
        "action_type": "rbac.role.update",
        "params": {
            "id": role_id,
            "name": "triage",
            "scopes": ["mcp:read", "mcp:invoke"]
        },
        "justification": "grant triage the baseline invoke scope"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        rbac.get_by_id(role_id).unwrap().scopes,
        vec!["mcp:read".to_string(), "mcp:invoke".to_string()],
        "role scopes replaced in the store"
    );
}

#[tokio::test]
async fn rbac_role_update_stale_target_fails_closed() {
    // Freshness guard: a maker proposes a role-scope update; an operator
    // edits the SAME role out-of-band during the pending window; on approve the
    // guard re-captures the (now-changed) target etag, sees it differs from the
    // propose-time token, and refuses (409 -> durably failed) rather than
    // clobbering the operator's edit. update_role_core does an unconditional
    // UPDATE ... WHERE id, so without the guard the maker's stale [read, invoke]
    // would silently overwrite the operator's [read, scim:read].
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x9001);
    let seed = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "triage".into(),
        description: None,
        scopes: vec!["mcp:read".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(seed));
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    let body = json!({
        "action_type": "rbac.role.update",
        "params": {
            "id": role_id,
            "name": "triage",
            "scopes": ["mcp:read", "mcp:invoke"]
        },
        "justification": "add invoke to triage"
    });
    let id = propose_as(&app, &body, "alice").await;
    // Out-of-band edit during the pending window: an operator changes the role's
    // scopes to something else entirely (a different privilege set).
    rbac.update_role(
        waygate_core::TenantId::default().as_str(),
        role_id,
        "triage",
        None,
        &["mcp:read".to_string(), "scim:read".to_string()],
    )
    .await
    .unwrap();
    // Approve: the guard must refuse — the target moved since propose.
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    // The operator's out-of-band edit is preserved — the stale approved write
    // did NOT clobber it back to the proposed [mcp:read, mcp:invoke].
    assert_eq!(
        rbac.get_by_id(role_id).unwrap().scopes,
        vec!["mcp:read".to_string(), "scim:read".to_string()],
        "the out-of-band edit must survive; the stale write must not clobber it"
    );
    // And the maker sees the change durably `failed`.
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "failed");
}

#[tokio::test]
async fn rbac_role_update_stale_description_fails_closed() {
    // The freshness token must cover EVERY field the update
    // replaces. rbac.role.update is a full replacement of name + description +
    // scopes, so a description-only out-of-band edit must be caught — otherwise
    // the approved stale update (which here omits description, clearing it)
    // silently clobbers the operator's note. This pins the token to include
    // description; without that field in the hash this test fails (the etag
    // matches and the clobber goes through).
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x9002);
    let seed = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "triage".into(),
        description: Some("original".into()),
        scopes: vec!["mcp:read".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(seed));
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    // The proposed update omits description (would clear it) and leaves scopes
    // as-is — so only a description-sensitive token can catch the race below.
    let body = json!({
        "action_type": "rbac.role.update",
        "params": { "id": role_id, "name": "triage", "scopes": ["mcp:read"] },
        "justification": "rename note"
    });
    let id = propose_as(&app, &body, "alice").await;
    // Out-of-band: operator edits ONLY the description (name + scopes unchanged).
    rbac.update_role(
        waygate_core::TenantId::default().as_str(),
        role_id,
        "triage",
        Some("operator's important note"),
        &["mcp:read".to_string()],
    )
    .await
    .unwrap();
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    // The operator's description survives — the stale update did not clear it.
    assert_eq!(
        rbac.get_by_id(role_id).unwrap().description,
        Some("operator's important note".to_string()),
        "a description-only out-of-band edit must shift the token and be caught"
    );
}

#[tokio::test]
async fn approve_executes_rbac_role_delete() {
    // A maker proposes the delete, an eligible operator approves,
    // and the role is gone from the store. The non-secret result confirms
    // the id.
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x6007);
    let seed = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "obsolete".into(),
        description: None,
        scopes: vec!["mcp:read".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(seed));
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    let body = json!({
        "action_type": "rbac.role.delete",
        "params": { "id": role_id },
        "justification": "retire the obsolete role"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert!(
        v["execution_result"]["deleted"].as_bool().unwrap(),
        "result confirms deletion"
    );
    assert!(
        rbac.get_by_id(role_id).is_none(),
        "role removed from the store"
    );
    assert_eq!(rbac.count(), 0);
}

#[tokio::test]
async fn rbac_role_delete_missing_target_fails_closed() {
    // The target role disappeared between propose and approve (or never
    // existed). delete_role_core returns Ok(false); the executor maps that to a
    // precondition failure (-> 409 Conflict) so the change is durably `failed` —
    // never a phantom "executed" for a delete that deleted nothing.
    let rbac = Arc::new(FakeRbacStore::new());
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    let body = json!({
        "action_type": "rbac.role.delete",
        "params": { "id": Uuid::from_u128(0x6008) },
        "justification": "delete a role that isn't there"
    });
    let id = propose_as(&app, &body, "alice").await;
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    // The maker sees the change durably `failed`.
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "failed");
}

#[tokio::test]
async fn rbac_role_delete_refuses_control_plane_role() {
    // A role carrying a control-plane scope
    // (mcp:admin / mcp:propose / scim:write) defines the approver / maker /
    // provisioning set, so DELETING it is a protected approver-set change — not
    // agent-proposable, the same doctrine that bars granting those scopes via
    // create/update. It must fail at execute (before the delete), the role must
    // remain, and the change must be durably `failed`. No maker can drop an
    // approver/maker/provisioning role through one approval of an
    // innocuous-looking delete.
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x6009);
    let seed = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "operators".into(),
        description: None,
        scopes: vec!["mcp:read".into(), "mcp:admin".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(seed));
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    let body = json!({
        "action_type": "rbac.role.delete",
        "params": { "id": role_id },
        "justification": "quietly drop the operators role"
    });
    let id = propose_as(&app, &body, "alice").await;
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // The role is untouched — no approver-set change persisted.
    assert!(
        rbac.get_by_id(role_id).is_some(),
        "the control-plane role must not be deleted"
    );
    // The maker sees the change durably `failed`.
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "failed");
}

#[derive(Default)]
struct FakeGroupStore {
    rows: Mutex<Vec<GroupView>>,
}

impl FakeGroupStore {
    fn get(&self, tenant_id: &str, display_name: &str) -> Option<GroupView> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.tenant_id == tenant_id && row.display_name == display_name)
            .cloned()
    }
}

#[async_trait]
impl GroupStore for FakeGroupStore {
    async fn list_with_usage(&self, tenant_id: &str) -> Result<Vec<GroupView>, GroupStoreError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn delete_all_local_for_tenant(&self, tenant_id: &str) -> Result<u64, GroupStoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| row.tenant_id != tenant_id || row.source != "local");
        Ok((before - rows.len()) as u64)
    }

    async fn create_local(
        &self,
        tenant_id: &str,
        display_name: &str,
    ) -> Result<(), GroupStoreError> {
        let mut rows = self.rows.lock().unwrap();
        if rows
            .iter()
            .any(|row| row.tenant_id == tenant_id && row.display_name == display_name)
        {
            return Err(GroupStoreError::Conflict(display_name.to_owned()));
        }
        rows.push(GroupView {
            id: Uuid::now_v7(),
            tenant_id: tenant_id.to_owned(),
            display_name: display_name.to_owned(),
            source: "local".into(),
            external_id: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            user_member_count: 0,
            key_member_count: 0,
            role_mapping_count: 0,
        });
        Ok(())
    }

    async fn get_local_delete_target(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<waygate_apikeys::LocalGroupDeleteTarget, GroupStoreError> {
        let row = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.tenant_id == tenant_id && row.id == id)
            .cloned()
            .ok_or(GroupStoreError::NotFound(id))?;
        if row.source != "local" {
            return Err(GroupStoreError::NotLocal(id));
        }
        Ok(waygate_apikeys::LocalGroupDeleteTarget {
            id: row.id,
            display_name: row.display_name,
            updated_at: row.updated_at,
            user_member_count: row.user_member_count,
            key_member_count: row.key_member_count,
            role_mapping_count: row.role_mapping_count,
        })
    }

    async fn delete_local_if_unchanged(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_display_name: &str,
        expected_updated_at: OffsetDateTime,
    ) -> Result<(), GroupStoreError> {
        let mut rows = self.rows.lock().unwrap();
        let index = rows
            .iter()
            .position(|row| row.tenant_id == tenant_id && row.id == id)
            .ok_or(GroupStoreError::NotFound(id))?;
        let row = &rows[index];
        if row.source != "local" {
            return Err(GroupStoreError::NotLocal(id));
        }
        if row.display_name != expected_display_name || row.updated_at != expected_updated_at {
            return Err(GroupStoreError::Changed(id));
        }
        if row.user_member_count != 0 || row.key_member_count != 0 || row.role_mapping_count != 0 {
            return Err(GroupStoreError::InUse {
                user_members: row.user_member_count,
                key_members: row.key_member_count,
                role_mappings: row.role_mapping_count,
            });
        }
        rows.remove(index);
        Ok(())
    }

    async fn unknown_groups(
        &self,
        tenant_id: &str,
        names: &[String],
    ) -> Result<Vec<String>, GroupStoreError> {
        let rows = self.rows.lock().unwrap();
        Ok(names
            .iter()
            .filter(|name| {
                !rows
                    .iter()
                    .any(|row| row.tenant_id == tenant_id && row.display_name == name.as_str())
            })
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct FakeScopeStore {
    rows: Mutex<Vec<ScopeView>>,
}

impl FakeScopeStore {
    fn get(&self, tenant_id: &str, name: &str) -> Option<ScopeView> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.tenant_id.as_deref() == Some(tenant_id) && row.name == name)
            .cloned()
    }
}

#[async_trait]
impl ScopeStore for FakeScopeStore {
    async fn list_with_usage(&self, tenant_id: &str) -> Result<Vec<ScopeView>, ScopeStoreError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.tenant_id.is_none() || row.tenant_id.as_deref() == Some(tenant_id))
            .cloned()
            .collect())
    }

    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, ScopeStoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| row.tenant_id.as_deref() != Some(tenant_id));
        Ok((before - rows.len()) as u64)
    }

    async fn upsert_policy_scopes(&self, names: &[String]) -> Result<u64, ScopeStoreError> {
        let mut rows = self.rows.lock().unwrap();
        let mut inserted = 0;
        for name in names {
            if rows
                .iter()
                .any(|row| row.tenant_id.is_none() && row.name == *name)
            {
                continue;
            }
            let now = OffsetDateTime::now_utc();
            rows.push(ScopeView {
                id: Uuid::now_v7(),
                tenant_id: None,
                name: name.clone(),
                source: "policy".into(),
                description: None,
                created_at: now,
                updated_at: now,
                key_refs: 0,
                role_refs: 0,
            });
            inserted += 1;
        }
        Ok(inserted)
    }

    async fn create_local(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), ScopeStoreError> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|row| {
            row.name == name
                && (row.tenant_id.is_none() || row.tenant_id.as_deref() == Some(tenant_id))
        }) {
            return Err(ScopeStoreError::Conflict(name.to_owned()));
        }
        let now = OffsetDateTime::now_utc();
        rows.push(ScopeView {
            id: Uuid::now_v7(),
            tenant_id: Some(tenant_id.to_owned()),
            name: name.to_owned(),
            source: "local".into(),
            description: description.map(str::to_owned),
            created_at: now,
            updated_at: now,
            key_refs: 0,
            role_refs: 0,
        });
        Ok(())
    }

    async fn get_local_delete_target(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<waygate_apikeys::LocalScopeDeleteTarget, ScopeStoreError> {
        let row = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| {
                row.id == id
                    && (row.tenant_id.is_none() || row.tenant_id.as_deref() == Some(tenant_id))
            })
            .cloned()
            .ok_or(ScopeStoreError::NotFound(id))?;
        if row.tenant_id.as_deref() != Some(tenant_id) || row.source != "local" {
            return Err(ScopeStoreError::NotLocal(id));
        }
        Ok(waygate_apikeys::LocalScopeDeleteTarget {
            id: row.id,
            name: row.name,
            updated_at: row.updated_at,
            key_refs: row.key_refs,
            role_refs: row.role_refs,
        })
    }

    async fn delete_local_if_unchanged(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_name: &str,
        expected_updated_at: OffsetDateTime,
    ) -> Result<(), ScopeStoreError> {
        let mut rows = self.rows.lock().unwrap();
        let index = rows
            .iter()
            .position(|row| {
                row.id == id
                    && (row.tenant_id.is_none() || row.tenant_id.as_deref() == Some(tenant_id))
            })
            .ok_or(ScopeStoreError::NotFound(id))?;
        let row = &rows[index];
        if row.tenant_id.as_deref() != Some(tenant_id) || row.source != "local" {
            return Err(ScopeStoreError::NotLocal(id));
        }
        if row.name != expected_name || row.updated_at != expected_updated_at {
            return Err(ScopeStoreError::Changed(id));
        }
        if row.key_refs != 0 || row.role_refs != 0 {
            return Err(ScopeStoreError::InUse {
                key_refs: row.key_refs,
                role_refs: row.role_refs,
            });
        }
        rows.remove(index);
        Ok(())
    }

    async fn unknown_scopes(
        &self,
        tenant_id: &str,
        names: &[String],
    ) -> Result<Vec<String>, ScopeStoreError> {
        let rows = self.rows.lock().unwrap();
        Ok(names
            .iter()
            .filter(|name| {
                !rows.iter().any(|row| {
                    row.name == name.as_str()
                        && (row.tenant_id.is_none() || row.tenant_id.as_deref() == Some(tenant_id))
                })
            })
            .cloned()
            .collect())
    }
}

#[tokio::test]
async fn approve_executes_local_group_and_scope_lifecycle() {
    let groups = Arc::new(FakeGroupStore::default());
    let scopes = Arc::new(FakeScopeStore::default());
    let tenant = waygate_core::TenantId::default();
    let app = api_router(
        state_with_local_catalog(Some(mem_store()), groups.clone(), scopes.clone()).await,
    );

    let group_id = propose_as(
        &app,
        &json!({
            "action_type": "group.create_local",
            "params": { "display_name": "  incident-responders  " },
            "justification": "register the responder group before assigning access"
        }),
        "alice",
    )
    .await;
    let group_result = approve_as(&app, &group_id, "bob").await;
    assert_eq!(group_result["status"], "executed");
    assert_eq!(
        group_result["execution_result"]["display_name"],
        "incident-responders"
    );
    let group = groups
        .get(tenant.as_str(), "incident-responders")
        .expect("approved change creates normalized local group");
    assert_eq!(group.source, "local");

    let group_delete_id = propose_as(
        &app,
        &json!({
            "action_type": "group.delete_local",
            "params": {
                "group_id": group.id,
                "display_name": group.display_name
            },
            "justification": "retire the unused responder group"
        }),
        "alice",
    )
    .await;
    let group_deleted = approve_as(&app, &group_delete_id, "bob").await;
    assert_eq!(group_deleted["status"], "executed");
    assert_eq!(group_deleted["execution_result"]["removed"], true);
    assert!(
        groups.get(tenant.as_str(), "incident-responders").is_none(),
        "approved change deletes the reviewed local group"
    );

    let scope_id = propose_as(
        &app,
        &json!({
            "action_type": "scope.create_local",
            "params": {
                "name": "  example-security:triage  ",
                "description": "  Read synthetic security findings  "
            },
            "justification": "register the policy scope before granting it"
        }),
        "alice",
    )
    .await;
    let scope_result = approve_as(&app, &scope_id, "bob").await;
    assert_eq!(scope_result["status"], "executed");
    assert_eq!(
        scope_result["execution_result"]["name"],
        "example-security:triage"
    );
    let scope = scopes
        .get(tenant.as_str(), "example-security:triage")
        .expect("approved change creates normalized local scope");
    assert_eq!(scope.source, "local");
    assert_eq!(
        scope.description.as_deref(),
        Some("Read synthetic security findings")
    );

    let scope_delete_id = propose_as(
        &app,
        &json!({
            "action_type": "scope.delete_local",
            "params": {
                "scope_id": scope.id,
                "name": scope.name
            },
            "justification": "retire the unused synthetic security scope"
        }),
        "alice",
    )
    .await;
    let scope_deleted = approve_as(&app, &scope_delete_id, "bob").await;
    assert_eq!(scope_deleted["status"], "executed");
    assert_eq!(scope_deleted["execution_result"]["removed"], true);
    assert!(
        scopes
            .get(tenant.as_str(), "example-security:triage")
            .is_none(),
        "approved change deletes the reviewed local scope"
    );
}

#[tokio::test]
async fn local_catalog_deletion_refuses_referenced_and_stale_targets() {
    let tenant = waygate_core::TenantId::default();
    let now = OffsetDateTime::now_utc();
    let group_id = Uuid::from_u128(0x6201);
    let scope_id = Uuid::from_u128(0x6202);
    let referenced_scope_id = Uuid::from_u128(0x6203);
    let groups = Arc::new(FakeGroupStore {
        rows: Mutex::new(vec![GroupView {
            id: group_id,
            tenant_id: tenant.as_str().to_owned(),
            display_name: "active-responders".into(),
            source: "local".into(),
            external_id: None,
            created_at: now,
            updated_at: now,
            user_member_count: 0,
            key_member_count: 1,
            role_mapping_count: 0,
        }]),
    });
    let scopes = Arc::new(FakeScopeStore {
        rows: Mutex::new(vec![
            ScopeView {
                id: scope_id,
                tenant_id: Some(tenant.as_str().to_owned()),
                name: "example-security:triage".into(),
                source: "local".into(),
                description: None,
                created_at: now,
                updated_at: now,
                key_refs: 0,
                role_refs: 0,
            },
            ScopeView {
                id: referenced_scope_id,
                tenant_id: Some(tenant.as_str().to_owned()),
                name: "example-security:active".into(),
                source: "local".into(),
                description: None,
                created_at: now,
                updated_at: now,
                key_refs: 1,
                role_refs: 0,
            },
        ]),
    });
    let app = api_router(
        state_with_local_catalog(Some(mem_store()), groups.clone(), scopes.clone()).await,
    );

    let referenced = app
        .clone()
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &json!({
                "action_type": "group.delete_local",
                "params": {
                    "group_id": group_id,
                    "display_name": "active-responders"
                },
                "justification": "retire the group"
            }),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(referenced.status(), StatusCode::BAD_REQUEST);
    assert!(
        groups.get(tenant.as_str(), "active-responders").is_some(),
        "a referenced local group must remain intact"
    );

    let referenced_scope = app
        .clone()
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &json!({
                "action_type": "scope.delete_local",
                "params": {
                    "scope_id": referenced_scope_id,
                    "name": "example-security:active"
                },
                "justification": "retire the scope"
            }),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(referenced_scope.status(), StatusCode::BAD_REQUEST);
    assert!(
        scopes
            .get(tenant.as_str(), "example-security:active")
            .is_some(),
        "a scope referenced only by a live key must remain intact"
    );

    let stale_id = propose_as(
        &app,
        &json!({
            "action_type": "scope.delete_local",
            "params": { "scope_id": scope_id, "name": "example-security:triage" },
            "justification": "retire the unused scope"
        }),
        "alice",
    )
    .await;
    scopes
        .rows
        .lock()
        .unwrap()
        .iter_mut()
        .find(|row| row.id == scope_id)
        .expect("seeded scope")
        .updated_at += time::Duration::seconds(1);

    let stale = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{stale_id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert!(
        scopes
            .get(tenant.as_str(), "example-security:triage")
            .is_some(),
        "an out-of-band scope edit must survive stale approval"
    );
}

#[tokio::test]
async fn approve_executes_agent_config_lifecycle_and_refuses_a_stale_update() {
    let agent_store = Arc::new(InMemoryAgentConfigStore::new());
    let tenant = waygate_core::TenantId::default();
    let app = api_router(
        state_with_agent_configs(
            Some(mem_store()),
            agent_store.clone() as Arc<dyn AgentConfigStore>,
        )
        .await,
    );

    let create_id = propose_as(
        &app,
        &json!({
            "action_type": "agent_config.create",
            "params": {
                "name": "triage",
                "kind": "classification",
                "model_alias": "reasoning-default",
                "instructions": "Summarize security findings.",
                "allowed_tools": ["gateway-observe.query_audit", "example-security.list_alerts"],
                "max_steps": 6,
                "max_tool_calls": 12,
                "token_budget": 4000,
                "enabled": false
            },
            "justification": "create a bounded security-triage agent"
        }),
        "alice",
    )
    .await;
    let created = approve_as(&app, &create_id, "bob").await;
    assert_eq!(created["status"], "executed");
    let create_result = created["execution_result"]
        .as_object()
        .expect("structured creation result");
    assert_eq!(create_result.len(), 2, "history result stays bounded");
    assert!(create_result.contains_key("agent_id"));
    assert!(create_result.contains_key("updated_at"));
    let agent_id = Uuid::parse_str(
        created["execution_result"]["agent_id"]
            .as_str()
            .expect("agent id result"),
    )
    .expect("valid agent id");
    assert_eq!(
        agent_store
            .get(tenant.as_str(), agent_id)
            .await
            .expect("get created")
            .expect("created config")
            .allowed_tools,
        [
            "gateway-observe.query_audit",
            "example-security.list_alerts"
        ]
    );

    let stale_update_id = propose_as(
        &app,
        &json!({
            "action_type": "agent_config.update",
            "params": {
                "agent_id": agent_id,
                "config": {
                    "name": "triage",
                    "kind": "classification",
                    "model_alias": "maker-choice",
                    "allowed_tools": ["example-security.list_alerts"],
                    "max_steps": 4,
                    "max_tool_calls": 8,
                    "enabled": true
                }
            },
            "justification": "enable the reviewed triage configuration"
        }),
        "alice",
    )
    .await;

    let operator_tools = vec!["gateway-observe.query_audit".to_owned()];
    agent_store
        .update(
            tenant.as_str(),
            agent_id,
            AgentConfigFields {
                name: "triage",
                kind: AgentKind::Classification,
                model_alias: "operator-edit",
                instructions: Some("Preserve this newer operator change."),
                allowed_tools: &operator_tools,
                max_steps: 3,
                max_tool_calls: 5,
                token_budget: Some(2_000),
                enabled: false,
            },
        )
        .await
        .expect("out-of-band update")
        .expect("target exists");

    let stale_response = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{stale_update_id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .expect("approve stale update");
    assert_eq!(stale_response.status(), StatusCode::CONFLICT);
    let after_stale = agent_store
        .get(tenant.as_str(), agent_id)
        .await
        .expect("get after stale")
        .expect("still present");
    assert_eq!(after_stale.model_alias, "operator-edit");
    assert_eq!(after_stale.allowed_tools, operator_tools);

    let poll = body_json(
        app.clone()
            .oneshot(get_req(
                &format!("/api/v1/admin/change_requests/{stale_update_id}"),
                "alice",
                &["mcp:propose"],
            ))
            .await
            .expect("poll stale update"),
    )
    .await;
    assert_eq!(poll["status"], "failed");

    let current_update_id = propose_as(
        &app,
        &json!({
            "action_type": "agent_config.update",
            "params": {
                "agent_id": agent_id,
                "config": {
                    "name": "triage",
                    "kind": "classification",
                    "model_alias": "reviewed-choice",
                    "instructions": "Use the reviewed allowlist only.",
                    "allowed_tools": ["gateway-observe.query_audit"],
                    "max_steps": 4,
                    "max_tool_calls": 6,
                    "token_budget": 2500,
                    "enabled": true
                }
            },
            "justification": "apply the current reviewed triage configuration"
        }),
        "alice",
    )
    .await;
    let updated = approve_as(&app, &current_update_id, "bob").await;
    assert_eq!(updated["status"], "executed");
    let stored_update = agent_store
        .get(tenant.as_str(), agent_id)
        .await
        .expect("get updated")
        .expect("updated config");
    assert_eq!(stored_update.model_alias, "reviewed-choice");
    assert_eq!(
        stored_update.allowed_tools,
        vec!["gateway-observe.query_audit".to_owned()]
    );
    assert!(stored_update.enabled);

    let delete_id = propose_as(
        &app,
        &json!({
            "action_type": "agent_config.delete",
            "params": { "agent_id": agent_id },
            "justification": "remove the retired triage agent"
        }),
        "alice",
    )
    .await;
    let deleted = approve_as(&app, &delete_id, "bob").await;
    assert_eq!(deleted["status"], "executed");
    assert_eq!(deleted["execution_result"]["removed"], true);
    assert!(agent_store
        .get(tenant.as_str(), agent_id)
        .await
        .expect("get deleted")
        .is_none());
}

#[tokio::test]
async fn approve_executes_api_key_profile_lifecycle_and_observe_is_tenant_scoped() {
    let profiles = Arc::new(InMemoryProfileStore::default());
    profiles.seed_profile("other", "foreign-profile");
    let state =
        state_with_api_key_profiles(Some(mem_store()), profiles.clone() as Arc<dyn ProfileStore>)
            .await;
    let app = api_router(state.clone());

    let create_id = propose_as(
        &app,
        &json!({
            "action_type": "api_key_profile.create",
            "params": {
                "name": "example-security-readonly",
                "description": "Bounded synthetic security triage",
                "max_ttl_seconds": 3600,
                "allowed_scopes": ["mcp:invoke"],
                "allowed_servers": ["example-security"],
                "allowed_tools": ["example-security.list_alerts"],
                "requires_reason": true,
                "requires_owner": true
            },
            "justification": "create a reviewable least-privilege key profile"
        }),
        "alice",
    )
    .await;
    let created = approve_as(&app, &create_id, "bob").await;
    assert_eq!(created["status"], "executed");
    let profile_id = Uuid::parse_str(
        created["execution_result"]["id"]
            .as_str()
            .expect("created profile id"),
    )
    .expect("valid profile id");
    let stored = profiles
        .snapshot()
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .expect("approved create persists profile");
    assert_eq!(stored.tenant_id, "default");
    assert_eq!(stored.allowed_scopes, ["mcp:invoke"]);
    assert_eq!(
        stored.allowed_servers,
        Some(vec!["example-security".into()])
    );
    assert_eq!(
        stored.allowed_tools,
        Some(vec!["example-security.list_alerts".into()])
    );
    assert!(stored.requires_reason && stored.requires_owner);

    let page = waygate_admin::resource_catalog::read(
        &state,
        "api_key_profile",
        "default",
        &Map::new(),
        50,
        0,
    )
    .await
    .expect("read API-key profile resource");
    assert_eq!(page.rows.len(), 1, "foreign tenant profiles stay hidden");
    assert_eq!(page.rows[0]["id"], profile_id.to_string());
    assert_eq!(
        page.rows[0]["allowed_tools"],
        json!(["example-security.list_alerts"])
    );

    let delete_id = propose_as(
        &app,
        &json!({
            "action_type": "api_key_profile.delete",
            "params": { "profile_id": profile_id },
            "justification": "retire the reviewed profile after key rotation"
        }),
        "alice",
    )
    .await;
    let deleted = approve_as(&app, &delete_id, "bob").await;
    assert_eq!(deleted["status"], "executed");
    assert_eq!(deleted["execution_result"]["removed"], true);
    assert!(profiles
        .get("default", profile_id)
        .await
        .expect("get deleted profile")
        .is_none());
}

#[tokio::test]
async fn api_key_profile_delete_refuses_stale_referenced_or_foreign_targets() {
    let profiles = Arc::new(InMemoryProfileStore::default());
    let profile_id = profiles.seed_profile("default", "retiring");
    let foreign_id = profiles.seed_profile("other", "foreign");
    let state =
        state_with_api_key_profiles(Some(mem_store()), profiles.clone() as Arc<dyn ProfileStore>)
            .await;
    let app = api_router(state);

    let delete_id = propose_as(
        &app,
        &json!({
            "action_type": "api_key_profile.delete",
            "params": { "profile_id": profile_id },
            "justification": "remove the retired profile"
        }),
        "alice",
    )
    .await;
    assert!(profiles
        .delete("default", profile_id)
        .await
        .expect("out-of-band delete"));

    let stale = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{delete_id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .expect("approve stale profile delete");
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let poll = body_json(
        app.clone()
            .oneshot(get_req(
                &format!("/api/v1/admin/change_requests/{delete_id}"),
                "alice",
                &["mcp:propose"],
            ))
            .await
            .expect("poll stale profile delete"),
    )
    .await;
    assert_eq!(poll["status"], "failed");

    let final_window_id = profiles.seed_profile("default", "final-window");
    let final_window_delete_id = propose_as(
        &app,
        &json!({
            "action_type": "api_key_profile.delete",
            "params": { "profile_id": final_window_id },
            "justification": "delete only the exact reviewed profile version"
        }),
        "alice",
    )
    .await;
    profiles.advance_before_conditional_delete();
    let final_window = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{final_window_delete_id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .expect("approve final-window profile delete");
    assert_eq!(final_window.status(), StatusCode::CONFLICT);
    assert_eq!(
        profiles
            .get("default", final_window_id)
            .await
            .expect("get final-window profile")
            .expect("newer profile version is preserved")
            .updated_at,
        OffsetDateTime::UNIX_EPOCH + Duration::SECOND,
    );

    let referenced_id = profiles.seed_profile("default", "in-use");
    profiles.set_delete_block(Some(2));
    let referenced_delete_id = propose_as(
        &app,
        &json!({
            "action_type": "api_key_profile.delete",
            "params": { "profile_id": referenced_id },
            "justification": "remove only after live keys have rotated"
        }),
        "alice",
    )
    .await;
    let referenced = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{referenced_delete_id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .expect("approve referenced profile delete");
    assert_eq!(referenced.status(), StatusCode::CONFLICT);
    assert!(profiles
        .get("default", referenced_id)
        .await
        .expect("get referenced profile")
        .is_some());
    profiles.set_delete_block(None);

    let foreign = app
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &json!({
                "action_type": "api_key_profile.delete",
                "params": { "profile_id": foreign_id },
                "justification": "must not reach another tenant"
            }),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .expect("propose foreign profile delete");
    assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);
    assert!(profiles
        .get("other", foreign_id)
        .await
        .expect("get foreign profile")
        .is_some());
}

/// In-memory `RetentionStore` for the audit-config freshness regression. Only
/// `list` / `upsert` / `delete` are on this path (what `set_retention_core`,
/// `clear_retention_core`, and the `retention_row_etag` freshness helper reach).
struct FakeRetentionStore {
    rows: Mutex<Vec<RetentionPolicy>>,
}

impl FakeRetentionStore {
    fn empty() -> Self {
        Self {
            rows: Mutex::new(vec![]),
        }
    }

    fn get(&self, tenant_id: &str, category: &str) -> Option<RetentionPolicy> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.category == category)
            .cloned()
    }
}

#[async_trait]
impl RetentionStore for FakeRetentionStore {
    async fn list(&self, tenant_id: Option<&str>) -> Result<Vec<RetentionPolicy>, sqlx::Error> {
        let g = self.rows.lock().unwrap();
        Ok(match tenant_id {
            Some(t) => g.iter().filter(|r| r.tenant_id == t).cloned().collect(),
            None => g.clone(),
        })
    }

    async fn upsert(
        &self,
        tenant_id: &str,
        category: &str,
        delete_after_days: i32,
    ) -> Result<RetentionPolicy, sqlx::Error> {
        let mut g = self.rows.lock().unwrap();
        let now = OffsetDateTime::now_utc();
        if let Some(r) = g
            .iter_mut()
            .find(|r| r.tenant_id == tenant_id && r.category == category)
        {
            r.delete_after_days = delete_after_days;
            r.updated_at = now;
            return Ok(r.clone());
        }
        let row = RetentionPolicy {
            tenant_id: tenant_id.to_owned(),
            category: category.to_owned(),
            delete_after_days,
            created_at: now,
            updated_at: now,
        };
        g.push(row.clone());
        Ok(row)
    }

    async fn delete(&self, tenant_id: &str, category: &str) -> Result<bool, sqlx::Error> {
        let mut g = self.rows.lock().unwrap();
        let before = g.len();
        g.retain(|r| !(r.tenant_id == tenant_id && r.category == category));
        Ok(g.len() != before)
    }
}

async fn state_with_retention(
    cr: Option<SharedChangeRequestStore>,
    retention: Arc<dyn RetentionStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_retention_store(Some(retention)),
    )
}

#[tokio::test]
async fn audit_retention_set_stale_absent_target_fails_closed() {
    // A maker proposes `audit.retention.set` for a
    // category that has NO policy row yet; an operator creates that
    // `(tenant, category)` row out-of-band during the pending window; on approve
    // the freshness guard MUST refuse rather than overwrite the operator's new
    // row. The pinned bug: `capture_etag` returned `None` for an absent row, and
    // `execute_approved` only rechecks a `Some` token, so an absent-at-propose
    // proposal was unguarded and the stale set clobbered the new row. The fix
    // captures a `{present:false}` sentinel (always `Some`), so an absent→present
    // transition mismatches and fails closed. Against the old code this test
    // would see the set succeed and the row overwritten to 90.
    let tenant = waygate_core::TenantId::default();
    let retention = Arc::new(FakeRetentionStore::empty());
    let app = api_router(
        state_with_retention(
            Some(mem_store()),
            retention.clone() as Arc<dyn RetentionStore>,
        )
        .await,
    );
    let body = json!({
        "action_type": "audit.retention.set",
        "params": { "category": "invocation", "delete_after_days": 90 },
        "justification": "set invocation retention to 90d"
    });
    let id = propose_as(&app, &body, "alice").await;
    // Out-of-band: an operator creates the row the maker assumed was absent.
    retention
        .upsert(tenant.as_str(), "invocation", 30)
        .await
        .unwrap();
    // Approve: the guard must refuse — the target went absent -> present.
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "an absent-at-propose row created before approval must fail closed, not clobber"
    );
    // The operator's row survives unchanged (NOT overwritten to 90).
    assert_eq!(
        retention
            .get(tenant.as_str(), "invocation")
            .unwrap()
            .delete_after_days,
        30,
        "the operator's out-of-band policy must survive the stale approval"
    );
    // And the maker sees the change durably `failed`.
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "failed");
}

#[tokio::test]
async fn peer_update_result_omits_credential_bearing_urls() {
    // Input validation rejects NEW peer URLs
    // with `user:pass@host` userinfo, but a pre-existing row (older, or a
    // migration / DB-level insert) can still carry it. The maker-visible
    // execution_result must NOT echo the issuer / jwks_url, or a maker
    // proposing an unrelated change (here: only peer_name) could harvest a
    // credential it never supplied once a human approves the benign change.
    let peer_id = Uuid::from_u128(0x6005);
    let now = OffsetDateTime::now_utc();
    let credential_peer = FederatedPeer {
        id: peer_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        peer_name: "legacy-gw".into(),
        issuer: "https://alice:s3cr3t@idp.example".into(),
        jwks_url: "https://alice:s3cr3t@idp.example/jwks".into(),
        trust_tier: TrustTier::Restricted,
        created_at: now,
        updated_at: now,
    };
    let peers = Arc::new(FakeFederatedPeersStore::seeded(credential_peer));
    let app = api_router(
        state_with_peers(
            Some(mem_store()),
            peers.clone() as waygate_federation::SharedPeersStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "peer.update",
        "params": { "id": peer_id, "peer_name": "renamed-gw" },
        "justification": "promote legacy-gw to full trust"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    let result = &v["execution_result"];
    assert!(
        result.get("issuer").is_none(),
        "issuer must be omitted from the maker-visible result: {result}"
    );
    assert!(
        result.get("jwks_url").is_none(),
        "jwks_url must be omitted from the maker-visible result: {result}"
    );
    assert!(
        !result.to_string().contains("s3cr3t"),
        "no credential bytes may appear anywhere in the result: {result}"
    );
    // The non-sensitive confirmation fields are still present, and the store
    // mutation still happened.
    assert_eq!(result["peer_name"].as_str().unwrap(), "renamed-gw");
    assert_eq!(result["trust_tier"].as_str().unwrap(), "restricted");
    assert_eq!(
        peers.get_by_id(peer_id).unwrap().trust_tier,
        TrustTier::Restricted
    );
}

#[tokio::test]
async fn rbac_role_update_cannot_grant_control_plane_scopes() {
    // A role's scopes merge into every
    // assignee's Principal.scopes, which gate mcp:admin / mcp:propose. A maker
    // must not escalate by proposing a role update that adds a control-plane
    // scope — it fails at execute (before the store write), the role's scopes
    // stay put, and the change is durably `failed`. No assignee gains admin
    // from a single approval of an innocuous-looking role edit.
    let now = OffsetDateTime::now_utc();
    let role_id = Uuid::from_u128(0x6006);
    let seed = Role {
        id: role_id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        name: "triage".into(),
        description: None,
        scopes: vec!["mcp:read".into()],
        created_at: now,
        updated_at: now,
    };
    let rbac = Arc::new(FakeRbacStore::seeded(seed));
    let app =
        api_router(state_with_rbac(Some(mem_store()), rbac.clone() as Arc<dyn RbacStore>).await);
    let body = json!({
        "action_type": "rbac.role.update",
        "params": {
            "id": role_id,
            "name": "triage",
            "scopes": ["mcp:read", "mcp:admin"]
        },
        "justification": "sneak admin into the triage role"
    });
    let id = propose_as(&app, &body, "alice").await;
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // The role's scopes are unchanged — no escalation persisted.
    assert_eq!(
        rbac.get_by_id(role_id).unwrap().scopes,
        vec!["mcp:read".to_string()],
        "the privileged-scope update must not touch the role"
    );
    // The maker sees the change durably `failed`.
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "failed");
}

// ---- upstream_session.revoke ----

/// In-memory `UpstreamSessionStore` for the revoke executor test: only
/// `revoke` is real (a tenant-agnostic `(sub, upstream_issuer)` delete); the
/// ciphertext / sweeper / list surface isn't on this path.
struct FakeUpstreamSessionStore {
    sessions: Mutex<Vec<(String, String)>>,
}

impl FakeUpstreamSessionStore {
    fn seeded(sub: &str, upstream_issuer: &str) -> Self {
        Self {
            sessions: Mutex::new(vec![(sub.to_owned(), upstream_issuer.to_owned())]),
        }
    }

    fn contains(&self, sub: &str, upstream_issuer: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .any(|(s, i)| s == sub && i == upstream_issuer)
    }
}

#[async_trait]
impl UpstreamSessionStore for FakeUpstreamSessionStore {
    async fn revoke(&self, sub: &str, upstream_issuer: &str) -> Result<bool, SessionStoreError> {
        let mut g = self.sessions.lock().unwrap();
        let before = g.len();
        g.retain(|(s, i)| !(s == sub && i == upstream_issuer));
        Ok(g.len() != before)
    }

    async fn upsert(&self, _row: NewSessionRow<'_>) -> Result<(), SessionStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }

    async fn get(
        &self,
        _sub: &str,
        _upstream_issuer: &str,
    ) -> Result<Option<StoredSessionRow>, SessionStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }

    async fn revoke_if_ciphertext_matches(
        &self,
        _sub: &str,
        _upstream_issuer: &str,
        _expected_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }

    async fn update_if_ciphertext_matches(
        &self,
        _row: NewSessionRow<'_>,
        _expected_old_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }

    async fn list_off_active_key(
        &self,
        _active_id: &str,
        _decryptable_key_ids: &[String],
        _limit: u32,
    ) -> Result<Vec<OffKeyRow>, SessionStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }

    async fn list_all(
        &self,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<SessionMetadata>, SessionStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }

    async fn sweep_expired(&self, _retain: std::time::Duration) -> Result<u64, SessionStoreError> {
        unimplemented!("not exercised by the revoke executor test")
    }
}

async fn state_with_sessions(
    cr: Option<SharedChangeRequestStore>,
    sessions: waygate_as::sessions::SharedUpstreamSessionStore,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
            Some(sessions),
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_change_request_store(cr),
    )
}

#[tokio::test]
async fn approve_executes_upstream_session_revoke() {
    let sessions = Arc::new(FakeUpstreamSessionStore::seeded(
        "user-9",
        "https://idp.example",
    ));
    assert!(sessions.contains("user-9", "https://idp.example"));
    let app = api_router(
        state_with_sessions(
            Some(mem_store()),
            sessions.clone() as waygate_as::sessions::SharedUpstreamSessionStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "upstream_session.revoke",
        "params": { "sub": "user-9", "upstream_issuer": "https://idp.example" },
        "justification": "burn the compromised user's tier-a session"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert!(v["execution_result"]["removed"].as_bool().unwrap());
    assert!(
        !sessions.contains("user-9", "https://idp.example"),
        "session revoked in the store"
    );
}

// ---- break_glass.mint + break_glass.revoke ----

/// In-memory `BreakGlassStore` for the break-glass executor tests: real
/// `mint` and `delete` over a `Vec`; the hot-path claim/list surface isn't on
/// this path.
struct FakeBreakGlassStore {
    tokens: Mutex<Vec<BreakGlassToken>>,
}

impl FakeBreakGlassStore {
    fn new() -> Self {
        Self {
            tokens: Mutex::new(vec![]),
        }
    }

    fn seeded(token: BreakGlassToken) -> Self {
        Self {
            tokens: Mutex::new(vec![token]),
        }
    }

    fn count(&self) -> usize {
        self.tokens.lock().unwrap().len()
    }

    fn contains(&self, id: Uuid) -> bool {
        self.tokens.lock().unwrap().iter().any(|t| t.id == id)
    }
}

#[async_trait]
impl BreakGlassStore for FakeBreakGlassStore {
    async fn mint(&self, mint: NewBreakGlassToken<'_>) -> Result<BreakGlassToken, BreakGlassError> {
        let now = OffsetDateTime::now_utc();
        let token = BreakGlassToken {
            id: Uuid::now_v7(),
            tenant_id: mint.tenant_id.to_owned(),
            issued_to: mint.issued_to.to_owned(),
            issued_by: mint.issued_by.to_owned(),
            reason: mint.reason.to_owned(),
            scope_pattern: mint.scope_pattern.to_owned(),
            requires_amr: mint.requires_amr.to_vec(),
            expires_at: mint.expires_at,
            used_at: None,
            created_at: now,
        };
        self.tokens.lock().unwrap().push(token.clone());
        Ok(token)
    }

    async fn list(
        &self,
        _tenant_id: &str,
        _lifecycle: Option<BreakGlassLifecycle>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
        unimplemented!("not exercised by the break-glass executor tests")
    }

    async fn delete(&self, tenant_id: &str, token_id: Uuid) -> Result<bool, BreakGlassError> {
        let mut g = self.tokens.lock().unwrap();
        let before = g.len();
        g.retain(|t| !(t.tenant_id == tenant_id && t.id == token_id));
        Ok(g.len() != before)
    }

    async fn list_candidates(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _fq_tool_name: &str,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
        unimplemented!("not exercised by the break-glass executor tests")
    }

    async fn try_claim(&self, _token_id: Uuid) -> Result<Option<BreakGlassToken>, BreakGlassError> {
        unimplemented!("not exercised by the break-glass executor tests")
    }
}

async fn state_with_break_glass(
    cr: Option<SharedChangeRequestStore>,
    bg: waygate_authz::SharedBreakGlassStore,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_break_glass_store(Some(bg)),
    )
}

fn seed_token(id: Uuid) -> BreakGlassToken {
    let now = OffsetDateTime::now_utc();
    BreakGlassToken {
        id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        issued_to: "alice".into(),
        issued_by: "operator".into(),
        reason: "incident #7".into(),
        scope_pattern: "example-messages.send".into(),
        requires_amr: vec![],
        expires_at: now + Duration::hours(1),
        used_at: None,
        created_at: now,
    }
}

#[tokio::test]
async fn approve_executes_break_glass_mint() {
    let bg = Arc::new(FakeBreakGlassStore::new());
    let app = api_router(
        state_with_break_glass(
            Some(mem_store()),
            bg.clone() as waygate_authz::SharedBreakGlassStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "break_glass.mint",
        "params": {
            "issued_to": "alice",
            "reason": "incident #7: example-messages pager is down",
            "scope_pattern": "example-messages.send",
            "ttl_seconds": 900
        },
        "justification": "alice needs to page the on-call during the incident"
    });
    let id = propose_as(&app, &body, "maker").await;
    let v = approve_as(&app, &id, "operator").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        v["execution_result"]["issued_to"].as_str().unwrap(),
        "alice"
    );
    assert_eq!(
        v["execution_result"]["scope_pattern"].as_str().unwrap(),
        "example-messages.send"
    );
    // The token id is surfaced (the admin's revoke handle, not a bearer secret).
    assert!(v["execution_result"]["token_id"].is_string());
    assert_eq!(bg.count(), 1, "token minted in the store");
}

#[tokio::test]
async fn approve_executes_break_glass_revoke() {
    let token_id = Uuid::from_u128(0x7001);
    let bg = Arc::new(FakeBreakGlassStore::seeded(seed_token(token_id)));
    assert!(bg.contains(token_id));
    let app = api_router(
        state_with_break_glass(
            Some(mem_store()),
            bg.clone() as waygate_authz::SharedBreakGlassStore,
        )
        .await,
    );
    let body = json!({
        "action_type": "break_glass.revoke",
        "params": { "token_id": token_id },
        "justification": "the incident is resolved; burn the override early"
    });
    let id = propose_as(&app, &body, "maker").await;
    let v = approve_as(&app, &id, "operator").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert!(v["execution_result"]["removed"].as_bool().unwrap());
    assert!(!bg.contains(token_id), "token removed from the store");
}

// ---- policy publish / rollback / fragment upsert -------------------

/// State with a change-request store + a policy store, but **no** policies_dir,
/// so `mirror_then` skips the on-disk mirror and runs the ledger op directly.
/// This isolates the executor wiring (propose -> approve ->
/// publish_bundle_core/rollback_bundle_core -> ledger); the disk-mirror
/// turnstile itself is covered by policy_bundles_api.rs.
async fn state_with_policies(
    cr: Option<SharedChangeRequestStore>,
    policy: Arc<dyn PolicyStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_change_request_store(cr)
        .with_policy_store(Some(policy)),
    )
}

struct NoRowsAudit {
    write_during_query: Mutex<Option<(usize, std::path::PathBuf, String)>>,
}

impl NoRowsAudit {
    fn empty() -> Self {
        Self {
            write_during_query: Mutex::new(None),
        }
    }

    fn mutating_on_query(query_number: usize, path: std::path::PathBuf, content: String) -> Self {
        Self {
            write_during_query: Mutex::new(Some((query_number, path, content))),
        }
    }
}

#[async_trait]
impl waygate_storage::AuditReader for NoRowsAudit {
    async fn recent_notable(
        &self,
        _tenant: &str,
        _since: time::OffsetDateTime,
        _limit: i64,
    ) -> Result<Vec<waygate_storage::AuditRow>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn recent_events(
        &self,
        _limit: i64,
        _after_id: Option<Uuid>,
    ) -> Result<Vec<waygate_storage::AuditRow>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn query_events(
        &self,
        _query: &waygate_storage::AuditQuery,
        _limit: i64,
        _after_id: Option<Uuid>,
    ) -> Result<Vec<waygate_storage::AuditRow>, sqlx::Error> {
        let mutation = {
            let mut pending = self.write_during_query.lock().unwrap();
            match pending.as_mut() {
                Some((queries_before_write, _, _)) if *queries_before_write > 1 => {
                    *queries_before_write -= 1;
                    None
                }
                Some(_) => pending.take().map(|(_, path, content)| (path, content)),
                None => None,
            }
        };
        if let Some((path, content)) = mutation {
            std::fs::write(path, content).unwrap();
        }
        Ok(Vec::new())
    }

    async fn facet_counts(
        &self,
        _query: &waygate_storage::AuditQuery,
    ) -> Result<waygate_storage::AuditFacets, sqlx::Error> {
        Ok(waygate_storage::AuditFacets {
            outcome: Vec::new(),
            risk: Vec::new(),
            category: Vec::new(),
            pii: Vec::new(),
            server: Vec::new(),
        })
    }

    async fn tool_stats(
        &self,
        _query: &waygate_storage::AuditQuery,
        _limit: i64,
    ) -> Result<Vec<waygate_storage::ToolStat>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn histogram(
        &self,
        _query: &waygate_storage::AuditQuery,
        _bucket_seconds: i64,
    ) -> Result<Vec<waygate_storage::HistogramBucket>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn fetch_event(
        &self,
        _id: Uuid,
    ) -> Result<Option<waygate_storage::AuditRow>, sqlx::Error> {
        Ok(None)
    }

    async fn count_events_by_sub_since(
        &self,
        _sub: &str,
        _since: OffsetDateTime,
        _exclude_issuer: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        Ok(0)
    }

    async fn verify_chain(
        &self,
        tenant_id: &str,
        from: Option<OffsetDateTime>,
        to: Option<OffsetDateTime>,
        _after_chain_seq: Option<i64>,
        _limit: i64,
    ) -> Result<waygate_storage::ChainVerifyReport, sqlx::Error> {
        Ok(waygate_storage::ChainVerifyReport {
            tenant_id: tenant_id.to_owned(),
            from,
            to,
            rows_walked: 0,
            status: waygate_storage::ChainVerifyStatus::Empty,
            first_mismatch: None,
            truncated: false,
            next_after_chain_seq: None,
            chain_head: None,
        })
    }

    async fn fetch_events_for_bundle(
        &self,
        _tenant_id: &str,
        _from: OffsetDateTime,
        _to: OffsetDateTime,
        _principal_sub: Option<&str>,
        _tool: Option<&str>,
        _limit: i64,
    ) -> Result<(Vec<waygate_storage::AuditRow>, bool), sqlx::Error> {
        Ok((Vec::new(), false))
    }
}

struct PolicyFragmentTmpDir(std::path::PathBuf);

impl PolicyFragmentTmpDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("change-policy-fragment-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for PolicyFragmentTmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn policy_live_base(dir: &std::path::Path) -> String {
    policy_content_hash(&waygate_policy::read_policy_dir(dir).unwrap().source)
}

async fn state_with_policy_fragment_dependencies(
    cr: SharedChangeRequestStore,
    policy: Arc<dyn PolicyStore>,
    policies_dir: std::path::PathBuf,
    audit_enabled: bool,
) -> Arc<AdminState> {
    let audit = audit_enabled
        .then(|| Arc::new(NoRowsAudit::empty()) as Arc<dyn waygate_storage::AuditReader>);
    state_with_policy_fragment_audit(cr, policy, policies_dir, audit).await
}

async fn state_with_policy_fragment_audit(
    cr: SharedChangeRequestStore,
    policy: Arc<dyn PolicyStore>,
    policies_dir: std::path::PathBuf,
    audit: Option<Arc<dyn waygate_storage::AuditReader>>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    Arc::new(
        AdminState::new(
            pool,
            None,
            audit,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_change_request_store(Some(cr))
        .with_policy_store(Some(policy))
        .with_policies_dir(policies_dir),
    )
}

fn sample_policy_bundle(id: Uuid, version: i32, status: PolicyStatus) -> PolicyBundle {
    PolicyBundle {
        id,
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        version,
        status,
        content: "permit(principal, action, resource);".to_owned(),
        content_hash: format!("hash-v{version}"),
        tests: None,
        author: Some("seed".to_owned()),
        created_at: OffsetDateTime::now_utc(),
        published_at: if status == PolicyStatus::Published {
            Some(OffsetDateTime::now_utc())
        } else {
            None
        },
        published_by: None,
    }
}

struct FakePolicyStore {
    bundles: Mutex<Vec<PolicyBundle>>,
    pointer: Mutex<Option<String>>,
    after_next_cas: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl FakePolicyStore {
    fn with_bundles(bundles: Vec<PolicyBundle>) -> Self {
        Self {
            bundles: Mutex::new(bundles),
            pointer: Mutex::new(None),
            after_next_cas: Mutex::new(None),
        }
    }

    fn after_next_cas(&self, hook: impl FnOnce() + Send + 'static) {
        *self.after_next_cas.lock().unwrap() = Some(Box::new(hook));
    }

    fn get_by_id(&self, id: Uuid) -> Option<PolicyBundle> {
        self.bundles
            .lock()
            .unwrap()
            .iter()
            .find(|b| b.id == id)
            .cloned()
    }
    fn published_versions(&self) -> Vec<i32> {
        let mut v: Vec<i32> = self
            .bundles
            .lock()
            .unwrap()
            .iter()
            .filter(|b| b.status == PolicyStatus::Published)
            .map(|b| b.version)
            .collect();
        v.sort_unstable();
        v
    }

    fn bundle_count(&self) -> usize {
        self.bundles.lock().unwrap().len()
    }

    fn replace_active_content(&self, content: &str) {
        let mut bundles = self.bundles.lock().unwrap();
        let active = bundles
            .iter_mut()
            .filter(|bundle| bundle.status == PolicyStatus::Published)
            .max_by_key(|bundle| bundle.version)
            .expect("test policy store has an active bundle");
        active.content = content.to_owned();
        active.content_hash = policy_content_hash(content);
    }
}

#[async_trait]
impl PolicyStore for FakePolicyStore {
    async fn active_bundle(&self, tenant_id: &str) -> Result<PolicyBundle, PolicyError> {
        self.bundles
            .lock()
            .unwrap()
            .iter()
            .filter(|bundle| {
                bundle.tenant_id == tenant_id && bundle.status == PolicyStatus::Published
            })
            .max_by_key(|bundle| bundle.version)
            .cloned()
            .ok_or(PolicyError::NotFound("no published policy bundle"))
    }
    async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError> {
        let mut latest = std::collections::BTreeMap::<String, PolicyBundle>::new();
        for bundle in self
            .bundles
            .lock()
            .unwrap()
            .iter()
            .filter(|bundle| bundle.status == PolicyStatus::Published)
        {
            let slot = latest
                .entry(bundle.tenant_id.clone())
                .or_insert_with(|| bundle.clone());
            if bundle.version > slot.version {
                *slot = bundle.clone();
            }
        }
        Ok(latest.into_values().collect())
    }
    async fn list_bundles(&self, tenant_id: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError> {
        Ok(self
            .bundles
            .lock()
            .unwrap()
            .iter()
            .filter(|b| b.tenant_id == tenant_id)
            .map(|b| PolicyBundleSummary {
                id: b.id,
                tenant_id: b.tenant_id.clone(),
                version: b.version,
                status: b.status,
                content_hash: b.content_hash.clone(),
                author: b.author.clone(),
                created_at: b.created_at,
                published_at: b.published_at,
                published_by: b.published_by.clone(),
            })
            .collect())
    }
    async fn get(&self, tenant_id: &str, bundle_id: Uuid) -> Result<PolicyBundle, PolicyError> {
        self.bundles
            .lock()
            .unwrap()
            .iter()
            .find(|b| b.tenant_id == tenant_id && b.id == bundle_id)
            .cloned()
            .ok_or(PolicyError::NotFound("no bundle with that id"))
    }
    async fn create_draft(
        &self,
        tenant_id: &str,
        content: &str,
        tests: Option<&serde_json::Value>,
        author: Option<&str>,
    ) -> Result<PolicyBundle, PolicyError> {
        let mut bundles = self.bundles.lock().unwrap();
        let version = bundles
            .iter()
            .map(|bundle| bundle.version)
            .max()
            .unwrap_or(0)
            + 1;
        let bundle = PolicyBundle {
            id: Uuid::now_v7(),
            tenant_id: tenant_id.to_owned(),
            version,
            status: PolicyStatus::Draft,
            content: content.to_owned(),
            content_hash: policy_content_hash(content),
            tests: tests.cloned(),
            author: author.map(str::to_owned),
            created_at: OffsetDateTime::now_utc(),
            published_at: None,
            published_by: None,
        };
        bundles.push(bundle.clone());
        Ok(bundle)
    }
    async fn publish(
        &self,
        tenant_id: &str,
        bundle_id: Uuid,
        publisher: &str,
    ) -> Result<PolicyBundle, PolicyError> {
        let mut g = self.bundles.lock().unwrap();
        let b = g
            .iter_mut()
            .find(|b| {
                b.tenant_id == tenant_id && b.id == bundle_id && b.status == PolicyStatus::Draft
            })
            .ok_or(PolicyError::NotFound("no draft bundle with that id"))?;
        b.status = PolicyStatus::Published;
        b.published_at = Some(OffsetDateTime::now_utc());
        b.published_by = Some(publisher.to_owned());
        Ok(b.clone())
    }
    async fn rollback_to(
        &self,
        tenant_id: &str,
        version: i32,
        actor: &str,
    ) -> Result<PolicyBundle, PolicyError> {
        let mut g = self.bundles.lock().unwrap();
        let target = g
            .iter()
            .find(|b| {
                b.tenant_id == tenant_id && b.version == version && b.status != PolicyStatus::Draft
            })
            .cloned()
            .ok_or(PolicyError::NotFound("no published bundle at that version"))?;
        let next = g.iter().map(|b| b.version).max().unwrap_or(0) + 1;
        let mut new = sample_policy_bundle(Uuid::now_v7(), next, PolicyStatus::Published);
        new.content = target.content.clone();
        new.content_hash = target.content_hash.clone();
        new.published_by = Some(actor.to_owned());
        g.push(new.clone());
        Ok(new)
    }
    async fn delete_all_bundles_for_tenant(&self, _tenant_id: &str) -> Result<u64, PolicyError> {
        unimplemented!("not exercised by the policy executor tests")
    }
    async fn read_pointer(&self, _tenant_id: &str) -> Result<Option<PolicyPointer>, PolicyError> {
        Ok(self
            .pointer
            .lock()
            .unwrap()
            .clone()
            .map(|current_hash| PolicyPointer {
                tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
                current_hash,
                updated_at: OffsetDateTime::now_utc(),
                updated_by: None,
            }))
    }
    async fn seed_pointer(&self, _tenant_id: &str, hash: &str) -> Result<(), PolicyError> {
        let mut pointer = self.pointer.lock().unwrap();
        if pointer.is_none() {
            *pointer = Some(hash.to_owned());
        }
        Ok(())
    }
    async fn cas_pointer(
        &self,
        _tenant_id: &str,
        expected_hash: &str,
        new_hash: &str,
        _actor: &str,
    ) -> Result<TurnstileOutcome, PolicyError> {
        let mut pointer = self.pointer.lock().unwrap();
        let outcome = if pointer.as_deref() == Some(expected_hash) {
            *pointer = Some(new_hash.to_owned());
            TurnstileOutcome::Won
        } else {
            TurnstileOutcome::Lost
        };
        drop(pointer);
        if matches!(outcome, TurnstileOutcome::Won) {
            if let Some(hook) = self.after_next_cas.lock().unwrap().take() {
                hook();
            }
        }
        Ok(outcome)
    }
}

#[tokio::test]
async fn approve_executes_policy_publish() {
    // A maker proposes publishing a draft bundle; a different operator
    // approves; the gateway runs publish_bundle_core in the approver's
    // tenant and the draft becomes Published. The result fingerprints the
    // now-active bundle (no secret).
    let draft_id = Uuid::from_u128(0x7001);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![sample_policy_bundle(
        draft_id,
        1,
        PolicyStatus::Draft,
    )]));
    let app = api_router(
        state_with_policies(Some(mem_store()), store.clone() as Arc<dyn PolicyStore>).await,
    );
    let body = json!({
        "action_type": "policy.publish",
        "params": { "bundle_id": draft_id },
        "justification": "ship the reviewed policy set"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        v["execution_result"]["bundle_id"].as_str().unwrap(),
        draft_id.to_string()
    );
    assert_eq!(v["execution_result"]["version"].as_i64().unwrap(), 1);
    assert_eq!(
        store.get_by_id(draft_id).unwrap().status,
        PolicyStatus::Published,
        "the draft must be published in the store"
    );
}

#[tokio::test]
async fn approve_executes_policy_rollback() {
    // A maker proposes rolling back to a previously-published version; on approval
    // the gateway re-publishes that version's content as a NEW active bundle
    // (roll-forward). The result fingerprints the target + the new version.
    let v1_id = Uuid::from_u128(0x7002);
    let v2_id = Uuid::from_u128(0x7003);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![
        sample_policy_bundle(v1_id, 1, PolicyStatus::Published),
        sample_policy_bundle(v2_id, 2, PolicyStatus::Published),
    ]));
    let app = api_router(
        state_with_policies(Some(mem_store()), store.clone() as Arc<dyn PolicyStore>).await,
    );
    let body = json!({
        "action_type": "policy.rollback",
        "params": { "version": 1 },
        "justification": "v2 broke auth; roll back to v1"
    });
    let id = propose_as(&app, &body, "alice").await;
    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        v["execution_result"]["rolled_back_to_version"]
            .as_i64()
            .unwrap(),
        1
    );
    assert_eq!(v["execution_result"]["new_version"].as_i64().unwrap(), 3);
    assert_eq!(
        store.published_versions(),
        vec![1, 2, 3],
        "rollback appends a new active version (roll-forward)"
    );
}

#[tokio::test]
async fn policy_publish_nondraft_fails_closed() {
    // The target bundle is already Published (not a draft) — publish_bundle_core
    // refuses with Conflict, which the executor maps to Precondition (-> 409 ->
    // durably failed). No phantom "executed" for a no-op publish.
    let id_pub = Uuid::from_u128(0x7004);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![sample_policy_bundle(
        id_pub,
        1,
        PolicyStatus::Published,
    )]));
    let app =
        api_router(state_with_policies(Some(mem_store()), store as Arc<dyn PolicyStore>).await);
    let body = json!({
        "action_type": "policy.publish",
        "params": { "bundle_id": id_pub },
        "justification": "publish something already published"
    });
    let id = propose_as(&app, &body, "alice").await;
    let resp = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let poll = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(poll["status"].as_str().unwrap(), "failed");
}

#[tokio::test]
async fn approve_upserts_policy_fragment_after_mandatory_impact_preview() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);\n\n@id(\"example-security\") forbid(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), live).unwrap();
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7010), 1, PolicyStatus::Published);
    // `--import-policies` stores the policy-directory reader's source verbatim,
    // including its reader-added trailing newline. That representation must
    // reconcile with the same live source without being canonicalized twice.
    active.content = waygate_policy::read_policy_dir(&dir.0).unwrap().source;
    active.content_hash = policy_content_hash(&active.content);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let state = state_with_policy_fragment_dependencies(
        mem_store(),
        store.clone() as Arc<dyn PolicyStore>,
        dir.0.clone(),
        true,
    )
    .await;
    let app = api_router(state.clone());
    let replacement =
        "@id(\"example-security\") permit(principal, action, resource) when { true };";
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": replacement,
            "author": "example-security-agent"
        },
        "justification": "publish the reviewed synthetic security authorization fragment"
    });

    let id = propose_as(&app, &body, "alice").await;
    let dashboard = dashboard_router(state, DashboardAuth::Disabled);
    for path in ["/changes", "/decisions"] {
        let response = dashboard
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            html.contains(&format!("/{id}/approve")),
            "{path} must allow review of an imported ledger representation"
        );
        assert!(html.contains(
            "type=\"checkbox\" name=\"effect_preview_acknowledged\" value=\"true\" required"
        ));
        assert!(html.contains("I reviewed the effect preview"));
        assert!(!html.contains("policy ledger has not reconciled"));
    }

    let missing_ack = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(missing_ack.status(), StatusCode::CONFLICT);
    let pending = body_json(
        app.clone()
            .oneshot(get_req(
                &format!("/api/v1/admin/change_requests/{id}"),
                "alice",
                &["mcp:propose"],
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(pending["status"].as_str(), Some("authorization_pending"));
    assert_eq!(
        store.bundle_count(),
        1,
        "missing preview acknowledgement must not consume approval or stage a draft"
    );

    let executed = approve_as(&app, &id, "bob").await;

    assert_eq!(executed["status"].as_str().unwrap(), "executed");
    assert_eq!(
        executed["execution_result"]["policy_id"].as_str().unwrap(),
        "example-security"
    );
    assert_eq!(
        executed["execution_result"]["impact_previewed"].as_bool(),
        Some(true)
    );
    assert!(
        executed["execution_result"].get("impact").is_none(),
        "maker-visible execution results must not expose audit-derived impact data"
    );
    let disk = waygate_policy::read_policy_dir(&dir.0).unwrap().source;
    assert!(disk.contains("@id(\"keep\") permit"));
    assert!(disk.contains(replacement));
    assert!(!disk.contains("@id(\"example-security\") forbid"));
    assert_eq!(
        store.bundle_count(),
        2,
        "the merged full set is staged once"
    );
    let published = store.active_bundle("default").await.unwrap();
    assert_eq!(published.version, 2);
    assert!(published.content.contains(replacement));
}

#[tokio::test]
async fn policy_fragment_refuses_before_staging_when_impact_reader_is_unavailable() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), live).unwrap();
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7011), 1, PolicyStatus::Published);
    active.content = live.to_owned();
    active.content_hash = policy_content_hash(live);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let app = api_router(
        state_with_policy_fragment_dependencies(
            mem_store(),
            store.clone() as Arc<dyn PolicyStore>,
            dir.0.clone(),
            false,
        )
        .await,
    );
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": "@id(\"example-security\") permit(principal, action, resource);"
        },
        "justification": "publish only after an impact preview"
    });

    let id = propose_as(&app, &body, "alice").await;
    let response = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "policy_preview_acknowledged": true }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        store.bundle_count(),
        1,
        "no draft may be staged without preview"
    );
    let disk = waygate_policy::read_policy_dir(&dir.0).unwrap().source;
    assert!(
        !disk.contains("example-security"),
        "live policy set must stay untouched"
    );
    let pending = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(
        pending["status"].as_str(),
        Some("authorization_pending"),
        "unavailable mandatory preview must not consume the approval"
    );
}

async fn assert_policy_fragment_review_queues_block_approval(
    state: Arc<AdminState>,
    id: &str,
    expected_reason: &str,
) {
    let dashboard = dashboard_router(state, DashboardAuth::Disabled);
    for path in ["/changes", "/decisions"] {
        let response = dashboard
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(html.contains("Approval unavailable"));
        assert!(html.contains(expected_reason));
        assert!(
            !html.contains(&format!("/{id}/approve")),
            "{path} must not render an approval form for a blocked preview"
        );
    }
}

#[tokio::test]
async fn policy_fragment_review_queues_disable_approval_without_mandatory_impact() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), live).unwrap();
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7013), 1, PolicyStatus::Published);
    active.content = live.to_owned();
    active.content_hash = policy_content_hash(live);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let state = state_with_policy_fragment_dependencies(
        mem_store(),
        store as Arc<dyn PolicyStore>,
        dir.0.clone(),
        false,
    )
    .await;
    let api = api_router(state.clone());
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": "@id(\"example-security\") permit(principal, action, resource);"
        },
        "justification": "review the exact impact before publishing"
    });
    let id = propose_as(&api, &body, "alice").await;
    assert_policy_fragment_review_queues_block_approval(
        state,
        &id,
        "mandatory impact preview is unavailable",
    )
    .await;
}

#[tokio::test]
async fn policy_fragment_review_queues_block_a_stale_proposal_witness() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), live).unwrap();
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7015), 1, PolicyStatus::Published);
    active.content = live.to_owned();
    active.content_hash = policy_content_hash(live);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let state = state_with_policy_fragment_dependencies(
        mem_store(),
        store.clone() as Arc<dyn PolicyStore>,
        dir.0.clone(),
        true,
    )
    .await;
    let api = api_router(state.clone());
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": "@id(\"example-security\") permit(principal, action, resource);"
        },
        "justification": "bind review to the exact live policy set"
    });
    let id = propose_as(&api, &body, "alice").await;

    let concurrent = "@id(\"keep\") permit(principal, action, resource);\n@id(\"concurrent\") forbid(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), concurrent).unwrap();
    store.replace_active_content(concurrent);

    assert_policy_fragment_review_queues_block_approval(
        state,
        &id,
        "live policy set changed after this fragment was proposed",
    )
    .await;
}

#[tokio::test]
async fn policy_fragment_review_queues_block_an_unreconciled_ledger() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), live).unwrap();
    let stale = "@id(\"stale\") permit(principal, action, resource);";
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7016), 1, PolicyStatus::Published);
    active.content = stale.to_owned();
    active.content_hash = policy_content_hash(stale);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let state = state_with_policy_fragment_dependencies(
        mem_store(),
        store as Arc<dyn PolicyStore>,
        dir.0.clone(),
        true,
    )
    .await;
    let api = api_router(state.clone());
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": "@id(\"example-security\") permit(principal, action, resource);"
        },
        "justification": "review only after the ledger matches the live policy set"
    });
    let id = propose_as(&api, &body, "alice").await;

    assert_policy_fragment_review_queues_block_approval(
        state,
        &id,
        "policy ledger has not reconciled to the live on-disk set",
    )
    .await;
}

#[tokio::test]
async fn policy_fragment_refuses_when_live_set_changes_after_proposal() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), live).unwrap();
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7012), 1, PolicyStatus::Published);
    active.content = live.to_owned();
    active.content_hash = policy_content_hash(live);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let app = api_router(
        state_with_policy_fragment_dependencies(
            mem_store(),
            store.clone() as Arc<dyn PolicyStore>,
            dir.0.clone(),
            true,
        )
        .await,
    );
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": "@id(\"example-security\") permit(principal, action, resource);"
        },
        "justification": "bind approval to the reviewed live set"
    });
    let id = propose_as(&app, &body, "alice").await;

    let concurrent = "@id(\"keep\") permit(principal, action, resource);\n@id(\"concurrent\") forbid(principal, action, resource);";
    std::fs::write(dir.0.join("00-published.cedar"), concurrent).unwrap();
    let response = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "policy_preview_acknowledged": true }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        store.bundle_count(),
        1,
        "stale approval must not stage a draft"
    );
    let disk = waygate_policy::read_policy_dir(&dir.0).unwrap().source;
    assert!(disk.contains("concurrent"));
    assert!(!disk.contains("example-security"));
}

#[tokio::test]
async fn policy_fragment_turnstile_refuses_a_write_during_impact_replay() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);";
    let policy_path = dir.0.join("00-published.cedar");
    std::fs::write(&policy_path, live).unwrap();
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7014), 1, PolicyStatus::Published);
    active.content = live.to_owned();
    active.content_hash = policy_content_hash(live);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let concurrent = "@id(\"keep\") permit(principal, action, resource);\n@id(\"concurrent\") forbid(principal, action, resource);";
    let audit: Arc<dyn waygate_storage::AuditReader> = Arc::new(NoRowsAudit::mutating_on_query(
        2,
        policy_path,
        concurrent.to_owned(),
    ));
    let state = state_with_policy_fragment_audit(
        mem_store(),
        store.clone() as Arc<dyn PolicyStore>,
        dir.0.clone(),
        Some(audit),
    )
    .await;
    let app = api_router(state);
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": "@id(\"example-security\") permit(principal, action, resource);"
        },
        "justification": "prevent a concurrent policy writer from being overwritten"
    });
    let id = propose_as(&app, &body, "alice").await;

    let response = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "policy_preview_acknowledged": true }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        store.published_versions(),
        vec![1],
        "the derived draft must not publish from a stale merge base"
    );
    let disk = waygate_policy::read_policy_dir(&dir.0).unwrap().source;
    assert!(disk.contains("concurrent"));
    assert!(!disk.contains("example-security"));
}

#[tokio::test]
async fn policy_fragment_preserves_an_edit_after_the_turnstile_cas() {
    let dir = PolicyFragmentTmpDir::new();
    let live = "@id(\"keep\") permit(principal, action, resource);";
    let policy_path = dir.0.join("00-published.cedar");
    std::fs::write(&policy_path, live).unwrap();
    let mut active = sample_policy_bundle(Uuid::from_u128(0x7017), 1, PolicyStatus::Published);
    active.content = live.to_owned();
    active.content_hash = policy_content_hash(live);
    let store = Arc::new(FakePolicyStore::with_bundles(vec![active]));
    let app = api_router(
        state_with_policy_fragment_dependencies(
            mem_store(),
            store.clone() as Arc<dyn PolicyStore>,
            dir.0.clone(),
            true,
        )
        .await,
    );
    let body = json!({
        "action_type": "policy.upsert_fragment",
        "params": {
            "base_hash": policy_live_base(&dir.0),
            "statement": "@id(\"example-security\") permit(principal, action, resource);"
        },
        "justification": "preserve a filesystem edit that races the final commit"
    });
    let id = propose_as(&app, &body, "alice").await;

    let concurrent = "@id(\"keep\") permit(principal, action, resource);\n@id(\"concurrent\") forbid(principal, action, resource);";
    store.after_next_cas({
        let policy_path = policy_path.clone();
        let concurrent = concurrent.to_owned();
        move || std::fs::write(policy_path, concurrent).unwrap()
    });
    let response = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "policy_preview_acknowledged": true }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        store.published_versions(),
        vec![1],
        "a derived draft must not publish after the live source changes"
    );
    let disk = waygate_policy::read_policy_dir(&dir.0).unwrap().source;
    assert!(disk.contains("concurrent"));
    assert!(!disk.contains("example-security"));
}

// ---- manifest.publish / manifest.rollback --------------------------

/// State with a change-request store + a manifest store, but **no** servers_dir,
/// so `turnstile_cas` short-circuits to `NoTurnstile` and
/// `mirror_manifest_set_to_disk` no-ops — isolating the approval-preview and
/// executor wiring. The turnstile + disk mirror themselves are covered by
/// manifest_bundles_api.rs.
async fn state_with_manifests(
    cr: Option<SharedChangeRequestStore>,
    manifest: Arc<dyn ManifestStore>,
    preview_available: bool,
    servers_dir: Option<std::path::PathBuf>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    let cedar = preview_available.then(|| {
        Arc::new(ReloadableCedar::new(
            CedarEngine::from_source("").expect("empty Cedar policy set"),
        ))
    });
    let audit = preview_available
        .then(|| Arc::new(NoRowsAudit::empty()) as Arc<dyn waygate_storage::AuditReader>);
    let state = AdminState::new(
        pool,
        cedar,
        audit,
        evidence,
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    )
    .with_change_request_store(cr)
    .with_manifest_store(Some(manifest));
    Arc::new(match servers_dir {
        Some(dir) => state.with_servers_dir(dir),
        None => state,
    })
}

/// A valid upstream-manifest set (a YAML sequence of one upstream), so the core's
/// `canonical_disk_hash(content)` parse succeeds.
const SAMPLE_MANIFEST_YAML: &str =
    "- name: example-messages\n  transport: http\n  url: http://example-messages/mcp\n";

fn sample_manifest_bundle(version: i32, status: ManifestStatus) -> ManifestBundle {
    ManifestBundle {
        id: Uuid::from_u128(0x8000u128 + version as u128),
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        version,
        status,
        content: SAMPLE_MANIFEST_YAML.to_owned(),
        content_hash: format!("mhash-v{version}"),
        author: Some("seed".to_owned()),
        created_at: OffsetDateTime::UNIX_EPOCH,
        published_at: if status == ManifestStatus::Draft {
            None
        } else {
            Some(OffsetDateTime::UNIX_EPOCH)
        },
        published_by: None,
    }
}

/// Canned manifest store: `get` returns a bundle at version 7 with `get_status`
/// (a Draft drives the happy publish path; a Published drives the non-draft
/// fail-closed path); `publish`/`rollback_to`/`get_by_version` return canned
/// published bundles. Pointer methods are unused (no servers_dir -> the
/// turnstile short-circuits before touching them).
struct FakeManifestStore {
    get_status: ManifestStatus,
}

#[async_trait]
impl ManifestStore for FakeManifestStore {
    async fn active_bundle(&self, _tenant: &str) -> Result<ManifestBundle, ManifestError> {
        unimplemented!("not exercised by the manifest executor tests")
    }
    async fn list_bundles(
        &self,
        _tenant: &str,
    ) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
        unimplemented!("not exercised by the manifest executor tests")
    }
    async fn get(&self, _tenant: &str, _id: Uuid) -> Result<ManifestBundle, ManifestError> {
        Ok(sample_manifest_bundle(7, self.get_status))
    }
    async fn get_by_version(
        &self,
        _tenant: &str,
        version: i32,
    ) -> Result<ManifestBundle, ManifestError> {
        Ok(sample_manifest_bundle(version, ManifestStatus::Published))
    }
    async fn create_draft(
        &self,
        _tenant: &str,
        _content: &str,
        _author: Option<&str>,
    ) -> Result<ManifestBundle, ManifestError> {
        unimplemented!("not exercised by the manifest executor tests")
    }
    async fn publish(
        &self,
        _tenant: &str,
        _id: Uuid,
        publisher: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        let mut b = sample_manifest_bundle(7, ManifestStatus::Published);
        b.published_by = Some(publisher.to_owned());
        Ok(b)
    }
    async fn rollback_to(
        &self,
        _tenant: &str,
        _version: i32,
        actor: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        let mut b = sample_manifest_bundle(8, ManifestStatus::Published);
        b.published_by = Some(actor.to_owned());
        Ok(b)
    }
    async fn delete_all_for_tenant(&self, _tenant: &str) -> Result<u64, ManifestError> {
        unimplemented!("not exercised by the manifest executor tests")
    }
    async fn read_pointer(&self, _tenant: &str) -> Result<Option<ManifestPointer>, ManifestError> {
        unimplemented!("not exercised by the manifest executor tests")
    }
    async fn seed_pointer(&self, _tenant: &str, _hash: &str) -> Result<(), ManifestError> {
        unimplemented!("not exercised by the manifest executor tests")
    }
    async fn cas_pointer(
        &self,
        _tenant: &str,
        _expected: &str,
        _new: &str,
        _actor: &str,
    ) -> Result<ManifestTurnstileOutcome, ManifestError> {
        unimplemented!("not exercised by the manifest executor tests")
    }
}

#[tokio::test]
async fn approve_executes_manifest_publish() {
    // A maker proposes publishing a draft server-manifest bundle; a
    // different operator approves; the gateway runs publish_manifest_core in the
    // approver's tenant. Result fingerprints the now-active bundle (no secret).
    let store = Arc::new(FakeManifestStore {
        get_status: ManifestStatus::Draft,
    });
    let app = api_router(
        state_with_manifests(
            Some(mem_store()),
            store as Arc<dyn ManifestStore>,
            true,
            None,
        )
        .await,
    );
    let body = json!({
        "action_type": "manifest.publish",
        "params": { "bundle_id": Uuid::from_u128(0x8007) },
        "justification": "ship the reviewed upstream set"
    });
    let id = propose_as(&app, &body, "alice").await;

    let missing_ack = app
        .clone()
        .oneshot(post_empty(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(missing_ack.status(), StatusCode::CONFLICT);
    let pending = body_json(
        app.clone()
            .oneshot(get_req(
                &format!("/api/v1/admin/change_requests/{id}"),
                "alice",
                &["mcp:propose"],
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(pending["status"].as_str(), Some("authorization_pending"));

    let v = approve_as(&app, &id, "bob").await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(v["execution_result"]["version"].as_i64().unwrap(), 7);
    assert!(v["execution_result"]["content_hash"].is_string());
    let canonical = waygate_upstream::serialize_manifest_set(
        &waygate_upstream::parse_manifest_set(SAMPLE_MANIFEST_YAML).unwrap(),
    )
    .unwrap();
    let expected_activation_hash = waygate_manifest_store::content_hash(&canonical);
    assert_eq!(
        v["execution_result"]["activation_hash"].as_str(),
        Some(expected_activation_hash.as_str()),
        "the receipt must fingerprint the canonical content replicas report"
    );
}

#[tokio::test]
async fn approve_executes_manifest_rollback() {
    // A maker proposes rolling back to a previously-published version; on approval
    // the gateway re-publishes that version's content as a NEW active bundle.
    let store = Arc::new(FakeManifestStore {
        get_status: ManifestStatus::Published,
    });
    let app = api_router(
        state_with_manifests(
            Some(mem_store()),
            store as Arc<dyn ManifestStore>,
            true,
            None,
        )
        .await,
    );
    let body = json!({
        "action_type": "manifest.rollback",
        "params": { "version": 2 },
        "justification": "v3 broke an upstream; roll back to v2"
    });
    let id = propose_as(&app, &body, "alice").await;
    let response = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "policy_preview_acknowledged": true }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let v = body_json(response).await;
    assert_eq!(v["status"].as_str().unwrap(), "executed");
    assert_eq!(
        v["execution_result"]["rolled_back_to_version"]
            .as_i64()
            .unwrap(),
        2
    );
    assert_eq!(v["execution_result"]["new_version"].as_i64().unwrap(), 8);
    assert!(v["execution_result"]["activation_hash"].is_string());
}

#[tokio::test]
async fn nondefault_tenants_can_propose_ledger_only_manifest_publish_and_rollback() {
    let store = Arc::new(FakeManifestStore {
        get_status: ManifestStatus::Draft,
    });
    let app = api_router(
        state_with_manifests(
            Some(mem_store()),
            store as Arc<dyn ManifestStore>,
            true,
            None,
        )
        .await,
    );
    let tenant = waygate_core::TenantId::parse("tenant-b").unwrap();

    for body in [
        json!({
            "action_type": "manifest.publish",
            "params": { "bundle_id": Uuid::from_u128(0x8007) },
            "justification": "publish the tenant-local manifest ledger entry"
        }),
        json!({
            "action_type": "manifest.rollback",
            "params": { "version": 2 },
            "justification": "roll forward the tenant-local manifest ledger entry"
        }),
    ] {
        let mut request = post_req(
            "/api/v1/admin/change_requests",
            &body,
            "alice",
            &["mcp:propose"],
        );
        let mut principal = principal_with_sub("alice", &["mcp:propose"]);
        principal.tenant = tenant.clone();
        request.extensions_mut().insert(principal);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED, "{body}");
        let created = body_json(response).await;
        let id = created["change_request_id"]
            .as_str()
            .expect("created change id");

        let mut approval = post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({"effect_preview_acknowledged": true}),
            "bob",
            &["mcp:admin"],
        );
        let mut approver = principal_with_sub("bob", &["mcp:admin"]);
        approver.tenant = tenant.clone();
        approval.extensions_mut().insert(approver);
        let approved = app.clone().oneshot(approval).await.unwrap();
        assert_eq!(approved.status(), StatusCode::OK, "{body}");
        let outcome = body_json(approved).await;
        assert_eq!(outcome["status"].as_str(), Some("executed"), "{body}");
        assert!(
            outcome["execution_result"]["activation_hash"].is_null(),
            "tenant-ledger-only publication must not claim a gateway-fleet activation target"
        );
    }
}

#[tokio::test]
async fn manifest_publish_nondraft_is_rejected_before_proposal() {
    // A publish witness can be captured only for a Draft target. Rejecting the
    // stale target before queueing avoids an unapprovable pending request.
    let store = Arc::new(FakeManifestStore {
        get_status: ManifestStatus::Published,
    });
    let app = api_router(
        state_with_manifests(
            Some(mem_store()),
            store as Arc<dyn ManifestStore>,
            true,
            None,
        )
        .await,
    );
    let body = json!({
        "action_type": "manifest.publish",
        "params": { "bundle_id": Uuid::from_u128(0x8009) },
        "justification": "publish a non-draft"
    });
    let resp = app
        .oneshot(post_req(
            "/api/v1/admin/change_requests",
            &body,
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn manifest_approval_refuses_when_the_effect_cannot_be_recomputed() {
    let store = Arc::new(FakeManifestStore {
        get_status: ManifestStatus::Draft,
    });
    let app = api_router(
        state_with_manifests(
            Some(mem_store()),
            store as Arc<dyn ManifestStore>,
            false,
            None,
        )
        .await,
    );
    let body = json!({
        "action_type": "manifest.publish",
        "params": { "bundle_id": Uuid::from_u128(0x8007) },
        "justification": "publish only after reviewing the current effect"
    });
    let id = propose_as(&app, &body, "alice").await;

    let response = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "effect_preview_acknowledged": true }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let pending = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(pending["status"].as_str(), Some("authorization_pending"));
}

#[tokio::test]
async fn stale_manifest_baseline_refuses_before_approval_is_consumed() {
    let dir = std::env::temp_dir().join(format!(
        "change-request-stale-manifest-preview-{}",
        Uuid::now_v7()
    ));
    let initial = waygate_upstream::parse_manifest_set(SAMPLE_MANIFEST_YAML).unwrap();
    waygate_upstream::write_manifest_set_to_dir(&dir, &initial).unwrap();
    let store = Arc::new(FakeManifestStore {
        get_status: ManifestStatus::Draft,
    });
    let state = state_with_manifests(
        Some(mem_store()),
        store as Arc<dyn ManifestStore>,
        true,
        Some(dir.clone()),
    )
    .await;
    let Some(Ok((_set, prepared_base))) = state.read_manifest_set_from_disk() else {
        panic!("expected readable initial manifest set");
    };
    let app = api_router(state);
    let body = json!({
        "action_type": "manifest.stage_and_publish",
        "params": {
            "base_hash": prepared_base,
            "content": "- name: example-messages\n  transport: http\n  url: http://example-messages-v2/mcp\n"
        },
        "justification": "replace the reviewed manifest set"
    });
    let id = propose_as(&app, &body, "alice").await;

    let changed = waygate_upstream::parse_manifest_set(
        "- name: example-messages\n  transport: http\n  url: http://example-messages-out-of-band/mcp\n",
    )
    .unwrap();
    waygate_upstream::write_manifest_set_to_dir(&dir, &changed).unwrap();

    let response = app
        .clone()
        .oneshot(post_req(
            &format!("/api/v1/admin/change_requests/{id}/approve"),
            &json!({ "effect_preview_acknowledged": true }),
            "bob",
            &["mcp:admin"],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let refusal = body_json(response).await;
    assert!(
        refusal["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("different baseline")),
        "approval must be refused by the stale effect preview: {refusal}"
    );
    let pending = body_json(
        app.oneshot(get_req(
            &format!("/api/v1/admin/change_requests/{id}"),
            "alice",
            &["mcp:propose"],
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(
        pending["status"].as_str(),
        Some("authorization_pending"),
        "a preview against a newer live baseline must not consume approval state"
    );

    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn stale_publish_and_rollback_baselines_refuse_before_approval_is_consumed() {
    for (action_type, params, target_status) in [
        (
            "manifest.publish",
            json!({"bundle_id": Uuid::from_u128(0x8007)}),
            ManifestStatus::Draft,
        ),
        (
            "manifest.rollback",
            json!({"version": 2}),
            ManifestStatus::Published,
        ),
    ] {
        let dir = std::env::temp_dir().join(format!(
            "change-request-stale-{action_type}-{}",
            Uuid::now_v7()
        ));
        let initial = waygate_upstream::parse_manifest_set(SAMPLE_MANIFEST_YAML).unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &initial).unwrap();
        let store = Arc::new(FakeManifestStore {
            get_status: target_status,
        });
        let state = state_with_manifests(
            Some(mem_store()),
            store as Arc<dyn ManifestStore>,
            true,
            Some(dir.clone()),
        )
        .await;
        let app = api_router(state);
        let body = json!({
            "action_type": action_type,
            "params": params,
            "justification": "apply the selected manifest set"
        });
        let id = propose_as(&app, &body, "alice").await;

        let changed = waygate_upstream::parse_manifest_set(
            "- name: example-messages\n  transport: http\n  url: http://example-messages-out-of-band/mcp\n",
        )
        .unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &changed).unwrap();

        let response = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/change_requests/{id}/approve"),
                &json!({ "effect_preview_acknowledged": true }),
                "bob",
                &["mcp:admin"],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{action_type}");
        let refusal = body_json(response).await;
        assert!(
            refusal["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("different baseline")),
            "{action_type} must be refused by the stale effect preview: {refusal}"
        );
        let pending = body_json(
            app.oneshot(get_req(
                &format!("/api/v1/admin/change_requests/{id}"),
                "alice",
                &["mcp:propose"],
            ))
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(
            pending["status"].as_str(),
            Some("authorization_pending"),
            "a stale {action_type} preview must not consume approval state"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn custom_inspection_writes_cannot_be_proposed() {
    let app = api_router(state_with(Some(mem_store())).await);
    for action in ["inspection_rule.create", "inspection_rule.update"] {
        let response = app.clone().oneshot(post_req(
            "/api/v1/admin/change_requests",
            &json!({"action_type": action, "params": {}, "justification": "test unsupported rule"}),
            "alice", &["mcp:propose"],
        )).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
