//! Route-level coverage for the `/api/v1/policy_bundles/*` admin
//! endpoints. Uses an in-memory `PolicyStore` fake so the test doesn't
//! need a live Postgres pool (the Pg impl is exercised by the
//! `waygate-policy` smoke test).
//!
//! Pins:
//! 1. `None` store ⇒ every endpoint 503 (DB-less deployment).
//! 2. `mcp:read` is insufficient; `mcp:admin` succeeds.
//! 3. With a store wired: list returns rows, active returns the bundle,
//!    create returns 201, publish returns 200, and an empty draft body
//!    is a 400.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::util::ServiceExt;

use uuid::Uuid;
use waygate_admin::{api_router, dashboard_router, AdminState, DashboardAuth};
use waygate_mcp::audit::{
    AuditEvent, AuditOutcome, EvidenceCategory, EvidenceError, EvidencePosture, EvidenceRecorder,
    SharedEvidence,
};
use waygate_oidc::Principal;
use waygate_policy::{
    content_hash, PolicyBundle, PolicyBundleSummary, PolicyError, PolicyStatus, PolicyStore,
    SharedPolicyStore,
};
use waygate_upstream::pool::UpstreamPool;

/// In-memory policy-store fake. `present` toggles whether
/// `active_bundle` / `get` / `publish` find a bundle (active ⇒ 200/404,
/// publish ⇒ 200/404).
struct FakePolicyStore {
    summaries: Vec<PolicyBundleSummary>,
    present: bool,
    /// Status `get` reports for the fetched bundle. The publish path's
    /// mirror-before-ledger pre-check requires a Draft, so the
    /// default is Draft; set non-Draft to exercise the 409 "not a draft"
    /// refusal.
    get_status: PolicyStatus,
    /// When true, the LEDGER ops (`publish` / `rollback_to`) fail even though
    /// `get` / `list_bundles` succeed — exercises the atomic mirror-then-ledger
    /// rollback (a ledger failure after a successful disk mirror must restore
    /// the prior on-disk set).
    commit_fails: bool,
    /// In-memory turnstile pointer, so the CAS path the write handlers
    /// take can actually win/lose. `Mutex<Option<hash>>`; `None` = unseeded.
    pointer: std::sync::Mutex<Option<String>>,
    /// When true, `cas_pointer` always loses — simulates another replica winning
    /// the turnstile, so the write handler returns 409 Conflict.
    cas_always_loses: bool,
    /// Tests JSON that `get` reports for the fetched DRAFT bundle (the publish
    /// path reads `draft.tests` to run the policy-test publish gate). `None` ⇒ the draft
    /// carries no attached tests (no gate). Set to a `[PolicyTestCase]` JSON to
    /// exercise the gate's pass/block behaviour.
    get_tests: Option<serde_json::Value>,
    /// Content `get` reports for the fetched draft. Defaults to the v9 permit
    /// content; tests that need the draft's Cedar to FAIL their attached
    /// assertion override it.
    get_content: Option<String>,
    notify_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for FakePolicyStore {
    fn default() -> Self {
        Self {
            summaries: vec![],
            present: false,
            get_status: PolicyStatus::Draft,
            commit_fails: false,
            pointer: std::sync::Mutex::new(None),
            cas_always_loses: false,
            get_tests: None,
            get_content: None,
            notify_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

fn sample_summary(version: i32, status: PolicyStatus) -> PolicyBundleSummary {
    let content = format!("permit(principal, action, resource); // v{version}");
    PolicyBundleSummary {
        id: Uuid::nil(),
        tenant_id: "default".into(),
        version,
        status,
        content_hash: content_hash(&content),
        author: Some("alice".into()),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        published_by: Some("bob".into()),
    }
}

fn sample_bundle(version: i32, status: PolicyStatus) -> PolicyBundle {
    let content = format!("permit(principal, action, resource); // v{version}");
    let published_at = match status {
        PolicyStatus::Draft => None,
        _ => Some(time::OffsetDateTime::UNIX_EPOCH),
    };
    PolicyBundle {
        id: Uuid::nil(),
        tenant_id: "default".into(),
        version,
        status,
        content_hash: content_hash(&content),
        content,
        tests: None,
        author: Some("alice".into()),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        published_at,
        published_by: None,
    }
}

#[async_trait]
impl PolicyStore for FakePolicyStore {
    async fn active_bundle(&self, _tenant: &str) -> Result<PolicyBundle, PolicyError> {
        if self.present {
            Ok(sample_bundle(3, PolicyStatus::Published))
        } else {
            Err(PolicyError::NotFound(
                "no published policy bundle for tenant",
            ))
        }
    }
    async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError> {
        match self.active_bundle("default").await {
            Ok(bundle) => Ok(vec![bundle]),
            Err(PolicyError::NotFound(_)) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }
    async fn list_bundles(&self, _tenant: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError> {
        if !self.summaries.is_empty() {
            Ok(self.summaries.clone())
        } else if self.present {
            // A canned published ledger so a rollback target (e.g. v2)
            // resolves via list→find→get. Newest first, matching the store.
            Ok(vec![
                sample_summary(3, PolicyStatus::Published),
                sample_summary(2, PolicyStatus::Published),
                sample_summary(1, PolicyStatus::Published),
            ])
        } else {
            Ok(vec![])
        }
    }
    async fn get(&self, _tenant: &str, _id: Uuid) -> Result<PolicyBundle, PolicyError> {
        if self.present {
            // Publish fetches the DRAFT it is about to promote; `get_status`
            // lets a test flip this to a non-draft to exercise the refusal.
            // `get_tests` / `get_content` let a test attach gate cases and/or
            // override the draft's Cedar so the policy-test publish gate can be
            // exercised pass/block.
            let mut b = sample_bundle(9, self.get_status);
            b.tests = self.get_tests.clone();
            if let Some(c) = &self.get_content {
                b.content = c.clone();
                b.content_hash = content_hash(c);
            }
            Ok(b)
        } else {
            Err(PolicyError::NotFound(
                "no policy bundle with that id in tenant",
            ))
        }
    }
    async fn create_draft(
        &self,
        _tenant: &str,
        content: &str,
        tests: Option<&serde_json::Value>,
        author: Option<&str>,
    ) -> Result<PolicyBundle, PolicyError> {
        Ok(PolicyBundle {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            version: 9,
            status: PolicyStatus::Draft,
            content_hash: content_hash(content),
            content: content.to_owned(),
            tests: tests.cloned(),
            author: author.map(str::to_owned),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: None,
            published_by: None,
        })
    }
    async fn publish(
        &self,
        _tenant: &str,
        _id: Uuid,
        publisher: &str,
    ) -> Result<PolicyBundle, PolicyError> {
        if self.commit_fails {
            return Err(PolicyError::NotFound("simulated ledger failure"));
        }
        if self.present {
            let mut b = sample_bundle(9, PolicyStatus::Published);
            b.published_by = Some(publisher.to_owned());
            Ok(b)
        } else {
            Err(PolicyError::NotFound("no draft policy bundle with that id"))
        }
    }
    async fn rollback_to(
        &self,
        _tenant: &str,
        _version: i32,
        actor: &str,
    ) -> Result<PolicyBundle, PolicyError> {
        if self.commit_fails {
            return Err(PolicyError::NotFound("simulated ledger failure"));
        }
        if self.present {
            let mut b = sample_bundle(10, PolicyStatus::Published);
            b.published_by = Some(actor.to_owned());
            Ok(b)
        } else {
            Err(PolicyError::NotFound(
                "no published policy bundle at that version in tenant",
            ))
        }
    }
    async fn delete_all_bundles_for_tenant(&self, _tenant: &str) -> Result<u64, PolicyError> {
        Ok(0)
    }
    async fn read_pointer(
        &self,
        _tenant: &str,
    ) -> Result<Option<waygate_policy::PolicyPointer>, PolicyError> {
        Ok(self
            .pointer
            .lock()
            .unwrap()
            .clone()
            .map(|h| waygate_policy::PolicyPointer {
                tenant_id: "default".into(),
                current_hash: h,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
                updated_by: None,
            }))
    }
    async fn seed_pointer(&self, _tenant: &str, hash: &str) -> Result<(), PolicyError> {
        // INSERT ON CONFLICT DO NOTHING: only establishes an absent pointer.
        let mut p = self.pointer.lock().unwrap();
        if p.is_none() {
            *p = Some(hash.to_owned());
        }
        Ok(())
    }
    async fn cas_pointer(
        &self,
        _tenant: &str,
        expected: &str,
        new: &str,
        _actor: &str,
    ) -> Result<waygate_policy::TurnstileOutcome, PolicyError> {
        if self.cas_always_loses {
            return Ok(waygate_policy::TurnstileOutcome::Lost);
        }
        let mut p = self.pointer.lock().unwrap();
        if p.as_deref() == Some(expected) {
            *p = Some(new.to_owned());
            Ok(waygate_policy::TurnstileOutcome::Won)
        } else {
            Ok(waygate_policy::TurnstileOutcome::Lost)
        }
    }
    async fn notify_reload(&self, _hash: &str) -> Result<(), PolicyError> {
        self.notify_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
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

async fn state_with(store: Option<SharedPolicyStore>) -> Arc<AdminState> {
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
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_policy_store(store),
    )
}

fn admin_get(uri: &str) -> Request<Body> {
    let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    req
}

fn admin_post(uri: &str, body: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    req
}

fn admin_post_for_tenant(uri: &str, body: &str, tenant: &str) -> Request<Body> {
    let mut req = admin_post(uri, body);
    let mut principal = principal_with(&["mcp:admin"]);
    principal.tenant = waygate_core::TenantId::parse(tenant).expect("valid test tenant");
    req.extensions_mut().insert(principal);
    req
}

#[tokio::test]
async fn preview_simulate_stamps_the_authenticated_tenant() {
    let app = api_router(state_with(None).await);
    let body = serde_json::json!({
        "content": "@id(\"tenant-preview\") permit (principal, action, resource) when { principal.tenant == \"acme\" };",
        "principal": {"sub": "alice"},
        "action": {"type": "search_tools"},
        "resource": {"type": "server", "name": "example-messages"}
    });
    let response = app
        .oneshot(admin_post_for_tenant(
            "/api/v1/policy_bundles/preview_simulate",
            &body.to_string(),
            "acme",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["decision"], "allow");
    assert_eq!(body["policy_ids"], serde_json::json!(["tenant-preview"]));
}

#[tokio::test]
async fn endpoints_503_without_store() {
    for (method, uri, body) in [
        ("GET", "/api/v1/policy_bundles", None),
        ("GET", "/api/v1/policy_bundles/active", None),
        (
            "POST",
            "/api/v1/policy_bundles",
            Some(r#"{"content":"permit(principal, action, resource);"}"#),
        ),
        (
            "POST",
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            Some("{}"),
        ),
        ("POST", "/api/v1/policy_bundles/2/rollback", Some("{}")),
    ] {
        let app = api_router(state_with(None).await);
        let req = match method {
            "POST" => admin_post(uri, body.unwrap_or("{}")),
            _ => admin_get(uri),
        };
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {uri} should 503 without a store",
        );
    }
}

#[tokio::test]
async fn list_requires_admin_scope() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(store)).await);

    // No principal → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policy_bundles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // mcp:read insufficient → 403.
    let mut req = Request::builder()
        .uri("/api/v1/policy_bundles")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_returns_summaries() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        summaries: vec![PolicyBundleSummary {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            version: 2,
            status: PolicyStatus::Published,
            content_hash: "abc".into(),
            author: Some("alice".into()),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            published_by: Some("bob".into()),
        }],
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_get("/api/v1/policy_bundles"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["bundles"][0]["version"], 2);
    assert_eq!(body["bundles"][0]["status"], "published");
}

#[tokio::test]
async fn active_returns_bundle_or_404() {
    // Present ⇒ 200 with content.
    let present: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(present)).await);
    let resp = app
        .oneshot(admin_get("/api/v1/policy_bundles/active"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Absent ⇒ 404 (NotFound mapped).
    let absent: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(absent)).await);
    let resp = app
        .oneshot(admin_get("/api/v1/policy_bundles/active"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_draft_returns_201() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles",
            r#"{"content":"permit(principal, action, resource);","author":"alice"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "draft");
}

/// Like [`state_with`] but with policy editing DISABLED — the deployment posture
/// when `GATEWAY_POLICY_EDITING=off` or the policies dir isn't writable. Pins
/// that every REST MUTATION 403s while reads stay open.
async fn state_with_editing_off(store: Option<SharedPolicyStore>) -> Arc<AdminState> {
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
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_policy_store(store)
        .with_policy_editing_off_reason(Some("the policies directory is not writable".into())),
    )
}

#[tokio::test]
async fn rest_mutations_403_when_editing_disabled() {
    // With editing disabled the REST surface is a read-only policy viewer —
    // create-draft / publish / rollback all 403 with the operator-facing reason
    // (BEFORE any store work, so a disabled deployment never half-applies a
    // write), while reads stay open. Mirrors the dashboard middleware gate.
    let store: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with_editing_off(Some(store)).await);

    let mutations = [
        (
            "/api/v1/policy_bundles",
            r#"{"content":"permit(principal, action, resource);","author":"alice"}"#,
        ),
        (
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ),
        ("/api/v1/policy_bundles/1/rollback", "{}"),
    ];
    for (uri, body) in mutations {
        let resp = app.clone().oneshot(admin_post(uri, body)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{uri} must 403 when editing is disabled"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "forbidden");
        assert!(
            v["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("policy editing is disabled"),
            "403 detail should name the disabled-editing reason: {v}"
        );
    }

    // Reads are NOT gated: listing bundles still works in read-only mode.
    let resp = app
        .oneshot(admin_get("/api/v1/policy_bundles"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_draft_rejects_empty_content() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post("/api/v1/policy_bundles", r#"{"content":"   "}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_draft_rejects_comment_only_policy_content() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles",
            r#"{"content":"// no policies here\n"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_draft_rejects_unparseable_cedar() {
    // Source that doesn't parse as Cedar must be rejected at draft time
    // so a published bundle is always loadable by the gate.
    let store: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles",
            r#"{"content":"this is not valid cedar {{{"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Captures every recorded `AuditEvent` so a test can assert that a
/// mutation produced durable evidence.
#[derive(Default)]
struct CapturingRecorder {
    events: std::sync::Mutex<Vec<AuditEvent>>,
    postures: std::sync::Mutex<Vec<EvidencePosture>>,
}

#[async_trait]
impl EvidenceRecorder for CapturingRecorder {
    async fn record_required(&self, e: AuditEvent) -> Result<Uuid, EvidenceError> {
        let id = e.id;
        self.events.lock().unwrap().push(e);
        self.postures
            .lock()
            .unwrap()
            .push(EvidencePosture::Required);
        Ok(id)
    }
    async fn record_chained_best_effort(&self, e: AuditEvent) {
        self.events.lock().unwrap().push(e);
        self.postures
            .lock()
            .unwrap()
            .push(EvidencePosture::ChainedBestEffort);
    }
    async fn record_best_effort(&self, e: AuditEvent) {
        self.events.lock().unwrap().push(e);
        self.postures
            .lock()
            .unwrap()
            .push(EvidencePosture::BestEffort);
    }
}

#[tokio::test]
async fn create_and_publish_emit_admin_mutation_evidence() {
    // Policy draft/publish are security-relevant mutations and must be
    // auditable, like the other mutating admin endpoints.
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let recorder = Arc::new(CapturingRecorder::default());
    let evidence: SharedEvidence = recorder.clone();
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let state = Arc::new(
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
        .with_policy_store(Some(store)),
    );
    let app = api_router(state);

    app.clone()
        .oneshot(admin_post(
            "/api/v1/policy_bundles",
            r#"{"content":"permit(principal, action, resource);"}"#,
        ))
        .await
        .unwrap();
    app.oneshot(admin_post(
        "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
        "{}",
    ))
    .await
    .unwrap();

    let events = recorder.events.lock().unwrap();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert!(
        actions.contains(&"policy_bundle.create_draft"),
        "create must emit evidence; got {actions:?}",
    );
    assert!(
        actions.contains(&"policy_bundle.publish"),
        "publish must emit evidence; got {actions:?}",
    );
    assert!(
        events
            .iter()
            .all(|e| matches!(e.category, EvidenceCategory::AdminMutation)),
        "policy mutations must be categorized AdminMutation",
    );
}

#[tokio::test]
async fn rollback_returns_200_or_404() {
    // Present ⇒ 200 (target version re-published as new active bundle).
    let present: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(present)).await);
    let resp = app
        .oneshot(admin_post("/api/v1/policy_bundles/2/rollback", "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Absent target version ⇒ 404.
    let absent: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(absent)).await);
    let resp = app
        .oneshot(admin_post("/api/v1/policy_bundles/2/rollback", "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn publish_returns_200_or_404() {
    // Present ⇒ 200, records publisher.
    let present: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(present)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Absent draft ⇒ 404.
    let absent: SharedPolicyStore = Arc::new(FakePolicyStore::default());
    let app = api_router(state_with(Some(absent)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Unique temp dir cleaned up on drop — keeps the test side-effect free.
struct TmpDir(std::path::PathBuf);
impl TmpDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("polbundles-api-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn state_with_policies_dir(
    store: Option<SharedPolicyStore>,
    dir: std::path::PathBuf,
) -> Arc<AdminState> {
    state_with_policies_dir_and_evidence(store, dir, AdminState::null_evidence()).await
}

/// As [`state_with_policies_dir`] but with a caller-supplied evidence sink, so a
/// test can capture the audit rows a publish (or a gated-out publish) emits.
async fn state_with_policies_dir_and_evidence(
    store: Option<SharedPolicyStore>,
    dir: std::path::PathBuf,
    evidence: SharedEvidence,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
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
        .with_policy_store(store)
        .with_policies_dir(dir),
    )
}

/// File-as-truth: a REST publish must MIRROR the draft onto the
/// on-disk `policies/*.cedar` set the gate loads — not just record the ledger
/// row. Otherwise a SIGHUP/restart would reload the stale disk set and drop the
/// publish (the "false success" the loader inversion is gated on).
#[tokio::test]
async fn publish_mirrors_draft_to_policies_dir() {
    let tmp = TmpDir::new();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let published = std::fs::read_to_string(tmp.0.join("00-published.cedar")).unwrap();
    assert!(
        published.contains("permit(principal, action, resource)"),
        "publish must write the draft content to disk; got {published:?}",
    );
    // The live dir collapses to the single machine-owned published file.
    let cedar: Vec<String> = std::fs::read_dir(&tmp.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".cedar"))
        .collect();
    assert_eq!(cedar, vec!["00-published.cedar".to_string()]);
}

/// A REST rollback must likewise mirror the target version's content onto disk
/// before the ledger roll-forward.
#[tokio::test]
async fn rollback_mirrors_target_to_policies_dir() {
    let tmp = TmpDir::new();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post("/api/v1/policy_bundles/2/rollback", "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let published = std::fs::read_to_string(tmp.0.join("00-published.cedar")).unwrap();
    assert!(
        published.contains("permit(principal, action, resource)"),
        "rollback must write the target content to disk; got {published:?}",
    );
}

/// `mirror_policy_bundle_to_disk` validates BEFORE writing: an empty policy set
/// would make boot load zero policies (deny-by-default lockout) that
/// `resolve_policies` cannot recover from, so it is refused and nothing is
/// written.
#[tokio::test]
async fn mirror_refuses_empty_bundle() {
    let tmp = TmpDir::new();
    let state = state_with_policies_dir(None, tmp.0.clone()).await;
    // Comment-only source parses but yields zero policies.
    let err = state
        .mirror_policy_bundle_to_disk("default", "// no policies here\n")
        .unwrap_err();
    assert!(err.contains("empty policy bundle"), "got {err}");
    assert!(!tmp.0.join("00-published.cedar").exists());
}

/// Unparseable Cedar is refused before reaching disk (disk is the boot source
/// of truth; a broken set there would fail boot).
#[tokio::test]
async fn mirror_refuses_unparseable_bundle() {
    let tmp = TmpDir::new();
    let state = state_with_policies_dir(None, tmp.0.clone()).await;
    assert!(state
        .mirror_policy_bundle_to_disk("default", "this is not valid cedar {{{")
        .is_err());
    assert!(!tmp.0.join("00-published.cedar").exists());
}

/// A non-default tenant is live from its own DB ledger; it must NOT mutate the
/// default tenant's on-disk policy set.
#[tokio::test]
async fn mirror_non_default_tenant_is_noop() {
    let tmp = TmpDir::new();
    let state = state_with_policies_dir(None, tmp.0.clone()).await;
    state
        .mirror_policy_bundle_to_disk("other-tenant", "permit(principal, action, resource);")
        .unwrap();
    assert!(
        !tmp.0.join("00-published.cedar").exists(),
        "non-default tenant must not write the global on-disk set",
    );
}

#[tokio::test]
async fn non_default_ledger_publish_rings_policy_doorbell() {
    let tmp = TmpDir::new();
    let fake = Arc::new(FakePolicyStore::default());
    let notify_calls = fake.notify_calls.clone();
    let state = state_with_policies_dir(Some(fake), tmp.0.clone()).await;
    let mut published = sample_bundle(4, PolicyStatus::Published);
    published.tenant_id = "other-tenant".to_owned();
    let content = published.content.clone();

    state
        .mirror_then("other-tenant", &content, "alice", || async {
            Ok(published)
        })
        .await
        .expect("ledger-backed tenant publish");

    assert_eq!(
        notify_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a tenant publish wakes every replica's tenant-policy refresh",
    );
    assert!(
        !tmp.0.join("00-published.cedar").exists(),
        "tenant publish still must not mutate the default policy directory",
    );
}

#[tokio::test]
async fn non_default_empty_bundle_is_refused_before_ledger_and_doorbell() {
    let tmp = TmpDir::new();
    let fake = Arc::new(FakePolicyStore::default());
    let notify_calls = fake.notify_calls.clone();
    let state = state_with_policies_dir(Some(fake), tmp.0.clone()).await;
    let ledger_called = std::sync::atomic::AtomicBool::new(false);

    let result = state
        .mirror_then("other-tenant", "// no policies here\n", "alice", || async {
            ledger_called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(sample_bundle(4, PolicyStatus::Published))
        })
        .await;

    assert!(result.is_err());
    assert!(!ledger_called.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(notify_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!tmp.0.join("00-published.cedar").exists());
}

/// Concatenated live `*.cedar` text on disk — used to assert what the gate
/// would load.
fn live_policy_text(dir: &std::path::Path) -> String {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("cedar"))
        .collect();
    names.sort();
    names
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// File-as-truth ledger failure: if the LEDGER publish fails AFTER
/// the disk mirror succeeded, the on-disk set (the SOURCE OF TRUTH) WINS — the
/// handler must NOT restore the prior disk (that would treat the ledger as
/// authoritative and, across replicas, clobber a concurrent writer). The
/// successfully-mirrored content stays live; the gate loads it on the next
/// reload and the ledger reconciles to disk. The request surfaces an
/// error so the operator knows the ledger lagged.
#[tokio::test]
async fn publish_ledger_failure_keeps_disk_applied() {
    let tmp = TmpDir::new();
    std::fs::write(
        tmp.0.join("10-prior.cedar"),
        "forbid(principal, action, resource); // prior\n",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        commit_fails: true,
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "a failed ledger publish must surface an error, got {}",
        resp.status(),
    );
    // Disk WINS: the mirrored draft stays live (NOT rolled back to the prior set).
    let live = live_policy_text(&tmp.0);
    assert!(
        live.contains("v9"),
        "the successfully-mirrored content must stay live (disk is the source of truth); got {live:?}",
    );
    assert!(
        !live.contains("prior"),
        "disk must NOT be rolled back to the prior set on a ledger failure; got {live:?}",
    );
}

/// Same disk-wins guarantee for rollback.
#[tokio::test]
async fn rollback_ledger_failure_keeps_disk_applied() {
    let tmp = TmpDir::new();
    std::fs::write(
        tmp.0.join("10-prior.cedar"),
        "forbid(principal, action, resource); // prior\n",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        commit_fails: true,
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post("/api/v1/policy_bundles/2/rollback", "{}"))
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "a failed ledger rollback must surface an error, got {}",
        resp.status(),
    );
    let live = live_policy_text(&tmp.0);
    assert!(
        !live.contains("prior"),
        "disk must NOT be rolled back to the prior set on a ledger failure; got {live:?}",
    );
}

/// Turnstile LOST: when the cross-replica CAS fails (another replica
/// advanced the on-disk set first), the publish is refused with 409 and NOTHING
/// is written to disk — the CAS precedes the mirror, so the lost update is
/// prevented, not just detected.
#[tokio::test]
async fn publish_lost_turnstile_is_conflict_and_does_not_touch_disk() {
    let tmp = TmpDir::new();
    // The on-disk set must be USABLE (parses + non-empty) for the turnstile to
    // run — a broken/empty set bypasses the CAS (repair path). Seed a valid one.
    std::fs::write(
        tmp.0.join("00-existing.cedar"),
        "forbid(principal, action, resource); // existing",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        cas_always_loses: true,
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(
        !tmp.0.join("00-published.cedar").exists(),
        "a lost turnstile must not write to disk (CAS precedes the mirror)",
    );
}

/// AlreadyCurrent: when the on-disk set already equals the
/// bundle's canonical content, the write is refused as a no-op (409) — it must
/// NOT record a competing ledger row (which can't own the turnstile and could
/// race a concurrent cross-replica writer into a disk/ledger divergence), and it
/// must NOT touch disk.
#[tokio::test]
async fn publish_already_current_is_refused_as_noop() {
    let tmp = TmpDir::new();
    // Seed disk with EXACTLY the draft's content (the fake's `get` returns
    // "permit(...); // v9"), so its canonical disk hash equals the draft's.
    // `read_policy_dir` appends one newline, which `canonical_policy_disk_hash`
    // accounts for — so a file holding the raw content (no trailing newline)
    // hashes equal to the draft.
    std::fs::write(
        tmp.0.join("00-existing.cedar"),
        "permit(principal, action, resource); // v9",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "AlreadyCurrent is refused as a no-op (no competing ledger row)"
    );
    // Disk is untouched — the original file remains as-is, NOT collapsed to the
    // machine-owned 00-published.cedar.
    let cedar: Vec<String> = std::fs::read_dir(&tmp.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".cedar"))
        .collect();
    assert_eq!(
        cedar,
        vec!["00-existing.cedar".to_string()],
        "AlreadyCurrent must not rewrite the on-disk set",
    );
}

/// Broken-disk repair: a readable-but-broken on-disk set
/// (empty/comment-only or unparseable) is what `resolve_policies` RECOVERS from,
/// and reconcile is skipped on a recovered load — so the turnstile pointer sits
/// at the previous-good hash, NOT the broken disk's. A publish meant to REPAIR
/// the source-of-truth dir must bypass the turnstile (rather than CAS from the
/// broken-disk hash, lose against the stale pointer, and 409), so the good
/// content lands.
#[tokio::test]
async fn publish_repairs_a_broken_on_disk_set() {
    let tmp = TmpDir::new();
    // Comment-only ⇒ empty policy set ⇒ "broken/recovered".
    std::fs::write(
        tmp.0.join("00-broken.cedar"),
        "// no policies — broken deploy\n",
    )
    .unwrap();
    let store = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    // The pointer sits at a previous-good hash that differs from the broken
    // disk, so a CAS keyed on the broken disk WOULD lose.
    *store.pointer.lock().unwrap() = Some("previous-good-hash".to_owned());
    let shared: SharedPolicyStore = store.clone();
    let app = api_router(state_with_policies_dir(Some(shared), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the repair publish must succeed (bypass the turnstile), not 409",
    );
    let live = live_policy_text(&tmp.0);
    assert!(
        live.contains("permit") && live.contains("v9"),
        "the good draft must have repaired the on-disk set; got {live:?}",
    );
}

/// Publishing a non-draft must be refused BEFORE any disk mirror or ledger
/// write (409), so disk can never drift ahead of the ledger on a no-op publish.
#[tokio::test]
async fn publish_non_draft_is_conflict_and_does_not_touch_disk() {
    let tmp = TmpDir::new();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        get_status: PolicyStatus::Published,
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(
        !tmp.0.join("00-published.cedar").exists(),
        "a refused publish must not write to disk",
    );
}

// ---------------------------------------------------------------------------
// Policy tests as publish gates.
//
// These exercise the gate through the real handler with the in-memory
// `FakePolicyStore` (no DB needed): `get_tests`/`get_content` attach the gate
// cases and the draft's Cedar so the gate can be driven pass/block. The
// keep-prior-set contract is asserted at the on-disk source-of-truth layer (the
// existing `state_with_policies_dir` harness), since that IS what the gate loads.
// ---------------------------------------------------------------------------

/// A draft that permits everything — every simulated request allows.
const PERMIT_ALL: &str = "permit(principal, action, resource);";

/// A POST with a chosen scope set (the simulate/run_tests surface accepts
/// `mcp:observe`, with `mcp:admin` satisfying it too).
fn post_with_scopes(uri: &str, body: &str, scopes: &[&str]) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    req.extensions_mut().insert(principal_with(scopes));
    req
}

/// One `PolicyTestCase` as wire JSON: a high-risk CallTool request asserting the
/// given decision.
fn test_case_json(name: &str, expect_decision: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "request": {
            "principal": { "sub": "alice" },
            "action": { "type": "call_tool", "name": "wire_money", "risk": "high" },
            "resource": {
                "type": "tool", "server": "bank", "name": "wire_money",
                "risk": "high", "side_effects": true
            }
        },
        "expect": { "decision": expect_decision }
    })
}

/// A draft with a PASSING attached test publishes: permit-all + expect allow ⇒
/// the gate passes and the bundle becomes active (mirrored to disk).
#[tokio::test]
async fn publish_with_passing_tests_succeeds() {
    let tmp = TmpDir::new();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        get_content: Some(PERMIT_ALL.to_owned()),
        get_tests: Some(serde_json::json!([test_case_json(
            "allows the call",
            "allow"
        )])),
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a draft whose attached tests pass must publish",
    );
    let published = std::fs::read_to_string(tmp.0.join("00-published.cedar")).unwrap();
    assert!(
        published.contains("permit(principal, action, resource)"),
        "the passing draft must be mirrored to disk; got {published:?}",
    );
}

/// THE KEY SECURITY TEST. A prior published set is live on disk. A new draft
/// whose attached test FAILS (permit-all but the operator asserts the high-risk
/// call must be DENIED) must have its publish REJECTED (4xx), and the PRIOR
/// on-disk set must be kept untouched — the gate runs BEFORE the irreversible
/// disk mirror, so a failing test can never let the write happen.
#[tokio::test]
async fn publish_with_failing_tests_is_rejected_and_keeps_prior_set() {
    let tmp = TmpDir::new();
    // The prior published set, live on disk (the source of truth the gate loads).
    std::fs::write(
        tmp.0.join("10-prior.cedar"),
        "forbid(principal, action, resource); // prior set\n",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        // Draft permits everything, but the attached test asserts the high-risk
        // call must be DENIED → the gate must block.
        get_content: Some(PERMIT_ALL.to_owned()),
        get_tests: Some(serde_json::json!([test_case_json(
            "high-risk call must be denied",
            "deny"
        )])),
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    // The publish is rejected with a 4xx (422 — the draft is well-formed and
    // authorized, but its own assertions fail).
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a failing policy test must reject the publish with a 4xx",
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("high-risk call must be denied"),
        "the rejection must name the failing case; got {body:?}",
    );
    // KEEP-PRIOR-SET CONTRACT: the gate ran BEFORE the disk mirror, so the prior
    // on-disk set is untouched and the draft was NOT written.
    let live = live_policy_text(&tmp.0);
    assert!(
        live.contains("prior set"),
        "the prior published set must remain live on disk; got {live:?}",
    );
    assert!(
        !tmp.0.join("00-published.cedar").exists(),
        "a gated-out publish must not write the machine-owned published file",
    );
    assert!(
        !live.contains("permit(principal, action, resource)"),
        "the failing draft's content must NOT have reached disk; got {live:?}",
    );
}

/// The `run_tests` endpoint returns a report with the right pass/fail counts and
/// does NOT publish. Gated on `mcp:observe` (read-only).
#[tokio::test]
async fn run_tests_returns_report_with_counts() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        get_content: Some(PERMIT_ALL.to_owned()),
        // One passing case (expect allow under permit-all) + one failing case
        // (expect deny under permit-all).
        get_tests: Some(serde_json::json!([
            test_case_json("allows", "allow"),
            test_case_json("should deny but allows", "deny"),
        ])),
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(post_with_scopes(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/run_tests",
            "{}",
            &["mcp:observe"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["total"], 2);
    assert_eq!(report["passed"], 1);
    assert_eq!(report["failed"], 1);
    assert_eq!(report["all_passed"], false);
    // The failing case carries a detail + trace; the passing one does not.
    let results = report["results"].as_array().unwrap();
    let failing = results.iter().find(|r| r["passed"] == false).unwrap();
    assert_eq!(failing["name"], "should deny but allows");
    assert!(failing["detail"]
        .as_str()
        .unwrap()
        .contains("expected deny"));
}

/// `run_tests` is read-only: `mcp:read` is insufficient (403), and a draft with
/// no attached tests reports a vacuous all-passed report.
#[tokio::test]
async fn run_tests_scope_and_empty_report() {
    // mcp:read is below the mcp:observe gate → 403.
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(post_with_scopes(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/run_tests",
            "{}",
            &["mcp:read"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // A draft with no attached tests → 200 with a vacuous all-passed report.
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        get_content: Some(PERMIT_ALL.to_owned()),
        get_tests: None,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(post_with_scopes(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/run_tests",
            "{}",
            &["mcp:observe"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["total"], 0);
    assert_eq!(report["all_passed"], true);
}

/// A draft with a malformed stored tests blob fails CLOSED at the publish gate:
/// the publish is refused (422) and the prior on-disk set is kept — a corrupt
/// test blob must never be silently treated as "no tests, publish freely".
#[tokio::test]
async fn publish_with_malformed_tests_blob_fails_closed() {
    let tmp = TmpDir::new();
    std::fs::write(
        tmp.0.join("10-prior.cedar"),
        "forbid(principal, action, resource); // prior\n",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        get_content: Some(PERMIT_ALL.to_owned()),
        // Not a [PolicyTestCase] array — a stored blob that can't deserialize.
        get_tests: Some(serde_json::json!({"garbage": "not a test array"})),
        ..Default::default()
    });
    let app = api_router(state_with_policies_dir(Some(store), tmp.0.clone()).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a malformed stored test blob must fail closed (refuse the publish)",
    );
    assert!(
        !tmp.0.join("00-published.cedar").exists(),
        "a fail-closed publish must not write to disk",
    );
    let live = live_policy_text(&tmp.0);
    assert!(
        live.contains("prior"),
        "the prior set must be kept on a fail-closed publish; got {live:?}",
    );
}

#[tokio::test]
async fn blocked_publish_by_malformed_tests_records_denied_audit() {
    // A publish blocked by a malformed/tampered stored test
    // blob must be AUDITED (Denied), not silently refused — the malformed path
    // must not return its 422 before reaching any audit. A corrupt tests
    // blob blocking a publish is security-relevant evidence.
    let tmp = TmpDir::new();
    std::fs::write(
        tmp.0.join("10-prior.cedar"),
        "forbid(principal, action, resource);\n",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        get_content: Some(PERMIT_ALL.to_owned()),
        // A blob that is not a [PolicyTestCase] array — deserialize fails.
        get_tests: Some(serde_json::json!({"garbage": "not a test array"})),
        ..Default::default()
    });
    let recorder = Arc::new(CapturingRecorder::default());
    let evidence: SharedEvidence = recorder.clone();
    let app = api_router(
        state_with_policies_dir_and_evidence(Some(store), tmp.0.clone(), evidence).await,
    );
    let resp = app
        .oneshot(admin_post(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let events = recorder.events.lock().unwrap();
    let blocked_index = events
        .iter()
        .position(|e| e.action == "policy_bundle.publish")
        .expect("the blocked publish must emit a policy_bundle.publish audit row");
    let blocked = &events[blocked_index];
    assert_eq!(
        blocked.outcome,
        AuditOutcome::Denied,
        "a gated-out publish must be audited as Denied, not Success",
    );
    assert!(
        blocked
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("malformed"),
        "the audit reason must name why the publish was blocked; got {:?}",
        blocked.reason,
    );
    assert_eq!(
        recorder.postures.lock().unwrap()[blocked_index],
        EvidencePosture::ChainedBestEffort,
        "a blocked security validation must extend the evidence chain"
    );
}

#[tokio::test]
async fn dashboard_publish_also_enforces_the_gate_and_keeps_prior_set() {
    // The DASHBOARD publish path must run the policy-test gate
    // too — a draft with failing tests (created via the API) must not be
    // promotable from the dashboard by bypassing the gate and auditing as
    // Success. It routes through the shared `publish_bundle_core`, so this
    // regression proves a failing-test draft is blocked from the dashboard
    // surface too and the prior on-disk set is kept.
    let tmp = TmpDir::new();
    std::fs::write(
        tmp.0.join("10-prior.cedar"),
        "forbid(principal, action, resource); // prior set\n",
    )
    .unwrap();
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        // Draft permits everything, but the attached test asserts DENY → block.
        get_content: Some(PERMIT_ALL.to_owned()),
        get_tests: Some(serde_json::json!([test_case_json(
            "high-risk call must be denied",
            "deny"
        )])),
        ..Default::default()
    });
    let app = dashboard_router(
        state_with_policies_dir(Some(store), tmp.0.clone()).await,
        DashboardAuth::Disabled,
    );
    // Dashboard form POST — `DashboardAuth::Disabled` injects the admin
    // principal + the `dev-csrf` token the handler checks.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policy_bundles/00000000-0000-0000-0000-000000000000/publish")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=dev-csrf"))
                .unwrap(),
        )
        .await
        .unwrap();
    // PRG redirect either way; the contract is the DISK state, not the status.
    assert!(
        resp.status().is_redirection() || resp.status().is_success(),
        "the dashboard publish is a PRG redirect; got {}",
        resp.status()
    );
    // KEEP-PRIOR-SET via the dashboard path: the gate ran inside
    // `publish_bundle_core` before the mirror, so the prior set is untouched.
    let live = live_policy_text(&tmp.0);
    assert!(
        live.contains("prior set"),
        "a failing-test draft published via the dashboard must keep the prior set; got {live:?}",
    );
    assert!(
        !tmp.0.join("00-published.cedar").exists(),
        "the gated-out dashboard publish must not write the published file",
    );
    assert!(
        !live.contains("permit(principal, action, resource)"),
        "the failing draft's content must NOT reach disk via the dashboard path; got {live:?}",
    );
}

// ---------------------------------------------------------------------------
// Exact decision replay / impact analysis.
//
// `POST /api/v1/policy_bundles/{id}/preview_impact` (REST, mcp:observe) and the
// dashboard "Preview impact" action replay the tenant's recent recorded
// decisions against a draft and report the blast radius. These pin the
// behavioral contract through the real handlers with the in-memory store + an
// in-memory audit reader: a draft whose content flips a recorded decision must
// surface the transition, and non-replayable rows (legacy / model) must be
// excluded from the replayed count, not evaluated.
// ---------------------------------------------------------------------------

use waygate_storage::{
    AuditFacets, AuditQuery, AuditReader, AuditRow, ChainVerifyReport, ChainVerifyStatus,
    HistogramBucket, ToolStat,
};

/// Minimal in-memory audit reader: the impact endpoint only calls
/// `query_events`, so that's the one method with real behaviour (tenant +
/// decision-category + `pre_call` filtering via `AuditQuery::matches`); the rest
/// of the trait is stubbed to the empty result so the fake satisfies the
/// `AuditReader` bound.
struct MemoryAudit {
    rows: Vec<AuditRow>,
}

#[async_trait]
impl AuditReader for MemoryAudit {
    async fn recent_notable(
        &self,
        tenant: &str,
        since: time::OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        let mut rows: Vec<_> = self
            .rows
            .iter()
            .filter(|r| {
                r.tenant_id == tenant
                    && r.ts >= since
                    && r.outcome != "success"
                    && r.reason.as_deref() != Some("pre_call")
            })
            .cloned()
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse((r.ts, r.id)));
        rows.truncate(limit.clamp(1, 500) as usize);
        Ok(rows)
    }

    async fn recent_events(
        &self,
        _limit: i64,
        _after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        Ok(self.rows.clone())
    }

    async fn query_events(
        &self,
        query: &AuditQuery,
        limit: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        let limit = limit.clamp(1, 500) as usize;
        Ok(self
            .rows
            .iter()
            .filter(|r| match after_id {
                Some(a) => r.id < a,
                None => true,
            })
            .filter(|r| query.matches(r))
            .take(limit)
            .cloned()
            .collect())
    }

    async fn facet_counts(&self, _query: &AuditQuery) -> Result<AuditFacets, sqlx::Error> {
        Ok(AuditFacets {
            outcome: vec![],
            risk: vec![],
            category: vec![],
            pii: vec![],
            server: vec![],
        })
    }

    async fn tool_stats(
        &self,
        _query: &AuditQuery,
        _limit: i64,
    ) -> Result<Vec<ToolStat>, sqlx::Error> {
        Ok(vec![])
    }

    async fn histogram(
        &self,
        _query: &AuditQuery,
        _bucket_seconds: i64,
    ) -> Result<Vec<HistogramBucket>, sqlx::Error> {
        Ok(vec![])
    }

    async fn fetch_event(&self, id: Uuid) -> Result<Option<AuditRow>, sqlx::Error> {
        Ok(self.rows.iter().find(|r| r.id == id).cloned())
    }

    async fn count_events_by_sub_since(
        &self,
        _sub: &str,
        _since: time::OffsetDateTime,
        _exclude_issuer: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        Ok(0)
    }

    async fn verify_chain(
        &self,
        tenant_id: &str,
        from: Option<time::OffsetDateTime>,
        to: Option<time::OffsetDateTime>,
        _after_chain_seq: Option<i64>,
        _limit: i64,
    ) -> Result<ChainVerifyReport, sqlx::Error> {
        Ok(ChainVerifyReport {
            tenant_id: tenant_id.to_owned(),
            from,
            to,
            rows_walked: 0,
            status: ChainVerifyStatus::Empty,
            first_mismatch: None,
            truncated: false,
            next_after_chain_seq: None,
            chain_head: None,
        })
    }

    async fn fetch_events_for_bundle(
        &self,
        _tenant_id: &str,
        _from: time::OffsetDateTime,
        _to: time::OffsetDateTime,
        _principal_sub: Option<&str>,
        _tool: Option<&str>,
        _limit: i64,
    ) -> Result<(Vec<AuditRow>, bool), sqlx::Error> {
        Ok((Vec::new(), false))
    }
}

/// A replayable recorded tool-call decision (`auth_method` set, so the
/// replay engine can reconstruct the original request). `outcome` selects the
/// recorded verdict; `risk` selects the tool's risk tier.
fn replayable_decision(outcome: &str, risk: &str) -> AuditRow {
    AuditRow {
        operation: None,
        id: Uuid::now_v7(),
        ts: time::OffsetDateTime::UNIX_EPOCH,
        category: Some("invocation".into()),
        tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
        action: "CallTool".into(),
        outcome: outcome.into(),
        principal_sub: Some("alice@example.com".into()),
        principal_email: Some("alice@example.com".into()),
        principal_groups: vec!["mcp-users".into()],
        issuer: Some("https://auth.example.com".into()),
        server: Some("bank".into()),
        tool: Some("wire_money".into()),
        risk_level: Some(risk.into()),
        pii: Some(false),
        policy_ids: vec!["baseline".into()],
        reason: None,
        trace_id: None,
        latency_ms: Some(7),
        scim_active: None,
        scim_groups: Vec::new(),
        target: None,
        req_scopes: vec!["mcp:invoke".into()],
        auth_method: Some("oauth".into()),
        req_roles: vec![],
        side_effects: Some(true),
        invocation_hierarchy: None,
    }
}

/// A legacy (pre-0062) decision row: no `auth_method`, so NOT replayable.
fn legacy_decision(outcome: &str) -> AuditRow {
    let mut r = replayable_decision(outcome, "low");
    r.auth_method = None;
    r.req_scopes = Vec::new();
    r.req_roles = Vec::new();
    r.side_effects = None;
    r
}

/// A draft that permits everything but FORBIDS high-risk tool calls — flips a
/// recorded high-risk ALLOW to a candidate DENY.
const FORBID_HIGH: &str = "@id(\"baseline\")\n\
     permit(principal, action, resource);\n\
     @id(\"forbid-high\")\n\
     forbid(principal, action == Action::\"CallTool\", resource)\n\
     when { resource.risk == \"high\" };";

/// Wire an `AdminState` with both a policy store (for the draft) and an audit
/// reader (for the recorded decisions) — the impact endpoint needs both.
async fn state_with_store_and_audit(
    store: SharedPolicyStore,
    rows: Vec<AuditRow>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
    Arc::new(
        AdminState::new(
            pool,
            None,
            Some(audit),
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_policy_store(Some(store)),
    )
}

/// The headline impact-preview test. A draft whose content (FORBID_HIGH) would
/// flip a recorded high-risk ALLOW to DENY must surface the `allow → deny` transition,
/// count the flip as `changed`, and EXCLUDE a non-replayable legacy row from the
/// replayed set (counting it `not_replayable` instead).
#[tokio::test]
async fn preview_impact_reports_the_flip_and_excludes_non_replayable() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        // The draft the endpoint replays against: forbids high-risk calls.
        get_content: Some(FORBID_HIGH.to_owned()),
        ..Default::default()
    });
    // Recorded decisions: a high-risk ALLOW (flips under the draft) + a legacy
    // row (no captured inputs → not replayable).
    let rows = vec![
        replayable_decision("success", "high"),
        legacy_decision("denied"),
    ];
    let app = api_router(state_with_store_and_audit(store, rows).await);
    let resp = app
        .oneshot(post_with_scopes(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/preview_impact",
            "{}",
            &["mcp:observe"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(report["considered"], 2, "both recorded rows considered");
    assert_eq!(
        report["replayed"], 1,
        "only the row with auth_method set replays"
    );
    assert_eq!(report["changed"], 1, "the high-risk allow flips to deny");
    assert_eq!(report["unchanged"], 0);
    assert_eq!(
        report["not_replayable"], 1,
        "the legacy row is excluded, not evaluated",
    );
    // The transition is named in the deltas.
    let deltas = report["deltas"].as_array().unwrap();
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0]["from"], "allow");
    assert_eq!(deltas[0]["to"], "deny");
    assert_eq!(deltas[0]["count"], 1);
    // A changed-decision sample names the call.
    let samples = report["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0]["recorded"], "allow");
    assert_eq!(samples[0]["candidate"], "deny");
    assert_eq!(samples[0]["server_tool"], "bank.wire_money");
}

/// Read-only gate: `mcp:read` is below the `mcp:observe` gate (403). And the
/// endpoint 503s without an audit store (it needs the recorded decisions).
#[tokio::test]
async fn preview_impact_scope_and_missing_audit() {
    // mcp:read → 403.
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with_store_and_audit(store, vec![]).await);
    let resp = app
        .oneshot(post_with_scopes(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/preview_impact",
            "{}",
            &["mcp:read"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Store wired but NO audit reader → 503 (the impact view needs both).
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(post_with_scopes(
            "/api/v1/policy_bundles/00000000-0000-0000-0000-000000000000/preview_impact",
            "{}",
            &["mcp:observe"],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// The dashboard "Preview impact" action re-renders the page with a
/// blast-radius panel naming the transition. Routes through the same shared
/// core, so the HTML must name the `allow → deny` flip and exclude the
/// non-replayable row.
#[tokio::test]
async fn dashboard_preview_impact_renders_blast_radius_panel() {
    let store: SharedPolicyStore = Arc::new(FakePolicyStore {
        present: true,
        get_content: Some(FORBID_HIGH.to_owned()),
        ..Default::default()
    });
    let rows = vec![
        replayable_decision("success", "high"),
        legacy_decision("denied"),
    ];
    let app = dashboard_router(
        state_with_store_and_audit(store, rows).await,
        DashboardAuth::Disabled,
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policy_bundles/00000000-0000-0000-0000-000000000000/preview_impact")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=dev-csrf"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    // The panel renders and names the transition + counts.
    assert!(
        html.contains("Preview impact"),
        "the blast-radius panel must render",
    );
    assert!(
        html.contains("allow → deny"),
        "the panel must name the flipped transition; got body without it",
    );
    assert!(
        html.contains("1 would change"),
        "the panel must report the changed count",
    );
    assert!(
        html.contains("1 not replayable"),
        "the panel must report the excluded (non-replayable) count",
    );
    // The provenance note must be prominent — the operator must not read the
    // replay as the complete decision history.
    assert!(
        html.contains("not the complete decision history"),
        "the panel must note the replay is a sample, not the full history",
    );
}
