//! Route-level coverage for the `/api/v1/server_manifests/*` admin
//! endpoints. Uses an in-memory `ManifestStore` fake so the test
//! doesn't need a live Postgres pool (the Pg impl is exercised by the
//! `waygate-manifest-store` smoke test). Ported from
//! `policy_bundles_api.rs`.
//!
//! Pins:
//! 1. `None` store ⇒ every store-backed endpoint 503 (DB-less deployment).
//! 2. `mcp:read` is insufficient; `mcp:admin` succeeds.
//! 3. With a store wired: list returns rows, active returns the bundle,
//!    validate parses without persisting, create returns 201 (and rejects
//!    empty / unparseable / duplicate-name sets), publish + rollback
//!    return 200/404, and both emit AdminMutation evidence.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::util::ServiceExt;

use uuid::Uuid;
use waygate_admin::{api_router, AdminState};
use waygate_manifest_store::{
    content_hash, ManifestBundle, ManifestBundleSummary, ManifestError, ManifestStatus,
    ManifestStore, SharedManifestStore,
};
use waygate_mcp::audit::{
    AuditEvent, EvidenceCategory, EvidenceError, EvidenceRecorder, SharedEvidence,
};
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;

/// A valid manifest-set YAML document (one upstream) for the given
/// version — the form `parse_manifest_set` accepts.
fn manifest_yaml(version: i32) -> String {
    format!("- name: u{version}\n  transport: http\n  url: http://u{version}/mcp\n")
}

/// In-memory manifest-store fake. `present` toggles whether
/// `active_bundle` / `publish` / `rollback_to` find a bundle; `cas_lost`
/// drives the turnstile `cas_pointer` to report a lost race (another replica
/// wrote first), exercising the REST 409 refusal path; `cas_store_err` makes
/// `cas_pointer` fail with a backing-store error, which must map to 500 (not
/// 409) so a DB outage isn't reported as a retryable conflict.
///
/// By default the draft (`get`) is a DIFFERENT version (v9) than the published
/// `active_bundle` (v3) the `servers_dir` is seeded from, so publish is a real
/// change that exercises the turnstile CAS. `draft_matches_disk` makes `get`
/// return v3 instead — content identical to disk — to drive the no-op
/// `AlreadyCurrent` refusal (422) path.
#[derive(Default)]
struct FakeManifestStore {
    summaries: Vec<ManifestBundleSummary>,
    present: bool,
    cas_lost: bool,
    cas_store_err: bool,
    draft_matches_disk: bool,
}

fn sample_bundle(version: i32, status: ManifestStatus) -> ManifestBundle {
    let content = manifest_yaml(version);
    let published_at = match status {
        ManifestStatus::Draft => None,
        _ => Some(time::OffsetDateTime::UNIX_EPOCH),
    };
    ManifestBundle {
        id: Uuid::nil(),
        tenant_id: "default".into(),
        version,
        status,
        content_hash: content_hash(&content),
        content,
        author: Some("alice".into()),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        published_at,
        published_by: None,
    }
}

#[async_trait]
impl ManifestStore for FakeManifestStore {
    async fn active_bundle(&self, _tenant: &str) -> Result<ManifestBundle, ManifestError> {
        if self.present {
            Ok(sample_bundle(3, ManifestStatus::Published))
        } else {
            Err(ManifestError::NotFound(
                "no published manifest bundle for tenant",
            ))
        }
    }
    async fn list_bundles(
        &self,
        _tenant: &str,
    ) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
        Ok(self.summaries.clone())
    }
    async fn get(&self, _tenant: &str, _id: Uuid) -> Result<ManifestBundle, ManifestError> {
        if self.present {
            // A draft: the publish path fetches the target with `get` and
            // verifies it is a draft before mirroring. By default
            // it's a DIFFERENT version (v9) than the disk-seeded active set (v3)
            // so publish is a real change and the turnstile CAS runs; with
            // `draft_matches_disk` it matches disk (v3) to drive the no-op path.
            let version = if self.draft_matches_disk { 3 } else { 9 };
            Ok(sample_bundle(version, ManifestStatus::Draft))
        } else {
            Err(ManifestError::NotFound(
                "no manifest bundle with that id in tenant",
            ))
        }
    }
    async fn get_by_version(
        &self,
        _tenant: &str,
        version: i32,
    ) -> Result<ManifestBundle, ManifestError> {
        if self.present {
            Ok(sample_bundle(version, ManifestStatus::Published))
        } else {
            Err(ManifestError::NotFound(
                "no previously-published manifest bundle at that version in tenant",
            ))
        }
    }
    async fn create_draft(
        &self,
        _tenant: &str,
        content: &str,
        author: Option<&str>,
    ) -> Result<ManifestBundle, ManifestError> {
        Ok(ManifestBundle {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            version: 9,
            status: ManifestStatus::Draft,
            content_hash: content_hash(content),
            content: content.to_owned(),
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
    ) -> Result<ManifestBundle, ManifestError> {
        if self.present {
            let mut b = sample_bundle(9, ManifestStatus::Published);
            b.published_by = Some(publisher.to_owned());
            Ok(b)
        } else {
            Err(ManifestError::NotFound(
                "no draft manifest bundle with that id",
            ))
        }
    }
    async fn rollback_to(
        &self,
        _tenant: &str,
        _version: i32,
        actor: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        if self.present {
            let mut b = sample_bundle(10, ManifestStatus::Published);
            b.published_by = Some(actor.to_owned());
            Ok(b)
        } else {
            Err(ManifestError::NotFound(
                "no published manifest bundle at that version in tenant",
            ))
        }
    }
    async fn delete_all_for_tenant(&self, _tenant: &str) -> Result<u64, ManifestError> {
        Ok(0)
    }
    async fn read_pointer(
        &self,
        _t: &str,
    ) -> Result<Option<waygate_manifest_store::ManifestPointer>, ManifestError> {
        Ok(None)
    }
    async fn seed_pointer(&self, _t: &str, _hash: &str) -> Result<(), ManifestError> {
        Ok(())
    }
    async fn cas_pointer(
        &self,
        _t: &str,
        _expected: &str,
        _new: &str,
        _actor: &str,
    ) -> Result<waygate_manifest_store::TurnstileOutcome, ManifestError> {
        if self.cas_store_err {
            return Err(ManifestError::UnknownStatus(
                "simulated store failure".into(),
            ));
        }
        Ok(if self.cas_lost {
            waygate_manifest_store::TurnstileOutcome::Lost
        } else {
            waygate_manifest_store::TurnstileOutcome::Won
        })
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

async fn state_with(store: Option<SharedManifestStore>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Wire a real on-disk servers_dir seeded from the store's active bundle, so
    // the publish/rollback turnstile actually runs (`turnstile_cas` skips the
    // CAS entirely when no servers_dir is wired — without this the REST Won/Lost
    // paths would never be exercised).
    let servers_dir = match &store {
        Some(s) => s
            .active_bundle(waygate_core::TenantId::DEFAULT)
            .await
            .ok()
            .and_then(|b| {
                let dir = std::env::temp_dir().join(format!("mbtest-servers-{}", Uuid::new_v4()));
                std::fs::create_dir_all(&dir).ok()?;
                let set = waygate_upstream::parse_manifest_set(&b.content).ok()?;
                waygate_upstream::write_manifest_set_to_dir(&dir, &set).ok()?;
                Some(dir)
            }),
        None => None,
    };
    let mut st = AdminState::new(
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
    .with_manifest_store(store);
    if let Some(dir) = servers_dir {
        st = st.with_servers_dir(dir);
    }
    Arc::new(st)
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

#[tokio::test]
async fn endpoints_503_without_store() {
    // validate is intentionally excluded — it never touches the store, so
    // it does not 503.
    for (method, uri, body) in [
        ("GET", "/api/v1/server_manifests", None),
        ("GET", "/api/v1/server_manifests/active", None),
        (
            "POST",
            "/api/v1/server_manifests",
            Some(r#"{"content":"- name: a\n  transport: http\n  url: http://a/mcp\n"}"#),
        ),
        (
            "POST",
            "/api/v1/server_manifests/00000000-0000-0000-0000-000000000000/publish",
            Some("{}"),
        ),
        ("POST", "/api/v1/server_manifests/2/rollback", Some("{}")),
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
    let store: SharedManifestStore = Arc::new(FakeManifestStore::default());
    let app = api_router(state_with(Some(store)).await);

    // No principal → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/server_manifests")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // mcp:read insufficient → 403.
    let mut req = Request::builder()
        .uri("/api/v1/server_manifests")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_returns_summaries() {
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
        summaries: vec![ManifestBundleSummary {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            version: 2,
            status: ManifestStatus::Published,
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
        .oneshot(admin_get("/api/v1/server_manifests"))
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
    let present: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(present)).await);
    let resp = app
        .oneshot(admin_get("/api/v1/server_manifests/active"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Absent ⇒ 404 (NotFound mapped).
    let absent: SharedManifestStore = Arc::new(FakeManifestStore::default());
    let app = api_router(state_with(Some(absent)).await);
    let resp = app
        .oneshot(admin_get("/api/v1/server_manifests/active"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn validate_accepts_valid_set() {
    // validate doesn't touch the store; a None store is fine.
    let app = api_router(state_with(None).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/validate",
            r#"{"content":"- name: a\n  transport: http\n  url: http://a/mcp\n"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["upstream_count"], 1);
}

#[tokio::test]
async fn validate_rejects_unparseable() {
    let app = api_router(state_with(None).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/validate",
            r#"{"content":"this is not valid manifest yaml: [[["}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn validate_rejects_duplicate_names() {
    // A set naming the same upstream twice is ambiguous and rejected.
    let app = api_router(state_with(None).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/validate",
            r#"{"content":"- name: dup\n  transport: http\n  url: http://a/mcp\n- name: dup\n  transport: http\n  url: http://b/mcp\n"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_draft_returns_201() {
    let store: SharedManifestStore = Arc::new(FakeManifestStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests",
            r#"{"content":"- name: example-messages\n  transport: http\n  url: http://example-messages/mcp\n","author":"alice"}"#,
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

#[tokio::test]
async fn create_draft_rejects_empty_content() {
    let store: SharedManifestStore = Arc::new(FakeManifestStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests",
            r#"{"content":"   "}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_draft_rejects_invalid_set() {
    // A set that doesn't parse must be rejected at draft time so a
    // published bundle is always loadable by boot/SIGHUP.
    let store: SharedManifestStore = Arc::new(FakeManifestStore::default());
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests",
            r#"{"content":"this is not valid manifest yaml: [[["}"#,
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
}

#[async_trait]
impl EvidenceRecorder for CapturingRecorder {
    async fn record_required(&self, e: AuditEvent) -> Result<Uuid, EvidenceError> {
        let id = e.id;
        self.events.lock().unwrap().push(e);
        Ok(id)
    }
    async fn record_chained_best_effort(&self, e: AuditEvent) {
        self.events.lock().unwrap().push(e);
    }
    async fn record_best_effort(&self, e: AuditEvent) {
        self.events.lock().unwrap().push(e);
    }
}

#[tokio::test]
async fn create_and_publish_emit_admin_mutation_evidence() {
    // Manifest draft/publish are operationally-relevant mutations and
    // must be auditable, like the other mutating admin endpoints.
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
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
        .with_manifest_store(Some(store)),
    );
    let app = api_router(state);

    app.clone()
        .oneshot(admin_post(
            "/api/v1/server_manifests",
            r#"{"content":"- name: example-messages\n  transport: http\n  url: http://example-messages/mcp\n"}"#,
        ))
        .await
        .unwrap();
    app.oneshot(admin_post(
        "/api/v1/server_manifests/00000000-0000-0000-0000-000000000000/publish",
        "{}",
    ))
    .await
    .unwrap();

    let events = recorder.events.lock().unwrap();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert!(
        actions.contains(&"server_manifest.create_draft"),
        "create must emit evidence; got {actions:?}",
    );
    assert!(
        actions.contains(&"server_manifest.publish"),
        "publish must emit evidence; got {actions:?}",
    );
    assert!(
        events
            .iter()
            .all(|e| matches!(e.category, EvidenceCategory::AdminMutation)),
        "manifest mutations must be categorized AdminMutation",
    );
}

#[tokio::test]
async fn rollback_returns_200_or_404() {
    // Present ⇒ 200 (target version re-published as new active bundle).
    let present: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(present)).await);
    let resp = app
        .oneshot(admin_post("/api/v1/server_manifests/2/rollback", "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Absent target version ⇒ 404.
    let absent: SharedManifestStore = Arc::new(FakeManifestStore::default());
    let app = api_router(state_with(Some(absent)).await);
    let resp = app
        .oneshot(admin_post("/api/v1/server_manifests/2/rollback", "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn publish_returns_200_or_404() {
    // Present ⇒ 200, records publisher.
    let present: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(present)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Absent draft ⇒ 404.
    let absent: SharedManifestStore = Arc::new(FakeManifestStore::default());
    let app = api_router(state_with(Some(absent)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn publish_turnstile_lost_returns_409() {
    // Another replica advanced the on-disk config since this draft's base: the
    // turnstile CAS loses, so publish must refuse with 409 Conflict and never
    // reach the ledger (fail-closed). `present:true` wires a servers_dir so the
    // CAS path actually runs (it is skipped when no servers_dir is configured).
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        cas_lost: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "a lost turnstile CAS must surface as 409, not 200/500",
    );
}

#[tokio::test]
async fn rollback_turnstile_lost_returns_409() {
    // Same contract for rollback: a lost CAS refuses with 409 before the ledger
    // transition, so a concurrent write is never silently clobbered.
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        cas_lost: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post("/api/v1/server_manifests/2/rollback", "{}"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "a lost turnstile CAS must surface as 409, not 200/500",
    );
}

#[tokio::test]
async fn publish_turnstile_store_error_returns_500_not_409() {
    // A backing-store failure inside the turnstile (seed/cas) is NOT the
    // client's to retry — it must surface as 500, not a 409 that tells the
    // client to "reload and retry" a conflict that doesn't exist.
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        cas_store_err: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a turnstile store failure must be 500, not 409",
    );
}

#[tokio::test]
async fn publish_noop_returns_422_not_clobber() {
    // Publishing a draft whose content already equals the live on-disk set is a
    // no-op. It MUST be refused (422) rather than mirrored: a `cas_pointer(base,
    // base)` would falsely "win" without advancing the pointer, so mirroring the
    // identical content could clobber a concurrent real write — the lost-update
    // the turnstile exists to prevent. 422, not the 409 a lost CAS
    // uses, because there's no conflict to retry.
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        draft_matches_disk: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post(
            "/api/v1/server_manifests/00000000-0000-0000-0000-000000000000/publish",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a no-op publish (draft == live disk) must be 422, not 200/409",
    );
}

#[tokio::test]
async fn rollback_noop_returns_422_not_clobber() {
    // Rolling back to the version whose content already equals the live on-disk
    // set is the same no-op: the disk is seeded from active_bundle v3, so
    // rolling back to v3 matches disk and must be refused (422), not mirrored.
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
        present: true,
        ..Default::default()
    });
    let app = api_router(state_with(Some(store)).await);
    let resp = app
        .oneshot(admin_post("/api/v1/server_manifests/3/rollback", "{}"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a no-op rollback (target == live disk) must be 422, not 200",
    );
}
