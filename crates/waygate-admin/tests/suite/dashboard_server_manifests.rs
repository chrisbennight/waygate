//! Route-level tests for the server-manifests dashboard page.
//!
//! Complements the pure unit tests in the handler module
//! (`dashboard_server_manifests::tests`). Covers: the page renders with
//! store + versions, the empty/no-store state, the **dual-mount guard**
//! (publish/rollback POSTs on the tenant-scoped `/t/{tenant}/...` mount
//! must 303, not 500), CSRF
//! rejection, validate + save-draft, and the YAML export download.
//!
//! Uses an in-memory `ManifestStore` fake — no Postgres. `DashboardAuth::
//! Disabled` injects an admin OAuth principal + the `dev-csrf` token.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

use uuid::Uuid;
use waygate_admin::{dashboard_router, AdminState, DashboardAuth};
use waygate_manifest_store::{
    content_hash, ManifestBundle, ManifestBundleSummary, ManifestError, ManifestStatus,
    ManifestStore, SharedManifestStore,
};
use waygate_upstream::pool::UpstreamPool;

const DRAFT_ID: &str = "00000000-0000-0000-0000-0000000000d2";
const PUB_ID: &str = "00000000-0000-0000-0000-0000000000f1";

fn yaml(v: i32) -> String {
    format!("- name: u{v}\n  transport: http\n  url: http://u{v}/mcp\n")
}

/// Fake with a fixed two-version history: a publishable draft (v2) and a
/// published-current (v1). `active_bundle` / `get` / `publish` /
/// `rollback_to` return Ok so the mutation handlers reach their 303
/// redirect (the point of the dual-mount guard test).
#[derive(Default)]
struct FakeManifestStore {
    /// When true, `cas_pointer` returns `Lost` — simulating another replica
    /// having advanced the turnstile, to exercise the publish/rollback refusal.
    /// Default `false` (no contention).
    cas_lost: bool,
    /// When true, `get` returns a PUBLISHED bundle (not a draft) — to exercise
    /// the publish draft-only guard refusing a non-draft id before any disk
    /// write. Default `false` (a draft, the publishable case).
    get_published: bool,
    /// Fleet heartbeats returned by `list_replica_heartbeats`.
    /// Default empty (the roll-up renders its empty state).
    heartbeats: Vec<waygate_manifest_store::ReplicaHeartbeat>,
}

fn summary(
    id_tail: &str,
    version: i32,
    status: ManifestStatus,
    published_at: Option<time::OffsetDateTime>,
) -> ManifestBundleSummary {
    ManifestBundleSummary {
        id: format!("00000000-0000-0000-0000-0000000000{id_tail}")
            .parse()
            .unwrap(),
        tenant_id: "default".into(),
        version,
        status,
        content_hash: content_hash(&yaml(version)),
        author: Some("alice".into()),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        published_at,
        published_by: published_at.map(|_| "alice".into()),
    }
}

fn full(version: i32, status: ManifestStatus) -> ManifestBundle {
    let content = yaml(version);
    ManifestBundle {
        id: Uuid::nil(),
        tenant_id: "default".into(),
        version,
        status,
        content_hash: content_hash(&content),
        content,
        author: None,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        published_at: match status {
            ManifestStatus::Draft => None,
            _ => Some(time::OffsetDateTime::UNIX_EPOCH),
        },
        published_by: None,
    }
}

#[async_trait]
impl ManifestStore for FakeManifestStore {
    async fn active_bundle(&self, _tenant: &str) -> Result<ManifestBundle, ManifestError> {
        Ok(full(1, ManifestStatus::Published))
    }
    async fn list_bundles(
        &self,
        _tenant: &str,
    ) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
        // Newest first (the store orders version DESC). Three versions so
        // every action renders: v3 draft (publishable), v2 published-and-
        // current (most recent publish), v1 published-but-older
        // (rollback-eligible).
        let t0 = time::OffsetDateTime::UNIX_EPOCH;
        let t1 = t0 + time::Duration::hours(1);
        Ok(vec![
            summary("03", 3, ManifestStatus::Draft, None),
            summary("02", 2, ManifestStatus::Published, Some(t1)),
            summary("01", 1, ManifestStatus::Published, Some(t0)),
        ])
    }
    async fn get(&self, _tenant: &str, _id: Uuid) -> Result<ManifestBundle, ManifestError> {
        if self.get_published {
            Ok(full(2, ManifestStatus::Published))
        } else {
            Ok(full(2, ManifestStatus::Draft))
        }
    }
    async fn get_by_version(
        &self,
        _tenant: &str,
        version: i32,
    ) -> Result<ManifestBundle, ManifestError> {
        Ok(full(version, ManifestStatus::Published))
    }
    async fn create_draft(
        &self,
        _tenant: &str,
        content: &str,
        _author: Option<&str>,
    ) -> Result<ManifestBundle, ManifestError> {
        let mut b = full(3, ManifestStatus::Draft);
        b.content = content.to_owned();
        b.content_hash = content_hash(content);
        Ok(b)
    }
    async fn publish(
        &self,
        _tenant: &str,
        _id: Uuid,
        _publisher: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        Ok(full(2, ManifestStatus::Published))
    }
    async fn rollback_to(
        &self,
        _tenant: &str,
        _version: i32,
        _actor: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        Ok(full(3, ManifestStatus::Published))
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
        Ok(if self.cas_lost {
            waygate_manifest_store::TurnstileOutcome::Lost
        } else {
            waygate_manifest_store::TurnstileOutcome::Won
        })
    }
    async fn list_replica_heartbeats(
        &self,
        _t: &str,
    ) -> Result<Vec<waygate_manifest_store::ReplicaHeartbeat>, ManifestError> {
        Ok(self.heartbeats.clone())
    }
}

async fn state_with_manifest_store(store: Option<SharedManifestStore>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    // Disk-truth: export reads the on-disk set, so sync a servers_dir
    // from the store's active bundle when there is one (and it parses).
    let servers_dir = match &store {
        Some(s) => s
            .active_bundle(waygate_core::TenantId::DEFAULT)
            .await
            .ok()
            .and_then(|b| {
                let dir = std::env::temp_dir().join(format!("smtest-servers-{}", Uuid::new_v4()));
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
        evidence,
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

async fn empty_state() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

async fn body_of(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn post_form(app: axum::Router, uri: &str, body: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, loc)
}

/// POST a form and return the response BODY (for re-render handlers like
/// validate / preview_impact that return HTML, not a PRG redirect).
async fn post_form_body(app: axum::Router, uri: &str, body: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn store() -> Option<SharedManifestStore> {
    Some(Arc::new(FakeManifestStore::default()))
}

/// Like [`store`] but the turnstile CAS loses — simulating a concurrent write
/// on another replica, to drive the publish/rollback refusal.
fn store_cas_lost() -> Option<SharedManifestStore> {
    Some(Arc::new(FakeManifestStore {
        cas_lost: true,
        ..Default::default()
    }))
}

/// Like [`store`] but `get` returns a non-draft bundle — to drive the publish
/// draft-only guard.
fn store_get_published() -> Option<SharedManifestStore> {
    Some(Arc::new(FakeManifestStore {
        get_published: true,
        ..Default::default()
    }))
}

#[tokio::test]
async fn page_renders_with_store_and_versions() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/server_manifests").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Server manifests"), "page title missing");
    // Versions table rendered (all three rows) + current marker + export.
    assert!(body.contains("v1"), "v1 row missing");
    assert!(body.contains("v2"), "v2 row missing");
    assert!(body.contains("v3"), "v3 row missing");
    assert!(body.contains("current"), "current chip missing");
    assert!(body.contains("Export active (YAML)"), "export link missing");
    // v3 draft offers Publish; v1 published-non-current offers Rollback.
    assert!(body.contains(">Publish<"), "publish button missing");
    assert!(body.contains(">Rollback<"), "rollback button missing");
}

#[tokio::test]
async fn page_renders_fleet_roll_up() {
    // The fleet section renders one row per replica heartbeat, with
    // the version (or "uncommitted"), and a live/stale status from updated_at.
    let now = time::OffsetDateTime::now_utc();
    let store: SharedManifestStore = Arc::new(FakeManifestStore {
        heartbeats: vec![
            waygate_manifest_store::ReplicaHeartbeat {
                replica_id: "pod-live".into(),
                tenant_id: "default".into(),
                version: Some(5),
                content_hash: "abcdef0123456789".into(),
                updated_at: now,
            },
            waygate_manifest_store::ReplicaHeartbeat {
                replica_id: "pod-stale".into(),
                tenant_id: "default".into(),
                version: None,
                content_hash: "0011223344556677".into(),
                updated_at: now - time::Duration::minutes(5),
            },
        ],
        ..Default::default()
    });
    let app = dashboard_router(
        state_with_manifest_store(Some(store)).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/server_manifests").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Fleet"), "fleet section heading missing");
    assert!(body.contains("pod-live"), "live replica row missing");
    assert!(body.contains("pod-stale"), "stale replica row missing");
    assert!(body.contains("v5"), "committed version label missing");
    assert!(
        body.contains("uncommitted"),
        "uncommitted version label missing"
    );
    assert!(body.contains(">live<"), "live status chip missing");
    assert!(body.contains(">stale<"), "stale status chip missing");
}

#[tokio::test]
async fn page_renders_empty_state_without_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/server_manifests").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("manifest store not configured"),
        "no-store empty state missing",
    );
}

/// The publish/rollback confirms must be STATIC (only the integer
/// version interpolated) — never a dynamic string that could break out
/// of the inline-JS attribute (a stored-XSS vector). Assert the
/// exact static skeleton is present.
#[tokio::test]
async fn publish_and_rollback_confirms_are_static() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (_status, body) = body_of(app, "/server_manifests").await;
    assert!(
        body.contains("confirm('Publish v3 as the active manifest set?')"),
        "publish confirm is not the expected static form",
    );
    assert!(
        body.contains("re-publish its content as a new active set"),
        "rollback confirm is not the expected static form",
    );
}

/// Dual-mount guard: a publish POST on the TENANT-SCOPED mount
/// (`/t/{tenant}/...`, two path captures) must reach the handler and
/// 303-redirect — not 500 with WrongNumberOfParameters. This is the
/// regression `AxumPath<HashMap>` + read-by-name prevents.
#[tokio::test]
async fn publish_on_tenant_scoped_mount_redirects_not_500() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/t/default/server_manifests/{DRAFT_ID}/publish"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "tenant-scoped publish must 303, not 500",
    );
    assert!(loc.contains("/server_manifests"), "redirect target: {loc}");
    assert!(
        loc.contains("banner=published"),
        "missing success banner: {loc}"
    );
}

#[tokio::test]
async fn rollback_on_tenant_scoped_mount_redirects_not_500() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    // Roll back to v2: its content (yaml(2)) differs from the disk-seeded
    // active set (yaml(1)), so it's a real change — not the no-op that rolling
    // back to v1 (== disk) would now be (covered by rollback_noop_is_refused).
    let (status, loc) = post_form(
        app,
        "/t/default/server_manifests/2/rollback",
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "tenant-scoped rollback must 303, not 500",
    );
    assert!(loc.contains("banner=rolled_back"), "missing banner: {loc}");
}

/// Rolling back to the version whose content already equals the live on-disk
/// set is a no-op: it must be refused (a `rollback_error` "nothing to roll
/// back" flash), NOT applied — a no-op turnstile CAS would falsely win and could
/// clobber a concurrent real write. The disk is seeded from
/// `active_bundle` (v1), so a rollback to v1 is the no-op.
#[tokio::test]
async fn rollback_noop_is_refused() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/t/default/server_manifests/1/rollback",
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "a no-op rollback still 303s");
    assert!(
        loc.contains("banner=rollback_error") && !loc.contains("banner=rolled_back"),
        "a no-op rollback (target == live disk) must be refused, got: {loc}"
    );
}

/// Publish on the flat (non-tenant) mount also 303s.
#[tokio::test]
async fn publish_on_flat_mount_redirects() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/server_manifests/{PUB_ID}/publish"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "flat-mount publish must 303");
    assert!(loc.contains("banner=published"), "missing banner: {loc}");
}

/// When the cross-replica turnstile CAS loses (another replica wrote
/// concurrently), the publish is refused fail-closed — a `publish_error`
/// banner, NOT a `published` one — so it never clobbers the other write.
#[tokio::test]
async fn publish_turnstile_lost_is_refused() {
    let app = dashboard_router(
        state_with_manifest_store(store_cas_lost()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/server_manifests/{PUB_ID}/publish"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=publish_error") && !loc.contains("banner=published"),
        "a lost turnstile CAS must refuse with publish_error, got: {loc}",
    );
}

/// Publishing a NON-draft id must fail closed BEFORE the
/// CAS/mirror/notify — `store.get` doesn't filter by status, so the handler
/// checks it. Otherwise a non-draft's content would reach disk + notify before
/// `publish` rejects it.
#[tokio::test]
async fn publish_non_draft_is_refused_fail_closed() {
    let app = dashboard_router(
        state_with_manifest_store(store_get_published()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/server_manifests/{PUB_ID}/publish"),
        "csrf=dev-csrf",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=publish_error") && !loc.contains("banner=published"),
        "publishing a non-draft must fail closed with publish_error, got: {loc}",
    );
}

/// A malformed bundle id is a clean 400 (read-by-name parse failure),
/// not a 500.
#[tokio::test]
async fn publish_bad_id_is_400_not_500() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) =
        post_form(app, "/server_manifests/not-a-uuid/publish", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn publish_rejects_missing_csrf() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(app, &format!("/server_manifests/{DRAFT_ID}/publish"), "").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "missing CSRF must 403");
}

#[tokio::test]
async fn validate_form_renders_count() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/server_manifests/validate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=dev-csrf&content=-+name:+a%0A++transport:+http%0A++url:+http://a/mcp%0A",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        body.contains("Valid manifest set"),
        "validate OK banner missing",
    );
}

#[tokio::test]
async fn save_draft_redirects_on_valid_set() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/server_manifests/save_draft",
        "csrf=dev-csrf&content=-+name:+a%0A++transport:+http%0A++url:+http://a/mcp%0A",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("banner=saved"), "missing saved banner: {loc}");
}

#[tokio::test]
async fn save_draft_rejects_invalid_set() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/server_manifests/save_draft",
        "csrf=dev-csrf&content=not+valid+manifest+yaml:+[[[",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=save_error"),
        "invalid set should flash save_error: {loc}",
    );
}

#[tokio::test]
async fn export_returns_yaml_attachment() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/server_manifests/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cd = resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cd.contains("attachment") && cd.contains("servers.yaml"),
        "export must be a servers.yaml attachment; got {cd:?}",
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        body.contains("name: u1"),
        "export body should be the active set YAML"
    );
}

#[tokio::test]
async fn export_503_without_servers_dir() {
    // Disk-truth: export reads the on-disk set, not the store. A
    // store with no active bundle yields no synced servers_dir, so export
    // 503s ("no servers dir configured") rather than 404.
    struct NoActive;
    #[async_trait]
    impl ManifestStore for NoActive {
        async fn active_bundle(&self, _t: &str) -> Result<ManifestBundle, ManifestError> {
            Err(ManifestError::NotFound("none"))
        }
        async fn list_bundles(
            &self,
            _t: &str,
        ) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
            Ok(vec![])
        }
        async fn get(&self, _t: &str, _id: Uuid) -> Result<ManifestBundle, ManifestError> {
            Err(ManifestError::NotFound("none"))
        }
        async fn create_draft(
            &self,
            _t: &str,
            _c: &str,
            _a: Option<&str>,
        ) -> Result<ManifestBundle, ManifestError> {
            Err(ManifestError::NotFound("none"))
        }
        async fn publish(
            &self,
            _t: &str,
            _id: Uuid,
            _by: &str,
        ) -> Result<ManifestBundle, ManifestError> {
            Err(ManifestError::NotFound("none"))
        }
        async fn rollback_to(
            &self,
            _t: &str,
            _v: i32,
            _by: &str,
        ) -> Result<ManifestBundle, ManifestError> {
            Err(ManifestError::NotFound("none"))
        }
        async fn delete_all_for_tenant(&self, _t: &str) -> Result<u64, ManifestError> {
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
            Ok(waygate_manifest_store::TurnstileOutcome::Won)
        }
    }
    let s: Option<SharedManifestStore> = Some(Arc::new(NoActive));
    let app = dashboard_router(state_with_manifest_store(s).await, DashboardAuth::Disabled);
    let (status, _body) = body_of(app, "/server_manifests/export").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// The editor's Preview-impact button re-renders the page (no redirect)
/// with the blast-radius panel and the submitted content carried back. The test
/// state wires the manifest store + servers_dir but no Cedar engine, so the
/// replay short-circuits to a panel error ("no cedar engine configured") — which
/// proves the route, CSRF + admin gate, page re-render, and panel wiring
/// end-to-end. (The replay math itself is unit-tested in `manifest_impact`.)
#[tokio::test]
async fn preview_impact_renders_panel_and_echoes_content() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = post_form_body(
        app,
        "/server_manifests/preview_impact",
        "csrf=dev-csrf&content=-%20name:%20bank%0A%20%20transport:%20http%0A%20%20url:%20http://bank",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "preview re-renders the page (no redirect)"
    );
    assert!(
        body.contains("Blast radius"),
        "the impact panel must render"
    );
    assert!(
        body.contains("name: bank"),
        "the submitted editor content must be carried back into the textarea",
    );
}

/// The preview route enforces the same CSRF gate as the other editor
/// mut* forms — a missing/garbage token is rejected, not silently previewed.
#[tokio::test]
async fn preview_impact_rejects_bad_csrf() {
    let app = dashboard_router(
        state_with_manifest_store(store()).await,
        DashboardAuth::Disabled,
    );
    let (status, _) = post_form_body(
        app,
        "/server_manifests/preview_impact",
        "csrf=wrong&content=- name: x",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "bad CSRF must be refused");
}
