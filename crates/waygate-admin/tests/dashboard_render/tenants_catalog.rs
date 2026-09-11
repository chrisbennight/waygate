//! Tenant create/edit + catalog lifecycle — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::common::*;
use crate::crud_pages::post_form;
use std::collections::HashMap;

// ---- tenant create --------------------------------------------------------

#[tokio::test]
pub(crate) async fn tenants_create_rejects_missing_csrf() {
    // Dev mode injects a CsrfToken, so a POST with no csrf field must 403.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tenants/create")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=acme&display_name=Acme"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn tenants_create_returns_503_without_store() {
    // empty_state has no tenants registry → create is service-unavailable
    // (admin gate + CSRF pass first, so this exercises the orchestration's
    // store check).
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tenants/create")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=dev-csrf&id=acme&display_name=Acme"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ---- Tenants inline edit + delete ------------------------------------------

/// Seedable in-memory `TenantStore` for the tenants dashboard tests.
/// Behaviour mirrors `PgTenantStore`'s contract closely enough to
/// exercise the edit/delete cores: `create` conflicts on duplicate id,
/// `update` applies only the provided fields (None = leave alone),
/// atomic delete reports whether a row existed.
pub(crate) struct FakeTenantStore {
    tenants: std::sync::Mutex<Vec<waygate_tenants::Tenant>>,
    fail_delete: bool,
}

impl FakeTenantStore {
    fn with(tenants: Vec<waygate_tenants::Tenant>) -> Self {
        Self {
            tenants: std::sync::Mutex::new(tenants),
            fail_delete: false,
        }
    }

    fn failing_delete(tenants: Vec<waygate_tenants::Tenant>) -> Self {
        Self {
            tenants: std::sync::Mutex::new(tenants),
            fail_delete: true,
        }
    }
}

#[async_trait]
impl waygate_tenants::TenantStore for FakeTenantStore {
    async fn create(
        &self,
        id: &str,
        display_name: &str,
        status: waygate_tenants::TenantStatus,
    ) -> Result<waygate_tenants::Tenant, waygate_tenants::TenantError> {
        let mut v = self.tenants.lock().unwrap();
        if v.iter().any(|t| t.id == id) {
            return Err(waygate_tenants::TenantError::Conflict(id.to_owned()));
        }
        let now = OffsetDateTime::now_utc();
        let t = waygate_tenants::Tenant {
            id: id.to_owned(),
            display_name: display_name.to_owned(),
            status: status.as_str().to_owned(),
            created_at: now,
            updated_at: now,
        };
        v.push(t.clone());
        Ok(t)
    }
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<waygate_tenants::Tenant>, waygate_tenants::TenantError> {
        Ok(self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.id == id)
            .cloned())
    }
    async fn list(&self) -> Result<Vec<waygate_tenants::Tenant>, waygate_tenants::TenantError> {
        let mut v = self.tenants.lock().unwrap().clone();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(v)
    }
    async fn update(
        &self,
        id: &str,
        display_name: Option<&str>,
        status: Option<waygate_tenants::TenantStatus>,
    ) -> Result<Option<waygate_tenants::Tenant>, waygate_tenants::TenantError> {
        let mut v = self.tenants.lock().unwrap();
        match v.iter_mut().find(|t| t.id == id) {
            Some(t) => {
                if let Some(n) = display_name {
                    t.display_name = n.to_owned();
                }
                if let Some(s) = status {
                    t.status = s.as_str().to_owned();
                }
                t.updated_at = OffsetDateTime::now_utc();
                Ok(Some(t.clone()))
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, id: &str) -> Result<bool, waygate_tenants::TenantError> {
        let mut v = self.tenants.lock().unwrap();
        let before = v.len();
        v.retain(|tenant| tenant.id != id);
        Ok(v.len() < before)
    }
}

#[async_trait]
impl waygate_admin::tenants::TenantLifecycleStore for FakeTenantStore {
    async fn delete_with_policy_bundles(
        &self,
        id: &str,
    ) -> Result<waygate_admin::tenants::TenantDeleteOutcome, waygate_tenants::TenantError> {
        if self.fail_delete {
            return Err(waygate_tenants::TenantError::Sqlx(sqlx::Error::Protocol(
                "injected atomic tenant deletion failure".to_owned(),
            )));
        }
        let mut v = self.tenants.lock().unwrap();
        let before = v.len();
        v.retain(|t| t.id != id);
        Ok(waygate_admin::tenants::TenantDeleteOutcome {
            tenant_deleted: v.len() < before,
            policy_bundles_deleted: 0,
        })
    }
}

pub(crate) fn tenant_fixture(id: &str, status: &str) -> waygate_tenants::Tenant {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    waygate_tenants::Tenant {
        id: id.to_owned(),
        display_name: format!("{id} display"),
        status: status.to_owned(),
        created_at: now,
        updated_at: now,
    }
}

/// Build an `AdminState` with the tenants store wired + a real
/// `InMemorySink` evidence sink — tenant edit/delete audit via
/// `record_required` (fail-closed), so a NullSink would turn the
/// happy path into an error. Mirrors `state_with_rbac_store`.
pub(crate) async fn state_with_tenant_store(store: Arc<FakeTenantStore>) -> Arc<AdminState> {
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
        .with_tenant_store(Some(store.clone()))
        .with_tenant_lifecycle_store(Some(store)),
    )
}

async fn state_with_tenant_and_policy_store(
    tenant_store: Arc<FakeTenantStore>,
    policy_store: waygate_policy::SharedPolicyStore,
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
        .with_tenant_store(Some(tenant_store.clone()))
        .with_tenant_lifecycle_store(Some(tenant_store))
        .with_policy_store(Some(policy_store)),
    )
}

/// Admin session (DashboardAuth::Disabled) renders the per-row edit +
/// delete forms and the Actions column for a seeded tenant.
#[tokio::test]
pub(crate) async fn tenants_admin_rows_render_edit_and_delete_forms() {
    let store = Arc::new(FakeTenantStore::with(vec![tenant_fixture(
        "acme", "active",
    )]));
    let app = dashboard_router(
        state_with_tenant_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<th>Actions</th>"), "Actions column missing");
    assert!(
        body.contains("/tenants/acme/update"),
        "edit form action missing",
    );
    assert!(
        body.contains("/tenants/acme/delete"),
        "delete form action missing",
    );
    assert!(body.contains("name=\"status\""), "status select missing");
    assert!(
        !body.contains(r#"class="empty""#),
        "legacy .empty class still rendered",
    );
}

/// Edit with admin + matching CSRF applies display_name + status and
/// PRG-redirects with no error channel.
#[tokio::test]
pub(crate) async fn tenants_update_persists_and_redirects() {
    let store = Arc::new(FakeTenantStore::with(vec![tenant_fixture(
        "acme", "active",
    )]));
    let app = dashboard_router(
        state_with_tenant_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/tenants/acme/update",
        "csrf=dev-csrf&display_name=Acme+Inc&status=suspended",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("/tenants"), "redirect target: {loc}");
    assert!(
        !loc.contains("tenants_error"),
        "success carried an error: {loc}"
    );
    let tenants = store.tenants.lock().unwrap();
    assert_eq!(tenants[0].display_name, "Acme Inc");
    assert_eq!(tenants[0].status, "suspended");
}

/// Edit rejects a missing CSRF token with 403.
#[tokio::test]
pub(crate) async fn tenants_update_rejects_missing_csrf() {
    let store = Arc::new(FakeTenantStore::with(vec![tenant_fixture(
        "acme", "active",
    )]));
    let app = dashboard_router(
        state_with_tenant_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) =
        post_form(app, "/tenants/acme/update", "display_name=x&status=active").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Delete with admin + CSRF removes the row (running the shared core's
/// residue cleanup + audit) and PRG-redirects with no error.
#[tokio::test]
pub(crate) async fn tenants_delete_removes_and_redirects() {
    let store = Arc::new(FakeTenantStore::with(vec![tenant_fixture(
        "acme", "active",
    )]));
    let app = dashboard_router(
        state_with_tenant_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(app, "/tenants/acme/delete", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !loc.contains("tenants_error"),
        "success carried an error: {loc}"
    );
    assert!(
        store.tenants.lock().unwrap().is_empty(),
        "tenant should be deleted",
    );
}

#[tokio::test]
pub(crate) async fn tenants_delete_evicts_the_local_tenant_policy() {
    let store = Arc::new(FakeTenantStore::with(vec![tenant_fixture(
        "acme", "active",
    )]));
    let cedar = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source("forbid (principal, action, resource);").unwrap(),
    ));
    cedar.replace_tenants(HashMap::from([(
        "acme".to_owned(),
        CedarEngine::from_source("permit (principal, action, resource);").unwrap(),
    )]));
    let default = cedar.snapshot();
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let epoch = pool.tool_catalog_epoch();
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    let state = Arc::new(
        AdminState::new(
            pool,
            Some(cedar.clone()),
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_tenant_store(Some(store.clone()))
        .with_tenant_lifecycle_store(Some(store)),
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);

    let (status, loc) = post_form(app, "/tenants/acme/delete", "csrf=dev-csrf").await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("tenants_error"));
    assert!(
        Arc::ptr_eq(&default, &cedar.snapshot_for_tenant("acme")),
        "a committed delete must synchronously restore default fallback on this replica",
    );
    assert_eq!(
        epoch.current(),
        1,
        "the local authorization change invalidates governed discovery",
    );
}

#[tokio::test]
pub(crate) async fn tenants_delete_failure_preserves_registry_and_policy_rows() {
    let tenants = Arc::new(FakeTenantStore::failing_delete(vec![tenant_fixture(
        "acme", "active",
    )]));
    let mut bundle = crate::editors::seeded_bundle(
        "00000000-0000-0000-0000-000000000156",
        1,
        waygate_policy::PolicyStatus::Published,
        "forbid(principal, action, resource);",
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    bundle.tenant_id = "acme".to_owned();
    let policies = Arc::new(crate::editors::InMemoryPolicyStore::seeded(vec![bundle]));
    let policy_handle = policies.clone();
    let app = dashboard_router(
        state_with_tenant_and_policy_store(tenants.clone(), policies).await,
        DashboardAuth::Disabled,
    );

    let (status, loc) = post_form(app, "/tenants/acme/delete", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("tenants_error"),
        "policy-cleanup failure must be visible to the operator: {loc}",
    );
    assert_eq!(
        tenants.tenants.lock().unwrap().len(),
        1,
        "tenant row must remain until its authorization bundles are gone",
    );
    assert_eq!(
        policy_handle.bundles.lock().await.len(),
        1,
        "the failed atomic delete must leave the restrictive bundle live",
    );
}

/// Deleting an unknown id is a no-op the core reports as `Ok(false)` →
/// the "no longer exists" banner via `?tenants_error=`.
#[tokio::test]
pub(crate) async fn tenants_delete_unknown_id_reports_error() {
    let store = Arc::new(FakeTenantStore::with(vec![tenant_fixture(
        "acme", "active",
    )]));
    let app = dashboard_router(
        state_with_tenant_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(app, "/tenants/ghost/delete", "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("tenants_error"),
        "unknown-id delete must carry an error: {loc}",
    );
}

/// With no tenants store the edit route still authorizes + parses, then
/// the shared core surfaces service-unavailable, funneled into the
/// `?tenants_error=` PRG channel (unlike create, which keeps a raw 503).
#[tokio::test]
pub(crate) async fn tenants_update_without_store_redirects_with_error() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, loc) = post_form(
        app,
        "/tenants/acme/update",
        "csrf=dev-csrf&display_name=x&status=active",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("tenants_error"),
        "store-unavailable edit must carry an error: {loc}",
    );
}

// ---- catalog lifecycle (dashboard) ----------------------------------------

#[tokio::test]
pub(crate) async fn catalog_quarantine_rejects_missing_csrf() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/catalog/quarantine")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=00000000-0000-0000-0000-000000000000"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
pub(crate) async fn catalog_approve_rejects_invalid_id() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/catalog/approve")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=dev-csrf&id=not-a-uuid"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
pub(crate) async fn catalog_quarantine_returns_503_without_store() {
    // Admin gate + CSRF + id parse pass; the catalog store is unwired, so
    // set_status surfaces service-unavailable.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/catalog/quarantine")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=dev-csrf&id=00000000-0000-0000-0000-000000000000",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
