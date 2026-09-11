//! OAuth-consent, catalog, scopes/groups, evidence pages — split from the
//! monolithic `dashboard_render.rs`; bodies verbatim, cut at the file's
//! own section markers.

use crate::common::*;

// ---- OAuth-consent page -------------------------------------------------

/// OAuth-consent page renders at both mounts. empty_state has no
/// consent store wired → renders the disabled-state card.
#[tokio::test]
pub(crate) async fn oauth_consent_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/oauth_consent", "/t/default/oauth_consent"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "oauth_consent page failed at {path}"
        );
        assert!(
            body.contains("OAuth consent"),
            "page title missing at {path}"
        );
        assert!(
            body.contains("OAuth consent store not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// Identity sidebar group force-opens on /oauth_consent
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn oauth_consent_page_marks_identity_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/oauth_consent").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/identities" aria-current="page""#),
        "the Identities destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/oauth_consent" aria-current="page""#),
        "OAuth consent nav link missing aria-current on legacy mount",
    );
}

/// Palette finds OAuth consent in its catalogue.
#[tokio::test]
pub(crate) async fn oauth_consent_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=consent").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"OAuth consent""#),
        "OAuth consent missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Per-(principal, client) OAuth consent grants"#),
        "OAuth consent hint missing from palette search result: {body}",
    );
}

// ---- Catalog page ---------------------------------------------------------

/// Catalog page renders at both mounts. empty_state has no
/// catalog store wired → renders the disabled-state card.
#[tokio::test]
pub(crate) async fn catalog_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/catalog", "/t/default/catalog"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "catalog page failed at {path}");
        assert!(body.contains("Catalog"), "page title missing at {path}");
        assert!(
            body.contains("Catalog store not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// Traffic sidebar group force-opens on /catalog
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn catalog_page_marks_traffic_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/catalog").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/tools" aria-current="page""#),
        "the Tools destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/catalog" aria-current="page""#),
        "Catalog nav link missing aria-current on legacy mount",
    );
}

// --- Scopes registry page ---

/// The Scopes page renders at both the legacy and tenant-prefixed
/// mounts, and shows its disabled-state card when no scope store is
/// wired (the `empty_state()` AdminState carries `scopes: None`).
#[tokio::test]
pub(crate) async fn scopes_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/scopes", "/t/default/scopes"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "scopes page failed at {path}");
        assert!(body.contains("Scopes"), "page title missing at {path}");
        assert!(
            body.contains("Scope store not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// The Scopes tab marks its parent Access Control destination (root
/// `/scim`) and its own `/scopes` tab as current in the sidebar.
#[tokio::test]
pub(crate) async fn scopes_page_marks_access_control_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/scopes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/scim" aria-current="page""#),
        "the Access Control destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/scopes" aria-current="page""#),
        "Scopes nav link missing aria-current on legacy mount",
    );
}

// --- Unified Groups page ---

/// The Groups page renders at both mounts and shows its disabled-state
/// card when no group store is wired (`empty_state()` carries `groups: None`).
#[tokio::test]
pub(crate) async fn groups_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/groups", "/t/default/groups"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "groups page failed at {path}");
        assert!(body.contains("Groups"), "page title missing at {path}");
        assert!(
            body.contains("Group store not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// The Groups tab marks its parent Access Control destination and its
/// own `/groups` tab as current in the sidebar.
#[tokio::test]
pub(crate) async fn groups_page_marks_access_control_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/groups").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/scim" aria-current="page""#),
        "the Access Control destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/groups" aria-current="page""#),
        "Groups nav link missing aria-current on legacy mount",
    );
}

// --- Catalog create UI on Scopes + Groups ---

/// Empty fake stores so the catalog pages render their configured branch
/// (create form + table) without a DB.
pub(crate) struct FakeScopeStore;
#[async_trait]
impl waygate_apikeys::ScopeStore for FakeScopeStore {
    async fn list_with_usage(
        &self,
        _t: &str,
    ) -> Result<Vec<waygate_apikeys::ScopeView>, waygate_apikeys::ScopeStoreError> {
        Ok(vec![])
    }
    async fn delete_all_for_tenant(
        &self,
        _t: &str,
    ) -> Result<u64, waygate_apikeys::ScopeStoreError> {
        Ok(0)
    }
    async fn upsert_policy_scopes(
        &self,
        _n: &[String],
    ) -> Result<u64, waygate_apikeys::ScopeStoreError> {
        Ok(0)
    }
    async fn create_local(
        &self,
        _t: &str,
        _n: &str,
        _d: Option<&str>,
    ) -> Result<(), waygate_apikeys::ScopeStoreError> {
        Ok(())
    }
    async fn get_local_delete_target(
        &self,
        _t: &str,
        id: uuid::Uuid,
    ) -> Result<waygate_apikeys::LocalScopeDeleteTarget, waygate_apikeys::ScopeStoreError> {
        Err(waygate_apikeys::ScopeStoreError::NotFound(id))
    }
    async fn delete_local_if_unchanged(
        &self,
        _t: &str,
        id: uuid::Uuid,
        _name: &str,
        _updated_at: time::OffsetDateTime,
    ) -> Result<(), waygate_apikeys::ScopeStoreError> {
        Err(waygate_apikeys::ScopeStoreError::NotFound(id))
    }
    async fn unknown_scopes(
        &self,
        _t: &str,
        _n: &[String],
    ) -> Result<Vec<String>, waygate_apikeys::ScopeStoreError> {
        Ok(vec![])
    }
}

pub(crate) struct FakeGroupStore;
#[async_trait]
impl waygate_apikeys::GroupStore for FakeGroupStore {
    async fn list_with_usage(
        &self,
        _t: &str,
    ) -> Result<Vec<waygate_apikeys::GroupView>, waygate_apikeys::GroupStoreError> {
        Ok(vec![])
    }
    async fn delete_all_local_for_tenant(
        &self,
        _t: &str,
    ) -> Result<u64, waygate_apikeys::GroupStoreError> {
        Ok(0)
    }
    async fn create_local(
        &self,
        _t: &str,
        _n: &str,
    ) -> Result<(), waygate_apikeys::GroupStoreError> {
        Ok(())
    }
    async fn get_local_delete_target(
        &self,
        _t: &str,
        id: uuid::Uuid,
    ) -> Result<waygate_apikeys::LocalGroupDeleteTarget, waygate_apikeys::GroupStoreError> {
        Err(waygate_apikeys::GroupStoreError::NotFound(id))
    }
    async fn delete_local_if_unchanged(
        &self,
        _t: &str,
        id: uuid::Uuid,
        _display_name: &str,
        _updated_at: time::OffsetDateTime,
    ) -> Result<(), waygate_apikeys::GroupStoreError> {
        Err(waygate_apikeys::GroupStoreError::NotFound(id))
    }
    async fn unknown_groups(
        &self,
        _t: &str,
        _n: &[String],
    ) -> Result<Vec<String>, waygate_apikeys::GroupStoreError> {
        Ok(vec![])
    }
}

pub(crate) async fn state_with_catalog_stores() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(
        base_admin_state_with_pool(pool)
            .with_scope_store(Some(Arc::new(FakeScopeStore)))
            .with_group_store(Some(Arc::new(FakeGroupStore))),
    )
}

/// The Scopes page renders the "Add a scope" create form (CSRF input +
/// POST to /scopes/create) once a store is wired, and surfaces a
/// `?scopes_error=` PRG banner.
#[tokio::test]
pub(crate) async fn scopes_page_renders_create_form_and_error_banner() {
    let app = dashboard_router(state_with_catalog_stores().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app.clone(), "/scopes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Add a scope"), "create form heading missing");
    assert!(
        body.contains(r#"action="/admin/scopes/create""#),
        "create form must POST to /scopes/create",
    );
    assert!(
        body.contains(r#"name="csrf""#),
        "create form must carry a CSRF input",
    );

    let (_, body) = body_of(app, "/scopes?scopes_error=boom-scope").await;
    assert!(
        body.contains("boom-scope"),
        "the ?scopes_error= banner should render the message",
    );
}

/// The Groups page renders the "Add a group" create form and surfaces a
/// `?groups_error=` PRG banner.
#[tokio::test]
pub(crate) async fn groups_page_renders_create_form_and_error_banner() {
    let app = dashboard_router(state_with_catalog_stores().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app.clone(), "/groups").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Add a group"), "create form heading missing");
    assert!(
        body.contains(r#"action="/admin/groups/create""#),
        "create form must POST to /groups/create",
    );

    let (_, body) = body_of(app, "/groups?groups_error=boom-group").await;
    assert!(
        body.contains("boom-group"),
        "the ?groups_error= banner should render the message",
    );
}

/// Palette finds Catalog in its catalogue.
#[tokio::test]
pub(crate) async fn catalog_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=catalog").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Catalog""#),
        "Catalog missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Governed catalog"#),
        "Catalog hint missing from palette search result: {body}",
    );
}

// ---- Evidence page --------------------------------------------------------

/// Evidence page renders at both mounts. empty_state has no
/// routing/retention/inspection stores wired → renders the
/// per-section "not configured" cards.
#[tokio::test]
pub(crate) async fn evidence_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/evidence", "/t/default/evidence"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "evidence page failed at {path}");
        assert!(body.contains("Evidence"), "page title missing at {path}");
        assert!(
            body.contains("Routing store not configured"),
            "expected routing disabled-state copy at {path}",
        );
        assert!(
            body.contains("does not establish full audit"),
            "empty chain-verification status must not imply full audit coverage at {path}",
        );
    }
}

/// Evidence sidebar group force-opens on /evidence
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn evidence_page_marks_evidence_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/evidence").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/activity" aria-current="page""#),
        "the Activity destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/evidence" aria-current="page""#),
        "Evidence nav link missing aria-current on legacy mount",
    );
}

/// Palette finds Evidence in its catalogue.
#[tokio::test]
pub(crate) async fn evidence_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=evidence").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Evidence pipeline""#),
        "Evidence missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Evidence pipeline"#),
        "Evidence hint missing from palette search result: {body}",
    );
}
