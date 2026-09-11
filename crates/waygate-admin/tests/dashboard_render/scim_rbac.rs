//! SCIM, provisioning log, RBAC pages — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::common::*;
use crate::consent_identities::FakeScopeStore;
use crate::crud_pages::post_form;

// ---- SCIM page ------------------------------------------------------------

/// SCIM page renders at both mounts. empty_state has no SCIM stores
/// wired → renders the disabled-state card.
#[tokio::test]
pub(crate) async fn scim_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/scim", "/t/default/scim"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "scim page failed at {path}");
        // De-acronymed: the nav tab + H1 read "Users" (the
        // underlying store/route stays SCIM).
        assert!(
            body.contains(r#"<h1 class="page-title">Users</h1>"#),
            "page title missing at {path}",
        );
        assert!(
            body.contains("SCIM store not configured"),
            "expected disabled-state copy at {path}",
        );
        // Disabled state uses the shared empty-state component.
        assert!(
            body.contains(r#"class="empty-state""#),
            "SCIM disabled state should use the shared .empty-state component at {path}",
        );
    }
}

/// Access Control sidebar group force-opens on /scim
/// (contains_active behavior). /scim is both the Access Control
/// destination default and its "Users" tab, so its href carries
/// aria-current.
#[tokio::test]
pub(crate) async fn scim_page_marks_access_control_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/scim").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/scim" aria-current="page""#),
        "the Access Control destination + Users tab should be current",
    );
}

/// Palette finds the Users directory in its catalogue (de-acronymed
/// from "SCIM"; palette matches on label, so the query is the
/// new noun).
#[tokio::test]
pub(crate) async fn users_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=users").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Users""#),
        "Users missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"SCIM-provisioned user directory"#),
        "Users hint missing from palette search result: {body}",
    );
}

// ---- SCIM provisioning-log timeline -----------------------------------

/// When the provisioning-log store isn't wired the
/// section hides entirely. The page falls back to the
/// users + groups only shape.
#[tokio::test]
pub(crate) async fn scim_hides_provisioning_log_section_without_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/scim").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(r#"aria-label="SCIM provisioning log""#),
        "Provisioning log section must not render when the store is unwired",
    );
}

/// With the provisioning-log store wired (even when
/// empty) the section renders with its empty-state copy +
/// the link back to the Activity page for the audit-log facet.
#[tokio::test]
pub(crate) async fn scim_renders_empty_provisioning_log_section() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let log: Arc<dyn waygate_dashboard_stores::scim_provisioning_log::ScimProvisioningLogStore> =
        Arc::new(InMemoryProvisioningLogStub::default());
    let state = Arc::new(base_admin_state_with_pool(pool).with_scim_provisioning_log(Some(log)));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/scim").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"aria-label="SCIM provisioning log""#),
        "Provisioning log section should render when the store is wired",
    );
    assert!(
        body.contains("No provisioning events yet"),
        "empty-store section should render the 'No provisioning events yet' notice",
    );
    // The empty-state copy references the SCIM REST endpoints
    // the writer hook fires on.
    assert!(
        body.contains("/scim/v2/Users"),
        "empty-state should reference the SCIM Users endpoint",
    );
    assert!(
        body.contains("/scim/v2/Groups"),
        "empty-state should reference the SCIM Groups endpoint",
    );
}

/// A populated log renders one row per entry with
/// the action, target, outcome chip, and actor.
#[tokio::test]
pub(crate) async fn scim_renders_populated_provisioning_log_rows() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let stub = InMemoryProvisioningLogStub::default();
    stub.seed_success_user("create", "alice@example.com", "alice");
    stub.seed_success_group("replace", "engineers", "ops-bot");
    stub.seed_error("delete", "carol@example.com", "Internal Server Error");
    let log: Arc<dyn waygate_dashboard_stores::scim_provisioning_log::ScimProvisioningLogStore> =
        Arc::new(stub);
    let state = Arc::new(base_admin_state_with_pool(pool).with_scim_provisioning_log(Some(log)));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/scim").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("alice@example.com"), "user target missing");
    assert!(body.contains("engineers"), "group target missing");
    assert!(body.contains("carol@example.com"), "error target missing");
    // Error message body renders inline.
    assert!(
        body.contains("Internal Server Error"),
        "error_message string should render under the error row",
    );
    // Success chip styling renders for at least one row.
    assert!(
        body.contains(r#"<span class="chip chip--ok">success</span>"#),
        "success outcome chip should render",
    );
}

/// In-memory `ScimProvisioningLogStore` stub for render
/// tests. Carries seed rows + thread-safe mutation so end-to-
/// end append/list work in tests without Postgres.
#[derive(Default)]
pub(crate) struct InMemoryProvisioningLogStub {
    rows: tokio::sync::Mutex<Vec<waygate_dashboard_stores::scim_provisioning_log::Entry>>,
}

impl InMemoryProvisioningLogStub {
    fn seed_success_user(&self, action: &str, target_display: &str, actor: &str) {
        let row = waygate_dashboard_stores::scim_provisioning_log::Entry {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            ts: time::OffsetDateTime::UNIX_EPOCH,
            target_kind: waygate_dashboard_stores::scim_provisioning_log::TargetKind::User,
            target_id: Uuid::now_v7(),
            target_display: target_display.into(),
            target_external_id: None,
            action: action.into(),
            outcome: waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
            actor_sub: Some(actor.into()),
            actor_email: None,
            error_message: None,
            detail: serde_json::json!({"active": true}),
        };
        let _ = self.rows.try_lock().map(|mut g| g.push(row));
    }
    fn seed_success_group(&self, action: &str, target_display: &str, actor: &str) {
        let row = waygate_dashboard_stores::scim_provisioning_log::Entry {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            ts: time::OffsetDateTime::UNIX_EPOCH,
            target_kind: waygate_dashboard_stores::scim_provisioning_log::TargetKind::Group,
            target_id: Uuid::now_v7(),
            target_display: target_display.into(),
            target_external_id: None,
            action: action.into(),
            outcome: waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
            actor_sub: Some(actor.into()),
            actor_email: None,
            error_message: None,
            detail: serde_json::json!({"member_count": 3}),
        };
        let _ = self.rows.try_lock().map(|mut g| g.push(row));
    }
    fn seed_error(&self, action: &str, target_display: &str, error_message: &str) {
        let row = waygate_dashboard_stores::scim_provisioning_log::Entry {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            ts: time::OffsetDateTime::UNIX_EPOCH,
            target_kind: waygate_dashboard_stores::scim_provisioning_log::TargetKind::User,
            target_id: Uuid::now_v7(),
            target_display: target_display.into(),
            target_external_id: None,
            action: action.into(),
            outcome: waygate_dashboard_stores::scim_provisioning_log::Outcome::Error,
            actor_sub: None,
            actor_email: None,
            error_message: Some(error_message.into()),
            detail: serde_json::json!({}),
        };
        let _ = self.rows.try_lock().map(|mut g| g.push(row));
    }
}

#[async_trait::async_trait]
impl waygate_dashboard_stores::scim_provisioning_log::ScimProvisioningLogStore
    for InMemoryProvisioningLogStub
{
    async fn append(
        &self,
        entry: waygate_dashboard_stores::scim_provisioning_log::NewEntry,
    ) -> Result<
        waygate_dashboard_stores::scim_provisioning_log::Entry,
        waygate_dashboard_stores::scim_provisioning_log::LogError,
    > {
        let mut g = self.rows.lock().await;
        let row = waygate_dashboard_stores::scim_provisioning_log::Entry {
            id: Uuid::now_v7(),
            tenant_id: entry.tenant_id,
            ts: time::OffsetDateTime::UNIX_EPOCH,
            target_kind: entry.target_kind,
            target_id: entry.target_id,
            target_display: entry.target_display,
            target_external_id: entry.target_external_id,
            action: entry.action,
            outcome: entry.outcome,
            actor_sub: entry.actor_sub,
            actor_email: entry.actor_email,
            error_message: entry.error_message,
            detail: entry.detail,
        };
        g.push(row.clone());
        Ok(row)
    }
    async fn list(
        &self,
        tenant_id: &str,
        limit: i64,
        _before: Option<time::OffsetDateTime>,
    ) -> Result<
        Vec<waygate_dashboard_stores::scim_provisioning_log::Entry>,
        waygate_dashboard_stores::scim_provisioning_log::LogError,
    > {
        let g = self.rows.lock().await;
        Ok(g.iter()
            .filter(|r| r.tenant_id == tenant_id)
            .take(limit as usize)
            .cloned()
            .collect())
    }
    async fn list_for_target(
        &self,
        tenant_id: &str,
        target_kind: waygate_dashboard_stores::scim_provisioning_log::TargetKind,
        target_id: Uuid,
        limit: i64,
    ) -> Result<
        Vec<waygate_dashboard_stores::scim_provisioning_log::Entry>,
        waygate_dashboard_stores::scim_provisioning_log::LogError,
    > {
        let g = self.rows.lock().await;
        Ok(g.iter()
            .filter(|r| {
                r.tenant_id == tenant_id && r.target_kind == target_kind && r.target_id == target_id
            })
            .take(limit as usize)
            .cloned()
            .collect())
    }
}

// ---- RBAC page --------------------------------------------------------

/// RBAC page renders at both mounts. empty_state has no RBAC store
/// wired → renders the disabled-state card.
#[tokio::test]
pub(crate) async fn rbac_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/rbac", "/t/default/rbac"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "rbac page failed at {path}");
        assert!(body.contains("RBAC"), "page title missing at {path}");
        assert!(
            body.contains("RBAC store not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// Access Control sidebar group force-opens on /rbac
/// (contains_active behavior). The destination default is `/scim`
/// (Users), and the Roles tab (`/rbac`) carries its own aria-current.
#[tokio::test]
pub(crate) async fn rbac_page_marks_access_control_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/rbac").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/scim" aria-current="page""#),
        "the Access Control destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/rbac" aria-current="page""#),
        "Roles (rbac) nav link missing aria-current on legacy mount",
    );
}

/// Palette finds the Roles page in its catalogue (de-acronymed from
/// "RBAC"; palette matches on label, so the query is the new
/// noun).
#[tokio::test]
pub(crate) async fn roles_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=roles").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Roles""#),
        "Roles missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Roles, assignments"#),
        "Roles hint missing from palette search result: {body}",
    );
}

// ---- RBAC effective + reverse lookups -----------------------------------

/// The page renders the "Effective permissions for subject"
/// lookup section even when no lookup has been submitted yet, with no
/// SCIM resolver wired — the warning card appears and the result panel
/// stays empty. (The "Who has scope X?" reverse lookup moved to the
/// Scopes page in the Identities revamp.) Verifies the GET form posts
/// back to the tenant-prefixed /rbac route, not the legacy mount.
#[tokio::test]
pub(crate) async fn rbac_renders_lookup_forms_with_no_resolver() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/rbac", "/t/default/rbac"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "rbac failed at {path}");
        // empty_state has no RBAC store → page renders the
        // "RBAC store not configured" card and the lookup
        // sections aren't reached (gated on store_configured).
        assert!(
            body.contains("RBAC store not configured"),
            "expected store-not-configured banner at {path}",
        );
        // The page heading reads "Roles" (de-acronymed; the
        // RBAC store/route are unchanged).
        assert!(body.contains("<h1 class=\"page-title\">Roles</h1>"));
    }
}

/// The "Effective permissions for subject" form renders with the
/// operator's typed value preserved in `value=` so a GET round-trip
/// doesn't lose the input. Mirrors the activity-page plain-GET re-fill
/// pattern. state_with_audit doesn't wire RBAC,
/// so we can't drive a real result, but we CAN drive the form re-fill on
/// the bare-page render path with a state that DOES wire RBAC. Build one
/// inline. (The companion "Who has scope X?" reverse lookup moved to the
/// Scopes page — see `scopes_reverse_lookup_repopulates_and_runs`.)
#[tokio::test]
pub(crate) async fn rbac_effective_form_repopulates_subject_input() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // The lookup-form re-fill is gated on `store_configured`;
    // we wire a no-op in-memory RBAC store to exercise it. The
    // empty store returns empty lists for every list_* call, so
    // the form re-renders but the result panels are empty.
    let rbac: Arc<dyn waygate_rbac::RbacStore> = Arc::new(InMemoryRbacStub::default());
    let state = Arc::new(base_admin_state_with_pool(pool).with_rbac_store(Some(rbac)));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/rbac?subject=alice%40example.com").await;
    assert_eq!(status, StatusCode::OK);
    // Subject form pre-filled.
    assert!(
        body.contains(r#"value="alice@example.com""#),
        "Subject `<input>` should pre-fill from ?subject=",
    );
    // The lookup form's action stays inside the active tenant prefix;
    // otherwise a submit would escape into /admin/rbac and lose the
    // tenant scope.
    assert!(
        body.contains(r#"action="/admin/t/default/rbac""#),
        "lookup-form action missing tenant prefix",
    );
    // The reverse "Who has scope X?" lookup is no longer on this page.
    assert!(
        !body.contains("Who has scope X?"),
        "the reverse scope lookup must have moved off the RBAC page",
    );
    // Effective lookup with no SCIM resolver wired → the
    // page shows the "SCIM resolver not configured" notice;
    // RBAC resolve still runs (returns empty roles + scopes).
    assert!(
        body.contains("SCIM resolver not configured"),
        "expected the SCIM-resolver-not-configured notice when \
         only the RBAC store is wired",
    );
}

/// Identities revamp: the "Who has scope X?" reverse lookup now
/// lives on the Scopes page. With both the scope store and an (empty)
/// RBAC store wired, `?scope=` pre-fills the form, the form action stays
/// tenant-prefixed, and the no-matches empty state renders against the
/// empty stub.
#[tokio::test]
pub(crate) async fn scopes_reverse_lookup_repopulates_and_runs() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let rbac: Arc<dyn waygate_rbac::RbacStore> = Arc::new(InMemoryRbacStub::default());
    let state = Arc::new(
        base_admin_state_with_pool(pool)
            .with_scope_store(Some(Arc::new(FakeScopeStore)))
            .with_rbac_store(Some(rbac)),
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/scopes?scope=mcp%3Aadmin").await;
    assert_eq!(status, StatusCode::OK);
    // The reverse section is present on the Scopes page.
    assert!(
        body.contains("Who has scope X?"),
        "the reverse scope lookup must render on the Scopes page",
    );
    // Scope form pre-filled from ?scope=.
    assert!(
        body.contains(r#"value="mcp:admin""#),
        "Scope `<input>` should pre-fill from ?scope=",
    );
    // The form action stays inside the active tenant prefix.
    assert!(
        body.contains(r#"action="/admin/t/default/scopes""#),
        "reverse-lookup form action missing tenant prefix",
    );
    // Reverse lookup with `mcp:admin` against the empty stub hits the
    // "no roles in this tenant carry this scope" empty-state copy.
    assert!(
        body.contains("No roles in this tenant carry"),
        "expected the no-matches empty state from the reverse \
         lookup against an empty RBAC stub",
    );
}

/// In-memory RBAC stub. Stateful for roles (create/get/update/delete/
/// list) and for the assignment + group-mapping create/delete paths, so
/// the dashboard CRUD tests can drive both fully. Keeps tests off
/// Postgres / `PgRbacStore`.
#[derive(Default)]
pub(crate) struct InMemoryRbacStub {
    roles: std::sync::Mutex<Vec<waygate_rbac::Role>>,
    pub(crate) assignments: std::sync::Mutex<Vec<waygate_rbac::RoleAssignment>>,
    pub(crate) mappings: std::sync::Mutex<Vec<waygate_rbac::GroupRoleMapping>>,
}

#[async_trait::async_trait]
impl waygate_rbac::RbacStore for InMemoryRbacStub {
    async fn resolve_for_subject(
        &self,
        _tenant_id: &str,
        _sub: &str,
        _scim_group_ids: &[Uuid],
    ) -> Result<waygate_rbac::ResolvedRoles, waygate_rbac::RbacError> {
        Ok(waygate_rbac::ResolvedRoles::default())
    }
    async fn create_role(
        &self,
        tenant: &str,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<waygate_rbac::Role, waygate_rbac::RbacError> {
        let mut g = self.roles.lock().unwrap();
        if g.iter().any(|r| r.name == name) {
            return Err(waygate_rbac::RbacError::Conflict(
                "a role with this name already exists".into(),
            ));
        }
        let role = waygate_rbac::Role {
            id: Uuid::new_v4(),
            tenant_id: tenant.to_owned(),
            name: name.to_owned(),
            description: description.map(str::to_owned),
            scopes: scopes.to_vec(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        g.push(role.clone());
        Ok(role)
    }
    async fn get_role(
        &self,
        _: &str,
        id: Uuid,
    ) -> Result<Option<waygate_rbac::Role>, waygate_rbac::RbacError> {
        Ok(self
            .roles
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }
    async fn list_roles(
        &self,
        _: &str,
    ) -> Result<Vec<waygate_rbac::Role>, waygate_rbac::RbacError> {
        Ok(self.roles.lock().unwrap().clone())
    }
    async fn update_role(
        &self,
        _: &str,
        id: Uuid,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<Option<waygate_rbac::Role>, waygate_rbac::RbacError> {
        let mut g = self.roles.lock().unwrap();
        if g.iter().any(|r| r.id != id && r.name == name) {
            return Err(waygate_rbac::RbacError::Conflict(
                "a role with this name already exists".into(),
            ));
        }
        match g.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.name = name.to_owned();
                r.description = description.map(str::to_owned);
                r.scopes = scopes.to_vec();
                Ok(Some(r.clone()))
            }
            None => Ok(None),
        }
    }
    async fn delete_role(&self, _: &str, id: Uuid) -> Result<bool, waygate_rbac::RbacError> {
        let mut g = self.roles.lock().unwrap();
        let before = g.len();
        g.retain(|r| r.id != id);
        Ok(g.len() != before)
    }
    async fn delete_all_roles_for_tenant(&self, _: &str) -> Result<u64, waygate_rbac::RbacError> {
        Ok(0)
    }
    async fn create_assignment(
        &self,
        tenant: &str,
        role_id: Uuid,
        subject_sub: &str,
    ) -> Result<waygate_rbac::RoleAssignment, waygate_rbac::RbacError> {
        let a = waygate_rbac::RoleAssignment {
            id: Uuid::new_v4(),
            tenant_id: tenant.to_owned(),
            role_id,
            subject_sub: subject_sub.to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        self.assignments.lock().unwrap().push(a.clone());
        Ok(a)
    }
    async fn create_assignment_if_role_version(
        &self,
        tenant: &str,
        role_id: Uuid,
        subject_sub: &str,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<waygate_rbac::RoleAssignment>, waygate_rbac::RbacError> {
        let matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant
                && role.id == role_id
                && role.updated_at == expected_role_updated_at
        });
        if !matches {
            return Ok(None);
        }
        self.create_assignment(tenant, role_id, subject_sub)
            .await
            .map(Some)
    }
    async fn get_assignment(
        &self,
        _: &str,
        id: Uuid,
    ) -> Result<Option<waygate_rbac::RoleAssignment>, waygate_rbac::RbacError> {
        Ok(self
            .assignments
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.id == id)
            .cloned())
    }
    async fn list_assignments(
        &self,
        _: &str,
        role_id: Option<Uuid>,
        subject_sub: Option<&str>,
    ) -> Result<Vec<waygate_rbac::RoleAssignment>, waygate_rbac::RbacError> {
        Ok(self
            .assignments
            .lock()
            .unwrap()
            .iter()
            .filter(|a| role_id.is_none_or(|r| a.role_id == r))
            .filter(|a| subject_sub.is_none_or(|s| a.subject_sub == s))
            .cloned()
            .collect())
    }
    async fn delete_assignment(&self, _: &str, id: Uuid) -> Result<bool, waygate_rbac::RbacError> {
        let mut g = self.assignments.lock().unwrap();
        let before = g.len();
        g.retain(|a| a.id != id);
        Ok(g.len() != before)
    }
    async fn delete_assignment_if_role_version(
        &self,
        tenant: &str,
        id: Uuid,
        expected_role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<waygate_rbac::RoleAssignment>, waygate_rbac::RbacError> {
        let role_matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant
                && role.id == expected_role_id
                && role.updated_at == expected_role_updated_at
        });
        if !role_matches {
            return Ok(None);
        }
        let mut assignments = self.assignments.lock().unwrap();
        let Some(index) = assignments.iter().position(|assignment| {
            assignment.tenant_id == tenant
                && assignment.id == id
                && assignment.role_id == expected_role_id
        }) else {
            return Ok(None);
        };
        Ok(Some(assignments.remove(index)))
    }
    async fn create_group_mapping(
        &self,
        tenant: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<waygate_rbac::GroupRoleMapping, waygate_rbac::RbacError> {
        let mut g = self.mappings.lock().unwrap();
        if g.iter()
            .any(|m| m.group_id == group_id && m.role_id == role_id)
        {
            return Err(waygate_rbac::RbacError::Conflict(
                "mapping already exists".into(),
            ));
        }
        let m = waygate_rbac::GroupRoleMapping {
            tenant_id: tenant.to_owned(),
            group_id,
            role_id,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        g.push(m.clone());
        Ok(m)
    }
    async fn create_group_mapping_if_role_version(
        &self,
        tenant: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<waygate_rbac::GroupRoleMapping>, waygate_rbac::RbacError> {
        let role_matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant
                && role.id == role_id
                && role.updated_at == expected_role_updated_at
        });
        if !role_matches {
            return Ok(None);
        }
        self.create_group_mapping(tenant, group_id, role_id)
            .await
            .map(Some)
    }
    async fn list_group_mappings(
        &self,
        _: &str,
        role_id: Option<Uuid>,
        group_id: Option<Uuid>,
    ) -> Result<Vec<waygate_rbac::GroupRoleMapping>, waygate_rbac::RbacError> {
        Ok(self
            .mappings
            .lock()
            .unwrap()
            .iter()
            .filter(|m| role_id.is_none_or(|r| m.role_id == r))
            .filter(|m| group_id.is_none_or(|gid| m.group_id == gid))
            .cloned()
            .collect())
    }
    async fn delete_group_mapping(
        &self,
        _: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, waygate_rbac::RbacError> {
        let mut g = self.mappings.lock().unwrap();
        let before = g.len();
        g.retain(|m| !(m.group_id == group_id && m.role_id == role_id));
        Ok(g.len() != before)
    }
    async fn delete_group_mapping_if_versions(
        &self,
        tenant: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_mapping_created_at: OffsetDateTime,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<waygate_rbac::GroupRoleMapping>, waygate_rbac::RbacError> {
        let role_matches = self.roles.lock().unwrap().iter().any(|role| {
            role.tenant_id == tenant
                && role.id == role_id
                && role.updated_at == expected_role_updated_at
        });
        if !role_matches {
            return Ok(None);
        }
        let mut mappings = self.mappings.lock().unwrap();
        let Some(index) = mappings.iter().position(|mapping| {
            mapping.tenant_id == tenant
                && mapping.group_id == group_id
                && mapping.role_id == role_id
                && mapping.created_at == expected_mapping_created_at
        }) else {
            return Ok(None);
        };
        Ok(Some(mappings.remove(index)))
    }
}

pub(crate) async fn state_with_rbac_store(
    store: Arc<dyn waygate_rbac::RbacStore>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // RBAC mutations audit via record_required (fail-closed) → real sink.
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
        .with_rbac_store(Some(store)),
    )
}

pub(crate) fn seed_role(store: &InMemoryRbacStub, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    store.roles.lock().unwrap().push(waygate_rbac::Role {
        id,
        tenant_id: "default".into(),
        name: name.into(),
        description: None,
        scopes: vec!["mcp:read".into()],
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    });
    id
}

pub(crate) const RBAC_ROLE_CREATE: &str = "/rbac/roles/create";

#[tokio::test]
pub(crate) async fn rbac_role_create_persists_and_redirects() {
    let store = Arc::new(InMemoryRbacStub::default());
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        RBAC_ROLE_CREATE,
        "csrf=dev-csrf&name=ops-readonly&description=&scopes=mcp:read+mcp:invoke",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("/rbac"), "redirect target: {loc}");
    assert!(
        !loc.contains("rbac_error"),
        "success must not carry an error: {loc}"
    );
    let roles = store.roles.lock().unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "ops-readonly");
    assert_eq!(roles[0].scopes, vec!["mcp:read", "mcp:invoke"]);
}

#[tokio::test]
pub(crate) async fn rbac_role_create_rejects_bad_csrf() {
    let store = Arc::new(InMemoryRbacStub::default());
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) =
        post_form(app, RBAC_ROLE_CREATE, "csrf=WRONG&name=ops&scopes=mcp:read").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.roles.lock().unwrap().len(),
        0,
        "CSRF failure must not create"
    );
}

#[tokio::test]
pub(crate) async fn rbac_role_create_rejects_empty_name() {
    let store = Arc::new(InMemoryRbacStub::default());
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) =
        post_form(app, RBAC_ROLE_CREATE, "csrf=dev-csrf&name=&scopes=mcp:read").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("rbac_error"),
        "empty name must redirect with error: {loc}"
    );
    assert_eq!(store.roles.lock().unwrap().len(), 0);
}

#[tokio::test]
pub(crate) async fn rbac_role_update_persists_and_redirects() {
    let store = Arc::new(InMemoryRbacStub::default());
    let id = seed_role(&store, "before");
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        &format!("/rbac/roles/{id}/update"),
        "csrf=dev-csrf&name=after&description=updated&scopes=mcp:admin",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("rbac_error"), "update should succeed: {loc}");
    let roles = store.roles.lock().unwrap();
    assert_eq!(roles[0].name, "after");
    assert_eq!(roles[0].scopes, vec!["mcp:admin"]);
}

#[tokio::test]
pub(crate) async fn rbac_role_delete_persists_and_redirects() {
    let store = Arc::new(InMemoryRbacStub::default());
    let id = seed_role(&store, "doomed");
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(app, &format!("/rbac/roles/{id}/delete"), "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("rbac_error"), "delete should succeed: {loc}");
    assert_eq!(store.roles.lock().unwrap().len(), 0, "role should be gone");
}

#[tokio::test]
pub(crate) async fn rbac_role_delete_rejects_bad_csrf() {
    let store = Arc::new(InMemoryRbacStub::default());
    let id = seed_role(&store, "keep");
    let app = dashboard_router(
        state_with_rbac_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(app, &format!("/rbac/roles/{id}/delete"), "csrf=WRONG").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.roles.lock().unwrap().len(),
        1,
        "CSRF failure must not delete"
    );
}

#[tokio::test]
pub(crate) async fn rbac_page_renders_role_create_form_for_admin() {
    let store = Arc::new(InMemoryRbacStub::default());
    let app = dashboard_router(state_with_rbac_store(store).await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/rbac").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Create a role") && body.contains(r#"action="/admin/rbac/roles/create""#),
        "role create form should render for an admin when the store is wired"
    );
}
