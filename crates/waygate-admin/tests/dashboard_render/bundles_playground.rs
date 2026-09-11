//! Policy bundles + playground + saved scenarios — split from the
//! monolithic `dashboard_render.rs`; bodies verbatim, cut at the file's
//! own section markers.

use crate::common::*;

// ---- Policy bundles page ---------------------------------------------

/// Policy-bundles page renders at both mounts. empty_state has no
/// policy store wired → renders the disabled-state card.
#[tokio::test]
pub(crate) async fn policy_bundles_page_renders_with_disabled_state_when_no_store() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/policy_bundles", "/t/default/policy_bundles"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "policy_bundles page failed at {path}"
        );
        assert!(
            body.contains("Policy bundles"),
            "page title missing at {path}"
        );
        assert!(
            body.contains("Policy bundle store not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// Policy sidebar group force-opens on /policy_bundles
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn policy_bundles_page_marks_policy_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policy_bundles").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/policies" aria-current="page""#),
        "the Policy destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/policy_bundles" aria-current="page""#),
        "Policy bundles nav link missing aria-current on legacy mount",
    );
}

/// Palette finds Policy bundles in its catalogue.
#[tokio::test]
pub(crate) async fn policy_bundles_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=bundle").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Policy bundles""#),
        "Policy bundles missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Cedar policy bundle versions"#),
        "Policy bundles hint missing from palette search result: {body}",
    );
}

// ---- Playground page --------------------------------------------------

/// Playground page renders at both mounts. empty_state has no Cedar
/// engine wired → renders the "cedar engine not configured" card.
#[tokio::test]
pub(crate) async fn playground_page_renders_with_disabled_state_when_no_engine() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/playground", "/t/default/playground"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "playground page failed at {path}");
        assert!(body.contains("Playground"), "page title missing at {path}");
        assert!(
            body.contains("Cedar engine is not configured"),
            "expected disabled-state copy at {path}",
        );
    }
}

/// Policy sidebar group force-opens on /playground
/// (contains_active behavior).
#[tokio::test]
pub(crate) async fn playground_page_marks_policy_group_active() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/playground").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/policies" aria-current="page""#),
        "the Policy destination should be current in the sidebar",
    );
    assert!(
        body.contains(r#"href="/admin/playground" aria-current="page""#),
        "Playground nav link missing aria-current on legacy mount",
    );
}

/// Palette finds Playground in its catalogue.
#[tokio::test]
pub(crate) async fn playground_search_item_appears_in_palette_catalogue() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/search?q=playground").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""label":"Playground""#),
        "Playground missing from palette search results: {body}",
    );
    assert!(
        body.contains(r#""hint":"Interactive Cedar policy simulator"#),
        "Playground hint missing from palette search result: {body}",
    );
}

// ---- Playground saved scenarios ------------------------------------------

/// The saved-scenarios sidebar + Save form hide entirely
/// when no scenarios store is wired. The page falls back to the
/// stateless shape and the warning chip notes the absent
/// store.
#[tokio::test]
pub(crate) async fn playground_hides_save_affordances_without_scenarios_store() {
    let app = dashboard_router(state_with_cedar().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/playground").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("scenarios store not configured"),
        "expected the scenarios-store-not-configured chip when only \
         the Cedar engine is wired",
    );
    assert!(
        !body.contains(r#"aria-label="Saved scenarios""#),
        "Saved scenarios sidebar must not render without the store",
    );
    assert!(
        !body.contains("/playground/scenarios"),
        "Save / Delete URLs must not render without the store",
    );
}

/// With the scenarios store wired (empty) the sidebar
/// renders, the Save form appears with the canonical defaults
/// stamped into the hidden inputs, and the URL stays inside
/// the active tenant prefix.
#[tokio::test]
pub(crate) async fn playground_renders_save_form_with_empty_store() {
    let state = state_with_cedar_and_scenarios(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/playground").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"aria-label="Saved scenarios""#),
        "Saved scenarios sidebar should render when the store is wired",
    );
    assert!(
        body.contains("None yet."),
        "empty-store sidebar should render the 'None yet.' notice",
    );
    // Save form POSTs to the tenant-prefixed mount.
    assert!(
        body.contains(r#"action="/admin/t/default/playground/scenarios""#),
        "Save form action should be the tenant-prefixed scenarios endpoint",
    );
    // Defaults from PlaygroundForm::default carry into the
    // Save form's hidden inputs so the first Save captures
    // the canonical example without an explicit Simulate click.
    assert!(body.contains(r#"name="sub" value="alice@example.com""#));
}

/// Loading a saved scenario by name pre-fills every
/// form input from the body JSON.
#[tokio::test]
pub(crate) async fn playground_load_prefills_form_from_saved_body() {
    let body = serde_json::json!({
        "sub": "bob@example.com",
        "groups": "ops",
        "scopes": "mcp:admin",
        "auth_method": "api_key",
        "action": "list_tools",
        "risk": "high",
        "resource_type": "server",
        "server": "example-observability",
        "tool": "query",
        "tool_name": "query",
        "pii": true,
    });
    let state = state_with_cedar_and_scenarios(vec![InMemoryScenario {
        name: "ops-deny".into(),
        body,
    }])
    .await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/playground?load=ops-deny").await;
    assert_eq!(status, StatusCode::OK);
    // Every form field reflects the saved body.
    assert!(body.contains(r#"name="sub" type="text" value="bob@example.com""#));
    assert!(body.contains(r#"name="groups" type="text" value="ops""#));
    assert!(body.contains(r#"name="scopes" type="text" value="mcp:admin""#));
    assert!(body.contains(r#"<option value="api_key" selected>"#));
    assert!(body.contains(r#"<option value="list_tools" selected>"#));
    assert!(body.contains(r#"<option value="high" selected>"#));
    assert!(body.contains(r#"<option value="server" selected>"#));
    assert!(body.contains(r#"id="pg-pii" name="pii" type="checkbox" checked"#));
    // The Save form's name input pre-fills with the loaded
    // name so re-save is one click.
    assert!(body.contains(r#"value="ops-deny""#));
}

/// Load against an unknown name renders the form with
/// defaults + the load-miss notice (no 404).
#[tokio::test]
pub(crate) async fn playground_load_unknown_name_renders_defaults_with_notice() {
    let state = state_with_cedar_and_scenarios(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/playground?load=never-saved").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Scenario not found"),
        "expected the load-miss notice for an unknown scenario name",
    );
    // Defaults still render.
    assert!(body.contains(r#"name="sub" type="text" value="alice@example.com""#));
}

/// Unknown JSON keys in an existing scenario body must survive
/// a re-save. The preservation lives in the STORE's atomic merge
/// upsert (`body || EXCLUDED.body`, mirroring saved-views' shape);
/// the Save handler sends known fields only and does no
/// pre-read. Seed a scenario whose body carries `_future_field`,
/// POST a Save against the same name, then fetch from the store
/// and assert the unknown key is still present alongside the
/// updated known fields.
#[tokio::test]
pub(crate) async fn playground_save_preserves_unknown_body_keys() {
    let stub = Arc::new(InMemoryScenarioStub::seeded(vec![InMemoryScenario {
        name: "future-test".into(),
        body: serde_json::json!({
            "sub": "alice@example.com",
            "_future_field": "must survive round-trip",
            "_another_unknown": 42,
        }),
    }]));

    use std::path::PathBuf;
    let policies_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("crates/waygate-authz/tests/fixtures/policies");
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::load_dir(&policies_dir).expect("load workspace policies/"),
    ));
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let state = Arc::new(
        AdminState::new(
            pool,
            Some(engine),
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_playground_scenarios(Some(stub.clone()
            as Arc<dyn waygate_dashboard_stores::playground_scenarios::PlaygroundScenarioStore>)),
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);

    // POST a Save against the same name. CSRF token is the
    // disabled-mode dev value injected by the auth middleware
    // (`dev-csrf`). Known fields all carry NEW values so the
    // assertion below can prove the merge wrote them in.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/playground/scenarios")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=dev-csrf&name=future-test\
                     &sub=bob@example.com&groups=ops&scopes=mcp:admin\
                     &auth_method=api_key&action=list_tools&risk=high\
                     &resource_type=server&server=example-observability&tool=query\
                     &tool_name=query",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // PRG: handler returns 303 (axum's Redirect::to default).
    assert!(
        resp.status().is_redirection(),
        "Save should redirect on success, got {}",
        resp.status(),
    );

    // Read back from the store directly. Unknown keys must survive;
    // known keys must reflect the new POST values.
    use waygate_dashboard_stores::playground_scenarios::PlaygroundScenarioStore as _;
    let saved = stub
        .get("default", "future-test")
        .await
        .expect("get must succeed")
        .expect("scenario must still exist");
    let obj = saved.body.as_object().expect("body must be a JSON object");
    assert_eq!(
        obj.get("_future_field").and_then(|v| v.as_str()),
        Some("must survive round-trip"),
        "unknown string key `_future_field` must round-trip across Save",
    );
    assert_eq!(
        obj.get("_another_unknown").and_then(|v| v.as_i64()),
        Some(42),
        "unknown numeric key `_another_unknown` must round-trip across Save",
    );
    // Known fields reflect the POST values, not the seed.
    assert_eq!(
        obj.get("sub").and_then(|v| v.as_str()),
        Some("bob@example.com"),
        "known `sub` field should reflect the new POST value",
    );
    assert_eq!(
        obj.get("risk").and_then(|v| v.as_str()),
        Some("high"),
        "known `risk` field should reflect the new POST value",
    );
}

/// In-memory `PlaygroundScenarioStore` stub for the saved-scenarios tests.
/// Carries a fixed seed list and a thread-safe mutation map so
/// save/delete work end-to-end. Reads + writes share the same
/// `tokio::sync::Mutex` so the GET handler sees writes made by
/// the POST handler in the same test.
#[derive(Default)]
pub(crate) struct InMemoryScenarioStub {
    rows: tokio::sync::Mutex<Vec<waygate_dashboard_stores::playground_scenarios::Scenario>>,
}

pub(crate) struct InMemoryScenario {
    name: String,
    body: serde_json::Value,
}

impl InMemoryScenarioStub {
    pub(crate) fn seeded(seed: Vec<InMemoryScenario>) -> Self {
        let rows = seed
            .into_iter()
            .map(
                |s| waygate_dashboard_stores::playground_scenarios::Scenario {
                    tenant_id: "default".into(),
                    name: s.name,
                    body: s.body,
                    created_by: Some("test".into()),
                    created_at: time::OffsetDateTime::UNIX_EPOCH,
                    updated_at: time::OffsetDateTime::UNIX_EPOCH,
                },
            )
            .collect();
        Self {
            rows: tokio::sync::Mutex::new(rows),
        }
    }
}

#[async_trait::async_trait]
impl waygate_dashboard_stores::playground_scenarios::PlaygroundScenarioStore
    for InMemoryScenarioStub
{
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<
        Vec<waygate_dashboard_stores::playground_scenarios::Scenario>,
        waygate_dashboard_stores::playground_scenarios::ScenarioError,
    > {
        let guard = self.rows.lock().await;
        Ok(guard
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect())
    }
    async fn get(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<
        Option<waygate_dashboard_stores::playground_scenarios::Scenario>,
        waygate_dashboard_stores::playground_scenarios::ScenarioError,
    > {
        let guard = self.rows.lock().await;
        Ok(guard
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.name == name)
            .cloned())
    }
    async fn save(
        &self,
        tenant_id: &str,
        name: &str,
        body: serde_json::Value,
        created_by: Option<&str>,
    ) -> Result<
        waygate_dashboard_stores::playground_scenarios::Scenario,
        waygate_dashboard_stores::playground_scenarios::ScenarioError,
    > {
        let mut guard = self.rows.lock().await;
        if let Some(existing) = guard
            .iter_mut()
            .find(|r| r.tenant_id == tenant_id && r.name == name)
        {
            // Mirror the trait contract the Pg impl provides: an atomic
            // top-level JSONB merge on overwrite (`body || EXCLUDED.body`)
            // — submitted keys win, existing keys survive — and COALESCE
            // authorship. Pinned by the playground_scenarios module's
            // pg_upsert_contract test.
            if let (serde_json::Value::Object(base), serde_json::Value::Object(new)) =
                (&mut existing.body, body)
            {
                for (k, v) in new {
                    base.insert(k, v);
                }
            }
            if existing.created_by.is_none() {
                existing.created_by = created_by.map(str::to_owned);
            }
            Ok(existing.clone())
        } else {
            let row = waygate_dashboard_stores::playground_scenarios::Scenario {
                tenant_id: tenant_id.into(),
                name: name.into(),
                body,
                created_by: created_by.map(str::to_owned),
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
            };
            guard.push(row.clone());
            Ok(row)
        }
    }
    async fn delete(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<bool, waygate_dashboard_stores::playground_scenarios::ScenarioError> {
        let mut guard = self.rows.lock().await;
        let before = guard.len();
        guard.retain(|r| !(r.tenant_id == tenant_id && r.name == name));
        Ok(guard.len() < before)
    }
}

pub(crate) async fn state_with_cedar_and_scenarios(seed: Vec<InMemoryScenario>) -> Arc<AdminState> {
    use std::path::PathBuf;
    let policies_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("crates/waygate-authz/tests/fixtures/policies");
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::load_dir(&policies_dir).expect("load workspace policies/"),
    ));
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let scenarios: Arc<
        dyn waygate_dashboard_stores::playground_scenarios::PlaygroundScenarioStore,
    > = Arc::new(InMemoryScenarioStub::seeded(seed));
    Arc::new(
        AdminState::new(
            pool,
            Some(engine),
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_playground_scenarios(Some(scenarios)),
    )
}
