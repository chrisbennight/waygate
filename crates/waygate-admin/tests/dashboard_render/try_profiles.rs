//! Governed try-tool + API-key profiles — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::common::*;
pub(crate) use waygate_test_support::mocks::InMemoryProfileStore;

// ---- Governed "Try this tool" ----------------------------------------------
//
// These tests pin the security contract of the dashboard try-it surface:
// every precondition (admin scope, CSRF, the high-risk confirm guard, and
// argument parsing) is enforced *before* the call reaches the invocation
// pipeline. The `CountingInvocation` stub stands in for the real
// `SharedInvocation`; its call counter lets us assert that a *blocked*
// request never reaches `invoke` (counter stays 0) while an allowed one
// does (counter ticks to 1). It deliberately returns `Forbidden` so the
// "reached the pipeline" tests don't have to construct a success
// `CallToolResult`, and the error-rendering path gets covered for free.

use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct CountingInvocation {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl waygate_invocation::InvocationService for CountingInvocation {
    async fn invoke(
        &self,
        _principal: Option<&waygate_oidc::Principal>,
        _req: waygate_invocation::InvocationRequest,
    ) -> Result<waygate_invocation::InvocationResponse, waygate_invocation::InvocationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(waygate_invocation::InvocationError::Forbidden {
            reason: "stub denied".into(),
            policy_ids: vec![],
            reasons: vec![],
        })
    }
}

/// `state_with_manifests` plus a counter-backed `try_invocation`, so the
/// try-it endpoint is "wired" and we can observe whether `invoke` runs.
/// Upstreams stay disconnected (so `list_tools` returns empty and the
/// existence check is skipped — the catalog/invoke path is the authority).
pub(crate) fn counting_state(calls: Arc<AtomicUsize>) -> Arc<AdminState> {
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let inv: waygate_mcp::SharedInvocation = Arc::new(CountingInvocation { calls });
    Arc::new(base_admin_state_with_pool(pool).with_try_invocation(inv))
}

pub(crate) async fn post_try(app: axum::Router, body: &'static str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tools/try")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
pub(crate) async fn tools_try_unavailable_when_pipeline_unwired() {
    // `state_with_manifests` leaves `try_invocation = None` — the endpoint
    // must explain rather than 500.
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = post_try(
        app,
        "csrf=dev-csrf&server=example-messages&tool=list_contacts&arguments=",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Try-it unavailable"),
        "expected unavailable fragment, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn tools_try_rejects_bad_csrf() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = dashboard_router(counting_state(calls.clone()), DashboardAuth::Disabled);
    let (status, _body) = post_try(
        app,
        "csrf=WRONG&server=example-messages&tool=list_contacts&arguments=",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "CSRF failure must not invoke"
    );
}

#[tokio::test]
pub(crate) async fn tools_try_high_risk_requires_confirm_and_does_not_invoke() {
    // send_msg is High + side_effects. Without the confirm box, the guard
    // must block BEFORE the irreversible call — counter stays 0.
    let calls = Arc::new(AtomicUsize::new(0));
    let app = dashboard_router(counting_state(calls.clone()), DashboardAuth::Disabled);
    let (status, body) = post_try(
        app,
        "csrf=dev-csrf&server=example-messages&tool=send_msg&arguments=%7B%7D",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Confirmation required"),
        "expected confirm-required fragment, got: {body}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "high-risk tool without confirm must NOT reach the invocation pipeline"
    );
}

#[tokio::test]
pub(crate) async fn tools_try_invalid_arguments_blocks_invoke() {
    // Malformed JSON is rejected before the call (validate-before-invoke).
    let calls = Arc::new(AtomicUsize::new(0));
    let app = dashboard_router(counting_state(calls.clone()), DashboardAuth::Disabled);
    let (status, body) = post_try(
        app,
        "csrf=dev-csrf&server=example-messages&tool=list_contacts&arguments=not-json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Invalid arguments"),
        "expected invalid-arguments fragment, got: {body}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "unparseable arguments must NOT reach the invocation pipeline"
    );
}

#[tokio::test]
pub(crate) async fn tools_try_low_risk_reaches_pipeline() {
    // list_contacts is Low + no side effects ⇒ no confirm needed. The call
    // reaches `invoke` (counter == 1) and the stub's Forbidden renders.
    let calls = Arc::new(AtomicUsize::new(0));
    let app = dashboard_router(counting_state(calls.clone()), DashboardAuth::Disabled);
    let (status, body) = post_try(
        app,
        "csrf=dev-csrf&server=example-messages&tool=list_contacts&arguments=%7B%7D",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a low-risk allowed call must reach the invocation pipeline exactly once"
    );
    assert!(
        body.contains("Denied by policy") && body.contains("stub denied"),
        "expected the pipeline's Forbidden verdict to render, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn tools_try_high_risk_with_confirm_reaches_pipeline() {
    // With the confirm box ticked, the high-risk guard unlocks and the call
    // reaches the pipeline.
    let calls = Arc::new(AtomicUsize::new(0));
    let app = dashboard_router(counting_state(calls.clone()), DashboardAuth::Disabled);
    let (status, _body) = post_try(
        app,
        "csrf=dev-csrf&server=example-messages&tool=send_msg&arguments=%7B%7D&confirm=on",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a confirmed high-risk call must reach the invocation pipeline"
    );
}

// The crux of the fix: the confirm guard must key off the
// SAME facts the invocation pipeline uses (the governed, tenant-aware
// catalog), not the manifest-only `tool_facts`. This fake classifies
// `list_contacts` as High even though the manifest (example_messages_manifest) marks
// it Low/no-side-effects — so if the guard followed the manifest it would
// wrongly skip confirmation. All methods but `resolve_tool` are inert
// stubs (the catalog_api.rs fake skeleton).
pub(crate) struct HighRiskCatalog;

#[async_trait]
impl waygate_catalog::CatalogStore for HighRiskCatalog {
    async fn resolve_tool(
        &self,
        _tenant: &str,
        fq: &str,
    ) -> Result<waygate_catalog::ResolvedTool, waygate_catalog::CatalogError> {
        if fq == "example-messages.list_contacts" {
            Ok(waygate_catalog::ResolvedTool::Live(Box::new(
                waygate_catalog::ToolDefinition {
                    discriminator: None,
                    operations: Vec::new(),
                    tool_id: Uuid::nil(),
                    server_id: Uuid::nil(),
                    server_name: "example-messages".into(),
                    tool_name: "list_contacts".into(),
                    schema_hash: String::new(),
                    description: String::new(),
                    classification_mode: "manifest".into(),
                    input_schema: None,
                    output_schema: None,
                    tool_annotations: None,
                    action_metadata: None,
                    // Catalog says High; the manifest says Low. The guard
                    // must follow THIS source.
                    risk: "high".into(),
                    side_effects: false,
                    pii: false,
                    data_classification: None,
                    cost_class: None,
                    requires_approval: false,
                },
            )))
        } else {
            Ok(waygate_catalog::ResolvedTool::NotFound)
        }
    }
    async fn approved_servers(
        &self,
        _t: &str,
    ) -> Result<Vec<waygate_catalog::CatalogServerSummary>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn record_drift(
        &self,
        _o: waygate_catalog::DriftObservation<'_>,
    ) -> Result<(), waygate_catalog::CatalogError> {
        Ok(())
    }
    async fn record_approval(
        &self,
        _a: waygate_catalog::ApprovalAction<'_>,
    ) -> Result<(), waygate_catalog::CatalogError> {
        Ok(())
    }
    async fn list_drift_events(
        &self,
        _t: &str,
        _since: time::OffsetDateTime,
        _limit: u32,
    ) -> Result<Vec<waygate_catalog::DriftEvent>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn set_server_status(
        &self,
        _tenant: &str,
        _server_id: Uuid,
        _status: waygate_catalog::CatalogServerStatus,
        _actor: &str,
        _reason: Option<&str>,
    ) -> Result<bool, waygate_catalog::CatalogError> {
        Ok(false)
    }
    async fn last_approve_actor(
        &self,
        _tenant: &str,
        _server_id: Uuid,
    ) -> Result<Option<String>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn find_grant<'a>(
        &self,
        _lookup: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn claim_grant<'a>(
        &self,
        _lookup: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        Ok(None)
    }
    async fn create_grant<'a>(
        &self,
        _grant: waygate_catalog::NewApprovalGrant<'a>,
    ) -> Result<waygate_catalog::ApprovalGrant, waygate_catalog::CatalogError> {
        Err(waygate_catalog::CatalogError::Unknown("unused"))
    }
    async fn list_grants<'a>(
        &self,
        _tenant_id: &'a str,
        _filter: waygate_catalog::GrantFilter<'a>,
    ) -> Result<Vec<waygate_catalog::ApprovalGrant>, waygate_catalog::CatalogError> {
        Ok(vec![])
    }
    async fn revoke_grant(
        &self,
        _tenant_id: &str,
        _id: Uuid,
    ) -> Result<bool, waygate_catalog::CatalogError> {
        Ok(false)
    }
    async fn sweep_grants(
        &self,
        _older_than: time::OffsetDateTime,
    ) -> Result<u64, waygate_catalog::CatalogError> {
        Ok(0)
    }
}

pub(crate) fn counting_state_with_catalog(
    calls: Arc<AtomicUsize>,
    catalog: waygate_catalog::SharedCatalogStore,
) -> Arc<AdminState> {
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests).with_catalog(catalog));
    let inv: waygate_mcp::SharedInvocation = Arc::new(CountingInvocation { calls });
    Arc::new(base_admin_state_with_pool(pool).with_try_invocation(inv))
}

#[tokio::test]
pub(crate) async fn tools_try_guard_follows_catalog_risk_not_manifest() {
    // The manifest marks list_contacts Low/no-side-effects, but the governed
    // catalog (which the invocation pipeline resolves facts from) marks it
    // High. The confirm guard must follow the catalog: a POST without confirm
    // is blocked and never reaches `invoke` — even though the manifest alone
    // would have allowed it straight through.
    let calls = Arc::new(AtomicUsize::new(0));
    let catalog: waygate_catalog::SharedCatalogStore = Arc::new(HighRiskCatalog);
    let app = dashboard_router(
        counting_state_with_catalog(calls.clone(), catalog),
        DashboardAuth::Disabled,
    );
    let (status, body) = post_try(
        app,
        "csrf=dev-csrf&server=example-messages&tool=list_contacts&arguments=%7B%7D",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Confirmation required"),
        "a catalog-classified high-risk tool must require confirmation even when \
         the manifest says low, got: {body}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the guard must use the catalog's High classification, not the manifest's Low — \
         the call must NOT reach the invocation pipeline without confirmation"
    );
}

// ---- API-key profiles: in-page create form ---------------------------------
//
// An in-memory ProfileStore drives the identities page's create form end to
// end: the form renders for an admin when the store is wired, bad CSRF is
// rejected, a valid POST persists (with the list fields parsed from the
// free-text inputs) and PRG-redirects, and a validation failure redirects
// with an `?akp_error=` message instead of persisting.

pub(crate) async fn state_with_profile_store(
    store: Arc<dyn waygate_apikeys::ProfileStore>,
) -> Arc<AdminState> {
    let mut manifests = BTreeMap::new();
    manifests.insert("example-messages".into(), example_messages_manifest());
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    // The create path's audit uses `record_required` (fail-closed), which
    // errors on `NullSink` — use an in-memory sink so a successful create can
    // complete its durable AdminMutation row.
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
        .with_api_key_profile_store(Some(store)),
    )
}

/// POST to the create route; returns (status, location-header).
pub(crate) async fn post_akp(app: axum::Router, body: &'static str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/identities/api-key-profiles/create")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
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

/// POST to the per-row delete route for `id`; returns (status, location).
pub(crate) async fn post_akp_delete(
    app: axum::Router,
    id: Uuid,
    body: &'static str,
) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/identities/api-key-profiles/{id}/delete"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
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

/// Push a profile with a known id into the fake store; returns the id so a
/// test can drive the delete route against it.
pub(crate) fn seed_profile(store: &InMemoryProfileStore, name: &str) -> Uuid {
    store.seed_profile("default", name)
}

#[tokio::test]
pub(crate) async fn api_key_profiles_delete_persists_and_redirects() {
    let store = Arc::new(InMemoryProfileStore::default());
    let id = seed_profile(&store, "to-delete");
    let app = dashboard_router(
        state_with_profile_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_akp_delete(app, id, "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("/profiles"), "redirect target: {loc}");
    assert!(
        !loc.contains("akp_error"),
        "a successful delete must not carry an error: {loc}"
    );
    assert_eq!(store.len(), 0, "the profile should be gone after delete");
}

#[tokio::test]
pub(crate) async fn api_key_profiles_delete_rejects_bad_csrf() {
    let store = Arc::new(InMemoryProfileStore::default());
    let id = seed_profile(&store, "keep-me");
    let app = dashboard_router(
        state_with_profile_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_akp_delete(app, id, "csrf=WRONG").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(store.len(), 1, "a CSRF failure must not delete the profile");
}

#[tokio::test]
pub(crate) async fn api_key_profiles_delete_referenced_redirects_with_error() {
    // The migration-0027 BEFORE-DELETE trigger refuses to delete a profile
    // still referenced by a live api_keys row; the store surfaces
    // ProfileStoreError::Blocked, which delete_profile_core maps to a 409
    // whose message the section re-renders beside the table via akp_error.
    let store = Arc::new(InMemoryProfileStore::default());
    let id = seed_profile(&store, "in-use");
    store.set_delete_block(Some(2));
    let app = dashboard_router(
        state_with_profile_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_akp_delete(app, id, "csrf=dev-csrf").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("akp_error"),
        "a blocked delete must redirect with an error: {loc}"
    );
    assert_eq!(
        store.len(),
        1,
        "a blocked delete must not remove the profile"
    );
}

#[tokio::test]
pub(crate) async fn api_key_profiles_form_renders_for_admin_when_store_wired() {
    let store = Arc::new(InMemoryProfileStore::default());
    let app = dashboard_router(
        state_with_profile_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/profiles").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Create an API-key profile"),
        "the create form should render for an admin when the store is wired"
    );
    assert!(
        body.contains(r#"name="allowed_scopes""#) && body.contains(r#"name="max_ttl_seconds""#),
        "form fields should be present"
    );
    // The create form is built from the shared .form-* vocabulary.
    assert!(
        body.contains(r#"class="form-input""#) && body.contains(r#"class="form-label""#),
        "create form should use the shared .form-* components"
    );
}

#[tokio::test]
pub(crate) async fn api_key_profiles_create_rejects_bad_csrf() {
    let store = Arc::new(InMemoryProfileStore::default());
    let app = dashboard_router(
        state_with_profile_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_akp(
        app,
        "csrf=WRONG&name=ci&max_ttl_seconds=3600&allowed_scopes=mcp:invoke",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(store.len(), 0, "a CSRF failure must not persist a profile");
}

#[tokio::test]
pub(crate) async fn api_key_profiles_create_persists_and_redirects() {
    let store = Arc::new(InMemoryProfileStore::default());
    let app = dashboard_router(
        state_with_profile_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    // Two scopes (space-separated), blank servers/tools (⇒ None), both gates on.
    let (status, loc) = post_akp(
        app,
        "csrf=dev-csrf&name=ci-readonly&description=&max_ttl_seconds=3600\
         &allowed_scopes=mcp:invoke+mcp:read&allowed_servers=&allowed_tools=\
         &requires_reason=on&requires_owner=on",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(loc.contains("/profiles"), "redirect target: {loc}");
    assert!(
        !loc.contains("akp_error"),
        "success must not carry an error: {loc}"
    );

    let profiles = store.snapshot();
    assert_eq!(profiles.len(), 1);
    let p = &profiles[0];
    assert_eq!(p.name, "ci-readonly");
    assert_eq!(p.max_ttl_seconds, 3600);
    assert_eq!(p.allowed_scopes, vec!["mcp:invoke", "mcp:read"]);
    assert!(
        p.allowed_servers.is_none(),
        "blank allowed_servers must parse to None (any)"
    );
    assert!(p.allowed_tools.is_none());
    assert!(p.requires_reason && p.requires_owner);
}

#[tokio::test]
pub(crate) async fn api_key_profiles_create_invalid_scopes_redirects_with_error() {
    // validate_create rejects an empty allowed_scopes list. The form should
    // PRG-redirect with an akp_error message and NOT persist.
    let store = Arc::new(InMemoryProfileStore::default());
    let app = dashboard_router(
        state_with_profile_store(store.clone()).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_akp(
        app,
        "csrf=dev-csrf&name=bad&max_ttl_seconds=3600&allowed_scopes=&allowed_servers=&allowed_tools=",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("akp_error"),
        "a validation failure must redirect with an error: {loc}"
    );
    assert_eq!(store.len(), 0, "an invalid submission must not persist");
}

#[tokio::test]
pub(crate) async fn api_key_profiles_create_error_opens_form_even_with_existing_profiles() {
    // A duplicate-name failure has existing profiles, so keying the form's
    // default-open state only off `profiles.is_empty()` would hide the error
    // in a collapsed `<details>`. The error must force it open.
    let store = Arc::new(InMemoryProfileStore::default());
    store.seed_profile("default", "existing");
    let app = dashboard_router(
        state_with_profile_store(store).await,
        DashboardAuth::Disabled,
    );
    // The PRG redirect lands here with the create error in the query string.
    let (status, body) = body_of(app, "/profiles?akp_error=duplicate%20name").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("duplicate name"),
        "the create error must render beside the form"
    );
    assert!(
        body.contains(r#"class="disclosure" open"#),
        "the form must be open so the error is visible even though a profile already exists"
    );
}

#[tokio::test]
pub(crate) async fn api_key_profiles_create_form_is_in_its_own_padded_card() {
    // Regression: the create form must NOT be nested inside the profiles
    // `.card--table`. That variant zeroes the card's content gutter so a table
    // can sit flush; a form placed in it renders flush to the card edge (its
    // inputs lose the left padding) — the alignment defect this fixes, and the
    // odd-one-out vs every other management page. The form must sit in its own
    // plain `.card`, which carries the standard 16/20px content inset.
    let store = Arc::new(InMemoryProfileStore::default());
    let app = dashboard_router(
        state_with_profile_store(store).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/profiles").await;
    assert_eq!(status, StatusCode::OK);

    let table_card = body
        .find(r#"class="card card--table""#)
        .expect("profiles table-card present");
    let summary = body
        .find("+ Create an API-key profile")
        .expect("create form present");
    assert!(
        summary > table_card,
        "the create form should render after the profiles table-card"
    );
    // The card immediately enclosing the create form must be a plain `.card`,
    // not the flush `.card--table`. Find the nearest card opening before the
    // form summary and assert it isn't the table variant.
    let form_card = body[..summary]
        .rfind(r#"<div class="card"#)
        .expect("create form is wrapped in a card");
    assert!(
        !body[form_card..summary].contains("card--table"),
        "the create form must be in a plain .card (padded), not the flush .card--table"
    );
}
