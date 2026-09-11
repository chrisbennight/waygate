//! Mobile polish + policy-bundles editor — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::chrome::stub_enforce_auth;
use crate::common::*;
use crate::crud_pages::post_form_body;
use crate::policy_edit_agents::encode_form_value;

// ---- Mobile polish ----------------------------------------------------

/// Every table-bearing card uses the `card--table` modifier
/// class instead of the prior inline `style="padding: 0;
/// overflow: hidden"`. The shared CSS rule in base.css gives the
/// modifier `overflow: auto` so narrow-viewport readers can
/// horizontally scroll wide tables instead of having columns
/// silently clipped past the card edge. This regression test
/// catches anyone re-introducing the old inline style on a new
/// table card, OR mass-applying the wrong class on a future
/// page.
///
/// We sample a handful of representative tables (servers — wide
/// columns; rbac — three cards on one page; scim — disabled vs
/// populated branches; settings — multiple kv tables; activity —
/// the heaviest table) rather than scanning every template, so a
/// targeted edit on one page doesn't have to rewrite every other
/// page's body.
#[tokio::test]
pub(crate) async fn table_cards_carry_responsive_class_not_inline_overflow() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/servers", "/rbac", "/scim", "/settings", "/activity"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "page {path} failed to render");
        assert!(
            !body.contains(r#"style="padding: 0; overflow: hidden""#),
            "{path}: legacy inline `style=\"padding: 0; overflow: hidden\"` \
             on a card has reappeared — should use `.card card--table` so \
             narrow viewports get horizontal scroll instead of a hidden \
             clip.",
        );
    }
    // At least one page should actually carry the new class — proves
    // the modifier rendered (vs. the substring check above being a
    // tautology that passes when no cards render at all).
    let (_, body) = body_of(app, "/servers").await;
    assert!(
        body.contains(r#"class="card card--table""#),
        "expected at least one `.card card--table` on /servers — the \
         modifier class didn't render",
    );
}

#[tokio::test]
pub(crate) async fn enforce_mode_logout_clears_session_cookie() {
    let app = dashboard_router(empty_state().await, stub_enforce_auth());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cookie.starts_with("mcp-gw-session="),
        "session clear cookie missing"
    );
    assert!(cookie.contains("Max-Age=0"));
}

// ---- Policy bundles editor ------------------------------------------------

/// In-memory PolicyStore stub mirroring the per-domain shape the
/// playground/scenarios/provisioning-log tests use. Holds a static
/// list of bundles + an optional "active" id so the editor's
/// `?load=<id>` path can fetch a known source. Mutating methods
/// (`create_draft`, `publish`, `rollback_to`, `delete_all_*`) are
/// not exercised by the render tests (the dashboard mutation
/// handlers POST to redirect, and `body_of` follows redirects
/// without re-issuing GETs at the new URL); they panic to make
/// any future render test that calls them loud.
#[derive(Default)]
pub(crate) struct InMemoryPolicyStore {
    pub(crate) bundles: tokio::sync::Mutex<Vec<waygate_policy::PolicyBundle>>,
}

impl InMemoryPolicyStore {
    pub(crate) fn seeded(seed: Vec<waygate_policy::PolicyBundle>) -> Self {
        Self {
            bundles: tokio::sync::Mutex::new(seed),
        }
    }
}

#[async_trait::async_trait]
impl waygate_policy::PolicyStore for InMemoryPolicyStore {
    async fn active_bundle(
        &self,
        tenant_id: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        let guard = self.bundles.lock().await;
        guard
            .iter()
            .filter(|b| b.tenant_id == tenant_id)
            .filter(|b| matches!(b.status, waygate_policy::PolicyStatus::Published))
            .filter(|b| b.published_at.is_some())
            .max_by(|a, b| {
                let ord = a.published_at.cmp(&b.published_at);
                if ord == std::cmp::Ordering::Equal {
                    a.version.cmp(&b.version)
                } else {
                    ord
                }
            })
            .cloned()
            .ok_or(waygate_policy::PolicyError::NotFound(
                "no published policy bundle for tenant",
            ))
    }
    async fn active_bundles(
        &self,
    ) -> Result<Vec<waygate_policy::PolicyBundle>, waygate_policy::PolicyError> {
        let guard = self.bundles.lock().await;
        let mut latest = std::collections::BTreeMap::<String, waygate_policy::PolicyBundle>::new();
        for bundle in guard
            .iter()
            .filter(|bundle| bundle.status == waygate_policy::PolicyStatus::Published)
            .filter(|bundle| bundle.published_at.is_some())
        {
            let slot = latest
                .entry(bundle.tenant_id.clone())
                .or_insert_with(|| bundle.clone());
            if (bundle.published_at, bundle.version) > (slot.published_at, slot.version) {
                *slot = bundle.clone();
            }
        }
        Ok(latest.into_values().collect())
    }
    async fn list_bundles(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<waygate_policy::PolicyBundleSummary>, waygate_policy::PolicyError> {
        let guard = self.bundles.lock().await;
        let mut out: Vec<_> = guard
            .iter()
            .filter(|b| b.tenant_id == tenant_id)
            .map(|b| waygate_policy::PolicyBundleSummary {
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
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.version));
        Ok(out)
    }
    async fn get(
        &self,
        tenant_id: &str,
        bundle_id: uuid::Uuid,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        let guard = self.bundles.lock().await;
        guard
            .iter()
            .find(|b| b.tenant_id == tenant_id && b.id == bundle_id)
            .cloned()
            .ok_or(waygate_policy::PolicyError::NotFound(
                "no policy bundle with that id in tenant",
            ))
    }
    async fn create_draft(
        &self,
        tenant_id: &str,
        content: &str,
        tests: Option<&serde_json::Value>,
        author: Option<&str>,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        // Append a Draft at the next version (the real store's behavior) so the
        // per-policy edit handlers can be driven end-to-end and the resulting
        // draft inspected. Tests carry the base's `tests` forward, so round-trip
        // them.
        let mut guard = self.bundles.lock().await;
        let next_version = guard
            .iter()
            .filter(|b| b.tenant_id == tenant_id)
            .map(|b| b.version)
            .max()
            .unwrap_or(0)
            + 1;
        let bundle = waygate_policy::PolicyBundle {
            id: uuid::Uuid::new_v4(),
            tenant_id: tenant_id.to_string(),
            version: next_version,
            status: waygate_policy::PolicyStatus::Draft,
            content: content.to_string(),
            content_hash: waygate_policy::content_hash(content),
            tests: tests.cloned(),
            author: author.map(str::to_string),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: None,
            published_by: None,
        };
        guard.push(bundle.clone());
        Ok(bundle)
    }
    async fn publish(
        &self,
        _tenant_id: &str,
        _bundle_id: uuid::Uuid,
        _publisher: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        panic!("publish not exercised by render tests");
    }
    async fn rollback_to(
        &self,
        _tenant_id: &str,
        _version: i32,
        _actor: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        panic!("rollback_to not exercised by render tests");
    }
    async fn delete_all_bundles_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<u64, waygate_policy::PolicyError> {
        let mut guard = self.bundles.lock().await;
        let before = guard.len();
        guard.retain(|bundle| bundle.tenant_id != tenant_id);
        Ok((before - guard.len()) as u64)
    }
    async fn read_pointer(
        &self,
        _tenant_id: &str,
    ) -> Result<Option<waygate_policy::PolicyPointer>, waygate_policy::PolicyError> {
        Ok(None)
    }
    async fn seed_pointer(
        &self,
        _tenant_id: &str,
        _hash: &str,
    ) -> Result<(), waygate_policy::PolicyError> {
        Ok(())
    }
    async fn cas_pointer(
        &self,
        _tenant_id: &str,
        _expected: &str,
        _new: &str,
        _actor: &str,
    ) -> Result<waygate_policy::TurnstileOutcome, waygate_policy::PolicyError> {
        Ok(waygate_policy::TurnstileOutcome::Lost)
    }
}

pub(crate) fn seeded_bundle(
    id: &str,
    version: i32,
    status: waygate_policy::PolicyStatus,
    content: &str,
    published_at: Option<time::OffsetDateTime>,
) -> waygate_policy::PolicyBundle {
    waygate_policy::PolicyBundle {
        id: id.parse().unwrap(),
        tenant_id: "default".into(),
        version,
        status,
        content: content.into(),
        content_hash: waygate_policy::content_hash(content),
        tests: None,
        author: Some("test".into()),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        published_at,
        published_by: published_at.map(|_| "publisher".into()),
    }
}

pub(crate) async fn state_with_policy_store(
    seed: Vec<waygate_policy::PolicyBundle>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let store: waygate_policy::SharedPolicyStore = Arc::new(InMemoryPolicyStore::seeded(seed));
    let state = base_admin_state_with_pool(pool);
    Arc::new(state.with_policy_store(Some(store)))
}

/// Like [`state_with_policy_store`] but with policy editing DISABLED — the
/// posture under `GATEWAY_POLICY_EDITING=off` or a read-only policies dir. Used
/// to pin that the editor page becomes a read-only viewer (mutation affordances
/// hidden, banner shown) while reads still render.
pub(crate) async fn state_with_policy_store_editing_off(
    seed: Vec<waygate_policy::PolicyBundle>,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let store: waygate_policy::SharedPolicyStore = Arc::new(InMemoryPolicyStore::seeded(seed));
    let state = base_admin_state_with_pool(pool);
    Arc::new(
        state
            .with_policy_store(Some(store))
            .with_policy_editing_off_reason(Some("the policies directory is not writable".into())),
    )
}

/// Editor section renders when a policy store is wired AND the
/// dashboard principal has the admin gate. Carries the textarea,
/// Validate button, Save draft button, and the action target URLs.
#[tokio::test]
pub(crate) async fn policy_bundles_editor_renders_when_store_wired_and_admin() {
    let state = state_with_policy_store(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/policy_bundles").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"aria-label="Policy bundle editor""#),
        "editor section missing",
    );
    assert!(
        // The editor textarea posts as the `content` field. (It also carries
        // `id="policy-editor"` for the focus-scroll script, so assert the
        // field name rather than the exact tag-open string.)
        body.contains(r#"name="content""#) && body.contains(r#"id="policy-editor""#),
        "editor textarea missing",
    );
    assert!(
        body.contains(r#"formaction="/admin/t/default/policy_bundles/save_draft""#),
        "Save draft formaction missing or not tenant-prefixed",
    );
    assert!(
        body.contains(r#"action="/admin/t/default/policy_bundles/validate""#),
        "Validate form action missing or not tenant-prefixed",
    );
    assert!(
        body.contains(r#"name="csrf""#),
        "CSRF hidden input missing in editor form",
    );
}

/// When policy editing is disabled, the editor page is a read-only viewer —
/// the read-only banner shows, and every mutation affordance (Save draft, per-row
/// Publish) is hidden, while the read-only ones (Validate, Preview impact) stay.
/// Asserted as a CONTRAST against the same seed with editing enabled, so the
/// absence checks can't pass vacuously.
#[tokio::test]
pub(crate) async fn policy_bundles_editor_hides_mutations_when_editing_disabled() {
    // A single DRAFT bundle ⇒ `can_publish` is true, so the per-row Publish form
    // renders when editing is enabled (the anchor the disabled case must drop).
    let seed = || {
        vec![seeded_bundle(
            "11111111-1111-1111-1111-111111111111",
            1,
            waygate_policy::PolicyStatus::Draft,
            "permit(principal, action, resource);",
            None,
        )]
    };

    // Baseline (editing enabled): mutation affordances present, no banner.
    let on = dashboard_router(
        state_with_policy_store(seed()).await,
        DashboardAuth::Disabled,
    );
    let (s_on, b_on) = body_of(on, "/t/default/policy_bundles").await;
    assert_eq!(s_on, StatusCode::OK);
    assert!(
        b_on.contains("/policy_bundles/save_draft"),
        "baseline: Save draft affordance should be present when editing is enabled",
    );
    assert!(
        b_on.contains("/publish\""),
        "baseline: per-row Publish form should render for a draft when editing is enabled",
    );
    assert!(
        !b_on.contains("Policy editing is disabled"),
        "baseline: no read-only banner when editing is enabled",
    );

    // Editing disabled: banner shown, mutations gone, reads stay.
    let off = dashboard_router(
        state_with_policy_store_editing_off(seed()).await,
        DashboardAuth::Disabled,
    );
    let (s_off, b_off) = body_of(off, "/t/default/policy_bundles").await;
    assert_eq!(s_off, StatusCode::OK);
    assert!(
        b_off.contains("Policy editing is disabled"),
        "read-only banner missing when editing is disabled",
    );
    assert!(
        !b_off.contains("/policy_bundles/save_draft"),
        "Save draft must be hidden when editing is disabled",
    );
    assert!(
        !b_off.contains("/publish\""),
        "per-row Publish must be hidden when editing is disabled",
    );
    // Read-only affordances survive — the page is a viewer, not blank.
    assert!(
        b_off.contains("/policy_bundles/validate"),
        "Validate (read-only) must stay available when editing is disabled",
    );
    assert!(
        b_off.contains("/preview_impact"),
        "Preview impact (read-only) must stay available when editing is disabled",
    );
}

/// The mutation endpoints themselves 403 when editing is disabled — the
/// `gate_policy_editing` middleware fires before the handler (and before the CSRF
/// check), so even a well-formed dev-CSRF POST is refused. Defense in depth
/// behind the hidden affordances above.
#[tokio::test]
pub(crate) async fn policy_bundles_mutation_endpoints_403_when_editing_disabled() {
    let mutation_uris = [
        "/policy_bundles/save_draft",
        "/policy_bundles/11111111-1111-1111-1111-111111111111/publish",
        "/policy_bundles/1/rollback",
        "/policy_bundles/policy/edit",
        "/policy_bundles/policy/remove",
        "/policy_bundles/policy/add",
    ];
    for uri in mutation_uris {
        let app = dashboard_router(
            state_with_policy_store_editing_off(Vec::new()).await,
            DashboardAuth::Disabled,
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "csrf=dev-csrf&content=permit(principal, action, resource);",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{uri} must 403 when policy editing is disabled",
        );
    }
}

/// The page loads the vendored CodeMirror 6 bundle and mounts it over the
/// editor textarea (progressive enhancement). The textarea stays the form field
/// (asserted above); CM6 syncs to it. We can't run the JS in a render test, so
/// assert the bundle script and the mount hook are wired.
#[tokio::test]
pub(crate) async fn policy_bundles_editor_mounts_codemirror() {
    let state = state_with_policy_store(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/policy_bundles").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"src="/admin/static/js/codemirror.bundle.js""#),
        "CodeMirror bundle script not loaded",
    );
    assert!(
        body.contains("CedarEditor.init"),
        "CM6 mount hook (CedarEditor.init) missing from the editor scripts",
    );
}

/// The editor textarea carries the as-you-type validation config
/// (`data-lint-url` → the diagnostics endpoint, + `data-csrf`) that the CM6
/// linter reads. Server-escaped attributes (never interpolated into JS).
#[tokio::test]
pub(crate) async fn policy_bundles_editor_wires_lint_endpoint() {
    let state = state_with_policy_store(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/policy_bundles").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"data-lint-url="/admin/t/default/policy_bundles/diagnostics""#),
        "lint endpoint URL not wired onto the editor (tenant-prefixed)",
    );
    assert!(
        body.contains("data-csrf="),
        "csrf not threaded to the CM6 linter",
    );
}

/// The diagnostics endpoint returns an empty diagnostics set (ok:true)
/// for a policy that parses cleanly.
#[tokio::test]
pub(crate) async fn policy_diagnostics_empty_for_valid_policy() {
    let app = dashboard_router(
        state_with_policy_store(Vec::new()).await,
        DashboardAuth::Disabled,
    );
    let form = format!(
        "csrf=dev-csrf&content={}",
        encode_form_value("@id(\"a\")\npermit(principal, action, resource);")
    );
    let (status, body) = post_form_body(app, "/policy_bundles/diagnostics", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"ok\":true"),
        "expected ok:true, got: {body}"
    );
    assert!(
        body.contains("\"diagnostics\":[]"),
        "expected no diagnostics, got: {body}"
    );
}

/// A parse error yields ok:false plus a positioned diagnostic.
#[tokio::test]
pub(crate) async fn policy_diagnostics_flags_a_parse_error() {
    let app = dashboard_router(
        state_with_policy_store(Vec::new()).await,
        DashboardAuth::Disabled,
    );
    let form = format!(
        "csrf=dev-csrf&content={}",
        // Line 2 has the parse error (`permitt` is not a keyword).
        encode_form_value("@id(\"a\")\npermitt(principal, action, resource);")
    );
    let (status, body) = post_form_body(app, "/policy_bundles/diagnostics", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"ok\":false"),
        "expected ok:false, got: {body}"
    );
    assert!(
        body.contains("\"line\""),
        "diagnostic should carry a line, got: {body}"
    );
    assert!(
        body.contains("\"message\""),
        "diagnostic should carry a message, got: {body}"
    );
}

/// The diagnostics POST is CSRF-gated.
#[tokio::test]
pub(crate) async fn policy_diagnostics_requires_csrf() {
    let app = dashboard_router(
        state_with_policy_store(Vec::new()).await,
        DashboardAuth::Disabled,
    );
    let form = format!(
        "csrf=WRONG&content={}",
        encode_form_value("permit(principal, action, resource);")
    );
    let (status, _body) = post_form_body(app, "/policy_bundles/diagnostics", &form).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// `?load=<id>` against the active bundle pre-fills the textarea
/// with that bundle's source AND surfaces the "Loaded from vN"
/// meta line.
#[tokio::test]
pub(crate) async fn policy_bundles_editor_load_prefills_active_bundle_source() {
    let id = "00000000-0000-0000-0000-000000000007";
    let content = "// active bundle source\nforbid(principal, action, resource);";
    let active = seeded_bundle(
        id,
        7,
        waygate_policy::PolicyStatus::Published,
        content,
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let state = state_with_policy_store(vec![active]).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let url = format!("/t/default/policy_bundles?load={id}");
    let (status, body) = body_of(app, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("forbid(principal, action, resource);"),
        "loaded bundle source missing from rendered textarea",
    );
    assert!(
        body.contains("Loaded from <code>v7</code>")
            || body.contains("Loaded from <code>v7</code\n"),
        "editor meta line should name the loaded version",
    );
}

/// Per-row Publish + Rollback buttons appear only on the rows
/// that qualify: a draft → Publish; a published-but-not-current
/// → Rollback; the current bundle → neither.
#[tokio::test]
pub(crate) async fn policy_bundles_per_row_action_buttons_match_eligibility() {
    let t = time::OffsetDateTime::UNIX_EPOCH;
    let t1 = t + time::Duration::hours(1);
    let bundles = vec![
        // v3 — current (most recently published).
        seeded_bundle(
            "00000000-0000-0000-0000-000000000003",
            3,
            waygate_policy::PolicyStatus::Published,
            "// v3\nforbid(principal, action, resource);",
            Some(t1),
        ),
        // v2 — previously published, eligible for rollback.
        seeded_bundle(
            "00000000-0000-0000-0000-000000000002",
            2,
            waygate_policy::PolicyStatus::Published,
            "// v2\nforbid(principal, action, resource);",
            Some(t),
        ),
        // v1 — draft, eligible for publish.
        seeded_bundle(
            "00000000-0000-0000-0000-000000000001",
            1,
            waygate_policy::PolicyStatus::Draft,
            "// v1\nforbid(principal, action, resource);",
            None,
        ),
    ];
    let state = state_with_policy_store(bundles).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/policy_bundles").await;
    assert_eq!(status, StatusCode::OK);
    // v1 draft → Publish button present.
    assert!(
        body.contains(
            r#"action="/admin/t/default/policy_bundles/00000000-0000-0000-0000-000000000001/publish""#
        ),
        "draft v1 should have a Publish form",
    );
    // v2 previously-published-not-current → Rollback button present.
    assert!(
        body.contains(r#"action="/admin/t/default/policy_bundles/2/rollback""#),
        "previously-published v2 should have a Rollback form",
    );
    // v3 current → NEITHER publish nor rollback on its row.
    // Cheapest assertion: there must be no Publish form for v3 (it isn't a draft)
    // and no Rollback form for v3 (it IS current).
    assert!(
        !body.contains(
            r#"action="/admin/t/default/policy_bundles/00000000-0000-0000-0000-000000000003/publish""#
        ),
        "current v3 should not expose a Publish button",
    );
    assert!(
        !body.contains(r#"action="/t/default/policy_bundles/3/rollback""#),
        "current v3 should not expose a Rollback button",
    );
}

/// Regression: the editor's `?load=<id>` path must read a
/// non-active draft's source, not render a load-miss banner.
/// Without `PolicyStore::get`, Save Draft's PRG
/// (`?load=<new_draft_id>`) ALWAYS landed on load_miss because a
/// freshly-saved draft is never the active bundle.
#[tokio::test]
pub(crate) async fn policy_bundles_editor_load_prefills_non_active_draft_source() {
    let active_id = "00000000-0000-0000-0000-000000000005";
    let draft_id = "00000000-0000-0000-0000-000000000006";
    let active = seeded_bundle(
        active_id,
        5,
        waygate_policy::PolicyStatus::Published,
        "// active v5\nforbid(principal, action, resource);",
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let draft = seeded_bundle(
        draft_id,
        6,
        waygate_policy::PolicyStatus::Draft,
        "// draft v6 — operator just saved this\npermit(principal, action, resource);",
        None,
    );
    let state = state_with_policy_store(vec![active, draft]).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let url = format!("/t/default/policy_bundles?load={draft_id}");
    let (status, body) = body_of(app, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("draft v6 — operator just saved this"),
        "draft v6 source missing from textarea — load_miss regression",
    );
    assert!(
        body.contains("Loaded from <code>v6</code>"),
        "editor meta line should name the loaded draft version",
    );
    assert!(
        !body.contains("Could not load the requested bundle"),
        "load-miss banner should not render for a present draft",
    );
}

/// `?banner=published&banner_detail=v4` after a PRG redirect
/// surfaces the post-mutation flash banner inline.
#[tokio::test]
pub(crate) async fn policy_bundles_post_mutation_flash_banner_renders() {
    let state = state_with_policy_store(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(
        app,
        "/t/default/policy_bundles?banner=published&banner_detail=v4",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Published to <code>policies/*.cedar</code>"),
        "published flash banner missing (should name the on-disk source of truth)",
    );
    assert!(body.contains("<code>v4</code>"), "detail not rendered");
}
