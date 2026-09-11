//! Policy edit-in-place + per-policy editor + Agents page — split from the
//! monolithic `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::common::*;
use crate::crud_pages::post_form;
use crate::editors::seeded_bundle;
use crate::editors::state_with_policy_store;
use crate::editors::InMemoryPolicyStore;

// ---- Edit-in-place wiring ---------------------------------------------

/// Layered Cedar (so the policy ids render) PLUS a wired store with a PUBLISHED
/// active bundle (so `load=active` resolves and the Edit deep-link is offered —
/// it's gated on admin + a store + an active bundle).
pub(crate) async fn state_with_layered_cedar_and_store() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(LAYERED_POLICY).unwrap(),
    ));
    let active = seeded_bundle(
        "22222222-2222-2222-2222-222222222222",
        1,
        waygate_policy::PolicyStatus::Published,
        LAYERED_POLICY,
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let store: waygate_policy::SharedPolicyStore =
        Arc::new(InMemoryPolicyStore::seeded(vec![active]));
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
        .with_policy_store(Some(store)),
    )
}

/// Layered Cedar + a wired store but NO published bundle — `load=active` would
/// miss, so the Edit link must be hidden.
pub(crate) async fn state_with_layered_cedar_and_empty_store() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(LAYERED_POLICY).unwrap(),
    ));
    let store: waygate_policy::SharedPolicyStore =
        Arc::new(InMemoryPolicyStore::seeded(Vec::new()));
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
        .with_policy_store(Some(store)),
    )
}

#[tokio::test]
pub(crate) async fn policies_page_offers_inline_editor_for_admin() {
    // An addressable policy (present in the active bundle) carries an
    // INLINE editor on the Policies pane — a details block with a textarea
    // pre-filled with that policy's exact source, posting to the per-policy edit
    // endpoint — so editing happens in place (no switch-tab / hunt loop).
    let app = dashboard_router(
        state_with_layered_cedar_and_store().await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"<details class="policy-inline-edit">"#),
        "inline per-policy editor missing from the policy card"
    );
    assert!(
        body.contains(r#"name="id" value="step-up-delete-dataset""#),
        "inline editor should target this policy by @id"
    );
    assert!(
        body.contains(r#"name="statement""#),
        "inline editor textarea (the form field) missing"
    );
    assert!(
        body.contains("/policy_bundles/policy/edit"),
        "inline editor should post to the per-policy edit endpoint"
    );
    // The CM6 bundle + lint endpoint are wired onto the inline editor.
    assert!(
        body.contains("/admin/static/js/codemirror.bundle.js"),
        "CodeMirror bundle not loaded for the inline editor"
    );
    assert!(
        body.contains(r#"data-lint-url=""#) && body.contains("/policy_bundles/diagnostics"),
        "as-you-type lint endpoint not wired onto the inline editor",
    );
}

#[tokio::test]
pub(crate) async fn policies_page_inline_editor_carries_exact_source() {
    // The inline editor's textarea holds the policy's EXACT, byte-faithful
    // source from the segmenter — including a `//` comment that Cedar's
    // re-serialization would drop. Proves we offer the real text, not a
    // canonicalized rendering.
    let content = "@id(\"a\")\n// keep this note\npermit(principal, action, resource);\n";
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(content).unwrap(),
    ));
    let active = seeded_bundle(
        "22222222-2222-2222-2222-222222222222",
        1,
        waygate_policy::PolicyStatus::Published,
        content,
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let store: waygate_policy::SharedPolicyStore =
        Arc::new(InMemoryPolicyStore::seeded(vec![active]));
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
        .with_policy_store(Some(store)),
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("keep this note"),
        "the inline editor must carry the policy's exact source incl. comments"
    );
}

#[tokio::test]
pub(crate) async fn policies_page_hides_edit_when_no_policy_store() {
    // Cedar is loaded (policies render) but the policy-bundle store is unwired —
    // editing would dead-end, so neither the inline editor nor the fallback
    // bundle-editor link must be shown.
    let app = dashboard_router(state_with_layered_cedar().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);
    // The policies still render (proving Cedar is loaded)...
    assert!(
        body.contains("step-up-delete-dataset"),
        "policies should still list"
    );
    // ...but no edit affordance (inline-editor markup or the fallback link).
    assert!(
        !body.contains(r#"<details class="policy-inline-edit">"#),
        "the inline editor must be hidden when the policy store is unconfigured"
    );
    assert!(
        !body.contains("Edit in bundle editor"),
        "the fallback edit link must be hidden when the store is unconfigured"
    );
}

#[tokio::test]
pub(crate) async fn policies_page_hides_edit_when_no_active_bundle() {
    // Store wired but NO published bundle (policies loaded from disk, never
    // imported into the ledger) — there's nothing to edit against, so no edit
    // affordance.
    let app = dashboard_router(
        state_with_layered_cedar_and_empty_store().await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("step-up-delete-dataset"),
        "policies should still list"
    );
    assert!(
        !body.contains(r#"<details class="policy-inline-edit">"#),
        "the inline editor must be hidden when there is no active bundle"
    );
    assert!(
        !body.contains("Edit in bundle editor"),
        "the fallback edit link must be hidden when there is no active bundle"
    );
}

#[tokio::test]
pub(crate) async fn editor_loads_active_bundle_and_focuses_a_policy() {
    // The editor accepts `?load=active` (the Edit deep-link target, which doesn't
    // know the active bundle's id) and `?focus=<@id>` to position on one policy.
    let content = "@id(\"step-up-delete-dataset\")\nforbid(principal, action, resource);\n";
    let bundle = seeded_bundle(
        "11111111-1111-1111-1111-111111111111",
        3,
        waygate_policy::PolicyStatus::Published,
        content,
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let state = state_with_policy_store(vec![bundle]).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(
        app,
        "/policy_bundles?load=active&focus=step-up-delete-dataset",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The active bundle's source is pre-filled into the editor textarea...
    assert!(
        body.contains("forbid(principal, action, resource)"),
        "active bundle content not loaded into the editor"
    );
    // ...and the focus @id rides as a data attribute the scroll script reads.
    assert!(
        body.contains(r#"data-focus="step-up-delete-dataset""#),
        "focus @id not threaded to the editor textarea"
    );
    // The focus-hint hook is rendered for the scripts block to fill with the
    // actual jump outcome (server-side static render can't run the JS, so assert
    // the hook is present rather than the JS-injected text).
    assert!(
        body.contains(r#"id="focus-hint""#),
        "the editor-meta focus-hint hook should render when focus is present"
    );
}

// ---- policy-edit: per-policy edit backend ----

/// Build state from a freshly-seeded store and keep a CONCRETE handle so a test
/// can inspect the drafts a per-policy mutation creates. The active bundle is
/// the two-policy `LAYERED_POLICY` (`baseline-discovery` + `step-up-delete-dataset`).
pub(crate) async fn state_and_store_with_layered_active(
) -> (Arc<AdminState>, Arc<InMemoryPolicyStore>) {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let active = seeded_bundle(
        "22222222-2222-2222-2222-222222222222",
        1,
        waygate_policy::PolicyStatus::Published,
        LAYERED_POLICY,
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let store = Arc::new(InMemoryPolicyStore::seeded(vec![active]));
    let store_dyn: waygate_policy::SharedPolicyStore = store.clone();
    let state = Arc::new(base_admin_state_with_pool(pool).with_policy_store(Some(store_dyn)));
    (state, store)
}

/// Percent-encode a value for an `application/x-www-form-urlencoded` body so a
/// multi-line Cedar statement (newlines, quotes, `;`, parens) survives the POST.
pub(crate) fn encode_form_value(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub(crate) async fn latest_draft(
    store: &InMemoryPolicyStore,
) -> Option<waygate_policy::PolicyBundle> {
    let guard = store.bundles.lock().await;
    guard
        .iter()
        .filter(|b| matches!(b.status, waygate_policy::PolicyStatus::Draft))
        .max_by_key(|b| b.version)
        .cloned()
}

#[tokio::test]
pub(crate) async fn per_policy_get_returns_one_statement() {
    let (state, _store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(
        app,
        "/policy_bundles/policy?base=active&id=baseline-discovery",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"ok\":true"),
        "expected ok:true, got: {body}"
    );
    // The returned statement is THAT policy (the SearchTools permit)...
    assert!(
        body.contains("SearchTools"),
        "statement should be the baseline-discovery permit, got: {body}"
    );
    // ...and not the OTHER policy in the bundle.
    assert!(
        !body.contains("delete_dataset"),
        "must not leak the other policy's body, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_get_unknown_id_is_not_found() {
    let (state, _store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policy_bundles/policy?base=active&id=does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("\"ok\":false"),
        "expected ok:false, got: {body}"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_changes_only_that_policy() {
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);

    // Replace step-up-delete-dataset's body (keep the @id so it stays addressable).
    let new_stmt = "@id(\"step-up-delete-dataset\")\nforbid(principal, action, resource);";
    let form = format!(
        "csrf=dev-csrf&base=active&id=step-up-delete-dataset&statement={}",
        encode_form_value(new_stmt)
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=saved"),
        "expected saved redirect, got: {loc}"
    );
    assert!(
        loc.contains("focus=step-up-delete-dataset"),
        "redirect should focus the edited policy, got: {loc}"
    );

    let draft = latest_draft(&store).await.expect("a draft was created");
    // The UNTOUCHED policy is preserved byte-for-byte, comments and all.
    assert!(
        draft.content.contains("@id(\"baseline-discovery\")"),
        "untouched policy id preserved"
    );
    assert!(
        draft
            .content
            .contains("Any authenticated principal may list and search tools."),
        "untouched policy's @description comment preserved verbatim"
    );
    // The edited policy's NEW body is spliced in and the OLD body is gone.
    assert!(
        draft
            .content
            .contains("forbid(principal, action, resource);"),
        "new statement spliced in"
    );
    assert!(
        !draft
            .content
            .contains("resource.name == \"delete_dataset\""),
        "old statement body removed"
    );
    // The recomposed draft is still valid Cedar.
    assert!(
        CedarEngine::from_source(&draft.content).is_ok(),
        "recomposed draft parses as Cedar"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_unknown_id_creates_no_draft() {
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let form = format!(
        "csrf=dev-csrf&base=active&id=ghost&statement={}",
        encode_form_value("@id(\"ghost\")\npermit(principal, action, resource);")
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=save_error"),
        "expected error flash, got: {loc}"
    );
    assert!(
        latest_draft(&store).await.is_none(),
        "a non-existent @id must not produce a draft"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_rejects_unparseable_statement() {
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    // Valid @id so it's found, but a body that doesn't parse as Cedar.
    let form = format!(
        "csrf=dev-csrf&base=active&id=step-up-delete-dataset&statement={}",
        encode_form_value("@id(\"step-up-delete-dataset\")\nthis is not cedar {{{")
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=save_error"),
        "expected error flash, got: {loc}"
    );
    assert!(
        latest_draft(&store).await.is_none(),
        "an unparseable edit must never be staged as a draft"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_remove_drops_the_policy() {
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let form = "csrf=dev-csrf&base=active&id=baseline-discovery";
    let (status, loc) = post_form(app, "/policy_bundles/policy/remove", form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=saved"),
        "expected saved redirect, got: {loc}"
    );

    let draft = latest_draft(&store).await.expect("a draft was created");
    assert!(
        !draft.content.contains("@id(\"baseline-discovery\")"),
        "removed policy gone from draft"
    );
    assert!(
        draft.content.contains("@id(\"step-up-delete-dataset\")"),
        "the other policy survives"
    );
    assert!(
        CedarEngine::from_source(&draft.content).is_ok(),
        "draft parses"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_add_appends_a_policy() {
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let new_stmt =
        "@id(\"extra-grant\")\npermit(principal, action == Action::\"ListTools\", resource);";
    let form = format!(
        "csrf=dev-csrf&base=active&statement={}",
        encode_form_value(new_stmt)
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/add", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=saved"),
        "expected saved redirect, got: {loc}"
    );

    let draft = latest_draft(&store).await.expect("a draft was created");
    // Both originals AND the new policy are present.
    assert!(draft.content.contains("@id(\"baseline-discovery\")"));
    assert!(draft.content.contains("@id(\"step-up-delete-dataset\")"));
    assert!(
        draft.content.contains("@id(\"extra-grant\")"),
        "new policy appended"
    );
    assert!(
        CedarEngine::from_source(&draft.content).is_ok(),
        "draft parses"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_requires_csrf() {
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let form = format!(
        "csrf=WRONG&base=active&id=step-up-delete-dataset&statement={}",
        encode_form_value("@id(\"step-up-delete-dataset\")\nforbid(principal, action, resource);")
    );
    let (status, _loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        latest_draft(&store).await.is_none(),
        "a CSRF-rejected edit must not mutate the store"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_falls_back_on_unparseable_base() {
    // A stored base that doesn't parse as Cedar can't be segmented; the handler
    // must bounce to whole-bundle editing (load the base + an error flash) rather
    // than splice blindly — the fail-safe contract.
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let broken = seeded_bundle(
        "33333333-3333-3333-3333-333333333333",
        1,
        waygate_policy::PolicyStatus::Published,
        "this is not valid cedar {{{",
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    let store = Arc::new(InMemoryPolicyStore::seeded(vec![broken]));
    let store_dyn: waygate_policy::SharedPolicyStore = store.clone();
    let state = Arc::new(base_admin_state_with_pool(pool).with_policy_store(Some(store_dyn)));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let form = format!(
        "csrf=dev-csrf&base=active&id=whatever&statement={}",
        encode_form_value("permit(principal, action, resource);")
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=save_error"),
        "expected error flash, got: {loc}"
    );
    // Bounced to the whole-bundle editor with the base loaded (load=<base id>).
    assert!(
        loc.contains("load=33333333-3333-3333-3333-333333333333"),
        "fallback should reload the base bundle, got: {loc}"
    );
    assert!(
        latest_draft(&store).await.is_none(),
        "the fallback must not stage a draft"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_preserves_bundle_tests() {
    // A per-policy edit must carry the base bundle's `tests` forward — dropping
    // them would silently disarm the publish-time test gate.
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mut base = seeded_bundle(
        "44444444-4444-4444-4444-444444444444",
        1,
        waygate_policy::PolicyStatus::Published,
        LAYERED_POLICY,
        Some(time::OffsetDateTime::UNIX_EPOCH),
    );
    base.tests = Some(serde_json::json!([{"name": "smoke", "expect": "Allow"}]));
    let store = Arc::new(InMemoryPolicyStore::seeded(vec![base]));
    let store_dyn: waygate_policy::SharedPolicyStore = store.clone();
    let state = Arc::new(base_admin_state_with_pool(pool).with_policy_store(Some(store_dyn)));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let form = format!(
        "csrf=dev-csrf&base=active&id=step-up-delete-dataset&statement={}",
        encode_form_value("@id(\"step-up-delete-dataset\")\nforbid(principal, action, resource);")
    );
    let (status, _loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let draft = latest_draft(&store).await.expect("a draft was created");
    assert_eq!(
        draft.tests,
        Some(serde_json::json!([{"name": "smoke", "expect": "Allow"}])),
        "the base bundle's test cases must survive a per-policy edit"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_rejects_multiple_policies() {
    // A single "edit" must not smuggle in extra policies: the
    // submitted payload carries TWO policies → rejected, no draft staged.
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let two = "@id(\"step-up-delete-dataset\")\nforbid(principal, action, resource);\n\
               @id(\"sneaky\")\npermit(principal, action, resource);";
    let form = format!(
        "csrf=dev-csrf&base=active&id=step-up-delete-dataset&statement={}",
        encode_form_value(two)
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=save_error"),
        "expected error flash, got: {loc}"
    );
    assert!(
        latest_draft(&store).await.is_none(),
        "an edit carrying multiple policies must not stage a draft"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_edit_rejects_renamed_id() {
    // Editing policy `a` may not silently rename it (that's remove + add).
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let renamed = "@id(\"renamed\")\nforbid(principal, action, resource);";
    let form = format!(
        "csrf=dev-csrf&base=active&id=step-up-delete-dataset&statement={}",
        encode_form_value(renamed)
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/edit", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=save_error"),
        "expected error flash, got: {loc}"
    );
    assert!(
        latest_draft(&store).await.is_none(),
        "an edit that renames the target @id must not stage a draft"
    );
}

#[tokio::test]
pub(crate) async fn per_policy_add_rejects_multiple_policies() {
    // "Add" appends exactly ONE policy — a payload with several is rejected.
    let (state, store) = state_and_store_with_layered_active().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let two = "@id(\"one\")\npermit(principal, action, resource);\n\
               @id(\"two\")\npermit(principal, action, resource);";
    let form = format!(
        "csrf=dev-csrf&base=active&statement={}",
        encode_form_value(two)
    );
    let (status, loc) = post_form(app, "/policy_bundles/policy/add", &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        loc.contains("banner=save_error"),
        "expected error flash, got: {loc}"
    );
    assert!(
        latest_draft(&store).await.is_none(),
        "an add carrying multiple policies must not stage a draft"
    );
}

// ---- Gateway Agents page ---------------------------------------------------

pub(crate) async fn state_with_agent_store(
    store: waygate_dashboard_stores::agent_config::SharedAgentConfigStore,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Agent-config mutations audit via record_required (fail-closed).
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
        .with_agent_configs(Some(store)),
    )
}

/// The Gateway Agents page renders at both mounts and shows the shared
/// "store not configured" empty state when no agent-config store is wired.
#[tokio::test]
pub(crate) async fn agents_page_renders_store_not_configured() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    for path in ["/agents", "/t/default/agents"] {
        let (status, body) = body_of(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "agents page failed at {path}");
        assert!(
            body.contains("Gateway Agents"),
            "page title missing at {path}"
        );
        assert!(
            body.contains("Agent store not configured"),
            "expected disabled-state copy at {path}",
        );
        assert!(
            body.contains(r#"class="empty-state""#) && body.contains("lucide.svg#alert-triangle"),
            "agents disabled state should use the shared .empty-state component at {path}",
        );
    }
}

/// With a store + a seeded agent, the page renders the composer, the table,
/// and per-row edit/delete actions — and never a raw curl instruction.
#[tokio::test]
pub(crate) async fn agents_page_renders_rows_and_action_forms() {
    use waygate_dashboard_stores::agent_config::{
        AgentConfigFields, AgentConfigStore, AgentKind, InMemoryAgentConfigStore,
    };
    let store: Arc<InMemoryAgentConfigStore> = Arc::new(InMemoryAgentConfigStore::new());
    let seeded = store
        .insert(
            "default",
            AgentConfigFields {
                name: "ops-chat",
                kind: AgentKind::Chat,
                model_alias: "gpt-x",
                instructions: None,
                allowed_tools: &["gateway-observe.query_audit".to_owned()],
                max_steps: 8,
                max_tool_calls: 16,
                token_budget: None,
                enabled: true,
            },
        )
        .await
        .unwrap();
    let shared: waygate_dashboard_stores::agent_config::SharedAgentConfigStore = store.clone();
    let app = dashboard_router(
        state_with_agent_store(shared).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/agents").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("/agents/create"), "composer missing");
    assert!(body.contains("<th>Actions</th>"), "Actions column missing");
    assert!(body.contains("ops-chat"), "seeded agent name missing");
    assert!(
        body.contains(&format!("/agents/{}/update", seeded.id))
            && body.contains(&format!("/agents/{}/delete", seeded.id)),
        "per-row edit/delete actions missing",
    );
    assert!(
        !body.contains("POST /api/v1/admin/agent"),
        "raw curl instruction must not appear",
    );
}

/// Create via the dashboard composer persists the row (allowlist parsed,
/// enabled flag honored) and PRG-redirects without an error.
#[tokio::test]
pub(crate) async fn agents_create_persists_and_redirects() {
    use waygate_dashboard_stores::agent_config::{AgentConfigStore, InMemoryAgentConfigStore};
    let store: Arc<InMemoryAgentConfigStore> = Arc::new(InMemoryAgentConfigStore::new());
    let shared: waygate_dashboard_stores::agent_config::SharedAgentConfigStore = store.clone();
    let app = dashboard_router(
        state_with_agent_store(shared).await,
        DashboardAuth::Disabled,
    );
    let (status, loc) = post_form(
        app,
        "/agents/create",
        "csrf=dev-csrf&name=ops-chat&kind=chat&model_alias=gpt-x&instructions=&\
         allowed_tools=gateway-observe.query_audit&max_steps=8&max_tool_calls=16&\
         token_budget=&enabled=on",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!loc.contains("ag_error"), "create carried an error: {loc}");
    let rows = store.list("default", 500, 0).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "ops-chat");
    assert!(rows[0].enabled);
    assert_eq!(rows[0].allowed_tools, vec!["gateway-observe.query_audit"]);
}

/// A create without the CSRF token is rejected (no row written).
#[tokio::test]
pub(crate) async fn agents_create_rejects_missing_csrf() {
    use waygate_dashboard_stores::agent_config::{AgentConfigStore, InMemoryAgentConfigStore};
    let store: Arc<InMemoryAgentConfigStore> = Arc::new(InMemoryAgentConfigStore::new());
    let shared: waygate_dashboard_stores::agent_config::SharedAgentConfigStore = store.clone();
    let app = dashboard_router(
        state_with_agent_store(shared).await,
        DashboardAuth::Disabled,
    );
    let (status, _loc) = post_form(
        app,
        "/agents/create",
        "name=x&kind=chat&model_alias=gpt-x&max_steps=8&max_tool_calls=16",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(store.list("default", 500, 0).await.unwrap().is_empty());
}

/// Sidebar nav surfaces Agents as its own destination under the LLM Gateway
/// section, current on /agents. Confirms DESTINATIONS → nav() → layout.html.
#[tokio::test]
pub(crate) async fn agents_page_marks_destination_active_in_sidebar() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/agents").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/agents" aria-current="page""#),
        "Agents active link should carry aria-current",
    );
}

/// Nav consolidation: the standalone Agent Chat / Policy Review /
/// Classification Audit destinations are retired from the sidebar (the docked
/// assistant panel replaces them), but their routes stay registered so the
/// panel's chips and existing bookmarks still reach the full immersive views.
#[tokio::test]
pub(crate) async fn retired_agent_destinations_leave_sidebar_but_routes_stay_deep_links() {
    // Sidebar (rendered on every page; the overview is representative) no longer
    // carries the three destinations as nav rows.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, home) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    for label in ["Agent Chat", "Policy Review", "Classification Audit"] {
        assert!(
            !home.contains(&format!(r#"<span class="sidebar-label">{label}</span>"#)),
            "{label} should no longer be a sidebar destination",
        );
    }
    // The routes still resolve as deep-links (fresh router per request, since
    // body_of consumes it).
    for path in ["/agent_chat", "/agent_review", "/classification_audit"] {
        let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
        let (status, _) = body_of(app, path).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "deep-link {path} should still resolve after nav retirement",
        );
    }
}

#[tokio::test]
pub(crate) async fn agent_chat_bootstrap_echoes_csrf_and_stream_url_without_a_store() {
    // The docked assistant panel hydrates its chat client from this on
    // ANY page. With no agent-config store wired it must still return a usable
    // bootstrap: the session CSRF (so the panel can POST to /stream — the token
    // lives in the encrypted cookie and isn't otherwise client-readable), the
    // tenant-correct stream URL, and configured=false with an empty agent set.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/agent_chat/bootstrap").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["csrf"], "dev-csrf",
        "panel needs the session CSRF to POST"
    );
    let stream = v["stream_url"].as_str().unwrap();
    assert!(
        stream.ends_with("/agent_chat/stream"),
        "stream_url should target the chat stream: {stream}"
    );
    assert_eq!(v["configured"], false);
    assert_eq!(v["inference_ready"], false);
    assert_eq!(v["history_enabled"], false);
    assert_eq!(v["agents"].as_array().unwrap().len(), 0);
}

#[tokio::test]
pub(crate) async fn assist_panel_drawer_and_toggle_render_on_every_page() {
    // The docked assistant is part of the layout chrome, so it appears on
    // ANY page for an authenticated user. The overview page is the home page —
    // if the drawer + toggle are here, they're everywhere.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"id="gw-assist-panel""#),
        "docked assistant drawer missing"
    );
    assert!(
        body.contains("data-assist-toggle"),
        "assistant toggle missing"
    );
    assert!(
        body.contains("data-agent-chat"),
        "drawer chat block missing"
    );
    // Closed by default and inert, so its controls aren't keyboard-reachable on
    // a page where the drawer is shut.
    assert!(
        body.contains(r#"data-open="false""#),
        "drawer should start closed"
    );
    assert!(
        body.contains(" inert"),
        "closed drawer must be inert (a11y)"
    );
    // The drawer's chat block must be UN-hydrated server-side (no stream URL):
    // the client hydrates it from /agent_chat/bootstrap on first open. The
    // overview page has no other chat, so no stream URL should appear at all.
    assert!(
        !body.contains("data-stream-url"),
        "overview must not pre-hydrate the docked chat",
    );
}

#[tokio::test]
pub(crate) async fn assist_context_drops_review_chip_without_a_configured_agent() {
    // A OneShotReview chip can only run if an enabled agent of its kind
    // exists. With no agent store wired, /policies shows the generic chips but
    // NOT the review chip. The client payload must also not leak grounding.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/assist/context?page=/policies").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["title"], "Policies");
    let ids: Vec<&str> = v["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert!(
        !ids.contains(&"review_policy_set"),
        "review chip must be dropped when no agent is configured: {ids:?}"
    );
    assert!(
        ids.contains(&"explain_page") && ids.contains(&"recent_activity"),
        "generic chips missing: {ids:?}"
    );
    // Trust boundary: grounding (prompt text) is injected server-side at chat
    // time and must never reach the client context payload.
    assert!(
        v.get("grounding").is_none(),
        "/assist/context must not leak grounding"
    );
}

#[tokio::test]
pub(crate) async fn assist_context_includes_review_chip_with_agent_id_when_configured() {
    // With an enabled policy_review agent, the /policies review chip is
    // emitted (admin caller) carrying that agent's id so the panel can run it.
    use waygate_dashboard_stores::agent_config::{
        AgentConfigFields, AgentConfigStore, AgentKind, InMemoryAgentConfigStore,
    };
    let store: Arc<InMemoryAgentConfigStore> = Arc::new(InMemoryAgentConfigStore::new());
    let seeded = store
        .insert(
            "default",
            AgentConfigFields {
                name: "pol-rev",
                kind: AgentKind::PolicyReview,
                model_alias: "gpt-x",
                instructions: None,
                allowed_tools: &[],
                max_steps: 4,
                max_tool_calls: 0,
                token_budget: None,
                enabled: true,
            },
        )
        .await
        .unwrap();
    let shared: waygate_dashboard_stores::agent_config::SharedAgentConfigStore = store.clone();
    let app = dashboard_router(
        state_with_agent_store(shared).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/assist/context?page=/policies").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let review = v["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "review_policy_set")
        .expect("review chip should be present with a configured agent");
    assert_eq!(review["action"], "one_shot_review");
    assert_eq!(
        review["agent_id"],
        seeded.id.to_string(),
        "review chip must carry the resolved agent id"
    );
}

#[tokio::test]
pub(crate) async fn assist_context_grounds_unknown_pages_with_generic_chips_only() {
    // Universal coverage: a page with no catalog entry still returns a usable
    // context — just the generic chips, no curated overlay.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/assist/context?page=/zzz-unknown").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = v["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["explain_page", "recent_activity"]);
}

#[tokio::test]
pub(crate) async fn assist_context_resolves_review_agent_beyond_the_first_page() {
    // The review-agent lookup must page through ALL configs. With
    // 200 chat agents sorting before the lone (name-ordered) policy_review agent,
    // that agent lands on the second list() page — the review chip must still
    // resolve to it rather than dropping.
    use waygate_dashboard_stores::agent_config::{
        AgentConfigFields, AgentConfigStore, AgentKind, InMemoryAgentConfigStore,
    };
    let store: Arc<InMemoryAgentConfigStore> = Arc::new(InMemoryAgentConfigStore::new());
    for i in 0..200 {
        store
            .insert(
                "default",
                AgentConfigFields {
                    name: &format!("chat-{i:03}"),
                    kind: AgentKind::Chat,
                    model_alias: "gpt-x",
                    instructions: None,
                    allowed_tools: &[],
                    max_steps: 1,
                    max_tool_calls: 0,
                    token_budget: None,
                    enabled: true,
                },
            )
            .await
            .unwrap();
    }
    let pol = store
        .insert(
            "default",
            AgentConfigFields {
                name: "zzz-pol-rev", // sorts after every chat-NNN
                kind: AgentKind::PolicyReview,
                model_alias: "gpt-x",
                instructions: None,
                allowed_tools: &[],
                max_steps: 4,
                max_tool_calls: 0,
                token_budget: None,
                enabled: true,
            },
        )
        .await
        .unwrap();
    let shared: waygate_dashboard_stores::agent_config::SharedAgentConfigStore = store.clone();
    let app = dashboard_router(
        state_with_agent_store(shared).await,
        DashboardAuth::Disabled,
    );
    let (status, body) = body_of(app, "/assist/context?page=/policies").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let review = v["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "review_policy_set")
        .expect("review chip must resolve even when its agent is past page 1");
    assert_eq!(review["agent_id"], pol.id.to_string());
}

#[tokio::test]
async fn agent_model_suggestions_only_include_chat_models() {
    struct Catalog;
    #[async_trait::async_trait]
    impl waygate_storage::LlmModelCatalog for Catalog {
        async fn list_models(
            &self,
            tenant: &str,
        ) -> Result<Vec<waygate_storage::LlmModelRow>, sqlx::Error> {
            assert_eq!(tenant, "default");
            Ok([
                "chat_completions",
                "responses",
                "messages",
                "generate_content",
                "images",
                "embeddings",
            ]
            .into_iter()
            .map(|api| waygate_storage::LlmModelRow {
                tenant_id: tenant.into(),
                alias: format!("suggest-{api}"),
                provider: "openai".into(),
                credential_label: "TEST".into(),
                upstream_model: api.into(),
                base_url: "http://127.0.0.1:1".into(),
                path: api.into(),
                upstream_api: api.into(),
                openai_chatgpt: false,
                risk: "low".into(),
                requires_approval: false,
                description: None,
                input_cost_per_mtok: None,
                output_cost_per_mtok: None,
                cached_read_cost_per_mtok: None,
                cache_write_cost_per_mtok: None,
                currency: "USD".into(),
                enabled: true,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
            })
            .collect())
        }
    }
    let store = Arc::new(waygate_dashboard_stores::agent_config::InMemoryAgentConfigStore::new());
    let mut state = state_with_agent_store(store).await;
    Arc::get_mut(&mut state)
        .unwrap()
        .llm
        .llm_models
        .set(Some(Arc::new(Catalog)));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/agents").await;
    assert_eq!(status, StatusCode::OK);
    for api in [
        "chat_completions",
        "responses",
        "messages",
        "generate_content",
    ] {
        assert!(body.contains(&format!("suggest-{api}")));
    }
    assert!(!body.contains("suggest-images"));
    assert!(!body.contains("suggest-embeddings"));
}
