//! Policies page + simulator — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::common::*;

#[tokio::test]
async fn email_simulator_explains_internal_external_and_invalid_recipients() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(include_str!(
            "../../../../examples/email-policy/email.cedar"
        ))
        .unwrap(),
    ));
    let state = Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, page) = body_of(app.clone(), "/policies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Simulation inputs"));
    assert!(page.contains("sim-arguments"));
    for (arguments, expected) in [
        (r#"{"to":["alice@example.com"]}"#, ">ALLOW<"),
        (
            r#"{"to":["alice@example.com"],"bcc":["partner@outside.example"]}"#,
            ">APPROVAL_REQUIRED<",
        ),
        (r#"{"to":["Alice <alice@example.com>"]}"#, ">DENY<"),
        ("not json", "Tool arguments must be a JSON object."),
    ] {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf", "dev-csrf"),
                ("sub", "assistant@example.com"),
                ("groups", "mail-assistants"),
                ("action", "call_tool"),
                ("resource_type", "tool"),
                ("server", "example-messages"),
                ("tool", "send"),
                ("tool_name", "send"),
                ("side_effects", "on"),
                ("arguments", arguments),
            ])
            .finish();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/policies/simulate")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains(expected), "{body}");
        if expected == ">APPROVAL_REQUIRED<" {
            assert!(body.contains("outside.example"));
            assert!(body.contains("approve-external-email"));
        }
    }
}

// ---- policies + simulator -------------------------------------------------

#[tokio::test]
pub(crate) async fn policies_page_shows_empty_when_no_cedar() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No Cedar engine configured"));
}

#[tokio::test]
pub(crate) async fn policies_page_lists_loaded_policies() {
    let app = dashboard_router(state_with_cedar().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);
    // Simulator form is rendered (Cedar configured).
    assert!(body.contains(r#"hx-post="/admin/policies/simulate""#));
    // Syntax highlighter should wrap the keyword `forbid`.
    assert!(body.contains(r#"<span class="kw">forbid</span>"#));
}

#[tokio::test]
pub(crate) async fn policies_page_groups_by_layer_with_metadata() {
    let app = dashboard_router(state_with_layered_cedar().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/policies").await;
    assert_eq!(status, StatusCode::OK);

    // No longer a single flat "All policies" dump — grouped by @layer with
    // human display titles.
    assert!(!body.contains("All policies"));
    assert!(body.contains("Baseline permits"));
    assert!(body.contains("Step-up overlay"));

    // Stable @id and @description surface per policy.
    assert!(body.contains("baseline-discovery"));
    assert!(body.contains("step-up-delete-dataset"));
    assert!(body.contains("Any authenticated principal may list and search tools."));

    // Tags render as chips and the @reason is shown.
    assert!(body.contains(">discovery</span>"));
    assert!(body.contains("delete_dataset requires the mcp:invoke:high step-up scope"));

    // The client-side filter input is present.
    assert!(body.contains(r#"id="policy-search""#));

    // Each policy carries a deep-link anchor the simulator trace targets.
    assert!(
        body.contains(r#"id="policy-step-up-delete-dataset""#),
        "policy deep-link anchor missing"
    );

    // Simulator registry inputs — catalog script, tool datalist, and the
    // side_effects checkbox all render (catalog is `[]` here: empty pool).
    assert!(
        body.contains(r#"id="sim-tool-catalog""#),
        "tool catalog script missing"
    );
    assert!(
        body.contains(r#"list="sim-tool-list""#),
        "tool typeahead missing"
    );
    assert!(
        body.contains(r#"name="side_effects""#),
        "side_effects input missing"
    );

    // Layers render in canonical evaluation order: baseline before step-up.
    let baseline_ix = body.find("Baseline permits").expect("baseline layer");
    let stepup_ix = body.find("Step-up overlay").expect("step-up layer");
    assert!(
        baseline_ix < stepup_ix,
        "baseline layer must render before the step-up overlay"
    );
}

#[tokio::test]
pub(crate) async fn simulate_returns_fragment_with_decision() {
    let app = dashboard_router(state_with_cedar().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policies/simulate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=dev-csrf&sub=alice&action=search_tools&resource_type=server&server=example-messages",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    // Fragment must be the drop-in `#sim-result` for htmx outerHTML swap.
    assert!(body.contains(r#"id="sim-result""#));
    // Deny-all policy + no allow → DENY chip.
    assert!(body.contains("DENY"), "expected DENY chip, got: {body}");
}

#[tokio::test]
pub(crate) async fn simulate_renders_structured_trace_with_determinative() {
    // A call to delete_dataset hits the annotated step-up forbid in the
    // layered fixture. The fragment must render the structured "why" trace, not
    // a flat list of opaque ids.
    let app = dashboard_router(state_with_layered_cedar().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policies/simulate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=dev-csrf&sub=alice&action=call_tool&tool_name=delete_dataset&risk=high\
                     &resource_type=tool&server=example-memory-assistant&tool=delete_dataset",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();

    // The fired forbid is shown with its layer, stable id, @reason, and is
    // flagged determinative.
    assert!(
        body.contains("Evaluation trace"),
        "trace section missing: {body}"
    );
    assert!(
        body.contains("Step-up overlay"),
        "layer name missing: {body}"
    );
    assert!(
        body.contains("step-up-delete-dataset"),
        "policy id missing: {body}"
    );
    assert!(
        body.contains("delete_dataset requires the mcp:invoke:high step-up scope"),
        "policy @reason missing: {body}"
    );
    // The trace policy id deep-links to its entry in the layered pane.
    // (Double-hash raw string: the href value itself contains `"#`.)
    assert!(
        body.contains(r##"href="#policy-step-up-delete-dataset""##),
        "trace deep-link missing: {body}"
    );
    assert!(
        body.contains("determinative"),
        "determinative flag missing: {body}"
    );
}

#[tokio::test]
pub(crate) async fn simulate_side_effects_field_changes_decision() {
    // The side_effects checkbox must flow into the decision. The
    // baseline read-only grant permits a low tool only when !side_effects.
    let state = state_with_readonly_low_policy().await;
    let base = "csrf=dev-csrf&sub=alice&action=call_tool&tool_name=t&risk=low\
                &resource_type=tool&server=s&tool=t";

    // side_effects OFF → read-only → ALLOW.
    let app = dashboard_router(state.clone(), DashboardAuth::Disabled);
    let (status, body) = simulate_post(app, base).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("ALLOW"),
        "read-only low tool should allow: {body}"
    );

    // side_effects ON → not read-only → DENY (no other permit).
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = simulate_post(app, &format!("{base}&side_effects=on")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("DENY"),
        "side-effecting tool must fall out of the read-only grant: {body}"
    );
}

/// POST a urlencoded body to `/policies/simulate` and return `(status, body)`.
pub(crate) async fn simulate_post(app: axum::Router, form: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policies/simulate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
pub(crate) async fn simulate_returns_503_when_no_cedar() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policies/simulate")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=dev-csrf&action=search_tools&resource_type=server&server=x",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(body.contains(r#"id="sim-result""#));
}
