//! Tools page — split from the monolithic `dashboard_render.rs`;
//! bodies verbatim, cut at the file's own section markers.

use crate::common::*;

// ---- tools ----------------------------------------------------------------

#[tokio::test]
pub(crate) async fn tools_page_renders_manifest_fallback() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools").await;
    assert_eq!(status, StatusCode::OK);
    // Both classified tools from the manifest appear with their risk chips.
    assert!(body.contains("send_msg"));
    assert!(body.contains("list_contacts"));
    assert!(body.contains("chip--bad"), "high-risk chip missing");
}

#[tokio::test]
pub(crate) async fn tools_page_rows_open_schema_drawer() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools").await;
    assert_eq!(status, StatusCode::OK);
    // Rows carry the data attributes the drawer JS keys off, plus the
    // drawer container and its read-only GET base URL.
    assert!(
        body.contains(r#"data-tool="send_msg""#),
        "row data-tool missing"
    );
    assert!(
        body.contains(r#"data-server="example-messages""#),
        "row data-server missing"
    );
    assert!(body.contains(r#"id="drawer""#), "drawer container missing");
    assert!(body.contains("/tools/drawer"), "drawer base URL missing");
}

#[tokio::test]
pub(crate) async fn tools_drawer_renders_overview_when_upstream_disconnected() {
    // The manifest fixture is disconnected, so list_tools is empty and the
    // drawer falls back to the manifest-backed overview (no live schema).
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools/drawer?server=example-messages&tool=send_msg").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("send_msg"), "tool name missing from drawer");
    assert!(body.contains("Overview"), "overview section missing");
    // high-risk send_msg keeps its risk chip even without a live schema.
    assert!(body.contains("chip--bad"), "risk chip missing");
    assert!(
        body.contains("live schema is unavailable"),
        "fallback note missing"
    );
}

#[tokio::test]
pub(crate) async fn tools_page_renders_filter_bar_and_count() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools").await;
    assert_eq!(status, StatusCode::OK);
    // Filter form with the server facet (count from the unfiltered catalogue).
    assert!(body.contains(r#"name="server""#), "server select missing");
    assert!(body.contains("All servers"), "server 'all' option missing");
    assert!(
        body.contains("example-messages (2)"),
        "server facet count missing"
    );
    // Two tools, unfiltered (count renders the number bolded: "<strong>2</strong> tools.").
    assert!(body.contains("2</strong> tool"), "result count missing");
}

#[tokio::test]
pub(crate) async fn tools_page_search_narrows_results() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools?q=contacts").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("list_contacts"), "matching tool dropped");
    // send_msg is the row text; it must be filtered out (the filter form has no
    // option text containing 'send_msg', so this is a reliable signal).
    assert!(
        !body.contains("send_msg"),
        "non-matching tool not filtered out"
    );
}

#[tokio::test]
pub(crate) async fn tools_page_filters_by_risk() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools?risk=high").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("send_msg"), "high-risk tool dropped");
    assert!(
        !body.contains("list_contacts"),
        "low-risk tool not filtered out"
    );
}

#[tokio::test]
pub(crate) async fn tools_page_filters_by_side_effects() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    // list_contacts has no side effects; send_msg does.
    let (status, body) = body_of(app, "/tools?side_effects=no").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("list_contacts"),
        "no-side-effect tool dropped"
    );
    assert!(
        !body.contains("send_msg"),
        "side-effecting tool not filtered out"
    );
}

#[tokio::test]
pub(crate) async fn tools_page_ignores_unrepresentable_filter_values() {
    // A hand-crafted URL with values no <select> can show must NOT silently
    // filter the rows (the control would still read "Any") — they're dropped.
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(
        app,
        "/tools?risk=garbage&pii=garbage&server=nope&side_effects=maybe",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("send_msg"), "tool dropped by invalid filter");
    assert!(
        body.contains("list_contacts"),
        "tool dropped by invalid filter"
    );
}
