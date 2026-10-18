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

// ---- connected versus disconnected publication -----------------------------

/// A disconnected server's rows come from its manifest, so each is marked as
/// not currently connected rather than presented as a working tool.
#[tokio::test]
pub(crate) async fn tools_page_marks_disconnected_manifest_rows_not_connected() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"data-tool="send_msg""#));
    assert!(body.contains(r#"data-tool="list_contacts""#));
    assert_eq!(
        body.matches(">not connected</span>").count(),
        2,
        "both manifest rows carry the not-connected label: {body}"
    );
    assert!(
        !body.contains("Connected servers publishing no tools"),
        "a disconnected server is not reported as withheld"
    );
}

/// Advertises one tool the manifest does not classify, so a connected lane
/// publishes none of the manifest's tools.
#[derive(Clone)]
struct UnclassifiedOnlyUpstream;

impl rmcp::ServerHandler for UnclassifiedOnlyUpstream {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        rmcp::model::ServerConfig::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(rmcp::model::Implementation::new(
            "unclassified-only-fixture",
            "1",
        ))
        .with_protocol_version(rmcp::model::ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListToolsResult::with_all_items(vec![
            rmcp::model::Tool::new(
                "rogue",
                "Not classified by the manifest",
                serde_json::json!({"type": "object", "properties": {}})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        ]))
    }
}

/// A connected server whose published list is empty lists no rows; its
/// classified tools are reported as blocked instead of falling back to the
/// manifest as if they worked.
#[tokio::test]
pub(crate) async fn tools_page_withholds_a_connected_server_that_publishes_no_tools() {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    let service = StreamableHttpService::new(
        || Ok(UnclassifiedOnlyUpstream),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, axum::Router::new().nest_service("/mcp", service))
            .await
            .unwrap();
    });
    let mut manifest = example_messages_manifest();
    manifest.url = Some(format!("http://{address}/mcp"));
    let pool =
        Arc::new(UpstreamPool::connect(BTreeMap::from([(manifest.name.clone(), manifest)])).await);
    let health = pool.health_snapshot().await;
    assert!(health[0].connected_lanes > 0, "the fixture lanes connect");
    assert_eq!(health[0].published_tool_count, 0);
    let state = Arc::new(base_admin_state_with_pool(pool));
    let app = dashboard_router(state.clone(), DashboardAuth::Disabled);

    let (status, body) = body_of(app.clone(), "/tools").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(r#"data-tool="send_msg""#) && !body.contains(r#"data-tool="list_contacts""#),
        "blocked tools must not be listed as rows: {body}"
    );
    assert!(body.contains("Connected servers publishing no tools"));
    assert!(
        body.contains("none of its 2 classified tools are published"),
        "{body}"
    );
    // The development administrator passes the Blocked page's gate, so the
    // count links to that server's blocked tools.
    assert!(
        body.contains(r#"href="/admin/tools/blocked?server=example-messages">2 blocked</a>"#),
        "{body}"
    );
    assert!(body.contains(r#"<a href="/admin/tools/blocked">Blocked tools</a>"#));
    assert!(!body.contains(">not connected</span>"));

    // Filtering to the withheld server keeps the selection and the notice.
    let (status, body) = body_of(app, "/t/default/tools?server=example-messages").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"<option value="example-messages" selected>example-messages (0)</option>"#),
        "{body}"
    );
    assert!(body.contains(
        r#"href="/admin/t/default/tools/blocked?server=example-messages">2 blocked</a>"#
    ));
    assert!(body.contains(r#"<a href="/admin/t/default/servers">Servers</a>"#));

    // A viewer without the admin gate sees the count without the links.
    let mut request = axum::http::Request::builder()
        .uri("/tools")
        .body(axum::body::Body::empty())
        .unwrap();
    request.extensions_mut().insert(waygate_oidc::Principal {
        sub: "viewer@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "https://idp.example.com".into(),
        scopes: vec!["mcp:read".into()],
        tenant: waygate_core::TenantId::parse("default").expect("tenant id"),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    });
    let response = tower::ServiceExt::oneshot(waygate_admin::dashboard::router(state), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains(">2 blocked</span>"), "{body}");
    assert!(!body.contains("tools/blocked?server="), "{body}");
    assert!(!body.contains(">Blocked tools</a>"), "{body}");
    server.abort();
}
