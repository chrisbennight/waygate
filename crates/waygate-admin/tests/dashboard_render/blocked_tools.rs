//! Blocked tools page: route, admin gate, tenant scope, and the links that
//! lead to it from Overview, Activity, and the command palette.

use crate::common::*;

/// A disconnected annotation-mode upstream: with no connected session, the
/// call path holds each of its two tools as temporarily unavailable.
async fn state_with_blocked_tools() -> Arc<AdminState> {
    let mut manifest = example_messages_manifest();
    manifest.classification_mode = waygate_upstream::ClassificationMode::McpAnnotations;
    for tool in &mut manifest.tools {
        tool.approved_behavior_hash = Some("a".repeat(64));
        tool.side_effects = false;
        tool.pii = false;
    }
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        ("example-messages".to_owned(), manifest),
    ])));
    Arc::new(base_admin_state_with_pool(pool))
}

fn principal(
    tenant: &str,
    scopes: &[&str],
    method: waygate_oidc::AuthMethod,
) -> waygate_oidc::Principal {
    waygate_oidc::Principal {
        sub: "operator@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "https://idp.example.com".into(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        tenant: waygate_core::TenantId::parse(tenant).expect("tenant id"),
        auth_method: method,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

/// GET `uri` on the page routes as `principal`, bypassing the session layer
/// that would otherwise inject the development administrator.
async fn body_as(
    state: Arc<AdminState>,
    principal: waygate_oidc::Principal,
    uri: &str,
) -> (StatusCode, String) {
    let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    request.extensions_mut().insert(principal);
    let response = waygate_admin::dashboard::router(state)
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
pub(crate) async fn blocked_tools_page_lists_each_tool_with_reason_and_scope() {
    let app = dashboard_router(state_with_blocked_tools().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/tools/blocked").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/admin/t/default/tools/blocked" aria-current="page""#),
        "the Blocked tab is current: {body}"
    );
    assert!(
        body.contains(r#"href="/admin/t/default/tools" aria-current="page""#),
        "the Tools destination is current"
    );
    assert!(body.contains("2 blocked"));
    assert!(body.contains("example-messages"));
    assert!(body.contains("send_msg") && body.contains("list_contacts"));
    assert!(body.contains("Server not connected"));
    assert!(body.contains("should clear on its own once the gateway reconnects"));
    assert!(body.contains("unavailable:no_connected_lane"));
    assert!(body.contains("No action needed"));
}

#[tokio::test]
pub(crate) async fn blocked_tools_page_says_so_when_nothing_is_blocked() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/tools/blocked").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No blocked tools"));
}

#[tokio::test]
pub(crate) async fn blocked_tools_page_can_be_limited_to_one_server() {
    let app = dashboard_router(state_with_blocked_tools().await, DashboardAuth::Disabled);
    let (_, body) = body_of(app, "/tools/blocked?server=example-messages").await;
    assert!(body.contains("send_msg"));
    assert!(body.contains("Show every server"));
    let app = dashboard_router(state_with_blocked_tools().await, DashboardAuth::Disabled);
    let (_, body) = body_of(app, "/tools/blocked?server=another-server").await;
    assert!(body.contains("No blocked tools"), "{body}");
}

#[tokio::test]
pub(crate) async fn blocked_tools_page_requires_the_catalog_admin_gate() {
    use waygate_oidc::AuthMethod;
    for (who, principal) in [
        (
            "reader",
            principal("default", &["mcp:read"], AuthMethod::Oauth),
        ),
        (
            "peer assertion",
            principal("default", &["mcp:admin"], AuthMethod::PeerAssertion),
        ),
    ] {
        let (status, body) = body_as(
            state_with_blocked_tools().await,
            principal,
            "/tools/blocked",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{who}");
        assert!(body.contains("Admin scope required"), "{who}");
        assert!(
            !body.contains("send_msg") && !body.contains("example-messages"),
            "{who} must not learn which tools are blocked"
        );
    }
    let (_, body) = body_as(
        state_with_blocked_tools().await,
        principal("default", &["mcp:admin"], AuthMethod::Oauth),
        "/tools/blocked",
    )
    .await;
    assert!(
        body.contains("send_msg"),
        "an administrator sees the report"
    );
}

/// Without a catalog row visible to it, another tenant's administrator sees
/// none of the gateway-wide servers.
#[tokio::test]
pub(crate) async fn blocked_tools_page_is_scoped_to_the_viewer_tenant() {
    let (_, body) = body_as(
        state_with_blocked_tools().await,
        principal("acme", &["mcp:admin"], waygate_oidc::AuthMethod::Oauth),
        "/tools/blocked",
    )
    .await;
    assert!(body.contains("No blocked tools"), "{body}");
    assert!(!body.contains("send_msg"));
}

#[tokio::test]
pub(crate) async fn overview_loads_blocked_counts_separately_and_keeps_the_admin_gate() {
    let app = dashboard_router(state_with_blocked_tools().await, DashboardAuth::Disabled);
    let (_, body) = body_of(app.clone(), "/t/default").await;
    assert!(body.contains("Checking blocked tools"));
    assert!(!body.contains("2 blocked tools"));
    assert!(body.contains(r#"hx-get="/admin/t/default/overview/blocked-tools""#));
    let (status, body) = body_of(app, "/t/default/overview/blocked-tools").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("2 blocked tools"), "{body}");
    assert!(body.contains(r#"href="/admin/t/default/tools/blocked""#));

    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (_, body) = body_of(app, "/overview/blocked-tools").await;
    assert!(body.contains("No blocked tools"));

    let (_, body) = body_as(
        state_with_blocked_tools().await,
        principal("default", &["mcp:read"], waygate_oidc::AuthMethod::Oauth),
        "/",
    )
    .await;
    assert!(
        !body.contains("blocked tool"),
        "a non-administrator sees no count"
    );
    let (status, body) = body_as(
        state_with_blocked_tools().await,
        principal("default", &["mcp:read"], waygate_oidc::AuthMethod::Oauth),
        "/overview/blocked-tools",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!body.contains("2 blocked tools"));
    let (status, body) = body_as(
        state_with_blocked_tools().await,
        principal("other", &["mcp:admin"], waygate_oidc::AuthMethod::Oauth),
        "/overview/blocked-tools",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No blocked tools"));
}

#[tokio::test]
pub(crate) async fn activity_detail_of_a_refused_call_links_to_the_blocked_page() {
    let mut refused = sample_row("denied", Some("example-messages"), Some("high"));
    refused.reason = Some("refused:server_quarantined".into());
    let mut unavailable = sample_row("error", Some("example-messages"), Some("high"));
    unavailable.reason = Some("unavailable:catalog_converging".into());
    let denied = sample_row("denied", Some("example-messages"), Some("high"));
    let ids = [refused.id, unavailable.id, denied.id];
    let state = state_with_audit_reader(Arc::new(MemoryAudit {
        rows: vec![refused, unavailable, denied],
    }))
    .await;
    for (id, linked) in ids.into_iter().zip([true, true, false]) {
        let app = dashboard_router(state.clone(), DashboardAuth::Disabled);
        let (status, body) = body_of(app, &format!("/t/default/activity/{id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body.contains(r#"href="/admin/t/default/tools/blocked?server=example-messages""#),
            linked,
            "{body}"
        );
    }
}

#[tokio::test]
pub(crate) async fn blocked_tools_appears_in_the_palette() {
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/search?q=blocked").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Blocked tools"), "{body}");
    assert!(body.contains("/admin/t/default/tools/blocked"));
}
