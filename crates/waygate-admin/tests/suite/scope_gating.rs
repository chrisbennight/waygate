//! Route-level sanity: scope gating rejects unauthorized calls and lets
//! properly-scoped callers through, even against an empty state.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

use waygate_admin::{api_router, AdminState};
use waygate_authz::{CedarEngine, ReloadableCedar};
use waygate_mcp::audit::InMemorySink;
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;
use waygate_upstream::{Transport, UpstreamManifest};

fn principal_with(scopes: &[&str]) -> Principal {
    Principal {
        sub: "test-user".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn empty_state() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

async fn state_with_tenant_cedar() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(
        CedarEngine::from_source(
            r#"@id("default-only")
permit(principal, action, resource);"#,
        )
        .unwrap(),
    ));
    engine.replace_tenants(HashMap::from([(
        "acme".to_owned(),
        CedarEngine::from_source(
            r#"@id("tenant-block")
forbid(principal, action, resource);"#,
        )
        .unwrap(),
    )]));
    Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

fn disconnected_manifest(name: &str) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: name.to_owned(),
        transport: Transport::Http,
        protocol: Default::default(),
        url: Some("http://127.0.0.1:9/mcp".to_owned()),
        command: None,
        tools: Vec::new(),
        resources: Vec::new(),
        exchange: None,
        tier_a_required: false,
        auth: None,
        mtls: None,
        tier_c_peer: None,
        session: None,
    }
}

#[tokio::test]
async fn servers_list_exposes_the_runtime_health_snapshot() {
    let manifest = disconnected_manifest("mock");
    let pool = Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::from([
        (manifest.name.clone(), manifest),
    ])));
    let state = Arc::new(AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = api_router(state);
    let mut req = Request::builder()
        .uri("/api/v1/servers")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));

    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body[0]["name"], "mock");
    assert_eq!(body[0]["runtime_status"], "disconnected");
    assert!(body[0]["last_success_at"].is_null());
    assert!(body[0]["last_error_class"].is_null());
    assert!(
        body[0]["next_retry_at"].is_string(),
        "a disconnected upstream exposes its independently scheduled retry"
    );
    assert_eq!(body[0]["connected"], false);
    assert_eq!(body[0]["breaker"], "closed");
    assert_eq!(body[0]["connected_lanes"], 0);
    assert_eq!(body[0]["total_lanes"], 1);
    assert_eq!(body[0]["published_tool_count"], 0);
    assert_eq!(body[0]["quarantined_tool_count"], 0);
}

#[tokio::test]
async fn servers_requires_read_scope() {
    let app = api_router(empty_state().await);

    // No principal at all → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/servers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Principal with wrong scope → 403.
    let mut req = Request::builder()
        .uri("/api/v1/servers")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:invoke"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Principal with mcp:read → 200 with empty array.
    let mut req = Request::builder()
        .uri("/api/v1/servers")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&bytes[..], b"[]");
}

#[tokio::test]
async fn upstream_operational_controls_require_admin_scope() {
    let app = api_router(empty_state().await);

    for uri in [
        "/api/v1/servers/missing/reconnect",
        "/api/v1/servers/missing/catalog/refresh",
        "/api/v1/servers/missing/quarantine/clear",
    ] {
        let mut req = Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(principal_with(&["mcp:read"]));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");

        let mut req = Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(principal_with(&["mcp:admin"]));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "admin scope must pass the gate and reach the server lookup for {uri}"
        );
    }
}

#[tokio::test]
async fn catalog_refresh_audit_attributes_the_admin_principal() {
    let manifest = disconnected_manifest("mock");
    let sink = Arc::new(InMemorySink::new());
    let pool = Arc::new(
        UpstreamPool::from_manifests_disconnected(BTreeMap::from([(
            manifest.name.clone(),
            manifest,
        )]))
        .with_evidence(sink.clone()),
    );
    let state = Arc::new(AdminState::new(
        pool,
        None,
        None,
        sink.clone(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = api_router(state);
    let actor = principal_with(&["mcp:admin"]);
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/servers/mock/catalog/refresh")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(actor.clone());

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while sink.snapshot().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("attributed refresh event was scheduled");
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 1, "REST refresh emits one attributed event");
    let event = &events[0];
    assert_eq!(event.action, "UpstreamCatalogRefresh");
    assert_eq!(
        event.principal.as_ref().map(|p| p.sub.as_str()),
        Some("test-user")
    );
    assert_eq!(event.tenant, actor.tenant);
    assert_eq!(event.target.as_deref(), Some("mock"));
}

#[tokio::test]
async fn builtins_require_read_scope() {
    // The built-in surfaces view is read-only and non-sensitive (static
    // descriptors), gated by `mcp:read` like the Servers list.
    let app = api_router(empty_state().await);

    // No principal → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/gateway/builtins")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong scope → 403.
    let mut req = Request::builder()
        .uri("/api/v1/gateway/builtins")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:invoke"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // mcp:read → 200 (empty array; empty_state injects no descriptors).
    let mut req = Request::builder()
        .uri("/api/v1/gateway/builtins")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn policies_require_admin_scope() {
    let app = api_router(empty_state().await);

    let mut req = Request::builder()
        .uri("/api/v1/policies")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let mut req = Request::builder()
        .uri("/api/v1/policies")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn policy_listing_and_simulation_use_the_callers_tenant_engine() {
    let app = api_router(state_with_tenant_cedar().await);
    let mut caller = principal_with(&["mcp:admin", "mcp:observe"]);
    caller.tenant = waygate_core::TenantId::parse("acme").unwrap();

    let mut req = Request::builder()
        .uri("/api/v1/policies")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(caller.clone());
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        body.contains("tenant-block"),
        "tenant policy missing: {body}"
    );
    assert!(
        !body.contains("default-only"),
        "default tenant source crossed the tenant boundary: {body}",
    );

    let simulation = serde_json::json!({
        "principal": {"sub": "alice"},
        "action": {"type": "search_tools"},
        "resource": {"type": "server", "name": "example-messages"}
    });
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/policies/simulate")
        .header("content-type", "application/json")
        .body(Body::from(simulation.to_string()))
        .unwrap();
    req.extensions_mut().insert(caller);
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["policy_ids"], serde_json::json!(["tenant-block"]));
}

#[tokio::test]
async fn simulate_requires_observe_scope() {
    // Design decision: `/policies/simulate` is the read-only "would X be
    // allowed?" diagnostic, gated on `mcp:observe` (the list dump stays admin).
    let app = api_router(empty_state().await);
    let body = r#"{"principal":{"sub":"x"},"action":{"type":"list_tools"},"resource":{"type":"server","name":"s"}}"#;

    // `mcp:read` (neither observe nor admin) → 403 at the gate.
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/policies/simulate")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // `mcp:observe` passes the gate; the empty state has no Cedar engine, so the
    // handler returns 503 — proving the request reached the handler (the gate
    // moved from mcp:admin to mcp:observe).
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/policies/simulate")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    req.extensions_mut()
        .insert(principal_with(&["mcp:observe"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn audit_endpoint_503s_without_store() {
    let app = api_router(empty_state().await);

    let mut req = Request::builder()
        .uri("/api/v1/audit")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn simulate_503s_without_cedar_engine() {
    let app = api_router(empty_state().await);

    let body = serde_json::json!({
        "principal": {"sub": "alice", "scopes": []},
        "action": {"type": "search_tools"},
        "resource": {"type": "server", "name": "example-messages"}
    });
    let mut req = Request::builder()
        .uri("/api/v1/policies/simulate")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
