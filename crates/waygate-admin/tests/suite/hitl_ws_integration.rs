//! End-to-end coverage for the HITL approval WebSocket.
//!
//! Stands up an axum server on `127.0.0.1:0`, mounts the
//! `hitl_ws::router` behind a fake Principal injector (so
//! `require_admin` sees a real principal with the right scope), and
//! connects via `tokio-tungstenite` as a real WS client. Then
//! drives the `ApprovalHub` directly and asserts the wire shape
//! the operator's browser would see.
//!
//! Pins five behaviours future changes to this WebSocket must not regress:
//!
//! 1. **Happy path** — publish reaches an admin subscriber in the
//!    same tenant; the JSON wire shape matches the documented
//!    contract (event tag, field names).
//! 2. **Tenant scoping** — a publish for tenant B is filtered out
//!    by a subscriber bound to tenant A. The receive-side filter is
//!    the authoritative scope; cross-tenant leakage is the
//!    highest-impact regression to catch.
//! 3. **Scope gate** — a `mcp:read` (read-only) bearer is rejected
//!    at the upgrade with HTTP 403, NOT a half-open WebSocket.
//! 4. **Anonymous reject** — no `Principal` extension at all (the
//!    bearer middleware would have 401'd in production) → upgrade
//!    fails with 401.
//! 5. **Lagged-subscriber tolerance** — a slow subscriber that
//!    overflows the broadcast buffer must NOT take the hub down
//!    (other subscribers keep receiving). Covered indirectly here
//!    via the unit test in `hitl_ws::tests::hub_publish_reaches_subscriber`;
//!    the end-to-end WS path is the harder coverage to keep stable.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use futures_util::StreamExt;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use waygate_admin::hitl_ws;
use waygate_admin::AdminState;
use waygate_core::TenantId;
use waygate_invocation::{HitlApprovalNeeded, HitlNotifier};
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;

/// Build a Principal in `tenant` with the given scopes.
fn principal_in(tenant: &str, scopes: &[&str]) -> Principal {
    Principal {
        sub: "alice@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        tenant: TenantId::parse(tenant.to_owned()).expect("valid tenant id"),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

/// Fake bearer-layer replacement: if the request's
/// `X-Test-Principal-Tenant` header is set, install a Principal in
/// that tenant with the comma-separated `X-Test-Principal-Scopes`
/// scopes. Mirrors what the real bearer middleware would do, but
/// without forcing the test to stand up OIDC + JWKS.
async fn inject_test_principal(mut req: Request, next: Next) -> Response {
    let principal_hdrs: Option<(String, String)> = (|| {
        let tenant = req
            .headers()
            .get("X-Test-Principal-Tenant")?
            .to_str()
            .ok()?
            .to_owned();
        let scopes = req
            .headers()
            .get("X-Test-Principal-Scopes")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("mcp:admin")
            .to_owned();
        Some((tenant, scopes))
    })();
    if let Some((tenant, scopes_str)) = principal_hdrs {
        let scopes: Vec<&str> = scopes_str.split(',').collect();
        req.extensions_mut().insert(principal_in(&tenant, &scopes));
    }
    next.run(req).await
}

async fn build_state() -> Arc<AdminState> {
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

/// Build a test app that mounts the hitl_ws router with our
/// fake-principal injector wrapped around it. The injector layer
/// must run BEFORE `require_admin` (i.e. outside the router under
/// test), which is exactly how the real bearer middleware sits in
/// the production composition.
fn build_app(state: Arc<AdminState>) -> Router {
    hitl_ws::router(state).layer(axum::middleware::from_fn(inject_test_principal))
}

/// Start the test server on 127.0.0.1:0, return `(addr, hub)`.
async fn spawn_test_server() -> (std::net::SocketAddr, Arc<hitl_ws::ApprovalHub>) {
    let hub = Arc::new(hitl_ws::ApprovalHub::default());
    // build_state returns Arc<AdminState>; with_hitl_hub takes self
    // by value, so we unwrap once (the Arc has no other clones yet)
    // and re-wrap.
    let state_arc = build_state().await;
    let state = Arc::try_unwrap(state_arc)
        .map_err(|_| ())
        .expect("solo Arc<AdminState>")
        .with_hitl_hub(hub.clone());
    let state = Arc::new(state);
    let app = build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    // tiny yield so the bind is observable to clients
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, hub)
}

fn ws_url(addr: std::net::SocketAddr) -> String {
    format!("ws://{}/api/v1/admin/approval_grants/subscribe", addr)
}

/// Connect with mcp:admin in the given tenant. Returns the
/// connected socket on success.
async fn connect_admin(
    addr: std::net::SocketAddr,
    tenant: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut req = ws_url(addr).into_client_request().expect("ws request");
    let headers = req.headers_mut();
    headers.insert(
        "X-Test-Principal-Tenant",
        tenant.parse().expect("tenant header"),
    );
    headers.insert(
        "X-Test-Principal-Scopes",
        "mcp:admin".parse().expect("scopes header"),
    );
    let (ws, _resp) = tokio_tungstenite::connect_async(req)
        .await
        .expect("ws upgrade");
    ws
}

/// Helper: pull the next non-keepalive (non-Ping/Pong) message.
async fn next_text_message(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<String> {
    while let Some(frame) = ws.next().await {
        match frame.ok()? {
            Message::Text(t) => return Some(t.to_string()),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return None,
            _ => continue,
        }
    }
    None
}

// --- Tests --------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_subscriber_receives_publish_in_same_tenant() {
    let (addr, hub) = spawn_test_server().await;
    let mut ws = connect_admin(addr, "acme").await;
    // Brief settle so the subscriber count increments before we
    // publish (otherwise the broadcast Drops it on the floor).
    tokio::time::sleep(Duration::from_millis(50)).await;
    hub.notify_approval_needed(HitlApprovalNeeded {
        summary: Default::default(),
        tenant_id: "acme".into(),
        principal_sub: "user@acme.example".into(),
        principal_issuer: "https://issuer.test".to_owned(),
        server: "example-messages".into(),
        tool: "send_msg".into(),
        argument_hash: "abc123".into(),
        behavior_hash: "beef".into(),
    });

    let raw = tokio::time::timeout(Duration::from_secs(2), next_text_message(&mut ws))
        .await
        .expect("timed out waiting for ws event")
        .expect("ws closed before delivering event");
    let v: Value = serde_json::from_str(&raw).expect("parse json");

    assert_eq!(v["event"], "approval_needed");
    assert_eq!(v["tenant_id"], "acme");
    assert_eq!(v["principal_sub"], "user@acme.example");
    assert_eq!(v["server"], "example-messages");
    assert_eq!(v["tool"], "send_msg");
    assert_eq!(v["argument_hash"], "abc123");
    assert!(
        v["emitted_at"].is_string(),
        "emitted_at must be present and RFC3339",
    );

    let _ = ws.close(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriber_does_not_receive_events_for_other_tenant() {
    let (addr, hub) = spawn_test_server().await;
    // Two subscribers, one per tenant. Same hub, same channel —
    // the per-receiver tenant filter is the only thing keeping
    // tenant B's events away from tenant A's admin.
    let mut a_ws = connect_admin(addr, "acme").await;
    let mut b_ws = connect_admin(addr, "globex").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish ONE event for tenant globex.
    hub.notify_approval_needed(HitlApprovalNeeded {
        summary: Default::default(),
        tenant_id: "globex".into(),
        principal_sub: "user@globex.example".into(),
        principal_issuer: "https://issuer.test".to_owned(),
        server: "github".into(),
        tool: "merge_pr".into(),
        argument_hash: "ff00ff".into(),
        behavior_hash: "beef".into(),
    });

    // Tenant B sees it.
    let b_raw = tokio::time::timeout(Duration::from_secs(2), next_text_message(&mut b_ws))
        .await
        .expect("tenant B receives event")
        .expect("ws closed");
    let b_v: Value = serde_json::from_str(&b_raw).expect("parse json");
    assert_eq!(b_v["tenant_id"], "globex");

    // Tenant A must NOT see it. Wait briefly to confirm absence.
    let a_attempt =
        tokio::time::timeout(Duration::from_millis(400), next_text_message(&mut a_ws)).await;
    assert!(
        a_attempt.is_err(),
        "tenant A must NOT receive tenant B's event; got {a_attempt:?}",
    );

    let _ = a_ws.close(None).await;
    let _ = b_ws.close(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_read_only_principal_is_rejected_at_upgrade() {
    let (addr, _hub) = spawn_test_server().await;
    let mut req = ws_url(addr).into_client_request().expect("ws request");
    let headers = req.headers_mut();
    headers.insert(
        "X-Test-Principal-Tenant",
        "acme".parse().expect("tenant header"),
    );
    headers.insert(
        "X-Test-Principal-Scopes",
        "mcp:read".parse().expect("scopes header"),
    );
    let err = tokio_tungstenite::connect_async(req)
        .await
        .expect_err("upgrade should be rejected for non-admin scope");
    // The 403 surface is what we care about; tungstenite reports
    // it as Http response on the handshake error.
    let s = format!("{err:?}");
    assert!(
        s.contains("403") || s.contains("Forbidden"),
        "expected 403 on missing mcp:admin scope; got {s}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_request_is_rejected_at_upgrade() {
    let (addr, _hub) = spawn_test_server().await;
    // No injector headers → the require_admin layer sees no
    // Principal extension → 401.
    let req = ws_url(addr).into_client_request().expect("ws request");
    let err = tokio_tungstenite::connect_async(req)
        .await
        .expect_err("upgrade should be rejected without a principal");
    let s = format!("{err:?}");
    assert!(
        s.contains("401") || s.contains("Unauthorized"),
        "expected 401 on missing principal; got {s}",
    );
}
