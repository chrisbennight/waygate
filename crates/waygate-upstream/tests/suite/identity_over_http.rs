//! HTTP-level proof that `IdentityForwardingClient` wrapping a real
//! `reqwest::Client` puts `X-MCP-Identity` on the wire.
//!
//! Unit tests already verify the wrapper delegates to its inner client with
//! the header injected; this test closes the last gap — that the header
//! survives reqwest serialization and arrives at a real upstream — by
//! standing up a tiny axum service that captures every incoming header.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, JsonRpcRequest, JsonRpcVersion2_0, NumberOrString,
    PingRequest,
};
use rmcp::transport::streamable_http_client::StreamableHttpClient;
use tokio::net::TcpListener;

use waygate_oidc::{IdentityClaims, Principal};
use waygate_upstream::{IdentityCell, IdentityContext, IdentityForwardingClient, IDENTITY_HEADER};

use super::test_identity_issuer;

#[derive(Default, Clone)]
struct Captured {
    headers: Arc<Mutex<HeaderMap>>,
}

async fn capture(State(state): State<Captured>, headers: HeaderMap, _body: String) -> Response {
    *state.headers.lock().unwrap() = headers;
    // rmcp's reqwest impl accepts 202 Accepted with no body as "fire-and-forget"
    // OK. That's enough for `post_message` to return success here.
    Response::builder()
        .status(202)
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn spawn_capture_server() -> (SocketAddr, Captured) {
    let captured = Captured::default();
    let app: Router = Router::new()
        .route("/mcp", post(capture))
        .with_state(captured.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, captured)
}

fn ping_message() -> ClientJsonRpcMessage {
    ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: NumberOrString::Number(1),
        request: ClientRequest::PingRequest(PingRequest::default()),
    })
}

#[tokio::test]
async fn identity_header_arrives_at_upstream_over_real_http() {
    let (addr, captured) = spawn_capture_server().await;
    let issuer = test_identity_issuer();
    let cell = IdentityCell::new();
    let client =
        IdentityForwardingClient::new(reqwest::Client::new(), issuer.clone(), cell.clone());

    cell.set(IdentityContext {
        principal: Principal {
            sub: "e2e-user".into(),
            email: Some("e2e@example.test".into()),
            groups: vec!["mcp-users".into()],
            issuer: "https://auth.test/".into(),
            scopes: vec!["mcp:invoke".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        },
        audience: "upstream-e2e".into(),
        exchange: None,
        stored_upstream_subject_token: None,
        exchanged_bearer: None,
        tier_c_audience: None,
    });

    let uri: Arc<str> = format!("http://{addr}/mcp").into();
    client
        .post_message(uri, ping_message(), None, None, HashMap::new())
        .await
        .expect("post_message");

    let headers = captured.headers.lock().unwrap().clone();
    let jwt = headers
        .get(IDENTITY_HEADER.as_str())
        .expect("X-MCP-Identity reached the upstream")
        .to_str()
        .unwrap()
        .to_owned();

    // Verify claims round-trip via the issuer's own JWKS — same path an upstream
    // would take when validating the token.
    let jwks = issuer.jwks();
    let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();
    let mut v = Validation::new(Algorithm::EdDSA);
    v.set_issuer(&["https://mcp.test"]);
    v.set_audience(&["upstream-e2e"]);
    let decoded = decode::<IdentityClaims>(&jwt, &key, &v).unwrap();
    assert_eq!(decoded.claims.sub, "e2e-user");
    assert_eq!(decoded.claims.act.sub, "gateway-e2e");
    assert_eq!(decoded.claims.aud, "upstream-e2e");
    assert_eq!(decoded.claims.email.as_deref(), Some("e2e@example.test"));
    assert_eq!(decoded.claims.groups, vec!["mcp-users".to_string()]);
}

/// When the cell carries
/// `tier_c_audience = Some(<peer_issuer>)`, the
/// minted JWT must land on BOTH `X-MCP-Identity` (for
/// upstreams that still consume it) AND `Authorization:
/// Bearer` so the remote gateway's `PeerJwtValidator`
/// actually sees it. The same JWT must also carry the
/// peer's issuer URL as `aud`.
#[tokio::test]
async fn tier_c_stamps_authorization_with_peer_audience_jwt() {
    let (addr, captured) = spawn_capture_server().await;
    let issuer = test_identity_issuer();
    let cell = IdentityCell::new();
    let client =
        IdentityForwardingClient::new(reqwest::Client::new(), issuer.clone(), cell.clone());

    cell.set(IdentityContext {
        principal: Principal {
            sub: "alice".into(),
            email: None,
            groups: vec![],
            issuer: "https://auth.test/".into(),
            scopes: vec!["mcp:invoke".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        },
        // `audience` is the local server name (existing
        // Tier-B behaviour) — Tier-C overrides via
        // `tier_c_audience`.
        audience: "upstream-server".into(),
        exchange: None,
        stored_upstream_subject_token: None,
        exchanged_bearer: None,
        tier_c_audience: Some("https://remote-peer.example/".into()),
    });

    let uri: Arc<str> = format!("http://{addr}/mcp").into();
    client
        .post_message(uri, ping_message(), None, None, HashMap::new())
        .await
        .expect("post_message");

    let headers = captured.headers.lock().unwrap().clone();
    let jwt_h = headers
        .get(IDENTITY_HEADER.as_str())
        .expect("X-MCP-Identity stamped")
        .to_str()
        .unwrap()
        .to_owned();
    let bearer_h = headers
        .get("authorization")
        .expect("Authorization stamped under tier_c")
        .to_str()
        .unwrap()
        .to_owned();
    let bearer_jwt = bearer_h
        .strip_prefix("Bearer ")
        .expect("Authorization must be Bearer-shaped");

    // Both headers carry the same JWT, and both verify
    // against the PEER's audience (not the local server
    // name).
    assert_eq!(jwt_h, bearer_jwt);
    let jwks = issuer.jwks();
    let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();
    let mut v = Validation::new(Algorithm::EdDSA);
    v.set_issuer(&["https://mcp.test"]);
    v.set_audience(&["https://remote-peer.example/"]);
    let decoded = decode::<IdentityClaims>(bearer_jwt, &key, &v).unwrap();
    assert_eq!(decoded.claims.sub, "alice");
    assert_eq!(decoded.claims.aud, "https://remote-peer.example/");
}

#[tokio::test]
async fn no_identity_header_when_cell_empty_over_real_http() {
    let (addr, captured) = spawn_capture_server().await;
    let client = IdentityForwardingClient::new(
        reqwest::Client::new(),
        test_identity_issuer(),
        IdentityCell::new(),
    );

    let uri: Arc<str> = format!("http://{addr}/mcp").into();
    client
        .post_message(uri, ping_message(), None, None, HashMap::new())
        .await
        .expect("post_message");

    let headers = captured.headers.lock().unwrap().clone();
    assert!(
        headers.get(IDENTITY_HEADER.as_str()).is_none(),
        "empty cell must not inject header"
    );
}
