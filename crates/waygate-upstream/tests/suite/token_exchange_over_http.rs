//! End-to-end proof of Tier A (RFC 8693) identity chaining:
//! 1. Gateway receives a caller's subject token via `principal.raw_token`.
//! 2. `IdentityForwardingClient` swaps it at a mock IdP `/token` endpoint.
//! 3. The downscoped `access_token` arrives at the upstream as
//!    `Authorization: Bearer …`.
//! 4. A repeated call within the cache TTL must NOT hit the IdP again.
//!
//! The test stands up two tiny axum services (IdP + upstream) on ephemeral
//! ports so we exercise real reqwest serialization — mirrors the pattern in
//! `identity_over_http.rs` for Tier B.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, JsonRpcRequest, JsonRpcVersion2_0, NumberOrString,
    PingRequest,
};
use rmcp::transport::streamable_http_client::StreamableHttpClient;
use tokio::net::TcpListener;

use waygate_oidc::{IdentityIssuer, Principal, TokenCache, TokenExchangeClient};
use waygate_upstream::{
    ExchangeSettings, IdentityCell, IdentityContext, IdentityForwardingClient, IDENTITY_HEADER,
};

#[derive(Default, Clone)]
struct IdpCaptured {
    last_body: Arc<Mutex<String>>,
    call_count: Arc<Mutex<u32>>,
}

async fn idp_handler(State(state): State<IdpCaptured>, body: String) -> Response {
    *state.last_body.lock().unwrap() = body;
    *state.call_count.lock().unwrap() += 1;
    let body = serde_json::json!({
        "access_token": "downscoped-example-messages-xyz",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "upstream:example-messages",
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn spawn_idp() -> (SocketAddr, IdpCaptured) {
    let cap = IdpCaptured::default();
    let app = Router::new()
        .route("/token", post(idp_handler))
        .with_state(cap.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, cap)
}

#[derive(Default, Clone)]
struct UpstreamCaptured {
    headers: Arc<Mutex<HeaderMap>>,
}

async fn upstream_handler(
    State(state): State<UpstreamCaptured>,
    headers: HeaderMap,
    _body: String,
) -> Response {
    *state.headers.lock().unwrap() = headers;
    Response::builder()
        .status(202)
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn spawn_upstream() -> (SocketAddr, UpstreamCaptured) {
    let cap = UpstreamCaptured::default();
    let app = Router::new()
        .route("/mcp", post(upstream_handler))
        .with_state(cap.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, cap)
}

fn test_issuer() -> Arc<IdentityIssuer> {
    let sk = SigningKey::from_bytes(&[21u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
    Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            "gw-tierA",
            "https://mcp.test",
            "gateway-tierA",
            Duration::from_secs(60),
        )
        .unwrap(),
    )
}

fn ping_message() -> ClientJsonRpcMessage {
    ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: NumberOrString::Number(1),
        request: ClientRequest::PingRequest(PingRequest::default()),
    })
}

#[tokio::test]
async fn token_exchange_injects_bearer_and_caches() {
    let (idp_addr, idp_cap) = spawn_idp().await;
    let (up_addr, up_cap) = spawn_upstream().await;

    let exchange_client = Arc::new(TokenExchangeClient::new(
        waygate_core::http_client::client(waygate_core::http_client::Profile::Interactive).unwrap(),
        format!("http://{idp_addr}/token"),
        "gateway-client",
        "gateway-secret",
    ));
    let cache = Arc::new(TokenCache::default());

    let cell = IdentityCell::new();
    let client = IdentityForwardingClient::new(reqwest::Client::new(), test_issuer(), cell.clone())
        .with_exchange(exchange_client, cache);

    cell.set(IdentityContext {
        principal: Principal {
            sub: "alice".into(),
            email: Some("alice@example.test".into()),
            groups: vec!["mcp-users".into()],
            issuer: "https://auth.test/".into(),
            scopes: vec!["mcp:invoke".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: Some("user-access-token-12345".into()),
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        },
        audience: "example-messages".into(),
        exchange: Some(ExchangeSettings {
            audience: "https://example-messages.test/mcp".into(),
            scope: Some("upstream:example-messages".into()),
        }),
        stored_upstream_subject_token: None,
        exchanged_bearer: None,
        tier_c_audience: None,
    });

    let uri: Arc<str> = format!("http://{up_addr}/mcp").into();
    client
        .post_message(uri.clone(), ping_message(), None, None, HashMap::new())
        .await
        .expect("post_message");

    // Upstream should have received the downscoped bearer and a Tier B JWT.
    let captured = up_cap.headers.lock().unwrap().clone();
    let bearer = captured
        .get(http::header::AUTHORIZATION)
        .expect("Authorization header on upstream call");
    assert_eq!(
        bearer.to_str().unwrap(),
        "Bearer downscoped-example-messages-xyz",
        "exchanged token must be forwarded verbatim",
    );
    assert!(
        captured.get(IDENTITY_HEADER.as_str()).is_some(),
        "Tier B identity JWT also goes along by default",
    );

    // IdP should see the RFC 8693 form body exactly once.
    assert_eq!(*idp_cap.call_count.lock().unwrap(), 1);
    let body = idp_cap.last_body.lock().unwrap().clone();
    assert!(
        body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"),
        "body: {body}"
    );
    assert!(body.contains("subject_token=user-access-token-12345"));
    assert!(body.contains("audience=https%3A%2F%2Fexample-messages.test%2Fmcp"));
    assert!(body.contains("scope=upstream%3Aexample-messages"));

    // Second call within cache TTL: IdP call_count stays at 1.
    client
        .post_message(uri, ping_message(), None, None, HashMap::new())
        .await
        .expect("post_message 2");
    assert_eq!(
        *idp_cap.call_count.lock().unwrap(),
        1,
        "second call must be served from cache",
    );
}

#[tokio::test]
async fn exchange_skipped_when_raw_token_missing() {
    let (idp_addr, idp_cap) = spawn_idp().await;
    let (up_addr, up_cap) = spawn_upstream().await;

    let exchange_client = Arc::new(TokenExchangeClient::new(
        waygate_core::http_client::client(waygate_core::http_client::Profile::Interactive).unwrap(),
        format!("http://{idp_addr}/token"),
        "c",
        "s",
    ));
    let cache = Arc::new(TokenCache::default());

    let cell = IdentityCell::new();
    let client = IdentityForwardingClient::new(reqwest::Client::new(), test_issuer(), cell.clone())
        .with_exchange(exchange_client, cache);

    cell.set(IdentityContext {
        principal: Principal {
            sub: "alice".into(),
            email: None,
            groups: vec![],
            issuer: "https://auth.test/".into(),
            scopes: vec![],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None, // dev principal, no inbound bearer
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        },
        audience: "example-messages".into(),
        exchange: Some(ExchangeSettings {
            audience: "https://example-messages.test/mcp".into(),
            scope: None,
        }),
        stored_upstream_subject_token: None,
        exchanged_bearer: None,
        tier_c_audience: None,
    });

    let uri: Arc<str> = format!("http://{up_addr}/mcp").into();
    client
        .post_message(uri, ping_message(), None, None, HashMap::new())
        .await
        .expect("post_message");

    assert_eq!(
        *idp_cap.call_count.lock().unwrap(),
        0,
        "no subject token → skip exchange",
    );
    let captured = up_cap.headers.lock().unwrap().clone();
    assert!(
        captured.get(http::header::AUTHORIZATION).is_none(),
        "no Authorization header when exchange skipped",
    );
    assert!(
        captured.get(IDENTITY_HEADER.as_str()).is_some(),
        "Tier B identity JWT still goes on the wire",
    );
}
