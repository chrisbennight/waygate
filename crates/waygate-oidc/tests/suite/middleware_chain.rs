//! End-to-end test for `bearer_middleware`'s validator-chain semantics.
//!
//! Reproduces the production failure where a preloaded validator first in the
//! chain (the gateway's own AS-minted JWKS) saw a JWT it didn't know the kid
//! for, tried to lazy-refresh against a discovery URL that didn't exist, and
//! short-circuited the entire request with 503 — even though a later
//! Authentik-backed validator in the same chain would have accepted the
//! token. Two interlocking fixes made this case healthy:
//!
//! 1. `JwksProvider::from_preloaded` pins its key set, so a cache miss returns
//!    `UnknownKid` synchronously instead of attempting a network fetch.
//! 2. `bearer_middleware` no longer short-circuits on the first infra error;
//!    it tries every validator and surfaces 503 only if every validator
//!    failed AND at least one infra-errored. `UnknownKid` is now classified
//!    as a client error so the chain falls through to the next validator
//!    cleanly.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use tower::ServiceExt;

use waygate_oidc::middleware::bearer_middleware;
use waygate_oidc::{BearerLayer, BearerValidator, JwksProvider};

const ISSUER_A: &str = "https://test-as.local";
const ISSUER_B: &str = "https://test-idp.local";
const AUDIENCE: &str = "https://mcp.example.com";

// Validator A holds an intentionally empty preloaded JWKS — no KID lookups
// will match — so it always falls through with `UnknownKid`. Validator B's
// JWKS is the test fixture under `tests/fixtures/jwks.json`, whose only key
// has kid `test-key-1`.
const KID_B: &str = "test-key-1";

const PRIVATE_PEM: &[u8] = include_bytes!("../fixtures/private.pem");
const JWKS_JSON: &str = include_str!("../fixtures/jwks.json");

#[derive(Debug, Serialize)]
struct Claims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_with(kid: &str, claims: &Claims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    let key = EncodingKey::from_rsa_pem(PRIVATE_PEM).expect("rsa private");
    encode(&header, claims, &key).expect("encode")
}

/// Builds the chain: validator A with an empty preloaded JWKS (every kid
/// lookup misses), then validator B with the test fixture JWKS containing
/// `KID_B`. This mirrors how the gateway-AS validator in production has only
/// the gateway-minted ed25519 keys and rejects every Authentik-issued RSA
/// token by `UnknownKid`, before the chain falls through to the
/// Authentik-backed validator that owns the actual signing key.
fn chain() -> BearerLayer {
    let empty_jwks = r#"{"keys":[]}"#;
    let v_a = Arc::new(BearerValidator::new(
        Arc::new(JwksProvider::from_preloaded(ISSUER_A, empty_jwks).unwrap()),
        ISSUER_A,
        AUDIENCE,
    ));
    let v_b = Arc::new(BearerValidator::new(
        Arc::new(JwksProvider::from_preloaded(ISSUER_B, JWKS_JSON).unwrap()),
        ISSUER_B,
        AUDIENCE,
    ));
    BearerLayer::enforce_multi(
        vec![v_a, v_b],
        "https://mcp.example.com/.well-known/jwks.json",
    )
}

fn router(layer: BearerLayer) -> Router {
    Router::new()
        .route("/test", get(|| async { "ok".into_response() }))
        .layer(from_fn_with_state(layer, bearer_middleware))
}

#[tokio::test]
async fn chain_falls_through_to_second_validator_when_first_does_not_know_kid() {
    // Pre-fix: validator A (preloaded, no kids) tipped past
    // min_refresh_interval=30s and tried to fetch
    // <ISSUER_A>/.well-known/openid-configuration. With test-as.local
    // unresolvable, refresh would either hang or error infra → 503.
    // With the fix, UnknownKid is synchronous and is_client_error()=true,
    // so the chain proceeds to validator B which has KID_B and accepts.
    let claims = Claims {
        sub: "alice",
        iss: ISSUER_B,
        aud: AUDIENCE,
        exp: now() + 300,
    };
    let token = sign_with(KID_B, &claims);

    let resp = router(chain())
        .oneshot(
            Request::builder()
                .uri("/test")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "chain must accept via v_b");
}

#[tokio::test]
async fn chain_returns_401_when_no_validator_accepts_and_none_infra_errored() {
    // Token signed by KID_B but with the wrong audience — both validators
    // reject it (validator A: UnknownKid; validator B: Jwt(InvalidAudience)).
    // Since every error is a client error, this is a legitimate 401 — not
    // 503.
    let claims = Claims {
        sub: "alice",
        iss: ISSUER_B,
        aud: "https://someone-else.example",
        exp: now() + 300,
    };
    let token = sign_with(KID_B, &claims);

    let resp = router(chain())
        .oneshot(
            Request::builder()
                .uri("/test")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().contains("Bearer"))
            .unwrap_or(false),
        "401 must carry WWW-Authenticate: Bearer with resource_metadata"
    );
}

#[tokio::test]
async fn missing_authorization_returns_401_with_scope_hint_when_configured() {
    // MCP 2025-11-25 SHOULDs `scope=` on the 401 WWW-Authenticate so a
    // fresh client knows what to ask for on the first authorize hop.
    // The hint is the operator-configured baseline; here we pin it to
    // the gateway's documented default.
    let layer = chain().with_scope_hint("mcp:invoke mcp:read");

    let resp = router(layer)
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .expect("401 must carry WWW-Authenticate");
    assert!(
        www.contains("Bearer "),
        "must use the Bearer scheme; got: {www}"
    );
    assert!(
        www.contains(r#"resource_metadata="https://mcp.example.com/.well-known/jwks.json""#),
        "must carry resource_metadata; got: {www}"
    );
    assert!(
        www.contains(r#"error="invalid_token""#),
        "must carry error=invalid_token for missing/invalid tokens; got: {www}"
    );
    assert!(
        www.contains(r#"scope="mcp:invoke mcp:read""#),
        "must carry scope hint when configured (MCP 2025-11-25 SHOULD); got: {www}"
    );
}

#[tokio::test]
async fn missing_authorization_returns_401_without_scope_hint_when_unconfigured() {
    // Backward-compat: the default layer (no scope hint configured) must
    // not emit a `scope=` parameter. Some clients may key off its
    // absence vs. presence to detect spec-version awareness.
    let resp = router(chain())
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .expect("401 must carry WWW-Authenticate");
    assert!(
        !www.contains("scope="),
        "must omit scope= when no hint configured; got: {www}"
    );
}
