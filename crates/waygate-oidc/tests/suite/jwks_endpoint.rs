//! HTTP-level smoke test for the `/.well-known/jwks.json` route. We spin the
//! router up with `tower::ServiceExt::oneshot` rather than binding a socket —
//! no actual TCP, but the axum layers run end-to-end.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm};
use tower::ServiceExt;

use waygate_oidc::{jwks_router, IdentityIssuer, IdentityKeyring, JWKS_PATH};

fn issuer() -> IdentityIssuer {
    let sk = SigningKey::from_bytes(&[13u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    IdentityIssuer::from_ed25519_pkcs8_pem(
        &pem,
        "gw-test",
        "https://mcp.example.test",
        "gateway-main",
        Duration::from_secs(60),
    )
    .expect("issuer")
}

#[tokio::test]
async fn jwks_endpoint_returns_public_key() {
    let router = jwks_router::<()>(Arc::new(IdentityKeyring::single(Arc::new(issuer()))));
    let request = Request::builder()
        .uri(JWKS_PATH)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.expect("routed");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let jwks: JwkSet = serde_json::from_slice(&body).expect("parse jwks");
    assert_eq!(jwks.keys.len(), 1);
    let jwk = &jwks.keys[0];
    assert_eq!(jwk.common.key_id.as_deref(), Some("gw-test"));
    assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::EdDSA));
    match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(okp) => {
            assert_eq!(okp.curve, EllipticCurve::Ed25519);
        }
        _ => panic!("unexpected algorithm params"),
    }
}

#[tokio::test]
async fn jwks_endpoint_404s_unknown_paths() {
    let router = jwks_router::<()>(Arc::new(IdentityKeyring::single(Arc::new(issuer()))));
    let request = Request::builder()
        .uri("/.well-known/openid-configuration")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
