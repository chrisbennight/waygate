//! Coverage for the `tower-http` `CorsLayer` mounted by
//! [`waygate_as::build_router`] (`crates/waygate-as/src/router.rs`).
//!
//! Every other `waygate-as` integration test drives the OAuth handlers
//! behind a live Postgres (`*_pg.rs`) and skips when no DB URL is set, so a
//! `tower-http` regression in the CORS layer — preflight no longer answered,
//! `access-control-allow-*` headers dropped or narrowed — would never trip
//! CI on a DB-less runner. This file mounts the *real* router and asserts
//! the CORS contract through `tower::ServiceExt::oneshot`, so it runs
//! unconditionally and never touches the network or a database.
//!
//! Why no DB is needed: the `CorsLayer` wraps the whole router, so a
//! preflight `OPTIONS` is answered by the layer *before* any handler runs;
//! and the only non-preflight request here targets
//! `/.well-known/oauth-authorization-server`, whose handler reads
//! `config.public_url` and never queries the store. The pool is therefore
//! built with `connect_lazy` (no socket opened) purely to satisfy the
//! `build_router` signature.
//!
//! The assertions track the router's *configured* policy
//! (`allow_origin(Any) / allow_methods(Any) / allow_headers(Any)`) by
//! checking the wire behaviour that policy produces — a permissive `*`
//! echo for origin/methods/headers. They do not re-declare the policy
//! literal, so if `router.rs` tightened the CORS config the wire headers
//! would change and these tests would fail rather than silently agree.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use sqlx::postgres::PgPool;
use tower::ServiceExt;

use waygate_as::{build_router, AsConfig, UpstreamCrypto};
use waygate_evidence::audit::NullSink;
use waygate_oidc::{IdTokenValidator, IdentityIssuer, JwksProvider};

const ISSUER: &str = "https://mcp.test";
const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
const CROSS_ORIGIN: &str = "https://claude.ai";

/// Minimal AS config. Only `public_url` is read by the request path these
/// tests touch (the metadata handler); the rest satisfy the struct.
fn test_config() -> AsConfig {
    AsConfig {
        public_url: ISSUER.into(),
        audience: "https://mcp.test/mcp".into(),
        upstream_issuer: "https://auth.test".into(),
        upstream_authorize_endpoint: "https://auth.test/authorize".into(),
        upstream_token_endpoint: "https://auth.test/token".into(),
        upstream_client_id: "gateway-client".into(),
        upstream_client_secret: "unused".into(),
        upstream_redirect_uri: "https://mcp.test/oauth/callback".into(),
        upstream_scopes: vec!["openid".into()],
        upstream_crypto: UpstreamCrypto::from_key_bytes([0x42; 32]),
        cimd_allowed_hosts: None,
        cimd_dev_doc_dir: None,
        access_token_ttl: Duration::from_secs(3600),
        refresh_token_ttl: Duration::from_secs(30 * 86_400),
        transaction_ttl: Duration::from_secs(900),
        code_ttl: Duration::from_secs(60),
        allowed_scopes: vec!["mcp:invoke".into()],
        require_explicit_consent: false,
        idjag_ttl: Duration::from_secs(300),
        idjag_require_scim: true,
        idjag_allowed_audiences: vec![],
        idjag_known_resources: vec![],
        idjag_trusted_issuers: vec![],
        idjag_advertise: false,
    }
}

fn test_issuer() -> Arc<IdentityIssuer> {
    let sk = SigningKey::from_bytes(&[23u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            "gw-test-kid",
            ISSUER,
            "gateway-main",
            Duration::from_secs(60),
        )
        .expect("build issuer"),
    )
}

/// Empty-JWKS id-token validator — never invoked on the request paths these
/// tests drive; present only to satisfy the router signature.
fn test_id_validator() -> Arc<IdTokenValidator> {
    let jwks = Arc::new(
        JwksProvider::from_preloaded(ISSUER, r#"{"keys":[]}"#).expect("preload empty jwks"),
    );
    Arc::new(IdTokenValidator::new(
        jwks,
        ISSUER,
        "https://cli.test/c.json",
    ))
}

/// Build the production router with a lazily-connected pool. `connect_lazy`
/// opens no socket: it would only dial Postgres on first query, and no
/// request in this file reaches a store query.
fn router() -> axum::Router<()> {
    let pool = PgPool::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool construction never connects");
    build_router(
        test_config(),
        pool,
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        test_issuer(),
        test_id_validator(),
        Arc::new(NullSink),
        None,
    )
}

/// A real CORS preflight (`OPTIONS` + `Origin` +
/// `Access-Control-Request-Method`) must be answered by the layer with the
/// configured permissive policy. Pins that tower-http still:
///   * answers the preflight (2xx, not 404/405 from "no OPTIONS route"),
///   * echoes `Any` origin as `*`,
///   * advertises `Any` methods and headers as `*`.
/// A tower-http minor that changed how `Any` is rendered on the wire, or
/// that stopped short-circuiting the preflight, would fail here.
#[tokio::test]
async fn preflight_returns_configured_permissive_cors() {
    let resp = router()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(METADATA_PATH)
                .header(header::ORIGIN, CROSS_ORIGIN)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("preflight oneshot");

    // tower-http answers a valid preflight with 200 OK.
    assert!(
        resp.status().is_success(),
        "CORS preflight must be answered by the layer, got {}",
        resp.status()
    );

    let headers = resp.headers();
    assert_eq!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "allow_origin(Any) must surface as `*`",
    );
    assert_eq!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "allow_methods(Any) must surface as `*` on the preflight",
    );
    assert_eq!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "allow_headers(Any) must surface as `*` on the preflight",
    );
}

/// An actual cross-origin request (not a preflight) must still carry the
/// `access-control-allow-origin` header so the browser hands the response
/// body to the calling page. The metadata handler runs for real here — it
/// only reads `config.public_url`, so no DB is touched — and the CORS layer
/// decorates the response on the way out.
#[tokio::test]
async fn actual_cross_origin_request_is_allowed() {
    let resp = router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(METADATA_PATH)
                .header(header::ORIGIN, CROSS_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("cross-origin GET oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "metadata endpoint must serve the cross-origin GET",
    );
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "allow_origin(Any) must echo `*` on the actual response so the \
         browser exposes the body to the cross-origin caller",
    );
}
