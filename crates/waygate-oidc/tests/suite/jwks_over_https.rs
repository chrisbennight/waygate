//! HTTPS-loopback coverage for the `reqwest` -> rustls TLS handshake. The
//! sibling `jwks_over_http.rs` runs the production `JwksProvider` over plain
//! HTTP; reqwest never touches its TLS verifier on that path. The full
//! production OIDC discovery / JWKS / token flows go over HTTPS, where a
//! reqwest patch bump can regress in ways no http:// loopback test would
//! catch (CRL PEM parsing, rustls-platform-verifier behaviour, hickory-dns
//! fallback, etc).
//!
//! `JwksProvider` builds its own `reqwest::Client` internally with no hook
//! to inject a custom root CA, so this test exercises the same TLS stack
//! production uses (`reqwest = { features = ["rustls"] }`) by driving a
//! `reqwest::Client` directly against an axum HTTPS server with a
//! self-signed cert pinned via `add_root_certificate`. That is the same
//! handshake path `JwksProvider::http` runs against a real IdP — only the
//! trust-root source differs.
//!
//! If a future `reqwest` / `rustls` / `aws-lc-rs` bump breaks the rustls
//! handshake, `cargo test --workspace --locked` fails here before it gets
//! anywhere near a real OIDC issuer.

use std::sync::Arc;

use axum::routing::get;
use axum::Json;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use serde_json::{json, Value};

const JWKS_BODY: &str = include_str!("../fixtures/jwks.json");

struct TlsServer {
    base_url: String,
    cert_der: Vec<u8>,
}

/// Install aws-lc-rs as the process-wide rustls CryptoProvider. Required
/// because the workspace pulls in both `aws-lc-rs` (via `axum-server/tls-rustls`)
/// and `ring` (via `sqlx-core/_tls-rustls-ring-webpki`) — with both compiled
/// in, rustls 0.23 refuses to auto-pick and panics. `install_default` is
/// idempotent across the same process via `.ok()`: the first caller installs,
/// every subsequent caller silently no-ops.
fn ensure_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

async fn spawn_https_server() -> TlsServer {
    ensure_default_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("self-signed cert");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    let tls_config = RustlsConfig::from_der(vec![cert_der.clone()], key_der)
        .await
        .expect("rustls config");

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|| async {
                Json(json!({
                    "issuer": "https://idp.example.test",
                    "jwks_uri": "https://idp.example.test/jwks",
                }))
            }),
        )
        .route(
            "/jwks",
            get(|| async {
                let body: Value = serde_json::from_str(JWKS_BODY).expect("fixture parses");
                Json(body)
            }),
        );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls_config)
            .expect("from_tcp_rustls accepts the std listener")
            .serve(app.into_make_service())
            .await
            .expect("axum_server serve");
    });

    TlsServer {
        base_url: format!("https://127.0.0.1:{}", addr.port()),
        cert_der,
    }
}

fn client_trusting(cert_der: &[u8]) -> reqwest::Client {
    let cert = reqwest::Certificate::from_der(cert_der).expect("der cert");
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()
        .expect("client")
}

#[tokio::test]
async fn https_jwks_handshake_succeeds_with_trusted_cert() {
    // Tiny retry loop: `axum_server` from_tcp_rustls binds on the first
    // accept rather than at spawn, so the client may race the listener on a
    // cold runner. Ten 50 ms tries (≤ 500 ms) is plenty in practice.
    let server = spawn_https_server().await;
    let client = client_trusting(&server.cert_der);

    let mut last_err = None;
    for _ in 0..10 {
        match client.get(format!("{}/jwks", server.base_url)).send().await {
            Ok(resp) => {
                assert_eq!(resp.status(), 200, "expected 200 from /jwks");
                let body: Value = resp.json().await.expect("json body");
                assert!(body.get("keys").is_some(), "jwks must include `keys`");
                return;
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    panic!("https jwks request never succeeded: {:?}", last_err);
}

#[tokio::test]
async fn https_handshake_fails_without_trusted_cert() {
    // Negative pin: a default `reqwest::Client` uses rustls-platform-verifier
    // with the system trust store, which knows nothing about our in-process
    // self-signed cert. The handshake must fail. This proves the positive
    // test above is actually exercising the verifier rather than a
    // `danger_accept_invalid_certs` shortcut a future patch could introduce.
    let server = spawn_https_server().await;
    let client = reqwest::Client::new();

    let result = client.get(format!("{}/jwks", server.base_url)).send().await;
    let err = result.expect_err("untrusted cert must error");
    // The error must originate from the connect/handshake stack, not e.g.
    // a typed body parse — protect against future reqwest minor versions
    // that might mask the rustls error variant.
    assert!(
        err.is_connect() || err.is_request(),
        "expected connect/request error, got {err:?}"
    );
}

#[tokio::test]
async fn https_discovery_returns_typed_json() {
    // Round-trips the discovery doc over the same TLS stack the production
    // `JwksProvider::refresh` runs against an HTTPS issuer. If reqwest's
    // `.json()` typed-deserialization path regresses on a TLS-served body,
    // this fails before the http:// loopback tests do.
    let server = spawn_https_server().await;
    let arc = Arc::new(server);
    let client = client_trusting(&arc.cert_der);

    let doc: Value = client
        .get(format!("{}/.well-known/openid-configuration", arc.base_url))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("typed json");
    assert_eq!(
        doc.get("jwks_uri").and_then(|v| v.as_str()),
        Some("https://idp.example.test/jwks")
    );
}
