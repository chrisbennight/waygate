//! Real-socket coverage for `pkce::OidcEndpoints::discover` and
//! `pkce::exchange_code`. Both paths use an injected bounded client, issue a
//! request, and parse the response body. This file is the only
//! integration coverage that walks `#[tokio::test]` → `reqwest::*` for these
//! specific functions, so the real HTTP client path stays exercised.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::State;
use axum::response::{Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use tokio::net::TcpListener;

use waygate_oidc::pkce::{
    self, exchange_code, refresh_access_token, ExchangeParams, OidcEndpoints, RefreshParams,
};

fn discovery_http() -> reqwest::Client {
    waygate_core::http_client::client(waygate_core::http_client::Profile::Standard)
        .expect("discovery client")
}

fn token_http() -> reqwest::Client {
    waygate_core::http_client::builder(waygate_core::http_client::Profile::Standard)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("token client")
}

#[derive(Default, Clone)]
struct ServerState {
    last_token_body: Arc<Mutex<Option<String>>>,
    discovery_status: Arc<std::sync::atomic::AtomicU16>,
    discovery_body: Arc<std::sync::RwLock<String>>,
    token_status: Arc<std::sync::atomic::AtomicU16>,
    token_body: Arc<std::sync::RwLock<String>>,
    base_url: Arc<OnceLock<String>>,
}

impl ServerState {
    fn new() -> Self {
        let me = Self::default();
        me.discovery_status
            .store(200, std::sync::atomic::Ordering::SeqCst);
        me.token_status
            .store(200, std::sync::atomic::Ordering::SeqCst);
        // Filled per-test before the discovery handler runs.
        *me.discovery_body.write().unwrap() = String::new();
        *me.token_body.write().unwrap() = json!({
            "access_token": "at-xyz",
            "token_type": "Bearer",
            "expires_in": 300,
        })
        .to_string();
        me
    }
}

async fn discovery_handler(State(state): State<ServerState>) -> Response {
    let status = state
        .discovery_status
        .load(std::sync::atomic::Ordering::SeqCst);
    let body = state.discovery_body.read().unwrap().clone();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn token_handler(State(state): State<ServerState>, body: String) -> Response {
    *state.last_token_body.lock().unwrap() = Some(body);
    let status = state.token_status.load(std::sync::atomic::Ordering::SeqCst);
    let body = state.token_body.read().unwrap().clone();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn token_redirect() -> Redirect {
    Redirect::temporary("/token")
}

async fn spawn_idp() -> (String, ServerState) {
    let state = ServerState::new();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery_handler))
        .route("/token", post(token_handler))
        .route("/redirect", post(token_redirect))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    state.base_url.set(base.clone()).unwrap();
    // Default discovery body: absolute endpoints rooted at this listener.
    *state.discovery_body.write().unwrap() = json!({
        "authorization_endpoint": format!("{base}/auth"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "issuer": base.clone(),
    })
    .to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, state)
}

#[tokio::test]
async fn discover_happy_path() {
    let (base, _state) = spawn_idp().await;
    let http = discovery_http();
    let endpoints = OidcEndpoints::discover(&http, &base)
        .await
        .expect("discover");
    assert_eq!(endpoints.token_endpoint, format!("{base}/token"));
    assert_eq!(endpoints.authorization_endpoint, format!("{base}/auth"));
    assert_eq!(endpoints.jwks_uri, format!("{base}/jwks"));
    assert_eq!(endpoints.issuer, base);
}

#[tokio::test]
async fn discover_strips_trailing_slash() {
    // The contract from `discover`'s doc-comment: "https://auth/" and
    // "https://auth" both work. Pin it so a reqwest URL-builder change can't
    // silently double-slash the discovery path.
    let (base, _state) = spawn_idp().await;
    let with_slash = format!("{base}/");
    let http = discovery_http();
    let endpoints = OidcEndpoints::discover(&http, &with_slash)
        .await
        .expect("discover");
    assert_eq!(endpoints.token_endpoint, format!("{base}/token"));
}

#[tokio::test]
async fn discover_404_surfaces_status() {
    let (base, state) = spawn_idp().await;
    state
        .discovery_status
        .store(404, std::sync::atomic::Ordering::SeqCst);
    let http = discovery_http();

    match OidcEndpoints::discover(&http, &base).await {
        Err(pkce::DiscoveryError::Status(s)) => assert_eq!(s.as_u16(), 404),
        other => panic!("expected Status(404), got {other:?}"),
    }
}

#[tokio::test]
async fn discover_malformed_body_surfaces_json_error() {
    let (base, state) = spawn_idp().await;
    *state.discovery_body.write().unwrap() = "{not-json".into();
    let http = discovery_http();

    match OidcEndpoints::discover(&http, &base).await {
        Err(pkce::DiscoveryError::Json(_)) => {}
        // `discover` reads bytes and decodes via `serde_json::from_slice`, so
        // a body that doesn't parse hits the explicit Json arm. If a reqwest
        // change ever moves this through the `.json()` helper, the variant
        // would flip to Http — that's the regression this assertion catches.
        other => panic!("expected Json, got {other:?}"),
    }
}

#[tokio::test]
async fn exchange_code_round_trips_form_body() {
    let (base, state) = spawn_idp().await;
    let token_endpoint = format!("{base}/token");
    let http = token_http();
    let resp = exchange_code(
        &http,
        ExchangeParams {
            token_endpoint: &token_endpoint,
            client_id: "dashboard",
            client_secret: "shh",
            redirect_uri: "https://gw.test/callback",
            code: "auth-code-1",
            pkce_verifier: "verifier-abc",
        },
    )
    .await
    .expect("exchange");

    assert_eq!(resp.access_token, "at-xyz");

    let captured = state
        .last_token_body
        .lock()
        .unwrap()
        .clone()
        .expect("token POST captured");
    // Every required pair must round-trip through reqwest unchanged. A body
    // that drops or reorders pairs would cause one of these substring asserts
    // to fail and surface immediately.
    for needle in [
        "grant_type=authorization_code",
        "code=auth-code-1",
        "client_id=dashboard",
        "client_secret=shh",
        "code_verifier=verifier-abc",
    ] {
        assert!(
            captured.contains(needle),
            "missing `{needle}` in body `{captured}`",
        );
    }
    // `redirect_uri` is %-encoded by `urlencode` before being sent.
    assert!(
        captured.contains("redirect_uri=https%3A%2F%2Fgw.test%2Fcallback"),
        "redirect_uri was not percent-encoded: `{captured}`",
    );
}

#[tokio::test]
async fn exchange_code_400_preserves_body() {
    let (base, state) = spawn_idp().await;
    state
        .token_status
        .store(400, std::sync::atomic::Ordering::SeqCst);
    *state.token_body.write().unwrap() =
        r#"{"error":"invalid_grant","error_description":"code expired"}"#.into();
    let token_endpoint = format!("{base}/token");
    let http = token_http();

    match exchange_code(
        &http,
        ExchangeParams {
            token_endpoint: &token_endpoint,
            client_id: "dashboard",
            client_secret: "shh",
            redirect_uri: "https://gw.test/callback",
            code: "stale-code",
            pkce_verifier: "verifier-abc",
        },
    )
    .await
    {
        Err(pkce::TokenError::Status { status, body }) => {
            assert_eq!(status.as_u16(), 400);
            // Body is preserved verbatim — the dashboard surfaces the IdP's
            // error_description back to the operator. A reqwest minor that
            // changes how `Response::bytes()` collects a small body would
            // either truncate or re-encode this string.
            assert!(body.contains("invalid_grant"), "body was: {body}");
            assert!(body.contains("code expired"), "body was: {body}");
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_400_preserves_body() {
    let (base, state) = spawn_idp().await;
    state
        .token_status
        .store(401, std::sync::atomic::Ordering::SeqCst);
    *state.token_body.write().unwrap() =
        r#"{"error":"invalid_grant","error_description":"refresh token revoked"}"#.into();
    let token_endpoint = format!("{base}/token");
    let http = token_http();

    match refresh_access_token(
        &http,
        RefreshParams {
            token_endpoint: &token_endpoint,
            client_id: "gateway",
            client_secret: "shh",
            refresh_token: "revoked-refresh-token",
        },
    )
    .await
    {
        Err(pkce::TokenError::Status { status, body }) => {
            assert_eq!(status.as_u16(), 401);
            assert!(body.contains("invalid_grant"), "body was: {body}");
            assert!(body.contains("refresh token revoked"), "body was: {body}");
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn code_exchange_honors_injected_no_redirect_policy() {
    let (base, state) = spawn_idp().await;
    let token_endpoint = format!("{base}/redirect");
    let http = token_http();

    match exchange_code(
        &http,
        ExchangeParams {
            token_endpoint: &token_endpoint,
            client_id: "dashboard",
            client_secret: "shh",
            redirect_uri: "https://gw.test/callback",
            code: "auth-code-1",
            pkce_verifier: "verifier-abc",
        },
    )
    .await
    {
        Err(pkce::TokenError::Status { status, .. }) => assert_eq!(status.as_u16(), 307),
        other => panic!("expected redirect status, got {other:?}"),
    }
    assert!(state.last_token_body.lock().unwrap().is_none());
}

async fn spawn_stalled_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn injected_deadline_bounds_discovery() {
    let base = spawn_stalled_endpoint().await;
    let http = waygate_core::http_client::client(waygate_core::http_client::Profile::Custom(
        Duration::from_millis(50),
    ))
    .expect("short-timeout client");

    match OidcEndpoints::discover(&http, &base).await {
        Err(pkce::DiscoveryError::Http(error)) => assert!(error.is_timeout(), "{error}"),
        other => panic!("expected discovery timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn injected_deadline_bounds_code_exchange() {
    let base = spawn_stalled_endpoint().await;
    let token_endpoint = format!("{base}/token");
    let http = waygate_core::http_client::builder(waygate_core::http_client::Profile::Custom(
        Duration::from_millis(50),
    ))
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .expect("short-timeout client");

    match exchange_code(
        &http,
        ExchangeParams {
            token_endpoint: &token_endpoint,
            client_id: "dashboard",
            client_secret: "shh",
            redirect_uri: "https://gw.test/callback",
            code: "auth-code-1",
            pkce_verifier: "verifier-abc",
        },
    )
    .await
    {
        Err(pkce::TokenError::Http(error)) => assert!(error.is_timeout(), "{error}"),
        other => panic!("expected code-exchange timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn injected_deadline_bounds_refresh_exchange() {
    let base = spawn_stalled_endpoint().await;
    let token_endpoint = format!("{base}/token");
    let http = waygate_core::http_client::builder(waygate_core::http_client::Profile::Custom(
        Duration::from_millis(50),
    ))
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .expect("short-timeout client");

    match refresh_access_token(
        &http,
        RefreshParams {
            token_endpoint: &token_endpoint,
            client_id: "gateway",
            client_secret: "shh",
            refresh_token: "refresh-token",
        },
    )
    .await
    {
        Err(pkce::TokenError::Http(error)) => assert!(error.is_timeout(), "{error}"),
        other => panic!("expected refresh timeout, got {other:?}"),
    }
}
