//! Exercises the in-process OAuth refresh path against a loopback token
//! endpoint (no real network, no real credentials) — mirrors the
//! `waygate-upstream` HTTP-test pattern (ephemeral `TcpListener` + `axum::serve`).
//!
//! Proves the three contracts a subscription-OAuth credential must hold:
//! 1. an at/near-expiry access token is refreshed against the token endpoint;
//! 2. concurrent callers coalesce onto a *single* refresh (single-flight);
//! 3. a failing refresh is `Failing` first and only `Stale` after the window.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use tokio::net::TcpListener;

use waygate_llm_credentials::{
    CredentialError, Health, LlmCredentialStore, LlmProvider, ProviderOAuthConfig,
};

/// A token endpoint that counts calls and returns a fresh long-lived token.
/// It **requires** an `application/x-www-form-urlencoded` `refresh_token`
/// grant (OAuth 2.0) and rejects anything else (e.g. a JSON body) with 400,
/// so a regression in the client's request wire format fails this test rather
/// than passing silently.
async fn token_handler(
    State(calls): State<Arc<Mutex<u32>>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    *calls.lock().unwrap() += 1;
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/x-www-form-urlencoded")
        || !body.contains("grant_type=refresh_token")
    {
        return Response::builder()
            .status(400)
            .body(Body::from("expected form-encoded refresh_token grant"))
            .unwrap();
    }
    let body = serde_json::json!({
        "access_token": "refreshed-access-1",
        "token_type": "Bearer",
        "expires_in": 3600,
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// A token endpoint that always fails.
async fn failing_handler() -> Response {
    Response::builder()
        .status(500)
        .body(Body::from("boom"))
        .unwrap()
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn spawn_stalled_endpoint() -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let (user_agent_tx, user_agent_rx) = tokio::sync::oneshot::channel();
    let user_agent_tx = Arc::new(Mutex::new(Some(user_agent_tx)));
    let app = Router::new().route(
        "/token",
        post(move |headers: axum::http::HeaderMap| {
            let user_agent_tx = user_agent_tx.clone();
            async move {
                let user_agent = headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                if let Some(tx) = user_agent_tx.lock().unwrap().take() {
                    let _ = tx.send(user_agent);
                }
                std::future::pending::<Response>().await
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, user_agent_rx)
}

const EXPIRED_BLOB: &str = r#"{"tokens":{"access_token":"old-at","refresh_token":"rt-1"},"expires_at":"2000-01-01T00:00:00Z"}"#;

fn store_pointing_at(addr: SocketAddr, blob: &str) -> LlmCredentialStore {
    LlmCredentialStore::from_vars([("LLM_CRED_OPENAI_PRIMARY".to_string(), blob.to_string())])
        .with_oauth_config(
            LlmProvider::OpenAi,
            ProviderOAuthConfig {
                token_url: format!("http://{addr}/token"),
                client_id: "test-client".to_string(),
                client_secret: None,
            },
        )
}

#[tokio::test]
async fn expired_token_is_refreshed_then_cached() {
    let calls = Arc::new(Mutex::new(0u32));
    let app = Router::new()
        .route("/token", post(token_handler))
        .with_state(calls.clone());
    let addr = spawn(app).await;

    let store = store_pointing_at(addr, EXPIRED_BLOB);

    // First call refreshes against the endpoint.
    assert_eq!(
        store.bearer(LlmProvider::OpenAi, "PRIMARY").await.unwrap(),
        "refreshed-access-1"
    );
    assert_eq!(*calls.lock().unwrap(), 1);
    assert_eq!(
        store.health(LlmProvider::OpenAi, "PRIMARY").await,
        Some(Health::Healthy)
    );

    // Second call serves the cached (now-unexpired) token — no new request.
    assert_eq!(
        store.bearer(LlmProvider::OpenAi, "PRIMARY").await.unwrap(),
        "refreshed-access-1"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "no second refresh for a valid token"
    );
}

#[tokio::test]
async fn injected_deadline_bounds_oauth_refresh() {
    let (addr, _user_agent) = spawn_stalled_endpoint().await;
    let http = waygate_core::http_client::client(waygate_core::http_client::Profile::Custom(
        Duration::from_millis(50),
    ))
    .expect("short-timeout refresh client");
    let store = store_pointing_at(addr, EXPIRED_BLOB).with_http_client(http);

    let error = store
        .bearer(LlmProvider::OpenAi, "PRIMARY")
        .await
        .expect_err("stalled refresh must time out");

    assert!(
        matches!(error, CredentialError::RefreshFailed { .. }),
        "expected refresh failure, got {error:?}"
    );
}

#[tokio::test]
async fn concurrent_callers_coalesce_into_one_refresh() {
    let calls = Arc::new(Mutex::new(0u32));
    let app = Router::new()
        .route("/token", post(token_handler))
        .with_state(calls.clone());
    let addr = spawn(app).await;

    let store = Arc::new(store_pointing_at(addr, EXPIRED_BLOB));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            s.bearer(LlmProvider::OpenAi, "PRIMARY").await
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap().unwrap(), "refreshed-access-1");
    }
    // Single-flight: the per-credential lock means exactly one HTTP refresh
    // served all eight concurrent callers.
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn failing_refresh_is_failing_then_stale() {
    let app = Router::new().route("/token", post(failing_handler));
    let addr = spawn(app).await;

    // staleness=0 ⇒ the second consecutive failure (a few ms later, after the
    // failing-since anchor is set) crosses the window and becomes Stale.
    let store = store_pointing_at(addr, EXPIRED_BLOB).with_staleness(Duration::from_secs(0));

    let first = store.bearer(LlmProvider::OpenAi, "PRIMARY").await;
    assert!(
        matches!(first, Err(CredentialError::RefreshFailed { .. })),
        "first failure should be RefreshFailed, got {first:?}"
    );
    assert_eq!(
        store.health(LlmProvider::OpenAi, "PRIMARY").await,
        Some(Health::Failing)
    );

    let second = store.bearer(LlmProvider::OpenAi, "PRIMARY").await;
    assert!(
        matches!(second, Err(CredentialError::Stale { .. })),
        "sustained failure should be Stale, got {second:?}"
    );
    assert_eq!(
        store.health(LlmProvider::OpenAi, "PRIMARY").await,
        Some(Health::Stale)
    );
}

#[tokio::test]
async fn failed_proactive_refresh_serves_still_valid_token() {
    let app = Router::new().route("/token", post(failing_handler));
    let addr = spawn(app).await;
    // Token still valid for ~60s — but inside the default 120s refresh skew,
    // so bearer() attempts a proactive refresh. The refresh fails (500), yet
    // the current token is unexpired, so bearer() must serve it (not fail).
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::seconds(60))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let blob = format!(
        r#"{{"tokens":{{"access_token":"still-good","refresh_token":"rt"}},"expires_at":"{expires}"}}"#
    );
    let store = store_pointing_at(addr, &blob);
    assert_eq!(
        store
            .bearer(LlmProvider::OpenAi, "PRIMARY")
            .await
            .expect("a still-valid token must be served despite a failed proactive refresh"),
        "still-good"
    );
    // Health reflects the failed refresh even though the call succeeded.
    assert_eq!(
        store.health(LlmProvider::OpenAi, "PRIMARY").await,
        Some(Health::Failing)
    );
}
