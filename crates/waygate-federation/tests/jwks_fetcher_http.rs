//! End-to-end coverage for `PeerJwksFetcher` over a real
//! `reqwest::Client` against a
//! loopback axum server. Mirrors the pattern in
//! `crates/waygate-oidc/tests/suite/jwks_over_http.rs` so the
//! per-request shape (timeout, body cap, scheme check) runs
//! unmocked. Predicates pinned here:
//!
//! 1. Happy path — well-formed JWKS body → parsed `JwkSet`.
//! 2. HTTP 5xx surfaces as `Http(_)`.
//! 3. Malformed JSON surfaces as `Parse(_)`.
//! 4. Oversized body (advertised + actual) → `BodyTooLarge`.
//! 5. `http://` to loopback is accepted (local-dev seed
//!    path is the documented exception).
//! 6. `http://` to a non-loopback host is rejected before
//!    the socket connects — pins the safety envelope so a
//!    future refactor can't accidentally loosen it.
//!
//! The fetcher's per-cycle behaviour is covered separately
//! in `jwks_refresher.rs`; this file is the per-call
//! contract.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

use waygate_federation::jwks::{JwksFetchError, PeerJwksFetcher};

const VALID_JWKS: &str = r#"{
  "keys": [
    {
      "kty": "RSA",
      "kid": "peer-key-1",
      "alg": "RS256",
      "use": "sig",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}"#;

#[derive(Default, Clone)]
struct ServerState {
    hits: Arc<AtomicU32>,
    status: Arc<AtomicU32>,
    body: Arc<std::sync::RwLock<String>>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            hits: Arc::new(AtomicU32::new(0)),
            status: Arc::new(AtomicU32::new(200)),
            body: Arc::new(std::sync::RwLock::new(VALID_JWKS.into())),
        }
    }
}

async fn jwks_handler(State(state): State<ServerState>) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    let status = state.status.load(Ordering::SeqCst);
    let body = state.body.read().unwrap().clone();
    Response::builder()
        .status(status as u16)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn spawn_jwks_server() -> (String, ServerState) {
    let state = ServerState::new();
    let app = Router::new()
        .route("/jwks", get(jwks_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, state)
}

#[tokio::test]
async fn happy_path_parses_jwks() {
    let (base, state) = spawn_jwks_server().await;
    let fetcher = PeerJwksFetcher::new();
    let set = fetcher
        .fetch(&format!("{base}/jwks"))
        .await
        .expect("happy fetch");
    assert_eq!(set.keys.len(), 1);
    assert_eq!(set.keys[0].common.key_id.as_deref(), Some("peer-key-1"));
    assert_eq!(state.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn http_5xx_surfaces_as_http_error() {
    let (base, state) = spawn_jwks_server().await;
    state.status.store(503, Ordering::SeqCst);
    let fetcher = PeerJwksFetcher::new();
    let err = fetcher
        .fetch(&format!("{base}/jwks"))
        .await
        .expect_err("5xx must error");
    assert!(
        matches!(err, JwksFetchError::Http(_)),
        "expected Http variant, got {err:?}",
    );
}

#[tokio::test]
async fn malformed_body_surfaces_as_parse_error() {
    let (base, state) = spawn_jwks_server().await;
    *state.body.write().unwrap() = "definitely not json".into();
    let fetcher = PeerJwksFetcher::new();
    let err = fetcher
        .fetch(&format!("{base}/jwks"))
        .await
        .expect_err("malformed json must error");
    assert!(
        matches!(err, JwksFetchError::Parse(_)),
        "expected Parse variant, got {err:?}",
    );
}

#[tokio::test]
async fn oversized_body_exceeds_cap() {
    // Server returns a body that genuinely exceeds the
    // 1 MiB cap. Axum/hyper will set Content-Length
    // honestly, so the fetcher's pre-stream check (when
    // Content-Length is present) is exercised here.
    let (base, state) = spawn_jwks_server().await;
    // ~2.2 MiB JSON-shaped blob, well above the 1 MiB cap.
    let large = format!("[{}]", "1,".repeat(1_100_000));
    *state.body.write().unwrap() = large;
    let fetcher = PeerJwksFetcher::with_limits(Duration::from_secs(5), 1024 * 1024);
    let err = fetcher
        .fetch(&format!("{base}/jwks"))
        .await
        .expect_err("oversized must error");
    assert!(
        matches!(err, JwksFetchError::BodyTooLarge { .. }),
        "expected BodyTooLarge, got {err:?}",
    );
}

#[tokio::test]
async fn http_loopback_is_accepted() {
    // Reachable loopback: full request cycle succeeds via
    // the local-dev exception path.
    let (base, _state) = spawn_jwks_server().await;
    let fetcher = PeerJwksFetcher::new();
    fetcher
        .fetch(&format!("{base}/jwks"))
        .await
        .expect("loopback http should fetch");
}

#[tokio::test]
async fn http_non_loopback_is_rejected_pre_connect() {
    // Marker URL that, if the scheme guard regressed, would
    // attempt a DNS lookup against a public name. Test would
    // hang OR succeed-then-fail with HttpError instead of
    // the expected SchemeRejected — both would fail this
    // assertion. We don't *want* the network hop, so use a
    // host that is plainly non-loopback even by name.
    let fetcher = PeerJwksFetcher::with_limits(Duration::from_secs(1), 1024 * 1024);
    let err = fetcher
        .fetch("http://gw.acme.example/jwks")
        .await
        .expect_err("non-loopback http must be rejected");
    assert!(
        matches!(err, JwksFetchError::SchemeRejected { .. }),
        "expected SchemeRejected before network hop, got {err:?}",
    );
}

/// With no Content-Length header (chunked encoding,
/// hyper-default behaviour for streaming responses), the
/// streaming-body loop must abort the moment the cumulative
/// byte count passes `max_bytes`. Calling `resp.bytes().await`
/// would buffer the full response into memory first, defeating
/// the cap.
///
/// To exercise this path the test server emits the large
/// body via a stream-of-chunks `Body::from_stream(...)` so
/// hyper does NOT compute a Content-Length up front. The
/// fetcher must still cap at ~max_bytes instead of
/// allocating the full advertised body.
#[tokio::test]
async fn streaming_body_without_content_length_aborts_at_cap() {
    use axum::body::Body;
    use axum::Router;
    use futures::stream;
    use tokio::net::TcpListener;
    use tokio_util::bytes::Bytes;

    async fn streaming_handler() -> Response {
        // 64 KiB chunks * 40 = 2.5 MiB total, well past the
        // 1 MiB cap we'll set on the fetcher.
        let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
        let s = stream::iter(
            std::iter::repeat_with(move || Ok::<_, std::io::Error>(chunk.clone())).take(40),
        );
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("transfer-encoding", "chunked")
            .body(Body::from_stream(s))
            .unwrap()
    }

    let app = Router::new().route("/jwks", get(streaming_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let fetcher = PeerJwksFetcher::with_limits(Duration::from_secs(5), 1024 * 1024);
    let err = fetcher
        .fetch(&format!("{base}/jwks"))
        .await
        .expect_err("streamed-oversized must error");
    assert!(
        matches!(err, JwksFetchError::BodyTooLarge { .. }),
        "expected BodyTooLarge for streamed body, got {err:?}",
    );
}

// Ensure OnceLock + the rest of std::sync compile cleanly
// in this test crate so a future refactor of the helpers
// above doesn't unintentionally lose them.
#[allow(dead_code)]
static _ONCE_LOCK_SANITY: OnceLock<()> = OnceLock::new();
