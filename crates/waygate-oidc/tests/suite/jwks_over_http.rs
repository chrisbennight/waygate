//! Real-socket coverage for `JwksProvider` — discovery + JWKS fetch through
//! `reqwest`. The other tests in this crate use `JwksProvider::from_preloaded`
//! which never touches the network; this file is the crate's only coverage of
//! the real `#[tokio::test]` → `reqwest::Client::*` path.
//!
//! Each test stands up a tiny axum app on `127.0.0.1:0` so the full
//! `Client::builder() → get → send → Response::json` chain runs unmocked.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};

use waygate_oidc::{JwksError, JwksProvider};

const JWKS_BODY: &str = include_str!("../fixtures/jwks.json");
const KNOWN_KID: &str = "test-key-1";

#[derive(Default, Clone)]
struct Counters {
    discovery: Arc<AtomicU32>,
    jwks: Arc<AtomicU32>,
}

#[derive(Clone)]
struct ServerCfg {
    counters: Counters,
    discovery_status: Arc<AtomicU32>,
    jwks_status: Arc<AtomicU32>,
    jwks_body: Arc<std::sync::RwLock<String>>,
    /// Filled once the listener is bound — discovery returns this as an
    /// absolute `jwks_uri` so the second hop hits the same server.
    base_url: Arc<std::sync::OnceLock<String>>,
    /// Serve a discovery document past the fetch cap, to pin that the
    /// discovery hop is capped independently of the JWKS hop.
    oversize_discovery: Arc<std::sync::atomic::AtomicBool>,
    /// Serve a JWKS past the fetch cap, chunked so no length is advertised.
    oversize_jwks: Arc<std::sync::atomic::AtomicBool>,
    pause_discovery: Arc<std::sync::atomic::AtomicBool>,
    discovery_entered: Arc<Notify>,
    release_discovery: Arc<Semaphore>,
}

impl ServerCfg {
    fn new() -> Self {
        Self {
            counters: Counters::default(),
            discovery_status: Arc::new(AtomicU32::new(200)),
            jwks_status: Arc::new(AtomicU32::new(200)),
            jwks_body: Arc::new(std::sync::RwLock::new(JWKS_BODY.to_owned())),
            oversize_discovery: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            oversize_jwks: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            pause_discovery: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            discovery_entered: Arc::new(Notify::new()),
            release_discovery: Arc::new(Semaphore::new(0)),
            base_url: Arc::new(std::sync::OnceLock::new()),
        }
    }
}

/// A response whose body is streamed in chunks, so axum emits it with
/// `Transfer-Encoding: chunked` and **no** `Content-Length`. Serving an
/// oversized body from a `String` instead would give it an exact size hint,
/// the client's Content-Length pre-check would answer first, and the streaming
/// counter — the guard that makes the pre-check non-bypassable — would go
/// untested while appearing covered.
fn chunked_body_of(len: usize) -> Response {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        std::iter::repeat_with(|| Ok(vec![b'x'; 8192]))
            .take(len.div_ceil(8192))
            .collect();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from_stream(futures::stream::iter(chunks)))
        .unwrap()
}

async fn discovery_handler(State(cfg): State<ServerCfg>) -> Response {
    cfg.counters.discovery.fetch_add(1, Ordering::SeqCst);
    if cfg.pause_discovery.load(Ordering::SeqCst) {
        cfg.discovery_entered.notify_one();
        cfg.release_discovery.acquire().await.unwrap().forget();
    }
    let status = cfg.discovery_status.load(Ordering::SeqCst);
    if status >= 400 {
        return Response::builder()
            .status(status as u16)
            .body(axum::body::Body::from("upstream error"))
            .unwrap();
    }
    if cfg.oversize_discovery.load(Ordering::SeqCst) {
        return chunked_body_of(2 * 1024 * 1024);
    }
    // Return the JWKS URL as absolute so reqwest accepts it — the discovery
    // → jwks hop runs as a separate `Client::get`, not a relative join.
    let base = cfg.base_url.get().expect("base url set after bind");
    let body = json!({"jwks_uri": format!("{base}/jwks")}).to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn jwks_handler(State(cfg): State<ServerCfg>) -> Response {
    cfg.counters.jwks.fetch_add(1, Ordering::SeqCst);
    if cfg.oversize_jwks.load(Ordering::SeqCst) {
        return chunked_body_of(2 * 1024 * 1024);
    }
    let status = cfg.jwks_status.load(Ordering::SeqCst);
    let body = cfg.jwks_body.read().unwrap().clone();
    Response::builder()
        .status(status as u16)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn spawn_idp() -> (String, ServerCfg) {
    let cfg = ServerCfg::new();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery_handler))
        .route("/jwks", get(jwks_handler))
        .with_state(cfg.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    cfg.base_url.set(base.clone()).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, cfg)
}

#[tokio::test]
async fn happy_path_discovers_then_fetches_jwks() {
    let (issuer, cfg) = spawn_idp().await;
    let provider = Arc::new(JwksProvider::new(issuer));

    provider.prime().await;
    let key = provider
        .decoding_key(KNOWN_KID)
        .await
        .expect("kid must resolve");
    drop(key);

    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 1);
    assert_eq!(cfg.counters.jwks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cached_kid_does_not_refetch() {
    let (issuer, cfg) = spawn_idp().await;
    let provider = Arc::new(JwksProvider::new(issuer));

    provider.prime().await;
    for _ in 0..3 {
        provider
            .decoding_key(KNOWN_KID)
            .await
            .expect("kid resolves");
    }

    // A fresh cached key does not require another fetch.
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 1);
    assert_eq!(cfg.counters.jwks.load(Ordering::SeqCst), 1);
}

/// Advance the provider's monotonic clock without leaving real-socket I/O
/// subject to Tokio's automatic time advancement while the runtime is idle.
async fn advance_cache_clock(seconds: u64) {
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(seconds)).await;
    tokio::time::resume();
}

#[tokio::test]
async fn known_key_is_withdrawn_after_cache_expiry_without_an_unknown_kid_request() {
    let (issuer, cfg) = spawn_idp().await;
    let provider = Arc::new(JwksProvider::new(issuer));
    provider.prime().await;
    *cfg.jwks_body.write().unwrap() = json!({"keys": []}).to_string();

    provider.decoding_key(KNOWN_KID).await.unwrap();
    advance_cache_clock(300).await;
    assert!(matches!(
        provider.decoding_key(KNOWN_KID).await,
        Err(JwksError::UnknownKid(_))
    ));
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 2);
    assert_eq!(cfg.counters.jwks.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rollover_discovers_a_new_key_after_the_refresh_interval() {
    let (issuer, cfg) = spawn_idp().await;
    let provider = Arc::new(JwksProvider::new(issuer));
    provider.prime().await;
    let mut next: serde_json::Value = serde_json::from_str(JWKS_BODY).unwrap();
    let mut new_key = next["keys"][0].clone();
    new_key["kid"] = json!("successor");
    next["keys"].as_array_mut().unwrap().push(new_key);
    *cfg.jwks_body.write().unwrap() = next.to_string();

    assert!(matches!(
        provider.decoding_key("successor").await,
        Err(JwksError::UnknownKid(_))
    ));
    advance_cache_clock(30).await;
    provider.decoding_key("successor").await.unwrap();
    provider.decoding_key(KNOWN_KID).await.unwrap();
    assert_eq!(cfg.counters.jwks.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn failed_refresh_does_not_extend_known_keys_and_recovery_needs_no_restart() {
    let (issuer, cfg) = spawn_idp().await;
    let provider = Arc::new(JwksProvider::new(issuer));
    provider.prime().await;
    cfg.discovery_status.store(503, Ordering::SeqCst);
    advance_cache_clock(30).await;
    assert!(matches!(
        provider.decoding_key("unknown").await,
        Err(JwksError::Http(_))
    ));
    provider.decoding_key(KNOWN_KID).await.unwrap();

    advance_cache_clock(270).await;
    assert!(matches!(
        provider.decoding_key(KNOWN_KID).await,
        Err(JwksError::Http(_))
    ));
    for _ in 0..5 {
        assert!(matches!(
            provider.decoding_key(KNOWN_KID).await,
            Err(JwksError::RefreshUnavailable)
        ));
    }
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 3);

    cfg.discovery_status.store(200, Ordering::SeqCst);
    advance_cache_clock(30).await;
    provider.decoding_key(KNOWN_KID).await.unwrap();
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn cold_cache_failures_are_backed_off_and_can_recover() {
    let (issuer, cfg) = spawn_idp().await;
    cfg.discovery_status.store(503, Ordering::SeqCst);
    let provider = Arc::new(JwksProvider::new(issuer));
    assert!(matches!(
        provider.decoding_key(KNOWN_KID).await,
        Err(JwksError::Http(_))
    ));
    for _ in 0..5 {
        assert!(matches!(
            provider.decoding_key(KNOWN_KID).await,
            Err(JwksError::RefreshUnavailable)
        ));
    }
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 1);
    cfg.discovery_status.store(200, Ordering::SeqCst);
    advance_cache_clock(30).await;
    provider.decoding_key(KNOWN_KID).await.unwrap();
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn concurrent_lookups_share_both_successful_and_failed_refreshes() {
    for status in [200, 503] {
        let (issuer, cfg) = spawn_idp().await;
        cfg.discovery_status.store(status, Ordering::SeqCst);
        cfg.pause_discovery.store(true, Ordering::SeqCst);
        let provider = Arc::new(JwksProvider::new(issuer));
        let leader = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.decoding_key(KNOWN_KID).await })
        };
        cfg.discovery_entered.notified().await;

        let followers = futures::future::join_all((0..8).map(|_| provider.decoding_key(KNOWN_KID)));
        futures::pin_mut!(followers);
        assert!(futures::poll!(followers.as_mut()).is_pending());
        assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 1);
        cfg.release_discovery.add_permits(1);
        let (leader, followers) = tokio::join!(leader, followers);
        assert_eq!(leader.unwrap().is_ok(), status == 200);
        for follower in followers {
            if status == 200 {
                assert!(follower.is_ok());
            } else {
                assert!(matches!(follower, Err(JwksError::RefreshUnavailable)));
            }
        }
        assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn cancelled_refresh_retains_backoff_and_releases_waiters() {
    let (issuer, cfg) = spawn_idp().await;
    cfg.pause_discovery.store(true, Ordering::SeqCst);
    let provider = Arc::new(JwksProvider::new(issuer));
    let leader = {
        let provider = provider.clone();
        tokio::spawn(async move { provider.decoding_key(KNOWN_KID).await })
    };
    cfg.discovery_entered.notified().await;
    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());

    for _ in 0..5 {
        assert!(matches!(
            provider.decoding_key(KNOWN_KID).await,
            Err(JwksError::RefreshUnavailable)
        ));
    }
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 1);
    cfg.pause_discovery.store(false, Ordering::SeqCst);
    cfg.release_discovery.add_permits(1);
    advance_cache_clock(30).await;
    provider.decoding_key(KNOWN_KID).await.unwrap();
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn pinned_keys_never_expire_or_fetch_even_when_primed() {
    let (issuer, cfg) = spawn_idp().await;
    let provider = Arc::new(JwksProvider::from_preloaded(issuer, JWKS_BODY).unwrap());
    provider.prime().await;
    advance_cache_clock(24 * 60 * 60).await;
    provider.decoding_key(KNOWN_KID).await.unwrap();
    assert!(matches!(
        provider.decoding_key("unknown").await,
        Err(JwksError::UnknownKid(_))
    ));
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), 0);
    assert_eq!(cfg.counters.jwks.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unknown_kid_is_rate_limited_after_first_refresh() {
    let (issuer, cfg) = spawn_idp().await;
    let provider = Arc::new(JwksProvider::new(issuer));

    provider.prime().await;
    let pre_discovery = cfg.counters.discovery.load(Ordering::SeqCst);
    let pre_jwks = cfg.counters.jwks.load(Ordering::SeqCst);

    for _ in 0..3 {
        let result = provider.decoding_key("definitely-not-in-the-set").await;
        match result {
            Err(JwksError::UnknownKid(ref k)) if k == "definitely-not-in-the-set" => {}
            Err(other) => panic!("expected UnknownKid, got {other:?}"),
            Ok(_) => panic!("unknown kid must not resolve"),
        }
    }

    // The 30-second refresh interval means none of the three
    // lookups trigger a fresh GET — protects against the spin-the-IdP DoS.
    assert_eq!(cfg.counters.discovery.load(Ordering::SeqCst), pre_discovery);
    assert_eq!(cfg.counters.jwks.load(Ordering::SeqCst), pre_jwks);
}

#[tokio::test]
async fn discovery_5xx_surfaces_as_http_error() {
    let (issuer, cfg) = spawn_idp().await;
    cfg.discovery_status.store(503, Ordering::SeqCst);
    let provider = Arc::new(JwksProvider::new(issuer));

    // A non-2xx is now refused by `error_for_status` before the body is read,
    // so this is an Http error because of the STATUS rather than because the
    // body happened not to parse. That is the more robust reason: it holds
    // even for a 5xx that returns well-formed JSON.
    match provider.decoding_key(KNOWN_KID).await {
        Err(JwksError::Http(_)) => {}
        Err(other) => panic!("expected Http, got {other:?}"),
        Ok(_) => panic!("503 must not resolve a key"),
    }
}

#[tokio::test]
async fn malformed_jwks_body_surfaces_as_a_json_error() {
    let (issuer, cfg) = spawn_idp().await;
    *cfg.jwks_body.write().unwrap() = "not-json-at-all".into();
    let provider = Arc::new(JwksProvider::new(issuer));

    // The fetch reads the body under a size cap and decodes it itself rather
    // than going through reqwest's `.json()`, so a malformed 200 body is now
    // reported by the JSON decoder as `Json` instead of arriving as a reqwest
    // decode failure wrapped in `Http`. `Json` is the accurate variant — the
    // transport succeeded — and it is no longer reserved for the
    // `from_preloaded` path. The contract this pins is unchanged: a malformed
    // body surfaces a typed error and never resolves a key.
    match provider.decoding_key(KNOWN_KID).await {
        // The document is named so a malformed discovery response is not
        // reported as a malformed JWKS.
        Err(JwksError::Json { document, .. }) => assert_eq!(document, "JWKS"),
        Err(other) => panic!("expected Json, got {other:?}"),
        Ok(_) => panic!("malformed body must not resolve a key"),
    }
}

#[tokio::test]
async fn from_preloaded_rejects_malformed_json() {
    // Covers the explicit JwksError::Json arm. Lives here so the kid-resolution
    // contract for preloaded providers stays adjacent to the over-HTTP one.
    let err = JwksProvider::from_preloaded("https://example.test", "{not json")
        .err()
        .expect("malformed json must fail");
    assert!(matches!(err, JwksError::Json { .. }), "got {err:?}");
}

#[tokio::test]
async fn discovery_404_surfaces_as_http_error() {
    // Prove the "discovery returns the wrong thing" path hits the wire and
    // surfaces a typed error. The hazard this guards against — a 404 whose body
    // parses as `{}`, deserializing to `OidcDiscovery { jwks_uri: None }` and
    // reporting MissingJwksUri — is now closed by construction, because
    // `error_for_status` rejects the response before its body is read.
    let (issuer, cfg) = spawn_idp().await;
    cfg.discovery_status.store(404, Ordering::SeqCst);
    let provider = Arc::new(JwksProvider::new(issuer));

    match provider.decoding_key(KNOWN_KID).await {
        Err(JwksError::Http(_)) => {}
        Err(other) => panic!("expected Http, got {other:?}"),
        Ok(_) => panic!("404 discovery must not resolve a key"),
    }
}

/// Pins the CALL SITE, not the shared reader: the production `JwksProvider`
/// fetch must actually be wired through the cap. The oversize cases in
/// `waygate-core` exercise `read_body_capped` directly, so on their own they
/// would stay green if this fetch were reverted to an uncapped body read —
/// which is where the vulnerability would live.
///
/// Served over a real socket with no `Content-Length` the provider could
/// short-circuit on, so the streaming counter is what refuses it.
#[tokio::test]
async fn oversized_jwks_body_is_refused_by_the_provider() {
    let (issuer, cfg) = spawn_idp().await;
    // Comfortably past the 1 MiB cap, served chunked so no Content-Length is
    // advertised and the streaming counter is what refuses it. The body is not
    // valid JSON either, so the assertion below distinguishes "refused by size"
    // from "read in full, then refused by the decoder".
    cfg.oversize_jwks.store(true, Ordering::SeqCst);
    let provider = Arc::new(JwksProvider::new(issuer));

    match provider.decoding_key(KNOWN_KID).await {
        Err(JwksError::BodyTooLarge(_)) => {}
        Err(other) => panic!("expected BodyTooLarge, got {other:?}"),
        Ok(_) => panic!("an oversized JWKS must not resolve a key"),
    }
}

/// The discovery hop is a separate fetch and needs its own pin — capping only
/// the JWKS leg would leave the first request unbounded.
#[tokio::test]
async fn oversized_discovery_body_is_refused_by_the_provider() {
    let (issuer, cfg) = spawn_idp().await;
    cfg.oversize_discovery.store(true, Ordering::SeqCst);
    let provider = Arc::new(JwksProvider::new(issuer));

    match provider.decoding_key(KNOWN_KID).await {
        Err(JwksError::BodyTooLarge(_)) => {}
        Err(other) => panic!("expected BodyTooLarge, got {other:?}"),
        Ok(_) => panic!("an oversized discovery document must not resolve a key"),
    }
}
