//! RFC 8693 OAuth 2.0 Token Exchange client.
//!
//! Upgrades the gateway from Tier B (gateway-minted identity JWTs signed by
//! the gateway's own key) to Tier A (real downscoped access tokens issued by
//! the shared IdP) for upstreams whose identity provider supports it.
//!
//! The gateway POSTs the caller's incoming access token as `subject_token`
//! along with the upstream's canonical URI as `audience`; the IdP returns a
//! downscoped token the gateway forwards as `Authorization: Bearer …` on the
//! upstream call.
//!
//! Tokens are cached per (subject, audience, scope). Cache keys include the
//! subject token's hash — rotating the incoming token invalidates the entry.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;

/// RFC 8693 §2.1 — the grant_type value for token exchange requests.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 §3 — token type URIs. Only `access_token` is used in both
/// directions; the IdP picks the concrete format.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("token endpoint returned {status}: {body}")]
    Status {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("parse token response: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("token endpoint returned issued_token_type={0}; only access_token is supported")]
    UnsupportedTokenType(String),
}

/// One exchange request. Borrowed fields so callers don't have to copy the
/// subject token every time.
pub struct ExchangeRequest<'a> {
    pub subject_token: &'a str,
    pub audience: &'a str,
    pub scope: Option<&'a str>,
}

/// Response returned by the IdP.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExchangedToken {
    pub access_token: String,
    /// RFC 8693 §2.2.1 — the IdP must tell us what kind of token it issued.
    #[serde(default)]
    pub issued_token_type: Option<String>,
    /// Seconds until the token expires; used to drive cache TTL.
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// HTTP client for RFC 8693 token exchange against a single IdP. Cheap to
/// clone (Arc-shared internals).
pub struct TokenExchangeClient {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TokenExchangeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeClient")
            .field("token_endpoint", &self.inner.token_endpoint)
            .field("client_id", &self.inner.client_id)
            .finish_non_exhaustive()
    }
}

struct Inner {
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

impl TokenExchangeClient {
    /// Construct a token-exchange client with the composition root's bounded
    /// HTTP client. The caller owns timeout, redirect, proxy, and TLS policy;
    /// there is deliberately no convenience constructor that can create an
    /// unconfigured client.
    pub fn new(
        http: reqwest::Client,
        token_endpoint: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                token_endpoint: token_endpoint.into(),
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                http,
            }),
        }
    }

    pub async fn exchange(
        &self,
        req: ExchangeRequest<'_>,
    ) -> Result<ExchangedToken, ExchangeError> {
        let body = build_form_body(&self.inner.client_id, &self.inner.client_secret, &req);
        let resp = self
            .inner
            .http
            .post(&self.inner.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            return Err(ExchangeError::Status {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        let parsed: ExchangedToken = serde_json::from_slice(&body)?;
        if let Some(kind) = parsed.issued_token_type.as_deref() {
            if kind != ACCESS_TOKEN_TYPE {
                return Err(ExchangeError::UnsupportedTokenType(kind.to_owned()));
            }
        }
        Ok(parsed)
    }
}

fn build_form_body(client_id: &str, client_secret: &str, req: &ExchangeRequest<'_>) -> String {
    // client_secret_post auth — simplest interop; Authentik, Keycloak, Okta
    // all accept it. A follow-up can add client_secret_basic if any IdP needs
    // the Authorization header form.
    let mut pairs = vec![
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", req.subject_token),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", ACCESS_TOKEN_TYPE),
        ("audience", req.audience),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    if let Some(s) = req.scope {
        pairs.push(("scope", s));
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// In-memory cache keyed by (subject-hash, audience, scope). The subject token
/// hash is included so a token rotation on the caller side does not return
/// stale entries — two distinct inbound tokens for the same user produce two
/// cache slots.
///
/// The stored token is cleared a safety margin *before* its real expiry
/// ([`SAFETY_MARGIN`]) so that in-flight requests don't see a just-expired
/// token slip past.
pub struct TokenCache {
    entries: RwLock<HashMap<CacheKey, Entry>>,
    safety_margin: Duration,
}

const SAFETY_MARGIN: Duration = Duration::from_secs(30);
/// Fallback TTL used when the IdP omits `expires_in` — avoids never-expiring
/// cache entries.
const DEFAULT_TTL: Duration = Duration::from_secs(300);

#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    subject_hash: [u8; 32],
    audience: String,
    scope: Option<String>,
}

struct Entry {
    token: ExchangedToken,
    expires_at: Instant,
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new(SAFETY_MARGIN)
    }
}

impl TokenCache {
    pub fn new(safety_margin: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            safety_margin,
        }
    }

    /// Fetch a cached token or run a fresh exchange. The closure-based API
    /// keeps the cache agnostic of the client type (useful for tests).
    pub async fn get_or_exchange<F, Fut>(
        &self,
        subject_token: &str,
        audience: &str,
        scope: Option<&str>,
        fetch: F,
    ) -> Result<ExchangedToken, ExchangeError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<ExchangedToken, ExchangeError>>,
    {
        let key = CacheKey {
            subject_hash: hash_token(subject_token),
            audience: audience.to_owned(),
            scope: scope.map(str::to_owned),
        };
        {
            let read = self.entries.read().await;
            if let Some(entry) = read.get(&key) {
                if is_fresh(Instant::now(), entry.expires_at) {
                    return Ok(entry.token.clone());
                }
            }
        }
        let fresh = fetch().await?;
        let ttl = fresh
            .expires_in
            .filter(|&n| n > 0)
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(DEFAULT_TTL);
        let expires_at = Instant::now() + ttl.saturating_sub(self.safety_margin);
        let mut write = self.entries.write().await;
        write.insert(
            key,
            Entry {
                token: fresh.clone(),
                expires_at,
            },
        );
        Ok(fresh)
    }

    /// Test / admin hook — drop every cached token. Useful when an operator
    /// rotates the gateway's IdP client secret.
    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }
}

fn is_fresh(now: Instant, expires_at: Instant) -> bool {
    now < expires_at
}

fn hash_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Debug-only helper for logs: short hash of the subject token for correlation
/// without leaking the token itself.
pub fn subject_fingerprint(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(&hash_token(token)[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use axum::extract::State;
    use axum::response::{Redirect, Response};
    use axum::routing::post;
    use axum::Router;
    use tokio::net::TcpListener;
    use waygate_core::http_client::{self, Profile};

    fn test_http() -> reqwest::Client {
        http_client::client(Profile::Interactive).expect("test HTTP client")
    }

    #[derive(Default, Clone)]
    struct Captured {
        last_body: Arc<Mutex<String>>,
        call_count: Arc<Mutex<u32>>,
        next_response: Arc<Mutex<Option<(u16, String)>>>,
    }

    async fn handler(State(state): State<Captured>, body: String) -> Response {
        *state.last_body.lock().unwrap() = body;
        *state.call_count.lock().unwrap() += 1;
        let (status, body) = state
            .next_response
            .lock()
            .unwrap()
            .clone()
            .unwrap_or((200, default_success()));
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    async fn redirect_handler() -> Redirect {
        Redirect::temporary("/token")
    }

    fn default_success() -> String {
        serde_json::json!({
            "access_token": "downscoped-xyz",
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": 300,
        })
        .to_string()
    }

    fn cached_token(access_token: &str, expires_in: i64) -> ExchangedToken {
        ExchangedToken {
            access_token: access_token.to_owned(),
            issued_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
            expires_in: Some(expires_in),
            scope: None,
            token_type: Some("Bearer".to_owned()),
        }
    }

    async fn spawn() -> (SocketAddr, Captured) {
        let captured = Captured::default();
        let app = Router::new()
            .route("/token", post(handler))
            .route("/redirect", post(redirect_handler))
            .with_state(captured.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, captured)
    }

    async fn spawn_stalled_endpoint() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        addr
    }

    #[test]
    fn form_body_includes_all_rfc8693_params() {
        let body = build_form_body(
            "gw-client",
            "secret",
            &ExchangeRequest {
                subject_token: "abc.def.ghi",
                audience: "https://example-messages.test/mcp",
                scope: Some("upstream:call"),
            },
        );
        assert!(
            body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
        );
        assert!(body.contains("subject_token=abc.def.ghi"));
        assert!(body.contains(
            "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
        ));
        assert!(body.contains(
            "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
        ));
        assert!(body.contains("audience=https%3A%2F%2Fexample-messages.test%2Fmcp"));
        assert!(body.contains("client_id=gw-client"));
        assert!(body.contains("client_secret=secret"));
        assert!(body.contains("scope=upstream%3Acall"));
    }

    #[test]
    fn form_body_omits_scope_when_none() {
        let body = build_form_body(
            "c",
            "s",
            &ExchangeRequest {
                subject_token: "t",
                audience: "a",
                scope: None,
            },
        );
        assert!(!body.contains("scope="));
    }

    #[tokio::test]
    async fn exchange_happy_path_returns_token() {
        let (addr, _cap) = spawn().await;
        let client = TokenExchangeClient::new(
            test_http(),
            format!("http://{addr}/token"),
            "gw-client",
            "gw-secret",
        );
        let tok = client
            .exchange(ExchangeRequest {
                subject_token: "user-token",
                audience: "https://example-messages.test/mcp",
                scope: None,
            })
            .await
            .expect("exchange");
        assert_eq!(tok.access_token, "downscoped-xyz");
        assert_eq!(tok.expires_in, Some(300));
        assert_eq!(tok.issued_token_type.as_deref(), Some(ACCESS_TOKEN_TYPE));
    }

    #[test]
    fn debug_identifies_destination_without_exposing_secret() {
        let client = TokenExchangeClient::new(
            test_http(),
            "https://identity.example.test/token",
            "gateway-client",
            "never-log-this-secret",
        );

        let rendered = format!("{client:?}");
        assert!(rendered.contains("https://identity.example.test/token"));
        assert!(rendered.contains("gateway-client"));
        assert!(!rendered.contains("never-log-this-secret"));
    }

    #[tokio::test]
    async fn exchange_propagates_error_status() {
        let (addr, cap) = spawn().await;
        *cap.next_response.lock().unwrap() = Some((
            400,
            serde_json::json!({"error": "invalid_grant"}).to_string(),
        ));
        let client =
            TokenExchangeClient::new(test_http(), format!("http://{addr}/token"), "c", "s");
        let err = client
            .exchange(ExchangeRequest {
                subject_token: "user-token",
                audience: "aud",
                scope: None,
            })
            .await
            .expect_err("expected error");
        match err {
            ExchangeError::Status { status, body } => {
                assert_eq!(status.as_u16(), 400);
                assert!(body.contains("invalid_grant"), "body was: {body}");
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn exchange_honors_injected_timeout() {
        let addr = spawn_stalled_endpoint().await;
        let http = http_client::client(Profile::Custom(Duration::from_millis(50)))
            .expect("short-timeout client");
        let client = TokenExchangeClient::new(http, format!("http://{addr}/token"), "c", "s");

        let error = client
            .exchange(ExchangeRequest {
                subject_token: "user-token",
                audience: "aud",
                scope: None,
            })
            .await
            .expect_err("stalled exchange must time out");
        match error {
            ExchangeError::Http(error) => assert!(error.is_timeout(), "{error}"),
            other => panic!("expected timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exchange_honors_injected_no_redirect_policy() {
        let (addr, captured) = spawn().await;
        let http = http_client::builder(Profile::Interactive)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("no-redirect client");
        let client = TokenExchangeClient::new(http, format!("http://{addr}/redirect"), "c", "s");

        let error = client
            .exchange(ExchangeRequest {
                subject_token: "user-token",
                audience: "aud",
                scope: None,
            })
            .await
            .expect_err("redirect response must not be followed");
        match error {
            ExchangeError::Status { status, .. } => assert_eq!(status.as_u16(), 307),
            other => panic!("expected redirect status, got {other:?}"),
        }
        assert_eq!(*captured.call_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn exchange_rejects_unsupported_issued_token_type() {
        let (addr, cap) = spawn().await;
        *cap.next_response.lock().unwrap() = Some((
            200,
            serde_json::json!({
                "access_token": "x",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "expires_in": 60,
            })
            .to_string(),
        ));
        let client =
            TokenExchangeClient::new(test_http(), format!("http://{addr}/token"), "c", "s");
        let err = client
            .exchange(ExchangeRequest {
                subject_token: "t",
                audience: "a",
                scope: None,
            })
            .await
            .expect_err("expected reject");
        assert!(matches!(err, ExchangeError::UnsupportedTokenType(_)));
    }

    #[tokio::test]
    async fn cache_returns_same_token_within_ttl() {
        let (addr, cap) = spawn().await;
        let client =
            TokenExchangeClient::new(test_http(), format!("http://{addr}/token"), "c", "s");
        let cache = TokenCache::default();

        let first = cache
            .get_or_exchange("subject-1", "aud-1", None, || {
                client.exchange(ExchangeRequest {
                    subject_token: "subject-1",
                    audience: "aud-1",
                    scope: None,
                })
            })
            .await
            .unwrap();
        let second = cache
            .get_or_exchange("subject-1", "aud-1", None, || async {
                panic!("should have been cached")
            })
            .await
            .unwrap();
        assert_eq!(first.access_token, second.access_token);
        assert_eq!(*cap.call_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn cache_separates_by_subject_and_audience() {
        let (addr, cap) = spawn().await;
        let client =
            TokenExchangeClient::new(test_http(), format!("http://{addr}/token"), "c", "s");
        let cache = TokenCache::default();

        for (sub, aud) in [
            ("alice", "example-messages"),
            ("alice", "example-observability"),
            ("bob", "example-messages"),
        ] {
            cache
                .get_or_exchange(sub, aud, None, || {
                    client.exchange(ExchangeRequest {
                        subject_token: sub,
                        audience: aud,
                        scope: None,
                    })
                })
                .await
                .unwrap();
        }
        assert_eq!(*cap.call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn cache_expires_when_ttl_elapses() {
        let (addr, cap) = spawn().await;
        *cap.next_response.lock().unwrap() = Some((
            200,
            // Token lifetime just barely exceeds the safety margin so the
            // entry should fall out of the cache immediately.
            serde_json::json!({
                "access_token": "a",
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "expires_in": 1,
            })
            .to_string(),
        ));
        let client =
            TokenExchangeClient::new(test_http(), format!("http://{addr}/token"), "c", "s");
        let cache = TokenCache::new(Duration::from_secs(2)); // margin > ttl → always expired

        cache
            .get_or_exchange("s", "a", None, || {
                client.exchange(ExchangeRequest {
                    subject_token: "s",
                    audience: "a",
                    scope: None,
                })
            })
            .await
            .unwrap();
        cache
            .get_or_exchange("s", "a", None, || {
                client.exchange(ExchangeRequest {
                    subject_token: "s",
                    audience: "a",
                    scope: None,
                })
            })
            .await
            .unwrap();
        assert_eq!(*cap.call_count.lock().unwrap(), 2);
    }

    #[test]
    fn cache_entry_is_expired_at_its_deadline() {
        let deadline = Instant::now();
        assert!(!is_fresh(deadline, deadline));
    }

    #[tokio::test]
    async fn zero_expires_in_uses_the_default_ttl() {
        let cache = TokenCache::new(Duration::ZERO);
        let fetches = AtomicU32::new(0);

        let first = cache
            .get_or_exchange("subject", "audience", None, || async {
                fetches.fetch_add(1, Ordering::SeqCst);
                Ok(cached_token("first", 0))
            })
            .await
            .unwrap();
        let second = cache
            .get_or_exchange("subject", "audience", None, || async {
                fetches.fetch_add(1, Ordering::SeqCst);
                Ok(cached_token("second", 0))
            })
            .await
            .unwrap();

        assert_eq!(first.access_token, "first");
        assert_eq!(second.access_token, "first");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn clear_forces_the_next_exchange() {
        let cache = TokenCache::new(Duration::ZERO);
        let fetches = AtomicU32::new(0);

        cache
            .get_or_exchange("subject", "audience", None, || async {
                fetches.fetch_add(1, Ordering::SeqCst);
                Ok(cached_token("first", 300))
            })
            .await
            .unwrap();
        cache.clear().await;
        let after_clear = cache
            .get_or_exchange("subject", "audience", None, || async {
                fetches.fetch_add(1, Ordering::SeqCst);
                Ok(cached_token("second", 300))
            })
            .await
            .unwrap();

        assert_eq!(after_clear.access_token, "second");
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn subject_fingerprint_stable_and_short() {
        let a = subject_fingerprint("token-abc");
        let b = subject_fingerprint("token-abc");
        assert_eq!(a, b);
        assert_ne!(a, subject_fingerprint("different"));
        assert!(a.len() <= 16); // base64(8 bytes) = 11 chars
    }
}
