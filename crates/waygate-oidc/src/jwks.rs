//! JWKS cache backed by an OIDC discovery document.
//!
//! Network-backed keys expire even when their `kid` remains in use. Refreshes
//! are serialized and rate-limited on success, failure, and cancellation.
//! Pinned key sets never expire or contact an external issuer.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::Instant;
use waygate_core::http_client::{self, Profile};

#[derive(Debug, Error)]
pub enum JwksError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("discovery doc missing jwks_uri")]
    MissingJwksUri,
    #[error("kid `{0}` not present in JWKS")]
    UnknownKid(String),
    #[error("signing keys unavailable while issuer refresh is backed off")]
    RefreshUnavailable,
    #[error("jwt key material: {0}")]
    Key(#[from] jsonwebtoken::errors::Error),
    /// Names the document because this covers both IdP fetches — a malformed
    /// discovery response reported as a malformed JWKS would send an operator
    /// to the wrong endpoint.
    #[error("malformed {document} json: {source}")]
    Json {
        document: &'static str,
        #[source]
        source: serde_json::Error,
    },
    /// The IdP's JWKS or discovery response exceeded the cap. Carries only the
    /// limit — never the URL or any bytes read.
    #[error(transparent)]
    BodyTooLarge(#[from] waygate_core::http_client::BodyTooLarge),
    /// A non-2xx that `error_for_status` does not reject — a 3xx the client did
    /// not follow, such as `304` or `300`. Without this the body would reach
    /// the JSON decoder and a valid-looking document on a redirect status would
    /// be accepted as the real thing.
    #[error("idp returned unexpected status {0}")]
    UnexpectedStatus(u16),
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: Option<String>,
}

struct CacheEntry {
    keys: JwkSet,
    fetched_at: Instant,
}

#[derive(Default)]
struct CacheState {
    entry: Option<CacheEntry>,
    next_refresh: Option<Instant>,
    refresh_failed: bool,
}

const MAX_CACHE_AGE: Duration = Duration::from_secs(300);
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

pub struct JwksProvider {
    issuer: String,
    http: reqwest::Client,
    cache: RwLock<CacheState>,
    refresh_lock: Mutex<()>,
    pinned: bool,
}

impl JwksProvider {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            http: http_client::builder(Profile::Standard)
                .build()
                .expect("reqwest client"),
            cache: RwLock::new(CacheState::default()),
            refresh_lock: Mutex::new(()),
            pinned: false,
        }
    }

    /// Build a provider whose cache is pre-seeded from a JWKS JSON document,
    /// skipping OIDC discovery entirely. Useful for tests, air-gapped
    /// deployments, and pinning a known-good key set.
    ///
    /// Lazy refresh is **disabled** for preloaded providers — by definition
    /// there is no upstream URL to refresh from, so a cache miss must return
    /// `UnknownKid` directly rather than attempting to fetch
    /// `<issuer>/.well-known/openid-configuration` (which may not exist, e.g.
    /// when the issuer is the gateway's own AS public URL). Without this, a
    /// JWT carrying a kid the preloaded set does not know — common in a
    /// multi-validator chain where some validators are preloaded and others
    /// are network-backed — would surface as an HTTP infra error rather than
    /// a fall-through-able `UnknownKid`. See `bearer_middleware` for how the
    /// chain consumes that distinction.
    pub fn from_preloaded(issuer: impl Into<String>, jwks_json: &str) -> Result<Self, JwksError> {
        let keys: JwkSet = serde_json::from_str(jwks_json).map_err(|source| JwksError::Json {
            document: "JWKS",
            source,
        })?;
        let mut me = Self::new(issuer);
        me.pinned = true;
        me.cache.write().expect("cache poisoned").entry = Some(CacheEntry {
            keys,
            fetched_at: Instant::now(),
        });
        Ok(me)
    }

    /// Warm the cache. Called once at startup; failures are logged but don't
    /// abort boot. Requests retry after the refresh backoff has elapsed.
    pub async fn prime(self: &Arc<Self>) {
        if let Err(e) = self.refresh().await {
            tracing::warn!(error = %e, issuer = %self.issuer, "jwks prime failed");
        }
    }

    /// Resolve a `kid` using pinned keys or a network snapshot younger than
    /// five minutes. Missing or expired keys require a rate-limited refresh;
    /// an issuer outage never extends the lifetime of a cached network key.
    pub async fn decoding_key(self: &Arc<Self>, kid: &str) -> Result<DecodingKey, JwksError> {
        if let Some(jwk) = self.lookup(kid) {
            return Ok(DecodingKey::from_jwk(&jwk)?);
        }

        self.refresh().await?;

        let jwk = self
            .lookup(kid)
            .ok_or_else(|| JwksError::UnknownKid(kid.to_owned()))?;
        Ok(DecodingKey::from_jwk(&jwk)?)
    }

    fn lookup(&self, kid: &str) -> Option<Jwk> {
        let guard = self.cache.read().expect("cache poisoned");
        guard
            .entry
            .as_ref()
            .filter(|entry| self.pinned || entry.fetched_at.elapsed() < MAX_CACHE_AGE)
            .and_then(|entry| entry.keys.find(kid).cloned())
    }

    async fn refresh(&self) -> Result<(), JwksError> {
        if self.pinned {
            return Ok(());
        }
        let _refresh = self.refresh_lock.lock().await;
        {
            let mut cache = self.cache.write().expect("cache poisoned");
            if cache.next_refresh.is_some_and(|next| Instant::now() < next) {
                return if cache.refresh_failed {
                    Err(JwksError::RefreshUnavailable)
                } else {
                    Ok(())
                };
            }
            // Set backoff before awaiting so cancellation cannot turn a queue
            // of callers into repeated attempts against an unavailable issuer.
            cache.next_refresh = Some(Instant::now() + MIN_REFRESH_INTERVAL);
            cache.refresh_failed = true;
        }

        let fetched = async {
            let jwks_uri = self.resolve_jwks_uri().await?;
            tracing::debug!(%jwks_uri, "refreshing JWKS");
            let body = self.fetch_capped(&jwks_uri).await?;
            serde_json::from_slice::<JwkSet>(&body).map_err(|source| JwksError::Json {
                document: "JWKS",
                source,
            })
        }
        .await;

        let mut cache = self.cache.write().expect("cache poisoned");
        cache.next_refresh = Some(Instant::now() + MIN_REFRESH_INTERVAL);
        match fetched {
            Ok(keys) => {
                cache.entry = Some(CacheEntry {
                    keys,
                    fetched_at: Instant::now(),
                });
                cache.refresh_failed = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn resolve_jwks_uri(&self) -> Result<String, JwksError> {
        let mut url = self.issuer.trim_end_matches('/').to_owned();
        url.push_str("/.well-known/openid-configuration");
        let body = self.fetch_capped(&url).await?;
        let disc: OidcDiscovery =
            serde_json::from_slice(&body).map_err(|source| JwksError::Json {
                document: "discovery",
                source,
            })?;
        disc.jwks_uri.ok_or(JwksError::MissingJwksUri)
    }
}

/// Hard ceiling on an IdP JWKS or discovery body.
///
/// These are read on the token-validation path, from an endpoint the gateway
/// trusts only as far as its TLS certificate — a compromised, misconfigured, or
/// trusted-cert-MITM'd IdP could otherwise stream a body the gateway buffers
/// and deserializes in full while verifying a request. 1 MiB is orders of
/// magnitude above a real JWKS (an RSA-2048 JWK is ~600 bytes, so even a 50-key
/// set fits in well under 40 KiB) or discovery document; it exists to stop
/// runaway allocation, not to be a tight fit. Matches the peer-JWKS cap.
const MAX_IDP_BODY_BYTES: usize = 1024 * 1024;

impl JwksProvider {
    /// Fetch `url` and read at most [`MAX_IDP_BODY_BYTES`] of it.
    ///
    /// The status is checked before the body is read, in two steps.
    /// `error_for_status` rejects 4xx and 5xx as transport errors — previously
    /// a non-2xx surfaced that way only because its body failed to parse as
    /// JSON, so an IdP returning `404` with a valid `{}` would have
    /// deserialized to a discovery document with no `jwks_uri` and reported
    /// `MissingJwksUri`. It does **not** reject 3xx, though, and the client
    /// does not follow every 3xx (a `304` or `300` is returned as-is), so
    /// anything not 2xx is refused explicitly as well. Otherwise a
    /// valid-looking document served on a redirect status would be accepted as
    /// the real one.
    async fn fetch_capped(&self, url: &str) -> Result<Vec<u8>, JwksError> {
        use waygate_core::http_client::ReadBodyError;

        let response = self.http.get(url).send().await?.error_for_status()?;
        let status = response.status();
        if !status.is_success() {
            return Err(JwksError::UnexpectedStatus(status.as_u16()));
        }
        waygate_core::http_client::read_body_capped(response, MAX_IDP_BODY_BYTES)
            .await
            .map_err(|e| match e {
                ReadBodyError::Http(e) => JwksError::Http(e),
                ReadBodyError::TooLarge(e) => JwksError::BodyTooLarge(e),
            })
    }
}
