//! Peer JWKS fetcher + in-memory cache.
//!
//! The federated peer registry ([`crate`]) stores a per-peer
//! `jwks_url`. The peer JWT verifier needs verified signing
//! keys at JWT-validation time, *synchronously*, with no
//! network hop in the request path. This module bridges
//! those:
//!
//! - [`PeerJwksFetcher`] pulls JWKS over HTTP(S) under the
//!   established safety envelope (scheme allow-list,
//!   response-body size cap, request timeout).
//! - [`InMemoryPeerJwksCache`] keeps the parsed `JwkSet`
//!   keyed by `peer_id` *and* indexed by `issuer` (the
//!   key the verifier looks up by — JWT `iss` claim).
//! - [`PeerJwksRefresher`] is the background actor that
//!   periodically walks every registered peer and refreshes
//!   the cache. Partial failures (one peer's URL is down)
//!   leave the other peers' entries intact and surface as
//!   a `WARN` log + a non-zero count in [`RefreshSummary`].
//!
//! ## Safety envelope on the fetch
//!
//! Even though every `jwks_url` row reaches us via the
//! admin-only CRUD (operator-controlled), this module
//! re-validates each URL at fetch time. The admin validator
//! accepts `http://` for local-dev seeding and explicitly
//! defers HTTPS-only enforcement to the runtime
//! ([crates/waygate-admin/src/federated_peers.rs](../../../waygate-admin/src/federated_peers.rs)
//! comments). This is where that lands:
//!
//! - **Scheme**: `https://` always; `http://` only when the
//!   host is `localhost`, `127.0.0.1`, or `[::1]` so the
//!   local-dev seed path still works without leaking JWKS
//!   pulls across the network in plaintext.
//! - **No URL userinfo**: a `user:pass@` form is refused
//!   rather than sanitized. A JWKS document is public by
//!   contract, so request-line credentials serve no purpose
//!   and would be replayed on every refresh.
//! - **Response size**: bounded to `MAX_JWKS_BYTES` so a
//!   misconfigured upstream serving a multi-GB blob can't
//!   OOM the gateway.
//! - **Request timeout**: bounded to `DEFAULT_FETCH_TIMEOUT`
//!   so a hanging upstream can't stall the refresher.
//!
//! ## Cache lookup semantics
//!
//! [`PeerJwksCache::get_by_issuer`] returns a `Vec` rather
//! than a single match because the storage layer permits the
//! same `issuer` across distinct tenants (the migration's
//! UNIQUE constraint is `(tenant_id, issuer)`, not
//! `(issuer)`). The verifier iterates the returned entries
//! to find one whose `kid` resolves the incoming JWT, then
//! applies per-tenant routing logic from that match. Per-id
//! lookup is exposed for diagnostics and for the per-
//! upstream identity selector's outbound assertion minting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{SharedPeersStore, TrustTier};
use waygate_core::http_client::{self, Profile};

/// Hard ceiling on the JWKS HTTP body. 1 MiB is ~3 orders of
/// magnitude above a realistic JWKS (an RSA-2048 JWK is ~600
/// bytes; even a 50-key set fits in <40 KiB) and well below
/// any reasonable connection-level limit. Sized to stop a
/// misconfigured/malicious upstream from streaming gigabytes
/// before we notice, not to be a tight fit.
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// Total per-request timeout for the JWKS fetch. Matches the
/// existing `waygate-oidc::JwksProvider` envelope.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default refresh cadence for the background refresher.
/// 10 minutes is a balance between "keys rotate within an
/// operationally reasonable window" and "we are not DoS-ing
/// the peer's JWKS endpoint." A faster reactive refresh
/// (cache-miss-on-kid) could be layered on top of this
/// polling cadence if a peer's key rotation needs to be
/// picked up sooner than the next scheduled cycle.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// Default page size used by the refresher when walking the
/// store. Sized so a single page covers any realistic
/// federation deployment in one DB round-trip.
pub const DEFAULT_REFRESH_PAGE_SIZE: u32 = 200;

/// Parsed + timestamped JWKS for a single registered peer.
/// Wrapped in `Arc` at the cache surface so the verifier
/// can pin a snapshot for the duration of a validation
/// without blocking concurrent refreshes.
#[derive(Debug, Clone)]
pub struct CachedJwks {
    pub peer_id: Uuid,
    pub tenant_id: String,
    pub issuer: String,
    pub trust_tier: TrustTier,
    pub keys: JwkSet,
    pub fetched_at: OffsetDateTime,
}

/// Outcome of a single fetch attempt — surfaced to logs and
/// to [`RefreshSummary`] so the refresher's progress can be
/// asserted in tests without timing assumptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    Success,
    SchemeRejected,
    UserinfoRejected,
    BadUrl,
    HttpError,
    BodyTooLarge,
    ParseError,
}

impl FetchOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::SchemeRejected => "scheme_rejected",
            Self::UserinfoRejected => "userinfo_rejected",
            Self::BadUrl => "bad_url",
            Self::HttpError => "http_error",
            Self::BodyTooLarge => "body_too_large",
            Self::ParseError => "parse_error",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwksFetchError {
    /// Scheme name held internally for debugging, but
    /// Display intentionally elides it — surfacing the raw
    /// scheme is harmless but the URL is not, and a future
    /// refactor adding the URL here would silently leak any
    /// userinfo (`https://user:pass@host/...`) a peer
    /// might register. Identify the offending peer via the
    /// surrounding `peer_id` / `peer_name` tracing fields.
    #[error("jwks_url scheme rejected (must be https, or http to loopback)")]
    SchemeRejected { scheme: String },
    /// The URL carried `user:pass@` credentials. The message embeds no URL
    /// bytes, so it cannot leak the credential it refused.
    #[error("jwks_url must not contain URL userinfo (the `user:pass@` form is rejected)")]
    UserinfoRejected,
    /// `url::ParseError::Display` is opaque ("relative URL
    /// without a base", etc.) — no URL bytes embedded — so
    /// it's safe to surface as-is.
    #[error("jwks_url malformed: {0}")]
    BadUrl(#[source] url::ParseError),
    /// `reqwest::Error::Display` *does* include the URL it
    /// was trying to reach. Surfaced via `#[source]` so
    /// callers that want the chain can opt in; the default
    /// `{}` for the wrapper itself stays terse so the
    /// refresher's `error = %e` does not log the URL.
    #[error("http error fetching jwks_url")]
    Http(#[source] reqwest::Error),
    #[error("response body exceeded {limit} bytes")]
    BodyTooLarge { limit: usize },
    #[error("malformed JWKS json: {0}")]
    Parse(#[source] serde_json::Error),
}

impl JwksFetchError {
    fn outcome(&self) -> FetchOutcome {
        match self {
            Self::SchemeRejected { .. } => FetchOutcome::SchemeRejected,
            Self::UserinfoRejected => FetchOutcome::UserinfoRejected,
            Self::BadUrl(_) => FetchOutcome::BadUrl,
            Self::Http(_) => FetchOutcome::HttpError,
            Self::BodyTooLarge { .. } => FetchOutcome::BodyTooLarge,
            Self::Parse(_) => FetchOutcome::ParseError,
        }
    }
}

/// Validate that a `jwks_url` is acceptable to fetch in this
/// gateway's safety envelope: no URL userinfo, and `https://`
/// everywhere, or
/// `http://` only when the host resolves to loopback at the
/// URL level (`localhost`, `127.0.0.1`, `::1`). Returns the
/// parsed `Url` so the caller doesn't re-parse.
///
/// Rationale lives at the module doc comment; this function
/// is the single enforcement point so the rule can't drift
/// between the eager validator and the runtime fetcher.
pub fn validate_jwks_url(jwks_url: &str) -> Result<url::Url, JwksFetchError> {
    let parsed = url::Url::parse(jwks_url).map_err(JwksFetchError::BadUrl)?;
    // A JWKS document is public by contract, so request-line credentials serve
    // no purpose and would be sent on every refresh. Checked before the scheme
    // arms so it applies to the loopback exception too. `username()` is `""`
    // when unset; `password()` is `None`.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(JwksFetchError::UserinfoRejected);
    }
    let scheme = parsed.scheme();
    if scheme == "https" {
        return Ok(parsed);
    }
    if scheme == "http" && is_loopback_host(&parsed) {
        return Ok(parsed);
    }
    Err(JwksFetchError::SchemeRejected {
        scheme: scheme.to_owned(),
    })
}

fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

// -----------------------------------------------------------------------------
// Cache
// -----------------------------------------------------------------------------

/// Read-side cache contract used by the peer JWT verifier
/// and the per-upstream identity selector that mints
/// outbound peer assertions. Held behind `Arc` since the
/// same cache backs every request.
#[async_trait]
pub trait PeerJwksCache: Send + Sync + 'static {
    /// All cached entries advertising the given issuer.
    /// May be empty (no peer with that issuer yet refreshed)
    /// or contain multiple entries (same issuer registered
    /// in distinct tenants — permitted by the migration's
    /// UNIQUE(tenant_id, issuer) constraint).
    async fn get_by_issuer(&self, issuer: &str) -> Vec<Arc<CachedJwks>>;

    /// Direct lookup by peer id — used to mint outbound peer
    /// assertions against a specific entry.
    async fn get_by_peer_id(&self, peer_id: Uuid) -> Option<Arc<CachedJwks>>;

    /// Current cache size in entries. Diagnostic; exposed so
    /// the wiring layer can emit a gauge without poking into
    /// the implementation.
    async fn len(&self) -> usize;

    /// `true` when [`Self::len`] is zero. Convenience wrapper
    /// only; default impl in terms of `len()` so backends
    /// don't have to override.
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Drop the entry for `peer_id` from the cache. Called by
    /// the admin PATCH and DELETE handlers after a successful
    /// metadata rotation or removal so the next inbound JWT
    /// can't be validated against the OLD issuer / key
    /// bundle. Returns `true` when an entry was removed;
    /// `false` when no such entry existed (already-forgotten,
    /// never refreshed).
    async fn invalidate(&self, peer_id: Uuid) -> bool;
}

pub type SharedPeerJwksCache = Arc<dyn PeerJwksCache>;

/// In-memory cache backed by a single `RwLock<HashMap>`. The
/// expected steady-state size is a small handful of entries
/// (one per registered peer) so a single lock is fine —
/// readers fan out and the writer (refresher) takes the
/// lock only at the end of each cycle to swap entries.
#[derive(Default)]
pub struct InMemoryPeerJwksCache {
    inner: RwLock<CacheInner>,
}

#[derive(Default)]
struct CacheInner {
    by_peer: HashMap<Uuid, Arc<CachedJwks>>,
    /// Per-peer monotonic generation counter. Bumped on every
    /// `invalidate` / `forget`; refreshers snapshot it at
    /// fetch start and upsert only if the entry hasn't been
    /// invalidated since. Defaults to 0 for never-seen peers
    /// — first upsert lands at gen 0, admin invalidate bumps
    /// to 1, subsequent upserts compare against the bumped
    /// value.
    generations: HashMap<Uuid, u64>,
}

impl InMemoryPeerJwksCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current generation for `peer_id`. Returns 0
    /// when the peer has never been invalidated. Refreshers
    /// MUST call this BEFORE starting their `fetcher.fetch`
    /// and pass the snapshot to [`Self::try_upsert_at_gen`]
    /// after the fetch — the race-free path.
    pub fn generation(&self, peer_id: Uuid) -> u64 {
        let guard = self.inner.read().expect("peer jwks cache poisoned");
        guard.generations.get(&peer_id).copied().unwrap_or(0)
    }

    /// Try to upsert `entry` IFF the per-peer generation
    /// snapshotted at `expected_gen` hasn't been bumped by an
    /// intervening admin invalidation. Returns `true` when
    /// the upsert landed, `false` when the entry was stale
    /// (admin mutated the peer while the fetch was in
    /// flight). The refresher uses the `false` branch to
    /// discard the fetched keys rather than re-insert stale
    /// ones into the cache.
    pub fn try_upsert_at_gen(&self, entry: CachedJwks, expected_gen: u64) -> bool {
        let arc = Arc::new(entry);
        let mut guard = self.inner.write().expect("peer jwks cache poisoned");
        let current = guard.generations.get(&arc.peer_id).copied().unwrap_or(0);
        if current != expected_gen {
            return false;
        }
        guard.by_peer.insert(arc.peer_id, arc);
        true
    }

    /// Replace (or insert) the entry for a given peer,
    /// IGNORING the generation counter. Kept on the inherent
    /// surface for tests + internal callers that don't race
    /// with admin invalidation. Prefer
    /// [`Self::try_upsert_at_gen`] from the refresher.
    pub fn upsert(&self, entry: CachedJwks) {
        let arc = Arc::new(entry);
        let mut guard = self.inner.write().expect("peer jwks cache poisoned");
        guard.by_peer.insert(arc.peer_id, arc);
    }

    /// Drop the entry for `peer_id` AND bump the per-peer
    /// generation counter. Returns `true` when an entry
    /// existed. Called by the refresher's GC path
    /// (peer-deleted-from-store) and by admin PATCH/DELETE.
    /// The generation bump fences any in-flight refresher
    /// fetch from re-inserting the stale entry — see
    /// [`Self::try_upsert_at_gen`].
    pub fn forget(&self, peer_id: Uuid) -> bool {
        let mut guard = self.inner.write().expect("peer jwks cache poisoned");
        let existed = guard.by_peer.remove(&peer_id).is_some();
        // Always bump on forget so even an invalidate against
        // a never-cached peer fences an in-flight first
        // refresh that would otherwise land stale data after
        // the admin's `invalidate` returned.
        *guard.generations.entry(peer_id).or_insert(0) += 1;
        existed
    }

    /// Snapshot of currently cached peer ids. Used by the
    /// refresher to compute the GC set ("known to cache but
    /// no longer in the store").
    pub fn known_peer_ids(&self) -> Vec<Uuid> {
        let guard = self.inner.read().expect("peer jwks cache poisoned");
        guard.by_peer.keys().copied().collect()
    }
}

#[async_trait]
impl PeerJwksCache for InMemoryPeerJwksCache {
    async fn get_by_issuer(&self, issuer: &str) -> Vec<Arc<CachedJwks>> {
        let guard = self.inner.read().expect("peer jwks cache poisoned");
        guard
            .by_peer
            .values()
            .filter(|c| c.issuer == issuer)
            .cloned()
            .collect()
    }

    async fn get_by_peer_id(&self, peer_id: Uuid) -> Option<Arc<CachedJwks>> {
        let guard = self.inner.read().expect("peer jwks cache poisoned");
        guard.by_peer.get(&peer_id).cloned()
    }

    async fn len(&self) -> usize {
        let guard = self.inner.read().expect("peer jwks cache poisoned");
        guard.by_peer.len()
    }

    async fn invalidate(&self, peer_id: Uuid) -> bool {
        // Delegates to the inherent `forget` method already
        // used by the refresher's GC path. Implementations
        // can override if a different sync vs async path is
        // appropriate; here both paths take the same write
        // lock.
        self.forget(peer_id)
    }
}

// -----------------------------------------------------------------------------
// Fetcher
// -----------------------------------------------------------------------------

/// HTTP-backed JWKS fetcher. Holds a single `reqwest::Client`
/// so connection pooling + TLS-context reuse happens across
/// every refresh cycle.
pub struct PeerJwksFetcher {
    http: reqwest::Client,
    max_bytes: usize,
}

impl PeerJwksFetcher {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_FETCH_TIMEOUT, MAX_JWKS_BYTES)
    }

    pub fn with_limits(timeout: Duration, max_bytes: usize) -> Self {
        let http = http_client::builder(Profile::Custom(timeout))
            .user_agent(concat!(
                "waygate/",
                env!("CARGO_PKG_VERSION"),
                " (peer-jwks)",
            ))
            .build()
            .expect("reqwest client");
        Self { http, max_bytes }
    }

    /// Fetch + parse the JWKS for one peer. The result is
    /// the parsed key set; the caller composes the
    /// surrounding `CachedJwks` so per-peer metadata
    /// (tenant_id, trust_tier) stays at the call site.
    ///
    /// Body-cap enforcement is streaming, not after-the-fact:
    /// calling `resp.bytes().await` on the no-Content-Length
    /// path would fully buffer the response into memory
    /// before `len() > max_bytes` could ever be checked, so a
    /// malicious peer JWKS endpoint could force allocation of
    /// an arbitrarily large body within the request timeout —
    /// the cap would be advisory, not load-bearing. Draining
    /// the body to "consume" it when Content-Length exceeds
    /// the cap has the same problem: that allocates exactly
    /// the bytes the cap is meant to refuse. Instead: a
    /// too-large Content-Length errors out IMMEDIATELY (the
    /// response is dropped, the underlying socket closes),
    /// and the chunked / no-Content-Length path streams via
    /// `bytes_stream()` with a per-chunk counter that aborts
    /// the moment the cumulative read exceeds the cap.
    pub async fn fetch(&self, jwks_url: &str) -> Result<JwkSet, JwksFetchError> {
        let url = validate_jwks_url(jwks_url)?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(JwksFetchError::Http)?
            .error_for_status()
            .map_err(JwksFetchError::Http)?;

        // Pre-stream pre-check: if the server advertised a
        // Content-Length above our cap, refuse without
        // draining a single byte. Dropping `resp` here closes
        // the underlying socket so the peer can't keep
        // streaming data we'd ignore.
        if let Some(cl) = resp.content_length() {
            if cl as usize > self.max_bytes {
                return Err(JwksFetchError::BodyTooLarge {
                    limit: self.max_bytes,
                });
            }
        }

        // Stream the body with a running byte counter so a
        // peer that lies about (or omits) Content-Length can
        // still be cut off at the cap without ever
        // allocating more than ~one chunk past the limit.
        use futures::StreamExt;
        let mut stream = resp.bytes_stream();
        let mut acc: Vec<u8> = Vec::with_capacity(4096.min(self.max_bytes));
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(JwksFetchError::Http)?;
            if acc.len() + chunk.len() > self.max_bytes {
                return Err(JwksFetchError::BodyTooLarge {
                    limit: self.max_bytes,
                });
            }
            acc.extend_from_slice(&chunk);
        }

        let set: JwkSet = serde_json::from_slice(&acc).map_err(JwksFetchError::Parse)?;
        Ok(set)
    }
}

impl Default for PeerJwksFetcher {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Refresher
// -----------------------------------------------------------------------------

/// Per-cycle outcome of [`PeerJwksRefresher::refresh_once`].
/// Returned so tests + log lines can describe the cycle
/// without timing assumptions.
#[derive(Debug, Clone, Default)]
pub struct RefreshSummary {
    pub total: usize,
    pub ok: usize,
    pub failed: usize,
    pub gc: usize,
    pub failures: Vec<RefreshFailure>,
}

#[derive(Debug, Clone)]
pub struct RefreshFailure {
    pub peer_id: Uuid,
    pub peer_name: String,
    pub outcome: FetchOutcome,
    pub message: String,
}

/// Background actor that walks every registered peer once
/// per `interval` and refreshes the in-memory cache. Owns
/// the cache `Arc` so it can both populate it and GC stale
/// entries (peers deleted from the store between cycles).
pub struct PeerJwksRefresher {
    store: SharedPeersStore,
    cache: Arc<InMemoryPeerJwksCache>,
    fetcher: Arc<PeerJwksFetcher>,
    interval: Duration,
    page_size: u32,
}

impl PeerJwksRefresher {
    pub fn new(
        store: SharedPeersStore,
        cache: Arc<InMemoryPeerJwksCache>,
        fetcher: Arc<PeerJwksFetcher>,
        interval: Duration,
    ) -> Self {
        Self {
            store,
            cache,
            fetcher,
            interval,
            page_size: DEFAULT_REFRESH_PAGE_SIZE,
        }
    }

    pub fn cache(&self) -> Arc<InMemoryPeerJwksCache> {
        self.cache.clone()
    }

    /// Run one refresh cycle. Iterates the store in pages,
    /// fetches each peer, upserts into the cache, then GCs
    /// any cached entry whose peer is no longer in the
    /// store. Per-peer fetch failures are *not* fatal — the
    /// previous cache entry (if any) is retained so a
    /// flapping peer doesn't blank-out signatures we
    /// already trusted.
    pub async fn refresh_once(&self) -> RefreshSummary {
        let mut summary = RefreshSummary::default();
        let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
        let mut offset: u32 = 0;
        loop {
            let page = match self
                .store
                .list_all_for_refresh(self.page_size, offset)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        offset,
                        "peer jwks refresher: store paging failed; aborting cycle",
                    );
                    return summary;
                }
            };
            if page.is_empty() {
                break;
            }
            for peer in &page {
                summary.total += 1;
                seen.insert(peer.id);
                // Snapshot the cache generation BEFORE the
                // async fetch. Admin PATCH/DELETE bumps the
                // generation when it invalidates; if our
                // generation no longer matches at upsert
                // time, the row was mutated while we were
                // fetching and the upsert is silently
                // discarded — the next refresh cycle starts
                // clean with the new jwks_url. Without this
                // fence, an in-flight refresh that started
                // against the OLD jwks_url could re-insert
                // the OLD keys AFTER admin invalidation,
                // leaving the compromised key trusted
                // indefinitely.
                let gen_snapshot = self.cache.generation(peer.id);
                match self.fetcher.fetch(&peer.jwks_url).await {
                    Ok(keys) => {
                        let landed = self.cache.try_upsert_at_gen(
                            CachedJwks {
                                peer_id: peer.id,
                                tenant_id: peer.tenant_id.clone(),
                                issuer: peer.issuer.clone(),
                                trust_tier: peer.trust_tier,
                                keys,
                                fetched_at: OffsetDateTime::now_utc(),
                            },
                            gen_snapshot,
                        );
                        if landed {
                            summary.ok += 1;
                            tracing::debug!(
                                peer_id = %peer.id,
                                peer_name = %peer.peer_name,
                                tenant_id = %peer.tenant_id,
                                issuer = %peer.issuer,
                                "peer jwks refreshed",
                            );
                        } else {
                            // Counts as a failure for
                            // summary purposes — the operator
                            // sees this in metrics and can
                            // confirm the eviction worked.
                            summary.failed += 1;
                            tracing::info!(
                                peer_id = %peer.id,
                                peer_name = %peer.peer_name,
                                "peer jwks refresh raced with admin mutation; discarding stale fetch result",
                            );
                        }
                    }
                    Err(e) => {
                        let outcome = e.outcome();
                        summary.failed += 1;
                        summary.failures.push(RefreshFailure {
                            peer_id: peer.id,
                            peer_name: peer.peer_name.clone(),
                            outcome,
                            message: e.to_string(),
                        });
                        tracing::warn!(
                            peer_id = %peer.id,
                            peer_name = %peer.peer_name,
                            tenant_id = %peer.tenant_id,
                            outcome = outcome.as_str(),
                            error = %e,
                            "peer jwks fetch failed; retaining previous cache entry if any",
                        );
                    }
                }
            }
            if (page.len() as u32) < self.page_size {
                break;
            }
            offset = offset.saturating_add(self.page_size);
        }

        // GC cached entries for peers no longer in the
        // store. Without this, a peer removed via the
        // admin REST surface would keep verifying
        // assertions until the process restarted.
        for cached_id in self.cache.known_peer_ids() {
            if !seen.contains(&cached_id) && self.cache.forget(cached_id) {
                summary.gc += 1;
                tracing::info!(
                    peer_id = %cached_id,
                    "peer jwks evicted (peer row no longer in store)",
                );
            }
        }

        summary
    }

    /// Run the refresh loop forever. Spawn this on a
    /// dedicated tokio task — it never returns.
    pub async fn run(self) -> ! {
        // Eager refresh on startup so the cache is non-empty
        // by the time the first request hits the peer JWT
        // verifier. Subsequent cycles tick on the interval.
        loop {
            let _summary = self.refresh_once().await;
            tokio::time::sleep(self.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_https_accepted() {
        let u = validate_jwks_url("https://gw.acme.example/jwks.json").unwrap();
        assert_eq!(u.scheme(), "https");
    }

    #[test]
    fn validate_http_loopback_accepted() {
        for url in [
            "http://localhost/jwks",
            "http://LOCALHOST/jwks",
            "http://127.0.0.1/jwks",
            "http://127.0.0.1:8080/jwks",
            "http://[::1]/jwks",
        ] {
            validate_jwks_url(url)
                .unwrap_or_else(|_| panic!("loopback url should be accepted: {url}"));
        }
    }

    #[test]
    fn validate_http_remote_rejected() {
        for url in [
            "http://gw.acme.example/jwks.json",
            "http://10.0.0.1/jwks",
            "http://192.168.1.1/jwks",
            "http://example.com/jwks",
        ] {
            let err = validate_jwks_url(url).unwrap_err();
            assert!(
                matches!(err, JwksFetchError::SchemeRejected { .. }),
                "non-loopback http should be rejected: {url}",
            );
        }
    }

    #[test]
    fn validate_other_schemes_rejected() {
        for url in [
            "ftp://example.com/jwks",
            "file:///etc/jwks.json",
            "javascript:alert(1)",
        ] {
            let err = validate_jwks_url(url).unwrap_err();
            assert!(
                matches!(
                    err,
                    JwksFetchError::SchemeRejected { .. } | JwksFetchError::BadUrl(_)
                ),
                "non-http(s) should be rejected: {url} (got {err:?})",
            );
        }
    }

    /// A JWKS document is public by contract, so `user:pass@` credentials
    /// serve no purpose and would be replayed on every background refresh.
    /// The module documents userinfo rejection as part of its safety
    /// envelope; this pins that the validator actually implements it, on the
    /// `https` path and on the `http`-loopback exception alike.
    #[test]
    fn validate_userinfo_rejected() {
        // Distinctive values so the leak check cannot be satisfied by the
        // message's own illustrative `user:pass@` text.
        // Every userinfo shape (full, username-only, password-only) on BOTH the
        // https path and the http-loopback exception, so neither arm can regain
        // the credential-carrying form on its own.
        for url in [
            "https://alicename:s3cr3tv4lue@gw.acme.example/jwks.json",
            "https://alicename@gw.acme.example/jwks.json",
            "https://:s3cr3tv4lue@gw.acme.example/jwks.json",
            "http://alicename:s3cr3tv4lue@localhost/jwks",
            "http://alicename@localhost/jwks",
            "http://:s3cr3tv4lue@localhost/jwks",
            "http://alicename:s3cr3tv4lue@127.0.0.1:8080/jwks",
            "http://alicename@127.0.0.1:8080/jwks",
            "http://:s3cr3tv4lue@[::1]/jwks",
        ] {
            let err = validate_jwks_url(url).unwrap_err();
            assert!(
                matches!(err, JwksFetchError::UserinfoRejected),
                "userinfo must be refused, not sanitized: {url} (got {err:?})",
            );
            let msg = format!("{err}");
            for secret in [
                "s3cr3tv4lue",
                "alicename",
                "gw.acme.example",
                "localhost",
                "127.0.0.1",
                "::1",
            ] {
                assert!(
                    !msg.contains(secret),
                    "the refusal must not echo `{secret}` from {url}; got `{msg}`",
                );
            }
        }
    }

    #[test]
    fn scheme_rejected_display_does_not_echo_url_bytes() {
        // Log-exposure hardening: a peer JWKS URL MAY carry
        // `https://user:pass@host/...`. The fetcher must
        // never log those bytes; the {peer_id, peer_name,
        // tenant_id} tracing fields already identify the
        // failing peer. Pin the contract on the Display impl
        // so a future refactor that embeds `jwks_url` back
        // into the message would fail here instead of
        // silently leaking creds to logs.
        let err = validate_jwks_url("ftp://USER:PASS@evil.example/jwks").unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains("USER:PASS"),
            "scheme rejected message must not echo userinfo; got `{msg}`",
        );
        assert!(
            !msg.contains("evil.example"),
            "scheme rejected message must not echo host; got `{msg}`",
        );
    }

    #[test]
    fn validate_malformed_url_is_bad_url() {
        let err = validate_jwks_url("not a url at all").unwrap_err();
        assert!(matches!(err, JwksFetchError::BadUrl(_)));
    }

    #[tokio::test]
    async fn cache_upsert_then_get_by_issuer_returns_arc() {
        let cache = InMemoryPeerJwksCache::new();
        let peer_id = Uuid::new_v4();
        cache.upsert(CachedJwks {
            peer_id,
            tenant_id: "t1".into(),
            issuer: "https://gw.example".into(),
            trust_tier: TrustTier::Restricted,
            keys: JwkSet { keys: vec![] },
            fetched_at: OffsetDateTime::now_utc(),
        });
        let by_iss = cache.get_by_issuer("https://gw.example").await;
        assert_eq!(by_iss.len(), 1);
        assert_eq!(by_iss[0].peer_id, peer_id);
        let by_id = cache.get_by_peer_id(peer_id).await.unwrap();
        assert_eq!(by_id.tenant_id, "t1");
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn cache_get_by_issuer_returns_all_tenant_matches() {
        // The migration's UNIQUE(tenant_id, issuer) means
        // two tenants CAN register the same issuer string.
        // The verifier needs to see both entries to pick
        // the right one — pin that.
        let cache = InMemoryPeerJwksCache::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        cache.upsert(CachedJwks {
            peer_id: a,
            tenant_id: "t1".into(),
            issuer: "https://shared.example".into(),
            trust_tier: TrustTier::Full,
            keys: JwkSet { keys: vec![] },
            fetched_at: OffsetDateTime::now_utc(),
        });
        cache.upsert(CachedJwks {
            peer_id: b,
            tenant_id: "t2".into(),
            issuer: "https://shared.example".into(),
            trust_tier: TrustTier::Restricted,
            keys: JwkSet { keys: vec![] },
            fetched_at: OffsetDateTime::now_utc(),
        });
        let hits = cache.get_by_issuer("https://shared.example").await;
        assert_eq!(hits.len(), 2);
        let tenants: std::collections::BTreeSet<&str> =
            hits.iter().map(|c| c.tenant_id.as_str()).collect();
        assert_eq!(
            tenants.into_iter().collect::<Vec<_>>(),
            vec!["t1", "t2"],
            "both tenant entries must surface",
        );
    }

    #[tokio::test]
    async fn cache_forget_drops_entry() {
        let cache = InMemoryPeerJwksCache::new();
        let id = Uuid::new_v4();
        cache.upsert(CachedJwks {
            peer_id: id,
            tenant_id: "t".into(),
            issuer: "https://x".into(),
            trust_tier: TrustTier::Restricted,
            keys: JwkSet { keys: vec![] },
            fetched_at: OffsetDateTime::now_utc(),
        });
        assert!(cache.forget(id));
        assert!(cache.get_by_peer_id(id).await.is_none());
        assert_eq!(cache.len().await, 0);
        // Idempotent — second forget is a no-op.
        assert!(!cache.forget(id));
    }

    #[test]
    fn fetch_outcome_strings_are_stable() {
        // Pin the strings — they're emitted in logs and any
        // future metrics labels. Renames are breaking.
        assert_eq!(FetchOutcome::Success.as_str(), "success");
        assert_eq!(FetchOutcome::SchemeRejected.as_str(), "scheme_rejected");
        assert_eq!(FetchOutcome::BadUrl.as_str(), "bad_url");
        assert_eq!(FetchOutcome::HttpError.as_str(), "http_error");
        assert_eq!(FetchOutcome::BodyTooLarge.as_str(), "body_too_large");
        assert_eq!(FetchOutcome::ParseError.as_str(), "parse_error");
    }

    fn cached_entry(peer_id: Uuid, issuer: &str) -> CachedJwks {
        CachedJwks {
            peer_id,
            tenant_id: "tenant-a".into(),
            issuer: issuer.into(),
            trust_tier: TrustTier::Full,
            keys: JwkSet { keys: vec![] },
            fetched_at: OffsetDateTime::now_utc(),
        }
    }

    /// The per-peer generation counter must fence an
    /// in-flight refresher fetch from re-inserting stale keys
    /// after admin `invalidate` (== `forget`) ran. Pin the
    /// contract:
    /// 1. refresher reads gen at fetch start
    /// 2. admin invalidates, bumping gen
    /// 3. refresher's post-fetch try_upsert returns false
    ///    and the cache stays empty
    #[tokio::test]
    async fn try_upsert_at_gen_fences_in_flight_refresh() {
        let cache = InMemoryPeerJwksCache::new();
        let peer = Uuid::new_v4();

        // Step 1: refresher snapshots the generation BEFORE
        // its async fetch.
        let gen_at_fetch_start = cache.generation(peer);
        assert_eq!(gen_at_fetch_start, 0, "never-seen peer starts at gen 0");

        // Step 2: while the refresher is fetching, admin
        // PATCH/DELETE runs `invalidate` (delegated to
        // `forget`). The peer wasn't in the cache yet, so
        // `forget` returns false, but the generation MUST
        // still bump so a subsequent in-flight upsert is
        // fenced.
        let existed = cache.forget(peer);
        assert!(
            !existed,
            "forget on never-cached peer returns false (entry absent) but still bumps gen",
        );
        assert_eq!(
            cache.generation(peer),
            1,
            "forget bumped gen even without entry"
        );

        // Step 3: refresher's fetch completes and tries to
        // upsert with its stale gen snapshot. Must fail.
        let landed = cache.try_upsert_at_gen(
            cached_entry(peer, "https://peer.example/"),
            gen_at_fetch_start,
        );
        assert!(!landed, "stale upsert must be rejected");
        assert!(
            cache.get_by_peer_id(peer).await.is_none(),
            "cache must NOT contain the stale entry the refresher tried to insert",
        );
    }

    /// Pin the happy path: when no admin mutation races,
    /// `try_upsert_at_gen` with the matching snapshot does
    /// land the entry.
    #[tokio::test]
    async fn try_upsert_at_gen_succeeds_when_no_mutation() {
        let cache = InMemoryPeerJwksCache::new();
        let peer = Uuid::new_v4();
        let gen_at_fetch_start = cache.generation(peer);
        let landed = cache.try_upsert_at_gen(
            cached_entry(peer, "https://peer.example/"),
            gen_at_fetch_start,
        );
        assert!(landed);
        assert_eq!(cache.len().await, 1);
    }

    /// Same fence after the peer was already cached and the
    /// admin invalidates. Refresher's pre-fetch gen is 0,
    /// admin bumps to 1, refresher's upsert is rejected.
    #[tokio::test]
    async fn try_upsert_at_gen_fences_after_cached_entry_invalidated() {
        let cache = InMemoryPeerJwksCache::new();
        let peer = Uuid::new_v4();
        // Bootstrap: a prior refresh landed an entry.
        cache.upsert(cached_entry(peer, "https://peer.example/"));
        assert_eq!(cache.len().await, 1);

        let gen_at_fetch_start = cache.generation(peer);
        // Admin PATCH bumps the issuer; invalidates the cache.
        assert!(cache.forget(peer));
        assert!(cache.is_empty().await);

        // Refresher (in flight against the OLD jwks_url)
        // tries to upsert. Must be discarded.
        let landed = cache.try_upsert_at_gen(
            cached_entry(peer, "https://OLD.example/"),
            gen_at_fetch_start,
        );
        assert!(!landed);
        assert!(cache.is_empty().await);
    }
}
