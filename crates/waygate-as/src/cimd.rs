//! Client ID Metadata Document fetcher.
//!
//! When an MCP client presents an HTTPS URL as its `client_id`, the gateway
//! fetches a JSON document from that URL describing the client
//! (`redirect_uris`, `token_endpoint_auth_method`, etc.). See
//! draft-parecki-oauth-client-id-metadata-document.
//!
//! Security surface:
//! * HTTPS only.
//! * DNS resolution validated against [`is_public_ip`], the shared
//!   outbound-destination classifier. Anything not globally routable
//!   unicast is refused: loopback, RFC 1918 private, link-local (so cloud
//!   metadata at 169.254.169.254), broadcast, multicast, unspecified,
//!   RFC 5737 documentation, RFC 6598 shared (CGNAT), 0.0.0.0/8, the
//!   192.0.0.0/24 protocol assignments, the 198.18.0.0/15 benchmarking
//!   block and RFC 1112 reserved (240/4); for v6, loopback, unspecified,
//!   multicast, fc00::/7 ULA, fe80::/10 link-local, fec0::/10 deprecated
//!   site-local, 2001:db8::/32 documentation and the other non-public
//!   IETF assignments. Every form that embeds an IPv4 target is
//!   unwrapped and re-checked as v4, or rejected outright: IPv4-mapped
//!   ::ffff:0:0/96, IPv4-compatible ::/96, NAT64 64:ff9b::/96 and
//!   64:ff9b:1::/48, and 6to4 2002::/16 — so a AAAA record naming an
//!   internal address through a translation prefix cannot slip past.
//! * DNS pinning: reqwest is configured to connect to the exact resolved IP
//!   so a second lookup can't redirect to an internal address (rebinding).
//! * No redirects followed.
//! * Response capped at 5 KiB, enforced during the read (advertised
//!   over-length refused before draining; streaming counter otherwise) so a
//!   chunked or lying peer cannot buffer past the cap.
//! * 10-second timeout.
//! * `client_id` inside the doc MUST equal the fetch URL.
//! * Cached with full HTTP-cache semantics (ETag / Last-Modified / max-age),
//!   fallback TTL 1h, `no-store` disables caching.
//!
//! Same-origin shortcut: when the fetch URL is same-origin with the AS's
//! own public URL AND matches our on-disk dev-doc registry
//! (`/cimd/dev-clients/<safe>.json` under [`AsConfig::cimd_dev_doc_dir`]),
//! we read the file directly instead of issuing an HTTP request. This is
//! NOT the draft-ietf-oauth-client-id-metadata-document §6.5.1 loopback
//! exemption — that clause only applies when the AS itself is on a
//! loopback address. We're solving a different problem: in a container
//! where the gateway's own public hostname resolves via split-horizon DNS
//! to a LAN address, the SSRF guard would otherwise reject a perfectly
//! legitimate self-served CIMD document. Reading the file we're about to
//! serve to ourselves isn't a URL fetch — it's a local registry lookup,
//! so the SSRF surface doesn't apply. `validate_doc` still runs with the
//! original fetch URL, preserving the `client_id == fetch_url` invariant.
//!
//! Intentional gaps (v1):
//! * `private_key_jwt` clients are rejected — CIMD v1 here is `none` only.
//! * Optional `jwks_uri` is stored but not SSRF-validated until we need it
//!   (no `private_key_jwt` path).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Origin, Url};

use crate::cimd_dev_host::is_safe_filename;
use waygate_core::http_client::{self, Profile};
use waygate_core::net::is_public_ip;

/// Parsed CIMD document. Only fields we consume are typed — everything else is
/// ignored (`#[serde(default)]` on the whole struct would hide typos in the
/// doc; we'd rather surface unknown fields as "ignored" and parse errors as
/// "broken doc").
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CimdDocument {
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_auth_method")]
    pub token_endpoint_auth_method: String,
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<String>,
    #[serde(default = "default_response_types")]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
    #[serde(default)]
    pub software_id: Option<String>,
    #[serde(default)]
    pub software_version: Option<String>,
}

fn default_auth_method() -> String {
    "none".into()
}
fn default_grant_types() -> Vec<String> {
    vec!["authorization_code".into()]
}
fn default_response_types() -> Vec<String> {
    vec!["code".into()]
}

#[derive(Debug, Error)]
pub enum CimdError {
    #[error("client_id is not a valid URL: {0}")]
    InvalidUrl(String),
    #[error("client_id must be HTTPS (got `{0}`)")]
    NotHttps(String),
    #[error("client_id must have a host")]
    NoHost,
    #[error("client_id must have a non-root path (CIMD is not served at `/`)")]
    RootPath,
    #[error("CIMD host `{0}` not in allow-list")]
    HostNotAllowed(String),
    #[error("DNS resolution failed: {0}")]
    Dns(String),
    #[error("URL resolves to non-public IP {0}")]
    BlockedIp(IpAddr),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("upstream returned status {0}")]
    Status(u16),
    #[error("response too large (limit {limit} bytes)")]
    TooLarge { limit: usize },
    #[error("JSON parse: {0}")]
    Json(String),
    #[error("client_id in document (`{in_doc}`) does not match fetch URL (`{fetch_url}`)")]
    ClientIdMismatch { in_doc: String, fetch_url: String },
    #[error("redirect_uris must be non-empty")]
    NoRedirectUris,
    #[error(
        "token_endpoint_auth_method must be `none` (got `{0}`); \
         shared-secret methods not allowed for CIMD"
    )]
    UnsupportedAuthMethod(String),
    #[error("not a CIMD client_id")]
    NotCimd,
}

const MAX_BODY: usize = 5 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Parsed cache directives from the upstream response.
#[derive(Debug, Clone)]
struct CachePolicy {
    etag: Option<String>,
    last_modified: Option<String>,
    expires_at: Instant,
    no_store: bool,
    must_revalidate: bool,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    doc: CimdDocument,
    policy: CachePolicy,
}

/// CIMD fetcher. Single instance lives for the life of the process.
pub struct CimdFetcher {
    cache: Cache<String, CacheEntry>,
    allowed_hosts: Option<Vec<String>>,
    /// AS's own public-URL origin. When a fetch target has a matching
    /// origin and the path is under our dev-doc registry, we read the
    /// document from disk instead of HTTP-fetching it. See the crate-
    /// level docs for the rationale.
    self_origin: Option<Origin>,
    /// Directory of on-disk dev CIMD documents, mirrored from
    /// [`AsConfig::cimd_dev_doc_dir`]. `None` disables the shortcut.
    dev_doc_dir: Option<PathBuf>,
}

impl CimdFetcher {
    pub fn new(
        allowed_hosts: Option<Vec<String>>,
        self_origin: Option<Origin>,
        dev_doc_dir: Option<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cache: Cache::builder()
                .max_capacity(1024)
                // Hard upper bound even if a doc says `max-age: 31536000`.
                .time_to_live(Duration::from_secs(24 * 3600))
                .build(),
            allowed_hosts: allowed_hosts.map(|v| v.into_iter().map(|s| s.to_lowercase()).collect()),
            self_origin,
            dev_doc_dir,
        })
    }

    /// Returns `true` if `host` (case-insensitive) is acceptable per the
    /// configured allowlist, or unconditionally if no allowlist is set.
    ///
    /// Extracted from the inline `fetch` check so unit tests can exercise
    /// the allowlist gate without DNS-resolving anything — passing the
    /// gate previously required `fetch` to fail downstream (typically
    /// in DNS) for the assertion to fire, which made the test
    /// dependent on external resolver timing.
    pub(crate) fn host_allowed(&self, host: &str) -> bool {
        match &self.allowed_hosts {
            None => true,
            Some(list) => {
                let host = host.to_ascii_lowercase();
                list.iter().any(|h| h == &host)
            }
        }
    }

    /// Returns `true` if `client_id` is a CIMD URL (HTTPS, host, non-root path).
    pub fn is_cimd_client_id(client_id: &str) -> bool {
        let Ok(url) = Url::parse(client_id) else {
            return false;
        };
        url.scheme() == "https" && url.host_str().is_some() && !matches!(url.path(), "" | "/")
    }

    /// If `url` is same-origin with the AS's own public URL AND the path
    /// names a file under our on-disk dev-doc registry, return that path.
    /// The caller reads it in place of issuing an HTTP request. See the
    /// crate-level docs for why this isn't an SSRF bypass.
    fn local_doc_path(&self, url: &Url) -> Option<PathBuf> {
        let dir = self.dev_doc_dir.as_ref()?;
        let self_origin = self.self_origin.as_ref()?;
        if url.origin() != *self_origin {
            return None;
        }
        let rest = url.path().strip_prefix("/cimd/dev-clients/")?;
        if !is_safe_filename(rest) {
            return None;
        }
        Some(dir.join(rest))
    }

    /// Fetch and validate a CIMD document. Returns the cached copy if fresh.
    pub async fn fetch(&self, client_id_url: &str) -> Result<CimdDocument, CimdError> {
        let url = Url::parse(client_id_url)
            .map_err(|e| CimdError::InvalidUrl(format!("{client_id_url}: {e}")))?;
        if url.scheme() != "https" {
            return Err(CimdError::NotHttps(url.scheme().into()));
        }
        let host = url.host_str().ok_or(CimdError::NoHost)?.to_lowercase();
        if matches!(url.path(), "" | "/") {
            return Err(CimdError::RootPath);
        }
        if !self.host_allowed(&host) {
            return Err(CimdError::HostNotAllowed(host));
        }

        // Same-origin shortcut: read the on-disk doc directly. Skip the
        // cache and the HTTP path entirely — filesystem reads are cheap
        // and we'd rather operators see `touch` take effect immediately.
        if let Some(local_path) = self.local_doc_path(&url) {
            let doc = read_local_cimd(&local_path).await?;
            validate_doc(&doc, client_id_url)?;
            return Ok(doc);
        }

        let now = Instant::now();
        let cached = self.cache.get(client_id_url).await;

        if let Some(entry) = &cached {
            if !entry.policy.must_revalidate && now < entry.policy.expires_at {
                return Ok(entry.doc.clone());
            }
        }

        let fetched = fetch_with_ssrf_guard(&url, cached.as_ref()).await?;

        match fetched {
            FetchOutcome::NotModified(headers) => {
                let entry = cached.ok_or_else(|| {
                    CimdError::Http("304 Not Modified without cached document".into())
                })?;
                let policy = merge_policy_on_304(&entry.policy, &headers, Instant::now());
                if !policy.no_store {
                    self.cache
                        .insert(
                            client_id_url.to_owned(),
                            CacheEntry {
                                doc: entry.doc.clone(),
                                policy,
                            },
                        )
                        .await;
                } else {
                    self.cache.invalidate(client_id_url).await;
                }
                Ok(entry.doc)
            }
            FetchOutcome::Fresh { body, headers } => {
                let doc: CimdDocument =
                    serde_json::from_slice(&body).map_err(|e| CimdError::Json(e.to_string()))?;
                validate_doc(&doc, client_id_url)?;
                let policy = parse_policy(&headers, Instant::now());
                if !policy.no_store {
                    self.cache
                        .insert(
                            client_id_url.to_owned(),
                            CacheEntry {
                                doc: doc.clone(),
                                policy,
                            },
                        )
                        .await;
                }
                Ok(doc)
            }
        }
    }

    /// Validate a redirect URI against a CIMD document. See
    /// [`match_redirect_uri`] for pattern semantics.
    pub fn validate_redirect_uri(&self, doc: &CimdDocument, redirect_uri: &str) -> bool {
        doc.redirect_uris
            .iter()
            .any(|pat| match_redirect_uri(redirect_uri, pat))
    }
}

fn validate_doc(doc: &CimdDocument, fetch_url: &str) -> Result<(), CimdError> {
    if doc.redirect_uris.is_empty() {
        return Err(CimdError::NoRedirectUris);
    }
    // v1 clients must use PKCE-only (no shared secret). `private_key_jwt` is
    // in the spec but our token endpoint doesn't implement client_assertion.
    if doc.token_endpoint_auth_method != "none" {
        return Err(CimdError::UnsupportedAuthMethod(
            doc.token_endpoint_auth_method.clone(),
        ));
    }
    let in_doc = doc.client_id.trim_end_matches('/');
    let fetched = fetch_url.trim_end_matches('/');
    if in_doc != fetched {
        return Err(CimdError::ClientIdMismatch {
            in_doc: doc.client_id.clone(),
            fetch_url: fetch_url.to_owned(),
        });
    }
    Ok(())
}

enum FetchOutcome {
    Fresh {
        body: Vec<u8>,
        headers: reqwest::header::HeaderMap,
    },
    NotModified(reqwest::header::HeaderMap),
}

async fn read_local_cimd(path: &std::path::Path) -> Result<CimdDocument, CimdError> {
    // Stat first so we can reject oversized docs without buffering them, and
    // so we can surface a consistent NotFound mapping that's independent of
    // platform errno text.
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CimdError::Status(404),
            _ => CimdError::Http(format!("local CIMD metadata: {e}")),
        })?;
    if !meta.is_file() {
        return Err(CimdError::Status(404));
    }
    if meta.len() > MAX_BODY as u64 {
        return Err(CimdError::TooLarge { limit: MAX_BODY });
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| CimdError::Http(format!("local CIMD read: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| CimdError::Json(e.to_string()))
}

async fn fetch_with_ssrf_guard(
    url: &Url,
    cached: Option<&CacheEntry>,
) -> Result<FetchOutcome, CimdError> {
    let host = url.host_str().ok_or(CimdError::NoHost)?.to_owned();
    let port = url.port().unwrap_or(443);
    let ips = resolve_and_validate(&host, port).await?;
    let client = build_pinned_client(&host, port, &ips)?;
    issue_cimd_request(&client, url, cached).await
}

/// Build the SSRF-guarded HTTP client used to fetch a CIMD document. Split
/// out from [`fetch_with_ssrf_guard`] so tests can exercise the
/// request/response decoding path against a plain loopback client without
/// having to spoof `is_public_ip`.
fn build_pinned_client(
    host: &str,
    port: u16,
    ips: &[IpAddr],
) -> Result<reqwest::Client, CimdError> {
    let mut builder = http_client::builder(Profile::Custom(FETCH_TIMEOUT))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("waygate-as/", env!("CARGO_PKG_VERSION")));

    // DNS pinning: reqwest short-circuits DNS and connects to the exact
    // resolved socket address, so a rebinding second lookup can't flip us
    // onto an internal target.
    for ip in ips {
        builder = builder.resolve(host, SocketAddr::new(*ip, port));
    }
    builder
        .build()
        .map_err(|e| CimdError::Http(format!("reqwest build: {e}")))
}

/// Issue the CIMD GET and decode the response into a [`FetchOutcome`].
/// Conditional-request headers (`If-None-Match`, `If-Modified-Since`) come
/// from `cached`. The `MAX_BODY` cap is enforced DURING the read: an
/// advertised `Content-Length` over the cap is refused before a byte is
/// drained, and the body is otherwise streamed with a running counter. It is
/// deliberately not a post-read length comparison — that buffers the whole
/// body first, so a peer omitting or understating `Content-Length` allocates
/// without bound before being refused.
async fn issue_cimd_request(
    client: &reqwest::Client,
    url: &Url,
    cached: Option<&CacheEntry>,
) -> Result<FetchOutcome, CimdError> {
    let mut req = client.get(url.as_str());
    if let Some(entry) = cached {
        if let Some(etag) = &entry.policy.etag {
            if let Ok(v) = HeaderValue::from_str(etag) {
                req = req.header(reqwest::header::IF_NONE_MATCH, v);
            }
        }
        if let Some(lm) = &entry.policy.last_modified {
            if let Ok(v) = HeaderValue::from_str(lm) {
                req = req.header(reqwest::header::IF_MODIFIED_SINCE, v);
            }
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| CimdError::Http(e.to_string()))?;

    let status = resp.status();
    let headers = resp.headers().clone();

    if status.as_u16() == 304 {
        return Ok(FetchOutcome::NotModified(headers));
    }
    if !status.is_success() {
        return Err(CimdError::Status(status.as_u16()));
    }

    // The size check has to happen DURING the read, not after it. Comparing
    // `resp.bytes().await` against the cap buffers the whole body first, so a
    // peer that omits or understates Content-Length — trivial with chunked
    // encoding — gets to allocate without bound before being refused. The
    // shared reader refuses an advertised over-length response before draining
    // a byte and otherwise streams with a running counter.
    let bytes = waygate_core::http_client::read_body_capped(resp, MAX_BODY)
        .await
        .map_err(|e| match e {
            waygate_core::http_client::ReadBodyError::Http(e) => CimdError::Http(e.to_string()),
            waygate_core::http_client::ReadBodyError::TooLarge(_) => {
                CimdError::TooLarge { limit: MAX_BODY }
            }
        })?;

    Ok(FetchOutcome::Fresh {
        body: bytes,
        headers,
    })
}

async fn resolve_and_validate(host: &str, port: u16) -> Result<Vec<IpAddr>, CimdError> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| CimdError::Dns(e.to_string()))?;
    let mut ips = Vec::new();
    for a in addrs {
        let ip = a.ip();
        if !is_public_ip(&ip) {
            return Err(CimdError::BlockedIp(ip));
        }
        ips.push(ip);
    }
    if ips.is_empty() {
        return Err(CimdError::Dns(format!("no addresses for {host}")));
    }
    Ok(ips)
}

fn parse_policy(headers: &reqwest::header::HeaderMap, now: Instant) -> CachePolicy {
    let cache_control = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut max_age: Option<u64> = None;
    let mut no_store = false;
    let mut must_revalidate = false;
    for part in cache_control.split(',') {
        let directive = part.trim().to_ascii_lowercase();
        if directive == "no-store" {
            no_store = true;
        } else if directive == "no-cache" {
            must_revalidate = true;
        } else if let Some(v) = directive.strip_prefix("max-age=") {
            if let Ok(secs) = v.trim().parse::<u64>() {
                max_age = Some(secs);
            }
        }
    }
    let ttl = match max_age {
        Some(0) => Duration::ZERO,
        Some(s) => Duration::from_secs(s),
        None => DEFAULT_CACHE_TTL,
    };
    let expires_at = now + ttl;

    CachePolicy {
        etag: headers
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        last_modified: headers
            .get(HeaderName::from_static("last-modified"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        expires_at,
        no_store,
        must_revalidate,
    }
}

/// Per RFC 7234 §4.3.4, a 304 may omit unchanged headers; preserve the
/// existing freshness window rather than fall back to the default TTL.
fn merge_policy_on_304(
    prev: &CachePolicy,
    headers: &reqwest::header::HeaderMap,
    now: Instant,
) -> CachePolicy {
    let has_freshness = headers.contains_key(reqwest::header::CACHE_CONTROL)
        || headers.contains_key(reqwest::header::EXPIRES);
    if has_freshness {
        let mut fresh = parse_policy(headers, now);
        if fresh.etag.is_none() {
            fresh.etag = prev.etag.clone();
        }
        if fresh.last_modified.is_none() {
            fresh.last_modified = prev.last_modified.clone();
        }
        fresh
    } else {
        let remaining = prev
            .expires_at
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        CachePolicy {
            etag: prev.etag.clone(),
            last_modified: prev.last_modified.clone(),
            expires_at: now + remaining.max(Duration::from_secs(30)),
            no_store: false,
            must_revalidate: prev.must_revalidate,
        }
    }
}

/// Match a concrete `redirect_uri` against a CIMD pattern. Components
/// compared individually to avoid naive-string bypasses like
/// `http://localhost@evil/cb`.
///
/// Patterns support:
/// * `http://localhost:*` — any port on a loopback host (RFC 8252 §7.3).
/// * `http://127.0.0.1:*`, `http://[::1]:*` — same.
/// * Exact host/port match otherwise.
/// * Path fnmatch-style: `*` matches any chars including `/`, but the URI
///   is rejected if its path contains dot-segments (`.` / `..`) —
///   post-redirect path traversal defense.
/// * Query component must match exactly. A pattern with no `?…` only
///   matches URIs with no query. A pattern with `?foo=1` matches only
///   the literal string `foo=1` — no wildcarding, no extra params.
/// * Fragments are rejected in both pattern and URI (RFC 6749 §3.1.2).
pub fn match_redirect_uri(uri: &str, pattern: &str) -> bool {
    // Pattern cannot be parsed with `url::Url` (a `*` port breaks it); use
    // a hand-rolled parser that understands `:*` as a wildcard.
    let Some(pat) = PatternParts::parse(pattern) else {
        return false;
    };
    let Ok(u) = Url::parse(uri) else {
        return false;
    };

    // Reject userinfo on the incoming URI (userinfo-bypass defense).
    if !u.username().is_empty() || u.password().is_some() {
        return false;
    }

    // RFC 6749 §3.1.2: the redirect URI MUST NOT include a fragment. We
    // rely on this both for spec compliance and because `build_redirect`
    // appends `?code=` by string concat; a fragment would swallow the
    // code. `u.fragment()` returns `Some("")` even for a bare trailing
    // `#`, so treat any Some as a reject.
    if u.fragment().is_some() {
        return false;
    }

    if path_has_dot_segments(u.path()) {
        return false;
    }

    if !u.scheme().eq_ignore_ascii_case(&pat.scheme) {
        return false;
    }

    let u_host = u.host_str().unwrap_or("").to_ascii_lowercase();
    if u_host != pat.host {
        return false;
    }

    let is_loopback = matches!(u_host.as_str(), "localhost" | "127.0.0.1" | "::1");

    let port_ok = match &pat.port {
        PatternPort::Wildcard => true,
        PatternPort::Explicit(p) => u.port_or_known_default() == Some(*p),
        PatternPort::Default => {
            if is_loopback {
                true
            } else {
                u.port_or_known_default() == default_port_for_scheme(&pat.scheme)
            }
        }
    };
    if !port_ok {
        return false;
    }

    if !fnmatch_path(u.path(), &pat.path) {
        return false;
    }

    // Exact-equality on query: `None == None`, or `Some(a) == Some(b)`
    // with byte-for-byte equality. No wildcarding, no subset rules. The
    // OAuth 2.1 security BCP (RFC 9700 §2.1) requires exact match on
    // non-wildcarded redirect-URI components, and this is the one
    // component our pattern language doesn't wildcard.
    u.query() == pat.query.as_deref()
}

/// A CIMD `redirect_uris` pattern broken into components. Exists because
/// `url::Url` can't parse `http://localhost:*/cb`.
///
/// `query` is `None` when the pattern carries no `?…` component and is
/// compared as exact-equality against the incoming URI's `u.query()`.
/// Fragments are not stored — RFC 6749 §3.1.2 forbids them in the
/// redirect URI, so any pattern containing `#` is rejected at parse
/// time and any incoming URI with `#` is rejected at match time.
struct PatternParts {
    scheme: String,
    host: String,
    port: PatternPort,
    path: String,
    query: Option<String>,
}

enum PatternPort {
    /// No port in the pattern.
    Default,
    /// `:*` — matches any port.
    Wildcard,
    /// Explicit numeric port.
    Explicit(u16),
}

impl PatternParts {
    fn parse(pattern: &str) -> Option<Self> {
        // Fragments are forbidden in redirect URIs per RFC 6749 §3.1.2 —
        // reject outright rather than silently strip.
        if pattern.contains('#') {
            return None;
        }
        let (scheme, rest) = pattern.split_once("://")?;
        if scheme.is_empty() {
            return None;
        }
        let (authority, path_and_query) = match rest.find(['/', '?']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(rest6) = host_port.strip_prefix('[') {
            let end = rest6.find(']')?;
            let host = &rest6[..end];
            let after = &rest6[end + 1..];
            let port = if let Some(raw) = after.strip_prefix(':') {
                parse_pattern_port(raw)?
            } else {
                PatternPort::Default
            };
            (host.to_ascii_lowercase(), port)
        } else if let Some((h, p)) = host_port.rsplit_once(':') {
            // Guard against IPv6-without-brackets (should already have been
            // caught above, but safety net).
            if h.is_empty() {
                return None;
            }
            (h.to_ascii_lowercase(), parse_pattern_port(p)?)
        } else {
            (host_port.to_ascii_lowercase(), PatternPort::Default)
        };
        let (path_part, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q.to_owned())),
            None => (path_and_query, None),
        };
        let path = if path_part.is_empty() {
            "/".to_owned()
        } else {
            path_part.to_owned()
        };
        Some(Self {
            scheme: scheme.to_ascii_lowercase(),
            host,
            port,
            path,
            query,
        })
    }
}

fn parse_pattern_port(s: &str) -> Option<PatternPort> {
    if s == "*" {
        Some(PatternPort::Wildcard)
    } else {
        s.parse::<u16>().ok().map(PatternPort::Explicit)
    }
}

fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

fn path_has_dot_segments(path: &str) -> bool {
    for seg in path.split('/') {
        let lower = seg.to_ascii_lowercase();
        if lower == "." || lower == ".." || lower == "%2e" || lower == "%2e%2e" {
            return true;
        }
    }
    false
}

fn fnmatch_path(path: &str, pattern: &str) -> bool {
    let path = if path.is_empty() { "/" } else { path };
    let pattern = if pattern.is_empty() { "/" } else { pattern };
    // A bare `/` pattern matches any path (makes `http://localhost:*` match
    // `http://localhost:3000/callback` regardless of path).
    if pattern == "/" {
        return true;
    }
    glob_match(pattern, path)
}

fn glob_match(pattern: &str, target: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = target.chars().collect();
    // Iterative DP: O(p*t).
    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;
    for i in 1..=p.len() {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=p.len() {
        for j in 1..=t.len() {
            dp[i][j] = match p[i - 1] {
                '*' => dp[i - 1][j] || dp[i][j - 1],
                '?' => dp[i - 1][j - 1],
                c => c == t[j - 1] && dp[i - 1][j - 1],
            };
        }
    }
    dp[p.len()][t.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[cfg(test)]
    fn raw_test_http_client() -> reqwest::Client {
        reqwest::Client::new() // A raw test client isolates CIMD wire behavior from gateway policy.
    }

    fn origin_of(url: &str) -> Origin {
        Url::parse(url).unwrap().origin()
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "gateway-as-cimd-shortcut-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn local_doc_path_matches_same_origin_dev_host_url() {
        let dir = scratch_dir("match");
        let fetcher = CimdFetcher::new(
            None,
            Some(origin_of("https://gateway.example.com")),
            Some(dir.clone()),
        );
        let url = Url::parse("https://gateway.example.com/cimd/dev-clients/app.json").unwrap();
        assert_eq!(fetcher.local_doc_path(&url), Some(dir.join("app.json")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_doc_path_rejects_cross_origin() {
        let dir = scratch_dir("xorigin");
        let fetcher = CimdFetcher::new(
            None,
            Some(origin_of("https://gateway.example.com")),
            Some(dir.clone()),
        );
        let url = Url::parse("https://evil.example.com/cimd/dev-clients/app.json").unwrap();
        assert!(fetcher.local_doc_path(&url).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_doc_path_rejects_non_dev_host_path() {
        let dir = scratch_dir("badpath");
        let fetcher = CimdFetcher::new(
            None,
            Some(origin_of("https://gateway.example.com")),
            Some(dir.clone()),
        );
        let url = Url::parse("https://gateway.example.com/oauth/authorize").unwrap();
        assert!(fetcher.local_doc_path(&url).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_doc_path_rejects_unsafe_filenames() {
        let dir = scratch_dir("traversal");
        let fetcher = CimdFetcher::new(
            None,
            Some(origin_of("https://gateway.example.com")),
            Some(dir.clone()),
        );
        for bad in [
            "https://gateway.example.com/cimd/dev-clients/..%2Fetc.json",
            "https://gateway.example.com/cimd/dev-clients/.hidden.json",
            "https://gateway.example.com/cimd/dev-clients/app",
            "https://gateway.example.com/cimd/dev-clients/sub/app.json",
        ] {
            let url = Url::parse(bad).unwrap();
            assert!(
                fetcher.local_doc_path(&url).is_none(),
                "expected None for {bad}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_doc_path_disabled_when_dir_unset() {
        let fetcher = CimdFetcher::new(None, Some(origin_of("https://gateway.example.com")), None);
        let url = Url::parse("https://gateway.example.com/cimd/dev-clients/app.json").unwrap();
        assert!(fetcher.local_doc_path(&url).is_none());
    }

    #[tokio::test]
    async fn fetch_reads_local_doc_and_validates_client_id() {
        let dir = scratch_dir("read-ok");
        let doc = serde_json::json!({
            "client_id": "https://gateway.example.com/cimd/dev-clients/app.json",
            "redirect_uris": ["http://localhost:*/callback"],
            "token_endpoint_auth_method": "none",
        });
        std::fs::write(dir.join("app.json"), doc.to_string()).unwrap();

        let fetcher = CimdFetcher::new(
            None,
            Some(origin_of("https://gateway.example.com")),
            Some(dir.clone()),
        );
        let out = fetcher
            .fetch("https://gateway.example.com/cimd/dev-clients/app.json")
            .await
            .expect("local doc fetch");
        assert_eq!(
            out.client_id,
            "https://gateway.example.com/cimd/dev-clients/app.json"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fetch_rejects_local_doc_with_mismatched_client_id() {
        // A dev doc whose `client_id` doesn't match its fetch URL must still
        // be rejected — the same invariant `validate_doc` enforces on the
        // HTTP path applies verbatim to the disk-read path.
        let dir = scratch_dir("read-mismatch");
        let doc = serde_json::json!({
            "client_id": "https://other.example.com/app.json",
            "redirect_uris": ["http://localhost:*/callback"],
            "token_endpoint_auth_method": "none",
        });
        std::fs::write(dir.join("app.json"), doc.to_string()).unwrap();

        let fetcher = CimdFetcher::new(
            None,
            Some(origin_of("https://gateway.example.com")),
            Some(dir.clone()),
        );
        let err = fetcher
            .fetch("https://gateway.example.com/cimd/dev-clients/app.json")
            .await
            .expect_err("should reject mismatched client_id");
        assert!(matches!(err, CimdError::ClientIdMismatch { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_cimd_client_id_detects_https_url_with_path() {
        assert!(CimdFetcher::is_cimd_client_id(
            "https://cli.example.com/claude.json"
        ));
        assert!(!CimdFetcher::is_cimd_client_id("https://cli.example.com/"));
        assert!(!CimdFetcher::is_cimd_client_id(
            "http://cli.example.com/claude.json"
        ));
        assert!(!CimdFetcher::is_cimd_client_id("not-a-url"));
    }

    // SSRF entry-point guards. The classifier itself is covered by
    // `public_ip_classifier_blocks_the_usual_suspects`; these pin the
    // pre-DNS rejections in `CimdFetcher::fetch` so a regression in the
    // scheme/path/allowlist gates shows up immediately rather than
    // requiring DNS-mock plumbing to trigger.

    #[tokio::test]
    async fn fetch_rejects_non_https_scheme() {
        let fetcher = CimdFetcher::new(None, None, None);
        let err = fetcher
            .fetch("http://example.com/client.json")
            .await
            .expect_err("http:// must be rejected before any network IO");
        match err {
            CimdError::NotHttps(scheme) => assert_eq!(scheme, "http"),
            other => panic!("expected NotHttps, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_rejects_root_path() {
        let fetcher = CimdFetcher::new(None, None, None);
        let err = fetcher
            .fetch("https://example.com/")
            .await
            .expect_err("root path must be rejected (no client document there)");
        assert!(matches!(err, CimdError::RootPath), "got: {err:?}");
    }

    #[tokio::test]
    async fn fetch_rejects_host_outside_allowlist() {
        let fetcher = CimdFetcher::new(
            Some(vec!["cli.example.com".into(), "claude.ai".into()]),
            None,
            None,
        );
        let err = fetcher
            .fetch("https://evil.example.com/client.json")
            .await
            .expect_err("host outside allowlist must be rejected before DNS");
        match err {
            CimdError::HostNotAllowed(host) => assert_eq!(host, "evil.example.com"),
            other => panic!("expected HostNotAllowed, got: {other:?}"),
        }
    }

    #[test]
    fn host_allowed_is_case_insensitive() {
        // Allowlist stored lowercased on construction; lookup
        // lowercases the input. Mixed-case input must still match so an
        // operator pinning Capitalized.Example.Com doesn't accidentally
        // lock themselves out. Exercises `host_allowed` directly to
        // stay entirely inside the pre-DNS gate (the previous version
        // relied on fetch() failing DNS to surface the assertion,
        // making it dependent on external resolver timing).
        let fetcher = CimdFetcher::new(Some(vec!["cli.example.com".into()]), None, None);
        assert!(fetcher.host_allowed("cli.example.com"));
        assert!(fetcher.host_allowed("CLI.Example.Com"));
        assert!(fetcher.host_allowed("CLI.EXAMPLE.COM"));
        assert!(!fetcher.host_allowed("evil.example.com"));
    }

    #[test]
    fn host_allowed_no_allowlist_accepts_anything() {
        let fetcher = CimdFetcher::new(None, None, None);
        assert!(fetcher.host_allowed("any.host.example"));
        assert!(fetcher.host_allowed("evil.example.com"));
    }

    /// The CIMD fetch takes its destination policy from the shared classifier
    /// rather than a private copy. The full range contract lives with that
    /// classifier; what matters here is that this surface — the one reached by
    /// a client-supplied `client_id` URL — no longer admits the ranges the
    /// local copy used to let through.
    #[test]
    fn cimd_destination_policy_blocks_ipv6_embedded_and_reserved_targets() {
        // NAT64 and 6to4 wrappers around 127.0.0.1: the old local copy only
        // unwrapped `::ffff:0:0/96`, so these classified public.
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1,
        ))));
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2002, 0, 0, 0, 0, 0, 0, 1,
        ))));
        // Deprecated IPv4-compatible `::127.0.0.1`, which `to_ipv4_mapped`
        // does not recognise.
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0x7f00, 1,
        ))));
        // IPv4 ranges the local copy admitted: protocol assignments and the
        // benchmarking block.
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 8))));
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3))));
        // The everyday cases stay classified as before.
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 1,
        ))));
    }

    #[test]
    fn match_redirect_uri_exact_host() {
        assert!(match_redirect_uri(
            "https://app.example.com/cb",
            "https://app.example.com/cb",
        ));
        assert!(!match_redirect_uri(
            "https://evil.example.com/cb",
            "https://app.example.com/cb",
        ));
    }

    #[test]
    fn match_redirect_uri_loopback_port_wildcard() {
        assert!(match_redirect_uri(
            "http://localhost:54321/callback",
            "http://localhost:*/callback",
        ));
        assert!(match_redirect_uri(
            "http://127.0.0.1:9999/callback",
            "http://127.0.0.1:*/callback",
        ));
    }

    #[test]
    fn match_redirect_uri_bare_loopback_pattern_matches_any_port() {
        assert!(match_redirect_uri(
            "http://localhost:54321/callback",
            "http://localhost/callback",
        ));
    }

    #[test]
    fn match_redirect_uri_rejects_userinfo_bypass() {
        // Naive fnmatch: `http://localhost@evil/cb` might match
        // `http://localhost:*/cb`. Component-level compare rejects it because
        // the actual host is `evil`.
        assert!(!match_redirect_uri(
            "http://localhost@evil.com/callback",
            "http://localhost:*/callback",
        ));
    }

    #[test]
    fn match_redirect_uri_rejects_dot_segments() {
        assert!(!match_redirect_uri(
            "http://localhost:8080/callback/../steal",
            "http://localhost:*/callback/*",
        ));
    }

    #[test]
    fn match_redirect_uri_scheme_must_match() {
        assert!(!match_redirect_uri(
            "http://app.example.com/cb",
            "https://app.example.com/cb",
        ));
    }

    #[test]
    fn match_redirect_uri_port_wildcard_non_loopback() {
        assert!(match_redirect_uri(
            "https://app.example.com:8443/cb",
            "https://app.example.com:*/cb",
        ));
        assert!(!match_redirect_uri(
            "https://app.example.com:80/cb",
            "https://app.example.com:8443/cb",
        ));
    }

    #[test]
    fn match_redirect_uri_rejects_fragment_in_uri() {
        // RFC 6749 §3.1.2 — redirect URI must not contain a fragment.
        assert!(!match_redirect_uri(
            "https://app.example.com/cb#frag",
            "https://app.example.com/cb",
        ));
        assert!(!match_redirect_uri(
            "http://localhost:8080/cb#",
            "http://localhost:*/cb",
        ));
    }

    #[test]
    fn match_redirect_uri_rejects_fragment_in_pattern() {
        // A pattern that registered a fragment is itself invalid.
        assert!(!match_redirect_uri(
            "https://app.example.com/cb",
            "https://app.example.com/cb#frag",
        ));
    }

    #[test]
    fn match_redirect_uri_rejects_extra_query_param() {
        // Pattern has no query; URI smuggles one in.
        assert!(!match_redirect_uri(
            "https://app.example.com/cb?foo=1",
            "https://app.example.com/cb",
        ));
        // Pattern has a specific query; URI adds extra params.
        assert!(!match_redirect_uri(
            "https://app.example.com/cb?foo=1&bar=2",
            "https://app.example.com/cb?foo=1",
        ));
    }

    #[test]
    fn match_redirect_uri_requires_exact_query_match() {
        assert!(match_redirect_uri(
            "https://app.example.com/cb?foo=1",
            "https://app.example.com/cb?foo=1",
        ));
        // Different value.
        assert!(!match_redirect_uri(
            "https://app.example.com/cb?foo=2",
            "https://app.example.com/cb?foo=1",
        ));
        // Reordered params are not byte-equal, so they do not match —
        // a restrictive but predictable rule.
        assert!(!match_redirect_uri(
            "https://app.example.com/cb?b=2&a=1",
            "https://app.example.com/cb?a=1&b=2",
        ));
    }

    #[test]
    fn match_redirect_uri_query_pattern_matches_with_localhost_wildcard() {
        // Ensures the query-handling interacts correctly with the port
        // wildcard path.
        assert!(match_redirect_uri(
            "http://localhost:54321/cb?state=legacy",
            "http://localhost:*/cb?state=legacy",
        ));
        assert!(!match_redirect_uri(
            "http://localhost:54321/cb",
            "http://localhost:*/cb?state=legacy",
        ));
    }

    #[test]
    fn match_redirect_uri_path_wildcard() {
        assert!(match_redirect_uri(
            "https://app.example.com/oauth/callback",
            "https://app.example.com/oauth/*",
        ));
        // `*` in the fnmatch crosses slashes (Python behaviour); we match that.
        assert!(match_redirect_uri(
            "https://app.example.com/oauth/x/y",
            "https://app.example.com/oauth/*",
        ));
    }

    #[test]
    fn glob_matches_basic_cases() {
        assert!(glob_match("abc", "abc"));
        assert!(glob_match("a*c", "abbbc"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn parse_policy_respects_max_age() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=120"),
        );
        let now = Instant::now();
        let p = parse_policy(&h, now);
        assert!(p.expires_at >= now + Duration::from_secs(119));
        assert!(p.expires_at <= now + Duration::from_secs(121));
        assert!(!p.no_store);
        assert!(!p.must_revalidate);
    }

    #[test]
    fn parse_policy_flags_no_store_and_no_cache() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache"),
        );
        let p = parse_policy(&h, Instant::now());
        assert!(p.no_store);
        assert!(p.must_revalidate);
    }

    #[test]
    fn parse_policy_captures_etag_and_last_modified() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(reqwest::header::ETAG, HeaderValue::from_static("\"abc\""));
        h.insert(
            reqwest::header::LAST_MODIFIED,
            HeaderValue::from_static("Wed, 21 Oct 2020 07:28:00 GMT"),
        );
        let p = parse_policy(&h, Instant::now());
        assert_eq!(p.etag.as_deref(), Some("\"abc\""));
        assert!(p.last_modified.is_some());
    }

    #[test]
    fn validate_doc_requires_redirect_uris() {
        let d = CimdDocument {
            client_id: "https://cli.example.com/c.json".into(),
            client_name: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            software_id: None,
            software_version: None,
        };
        assert!(matches!(
            validate_doc(&d, "https://cli.example.com/c.json"),
            Err(CimdError::NoRedirectUris)
        ));
    }

    #[test]
    fn validate_doc_rejects_shared_secret_auth() {
        let d = CimdDocument {
            client_id: "https://cli.example.com/c.json".into(),
            client_name: None,
            redirect_uris: vec!["http://localhost:*/cb".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            software_id: None,
            software_version: None,
        };
        assert!(matches!(
            validate_doc(&d, "https://cli.example.com/c.json"),
            Err(CimdError::UnsupportedAuthMethod(_))
        ));
    }

    #[test]
    fn validate_doc_enforces_client_id_equals_fetch_url() {
        let d = CimdDocument {
            client_id: "https://other.example.com/c.json".into(),
            client_name: None,
            redirect_uris: vec!["http://localhost:*/cb".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            software_id: None,
            software_version: None,
        };
        assert!(matches!(
            validate_doc(&d, "https://cli.example.com/c.json"),
            Err(CimdError::ClientIdMismatch { .. })
        ));
    }

    #[test]
    fn validate_doc_tolerates_trailing_slash() {
        let d = CimdDocument {
            client_id: "https://cli.example.com/c.json/".into(),
            client_name: None,
            redirect_uris: vec!["http://localhost:*/cb".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            software_id: None,
            software_version: None,
        };
        assert!(validate_doc(&d, "https://cli.example.com/c.json").is_ok());
    }

    // -- HTTP-fetch path coverage ------------------------------------------
    //
    // The DNS-pin + SSRF guard in `fetch_with_ssrf_guard` rejects loopback
    // addresses, so these tests drive `issue_cimd_request` directly with a
    // plain `reqwest::Client` against a tiny axum server bound to
    // `127.0.0.1:0`. They exercise the same reqwest send + response decode
    // logic that `fetch_with_ssrf_guard` runs in production — the only piece
    // not exercised here is the SSRF allow/deny check, which has dedicated
    // unit tests in `is_public_ip_*` above.

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use axum::extract::State;
    use axum::http::HeaderMap as AxHeaderMap;
    use axum::response::Response as AxResponse;
    use axum::routing::get;
    use axum::Router;
    use tokio::net::TcpListener;

    #[derive(Clone, Default)]
    struct CimdSrv {
        body: Arc<std::sync::RwLock<String>>,
        status: Arc<AtomicU32>,
        cache_control: Arc<std::sync::RwLock<String>>,
        etag: Arc<std::sync::RwLock<String>>,
        respond_304_if_inm: Arc<std::sync::atomic::AtomicBool>,
        /// Stream a vastly oversized body in chunks, so axum emits it with
        /// `Transfer-Encoding: chunked` and no `Content-Length`.
        chunked_oversize: Arc<std::sync::atomic::AtomicBool>,
        /// Chunks the server actually managed to hand to the transport. A
        /// client that stops reading at the cap closes the connection, so this
        /// stays far below the total; one that buffers the whole body drains
        /// them all.
        chunks_written: Arc<AtomicU32>,
        captured_inm: Arc<Mutex<Option<String>>>,
        request_count: Arc<AtomicU32>,
    }

    impl CimdSrv {
        fn new() -> Self {
            let me = Self::default();
            me.status.store(200, Ordering::SeqCst);
            *me.body.write().unwrap() = "{}".into();
            me
        }
    }

    async fn cimd_handler(State(srv): State<CimdSrv>, headers: AxHeaderMap) -> AxResponse {
        srv.request_count.fetch_add(1, Ordering::SeqCst);
        if let Some(inm) = headers.get("if-none-match") {
            if let Ok(s) = inm.to_str() {
                *srv.captured_inm.lock().unwrap() = Some(s.to_owned());
            }
        }
        if srv.respond_304_if_inm.load(Ordering::SeqCst) && headers.contains_key("if-none-match") {
            return AxResponse::builder()
                .status(304)
                .body(axum::body::Body::empty())
                .unwrap();
        }
        let mut builder = AxResponse::builder().status(srv.status.load(Ordering::SeqCst) as u16);
        let cc = srv.cache_control.read().unwrap().clone();
        if !cc.is_empty() {
            builder = builder.header("cache-control", cc);
        }
        let etag = srv.etag.read().unwrap().clone();
        if !etag.is_empty() {
            builder = builder.header("etag", etag);
        }
        if srv.chunked_oversize.load(Ordering::SeqCst) {
            // Far larger than the cap so the two behaviours are unmistakable:
            // a reader that stops at 5 KiB abandons this almost immediately,
            // while one that buffers first drains all 8 MiB.
            const CHUNK: usize = 8192;
            const TOTAL_CHUNKS: u32 = 1024;
            let counter = Arc::clone(&srv.chunks_written);
            let stream = futures::stream::iter((0..TOTAL_CHUNKS).map(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::io::Error>(vec![b'x'; CHUNK])
            }));
            return builder
                .header("content-type", "application/json")
                .body(axum::body::Body::from_stream(stream))
                .unwrap();
        }
        let body = srv.body.read().unwrap().clone();
        builder
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    async fn spawn_cimd_srv() -> (Url, CimdSrv) {
        let srv = CimdSrv::new();
        let app = Router::new()
            .route("/c.json", get(cimd_handler))
            .with_state(srv.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = Url::parse(&format!("http://{addr}/c.json")).unwrap();
        (url, srv)
    }

    fn fake_cached(etag: Option<&str>) -> CacheEntry {
        CacheEntry {
            doc: CimdDocument {
                client_id: "https://x.test/c.json".into(),
                client_name: None,
                redirect_uris: vec!["http://localhost:*/cb".into()],
                token_endpoint_auth_method: "none".into(),
                grant_types: vec!["authorization_code".into()],
                response_types: vec!["code".into()],
                scope: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                software_id: None,
                software_version: None,
            },
            policy: CachePolicy {
                etag: etag.map(str::to_owned),
                last_modified: None,
                expires_at: Instant::now() - Duration::from_secs(1),
                no_store: false,
                must_revalidate: false,
            },
        }
    }

    #[tokio::test]
    async fn issue_request_returns_fresh_with_etag_and_cache_control() {
        let (url, srv) = spawn_cimd_srv().await;
        *srv.body.write().unwrap() = r#"{"client_id":"x"}"#.into();
        *srv.cache_control.write().unwrap() = "public, max-age=300".into();
        *srv.etag.write().unwrap() = "\"v1\"".into();

        let client = raw_test_http_client();
        let outcome = issue_cimd_request(&client, &url, None).await.unwrap();

        match outcome {
            FetchOutcome::Fresh { body, headers } => {
                assert_eq!(&body, br#"{"client_id":"x"}"#);
                let policy = parse_policy(&headers, Instant::now());
                assert_eq!(policy.etag.as_deref(), Some("\"v1\""));
                assert!(!policy.no_store);
            }
            FetchOutcome::NotModified(_) => panic!("first call must be Fresh"),
        }
    }

    #[tokio::test]
    async fn issue_request_sends_if_none_match_when_cached() {
        let (url, srv) = spawn_cimd_srv().await;
        srv.respond_304_if_inm
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let cached = fake_cached(Some("\"v1\""));

        let client = raw_test_http_client();
        let outcome = issue_cimd_request(&client, &url, Some(&cached))
            .await
            .unwrap();

        // The captured header is what the server saw — confirms reqwest
        // round-tripped the `If-None-Match` value byte-for-byte.
        assert_eq!(srv.captured_inm.lock().unwrap().as_deref(), Some("\"v1\""));
        assert!(matches!(outcome, FetchOutcome::NotModified(_)));
    }

    #[tokio::test]
    async fn issue_request_5xx_surfaces_status_error() {
        let (url, srv) = spawn_cimd_srv().await;
        srv.status.store(503, Ordering::SeqCst);

        let client = raw_test_http_client();
        match issue_cimd_request(&client, &url, None).await {
            Err(CimdError::Status(c)) => assert_eq!(c, 503),
            Err(other) => panic!("expected Status, got {other:?}"),
            Ok(_) => panic!("503 must not produce an outcome"),
        }
    }

    #[tokio::test]
    async fn issue_request_redirect_surfaces_as_status_not_followed() {
        // CIMD must NOT follow redirects (`redirect::Policy::none`). Build a
        // server that 302s and prove the typed error reflects the 302 rather
        // than re-fetching the Location target. This is the exact reqwest
        // behaviour pinned by `build_pinned_client`.
        let app = Router::new().route(
            "/c.json",
            get(|| async {
                AxResponse::builder()
                    .status(302)
                    .header("location", "http://127.0.0.1:1/elsewhere")
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = Url::parse(&format!("http://{addr}/c.json")).unwrap();

        // Use the production builder (sans DNS-pin) so the redirect-policy
        // setting is what gets tested. Pass empty `ips` — DNS pinning is a
        // no-op when the host already resolves naturally to loopback.
        let client = build_pinned_client("127.0.0.1", addr.port(), &[]).unwrap();
        match issue_cimd_request(&client, &url, None).await {
            Err(CimdError::Status(c)) => assert_eq!(c, 302),
            Err(other) => panic!("expected Status(302), got {other:?}"),
            Ok(_) => panic!("redirect must not produce an outcome"),
        }
    }

    /// Pins that the cap is applied DURING the read, not after it.
    ///
    /// The returned error alone cannot show this: a post-read length
    /// comparison also reports `TooLarge`, just after buffering the whole
    /// body — which is the unbounded allocation the convergence removed. The
    /// difference is observable only in how much the peer got to send, so this
    /// counts the chunks the server handed to the transport. A reader that
    /// stops at the 5 KiB cap drops the response and closes the connection
    /// almost immediately; one that buffers first drains all 8 MiB.
    ///
    /// The body is streamed, so nothing is advertised and the pre-check cannot
    /// answer — only the running counter can.
    #[tokio::test]
    async fn issue_request_stops_reading_an_unadvertised_oversize_body() {
        let (url, srv) = spawn_cimd_srv().await;
        srv.chunked_oversize.store(true, Ordering::SeqCst);

        let client = raw_test_http_client();
        match issue_cimd_request(&client, &url, None).await {
            Err(CimdError::TooLarge { limit }) => assert_eq!(limit, MAX_BODY),
            Err(other) => panic!("expected TooLarge, got {other:?}"),
            Ok(_) => panic!("an unadvertised oversize body must not be returned"),
        }

        // Generous bound: the cap is 5 KiB of 8 MiB offered, so even with
        // socket buffering a during-the-read refusal cannot approach half.
        let written = srv.chunks_written.load(Ordering::SeqCst);
        assert!(
            written < 512,
            "the fetch must abandon the body near the cap, but the server wrote {written} of \
             1024 chunks — the whole response was drained before being refused",
        );
    }

    #[tokio::test]
    async fn issue_request_rejects_oversize_via_content_length() {
        let (url, srv) = spawn_cimd_srv().await;
        // 6 KiB > MAX_BODY (5 KiB). The handler honours Content-Length
        // because we hand axum a fixed body, so the cheap pre-check fires
        // before the body is buffered.
        *srv.body.write().unwrap() = "x".repeat(MAX_BODY + 1024);

        let client = raw_test_http_client();
        match issue_cimd_request(&client, &url, None).await {
            Err(CimdError::TooLarge { limit }) => assert_eq!(limit, MAX_BODY),
            Err(other) => panic!("expected TooLarge, got {other:?}"),
            Ok(_) => panic!("oversize body must not be returned"),
        }
    }
}
