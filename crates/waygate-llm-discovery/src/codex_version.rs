//! Auto-tracking of the Codex CLI release version sent on the model listing.
//!
//! The ChatGPT backend's `/models` filters its response by the required
//! `client_version` query parameter: an old version silently returns the
//! model subset that CLI release was allowed to see (and an ancient one an
//! *empty* list), so a compile-time pin decays as the CLI ships. The tracker
//! learns the latest released CLI version at refresh time from public release
//! metadata and falls back through the last successful fetch to the compiled
//! default, so a registry outage can never make discovery worse than the pin.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::{read_body_capped, DiscoveryError, CODEX_DEFAULT_CLIENT_VERSION};

/// npm registry metadata for the released Codex CLI (`@openai/codex`); the
/// primary version source. Unauthenticated; the response carries a top-level
/// `version` field.
pub const CODEX_VERSION_NPM_URL: &str = "https://registry.npmjs.org/@openai/codex/latest";

/// GitHub latest-release fallback for the Codex CLI. Unauthenticated; the
/// response's `tag_name` is `rust-vX.Y.Z`.
pub const CODEX_VERSION_GITHUB_URL: &str =
    "https://api.github.com/repos/openai/codex/releases/latest";

/// How long a fetched version is trusted before re-checking. CLI releases are
/// far less frequent than the discovery interval, so one re-check per day
/// keeps the version current without hammering the registries.
pub const CODEX_VERSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cap on the bytes read from a version-metadata response. The npm manifest
/// and a GitHub release document are tens of KB; the cap bounds a buggy or
/// hostile response the same way the listing cap does.
const VERSION_BODY_CAP: usize = 1024 * 1024;

/// Parse a plain all-digit `MAJOR.MINOR.PATCH` version — the only shape the
/// ChatGPT backend accepts — into its numeric components (the tuple orders
/// correctly for downgrade comparison). `None` for anything else.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.');
    let (a, b, c) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    let num = |p: &str| -> Option<u64> {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    Some((num(a)?, num(b)?, num(c)?))
}

/// Whether `v` is a plain all-digit `MAJOR.MINOR.PATCH` version — the only
/// shape the ChatGPT backend accepts (anything else is rejected with
/// `Invalid client_version format`, so validating here keeps a garbled
/// registry response from breaking the listing request).
pub fn is_valid_codex_client_version(v: &str) -> bool {
    parse_version(v).is_some()
}

fn validated(v: &str) -> Result<String, DiscoveryError> {
    if is_valid_codex_client_version(v) {
        Ok(v.to_string())
    } else {
        Err(DiscoveryError::Decode(format!(
            "not a MAJOR.MINOR.PATCH version: {v:?}"
        )))
    }
}

#[derive(Deserialize)]
struct NpmLatest {
    #[serde(default)]
    version: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    #[serde(default)]
    tag_name: String,
}

async fn get_capped(http: &reqwest::Client, url: &str) -> Result<String, DiscoveryError> {
    let resp = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| DiscoveryError::Transport(e.to_string()))?;
    read_body_capped(resp, VERSION_BODY_CAP).await
}

/// Latest released CLI version per the npm registry (`{"version":"X.Y.Z"}`).
async fn npm_version(http: &reqwest::Client, url: &str) -> Result<String, DiscoveryError> {
    let body = get_capped(http, url).await?;
    let parsed: NpmLatest =
        serde_json::from_str(&body).map_err(|e| DiscoveryError::Decode(e.to_string()))?;
    validated(&parsed.version)
}

/// Latest released CLI version per the GitHub latest-release document
/// (`{"tag_name":"rust-vX.Y.Z"}`); the `rust-v`/`v` tag prefix is stripped.
async fn github_version(http: &reqwest::Client, url: &str) -> Result<String, DiscoveryError> {
    let body = get_capped(http, url).await?;
    let parsed: GithubRelease =
        serde_json::from_str(&body).map_err(|e| DiscoveryError::Decode(e.to_string()))?;
    let tag = parsed.tag_name;
    let v = tag
        .strip_prefix("rust-v")
        .or_else(|| tag.strip_prefix('v'))
        .unwrap_or(&tag);
    validated(v)
}

#[derive(Debug, Clone)]
struct Cached {
    version: String,
    fetched_at: Instant,
}

/// Resolves the `client_version` for Codex model listings, refreshing from
/// the release trackers on a TTL and never failing:
///
/// 1. a fresh cached fetch (within [`CODEX_VERSION_TTL`]),
/// 2. the npm registry, then the GitHub latest release (validated strictly —
///    a garbled response never reaches the backend),
/// 3. the last successful fetch (kept stale so the next cycle retries),
/// 4. the compiled [`CODEX_DEFAULT_CLIENT_VERSION`].
///
/// Every fallback step logs a `WARN`, so a silently-pinned version is
/// operator-visible.
///
/// The resolved version is **monotonic over a floor**: a fetched version
/// below the greater of the compiled default and the last successful fetch
/// is rejected as a downgrade (registry rollback, stale mirror). The backend
/// scopes the model listing to the version it is asked as, so accepting a
/// lower-but-valid version would shrink the listing *non-empty* — and a
/// smaller successful listing reconciles, soft-disabling the newer
/// discovered models. The empty-listing fail-open cannot catch that case;
/// this floor does.
#[derive(Debug)]
pub struct CodexVersionTracker {
    npm_url: String,
    github_url: String,
    ttl: Duration,
    cached: Mutex<Option<Cached>>,
}

impl Default for CodexVersionTracker {
    fn default() -> Self {
        Self::new(
            CODEX_VERSION_NPM_URL,
            CODEX_VERSION_GITHUB_URL,
            CODEX_VERSION_TTL,
        )
    }
}

impl CodexVersionTracker {
    pub fn new(npm_url: impl Into<String>, github_url: impl Into<String>, ttl: Duration) -> Self {
        Self {
            npm_url: npm_url.into(),
            github_url: github_url.into(),
            ttl,
            cached: Mutex::new(None),
        }
    }

    /// The `client_version` to send now. Infallible: falls back through
    /// last-good to the compiled default (see the type docs for the chain).
    pub async fn current(&self, http: &reqwest::Client) -> String {
        if let Some(c) = self.cached.lock().expect("tracker lock").clone() {
            if c.fetched_at.elapsed() < self.ttl {
                return c.version;
            }
        }
        match npm_version(http, &self.npm_url).await {
            Ok(v) => {
                if let Some(accepted) = self.accept_above_floor(v, "npm") {
                    return accepted;
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "codex client_version: npm registry read failed; trying the GitHub release fallback"
            ),
        }
        match github_version(http, &self.github_url).await {
            Ok(v) => {
                if let Some(accepted) = self.accept_above_floor(v, "github") {
                    return accepted;
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "codex client_version: GitHub release read failed"
            ),
        }
        // Both sources failed. Keep serving the last successful fetch WITHOUT
        // renewing its timestamp, so the next cycle retries the sources
        // instead of trusting a stale value for another full TTL.
        if let Some(c) = self.cached.lock().expect("tracker lock").clone() {
            tracing::warn!(
                version = %c.version,
                "codex client_version: both release sources failed; keeping the last-good version"
            );
            return c.version;
        }
        tracing::warn!(
            version = CODEX_DEFAULT_CLIENT_VERSION,
            "codex client_version: both release sources failed with no prior success; \
             using the compiled default (the model listing may be a stale subset)"
        );
        CODEX_DEFAULT_CLIENT_VERSION.to_string()
    }

    /// Accept `fetched` only at or above the floor — the greater of the
    /// compiled default and the last successful fetch. A lower-but-valid
    /// version ("latest" pointing below something we already trusted) is a
    /// downgrade that would shrink the model listing non-empty, letting a
    /// successful reconcile soft-disable the newer discovered models — the
    /// decay this tracker exists to prevent. Rejection returns `None` so the
    /// caller falls through to the next source, then last-good, then the
    /// default: the resolved version never moves below the floor.
    fn accept_above_floor(&self, fetched: String, source: &'static str) -> Option<String> {
        let fetched_v = parse_version(&fetched)?;
        let default_v =
            parse_version(CODEX_DEFAULT_CLIENT_VERSION).expect("compiled default parses");
        let floor_v = match self.cached.lock().expect("tracker lock").as_ref() {
            Some(c) => default_v.max(parse_version(&c.version).unwrap_or(default_v)),
            None => default_v,
        };
        if fetched_v < floor_v {
            tracing::warn!(
                source,
                fetched = %fetched,
                "codex client_version: fetched version is below the known floor \
                 (compiled default / last-good); rejecting the downgrade"
            );
            return None;
        }
        Some(self.store(fetched))
    }

    fn store(&self, version: String) -> String {
        *self.cached.lock().expect("tracker lock") = Some(Cached {
            version: version.clone(),
            fetched_at: Instant::now(),
        });
        version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;

    #[cfg(test)]
    fn raw_test_http_client() -> reqwest::Client {
        reqwest::Client::new() // A raw test client isolates release-source behavior from gateway policy.
    }

    #[test]
    fn version_validation_is_strict_major_minor_patch() {
        assert!(is_valid_codex_client_version("0.144.0"));
        assert!(is_valid_codex_client_version("10.2.33"));
        // Anything the backend would 400 on is rejected.
        for bad in [
            "", "abc", "1.2", "1.2.3.4", "1.2.x", "v1.2.3", "1.2.3 ", " 1.2.3", "1..3", "1.2.",
        ] {
            assert!(
                !is_valid_codex_client_version(bad),
                "{bad:?} must be invalid"
            );
        }
    }

    /// Serve `app` on an ephemeral loopback port; return its base URL.
    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// A fake pair of release sources with per-route hit counters, switchable
    /// failure, and swappable bodies (so a test can drive a registry rollback
    /// between calls), driving the tracker's fallback chain.
    struct Sources {
        base: String,
        npm_hits: Arc<AtomicUsize>,
        github_hits: Arc<AtomicUsize>,
        npm_fail: Arc<AtomicUsize>,
        github_fail: Arc<AtomicUsize>,
        npm_body: Arc<Mutex<String>>,
        github_body: Arc<Mutex<String>>,
    }

    async fn serve_sources(npm_body: &str, github_body: &str) -> Sources {
        #[derive(Clone)]
        struct Route {
            hits: Arc<AtomicUsize>,
            fail: Arc<AtomicUsize>,
            body: Arc<Mutex<String>>,
        }
        async fn handle(State(r): State<Route>) -> (StatusCode, String) {
            r.hits.fetch_add(1, Ordering::SeqCst);
            if r.fail.load(Ordering::SeqCst) != 0 {
                (StatusCode::SERVICE_UNAVAILABLE, "down".to_string())
            } else {
                (StatusCode::OK, r.body.lock().unwrap().clone())
            }
        }
        let npm = Route {
            hits: Arc::new(AtomicUsize::new(0)),
            fail: Arc::new(AtomicUsize::new(0)),
            body: Arc::new(Mutex::new(npm_body.to_string())),
        };
        let github = Route {
            hits: Arc::new(AtomicUsize::new(0)),
            fail: Arc::new(AtomicUsize::new(0)),
            body: Arc::new(Mutex::new(github_body.to_string())),
        };
        let (npm_hits, npm_fail, npm_body) = (npm.hits.clone(), npm.fail.clone(), npm.body.clone());
        let (github_hits, github_fail, github_body) = (
            github.hits.clone(),
            github.fail.clone(),
            github.body.clone(),
        );
        let app = Router::new()
            .route("/npm", get(handle).with_state(npm))
            .route("/github", get(handle).with_state(github));
        Sources {
            base: serve(app).await,
            npm_hits,
            github_hits,
            npm_fail,
            github_fail,
            npm_body,
            github_body,
        }
    }

    fn tracker(s: &Sources, ttl: Duration) -> CodexVersionTracker {
        CodexVersionTracker::new(format!("{}/npm", s.base), format!("{}/github", s.base), ttl)
    }

    #[tokio::test]
    async fn npm_is_primary_and_result_is_cached_within_ttl() {
        let s = serve_sources(
            r#"{"version":"0.150.0","name":"@openai/codex"}"#,
            r#"{"tag_name":"rust-v0.149.0"}"#,
        )
        .await;
        let t = tracker(&s, Duration::from_secs(3600));
        let http = raw_test_http_client();

        assert_eq!(t.current(&http).await, "0.150.0");
        assert_eq!(t.current(&http).await, "0.150.0");
        // The second call was a cache hit: one npm fetch, no GitHub fetch.
        assert_eq!(s.npm_hits.load(Ordering::SeqCst), 1);
        assert_eq!(s.github_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn github_fallback_strips_tag_prefix() {
        let s = serve_sources(
            r#"{"version":"garbled"}"#,
            r#"{"tag_name":"rust-v0.151.0"}"#,
        )
        .await;
        let t = tracker(&s, Duration::from_secs(3600));
        // The npm body parses but fails strict validation → GitHub wins.
        assert_eq!(t.current(&raw_test_http_client()).await, "0.151.0");
        assert_eq!(s.github_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn both_sources_down_falls_back_to_compiled_default() {
        let s = serve_sources(r#"{"version":"0.150.0"}"#, r#"{"tag_name":"v0.150.0"}"#).await;
        s.npm_fail.store(1, Ordering::SeqCst);
        s.github_fail.store(1, Ordering::SeqCst);
        let t = tracker(&s, Duration::from_secs(3600));
        assert_eq!(
            t.current(&raw_test_http_client()).await,
            CODEX_DEFAULT_CLIENT_VERSION,
            "no prior success ⇒ the compiled default"
        );
    }

    /// Backdate the tracker's cached fetch to just past `ttl`, so the next
    /// `current` call takes the stale path (consult the sources) rather than
    /// the fresh-cache path. Same-module test: reaches the private cache.
    fn backdate_past_ttl(t: &CodexVersionTracker, ttl: Duration) {
        let mut guard = t.cached.lock().unwrap();
        let cached = guard.as_mut().expect("a fetch was cached");
        cached.fetched_at = Instant::now()
            .checked_sub(ttl + Duration::from_secs(1))
            .expect("machine uptime exceeds the test TTL");
    }

    #[tokio::test]
    async fn last_good_survives_a_source_outage_and_retries_next_call() {
        let s = serve_sources(
            r#"{"version":"0.152.0"}"#,
            r#"{"tag_name":"rust-v0.152.0"}"#,
        )
        .await;
        // A NONZERO TTL is what gives the final assertion teeth: if the
        // outage path incorrectly re-stored/re-timestamped last-good, the
        // cache would be fresh for the whole TTL and the follow-up call
        // would return from cache WITHOUT touching the sources. (With a zero
        // TTL every entry is instantly stale and the assertion is vacuous.)
        // Small enough that `checked_sub` backdating works on any host that
        // has been up longer than the test run.
        let ttl = Duration::from_secs(5);
        let t = tracker(&s, ttl);
        let http = raw_test_http_client();

        assert_eq!(t.current(&http).await, "0.152.0", "initial fetch succeeds");
        // Expire the cache, then take both sources down: the stale path must
        // serve last-good.
        backdate_past_ttl(&t, ttl);
        s.npm_fail.store(1, Ordering::SeqCst);
        s.github_fail.store(1, Ordering::SeqCst);
        assert_eq!(
            t.current(&http).await,
            "0.152.0",
            "outage serves the last-good version"
        );
        // Immediately (well within the 5s TTL) call again: only a
        // NOT-re-timestamped cache forces another source consult here.
        let npm_before = s.npm_hits.load(Ordering::SeqCst);
        assert_eq!(t.current(&http).await, "0.152.0");
        assert!(
            s.npm_hits.load(Ordering::SeqCst) > npm_before,
            "last-good is NOT re-timestamped: the sources are retried on the next call"
        );
    }

    #[tokio::test]
    async fn registry_rollback_below_last_good_is_rejected() {
        // A valid-but-LOWER "latest" (registry rollback, stale mirror) must
        // not overwrite last-good: the backend would return that older
        // release's smaller-but-nonempty listing, and a successful reconcile
        // would soft-disable the newer discovered models.
        let s = serve_sources(
            r#"{"version":"0.152.0"}"#,
            r#"{"tag_name":"rust-v0.151.0"}"#,
        )
        .await;
        let t = tracker(&s, Duration::ZERO);
        let http = raw_test_http_client();

        assert_eq!(t.current(&http).await, "0.152.0", "initial fetch succeeds");
        // Both sources roll back to valid older versions.
        *s.npm_body.lock().unwrap() = r#"{"version":"0.150.0"}"#.to_string();
        *s.github_body.lock().unwrap() = r#"{"tag_name":"rust-v0.149.0"}"#.to_string();
        assert_eq!(
            t.current(&http).await,
            "0.152.0",
            "both downgrades rejected; last-good keeps serving"
        );
        // The registry moves FORWARD past last-good again → accepted.
        *s.npm_body.lock().unwrap() = r#"{"version":"0.153.0"}"#.to_string();
        assert_eq!(
            t.current(&http).await,
            "0.153.0",
            "a genuine advance is accepted"
        );
    }

    #[tokio::test]
    async fn fetched_below_compiled_default_falls_to_default() {
        // With no prior success the compiled default IS the floor: a fresh
        // tracker seeing only sub-default versions must not go below it.
        let s = serve_sources(r#"{"version":"0.1.0"}"#, r#"{"tag_name":"v0.2.0"}"#).await;
        let t = tracker(&s, Duration::from_secs(3600));
        assert_eq!(
            t.current(&raw_test_http_client()).await,
            CODEX_DEFAULT_CLIENT_VERSION,
            "sub-default fetches are rejected; the compiled default is the floor"
        );
    }

    #[tokio::test]
    async fn fetched_equal_to_the_floor_is_accepted() {
        // Equality is not a downgrade: "latest" == the compiled default (or
        // last-good) is the steady state right after a release the default
        // was bumped to.
        let npm = format!(r#"{{"version":"{CODEX_DEFAULT_CLIENT_VERSION}"}}"#);
        let s = serve_sources(&npm, r#"{"tag_name":"v0.0.1"}"#).await;
        let t = tracker(&s, Duration::from_secs(3600));
        assert_eq!(
            t.current(&raw_test_http_client()).await,
            CODEX_DEFAULT_CLIENT_VERSION
        );
        assert_eq!(
            s.github_hits.load(Ordering::SeqCst),
            0,
            "npm's floor-equal version was accepted; no fallback needed"
        );
    }

    #[test]
    fn version_ordering_is_numeric_not_lexicographic() {
        // 0.9.0 < 0.144.0 numerically but "0.9.0" > "0.144.0" as strings —
        // the floor comparison must use the parsed components.
        assert!(parse_version("0.9.0").unwrap() < parse_version("0.144.0").unwrap());
        assert!(parse_version("1.0.0").unwrap() > parse_version("0.999.99").unwrap());
    }
}
