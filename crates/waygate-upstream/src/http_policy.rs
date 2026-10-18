//! Outbound HTTP policy shared by the runtime upstream dialer and `classify`.
//!
//! MCP receive streams may legitimately outlive ordinary request deadlines, so
//! their client has no total timeout. Connection establishment, the initial
//! protocol handshake, and legacy-SSE message writes remain independently
//! bounded by the constants in this module.
//!
//! Upstream requests never follow redirects. They carry the static bearer, the
//! caller's identity headers, and the MCP session headers, and a dial pins only
//! the configured host's addresses. A redirect would send those headers to a
//! host the operator never configured, outside that pinning, so the client
//! fails the request with [`RedirectRefused`] instead.

use std::time::Duration;

use waygate_core::http_client::{self, Profile};

/// TCP/TLS connection establishment must not inherit the receive stream's
/// unlimited lifetime.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Initial request plus the first protocol event/initialize response.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Legacy SSE JSON-RPC POSTs are ordinary interactive operations even though
/// the paired receive stream is long-lived.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// A redirect an upstream answered with, which the upstream client refused to
/// follow. It keeps only the status: the `Location` can name another host and
/// carry credentials in its query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("redirect refused (HTTP {status})")]
pub struct RedirectRefused {
    pub status: http::StatusCode,
}

impl RedirectRefused {
    /// The refused redirect that failed `error`, if any.
    pub fn from_reqwest(error: &reqwest::Error) -> Option<Self> {
        if !error.is_redirect() {
            return None;
        }
        std::error::Error::source(error)?
            .downcast_ref::<Self>()
            .copied()
    }
}

/// Build the common streaming client policy while leaving room for per-upstream
/// TLS identity and trust material. Every client that talks to an upstream MCP
/// server starts here, so each one inherits the redirect refusal.
pub(crate) fn streaming_builder() -> reqwest::ClientBuilder {
    http_client::builder(Profile::NoTotalTimeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_max_idle_per_host(0)
        .redirect(refuse_redirects())
}

/// reqwest consults this for a redirect it could follow: a 301, 302, 303, 307,
/// or 308 with a usable `Location`. Any other 3xx response reaches the caller
/// as an ordinary unexpected status, and is not followed either.
fn refuse_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let status = attempt.status();
        attempt.error(RedirectRefused { status })
    })
}

/// Build a long-lived receive client with a bounded connection attempt.
pub fn streaming_client() -> reqwest::Result<reqwest::Client> {
    streaming_builder().build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_policy_builds() {
        streaming_client().expect("streaming client policy must build");
    }

    /// Every redirect reqwest could follow fails the request with its status,
    /// and the redirect target never receives a request.
    #[tokio::test]
    async fn the_streaming_client_refuses_every_followable_redirect() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use axum::extract::Path;
        use axum::routing::get;
        use http::{header::LOCATION, StatusCode};

        let target_requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&target_requests);
        let target = axum::Router::new().fallback(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { StatusCode::OK }
        });
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect target");
        let target_addr = target_listener.local_addr().expect("target address");
        let target_server =
            tokio::spawn(async move { axum::serve(target_listener, target).await.unwrap() });

        let redirector = axum::Router::new().route(
            "/{status}",
            get(move |Path(status): Path<u16>| async move {
                (
                    StatusCode::from_u16(status).expect("valid redirect status"),
                    [(LOCATION, format!("http://{target_addr}/moved"))],
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirector");
        let addr = listener.local_addr().expect("redirector address");
        let server = tokio::spawn(async move { axum::serve(listener, redirector).await.unwrap() });

        let client = streaming_client().expect("streaming client policy must build");
        for status in [301, 302, 303, 307, 308] {
            let error = client
                .get(format!("http://{addr}/{status}"))
                .send()
                .await
                .expect_err("a redirect must fail the request");
            assert_eq!(
                RedirectRefused::from_reqwest(&error),
                Some(RedirectRefused {
                    status: StatusCode::from_u16(status).unwrap()
                }),
                "{status}: {error}",
            );
        }
        server.abort();
        target_server.abort();

        assert_eq!(
            target_requests.load(Ordering::SeqCst),
            0,
            "no request may reach a redirect target",
        );
    }

    /// A per-call dial can spend [`HANDSHAKE_TIMEOUT`] **twice**: an
    /// `auto`-lifecycle attempt rejected at initialize retries under the legacy
    /// lifecycle with a fresh budget, and that second leg can be the one that
    /// succeeds. The establishment histogram's finite buckets must reach both
    /// legs, or a healthy-but-slow establishment lands only in the overflow
    /// bucket and its quantiles saturate.
    ///
    /// This pins only the handshake-bounded part. Name resolution runs before
    /// the handshake deadline starts and is limited by the configurable outer
    /// call budget, which no fixed bucket can track; the registration site
    /// documents how such an establishment reads.
    ///
    /// The telemetry crate is a leaf and cannot see this constant, so the
    /// coupling is asserted from here, where both are visible.
    #[test]
    fn the_two_leg_handshake_bound_fits_inside_the_establishment_buckets() {
        let largest = waygate_telemetry::metrics::UPSTREAM_SESSION_ESTABLISH_BUCKETS
            .last()
            .copied()
            .expect("establishment buckets are not empty");
        let two_legs = HANDSHAKE_TIMEOUT.as_secs_f64() * 2.0;
        assert!(
            largest >= two_legs,
            "the largest finite establishment bucket ({largest}s) must cover two handshake \
             deadlines ({two_legs}s, because an auto-lifecycle dial retries once under \
             the legacy lifecycle); raising the deadline or adding another retried leg \
             requires raising the bucket",
        );
    }
}
