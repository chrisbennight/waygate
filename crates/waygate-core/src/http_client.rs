//! The one factory for outbound `reqwest` clients.
//!
//! Before this module, ~14 call sites each hand-rolled
//! `reqwest::Client::builder()` with drifting total timeouts
//! (5s/10s/15s/30s), and the gateway user-agent string was
//! copy-pasted in three of them (with one variant spelling). Every
//! outbound HTTP client is now constructed through [`builder`] /
//! [`client`]; CI fails on a direct `reqwest::Client::builder()`
//! outside this module (`scripts/check-shared-http-client.sh`).
//!
//! What the factory owns: the shared user-agent and the TOTAL request
//! timeout, named by [`Profile`]. What callers own: everything
//! genuinely per-site — mTLS identity, redirect policy, proxies,
//! connect/read timeouts, a user-agent override (call
//! `.user_agent(..)` again; last one wins) — layered onto the returned
//! builder, plus their own error mapping on `build()`.
//!
//! Only compiled with the `http` cargo feature so waygate-core's many
//! dependency-light consumers don't pull `reqwest`.

use std::time::Duration;

/// Shared user-agent for gateway-originated requests. The workspace
/// pins one version for every crate, so this reports the gateway
/// release regardless of which crate constructs the client.
pub const USER_AGENT: &str = concat!("waygate/", env!("CARGO_PKG_VERSION"));

/// Named total-timeout profiles for outbound clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A caller is blocked on this request right now (token
    /// introspection on the hot path): 5s.
    Interactive,
    /// Ordinary control-plane fetch (JWKS, CIMD, webhook/export
    /// delivery): 10s.
    Standard,
    /// Known-slow endpoints (provider model discovery, token
    /// refresh round-trips): 30s.
    Slow,
    /// A caller-supplied total timeout that is deliberately not one of
    /// the named tiers. Prefer a named tier; use this to preserve a
    /// load-bearing site-specific value.
    Custom(Duration),
    /// No total timeout — for long-lived streaming responses (LLM
    /// SSE) where the body legitimately outlives any fixed deadline.
    /// Callers should still bound connect/read as appropriate.
    NoTotalTimeout,
}

impl Profile {
    /// Total request deadline installed by this profile. Exposed so callers
    /// can test their selected policy without coupling a virtual Tokio clock
    /// to live socket I/O.
    pub const fn total_timeout(self) -> Option<Duration> {
        match self {
            Profile::Interactive => Some(Duration::from_secs(5)),
            Profile::Standard => Some(Duration::from_secs(10)),
            Profile::Slow => Some(Duration::from_secs(30)),
            Profile::Custom(d) => Some(d),
            Profile::NoTotalTimeout => None,
        }
    }
}

/// A `reqwest` builder pre-configured with the shared user-agent and
/// the profile's total timeout. Callers layer site-specific settings
/// on top and keep their own `build()` error mapping.
pub fn builder(profile: Profile) -> reqwest::ClientBuilder {
    let mut b = reqwest::Client::builder().user_agent(USER_AGENT);
    if let Some(t) = profile.total_timeout() {
        b = b.timeout(t);
    }
    b
}

/// [`builder`] + `build()` for the common no-extra-settings case.
pub fn client(profile: Profile) -> reqwest::Result<reqwest::Client> {
    builder(profile).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_builds_a_client() {
        for p in [
            Profile::Interactive,
            Profile::Standard,
            Profile::Slow,
            Profile::Custom(Duration::from_secs(15)),
            Profile::NoTotalTimeout,
        ] {
            assert!(client(p).is_ok(), "{p:?} must build");
        }
    }

    #[test]
    fn user_agent_names_the_gateway_and_its_version() {
        assert!(USER_AGENT.starts_with("waygate/"));
        assert!(USER_AGENT.len() > "waygate/".len());
    }

    #[test]
    fn caller_overrides_layer_on_top() {
        // The factory's settings must not prevent per-site extension —
        // a second user_agent call wins, redirect policy is free.
        let b = builder(Profile::Standard)
            .user_agent("custom-agent/1")
            .redirect(reqwest::redirect::Policy::none());
        assert!(b.build().is_ok());
    }
}

/// A response body exceeded the caller's cap.
///
/// Carries only the limit, never any bytes read or the URL, so logging it
/// cannot leak response content or a credential-bearing request URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("response body exceeded {limit} bytes")]
pub struct BodyTooLarge {
    pub limit: usize,
}

/// Read a response body, refusing anything over `limit`.
///
/// Outbound responses come from sources the gateway trusts only partially — a
/// configured IdP, a registered federation peer, a client-supplied metadata URL
/// — and several of them are read on the token-validation path. Buffering an
/// unbounded body there turns a compromised or misconfigured endpoint into
/// memory pressure during request verification, so every such read goes through
/// a cap.
///
/// Two guards, because either alone is insufficient:
///
/// - An advertised `Content-Length` over the cap is refused **before a single
///   byte is drained**. Dropping the response closes the socket, so the peer
///   cannot keep streaming a body that would be discarded.
/// - The body is then streamed with a running counter, so a peer that omits or
///   lies about `Content-Length` — or uses chunked encoding — is still cut off
///   at the cap, having allocated at most one chunk beyond it.
#[cfg(feature = "http")]
pub async fn read_body_capped(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ReadBodyError> {
    use futures::StreamExt as _;

    if let Some(advertised) = response.content_length() {
        if advertised as usize > limit {
            return Err(ReadBodyError::TooLarge(BodyTooLarge { limit }));
        }
    }
    let mut stream = response.bytes_stream();
    let mut body: Vec<u8> = Vec::with_capacity(4096.min(limit));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(ReadBodyError::Http)?;
        if body.len() + chunk.len() > limit {
            return Err(ReadBodyError::TooLarge(BodyTooLarge { limit }));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Failure reading a capped body: either the transport failed, or the peer
/// exceeded the cap.
#[cfg(feature = "http")]
#[derive(Debug, thiserror::Error)]
pub enum ReadBodyError {
    /// `reqwest::Error`'s `Display` includes the URL it was fetching, which may
    /// carry userinfo, so callers that surface this to logs should wrap it
    /// rather than formatting it directly.
    #[error("transport error reading response body")]
    Http(#[source] reqwest::Error),
    #[error(transparent)]
    TooLarge(#[from] BodyTooLarge),
}

#[cfg(all(test, feature = "http"))]
mod capped_body_tests {
    use super::*;

    fn response_with_body(body: &'static [u8], advertise_len: bool) -> reqwest::Response {
        let mut builder = http::Response::builder().status(200);
        if advertise_len {
            builder = builder.header(http::header::CONTENT_LENGTH, body.len());
        }
        reqwest::Response::from(builder.body(body).expect("build response"))
    }

    #[tokio::test]
    async fn reads_a_body_within_the_cap() {
        let body = read_body_capped(response_with_body(b"{\"keys\":[]}", true), 1024)
            .await
            .expect("within cap");
        assert_eq!(body, b"{\"keys\":[]}");
    }

    /// An advertised Content-Length over the cap is refused, returning the cap
    /// rather than the body.
    ///
    /// Scope, stated so this is not read as more than it is: it pins that the
    /// pre-check path exists and reports `TooLarge`, NOT that it refuses
    /// *without draining*. That distinction is not observable in-process,
    /// because `Response::content_length()` derives from the body's size hint
    /// — so any fixture that advertises a length is already fully in memory
    /// and there is nothing left to avoid reading. The draining behaviour is
    /// pinned over a real socket by `waygate-as`'s
    /// `issue_request_stops_reading_an_unadvertised_oversize_body`, which
    /// counts what the peer got to send.
    ///
    /// The pre-check is an optimisation over the counter, not the guard that
    /// bounds allocation: with it deleted the counter still refuses, having
    /// read at most one chunk past the cap.
    #[tokio::test]
    async fn refuses_an_advertised_length_over_the_cap() {
        let err = read_body_capped(response_with_body(&[b'x'; 512], true), 64)
            .await
            .expect_err("over cap");
        assert!(matches!(
            err,
            ReadBodyError::TooLarge(BodyTooLarge { limit: 64 })
        ));
    }

    /// A body with no length known up front — what chunked transfer-encoding
    /// produces. Built from a stream rather than a slice on purpose: a slice
    /// carries an exact size hint, so `content_length()` reports it even with
    /// no header, the pre-check answers before the counter ever runs, and this
    /// invariant would sit untested while appearing to be covered.
    fn streamed_response(chunks: Vec<&'static [u8]>) -> reqwest::Response {
        let body = reqwest::Body::wrap_stream(futures::stream::iter(
            chunks
                .into_iter()
                .map(Ok::<_, std::io::Error>)
                .collect::<Vec<_>>(),
        ));
        reqwest::Response::from(
            http::Response::builder()
                .status(200)
                .body(body)
                .expect("build response"),
        )
    }

    /// The counter is the guard that actually matters: a peer that omits
    /// Content-Length — or lies about it — must still be cut off, or the
    /// pre-check would be trivially bypassed by using chunked encoding.
    #[tokio::test]
    async fn refuses_an_unadvertised_body_over_the_cap() {
        let response = streamed_response(vec![&[b'x'; 32], &[b'x'; 32], &[b'x'; 32]]);
        assert_eq!(
            response.content_length(),
            None,
            "the fixture must carry no length up front, or this exercises the pre-check",
        );
        let err = read_body_capped(response, 64).await.expect_err("over cap");
        assert!(matches!(
            err,
            ReadBodyError::TooLarge(BodyTooLarge { limit: 64 })
        ));
    }

    /// The counter must not fire early: a streamed body that fits is read whole.
    #[tokio::test]
    async fn reads_a_streamed_body_within_the_cap() {
        let body = read_body_capped(streamed_response(vec![b"{\"ke", b"ys\":[]}"]), 64)
            .await
            .expect("within cap");
        assert_eq!(body, b"{\"keys\":[]}");
    }

    /// The refusal must name only the limit — never the bytes it read or the
    /// URL, which on some outbound paths can carry userinfo.
    #[tokio::test]
    async fn the_refusal_does_not_echo_the_body() {
        let err = read_body_capped(response_with_body(b"supersecretpayload", true), 4)
            .await
            .expect_err("over cap");
        let rendered = err.to_string();
        assert!(!rendered.contains("supersecret"), "got `{rendered}`");
    }
}
