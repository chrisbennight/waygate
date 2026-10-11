//! Outbound HTTP policy shared by the runtime upstream dialer and `classify`.
//!
//! MCP receive streams may legitimately outlive ordinary request deadlines, so
//! their client has no total timeout. Connection establishment, the initial
//! protocol handshake, and legacy-SSE message writes remain independently
//! bounded by the constants in this module.

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

/// Build the common streaming client policy while leaving room for per-upstream
/// TLS identity and trust material.
pub(crate) fn streaming_builder() -> reqwest::ClientBuilder {
    http_client::builder(Profile::NoTotalTimeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_max_idle_per_host(0)
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
