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

    /// A successful establishment is bounded by [`HANDSHAKE_TIMEOUT`], so that
    /// bound must fall inside the establishment histogram's finite buckets.
    /// Otherwise slow-but-successful dials land only in the overflow bucket and
    /// a quantile saturates at the largest boundary instead of reporting the
    /// real tail. The telemetry crate is a leaf and cannot see this constant,
    /// so the coupling is checked from here, where both are visible.
    #[test]
    fn the_handshake_deadline_fits_inside_the_establishment_buckets() {
        let largest = waygate_telemetry::metrics::UPSTREAM_SESSION_ESTABLISH_BUCKETS
            .last()
            .copied()
            .expect("establishment buckets are not empty");
        assert!(
            largest >= HANDSHAKE_TIMEOUT.as_secs_f64(),
            "the largest finite establishment bucket ({largest}s) must cover the handshake \
             deadline ({}s); raising the deadline requires raising the bucket",
            HANDSHAKE_TIMEOUT.as_secs_f64(),
        );
    }
}
