//! Server-initiated MCP `ping` loop.
//!
//! The MCP ping utility is the spec's sanctioned connection-health probe:
//! implementations SHOULD periodically issue pings, the frequency SHOULD be
//! configurable, timeouts SHOULD be treated as connection failures, and
//! failures SHOULD be logged. This module implements the server side of
//! that contract for streamable-HTTP sessions: one detached task per
//! session, spawned when the client sends `notifications/initialized`.
//!
//! Beyond health detection, each ping puts a real JSON-RPC frame on the
//! standalone GET stream (and elicits a client POST in response), so the
//! loop doubles as an application-layer keepalive for clients that
//! implement none of their own — complementing the transport-level SSE
//! comment frames (`GATEWAY_SSE_KEEPALIVE_SECONDS`), which produce
//! server→client bytes only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::ServerRequest;
use rmcp::service::{Peer, RoleServer};

/// Consecutive ping timeouts after which the loop stops for the session's
/// remaining lifetime. Stopping (rather than pinging forever) is
/// load-bearing, not just polite: rmcp's session worker re-arms its idle
/// timer on OUTBOUND messages too, so a perpetual ping loop would keep a
/// dead client's session alive past the
/// `GATEWAY_SESSION_KEEPALIVE_SECONDS` reap forever. Once the loop stops,
/// the idle clock resumes counting from the last ping and the session
/// expires normally.
const MAX_CONSECUTIVE_TIMEOUTS: u64 = 3;

/// Ceiling on how long one ping waits for its pong. Short intervals wait
/// one full interval (so at most one ping is ever outstanding — each tick
/// awaits the previous send's resolution); long intervals cap at 30s so a
/// dead client is detected long before the next tick.
const MAX_PING_WAIT: Duration = Duration::from_secs(30);

pub(crate) fn ping_wait(interval: Duration) -> Duration {
    interval.min(MAX_PING_WAIT)
}

/// Per-loop counters, readable while the loop runs. Integration tests (and
/// any diagnostic surface) observe loop progress through this handle; the
/// process-wide Prometheus counters (`mcp_client_pings_total`) are bumped
/// alongside and serve operators.
#[derive(Debug, Default)]
pub struct PingStats {
    /// Pings sent (a send that timed out still counts as sent).
    pub sent: AtomicU64,
    /// Pongs received within the wait window.
    pub ok: AtomicU64,
    /// Pings that got no pong within the wait window.
    pub timed_out: AtomicU64,
    /// Times a loop stopped after `MAX_CONSECUTIVE_TIMEOUTS` — at most one
    /// per session.
    pub stopped: AtomicU64,
}

impl PingStats {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn ok(&self) -> u64 {
        self.ok.load(Ordering::Relaxed)
    }
    pub fn timed_out(&self) -> u64 {
        self.timed_out.load(Ordering::Relaxed)
    }
    pub fn stopped(&self) -> u64 {
        self.stopped.load(Ordering::Relaxed)
    }
}

/// Spawn the per-session ping loop. Detached on purpose: every exit path
/// is bounded — a closed session surfaces as a `send_request` error within
/// one interval + wait window, and repeated timeouts stop the loop after
/// `MAX_CONSECUTIVE_TIMEOUTS` — so no handle needs joining at shutdown.
pub(crate) fn spawn_ping_loop(
    peer: Peer<RoleServer>,
    interval: Duration,
    stats: Arc<PingStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let wait = ping_wait(interval);
        let mut consecutive_timeouts: u64 = 0;
        loop {
            tokio::time::sleep(interval).await;
            stats.sent.fetch_add(1, Ordering::Relaxed);
            let ping = ServerRequest::PingRequest(rmcp::model::PingRequest {
                method: Default::default(),
                extensions: Default::default(),
            });
            match tokio::time::timeout(wait, peer.send_request(ping)).await {
                Ok(Ok(_)) => {
                    consecutive_timeouts = 0;
                    stats.ok.fetch_add(1, Ordering::Relaxed);
                    waygate_telemetry::metrics::record_client_ping("ok");
                }
                Ok(Err(e)) => {
                    // The session/transport is gone — the normal loop exit.
                    tracing::debug!(error = %e, "client ping loop exiting: session closed");
                    waygate_telemetry::metrics::record_client_ping("session_closed");
                    return;
                }
                Err(_elapsed) => {
                    consecutive_timeouts += 1;
                    stats.timed_out.fetch_add(1, Ordering::Relaxed);
                    waygate_telemetry::metrics::record_client_ping("timeout");
                    tracing::debug!(
                        consecutive_timeouts,
                        wait_secs = wait.as_secs_f64(),
                        "client ping got no pong within the wait window"
                    );
                    if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                        stats.stopped.fetch_add(1, Ordering::Relaxed);
                        waygate_telemetry::metrics::record_client_ping("stopped");
                        tracing::info!(
                            consecutive_timeouts,
                            "client ping loop stopped: client unresponsive; \
                             session idle timeout resumes control"
                        );
                        return;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_wait_is_one_interval_for_short_intervals() {
        // At most one outstanding ping: each tick awaits the previous
        // send's resolution, so the wait window must not exceed the
        // interval for sub-30s cadences.
        let interval = Duration::from_millis(200);
        assert_eq!(ping_wait(interval), interval);
    }

    #[test]
    fn ping_wait_caps_at_thirty_seconds_for_long_intervals() {
        // A 10-minute cadence must not wait 10 minutes to declare a ping
        // lost — detection stays bounded regardless of interval.
        assert_eq!(ping_wait(Duration::from_secs(600)), MAX_PING_WAIT);
    }
}
