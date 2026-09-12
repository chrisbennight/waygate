//! Construction-time overrides for the upstream pool.

use super::*;

impl UpstreamPool {
    /// Override the per-call upstream timeout. Pass `None` to disable
    /// (calls then rely on transport closure or caller cancellation).
    /// Default is 300s (5 minutes); the
    /// `GATEWAY_UPSTREAM_CALL_TIMEOUT_SECONDS` env var in
    /// `waygate-server::config` exposes this knob to operators.
    pub fn with_call_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// Override the per-lane [`DEFAULT_REDIAL_DIAL_TIMEOUT`] used by a
    /// live re-dial. Mainly for tests (a short bound so the black-hole-target
    /// path is exercised quickly); operators can leave the 15s default.
    pub fn with_redial_dial_timeout(mut self, timeout: Duration) -> Self {
        self.redial_dial_timeout = timeout;
        self
    }

    /// Override the tool-contract drift auto-quarantine threshold (normally read from
    /// `GATEWAY_QUARANTINE_ON_DRIFT_RISK` at [`connect`](Self::connect)). Lets a
    /// caller or test exercise drift detection without mutating the process
    /// environment.
    pub fn with_quarantine_threshold(mut self, threshold: QuarantineThreshold) -> Self {
        self.quarantine_threshold = threshold;
        self
    }
}
