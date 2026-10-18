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

    /// Override the gateway-wide raw-byte limit on one tool-call response.
    /// Default is [`DEFAULT_CALL_RESPONSE_MAX_BYTES`]; the
    /// `GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES` env var in
    /// `waygate-server::config` exposes this knob to operators.
    pub fn with_call_response_max_bytes(mut self, limit_bytes: usize) -> Self {
        self.call_response_max_bytes = limit_bytes;
        self
    }

    /// The call deadline for one call to the upstream `manifest` describes:
    /// its `limits.call_timeout_seconds` when set (`0` disables it), and the
    /// gateway-wide timeout otherwise. Read from the call's own manifest
    /// snapshot, so a reload applies a change to the next call.
    pub(super) fn call_timeout_for(&self, manifest: &UpstreamManifest) -> Option<Duration> {
        match manifest
            .limits
            .as_ref()
            .and_then(|limits| limits.call_timeout_seconds)
        {
            None => self.call_timeout,
            Some(0) => None,
            Some(seconds) => Some(Duration::from_secs(seconds)),
        }
    }

    /// The raw-byte limit on one tool-call response from the upstream
    /// `manifest` describes, or `None` when its transport cannot enforce one.
    /// Only the streamable-HTTP client can stop reading a response at a byte
    /// count; legacy SSE shares one inbound stream across requests and stdio
    /// reads whole lines.
    pub(super) fn call_response_limit_for(&self, manifest: &UpstreamManifest) -> Option<usize> {
        if !matches!(manifest.transport, crate::Transport::Http) {
            return None;
        }
        Some(
            manifest
                .limits
                .as_ref()
                .and_then(|limits| limits.call_response_max_bytes)
                .map_or(self.call_response_max_bytes, |bytes| {
                    usize::try_from(bytes).unwrap_or(usize::MAX)
                }),
        )
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
