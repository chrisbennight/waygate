//! Per-upstream circuit breaker.
//!
//! Three states:
//! * **Closed** — calls flow through. Consecutive failures are counted;
//!   reaching `failure_threshold` trips the breaker to `Open`.
//! * **Open** — calls are rejected immediately with [`BreakerError::Open`]
//!   for `open_duration` after the trip. This keeps the gateway responsive
//!   while a flapping upstream is down and prevents thread-pile-ups on a
//!   hung rmcp client.
//! * **HalfOpen** — once the cooldown has elapsed, the next call is allowed
//!   as a single probe. Success → close; failure → re-open for another
//!   cooldown. Concurrent calls during half-open are still rejected so a
//!   burst of traffic doesn't defeat the probe semantics.
//!
//! Successful calls in `Closed` state reset the failure counter; this keeps
//! intermittent blips from accumulating across minutes of healthy traffic.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    pub failure_threshold: u32,
    pub open_duration: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    /// Stable operator/API label for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerError {
    /// Breaker is tripped; rejected without attempting the call.
    Open,
    /// Half-open probe already in flight; rejected to preserve single-flight
    /// probe semantics.
    ProbeInFlight,
}

#[derive(Debug)]
struct State {
    state: BreakerState,
    failures: u32,
    opened_at: Option<Instant>,
    /// True while a half-open probe is in flight. Any concurrent call during
    /// the probe window is rejected with `ProbeInFlight`.
    probe_running: bool,
}

#[derive(Debug)]
pub struct Breaker {
    cfg: BreakerConfig,
    inner: Mutex<State>,
    open_notify: Option<Arc<Notify>>,
}

impl Breaker {
    pub fn new(cfg: BreakerConfig) -> Self {
        Self::new_inner(cfg, None)
    }

    pub(crate) fn new_with_open_notify(cfg: BreakerConfig, open_notify: Arc<Notify>) -> Self {
        Self::new_inner(cfg, Some(open_notify))
    }

    fn new_inner(cfg: BreakerConfig, open_notify: Option<Arc<Notify>>) -> Self {
        Self {
            cfg,
            inner: Mutex::new(State {
                state: BreakerState::Closed,
                failures: 0,
                opened_at: None,
                probe_running: false,
            }),
            open_notify,
        }
    }

    /// Check whether a call may proceed. Returns a [`Permit`] the caller
    /// must report back to via `success()` / `failure()`. Dropping the
    /// permit without reporting defaults to `failure()` — better to
    /// pessimistically count a panic or task cancellation as a failure
    /// than to leave the breaker unable to trip.
    pub fn acquire(&self) -> Result<Permit<'_>, BreakerError> {
        let mut g = self.inner.lock().expect("breaker mutex poisoned");
        match g.state {
            BreakerState::Closed => Ok(Permit::closed(self)),
            BreakerState::Open => {
                let elapsed = g.opened_at.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
                if elapsed >= self.cfg.open_duration {
                    g.state = BreakerState::HalfOpen;
                    g.probe_running = true;
                    Ok(Permit::half_open(self))
                } else {
                    Err(BreakerError::Open)
                }
            }
            BreakerState::HalfOpen => {
                if g.probe_running {
                    Err(BreakerError::ProbeInFlight)
                } else {
                    g.probe_running = true;
                    Ok(Permit::half_open(self))
                }
            }
        }
    }

    pub fn state(&self) -> BreakerState {
        self.inner.lock().expect("breaker mutex poisoned").state
    }

    /// Force the breaker back to `Closed` with a fresh failure count. Called
    /// by the pool's reconnect path after it installs a brand-new rmcp
    /// session — without this, the next call would still hit the Open /
    /// HalfOpen machinery from the dead session's failures and reject for up
    /// to one `open_duration` window.
    pub fn reset(&self) {
        let mut g = self.inner.lock().expect("breaker mutex poisoned");
        g.state = BreakerState::Closed;
        g.failures = 0;
        g.opened_at = None;
        g.probe_running = false;
    }

    fn on_success(&self, was_probe: bool) -> bool {
        let mut g = self.inner.lock().expect("breaker mutex poisoned");
        let recovered = was_probe && g.state == BreakerState::HalfOpen && g.probe_running;
        g.failures = 0;
        if was_probe {
            g.probe_running = false;
        }
        g.state = BreakerState::Closed;
        g.opened_at = None;
        recovered
    }

    /// Release a half-open probe slot WITHOUT recording success or failure, so
    /// the next call can take a fresh probe. Used by [`Permit::neutral`] when a
    /// probe-state permit is released for a reason unrelated to upstream health
    /// (a local config-change refusal): the upstream was never actually probed,
    /// so leave the breaker HalfOpen and let the next call test it for real.
    /// Without this, `probe_running` would stay `true` forever and every
    /// subsequent call would be rejected with `ProbeInFlight`.
    fn release_probe(&self) {
        let mut g = self.inner.lock().expect("breaker mutex poisoned");
        g.probe_running = false;
    }

    fn on_failure(&self, was_probe: bool) {
        let mut g = self.inner.lock().expect("breaker mutex poisoned");
        let opened = if was_probe {
            g.probe_running = false;
            g.state = BreakerState::Open;
            g.opened_at = Some(Instant::now());
            // Keep failure count parked at the threshold so a subsequent
            // success still looks like a recovery rather than "off by one".
            g.failures = self.cfg.failure_threshold;
            true
        } else {
            g.failures = g.failures.saturating_add(1);
            if g.failures >= self.cfg.failure_threshold {
                let transitioned = g.state != BreakerState::Open;
                g.state = BreakerState::Open;
                g.opened_at = Some(Instant::now());
                transitioned
            } else {
                false
            }
        };
        drop(g);
        if opened {
            if let Some(notify) = &self.open_notify {
                notify.notify_waiters();
            }
        }
    }
}

#[derive(Debug)]
pub struct Permit<'a> {
    breaker: &'a Breaker,
    was_probe: bool,
    /// Set to true when `success()` / `failure()` has been called. Used by
    /// `Drop` to decide whether to auto-fail.
    reported: bool,
}

impl<'a> Permit<'a> {
    fn closed(b: &'a Breaker) -> Self {
        Self {
            breaker: b,
            was_probe: false,
            reported: false,
        }
    }
    fn half_open(b: &'a Breaker) -> Self {
        Self {
            breaker: b,
            was_probe: true,
            reported: false,
        }
    }

    /// Record a healthy upstream response and report whether this permit
    /// completed the breaker's `HalfOpen` to `Closed` recovery transition.
    pub fn success(mut self) -> bool {
        let recovered = self.breaker.on_success(self.was_probe);
        self.reported = true;
        recovered
    }

    pub fn failure(mut self) {
        self.breaker.on_failure(self.was_probe);
        self.reported = true;
    }

    /// Release the permit WITHOUT recording a success or a failure: the outcome
    /// carried no signal about upstream health. Used when the gateway refuses a
    /// call locally for a reason unrelated to the upstream — e.g. a live config
    /// re-dial landed during call setup and the caller will retry. Neither
    /// advances the failure count nor resets it, so a burst of these during a
    /// reload can't trip the circuit on a healthy upstream, nor hide a real
    /// failure streak.
    pub fn neutral(mut self) {
        if self.was_probe {
            self.breaker.release_probe();
        }
        self.reported = true;
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.reported {
            // Cancellation/panic path: count as failure. Safer than
            // silently releasing because an uncounted cancel that
            // corresponds to a hung upstream would keep the breaker
            // closed forever.
            self.breaker.on_failure(self.was_probe);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: u32, open_ms: u64) -> BreakerConfig {
        BreakerConfig {
            failure_threshold: threshold,
            open_duration: Duration::from_millis(open_ms),
        }
    }

    #[test]
    fn closed_allows_calls() {
        let b = Breaker::new(cfg(3, 100));
        let p = b.acquire().expect("closed");
        p.success();
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn trips_open_after_threshold_failures() {
        let b = Breaker::new(cfg(3, 100));
        for _ in 0..3 {
            b.acquire().expect("closed").failure();
        }
        assert_eq!(b.state(), BreakerState::Open);
        assert_eq!(b.acquire().unwrap_err(), BreakerError::Open);
    }

    #[tokio::test]
    async fn cancellation_trip_notifies_recovery_waiter() {
        let notify = Arc::new(Notify::new());
        let b = Breaker::new_with_open_notify(cfg(2, 100), notify.clone());
        let notified = notify.notified();

        drop(b.acquire().expect("first cancelled call"));
        drop(b.acquire().expect("second cancelled call"));

        notified.await;
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn success_resets_failure_count() {
        let b = Breaker::new(cfg(3, 100));
        b.acquire().unwrap().failure();
        b.acquire().unwrap().failure();
        b.acquire().unwrap().success(); // resets
        for _ in 0..2 {
            b.acquire().unwrap().failure();
        }
        // Only 2 consecutive failures after the reset → still closed.
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_probe_success_closes() {
        let b = Breaker::new(cfg(1, 10));
        b.acquire().unwrap().failure(); // trips open
        std::thread::sleep(Duration::from_millis(15));
        let p = b.acquire().expect("half-open probe");
        assert!(p.success());
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(
            !b.acquire().expect("ordinary closed permit").success(),
            "only the half-open transition reports recovery",
        );
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        let b = Breaker::new(cfg(1, 10));
        b.acquire().unwrap().failure();
        std::thread::sleep(Duration::from_millis(15));
        b.acquire().unwrap().failure(); // probe fails
        assert_eq!(b.state(), BreakerState::Open);
        assert_eq!(b.acquire().unwrap_err(), BreakerError::Open);
    }

    #[test]
    fn half_open_rejects_concurrent_probes() {
        let b = Breaker::new(cfg(1, 10));
        b.acquire().unwrap().failure();
        std::thread::sleep(Duration::from_millis(15));
        let _probe = b.acquire().expect("first probe");
        // Second concurrent acquire during probe → rejected.
        assert_eq!(b.acquire().unwrap_err(), BreakerError::ProbeInFlight);
    }

    #[test]
    fn reset_returns_open_breaker_to_closed() {
        let b = Breaker::new(cfg(2, 60_000));
        b.acquire().unwrap().failure();
        b.acquire().unwrap().failure();
        assert_eq!(b.state(), BreakerState::Open);
        b.reset();
        assert_eq!(b.state(), BreakerState::Closed);
        // Fresh failure budget after reset — needs the full threshold again.
        b.acquire().unwrap().failure();
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn dropped_permit_counts_as_failure() {
        let b = Breaker::new(cfg(2, 100));
        {
            let _p = b.acquire().expect("closed");
            // dropped without reporting
        }
        {
            let _p = b.acquire().expect("closed");
        }
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn neutral_permit_neither_trips_nor_resets_the_breaker() {
        // A burst of neutral dispositions must NOT trip the circuit on a healthy
        // upstream — even well past the failure threshold.
        let b = Breaker::new(cfg(2, 100));
        for _ in 0..10 {
            b.acquire().expect("closed").neutral();
        }
        assert_eq!(
            b.state(),
            BreakerState::Closed,
            "neutral must not trip the breaker"
        );

        // ...and a neutral in the middle of a real failure streak must NOT reset
        // it — the upstream is still failing.
        b.acquire().expect("closed").failure(); // streak = 1
        b.acquire().expect("closed").neutral(); // streak unchanged
        b.acquire().expect("closed").failure(); // streak = 2 → trips (threshold 2)
        assert_eq!(
            b.state(),
            BreakerState::Open,
            "neutral must not reset a real failure streak",
        );
    }

    #[test]
    fn neutral_releases_a_half_open_probe_slot() {
        // Trip the breaker, then let the cooldown elapse so the next acquire is
        // a half-open probe.
        let b = Breaker::new(cfg(1, 5));
        b.acquire().expect("closed").failure();
        assert_eq!(b.state(), BreakerState::Open);
        std::thread::sleep(Duration::from_millis(10));
        let probe = b.acquire().expect("cooldown elapsed ⇒ half-open probe");
        // Releasing the probe NEUTRALLY (a config-change refusal) must free the
        // probe slot — otherwise `probe_running` stays set and every later call
        // is rejected with ProbeInFlight, wedging a healthy upstream.
        probe.neutral();
        assert!(
            b.acquire().is_ok(),
            "a neutral probe release must let the next call take a fresh probe",
        );
    }
}
