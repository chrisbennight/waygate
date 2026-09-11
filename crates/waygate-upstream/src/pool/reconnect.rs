//! Per-upstream reconnect scheduling.
//!
//! The scheduler state lives with the entry it governs. A distressed server
//! therefore cannot impose its retry cadence on another server, and replacing
//! an entry on manifest reload also replaces its failure episode.

use std::time::{Duration, Instant};

use time::OffsetDateTime;

use super::UpstreamPool;
use crate::{
    transport::{self, CredentialMaterialVersion},
    UpstreamManifest,
};

const DEFAULT_BASE: Duration = Duration::from_secs(60);
const DEFAULT_CEILING: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy)]
pub(super) struct ReconnectPolicy {
    base: Duration,
    ceiling: Duration,
    seed: u64,
    credential_key: [u8; 32],
}

impl ReconnectPolicy {
    pub(super) fn random() -> Self {
        use rand::Rng as _;

        let mut rng = rand::rng();
        let mut credential_key = [0; 32];
        rng.fill_bytes(&mut credential_key);
        Self {
            base: DEFAULT_BASE,
            ceiling: DEFAULT_CEILING,
            seed: rng.next_u64(),
            credential_key,
        }
    }

    pub(super) fn configured(self, base: Duration, ceiling: Duration) -> Self {
        debug_assert!(!base.is_zero());
        debug_assert!(ceiling >= base);
        Self {
            base,
            ceiling,
            ..self
        }
    }

    fn for_server(self, server: &str) -> ServerReconnectPolicy {
        ServerReconnectPolicy {
            base: self.base,
            ceiling: self.ceiling,
            seed: mix64(self.seed ^ stable_hash(server.as_bytes())),
        }
    }

    pub(super) fn credential_key(&self) -> &[u8; 32] {
        &self.credential_key
    }
}

#[derive(Debug, Clone, Copy)]
struct ServerReconnectPolicy {
    base: Duration,
    ceiling: Duration,
    seed: u64,
}

/// Result of advancing a failure episode after one reconnect attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReconnectFailure {
    pub(super) episode_started: bool,
    pub(super) episode_attempt: u64,
    pub(super) backoff: Duration,
}

#[derive(Debug, Clone)]
pub(super) struct ReconnectState {
    policy: ServerReconnectPolicy,
    credential_version: CredentialMaterialVersion,
    /// Monotonic witness for optimistic outcome finalization. Any recovery
    /// state observation made before an await must compare this value again
    /// before clearing schedules or failure episodes.
    revision: u64,
    consecutive_failures: u32,
    episode_attempts: u64,
    jitter_generation: u64,
    current_backoff: Option<Duration>,
    next_retry: Option<Instant>,
    next_retry_at: Option<OffsetDateTime>,
    active_claim: Option<u64>,
    next_claim: u64,
}

impl ReconnectState {
    pub(super) fn after_boot_manifest(
        policy: ReconnectPolicy,
        server: &str,
        needs_recovery: bool,
        manifest: &UpstreamManifest,
    ) -> Self {
        let credential_version =
            transport::credential_material_version(manifest, policy.credential_key());
        Self::after_boot(policy, server, needs_recovery, credential_version)
    }

    pub(super) fn after_boot(
        policy: ReconnectPolicy,
        server: &str,
        needs_recovery: bool,
        credential_version: CredentialMaterialVersion,
    ) -> Self {
        Self::after_boot_at(
            policy,
            server,
            needs_recovery,
            credential_version,
            Instant::now(),
            OffsetDateTime::now_utc(),
        )
    }

    fn after_boot_at(
        policy: ReconnectPolicy,
        server: &str,
        needs_recovery: bool,
        credential_version: CredentialMaterialVersion,
        now: Instant,
        wall: OffsetDateTime,
    ) -> Self {
        let mut state = Self {
            policy: policy.for_server(server),
            credential_version,
            revision: 0,
            // A failed boot dial is already the first consecutive transport
            // failure, even though evidence is attached only after boot.
            consecutive_failures: u32::from(needs_recovery),
            episode_attempts: 0,
            jitter_generation: 0,
            current_backoff: None,
            next_retry: None,
            next_retry_at: None,
            active_claim: None,
            next_claim: 0,
        };
        if needs_recovery {
            state.schedule(state.policy.base, now, wall);
        }
        state
    }

    pub(super) fn reconfigure(
        &mut self,
        policy: ReconnectPolicy,
        server: &str,
        needs_recovery: bool,
    ) {
        self.policy = policy.for_server(server);
        self.reset(needs_recovery, Instant::now(), OffsetDateTime::now_utc());
    }

    /// Arm the first retry after an ordinary runtime failure without
    /// escalating for repeated RPC failures. Only failed reconnect dials
    /// advance the reconnect backoff itself.
    pub(super) fn observe_runtime_failure(&mut self) {
        self.observe_runtime_failure_at(Instant::now(), OffsetDateTime::now_utc());
    }

    fn observe_runtime_failure_at(&mut self, now: Instant, wall: OffsetDateTime) {
        // Even an already-scheduled failure invalidates a success snapshot:
        // it may represent a different lane failing while recovery is active.
        self.advance_revision();
        if self.next_retry.is_none() && self.active_claim.is_none() {
            self.consecutive_failures = 0;
            self.schedule(self.policy.base, now, wall);
        }
    }

    /// Start a fresh episode before an explicit operator attempt while keeping
    /// a base-delay fallback armed if the attempt future is cancelled.
    pub(super) fn reset_for_operator(&mut self) {
        self.reset(true, Instant::now(), OffsetDateTime::now_utc());
    }

    pub(super) fn record_failure(&mut self) -> ReconnectFailure {
        self.record_failure_at(Instant::now(), OffsetDateTime::now_utc())
    }

    /// Apply a failed dial only if no newer lane/reload transition has changed
    /// the recovery state sampled at install time.
    pub(super) fn record_failure_if_revision(
        &mut self,
        expected: u64,
        credential_version: CredentialMaterialVersion,
    ) -> Option<ReconnectFailure> {
        if self.revision != expected {
            return None;
        }
        self.credential_version = credential_version;
        Some(self.record_failure())
    }

    fn record_failure_at(&mut self, now: Instant, wall: OffsetDateTime) -> ReconnectFailure {
        self.advance_revision();
        let episode_started = self.episode_attempts == 0;
        self.episode_attempts = self.episode_attempts.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.active_claim = None;
        let cap = exponential_cap(
            self.policy.base,
            self.policy.ceiling,
            self.consecutive_failures,
        );
        let backoff = self.schedule(cap, now, wall);
        ReconnectFailure {
            episode_started,
            episode_attempt: self.episode_attempts,
            backoff,
        }
    }

    pub(super) fn record_success(&mut self, needs_recovery: bool) {
        self.record_success_at(needs_recovery, Instant::now(), OffsetDateTime::now_utc());
    }

    /// Apply a success derived from an earlier lane snapshot only if no newer
    /// failure or operator transition has changed recovery state since then.
    pub(super) fn record_success_if_revision(
        &mut self,
        expected: u64,
        needs_recovery: bool,
        credential_version: CredentialMaterialVersion,
    ) -> bool {
        if self.revision != expected {
            return false;
        }
        self.credential_version = credential_version;
        self.record_success(needs_recovery);
        true
    }

    /// Observe current dial inputs. Returns true exactly once per material
    /// change so a relevant credential rotation can start a fresh episode
    /// without letting repeated no-op SIGHUPs collapse the backoff.
    pub(super) fn update_credential_version(
        &mut self,
        credential_version: CredentialMaterialVersion,
    ) -> bool {
        if self.credential_version == credential_version {
            return false;
        }
        self.credential_version = credential_version;
        true
    }

    fn record_success_at(&mut self, needs_recovery: bool, now: Instant, wall: OffsetDateTime) {
        self.reset(needs_recovery, now, wall);
    }

    fn reset(&mut self, needs_recovery: bool, now: Instant, wall: OffsetDateTime) {
        self.advance_revision();
        self.consecutive_failures = 0;
        self.episode_attempts = 0;
        self.current_backoff = None;
        self.next_retry = None;
        self.next_retry_at = None;
        self.active_claim = None;
        if needs_recovery {
            self.schedule(self.policy.base, now, wall);
        }
    }

    fn schedule(&mut self, cap: Duration, now: Instant, wall: OffsetDateTime) -> Duration {
        self.jitter_generation = self.jitter_generation.wrapping_add(1);
        let backoff = full_jitter(cap, self.policy.seed, self.jitter_generation);
        self.current_backoff = Some(backoff);
        self.next_retry = now.checked_add(backoff);
        self.next_retry_at = time::Duration::try_from(backoff)
            .ok()
            .and_then(|delay| wall.checked_add(delay));
        backoff
    }

    pub(super) fn claim_due(&mut self, now: Instant) -> Option<u64> {
        if self.active_claim.is_some() || !self.next_retry.is_some_and(|deadline| deadline <= now) {
            return None;
        }
        self.advance_revision();
        self.next_claim = self.next_claim.wrapping_add(1);
        self.active_claim = Some(self.next_claim);
        self.current_backoff = None;
        self.next_retry = None;
        self.next_retry_at = None;
        self.active_claim
    }

    #[cfg(test)]
    pub(super) fn is_due(&self, now: Instant) -> bool {
        self.active_claim.is_none() && self.next_retry.is_some_and(|deadline| deadline <= now)
    }

    pub(super) fn claim_is_active(&self, claim: u64) -> bool {
        self.active_claim == Some(claim)
    }

    /// Release a claimed attempt that ended before it could report success or
    /// failure. This is also the cancellation/panic fallback used by the
    /// scheduler's claim guard.
    pub(super) fn release_claim(&mut self, claim: u64, needs_recovery: bool) -> bool {
        if !self.claim_is_active(claim) {
            return false;
        }
        self.advance_revision();
        self.active_claim = None;
        self.current_backoff = None;
        self.next_retry = None;
        self.next_retry_at = None;
        if needs_recovery {
            self.schedule(self.policy.base, Instant::now(), OffsetDateTime::now_utc());
        }
        true
    }

    pub(super) fn delay(&self, now: Instant) -> Option<Duration> {
        if self.active_claim.is_some() {
            return None;
        }
        self.next_retry
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    pub(super) fn snapshot(&self) -> (Option<Duration>, Option<OffsetDateTime>) {
        (self.current_backoff, self.next_retry_at)
    }

    pub(super) fn is_scheduled(&self) -> bool {
        self.next_retry.is_some() || self.active_claim.is_some()
    }

    pub(super) fn episode_attempts(&self) -> u64 {
        self.episode_attempts
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    fn advance_revision(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /// Stable per-entry fraction used to spread catalog deadlines within the
    /// operator-approved `[floor, effective_ttl]` window. This never makes a
    /// catalog older than its hint/ceiling or refreshes faster than the floor.
    pub(super) fn jitter_catalog_interval(
        &self,
        floor: Duration,
        effective_ttl: Duration,
    ) -> Duration {
        let slack = effective_ttl.saturating_sub(floor);
        let max_advance = slack.min(effective_ttl / 10);
        effective_ttl.saturating_sub(full_jitter(max_advance, self.policy.seed, u64::MAX))
    }
}

impl UpstreamPool {
    /// Wait until the earliest per-upstream retry deadline becomes due. A new
    /// runtime failure or policy reset wakes the scan so a late, ceiling-sized
    /// sleep can never hide newly distressed work.
    pub async fn wait_for_reconnect_due(&self) {
        loop {
            let notified = self.reconnect_notify.notified();
            tokio::pin!(notified);
            // `notify_waiters` only wakes waiters that are already registered;
            // constructing `Notified` is not registration until its first poll.
            // Enable it before the scan so a failure observed in the
            // scan-to-sleep window cannot strand an otherwise empty schedule.
            notified.as_mut().enable();
            let now = Instant::now();
            let map = self.entries.load_full();
            let mut unscheduled_open = Vec::new();
            for (name, entry) in map.iter() {
                if !entry.removed.load(std::sync::atomic::Ordering::Acquire)
                    && entry.breaker.state() == crate::breaker::BreakerState::Open
                {
                    let scheduled = entry
                        .reconnect
                        .lock()
                        .expect("upstream reconnect lock poisoned")
                        .is_scheduled();
                    if !scheduled {
                        unscheduled_open.push((name.clone(), entry.clone()));
                    }
                }
            }
            for (name, entry) in unscheduled_open {
                self.arm_reconnect(&name, &entry).await;
            }
            let delay = map
                .values()
                .filter_map(|entry| {
                    entry
                        .reconnect
                        .lock()
                        .expect("upstream reconnect lock poisoned")
                        .delay(now)
                })
                .min();
            #[cfg(test)]
            self.pause_after_reconnect_scan().await;
            match delay {
                Some(delay) if delay.is_zero() => return,
                Some(delay) => {
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => return,
                        _ = notified.as_mut() => {}
                    }
                }
                None => notified.as_mut().await,
            }
        }
    }

    #[cfg(test)]
    async fn pause_after_reconnect_scan(&self) {
        let hook = self
            .reconnect_commit_hook
            .lock()
            .expect("reconnect wait hook lock poisoned")
            .take();
        if let Some((reached, resume)) = hook {
            reached.notify_one();
            resume.notified().await;
        }
    }
}

pub(super) fn publish_schedule(server: &str, state: &ReconnectState) {
    let (backoff, next_retry_at) = state.snapshot();
    waygate_telemetry::metrics::set_upstream_reconnect_schedule(
        server,
        backoff,
        next_retry_at.map(OffsetDateTime::unix_timestamp),
    );
}

fn exponential_cap(base: Duration, ceiling: Duration, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(63);
    base.checked_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .unwrap_or(ceiling)
        .min(ceiling)
}

fn full_jitter(cap: Duration, seed: u64, generation: u64) -> Duration {
    let cap_ms = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX);
    if cap_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(mix64(seed ^ generation) % (cap_ms.saturating_add(1)))
}

fn stable_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x1000_0000_01b3)
    })
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use crate::{Transport, UpstreamAuth, UpstreamManifest};

    fn policy(base: u64, ceiling: u64) -> ReconnectPolicy {
        ReconnectPolicy {
            base: Duration::from_secs(base),
            ceiling: Duration::from_secs(ceiling),
            seed: 7,
            credential_key: [9; 32],
        }
    }

    fn credential_version(value: u8) -> CredentialMaterialVersion {
        CredentialMaterialVersion::test_value(value)
    }

    fn stdio_manifest(name: &str, command: Vec<&str>) -> UpstreamManifest {
        UpstreamManifest {
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            name: name.to_owned(),
            transport: Transport::Stdio,
            protocol: Default::default(),
            url: None,
            command: Some(command.into_iter().map(str::to_owned).collect()),
            tools: Vec::new(),
            resources: Vec::new(),
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        }
    }

    fn http_manifest_with_bearer(name: &str, bearer_env: &str) -> UpstreamManifest {
        UpstreamManifest {
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            name: name.to_owned(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some("http://127.0.0.1:1/mcp".to_owned()),
            command: None,
            tools: Vec::new(),
            resources: Vec::new(),
            exchange: None,
            auth: Some(UpstreamAuth {
                bearer_env: Some(bearer_env.to_owned()),
                ..Default::default()
            }),
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        }
    }

    fn disconnected_pool(manifests: Vec<UpstreamManifest>, timeout: Duration) -> UpstreamPool {
        let manifests = manifests
            .into_iter()
            .map(|manifest| (manifest.name.clone(), manifest))
            .collect::<BTreeMap<_, _>>();
        UpstreamPool::from_manifests_disconnected(manifests).with_redial_dial_timeout(timeout)
    }

    fn force_deadline(entry: &super::super::UpstreamEntry, deadline: Instant) {
        let mut state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        state.active_claim = None;
        state.current_backoff = Some(deadline.saturating_duration_since(Instant::now()));
        state.next_retry = Some(deadline);
        state.next_retry_at = Some(OffsetDateTime::now_utc());
    }

    fn reconnect_backoff_gauge(server: &str) -> Option<f64> {
        waygate_telemetry::gather_text().lines().find_map(|line| {
            (line.starts_with("mcp_upstream_reconnect_backoff_seconds")
                && line.contains(&format!("server=\"{server}\"")))
            .then(|| line.rsplit_once(' ')?.1.parse().ok())
            .flatten()
        })
    }

    #[test]
    fn exponential_backoff_escalates_and_stops_at_the_ceiling() {
        assert_eq!(
            exponential_cap(Duration::from_secs(5), Duration::from_secs(20), 1),
            Duration::from_secs(5)
        );
        assert_eq!(
            exponential_cap(Duration::from_secs(5), Duration::from_secs(20), 2),
            Duration::from_secs(10)
        );
        assert_eq!(
            exponential_cap(Duration::from_secs(5), Duration::from_secs(20), 3),
            Duration::from_secs(20)
        );
        assert_eq!(
            exponential_cap(Duration::from_secs(5), Duration::from_secs(20), 40),
            Duration::from_secs(20)
        );
    }

    #[test]
    fn full_jitter_is_deterministic_and_bounded() {
        let cap = Duration::from_secs(10);
        let first = full_jitter(cap, 42, 1);
        assert_eq!(first, full_jitter(cap, 42, 1));
        assert!(first <= cap);
        assert_ne!(first, full_jitter(cap, 42, 2));
    }

    #[test]
    fn success_and_operator_reset_end_the_failure_episode() {
        let mut state =
            ReconnectState::after_boot(policy(5, 20), "kagi", true, credential_version(1));
        let first = state.record_failure();
        let second = state.record_failure();
        assert!(first.episode_started);
        assert_eq!(second.episode_attempt, 2);
        state.record_success(false);
        assert_eq!(state.snapshot(), (None, None));

        state.observe_runtime_failure();
        assert!(state.snapshot().1.is_some());
        state.reset_for_operator();
        assert!(state.snapshot().0.is_some());
        assert!(state.snapshot().1.is_some());
        assert!(state.record_failure().episode_started);
    }

    #[test]
    fn stale_redial_success_cannot_clear_a_newer_lane_failure() {
        let mut state =
            ReconnectState::after_boot(policy(5, 20), "versioned", false, credential_version(1));
        let revision_at_install = state.revision();

        state.observe_runtime_failure();
        let newer_schedule = state.snapshot();
        let newer_revision = state.revision();

        assert!(!state.record_success_if_revision(
            revision_at_install,
            false,
            credential_version(2),
        ));
        assert_eq!(state.revision(), newer_revision);
        assert_eq!(state.snapshot(), newer_schedule);
        assert!(state.is_scheduled());

        assert!(state.record_success_if_revision(newer_revision, false, credential_version(2),));
        assert!(!state.is_scheduled());
    }

    #[test]
    fn stale_reconnect_failure_cannot_overwrite_a_newer_redial_success() {
        let mut state =
            ReconnectState::after_boot(policy(5, 20), "versioned", true, credential_version(1));
        let revision_at_install = state.revision();

        state.record_success(false);
        let recovered_revision = state.revision();
        assert_eq!(state.snapshot(), (None, None));

        assert!(state
            .record_failure_if_revision(revision_at_install, credential_version(1))
            .is_none());
        assert_eq!(state.revision(), recovered_revision);
        assert_eq!(state.snapshot(), (None, None));
        assert_eq!(state.episode_attempts(), 0);
    }

    #[test]
    fn stale_reconnect_success_leaves_its_claim_to_rearm_after_a_newer_failure() {
        let now = Instant::now();
        let mut state =
            ReconnectState::after_boot(policy(5, 20), "claimed", true, credential_version(1));
        let claim = state
            .claim_due(now + Duration::from_secs(30))
            .expect("boot retry is due");
        let revision_at_install = state.revision();

        // A lane can fail after reconnect installed its snapshot but before
        // the awaited outcome finalizer runs. The active claim intentionally
        // defers scheduling to its cancellation-safe guard.
        state.observe_runtime_failure();
        assert!(!state.record_success_if_revision(
            revision_at_install,
            false,
            credential_version(2),
        ));
        assert!(state.claim_is_active(claim));
        assert_eq!(state.snapshot(), (None, None));

        assert!(state.release_claim(claim, true));
        assert!(state.is_scheduled());
    }

    #[test]
    fn catalog_jitter_stays_between_floor_and_deadline() {
        let state = ReconnectState::after_boot(policy(5, 20), "kagi", false, credential_version(1));
        let floor = Duration::from_secs(60);
        let ttl = Duration::from_secs(900);
        let interval = state.jitter_catalog_interval(floor, ttl);
        assert!((floor..=ttl).contains(&interval));
        assert!(interval >= ttl - ttl / 10);
        assert_eq!(state.jitter_catalog_interval(floor, ttl), interval);
    }

    #[test]
    fn fake_time_pins_deadlines_escalation_and_reset() {
        let now = Instant::now();
        let wall = OffsetDateTime::UNIX_EPOCH;
        let mut state = ReconnectState::after_boot_at(
            policy(5, 20),
            "kagi",
            true,
            credential_version(1),
            now,
            wall,
        );
        let (initial_backoff, initial_deadline) = state.snapshot();
        let initial_backoff = initial_backoff.expect("boot failure schedules a retry");
        assert!(initial_backoff <= Duration::from_secs(5));
        assert_eq!(
            initial_deadline,
            Some(wall + time::Duration::try_from(initial_backoff).unwrap())
        );
        assert_eq!(state.delay(now), Some(initial_backoff));

        let retry_now = now + Duration::from_secs(30);
        let retry_wall = wall + time::Duration::seconds(30);
        let second = state.record_failure_at(retry_now, retry_wall);
        assert!(second.backoff <= Duration::from_secs(10));
        let third = state.record_failure_at(retry_now, retry_wall);
        assert!(third.backoff <= Duration::from_secs(20));
        let capped = state.record_failure_at(retry_now, retry_wall);
        assert!(capped.backoff <= Duration::from_secs(20));

        state.record_success_at(false, retry_now, retry_wall);
        assert_eq!(state.snapshot(), (None, None));
        assert!(!state.is_due(retry_now + Duration::from_secs(3600)));
    }

    #[test]
    fn claimed_deadline_is_hidden_until_attempt_settles() {
        let now = Instant::now();
        let mut state = ReconnectState::after_boot_at(
            policy(5, 20),
            "kagi",
            true,
            credential_version(1),
            now - Duration::from_secs(30),
            OffsetDateTime::UNIX_EPOCH,
        );

        let claim = state.claim_due(now).expect("due deadline is claimed");
        assert_eq!(state.claim_due(now), None);
        assert_eq!(state.delay(now), None);
        state.observe_runtime_failure();
        assert_eq!(state.delay(now), None);

        assert!(state.release_claim(claim, true));
        assert!(state.snapshot().1.is_some());
    }

    #[tokio::test]
    async fn cancellation_only_breaker_trip_arms_scheduler_deadline() {
        let pool = Arc::new(
            disconnected_pool(
                vec![stdio_manifest("cancelled", vec!["/does-not-run"])],
                Duration::from_millis(50),
            )
            .with_reconnect_policy(Duration::from_millis(1), Duration::from_millis(1)),
        );
        let entry = pool
            .entries
            .load()
            .get("cancelled")
            .expect("entry exists")
            .clone();
        {
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            state.record_success(false);
        }

        let waiting_pool = Arc::clone(&pool);
        let waiter = tokio::spawn(async move { waiting_pool.wait_for_reconnect_due().await });
        tokio::task::yield_now().await;
        for _ in 0..5 {
            drop(entry.breaker.acquire().expect("closed breaker permit"));
        }

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("Open transition did not wake reconnect scheduler")
            .expect("scheduler waiter panicked");
        assert!(
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .is_scheduled(),
            "cancellation-only failures must create recovery work",
        );
    }

    #[tokio::test]
    async fn notification_during_schedule_scan_is_not_lost() {
        let pool = Arc::new(
            disconnected_pool(
                vec![stdio_manifest("scan-wake", vec!["/does-not-run"])],
                Duration::from_millis(50),
            )
            .with_reconnect_policy(Duration::from_millis(1), Duration::from_millis(1)),
        );
        let entry = pool
            .entries
            .load()
            .get("scan-wake")
            .expect("entry exists")
            .clone();
        entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_success(false);

        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *pool
            .reconnect_commit_hook
            .lock()
            .expect("reconnect wait hook lock poisoned") =
            Some((Arc::clone(&reached), Arc::clone(&resume)));
        let waiting_pool = Arc::clone(&pool);
        let waiter = tokio::spawn(async move { waiting_pool.wait_for_reconnect_due().await });
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .expect("scheduler did not reach the scan-to-wait boundary");

        entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .observe_runtime_failure();
        pool.reconnect_notify.notify_waiters();
        resume.notify_one();

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("notification in the scan-to-wait window was lost")
            .expect("scheduler waiter panicked");
    }

    #[tokio::test]
    async fn removal_clear_is_final_against_a_late_reconnect_arm() {
        let pool = disconnected_pool(
            vec![stdio_manifest("removed-race", vec!["/does-not-run"])],
            Duration::from_millis(50),
        );
        let entry = pool
            .entries
            .load()
            .get("removed-race")
            .expect("entry exists")
            .clone();

        entry
            .removed
            .store(true, std::sync::atomic::Ordering::Release);
        entry.retire_reconnect("removed-race");
        pool.arm_reconnect("removed-race", &entry).await;

        let state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert!(!state.is_scheduled());
        assert_eq!(state.snapshot(), (None, None));
    }

    #[tokio::test]
    async fn same_name_replacement_owns_the_reconnect_schedule() {
        let pool = disconnected_pool(
            vec![stdio_manifest("replaced-arm", vec!["/does-not-run"])],
            Duration::from_millis(50),
        );
        let retired = pool
            .entries
            .load()
            .get("replaced-arm")
            .expect("entry exists")
            .clone();
        retired
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_success(false);

        let replacement_pool = disconnected_pool(
            vec![stdio_manifest(
                "replaced-arm",
                vec!["/replacement-does-not-run"],
            )],
            Duration::from_millis(50),
        );
        let replacement = replacement_pool
            .entries
            .load()
            .get("replaced-arm")
            .expect("replacement entry exists")
            .clone();
        replacement
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_success(false);
        {
            let _structural_guard = pool.reload_lock.lock().await;
            pool.entries
                .store(Arc::new(std::collections::HashMap::from([(
                    "replaced-arm".to_owned(),
                    replacement.clone(),
                )])));
        }

        pool.arm_reconnect("replaced-arm", &retired).await;

        assert!(!retired
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .is_scheduled());
        assert!(!replacement
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .is_scheduled());
    }

    #[tokio::test]
    async fn retired_probe_recovery_cannot_clear_its_successor_schedule() {
        let pool = disconnected_pool(
            vec![stdio_manifest("replaced-probe", vec!["/does-not-run"])],
            Duration::from_millis(50),
        );
        let retired = pool
            .entries
            .load()
            .get("replaced-probe")
            .expect("entry exists")
            .clone();
        let replacement_pool = disconnected_pool(
            vec![stdio_manifest(
                "replaced-probe",
                vec!["/replacement-does-not-run"],
            )],
            Duration::from_millis(50),
        );
        let replacement = replacement_pool
            .entries
            .load()
            .get("replaced-probe")
            .expect("replacement entry exists")
            .clone();
        {
            let _structural_guard = pool.reload_lock.lock().await;
            pool.entries
                .store(Arc::new(std::collections::HashMap::from([(
                    "replaced-probe".to_owned(),
                    replacement.clone(),
                )])));
        }

        pool.settle_probe_recovery("replaced-probe", &retired, true)
            .await;

        assert!(
            retired
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .is_scheduled(),
            "the retired entry's private state must not be republished or settled",
        );
        assert!(
            replacement
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .is_scheduled(),
            "a stale success must not clear its successor's retry",
        );
    }

    #[tokio::test]
    async fn replacement_before_due_claim_cannot_launch_the_retired_entry() {
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest("replaced-claim", vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let retired = pool
            .entries
            .load()
            .get("replaced-claim")
            .expect("entry exists")
            .clone();
        force_deadline(&retired, Instant::now());

        let replacement_pool = disconnected_pool(
            vec![stdio_manifest(
                "replaced-claim",
                vec!["/replacement-does-not-run"],
            )],
            Duration::from_millis(50),
        );
        let replacement = replacement_pool
            .entries
            .load()
            .get("replaced-claim")
            .expect("replacement entry exists")
            .clone();
        replacement
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_success(false);

        {
            let _structural_guard = pool.reload_lock.lock().await;
            pool.entries
                .store(Arc::new(std::collections::HashMap::from([(
                    "replaced-claim".to_owned(),
                    replacement.clone(),
                )])));
        }

        assert!(
            tokio::time::timeout(Duration::from_secs(1), pool.reconnect_due_task())
                .await
                .expect("due claim did not settle")
                .is_none(),
            "the replacement has no due work, so no task may be returned",
        );
        let retired_state = retired
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert!(retired_state.active_claim.is_none());
        assert!(retired_state.is_scheduled());
        assert!(!replacement
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .is_scheduled());
    }

    #[tokio::test]
    async fn cancelled_claim_after_replacement_does_not_rearm_the_retired_entry() {
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest("claimed-replacement", vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let retired = pool
            .entries
            .load()
            .get("claimed-replacement")
            .expect("entry exists")
            .clone();
        force_deadline(&retired, Instant::now());
        let claimed = pool
            .reconnect_due_task()
            .await
            .expect("due retired entry was claimed");

        let replacement_pool = disconnected_pool(
            vec![stdio_manifest(
                "claimed-replacement",
                vec!["/replacement-does-not-run"],
            )],
            Duration::from_millis(50),
        );
        let replacement = replacement_pool
            .entries
            .load()
            .get("claimed-replacement")
            .expect("replacement entry exists")
            .clone();
        replacement
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_success(false);
        {
            let _structural_guard = pool.reload_lock.lock().await;
            pool.entries
                .store(Arc::new(std::collections::HashMap::from([(
                    "claimed-replacement".to_owned(),
                    replacement.clone(),
                )])));
        }

        drop(claimed);

        let retired_state = retired
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert!(retired_state.active_claim.is_none());
        assert!(!retired_state.is_scheduled());
        assert!(!replacement
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .is_scheduled());
    }

    #[tokio::test]
    async fn cancelled_claim_cannot_publish_after_a_replacement_commits() {
        let server = "claimed-replacement-metric-fence";
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest(server, vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let retired = pool
            .entries
            .load()
            .get(server)
            .expect("entry exists")
            .clone();
        force_deadline(&retired, Instant::now());
        let claimed = pool
            .reconnect_due_task()
            .await
            .expect("due retired entry was claimed");

        let replacement_pool = disconnected_pool(
            vec![stdio_manifest(server, vec!["/replacement-does-not-run"])],
            Duration::from_millis(50),
        );
        let replacement = replacement_pool
            .entries
            .load()
            .get(server)
            .expect("replacement entry exists")
            .clone();

        let structural_guard = pool.reload_lock.lock().await;
        drop(claimed);
        pool.entries
            .store(Arc::new(std::collections::HashMap::from([(
                server.to_owned(),
                replacement,
            )])));
        waygate_telemetry::metrics::set_upstream_reconnect_schedule(
            server,
            Some(Duration::from_secs(37)),
            Some(41),
        );
        drop(structural_guard);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if retired
                    .reconnect
                    .lock()
                    .expect("upstream reconnect lock poisoned")
                    .active_claim
                    .is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deferred claim settlement did not finish");
        assert_eq!(reconnect_backoff_gauge(server), Some(37.0));
    }

    #[tokio::test]
    async fn cancelled_claim_deferred_by_the_structural_fence_rearms_current_entry() {
        let server = "claimed-current-fence";
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest(server, vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let entry = pool
            .entries
            .load()
            .get(server)
            .expect("entry exists")
            .clone();
        force_deadline(&entry, Instant::now());
        let claimed = pool
            .reconnect_due_task()
            .await
            .expect("due entry was claimed");

        let structural_guard = pool.reload_lock.lock().await;
        drop(claimed);
        assert!(
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .active_claim
                .is_some(),
            "claim settlement must wait for the structural owner",
        );
        drop(structural_guard);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if entry
                    .reconnect
                    .lock()
                    .expect("upstream reconnect lock poisoned")
                    .is_scheduled()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deferred claim settlement did not rearm the current entry");
    }

    #[tokio::test]
    async fn due_claim_and_other_upstream_commit_progress_while_one_lane_is_busy() {
        let pool = Arc::new(
            disconnected_pool(
                vec![
                    stdio_manifest("busy", vec!["/does-not-run"]),
                    stdio_manifest("due", vec!["/also-does-not-run"]),
                ],
                Duration::from_millis(50),
            )
            .with_reconnect_policy(Duration::from_millis(1), Duration::from_millis(64)),
        );
        let map = pool.entries.load_full();
        let busy = map.get("busy").expect("busy entry exists").clone();
        let due = map.get("due").expect("due entry exists").clone();
        busy.reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_success(false);
        force_deadline(&due, Instant::now());

        let lane_reader = busy.slots[0].conn.read().await;
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *pool
            .reconnect_commit_hook
            .lock()
            .expect("reconnect commit hook lock poisoned") =
            Some((Arc::clone(&reached), Arc::clone(&resume)));
        let reconnect_pool = Arc::clone(&pool);
        let reconnect = tokio::spawn(async move { reconnect_pool.reconnect_one("busy").await });
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .expect("busy reconnect did not reach its lane commit");
        *pool
            .reconnect_commit_hook
            .lock()
            .expect("reconnect commit hook lock poisoned") = None;
        resume.notify_one();
        tokio::task::yield_now().await;

        let structural_guard =
            tokio::time::timeout(Duration::from_secs(1), pool.reload_lock.lock())
                .await
                .expect("busy upstream held the fleet fence while waiting for its lane");
        let claimed = tokio::time::timeout(Duration::from_secs(1), pool.reconnect_due_task())
            .await
            .expect("due upstream claim waited behind the fleet fence")
            .expect("due upstream was not claimed");
        assert!(
            due.reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .active_claim
                .is_some(),
            "the independent upstream must own its due claim",
        );

        drop(claimed);
        drop(structural_guard);
        drop(lane_reader);
        tokio::time::timeout(Duration::from_secs(1), reconnect)
            .await
            .expect("busy reconnect did not settle after its lane released")
            .expect("busy reconnect task panicked");
    }

    #[tokio::test]
    async fn fleet_reload_attempt_preserves_the_failure_episode() {
        let pool = disconnected_pool(
            vec![stdio_manifest("reload-reset", vec!["/does-not-run"])],
            Duration::from_millis(50),
        )
        .with_reconnect_policy(Duration::from_millis(1), Duration::from_millis(64));
        let entry = pool
            .entries
            .load()
            .get("reload-reset")
            .expect("entry exists")
            .clone();
        {
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            for _ in 0..6 {
                state.record_failure();
            }
            assert_eq!(state.episode_attempts, 6);
            assert_eq!(state.consecutive_failures, 6);
        }

        pool.try_reconnect_disconnected().await;

        let state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert_eq!(state.episode_attempts, 7);
        assert_eq!(state.consecutive_failures, 7);
        assert!(state.current_backoff <= Some(Duration::from_millis(64)));
    }

    #[tokio::test]
    async fn fleet_reload_resets_once_when_referenced_credential_material_rotates() {
        let env = "GW_TEST_RECONNECT_ROTATED_BEARER";
        let file_env = format!("{env}_FILE");
        let dir = std::env::temp_dir().join(format!(
            "gateway-reconnect-credential-{}",
            uuid::Uuid::new_v4()
        ));
        let path = dir.join("bearer");
        std::fs::create_dir(&dir).expect("create isolated credential directory");
        std::fs::write(&path, b"first-secret\n").expect("write initial credential");
        // The name is unique to this test, so concurrent environment readers
        // cannot observe a source they recognize.
        unsafe {
            std::env::remove_var(env);
            std::env::set_var(&file_env, &path);
        }

        let pool = disconnected_pool(
            vec![http_manifest_with_bearer("rotated", env)],
            Duration::from_millis(50),
        )
        .with_reconnect_policy(Duration::from_millis(1), Duration::from_millis(64));
        let entry = pool
            .entries
            .load()
            .get("rotated")
            .expect("entry exists")
            .clone();
        {
            let mut state = entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned");
            for _ in 0..6 {
                state.record_failure();
            }
        }

        pool.try_reconnect_disconnected().await;
        assert_eq!(
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .episode_attempts(),
            7,
            "unchanged material must preserve the current failure episode",
        );

        std::fs::write(&path, b"second-secret\n").expect("rotate credential in place");
        pool.try_reconnect_disconnected().await;
        assert_eq!(
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .episode_attempts(),
            1,
            "the first attempt after rotation must start a new episode",
        );

        pool.try_reconnect_disconnected().await;
        assert_eq!(
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .episode_attempts(),
            2,
            "repeated reloads must not repeatedly reset unchanged material",
        );

        unsafe { std::env::remove_var(&file_env) };
        std::fs::remove_dir_all(dir).expect("remove isolated credential directory");
    }

    #[tokio::test]
    async fn replacement_during_outcome_gap_suppresses_stale_failure() {
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest("replaced", vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let retired = pool
            .entries
            .load()
            .get("replaced")
            .expect("entry exists")
            .clone();
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *pool
            .reconnect_outcome_hook
            .lock()
            .expect("reconnect outcome hook lock poisoned") =
            Some((Arc::clone(&reached), Arc::clone(&resume)));

        let reconnect_pool = Arc::clone(&pool);
        let reconnect = tokio::spawn(async move {
            reconnect_pool.try_reconnect_disconnected().await;
        });
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .expect("reconnect did not reach the post-publication gap");

        let replacement_pool = disconnected_pool(
            vec![stdio_manifest(
                "replaced",
                vec!["/replacement-does-not-run"],
            )],
            Duration::from_millis(50),
        );
        let replacement = replacement_pool
            .entries
            .load()
            .get("replaced")
            .expect("replacement entry exists")
            .clone();
        {
            let _structural_guard = pool.reload_lock.lock().await;
            pool.entries
                .store(Arc::new(std::collections::HashMap::from([(
                    "replaced".to_owned(),
                    replacement,
                )])));
        }
        resume.notify_one();
        tokio::time::timeout(Duration::from_secs(1), reconnect)
            .await
            .expect("stale reconnect did not settle")
            .expect("reconnect task panicked");

        let state = retired
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert_eq!(state.episode_attempts, 0);
        assert_eq!(state.consecutive_failures, 1);
        assert!(state.is_scheduled());
    }

    #[tokio::test]
    async fn successful_redial_state_wins_over_an_older_reconnect_failure() {
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest("redial-wins", vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let entry = pool
            .entries
            .load()
            .get("redial-wins")
            .expect("entry exists")
            .clone();
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *pool
            .reconnect_outcome_hook
            .lock()
            .expect("reconnect outcome hook lock poisoned") =
            Some((Arc::clone(&reached), Arc::clone(&resume)));

        let reconnect_pool = Arc::clone(&pool);
        let reconnect = tokio::spawn(async move {
            reconnect_pool.try_reconnect_disconnected().await;
        });
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .expect("reconnect did not reach the outcome gap");

        // Model the state commit performed by a successful live redial while
        // the older reconnect is awaiting its finalizer.
        {
            let _structural_guard = pool.reload_lock.lock().await;
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .record_success(false);
        }
        resume.notify_one();
        tokio::time::timeout(Duration::from_secs(1), reconnect)
            .await
            .expect("stale reconnect did not settle")
            .expect("reconnect task panicked");

        let state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert_eq!(state.episode_attempts(), 0);
        assert_eq!(state.snapshot(), (None, None));
    }

    #[tokio::test]
    async fn probe_recovery_during_reconnect_suppresses_the_stale_dial_failure() {
        let pool = Arc::new(
            disconnected_pool(
                vec![stdio_manifest("probe-wins", vec!["/does-not-run"])],
                Duration::from_millis(50),
            )
            .with_reconnect_policy(Duration::from_millis(1), Duration::from_millis(64)),
        );
        let entry = pool
            .entries
            .load()
            .get("probe-wins")
            .expect("entry exists")
            .clone();
        for _ in 0..5 {
            entry
                .breaker
                .acquire()
                .expect("closed breaker admits failure")
                .failure();
        }
        assert_eq!(entry.breaker.state(), crate::breaker::BreakerState::Open);

        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *pool
            .reconnect_commit_hook
            .lock()
            .expect("reconnect commit hook lock poisoned") =
            Some((Arc::clone(&reached), Arc::clone(&resume)));

        let reconnect_pool = Arc::clone(&pool);
        let reconnect = tokio::spawn(async move {
            reconnect_pool.try_reconnect_disconnected().await;
        });
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .expect("reconnect did not reach its commit fence");

        // Model the half-open application's successful disposition. The call
        // path publishes this transition before releasing its lane read lock,
        // so reconnect observes it after taking the corresponding write lock.
        entry.breaker.reset();
        resume.notify_one();
        tokio::time::timeout(Duration::from_secs(1), reconnect)
            .await
            .expect("reconnect did not settle after probe recovery")
            .expect("reconnect task panicked");

        let state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert_eq!(state.episode_attempts, 0);
        assert_eq!(state.consecutive_failures, 0);
        assert!(
            state.is_scheduled(),
            "the still-missing lane must retain a base-delay retry"
        );
    }

    #[tokio::test]
    #[ignore = "wall-clock reconnect scheduling race; manual diagnostic only"]
    async fn newly_due_upstream_progresses_while_prior_attempt_is_slow() {
        let pool = Arc::new(disconnected_pool(
            vec![
                stdio_manifest("slow", vec!["/bin/sh", "-c", "sleep 10"]),
                stdio_manifest("fast", vec!["/does-not-run"]),
            ],
            Duration::from_millis(400),
        ));
        let entries = pool.entries.load_full();
        let slow = entries.get("slow").expect("slow entry").clone();
        let fast = entries.get("fast").expect("fast entry").clone();
        let now = Instant::now();
        force_deadline(&slow, now);
        force_deadline(&fast, now + Duration::from_millis(75));
        drop(entries);

        let slow_task = pool
            .reconnect_due_task()
            .await
            .expect("slow deadline is due and claimed");
        let slow_handle = tokio::spawn(slow_task);

        tokio::time::timeout(Duration::from_millis(200), pool.wait_for_reconnect_due())
            .await
            .expect("fast deadline was hidden by the slow attempt");
        let fast_task = pool
            .reconnect_due_task()
            .await
            .expect("newly due fast deadline is independently claimable");
        tokio::time::timeout(Duration::from_millis(200), fast_task)
            .await
            .expect("fast reconnect waited for the slow dial");
        assert!(
            !slow_handle.is_finished(),
            "slow control attempt must still be in flight when fast completes",
        );

        slow_handle.abort();
        let _ = slow_handle.await;
    }

    #[tokio::test]
    async fn operator_reset_linearizes_after_queued_attempt() {
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest("missing", vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let entry = pool
            .entries
            .load()
            .get("missing")
            .expect("entry exists")
            .clone();
        entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_failure();

        let prior_attempt_guard = entry.session_mutation.lock().await;
        let operator_pool = Arc::clone(&pool);
        let operator = tokio::spawn(async move { operator_pool.reconnect_one("missing").await });
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_failure();
        drop(prior_attempt_guard);

        assert!(
            !tokio::time::timeout(Duration::from_secs(1), operator)
                .await
                .expect("operator reconnect hung")
                .expect("operator reconnect panicked"),
            "the nonexistent upstream remains disconnected",
        );
        assert_eq!(
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .episode_attempts(),
            1,
            "the operator dial must be the first attempt after its reset",
        );
    }

    #[tokio::test]
    async fn cancelled_operator_reconnect_keeps_scheduler_fallback() {
        let pool = Arc::new(
            disconnected_pool(
                vec![stdio_manifest(
                    "cancelled-operator",
                    vec!["/bin/sh", "-c", "sleep 10"],
                )],
                Duration::from_secs(10),
            )
            .with_reconnect_policy(Duration::from_secs(30), Duration::from_secs(30)),
        );
        let entry = pool
            .entries
            .load()
            .get("cancelled-operator")
            .expect("entry exists")
            .clone();
        entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned")
            .record_success(false);

        let operator_pool = Arc::clone(&pool);
        let operator =
            tokio::spawn(async move { operator_pool.reconnect_one("cancelled-operator").await });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if entry
                    .reconnect
                    .lock()
                    .expect("upstream reconnect lock poisoned")
                    .is_scheduled()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("operator reconnect did not arm its cancellation fallback");

        operator.abort();
        assert!(operator
            .await
            .expect_err("operator reconnect must be cancelled")
            .is_cancelled());
        let state = entry
            .reconnect
            .lock()
            .expect("upstream reconnect lock poisoned");
        assert!(state.is_scheduled());
        assert_eq!(state.episode_attempts(), 0);
    }

    #[tokio::test]
    async fn operator_reset_invalidates_an_unstarted_background_claim() {
        let pool = Arc::new(disconnected_pool(
            vec![stdio_manifest("missing", vec!["/does-not-run"])],
            Duration::from_millis(50),
        ));
        let entry = pool
            .entries
            .load()
            .get("missing")
            .expect("entry exists")
            .clone();
        force_deadline(&entry, Instant::now());
        let stale_background = pool
            .reconnect_due_task()
            .await
            .expect("background deadline is claimed before the task is returned");

        assert!(!pool.reconnect_one("missing").await);
        stale_background.await;

        assert_eq!(
            entry
                .reconnect
                .lock()
                .expect("upstream reconnect lock poisoned")
                .episode_attempts(),
            1,
            "the invalidated background claim must not dial after the operator attempt",
        );
    }
}
