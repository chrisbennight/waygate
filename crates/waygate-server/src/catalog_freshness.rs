//! Periodic driver for upstream catalog freshness: re-run the one existing
//! refresh path ([`waygate_upstream::UpstreamPool::refresh_server_catalog`])
//! once an upstream's clamped `ttlMs` hint expires or, without a hint, once
//! the operator's maximum catalog age is reached.
//!
//! A hint can only choose a point *between* the floor and ceiling: it can
//! neither force a redial storm (`ttlMs: 1`) nor stretch scheduling beyond
//! the ceiling. An upstream that offers no hint uses the ceiling itself, so
//! legacy and stateless catalogs still converge without a gateway restart.
//!
//! Every refresh this task drives is audit-attributed to the
//! [`freshness_actor`] system principal, so an operator reading the
//! activity feed can tell a scheduled refresh from an admin's.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use waygate_oidc::{AuthMethod, Principal};
use waygate_upstream::UpstreamPool;

/// Scheduling bounds, read from the environment.
pub struct CatalogFreshnessConfig {
    /// Minimum effective TTL and the task's tick cadence. `None` ⇒ the
    /// operator disabled scheduled freshness refreshes entirely.
    pub floor: Option<Duration>,
    /// Maximum catalog age: a hint larger than this refreshes at the ceiling,
    /// and an unhinted upstream uses the ceiling as its fallback interval.
    pub ceiling: Duration,
}

impl CatalogFreshnessConfig {
    /// - `GATEWAY_CATALOG_FRESHNESS_FLOOR_SECONDS` — default 60, minimum 5
    ///   when nonzero; `0` disables scheduled freshness refreshes. Also the
    ///   task's tick interval, so refresh load per upstream is bounded to
    ///   one dial per floor even while an upstream stays past due.
    /// - `GATEWAY_CATALOG_FRESHNESS_CEILING_SECONDS` — default 900 (15m);
    ///   must be ≥ the floor. Bounded to ten years: a larger value is
    ///   indistinguishable from "never" and would only serve to push the
    ///   clamped deadline toward the platform's `Instant` range.
    pub fn from_env() -> anyhow::Result<Self> {
        let floor = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_CATALOG_FRESHNESS_FLOOR_SECONDS",
            60,
            5,
            "0 disables scheduled catalog-freshness refreshes",
        )?;
        let ceiling = waygate_core::env::duration_secs(
            "GATEWAY_CATALOG_FRESHNESS_CEILING_SECONDS",
            900,
            1..=315_360_000,
            "at most ten years",
        )?;
        if let Some(floor) = floor {
            anyhow::ensure!(
                ceiling >= floor,
                "GATEWAY_CATALOG_FRESHNESS_CEILING_SECONDS ({}s) must be >= \
                 GATEWAY_CATALOG_FRESHNESS_FLOOR_SECONDS ({}s)",
                ceiling.as_secs(),
                floor.as_secs()
            );
        }
        Ok(Self { floor, ceiling })
    }
}

/// The system principal a scheduled refresh is audit-attributed to. Not an
/// authenticated identity: it never passes the bearer middleware and never
/// reaches Cedar — `refresh_server_catalog` uses its principal solely for
/// the attributed `UpstreamCatalogRefresh` evidence row, which persists
/// `sub` / `issuer` (never `auth_method`). The `system:` sub and internal
/// issuer make the attribution self-describing in the activity feed.
fn freshness_actor() -> Principal {
    Principal {
        sub: "system:catalog-freshness".into(),
        email: None,
        groups: Vec::new(),
        issuer: "gateway:internal".into(),
        scopes: Vec::new(),
        tenant: waygate_core::TenantId::default(),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        roles: Vec::new(),
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

/// Spawn the freshness driver. Returns `None` when disabled by
/// configuration (floor = 0). Mirrors the upstream re-probe task's shape:
/// tick, skip missed ticks, burn the immediate first tick, exit on
/// shutdown.
pub fn spawn(
    pool: Arc<UpstreamPool>,
    cfg: CatalogFreshnessConfig,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let floor = cfg.floor?;
    let ceiling = cfg.ceiling;
    tracing::info!(
        floor_secs = floor.as_secs(),
        ceiling_secs = ceiling.as_secs(),
        "spawning catalog-freshness refresh task"
    );
    Some(tokio::spawn(async move {
        let actor = freshness_actor();
        let mut ticker = tokio::time::interval(floor);
        // Skip absorbs a gateway stall without firing catch-up refreshes
        // back-to-back; burning the immediate first tick avoids re-listing
        // catalogs the boot dial fetched moments ago.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {
                    let due = pool.catalog_refresh_due(floor, ceiling, Instant::now()).await;
                    for server in due {
                        if shutdown.is_cancelled() {
                            return;
                        }
                        // Sequential on purpose: one refresh dials every
                        // lane of one upstream; refreshing the fleet in
                        // parallel would multiply dial load for no
                        // freshness benefit. Eligibility is re-evaluated
                        // inside `scheduled_catalog_refresh`, under the
                        // same session guard the redial runs under — the
                        // tick-time queue is only a candidate list.
                        match pool
                            .scheduled_catalog_refresh(
                                &server,
                                floor,
                                ceiling,
                                Instant::now(),
                                &actor,
                            )
                            .await
                        {
                            waygate_upstream::ScheduledCatalogRefresh::Refreshed {
                                report,
                                trigger,
                            } => {
                                tracing::debug!(
                                    server = %server,
                                    outcome = ?report.outcome,
                                    trigger = trigger.as_str(),
                                    "scheduled catalog-freshness refresh"
                                )
                            }
                            waygate_upstream::ScheduledCatalogRefresh::NotDue => tracing::debug!(
                                server = %server,
                                "scheduled refresh skipped: no longer due or eligible"
                            ),
                            waygate_upstream::ScheduledCatalogRefresh::Unknown => tracing::debug!(
                                server = %server,
                                "scheduled refresh skipped: upstream no longer registered"
                            ),
                        }
                    }
                }
            }
        }
    }))
}
