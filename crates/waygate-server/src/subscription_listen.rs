//! Reconciler for upstream `subscriptions/listen` catalog listeners: keeps
//! one background listener per eligible upstream
//! ([`waygate_upstream::UpstreamPool::run_catalog_listener`]), respawning
//! them as upstreams appear, reload their connection shape, or recover —
//! with a per-server cooldown so an upstream that refuses or drops the
//! stream is not re-dialed in a tight loop.
//!
//! Event-driven refreshes are audit-attributed to the
//! [`listener_actor`] system principal, distinct from the scheduled
//! freshness task's actor, so the activity feed tells push invalidation
//! apart from schedule and from an admin's hand.

use std::collections::HashMap;
use std::time::Duration;

use std::sync::Arc;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use waygate_oidc::{AuthMethod, Principal};
use waygate_upstream::pool::listen::{
    manifest_connection_shape_eq, CatalogListenerExit, CatalogListenerOutcome,
};
use waygate_upstream::{UpstreamManifest, UpstreamPool};

/// How often the reconciler re-evaluates the eligible set. Also bounds how
/// fast a fresh upstream or a recovered lane gains a listener.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Cooldown before re-dialing an upstream whose listener exited without a
/// shape change: `Unsupported` waits the long window (the upstream said no
/// — only a reload or its own upgrade changes that), `Ended` the short one
/// (streams drop for transient reasons).
const UNSUPPORTED_COOLDOWN: Duration = Duration::from_secs(900);
const ENDED_COOLDOWN: Duration = Duration::from_secs(60);

/// One server's respawn cooldown, scoped to the connection shape it was
/// recorded against.
struct Cooldown {
    until: Instant,
    /// The manifest shape at cooldown time; `None` when the server was
    /// already unregistered (the cooldown then applies until expiry).
    shape: Option<UpstreamManifest>,
}

/// Whether a cooldown still blocks this server: expired cooldowns never
/// block, and neither does one recorded against a connection shape a
/// reload has since replaced.
fn cooldown_blocks(
    cooldowns: &HashMap<String, Cooldown>,
    server: &str,
    current_shape: Option<&UpstreamManifest>,
) -> bool {
    let Some(cooldown) = cooldowns.get(server) else {
        return false;
    };
    if Instant::now() >= cooldown.until {
        return false;
    }
    match (&cooldown.shape, current_shape) {
        (Some(recorded), Some(current)) => manifest_connection_shape_eq(recorded, current),
        _ => true,
    }
}

/// The system principal an event-driven refresh is audit-attributed to.
/// Not an authenticated identity — it never passes the bearer middleware
/// and never reaches Cedar; `refresh_server_catalog` persists only
/// `sub`/`issuer` on the attributed evidence row.
fn listener_actor() -> Principal {
    Principal {
        sub: "system:subscription-listen".into(),
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

/// Spawn the reconciler. `min_refresh_interval` is the rate bound every
/// listener applies to upstream events (an untrusted hint must not drive a
/// refresh storm); callers pass the catalog-freshness floor so one operator
/// knob bounds both the schedule and the push path.
pub fn spawn(
    pool: Arc<UpstreamPool>,
    min_refresh_interval: Duration,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tracing::info!(
        min_refresh_secs = min_refresh_interval.as_secs(),
        "spawning upstream subscription-listen reconciler"
    );
    tokio::spawn(async move {
        let mut running: HashMap<String, tokio::task::JoinHandle<CatalogListenerOutcome>> =
            HashMap::new();
        let mut cooldowns: HashMap<String, Cooldown> = HashMap::new();
        let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    // Listeners watch the same token and exit on their own.
                    return;
                }
                _ = ticker.tick() => {}
            }
            // Harvest finished listeners and set their respawn cooldowns.
            let finished: Vec<String> = running
                .iter()
                .filter(|(_, handle)| handle.is_finished())
                .map(|(server, _)| server.clone())
                .collect();
            for server in finished {
                let Some(handle) = running.remove(&server) else {
                    continue;
                };
                let outcome = handle.await.unwrap_or(CatalogListenerOutcome {
                    exit: CatalogListenerExit::Ended,
                    shape: None,
                });
                let cooldown = match outcome.exit {
                    CatalogListenerExit::Unsupported => Some(UNSUPPORTED_COOLDOWN),
                    CatalogListenerExit::Ended => Some(ENDED_COOLDOWN),
                    // A shape change means the old dial is stale and a
                    // fresh listener should try immediately; a removal
                    // drops the server from candidacy by itself.
                    CatalogListenerExit::ManifestChanged | CatalogListenerExit::Removed => None,
                    CatalogListenerExit::Shutdown => return,
                };
                tracing::debug!(server = %server, exit = ?outcome.exit, "catalog listener exited");
                if let Some(cooldown) = cooldown {
                    // Scope the cooldown to the shape the LISTENER ITSELF
                    // ran against — never a harvest-time snapshot, which a
                    // reload landing between exit and harvest could turn
                    // into the new shape and wrongly suppress it.
                    cooldowns.insert(
                        server.clone(),
                        Cooldown {
                            until: Instant::now() + cooldown,
                            shape: outcome.shape,
                        },
                    );
                }
            }
            for server in pool.catalog_listener_candidates().await {
                if running.contains_key(&server) {
                    continue;
                }
                if cooldown_blocks(
                    &cooldowns,
                    &server,
                    pool.listener_manifest(&server).as_ref(),
                ) {
                    continue;
                }
                cooldowns.remove(&server);
                let pool = Arc::clone(&pool);
                let shutdown = shutdown.clone();
                let server_name = server.clone();
                running.insert(
                    server,
                    tokio::spawn(async move {
                        let actor = listener_actor();
                        pool.run_catalog_listener(
                            &server_name,
                            min_refresh_interval,
                            &actor,
                            shutdown,
                        )
                        .await
                    }),
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(url: &str) -> UpstreamManifest {
        serde_yaml::from_str(&format!("name: mock\ntransport: http\nurl: {url}\n"))
            .expect("manifest parses")
    }

    /// A cooldown blocks only while its recorded connection shape is still
    /// the live one: a reload that changes the shape re-qualifies the
    /// server immediately, and expiry always clears it.
    #[tokio::test]
    async fn cooldown_is_scoped_to_the_recorded_connection_shape() {
        let recorded = manifest("http://127.0.0.1:1/mcp");
        let mut cooldowns = HashMap::new();
        cooldowns.insert(
            "mock".to_owned(),
            Cooldown {
                until: Instant::now() + Duration::from_secs(600),
                shape: Some(recorded.clone()),
            },
        );

        // Same shape, unexpired: blocked.
        assert!(cooldown_blocks(&cooldowns, "mock", Some(&recorded)));
        // No cooldown recorded for another server: never blocked.
        assert!(!cooldown_blocks(&cooldowns, "other", Some(&recorded)));
        // A reload changed the connection shape: re-qualified immediately.
        let reloaded = manifest("http://127.0.0.1:2/mcp");
        assert!(!cooldown_blocks(&cooldowns, "mock", Some(&reloaded)));
        // Expired: cleared regardless of shape.
        cooldowns.get_mut("mock").expect("entry").until = Instant::now() - Duration::from_secs(1);
        assert!(!cooldown_blocks(&cooldowns, "mock", Some(&recorded)));
    }
}
