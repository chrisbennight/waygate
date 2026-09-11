//! Upstream MCP server connection pool.
//!
//! Each upstream is declared by a YAML manifest under `servers/*.yaml` and
//! spoken to over HTTP (streamable HTTP), SSE (legacy two-endpoint MCP SSE),
//! or stdio. See [`pool`] for the dial/lifecycle contract and [`Transport`]
//! for the manifest surface.
//!
//! The manifest *domain* — [`UpstreamManifest`] and friends, the parsers,
//! and [`validate_manifest_invariants`] — lives in `waygate-manifest-types`
//! and is re-exported here at its historical paths, so
//! consumers of this crate see one unchanged surface.

mod bounded_http_client;
pub mod breaker;
mod catalog_probe;
pub mod http_policy;
pub mod identity_client;
pub mod pool;
pub mod security_metadata;
pub mod sse_client;
pub mod transport;

pub use breaker::{Breaker, BreakerConfig, BreakerError, BreakerState};
pub use identity_client::{
    ExchangeSettings, IdentityAugmenter, IdentityCell, IdentityContext, IdentityForwardingClient,
    IDENTITY_HEADER,
};
pub use pool::health::{CandidateObservation, UpstreamErrorClass, UpstreamRuntimeState};
pub use pool::reload::resource_shape_change_requires_restart;
pub use pool::{
    list_all_tools, CatalogFreshnessTrigger, CatalogRefreshOutcome, CatalogRefreshReport,
    ExchangeBundle, ListedCatalog, ObservedContracts, ObservedToolContract, ReloadReport,
    ScheduledCatalogRefresh, UpstreamHealth, UpstreamPool, UpstreamStatus,
};
pub use transport::{default_auto_lifecycle, legacy_bridge_lifecycle};

/// Canonical behavior hash of a live tool descriptor — the exact value an
/// annotation-native manifest entry must carry in `approved_behavior_hash`
/// for the tool to be admitted. Covers name, description, input schema,
/// output schema, standard annotations, and action metadata.
pub fn tool_behavior_hash(tool: &rmcp::model::Tool) -> String {
    security_metadata::behavior_hash(tool)
}

// The manifest domain: canonical home is `waygate-manifest-types`; these
// keep-resolving re-exports preserve every pre-split `waygate_upstream::…`
// path (the `RiskTier` pattern).
pub use waygate_manifest_types::{
    enforce_no_prod_stdio, load_manifests, manifest_write_in_progress, parse_manifest_set,
    serialize_manifest_set, validate_manifest_invariants, write_manifest_set_to_dir,
    write_manifest_set_to_dir_from_base, ApprovalMode, ClassificationMode, ExchangeConfig,
    MtlsConfig, OperationClassification, ResourceClassification, SessionConfig, SessionIsolation,
    SessionScope, ToolClassification, Transport, UpstreamAuth, UpstreamError, UpstreamManifest,
    UpstreamProtocol, MANIFEST_WRITE_MARKER,
};

/// A point-in-time snapshot of the upstream-manifest config health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigHealthSnapshot {
    /// `true` when the last load / reload succeeded and the live set is the
    /// intended on-disk set; `false` when a load/reload was refused and the
    /// gateway is serving the **previous** set (a broken `servers/*.yaml`,
    /// an unreadable dir, or a prod-safety refusal).
    pub healthy: bool,
    /// Human-readable detail — a one-line summary on success, or the
    /// refusal / parse error on degradation.
    pub detail: String,
    /// Unix seconds when the *current* state began (only reset on a health
    /// transition, so "STALE since T" reflects when it broke).
    pub since_unix: i64,
}

/// Liveness signal for a file-as-truth config set.
/// Shared between the reload path (the writer — boot /
/// SIGHUP / dashboard reload) and the dashboard (the reader) so a broken
/// on-disk set, an unreadable dir, or a refused reload surfaces loudly
/// instead of the gateway silently serving a stale set. Cheap `RwLock` over
/// a single snapshot; updated on every load/reload, read on render.
///
/// One instance per config set: `waygate-server` wires one for the upstream
/// manifests (`servers/*.yaml`) and a SEPARATE one for the Cedar policy set
/// (`policies/*.cedar`) so the two banners never clobber each other.
#[derive(Default)]
pub struct ConfigHealth {
    inner: std::sync::RwLock<Option<ConfigHealthSnapshot>>,
}

/// Shared handle, matching the workspace's `Shared*` convention.
pub type SharedConfigHealth = std::sync::Arc<ConfigHealth>;

impl ConfigHealth {
    /// The current snapshot, or `None` before the first load.
    pub fn snapshot(&self) -> Option<ConfigHealthSnapshot> {
        self.inner
            .read()
            .expect("config health lock poisoned")
            .clone()
    }
    /// Record a successful load/reload — the live set is the intended one.
    pub fn set_healthy(&self, detail: impl Into<String>) {
        self.set(true, detail.into());
    }
    /// Record a refused load/reload — the gateway is serving the previous
    /// set. Surfaced as a prominent banner; never silently good.
    pub fn set_degraded(&self, detail: impl Into<String>) {
        self.set(false, detail.into());
    }
    fn set(&self, healthy: bool, detail: String) {
        let mut g = self.inner.write().expect("config health lock poisoned");
        let since_unix = match g.as_ref() {
            // Keep `since` across same-health updates so the banner shows
            // when the gateway WENT stale, not the most recent reload.
            Some(prev) if prev.healthy == healthy => prev.since_unix,
            _ => now_unix(),
        };
        *g = Some(ConfigHealthSnapshot {
            healthy,
            detail,
            since_unix,
        });
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_health_tracks_healthy_and_degraded() {
        let h = ConfigHealth::default();
        assert!(h.snapshot().is_none(), "no snapshot before the first load");

        h.set_healthy("12 upstream(s) loaded from servers/*.yaml");
        let s1 = h.snapshot().expect("snapshot after set_healthy");
        assert!(s1.healthy);
        assert!(s1.detail.contains("12 upstream"));

        // A same-health update keeps `since` (so the banner shows when the
        // gateway WENT stale, not the most recent reload).
        h.set_healthy("13 upstream(s) loaded from servers/*.yaml");
        let s2 = h.snapshot().unwrap();
        assert!(s2.healthy && s2.detail.contains("13 upstream"));
        assert_eq!(
            s2.since_unix, s1.since_unix,
            "`since` must not reset without a health transition",
        );

        // Degrading flips healthy to false and surfaces the reason.
        h.set_degraded("reload refused — serving the previous set: bad yaml");
        let s3 = h.snapshot().unwrap();
        assert!(!s3.healthy);
        assert!(s3.detail.contains("refused"));
        assert!(s3.since_unix >= s1.since_unix);
    }
}
