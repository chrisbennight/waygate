use std::sync::Arc;

use waygate_authz::ReloadableCedar;
use waygate_skills::ReloadableSkillCatalog;
use waygate_upstream::UpstreamPool;

use crate::config::Config;

/// Shared application state wired into every axum handler via `State<Arc<AppState>>`.
///
/// Held by the root handlers (`/healthz`, `/readyz`, `/metrics`) and by the
/// SIGHUP handler. Everything live-reloadable sits behind an `Arc` so the
/// reload path mutates shared state without touching the axum graph.
pub struct AppState {
    #[allow(dead_code)]
    pub config: Config,
    pub upstreams: Arc<UpstreamPool>,
    /// Process-local BM25 accelerator used only by the legacy searchTools
    /// compatibility surface. The authoritative gateway discovery paths rank
    /// their current authorization-filtered catalog directly.
    pub search_index: Option<waygate_mcp::SearchIndex>,
    /// `None` when auth is disabled (no Cedar engine in that mode).
    pub cedar: Option<Arc<ReloadableCedar>>,
    /// Complete verified external skill snapshot. Acquisition and validation
    /// happen before this handle is published to request-serving state.
    pub skills: Option<Arc<ReloadableSkillCatalog>>,
    /// Whether the audit sink is a real Postgres one (as opposed to `NullSink`).
    /// Feeds `/readyz` — a gateway configured for Postgres audit but running
    /// on NullSink is a misconfiguration we want to flag.
    pub audit_enabled: bool,
}

impl AppState {
    pub fn new(
        config: Config,
        upstreams: Arc<UpstreamPool>,
        cedar: Option<Arc<ReloadableCedar>>,
        skills: Option<Arc<ReloadableSkillCatalog>>,
        audit_enabled: bool,
    ) -> Self {
        Self {
            config,
            search_index: upstreams.search_index().cloned(),
            upstreams,
            cedar,
            skills,
            audit_enabled,
        }
    }
}
