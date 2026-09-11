//! Model resolution: map an inbound `(server, model)` pair to the
//! [`ResolvedRoute`](crate::ResolvedRoute) that dispatch sends it to, and to
//! the risk tier the pipeline's gates use. This is the seam the invocation
//! pipeline consults to decide whether a request is an LLM call at all.
//!
//! v1 ships [`StaticModelResolver`] — a fixed in-memory table populated from
//! config/env at startup. Dynamic pooling, failover, and a DB-backed model
//! catalog slot in behind the same [`LlmModelResolver`] trait, so the
//! pipeline integration does not change when they land.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::ResolvedRoute;

/// The coarse risk tier a resolved model carries, used by the pipeline's
/// authorize/audit stages. Mirrors the gateway's `RiskTier` without depending
/// on it here (the pipeline maps this onto its own type). A model with no
/// explicit risk defaults to `Low`; models are not step-up-gated (model
/// access is a Cedar-permit concern), so the tier drives audit/quota and
/// any future per-risk `Model` permits. An explicit but unrecognized risk value
/// fails safe to `High` (see `parse_risk`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRisk {
    Low,
    Medium,
    High,
}

/// The operation a resolved model serves. `Chat` is a chat/completions-family
/// call (`/v1/chat/completions`, `/v1/responses`), dispatched through the
/// canonical `LlmRequest` path; `Embeddings` is a `/v1/embeddings` call,
/// dispatched through the embeddings path (its own canonical request, unary
/// only). The invocation pipeline branches on this to pick the parse/dispatch
/// path, and validates that the inbound client surface matches (an embeddings
/// model hit on `/v1/chat/completions`, or vice-versa, is a clean client error,
/// not a mis-dispatch). `Images` serves generation and editing through the
/// separate Images API parser and direct Codex transport. Defaults to `Chat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LlmOperation {
    #[default]
    Chat,
    Embeddings,
    Images,
}

/// A resolved model target: where to send it and how the gates should treat it.
#[derive(Debug, Clone)]
pub struct ResolvedModel {
    /// Primary transport + identity for dispatch — the first target tried.
    pub route: ResolvedRoute,
    /// Which operation this model serves (chat, embeddings, or images) — selects the
    /// pipeline's parse/dispatch path. Defaults to `Chat`.
    pub operation: LlmOperation,
    /// Ordered fallback routes, tried in order only when the primary (and each
    /// earlier fallback) fails with a *retryable* error — the §7 credential
    /// pool / failover. These may be a same-provider credential pool and/or
    /// cross-provider target groups (each carrying its own provider / endpoint /
    /// protocol); empty for a single-credential model.
    pub fallbacks: Vec<ResolvedRoute>,
    /// Risk tier for the authorize/audit stages.
    pub risk: ModelRisk,
    /// Optional time-to-first-byte deadline for a streamed call (§7 stall
    /// detection). When set, dispatch fails over to the next candidate if the
    /// first SSE frame does not arrive within this window — turning a
    /// dead-on-arrival stream into a fast failover instead of a slow abort.
    /// `None` (the default) leaves streaming bounded only by the provider
    /// client's idle-read timeout, so long-pre-token reasoning models are
    /// unaffected unless an operator opts them in.
    pub ttfb: Option<Duration>,
    /// Optional per-principal completion-cache TTL. `Some` opts this
    /// model into the exact-match cache: the pipeline serves a hit (free, no
    /// provider call) and stores a unary completion for this long after a miss.
    /// `None` (the default) ⇒ the model is never cached.
    pub cache_ttl: Option<Duration>,
}

/// Resolves an inbound `(server, model)` pair to a model target, or `None` when
/// the pair is not an LLM model (so the caller falls back to the MCP path).
pub trait LlmModelResolver: Send + Sync + 'static {
    fn resolve(&self, server: &str, model: &str) -> Option<ResolvedModel>;

    /// Whether `server` is an LLM namespace this resolver owns (has at least one
    /// model under it). The pipeline uses this to reject an unknown model on an
    /// owned namespace rather than falling through to the MCP path — so a
    /// same-named MCP upstream can never shadow an unconfigured model.
    fn owns_server(&self, server: &str) -> bool;
}

/// A fixed in-memory resolver keyed by `(server, model)`. Built once at startup
/// from configuration; immutable thereafter.
#[derive(Debug, Clone, Default)]
pub struct StaticModelResolver {
    models: HashMap<(String, String), ResolvedModel>,
}

impl StaticModelResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a model under `(server, model)`. Chainable.
    #[must_use]
    pub fn with_model(
        mut self,
        server: impl Into<String>,
        model: impl Into<String>,
        resolved: ResolvedModel,
    ) -> Self {
        self.models.insert((server.into(), model.into()), resolved);
        self
    }

    /// Whether any models are registered (lets the pipeline skip the LLM
    /// fast-path entirely when no models are configured).
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }
}

impl LlmModelResolver for StaticModelResolver {
    fn resolve(&self, server: &str, model: &str) -> Option<ResolvedModel> {
        // Borrow-friendly lookup without allocating the key tuple.
        self.models
            .iter()
            .find(|((s, m), _)| s == server && m == model)
            .map(|(_, resolved)| resolved.clone())
    }

    fn owns_server(&self, server: &str) -> bool {
        self.models.keys().any(|(s, _)| s == server)
    }
}

/// Discovered-model layer: the `(server, model)` table the discovery refresher
/// rebuilds from the DB catalog.
type DiscoveredModels = HashMap<(String, String), ResolvedModel>;

/// A resolver whose model table can be reloaded at runtime. Two layers:
///
/// - **pins** — the env-configured models ([`StaticModelResolver`]), with their
///   full-fidelity routing (failover pools, TTFB, cache TTL). Fixed for the
///   process lifetime.
/// - **discovered** — models the discovery refresher found upstream and wrote to
///   the catalog, rebuilt from the catalog and swapped in via [`reload`] without
///   a restart (simple single-route models — the catalog carries no failover).
///
/// The same `Arc<DbModelResolver>` is handed to the invocation pipeline (as
/// `Arc<dyn LlmModelResolver>`) AND kept by the refresher, so a reload is visible
/// to routing immediately while the pipeline's handle never changes. A **pin
/// always wins** over a discovered row of the same `(server, model)`: an operator
/// pin keeps its full routing and a stale discovered row can never shadow it.
pub struct DbModelResolver {
    pins: StaticModelResolver,
    discovered: RwLock<Arc<DiscoveredModels>>,
    /// The LLM namespace this resolver reserves. It is **owned unconditionally**
    /// (see [`owns_server`](LlmModelResolver::owns_server)) — even with zero
    /// models loaded — so that on a discovery-only deployment whose discovered
    /// layer has not been filled yet, an inbound `(reserved, model)` request is
    /// rejected as an unknown model instead of falling through to the MCP path
    /// (which would run an LLM `/v1` request under MCP facts/audit/budget — a
    /// governance bypass). A `DbModelResolver` exists only when the LLM path is
    /// active, so reserving the namespace can never wrongly shadow MCP.
    reserved_server: String,
}

impl DbModelResolver {
    /// Build from the env `pins`, an initial `discovered` layer (the boot
    /// snapshot of the catalog's discovered models — empty when none are present
    /// or no DB is wired), and the `reserved_server` LLM namespace this resolver
    /// owns unconditionally.
    pub fn new(
        pins: StaticModelResolver,
        discovered: DiscoveredModels,
        reserved_server: impl Into<String>,
    ) -> Self {
        Self {
            pins,
            discovered: RwLock::new(Arc::new(discovered)),
            reserved_server: reserved_server.into(),
        }
    }

    /// Replace the discovered layer with a fresh snapshot (the refresher calls
    /// this after each successful discovery cycle). The pins are untouched.
    pub fn reload(&self, discovered: DiscoveredModels) {
        *self
            .discovered
            .write()
            .expect("discovered layer lock poisoned") = Arc::new(discovered);
    }

    /// The current discovered-model count (logging / metrics).
    pub fn discovered_len(&self) -> usize {
        self.discovered
            .read()
            .expect("discovered layer lock poisoned")
            .len()
    }

    /// A cheap `Arc` snapshot of the discovered layer, so a lookup never holds
    /// the lock while cloning a `ResolvedModel`.
    fn discovered_snapshot(&self) -> Arc<DiscoveredModels> {
        self.discovered
            .read()
            .expect("discovered layer lock poisoned")
            .clone()
    }
}

impl LlmModelResolver for DbModelResolver {
    fn resolve(&self, server: &str, model: &str) -> Option<ResolvedModel> {
        // A pin wins; otherwise consult the discovered layer.
        if let Some(pinned) = self.pins.resolve(server, model) {
            return Some(pinned);
        }
        self.discovered_snapshot()
            .iter()
            .find(|((s, m), _)| s == server && m == model)
            .map(|(_, resolved)| resolved.clone())
    }

    fn owns_server(&self, server: &str) -> bool {
        // The reserved LLM namespace is owned even when empty, so an unknown
        // model under it is rejected rather than falling through to MCP.
        server == self.reserved_server
            || self.pins.owns_server(server)
            || self.discovered_snapshot().keys().any(|(s, _)| s == server)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResolvedRoute;
    use waygate_llm_credentials::LlmProvider;
    use waygate_llm_translate::UpstreamProtocol;

    fn route() -> ResolvedRoute {
        ResolvedRoute {
            provider: LlmProvider::OpenRouter,
            credential_label: "MAIN".into(),
            base_url: "http://example".into(),
            path: "chat/completions".into(),
            upstream_model: "openrouter/x".into(),
            protocol: UpstreamProtocol::OpenAiChat,
            embeddings_no_auth: false,
            openai_chatgpt: false,
        }
    }

    #[test]
    fn resolves_registered_model_and_misses_others() {
        let resolver = StaticModelResolver::new().with_model(
            "llm",
            "gpt-x",
            ResolvedModel {
                route: route(),
                operation: LlmOperation::Chat,
                fallbacks: vec![],
                risk: ModelRisk::High,
                ttfb: None,
                cache_ttl: None,
            },
        );
        let hit = resolver.resolve("llm", "gpt-x").expect("registered");
        assert_eq!(hit.risk, ModelRisk::High);
        assert_eq!(hit.route.upstream_model, "openrouter/x");
        // Unregistered server or model → not an LLM target.
        assert!(resolver.resolve("llm", "other").is_none());
        assert!(resolver.resolve("tools", "gpt-x").is_none());
        // The `llm` namespace is owned (so an unknown model under it is
        // rejected, not routed to MCP); other namespaces are not.
        assert!(resolver.owns_server("llm"));
        assert!(!resolver.owns_server("tools"));
        assert!(StaticModelResolver::new().is_empty());
    }

    /// A `ResolvedModel` with `upstream` as its route's upstream model, so a test
    /// can tell which layer a resolution came from.
    fn resolved(upstream: &str) -> ResolvedModel {
        ResolvedModel {
            route: ResolvedRoute {
                upstream_model: upstream.into(),
                ..route()
            },
            operation: LlmOperation::Chat,
            fallbacks: vec![],
            risk: ModelRisk::High,
            ttfb: None,
            cache_ttl: None,
        }
    }

    #[test]
    fn db_resolver_overlays_discovered_on_pins_with_pin_precedence() {
        let pins = StaticModelResolver::new().with_model("llm", "pinned", resolved("pin/up"));
        let mut discovered = HashMap::new();
        discovered.insert(("llm".to_string(), "disc".to_string()), resolved("disc/up"));
        // A discovered row colliding with a pin must be shadowed by the pin.
        discovered.insert(
            ("llm".to_string(), "pinned".to_string()),
            resolved("SHADOWED"),
        );
        let r = DbModelResolver::new(pins, discovered, "llm");

        // The pin resolves with its OWN route, never the colliding discovered one.
        assert_eq!(
            r.resolve("llm", "pinned").unwrap().route.upstream_model,
            "pin/up"
        );
        // A discovered-only model resolves from the discovered layer.
        assert_eq!(
            r.resolve("llm", "disc").unwrap().route.upstream_model,
            "disc/up"
        );
        // An unknown model under the owned namespace misses (rejected, not routed).
        assert!(r.resolve("llm", "absent").is_none());
        assert!(r.owns_server("llm"));
        assert!(!r.owns_server("tools"));
        assert_eq!(r.discovered_len(), 2);
    }

    #[test]
    fn db_resolver_reload_swaps_the_discovered_layer() {
        let r = DbModelResolver::new(StaticModelResolver::new(), HashMap::new(), "llm");
        // Empty discovered ⇒ nothing routes (the reserved namespace stays owned).
        assert!(r.resolve("llm", "m").is_none());

        // A discovery cycle adds a model.
        let mut next = HashMap::new();
        next.insert(("llm".to_string(), "m".to_string()), resolved("m/up"));
        r.reload(next);
        assert_eq!(r.resolve("llm", "m").unwrap().route.upstream_model, "m/up");
        assert!(r.owns_server("llm"));

        // A later cycle drops it (soft-disabled / absent) ⇒ it stops routing.
        r.reload(HashMap::new());
        assert!(r.resolve("llm", "m").is_none());
        assert_eq!(r.discovered_len(), 0);
    }

    #[test]
    fn db_resolver_with_empty_discovered_resolves_pins() {
        let pins = StaticModelResolver::new().with_model("llm", "p", resolved("p/up"));
        let r = DbModelResolver::new(pins, HashMap::new(), "llm");
        assert_eq!(r.resolve("llm", "p").unwrap().route.upstream_model, "p/up");
        assert!(r.resolve("llm", "absent").is_none());
        assert!(r.owns_server("llm"));
    }

    #[test]
    fn db_resolver_owns_reserved_namespace_even_when_empty() {
        // Discovery-only at boot: empty pins + empty discovered. The reserved llm
        // namespace MUST be owned so an inbound `(llm, model)` request is rejected
        // as an unknown model — never fallen through to the MCP path (which would
        // run a /v1 LLM request under MCP facts/audit/budget, a governance bypass).
        let r = DbModelResolver::new(StaticModelResolver::new(), HashMap::new(), "llm");
        assert!(
            r.resolve("llm", "anything").is_none(),
            "no models loaded yet"
        );
        assert!(
            r.owns_server("llm"),
            "the reserved namespace is owned with zero models"
        );
        assert!(
            !r.owns_server("tools"),
            "non-reserved namespaces are not owned"
        );
    }
}
