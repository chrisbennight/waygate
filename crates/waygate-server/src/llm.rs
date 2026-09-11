//! Inference-plane composition + HTTP surface for `waygate-server`.
//!
//! - [`build_from_env`] reads the configured model catalog and builds the
//!   [`LlmDispatcher`] + [`LlmModelResolver`] that the unified invocation
//!   pipeline's LLM fast-path uses. Credentials are *injected* into the
//!   container (Infisical) and read from the environment by the credential
//!   store — the gateway is a pure consumer (invariant I4).
//! - [`router`] exposes the OpenAI-compatible `/v1/chat/completions` endpoint.
//!   It builds an `InvocationRequest` and dispatches through the SAME
//!   `InvocationService` as everything else (invariant I1), so authorize /
//!   quota / audit all apply. Both response shapes are served: a non-streaming
//!   request returns the provider JSON body, and a `stream: true` request maps
//!   the pipeline's `InvocationResponse::Stream` to an axum SSE response
//!   (`data: <delta>` frames, a `data: [DONE]` sentinel, and an `event: error`
//!   frame for a mid-stream failure).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};

use waygate_core::http_client::{self, Profile};
use waygate_invocation::{
    InvocationError, InvocationRequest, InvocationResponse, InvocationStream,
};
use waygate_llm_credentials::{LlmCredentialStore, LlmProvider};
use waygate_llm_dispatch::{
    DbModelResolver, LlmDispatcher, LlmModelResolver, LlmOperation, ModelRisk, ResolvedModel,
    ResolvedRoute, StaticModelResolver,
};
use waygate_llm_providers::ProviderClient;
use waygate_llm_translate::{EmbeddingsProtocol, UpstreamProtocol};
use waygate_mcp::SharedInvocation;

/// Reserved server namespace for LLM models in the invocation pipeline. The
/// resolver is keyed on `(LLM_SERVER, <model alias>)` and the `/v1` route
/// builds its `InvocationRequest` with this server. Single source of truth in
/// `waygate-core`, shared with the manifest-load reservation so an MCP upstream
/// can never claim it.
pub const LLM_SERVER: &str = waygate_core::LLM_RESERVED_NAMESPACE;

/// Env var carrying the model catalog as a JSON array of [`ModelDef`].
const MODELS_ENV: &str = "GATEWAY_LLM_MODELS";

mod embedding_config;
mod embedding_errors;
mod images;

/// Max inbound request body (bytes) for an LLM call.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// The wired LLM deps. The resolver is the concrete [`DbModelResolver`] (env
/// pins overlaid with the catalog's discovered layer) so the boot loader — and
/// the discovery refresher slice — can call `reload` on it; it coerces to
/// `Arc<dyn LlmModelResolver>` where the pipeline consumes it.
pub type LlmDeps = (LlmDispatcher, Arc<DbModelResolver>);

/// Project [`LlmDeps`] into the `(dispatcher, dyn resolver)` shape the invocation
/// service consumes. The concrete `Arc<DbModelResolver>` (kept so the boot loader
/// / refresher can `reload` it) coerces to `Arc<dyn LlmModelResolver>` here.
pub fn deps_as_dyn(deps: &LlmDeps) -> (LlmDispatcher, Arc<dyn LlmModelResolver>) {
    let resolver: Arc<dyn LlmModelResolver> = deps.1.clone();
    (deps.0.clone(), resolver)
}

/// One configured model. v1 is OpenAI-chat-compatible across all providers.
#[derive(Debug, Clone, Deserialize)]
struct ModelDef {
    /// Client-facing model name (the `model` field clients send).
    alias: String,
    /// Provider owning the credential: openai | anthropic | google | openrouter.
    /// Required UNLESS the `model` shorthand supplies it; the two are mutually
    /// exclusive (set `provider`+`upstream_model`, or `model`, never both).
    /// Defaulted at the serde layer so a `model`-only entry deserializes;
    /// `normalize_model_defs` then fills it from the shorthand and rejects a
    /// def that ends up with neither.
    #[serde(default)]
    provider: String,
    /// Which injected credential label to use (`LLM_CRED_<PROVIDER>_<LABEL>`).
    /// The primary of the pool — the first target tried.
    #[serde(default)]
    credential_label: String,
    /// Upstream authentication, independent of client authentication at the gateway.
    #[serde(default)]
    authentication: Option<String>,
    /// Optional additional credential labels for the same provider/endpoint,
    /// forming an ordered failover pool with `credential_label` first (§7). On a
    /// retryable failure (429/5xx/transport/unavailable credential) dispatch
    /// fails over to these in order. Duplicates of `credential_label` are
    /// ignored. Empty/absent ⇒ a single-credential model.
    #[serde(default)]
    credential_labels: Option<Vec<String>>,
    /// Provider base URL, no trailing slash.
    base_url: String,
    /// Endpoint path under the base. When omitted, defaults per provider —
    /// `messages` for Anthropic, `chat/completions` otherwise — so an Anthropic
    /// model entry need not (and must not be silently mis-)route to the
    /// OpenAI-chat path. Set explicitly to override.
    #[serde(default)]
    path: Option<String>,
    /// The upstream model name to send (defaults to `alias`).
    #[serde(default)]
    upstream_model: Option<String>,
    /// Combined `provider:upstream_model` shorthand — one value carrying BOTH the
    /// provider and the upstream model name, e.g.
    /// `openrouter:qwen/qwen3-embedding-8b`. A convenience for env substitution:
    /// an operator can drive the whole upstream identity from a single variable
    /// (`"model":"${EMBEDDING_MODEL}"`) while `alias` — the client-facing name the
    /// `model` request field maps to — stays fixed and independent. Split on the
    /// FIRST `:` into `(provider, upstream_model)` (the upstream id may contain `/`
    /// but carries no leading provider colon). Mutually exclusive with `provider`
    /// / `upstream_model`: set the shorthand OR the split fields, never both.
    /// Resolved in place at parse time by `normalize_model_defs`, so every
    /// downstream consumer sees only the split form. Top-level convenience only —
    /// `fallbacks` keep their explicit `provider` / `upstream_model`.
    #[serde(default)]
    model: Option<String>,
    /// Risk tier: low | medium | high (omitted ⇒ low / no step-up; an explicit
    /// unrecognized value fails safe to high).
    #[serde(default)]
    risk: Option<String>,
    /// Optional surface selector (case-insensitive):
    /// - `responses` routes the model to the OpenAI Responses API (`/responses`,
    ///   `UpstreamProtocol::OpenAiResponses`) with plain `Bearer` auth — point
    ///   `base_url` at an OpenAI-compatible Responses endpoint.
    /// - `codex` is the ChatGPT backend (`base_url:
    ///   https://chatgpt.com/backend-api/codex`): the Responses body shape *plus*
    ///   the Codex auth fingerprint (`ProviderAuth::OpenAiChatGpt` —
    ///   originator/session/`chatgpt-account-id`), which a Codex subscription
    ///   OAuth token requires.
    ///
    /// Both record `upstream_api = responses`. Unset (or any other value) uses
    /// the provider's default protocol + path.
    #[serde(default)]
    surface: Option<String>,
    /// Optional operation selector (case-insensitive). `embeddings` makes this an
    /// embeddings model (`POST /v1/embeddings`): the route's default path becomes
    /// `embeddings`, auth defaults to `Bearer` (OpenAI-compatible embeddings is
    /// the only wired shape), and the catalog records `upstream_api = embeddings`.
    /// Unset (or `chat`) is a chat/completions model (the default). An embeddings
    /// model must be called on `/v1/embeddings`; the pipeline rejects a
    /// surface/operation mismatch. `surface` (responses/codex) does not apply to
    /// an embeddings model. `images` selects the direct Codex Images API,
    /// requires `surface: codex`, and defaults the endpoint prefix to `images`.
    #[serde(default)]
    kind: Option<String>,
    /// Optional ordered cross-provider failover groups (§7). After the primary
    /// group's credential pool is exhausted on retryable failures, dispatch fails
    /// over to each of these in turn — e.g. a subscription group falling back to
    /// an api-key group on a different provider/endpoint. Each is a full target
    /// (its own provider / base_url / credential pool / surface), with its own
    /// per-credential cooldown. Empty/absent ⇒ the model has only its primary
    /// group.
    #[serde(default)]
    fallbacks: Vec<FallbackTarget>,
    /// Optional time-to-first-byte deadline (milliseconds) for streamed calls
    /// (§7 stall detection). When set, a streamed call whose first SSE frame does
    /// not arrive within this window fails over to the next candidate instead of
    /// stalling. Absent ⇒ no TTFB failover (streaming stays bounded only by the
    /// idle-read timeout) — leave it unset for long-pre-token reasoning models.
    #[serde(default)]
    ttfb_ms: Option<u64>,
    /// Optional per-principal completion-cache TTL (milliseconds).
    /// `Some` opts this model into the exact-match cache (hit = free replay,
    /// miss = store the unary completion for this long). Absent ⇒ never cached.
    /// Off by default — set deliberately, and only for models whose responses
    /// are safe to reuse for an identical request from the same principal.
    #[serde(default)]
    cache_ttl_ms: Option<u64>,
}

/// One cross-provider failover group for a model (§7) — a full upstream target
/// with its own credential pool. `upstream_model` defaults to the model's alias
/// when omitted, like the primary target.
#[derive(Debug, Clone, Deserialize)]
struct FallbackTarget {
    provider: String,
    credential_label: String,
    #[serde(default)]
    credential_labels: Option<Vec<String>>,
    base_url: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    upstream_model: Option<String>,
    #[serde(default)]
    surface: Option<String>,
}

/// Whether a surface selector opts into the OpenAI Responses protocol
/// (`surface: responses`, case-insensitive).
fn surface_is_responses(surface: Option<&str>) -> bool {
    surface.is_some_and(|s| s.eq_ignore_ascii_case("responses"))
}

/// Whether a surface selector opts into the ChatGPT backend (`surface: codex`,
/// case-insensitive). The ChatGPT backend speaks the OpenAI Responses shape, so
/// it uses the same render/extract adapter as `surface: responses` but with the
/// Codex auth fingerprint (`ProviderAuth::OpenAiChatGpt`) — see
/// [`routes_for_target`].
fn surface_is_codex(surface: Option<&str>) -> bool {
    surface.is_some_and(|s| s.eq_ignore_ascii_case("codex"))
}

/// Whether a model entry uses the OpenAI Responses protocol
/// (`UpstreamProtocol::OpenAiResponses`) — via `surface: responses` OR
/// `surface: codex` (the ChatGPT backend, which is Responses-shaped). Any other
/// value — or none — uses the provider default. Drives both the route protocol
/// and the boot seeder's `upstream_api`.
fn wants_responses(def: &ModelDef) -> bool {
    surface_is_responses(def.surface.as_deref()) || surface_is_codex(def.surface.as_deref())
}

/// Whether this model serves the separate Images API.
fn is_images(def: &ModelDef) -> bool {
    def.kind
        .as_deref()
        .is_some_and(|k| k.eq_ignore_ascii_case("images"))
}

/// Whether this model serves the OpenAI-compatible embeddings operation.
fn is_embeddings(def: &ModelDef) -> bool {
    def.kind
        .as_deref()
        .is_some_and(|k| k.eq_ignore_ascii_case("embeddings"))
}

/// The model's upstream wire API for the catalog's `upstream_api` column.
/// An embeddings model is `embeddings`; otherwise the resolved
/// [`UpstreamProtocol`]'s name: `surface: responses|codex` → `responses` (the
/// Codex auth variant is carried separately by `openai_chatgpt`); else the
/// provider's native shape (Anthropic → `messages`, Google → `generate_content`,
/// OpenAI/OpenRouter → `chat_completions`). Mirrors the protocol/path
/// [`routes_for_target`] resolves, so the catalog never disagrees with the live
/// route (#395).
fn upstream_api_for(def: &ModelDef) -> &'static str {
    if is_images(def) {
        return "images";
    }
    if is_embeddings(def) {
        return EmbeddingsProtocol::OpenAi.wire_name();
    }
    let protocol = if wants_responses(def) {
        UpstreamProtocol::OpenAiResponses
    } else {
        protocol_for(parse_provider(&def.provider).unwrap_or(LlmProvider::OpenAi))
    };
    protocol.wire_name()
}

/// Build the ordered `ResolvedRoute`s for one target group: its primary
/// Apply an optional egress proxy (env `GATEWAY_LLM_EGRESS_PROXY`) to the LLM
/// provider HTTP client builder, scoped to this client ONLY so it does not
/// reroute the gateway's other HTTPS (OIDC, JWKS, discovery). The intended target
/// is a uTLS-terminating sidecar that re-originates the upstream TLS with a
/// CLI-like ClientHello — the JA3/JA4 transport fingerprint that header/body
/// fidelity cannot address (see `docs/inference-plane.md` §13.1). `None`/blank ⇒
/// unchanged (reqwest still honors the system `*_PROXY` vars). A malformed URL is
/// a hard error (fail boot loudly); the URL is never logged (it may embed proxy
/// credentials).
fn apply_egress_proxy(
    builder: reqwest::ClientBuilder,
    proxy_url: Option<&str>,
) -> anyhow::Result<reqwest::ClientBuilder> {
    match proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(builder),
        Some(url) => {
            // Only http/https are wired: the workspace builds reqwest without its
            // `socks` feature, so a `socks5://` proxy would parse but fail at
            // request time. Reject any other scheme at boot rather than silently
            // accepting a proxy that cannot work. (Scheme compared case-insensitively;
            // the rest of the URL — which may carry credentials — is never echoed.)
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                return Err(anyhow::anyhow!(
                    "GATEWAY_LLM_EGRESS_PROXY must be an http:// or https:// URL \
                     (SOCKS is not supported — reqwest is built without its `socks` feature)"
                ));
            }
            let proxy = reqwest::Proxy::all(url)
                .map_err(|e| anyhow::anyhow!("invalid GATEWAY_LLM_EGRESS_PROXY: {e}"))?;
            tracing::info!("LLM provider egress is routed through GATEWAY_LLM_EGRESS_PROXY");
            Ok(builder.proxy(proxy))
        }
    }
}

/// credential label first, then any additional pool labels (deduped against the
/// primary), all sharing the group's provider / endpoint / protocol / upstream
/// model. `surface: responses` selects the Responses protocol + default path.
#[allow(clippy::too_many_arguments)]
fn routes_for_target(
    provider_str: &str,
    primary_label: String,
    extra_labels: Option<Vec<String>>,
    base_url: String,
    path: Option<String>,
    upstream_model: String,
    surface: Option<&str>,
    is_embeddings: bool,
) -> anyhow::Result<Vec<ResolvedRoute>> {
    let provider = parse_provider(provider_str)?;
    // `surface: codex` is the ChatGPT backend — Responses-shaped body, but it
    // flips the auth to the Codex fingerprint (set via `openai_chatgpt` below).
    // It does not apply to an embeddings route (which defaults to Bearer).
    let chatgpt = !is_embeddings && surface_is_codex(surface);
    let (protocol, default_path) = if is_embeddings {
        // OpenAI-compatible embeddings: POST to `embeddings` with plain `Bearer`.
        // `OpenAiChat` is the inert protocol placeholder on an embeddings route —
        // `dispatch_embeddings` never reads it; the operation lives on
        // `ResolvedModel`. `surface` (responses/codex) does not apply.
        (UpstreamProtocol::OpenAiChat, "embeddings".to_string())
    } else if surface_is_responses(surface) || chatgpt {
        (UpstreamProtocol::OpenAiResponses, "responses".to_string())
    } else {
        (protocol_for(provider), default_path_for(provider))
    };
    let resolved_path = path.unwrap_or(default_path);
    // The Anthropic Messages path is the bare `messages`; the `/v1` lives in
    // base_url (the gateway joins `{base_url}/{path}`). A base_url without `/v1`
    // ⇒ the request goes to `<host>/messages`, which api.anthropic.com answers
    // with a 404 (empty body). Warn loudly at boot rather than 404 at call time.
    if protocol == UpstreamProtocol::AnthropicMessages
        && !base_url.contains("/v1")
        && !resolved_path.contains("v1")
    {
        tracing::warn!(
            provider = provider_str,
            base_url = %base_url,
            "anthropic base_url has no `/v1` segment; the Messages path is `messages`, so the \
             request URL becomes `<base_url>/messages` — set base_url to e.g. \
             https://api.anthropic.com/v1 or the upstream returns 404"
        );
    }
    // Ordered labels: primary first, then the deduped extras.
    let mut labels = vec![primary_label.clone()];
    for label in extra_labels.unwrap_or_default() {
        if label != primary_label && !labels.contains(&label) {
            labels.push(label);
        }
    }
    Ok(labels
        .into_iter()
        .map(|label| ResolvedRoute {
            provider,
            credential_label: label,
            base_url: base_url.clone(),
            path: resolved_path.clone(),
            upstream_model: upstream_model.clone(),
            protocol,
            embeddings_no_auth: false,
            openai_chatgpt: chatgpt,
        })
        .collect())
}

/// The default endpoint path for a provider when a model entry omits `path`.
/// Anthropic speaks the Messages API (`messages`); the OpenAI-chat-compatible
/// providers use `chat/completions`. Google/Gemini's real path is templated with
/// the model at dispatch time (`v1beta/models/<model>:generateContent`), so the
/// stored path is unused for it — `v1beta` is a harmless display placeholder.
/// Keep in lockstep with [`protocol_for`].
fn default_path_for(provider: LlmProvider) -> String {
    match provider {
        LlmProvider::Anthropic => "messages".to_string(),
        LlmProvider::Google => "v1beta".to_string(),
        _ => "chat/completions".to_string(),
    }
}

/// Build the dispatcher + resolver from `GATEWAY_LLM_MODELS`. `Ok(None)` when no
/// models are configured (the gateway runs MCP-only, unchanged). `call_timeout`
/// (the operator's `upstream_call_timeout`) bounds a slow/wedged provider: it is
/// the connect + idle-read timeout for every call, and additionally the total
/// per-request deadline for *non-streaming* calls (a streaming response is
/// long-lived, so it is bounded by the idle-read gap only — a total deadline
/// would sever a healthy stream).
/// `discovery_configured` is `true` when `GATEWAY_LLM_DISCOVERY` names at least
/// one usable target. The LLM path is built when there are configured pins OR
/// discovery is enabled — a **discovery-only** deployment (no
/// `GATEWAY_LLM_MODELS`) still needs the dispatcher, resolver, credentials, and
/// `/v1` routes so the refresher can populate the catalog and the discovered
/// models become routable. `Ok(None)` only when neither is configured (MCP-only).
pub fn build_from_env(
    call_timeout: Option<std::time::Duration>,
    discovery_configured: bool,
) -> anyhow::Result<Option<LlmDeps>> {
    let defs = parse_model_defs()?.unwrap_or_default();
    if defs.is_empty() && !discovery_configured {
        return Ok(None);
    }
    build_from_defs(defs, call_timeout)
}

/// Parse the configured model catalog from `GATEWAY_LLM_MODELS`. `Ok(None)`
/// when the var is unset or blank (the gateway runs MCP-only). Shared by
/// [`build_from_env`] (which builds the routing resolver) and
/// [`configured_model_rows`] (the boot seeder), so both see exactly the same
/// catalog.
fn parse_model_defs() -> anyhow::Result<Option<Vec<ModelDef>>> {
    let raw = match std::env::var(MODELS_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(None),
    };
    let mut defs: Vec<ModelDef> = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("{MODELS_ENV} is not a valid JSON array of models: {e}"))?;
    normalize_model_defs(&mut defs)?;
    Ok(Some(defs))
}

/// Resolve each model's `model: "provider:upstream"` shorthand into the explicit
/// `provider` + `upstream_model` fields, in place, BEFORE any consumer reads
/// them. Both real consumers — the routing resolver ([`build_from_defs`]) and the
/// catalog seeder ([`configured_model_rows`]) — flow through [`parse_model_defs`],
/// so normalizing there is the single seam that keeps them seeing one catalog.
/// Split out as a pure function over `&mut [ModelDef]` so the shorthand contract
/// is unit-testable without touching the process environment.
///
/// Rules, fail-closed (a malformed pin fails boot loudly rather than routing
/// somewhere unintended):
/// - `model` splits on the FIRST `:` into `(provider, upstream_model)`; both
///   halves must be non-empty, and a value with no `:` is rejected.
/// - `model` is mutually exclusive with `provider` / `upstream_model` — setting
///   the shorthand AND either split field is ambiguous and rejected.
/// - After resolution every entry must carry a non-empty `provider`. The provider
///   STRING is validated downstream by `parse_provider` (in [`routes_for_target`]);
///   this step is purely structural so it stays decoupled from the provider set.
fn normalize_model_defs(defs: &mut [ModelDef]) -> anyhow::Result<()> {
    for def in defs.iter_mut() {
        if let Some(model) = def.model.take() {
            if !def.provider.is_empty() {
                return Err(anyhow::anyhow!(
                    "model \"{}\": set either `model` (the provider:upstream shorthand) \
                     or `provider`, not both",
                    def.alias
                ));
            }
            if def.upstream_model.is_some() {
                return Err(anyhow::anyhow!(
                    "model \"{}\": set either `model` (the provider:upstream shorthand) \
                     or `upstream_model`, not both",
                    def.alias
                ));
            }
            let (provider, upstream) = model.split_once(':').ok_or_else(|| {
                anyhow::anyhow!(
                    "model \"{}\": `model` must be \"provider:upstream\" \
                     (e.g. openrouter:qwen/qwen3-embedding-8b), got \"{model}\"",
                    def.alias
                )
            })?;
            if provider.is_empty() || upstream.is_empty() {
                return Err(anyhow::anyhow!(
                    "model \"{}\": `model` must be \"provider:upstream\" with both halves \
                     non-empty, got \"{model}\"",
                    def.alias
                ));
            }
            def.provider = provider.to_owned();
            def.upstream_model = Some(upstream.to_owned());
        }
        if def.provider.is_empty() {
            return Err(anyhow::anyhow!(
                "model \"{}\": missing `provider` (set it, or use the `model` \
                 provider:upstream shorthand)",
                def.alias
            ));
        }
    }
    Ok(())
}

/// Build the dispatcher + DB-backed resolver from the configured pins. `defs`
/// MAY be empty (a discovery-only deployment): the pins layer is then empty and
/// the discovery refresher fills the discovered layer. Always returns `Some` —
/// the "no LLM path at all" decision lives in [`build_from_env`].
fn build_from_defs(
    defs: Vec<ModelDef>,
    call_timeout: Option<std::time::Duration>,
) -> anyhow::Result<Option<LlmDeps>> {
    let mut resolver = StaticModelResolver::new();
    for def in defs {
        let risk = parse_risk(def.risk.as_deref());
        // A model is wholly chat or wholly embeddings; the operation applies to
        // the primary AND every fallback target (you cannot fail an embeddings
        // call over to a chat endpoint).
        let is_emb = is_embeddings(&def);
        let is_img = is_images(&def);
        let no_auth = embedding_config::no_auth(&def)?;
        if is_img
            && (!def.provider.eq_ignore_ascii_case("openai")
                || !surface_is_codex(def.surface.as_deref())
                || !def.fallbacks.is_empty()
                || def
                    .credential_labels
                    .as_ref()
                    .is_some_and(|labels| !labels.is_empty())
                || def.cache_ttl_ms.is_some()
                || def.ttfb_ms.is_some())
        {
            anyhow::bail!("image models require one OpenAI Codex credential without fallbacks, caching, or streaming deadlines");
        }
        // Build the primary group's routes (its credential pool), then each
        // cross-provider fallback group's routes, flattened in order. The first
        // route is the model's primary; the rest are its ordered fallbacks (§7).
        let primary_model = def
            .upstream_model
            .clone()
            .unwrap_or_else(|| def.alias.clone());
        let mut routes = routes_for_target(
            &def.provider,
            def.credential_label.clone(),
            def.credential_labels.clone(),
            def.base_url.clone(),
            if is_img {
                Some(def.path.clone().unwrap_or_else(|| "images".into()))
            } else {
                def.path.clone()
            },
            primary_model,
            def.surface.as_deref(),
            is_emb,
        )?;
        routes[0].embeddings_no_auth = no_auth;
        for fb in &def.fallbacks {
            let fb_model = fb
                .upstream_model
                .clone()
                .unwrap_or_else(|| def.alias.clone());
            routes.extend(routes_for_target(
                &fb.provider,
                fb.credential_label.clone(),
                fb.credential_labels.clone(),
                fb.base_url.clone(),
                fb.path.clone(),
                fb_model,
                fb.surface.as_deref(),
                is_emb,
            )?);
        }
        let mut routes = routes.into_iter();
        let route = routes
            .next()
            .expect("a target group yields at least its primary route");
        let fallbacks: Vec<ResolvedRoute> = routes.collect();
        resolver = resolver.with_model(
            LLM_SERVER,
            def.alias,
            ResolvedModel {
                route,
                operation: if is_img {
                    LlmOperation::Images
                } else if is_emb {
                    LlmOperation::Embeddings
                } else {
                    LlmOperation::Chat
                },
                fallbacks,
                risk,
                ttfb: def.ttfb_ms.map(std::time::Duration::from_millis),
                cache_ttl: def.cache_ttl_ms.map(std::time::Duration::from_millis),
            },
        );
    }
    // The store reads injected `LLM_CRED_*` credentials from the environment and
    // owns OAuth refresh; this process never sources or persists them (I4).
    let credentials = Arc::new(
        LlmCredentialStore::from_env()
            .map_err(|e| anyhow::anyhow!("building the LLM credential refresh client: {e}"))?,
    );
    // Bound a slow/wedged provider with connect + idle-read timeouts on the
    // shared client (NOT a client-wide total-request timeout): a healthy
    // streaming response is long-lived, so a total timeout would sever it after
    // a fixed duration. connect_timeout caps the initial connect; read_timeout
    // caps the gap between bytes — together they catch a hung provider for both
    // unary and streaming calls without killing a working stream.
    // Both clients inherit the same optional egress proxy (which can contain
    // credentials and must never be logged), TLS defaults, and timeouts.
    let egress_proxy = std::env::var("GATEWAY_LLM_EGRESS_PROXY").ok();
    let build_http = || {
        let mut builder = http_client::builder(Profile::NoTotalTimeout);
        if let Some(timeout) = call_timeout {
            builder = builder.connect_timeout(timeout).read_timeout(timeout);
        }
        apply_egress_proxy(builder, egress_proxy.as_deref())
    };
    let http = build_http()?
        .build()
        .map_err(|e| anyhow::anyhow!("building the LLM HTTP client: {e}"))?;
    // Idle-read alone leaves a *unary* call unbounded against a slow-drip
    // provider (bytes just under read_timeout, forever). Give the non-streaming
    // path a total per-request deadline; the ProviderClient applies it only to
    // unary calls, so streams keep relying on idle-read.
    let providers = ProviderClient::new(http)
        .with_single_attempt_http(build_http()?)
        .map_err(|e| anyhow::anyhow!("building the image HTTP client: {e}"))?
        .with_unary_timeout(call_timeout);
    // The shared Codex UA version handle: dispatch reads it per ChatGPT-backend
    // request; the discovery refresher (when a Codex target is configured)
    // hot-swaps it to the version the model listing was fetched as, so both
    // surfaces present one client identity. Seeded from the discovery crate's
    // compiled default so a pinned-model-only deployment (no discovery) still
    // sends a current version.
    let codex_ua_version: waygate_llm_providers::SharedCodexUaVersion = Arc::new(
        std::sync::RwLock::new(waygate_llm_discovery::CODEX_DEFAULT_CLIENT_VERSION.to_string()),
    );
    let dispatcher =
        LlmDispatcher::new(providers, credentials).with_codex_ua_version(codex_ua_version);
    // Wrap the env pins in a DB-backed resolver with an empty discovered layer.
    // The boot loader fills it from the catalog (and the discovery refresher
    // reloads it at runtime); with no discovered rows it resolves exactly like
    // the bare pins, so this is behavior-preserving until discovery lands.
    let resolver = Arc::new(DbModelResolver::new(resolver, HashMap::new(), LLM_SERVER));
    Ok(Some((dispatcher, resolver)))
}

/// Convert a catalog row into a routable [`ResolvedModel`] — a simple
/// single-route model (the catalog carries no failover / TTFB / cache TTL; those
/// are env-pin-only). `None` when the row's provider string does not parse (a
/// malformed row that could never route); the loader logs and skips it rather
/// than failing the whole load.
fn resolved_from_catalog_row(row: &waygate_storage::LlmModelRow) -> Option<ResolvedModel> {
    let provider = parse_provider(&row.provider).ok()?;
    // `upstream_api` IS routing-determinative here (the one place a catalog row's
    // value drives routing): `embeddings` selects the embeddings operation,
    // `responses` selects the OpenAI Responses protocol; every other value
    // (`messages` / `generate_content` / `chat_completions`) falls through to the
    // provider-derived chat protocol. An `embeddings` row reaches here either from
    // a config pin (`kind: embeddings`) or from discovery (the refresher tags
    // OpenRouter's `/embeddings/models` rows `upstream_api = embeddings`).
    let is_img = row.upstream_api.eq_ignore_ascii_case("images");
    let is_emb = row.upstream_api.eq_ignore_ascii_case("embeddings");
    let protocol = if is_emb {
        // Inert on the embeddings path (dispatch_embeddings ignores it); the
        // operation below is what routes the call.
        UpstreamProtocol::OpenAiChat
    } else if row.upstream_api.eq_ignore_ascii_case("responses") {
        UpstreamProtocol::OpenAiResponses
    } else {
        protocol_for(provider)
    };
    Some(ResolvedModel {
        route: ResolvedRoute {
            provider,
            credential_label: row.credential_label.clone(),
            base_url: row.base_url.clone(),
            path: row.path.clone(),
            upstream_model: row.upstream_model.clone(),
            protocol,
            // The ChatGPT-backend (Codex) auth variant is carried by its own
            // catalog column: `upstream_api = responses` selects the Responses
            // protocol (above), and `openai_chatgpt` then flips the transport auth
            // to the Codex fingerprint. Discovered Codex rows set the column at
            // upsert time (the refresher's Codex arm), so a discovered route can
            // now reach the ChatGPT backend — not just an env-pin `surface: codex`.
            embeddings_no_auth: false,
            openai_chatgpt: row.openai_chatgpt,
        },
        operation: if is_img {
            LlmOperation::Images
        } else if is_emb {
            LlmOperation::Embeddings
        } else {
            LlmOperation::Chat
        },
        fallbacks: vec![],
        risk: parse_risk(Some(&row.risk)),
        ttfb: None,
        cache_ttl: None,
    })
}

/// Load the default tenant's effective-live **discovered** models from the
/// catalog and build the resolver's discovered layer, keyed by
/// `(LLM_SERVER, alias)`. A row whose provider does not parse is logged and
/// skipped (fail-open: one bad row never blocks the rest). Shared by the boot
/// loader and the discovery refresher slice.
pub async fn load_discovered_models(
    pool: &sqlx::PgPool,
) -> anyhow::Result<HashMap<(String, String), ResolvedModel>> {
    let tenant = waygate_core::TenantId::default();
    let rows = waygate_storage::list_discovered_llm_models(pool, tenant.as_str()).await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in &rows {
        match resolved_from_catalog_row(row) {
            Some(model) => {
                map.insert((LLM_SERVER.to_string(), row.alias.clone()), model);
            }
            None => tracing::warn!(
                alias = %row.alias,
                provider = %row.provider,
                "discovered model has an unparseable provider; skipping it in the resolver"
            ),
        }
    }
    Ok(map)
}

/// Boot loader: read the discovered models and swap them into `resolver`'s
/// discovered layer, returning the count loaded. Safe with an empty catalog
/// (loads nothing → the resolver keeps resolving env pins only). On a restart
/// after a prior discovery run, this makes the persisted discovered models
/// routable immediately, before the first refresh cycle.
pub async fn boot_load_discovered(
    pool: &sqlx::PgPool,
    resolver: &DbModelResolver,
) -> anyhow::Result<usize> {
    let map = load_discovered_models(pool).await?;
    let n = map.len();
    resolver.reload(map);
    Ok(n)
}

/// Map one configured [`ModelDef`] to its catalog upsert row for the boot
/// seeder. Costing is absent from the env config — operators set it in the DB
/// and the upsert preserves it on conflict — so it is left unset here. Provider
/// and risk are normalized to the lowercase vocabulary the `llm_models` CHECK
/// constraints accept. `upstream_api` records the model's real upstream wire API
/// — the resolved `UpstreamProtocol` via [`upstream_api_for`]: `messages` for
/// Anthropic, `generate_content` for Gemini, `responses` for
/// `surface: responses|codex`, `chat_completions` otherwise (#395).
fn model_def_to_upsert(def: &ModelDef) -> waygate_storage::LlmModelUpsert {
    let responses = wants_responses(def);
    waygate_storage::LlmModelUpsert {
        tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
        alias: def.alias.clone(),
        provider: def.provider.to_ascii_lowercase(),
        credential_label: def.credential_label.clone(),
        upstream_model: def
            .upstream_model
            .clone()
            .unwrap_or_else(|| def.alias.clone()),
        base_url: def.base_url.clone(),
        // Same default resolution as the route (build_from_defs): an embeddings
        // model defaults to `embeddings`; a `surface: responses` entry to
        // `responses`; otherwise an omitted path becomes `messages` for Anthropic,
        // else `chat/completions`. Falls back to the OpenAI-chat path if the
        // provider string doesn't parse (build_from_defs surfaces that as a hard
        // error).
        path: def.path.clone().unwrap_or_else(|| {
            if is_images(def) {
                "images".to_string()
            } else if is_embeddings(def) {
                "embeddings".to_string()
            } else if responses {
                "responses".to_string()
            } else {
                parse_provider(&def.provider)
                    .map(default_path_for)
                    .unwrap_or_else(|_| "chat/completions".to_string())
            }
        }),
        upstream_api: upstream_api_for(def).to_owned(),
        // A `surface: codex` pin is the Responses shape against the ChatGPT
        // backend; persist that auth variant so a redeploy (or the dashboard
        // reading the catalog) sees the same Codex fingerprint the in-memory
        // route uses. Every other surface — and every embeddings model — is plain
        // Bearer ⇒ false.
        openai_chatgpt: !is_embeddings(def) && surface_is_codex(def.surface.as_deref()),
        risk: model_risk_str(parse_risk(def.risk.as_deref())).to_owned(),
        requires_approval: false,
        description: None,
        enabled: true,
    }
}

/// String form of a [`ModelRisk`] for the `llm_models.risk` column (matches the
/// CHECK vocabulary and the Cedar risk attribute).
fn model_risk_str(r: ModelRisk) -> &'static str {
    match r {
        ModelRisk::Low => "low",
        ModelRisk::Medium => "medium",
        ModelRisk::High => "high",
    }
}

/// The configured models as catalog upsert rows. `Ok(vec![])` when none are
/// configured. Re-parses `GATEWAY_LLM_MODELS` — already validated by
/// `build_from_env` at boot — to keep the seeder decoupled from the resolver
/// build.
pub fn configured_model_rows() -> anyhow::Result<Vec<waygate_storage::LlmModelUpsert>> {
    Ok(parse_model_defs()?
        .unwrap_or_default()
        .iter()
        .map(model_def_to_upsert)
        .collect())
}

/// Seed the configured models into `llm_models`. Idempotent: each
/// upsert is keyed on `(tenant_id, alias)` and the ON CONFLICT path preserves
/// operator-set costing, so this is safe to run on every boot. One transaction
/// so a discovery / budget reader never observes a half-seeded catalog.
pub async fn seed_models(
    pool: &sqlx::PgPool,
    rows: &[waygate_storage::LlmModelUpsert],
) -> anyhow::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for row in rows {
        waygate_storage::upsert_llm_model(&mut *tx, row).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) fn parse_provider(s: &str) -> anyhow::Result<LlmProvider> {
    match s.to_ascii_lowercase().as_str() {
        "openai" => Ok(LlmProvider::OpenAi),
        "anthropic" => Ok(LlmProvider::Anthropic),
        "google" => Ok(LlmProvider::Google),
        "openrouter" => Ok(LlmProvider::OpenRouter),
        other => Err(anyhow::anyhow!("unknown LLM provider {other:?}")),
    }
}

/// The wire protocol a provider's configured endpoint speaks. Anthropic talks
/// its Messages API; Google talks Gemini `generateContent`; OpenAI / OpenRouter
/// (which normalizes other providers to the OpenAI shape) are OpenAI-chat.
/// OpenAI-Responses keeps OpenAI-chat until its adapter lands.
fn protocol_for(provider: LlmProvider) -> UpstreamProtocol {
    match provider {
        LlmProvider::Anthropic => UpstreamProtocol::AnthropicMessages,
        LlmProvider::Google => UpstreamProtocol::Gemini,
        _ => UpstreamProtocol::OpenAiChat,
    }
}

fn parse_risk(s: Option<&str>) -> ModelRisk {
    match s.map(str::to_ascii_lowercase).as_deref() {
        // OMITTED risk ⇒ Low: this gateway's deliberate posture — an unclassified
        // model is invocable by any authenticated principal (models are not
        // step-up-gated; access is a Cedar-permit concern). Reverses migration
        // 0047's fail-closed default; the DB column default is flipped to
        // match (migration 0057).
        None => ModelRisk::Low,
        Some("low") => ModelRisk::Low,
        Some("medium") => ModelRisk::Medium,
        Some("high") => ModelRisk::High,
        // An EXPLICIT but unmapped value fails SAFE to High — never silently Low.
        // Covers the schema-accepted `critical` (there is no `ModelRisk::Critical`,
        // so it takes the strongest tier) and any typo of an elevated value (e.g.
        // "hihg"): ONLY omission takes the low default, never a present value. This
        // is the fix for the round-1 regression where every unrecognized string —
        // including `critical` and elevated-risk typos — collapsed to Low.
        Some(_) => ModelRisk::High,
    }
}

/// Shared state for the OpenAI-compatible `/v1` router. `invocation` drives the
/// governed dispatch path for `/v1/chat/completions`; `models` is the read-only
/// catalog the `/v1/models` discovery endpoint lists (`None` in DB-less dev mode,
/// where routing still works from the env resolver but there is no catalog to
/// enumerate); `resolver` is the same routing resolver `/v1/chat/completions`
/// dispatches through, used to filter the listing down to models a client can
/// actually call.
#[derive(Clone)]
struct LlmRouterState {
    invocation: SharedInvocation,
    models: Option<waygate_storage::SharedLlmModelCatalog>,
    resolver: Arc<dyn LlmModelResolver>,
    image_capacity: Arc<tokio::sync::Semaphore>,
}

/// The OpenAI-compatible inference router. Mounted behind the gateway's bearer
/// middleware, so the authenticated principal is read from the request.
pub fn router(
    invocation: SharedInvocation,
    models: Option<waygate_storage::SharedLlmModelCatalog>,
    resolver: Arc<dyn LlmModelResolver>,
) -> Router<()> {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/images/generations", post(images::generations))
        .route("/v1/images/edits", post(images::edits))
        .route("/v1/models", get(list_models))
        .with_state(LlmRouterState {
            invocation,
            models,
            resolver,
            image_capacity: Arc::new(tokio::sync::Semaphore::new(images::MAX_CONCURRENT_IMAGES)),
        })
}

/// Project catalog rows into the OpenAI `GET /v1/models` list body
/// (`{ "object": "list", "data": [...] }`). Each row becomes an OpenAI model
/// object keyed by its client-facing `alias` (`id`), with the provider as
/// `owned_by` and the catalog `created_at` as the unix `created` timestamp — the
/// fields an OpenAI SDK reads off a models listing.
fn models_list_json(rows: Vec<waygate_storage::LlmModelRow>) -> Value {
    let data: Vec<Value> = rows
        .into_iter()
        .map(|m| {
            json!({
                "id": m.alias,
                "object": "model",
                "created": m.created_at.unix_timestamp(),
                "owned_by": m.provider,
                "modality": model_modality(&m.upstream_api),
            })
        })
        .collect();
    json!({ "object": "list", "data": data })
}

/// The `/v1/models` `modality` discriminator derived from a catalog row's
/// `upstream_api` (the single source of truth for a model's operation): an
/// `embeddings` row is `text->embedding`; every chat-family surface
/// (`chat_completions` / `responses` / `messages` / `generate_content`) is
/// `text->text`. A non-standard OpenAI field (SDKs ignore unknown keys), it lets
/// an embeddings-aware client tell the surfaces apart without calling each one;
/// `GET /v1/models?type=embeddings|chat` filters on the same distinction.
fn model_modality(upstream_api: &str) -> &'static str {
    if upstream_api.eq_ignore_ascii_case("images") {
        return "text+image->image";
    }
    if upstream_api.eq_ignore_ascii_case("embeddings") {
        "text->embedding"
    } else {
        "text->text"
    }
}

/// `?type=` filter for `GET /v1/models`: narrows the listing to one operation
/// kind so a client can discover embeddings models as distinct from chat ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ModelKindFilter {
    Images,
    Embeddings,
    Chat,
}

impl ModelKindFilter {
    /// Extract a `type=embeddings|chat` filter from a raw URL query string.
    /// `None` when absent or unrecognized (the endpoint stays lenient — an
    /// unknown `type` yields the full, unfiltered listing).
    fn from_query(query: &str) -> Option<Self> {
        query.split('&').find_map(|pair| {
            let v = pair.strip_prefix("type=")?;
            match v.to_ascii_lowercase().as_str() {
                "embeddings" | "embedding" => Some(Self::Embeddings),
                "chat" => Some(Self::Chat),
                "images" | "image" => Some(Self::Images),
                _ => None,
            }
        })
    }

    /// Whether a catalog row matches this filter, by its `upstream_api`.
    fn matches(self, upstream_api: &str) -> bool {
        let is_emb = upstream_api.eq_ignore_ascii_case("embeddings");
        match self {
            Self::Images => upstream_api.eq_ignore_ascii_case("images"),
            Self::Embeddings => is_emb,
            Self::Chat => !is_emb && !upstream_api.eq_ignore_ascii_case("images"),
        }
    }
}

/// `GET /v1/models` — OpenAI-compatible model discovery. Lists the calling
/// principal's tenant's **enabled** catalog models (the same store the admin
/// `/llm_models` page reads), so an OpenAI SDK client can enumerate what it may
/// call — a combined listing of chat and embeddings models, each callable on its
/// matching surface (chat/responses on `/v1/chat/completions` · `/v1/responses`,
/// embeddings on `/v1/embeddings`). Each entry carries a `modality` field
/// (`text->embedding` vs `text->text`) so a client can tell the surfaces apart,
/// and the listing accepts `?type=embeddings|chat` to filter to one kind.
/// Tenant-scoped: a principal only ever sees its own tenant's models. With no
/// catalog store wired (DB-less dev mode) the list is empty even though routing
/// still works from the env resolver.
async fn list_models(State(state): State<LlmRouterState>, req: Request) -> Response {
    let tenant = waygate_oidc::middleware::principal_from_req(&req)
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::default().as_str().to_owned());
    let type_filter = req.uri().query().and_then(ModelKindFilter::from_query);
    models_response(
        state.models.as_ref(),
        &tenant,
        state.resolver.as_ref(),
        type_filter,
    )
    .await
}

/// Build the `GET /v1/models` response for `tenant` from the catalog store:
/// `None` (DB-less dev) ⇒ an empty list; a store read error ⇒ `503`; otherwise
/// the tenant's enabled rows projected by [`models_list_json`]. Factored out of
/// the handler so tenant-scoping, error mapping, and the OpenAI shape are
/// unit-testable without constructing a full invocation service / HTTP request.
///
/// The rows are filtered to those `resolver` can currently resolve — i.e. models
/// the inference plane can actually dispatch (each on its matching surface). The
/// catalog is upsert-seeded from `GATEWAY_LLM_MODELS` and never auto-prunes a row
/// dropped from the env config, so an enabled-but-orphaned alias can linger in
/// the DB; without this filter the discovery endpoint would advertise a model the
/// `/v1` routes would then reject as unknown. Once the catalog becomes the routing
/// authority (the dynamic-resolver slice), every listed row resolves and the
/// filter is a no-op.
async fn models_response(
    store: Option<&waygate_storage::SharedLlmModelCatalog>,
    tenant: &str,
    resolver: &dyn LlmModelResolver,
    type_filter: Option<ModelKindFilter>,
) -> Response {
    let rows = match store {
        Some(store) => match store.list_models(tenant).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, "GET /v1/models: list_models failed");
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "api_error",
                    "the model catalog is temporarily unavailable",
                );
            }
        },
        None => Vec::new(),
    };
    let rows: Vec<waygate_storage::LlmModelRow> = rows
        .into_iter()
        .filter(|r| resolver.resolve(LLM_SERVER, &r.alias).is_some())
        .filter(|r| match type_filter {
            Some(f) => f.matches(&r.upstream_api),
            None => true,
        })
        .collect();
    (StatusCode::OK, Json(models_list_json(rows))).into_response()
}

/// Shared inference-route body reader: consume the size-capped request body,
/// parse it as JSON, and extract the required `model`. `Err` is a
/// ready-to-return error envelope (oversized body / invalid JSON / missing
/// `model`). The caller reads the principal *before* calling this (it consumes the
/// request body). Shared by `/v1/chat/completions` and `/v1/responses`.
// The error side is boxed to satisfy clippy's `result_large_err` (a full
// axum `Response` is hundreds of bytes); callers `return *resp`.
async fn read_llm_body(req: Request) -> Result<(Value, String), Box<Response>> {
    let bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return Err(Box::new(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                "request body exceeds the maximum size",
            )))
        }
    };
    let payload: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("request body is not valid JSON: {e}"),
            )))
        }
    };
    let model = match payload.get("model").and_then(Value::as_str) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => {
            return Err(Box::new(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "missing required field `model`",
            )))
        }
    };
    Ok((payload, model))
}

async fn chat_completions(State(state): State<LlmRouterState>, req: Request) -> Response {
    // Read the authenticated principal (set by the bearer layer) before the
    // body is consumed. `None` only in auth-disabled dev mode.
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();

    let (payload, model) = match read_llm_body(req).await {
        Ok(parts) => parts,
        Err(resp) => return *resp,
    };
    let args = payload.as_object().cloned().unwrap_or_default();
    let request = InvocationRequest::new(LLM_SERVER, model).with_arguments(Some(args));

    match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::UnaryValue(body)) => (StatusCode::OK, Json(body)).into_response(),
        // An MCP CallToolResult (or MRTR pause — this surface declares no
        // input capabilities) on the LLM route is a wiring bug.
        Ok(InvocationResponse::Unary(_)) | Ok(InvocationResponse::InputRequired(_)) => {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "unexpected tool result on the inference route",
            )
        }
        // Streaming: re-emit each canonical chunk as an OpenAI-shaped SSE
        // frame. A terminal chunk is the `[DONE]` sentinel; a mid-stream error
        // surfaces as an `event: error` frame (the gates already passed before
        // the stream was returned, so this only carries upstream/transport
        // failures). The pipeline finalizes the outcome audit at stream close.
        Ok(InvocationResponse::Stream(stream)) => sse_from_invocation_stream(stream),
        Err(e) => invocation_error_response(e),
    }
}

/// Render an [`InvocationStream`] as an SSE response, transport-aware via each
/// chunk's `event_name`:
/// - `None` (the `/v1/chat/completions` transport): unnamed `data:` frames, and
///   the terminal frame is the OpenAI `[DONE]` sentinel.
/// - `Some(name)` (the `/v1/responses` transport): a *named* event
///   (`event: <name>\ndata: {…}`), including the terminal `response.completed` /
///   `response.incomplete` frame — that transport has no `[DONE]` sentinel.
///
/// A mid-stream error surfaces as an `event: error` frame either way (the gates
/// already passed before the stream was returned, so it only carries
/// upstream/transport failures); the pipeline finalizes the audit at close.
fn sse_from_invocation_stream(stream: InvocationStream) -> Response {
    let sse = stream.map(|item| {
        let event = match item {
            Ok(chunk) => match chunk.event_name {
                Some(name) => Event::default().event(name).data(chunk.event.to_string()),
                None if chunk.terminal => Event::default().data("[DONE]"),
                None => Event::default().data(chunk.event.to_string()),
            },
            Err(e) => Event::default().event("error").data(
                json!({ "error": { "message": e.to_string(), "type": "api_error" } }).to_string(),
            ),
        };
        Ok::<Event, std::convert::Infallible>(event)
    });
    Sse::new(sse).into_response()
}

/// `POST /v1/responses` — the OpenAI Responses API client surface. Dispatches
/// through the SAME governed `InvocationService` as `/v1/chat/completions`
/// (authorize / quota / budget / audit all apply — invariant I1); the call is
/// marked a Responses-surface call so the inference fast-path parses the Responses
/// request shape and renders the Responses egress (`provider → CanonicalResponse →
/// responses`). `stream: true` is served as a named-event Responses SSE stream for
/// every upstream: an OpenAI-Responses upstream's frames are relayed 1:1 (they
/// already speak the Responses event protocol), and for the other providers the
/// normalized chat-chunk stream is lifted into Responses streaming events.
async fn responses(State(state): State<LlmRouterState>, req: Request) -> Response {
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let (payload, model) = match read_llm_body(req).await {
        Ok(parts) => parts,
        Err(resp) => return *resp,
    };
    let args = payload.as_object().cloned().unwrap_or_default();
    let request = InvocationRequest::new(LLM_SERVER, model)
        .with_arguments(Some(args))
        .with_responses_surface(true);

    match state.invocation.invoke(principal.as_ref(), request).await {
        // The body is already Responses-shaped — dispatch rendered the canonical
        // response to the Responses surface.
        Ok(InvocationResponse::UnaryValue(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(InvocationResponse::Unary(_)) | Ok(InvocationResponse::InputRequired(_)) => {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "unexpected tool result on the inference route",
            )
        }
        // Named-event Responses SSE (the chunks carry their `event_name`).
        Ok(InvocationResponse::Stream(stream)) => sse_from_invocation_stream(stream),
        Err(e) => invocation_error_response(e),
    }
}

/// `POST /v1/embeddings` — the OpenAI embeddings API client surface. Dispatches
/// through the SAME governed `InvocationService` as the chat routes (authorize /
/// quota / budget / audit all apply — invariant I1); the call is marked an
/// embeddings-surface call so the inference fast-path parses the embeddings
/// request and dispatches it through the embeddings path. Embeddings are unary
/// only — there is no streaming form — so the response is always a single JSON
/// body (the provider's OpenAI-shaped embeddings response, returned verbatim). A
/// chat model addressed here (or an embeddings model on a chat route) is rejected
/// by the pipeline as a clean `400` surface/operation mismatch.
async fn embeddings(State(state): State<LlmRouterState>, req: Request) -> Response {
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let (payload, model) = match read_llm_body(req).await {
        Ok(parts) => parts,
        Err(resp) => return *resp,
    };
    let args = payload.as_object().cloned().unwrap_or_default();
    let request = InvocationRequest::new(LLM_SERVER, model)
        .with_arguments(Some(args))
        .with_embeddings_surface(true);

    match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::UnaryValue(body)) => (StatusCode::OK, Json(body)).into_response(),
        // `invoke_embeddings` only ever returns a unary value or an error; an MCP
        // tool result or a stream on the embeddings route is a wiring bug.
        Ok(InvocationResponse::Unary(_))
        | Ok(InvocationResponse::Stream(_))
        | Ok(InvocationResponse::InputRequired(_)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "unexpected non-unary result on the embeddings route",
        ),
        Err(e) => invocation_error_response(e),
    }
}

/// Map a pipeline error to an HTTP status + OpenAI-style error envelope.
fn invocation_error_response(e: InvocationError) -> Response {
    if let Some(response) = embedding_errors::response(&e) {
        return response;
    }
    match &e {
        InvocationError::Upstream(error)
            if error
                .data
                .as_ref()
                .and_then(|d| d.get("image_http_status"))
                .is_some() =>
        {
            let status = error
                .data
                .as_ref()
                .and_then(|d| d.get("image_http_status"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(502);
            let (status, kind) = match status {
                429 => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_error"),
                400..=499 if !matches!(status, 401 | 403) => (
                    StatusCode::from_u16(status as u16).expect("valid HTTP client error"),
                    "invalid_request_error",
                ),
                _ => (StatusCode::BAD_GATEWAY, "upstream_error"),
            };
            error_response(status, kind, &error.message)
        }
        // A step-up is the one error carrying a machine-actionable remedy —
        // the exact scope to re-authorize with. Surface it the RFC 6750 way
        // (a `WWW-Authenticate: Bearer error="insufficient_scope"` challenge
        // naming the scope) so a /v1 client can follow the step-up
        // programmatically, parity with the MCP adapter's insufficient_scope
        // data — instead of scraping the human-readable message.
        InvocationError::StepUpRequired {
            required_scope,
            reason,
        } => step_up_response(required_scope, reason),
        InvocationError::InvalidArguments(_)
        | InvocationError::InputSchemaViolation { .. }
        | InvocationError::ReadOnlyRequired { .. }
        | InvocationError::ReadOnlyOperationRequired { .. } => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &e.to_string(),
        ),
        InvocationError::Forbidden { .. }
        | InvocationError::ApprovalRequired { .. }
        | InvocationError::ProfileServerNotAllowed { .. }
        | InvocationError::ProfileToolNotAllowed { .. }
        | InvocationError::ResponseInspectionBlocked { .. } => {
            error_response(StatusCode::FORBIDDEN, "permission_error", &e.to_string())
        }
        InvocationError::RateLimited { .. } => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            &e.to_string(),
        ),
        // Budget exhaustion is the OpenAI-idiomatic 429 `insufficient_quota`
        // (distinct from a per-second rate limit): the principal has spent its
        // token/cost allowance for the window.
        InvocationError::BudgetExceeded { .. } => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "insufficient_quota",
            &e.to_string(),
        ),
        InvocationError::AuditUnavailable(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "api_error", &e.to_string())
        }
        InvocationError::Upstream(_)
        | InvocationError::OutputSchemaViolation { .. }
        | InvocationError::ToolSchemaInvalid { .. }
        | InvocationError::ResponseMaterializationLimit { .. }
        | InvocationError::InputSchemaInvalid { .. } => {
            error_response(StatusCode::BAD_GATEWAY, "api_error", &e.to_string())
        }
    }
}

/// A `403 insufficient_scope` for a step-up: an RFC 6750 `WWW-Authenticate`
/// Bearer challenge naming the scope (the standard machine-readable channel),
/// plus the OpenAI error body extended with `code` + `required_scope` for SDK
/// callers that read the body rather than the header. `required_scope` is a
/// controlled scope token (e.g. `mcp:invoke:high`), so it is safe to embed in
/// the header value verbatim — no header-injection surface.
fn step_up_response(required_scope: &str, reason: &str) -> Response {
    let challenge = format!("Bearer error=\"insufficient_scope\", scope=\"{required_scope}\"");
    let mut resp = (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "message": reason,
                "type": "permission_error",
                "code": "insufficient_scope",
                "required_scope": required_scope,
            }
        })),
    )
        .into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&challenge) {
        resp.headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    resp
}

fn error_response(status: StatusCode, err_type: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message, "type": err_type } })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_ua_fallback_version_matches_the_discovery_default() {
        // waygate-llm-providers (the /responses fingerprint fallback) and
        // waygate-llm-discovery (the /models listing fallback) deliberately do
        // not depend on each other, so each compiles its own default Codex CLI
        // version. This server — the composition root that depends on both —
        // pins them equal, so the two surfaces can never silently present
        // different client identities when neither a pin nor a tracked version
        // applies. Bump both together.
        assert_eq!(
            waygate_llm_providers::CODEX_FP_DEFAULT_VERSION,
            waygate_llm_discovery::CODEX_DEFAULT_CLIENT_VERSION,
        );
    }

    #[test]
    fn egress_proxy_is_optional_and_validated() {
        // Absent / blank ⇒ unchanged (no proxy configured).
        assert!(apply_egress_proxy(http_client::builder(Profile::NoTotalTimeout), None).is_ok());
        assert!(
            apply_egress_proxy(http_client::builder(Profile::NoTotalTimeout), Some("   ")).is_ok()
        );
        // A well-formed http/https proxy URL is accepted (http/https proxying
        // needs no extra reqwest feature).
        assert!(apply_egress_proxy(
            http_client::builder(Profile::NoTotalTimeout),
            Some("http://127.0.0.1:8888")
        )
        .is_ok());
        assert!(apply_egress_proxy(
            http_client::builder(Profile::NoTotalTimeout),
            Some("https://proxy.internal:8443")
        )
        .is_ok());
        // SOCKS is rejected at boot (not silently accepted then broken at request
        // time): the workspace builds reqwest without its `socks` feature.
        assert!(apply_egress_proxy(
            http_client::builder(Profile::NoTotalTimeout),
            Some("socks5://10.0.0.2:1080")
        )
        .is_err());
        // A malformed URL is a hard error (fail boot loudly, never silently drop
        // the operator's egress intent).
        assert!(apply_egress_proxy(
            http_client::builder(Profile::NoTotalTimeout),
            Some("http://a b c")
        )
        .is_err());
    }

    #[test]
    fn parses_a_model_catalog_and_builds_deps() {
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[
              {"alias":"gpt-x","provider":"openrouter","credential_label":"MAIN",
               "base_url":"https://openrouter.ai/api/v1","upstream_model":"openai/gpt-x"}
            ]"#,
        )
        .unwrap();
        let deps = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let (_dispatcher, resolver) = deps;
        let m = resolver.resolve(LLM_SERVER, "gpt-x").expect("resolves");
        assert_eq!(m.route.upstream_model, "openai/gpt-x");
        assert_eq!(m.route.provider, LlmProvider::OpenRouter);
        // Default risk is Low (no step-up scope required).
        assert_eq!(m.risk, ModelRisk::Low);
        // Unconfigured model is not an LLM target.
        assert!(resolver.resolve(LLM_SERVER, "absent").is_none());
    }

    #[test]
    fn model_shorthand_resolves_provider_and_upstream_keeping_alias() {
        // The `model` shorthand carries provider + upstream in ONE value while the
        // client-facing `alias` stays independent — the no-re-index path for an
        // env-substituted embedding model (`"model":"${EMBEDDING_MODEL}"`). After
        // normalize the split fields are populated and the shorthand consumed; the
        // model both seeds the catalog and routes end-to-end under the unchanged
        // alias.
        let mut defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"qwen3-embedding-8b",
                 "model":"openrouter:qwen/qwen3-embedding-8b",
                 "credential_label":"MAIN",
                 "base_url":"https://openrouter.ai/api/v1","kind":"embeddings"}]"#,
        )
        .unwrap();
        normalize_model_defs(&mut defs).expect("normalizes");
        assert_eq!(defs[0].provider, "openrouter");
        assert_eq!(
            defs[0].upstream_model.as_deref(),
            Some("qwen/qwen3-embedding-8b")
        );
        assert!(defs[0].model.is_none(), "shorthand is consumed");

        // Seeder (catalog upsert) path sees the split form.
        let row = model_def_to_upsert(&defs[0]);
        assert_eq!(row.provider, "openrouter");
        assert_eq!(row.upstream_model, "qwen/qwen3-embedding-8b");
        assert_eq!(row.upstream_api, "embeddings");

        // Resolver path: OpenRouter upstream + embeddings operation, reachable by
        // the unchanged client-facing alias.
        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver
            .resolve(LLM_SERVER, "qwen3-embedding-8b")
            .expect("resolves under the alias");
        assert_eq!(m.route.provider, LlmProvider::OpenRouter);
        assert_eq!(m.route.upstream_model, "qwen/qwen3-embedding-8b");
        assert_eq!(m.operation, LlmOperation::Embeddings);
    }

    #[test]
    fn model_shorthand_splits_on_first_colon_only() {
        // Provider is everything before the FIRST colon; the upstream id keeps any
        // remaining colons verbatim (defensive — real ids use `/`, not `:`).
        let mut defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"a","model":"openai:vendor:weird/model",
                 "credential_label":"MAIN","base_url":"https://x"}]"#,
        )
        .unwrap();
        normalize_model_defs(&mut defs).expect("normalizes");
        assert_eq!(defs[0].provider, "openai");
        assert_eq!(
            defs[0].upstream_model.as_deref(),
            Some("vendor:weird/model")
        );
    }

    #[test]
    fn model_shorthand_conflicts_with_explicit_provider_or_upstream() {
        // Setting the shorthand AND a split field is ambiguous → rejected.
        let mut with_provider: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"a","provider":"openrouter","model":"openrouter:m",
                 "credential_label":"MAIN","base_url":"https://x"}]"#,
        )
        .unwrap();
        assert!(normalize_model_defs(&mut with_provider).is_err());

        let mut with_upstream: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"a","upstream_model":"m","model":"openrouter:m",
                 "credential_label":"MAIN","base_url":"https://x"}]"#,
        )
        .unwrap();
        assert!(normalize_model_defs(&mut with_upstream).is_err());
    }

    #[test]
    fn model_shorthand_requires_both_halves() {
        // No colon, empty provider, or empty upstream are all rejected.
        for bad in ["openrouter", "openrouter:", ":model", ":"] {
            let json = format!(
                r#"[{{"alias":"a","model":"{bad}","credential_label":"MAIN","base_url":"https://x"}}]"#
            );
            let mut defs: Vec<ModelDef> = serde_json::from_str(&json).unwrap();
            assert!(
                normalize_model_defs(&mut defs).is_err(),
                "expected `model`=\"{bad}\" to be rejected"
            );
        }
    }

    #[test]
    fn missing_provider_without_shorthand_is_rejected() {
        // Relaxing `provider` to a serde default must NOT let a provider-less pin
        // through: normalize rejects an entry with neither `provider` nor the
        // `model` shorthand.
        let mut defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"a","credential_label":"MAIN","base_url":"https://x"}]"#,
        )
        .unwrap();
        assert!(normalize_model_defs(&mut defs).is_err());
    }

    #[test]
    fn anthropic_model_without_path_defaults_to_messages_and_protocol() {
        // An Anthropic entry that omits `path` must route to the Messages
        // endpoint with the Anthropic protocol — NOT the OpenAI-chat default,
        // which would send the Messages body/auth to /chat/completions.
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"claude","provider":"anthropic","credential_label":"MAIN",
                 "base_url":"https://api.anthropic.com/v1"}]"#,
        )
        .unwrap();
        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver.resolve(LLM_SERVER, "claude").expect("resolves");
        assert_eq!(m.route.path, "messages");
        assert_eq!(m.route.protocol, UpstreamProtocol::AnthropicMessages);

        // An OpenAI-compatible entry without `path` still defaults to chat/completions.
        assert_eq!(default_path_for(LlmProvider::OpenAi), "chat/completions");
        assert_eq!(default_path_for(LlmProvider::Anthropic), "messages");
    }

    #[test]
    fn responses_surface_selects_responses_protocol_path_and_upstream_api() {
        // `surface: responses` routes an OpenAI model to the Responses API:
        // UpstreamProtocol::OpenAiResponses + the `responses` path, and the
        // catalog row records upstream_api = responses (the CHECK allows it).
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"gpt-resp","provider":"openai","credential_label":"MAIN",
                 "base_url":"https://api.openai.com/v1","surface":"responses"}]"#,
        )
        .unwrap();
        // Catalog upsert reflects the surface.
        let row = model_def_to_upsert(&defs[0]);
        assert_eq!(row.upstream_api, "responses");
        assert_eq!(row.path, "responses");

        // Resolved route selects the Responses protocol + path.
        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver.resolve(LLM_SERVER, "gpt-resp").expect("resolves");
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiResponses);
        assert_eq!(m.route.path, "responses");
        // A plain `responses` surface is NOT the ChatGPT backend.
        assert!(!m.route.openai_chatgpt);
    }

    #[test]
    fn codex_surface_selects_responses_protocol_with_chatgpt_backend_auth() {
        // `surface: codex` is the ChatGPT backend: it reuses the Responses
        // protocol + `responses` path (Responses-shaped body) but flips
        // `openai_chatgpt` so dispatch sends the Codex auth fingerprint. The
        // catalog row still records upstream_api = responses (the CHECK has no
        // separate codex value).
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"gpt-5-codex","provider":"openai","credential_label":"PRIMARY",
                 "base_url":"https://chatgpt.com/backend-api/codex","surface":"codex"}]"#,
        )
        .unwrap();
        let row = model_def_to_upsert(&defs[0]);
        assert_eq!(row.upstream_api, "responses");
        assert_eq!(row.path, "responses");

        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver
            .resolve(LLM_SERVER, "gpt-5-codex")
            .expect("resolves");
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiResponses);
        assert_eq!(m.route.path, "responses");
        assert!(
            m.route.openai_chatgpt,
            "surface: codex must select the ChatGPT-backend auth path"
        );
    }

    #[test]
    fn credential_labels_build_an_ordered_failover_pool() {
        // `credential_labels` becomes the ordered failover pool: the primary
        // (credential_label) stays first, a duplicate of it is dropped, and the
        // rest become fallback routes sharing the primary's endpoint/protocol.
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"m","provider":"openrouter","credential_label":"MAIN",
                 "base_url":"https://x","upstream_model":"openrouter/m",
                 "credential_labels":["MAIN","BACKUP","FAMILY"]}]"#,
        )
        .unwrap();
        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver.resolve(LLM_SERVER, "m").expect("resolves");
        assert_eq!(m.route.credential_label, "MAIN");
        // Duplicate MAIN dropped; BACKUP then FAMILY are the ordered fallbacks.
        let labels: Vec<&str> = m
            .fallbacks
            .iter()
            .map(|r| r.credential_label.as_str())
            .collect();
        assert_eq!(labels, vec!["BACKUP", "FAMILY"]);
        // Fallbacks share the primary's endpoint / protocol / upstream model.
        assert!(m.fallbacks.iter().all(|r| r.base_url == m.route.base_url
            && r.protocol == m.route.protocol
            && r.upstream_model == m.route.upstream_model));
    }

    #[test]
    fn no_credential_labels_yields_no_fallbacks() {
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"m","provider":"openrouter","credential_label":"MAIN","base_url":"https://x"}]"#,
        )
        .unwrap();
        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver.resolve(LLM_SERVER, "m").expect("resolves");
        assert!(m.fallbacks.is_empty());
    }

    #[test]
    fn fallback_groups_build_cross_provider_failover() {
        // A primary OpenAI-chat group (pooled PRIMARY+SECONDARY) plus an
        // Anthropic fallback group. The resolved route is the primary; fallbacks
        // are the primary pool's extras THEN the Anthropic group, each carrying
        // its own provider / endpoint / protocol / path.
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{
                "alias":"smart","provider":"openai","credential_label":"PRIMARY",
                "base_url":"https://api.openai.com/v1",
                "credential_labels":["PRIMARY","SECONDARY"],
                "fallbacks":[
                    {"provider":"anthropic","credential_label":"MAIN","base_url":"https://api.anthropic.com/v1"}
                ]
            }]"#,
        )
        .unwrap();
        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver.resolve(LLM_SERVER, "smart").expect("resolves");

        // Primary: OpenAI chat, PRIMARY label, alias as upstream model.
        assert_eq!(m.route.provider, LlmProvider::OpenAi);
        assert_eq!(m.route.credential_label, "PRIMARY");
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiChat);
        assert_eq!(m.route.upstream_model, "smart");

        // Fallbacks in order: OpenAI SECONDARY (same group), then Anthropic MAIN
        // (its own provider / protocol / path / endpoint).
        assert_eq!(m.fallbacks.len(), 2);
        assert_eq!(m.fallbacks[0].provider, LlmProvider::OpenAi);
        assert_eq!(m.fallbacks[0].credential_label, "SECONDARY");
        assert_eq!(m.fallbacks[0].protocol, UpstreamProtocol::OpenAiChat);
        assert_eq!(m.fallbacks[1].provider, LlmProvider::Anthropic);
        assert_eq!(m.fallbacks[1].credential_label, "MAIN");
        assert_eq!(m.fallbacks[1].protocol, UpstreamProtocol::AnthropicMessages);
        assert_eq!(m.fallbacks[1].path, "messages");
        assert_eq!(m.fallbacks[1].base_url, "https://api.anthropic.com/v1");
        assert_eq!(m.fallbacks[1].upstream_model, "smart");
    }

    #[test]
    fn empty_pins_still_build_deps_for_discovery_only() {
        // A discovery-only deployment has no env pins: build_from_defs must still
        // produce the dispatcher + resolver (so the refresher can populate it and
        // /v1 can route), with an empty resolver until discovery runs. The
        // "no LLM path at all" decision lives in build_from_env, not here.
        let (_dispatcher, resolver) = build_from_defs(vec![], None)
            .unwrap()
            .expect("deps are built even with no pins");
        assert!(
            resolver.resolve(LLM_SERVER, "anything").is_none(),
            "the resolver is empty until discovery fills it"
        );
    }

    #[test]
    fn model_def_maps_to_a_catalog_upsert() {
        // Provider is normalized to lowercase (the llm_models CHECK vocabulary),
        // risk defaults to low, upstream_api is chat_completions, and costing
        // is left unset (operators set it in the DB).
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"gpt-x","provider":"OpenRouter","credential_label":"MAIN",
                 "base_url":"https://x","upstream_model":"openai/gpt-x"}]"#,
        )
        .unwrap();
        let row = model_def_to_upsert(&defs[0]);
        assert_eq!(row.alias, "gpt-x");
        assert_eq!(row.provider, "openrouter");
        assert_eq!(row.credential_label, "MAIN");
        assert_eq!(row.upstream_model, "openai/gpt-x");
        assert_eq!(row.risk, "low");
        assert_eq!(row.upstream_api, "chat_completions");
        assert!(row.enabled);
        assert!(row.description.is_none());
    }

    #[test]
    fn upstream_api_records_the_real_provider_wire_api() {
        // #395: the catalog records the REAL upstream wire API, not a coarse
        // chat_completions placeholder. Anthropic speaks Messages, Gemini speaks
        // generateContent, OpenRouter/OpenAI-chat speak chat/completions, and
        // surface: responses|codex both speak the OpenAI Responses shape.
        let cases = [
            (
                r#"{"alias":"a","provider":"anthropic","credential_label":"L","base_url":"https://a"}"#,
                "messages",
            ),
            (
                r#"{"alias":"g","provider":"google","credential_label":"L","base_url":"https://g"}"#,
                "generate_content",
            ),
            (
                r#"{"alias":"o","provider":"openrouter","credential_label":"L","base_url":"https://o"}"#,
                "chat_completions",
            ),
            (
                r#"{"alias":"r","provider":"openai","credential_label":"L","base_url":"https://r","surface":"responses"}"#,
                "responses",
            ),
            (
                r#"{"alias":"c","provider":"openai","credential_label":"L","base_url":"https://c","surface":"codex"}"#,
                "responses",
            ),
        ];
        for (json, expected) in cases {
            let defs: Vec<ModelDef> = serde_json::from_str(&format!("[{json}]")).unwrap();
            assert_eq!(
                model_def_to_upsert(&defs[0]).upstream_api,
                expected,
                "upstream_api for {json}"
            );
        }
    }

    #[test]
    fn model_def_upstream_defaults_to_alias_and_risk_parses() {
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"m","provider":"openai","credential_label":"L",
                 "base_url":"https://y","risk":"low"}]"#,
        )
        .unwrap();
        let row = model_def_to_upsert(&defs[0]);
        // upstream_model omitted ⇒ defaults to the alias.
        assert_eq!(row.upstream_model, "m");
        assert_eq!(row.risk, "low");
    }

    #[tokio::test]
    async fn seed_models_upserts_and_is_idempotent() {
        // Exercises the seeder's transaction loop against a real Postgres.
        // Skips cleanly when AUDIT_DATABASE_URL is unset (CI provides it).
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping seed_models pg test: AUDIT_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect to AUDIT_DATABASE_URL");
        waygate_storage::PgAuditSink::migrate(&pool)
            .await
            .expect("apply migrations");

        let alias = format!("seed-test-{}", uuid::Uuid::now_v7());
        let row = waygate_storage::LlmModelUpsert {
            tenant_id: "default".into(),
            alias: alias.clone(),
            provider: "openrouter".into(),
            credential_label: "MAIN".into(),
            upstream_model: "openai/x".into(),
            base_url: "https://x".into(),
            path: "chat/completions".into(),
            upstream_api: "chat_completions".into(),
            openai_chatgpt: false,
            risk: "high".into(),
            requires_approval: false,
            description: None,
            enabled: true,
        };

        // Idempotent: running twice must not error or duplicate.
        seed_models(&pool, std::slice::from_ref(&row))
            .await
            .expect("first seed");
        seed_models(&pool, std::slice::from_ref(&row))
            .await
            .expect("second seed (idempotent)");

        let got = waygate_storage::get_llm_model(&pool, "default", &alias)
            .await
            .expect("get")
            .expect("seeded row present");
        assert_eq!(got.provider, "openrouter");
        assert_eq!(got.upstream_model, "openai/x");

        sqlx::query("DELETE FROM llm_models WHERE tenant_id = 'default' AND alias = $1")
            .bind(&alias)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    #[tokio::test]
    async fn step_up_error_carries_an_insufficient_scope_challenge() {
        // The generic StepUpRequired -> 403 insufficient_scope mapping: a /v1
        // client learns the required scope from the RFC 6750 WWW-Authenticate
        // challenge + the OpenAI error body's `code` + `required_scope`. (Models
        // are not step-up-gated today, but the mapper still handles the shared
        // StepUpRequired variant, so exercise it with a real scope.)
        let resp = invocation_error_response(InvocationError::StepUpRequired {
            required_scope: "mcp:invoke:high".into(),
            reason: "denied without `mcp:invoke:high`".into(),
        });
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let www = resp
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .expect("a step-up carries a WWW-Authenticate challenge")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(www.contains("error=\"insufficient_scope\""), "{www}");
        assert!(www.contains("scope=\"mcp:invoke:high\""), "{www}");

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], "insufficient_scope");
        assert_eq!(body["error"]["required_scope"], "mcp:invoke:high");
    }

    #[tokio::test]
    async fn budget_exhausted_maps_to_429_insufficient_quota() {
        // A budget exhaustion is the OpenAI-idiomatic 429 `insufficient_quota`
        // (not a per-second rate limit).
        let resp = invocation_error_response(InvocationError::BudgetExceeded {
            dimension: "tokens".into(),
            reason: "1000 tokens used >= 500 limit over the last 86400s".into(),
        });
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["type"], "insufficient_quota");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("budget exhausted"),
            "message names the budget exhaustion"
        );
    }

    #[tokio::test]
    async fn invalid_tool_schema_maps_to_sanitized_gateway_error() {
        let resp = invocation_error_response(InvocationError::ToolSchemaInvalid {
            tool: "example-messages.send".into(),
        });
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["type"], "api_error");
        assert_eq!(
            body["error"]["message"],
            "approved output schema for `example-messages.send` is invalid"
        );
    }

    #[test]
    fn unknown_provider_is_rejected() {
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"m","provider":"madeup","credential_label":"X","base_url":"http://x"}]"#,
        )
        .unwrap();
        assert!(build_from_defs(defs, None).is_err());
    }

    #[test]
    fn risk_parsing_omitted_low_explicit_unmapped_high() {
        // OMITTED ⇒ low (the deliberate default).
        assert_eq!(parse_risk(None), ModelRisk::Low);
        // Explicit recognized values honored verbatim (case-insensitive).
        assert_eq!(parse_risk(Some("low")), ModelRisk::Low);
        assert_eq!(parse_risk(Some("Medium")), ModelRisk::Medium);
        assert_eq!(parse_risk(Some("HIGH")), ModelRisk::High);
        // Explicit but UNMAPPED values fail SAFE to High, never silently Low:
        // schema-accepted `critical` (no Critical tier) and elevated-risk typos.
        assert_eq!(parse_risk(Some("critical")), ModelRisk::High);
        assert_eq!(parse_risk(Some("nonsense")), ModelRisk::High);
    }

    /// A catalog row with the given alias/provider and a fixed timestamp, so the
    /// `/v1/models` projection tests can assert the `created` field exactly.
    fn catalog_row(alias: &str, provider: &str) -> waygate_storage::LlmModelRow {
        let ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        waygate_storage::LlmModelRow {
            tenant_id: "default".into(),
            alias: alias.into(),
            provider: provider.into(),
            credential_label: "MAIN".into(),
            upstream_model: alias.into(),
            base_url: "https://x".into(),
            path: "chat/completions".into(),
            upstream_api: "chat_completions".into(),
            openai_chatgpt: false,
            risk: "high".into(),
            requires_approval: false,
            description: None,
            input_cost_per_mtok: None,
            output_cost_per_mtok: None,
            cached_read_cost_per_mtok: None,
            cache_write_cost_per_mtok: None,
            currency: "USD".into(),
            enabled: true,
            created_at: ts,
            updated_at: ts,
        }
    }

    /// A catalog row for an **embeddings** model (`upstream_api`/`path` =
    /// `embeddings`), so a test can exercise the modality / `?type=` distinction.
    fn embeddings_row(alias: &str, provider: &str) -> waygate_storage::LlmModelRow {
        let mut r = catalog_row(alias, provider);
        r.upstream_api = "embeddings".into();
        r.path = "embeddings".into();
        r
    }

    /// In-memory catalog fake: records the tenant it was queried with (so a test
    /// can assert `/v1/models` is tenant-scoped) and can be made to error.
    struct ModelCatalogFake {
        rows: Vec<waygate_storage::LlmModelRow>,
        fail: bool,
        seen_tenant: std::sync::Mutex<Option<String>>,
    }

    #[async_trait::async_trait]
    impl waygate_storage::LlmModelCatalog for ModelCatalogFake {
        async fn list_models(
            &self,
            tenant_id: &str,
        ) -> Result<Vec<waygate_storage::LlmModelRow>, sqlx::Error> {
            *self.seen_tenant.lock().unwrap() = Some(tenant_id.to_owned());
            if self.fail {
                return Err(sqlx::Error::PoolClosed);
            }
            Ok(self.rows.clone())
        }
    }

    /// A resolver that resolves exactly `aliases` under `LLM_SERVER` (each with a
    /// throwaway route), so the `/v1/models` filter — "advertise only models the
    /// resolver can dispatch" — can be exercised against a known resolvable set.
    fn test_resolver(aliases: &[&str]) -> StaticModelResolver {
        let mut r = StaticModelResolver::new();
        for a in aliases {
            r = r.with_model(
                LLM_SERVER,
                *a,
                ResolvedModel {
                    route: ResolvedRoute {
                        provider: LlmProvider::OpenRouter,
                        credential_label: "MAIN".into(),
                        base_url: "https://x".into(),
                        path: "chat/completions".into(),
                        upstream_model: (*a).into(),
                        protocol: UpstreamProtocol::OpenAiChat,
                        embeddings_no_auth: false,
                        openai_chatgpt: false,
                    },
                    operation: LlmOperation::Chat,
                    fallbacks: vec![],
                    risk: ModelRisk::High,
                    ttfb: None,
                    cache_ttl: None,
                },
            );
        }
        r
    }

    #[test]
    fn models_list_json_projects_openai_shape() {
        // The /v1/models body is a translation contract: an OpenAI client reads
        // `object: "list"` and each entry's `id`/`object`/`owned_by`/`created`,
        // plus the `modality` extension that distinguishes embeddings from chat.
        let body = models_list_json(vec![
            catalog_row("gpt-x", "openrouter"),
            catalog_row("claude", "anthropic"),
            embeddings_row("embed-3", "openrouter"),
        ]);
        assert_eq!(body["object"], "list");
        let data = body["data"].as_array().expect("data is an array");
        assert_eq!(data.len(), 3);
        assert_eq!(data[0]["id"], "gpt-x");
        assert_eq!(data[0]["object"], "model");
        assert_eq!(data[0]["owned_by"], "openrouter");
        assert_eq!(data[0]["created"], 1_700_000_000_i64);
        assert_eq!(data[1]["id"], "claude");
        assert_eq!(data[1]["owned_by"], "anthropic");
        // modality discriminates the operation: chat-family vs embeddings.
        assert_eq!(data[0]["modality"], "text->text");
        assert_eq!(data[1]["modality"], "text->text");
        assert_eq!(data[2]["id"], "embed-3");
        assert_eq!(data[2]["modality"], "text->embedding");
    }

    #[test]
    fn model_modality_maps_upstream_api() {
        assert_eq!(model_modality("embeddings"), "text->embedding");
        assert_eq!(model_modality("Embeddings"), "text->embedding");
        assert_eq!(model_modality("chat_completions"), "text->text");
        assert_eq!(model_modality("responses"), "text->text");
        assert_eq!(model_modality("messages"), "text->text");
    }

    #[test]
    fn model_kind_filter_parses_query() {
        use ModelKindFilter::*;
        assert_eq!(
            ModelKindFilter::from_query("type=embeddings"),
            Some(Embeddings)
        );
        assert_eq!(
            ModelKindFilter::from_query("type=embedding"),
            Some(Embeddings)
        );
        assert_eq!(ModelKindFilter::from_query("type=CHAT"), Some(Chat));
        assert_eq!(
            ModelKindFilter::from_query("foo=1&type=embeddings"),
            Some(Embeddings)
        );
        // Absent / unrecognized ⇒ no filter (lenient).
        assert_eq!(ModelKindFilter::from_query("foo=bar"), None);
        assert_eq!(ModelKindFilter::from_query(""), None);
        assert_eq!(ModelKindFilter::from_query("type=audio"), None);
    }

    #[tokio::test]
    async fn models_response_filters_by_type() {
        // A mixed catalog: one chat model, one embeddings model, both resolvable.
        let store: waygate_storage::SharedLlmModelCatalog = Arc::new(ModelCatalogFake {
            rows: vec![
                catalog_row("gpt-x", "openrouter"),
                embeddings_row("embed-y", "openrouter"),
            ],
            fail: false,
            seen_tenant: std::sync::Mutex::new(None),
        });
        let resolver = test_resolver(&["gpt-x", "embed-y"]);
        let ids = |resp: Response| async {
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            body["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["id"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };

        // `?type=embeddings` ⇒ only the embeddings model.
        let resp = models_response(
            Some(&store),
            "default",
            &resolver,
            Some(ModelKindFilter::Embeddings),
        )
        .await;
        assert_eq!(ids(resp).await, vec!["embed-y"]);

        // `?type=chat` ⇒ only the chat model.
        let resp = models_response(
            Some(&store),
            "default",
            &resolver,
            Some(ModelKindFilter::Chat),
        )
        .await;
        assert_eq!(ids(resp).await, vec!["gpt-x"]);

        // No filter ⇒ both (order preserved).
        let resp = models_response(Some(&store), "default", &resolver, None).await;
        assert_eq!(ids(resp).await, vec!["gpt-x", "embed-y"]);
    }

    #[tokio::test]
    async fn models_response_lists_tenant_rows() {
        let fake = Arc::new(ModelCatalogFake {
            rows: vec![catalog_row("gpt-x", "openrouter")],
            fail: false,
            seen_tenant: std::sync::Mutex::new(None),
        });
        let store: waygate_storage::SharedLlmModelCatalog = fake.clone();
        let resolver = test_resolver(&["gpt-x"]);
        let resp = models_response(Some(&store), "acme", &resolver, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Listing is tenant-scoped: the store is queried with the caller's tenant.
        assert_eq!(fake.seen_tenant.lock().unwrap().as_deref(), Some("acme"));
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["object"], "list");
        assert_eq!(body["data"][0]["id"], "gpt-x");
    }

    #[tokio::test]
    async fn models_response_empty_when_no_store() {
        // DB-less dev mode: no catalog store ⇒ an empty (but well-formed) list,
        // not an error.
        let resp = models_response(None, "default", &test_resolver(&[]), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["object"], "list");
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn models_response_store_error_maps_to_503() {
        let store: waygate_storage::SharedLlmModelCatalog = Arc::new(ModelCatalogFake {
            rows: vec![],
            fail: true,
            seen_tenant: std::sync::Mutex::new(None),
        });
        let resp = models_response(Some(&store), "default", &test_resolver(&[]), None).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["type"], "api_error");
    }

    #[tokio::test]
    async fn models_response_lists_only_resolvable_models() {
        // The catalog is upsert-seeded from env and never auto-prunes a row
        // dropped from GATEWAY_LLM_MODELS, so an enabled-but-orphaned alias can
        // linger in the DB. /v1/models must advertise only models the resolver
        // can dispatch — i.e. the ones it still knows — so it never lists an alias
        // the /v1 routes would reject as unknown.
        let store: waygate_storage::SharedLlmModelCatalog = Arc::new(ModelCatalogFake {
            rows: vec![
                catalog_row("gpt-x", "openrouter"),
                catalog_row("stale", "openrouter"),
            ],
            fail: false,
            seen_tenant: std::sync::Mutex::new(None),
        });
        // Resolver knows only "gpt-x" (e.g. "stale" was removed from env config).
        let resolver = test_resolver(&["gpt-x"]);
        let resp = models_response(Some(&store), "default", &resolver, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let ids: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            vec!["gpt-x"],
            "the orphaned `stale` alias is filtered out"
        );
    }

    #[test]
    fn resolved_from_catalog_row_maps_routing() {
        // A plain openrouter row → an OpenAI-chat single-route model.
        let m = resolved_from_catalog_row(&catalog_row("openrouter:gpt-x", "openrouter"))
            .expect("parses");
        assert_eq!(m.route.provider, LlmProvider::OpenRouter);
        assert_eq!(m.route.credential_label, "MAIN");
        assert_eq!(m.route.upstream_model, "openrouter:gpt-x");
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiChat);
        assert_eq!(m.risk, ModelRisk::High);
        assert!(m.fallbacks.is_empty(), "discovered rows carry no failover");
        assert!(
            !m.route.openai_chatgpt,
            "a plain (non-Codex) catalog row routes with a bare Bearer"
        );

        // An unparseable provider → skipped (None), not a hard error.
        let mut bad = catalog_row("x", "openrouter");
        bad.provider = "madeup".into();
        assert!(resolved_from_catalog_row(&bad).is_none());
    }

    #[test]
    fn resolved_from_catalog_row_honors_surface_and_provider() {
        // upstream_api=responses selects the Responses protocol.
        let mut resp = catalog_row("gpt-resp", "openai");
        resp.upstream_api = "responses".into();
        resp.path = "responses".into();
        let m = resolved_from_catalog_row(&resp).unwrap();
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiResponses);
        assert_eq!(m.route.path, "responses");

        // Anthropic → the Messages protocol.
        let m2 = resolved_from_catalog_row(&catalog_row("claude", "anthropic")).unwrap();
        assert_eq!(m2.route.protocol, UpstreamProtocol::AnthropicMessages);
    }

    #[test]
    fn resolved_from_catalog_row_maps_codex_chatgpt_flag() {
        // A discovered Codex row: Responses shape + the openai_chatgpt column set.
        // The column must drive ResolvedRoute.openai_chatgpt so dispatch picks the
        // Codex request fingerprint rather than a bare Bearer — the routability the
        // schema column unlocks for discovered (non-env-pin) Codex models.
        let mut codex = catalog_row("openai:gpt-5.5-codex", "openai");
        codex.upstream_api = "responses".into();
        codex.path = "responses".into();
        codex.openai_chatgpt = true;
        let m = resolved_from_catalog_row(&codex).expect("parses");
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiResponses);
        assert!(
            m.route.openai_chatgpt,
            "the openai_chatgpt column flows into the resolved route"
        );
    }

    #[test]
    fn embeddings_kind_selects_embeddings_operation_path_and_upstream_api() {
        // `kind: embeddings` makes this an embeddings model: build_from_defs
        // resolves operation = Embeddings, the `embeddings` path, and plain Bearer
        // (OpenAiChat is the inert protocol placeholder; openai_chatgpt false). The
        // catalog row records upstream_api = embeddings + path embeddings.
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"text-embedding-3-small","provider":"openai","credential_label":"MAIN",
                 "base_url":"https://api.openai.com/v1","kind":"embeddings"}]"#,
        )
        .unwrap();

        let row = model_def_to_upsert(&defs[0]);
        assert_eq!(row.upstream_api, "embeddings");
        assert_eq!(row.path, "embeddings");
        assert!(!row.openai_chatgpt);

        let (_dispatcher, resolver) = build_from_defs(defs, None)
            .unwrap()
            .expect("models configured");
        let m = resolver
            .resolve(LLM_SERVER, "text-embedding-3-small")
            .expect("resolves");
        assert_eq!(m.operation, LlmOperation::Embeddings);
        assert_eq!(m.route.path, "embeddings");
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiChat);
        assert!(!m.route.openai_chatgpt);
    }

    #[test]
    fn embeddings_kind_overrides_surface_and_applies_to_fallbacks() {
        // An embeddings model with a cross-provider fallback: BOTH the primary and
        // the fallback route to `embeddings` (you cannot fail an embeddings call
        // over to a chat endpoint), and the operation is Embeddings. A stray
        // `surface: codex` is ignored for an embeddings model.
        let defs: Vec<ModelDef> = serde_json::from_str(
            r#"[{"alias":"embed","provider":"openai","credential_label":"MAIN",
                 "base_url":"https://api.openai.com/v1","kind":"embeddings","surface":"codex",
                 "fallbacks":[{"provider":"openrouter","credential_label":"OR",
                               "base_url":"https://openrouter.ai/api/v1"}]}]"#,
        )
        .unwrap();
        // The catalog upsert ignores the codex surface for an embeddings model.
        assert!(!model_def_to_upsert(&defs[0]).openai_chatgpt);

        let (_dispatcher, resolver) = build_from_defs(defs, None).unwrap().expect("configured");
        let m = resolver.resolve(LLM_SERVER, "embed").expect("resolves");
        assert_eq!(m.operation, LlmOperation::Embeddings);
        assert_eq!(m.route.path, "embeddings");
        assert!(
            !m.route.openai_chatgpt,
            "kind:embeddings overrides surface:codex"
        );
        assert_eq!(m.fallbacks.len(), 1);
        assert_eq!(
            m.fallbacks[0].path, "embeddings",
            "the fallback is also an embeddings endpoint"
        );
        assert!(!m.fallbacks[0].openai_chatgpt);
    }

    #[test]
    fn resolved_from_catalog_row_maps_embeddings_operation() {
        // upstream_api=embeddings selects the embeddings operation (OpenAiChat is
        // the inert protocol placeholder on that path).
        let mut emb = catalog_row("text-embedding-3-small", "openai");
        emb.upstream_api = "embeddings".into();
        emb.path = "embeddings".into();
        let m = resolved_from_catalog_row(&emb).expect("parses");
        assert_eq!(m.operation, LlmOperation::Embeddings);
        assert_eq!(m.route.path, "embeddings");
        assert_eq!(m.route.protocol, UpstreamProtocol::OpenAiChat);
        assert!(!m.route.openai_chatgpt);
    }

    #[tokio::test]
    async fn boot_load_makes_a_discovered_row_routable() {
        // The storage→resolver seam: a discovered catalog row (written via the
        // storage path) is not routable until boot_load_discovered reads it
        // and swaps it into the resolver's discovered layer.
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping boot_load pg test: AUDIT_DATABASE_URL not set");
            return;
        };
        // Shares the `(default, openrouter)` discovered-row scope with the
        // discovery refresher's reconcile tests; serialize so their
        // `mark_discovered_absent` never soft-disables this test's row mid-run.
        let _serial = crate::llm_discovery::DISCOVERY_PG_LOCK.lock().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        waygate_storage::PgAuditSink::migrate(&pool)
            .await
            .expect("migrate");

        let alias = format!("disc-{}", uuid::Uuid::now_v7());
        let discovered = waygate_storage::LlmDiscoveredModelUpsert {
            tenant_id: waygate_core::TenantId::default().as_str().to_owned(),
            alias: alias.clone(),
            provider: "openrouter".into(),
            credential_label: "MAIN".into(),
            upstream_model: format!("vendor/{alias}"),
            base_url: "https://x".into(),
            path: "chat/completions".into(),
            upstream_api: "chat_completions".into(),
            openai_chatgpt: false,
            input_cost_per_mtok: None,
            output_cost_per_mtok: None,
            cached_read_cost_per_mtok: None,
            cache_write_cost_per_mtok: None,
            currency: None,
        };
        waygate_storage::upsert_discovered_llm_model(&pool, &discovered)
            .await
            .expect("insert discovered");

        // Empty resolver does not resolve the alias...
        let resolver = DbModelResolver::new(StaticModelResolver::new(), HashMap::new(), LLM_SERVER);
        assert!(resolver.resolve(LLM_SERVER, &alias).is_none());

        // ...until the boot load reads the catalog and swaps it in.
        boot_load_discovered(&pool, &resolver)
            .await
            .expect("boot load");
        let m = resolver
            .resolve(LLM_SERVER, &alias)
            .expect("discovered row is routable after boot-load");
        assert_eq!(m.route.upstream_model, format!("vendor/{alias}"));
        assert_eq!(m.route.provider, LlmProvider::OpenRouter);

        sqlx::query("DELETE FROM llm_models WHERE tenant_id = 'default' AND alias = $1")
            .bind(&alias)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
