//! `waygate-llm-dispatch` — orchestrates a single LLM call: resolve the
//! credential, render the provider request, invoke the provider, and produce
//! the canonical `InferenceRecord` (unary) or the SSE frame stream plus a base
//! record to finalize at stream close (streaming).
//!
//! This is the composition seam the invocation pipeline's dispatch stage
//! (stage 10) calls — *after* authorize / quota / approval have passed
//! (invariant I1, one enforcement path). It deliberately owns none of that:
//! - **No policy / quota / audit.** Those are the pipeline's stages; this crate
//!   only performs the already-authorized provider call.
//! - **No routing policy.** The caller passes an already-[`ResolvedRoute`]
//!   (plus a credential pool): mapping a model alias → route is the resolver's
//!   job ([`StaticModelResolver`], static from env today). Credential-pool
//!   failover with per-credential cooldown lives in
//!   [`dispatch_with_failover`](LlmDispatcher::dispatch_with_failover).
//! - **No credential I/O.** The bearer comes from the injected credential store
//!   (`waygate-llm-credentials`), which owns in-process OAuth refresh; this
//!   crate is a pure consumer (invariant I4).
//!
//! Supports all four upstream protocols — OpenAI-chat, Anthropic-Messages,
//! Gemini, and OpenAI-Responses — for both unary and streaming. The
//! [`DispatchError::UnsupportedProtocol`] variant remains for a future protocol
//! added to the enum but not yet wired here.

mod images;
mod resolver;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use serde_json::Value;

use waygate_llm_credentials::{CredentialError, LlmCredentialStore, LlmProvider};

pub use resolver::{
    DbModelResolver, LlmModelResolver, LlmOperation, ModelRisk, ResolvedModel, StaticModelResolver,
};
use waygate_llm_providers::{
    ProviderAuth, ProviderClient, ProviderError, ProviderRequest, ProviderResponse,
    SharedCodexUaVersion, SseStream,
};
use waygate_llm_translate::{
    anthropic_to_canonical_response, canonical_response_to_openai_chat,
    canonical_response_to_responses, extract_anthropic_messages, extract_gemini,
    extract_openai_chat, extract_openai_embeddings, extract_openai_responses,
    finalize_codex_responses_body, gemini_to_canonical_response, openai_chat_to_canonical_response,
    openai_responses_to_canonical_response, render_anthropic_messages, render_gemini,
    render_openai_chat, render_openai_embeddings, render_openai_responses, CanonicalResponse,
    EmbeddingsRequest, InferenceRecord, LlmRequest, Surface, TranslateError, UpstreamProtocol,
};
// Re-export the provider SSE types so consumers (the invocation pipeline's
// streaming egress) can map a `DispatchOutcome::Stream` without a direct
// dependency on `waygate-llm-providers`.
pub use waygate_llm_providers::{SseEvent, SseStream as ProviderSseStream};

/// Where a resolved request is sent and how it authenticates. Produced by the
/// (stubbed-for-now) model resolver; carries transport + identity, no policy.
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// Explicit opt-in for an embedding backend without upstream authentication.
    /// Other inference operations always require their configured credential.
    pub embeddings_no_auth: bool,
    /// The provider that owns the credential.
    pub provider: LlmProvider,
    /// Which pooled credential label to use (`bearer(provider, label)`).
    pub credential_label: String,
    /// Provider base URL, no trailing slash (e.g. `https://openrouter.ai/api/v1`).
    pub base_url: String,
    /// Endpoint path under the base (e.g. `chat/completions`).
    pub path: String,
    /// The upstream model name to send (may differ from the client's alias).
    pub upstream_model: String,
    /// The provider-native protocol — selects the render/extract adapter. All
    /// four variants (`OpenAiChat`, `AnthropicMessages`, `Gemini`,
    /// `OpenAiResponses`) are supported for both unary and streaming.
    pub protocol: UpstreamProtocol,
    /// When `true`, this route targets the ChatGPT backend
    /// (`chatgpt.com/backend-api/codex`) rather than a standard OpenAI Responses
    /// endpoint: dispatch sends the Codex auth fingerprint
    /// ([`ProviderAuth::OpenAiChatGpt`]) instead of a plain `Bearer`, including
    /// the credential's `chatgpt-account-id`. Applies to Responses chat routes
    /// and the separate Images operation. Set by the server from a model's
    /// `surface: codex`; image configuration requires it.
    pub openai_chatgpt: bool,
}

/// The result of a dispatch.
pub enum DispatchOutcome {
    /// Non-streaming: the extracted record and the parsed response body.
    Unary {
        record: InferenceRecord,
        body: Value,
    },
    /// Streaming: the identity-stamped base record and the raw provider SSE
    /// frame stream. The consumer drives a
    /// `waygate_llm_translate::StreamTranslator` (seeded from `record_base`,
    /// whose `upstream_protocol` selects the variant) to translate frames to
    /// OpenAI chunks for the client and finalize the record at stream close.
    Stream {
        record_base: InferenceRecord,
        frames: SseStream,
    },
}

impl std::fmt::Debug for DispatchOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unary { record, .. } => f
                .debug_struct("Unary")
                .field("record", record)
                .finish_non_exhaustive(),
            Self::Stream { record_base, .. } => f
                .debug_struct("Stream")
                .field("record_base", record_base)
                .finish_non_exhaustive(),
        }
    }
}

/// Failure modes of a dispatch, before any post-dispatch pipeline stage.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// No usable credential (missing / expired / refresh failed). Retryable:
    /// [`dispatch_with_failover`](LlmDispatcher::dispatch_with_failover) advances
    /// to the next pooled credential; if the whole pool is exhausted the pipeline
    /// maps this to a fail-closed error.
    #[error("credential unavailable: {0}")]
    Credential(#[from] CredentialError),
    /// The request could not be faithfully rendered for the route's protocol.
    #[error("translation failed: {0}")]
    Translate(#[from] TranslateError),
    /// The provider call failed (transport / non-2xx / stream protocol).
    #[error("provider call failed: {0}")]
    Provider(#[from] ProviderError),
    /// The route's protocol has no adapter in this dispatcher yet.
    #[error("unsupported upstream protocol: {0:?}")]
    UnsupportedProtocol(UpstreamProtocol),
}

impl DispatchError {
    /// Gateway-generated protocol guidance, never a provider response body.
    pub fn provider_protocol_message(&self) -> Option<&str> {
        match self {
            Self::Provider(ProviderError::Protocol(message)) => Some(message),
            _ => None,
        }
    }

    /// Bounded retry advice that can be forwarded without exposing provider bodies.
    pub fn provider_retry_after_seconds(&self) -> Option<u64> {
        retry_after_of(self).map(|duration| duration.as_secs().min(300))
    }
}

/// Base of the per-credential exponential failover backoff: the cooldown after
/// the first consecutive retryable failure, doubling each subsequent failure.
const COOLDOWN_BASE: Duration = Duration::from_millis(500);
/// Ceiling on the exponential backoff (a single credential never cools longer
/// than this from failure-count alone; a provider `Retry-After` may exceed it,
/// up to [`RETRY_AFTER_MAX`]).
const COOLDOWN_MAX: Duration = Duration::from_secs(60);
/// Hard ceiling on a provider-advertised `Retry-After` we will honor. The value
/// is provider-controlled, so it MUST be clamped: an unbounded duration added to
/// an `Instant` panics on overflow, and that panic would happen while the
/// cooldown mutex is held — poisoning it and breaking every later dispatch. 5
/// minutes is well past any legitimate rate-limit window.
const RETRY_AFTER_MAX: Duration = Duration::from_secs(300);

/// In-process cooldown state for one `(provider, credential_label)` after
/// consecutive retryable failures. Cleared on the next success. Not persisted in
/// this slice — a restart starts every credential warm (persisted cooldown that
/// survives restart is a follow-up, per §7).
struct Cooldown {
    /// The credential is skipped during failover until this instant.
    until: Instant,
    /// Consecutive retryable failures, driving the exponential backoff.
    consecutive_failures: u32,
}

/// Composes credentials + translate + providers for one LLM call. Cheap to
/// clone; construct once and share. The cooldown map is shared across clones
/// (so failover backoff is process-wide, not per-clone).
#[derive(Clone)]
pub struct LlmDispatcher {
    providers: ProviderClient,
    credentials: Arc<LlmCredentialStore>,
    /// Per-`(provider, credential_label)` failover cooldown (§7). A std mutex is
    /// correct here: every critical section is synchronous (no `.await` is held
    /// across the lock — the provider call happens outside it).
    cooldowns: Arc<Mutex<HashMap<(LlmProvider, String), Cooldown>>>,
    /// Shared Codex CLI version for the ChatGPT-backend `User-Agent`
    /// fingerprint. The composition root wires the same handle the discovery
    /// refresher updates with the version it fetched the model listing as, so
    /// `/responses` and `/models` present one client identity. `None` (or an
    /// unwired handle) falls back to the providers crate's compiled default.
    codex_ua_version: Option<SharedCodexUaVersion>,
    response_capacity: Arc<tokio::sync::Semaphore>,
}

/// Shared gateway capacity for chat, Responses, and embedding processing.
pub const MAX_CONCURRENT_RESPONSES: usize = 8;

impl LlmDispatcher {
    pub fn new(providers: ProviderClient, credentials: Arc<LlmCredentialStore>) -> Self {
        Self {
            providers,
            credentials,
            cooldowns: Arc::new(Mutex::new(HashMap::new())),
            codex_ua_version: None,
            response_capacity: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RESPONSES)),
        }
    }

    /// Admit response processing without a wait queue. The invocation keeps
    /// this permit through unary finalization or stream completion/cancellation.
    /// Clones share admission, including services created for new MCP sessions.
    pub fn try_admit_response(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.response_capacity.clone().try_acquire_owned().ok()
    }

    /// Wire the shared Codex CLI version handle (see the field docs). Builder
    /// style so existing constructors stay unchanged.
    pub fn with_codex_ua_version(mut self, handle: SharedCodexUaVersion) -> Self {
        self.codex_ua_version = Some(handle);
        self
    }

    /// The shared Codex UA version handle, when wired — exposed (cloning the
    /// `Arc`) so the composition root can hand the SAME handle to the
    /// discovery refresher that keeps it current.
    pub fn codex_ua_version(&self) -> Option<SharedCodexUaVersion> {
        self.codex_ua_version.clone()
    }

    /// The shared credential store this dispatcher resolves bearers from.
    /// Exposed (cloning the `Arc`) so the composition root can hand the same
    /// in-process store to the admin credential-status panel — the panel
    /// reads live cached health from the very pool dispatch uses, not a separate
    /// snapshot that could drift.
    pub fn credentials(&self) -> Arc<LlmCredentialStore> {
        self.credentials.clone()
    }

    /// Whether `route`'s credential is currently in failover cooldown.
    fn is_cooled(&self, route: &ResolvedRoute) -> bool {
        self.cooldowns
            .lock()
            .expect("cooldown mutex poisoned")
            .get(&(route.provider, route.credential_label.clone()))
            .is_some_and(|cd| cd.until > Instant::now())
    }

    /// Record a retryable failure for `route`'s credential: bump the consecutive
    /// failure count and set the cooldown to `now + backoff`, where backoff is the
    /// exponential `COOLDOWN_BASE · 2^(failures-1)` capped at `COOLDOWN_MAX`, then
    /// raised to a provider `Retry-After` if it asked for longer.
    fn record_failure(&self, route: &ResolvedRoute, retry_after: Option<Duration>) {
        let now = Instant::now();
        let mut map = self.cooldowns.lock().expect("cooldown mutex poisoned");
        let cd = map
            .entry((route.provider, route.credential_label.clone()))
            .or_insert(Cooldown {
                until: now,
                consecutive_failures: 0,
            });
        cd.consecutive_failures = cd.consecutive_failures.saturating_add(1);
        let factor = 2u32.saturating_pow(cd.consecutive_failures - 1);
        let mut backoff = COOLDOWN_BASE.saturating_mul(factor).min(COOLDOWN_MAX);
        if let Some(ra) = retry_after {
            // Honor a longer provider Retry-After, but CLAMP it: the value is
            // provider-controlled, and an unbounded duration added to an Instant
            // panics on overflow (here, while holding the lock → poisons it).
            backoff = backoff.max(ra.min(RETRY_AFTER_MAX));
        }
        // `checked_add` is the panic-safe add; `backoff` is already clamped, so
        // this never actually overflows — the fallback is pure defense in depth.
        cd.until = now.checked_add(backoff).unwrap_or(now);
    }

    /// Clear any cooldown for `route`'s credential after a success — it recovered.
    fn clear_cooldown(&self, route: &ResolvedRoute) {
        self.cooldowns
            .lock()
            .expect("cooldown mutex poisoned")
            .remove(&(route.provider, route.credential_label.clone()));
    }

    /// Dispatch with **failover across a credential pool** (§7): try `primary`,
    /// then each of `fallbacks` in order, advancing only on a *retryable* error
    /// (a provider 429 / 5xx / transport failure, or an unavailable credential —
    /// see [`is_retryable`]). A non-retryable error (a non-429 4xx, a translation
    /// failure, an unsupported protocol) returns immediately — retrying the same
    /// request against another credential of the same provider would fail
    /// identically. The first success wins; if every candidate fails, the last
    /// error is returned.
    ///
    /// For a streamed call this fails over on the INITIAL dispatch error and —
    /// when `ttfb` is set (§7 stall detection) — on a time-to-first-byte stall:
    /// it waits for the first SSE frame, and a stall (or a pre-first-frame stream
    /// error) is retryable, so a dead-on-arrival stream fails over before any
    /// byte reaches the client. Once the first frame is forwarded, a mid-stream
    /// failure is a truncation at the egress — no silent retry once the client is
    /// streaming.
    ///
    /// Cooldown (§7): a credential that fails retryably enters an exponential
    /// backoff ([`COOLDOWN_BASE`] doubling per consecutive failure, capped at
    /// [`COOLDOWN_MAX`], raised to a clamped provider `Retry-After` when longer);
    /// a success clears it. Cooled credentials are tried **last** — non-cooled
    /// candidates first, cooled ones only as a last resort — so a cooled
    /// credential is deprioritized but never *excluded*: a serviceable request is
    /// never hard-blocked, even if every non-cooled candidate fails. In-process
    /// only in this slice; persistence across restart is a follow-up.
    pub async fn dispatch_with_failover(
        &self,
        req: &LlmRequest,
        primary: &ResolvedRoute,
        fallbacks: &[ResolvedRoute],
        ttfb: Option<Duration>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Try non-cooled candidates first, then cooled ones as a last resort:
        // cooldown *deprioritizes* a credential, it never excludes it, so a
        // serviceable request is never hard-blocked even if every live candidate
        // fails. `partition` preserves the within-group (primary-then-fallbacks)
        // order.
        let (live, cooled): (Vec<&ResolvedRoute>, Vec<&ResolvedRoute>) = std::iter::once(primary)
            .chain(fallbacks.iter())
            .partition(|r| !self.is_cooled(r));
        let order: Vec<&ResolvedRoute> = live.into_iter().chain(cooled).collect();

        let mut last_err: Option<DispatchError> = None;
        for route in order {
            // Settle the streamed first frame within the TTFB deadline (if any);
            // a stall there is retryable and fails over like any other error.
            let started = std::time::Instant::now();
            let result = match self.dispatch(req, route).await {
                Ok(outcome) => settle_stream_outcome(outcome, ttfb, started).await,
                Err(e) => Err(e),
            };
            match result {
                Ok(settled) => {
                    self.clear_cooldown(route);
                    return Ok(settled);
                }
                Err(e) if is_retryable(&e) => {
                    self.record_failure(route, retry_after_of(&e));
                    tracing::warn!(
                        provider = route.provider.as_str(),
                        credential_label = %route.credential_label,
                        error = %e,
                        "llm dispatch failed on a pool candidate; cooling it and failing over"
                    );
                    last_err = Some(e);
                }
                // Non-retryable: another credential of the same provider won't help.
                Err(e) => return Err(e),
            }
        }
        // `order` is non-empty (candidates always has the primary) and only
        // retryable failures fall through, so `last_err` is set.
        Err(last_err.expect("the candidate order is non-empty"))
    }

    /// Dispatch `req` to `route`: resolve the bearer (the store handles in-proc
    /// OAuth refresh), render the provider body, call the provider, and return
    /// the unary record+body or the streaming frames+base-record.
    pub async fn dispatch(
        &self,
        req: &LlmRequest,
        route: &ResolvedRoute,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Select the protocol adapter (render + auth scheme + endpoint path)
        // before resolving a credential or making any call. All four upstream
        // protocols — OpenAI-chat, Anthropic Messages, Gemini, and OpenAI
        // Responses — are supported for both unary and streaming. (The
        // `UnsupportedProtocol` error variant remains for a future protocol
        // added to the enum but not yet wired here.)
        let (body, auth, path) = match route.protocol {
            UpstreamProtocol::OpenAiChat => (
                render_openai_chat(req, &route.upstream_model)?,
                ProviderAuth::Bearer,
                route.path.clone(),
            ),
            UpstreamProtocol::AnthropicMessages => {
                // Both unary and streaming are supported: the streaming egress
                // selects the Anthropic SSE translator from record_base's
                // protocol, translating Anthropic events to OpenAI chunks.
                (
                    render_anthropic_messages(req, &route.upstream_model)?,
                    ProviderAuth::Anthropic,
                    route.path.clone(),
                )
            }
            UpstreamProtocol::Gemini => {
                // Gemini puts the model AND the method in the URL path, not the
                // body, so dispatch templates the path here — the configured
                // `route.path` is unused for Gemini. Streaming uses the SSE method
                // (`:streamGenerateContent?alt=sse`), unary `:generateContent`;
                // the streaming egress selects the Gemini SSE translator from
                // record_base's protocol. Auth is `Bearer`: the credential store
                // resolves Google as OAuth.
                let method = if req.stream {
                    "streamGenerateContent?alt=sse"
                } else {
                    "generateContent"
                };
                (
                    render_gemini(req)?,
                    ProviderAuth::Bearer,
                    format!("v1beta/models/{}:{}", route.upstream_model, method),
                )
            }
            UpstreamProtocol::OpenAiResponses => {
                // Both unary and streaming are supported. The Responses surface
                // lives at the configured `route.path` (`responses`) — the server
                // wires it from a model's `surface: responses` (or `surface:
                // codex` for the ChatGPT backend). Streaming is body-driven
                // (`stream: true`, set by render_openai_responses); the streaming
                // egress selects the Responses SSE translator from record_base's
                // protocol. Auth is `Bearer` for a standard Responses endpoint, or
                // the Codex fingerprint (`OpenAiChatGpt`) for the ChatGPT backend.
                let auth = if route.openai_chatgpt {
                    ProviderAuth::OpenAiChatGpt
                } else {
                    ProviderAuth::Bearer
                };
                let mut body = render_openai_responses(req, &route.upstream_model)?;
                if route.openai_chatgpt {
                    // The ChatGPT (Codex) backend is streaming-only and rejects a
                    // generic Responses body. A non-streaming client call would
                    // require streaming upstream and aggregating the SSE back into
                    // a unary body (the reference always streams upstream); this
                    // slice does not, so rather than send a body (`stream:true`)
                    // that contradicts a unary transport, fail closed with a clear,
                    // non-retryable message. Streaming Codex calls (the common
                    // path) are fully supported.
                    if !req.stream {
                        return Err(DispatchError::Translate(TranslateError::Unsupported {
                            surface: "openai_responses_codex",
                            param: "non-streaming request to the ChatGPT (Codex) backend; \
                                    use stream=true"
                                .into(),
                        }));
                    }
                    body = finalize_codex_responses_body(body);
                }
                (body, auth, route.path.clone())
            }
        };

        // I4: the bearer is injected and managed by the credential store.
        let (bearer, credential_account_id) = self
            .credentials
            .bearer_with_account(route.provider, &route.credential_label)
            .await?;
        let account_id = if matches!(auth, ProviderAuth::OpenAiChatGpt) {
            credential_account_id
        } else {
            None
        };

        // The Codex fingerprint's User-Agent version: read the shared handle
        // per request (the discovery refresher hot-swaps it), only for the
        // ChatGPT-backend auth path.
        let codex_ua_version = if matches!(auth, ProviderAuth::OpenAiChatGpt) {
            self.codex_ua_version
                .as_ref()
                .map(|h| h.read().expect("codex ua version lock").clone())
        } else {
            None
        };

        let mut record_base = InferenceRecord::new(
            route.provider,
            route.credential_label.as_str(),
            req.model_requested.as_str(),
            req.inbound_surface,
            route.protocol,
        );
        record_base.provider_account_id = account_id.clone();
        let started = std::time::Instant::now();

        let response = self
            .providers
            .send(ProviderRequest {
                base_url: route.base_url.clone(),
                path,
                bearer,
                auth,
                body,
                stream: req.stream,
                account_id,
                codex_ua_version,
            })
            .await
            .inspect_err(|_| {
                waygate_telemetry::metrics::record_llm_request_failure(
                    route.provider.as_str(),
                    &record_base.model_requested,
                    record_base.provider_account_id.as_deref(),
                    started.elapsed().as_secs_f64(),
                    waygate_telemetry::metrics::LlmFailurePhase::Dispatch,
                )
            })?;

        Ok(match response {
            // A unary body from any supported protocol. The metadata record is
            // extracted from the RAW provider body; the body returned to the client
            // is rendered to the *inbound client surface* (Chat Completions or
            // Responses) FROM the canonical response hub
            // (`provider → CanonicalResponse → {chat | responses}`) — symmetric with
            // the request side. The `canonical → chat` downcast reproduces the
            // legacy per-provider translators byte-for-byte (golden-oracle tested).
            // OpenAI-chat is a special case: for a chat client it stays a pure
            // passthrough (a typed hub cannot byte-preserve every chat field —
            // logprobs, `system_fingerprint`, multiple choices); for a Responses
            // client the chat body is lifted into the hub and rendered as Responses.
            ProviderResponse::Unary(body) => {
                let responses = req.inbound_surface == Surface::Responses;
                let (record, body) = match route.protocol {
                    UpstreamProtocol::AnthropicMessages => {
                        let record = extract_anthropic_messages(record_base, &body);
                        let body =
                            render_for_surface(&anthropic_to_canonical_response(&body), responses);
                        (record, body)
                    }
                    UpstreamProtocol::Gemini => {
                        let record = extract_gemini(record_base, &body);
                        let body =
                            render_for_surface(&gemini_to_canonical_response(&body), responses);
                        (record, body)
                    }
                    UpstreamProtocol::OpenAiResponses => {
                        let record = extract_openai_responses(record_base, &body);
                        let body = render_for_surface(
                            &openai_responses_to_canonical_response(&body),
                            responses,
                        );
                        (record, body)
                    }
                    _ => {
                        let record = extract_openai_chat(record_base, &body);
                        let body = if responses {
                            canonical_response_to_responses(&openai_chat_to_canonical_response(
                                &body,
                            ))
                        } else {
                            body // chat → chat passthrough
                        };
                        (record, body)
                    }
                };
                DispatchOutcome::Unary { record, body }
            }
            ProviderResponse::Stream(frames) => DispatchOutcome::Stream {
                record_base,
                frames,
            },
        })
    }

    /// Dispatch an **embeddings** request to `route` (the `/v1/embeddings`
    /// operation): apply the route's authentication, render the OpenAI-compatible
    /// embeddings body with the *resolved upstream* model, POST it, and extract
    /// the input-only [`InferenceRecord`]. Embeddings have no streaming form, so
    /// this always returns a unary `(record, body)` pair. The body is the
    /// provider's OpenAI-shaped embeddings response, returned to the client
    /// verbatim (the chat→chat passthrough analog).
    ///
    /// Only the OpenAI-compatible shape is supported. Authentication defaults to
    /// `Bearer`, resolved through the injected credential store (I4). Routes
    /// explicitly configured with `embeddings_no_auth` skip credential lookup
    /// and send no provider authorization header.
    pub async fn dispatch_embeddings(
        &self,
        req: &EmbeddingsRequest,
        route: &ResolvedRoute,
    ) -> Result<(InferenceRecord, Value), DispatchError> {
        let body = render_openai_embeddings(req, &route.upstream_model);
        // I4: the bearer is injected and managed by the credential store.
        let (bearer, auth) = if route.embeddings_no_auth {
            (String::new(), ProviderAuth::None)
        } else {
            (
                self.credentials
                    .bearer(route.provider, &route.credential_label)
                    .await?,
                ProviderAuth::Bearer,
            )
        };
        // `Surface::Embeddings` marks the durable usage row; the chat
        // `upstream_protocol` is a benign placeholder (inert on this path — it
        // only selects the chat stream translator, which embeddings never use).
        let record_base = InferenceRecord::new(
            route.provider,
            route.credential_label.as_str(),
            req.model_requested.as_str(),
            Surface::Embeddings,
            UpstreamProtocol::OpenAiChat,
        );
        let response = self
            .providers
            .send_with_limit(
                ProviderRequest {
                    base_url: route.base_url.clone(),
                    path: route.path.clone(),
                    bearer,
                    auth,
                    body,
                    // Embeddings are unary only — no SSE.
                    stream: false,
                    account_id: None,
                    codex_ua_version: None,
                },
                waygate_llm_providers::MAX_EMBEDDING_RESPONSE_BYTES,
            )
            .await?;
        // We sent `stream: false`, so `ProviderClient::send` always returns
        // `Unary` (it JSON-decodes the body); it only yields `Stream` for
        // `stream: true`. The `Stream` arm is therefore unreachable here — pure
        // defense in depth. A provider that returns an SSE body to this unary
        // request does NOT reach that arm: the JSON decode of the `data:` frames
        // fails upstream as `ProviderError::Decode` (also non-retryable), which
        // is the real "streamed response to a unary request" surface.
        match response {
            ProviderResponse::Unary(body) => {
                let record = extract_openai_embeddings(record_base, &body);
                Ok((record, body))
            }
            ProviderResponse::Stream(_) => Err(DispatchError::Provider(ProviderError::Protocol(
                "embeddings dispatch received a streamed response to a unary request \
                 (unreachable: stream=false yields Unary)"
                    .to_string(),
            ))),
        }
    }

    /// Dispatch an embeddings request with **failover across a credential pool**
    /// (§7), reusing the same per-credential cooldown machinery as the chat path
    /// ([`dispatch_with_failover`](Self::dispatch_with_failover)). Try `primary`,
    /// then each of `fallbacks`, advancing only on a *retryable* error; cooled
    /// credentials are tried last (deprioritized, never excluded); the first
    /// success clears its cooldown and wins. Unary-only, so there is no streaming
    /// TTFB stall to settle — this is the chat failover loop minus stream
    /// handling. If every candidate fails, the last error is returned.
    pub async fn dispatch_embeddings_with_failover(
        &self,
        req: &EmbeddingsRequest,
        primary: &ResolvedRoute,
        fallbacks: &[ResolvedRoute],
    ) -> Result<(InferenceRecord, Value), DispatchError> {
        // Non-cooled candidates first, then cooled as a last resort (cooldown
        // deprioritizes, never hard-blocks) — `partition` keeps within-group order.
        let (live, cooled): (Vec<&ResolvedRoute>, Vec<&ResolvedRoute>) = std::iter::once(primary)
            .chain(fallbacks.iter())
            .partition(|r| !self.is_cooled(r));
        let order: Vec<&ResolvedRoute> = live.into_iter().chain(cooled).collect();

        let mut last_err: Option<DispatchError> = None;
        for route in order {
            match self.dispatch_embeddings(req, route).await {
                Ok(out) => {
                    self.clear_cooldown(route);
                    return Ok(out);
                }
                Err(e) if is_retryable(&e) => {
                    self.record_failure(route, retry_after_of(&e));
                    tracing::warn!(
                        provider = route.provider.as_str(),
                        credential_label = %route.credential_label,
                        status = ?e.provider_status(),
                        "llm embeddings dispatch failed on a pool candidate; cooling it and failing over"
                    );
                    last_err = Some(e);
                }
                // Non-retryable: another credential of the same provider won't help.
                Err(e) => return Err(e),
            }
        }
        // `order` always has the primary, and only retryable failures fall
        // through, so `last_err` is set.
        Err(last_err.expect("the candidate order is non-empty"))
    }
}

/// Render a [`CanonicalResponse`] to the inbound client surface: the Responses
/// body for a `/v1/responses` caller, or the OpenAI Chat downcast otherwise.
fn render_for_surface(c: &CanonicalResponse, responses: bool) -> Value {
    if responses {
        canonical_response_to_responses(c)
    } else {
        canonical_response_to_openai_chat(c)
    }
}

/// Whether a dispatch error should trigger failover to the next pool candidate
/// (§7): an unavailable credential, or a provider 429 / 5xx / transport failure.
/// A non-429 4xx, a decode / stream-protocol violation, a translation error, or
/// an unsupported protocol is terminal — another credential of the same provider
/// would fail the same way, so there is nothing to fail over to.
fn is_retryable(e: &DispatchError) -> bool {
    match e {
        // Credential couldn't be resolved / refreshed, or is stale — the next
        // credential in the pool may be healthy.
        DispatchError::Credential(_) => true,
        DispatchError::Provider(ProviderError::Transport(_)) => true,
        DispatchError::Provider(ProviderError::Status { status, .. }) => {
            *status == 429 || (500..=599).contains(status)
        }
        DispatchError::Provider(_)
        | DispatchError::Translate(_)
        | DispatchError::UnsupportedProtocol(_) => false,
    }
}

/// The provider-advertised `Retry-After` carried by a dispatch error, if any —
/// honored by the failover cooldown so a rate-limited credential backs off for at
/// least the requested duration.
fn retry_after_of(e: &DispatchError) -> Option<Duration> {
    match e {
        DispatchError::Provider(ProviderError::Status { retry_after, .. }) => *retry_after,
        _ => None,
    }
}

/// Apply TTFB stall detection (§7) to a dispatch outcome before it is handed to
/// the caller. A [`DispatchOutcome::Unary`] (and a `Stream` with no `ttfb`)
/// passes through unchanged. For a `Stream` with a `ttfb` deadline, the first SSE
/// frame is awaited within that window: a stall, an empty stream, or a
/// pre-first-frame stream error becomes a **retryable** [`DispatchError`] so the
/// caller fails over before any byte reaches the client; on success the consumed
/// first frame is prepended back so the egress sees the full stream in order.
async fn settle_stream_outcome(
    outcome: DispatchOutcome,
    ttfb: Option<Duration>,
    started: std::time::Instant,
) -> Result<DispatchOutcome, DispatchError> {
    let (record_base, mut frames) = match outcome {
        DispatchOutcome::Stream {
            record_base,
            frames,
        } => (record_base, frames),
        // Unary: no time-to-first-byte concept; the unary timeout already bounds it.
        unary => return Ok(unary),
    };
    let Some(ttfb) = ttfb else {
        return Ok(DispatchOutcome::Stream {
            record_base,
            frames,
        });
    };
    let error = match tokio::time::timeout(ttfb, frames.next()).await {
        Ok(Some(Ok(first))) => {
            // Prepend the consumed first frame so the egress sees the stream whole.
            let frames = futures::stream::once(async move { Ok::<_, ProviderError>(first) })
                .chain(frames)
                .boxed();
            return Ok(DispatchOutcome::Stream {
                record_base,
                frames,
            });
        }
        // A pre-first-frame stream error: no client byte has been forwarded yet,
        // so failing over is always safe. Wrap as a (retryable) transport error —
        // keeping the original error's text for diagnostics — so the failover loop
        // advances even for an SSE protocol violation, which is otherwise terminal
        // once mid-stream.
        Ok(Some(Err(e))) => DispatchError::Provider(ProviderError::Transport(format!(
            "pre-first-frame stream error: {e}"
        ))),
        // An empty stream (closed before any frame) is treated as retryable so
        // another credential gets a chance.
        Ok(None) => DispatchError::Provider(ProviderError::Transport(
            "provider stream closed before the first frame".to_string(),
        )),
        // TTFB stall → retryable, so dispatch fails over before any client byte.
        Err(_elapsed) => DispatchError::Provider(ProviderError::Transport(format!(
            "time-to-first-byte exceeded {}ms",
            ttfb.as_millis()
        ))),
    };
    waygate_telemetry::metrics::record_llm_request_failure(
        record_base.provider.as_str(),
        &record_base.model_requested,
        record_base.provider_account_id.as_deref(),
        started.elapsed().as_secs_f64(),
        waygate_telemetry::metrics::LlmFailurePhase::Stream,
    );
    Err(error)
}

#[cfg(test)]
mod cooldown_tests {
    use super::*;
    use waygate_llm_credentials::LlmCredentialStore;
    use waygate_llm_translate::UpstreamProtocol;

    #[cfg(test)]
    fn raw_test_http_client() -> reqwest::Client {
        reqwest::Client::new() // A raw test client isolates cooldown behavior from gateway policy.
    }

    fn dispatcher() -> LlmDispatcher {
        LlmDispatcher::new(
            ProviderClient::new(raw_test_http_client()),
            Arc::new(LlmCredentialStore::from_vars(std::iter::empty::<(
                String,
                String,
            )>())),
        )
    }

    #[test]
    fn response_admission_is_shared_and_recovers_after_release() {
        let dispatcher = dispatcher();
        let clone = dispatcher.clone();
        let permits: Vec<_> = (0..MAX_CONCURRENT_RESPONSES)
            .map(|_| dispatcher.try_admit_response().unwrap())
            .collect();
        assert!(clone.try_admit_response().is_none());
        drop(permits);
        assert!(clone.try_admit_response().is_some());
    }

    fn route(label: &str) -> ResolvedRoute {
        ResolvedRoute {
            provider: LlmProvider::OpenAi,
            credential_label: label.into(),
            base_url: "http://x".into(),
            path: "p".into(),
            upstream_model: "m".into(),
            protocol: UpstreamProtocol::OpenAiChat,
            embeddings_no_auth: false,
            openai_chatgpt: false,
        }
    }

    #[test]
    fn a_retryable_failure_cools_and_a_success_clears() {
        let d = dispatcher();
        let r = route("A");
        assert!(!d.is_cooled(&r));
        d.record_failure(&r, None);
        assert!(d.is_cooled(&r), "a retryable failure cools the credential");
        d.clear_cooldown(&r);
        assert!(!d.is_cooled(&r), "a success clears the cooldown");
    }

    #[test]
    fn retry_after_extends_cooldown_beyond_the_base_backoff() {
        let d = dispatcher();
        let r = route("B");
        let before = Instant::now();
        // First failure's exponential backoff is COOLDOWN_BASE (500ms); a 30s
        // provider Retry-After must win.
        d.record_failure(&r, Some(Duration::from_secs(30)));
        let until = d
            .cooldowns
            .lock()
            .unwrap()
            .get(&(r.provider, r.credential_label.clone()))
            .unwrap()
            .until;
        assert!(
            until >= before + Duration::from_secs(29),
            "Retry-After (30s) must extend the cooldown well past the 500ms base"
        );
    }

    #[test]
    fn exponential_backoff_is_capped_and_never_overflows() {
        let d = dispatcher();
        let r = route("C");
        let before = Instant::now();
        // Many consecutive failures must neither overflow nor exceed COOLDOWN_MAX.
        for _ in 0..40 {
            d.record_failure(&r, None);
        }
        let until = d
            .cooldowns
            .lock()
            .unwrap()
            .get(&(r.provider, r.credential_label.clone()))
            .unwrap()
            .until;
        assert!(
            until <= before + COOLDOWN_MAX + Duration::from_secs(1),
            "backoff is capped at COOLDOWN_MAX"
        );
    }

    #[test]
    fn an_extreme_retry_after_is_clamped_and_never_panics() {
        // A provider-controlled `u64::MAX`-second Retry-After would overflow the
        // `Instant` add (panic, while holding the lock) if unclamped. It must be
        // clamped to RETRY_AFTER_MAX and the add must be panic-safe.
        let d = dispatcher();
        let r = route("D");
        let before = Instant::now();
        d.record_failure(&r, Some(Duration::from_secs(u64::MAX)));
        let until = d
            .cooldowns
            .lock()
            .unwrap()
            .get(&(r.provider, r.credential_label.clone()))
            .unwrap()
            .until;
        assert!(
            until <= before + RETRY_AFTER_MAX + Duration::from_secs(1),
            "an extreme Retry-After is clamped to RETRY_AFTER_MAX"
        );
        // And the credential is still usable afterward (mutex not poisoned).
        assert!(d.is_cooled(&r));
    }

    #[tokio::test]
    async fn first_frame_failures_record_one_account_observation() {
        for (name, frames) in [
            ("first-frame-timeout", futures::stream::pending().boxed()),
            ("first-frame-eof", futures::stream::empty().boxed()),
            (
                "first-frame-error",
                futures::stream::once(async {
                    Err(ProviderError::Protocol("invalid frame".into()))
                })
                .boxed(),
            ),
        ] {
            let mut record_base = InferenceRecord::new(
                LlmProvider::OpenAi,
                "MAIN",
                name,
                Surface::Responses,
                UpstreamProtocol::OpenAiResponses,
            );
            record_base.provider_account_id = Some("first-frame-account".into());
            let outcome = DispatchOutcome::Stream {
                record_base,
                frames,
            };
            assert!(settle_stream_outcome(
                outcome,
                Some(Duration::from_millis(1)),
                std::time::Instant::now(),
            )
            .await
            .is_err());
            let metrics = waygate_telemetry::gather_text();
            for metric in [
                "gen_ai_client_request_failures_total",
                "gen_ai_client_duration_seconds_count",
            ] {
                let line = metrics
                    .lines()
                    .find(|line| {
                        line.starts_with(metric) && line.contains(&format!("model=\"{name}\""))
                    })
                    .expect("failure metric");
                assert!(line.contains("user_account_id=\"first-frame-account\""));
                assert!(line.ends_with(" 1"), "{line}");
            }
        }
    }

    #[tokio::test]
    async fn a_pre_first_frame_stream_error_is_retryable_so_ttfb_fails_over() {
        // Before any client byte, a pre-first-frame stream error must be
        // retryable so dispatch fails over — even an SSE protocol violation,
        // which is otherwise terminal once mid-stream.
        use waygate_llm_translate::Surface;
        let base = InferenceRecord::new(
            LlmProvider::OpenAi,
            "L",
            "m",
            Surface::ChatCompletions,
            UpstreamProtocol::OpenAiChat,
        );
        let frames = futures::stream::iter(vec![Err(ProviderError::Protocol(
            "oversized event".to_string(),
        ))])
        .boxed();
        let outcome = DispatchOutcome::Stream {
            record_base: base,
            frames,
        };
        let err = settle_stream_outcome(
            outcome,
            Some(Duration::from_secs(1)),
            std::time::Instant::now(),
        )
        .await
        .expect_err("a pre-first-frame error settles to an error");
        assert!(
            is_retryable(&err),
            "a pre-first-frame stream error (even a protocol violation) must be retryable: {err:?}"
        );
    }
}
