//! `waygate-llm-providers` — the inference plane's outbound transport to LLM
//! providers (design §2.2). It is **transport only**: given an already-rendered
//! provider request body (from `waygate-llm-translate`), a resolved bearer
//! token, and a target URL, it performs the HTTP POST and returns either the
//! parsed unary JSON body or a stream of Server-Sent-Events `data:` frames.
//!
//! Deliberately narrow responsibilities:
//! - It is a pure **consumer** of a bearer string. It never reads, writes, or
//!   refreshes credential material — that is `waygate-llm-credentials`'
//!   job (invariant I4). OpenAI / Google subscription-OAuth and OpenRouter
//!   API-key authenticate with `Authorization: Bearer <token>`; Anthropic uses a
//!   first-party `x-api-key` + `anthropic-version`. Per-provider header divergence
//!   is selected by [`ProviderAuth`]: OpenAI/OpenRouter are Bearer-only, Anthropic
//!   is `x-api-key`, and the Codex (ChatGPT-backend) path adds the Codex CLI
//!   device fingerprint its OAuth token requires.
//! - It does **not** interpret payloads beyond SSE framing. Request rendering
//!   (including `stream_options.include_usage`) and response→`InferenceRecord`
//!   extraction live in `waygate-llm-translate`; this crate forwards the body
//!   verbatim and surfaces raw `data:` frames for the caller to translate.
//! - It does **not** enforce policy, quota, or audit. Those are the unified
//!   invocation pipeline's stages (invariant I1); this crate is the thing the
//!   dispatch stage calls *after* enforcement has passed.

mod sse;

use futures::stream::BoxStream;
use futures::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use sse::SseEvent;

/// Failure modes of an outbound provider call. Transport/HTTP/decode failures
/// are normalized here so the dispatch layer maps them to one error surface
/// regardless of provider.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// Connect/TLS/read failure before or during the response — no usable HTTP
    /// status was obtained.
    #[error("transport error: {0}")]
    Transport(String),
    /// The provider returned a non-2xx status. `body` is a bounded snippet of
    /// the error body for diagnostics (never the request payload). `retry_after`
    /// carries the `Retry-After` header (delta-seconds form) when the provider
    /// sent one — the dispatcher's failover cooldown honors it so a rate-limited
    /// credential backs off for at least that long. The HTTP-date form is not
    /// parsed (left `None`); providers' 429s use delta-seconds in practice.
    #[error("provider returned HTTP {status}: {body}")]
    Status {
        status: u16,
        body: String,
        retry_after: Option<std::time::Duration>,
    },
    /// A 2xx unary response whose body was not valid JSON.
    #[error("invalid JSON response body: {0}")]
    Decode(String),
    /// The provider response violated the transport contract, including unary
    /// body limits or an oversized or unterminated SSE event. These failures
    /// are not retried against another credential.
    #[error("provider response protocol violation: {0}")]
    Protocol(String),
}

/// A streamed provider response: a sequence of SSE `data:` events. Terminates
/// when the provider closes the stream; the OpenAI/OpenRouter terminal sentinel
/// is the literal `[DONE]` (see [`SseEvent::is_done`]).
pub type SseStream = BoxStream<'static, Result<SseEvent, ProviderError>>;

/// The outcome of a provider call. `stream` on the request selects which.
pub enum ProviderResponse {
    /// A non-streaming response: the parsed JSON body.
    Unary(Value),
    /// A streaming response: raw SSE `data:` frames, to be translated by the
    /// caller (`waygate-llm-translate`) into canonical chunks + the terminal
    /// `InferenceRecord`.
    Stream(SseStream),
}

impl std::fmt::Debug for ProviderResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unary(v) => f.debug_tuple("Unary").field(v).finish(),
            // The stream is lazy and not introspectable without consuming it.
            Self::Stream(_) => f.debug_tuple("Stream").field(&"<sse>").finish(),
        }
    }
}

/// How the resolved token is attached to the outbound request. Different
/// providers wire the same injected secret differently: OpenAI / OpenRouter use
/// `Authorization: Bearer`; Anthropic uses a first-party `x-api-key` (+
/// `anthropic-version`); the Codex ChatGPT backend uses `Bearer` plus its CLI
/// device fingerprint. The caller (dispatch) picks the scheme from the route's
/// protocol; this crate stays a pure transport that never sources the secret (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProviderAuth {
    /// Operator-configured backend that does not require an upstream credential.
    None,
    /// `Authorization: Bearer <token>` — OpenAI chat/responses, OpenRouter.
    #[default]
    Bearer,
    /// The Anthropic Messages API authenticated with a first-party **API key**:
    /// `x-api-key: <key>` + `anthropic-version` (no `Authorization: Bearer`, no
    /// device fingerprint). This is the sanctioned path; the prior
    /// subscription-OAuth / Claude-Code-impersonation support (Bearer token + the
    /// full Claude Code device fingerprint + system-prompt cloak) was removed —
    /// it violated Anthropic's ToS and risked account bans. Point `base_url` at
    /// `https://api.anthropic.com/v1` and inject an `sk-ant-…` key as the
    /// credential.
    Anthropic,
    /// The ChatGPT backend (`https://chatgpt.com/backend-api/codex`) with a Codex
    /// subscription OAuth access token. That backend (unlike `api.openai.com`)
    /// gates access to the Codex CLI identity, so this sends `Authorization:
    /// Bearer <token>` plus the Codex request fingerprint: `originator:
    /// codex_cli_rs`, the codex `User-Agent` ([`codex_fp_user_agent`]), a stable
    /// `session_id` + matching `x-client-request-id`, `x-codex-window-id`
    /// (`<session>:0`), the residency header, and — auth-critical for a
    /// workspace-scoped token — `chatgpt-account-id` from the credential's
    /// account id (set on [`ProviderRequest::account_id`]). The body is the
    /// caller-rendered Responses or Images shape; this transport only adds
    /// authentication headers. The `User-Agent`
    /// version comes from [`ProviderRequest::codex_ua_version`] (via
    /// [`codex_fp_user_agent`]).
    OpenAiChatGpt,
}

/// The Anthropic API version header value. Pinned here (not configurable) so the
/// wire contract this adapter renders/extracts against is explicit and stable;
/// bump it deliberately when the adapter is updated for a newer Messages schema.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// A stable CLI session UUID, keyed **per credential** by a hash of the bearer.
///
/// Used for the Codex `session_id` header (the Anthropic path no longer sends a
/// session id — it is a plain `x-api-key` provider). A real Codex CLI uses one
/// UUID for the life of a session; the reference proxy keys it on `sha256(apiKey)` — so a gateway
/// serving a *pool* of credentials must NOT share one process-wide id across
/// them. A single id under many different bearer tokens presents one "CLI
/// session" driving multiple accounts, a correlation anomaly the providers flag
/// on OAuth-gated backends. Keying per bearer gives each credential its own
/// stable session, exactly as the reference does (a token refresh starts a new
/// session id — same behavior).
///
/// The map key is `sha256(bearer)`, never the bearer itself: secret material
/// never lands in a long-lived structure (or a log). The returned UUID is random
/// and not derived from the secret.
fn session_id_for_bearer(bearer: &str) -> String {
    static PER_KEY: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<[u8; 32], String>>,
    > = std::sync::OnceLock::new();
    let digest = Sha256::digest(bearer.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    let map = PER_KEY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = map.lock().expect("session-id map poisoned");
    guard
        .entry(key)
        .or_insert_with(|| uuid::Uuid::new_v4().to_string())
        .clone()
}

/// Fallback Codex CLI version for the request fingerprint when the caller
/// supplies none. Kept equal to `waygate-llm-discovery`'s
/// `CODEX_DEFAULT_CLIENT_VERSION` — the two crates deliberately do not depend
/// on each other, and a `waygate-server` test pins the equality — so the
/// `/responses` fingerprint and the model listing present one client identity
/// even before the first discovery cycle. Bump both alongside notable CLI
/// releases.
pub const CODEX_FP_DEFAULT_VERSION: &str = "0.144.0";

/// The Codex CLI `User-Agent` for a given CLI version, so the gateway's
/// request fingerprint matches a real Codex CLI session — the ChatGPT backend
/// flags requests whose identity diverges. The real CLI derives the OS
/// segment dynamically; the gateway runs in a fixed Linux container, so a
/// stable platform segment is correct.
pub fn codex_fp_user_agent(version: &str) -> String {
    format!("codex_cli_rs/{version} (Linux 6.8.0; x86_64) unknown")
}

/// Shared, hot-swappable Codex CLI version for the request fingerprint: the
/// discovery refresher writes the version it fetched the model listing as,
/// and dispatch reads it per request — one client identity across both
/// surfaces, staying current as the tracked CLI version advances.
pub type SharedCodexUaVersion = std::sync::Arc<std::sync::RwLock<String>>;

/// ChatGPT backend residency header value. `us` matches a ChatGPT Plus/Pro
/// account default, as the reference Codex proxy sends.
pub const CODEX_RESIDENCY: &str = "us";

/// One outbound provider call. `body` is the already-rendered provider request
/// (e.g. from `waygate_llm_translate::render_openai_chat`); this crate adds
/// only transport concerns (URL, auth header, SSE `Accept`).
pub struct ProviderRequest {
    /// Base URL with no trailing slash, e.g. `https://openrouter.ai/api/v1`.
    pub base_url: String,
    /// Endpoint path under the base, e.g. `chat/completions` or `responses`.
    pub path: String,
    /// Resolved secret (OAuth access token or API key). Injected by the caller
    /// from `waygate-llm-credentials`; never sourced here.
    pub bearer: String,
    /// How `bearer` is attached to the request (provider-specific). Defaults to
    /// `Bearer` so existing OpenAI-shaped callers are unaffected.
    pub auth: ProviderAuth,
    /// The rendered provider request body.
    pub body: Value,
    /// Whether to request and parse a streamed (SSE) response. MUST match the
    /// `stream` flag in `body` — the caller renders the body and decides.
    pub stream: bool,
    /// ChatGPT workspace id for the `chatgpt-account-id` header, used ONLY by
    /// [`ProviderAuth::OpenAiChatGpt`]. The caller (dispatch) reads it from the
    /// credential via `LlmCredentialStore::oauth_account_id`. `None` (the default
    /// for every other auth scheme) omits the header.
    pub account_id: Option<String>,
    /// Codex CLI version for the `User-Agent` fingerprint, used ONLY by
    /// [`ProviderAuth::OpenAiChatGpt`]. The caller (dispatch) supplies the
    /// version the discovery listing was fetched as, so both surfaces present
    /// one client identity; `None` falls back to
    /// [`CODEX_FP_DEFAULT_VERSION`].
    pub codex_ua_version: Option<String>,
}

/// Max bytes of a non-2xx response body **read and** retained in
/// [`ProviderError::Status`]. The body is read streaming and capped at this
/// size, so a hostile/huge error body is never fully buffered.
const MAX_ERROR_BODY: usize = 2048;

/// Maximum decoded HTTP body for a unary chat or Responses call.
pub const MAX_CHAT_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Embedding batches carry larger numeric arrays than ordinary chat responses.
pub const MAX_EMBEDDING_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Outbound HTTP+SSE client to LLM providers. Cheap to clone (wraps a
/// connection-pooling `reqwest::Client`s); construct once and share.
#[derive(Clone)]
pub struct ProviderClient {
    http: reqwest::Client,
    single_attempt_http: Option<reqwest::Client>,
    /// Total per-request deadline applied to NON-streaming calls only. The
    /// shared `reqwest::Client` is configured with connect + idle-read timeouts
    /// rather than a total-request timeout, because a healthy streaming response
    /// is long-lived and a fixed total would sever it. That leaves a *unary*
    /// response bounded only by the idle-read gap — a provider that drips bytes
    /// just under that gap could hold a `/v1` request open indefinitely. This
    /// caps the whole unary request; streaming calls deliberately get no total
    /// deadline (they rely on idle-read). `None` = no total bound (e.g. tests).
    unary_timeout: Option<std::time::Duration>,
}

impl ProviderClient {
    /// Wrap a caller-provided `reqwest::Client` (so timeout/proxy/TLS policy is
    /// owned by the server, consistent with the rest of the gateway). No total
    /// unary deadline; use [`ProviderClient::with_unary_timeout`] to add one.
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            single_attempt_http: None,
            unary_timeout: None,
        }
    }

    /// Configure bounded image calls with the caller's proxy/TLS/timeout
    /// settings while refusing redirects and transport-level automatic retries.
    pub fn with_single_attempt_http(
        mut self,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, reqwest::Error> {
        self.single_attempt_http = Some(
            builder
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()?,
        );
        Ok(self)
    }

    /// Set the total per-request deadline for non-streaming calls (see the
    /// `unary_timeout` field). Streaming calls are unaffected.
    pub fn with_unary_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.unary_timeout = timeout;
        self
    }

    /// Perform the call. On a non-2xx status returns [`ProviderError::Status`]
    /// (body snippet bounded); on success returns [`ProviderResponse::Unary`]
    /// or [`ProviderResponse::Stream`] per `req.stream`.
    pub async fn send(&self, req: ProviderRequest) -> Result<ProviderResponse, ProviderError> {
        self.send_with_limit(req, MAX_CHAT_RESPONSE_BYTES).await
    }

    /// Use an operation-specific unary body limit with the standard transport.
    /// Streaming responses retain the SSE parser's per-event limit.
    pub async fn send_with_limit(
        &self,
        req: ProviderRequest,
        max_bytes: usize,
    ) -> Result<ProviderResponse, ProviderError> {
        self.send_inner(req, max_bytes, &self.http).await
    }

    /// Send a unary request with a hard response byte limit. Reads stop at the
    /// limit rather than buffering the entire response before checking it.
    /// Requires [`Self::with_single_attempt_http`]; redirects and automatic
    /// transport retries are disabled on this path.
    pub async fn send_bounded(
        &self,
        req: ProviderRequest,
        max_bytes: usize,
    ) -> Result<ProviderResponse, ProviderError> {
        if req.stream {
            return Err(ProviderError::Protocol(
                "bounded unary transport cannot stream".into(),
            ));
        }
        let http = self.single_attempt_http.as_ref().ok_or_else(|| {
            ProviderError::Protocol("single-attempt image transport is not configured".into())
        })?;
        self.send_inner(req, max_bytes, http).await
    }

    async fn send_inner(
        &self,
        req: ProviderRequest,
        max_bytes: usize,
        http: &reqwest::Client,
    ) -> Result<ProviderResponse, ProviderError> {
        let url = format!(
            "{}/{}",
            req.base_url.trim_end_matches('/'),
            req.path.trim_start_matches('/')
        );
        let mut builder = http.post(&url).json(&req.body);
        // Serialization owns the outbound bytes. Release the JSON tree before
        // awaiting the provider so large uploads do not overlap response storage.
        drop(req.body);
        builder = match req.auth {
            ProviderAuth::None => builder,
            ProviderAuth::Bearer => builder.bearer_auth(&req.bearer),
            // The Anthropic Messages API authenticated with a first-party **API
            // key** (`x-api-key`), not `Authorization: Bearer`. No Claude Code
            // device fingerprint — this is the sanctioned, ToS-clean path (the
            // subscription-OAuth/Claude-Code-impersonation path was removed). The
            // `anthropic-version` header is always required.
            ProviderAuth::Anthropic => builder
                .header("x-api-key", req.bearer.as_str())
                .header("anthropic-version", ANTHROPIC_VERSION),
            // ChatGPT-backend (Codex) fingerprint: the codex CLI identity the
            // backend gates on. `chatgpt-account-id` is included only when the
            // credential carried a workspace id (a workspace-scoped token needs
            // it; a personal one does not).
            ProviderAuth::OpenAiChatGpt => {
                let sid = session_id_for_bearer(&req.bearer);
                let ua = codex_fp_user_agent(
                    req.codex_ua_version
                        .as_deref()
                        .unwrap_or(CODEX_FP_DEFAULT_VERSION),
                );
                let mut b = builder
                    .bearer_auth(&req.bearer)
                    .header("originator", "codex_cli_rs")
                    .header(reqwest::header::USER_AGENT, ua)
                    .header("session_id", sid.as_str())
                    .header("x-client-request-id", sid.as_str())
                    .header("x-codex-window-id", format!("{sid}:0"))
                    .header("x-openai-internal-codex-residency", CODEX_RESIDENCY);
                if let Some(account_id) = req.account_id.as_deref() {
                    b = b.header("chatgpt-account-id", account_id);
                }
                b
            }
        };
        if req.stream {
            builder = builder.header(reqwest::header::ACCEPT, "text/event-stream");
        } else if let Some(timeout) = self.unary_timeout {
            // Non-streaming: bound the TOTAL request (connect + headers + body).
            // The shared client sets only connect/idle-read timeouts (so a long
            // healthy stream isn't severed), which would otherwise leave a
            // slow-drip unary response unbounded. Applied per-request so the same
            // client still serves streaming calls without a total deadline.
            builder = builder.timeout(timeout);
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| ProviderError::Transport(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            // Capture Retry-After (delta-seconds) BEFORE the body read consumes
            // `resp`. Used by the dispatcher's failover cooldown to honor a
            // provider-advertised backoff on a rate-limited credential.
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(std::time::Duration::from_secs);
            return Err(ProviderError::Status {
                status: status.as_u16(),
                retry_after,
                body: read_bounded_body(resp).await,
            });
        }

        if req.stream {
            Ok(ProviderResponse::Stream(sse::into_event_stream(resp)))
        } else {
            let mut stream = resp.bytes_stream();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk
                    .map_err(|_| ProviderError::Transport("response body interrupted".into()))?;
                if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
                    return Err(ProviderError::Protocol(format!(
                        "provider response exceeds {max_bytes}-byte limit; request a smaller response or embedding batch"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }
            let value = serde_json::from_slice(&bytes)
                .map_err(|_| ProviderError::Decode("invalid provider JSON response".into()))?;
            Ok(ProviderResponse::Unary(value))
        }
    }
}

/// Read at most [`MAX_ERROR_BODY`] bytes of a non-2xx response body, streaming
/// so an arbitrarily large (or hostile) error body is never fully buffered.
/// Bytes are lossy-decoded into a diagnostic snippet — which, unlike truncating
/// a `String` at a fixed byte offset, cannot panic on a multi-byte boundary.
async fn read_bounded_body(resp: reqwest::Response) -> String {
    let mut bytes = resp.bytes_stream();
    let mut collected: Vec<u8> = Vec::new();
    while collected.len() < MAX_ERROR_BODY {
        match bytes.next().await {
            Some(Ok(chunk)) => {
                let take = (MAX_ERROR_BODY - collected.len()).min(chunk.len());
                collected.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // hit the cap mid-chunk; stop reading the rest
                }
            }
            // Best-effort: the status is already known, so stop on error or EOF.
            Some(Err(_)) | None => break,
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

#[cfg(test)]
mod tests {
    use super::session_id_for_bearer;

    #[test]
    fn session_id_is_stable_per_bearer_and_distinct_across_bearers() {
        // The fingerprint-critical property: one credential = one stable CLI
        // session id (so a pool of credentials never shares a single id across
        // tokens — the correlation tell this replaces the old process-wide id to
        // avoid).
        let a1 = session_id_for_bearer("codex-access-AAA");
        let a2 = session_id_for_bearer("codex-access-AAA");
        let b = session_id_for_bearer("codex-access-BBB");
        assert_eq!(a1, a2, "same bearer ⇒ same stable session id");
        assert_ne!(
            a1, b,
            "distinct bearers ⇒ distinct session ids (no cross-credential sharing)"
        );
        // The id is a random UUID, never the bearer or a recoverable hash of it.
        assert_eq!(a1.len(), 36, "a hyphenated UUID");
        assert!(!a1.contains("sk-ant"), "the secret never appears in the id");
    }
}
