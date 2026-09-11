//! `waygate-llm-discovery` — fetch a provider's live model list so the
//! inference plane can populate its catalog without an operator hand-listing
//! every model.
//!
//! Transport + parse only: given an HTTP client, a resolved bearer, and the
//! target's base URL, an adapter GETs the provider's model listing and
//! normalizes it to [`DiscoveredModel`]s. It does NOT acquire or refresh
//! credentials (that is `waygate-llm-credentials`' job), and it does NOT touch
//! the catalog (the discovery refresher upserts the results). It is the thing
//! the refresher calls per credential, after a bearer has been resolved.
//!
//! ## The listing surface is keyed on (provider, auth-kind), not provider
//!
//! The model-listing endpoint, its parameters, and even its *existence* differ
//! by auth-kind — this is the crux of the inference plane's "OAuth paths are
//! different" reality:
//!
//! - **OpenRouter (api key)** lists chat models from `/api/v1/models` and
//!   embeddings models from the dedicated `/api/v1/embeddings/models`
//!   ([`list_openrouter_embeddings`]); it is the only provider whose listing
//!   carries pricing.
//! - **OpenAI Codex (subscription OAuth)** lists from the Codex CLI backend
//!   (`chatgpt.com/backend-api/codex/models`), which requires the Codex CLI
//!   fingerprint (`Originator` + `User-Agent`) and a `client_version` — NOT the
//!   public `api.openai.com/v1/models` an OpenAI api-key would use. The backend
//!   scopes the returned models to what that CLI release may see (an old
//!   version gets an old subset; an ancient one an empty list), so the
//!   refresher resolves a current version via [`CodexVersionTracker`] rather
//!   than trusting a compile-time pin.
//! - **Anthropic (`x-api-key`)** — discovery is unwired; its models stay
//!   operator-pinned. (`/v1/models` is an `x-api-key` endpoint, so listing is
//!   technically reachable, but the refresher arm is not built.)
//! - **Google / Gemini (OAuth)** lists only from a provider-specific internal
//!   endpoint whose shape depends on the OAuth flavor; left unwired here
//!   (mapped to [`DiscoverySurface::Unsupported`]) until it can be verified
//!   against the gateway's actual Google credential rather than guessed.
//!
//! [`DiscoverySurface::for_provider`] encodes that mapping; an `Unsupported`
//! surface is a normal outcome the refresher skips, not an error.

use std::str::FromStr;

use rust_decimal::Decimal;
use serde::Deserialize;

pub mod codex_version;
pub use codex_version::{is_valid_codex_client_version, CodexVersionTracker};

/// Per-MILLION-token rates (the unit the `llm_models` catalog stores), in
/// `currency`. Only OpenRouter publishes pricing in its listing today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPricing {
    pub input_per_mtok: Option<Decimal>,
    pub output_per_mtok: Option<Decimal>,
    pub cached_read_per_mtok: Option<Decimal>,
    pub cache_write_per_mtok: Option<Decimal>,
    pub currency: String,
}

/// One model from a provider's listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredModel {
    /// Upstream model id — the value a client sends as `model` and the catalog's
    /// `upstream_model`.
    pub id: String,
    /// Provider-published pricing when the listing carries it (OpenRouter), else
    /// `None`. `None` even for a listing *with* a pricing object whose every
    /// rate is absent/unparseable.
    pub pricing: Option<DiscoveredPricing>,
    /// `true` when this model came from a provider's **embeddings** listing
    /// (today: OpenRouter's dedicated `/embeddings/models`). The discovery
    /// refresher tags such a row `upstream_api = embeddings` so the resolver
    /// routes it as an embeddings operation; `false` ⇒ a chat-family model.
    pub is_embeddings: bool,
}

/// Failure modes of a listing fetch. Normalized so the refresher maps every
/// provider to one error surface.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Connect/TLS/read failure, or a body that could not be read.
    #[error("transport error: {0}")]
    Transport(String),
    /// A non-2xx response. `body` is a bounded snippet for diagnostics.
    #[error("provider returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    /// A 2xx body that did not parse as the expected listing shape.
    #[error("invalid JSON listing: {0}")]
    Decode(String),
}

/// The model-listing surface a credential maps to — which adapter (if any)
/// fetches its models. Distinct from the chat provider/auth because the listing
/// endpoint and its availability differ by auth-kind (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySurface {
    /// OpenRouter `/api/v1/models` (api key); carries pricing.
    OpenRouter,
    /// OpenAI Codex backend `/models` (subscription OAuth); no pricing.
    Codex,
    /// No wired listing endpoint — the refresher skips this credential and its
    /// models stay operator-pinned. Anthropic (first-party `x-api-key`; its
    /// `/v1/models` adapter is unwired), Google/Gemini OAuth, and a (currently
    /// unused) plain OpenAI api key all map here.
    Unsupported,
}

impl DiscoverySurface {
    /// Pick the listing surface for a `provider` (lowercase vocabulary:
    /// `openai`/`anthropic`/`google`/`openrouter`) and whether its credential is
    /// subscription OAuth. The gateway's real combos are OpenRouter-api-key and
    /// OpenAI-Codex-OAuth; everything else is [`Unsupported`](Self::Unsupported).
    pub fn for_provider(provider: &str, is_oauth: bool) -> Self {
        match (provider.to_ascii_lowercase().as_str(), is_oauth) {
            ("openrouter", false) => Self::OpenRouter,
            ("openai", true) => Self::Codex,
            _ => Self::Unsupported,
        }
    }

    /// Whether `provider` has a wired discovery adapter under *some* auth-kind.
    /// The discovery refresher's `parse_targets` runs before any credential is
    /// resolved — it has only the env config, not the credential store — so it
    /// cannot call [`Self::for_provider`] with the real `is_oauth`. This gate lets
    /// it keep a potentially-discoverable target; the refresher then resolves the
    /// credential's actual kind and calls [`Self::for_provider`] to pick the
    /// concrete surface. A target that passes this gate but whose credential maps
    /// to [`Self::Unsupported`] (e.g. `openai` with an api key, not Codex OAuth)
    /// is skipped at refresh time, not here.
    pub fn provider_has_adapter(provider: &str) -> bool {
        matches!(
            provider.to_ascii_lowercase().as_str(),
            "openrouter" | "openai"
        )
    }
}

/// Base URL of the OpenAI Codex CLI backend (the subscription-OAuth model
/// listing lives at `{base}/models`). Mirrors the Codex CLI itself; the gateway
/// uses the same so the backend accepts its subscription token.
pub const CODEX_MODELS_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
/// Compiled fallback for the `client_version` the Codex backend requires on
/// its model listing. The backend scopes the returned models to what that CLI
/// release may see, so this is a **last resort**: the refresher normally
/// resolves a current version via [`CodexVersionTracker`], and an operator can
/// pin one per target. Bump alongside notable CLI releases so the floor stays
/// useful.
pub const CODEX_DEFAULT_CLIENT_VERSION: &str = "0.144.0";
/// The Codex CLI `Originator` the backend gates the listing on.
const CODEX_ORIGINATOR: &str = "codex_cli_rs";
/// The Codex CLI `User-Agent` for a given `client_version` — the backend
/// expects the `codex_cli_rs/<ver>` prefix alongside the originator, and the
/// UA version must agree with the `client_version` query it accompanies.
fn codex_user_agent(client_version: &str) -> String {
    format!("codex_cli_rs/{client_version} (mcp-gateway model discovery)")
}

/// OpenRouter model listing: `GET {base_url}/models` with api-key Bearer auth
/// (`base_url` e.g. `https://openrouter.ai/api/v1`). Parses `data[].{id,
/// pricing}`, converting the USD-per-token pricing strings to per-Mtok rates.
pub async fn list_openrouter(
    http: &reqwest::Client,
    base_url: &str,
    bearer: &str,
) -> Result<Vec<DiscoveredModel>, DiscoveryError> {
    let url = format!("{}/models", base_url.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .bearer_auth(bearer)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| DiscoveryError::Transport(e.to_string()))?;
    let body = read_2xx_body(resp).await?;
    let parsed: OpenRouterList =
        serde_json::from_str(&body).map_err(|e| DiscoveryError::Decode(e.to_string()))?;
    Ok(parsed
        .data
        .into_iter()
        .filter(|m| !m.id.is_empty())
        .map(|m| DiscoveredModel {
            pricing: m.pricing.and_then(openrouter_pricing),
            id: m.id,
            is_embeddings: false,
        })
        .collect())
}

/// OpenRouter **embeddings** model listing: `GET {base_url}/embeddings/models`
/// with api-key Bearer auth (`base_url` e.g. `https://openrouter.ai/api/v1`).
/// This is OpenRouter's dedicated embeddings catalog and the authoritative
/// source for which models are embeddings models — the standard `/models`
/// listing ([`list_openrouter`]) is chat-shaped. Every returned model is marked
/// [`is_embeddings`](DiscoveredModel::is_embeddings) so the refresher tags its
/// catalog row `upstream_api = embeddings`. Same `data[].{id, pricing}` shape as
/// the chat listing — embeddings bill on input tokens only, but the parse is
/// identical (an absent output rate simply stays `None`).
pub async fn list_openrouter_embeddings(
    http: &reqwest::Client,
    base_url: &str,
    bearer: &str,
) -> Result<Vec<DiscoveredModel>, DiscoveryError> {
    let url = format!("{}/embeddings/models", base_url.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .bearer_auth(bearer)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| DiscoveryError::Transport(e.to_string()))?;
    let body = read_2xx_body(resp).await?;
    let parsed: OpenRouterList =
        serde_json::from_str(&body).map_err(|e| DiscoveryError::Decode(e.to_string()))?;
    Ok(parsed
        .data
        .into_iter()
        .filter(|m| !m.id.is_empty())
        .map(|m| DiscoveredModel {
            pricing: m.pricing.and_then(openrouter_pricing),
            id: m.id,
            is_embeddings: true,
        })
        .collect())
}

/// The Codex model listing: the picker-visible models plus what the raw
/// response looked like before filtering. The refresher needs the extra
/// signals to tell apart three empty-`models` cases:
///
/// - `raw_len == 0` — the backend returned nothing (the transient /
///   too-old-`client_version` case): fail-open, skip reconcile.
/// - `raw_len > 0`, `malformed_len > 0` — the payload parsed but carries
///   entries with a missing/empty `slug`: the listing cannot be trusted as
///   the complete model universe, so reconcile must be skipped (garbled
///   responses never mass-soft-disable last-good rows).
/// - `raw_len > 0`, `malformed_len == 0` — every entry was well-formed and
///   none are picker-visible: a complete answer that must reconcile,
///   soft-disabling previously discovered rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexListing {
    pub models: Vec<DiscoveredModel>,
    /// Entries in the raw response, before any filtering.
    pub raw_len: usize,
    /// Raw entries without a usable (non-empty) `slug`.
    pub malformed_len: usize,
}

/// OpenAI Codex backend model listing: `GET {base_url}/models?client_version=…`
/// with subscription-OAuth Bearer auth (`base_url` defaults to
/// [`CODEX_MODELS_BASE_URL`] in production). Sends the Codex CLI fingerprint
/// (`Originator` + `User-Agent`) the backend requires, plus `Chatgpt-Account-Id`
/// when `account_id` is known. Parses `models[].slug`; the Codex listing carries
/// no pricing.
pub async fn list_codex(
    http: &reqwest::Client,
    base_url: &str,
    bearer: &str,
    account_id: Option<&str>,
    client_version: &str,
) -> Result<CodexListing, DiscoveryError> {
    let url = reqwest::Url::parse_with_params(
        &format!("{}/models", base_url.trim_end_matches('/')),
        &[("client_version", client_version)],
    )
    .map_err(|e| DiscoveryError::Transport(e.to_string()))?;
    let mut req = http
        .get(url)
        .bearer_auth(bearer)
        .header(reqwest::header::ACCEPT, "application/json")
        .header("Originator", CODEX_ORIGINATOR)
        .header(
            reqwest::header::USER_AGENT,
            codex_user_agent(client_version),
        );
    if let Some(acct) = account_id {
        req = req.header("Chatgpt-Account-Id", acct);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| DiscoveryError::Transport(e.to_string()))?;
    let body = read_2xx_body(resp).await?;
    let parsed: CodexList =
        serde_json::from_str(&body).map_err(|e| DiscoveryError::Decode(e.to_string()))?;
    let raw_len = parsed.models.len();
    // An entry without a usable slug is MALFORMED, not merely filtered: it is
    // counted separately so the refresher can treat the whole listing as
    // incomplete (garbled) rather than as an authoritative "no visible
    // models" answer.
    let malformed_len = parsed.models.iter().filter(|m| m.slug.is_empty()).count();
    let models = parsed
        .models
        .into_iter()
        // Only picker-visible models become catalog rows: `visibility` values
        // other than "list" (e.g. "hide" on internal models like
        // codex-auto-review, or a future value with unknown semantics) mark
        // models the vendor does not offer to users, and exposing them as
        // routable aliases would surface internal/unsupported models. Mirrors
        // the reference CLI's picker (`visibility == list`). A previously
        // discovered model that turns hidden drops out of the seen-set and is
        // soft-disabled by the normal reconcile — never deleted.
        .filter(|m| !m.slug.is_empty() && m.visibility == "list")
        .map(|m| DiscoveredModel {
            id: m.slug,
            pricing: None,
            is_embeddings: false,
        })
        .collect();
    Ok(CodexListing {
        models,
        raw_len,
        malformed_len,
    })
}

/// Hard cap on the bytes buffered from a provider's listing response. A real
/// listing is well under this (OpenRouter's ~300-model list is a few hundred
/// KB); the cap exists so a buggy or hostile upstream — error page or response —
/// cannot grow memory without bound when this runs on a recurring refresher. A
/// legitimate listing that somehow exceeds it is truncated and then fails to
/// parse (a clean Decode error the refresher skips), never silently partial.
const MAX_LISTING_BODY: usize = 8 * 1024 * 1024;

/// Read a response body up to [`MAX_LISTING_BODY`] (streaming, so an oversized
/// body is never fully buffered), mapping a non-2xx status to
/// [`DiscoveryError::Status`] with a bounded snippet and a transport failure to
/// [`DiscoveryError::Transport`].
async fn read_2xx_body(resp: reqwest::Response) -> Result<String, DiscoveryError> {
    read_body_capped(resp, MAX_LISTING_BODY).await
}

/// Read at most `cap` bytes of a response body by streaming chunks and stopping
/// once the cap is reached — a hostile/buggy upstream can never make this buffer
/// more than `cap`. A non-2xx status maps to [`DiscoveryError::Status`] with a
/// bounded snippet; a read failure to [`DiscoveryError::Transport`].
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<String, DiscoveryError> {
    let status = resp.status();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| DiscoveryError::Transport(e.to_string()))?
    {
        let take = (cap - buf.len()).min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if buf.len() >= cap {
            break; // stop reading — never buffer past the cap
        }
    }
    let body = String::from_utf8_lossy(&buf).into_owned();
    if !status.is_success() {
        return Err(DiscoveryError::Status {
            status: status.as_u16(),
            body: bounded(&body),
        });
    }
    Ok(body)
}

/// Build [`DiscoveredPricing`] from an OpenRouter pricing object, or `None` when
/// no rate is usable (so a pricing object of all-absent rates does not produce a
/// currency-only pricing the refresher would have nothing to fill).
fn openrouter_pricing(p: OpenRouterPricing) -> Option<DiscoveredPricing> {
    let input = per_mtok(p.prompt.as_deref());
    let output = per_mtok(p.completion.as_deref());
    let cached_read = per_mtok(p.input_cache_read.as_deref());
    let cache_write = per_mtok(p.input_cache_write.as_deref());
    if input.is_none() && output.is_none() && cached_read.is_none() && cache_write.is_none() {
        return None;
    }
    Some(DiscoveredPricing {
        input_per_mtok: input,
        output_per_mtok: output,
        cached_read_per_mtok: cached_read,
        cache_write_per_mtok: cache_write,
        currency: "USD".to_string(),
    })
}

/// A USD-per-token decimal string → per-MILLION-token [`Decimal`]. `None` for an
/// absent/empty/unparseable value, or a negative one (the catalog rejects
/// negative rates, and a negative price is nonsensical).
fn per_mtok(s: Option<&str>) -> Option<Decimal> {
    let s = s?.trim();
    if s.is_empty() {
        return None;
    }
    let v = Decimal::from_str(s).ok()?;
    if v.is_sign_negative() {
        return None;
    }
    Some(v * Decimal::from(1_000_000))
}

/// Bound an error-body snippet (by chars, so never on a UTF-8 boundary) so a
/// huge/hostile error page cannot bloat a log line.
fn bounded(body: &str) -> String {
    const MAX: usize = 512;
    let snipped: String = body.chars().take(MAX).collect();
    if snipped.len() < body.len() {
        format!("{snipped}…")
    } else {
        snipped
    }
}

#[derive(Deserialize)]
struct OpenRouterList {
    #[serde(default)]
    data: Vec<OpenRouterModel>,
}

#[derive(Deserialize)]
struct OpenRouterModel {
    id: String,
    #[serde(default)]
    pricing: Option<OpenRouterPricing>,
}

#[derive(Deserialize)]
struct OpenRouterPricing {
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    completion: Option<String>,
    #[serde(default)]
    input_cache_read: Option<String>,
    #[serde(default)]
    input_cache_write: Option<String>,
}

#[derive(Deserialize)]
struct CodexList {
    #[serde(default)]
    models: Vec<CodexModel>,
}

#[derive(Deserialize)]
struct CodexModel {
    #[serde(default)]
    slug: String,
    /// The backend's picker visibility for this model. `"list"` is the only
    /// value that means "offer this to users" — the reference CLI shows a
    /// model in its picker iff `visibility == list`. Absent defaults to
    /// `"list"` (a listing shape without the field hides nothing).
    #[serde(default = "codex_visibility_list")]
    visibility: String,
}

fn codex_visibility_list() -> String {
    "list".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn raw_test_http_client() -> reqwest::Client {
        reqwest::Client::new() // A raw test client isolates provider wire behavior from gateway policy.
    }

    #[test]
    fn per_mtok_converts_and_rejects_bad_values() {
        // USD-per-token → per-million-token (×1e6).
        assert_eq!(
            per_mtok(Some("0.0000014")),
            Some(Decimal::from_str("1.4").unwrap())
        );
        assert_eq!(
            per_mtok(Some("0")),
            Some(Decimal::ZERO),
            "free is a real 0 rate"
        );
        assert_eq!(
            per_mtok(Some("  0.000003 ")),
            Some(Decimal::from_str("3").unwrap())
        );
        assert_eq!(per_mtok(None), None);
        assert_eq!(per_mtok(Some("")), None);
        assert_eq!(per_mtok(Some("not-a-number")), None);
        assert_eq!(per_mtok(Some("-0.001")), None, "negative rate rejected");
    }

    #[test]
    fn surface_maps_provider_and_auth_kind() {
        use DiscoverySurface as S;
        assert_eq!(S::for_provider("openrouter", false), S::OpenRouter);
        assert_eq!(
            S::for_provider("OpenRouter", false),
            S::OpenRouter,
            "case-insensitive"
        );
        assert_eq!(S::for_provider("openai", true), S::Codex);
        // OpenAI *api key* (not OAuth) has no wired adapter; Anthropic (api key),
        // Google OAuth, and unknown providers are Unsupported.
        assert_eq!(S::for_provider("openai", false), S::Unsupported);
        assert_eq!(S::for_provider("anthropic", false), S::Unsupported);
        assert_eq!(S::for_provider("google", true), S::Unsupported);
        assert_eq!(S::for_provider("whatever", false), S::Unsupported);
    }

    #[test]
    fn provider_has_adapter_gates_parse_time_targets() {
        use DiscoverySurface as S;
        // The two providers with a wired adapter under SOME auth-kind pass the
        // parse-time gate regardless of (unknown-at-parse) auth-kind.
        assert!(S::provider_has_adapter("openrouter"));
        assert!(S::provider_has_adapter("openai"));
        assert!(S::provider_has_adapter("OpenAI"), "case-insensitive");
        // Providers with no wired adapter at all are dropped at parse time.
        assert!(!S::provider_has_adapter("anthropic"));
        assert!(!S::provider_has_adapter("google"));
        assert!(!S::provider_has_adapter("whatever"));
    }

    // --- loopback adapter tests (no real network / credentials) --------------

    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::get;
    use axum::Router;

    /// Serve `app` on an ephemeral loopback port; return its base URL.
    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    const OPENROUTER_BODY: &str = r#"{
      "data": [
        {"id": "z-ai/glm-5.2",
         "pricing": {"prompt": "0.0000014", "completion": "0.0000044", "input_cache_read": "0.00000026"}},
        {"id": "vendor/free", "pricing": {"prompt": "0", "completion": "0"}},
        {"id": "vendor/no-pricing"},
        {"id": ""}
      ]
    }"#;

    const OPENROUTER_EMBEDDINGS_BODY: &str = r#"{
      "data": [
        {"id": "openai/text-embedding-3-small", "pricing": {"prompt": "0.00000002"}},
        {"id": "openai/text-embedding-3-large", "pricing": {"prompt": "0.00000013"}},
        {"id": ""}
      ]
    }"#;

    #[tokio::test]
    async fn openrouter_parses_models_and_converts_pricing() {
        let app = Router::new().route(
            "/api/v1/models",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    OPENROUTER_BODY,
                )
            }),
        );
        let base = format!("{}/api/v1", serve(app).await);
        let models = list_openrouter(&raw_test_http_client(), &base, "sk-test")
            .await
            .expect("list");

        // Empty-id row filtered; three real models, ordered as served.
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["z-ai/glm-5.2", "vendor/free", "vendor/no-pricing"]
        );
        assert!(
            models.iter().all(|m| !m.is_embeddings),
            "the chat /models listing never marks a model is_embeddings"
        );

        // Pricing converted USD-per-token → per-Mtok.
        let p = models[0].pricing.as_ref().expect("priced");
        assert_eq!(p.input_per_mtok, Some(Decimal::from_str("1.4").unwrap()));
        assert_eq!(p.output_per_mtok, Some(Decimal::from_str("4.4").unwrap()));
        assert_eq!(
            p.cached_read_per_mtok,
            Some(Decimal::from_str("0.26").unwrap())
        );
        assert_eq!(
            p.cache_write_per_mtok, None,
            "absent cache-write rate stays None"
        );
        assert_eq!(p.currency, "USD");

        // A free model is priced at 0 (not None).
        assert_eq!(
            models[1].pricing.as_ref().unwrap().input_per_mtok,
            Some(Decimal::ZERO)
        );
        // A model with no pricing object carries no pricing.
        assert!(models[2].pricing.is_none());
    }

    #[tokio::test]
    async fn openrouter_non_2xx_is_a_status_error() {
        let app = Router::new().route(
            "/api/v1/models",
            get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "upstream boom") }),
        );
        let base = format!("{}/api/v1", serve(app).await);
        let err = list_openrouter(&raw_test_http_client(), &base, "sk-test")
            .await
            .expect_err("5xx is an error");
        match err {
            DiscoveryError::Status { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("upstream boom"));
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn openrouter_embeddings_lists_and_marks_is_embeddings() {
        let app = Router::new().route(
            "/api/v1/embeddings/models",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    OPENROUTER_EMBEDDINGS_BODY,
                )
            }),
        );
        let base = format!("{}/api/v1", serve(app).await);
        let models = list_openrouter_embeddings(&raw_test_http_client(), &base, "sk-test")
            .await
            .expect("list");

        // Empty-id row filtered; both real embeddings models, ordered as served.
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "openai/text-embedding-3-small",
                "openai/text-embedding-3-large"
            ]
        );
        // Every model from the dedicated embeddings listing is marked embeddings —
        // this is the signal the refresher uses to tag `upstream_api = embeddings`.
        assert!(
            models.iter().all(|m| m.is_embeddings),
            "the /embeddings/models listing marks every model is_embeddings"
        );
        // Input-token pricing parses the same way as chat (USD/token ×1e6 → per-Mtok).
        assert_eq!(
            models[0].pricing.as_ref().expect("priced").input_per_mtok,
            Some(Decimal::from_str("0.02").unwrap())
        );
    }

    #[tokio::test]
    async fn openrouter_embeddings_non_2xx_is_a_status_error() {
        let app = Router::new().route(
            "/api/v1/embeddings/models",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "embeddings catalog down") }),
        );
        let base = format!("{}/api/v1", serve(app).await);
        let err = list_openrouter_embeddings(&raw_test_http_client(), &base, "sk-test")
            .await
            .expect_err("5xx is an error");
        match err {
            DiscoveryError::Status { status, .. } => assert_eq!(status, 503),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn body_read_is_capped() {
        // A provider that returns far more than the cap must not be fully
        // buffered: the read stops at `cap` bytes.
        let app = Router::new().route("/big", get(|| async { "x".repeat(4096) }));
        let base = serve(app).await;
        let resp = raw_test_http_client()
            .get(format!("{base}/big"))
            .send()
            .await
            .unwrap();
        let body = read_body_capped(resp, 1024).await.expect("ok body");
        assert_eq!(body.len(), 1024, "the body read is bounded at the cap");
    }

    /// Records the headers + query of the last request the codex fake saw.
    #[derive(Default)]
    struct Seen {
        originator: Option<String>,
        user_agent: Option<String>,
        account: Option<String>,
        client_version: Option<String>,
        authorization: Option<String>,
    }

    #[tokio::test]
    async fn codex_sends_cli_fingerprint_and_parses_slugs() {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let app = Router::new()
            .route(
                "/models",
                get(
                    |State(seen): State<Arc<Mutex<Seen>>>,
                     headers: HeaderMap,
                     Query(q): Query<std::collections::HashMap<String, String>>| async move {
                        let hv = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(String::from);
                        *seen.lock().unwrap() = Seen {
                            originator: hv("originator"),
                            user_agent: hv("user-agent"),
                            account: hv("chatgpt-account-id"),
                            client_version: q.get("client_version").cloned(),
                            authorization: hv("authorization"),
                        };
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            r#"{"models":[{"slug":"gpt-5.5"},{"slug":"gpt-5.5-codex"},{"slug":""}]}"#,
                        )
                    },
                ),
            )
            .with_state(seen.clone());
        let base = serve(app).await;

        let listing = list_codex(
            &raw_test_http_client(),
            &base,
            "oauth-token",
            Some("acct-123"),
            CODEX_DEFAULT_CLIENT_VERSION,
        )
        .await
        .expect("list");

        // Empty slug filtered; ids come from `slug`. raw_len counts the
        // pre-filter listing (including the empty-slug entry).
        let ids: Vec<&str> = listing.models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["gpt-5.5", "gpt-5.5-codex"]);
        assert_eq!(listing.raw_len, 3);
        assert_eq!(
            listing.malformed_len, 1,
            "the empty-slug entry counts as malformed, not merely filtered"
        );
        assert!(
            listing.models.iter().all(|m| m.pricing.is_none()),
            "codex listing has no pricing"
        );

        // The request carried the Codex CLI fingerprint the backend gates on —
        // this is the contract that distinguishes the OAuth path from a plain
        // api-key GET.
        let s = seen.lock().unwrap();
        assert_eq!(s.originator.as_deref(), Some(CODEX_ORIGINATOR));
        // The UA version agrees with the client_version query it accompanies.
        assert_eq!(
            s.user_agent.as_deref(),
            Some(codex_user_agent(CODEX_DEFAULT_CLIENT_VERSION).as_str())
        );
        assert_eq!(s.account.as_deref(), Some("acct-123"));
        assert_eq!(
            s.client_version.as_deref(),
            Some(CODEX_DEFAULT_CLIENT_VERSION)
        );
        assert_eq!(s.authorization.as_deref(), Some("Bearer oauth-token"));
    }

    #[tokio::test]
    async fn codex_listing_keeps_only_picker_visible_models() {
        // The live listing mixes picker-visible models with internal ones
        // (`visibility: "hide"`, e.g. codex-auto-review). Only `"list"`
        // becomes a catalog row; an unknown future visibility value is
        // conservatively skipped, and an ABSENT field defaults to visible
        // (a listing shape without the field hides nothing).
        const BODY: &str = r#"{"models":[
            {"slug":"gpt-visible","visibility":"list"},
            {"slug":"codex-auto-review","visibility":"hide"},
            {"slug":"gpt-mystery","visibility":"beta"},
            {"slug":"gpt-no-visibility-field"}
        ]}"#;
        let app = Router::new().route(
            "/models",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    BODY,
                )
            }),
        );
        let base = serve(app).await;
        let listing = list_codex(
            &raw_test_http_client(),
            &base,
            "oauth-token",
            None,
            CODEX_DEFAULT_CLIENT_VERSION,
        )
        .await
        .expect("list");
        let ids: Vec<&str> = listing.models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["gpt-visible", "gpt-no-visibility-field"]);
        assert_eq!(
            listing.raw_len, 4,
            "raw_len counts the whole upstream listing, so an all-filtered \
             response is distinguishable from an empty one"
        );
        assert_eq!(
            listing.malformed_len, 0,
            "visibility-filtered entries are well-formed, not malformed"
        );
    }

    #[tokio::test]
    async fn codex_listing_counts_slugless_entries_as_malformed() {
        // A payload that PARSES but carries no usable slugs (`{"models":[{}]}`)
        // is a garbled response, not an authoritative "no models" answer — the
        // malformed count is what lets the refresher keep last-good rows
        // instead of mass-soft-disabling on it.
        let app = Router::new().route(
            "/models",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    r#"{"models":[{}]}"#,
                )
            }),
        );
        let base = serve(app).await;
        let listing = list_codex(
            &raw_test_http_client(),
            &base,
            "oauth-token",
            None,
            CODEX_DEFAULT_CLIENT_VERSION,
        )
        .await
        .expect("list");
        assert!(listing.models.is_empty());
        assert_eq!(listing.raw_len, 1);
        assert_eq!(listing.malformed_len, 1);
    }
}
