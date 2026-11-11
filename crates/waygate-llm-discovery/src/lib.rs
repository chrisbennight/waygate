//! `waygate-llm-discovery` — fetch a provider's live model list so the
//! inference plane can populate its catalog without an operator hand-listing
//! every model.
//!
//! Transport + parse only: given an HTTP client, a resolved bearer, and the
//! target's base URL, an adapter GETs the provider's model listing and
//! normalizes it to [`DiscoveredModel`]s. It does NOT acquire or refresh
//! credentials (the injected API-key store owns that boundary), and it does NOT touch
//! the catalog (the discovery refresher upserts the results). It is the thing
//! the refresher calls per credential, after a bearer has been resolved.
//!
//! ## Supported provider API listing surfaces
//!
//! - **OpenRouter (api key)** lists chat models from `/api/v1/models` and
//!   embeddings models from the dedicated `/api/v1/embeddings/models`
//!   ([`list_openrouter_embeddings`]); it is the only provider whose listing
//!   carries pricing.
//! - **OpenAI API (API key)** lists from `/v1/models`. The listing has no
//!   endpoint or modality metadata, so operators explicitly select which IDs
//!   may be discovered as Responses models. Other operations remain pinned.
//! - **Anthropic (`x-api-key`)** — discovery is unwired; its models stay
//!   operator-pinned. (`/v1/models` is an `x-api-key` endpoint, so listing is
//!   technically reachable, but the refresher arm is not built.)
//! - **Google / Gemini (API key)** uses the documented `/v1beta/models` listing
//!   with bounded pagination. Selected text/function models must advertise
//!   generateContent; consumer OAuth discovery remains unsupported.
//!
//! [`DiscoverySurface::for_provider`] encodes that mapping; an `Unsupported`
//! surface is a normal outcome the refresher skips, not an error.

use std::str::FromStr;

use rust_decimal::Decimal;
use serde::Deserialize;

mod gemini;
pub use gemini::{list_gemini, GeminiListing};

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
    /// OpenAI public API `/v1/models` (API key); no pricing or modality.
    OpenAiApi,
    /// Documented Gemini Developer API `/v1beta/models`, with an API key.
    GoogleApi,
    /// No wired listing endpoint — the refresher skips this credential and its
    /// models stay operator-pinned. Anthropic (first-party `x-api-key`; its
    /// `/v1/models` adapter is unwired) maps here.
    Unsupported,
}

impl DiscoverySurface {
    /// Pick the supported provider API listing. Consumer credentials are
    /// rejected by credential loading, not negotiated as another surface.
    pub fn for_provider(provider: &str) -> Self {
        match provider.to_ascii_lowercase().as_str() {
            "openrouter" => Self::OpenRouter,
            "openai" => Self::OpenAiApi,
            "google" => Self::GoogleApi,
            _ => Self::Unsupported,
        }
    }

    /// Whether the provider has a supported API discovery adapter.
    pub fn provider_has_adapter(provider: &str) -> bool {
        matches!(
            provider.to_ascii_lowercase().as_str(),
            "openrouter" | "openai" | "google"
        )
    }
}

/// Public API listing after applying an operator's Responses model selection.
pub struct OpenAiListing {
    pub models: Vec<DiscoveredModel>,
    /// Distinguishes a transient empty provider response from a complete
    /// listing in which none of the configured Responses models remain.
    pub raw_len: usize,
}

/// List official API models with ordinary Bearer authentication. Selection is
/// explicit because the API does not identify a model's supported operations.
pub async fn list_openai(
    http: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    responses_models: &[String],
) -> Result<OpenAiListing, DiscoveryError> {
    let response = http
        .get(format!("{}/models", base_url.trim_end_matches('/')))
        .bearer_auth(api_key)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
    let body = read_2xx_body(response).await.map_err(|error| match error {
        DiscoveryError::Status { status, .. } => DiscoveryError::Status {
            status,
            body: "response body withheld".into(),
        },
        other => other,
    })?;
    let listing: OpenAiModels =
        serde_json::from_str(&body).map_err(|error| DiscoveryError::Decode(error.to_string()))?;
    if listing.data.iter().any(|model| model.id.trim().is_empty()) {
        return Err(DiscoveryError::Decode("model ID is empty".into()));
    }
    let raw_len = listing.data.len();
    let models = listing
        .data
        .into_iter()
        .filter(|model| responses_models.contains(&model.id))
        .map(|model| DiscoveredModel {
            id: model.id,
            pricing: None,
            is_embeddings: false,
        })
        .collect();
    Ok(OpenAiListing { models, raw_len })
}

#[derive(Deserialize)]
struct OpenAiModels {
    data: Vec<OpenAiModel>,
}

#[derive(Deserialize)]
struct OpenAiModel {
    id: String,
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
    fn surface_maps_supported_provider_apis() {
        use DiscoverySurface as S;
        assert_eq!(S::for_provider("openrouter"), S::OpenRouter);
        assert_eq!(
            S::for_provider("OpenRouter"),
            S::OpenRouter,
            "case-insensitive"
        );
        assert_eq!(S::for_provider("openai"), S::OpenAiApi);
        assert_eq!(S::for_provider("anthropic"), S::Unsupported);
        assert_eq!(S::for_provider("google"), S::GoogleApi);
        assert_eq!(S::for_provider("whatever"), S::Unsupported);
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
        assert!(S::provider_has_adapter("google"));
        assert!(!S::provider_has_adapter("whatever"));
    }

    // --- loopback adapter tests (no real network / credentials) --------------

    use std::net::SocketAddr;

    use axum::extract::Query;
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

    #[tokio::test]
    async fn openai_listing_selects_only_configured_responses_models_without_cli_identity() {
        let base = serve(Router::new().route(
            "/v1/models",
            get(
                |headers: HeaderMap,
                 Query(query): Query<std::collections::HashMap<String, String>>| async move {
                    assert_eq!(headers["authorization"], "Bearer synthetic-api-key");
                    assert!(!headers.contains_key("originator"));
                    assert!(!headers.contains_key("chatgpt-account-id"));
                    assert!(query.is_empty());
                    axum::Json(serde_json::json!({"data":[
                        {"id":"selected-response-model"}, {"id":"gpt-image-2"},
                        {"id":"an-unknown-future-model"}
                    ]}))
                },
            ),
        ))
        .await;
        let selected = vec!["selected-response-model".into()];
        let listing = list_openai(
            &raw_test_http_client(),
            &format!("{base}/v1"),
            "synthetic-api-key",
            &selected,
        )
        .await
        .unwrap();
        assert_eq!(listing.raw_len, 3);
        assert_eq!(listing.models.len(), 1);
        assert_eq!(listing.models[0].id, selected[0]);
        assert!(listing.models[0].pricing.is_none());
        assert!(!listing.models[0].is_embeddings);
    }

    #[tokio::test]
    async fn openai_listing_distinguishes_empty_selection_and_rejects_malformed_lists() {
        for (body, expected) in [
            (r#"{"data":[{"id":"other-model"}]}"#, Some(1)),
            (r#"{"data":[]}"#, Some(0)),
            (r#"{"data":[{"id":""}]}"#, None),
            (r#"{"data":[{}]}"#, None),
            (r#"{}"#, None),
        ] {
            let base =
                serve(Router::new().route("/models", get(move || async move { body }))).await;
            let result = list_openai(
                &raw_test_http_client(),
                &base,
                "synthetic-api-key",
                &["selected".into()],
            )
            .await;
            if let Some(raw_len) = expected {
                let listing = result.unwrap();
                assert_eq!(listing.raw_len, raw_len);
                assert!(listing.models.is_empty());
            } else {
                assert!(matches!(result, Err(DiscoveryError::Decode(_))));
            }
        }
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
}
