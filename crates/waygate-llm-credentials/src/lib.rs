//! `waygate-llm-credentials` — provider credential management for the
//! inference plane.
//!
//! Credentials are **injected** into the process environment by Infisical as
//! `LLM_CRED_<PROVIDER>_<LABEL>` variables (invariant I4 in
//! `docs/inference-plane.md`): this crate reads them, holds them in memory,
//! and — for subscription-OAuth providers — refreshes the access token
//! in-process before it expires. It deliberately does **not**:
//!
//! - call Infisical (there is no Infisical client here — injection is
//!   one-way, infra → container), nor
//! - write a refreshed token back anywhere (rotation re-seeding is an
//!   out-of-band concern on the seeding host; see design §5/§6).
//!
//! ## Naming
//!
//! `LLM_CRED_<PROVIDER>_<LABEL>` — `<PROVIDER>` is one of `OPENAI`,
//! `ANTHROPIC`, `GOOGLE` (alias `GEMINI`), `OPENROUTER`; `<LABEL>` is an
//! operator-meaningful account name (`PRIMARY`, `FAMILY`, …). The set of
//! labels for a provider is that provider's pool. Example:
//! `LLM_CRED_OPENAI_PRIMARY`, `LLM_CRED_OPENROUTER_MAIN`.
//!
//! ## Value shape
//!
//! - **Subscription (OAuth) providers** (OpenAI, Google) inject a JSON blob. Two
//!   shapes are accepted (see `parse_oauth_blob`), so the raw harness credential
//!   files that `ai-credential-refresh` mirrors into Infisical work verbatim:
//!   - canonical — `{"tokens":{"access_token","refresh_token","id_token"?},"expires_at":"<RFC3339>"}`;
//!   - Codex (`~/.codex/auth.json`) — the same `tokens` object with the expiry in
//!     the access-token JWT `exp` instead of a top-level `expires_at`.
//! - **API-key providers** (Anthropic, OpenRouter) inject the bare key string.
//!
//! ## Refresh
//!
//! [`LlmCredentialStore::bearer`] returns a currently-valid bearer token. For
//! an OAuth credential within [`DEFAULT_REFRESH_SKEW`] of expiry (or with an
//! unknown expiry) it performs a refresh against the provider's token
//! endpoint while **holding the per-credential lock**, so concurrent callers
//! coalesce onto a single in-flight refresh (single-flight) rather than each
//! hitting the endpoint. A credential whose refresh keeps failing past
//! [`DEFAULT_STALENESS`] while its access token is already expired is reported
//! [`Health::Stale`] and refused.
//!
//! ## OAuth client configuration
//!
//! Each OAuth provider has a built-in refresh config (token endpoint + the
//! public CLI `client_id` it authenticates as): OpenAI and Google ship one
//! (Anthropic is an `x-api-key` provider — no OAuth/refresh). A deployment can
//! inject or override any field — without a code change, and crucially keeping
//! secrets out of source (invariant I4) — via environment variables:
//!
//! - `LLM_OAUTH_<PROVIDER>_CLIENT_SECRET` — e.g. Google's installed-app refresh
//!   requires a `client_secret` in the request body; it is injected here, never
//!   committed.
//! - `LLM_OAUTH_<PROVIDER>_CLIENT_ID` / `LLM_OAUTH_<PROVIDER>_TOKEN_URL` —
//!   override the built-in client_id / token endpoint.
//!
//! `<PROVIDER>` is the same token set as `LLM_CRED_*` (`GEMINI` aliases
//! `GOOGLE`). Overrides apply only to providers that already have a built-in
//! default; they never register a brand-new provider from env alone.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use waygate_core::http_client::{self, Profile};

/// Refresh an OAuth access token when it is within this window of expiry.
pub const DEFAULT_REFRESH_SKEW: Duration = Duration::from_secs(120);
/// A credential whose refresh has been failing for longer than this — while
/// its access token is already expired — is reported [`Health::Stale`].
pub const DEFAULT_STALENESS: Duration = Duration::from_secs(15 * 60);
/// The LLM providers the inference plane fronts. The `as_str` forms are the
/// canonical provider identifiers used in metrics, audit, and catalog rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    OpenAi,
    Anthropic,
    Google,
    OpenRouter,
}

impl LlmProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::OpenRouter => "openrouter",
        }
    }

    /// Parse a canonical provider identifier — the exact `as_str` form
    /// (`"openai"`, `"anthropic"`, `"google"`, `"openrouter"`). The inverse of
    /// [`as_str`](Self::as_str), used to rehydrate a provider persisted as text
    /// (e.g. the completion cache's serving provider). Returns `None` for any
    /// other string; callers fall back rather than guess.
    pub fn from_canonical_str(s: &str) -> Option<Self> {
        match s {
            "openai" => Some(Self::OpenAi),
            "anthropic" => Some(Self::Anthropic),
            "google" => Some(Self::Google),
            "openrouter" => Some(Self::OpenRouter),
            _ => None,
        }
    }

    /// Parse a provider token from operator-facing configuration
    /// (case-insensitive). `GEMINI` is accepted as an alias for `GOOGLE`. This
    /// is the single shared vocabulary for the `<PROVIDER>` segment of an
    /// `LLM_CRED_*` env key *and* the `provider` field of the
    /// `GATEWAY_LLM_CRED_RELOAD` mapping, so the two accept identical strings by
    /// construction. Distinct from [`from_canonical_str`](Self::from_canonical_str),
    /// which round-trips the exact `as_str` form for persisted state and does
    /// not honor the `GEMINI` alias.
    pub fn from_env_token(token: &str) -> Option<Self> {
        match token.to_ascii_uppercase().as_str() {
            "OPENAI" => Some(Self::OpenAi),
            "ANTHROPIC" => Some(Self::Anthropic),
            "GOOGLE" | "GEMINI" => Some(Self::Google),
            "OPENROUTER" => Some(Self::OpenRouter),
            _ => None,
        }
    }

    /// Whether this provider authenticates with a subscription-OAuth token
    /// blob (`true`) or a bare API key (`false`). Determines how an injected
    /// credential value is parsed and validated.
    fn is_oauth(self) -> bool {
        // Anthropic is a bare API-key provider (`x-api-key`); the prior
        // subscription-OAuth/Claude-Code path was removed (ToS/ban risk).
        matches!(self, Self::OpenAi | Self::Google)
    }
}

/// Health of a single credential, surfaced to routing and the admin/Grafana
/// credential-status views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// Loaded and (for OAuth) a non-expired access token is available.
    Healthy,
    /// Loaded but not yet validated: an OAuth credential whose injected access
    /// token is already expired (or carries no expiry) and has not yet been
    /// refreshed in-process. The first `bearer()` call validates it. Reported
    /// instead of `Healthy` so a consumer that inspects `health()` before
    /// `bearer()` isn't misled into trusting an unvalidated credential.
    Unknown,
    /// The last refresh failed, but the credential is not yet stale.
    Failing,
    /// Refresh has been failing past the staleness threshold and the access
    /// token is expired — routing should skip this credential.
    Stale,
}

/// One configured credential's identity + current health, returned by
/// [`LlmCredentialStore::status_snapshot`] for the admin credential-status
/// panel. Carries no secret material — only the provider, the pool label, and
/// the cached [`Health`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialStatus {
    pub provider: LlmProvider,
    pub label: String,
    pub health: Health,
}

/// Failure modes surfaced by [`LlmCredentialStore::bearer`].
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("no credential configured for {provider}/{label}")]
    NotConfigured {
        provider: &'static str,
        label: String,
    },
    #[error("oauth refresh for {provider}/{label} failed: {detail}")]
    RefreshFailed {
        provider: &'static str,
        label: String,
        detail: String,
    },
    #[error("credential {provider}/{label} is stale (last success: {since})")]
    Stale {
        provider: &'static str,
        label: String,
        since: String,
    },
    #[error("no OAuth refresh config registered for provider {0}")]
    NoOAuthConfig(&'static str),
    /// An externally-refreshed credential's access token has expired and the
    /// store does not refresh it itself (an out-of-band refresher owns
    /// rotation). The re-read should have swapped in a fresh token; surfacing
    /// this rather than attempting a doomed in-process refresh on the rotated-
    /// away refresh token.
    #[error("externally-refreshed credential {provider}/{label} expired; awaiting re-read")]
    AwaitingReread {
        provider: &'static str,
        label: String,
    },
}

/// Failure modes for [`LlmCredentialStore::reload`].
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("no credential configured for {provider}/{label} to reload")]
    NotConfigured {
        provider: &'static str,
        label: String,
    },
    #[error("the reloaded value is not a valid credential for {0}")]
    Unparseable(&'static str),
}

// ----- injected blob shapes -------------------------------------------------

#[derive(Deserialize)]
struct InjectedOAuthBlob {
    tokens: InjectedTokens,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct InjectedTokens {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    id_token: Option<String>,
    /// ChatGPT/Codex workspace identifier (`~/.codex/auth.json` carries it under
    /// `tokens.account_id`). Surfaced to dispatch as the `chatgpt-account-id`
    /// header the ChatGPT backend requires. Absent on the canonical OpenAI blob.
    #[serde(default)]
    account_id: Option<String>,
}

// ----- internal credential state -------------------------------------------

#[derive(Clone)]
enum Material {
    ApiKey(String),
    OAuth(OAuthState),
}

#[derive(Clone)]
struct OAuthState {
    access_token: String,
    refresh_token: String,
    #[allow(dead_code)] // carried through refresh; reserved for dispatch use
    id_token: Option<String>,
    expires_at: Option<OffsetDateTime>,
    /// ChatGPT/Codex workspace id, surfaced via [`LlmCredentialStore::oauth_account_id`]
    /// for the `chatgpt-account-id` header. `None` for non-Codex OAuth credentials.
    account_id: Option<String>,
}

struct CredentialState {
    material: Material,
    health: Health,
    last_success: Option<OffsetDateTime>,
    /// When the current run of consecutive failures started (cleared on
    /// success). Anchors the staleness window independently of whether the
    /// credential ever refreshed successfully in-process.
    failing_since: Option<OffsetDateTime>,
    consecutive_failures: u32,
    /// `true` when this credential's token is kept fresh by an EXTERNAL refresher
    /// (`ai-credential-refresh`) and re-read into the store via [`reload`], rather
    /// than refreshed in-process. Such a credential's injected refresh token
    /// rotates out-of-band (single-use, every heartbeat), so the store must NOT
    /// attempt its own OAuth refresh — it would fail on the stale refresh token
    /// and fight the external refresher for rotation. `bearer()` therefore serves
    /// the current access token while valid and surfaces a clear "awaiting
    /// re-read" error once it expires, instead of refreshing.
    externally_refreshed: bool,
}

/// Per-provider OAuth refresh configuration: the token endpoint and the
/// client identity the refresh request authenticates as.
#[derive(Clone)]
pub struct ProviderOAuthConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

impl ProviderOAuthConfig {
    /// Built-in default for OpenAI (ChatGPT / Codex subscription), using the
    /// Codex CLI's public OAuth client. The other OAuth provider, Google, has
    /// its own [`ProviderOAuthConfig::google_default`]; tests override any of
    /// these via [`LlmCredentialStore::with_oauth_config`].
    fn openai_default() -> Self {
        Self {
            token_url: "https://auth.openai.com/oauth/token".to_string(),
            client_id: "app_EMoamEEZ73f0CkXaXp7hrann".to_string(),
            client_secret: None,
        }
    }

    /// Built-in default for Google (Gemini CLI / Code Assist subscription),
    /// scaffolded with the Gemini CLI's public installed-app `client_id` and
    /// Google's token endpoint (both non-secret, mirroring how OpenAI's public
    /// client_id is hardcoded above). Google's installed-app refresh ALSO needs
    /// a `client_secret` in the (form-urlencoded) request body — that secret is
    /// deliberately NOT in source: the deployment injects it via
    /// `LLM_OAUTH_GOOGLE_CLIENT_SECRET` (invariant I4, credentials are injected,
    /// never sourced). Until it is injected, Google's config is registered but
    /// secret-less, so a refresh attempt surfaces a provider error rather than
    /// `NoOAuthConfig`. The request encoding is exactly what `refresh_locked`
    /// already sends, so Google needs no special-casing beyond this config.
    fn google_default() -> Self {
        Self {
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            client_id: "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
                .to_string(),
            client_secret: None,
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// In-memory store of injected LLM provider credentials with in-process OAuth
/// refresh. Cheap to wrap in an `Arc` and share; all per-credential mutation
/// happens behind a per-credential async lock.
pub struct LlmCredentialStore {
    creds: HashMap<(LlmProvider, String), Arc<Mutex<CredentialState>>>,
    oauth: HashMap<LlmProvider, ProviderOAuthConfig>,
    http: reqwest::Client,
    refresh_skew: Duration,
    staleness: Duration,
}

fn default_oauth_configs() -> HashMap<LlmProvider, ProviderOAuthConfig> {
    let mut m = HashMap::new();
    m.insert(LlmProvider::OpenAi, ProviderOAuthConfig::openai_default());
    m.insert(LlmProvider::Google, ProviderOAuthConfig::google_default());
    // Anthropic is absent because it is not an OAuth provider here: it
    // authenticates with a bare `x-api-key` (`is_oauth(Anthropic) == false`), so
    // it has no token endpoint / refresh. (The prior subscription-OAuth path was
    // removed — ToS/ban risk.)
    m
}

/// Parse an `LLM_CRED_<PROVIDER>_<LABEL>` env key into its provider + label.
/// Provider identifiers contain no `_`, so the split is on the first `_`
/// after the prefix; the (possibly `_`-containing) remainder is the label.
fn parse_env_key(key: &str) -> Option<(LlmProvider, String)> {
    let rest = key.strip_prefix("LLM_CRED_")?;
    let (prov, label) = rest.split_once('_')?;
    let provider = LlmProvider::from_env_token(prov)?;
    if label.is_empty() {
        return None;
    }
    Some((provider, label.to_string()))
}

/// A field of a provider's OAuth refresh config, addressable from the
/// environment for deployment-time injection / override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OAuthConfigField {
    ClientId,
    ClientSecret,
    TokenUrl,
}

/// Accumulated `LLM_OAUTH_<PROVIDER>_*` overrides for one provider, applied on
/// top of that provider's built-in default at store construction. Lets a
/// deployment inject a `client_secret` (which must never live in source — I4)
/// or override the `client_id` / token endpoint without a code change.
#[derive(Default)]
struct OAuthOverride {
    client_id: Option<String>,
    client_secret: Option<String>,
    token_url: Option<String>,
}

/// Parse an `LLM_OAUTH_<PROVIDER>_<FIELD>` env key into its provider + field.
/// `<PROVIDER>` is the same token set as `LLM_CRED_*` (`GEMINI` aliases
/// `GOOGLE`); `<FIELD>` is `CLIENT_ID`, `CLIENT_SECRET`, or `TOKEN_URL`.
fn parse_oauth_config_key(key: &str) -> Option<(LlmProvider, OAuthConfigField)> {
    let rest = key.strip_prefix("LLM_OAUTH_")?;
    let (prov_tok, field) = if let Some(p) = rest.strip_suffix("_CLIENT_SECRET") {
        (p, OAuthConfigField::ClientSecret)
    } else if let Some(p) = rest.strip_suffix("_CLIENT_ID") {
        (p, OAuthConfigField::ClientId)
    } else {
        let p = rest.strip_suffix("_TOKEN_URL")?;
        (p, OAuthConfigField::TokenUrl)
    };
    Some((LlmProvider::from_env_token(prov_tok)?, field))
}

/// Apply an env override onto the OAuth config map. Overrides only mutate a
/// provider that already has a built-in default (currently OpenAI and Google):
/// a provider with no OAuth default (e.g. Anthropic, which is `x-api-key`) is NOT
/// registered from env alone, since a config for a non-OAuth provider would only
/// produce refreshes that silently fail.
fn apply_oauth_override(
    map: &mut HashMap<LlmProvider, ProviderOAuthConfig>,
    provider: LlmProvider,
    ov: OAuthOverride,
) {
    let Some(cfg) = map.get_mut(&provider) else {
        tracing::warn!(
            provider = provider.as_str(),
            "ignoring LLM_OAUTH_* override for a provider with no built-in refresh config"
        );
        return;
    };
    if let Some(id) = ov.client_id {
        cfg.client_id = id;
    }
    if let Some(secret) = ov.client_secret {
        cfg.client_secret = Some(secret);
    }
    if let Some(url) = ov.token_url {
        cfg.token_url = url;
    }
}

fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s.trim(), &time::format_description::well_known::Rfc3339).ok()
}

/// Read the `exp` claim (seconds epoch) from a JWT WITHOUT verifying its
/// signature — we only need the expiry to schedule freshness, never to trust
/// the token's contents (the upstream provider verifies it on use). Decodes the
/// base64url middle segment and reads `exp`. `None` for anything that isn't a
/// three-segment JWT with a numeric `exp`.
fn jwt_exp_secs(jwt: &str) -> Option<i64> {
    use base64::Engine;
    // Require EXACTLY three dot-separated segments (header.payload.signature).
    // A truncated 2-segment or an overlong 4+-segment string whose middle just
    // happens to decode to `{"exp":…}` must NOT be trusted as a JWT expiry — it
    // should fall through to refresh/rejection instead.
    let mut parts = jwt.split('.');
    let (_header, payload_b64, _sig) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return None,
        };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("exp")?.as_i64()
}

/// Read a string claim from a JWT payload WITHOUT verifying its signature (same
/// trust posture as [`jwt_exp_secs`] — we only read, never trust). Used to
/// recover the ChatGPT workspace id (`chatgpt_account_id`) from a Codex token's
/// id_token when the blob omits the explicit `tokens.account_id`. `None` for a
/// non-three-segment JWT or a missing/non-string claim.
fn jwt_str_claim(jwt: &str, claim: &str) -> Option<String> {
    use base64::Engine;
    let mut parts = jwt.split('.');
    let payload_b64 = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(p), Some(_), None) => p,
        _ => return None,
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get(claim)?.as_str().map(ToOwned::to_owned)
}

/// Parse an injected OAuth value into [`OAuthState`], accepting TWO on-the-wire
/// shapes so the gateway consumes provider credentials directly — including the
/// raw harness files `ai-credential-refresh` mirrors into Infisical:
///
/// 1. **Canonical** — `{"tokens":{access_token,refresh_token,id_token?},"expires_at":<RFC3339>}`.
/// 2. **Codex** (`~/.codex/auth.json`) — same `tokens` object but no top-level
///    `expires_at`; the expiry is the access-token JWT `exp` (seconds epoch).
///
/// Returns `None` for anything else, so a corrupt secret is rejected rather than
/// misused. Canonical and Codex share a top-level `tokens` and differ only in
/// whether `expires_at` is present (Codex falls back to the JWT `exp`). (Anthropic
/// is an `x-api-key` provider — not parsed here.)
fn parse_oauth_blob(value: &str) -> Option<OAuthState> {
    // Canonical + Codex: both carry a top-level `tokens`. Prefer an explicit
    // `expires_at` (canonical); else derive it from the access-token JWT `exp`
    // (Codex). serde ignores Codex's extra keys (`OPENAI_API_KEY`, `last_refresh`).
    if let Ok(blob) = serde_json::from_str::<InjectedOAuthBlob>(value) {
        let expires_at = blob
            .expires_at
            .as_deref()
            .and_then(parse_rfc3339)
            .or_else(|| {
                jwt_exp_secs(&blob.tokens.access_token)
                    .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
            });
        // ChatGPT workspace id: prefer the explicit `tokens.account_id` the Codex
        // file carries; else recover it from the id_token's `chatgpt_account_id`
        // claim (where the reference Codex client reads it). `None` for a
        // canonical OpenAI blob without either.
        let account_id = blob.tokens.account_id.or_else(|| {
            blob.tokens
                .id_token
                .as_deref()
                .and_then(|t| jwt_str_claim(t, "chatgpt_account_id"))
        });
        return Some(OAuthState {
            access_token: blob.tokens.access_token,
            refresh_token: blob.tokens.refresh_token,
            id_token: blob.tokens.id_token,
            expires_at,
            account_id,
        });
    }
    None
}

/// Parse an injected value into credential material, validated against the
/// provider's expected credential kind. An OAuth provider MUST present a valid
/// token blob (one of the shapes [`parse_oauth_blob`] accepts) — a malformed
/// blob is rejected (`None`) rather than silently treated as a bearer API key,
/// so a corrupt subscription secret is never sent upstream as a bearer token.
///
/// An API-key provider takes the trimmed value, but a JSON-object-shaped value
/// (`{…}`) is rejected (`None`): an api key is never a JSON object, so such a
/// value is almost certainly a legacy OAuth token blob left in the injected
/// secret — e.g. an Anthropic credential not yet swapped from the
/// subscription-OAuth blob to a first-party `sk-ant-api03` key. Without this
/// guard the gateway would transmit the blob — including its `access_token` /
/// `refresh_token` fields — verbatim as the `x-api-key` header. Both directions
/// fail closed at credential load instead of leaking token material upstream.
fn parse_material(provider: LlmProvider, value: &str) -> Option<Material> {
    let value = value.trim();
    if provider.is_oauth() {
        parse_oauth_blob(value).map(Material::OAuth)
    } else if value.is_empty() || value.starts_with('{') {
        None
    } else {
        Some(Material::ApiKey(value.to_string()))
    }
}

/// Build the refresh client with the shared 30-second profile. A transport
/// construction failure is returned to the composition root; it must never
/// downgrade credential refresh to an unbounded client.
fn default_http_client() -> Result<reqwest::Client, reqwest::Error> {
    http_client::client(default_http_profile())
}

const fn default_http_profile() -> Profile {
    Profile::Slow
}

/// Initial health for a freshly-loaded credential, before any refresh. An API
/// key — or an OAuth token with a still-future expiry — is [`Health::Healthy`];
/// an OAuth token that is already expired or carries no expiry is
/// [`Health::Unknown`] until the first `bearer()` validates it.
fn initial_health(material: &Material) -> Health {
    match material {
        Material::ApiKey(_) => Health::Healthy,
        Material::OAuth(o) => match o.expires_at {
            Some(exp) if exp > OffsetDateTime::now_utc() => Health::Healthy,
            _ => Health::Unknown,
        },
    }
}

impl LlmCredentialStore {
    /// Build a store from the process environment, reading every
    /// `LLM_CRED_<PROVIDER>_<LABEL>` variable.
    pub fn from_env() -> Result<Self, reqwest::Error> {
        Self::try_from_vars(std::env::vars())
    }

    /// Build from explicit variables for isolated tests. Production startup
    /// uses [`Self::from_env`] so transport initialization remains a returned
    /// boot error; this helper fails loudly if the process cannot initialize
    /// the shared test client.
    pub fn from_vars<I>(vars: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        Self::try_from_vars(vars).expect("building the LLM credential refresh test client")
    }

    fn try_from_vars<I>(vars: I) -> Result<Self, reqwest::Error>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut creds = HashMap::new();
        let mut overrides: HashMap<LlmProvider, OAuthOverride> = HashMap::new();
        for (k, v) in vars {
            if let Some((provider, label)) = parse_env_key(&k) {
                let Some(material) = parse_material(provider, &v) else {
                    tracing::warn!(
                        provider = provider.as_str(),
                        label = %label,
                        "skipping malformed LLM credential value (invalid for this provider)"
                    );
                    continue;
                };
                let health = initial_health(&material);
                creds.insert(
                    (provider, label),
                    Arc::new(Mutex::new(CredentialState {
                        material,
                        health,
                        last_success: None,
                        failing_since: None,
                        consecutive_failures: 0,
                        externally_refreshed: false,
                    })),
                );
            } else if let Some((provider, field)) = parse_oauth_config_key(&k) {
                // OAuth refresh-config overlay (e.g. an injected client_secret
                // that must not live in source). Empty values are ignored so an
                // unset-but-present env var doesn't blank a built-in default.
                let value = v.trim();
                if value.is_empty() {
                    continue;
                }
                let ov = overrides.entry(provider).or_default();
                match field {
                    OAuthConfigField::ClientId => ov.client_id = Some(value.to_string()),
                    OAuthConfigField::ClientSecret => ov.client_secret = Some(value.to_string()),
                    OAuthConfigField::TokenUrl => ov.token_url = Some(value.to_string()),
                }
            }
        }
        let mut oauth = default_oauth_configs();
        for (provider, ov) in overrides {
            apply_oauth_override(&mut oauth, provider, ov);
        }
        Ok(Self {
            creds,
            oauth,
            http: default_http_client()?,
            refresh_skew: DEFAULT_REFRESH_SKEW,
            staleness: DEFAULT_STALENESS,
        })
    }

    /// Override (or register) the OAuth refresh config for a provider. Tests
    /// point this at a loopback token endpoint; deployments can override a
    /// provider's token URL the same way.
    pub fn with_oauth_config(mut self, provider: LlmProvider, config: ProviderOAuthConfig) -> Self {
        self.oauth.insert(provider, config);
        self
    }

    /// Override the HTTP client (e.g. a client with a shorter timeout for tests).
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Override the refresh skew (refresh when within this of expiry).
    pub fn with_refresh_skew(mut self, skew: Duration) -> Self {
        self.refresh_skew = skew;
        self
    }

    /// Override the staleness threshold.
    pub fn with_staleness(mut self, staleness: Duration) -> Self {
        self.staleness = staleness;
        self
    }

    /// Labels currently loaded for a provider (its credential pool).
    pub fn labels(&self, provider: LlmProvider) -> Vec<String> {
        let mut out: Vec<String> = self
            .creds
            .keys()
            .filter(|(p, _)| *p == provider)
            .map(|(_, l)| l.clone())
            .collect();
        out.sort();
        out
    }

    /// Current health of a credential, or `None` if it isn't configured.
    pub async fn health(&self, provider: LlmProvider, label: &str) -> Option<Health> {
        let cell = self.creds.get(&(provider, label.to_string()))?;
        Some(cell.lock().await.health)
    }

    /// A point-in-time health snapshot of every configured credential, for the
    /// admin status panel. Read-only — like [`health`](Self::health) it
    /// reads each credential's cached `health` field and never triggers an OAuth
    /// refresh, so rendering the panel has no side effects on the pool. Sorted by
    /// `(provider, label)` for a stable display order.
    pub async fn status_snapshot(&self) -> Vec<CredentialStatus> {
        let mut out = Vec::with_capacity(self.creds.len());
        for ((provider, label), cell) in &self.creds {
            let health = cell.lock().await.health;
            out.push(CredentialStatus {
                provider: *provider,
                label: label.clone(),
                health,
            });
        }
        out.sort_by(|a, b| (a.provider.as_str(), &a.label).cmp(&(b.provider.as_str(), &b.label)));
        out
    }

    /// Mark a credential as externally refreshed: its token is kept fresh by an
    /// out-of-band refresher and re-read into the store via [`reload`], so
    /// `bearer()` must NOT refresh it in-process (its injected refresh token has
    /// already rotated away). The composition root calls this at startup for the
    /// credentials its Infisical re-read poller manages, BEFORE serving traffic,
    /// so a request in the window before the first re-read never triggers a
    /// doomed refresh. Returns `true` if the credential was found.
    pub async fn mark_externally_refreshed(&self, provider: LlmProvider, label: &str) -> bool {
        match self.creds.get(&(provider, label.to_string())) {
            Some(cell) => {
                cell.lock().await.externally_refreshed = true;
                true
            }
            None => false,
        }
    }

    /// Re-read an externally-refreshed credential's token from a freshly-fetched
    /// blob (the Infisical re-read poller calls this). Re-parses through the same
    /// schema detection [`bearer`] loaded from, swaps the access/id token and
    /// expiry into the existing cell, marks it externally refreshed, and resets
    /// the failure bookkeeping + health from the new token. Preserves
    /// `last_success`. Errors if the credential isn't configured or the blob is
    /// not a valid credential for the provider — leaving the prior token in place.
    pub async fn reload(
        &self,
        provider: LlmProvider,
        label: &str,
        raw_value: &str,
    ) -> Result<(), ReloadError> {
        let cell = self
            .creds
            .get(&(provider, label.to_string()))
            .ok_or_else(|| ReloadError::NotConfigured {
                provider: provider.as_str(),
                label: label.to_string(),
            })?;
        let material = parse_material(provider, raw_value)
            .ok_or(ReloadError::Unparseable(provider.as_str()))?;
        let health = initial_health(&material);
        let mut state = cell.lock().await;
        state.material = material;
        state.health = health;
        state.failing_since = None;
        state.consecutive_failures = 0;
        state.externally_refreshed = true;
        Ok(())
    }

    /// The ChatGPT/Codex workspace id (`chatgpt-account-id`) for an OAuth
    /// credential, if it carried one. `None` for an API-key credential (e.g.
    /// Anthropic or OpenRouter), an unconfigured `(provider, label)`, or an OAuth
    /// credential without an account id (e.g. a canonical OpenAI blob). Dispatch reads
    /// this to set the `chatgpt-account-id` header on a ChatGPT-backend route;
    /// it never returns secret material (the id is a workspace identifier, not a
    /// token), so it is safe to surface alongside `bearer()`.
    pub async fn oauth_account_id(&self, provider: LlmProvider, label: &str) -> Option<String> {
        let cell = self.creds.get(&(provider, label.to_string()))?;
        let state = cell.lock().await;
        match &state.material {
            Material::OAuth(o) => o.account_id.clone(),
            Material::ApiKey(_) => None,
        }
    }

    /// Whether a configured credential is OAuth-backed (`Some(true)`) or an API
    /// key (`Some(false)`); `None` when the `(provider, label)` is not
    /// configured at all. Discovery uses this to pick the upstream surface for a
    /// `(provider, credential)` target: e.g. `openai` over OAuth means the Codex
    /// ChatGPT backend (the Codex models listing + Responses transport), whereas
    /// `openai` over an API key means a plain OpenRouter/OpenAI-compatible
    /// listing. It reads only the credential *kind*, never the secret material.
    pub async fn credential_is_oauth(&self, provider: LlmProvider, label: &str) -> Option<bool> {
        let cell = self.creds.get(&(provider, label.to_string()))?;
        let state = cell.lock().await;
        Some(matches!(state.material, Material::OAuth(_)))
    }

    /// Return a currently-valid bearer token for a credential, refreshing an
    /// OAuth access token in-process if it is at/near expiry. Concurrent calls
    /// for the same credential coalesce onto one refresh (single-flight).
    pub async fn bearer(
        &self,
        provider: LlmProvider,
        label: &str,
    ) -> Result<String, CredentialError> {
        self.bearer_with_account(provider, label)
            .await
            .map(|(bearer, _)| bearer)
    }

    /// Read matching bearer and provider account metadata under the same lock.
    /// A credential reload cannot pair one account with another account's token.
    pub async fn bearer_with_account(
        &self,
        provider: LlmProvider,
        label: &str,
    ) -> Result<(String, Option<String>), CredentialError> {
        let cell = self
            .creds
            .get(&(provider, label.to_string()))
            .ok_or_else(|| CredentialError::NotConfigured {
                provider: provider.as_str(),
                label: label.to_string(),
            })?;

        // Holding this lock across the refresh await is what makes refresh
        // single-flight per credential: a second caller blocks here, then —
        // after the holder refreshes and updates `expires_at` — re-checks
        // validity below and returns the fresh token without a second
        // network round-trip. (A tokio Mutex is designed to be held across
        // `.await`, unlike a std Mutex.)
        let mut state = cell.lock().await;

        if let Material::ApiKey(key) = &state.material {
            return Ok((key.clone(), None));
        }

        // Externally-refreshed OAuth: an out-of-band refresher owns rotation and
        // the store re-reads the fresh token via `reload`. NEVER refresh
        // in-process — the injected refresh token has already rotated away, so a
        // refresh would fail and fight the refresher. Serve the current token
        // while still valid; once actually expired, surface `AwaitingReread`
        // (the re-read should have swapped it) rather than attempt a refresh.
        if state.externally_refreshed {
            if let Material::OAuth(oauth) = &state.material {
                match oauth.expires_at {
                    // No skew here: we can't refresh, so serve right up to expiry
                    // — the re-read swaps the token before it lapses.
                    Some(exp) if OffsetDateTime::now_utc() < exp => {
                        return Ok((oauth.access_token.clone(), oauth.account_id.clone()));
                    }
                    None => return Ok((oauth.access_token.clone(), oauth.account_id.clone())),
                    Some(_) => {
                        state.health = Health::Stale;
                        return Err(CredentialError::AwaitingReread {
                            provider: provider.as_str(),
                            label: label.to_string(),
                        });
                    }
                }
            }
        }

        // OAuth: serve the cached token if it is comfortably unexpired.
        if let Material::OAuth(oauth) = &state.material {
            if let Some(expires_at) = oauth.expires_at {
                let skew = time::Duration::seconds(self.refresh_skew.as_secs() as i64);
                if OffsetDateTime::now_utc() + skew < expires_at {
                    return Ok((oauth.access_token.clone(), oauth.account_id.clone()));
                }
            }
        }

        let bearer = self.refresh_locked(provider, label, &mut state).await?;
        let account = match &state.material {
            Material::OAuth(oauth) => oauth.account_id.clone(),
            Material::ApiKey(_) => None,
        };
        Ok((bearer, account))
    }

    async fn refresh_locked(
        &self,
        provider: LlmProvider,
        label: &str,
        state: &mut CredentialState,
    ) -> Result<String, CredentialError> {
        let oauth = match &state.material {
            Material::OAuth(o) => o.clone(),
            Material::ApiKey(key) => return Ok(key.clone()),
        };
        let config = match self.oauth.get(&provider).cloned() {
            Some(config) => config,
            None => {
                // Can't even attempt a refresh — reflect that in health so a
                // routing/status consumer doesn't keep treating the credential
                // as usable while bearer() returns NoOAuthConfig.
                state.health = Health::Failing;
                return Err(CredentialError::NoOAuthConfig(provider.as_str()));
            }
        };

        // OAuth 2.0 token requests are `application/x-www-form-urlencoded`
        // (RFC 6749 §4.1.3 / §6) — matching the gateway's existing OAuth
        // client (`waygate-oidc`) and what real provider token endpoints
        // accept. (The response is JSON; only the request is form-encoded.)
        let mut params: Vec<(&str, String)> = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", oauth.refresh_token.clone()),
            ("client_id", config.client_id.clone()),
        ];
        if let Some(secret) = &config.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        // Encode as application/x-www-form-urlencoded explicitly (the same
        // wire format reqwest's `.form()` produces) so this does not depend on
        // reqwest's optional feature set.
        let form_body = serde_urlencoded::to_string(&params).unwrap_or_default();
        let result = self
            .http
            .post(&config.token_url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form_body)
            .send()
            .await;

        // Snapshot the current token before `oauth` is consumed on the success
        // path, so the graceful-degradation path below can fall back to it.
        let current_access = oauth.access_token.clone();
        let current_expires = oauth.expires_at;

        let detail = match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<TokenResponse>().await {
                Ok(token) => {
                    let now = OffsetDateTime::now_utc();
                    state.material = Material::OAuth(OAuthState {
                        access_token: token.access_token.clone(),
                        refresh_token: token.refresh_token.unwrap_or(oauth.refresh_token),
                        id_token: oauth.id_token,
                        expires_at: token
                            .expires_in
                            .map(|secs| now + time::Duration::seconds(secs)),
                        // The workspace id is stable across token refresh — a
                        // refresh response never restates it, so carry it forward.
                        account_id: oauth.account_id,
                    });
                    state.health = Health::Healthy;
                    state.last_success = Some(now);
                    state.failing_since = None;
                    state.consecutive_failures = 0;
                    tracing::debug!(
                        provider = provider.as_str(),
                        label,
                        "refreshed llm oauth credential"
                    );
                    return Ok(token.access_token);
                }
                Err(e) => format!("decode token response: {e}"),
            },
            Ok(resp) => format!("token endpoint returned status {}", resp.status()),
            Err(e) => format!("token endpoint request failed: {e}"),
        };

        // Refresh failed. Record it (health → Failing/Stale), then degrade
        // gracefully: if the current access token is still unexpired, serve it
        // rather than failing the call — a proactive (within-skew) refresh that
        // fails must not break a token that still works. Only surface the error
        // once the token has actually expired.
        let err = self.mark_failure(state, provider, label, detail);
        if current_expires
            .map(|exp| exp > OffsetDateTime::now_utc())
            .unwrap_or(false)
        {
            tracing::warn!(
                provider = provider.as_str(),
                label,
                "serving still-valid access token after a failed proactive refresh"
            );
            return Ok(current_access);
        }
        Err(err)
    }

    fn mark_failure(
        &self,
        state: &mut CredentialState,
        provider: LlmProvider,
        label: &str,
        detail: String,
    ) -> CredentialError {
        state.consecutive_failures += 1;
        let now = OffsetDateTime::now_utc();
        let failing_since = *state.failing_since.get_or_insert(now);
        let token_expired = match &state.material {
            Material::OAuth(o) => o.expires_at.map(|e| e <= now).unwrap_or(true),
            Material::ApiKey(_) => false,
        };
        let staleness = time::Duration::seconds(self.staleness.as_secs() as i64);
        // Stale only once the access token is expired AND we've been failing
        // continuously for longer than the staleness window — a single
        // transient refresh failure is `Failing`, not `Stale`.
        let stale = token_expired && (now - failing_since) > staleness;
        tracing::warn!(
            provider = provider.as_str(),
            label,
            failures = state.consecutive_failures,
            "llm oauth refresh failed: {detail}"
        );
        if stale {
            state.health = Health::Stale;
            CredentialError::Stale {
                provider: provider.as_str(),
                label: label.to_string(),
                since: state
                    .last_success
                    .map(|t| t.unix_timestamp().to_string())
                    .unwrap_or_else(|| "never".to_string()),
            }
        } else {
            state.health = Health::Failing;
            CredentialError::RefreshFailed {
                provider: provider.as_str(),
                label: label.to_string(),
                detail,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_constructor_exposes_transport_initialization_failure() {
        let constructor: fn() -> Result<LlmCredentialStore, reqwest::Error> =
            LlmCredentialStore::from_env;
        let _ = constructor;
    }

    #[test]
    fn default_refresh_client_uses_the_bounded_slow_profile() {
        let profile = default_http_profile();
        assert_eq!(profile, Profile::Slow);
        assert_eq!(profile.total_timeout(), Some(Duration::from_secs(30)));
        default_http_client().expect("shared slow-profile refresh client must build");
    }

    #[test]
    fn canonical_str_round_trips_every_provider() {
        // from_canonical_str is the inverse of as_str for all variants, so a
        // provider persisted as text (e.g. the completion cache's serving
        // provider) rehydrates exactly. A non-canonical string yields None
        // (callers fall back rather than guess).
        for p in [
            LlmProvider::OpenAi,
            LlmProvider::Anthropic,
            LlmProvider::Google,
            LlmProvider::OpenRouter,
        ] {
            assert_eq!(LlmProvider::from_canonical_str(p.as_str()), Some(p));
        }
        assert_eq!(LlmProvider::from_canonical_str("gemini"), None);
        assert_eq!(LlmProvider::from_canonical_str("OPENAI"), None);
        assert_eq!(LlmProvider::from_canonical_str(""), None);
    }

    #[test]
    fn env_key_parses_provider_and_label() {
        assert_eq!(
            parse_env_key("LLM_CRED_OPENAI_PRIMARY"),
            Some((LlmProvider::OpenAi, "PRIMARY".to_string()))
        );
        // Labels may contain underscores; provider is the first segment.
        assert_eq!(
            parse_env_key("LLM_CRED_ANTHROPIC_FAMILY_2"),
            Some((LlmProvider::Anthropic, "FAMILY_2".to_string()))
        );
        // GEMINI aliases GOOGLE.
        assert_eq!(
            parse_env_key("LLM_CRED_GEMINI_MAIN"),
            Some((LlmProvider::Google, "MAIN".to_string()))
        );
        assert_eq!(
            parse_env_key("LLM_CRED_OPENROUTER_MAIN").map(|(p, _)| p),
            Some(LlmProvider::OpenRouter)
        );
    }

    #[test]
    fn env_key_rejects_non_credential_and_unknown_provider() {
        assert_eq!(parse_env_key("PATH"), None);
        assert_eq!(parse_env_key("LLM_CRED_OPENAI"), None); // no label segment
        assert_eq!(parse_env_key("LLM_CRED_MISTRAL_X"), None); // unknown provider
    }

    #[test]
    fn parse_material_is_provider_aware() {
        let blob = r#"{"tokens":{"access_token":"at","refresh_token":"rt","id_token":"it"},"expires_at":"2030-01-01T00:00:00Z"}"#;
        match parse_material(LlmProvider::OpenAi, blob) {
            Some(Material::OAuth(o)) => {
                assert_eq!(o.access_token, "at");
                assert_eq!(o.refresh_token, "rt");
                assert!(o.expires_at.is_some());
            }
            _ => panic!("expected OAuth material for a valid OpenAI blob"),
        }
        match parse_material(LlmProvider::OpenRouter, "sk-or-abc123") {
            Some(Material::ApiKey(k)) => assert_eq!(k, "sk-or-abc123"),
            _ => panic!("expected ApiKey material for OpenRouter"),
        }
        // A malformed OAuth blob for an OAuth provider is rejected, not
        // silently accepted as a bearer API key.
        assert!(parse_material(LlmProvider::OpenAi, "not-an-oauth-blob").is_none());
        // Anthropic is an API-key provider: it takes the bare key verbatim.
        match parse_material(LlmProvider::Anthropic, "sk-ant-api03-xyz") {
            Some(Material::ApiKey(k)) => assert_eq!(k, "sk-ant-api03-xyz"),
            _ => panic!("expected ApiKey material for Anthropic"),
        }
    }

    #[test]
    fn api_key_provider_rejects_a_json_oauth_blob_instead_of_sending_it() {
        // Migration-window safety: if an operator deploys the api-key build
        // before swapping the Anthropic Infisical secret away from the legacy
        // subscription-OAuth blob, the injected value is still a JSON blob. It
        // MUST fail closed at load — never become ApiKey material — so the blob
        // (with its `access_token` / `refresh_token`) is never transmitted as the
        // `x-api-key` header upstream. An api key is never a JSON object.
        let oauth_blob = r#"{"tokens":{"access_token":"sk-ant-oat-leak","refresh_token":"rt"},"expires_at":"2099-01-01T00:00:00Z"}"#;
        assert!(
            parse_material(LlmProvider::Anthropic, oauth_blob).is_none(),
            "an OAuth blob handed to an api-key provider must be rejected, not sent as x-api-key"
        );
        // Leading/trailing whitespace must not smuggle a blob past the guard.
        assert!(parse_material(LlmProvider::Anthropic, "  {\"tokens\":{}}  ").is_none());
        // A real bare key still parses.
        assert!(matches!(
            parse_material(LlmProvider::OpenRouter, "sk-or-v1-abc"),
            Some(Material::ApiKey(_))
        ));
    }

    /// Build a fake JWT (`header.payload.sig`) whose payload carries `exp`. Only
    /// the payload segment is real base64url; the signature is a placeholder
    /// because `jwt_exp_secs` never verifies it.
    fn jwt_with_exp(exp: i64) -> String {
        use base64::Engine;
        let payload = serde_json::to_vec(&serde_json::json!({ "exp": exp })).unwrap();
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("eyJhbGciOiJub25lIn0.{p}.sig")
    }

    #[test]
    fn jwt_exp_secs_reads_exp_or_none() {
        assert_eq!(
            jwt_exp_secs(&jwt_with_exp(4_102_444_800)),
            Some(4_102_444_800)
        );
        // Not a JWT / no exp / garbage → None (callers fall back, never panic).
        assert_eq!(jwt_exp_secs("not-a-jwt"), None);
        assert_eq!(jwt_exp_secs("h.bogus-base64-@@@.s"), None);
        use base64::Engine;
        let no_exp = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"sub\":\"x\"}");
        assert_eq!(jwt_exp_secs(&format!("h.{no_exp}.s")), None);
        // Segment count must be EXACTLY three: a 2-segment or 4+-segment string
        // whose middle decodes to a valid exp payload is still rejected.
        let exp_payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"exp\":4102444800}");
        assert_eq!(
            jwt_exp_secs(&format!("h.{exp_payload}")),
            None,
            "two segments"
        );
        assert_eq!(
            jwt_exp_secs(&format!("h.{exp_payload}.s.extra")),
            None,
            "four segments"
        );
    }

    #[test]
    fn parse_material_accepts_native_codex_blob_with_jwt_expiry() {
        // Native ~/.codex/auth.json shape: a `tokens` object, NO top-level
        // expires_at, extra keys, and the expiry inside the access-token JWT exp.
        let access = jwt_with_exp(4_102_444_800); // seconds epoch = 2100-01-01
        let blob = format!(
            r#"{{"tokens":{{"id_token":"id-codex","access_token":"{access}","refresh_token":"rt-codex","account_id":"acct"}},"OPENAI_API_KEY":"sk-x","last_refresh":"2026-01-01T00:00:00Z"}}"#
        );
        match parse_material(LlmProvider::OpenAi, &blob) {
            Some(Material::OAuth(o)) => {
                assert_eq!(o.access_token, access);
                assert_eq!(o.refresh_token, "rt-codex");
                assert_eq!(o.id_token.as_deref(), Some("id-codex"));
                // The Codex blob's `tokens.account_id` is captured for the
                // `chatgpt-account-id` header (ChatGPT-backend auth).
                assert_eq!(o.account_id.as_deref(), Some("acct"));
                let exp = o
                    .expires_at
                    .expect("expiry derived from the access-token JWT exp");
                assert_eq!(exp.year(), 2100);
            }
            _ => panic!("expected OAuth material for a native Codex blob"),
        }
    }

    #[test]
    fn codex_account_id_falls_back_to_id_token_chatgpt_account_id_claim() {
        // A Codex blob without an explicit `tokens.account_id` recovers the
        // workspace id from the id_token's `chatgpt_account_id` claim — where the
        // reference Codex client reads it.
        let access = jwt_with_exp(4_102_444_800);
        use base64::Engine;
        let id_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"chatgpt_account_id\":\"org_from_jwt\"}");
        let id_token = format!("h.{id_payload}.s");
        let blob = format!(
            r#"{{"tokens":{{"id_token":"{id_token}","access_token":"{access}","refresh_token":"rt"}}}}"#
        );
        match parse_material(LlmProvider::OpenAi, &blob) {
            Some(Material::OAuth(o)) => {
                assert_eq!(o.account_id.as_deref(), Some("org_from_jwt"));
            }
            _ => panic!("expected OAuth material"),
        }
    }

    #[test]
    fn canonical_blob_still_preferred_over_jwt_fallback() {
        // When an explicit RFC3339 expires_at IS present, it wins; the JWT
        // fallback is only for blobs that omit it (Codex).
        let blob = r#"{"tokens":{"access_token":"at","refresh_token":"rt"},"expires_at":"2031-06-01T00:00:00Z"}"#;
        match parse_material(LlmProvider::OpenAi, blob) {
            Some(Material::OAuth(o)) => {
                let exp = o.expires_at.expect("explicit expiry");
                assert_eq!(exp.year(), 2031);
            }
            _ => panic!("expected OAuth material"),
        }
    }

    #[tokio::test]
    async fn api_key_credential_returns_key_without_network() {
        let store = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENROUTER_MAIN".to_string(),
            "sk-or-secret".to_string(),
        )]);
        assert_eq!(
            store.bearer(LlmProvider::OpenRouter, "MAIN").await.unwrap(),
            "sk-or-secret"
        );
        assert_eq!(
            store.labels(LlmProvider::OpenRouter),
            vec!["MAIN".to_string()]
        );
        assert_eq!(
            store.health(LlmProvider::OpenRouter, "MAIN").await,
            Some(Health::Healthy)
        );
    }

    /// An OpenAI canonical blob with the given RFC3339 expiry. OpenAI has a
    /// built-in refresh config (real `auth.openai.com`), so a non-externally-
    /// refreshed expired credential would attempt a NETWORK refresh — which is
    /// exactly what the `externally_refreshed` flag must prevent.
    fn openai_blob(expires_at: &str) -> (String, String) {
        (
            "LLM_CRED_OPENAI_PRIMARY".to_string(),
            format!(
                r#"{{"tokens":{{"access_token":"at-{expires_at}","refresh_token":"rt"}},"expires_at":"{expires_at}"}}"#
            ),
        )
    }

    #[tokio::test]
    async fn externally_refreshed_serves_unexpired_token() {
        let store = LlmCredentialStore::from_vars([openai_blob("2100-01-01T00:00:00Z")]);
        assert!(
            store
                .mark_externally_refreshed(LlmProvider::OpenAi, "PRIMARY")
                .await
        );
        assert_eq!(
            store.bearer(LlmProvider::OpenAi, "PRIMARY").await.unwrap(),
            "at-2100-01-01T00:00:00Z"
        );
    }

    #[tokio::test]
    async fn externally_refreshed_expired_awaits_reread_without_network() {
        // Past expiry + externally refreshed: bearer must NOT attempt a refresh
        // (which for OpenAI would hit the real network and return RefreshFailed);
        // it returns AwaitingReread immediately. Asserting that specific error
        // proves the in-process refresh was skipped.
        let store = LlmCredentialStore::from_vars([openai_blob("2000-01-01T00:00:00Z")]);
        assert!(
            store
                .mark_externally_refreshed(LlmProvider::OpenAi, "PRIMARY")
                .await
        );
        match store.bearer(LlmProvider::OpenAi, "PRIMARY").await {
            Err(CredentialError::AwaitingReread { provider, label }) => {
                assert_eq!(provider, "openai");
                assert_eq!(label, "PRIMARY");
            }
            other => panic!("expected AwaitingReread (no network), got {other:?}"),
        }
        assert_eq!(
            store.health(LlmProvider::OpenAi, "PRIMARY").await,
            Some(Health::Stale)
        );
    }

    #[tokio::test]
    async fn reload_swaps_token_and_restores_health() {
        // Start expired → AwaitingReread; reload a fresh blob → bearer serves the
        // new token and health is restored, with no network in either step.
        let store = LlmCredentialStore::from_vars([openai_blob("2000-01-01T00:00:00Z")]);
        store
            .mark_externally_refreshed(LlmProvider::OpenAi, "PRIMARY")
            .await;
        assert!(store.bearer(LlmProvider::OpenAi, "PRIMARY").await.is_err());

        let fresh = r#"{"tokens":{"access_token":"at-fresh","refresh_token":"rt2"},"expires_at":"2100-01-01T00:00:00Z"}"#;
        store
            .reload(LlmProvider::OpenAi, "PRIMARY", fresh)
            .await
            .expect("reload of a configured credential succeeds");

        assert_eq!(
            store.bearer(LlmProvider::OpenAi, "PRIMARY").await.unwrap(),
            "at-fresh"
        );
        assert_eq!(
            store.health(LlmProvider::OpenAi, "PRIMARY").await,
            Some(Health::Healthy)
        );
    }

    #[tokio::test]
    async fn bearer_account_snapshot_survives_credential_replacement() {
        let store = LlmCredentialStore::from_vars([openai_blob("2100-01-01T00:00:00Z")]);
        let missing = store
            .bearer_with_account(LlmProvider::OpenAi, "PRIMARY")
            .await
            .unwrap();
        assert!(missing.1.is_none());
        let first = r#"{"tokens":{"access_token":"test-first","refresh_token":"test-refresh","account_id":"account-first"},"expires_at":"2100-01-01T00:00:00Z"}"#;
        let second = r#"{"tokens":{"access_token":"test-second","refresh_token":"test-refresh","account_id":"account-second"},"expires_at":"2100-01-01T00:00:00Z"}"#;
        store
            .reload(LlmProvider::OpenAi, "PRIMARY", first)
            .await
            .unwrap();
        let snapshot = store
            .bearer_with_account(LlmProvider::OpenAi, "PRIMARY")
            .await
            .unwrap();
        store
            .reload(LlmProvider::OpenAi, "PRIMARY", second)
            .await
            .unwrap();
        assert_eq!(
            snapshot,
            ("test-first".into(), Some("account-first".into()))
        );
        assert_eq!(
            store
                .bearer_with_account(LlmProvider::OpenAi, "PRIMARY")
                .await
                .unwrap(),
            ("test-second".into(), Some("account-second".into()))
        );
    }

    #[tokio::test]
    async fn reload_errors_are_clean() {
        let store = LlmCredentialStore::from_vars([openai_blob("2100-01-01T00:00:00Z")]);
        // Unknown credential.
        match store.reload(LlmProvider::Anthropic, "NOPE", "{}").await {
            Err(ReloadError::NotConfigured { provider, label }) => {
                assert_eq!(provider, "anthropic");
                assert_eq!(label, "NOPE");
            }
            other => panic!("expected NotConfigured, got {other:?}"),
        }
        // Configured but garbage blob → Unparseable; the prior token is untouched.
        match store
            .reload(LlmProvider::OpenAi, "PRIMARY", "not-a-blob")
            .await
        {
            Err(ReloadError::Unparseable(p)) => assert_eq!(p, "openai"),
            other => panic!("expected Unparseable, got {other:?}"),
        }
        assert_eq!(
            store.bearer(LlmProvider::OpenAi, "PRIMARY").await.unwrap(),
            "at-2100-01-01T00:00:00Z",
            "a failed reload leaves the prior token in place"
        );
    }

    #[tokio::test]
    async fn mark_externally_refreshed_unknown_returns_false() {
        let store = LlmCredentialStore::from_vars([openai_blob("2100-01-01T00:00:00Z")]);
        assert!(
            !store
                .mark_externally_refreshed(LlmProvider::Google, "PRIMARY")
                .await
        );
    }

    #[test]
    fn default_oauth_configs_wire_openai_and_google_refresh() {
        // Regression guard for the gap where only OpenAI had a refresh config,
        // so a Google (Gemini) OAuth token could never refresh in-process and
        // `bearer()` returned `NoOAuthConfig` once it neared expiry. Both
        // OpenAI and Google must be wired with their public CLI client_id +
        // token endpoint. Anthropic is intentionally NOT wired here — it is a
        // first-party `x-api-key` provider with no OAuth refresh (see the
        // assertion below and `is_oauth`).
        let configs = default_oauth_configs();
        assert!(
            configs.contains_key(&LlmProvider::OpenAi),
            "OpenAI refresh config must be registered"
        );
        let google = configs
            .get(&LlmProvider::Google)
            .expect("Google refresh config must be registered so Gemini tokens can refresh");
        assert_eq!(google.token_url, "https://oauth2.googleapis.com/token");
        assert!(!google.client_id.is_empty(), "Google client_id must be set");
        assert!(
            !configs.contains_key(&LlmProvider::Anthropic),
            "Anthropic is an x-api-key provider — it has no OAuth refresh config"
        );
    }

    #[test]
    fn google_client_secret_is_injected_from_env_not_source() {
        // I4: Google's installed-app refresh secret must not live in source —
        // the built-in default is secret-less, and a deployment injects it via
        // LLM_OAUTH_GOOGLE_CLIENT_SECRET (here using GEMINI, the GOOGLE alias).
        let bare = LlmCredentialStore::from_vars(std::iter::empty());
        assert!(
            bare.oauth
                .get(&LlmProvider::Google)
                .expect("google default present")
                .client_secret
                .is_none(),
            "no Google client_secret may be baked into source"
        );

        let injected = LlmCredentialStore::from_vars([(
            "LLM_OAUTH_GEMINI_CLIENT_SECRET".to_string(),
            "injected-secret".to_string(),
        )]);
        assert_eq!(
            injected
                .oauth
                .get(&LlmProvider::Google)
                .unwrap()
                .client_secret
                .as_deref(),
            Some("injected-secret")
        );
    }

    #[test]
    fn oauth_override_ignores_unwired_provider_and_empty_values() {
        // An override for a non-OAuth provider (Anthropic, which is x-api-key) is
        // ignored — it must not be registered with an OAuth config — and an empty
        // value must not blank a built-in default.
        let store = LlmCredentialStore::from_vars([
            (
                "LLM_OAUTH_ANTHROPIC_CLIENT_SECRET".to_string(),
                "x".to_string(),
            ),
            ("LLM_OAUTH_GOOGLE_CLIENT_ID".to_string(), "  ".to_string()),
        ]);
        assert!(
            !store.oauth.contains_key(&LlmProvider::Anthropic),
            "env override must not register an unwired provider"
        );
        // The empty client_id override left Google's built-in client_id intact.
        assert!(!store
            .oauth
            .get(&LlmProvider::Google)
            .unwrap()
            .client_id
            .is_empty());
    }

    #[tokio::test]
    async fn unconfigured_credential_errors() {
        let store = LlmCredentialStore::from_vars(std::iter::empty());
        assert!(matches!(
            store.bearer(LlmProvider::OpenAi, "PRIMARY").await,
            Err(CredentialError::NotConfigured { .. })
        ));
        assert_eq!(store.health(LlmProvider::OpenAi, "PRIMARY").await, None);
    }

    #[tokio::test]
    async fn unexpired_oauth_token_is_served_without_refresh() {
        // expires far in the future ⇒ bearer returns the cached access token
        // and never consults the (unset) token endpoint.
        let blob = r#"{"tokens":{"access_token":"cached-at","refresh_token":"rt"},"expires_at":"2099-01-01T00:00:00Z"}"#;
        let store = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_PRIMARY".to_string(),
            blob.to_string(),
        )]);
        assert_eq!(
            store.bearer(LlmProvider::OpenAi, "PRIMARY").await.unwrap(),
            "cached-at"
        );
        // A still-valid OAuth token loads as Healthy.
        assert_eq!(
            store.health(LlmProvider::OpenAi, "PRIMARY").await,
            Some(Health::Healthy)
        );
    }

    #[tokio::test]
    async fn expired_oauth_blob_loads_as_unknown_until_refreshed() {
        // An already-expired injected OAuth token must NOT report Healthy
        // before it has been validated/refreshed — it reports Unknown so a
        // consumer checking health() before bearer() isn't misled.
        let blob = r#"{"tokens":{"access_token":"old","refresh_token":"rt"},"expires_at":"2000-01-01T00:00:00Z"}"#;
        let store = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_PRIMARY".to_string(),
            blob.to_string(),
        )]);
        assert_eq!(
            store.health(LlmProvider::OpenAi, "PRIMARY").await,
            Some(Health::Unknown)
        );
    }

    #[tokio::test]
    async fn malformed_oauth_credential_is_skipped_not_loaded_as_bearer() {
        // An OAuth provider whose injected value isn't a valid token blob is
        // dropped at load → bearer() reports NotConfigured rather than sending
        // the malformed value upstream as a bearer token.
        let store = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_PRIMARY".to_string(),
            "totally-not-a-blob".to_string(),
        )]);
        assert!(matches!(
            store.bearer(LlmProvider::OpenAi, "PRIMARY").await,
            Err(CredentialError::NotConfigured { .. })
        ));
        assert!(store.labels(LlmProvider::OpenAi).is_empty());
    }
}
