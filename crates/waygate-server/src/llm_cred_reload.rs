//! In-process re-read of externally-refreshed LLM credentials from
//! Infisical.
//!
//! An external credential refresher owns token rotation and publishes updated
//! credential blobs to Infisical. The gateway loads credentials once at boot
//! (env is static), and it must NOT refresh externally managed tokens itself:
//! a single-use refresh token may already have rotated, so a competing
//! in-process refresh would fail and fight the designated owner
//! (see `waygate_llm_credentials`). This module closes the gap WITHOUT a sidecar:
//! a small read-only Infisical client + a periodic poller that re-fetches each
//! managed secret and swaps the fresh access token into the live store via
//! [`LlmCredentialStore::reload`].
//!
//! Security: the poller authenticates with a **scoped, read-only** Infisical
//! service token (`GATEWAY_INFISICAL_TOKEN`) — NOT the host's universal-auth
//! machine identity — so the gateway's blast radius is exactly the credential
//! path it must re-read, preserving the I4 "credentials injected, never sourced
//! broadly" posture.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use waygate_core::http_client::{self, Profile};
use waygate_llm_credentials::{LlmCredentialStore, LlmProvider};

/// Default re-read interval. Operators must select a cadence appropriate to
/// their external refresher's publication interval and credential lifetime.
/// Parsed at the `main.rs` use site via
/// `waygate_core::env::duration_secs_zero_disables` — garbage
/// `GATEWAY_LLM_CRED_RELOAD_SECS` rejects at boot; `0` disables the poller.
pub(crate) const DEFAULT_RELOAD_SECS: u64 = 300;

/// One credential to keep fresh: which `(provider, label)` in the store maps to
/// which Infisical secret name (at the client's configured path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredReloadEntry {
    pub provider: LlmProvider,
    pub label: String,
    pub secret: String,
}

#[derive(serde::Deserialize)]
struct RawEntry {
    provider: String,
    label: String,
    secret: String,
}

/// Parse `GATEWAY_LLM_CRED_RELOAD` — a JSON array of
/// `{"provider","label","secret"}`. The `provider` is resolved through
/// [`LlmProvider::from_env_token`] — the *same* case-insensitive vocabulary the
/// `LLM_CRED_<PROVIDER>_<LABEL>` env keys use, including the `GEMINI`→`GOOGLE`
/// alias — so an operator can mirror those keys' UPPERCASE provider strings
/// here verbatim. An entry whose provider is genuinely unknown is dropped with a
/// **warning** (never silently — a typo would otherwise leave that credential
/// unmanaged by the poller). Invalid JSON ⇒ empty (the poller then doesn't
/// spawn).
pub fn parse_reload_config(raw: &str) -> Vec<CredReloadEntry> {
    let entries: Vec<RawEntry> = serde_json::from_str(raw.trim()).unwrap_or_default();
    entries
        .into_iter()
        .filter_map(|e| match LlmProvider::from_env_token(e.provider.trim()) {
            Some(provider) => Some(CredReloadEntry {
                provider,
                label: e.label,
                secret: e.secret,
            }),
            None => {
                tracing::warn!(
                    provider = %e.provider,
                    label = %e.label,
                    "GATEWAY_LLM_CRED_RELOAD: unknown provider — entry dropped, this \
                     credential will NOT be re-read",
                );
                None
            }
        })
        .collect()
}

/// Minimal read-only Infisical client: fetch a single raw secret's value by name
/// from a fixed project/env/path, authenticating with a bearer service token.
#[derive(Clone)]
pub struct InfisicalReadClient {
    http: reqwest::Client,
    api_url: String,
    token: String,
    project_id: String,
    environment: String,
    secret_path: String,
}

impl InfisicalReadClient {
    pub fn new(
        http: reqwest::Client,
        api_url: impl Into<String>,
        token: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        secret_path: impl Into<String>,
    ) -> Self {
        Self {
            http,
            api_url: api_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            secret_path: secret_path.into(),
        }
    }

    /// Build from `GATEWAY_INFISICAL_*`. `None` (⇒ poller not spawned) unless the
    /// API URL, service token, and project id are all present. An enabled
    /// client requires explicit environment and path coordinates so it never
    /// silently reads another deployment's credential location.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Some(api_url) = non_empty("GATEWAY_INFISICAL_API_URL") else {
            return Ok(None);
        };
        let Some(token) = non_empty("GATEWAY_INFISICAL_TOKEN") else {
            return Ok(None);
        };
        let Some(project_id) = non_empty("GATEWAY_INFISICAL_PROJECT_ID") else {
            return Ok(None);
        };
        let environment = non_empty("GATEWAY_INFISICAL_ENV")
            .context("configured Infisical credential reload requires GATEWAY_INFISICAL_ENV")?;
        let secret_path = non_empty("GATEWAY_INFISICAL_SECRET_PATH").context(
            "configured Infisical credential reload requires GATEWAY_INFISICAL_SECRET_PATH",
        )?;
        Ok(Some(Self::new(
            crate::llm_cred_reload::default_http()
                .map_err(|e| anyhow::anyhow!("building the Infisical re-read HTTP client: {e}"))?,
            api_url,
            token,
            project_id,
            environment,
            secret_path,
        )))
    }

    /// `GET /api/v3/secrets/raw/{name}` → the secret's `secretValue`.
    pub async fn read_secret(&self, name: &str) -> anyhow::Result<String> {
        #[derive(serde::Deserialize)]
        struct Resp {
            secret: Secret,
        }
        #[derive(serde::Deserialize)]
        struct Secret {
            #[serde(rename = "secretValue")]
            secret_value: String,
        }
        // Build the URL with `reqwest::Url` (the query-pair encoder handles the
        // `/` in `secretPath`); the workspace reqwest is feature-trimmed and
        // doesn't expose `RequestBuilder::query`.
        let mut url =
            reqwest::Url::parse(&format!("{}/api/v3/secrets/raw/{}", self.api_url, name))?;
        url.query_pairs_mut()
            .append_pair("workspaceId", &self.project_id)
            .append_pair("environment", &self.environment)
            .append_pair("secretPath", &self.secret_path);
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?
            .json::<Resp>()
            .await?;
        Ok(resp.secret.secret_value)
    }
}

fn default_http() -> Result<reqwest::Client, reqwest::Error> {
    http_client::builder(Profile::Custom(Duration::from_secs(15))).build()
}

fn non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// One re-read pass: fetch each managed secret and swap it into the store.
/// Best-effort — a fetch or reload error for one credential is logged and the
/// others still proceed; a stale credential simply keeps its prior token until
/// the next pass succeeds (its `bearer()` surfaces `AwaitingReread` if it
/// lapses meanwhile). Never panics.
pub async fn reload_once(
    client: &InfisicalReadClient,
    store: &LlmCredentialStore,
    entries: &[CredReloadEntry],
) {
    for e in entries {
        match client.read_secret(&e.secret).await {
            Ok(value) => {
                if let Err(err) = store.reload(e.provider, &e.label, &value).await {
                    tracing::warn!(
                        provider = e.provider.as_str(),
                        label = %e.label,
                        error = %err,
                        "llm credential re-read: reload failed (keeping prior token)",
                    );
                }
            }
            Err(err) => tracing::warn!(
                provider = e.provider.as_str(),
                label = %e.label,
                secret = %e.secret,
                error = %err,
                "llm credential re-read: Infisical fetch failed (keeping prior token)",
            ),
        }
    }
}

/// Mark every managed credential externally-refreshed. The caller MUST `await`
/// this **synchronously, before the server starts accepting traffic** — their
/// boot refresh token is already stale, so `bearer()` must re-read rather than
/// refresh, and the suppression only takes effect once the flag is set. Doing it
/// here (not inside the spawned scheduler) closes the race where a request lands
/// in the window between the listener opening and the spawned task running.
/// A configured-but-unloaded credential is a non-fatal warning.
pub async fn mark_external(store: &LlmCredentialStore, entries: &[CredReloadEntry]) {
    for e in entries {
        if !store.mark_externally_refreshed(e.provider, &e.label).await {
            tracing::warn!(
                provider = e.provider.as_str(),
                label = %e.label,
                "llm credential re-read: configured to reload a credential that isn't loaded",
            );
        }
    }
}

/// Run the periodic re-read until `shutdown`. Mirrors the cache-sweep scheduler:
/// skip the t=0 tick, then re-read every `interval_period`. The managed
/// credentials must already be marked externally-refreshed via [`mark_external`]
/// (the caller does this synchronously before serving traffic).
pub async fn run_reload_scheduler(
    client: InfisicalReadClient,
    store: Arc<LlmCredentialStore>,
    entries: Vec<CredReloadEntry>,
    interval_period: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    use tokio::pin;
    use tokio::time::interval;

    pin!(shutdown);
    let mut ticker = interval(interval_period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // skip t=0: the boot-injected token is already fresh.
    tracing::info!(
        interval_secs = interval_period.as_secs(),
        entries = entries.len(),
        "llm credential re-read scheduler started",
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("llm credential re-read scheduler shutting down");
                return;
            }
            _ = ticker.tick() => {
                reload_once(&client, &store, &entries).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn raw_test_http_client() -> reqwest::Client {
        reqwest::Client::new() // A raw test client isolates secret reload behavior from gateway policy.
    }

    #[test]
    fn environment_constructor_is_fallible_when_transport_setup_fails() {
        let constructor: fn() -> anyhow::Result<Option<InfisicalReadClient>> =
            InfisicalReadClient::from_env;
        let _ = constructor;
    }

    #[test]
    fn configured_environment_requires_explicit_credential_coordinates() {
        let _guard = crate::config::ENV_GUARD
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        const KEYS: [&str; 5] = [
            "GATEWAY_INFISICAL_API_URL",
            "GATEWAY_INFISICAL_TOKEN",
            "GATEWAY_INFISICAL_PROJECT_ID",
            "GATEWAY_INFISICAL_ENV",
            "GATEWAY_INFISICAL_SECRET_PATH",
        ];
        let previous: Vec<_> = KEYS
            .into_iter()
            .map(|key| (key, std::env::var(key).ok()))
            .collect();
        for key in KEYS {
            std::env::remove_var(key);
        }
        let disabled = InfisicalReadClient::from_env();
        std::env::set_var("GATEWAY_INFISICAL_API_URL", "https://secrets-provider.test");
        std::env::set_var("GATEWAY_INFISICAL_TOKEN", "test-token");
        std::env::set_var("GATEWAY_INFISICAL_PROJECT_ID", "test-project");

        let missing_environment = InfisicalReadClient::from_env();
        std::env::set_var("GATEWAY_INFISICAL_ENV", "staging");
        let missing_path = InfisicalReadClient::from_env();
        std::env::set_var("GATEWAY_INFISICAL_SECRET_PATH", "/gateway/credentials");
        let result = InfisicalReadClient::from_env();

        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        assert!(disabled
            .expect("unconfigured integration stays disabled")
            .is_none());
        assert!(missing_environment
            .err()
            .expect("environment is required")
            .to_string()
            .contains("GATEWAY_INFISICAL_ENV"));
        assert!(missing_path
            .err()
            .expect("path is required")
            .to_string()
            .contains("GATEWAY_INFISICAL_SECRET_PATH"));
        let client = result
            .expect("configured client construction must succeed")
            .expect("complete Infisical configuration must enable the client");
        assert_eq!(client.environment, "staging");
        assert_eq!(client.secret_path, "/gateway/credentials");
    }

    #[test]
    fn parse_reload_config_maps_known_providers_and_drops_unknown() {
        let raw = r#"[
            {"provider":"ANTHROPIC","label":"PRIMARY","secret":"ANTHROPIC_API_KEY"},
            {"provider":"openai","label":"PRIMARY","secret":"CODEX_AUTH_JSON"},
            {"provider":"GEMINI","label":"PRIMARY","secret":"GEMINI_CREDENTIALS_JSON"},
            {"provider":"bogus","label":"X","secret":"Y"}
        ]"#;
        let entries = parse_reload_config(raw);
        assert_eq!(entries.len(), 3, "the unknown provider is dropped");
        // The reload mapping shares LLM_CRED_*'s case-insensitive provider
        // vocabulary: UPPERCASE maps, and the GEMINI alias resolves to Google.
        assert_eq!(entries[0].provider, LlmProvider::Anthropic);
        assert_eq!(entries[0].secret, "ANTHROPIC_API_KEY");
        assert_eq!(entries[1].provider, LlmProvider::OpenAi);
        assert_eq!(
            entries[2].provider,
            LlmProvider::Google,
            "GEMINI is an alias for GOOGLE, matching the LLM_CRED_* keys"
        );
        // Invalid / empty JSON ⇒ no entries (poller won't spawn).
        assert!(parse_reload_config("not json").is_empty());
        assert!(parse_reload_config("").is_empty());
    }

    /// Loopback stand-in for the Infisical raw-secrets API: serves a fresh
    /// OpenAI blob for the configured secret name.
    async fn spawn_fake_infisical(fresh_blob: &'static str) -> std::net::SocketAddr {
        use axum::extract::Path;
        use axum::routing::get;
        use axum::Router;
        let app = Router::new().route(
            "/api/v3/secrets/raw/{name}",
            get(move |Path(_name): Path<String>| async move {
                axum::Json(serde_json::json!({ "secret": { "secretValue": fresh_blob } }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    async fn spawn_stalled_infisical() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        addr
    }

    #[tokio::test]
    async fn injected_deadline_bounds_infisical_read() {
        let addr = spawn_stalled_infisical().await;
        let http = waygate_core::http_client::client(Profile::Custom(Duration::from_millis(50)))
            .expect("short-timeout Infisical client");
        let client = InfisicalReadClient::new(
            http,
            format!("http://{addr}"),
            "test-token",
            "proj",
            "prod",
            "/credentials",
        );

        let error = client
            .read_secret("CODEX_AUTH_JSON")
            .await
            .expect_err("stalled Infisical read must time out");

        let request_error = error
            .downcast_ref::<reqwest::Error>()
            .expect("request error preserved");
        assert!(request_error.is_timeout(), "{request_error}");
    }

    #[tokio::test(start_paused = true)]
    async fn default_infisical_client_enforces_fifteen_second_deadline() {
        let addr = spawn_stalled_infisical().await;
        let client = InfisicalReadClient::new(
            default_http().expect("default Infisical client"),
            format!("http://{addr}"),
            "test-token",
            "proj",
            "prod",
            "/credentials",
        );

        let read = tokio::spawn(async move {
            client
                .read_secret("CODEX_AUTH_JSON")
                .await
                .expect_err("stalled Infisical read must time out")
        });
        let error = tokio::time::timeout(Duration::from_secs(16), read)
            .await
            .expect("the Infisical client must bound the read")
            .expect("Infisical read task must complete");
        let request_error = error
            .downcast_ref::<reqwest::Error>()
            .expect("request error preserved");
        assert!(request_error.is_timeout(), "{request_error}");
    }

    #[tokio::test]
    async fn reload_once_swaps_in_the_fresh_token_from_infisical() {
        // Store boots with an EXPIRED OpenAI token (externally refreshed), so
        // bearer() initially fails with AwaitingReread — proving the token is
        // stale and not refreshed in-process.
        let store = Arc::new(LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_PRIMARY".to_string(),
            r#"{"tokens":{"access_token":"at-stale","refresh_token":"rt"},"expires_at":"2000-01-01T00:00:00Z"}"#
                .to_string(),
        )]));
        store
            .mark_externally_refreshed(LlmProvider::OpenAi, "PRIMARY")
            .await;
        assert!(store.bearer(LlmProvider::OpenAi, "PRIMARY").await.is_err());

        // Infisical now has a fresh (future-expiry) blob.
        let fresh = r#"{"tokens":{"access_token":"at-fresh","refresh_token":"rt2"},"expires_at":"2100-01-01T00:00:00Z"}"#;
        let addr = spawn_fake_infisical(fresh).await;
        let client = InfisicalReadClient::new(
            raw_test_http_client(),
            format!("http://{addr}"),
            "test-token",
            "proj",
            "prod",
            "/ai-credential-refresh",
        );
        let entries = vec![CredReloadEntry {
            provider: LlmProvider::OpenAi,
            label: "PRIMARY".to_string(),
            secret: "CODEX_AUTH_JSON".to_string(),
        }];

        reload_once(&client, &store, &entries).await;

        // The store now serves the fresh token — re-read picked it up, no
        // in-process OAuth refresh involved.
        assert_eq!(
            store.bearer(LlmProvider::OpenAi, "PRIMARY").await.unwrap(),
            "at-fresh",
        );
    }

    #[tokio::test]
    async fn mark_external_suppresses_refresh_and_tolerates_unloaded() {
        // A loaded OpenAI cred with an EXPIRED token, NOT yet marked external.
        let store = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_PRIMARY".to_string(),
            r#"{"tokens":{"access_token":"at","refresh_token":"rt"},"expires_at":"2000-01-01T00:00:00Z"}"#
                .to_string(),
        )]);
        let entries = vec![
            CredReloadEntry {
                provider: LlmProvider::OpenAi,
                label: "PRIMARY".to_string(),
                secret: "CODEX_AUTH_JSON".to_string(),
            },
            // A configured-but-unloaded credential: mark_external must not panic.
            CredReloadEntry {
                provider: LlmProvider::OpenAi,
                label: "ABSENT".to_string(),
                secret: "CODEX_AUTH_JSON".to_string(),
            },
        ];

        mark_external(&store, &entries).await;

        // The loaded cred is now externally refreshed: an expired token yields
        // AwaitingReread (no in-process refresh / network), proving the mark took.
        match store.bearer(LlmProvider::OpenAi, "PRIMARY").await {
            Err(waygate_llm_credentials::CredentialError::AwaitingReread { .. }) => {}
            other => panic!("expected AwaitingReread after mark_external, got {other:?}"),
        }
    }
}
