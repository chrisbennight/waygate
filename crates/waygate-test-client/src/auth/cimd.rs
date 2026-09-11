//! CIMD authorization-code + PKCE OAuth flow, tailored to Claude Code-style
//! ephemeral loopback callbacks.
//!
//! Flow:
//!   1. Discover the gateway's AS metadata (authorization_endpoint,
//!      token_endpoint).
//!   2. Generate PKCE S256 verifier/challenge (`rand` + `sha2` + `base64`,
//!      all workspace deps).
//!   3. Bind `127.0.0.1:0`, print the authorize URL, open the system
//!      browser.
//!   4. Accept exactly one callback, validate `state`, shut the server down,
//!      POST the token exchange form to `token_endpoint`.
//!   5. Return a `Token` ready to cache.
//!
//! Token values (access, refresh, code, verifier) are NEVER logged.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, info};

use crate::auth::cache::Token;
use crate::gateway::discover::AsMetadata;

/// Response surface of `POST /oauth/token` — mirrors `waygate-as::token::TokenResponse`
/// but is its own type here so the client doesn't take a compile-time
/// dependency on the gateway.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    pub expires_in: i64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: [u8; 32],
    pub challenge: String,
}

impl PkcePair {
    /// RFC 7636 §4.1: verifier is 43..=128 chars of URL-safe base64. 32 bytes
    /// yields 43 characters, which is the minimum (and what Authentik and
    /// most IdPs emit themselves).
    pub fn new() -> Self {
        let mut verifier = [0u8; 32];
        rand::rng().fill_bytes(&mut verifier);
        let verifier_b64 = URL_SAFE_NO_PAD.encode(verifier);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier_b64.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }

    pub fn verifier_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.verifier)
    }
}

impl Default for PkcePair {
    fn default() -> Self {
        Self::new()
    }
}

/// Random URL-safe opaque token — used for the `state` parameter.
fn random_opaque_token() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

type CallbackSender = Arc<Mutex<Option<oneshot::Sender<Result<String, CallbackError>>>>>;

/// Wait for exactly one successful callback, or a timeout / cancellation.
#[derive(Clone)]
struct CallbackState {
    expected_state: String,
    sender: CallbackSender,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum CallbackError {
    #[error("state mismatch (got `{got}`, expected `{expected}`) — possible CSRF")]
    StateMismatch { got: String, expected: String },
    #[error("missing `code` in callback query")]
    MissingCode,
    #[error("authorization server returned error `{error}`: {description}")]
    AsError { error: String, description: String },
}

async fn callback(
    State(st): State<CallbackState>,
    Query(q): Query<CallbackQuery>,
) -> Html<&'static str> {
    let sender = {
        let mut guard = st.sender.lock().await;
        guard.take()
    };
    let result = match q {
        CallbackQuery {
            error: Some(err),
            error_description,
            ..
        } => Err(CallbackError::AsError {
            error: err,
            description: error_description.unwrap_or_default(),
        }),
        CallbackQuery {
            state: Some(got), ..
        } if got != st.expected_state => Err(CallbackError::StateMismatch {
            got,
            expected: st.expected_state.clone(),
        }),
        CallbackQuery {
            code: Some(code), ..
        } => Ok(code),
        _ => Err(CallbackError::MissingCode),
    };

    let page = if result.is_ok() {
        "<!doctype html><title>Waygate test client</title>\
         <body style='font-family:system-ui;padding:2rem'>\
         <h1>Login complete</h1>\
         <p>You can close this tab and return to the terminal.</p>\
         </body>"
    } else {
        "<!doctype html><title>Waygate test client</title>\
         <body style='font-family:system-ui;padding:2rem'>\
         <h1>Login failed</h1>\
         <p>Check the terminal for details.</p>\
         </body>"
    };
    if let Some(tx) = sender {
        let _ = tx.send(result);
    }
    Html(page)
}

/// Run the full CIMD flow and return the newly-minted token.
pub async fn login(
    metadata: &AsMetadata,
    cimd_url: &str,
    scopes: &[String],
    http: &HttpClient,
) -> Result<Token> {
    let pkce = PkcePair::new();
    let state_token = random_opaque_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind loopback listener for OAuth callback")?;
    let local_addr = listener
        .local_addr()
        .context("read loopback port after bind")?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", local_addr.port());
    debug!(port = local_addr.port(), "CIMD callback listener bound");

    let (tx, rx) = oneshot::channel::<Result<String, CallbackError>>();
    let cb_state = CallbackState {
        expected_state: state_token.clone(),
        sender: Arc::new(Mutex::new(Some(tx))),
    };
    let app = axum::Router::new()
        .route("/callback", get(callback))
        .with_state(cb_state);

    // Run the server in the background; we'll ignore its shutdown signal
    // beyond dropping the task when we have a code in hand.
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let authorize_url = build_authorize_url(
        &metadata.authorization_endpoint,
        cimd_url,
        &redirect_uri,
        &pkce.challenge,
        &state_token,
        scopes,
    )?;

    info!(
        authorize_endpoint = %metadata.authorization_endpoint,
        client_id = %cimd_url,
        "opening browser for CIMD authorization"
    );
    eprintln!(
        "Opening browser for login:\n  {}\n\n\
         If the browser does not open automatically, paste the URL above.\n\
         Waiting for callback on http://127.0.0.1:{}/callback…",
        authorize_url,
        local_addr.port(),
    );
    // `open` best-effort — SSH sessions or headless envs print + wait.
    let _ = open::that(authorize_url.as_str());

    let code = tokio::select! {
        res = rx => {
            res.map_err(|_| anyhow!("callback channel dropped before delivery"))?
                .map_err(|e| anyhow!(e))?
        }
        _ = tokio::time::sleep(Duration::from_secs(300)) => {
            anyhow::bail!("timed out after 5 minutes waiting for authorization callback");
        }
    };
    server.abort();

    let token_resp = exchange_code(
        http,
        &metadata.token_endpoint,
        cimd_url,
        &redirect_uri,
        &code,
        &pkce.verifier_b64(),
    )
    .await?;

    let token = into_token(
        token_resp,
        cimd_url,
        &metadata.token_endpoint,
        metadata.issuer.clone(),
    );
    Ok(token)
}

fn build_authorize_url(
    authorize_endpoint: &str,
    cimd_url: &str,
    redirect_uri: &str,
    challenge: &str,
    state_token: &str,
    scopes: &[String],
) -> Result<String> {
    let mut u = url::Url::parse(authorize_endpoint)
        .with_context(|| format!("parse authorize endpoint `{authorize_endpoint}`"))?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", cimd_url)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state_token);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(u.into())
}

async fn exchange_code(
    http: &HttpClient,
    token_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse> {
    debug!(%token_endpoint, "exchanging authorization code for tokens");
    let resp = http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .with_context(|| format!("POST {token_endpoint}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("token endpoint returned {status}: {body}");
    }
    resp.json::<TokenResponse>()
        .await
        .context("decode token response")
}

pub async fn refresh(
    http: &HttpClient,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse> {
    debug!(%token_endpoint, "refreshing access token");
    let resp = http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])
        .send()
        .await
        .with_context(|| format!("POST {token_endpoint}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("refresh endpoint returned {status}: {body}");
    }
    resp.json::<TokenResponse>()
        .await
        .context("decode refresh response")
}

pub fn into_token(
    resp: TokenResponse,
    client_id: &str,
    token_endpoint: &str,
    issuer: Option<String>,
) -> Token {
    Token {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(resp.expires_in),
        token_type: resp.token_type.unwrap_or_else(|| "Bearer".to_owned()),
        scope: resp.scope,
        issuer,
        client_id: Some(client_id.to_owned()),
        token_endpoint: Some(token_endpoint.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-tests the live RNG-fill path through `PkcePair::new`. A broken
    /// rand-crate API surfaces as a compile failure here; distinct verifiers
    /// across calls additionally guard against a stuck-at-zero RNG.
    #[test]
    fn pkce_pair_new_uses_live_rng() {
        let a = PkcePair::new();
        let b = PkcePair::new();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
        // Challenge must be the SHA-256 of the base64url-encoded verifier.
        let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(a.verifier_b64().as_bytes()));
        assert_eq!(a.challenge, expect);
    }

    /// Companion smoke test for `random_opaque_token` — same rationale as
    /// `pkce_pair_new_uses_live_rng`. 24 bytes → 32 URL-safe base64 chars.
    #[test]
    fn random_opaque_token_shape_and_uniqueness() {
        let a = random_opaque_token();
        let b = random_opaque_token();
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        // Deterministic: override the verifier with the RFC 7636 example.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let chal = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(chal, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn authorize_url_includes_required_params() {
        let url = build_authorize_url(
            "https://gw.example/oauth/authorize",
            "https://client.example/cimd.json",
            "http://127.0.0.1:54321/callback",
            "CHALLENGE",
            "STATE",
            &["mcp:invoke".to_owned()],
        )
        .unwrap();
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=CHALLENGE"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=STATE"));
        assert!(url.contains("scope=mcp%3Ainvoke"));
        assert!(url.contains("client_id=https%3A%2F%2Fclient.example%2Fcimd.json"));
    }

    // The reqwest call sites below run against a tiny axum server bound to
    // 127.0.0.1:0. They cover the form-encoded POST + JSON decode + status
    // handling paths in `exchange_code` and `refresh` — the highest-value
    // reqwest paths in this crate, which no other test exercises (so a
    // reqwest bump could otherwise regress them silently).

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::extract::{Form, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::Json;
    use axum::Router;
    use reqwest::Client as HttpClient;
    use serde::Serialize;
    use tokio::net::TcpListener;

    #[derive(Default, Clone)]
    struct CapturedForm {
        last: Arc<Mutex<Option<HashMap<String, String>>>>,
    }

    #[derive(Serialize)]
    struct OkBody {
        access_token: &'static str,
        token_type: &'static str,
        expires_in: i64,
        refresh_token: &'static str,
        scope: &'static str,
    }

    async fn ok_handler(
        State(state): State<CapturedForm>,
        Form(payload): Form<HashMap<String, String>>,
    ) -> Response {
        *state.last.lock().unwrap() = Some(payload);
        Json(OkBody {
            access_token: "AT",
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: "RT",
            scope: "mcp:invoke",
        })
        .into_response()
    }

    async fn error_handler() -> Response {
        (
            StatusCode::BAD_REQUEST,
            "{\"error\":\"invalid_grant\"}".to_string(),
        )
            .into_response()
    }

    async fn spawn_token_endpoint(path: &'static str, ok: bool) -> (String, CapturedForm) {
        let captured = CapturedForm::default();
        let app: Router = if ok {
            Router::new()
                .route(path, post(ok_handler))
                .with_state(captured.clone())
        } else {
            Router::new().route(path, post(error_handler))
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}{path}"), captured)
    }

    #[tokio::test]
    async fn exchange_code_posts_form_and_decodes_json() {
        let (token_url, captured) = spawn_token_endpoint("/oauth/token", true).await;
        let http = HttpClient::new();
        let resp = exchange_code(
            &http,
            &token_url,
            "https://client.example/cimd.json",
            "http://127.0.0.1:0/callback",
            "AUTH-CODE",
            "VERIFIER",
        )
        .await
        .expect("exchange_code returned a TokenResponse");

        assert_eq!(resp.access_token, "AT");
        assert_eq!(resp.refresh_token.as_deref(), Some("RT"));
        assert_eq!(resp.expires_in, 3600);

        let form = captured.last.lock().unwrap().clone().unwrap();
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(form.get("code").map(String::as_str), Some("AUTH-CODE"));
        assert_eq!(
            form.get("code_verifier").map(String::as_str),
            Some("VERIFIER")
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("https://client.example/cimd.json"),
        );
    }

    #[tokio::test]
    async fn refresh_posts_form_and_decodes_json() {
        let (token_url, captured) = spawn_token_endpoint("/oauth/token", true).await;
        let http = HttpClient::new();
        let resp = refresh(
            &http,
            &token_url,
            "https://client.example/cimd.json",
            "OLD-REFRESH",
        )
        .await
        .expect("refresh returned a TokenResponse");

        assert_eq!(resp.access_token, "AT");

        let form = captured.last.lock().unwrap().clone().unwrap();
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert_eq!(
            form.get("refresh_token").map(String::as_str),
            Some("OLD-REFRESH")
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("https://client.example/cimd.json"),
        );
    }

    #[tokio::test]
    async fn refresh_surfaces_error_status() {
        let (token_url, _captured) = spawn_token_endpoint("/oauth/token", false).await;
        let http = HttpClient::new();
        let err = refresh(
            &http,
            &token_url,
            "https://client.example/cimd.json",
            "OLD-REFRESH",
        )
        .await
        .expect_err("error status must surface as Err");
        let msg = format!("{err:#}");
        assert!(msg.contains("400"), "expected status in message: {msg}");
        assert!(
            msg.contains("invalid_grant"),
            "expected body in message: {msg}"
        );
    }
}
