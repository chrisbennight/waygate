//! PKCE + OAuth 2.1 authorization-code flow used by the admin dashboard.
//!
//! The dashboard acts as a *confidential* client (it has a client secret,
//! stored in Infisical) but still uses PKCE. Authentik's docs recommend PKCE
//! for every client, and it's the defense against a leaked-redirect attack
//! on top of client_secret auth at the token endpoint.
//!
//! This module does three things:
//! 1. Generate a fresh PKCE verifier + S256 challenge (`new_pkce_pair`).
//! 2. Discover the IdP's authorize / token endpoints via
//!    `.well-known/openid-configuration` (`OidcEndpoints::discover`).
//! 3. Exchange an auth code for a token response (`exchange_code`), using
//!    the PKCE verifier and client credentials.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Result of [`new_pkce_pair`]. The verifier is held in the login-state
/// cookie until the callback; the challenge rides in the authorize URL.
#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// RFC 7636 §4.1 recommends 43–128 chars of URL-safe random. 32 bytes →
/// 43 chars base64url — the minimum. We use the minimum because the
/// verifier rides in a cookie and we'd like to keep the cookie small.
pub fn new_pkce_pair() -> PkcePair {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkcePair {
        verifier,
        challenge,
    }
}

/// Random URL-safe string used as the OAuth `state` parameter and as a
/// generic opaque token (CSRF, session identifiers). 32 bytes → 43 chars.
pub fn new_random_token() -> String {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Subset of OIDC discovery we actually use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub issuer: String,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("status {0}")]
    Status(reqwest::StatusCode),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl OidcEndpoints {
    /// Fetch `<issuer>/.well-known/openid-configuration` with the caller's
    /// shared client. Strips any trailing slash on `issuer` so
    /// `"https://auth/"` and `"https://auth"` both work.
    pub async fn discover(http: &reqwest::Client, issuer: &str) -> Result<Self, DiscoveryError> {
        let base = issuer.trim_end_matches('/');
        let url = format!("{base}/.well-known/openid-configuration");
        let resp = http.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(DiscoveryError::Status(resp.status()));
        }
        let body = resp.bytes().await?;
        let ep: OidcEndpoints = serde_json::from_slice(&body)?;
        Ok(ep)
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("token endpoint returned {status}: {body}")]
    Status {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Parameters for [`exchange_code`]. Carries everything PKCE needs: the
/// verifier that matches the pre-flight challenge plus the client creds
/// that prove we're the confidential client that issued the authorize URL.
pub struct ExchangeParams<'a> {
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub code: &'a str,
    pub pkce_verifier: &'a str,
}

/// POST to the token endpoint with the caller's shared client. Uses
/// `application/x-www-form-urlencoded` per RFC 6749 §4.1.3 (every OIDC IdP
/// expects form-encoded here). The caller owns timeout and redirect policy.
///
/// The body is constructed by hand rather than via `reqwest`'s `.form()`
/// helper because our workspace disables reqwest default features.
pub async fn exchange_code(
    http: &reqwest::Client,
    params: ExchangeParams<'_>,
) -> Result<TokenResponse, TokenError> {
    let pairs = [
        ("grant_type", "authorization_code"),
        ("code", params.code),
        ("redirect_uri", params.redirect_uri),
        ("client_id", params.client_id),
        ("client_secret", params.client_secret),
        ("code_verifier", params.pkce_verifier),
    ];
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let resp = http
        .post(params.token_endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.bytes().await?;
    if !status.is_success() {
        return Err(TokenError::Status {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    let parsed: TokenResponse = serde_json::from_slice(&body)?;
    Ok(parsed)
}

/// Parameters for [`refresh_access_token`]. RFC 6749 §6 refresh-token
/// grant. Same client-credentials shape as [`ExchangeParams`] minus the
/// PKCE / code fields; `refresh_token` replaces `code`.
pub struct RefreshParams<'a> {
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub refresh_token: &'a str,
}

/// POST to the IdP's token endpoint with the `refresh_token` grant through the
/// caller's shared client.
/// Returns a fresh [`TokenResponse`]; the upstream IdP MAY (Authentik
/// does) include a rotated `refresh_token` field which callers should
/// persist in place of the old one.
///
/// Same wire conventions as [`exchange_code`] — form-encoded body, no
/// `reqwest::Client::form()` because the workspace disables default
/// features.
pub async fn refresh_access_token(
    http: &reqwest::Client,
    params: RefreshParams<'_>,
) -> Result<TokenResponse, TokenError> {
    let pairs = [
        ("grant_type", "refresh_token"),
        ("refresh_token", params.refresh_token),
        ("client_id", params.client_id),
        ("client_secret", params.client_secret),
    ];
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    // The injected client owns the total request timeout and redirect policy.
    // The composition root shares one bounded token client across code exchange
    // and refresh so this hot path never constructs transport policy per call.
    let resp = http
        .post(params.token_endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.bytes().await?;
    if !status.is_success() {
        return Err(TokenError::Status {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    let parsed: TokenResponse = serde_json::from_slice(&body)?;
    Ok(parsed)
}

/// Parameters for [`authorize_url`]. `prompt` and `acr_values` expose the
/// independent standard OIDC controls. The dashboard uses `prompt=login` for
/// fresh re-authentication and leaves authentication-method policy to the IdP.
pub struct AuthorizeParams<'a> {
    pub authorization_endpoint: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a [String],
    pub state: &'a str,
    pub pkce_challenge: &'a str,
    /// OIDC `acr_values`. Whitespace-separated list of Authentication Context
    /// Class References the caller is asking for; Authentik maps these to
    /// its authentication flows.
    pub acr_values: Option<&'a str>,
    /// OIDC `prompt`. `login` forces the IdP to re-prompt for credentials
    /// even if a session exists.
    pub prompt: Option<&'a str>,
}

/// Build the authorize URL the browser is redirected to at login start.
/// Every param is explicit: no "and also these defaults" surprises in the
/// IdP round-trip.
pub fn authorize_url(p: &AuthorizeParams<'_>) -> String {
    let scope = p.scopes.join(" ");
    let mut url = format!(
        "{ep}?response_type=code&client_id={cid}&redirect_uri={rurl}\
         &scope={scope}&state={state}\
         &code_challenge={chal}&code_challenge_method=S256",
        ep = p.authorization_endpoint,
        cid = urlencode(p.client_id),
        rurl = urlencode(p.redirect_uri),
        scope = urlencode(&scope),
        state = urlencode(p.state),
        chal = urlencode(p.pkce_challenge),
    );
    if let Some(acr) = p.acr_values {
        url.push_str("&acr_values=");
        url.push_str(&urlencode(acr));
    }
    if let Some(prompt) = p.prompt {
        url.push_str("&prompt=");
        url.push_str(&urlencode(prompt));
    }
    url
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_pair_is_valid_s256() {
        let p = new_pkce_pair();
        // 32 random bytes → 43 URL-safe base64 chars.
        assert_eq!(p.verifier.len(), 43);
        // Manually recompute the challenge to confirm format.
        let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, expect);
    }

    /// Calls `new_pkce_pair()` repeatedly to exercise the RNG-fill path.
    /// A regression that breaks the `rand` API (e.g. an unfixed version bump)
    /// surfaces here as a compile failure even before the assertion runs;
    /// distinct outputs additionally guard against a stuck-at-zero RNG.
    #[test]
    fn pkce_pair_is_non_deterministic() {
        let a = new_pkce_pair();
        let b = new_pkce_pair();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
    }

    /// Counterpart for `new_random_token()`. Pairs the same RNG-fill smoke
    /// check with shape assertions (32 bytes → 43 URL-safe base64 chars).
    #[test]
    fn random_token_shape_and_uniqueness() {
        let a = new_random_token();
        let b = new_random_token();
        assert_eq!(a.len(), 43);
        assert_eq!(b.len(), 43);
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        assert_ne!(a, b);
    }

    #[test]
    fn authorize_url_encodes_all_fields() {
        let url = authorize_url(&AuthorizeParams {
            authorization_endpoint: "https://auth.example.com/authorize",
            client_id: "my/client",
            redirect_uri: "https://gw.example.com/admin/auth/callback?x=1",
            scopes: &["openid".into(), "profile email".into()],
            state: "state+val",
            pkce_challenge: "chal/val",
            acr_values: None,
            prompt: None,
        });
        assert!(url.contains("client_id=my%2Fclient"));
        assert!(url.contains(
            "redirect_uri=https%3A%2F%2Fgw.example.com%2Fadmin%2Fauth%2Fcallback%3Fx%3D1"
        ));
        assert!(url.contains("scope=openid%20profile%20email"));
        assert!(url.contains("state=state%2Bval"));
        assert!(url.contains("code_challenge=chal%2Fval"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(!url.contains("acr_values"));
        assert!(!url.contains("prompt"));
    }

    #[test]
    fn authorize_url_includes_step_up_params_when_set() {
        let url = authorize_url(&AuthorizeParams {
            authorization_endpoint: "https://auth.example.com/authorize",
            client_id: "c",
            redirect_uri: "https://gw.example.com/cb",
            scopes: &["openid".into(), "mcp:invoke:high".into()],
            state: "s",
            pkce_challenge: "ch",
            acr_values: Some("urn:authentik:mfa"),
            prompt: Some("login"),
        });
        assert!(url.contains("scope=openid%20mcp%3Ainvoke%3Ahigh"));
        assert!(url.contains("acr_values=urn%3Aauthentik%3Amfa"));
        assert!(url.contains("prompt=login"));
    }
}
