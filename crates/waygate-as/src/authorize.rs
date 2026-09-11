//! `GET /oauth/authorize` — entry point of the OAuth flow.
//!
//! Receives the client's authorize request, validates `client_id` (CIMD URL
//! or exact-match trusted client), checks the requested `redirect_uri`
//! against the CIMD document's `redirect_uris`, persists a transaction row,
//! then 302s the browser to Authentik with gateway-side PKCE.

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};

use waygate_oidc::pkce::{authorize_url, new_pkce_pair, new_random_token, AuthorizeParams};

use crate::cimd::{CimdError, CimdFetcher};
use crate::router::AsState;
use crate::store::Transaction;

/// Parsed query string of `/oauth/authorize`.
///
/// `response_type` + `code_challenge_method` MUST be `code` + `S256` — we
/// only implement authorization-code with PKCE. Anything else gets a
/// one-shot 400.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub resource: Option<String>,
}

pub async fn handler(State(state): State<AsState>, Query(q): Query<AuthorizeQuery>) -> Response {
    match handle(&state, q).await {
        Ok(redirect) => redirect_response(&redirect),
        Err(err) => err.into_response(),
    }
}

async fn handle(state: &AsState, q: AuthorizeQuery) -> Result<String, AuthorizeError> {
    if q.response_type != "code" {
        return Err(AuthorizeError::UnsupportedResponseType);
    }
    if q.code_challenge_method != "S256" {
        return Err(AuthorizeError::UnsupportedChallengeMethod);
    }

    // Only CIMD client IDs are accepted. Anything else is rejected up-front —
    // we explicitly don't do DCR and don't maintain a static-client registry.
    if !CimdFetcher::is_cimd_client_id(&q.client_id) {
        return Err(AuthorizeError::InvalidClient);
    }
    let doc = state
        .cimd
        .fetch(&q.client_id)
        .await
        .map_err(AuthorizeError::Cimd)?;

    if !state.cimd.validate_redirect_uri(&doc, &q.redirect_uri) {
        return Err(AuthorizeError::InvalidRedirectUri);
    }

    let scopes = parse_scopes(q.scope.as_deref(), &state.config.allowed_scopes)?;

    // Dual PKCE: gateway generates its own verifier to use with Authentik.
    let proxy_pkce = new_pkce_pair();
    let txn_id = new_random_token();

    let ttl = state.config.transaction_ttl;
    let expires_at = OffsetDateTime::now_utc() + TimeDuration::seconds(ttl.as_secs() as i64);
    let txn = Transaction {
        txn_id: txn_id.clone(),
        client_id: q.client_id.clone(),
        client_redirect_uri: q.redirect_uri.clone(),
        client_state: q.state.clone(),
        code_challenge: q.code_challenge.clone(),
        code_challenge_method: q.code_challenge_method.clone(),
        scopes: scopes.clone(),
        resource: q.resource.clone(),
        proxy_code_verifier: proxy_pkce.verifier.clone(),
        expires_at,
    };
    state
        .store
        .insert_transaction(&txn)
        .await
        .map_err(|e| AuthorizeError::Internal(e.to_string()))?;

    let url = authorize_url(&AuthorizeParams {
        authorization_endpoint: &state.config.upstream_authorize_endpoint,
        client_id: &state.config.upstream_client_id,
        redirect_uri: &state.config.upstream_redirect_uri,
        scopes: &state.config.upstream_scopes,
        state: &txn_id,
        pkce_challenge: &proxy_pkce.challenge,
        acr_values: None,
        prompt: None,
    });

    tracing::debug!(
        client_id = %q.client_id,
        txn_id = %txn_id,
        scopes = ?scopes,
        "/oauth/authorize → upstream"
    );
    Ok(url)
}

fn parse_scopes(raw: Option<&str>, allowed: &[String]) -> Result<Vec<String>, AuthorizeError> {
    let requested: Vec<String> = raw
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let effective = if requested.is_empty() {
        // Default to `mcp:invoke` if the client didn't ask — most OAuth
        // libraries omit scope on the authorize request and expect a sane
        // server-side default.
        vec!["mcp:invoke".to_owned()]
    } else {
        requested
    };
    for s in &effective {
        if !allowed.iter().any(|a| a == s) {
            return Err(AuthorizeError::InvalidScope(s.clone()));
        }
    }
    Ok(effective)
}

/// RFC 6749 §4.1.2.1 errors that fall into the "no redirect target" bucket
/// get a simple 400 — we can't redirect to an unverified client URL.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    #[error("response_type must be `code`")]
    UnsupportedResponseType,
    #[error("code_challenge_method must be `S256`")]
    UnsupportedChallengeMethod,
    #[error("invalid_client: client_id must be a CIMD URL")]
    InvalidClient,
    #[error("invalid_redirect_uri: not allowed by CIMD document")]
    InvalidRedirectUri,
    #[error("invalid_scope: `{0}` is not supported")]
    InvalidScope(String),
    #[error("cimd error: {0}")]
    Cimd(#[from] CimdError),
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for AuthorizeError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AuthorizeError::UnsupportedResponseType => {
                (StatusCode::BAD_REQUEST, "unsupported_response_type")
            }
            AuthorizeError::UnsupportedChallengeMethod => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            AuthorizeError::InvalidClient => (StatusCode::BAD_REQUEST, "invalid_client"),
            AuthorizeError::InvalidRedirectUri => (StatusCode::BAD_REQUEST, "invalid_redirect_uri"),
            AuthorizeError::InvalidScope(_) => (StatusCode::BAD_REQUEST, "invalid_scope"),
            AuthorizeError::Cimd(_) => (StatusCode::BAD_REQUEST, "invalid_client"),
            AuthorizeError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        tracing::info!(error = %self, "authorize rejected");
        let body = serde_json::json!({
            "error": code,
            "error_description": self.to_string(),
        });
        (status, axum::Json(body)).into_response()
    }
}

fn redirect_response(url: &str) -> Response {
    let mut resp = (StatusCode::FOUND, "").into_response();
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(url).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scopes_defaults_to_mcp_invoke() {
        let allowed = vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()];
        let s = parse_scopes(None, &allowed).unwrap();
        assert_eq!(s, vec!["mcp:invoke".to_owned()]);
    }

    #[test]
    fn parse_scopes_rejects_unknown() {
        let allowed = vec!["mcp:invoke".to_owned()];
        let err = parse_scopes(Some("mcp:invoke mcp:pwn"), &allowed).unwrap_err();
        assert!(matches!(err, AuthorizeError::InvalidScope(s) if s == "mcp:pwn"));
    }

    #[test]
    fn parse_scopes_accepts_space_separated() {
        let allowed = vec!["mcp:invoke".into(), "mcp:read".into()];
        let s = parse_scopes(Some("mcp:invoke mcp:read"), &allowed).unwrap();
        assert_eq!(s, vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()]);
    }
}
