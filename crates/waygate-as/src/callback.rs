//! `GET /oauth/callback` — Authentik hands the browser back here with
//! `?code=…&state=<txn_id>`. We exchange the code server-side, extract user
//! identity, encrypt the upstream tokens, mint our *own* authorization code,
//! then redirect the browser back to the client's redirect URI with that
//! code and the original `state` the client sent to `/oauth/authorize`.
//!
//! This is the "token factory" pivot: upstream tokens never leave the
//! gateway.

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};

use waygate_evidence::AuditOutcome;
use waygate_oidc::pkce::{exchange_code, ExchangeParams};

use crate::audit::{record as record_oauth_event, OauthFacts};
use crate::router::AsState;
use crate::sessions::NewSessionRow;
use crate::store::IssuedCode;

// The upstream-token envelope we serialise before AES-GCM encryption.
// Lives both as a one-shot row on `oauth_codes` (wiped by `take_code`
// during the first `/oauth/token` exchange) AND on the durable
// `user_upstream_sessions` row written below. The durable copy is
// what the Tier-A per-call path reads.

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

pub use waygate_oidc::upstream_session::UpstreamTokens;

/// Successful callback outcome. `redirect` is the URL the browser
/// follows back to the original MCP client; `client_id`/`sub` are
/// stamped onto the `OAuthEvent` audit row by the handler boundary so
/// the activity feed can correlate "this gateway code was minted for
/// alice@... acting as codex-cli."
struct CallbackOk {
    redirect: String,
    client_id: String,
    sub: String,
}

pub async fn handler(State(state): State<AsState>, Query(q): Query<CallbackQuery>) -> Response {
    match handle(&state, q).await {
        Ok(ok) => {
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action: "OAuthCallbackCompleted",
                    outcome: AuditOutcome::Success,
                    client_id: Some(&ok.client_id),
                    sub: Some(&ok.sub),
                    grant_type: None,
                    detail: None,
                },
            )
            .await;
            redirect_response(&ok.redirect)
        }
        Err(err) => {
            let detail = err.to_string();
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action: err.audit_action(),
                    outcome: AuditOutcome::ExecutionError,
                    client_id: None,
                    sub: None,
                    grant_type: None,
                    detail: Some(&detail),
                },
            )
            .await;
            err.into_response()
        }
    }
}

async fn handle(state: &AsState, q: CallbackQuery) -> Result<CallbackOk, CallbackError> {
    if let Some(e) = q.error {
        return Err(CallbackError::Upstream {
            code: e,
            description: q.error_description.unwrap_or_default(),
        });
    }
    let code = q.code.ok_or(CallbackError::MissingCode)?;
    let txn_id = q.state.ok_or(CallbackError::MissingState)?;

    let txn = state
        .store
        .take_transaction(&txn_id)
        .await
        .map_err(|e| CallbackError::Internal(e.to_string()))?
        .ok_or(CallbackError::UnknownTransaction)?;

    let token_resp = exchange_code(
        &state.token_http,
        ExchangeParams {
            token_endpoint: &state.config.upstream_token_endpoint,
            client_id: &state.config.upstream_client_id,
            client_secret: &state.config.upstream_client_secret,
            redirect_uri: &state.config.upstream_redirect_uri,
            code: &code,
            pkce_verifier: &txn.proxy_code_verifier,
        },
    )
    .await
    .map_err(|e| CallbackError::Upstream {
        code: "upstream_token_exchange_failed".into(),
        description: e.to_string(),
    })?;

    let id_token = token_resp.id_token.ok_or(CallbackError::MissingIdToken)?;
    // Verify signature (against Authentik's JWKS), `iss`, `aud`
    // (== gateway's upstream client_id), and `exp` *before* we trust any
    // identity claim. OIDC Core §3.1.3.7 technically permits skipping the
    // signature check when the id_token is received via direct TLS from
    // the token endpoint, but an attacker with a trusted-cert MITM on
    // that hop — or a misconfigured proxy in front of Authentik — could
    // still hand us a forged token. Cheap to validate; expensive to
    // discover we weren't.
    let principal = state
        .upstream_id_token_validator
        .validate(&id_token)
        .await
        .map_err(|e| CallbackError::InvalidIdToken(e.to_string()))?;

    let upstream = UpstreamTokens {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        id_token: Some(id_token),
        expires_in: token_resp.expires_in,
        scope: token_resp.scope,
    };
    let upstream_bytes = serde_json::to_vec(&upstream)
        .map_err(|e| CallbackError::Internal(format!("serialize upstream tokens: {e}")))?;
    let ciphertext = state
        .config
        .upstream_crypto
        .encrypt(&upstream_bytes)
        .map_err(|e| CallbackError::Internal(format!("encrypt upstream tokens: {e}")))?;

    let code_ttl = state.config.code_ttl;
    let expires_at = OffsetDateTime::now_utc() + TimeDuration::seconds(code_ttl.as_secs() as i64);
    let gw_code = waygate_oidc::pkce::new_random_token();

    // Tier-A: UPSERT the encrypted envelope onto the durable
    // `user_upstream_sessions` table so it survives past the one-shot
    // `oauth_codes.upstream_tokens_ciphertext` write (which gets wiped
    // by `take_code()` during the first /oauth/token exchange). Keyed
    // on (sub, upstream_issuer). Both writes happen; only this durable
    // row is read back afterward (the refresh-on-demand path and the
    // admin session listing) — the `oauth_codes` copy is discarded
    // unread once the code is redeemed.
    //
    // `access_expires_at` carries the *upstream IdP's* access-token
    // expiry, not the gateway code TTL. The refresh-on-demand path
    // (next slice) consults this column to decide whether to spend a
    // refresh token before forwarding the access token to an upstream
    // call.
    let access_expires_at = match token_resp.expires_in {
        Some(secs) if secs > 0 => OffsetDateTime::now_utc() + TimeDuration::seconds(secs),
        // Upstream didn't advertise an expiry — assume short-lived
        // (1 hour, Authentik default) so the refresh-on-demand path
        // re-evaluates before exposing a stale token. The conservative
        // floor here is "treat unspecified as already-stale enough to
        // refresh" — better than treating it as permanent.
        _ => OffsetDateTime::now_utc() + TimeDuration::hours(1),
    };
    // Stamp the active keyring id so a future decrypt routes to the
    // matching key after rotation. Sourced immediately before this
    // write so we can't drift from the key the `encrypt` above used.
    let key_id = state.config.upstream_crypto.active_id().to_owned();
    // Pre-consent gate: when the gateway-wide
    // `require_explicit_consent` flag is on AND the
    // user doesn't already have an active grant
    // covering the requested scopes, defer all three
    // writes (upstream session + consent + code) until
    // the user clicks approve on `/oauth/consent`. The
    // pending row carries the encrypted upstream tokens
    // + the original txn so the screen handler can
    // replay the writes without re-running the upstream
    // exchange. See `waygate_as::consent_screen` for
    // the GET/POST handlers.
    if state.config.require_explicit_consent
        && !consent_covers_request(state, &principal, &txn).await
    {
        let pending_token = waygate_oidc::pkce::new_random_token();
        let pending_expires_at = OffsetDateTime::now_utc()
            + TimeDuration::seconds(state.config.code_ttl.as_secs() as i64 + 300);
        state
            .consent_pending
            .insert(crate::consent_pending::NewPendingConsent {
                token: &pending_token,
                tenant_id: principal.tenant.as_str(),
                principal_sub: &principal.sub,
                principal_email: principal.email.as_deref(),
                principal_groups: &principal.groups,
                client_id: &txn.client_id,
                client_redirect_uri: &txn.client_redirect_uri,
                client_state: txn.client_state.as_deref(),
                code_challenge: &txn.code_challenge,
                scopes: &txn.scopes,
                upstream_tokens_ciphertext: &ciphertext,
                key_id: &key_id,
                // Carry the REAL upstream IdP access-token expiry
                // through to the approve path so the Tier-A
                // `user_upstream_sessions` row reflects the actual
                // expiry, not a synthetic now()+1h that would let a
                // 5-min upstream token be treated as fresh for an
                // hour.
                access_expires_at,
                expires_at: pending_expires_at,
            })
            .await
            .map_err(|e| CallbackError::Internal(format!("consent-pending insert: {e}")))?;
        tracing::info!(
            client_id = %txn.client_id,
            sub = %principal.sub,
            tenant = %principal.tenant.as_str(),
            scopes = ?txn.scopes,
            "consent screen required; redirecting to /oauth/consent",
        );
        // The redirect doesn't include any of the
        // upstream's state — the pending token is the
        // sole capability the screen handler needs to
        // reconstruct the rest. Same CSRF posture as
        // the OAuth `state` parameter: random,
        // single-use, server-side bound.
        let redirect = format!("/oauth/consent?token={pending_token}");
        return Ok(CallbackOk {
            redirect,
            client_id: txn.client_id.clone(),
            sub: principal.sub,
        });
    }

    state
        .upstream_sessions
        .upsert(NewSessionRow {
            sub: &principal.sub,
            upstream_issuer: &state.config.upstream_issuer,
            tokens_ciphertext: &ciphertext,
            key_id: &key_id,
            access_expires_at,
        })
        .await
        .map_err(|e| CallbackError::Internal(format!("upstream-session upsert: {e}")))?;

    // Record the consent grant. Upstream IdP has already proved the
    // user's identity; we know `(tenant, sub, client_id, scopes)` and
    // own the decision to mint the gateway authorization code next.
    // The row lands BEFORE `insert_code` so an inspector reading the
    // DB can never see a code without the matching consent fact.
    // UPSERT semantics: a re-consent refreshes scopes + clears any
    // prior revoked_at. The OAuth callback is single-actor (this
    // user, this browser), so there's no concurrent-write race window
    // on the same (tenant, sub, client_id) triple between this UPSERT
    // and any other writer.
    let consent_scopes: Vec<String> = txn.scopes.clone();
    state
        .consent
        .upsert(crate::consent::NewConsentGrant {
            tenant_id: principal.tenant.as_str(),
            principal_sub: &principal.sub,
            client_id: &txn.client_id,
            scopes: &consent_scopes,
            // This never sets an expiry — grants live until revoked.
            // A future per-tenant max-ttl setting may populate this
            // field.
            expires_at: None,
        })
        .await
        .map_err(|e| CallbackError::Internal(format!("consent upsert: {e}")))?;

    let issued = IssuedCode {
        code: gw_code.clone(),
        client_id: txn.client_id.clone(),
        redirect_uri: txn.client_redirect_uri.clone(),
        code_challenge: txn.code_challenge.clone(),
        scopes: txn.scopes.clone(),
        sub: principal.sub,
        email: principal.email,
        groups: principal.groups,
        upstream_tokens_ciphertext: Some(ciphertext),
        expires_at,
        // Persist the tenant claim the upstream IdToken validator
        // extracted from the upstream JWT. `token.rs::handle_auth_code`
        // reads this back from `take_code` and threads it through to
        // both the refresh-token row and the gateway-minted access
        // token's `tenant` claim, so subsequent admin API calls from
        // a non-default tenant actually carry their tenant.
        tenant_id: principal.tenant.as_str().to_owned(),
    };
    state
        .store
        .insert_code(&issued)
        .await
        .map_err(|e| CallbackError::Internal(e.to_string()))?;

    let redirect = build_redirect(
        &txn.client_redirect_uri,
        &gw_code,
        txn.client_state.as_deref(),
        state.config.issuer(),
    );
    Ok(CallbackOk {
        redirect,
        client_id: txn.client_id.clone(),
        sub: issued.sub.clone(),
    })
}

/// Build the authorization-response redirect URL.
///
/// RFC 9207 §2: when the AS supports issuer identification (advertised
/// via `authorization_response_iss_parameter_supported: true` in our
/// `/.well-known/oauth-authorization-server` metadata — see
/// [`crate::metadata`]), the authorization response MUST carry the
/// `iss` parameter so the client can detect AS mix-up attacks before
/// even reaching the token endpoint. The value is the AS's `issuer`,
/// which for this gateway is `state.config.public_url` (the same value
/// used as `iss` on the token response in [`crate::token::TokenResponse`]).
/// Does the existing consent grant for
/// `(tenant, sub, client_id)` cover the scopes the
/// current authorize transaction is requesting?
/// Returns `false` for "no row" / "scope set isn't a
/// superset" / store-error (treat unknown as
/// requires-screen). When true, the callback skips the
/// `/oauth/consent` redirect and proceeds with the
/// normal mint path.
async fn consent_covers_request(
    state: &crate::router::AsState,
    principal: &waygate_oidc::Principal,
    txn: &crate::store::Transaction,
) -> bool {
    let Ok(Some(grant)) = state
        .consent
        .find_active(principal.tenant.as_str(), &principal.sub, &txn.client_id)
        .await
    else {
        return false;
    };
    // Subset check: every requested scope must appear
    // in the existing grant. Same-order match isn't
    // required (OAuth scopes are an unordered set).
    txn.scopes
        .iter()
        .all(|s| grant.scopes.iter().any(|g| g == s))
}

pub(crate) fn build_redirect(base: &str, code: &str, state: Option<&str>, iss: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = format!("{base}{sep}code={}", urlencoding_minimal(code),);
    if let Some(s) = state {
        out.push_str("&state=");
        out.push_str(&urlencoding_minimal(s));
    }
    out.push_str("&iss=");
    out.push_str(&urlencoding_minimal(iss));
    out
}

fn urlencoding_minimal(s: &str) -> String {
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

impl CallbackError {
    /// Discriminator written into `audit_log.action` so the admin
    /// Activity feed can show e.g. "lots of UnknownTransaction events"
    /// (stale browser tabs) vs "InvalidIdToken events" (upstream JWKS
    /// rotation glitch) without parsing the free-form `reason`.
    pub(crate) fn audit_action(&self) -> &'static str {
        match self {
            CallbackError::MissingCode => "OAuthCallbackMissingCode",
            CallbackError::MissingState => "OAuthCallbackMissingState",
            CallbackError::UnknownTransaction => "OAuthCallbackUnknownTransaction",
            CallbackError::MissingIdToken => "OAuthCallbackMissingIdToken",
            CallbackError::InvalidIdToken(_) => "OAuthCallbackInvalidIdToken",
            CallbackError::Upstream { .. } => "OAuthCallbackUpstreamRejected",
            CallbackError::Internal(_) => "OAuthCallbackInternal",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CallbackError {
    #[error("missing `code`")]
    MissingCode,
    #[error("missing `state`")]
    MissingState,
    #[error("unknown or expired transaction")]
    UnknownTransaction,
    #[error("upstream id_token missing from token response")]
    MissingIdToken,
    #[error("upstream id_token rejected: {0}")]
    InvalidIdToken(String),
    #[error("upstream: {code}: {description}")]
    Upstream { code: String, description: String },
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for CallbackError {
    fn into_response(self) -> Response {
        let status = match &self {
            CallbackError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
        tracing::warn!(error = %self, "oauth callback failed");
        let body = serde_json::json!({ "error": self.to_string() });
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

    const ISS: &str = "https://mcp.example.com";

    #[test]
    fn build_redirect_no_query() {
        let out = build_redirect("https://client.example.com/cb", "CODE", Some("S"), ISS);
        assert_eq!(
            out,
            "https://client.example.com/cb?code=CODE&state=S&iss=https%3A%2F%2Fmcp.example.com"
        );
    }

    #[test]
    fn build_redirect_with_existing_query() {
        let out = build_redirect("https://client.example.com/cb?x=1", "CODE", None, ISS);
        assert_eq!(
            out,
            "https://client.example.com/cb?x=1&code=CODE&iss=https%3A%2F%2Fmcp.example.com"
        );
    }

    #[test]
    fn build_redirect_urlencodes_state() {
        let out = build_redirect("https://c/cb", "C", Some("a b/c"), ISS);
        assert_eq!(
            out,
            "https://c/cb?code=C&state=a%20b%2Fc&iss=https%3A%2F%2Fmcp.example.com"
        );
    }

    #[test]
    fn build_redirect_always_includes_iss_per_rfc_9207() {
        // RFC 9207 §2: when the AS supports issuer identification (we
        // advertise `authorization_response_iss_parameter_supported: true`
        // in OAuth metadata), the authorization response MUST carry the
        // `iss` parameter. The previous PR added `iss` only to the token
        // response; this test pins that the auth-response redirect now
        // carries it too on every code path.
        let with_state = build_redirect("https://c/cb", "C", Some("s"), ISS);
        let without_state = build_redirect("https://c/cb", "C", None, ISS);
        let with_query = build_redirect("https://c/cb?x=1", "C", None, ISS);
        for redirect in [&with_state, &without_state, &with_query] {
            assert!(
                redirect.contains("&iss=https%3A%2F%2Fmcp.example.com"),
                "iss missing from redirect: {redirect}",
            );
        }
    }
}
