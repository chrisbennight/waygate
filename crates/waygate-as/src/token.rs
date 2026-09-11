//! `POST /oauth/token` — swap a gateway-issued code (or refresh token) for
//! a gateway-minted access token.
//!
//! PKCE verification lives here: the client sent us `code_challenge` at
//! `/oauth/authorize` (persisted on the `oauth_codes` row) and now presents
//! `code_verifier` at `/oauth/token`; we check `S256(code_verifier) ==
//! code_challenge` before handing back a token.

use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};

use waygate_oidc::pkce::new_random_token;

use waygate_evidence::AuditOutcome;

use crate::audit::{record as record_oauth_event, OauthFacts};
use crate::client_auth::{authenticate_client, ClientAuthError, ClientCredentials};
use crate::router::AsState;
use crate::store::RefreshToken;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// Optional at the serde layer so a request with no `grant_type` at
    /// all still reaches our handler — otherwise `Form<TokenRequest>`
    /// 422s upstream of any audit emission, and the `OAuthMissingParameter`
    /// row the telemetry doc promises never gets written.
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    // RFC 8693 token-exchange parameters (EMA ID-JAG mint).
    #[serde(default)]
    pub subject_token: Option<String>,
    #[serde(default)]
    pub subject_token_type: Option<String>,
    #[serde(default)]
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 7523 jwt-bearer parameter (EMA ID-JAG redeem): the ID-JAG assertion.
    #[serde(default)]
    pub assertion: Option<String>,
    // Confidential-client authentication (EMA ID-JAG redeem).
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// RFC 9207 ([OAuth 2.0 Authorization Server Issuer
    /// Identification](https://datatracker.ietf.org/doc/html/rfc9207)) `iss`
    /// parameter. Identifies which authorization server minted this token
    /// so the client can detect mix-up attacks where a malicious AS
    /// returns a token the client then sends to the legitimate AS. Equal
    /// to the gateway's `public_url` (the same value advertised as
    /// `issuer` in `/.well-known/oauth-authorization-server`).
    pub iss: String,
}

/// RFC 8693 token-exchange grant — the EMA IdP-Authorization-Server path
/// that mints an ID-JAG. `pub(crate)` so the RFC 8414 metadata advert
/// (`metadata.rs`) lists the exact same URN the handler arms on.
pub(crate) const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// The only `requested_token_type` (and `issued_token_type`) this AS
/// supports via token-exchange.
const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// RFC 7523 jwt-bearer grant — the EMA Resource-AS path that redeems an ID-JAG
/// for an audience-restricted access token. `pub(crate)` for the metadata advert.
pub(crate) const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// RFC 8693 §2.2.1 response for an issued ID-JAG. Distinct from
/// [`TokenResponse`]: `token_type` is the literal `"N_A"` (an ID-JAG is
/// not a bearer token), there is no refresh token, and it carries
/// `issued_token_type`.
#[derive(Debug, Serialize)]
struct TokenExchangeResponse {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    expires_in: i64,
}

/// RFC 7523 §2.1 response for a redeemed ID-JAG: a bearer access token
/// audience-restricted to the ID-JAG's `resource`, with NO refresh token (the
/// client re-redeems a fresh ID-JAG when this one expires).
#[derive(Debug, Serialize)]
struct RedeemResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    iss: String,
}

/// `handle`'s success payload. Carries the canonical principal `sub`
/// and `client_id` so the handler boundary can stamp them onto the
/// `OAuthEvent` audit row without the wire shape (`TokenResponse`)
/// needing to leak identity. The refresh flow has `req.client_id`
/// empty by convention, so we fall back to the stored row's value
/// here rather than the request's.
struct Issued {
    response: TokenResponse,
    sub: String,
    client_id: String,
}

pub async fn handler(
    State(state): State<AsState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Response {
    // Capture the audit-relevant request facts upfront so an error
    // response (which moves `req`) still has them. The OAuthEvent row
    // therefore reflects what the client *claimed* even when the
    // request is rejected — exactly what an investigator needs to
    // correlate "who failed PKCE" across a noisy log.
    let grant_type = req.grant_type.clone();
    let req_client_id = req.client_id.clone();
    // Token-exchange (EMA ID-JAG mint) has a distinct response shape and a
    // separate dependency set — route it before the standard grant path.
    if grant_type.as_deref() == Some(GRANT_TOKEN_EXCHANGE) {
        return handle_token_exchange(&state, req).await;
    }
    // jwt-bearer (EMA ID-JAG redeem) also has a distinct response shape and
    // dependency set — route it before the standard grant path too. It needs
    // the Authorization header for HTTP Basic client authentication.
    if grant_type.as_deref() == Some(GRANT_JWT_BEARER) {
        let authorization = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        return handle_jwt_bearer(&state, authorization.as_deref(), req).await;
    }
    let result = handle(&state, req).await;
    match result {
        Ok(issued) => {
            let action = match grant_type.as_deref() {
                Some("authorization_code") => "OAuthTokenIssued",
                Some("refresh_token") => "OAuthTokenRefreshed",
                _ => "OAuthTokenIssued",
            };
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action,
                    outcome: AuditOutcome::Success,
                    // Prefer the canonical client_id from the stored
                    // row over the request — the refresh flow leaves
                    // `req.client_id` empty by convention, but the
                    // record path always has it via `Issued.client_id`.
                    client_id: Some(&issued.client_id),
                    sub: Some(&issued.sub),
                    grant_type: grant_type.as_deref(),
                    detail: None,
                },
            )
            .await;
            (StatusCode::OK, axum::Json(issued.response)).into_response()
        }
        Err(err) => {
            // For rejected requests we don't know `sub` (the code/refresh
            // didn't validate). The action discriminates the rejection
            // class so the activity feed can show "lots of PkceFailed
            // events" vs "lots of UnsupportedGrant" without parsing
            // `detail`.
            let detail = err.to_string();
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action: err.audit_action(),
                    outcome: AuditOutcome::ExecutionError,
                    client_id: req_client_id.as_deref(),
                    sub: None,
                    grant_type: grant_type.as_deref(),
                    detail: Some(&detail),
                },
            )
            .await;
            err.into_response()
        }
    }
}

async fn handle(state: &AsState, req: TokenRequest) -> Result<Issued, TokenError> {
    match req.grant_type.as_deref() {
        Some("authorization_code") => handle_auth_code(state, req).await,
        Some("refresh_token") => handle_refresh(state, req).await,
        // `grant_type` is missing entirely — record an
        // `OAuthMissingParameter` audit row from the handler boundary
        // rather than 422ing here at the serde layer, which would
        // leave the row unwritten.
        None => Err(TokenError::MissingGrantType),
        Some(other) => Err(TokenError::UnsupportedGrant(other.to_owned())),
    }
}

async fn handle_auth_code(state: &AsState, req: TokenRequest) -> Result<Issued, TokenError> {
    let code = req.code.ok_or(TokenError::MissingCode)?;
    let code_verifier = req.code_verifier.ok_or(TokenError::MissingCodeVerifier)?;
    let redirect_uri = req.redirect_uri.ok_or(TokenError::MissingRedirectUri)?;
    let client_id = req.client_id.ok_or(TokenError::MissingClientId)?;

    let issued = state
        .store
        .take_code(&code)
        .await
        .map_err(|e| TokenError::Internal(e.to_string()))?
        .ok_or(TokenError::InvalidCode)?;

    if issued.redirect_uri != redirect_uri {
        return Err(TokenError::RedirectUriMismatch);
    }
    if issued.client_id != client_id {
        return Err(TokenError::ClientIdMismatch);
    }

    // PKCE S256 check: BASE64URL(SHA256(code_verifier)) == stored challenge.
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    if !constant_time_eq(computed.as_bytes(), issued.code_challenge.as_bytes()) {
        return Err(TokenError::PkceFailed);
    }

    let sub = issued.sub.clone();
    let canonical_client_id = issued.client_id.clone();
    let response = mint_tokens(
        state,
        &issued.sub,
        issued.email.as_deref(),
        &issued.groups,
        &issued.scopes,
        &issued.client_id,
        // Thread the tenant from the redeemed code onto both
        // the access token's `tenant` claim and the new refresh
        // row, so the chain stays tenant-consistent from
        // callback → code → token → admin API.
        &issued.tenant_id,
    )
    .await?;
    Ok(Issued {
        response,
        sub,
        client_id: canonical_client_id,
    })
}

async fn handle_refresh(state: &AsState, req: TokenRequest) -> Result<Issued, TokenError> {
    let token = req.refresh_token.ok_or(TokenError::MissingRefreshToken)?;
    let rt = state
        .store
        .find_refresh(&token)
        .await
        .map_err(|e| TokenError::Internal(e.to_string()))?
        .ok_or(TokenError::InvalidRefresh)?;

    // Revoked replay: token previously rotated but we're being presented
    // again. Per RFC 6749 §10.4, treat as a theft signal and revoke every
    // descendant of this token in the rotation chain.
    if rt.revoked_at.is_some() {
        let revoked = state.store.revoke_chain(&token).await.unwrap_or_default();
        tracing::warn!(
            client_id = %rt.client_id,
            sub = %rt.sub,
            revoked,
            "refresh token replay detected — chain revoked",
        );
        return Err(TokenError::InvalidRefresh);
    }
    if rt.expires_at < OffsetDateTime::now_utc() {
        return Err(TokenError::InvalidRefresh);
    }

    // Mint the successor's access token + RT first; persist them via
    // the transactional `rotate_refresh` below. The mint itself is pure
    // crypto + RNG — no DB writes — so doing it before the rotation
    // transaction doesn't widen any window.
    let access = state
        .identity_issuer
        .mint_access_token(
            &rt.sub,
            rt.email.as_deref(),
            &rt.groups,
            &state.config.audience,
            &rt.scopes,
            Some(&rt.client_id),
            // Carry the tenant forward from the predecessor
            // refresh row onto the freshly minted access token.
            Some(rt.tenant_id.as_str()),
            state.config.access_token_ttl,
        )
        .map_err(|e| TokenError::Internal(format!("mint access token: {e}")))?;
    let refresh_value = new_random_token();
    let refresh_expires = OffsetDateTime::now_utc()
        + TimeDuration::seconds(state.config.refresh_token_ttl.as_secs() as i64);
    let successor = RefreshToken {
        token: refresh_value.clone(),
        sub: rt.sub.clone(),
        email: rt.email.clone(),
        groups: rt.groups.clone(),
        scopes: rt.scopes.clone(),
        client_id: rt.client_id.clone(),
        rotated_from: Some(token.clone()),
        expires_at: refresh_expires,
        revoked_at: None,
        // Carry the tenant forward onto the successor refresh
        // row so the chain stays tenant-consistent across
        // rotations.
        tenant_id: rt.tenant_id.clone(),
    };

    // Rotate atomically: revoke predecessor + insert successor inside a
    // single transaction that takes a Postgres advisory lock on the
    // `(client_id, sub)` pair. This serializes with the dashboard's
    // `revoke_by_client_sub`, which takes the same lock — so an admin
    // revoke can't slip between the two halves of a rotation and miss
    // the successor.
    //
    // `rotate_refresh` returns `false` when the predecessor was already
    // revoked at lock acquisition (concurrent rotation OR admin revoke
    // got there first). Same loser-of-race outcome as the previous
    // non-transactional code: surface `InvalidRefresh`.
    let won_rotation = state
        .store
        .rotate_refresh(&token, &successor)
        .await
        .map_err(|e| TokenError::Internal(e.to_string()))?;
    if !won_rotation {
        tracing::warn!(
            client_id = %rt.client_id,
            sub = %rt.sub,
            "refresh token rotation lost race — predecessor already revoked at lock acquisition",
        );
        return Err(TokenError::InvalidRefresh);
    }

    Ok(Issued {
        response: TokenResponse {
            access_token: access,
            token_type: "Bearer",
            expires_in: state.config.access_token_ttl.as_secs() as i64,
            refresh_token: refresh_value,
            scope: Some(rt.scopes.join(" ")),
            iss: state.config.issuer().to_owned(),
        },
        sub: rt.sub.clone(),
        // `req.client_id` is empty on refresh by convention (RFC 6749
        // doesn't require it on the refresh-token grant). Reach into
        // the stored token row so the audit reason carries the real
        // client identity.
        client_id: rt.client_id.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn mint_tokens(
    state: &AsState,
    sub: &str,
    email: Option<&str>,
    groups: &[String],
    scopes: &[String],
    client_id: &str,
    // Tenant carried in from the IssuedCode (auth-code
    // grant) so the gateway access token's `tenant` claim
    // and the new refresh chain both stay in lockstep with
    // the principal's upstream JWT tenant.
    tenant_id: &str,
) -> Result<TokenResponse, TokenError> {
    let access = state
        .identity_issuer
        .mint_access_token(
            sub,
            email,
            groups,
            &state.config.audience,
            scopes,
            Some(client_id),
            Some(tenant_id),
            state.config.access_token_ttl,
        )
        .map_err(|e| TokenError::Internal(format!("mint access token: {e}")))?;

    let refresh_value = new_random_token();
    let refresh_expires = OffsetDateTime::now_utc()
        + TimeDuration::seconds(state.config.refresh_token_ttl.as_secs() as i64);
    let rt = RefreshToken {
        token: refresh_value.clone(),
        sub: sub.to_owned(),
        email: email.map(str::to_owned),
        groups: groups.to_vec(),
        scopes: scopes.to_vec(),
        client_id: client_id.to_owned(),
        rotated_from: None,
        expires_at: refresh_expires,
        revoked_at: None,
        tenant_id: tenant_id.to_owned(),
    };
    state
        .store
        .insert_refresh(&rt)
        .await
        .map_err(|e| TokenError::Internal(e.to_string()))?;

    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: state.config.access_token_ttl.as_secs() as i64,
        refresh_token: refresh_value,
        scope: Some(scopes.join(" ")),
        iss: state.config.issuer().to_owned(),
    })
}

/// `POST /oauth/token` with `grant_type=token-exchange` — the EMA
/// IdP-Authorization-Server path. Distinct response shape, so it returns a
/// `Response` directly rather than threading the `Issued`/`handle`
/// machinery. Validate-before-mint; minting is the only side effect and
/// runs last.
async fn handle_token_exchange(state: &AsState, req: TokenRequest) -> Response {
    let req_client_id = req.client_id.clone();
    match mint_id_jag(state, req).await {
        Ok((response, sub, client_id)) => {
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action: "OAuthIdJagIssued",
                    outcome: AuditOutcome::Success,
                    client_id: Some(&client_id),
                    sub: Some(&sub),
                    grant_type: Some(GRANT_TOKEN_EXCHANGE),
                    detail: None,
                },
            )
            .await;
            (StatusCode::OK, axum::Json(response)).into_response()
        }
        Err(err) => {
            let detail = err.to_string();
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action: err.audit_action(),
                    outcome: AuditOutcome::ExecutionError,
                    client_id: req_client_id.as_deref(),
                    sub: None,
                    grant_type: Some(GRANT_TOKEN_EXCHANGE),
                    detail: Some(&detail),
                },
            )
            .await;
            err.into_response()
        }
    }
}

/// EMA mint pipeline: resolve subject → enrich (SCIM) → SCIM-active gate →
/// Cedar `GrantCrossAppAccess` → scope intersection → mint. Fails closed.
/// Returns the response plus the resolved `sub` + `client_id` for audit.
async fn mint_id_jag(
    state: &AsState,
    req: TokenRequest,
) -> Result<(TokenExchangeResponse, String, String), TokenError> {
    let ema = state
        .ema
        .as_ref()
        .ok_or_else(|| TokenError::UnsupportedGrant(GRANT_TOKEN_EXCHANGE.to_owned()))?;

    if req.requested_token_type.as_deref() != Some(TOKEN_TYPE_ID_JAG) {
        return Err(TokenError::UnsupportedTokenType);
    }
    let subject_token = req.subject_token.ok_or(TokenError::MissingSubjectToken)?;
    let subject_token_type = req
        .subject_token_type
        .ok_or(TokenError::MissingSubjectTokenType)?;
    let audience = req.audience.ok_or(TokenError::MissingAudience)?;
    let resource = req.resource.ok_or(TokenError::MissingResource)?;

    // 1. Resolve the subject token to a principal + its AUTHENTICATED client.
    let resolved = ema
        .subject_resolver
        .resolve(&subject_token_type, &subject_token)
        .await
        .map_err(|_| TokenError::InvalidSubjectToken)?;
    let principal = resolved.principal;

    // 2. Client binding. The ID-JAG is bound to the client the *subject token*
    //    was issued to — never a caller-asserted `client_id` form field, which
    //    a caller could set to any value. A form `client_id`, if present, MUST
    //    equal the authenticated one (mismatch ⇒ spoof attempt). A subject
    //    token with no client binding cannot mint: we'd have no authenticated
    //    client to put in the assertion or to evaluate the client-specific
    //    GrantCrossAppAccess policy against.
    let client_id = match resolved.client_id {
        Some(authenticated) => {
            if let Some(form) = req.client_id.as_deref() {
                if form != authenticated {
                    return Err(TokenError::ClientIdMismatch);
                }
            }
            authenticated
        }
        None => return Err(TokenError::InvalidSubjectToken),
    };

    // 3. Enrich with SCIM-authoritative facts (groups/active), then gate.
    let principal = match ema.enricher.as_ref() {
        Some(enricher) => enricher.enrich(principal).await,
        None => principal,
    };
    // SCIM deactivation / enricher-ambiguity fail-closed — same gate the
    // bearer middleware applies on every request.
    if principal.scim_blocks_request() {
        return Err(TokenError::AccessDenied);
    }
    // EMA posture: an ID-JAG must prove DIRECTORY membership. Require a
    // present + active SCIM row so a never-provisioned principal or one
    // whose directory entry was deprovisioned (the tombstone
    // surfaces it as inactive) cannot mint, even if a policy would permit.
    if state.config.idjag_require_scim
        && !principal.scim.as_ref().map(|s| s.active).unwrap_or(false)
    {
        return Err(TokenError::AccessDenied);
    }

    // 4. Target validation (before any mint). The AS only mints an ID-JAG for
    //    a Resource-AS `audience` it trusts and a `resource` (MCP server) it
    //    knows — otherwise the gateway could be coaxed into signing assertions
    //    aimed at an arbitrary audience or an unknown upstream. Both sets are
    //    fail-closed (empty ⇒ nothing accepted). RFC 8693 §2.2.2 maps this to
    //    `invalid_target`.
    if !state
        .config
        .idjag_allowed_audiences
        .iter()
        .any(|a| a == &audience)
    {
        return Err(TokenError::UntrustedAudience);
    }
    if !state
        .config
        .idjag_known_resources
        .iter()
        .any(|r| r == &resource)
    {
        return Err(TokenError::UnknownResource);
    }

    // 5. Cedar policy: GrantCrossAppAccess(principal, client_id, resource).
    //    The mint (side effect) only runs after this allows.
    ema.cross_app_policy
        .authorize(&principal, &client_id, &resource)
        .await
        .map_err(|_| TokenError::AccessDenied)?;

    // 6. Scope = requested ∩ AS allow-list ∩ principal-derived authority. An
    //    ID-JAG never carries a scope the AS won't issue, nor one the subject
    //    didn't already hold — so a low-scope subject token cannot escalate to
    //    a privileged scope (e.g. mcp:admin) via the exchange.
    let granted = granted_scopes(
        req.scope.as_deref(),
        &state.config.allowed_scopes,
        &principal.scopes,
    );

    // 7. Mint the ID-JAG. `audience` is the Resource AS issuer the client
    //    named; `resource` is the MCP server the redeemed token is bound to.
    //    Carry the subject's tenant (skip the default) so the Resource AS mints
    //    the redeemed token in the right tenant for SCIM/RBAC/Cedar/audit.
    let tenant = (!principal.tenant.is_default()).then(|| principal.tenant.as_str());
    let token = state
        .identity_issuer
        .mint_id_jag(
            &principal.sub,
            principal.email.as_deref(),
            &audience,
            &resource,
            &client_id,
            &granted,
            tenant,
            state.config.idjag_ttl,
        )
        .map_err(|e| TokenError::Internal(format!("mint id-jag: {e}")))?;

    let scope = (!granted.is_empty()).then(|| granted.join(" "));
    Ok((
        TokenExchangeResponse {
            access_token: token,
            issued_token_type: TOKEN_TYPE_ID_JAG,
            token_type: "N_A",
            scope,
            expires_in: state.config.idjag_ttl.as_secs() as i64,
        },
        principal.sub,
        client_id,
    ))
}

/// Intersect the client's requested scopes with BOTH the AS allow-list and the
/// subject principal's own scopes. An ID-JAG never carries a scope the AS isn't
/// configured to issue, nor one the subject didn't already hold — the second
/// term is the principal-derived authority limit that stops a low-scope subject
/// token from escalating to a privileged scope through the exchange.
fn granted_scopes(
    requested: Option<&str>,
    allowed: &[String],
    principal_scopes: &[String],
) -> Vec<String> {
    requested
        .unwrap_or("")
        .split_whitespace()
        .filter(|s| allowed.iter().any(|a| a == s) && principal_scopes.iter().any(|p| p == s))
        .map(str::to_owned)
        .collect()
}

/// `POST /oauth/token` with `grant_type=jwt-bearer` — the EMA Resource-AS
/// path. Distinct response shape, so it returns a `Response` directly.
/// Validate-before-mint; the access-token mint is the only externally-visible
/// side effect and runs last (after the guarded single-use jti claim).
async fn handle_jwt_bearer(
    state: &AsState,
    authorization: Option<&str>,
    req: TokenRequest,
) -> Response {
    let req_client_id = req.client_id.clone();
    match redeem_id_jag(state, authorization, req).await {
        Ok((response, sub, client_id)) => {
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action: "OAuthJwtBearerRedeemed",
                    outcome: AuditOutcome::Success,
                    client_id: Some(&client_id),
                    sub: Some(&sub),
                    grant_type: Some(GRANT_JWT_BEARER),
                    detail: None,
                },
            )
            .await;
            (StatusCode::OK, axum::Json(response)).into_response()
        }
        Err(err) => {
            let detail = err.to_string();
            record_oauth_event(
                &state.evidence,
                OauthFacts {
                    action: err.audit_action(),
                    outcome: AuditOutcome::ExecutionError,
                    client_id: req_client_id.as_deref(),
                    sub: None,
                    grant_type: Some(GRANT_JWT_BEARER),
                    detail: Some(&detail),
                },
            )
            .await;
            err.into_response()
        }
    }
}

/// EMA redeem pipeline: authenticate client → verify ID-JAG (typ + signature +
/// `aud` == our issuer + `iss` ∈ trusted + `exp`) → assert client binding →
/// single-use `jti` → scope ∩ allow-list (strip privileged on cross-org) →
/// mint an audience-restricted access token. Returns the response plus the
/// resolved `sub` + `client_id` for audit. Fails closed.
async fn redeem_id_jag(
    state: &AsState,
    authorization: Option<&str>,
    req: TokenRequest,
) -> Result<(RedeemResponse, String, String), TokenError> {
    let ema = state
        .ema
        .as_ref()
        .ok_or_else(|| TokenError::UnsupportedGrant(GRANT_JWT_BEARER.to_owned()))?;
    let verifier = ema
        .verifier
        .as_ref()
        .ok_or_else(|| TokenError::UnsupportedGrant(GRANT_JWT_BEARER.to_owned()))?;
    let client_store = ema
        .client_store
        .as_ref()
        .ok_or_else(|| TokenError::UnsupportedGrant(GRANT_JWT_BEARER.to_owned()))?;

    let assertion = req.assertion.ok_or(TokenError::MissingAssertion)?;

    // 1. Authenticate the redeeming client with its REGISTERED credential
    //    (draft §4.4 / §9.1 — confidential clients only): client_secret (Basic
    //    or POST) or private_key_jwt (client_assertion). A private_key_jwt
    //    assertion's `aud` may name our issuer or our token-endpoint URL.
    let token_endpoint = state.config.absolute("/oauth/token");
    let creds = ClientCredentials::extract(
        authorization,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        req.client_assertion.as_deref(),
        req.client_assertion_type.as_deref(),
    )
    .ok_or(TokenError::ClientAuthRequired)?;
    let authenticated_client = authenticate_client(
        client_store.as_ref(),
        &creds,
        &[state.config.issuer(), token_endpoint.as_str()],
    )
    .await
    .map_err(TokenError::from)?;

    // 2. Verify the assertion, routing on the (unverified) `iss`. A self-issued
    //    ID-JAG (`iss` == our issuer) verifies against our own keyring; a
    //    peer-minted one (`iss` == a registered Tier-C federated peer) verifies
    //    against that peer's cached JWKS (EMA). `expected_aud` is THIS
    //    gateway's issuer — we are the Resource AS the ID-JAG names. The typ
    //    guard (token-confusion), signature, iss-allowlist, and exp are enforced
    //    by `verify_id_jag` in BOTH paths.
    //
    //    `redeem_tenant` is the tenant the minted access token lands in: the
    //    assertion's own `tenant` for a self-issued ID-JAG (we minted it, so it
    //    is trustworthy), but for a peer-minted one the tenant comes from the
    //    peer's `federated_peers` record — a peer must NOT be able to pick our
    //    tenant by setting a `tenant` claim (see docs/agents/federation.md). The
    //    peer path fails closed on a multi-tenant-registered peer.
    //
    //    The (unverified) iss peek is routing only: a forged iss simply routes to
    //    a keyset that won't verify the forged signature, so it can't grant
    //    access. None (malformed) routes to the peer path, which re-peeks and
    //    rejects it.
    let self_issuer = state.config.issuer();
    let is_self = waygate_oidc::peek_unverified_issuer(&assertion).as_deref() == Some(self_issuer);
    let (claims, redeem_tenant): (waygate_oidc::IdJagClaims, Option<String>) = if is_self {
        let claims = waygate_oidc::verify_id_jag_with_jwks(
            &assertion,
            verifier,
            self_issuer,
            &state.config.idjag_trusted_issuers,
        )
        .await
        .map_err(|_| TokenError::InvalidAssertion)?;
        let tenant = claims.tenant.clone();
        (claims, tenant)
    } else {
        // Peer-minted (Tier-C). Rejected unless peer redemption is wired.
        let peer_cache = ema.peer_jwks.as_ref().ok_or(TokenError::InvalidAssertion)?;
        let verified = waygate_federation::peer_jwt::verify_peer_id_jag(
            peer_cache,
            &assertion,
            self_issuer,
            &state.config.idjag_trusted_issuers,
        )
        .await
        .map_err(|_| TokenError::InvalidAssertion)?;
        // Tenant from the peer record, NOT the assertion's `tenant` claim.
        (verified.claims, Some(verified.tenant.as_str().to_owned()))
    };

    // 3. Client binding MUST (draft §4.4.1): the ID-JAG's `client_id` MUST equal
    //    the AUTHENTICATED client — not a caller-asserted form value. This is
    //    what stops a stolen assertion being redeemed by a different client.
    if claims.client_id != authenticated_client {
        return Err(TokenError::ClientIdMismatch);
    }

    // 3b. Target validation (RFC 8693 §2.2.2 `invalid_target`) — BEFORE any side
    //     effect (the jti claim below is a DB write). The minted access token
    //     carries `aud = claims.resource`, and the /mcp BearerValidator only
    //     confines a token whose `aud` is a *registered* per-upstream resource id
    //     (EMA); an estate-audience token is deliberately unrestricted. So a
    //     trusted/peer ID-JAG issuer that set `resource` to the estate audience
    //     (or any non-manifest value) would otherwise be redeemed into an
    //     UNRESTRICTED estate bearer instead of a one-upstream bearer — bypassing
    //     the resource binding. Two checks, both fail closed:
    //       (a) the resource MUST be a known resource (same allow-list the local
    //           mint path enforces; empty ⇒ nothing accepted), AND
    //       (b) the resource MUST NOT be the estate audience. The estate audience
    //           is normally absent from `idjag_known_resources` (which holds only
    //           `{public_url}/servers/<name>` ids), but `idjag_known_resources`
    //           is unioned with operator-supplied `GATEWAY_AS_IDJAG_RESOURCES`
    //           (for mint targets), so an operator COULD list the estate audience
    //           there. Redeeming it is the *only* resource value that yields an
    //           unrestricted /mcp token, so reject it explicitly regardless of the
    //           allow-list — redeem must never mint an `aud` that /mcp can't
    //           confine. (Non-estate env-only resources are harmless: their token
    //           is not in the /mcp accepted-audience set, so /mcp 401s it.)
    if claims.resource == state.config.audience
        || !state
            .config
            .idjag_known_resources
            .iter()
            .any(|r| r == &claims.resource)
    {
        return Err(TokenError::UnknownResource);
    }

    // 4. Single-use jti (replay defense) — atomic claim. A second concurrent
    //    redeem of the same assertion inserts no row and loses here.
    let exp = OffsetDateTime::from_unix_timestamp(claims.exp)
        .map_err(|e| TokenError::Internal(format!("id-jag exp out of range: {e}")))?;
    let first_use = state
        .store
        .claim_id_jag_jti(&claims.jti, exp)
        .await
        .map_err(|e| TokenError::Internal(e.to_string()))?;
    if !first_use {
        return Err(TokenError::ReplayedAssertion);
    }

    // 5. Scope = ID-JAG scope ∩ AS allow-list, with privileged scopes stripped
    //    on a cross-org / peer-issued assertion.
    let cross_org = claims.iss != state.config.issuer();
    let granted = redeem_scopes(&claims.scope, &state.config.allowed_scopes, cross_org);

    // 6. Mint the audience-restricted access token (aud == the ID-JAG's
    //    `resource`), in `redeem_tenant` (the assertion's tenant for a
    //    self-issued ID-JAG; the peer record's tenant for a peer-minted one — see
    //    step 2) so downstream SCIM/RBAC/Cedar/audit are tenant-correct. No
    //    refresh token. Groups are deliberately empty: the Resource AS re-derives
    //    authorization from the SCIM directory when the token is used at /mcp (the
    //    bearer middleware enricher), not from a claim in the assertion.
    let access = state
        .identity_issuer
        .mint_access_token(
            &claims.sub,
            claims.email.as_deref(),
            &[],
            &claims.resource,
            &granted,
            Some(&claims.client_id),
            redeem_tenant.as_deref(),
            state.config.access_token_ttl,
        )
        .map_err(|e| TokenError::Internal(format!("mint access token: {e}")))?;

    let scope = (!granted.is_empty()).then(|| granted.join(" "));
    Ok((
        RedeemResponse {
            access_token: access,
            token_type: "Bearer",
            expires_in: state.config.access_token_ttl.as_secs() as i64,
            scope,
            iss: state.config.issuer().to_owned(),
        },
        claims.sub,
        claims.client_id,
    ))
}

/// Intersect the ID-JAG's scopes with the AS allow-list. On a cross-org /
/// peer-issued assertion (`iss` != our own), additionally strip the scopes that
/// must never be granted across an org boundary.
fn redeem_scopes(idjag_scope: &str, allowed: &[String], cross_org: bool) -> Vec<String> {
    const CROSS_ORG_FORBIDDEN: [&str; 2] = ["mcp:admin", "scim:write"];
    idjag_scope
        .split_whitespace()
        .filter(|s| allowed.iter().any(|a| a == s))
        .filter(|s| !(cross_org && CROSS_ORG_FORBIDDEN.contains(s)))
        .map(str::to_owned)
        .collect()
}

/// Constant-time byte equality. The compiler is free to vectorize but
/// won't short-circuit — that's enough to avoid the obvious
/// strcmp-style timing leak when comparing PKCE challenges.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl TokenError {
    /// Discriminator written into `audit_log.action` so the admin
    /// Activity feed can show "lots of PkceFailed events from
    /// client_id=X" without parsing the free-form `reason` detail.
    pub(crate) fn audit_action(&self) -> &'static str {
        match self {
            TokenError::UnsupportedGrant(_) => "OAuthUnsupportedGrant",
            TokenError::MissingGrantType
            | TokenError::MissingCode
            | TokenError::MissingRedirectUri
            | TokenError::MissingClientId
            | TokenError::MissingCodeVerifier
            | TokenError::MissingRefreshToken
            | TokenError::MissingSubjectToken
            | TokenError::MissingSubjectTokenType
            | TokenError::MissingAudience
            | TokenError::MissingResource
            | TokenError::MissingAssertion => "OAuthMissingParameter",
            TokenError::UnsupportedTokenType => "OAuthUnsupportedTokenType",
            TokenError::UntrustedAudience => "OAuthUntrustedAudience",
            TokenError::UnknownResource => "OAuthUnknownResource",
            TokenError::InvalidSubjectToken => "OAuthInvalidSubjectToken",
            TokenError::InvalidAssertion => "OAuthInvalidAssertion",
            TokenError::ReplayedAssertion => "OAuthReplayedAssertion",
            TokenError::ClientAuthRequired => "OAuthClientAuthRequired",
            TokenError::InvalidClient => "OAuthInvalidClient",
            TokenError::AccessDenied => "OAuthAccessDenied",
            TokenError::InvalidCode => "OAuthInvalidCode",
            TokenError::RedirectUriMismatch => "OAuthRedirectUriMismatch",
            TokenError::ClientIdMismatch => "OAuthClientIdMismatch",
            TokenError::PkceFailed => "OAuthPkceFailed",
            TokenError::InvalidRefresh => "OAuthInvalidRefresh",
            TokenError::Internal(_) => "OAuthInternal",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("unsupported grant_type: {0}")]
    UnsupportedGrant(String),
    #[error("missing `grant_type`")]
    MissingGrantType,
    #[error("missing `code`")]
    MissingCode,
    #[error("missing `redirect_uri`")]
    MissingRedirectUri,
    #[error("missing `client_id`")]
    MissingClientId,
    #[error("missing `code_verifier`")]
    MissingCodeVerifier,
    #[error("missing `refresh_token`")]
    MissingRefreshToken,
    #[error("invalid_grant: code not found or expired")]
    InvalidCode,
    #[error("invalid_grant: redirect_uri does not match")]
    RedirectUriMismatch,
    #[error("invalid_grant: client_id does not match")]
    ClientIdMismatch,
    #[error("invalid_grant: PKCE verification failed")]
    PkceFailed,
    #[error("invalid_grant: refresh token unknown, expired, or revoked")]
    InvalidRefresh,
    #[error("missing `assertion`")]
    MissingAssertion,
    #[error("invalid_grant: ID-JAG assertion invalid, expired, or untrusted")]
    InvalidAssertion,
    #[error("invalid_grant: ID-JAG assertion already redeemed (replay)")]
    ReplayedAssertion,
    #[error("invalid_client: client authentication required")]
    ClientAuthRequired,
    #[error("invalid_client: client authentication failed")]
    InvalidClient,
    #[error("invalid_request: requested_token_type must be the ID-JAG token type")]
    UnsupportedTokenType,
    #[error("invalid_target: audience is not a trusted Resource-AS issuer")]
    UntrustedAudience,
    #[error("invalid_target: resource is not a known upstream")]
    UnknownResource,
    #[error("missing `subject_token`")]
    MissingSubjectToken,
    #[error("missing `subject_token_type`")]
    MissingSubjectTokenType,
    #[error("missing `audience`")]
    MissingAudience,
    #[error("missing `resource`")]
    MissingResource,
    #[error("invalid_grant: subject_token invalid or not accepted")]
    InvalidSubjectToken,
    #[error("access_denied: not permitted to obtain a cross-app access grant")]
    AccessDenied,
    #[error("internal: {0}")]
    Internal(String),
}

impl From<ClientAuthError> for TokenError {
    fn from(e: ClientAuthError) -> Self {
        match e {
            // Storage/infra failure reaching the client registry — 500, don't
            // leak it as a client-auth rejection.
            ClientAuthError::Store(s) => TokenError::Internal(format!("client auth: {s}")),
            // Everything else is a client-authentication failure → invalid_client.
            _ => TokenError::InvalidClient,
        }
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            TokenError::UnsupportedGrant(_) => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
            TokenError::UnsupportedTokenType
            | TokenError::MissingSubjectToken
            | TokenError::MissingSubjectTokenType
            | TokenError::MissingAudience
            | TokenError::MissingResource
            | TokenError::MissingAssertion => (StatusCode::BAD_REQUEST, "invalid_request"),
            TokenError::AccessDenied => (StatusCode::FORBIDDEN, "access_denied"),
            // RFC 6749 §5.2: client authentication failed → 401 invalid_client.
            TokenError::ClientAuthRequired | TokenError::InvalidClient => {
                (StatusCode::UNAUTHORIZED, "invalid_client")
            }
            // RFC 8693 §2.2.2: the AS can't issue a token for the requested
            // audience/resource.
            TokenError::UntrustedAudience | TokenError::UnknownResource => {
                (StatusCode::BAD_REQUEST, "invalid_target")
            }
            TokenError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            _ => (StatusCode::BAD_REQUEST, "invalid_grant"),
        };
        tracing::info!(error = %self, "/oauth/token rejected");
        let body = serde_json::json!({
            "error": code,
            "error_description": self.to_string(),
        });
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_is_sane() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn redeem_scopes_intersects_allow_list() {
        let allowed = vec!["mcp:invoke".to_string(), "mcp:read".to_string()];
        // mcp:admin is requested but not allow-listed → dropped (same-org).
        let g = redeem_scopes("mcp:invoke mcp:read mcp:admin", &allowed, false);
        assert_eq!(g, vec!["mcp:invoke".to_string(), "mcp:read".to_string()]);
    }

    #[test]
    fn redeem_scopes_strips_privileged_only_on_cross_org() {
        let allowed = vec![
            "mcp:invoke".to_string(),
            "mcp:admin".to_string(),
            "scim:write".to_string(),
        ];
        // Same org: an allow-listed privileged scope survives.
        let same = redeem_scopes("mcp:invoke mcp:admin scim:write", &allowed, false);
        assert_eq!(
            same,
            vec![
                "mcp:invoke".to_string(),
                "mcp:admin".to_string(),
                "scim:write".to_string()
            ],
        );
        // Cross-org: mcp:admin + scim:write are stripped even though
        // allow-listed — they must never cross an org boundary.
        let cross = redeem_scopes("mcp:invoke mcp:admin scim:write", &allowed, true);
        assert_eq!(cross, vec!["mcp:invoke".to_string()]);
    }

    #[test]
    fn pkce_s256_matches_spec_example() {
        // RFC 7636 Appendix B example:
        // verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        // challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let chal = URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
        assert_eq!(chal, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn token_response_serializes_iss_per_rfc_9207() {
        // RFC 9207 §3 requires the AS include `iss` on token responses so
        // clients can detect mix-up attacks. Lock the wire shape.
        let resp = TokenResponse {
            access_token: "at_xxx".into(),
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: "rt_xxx".into(),
            scope: Some("mcp:invoke mcp:read".into()),
            iss: "https://gateway.example.com".into(),
        };
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(
            json.get("iss").and_then(|v| v.as_str()),
            Some("https://gateway.example.com"),
            "iss must be present and equal the issuer URL: {json}",
        );
        assert_eq!(
            json.get("token_type").and_then(|v| v.as_str()),
            Some("Bearer"),
        );
    }
}
