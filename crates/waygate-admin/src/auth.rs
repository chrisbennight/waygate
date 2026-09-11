//! PKCE + encrypted-cookie auth for the admin dashboard.
//!
//! The dashboard can't re-use the Bearer middleware on `/api/v1` — humans
//! don't paste access tokens into their browsers. This layer runs the OAuth
//! 2.1 authorization-code flow against Authentik (or any OIDC provider),
//! stashes the resulting [`Principal`] plus a CSRF token inside an
//! AES-256-GCM-encrypted session cookie, and then validates that cookie on
//! every subsequent `/admin/*` request.
//!
//! Routes (paths are relative to the nested `/admin` router):
//! * `GET  /login`         — start PKCE flow, redirect to IdP
//! * `GET  /auth/callback` — finish PKCE flow, mint session cookie
//! * `POST /logout`        — clear session cookie
//!
//! Middleware: every other `/admin/*` request is gated by [`session_middleware`],
//! which reads the `mcp-gw-session` cookie, decrypts it, and either (a) injects
//! [`Principal`] + [`CsrfToken`] into request extensions or (b) 302-redirects
//! to `/admin/login?next=<original-path>`.
//!
//! Dev mode (`DashboardAuth::Disabled`) short-circuits all of this with a
//! synthetic `dev@local` principal and a fixed CSRF token. A loud startup
//! warning is emitted so this can't slip into production unnoticed.

use std::sync::Arc;

use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use waygate_oidc::{
    authorize_url, build_cookie, clear_cookie, cookie_value, exchange_code, new_pkce_pair,
    new_random_token, session_decrypt, session_encrypt, AuthorizeParams, ExchangeParams,
    IdTokenAssurance, IdTokenValidator, LoginState, OidcEndpoints, Principal, PrincipalEnricher,
    Session, SessionAssurance, SessionError, SessionKey, LOGIN_STATE_COOKIE, SESSION_COOKIE,
};

/// CSRF token stamped into the session cookie at login and echoed back by
/// the dashboard on every state-changing form POST. Request handlers pull it
/// out of extensions (like [`Principal`]) when rendering or validating forms.
#[derive(Clone, Debug)]
pub struct CsrfToken(pub String);

/// Runtime auth posture for the dashboard. `Disabled` bypasses every check
/// and injects a synthetic admin principal — only safe in dev.
///
/// `Enforce` carries an optional
/// [`PrincipalEnricher`] alongside the OIDC config. When set,
/// `session_middleware` re-enriches the cookie principal on
/// every request so SCIM-deactivation (and any future
/// enricher) takes effect on dashboard sessions — not just on
/// bearer-gated paths. The session cookie itself stays small
/// (we don't serialise SCIM into it); enrichment runs against
/// the resolver's TTL cache so the per-request cost is a
/// `moka` `Arc` clone in the steady state.
#[derive(Clone)]
pub enum DashboardAuth {
    Enforce {
        cfg: Arc<DashboardOidcConfig>,
        enricher: Option<Arc<dyn PrincipalEnricher>>,
    },
    Disabled,
}

/// Everything a live PKCE flow needs. Built at startup from env vars + OIDC
/// discovery so request handlers can stay sync-free aside from the token POST.
pub struct DashboardOidcConfig {
    pub client_id: String,
    pub client_secret: String,
    /// Absolute `https://.../admin/auth/callback` URL registered with the IdP.
    pub redirect_uri: String,
    pub endpoints: OidcEndpoints,
    /// Shared bounded client for authorization-code exchange. Its redirect
    /// policy is fixed at startup; token responses never follow redirects.
    pub token_http: reqwest::Client,
    pub id_token_validator: Arc<IdTokenValidator>,
    pub session_key: SessionKey,
    /// Emit the `Secure` cookie attribute. Off for local HTTP dev, on for
    /// every deployed config (the gateway sits behind Traefik TLS).
    pub secure_cookies: bool,
    /// Session cookie lifetime, seconds. Short enough that a stolen laptop
    /// can't grant indefinite access; long enough to avoid re-auth churn.
    pub session_ttl: i64,
    /// Login-state cookie lifetime, seconds. Must outlive the IdP round-trip
    /// but nothing more — 10 minutes is ample.
    pub login_state_ttl: i64,
    /// OAuth scopes requested at authorize time. `openid` is mandatory;
    /// typical additions are `profile email groups` for Authentik.
    pub scopes: Vec<String>,
    /// Whitelist of step-up scopes the dashboard will accept on
    /// `/admin/login?step_up_scope=…`. Prevents an attacker from crafting a
    /// link that asks the IdP for arbitrary scopes (e.g. `mcp:admin`) and
    /// burying the mismatch in the browser history. Defaults to the known
    /// Cedar step-up scopes in [`waygate_oidc::Scope`].
    pub allowed_step_up_scopes: Vec<String>,
}

impl DashboardAuth {
    fn enforce(&self) -> Option<&Arc<DashboardOidcConfig>> {
        match self {
            DashboardAuth::Enforce { cfg, .. } => Some(cfg),
            DashboardAuth::Disabled => None,
        }
    }

    fn enricher(&self) -> Option<&Arc<dyn PrincipalEnricher>> {
        match self {
            DashboardAuth::Enforce { enricher, .. } => enricher.as_ref(),
            DashboardAuth::Disabled => None,
        }
    }

    /// Attach the SCIM (or chained) principal enricher
    /// post-construction. `waygate-server`
    /// calls this after building the dashboard auth so the
    /// dashboard session path picks up SCIM deactivation +
    /// any future enrichment hooks without changing every
    /// `DashboardAuth::Enforce { … }` construction site.
    #[must_use]
    pub fn with_principal_enricher(self, enricher: Option<Arc<dyn PrincipalEnricher>>) -> Self {
        match self {
            DashboardAuth::Enforce { cfg, .. } => DashboardAuth::Enforce { cfg, enricher },
            DashboardAuth::Disabled => DashboardAuth::Disabled,
        }
    }
}

/// Guard for routes that must not require auth themselves — the login
/// endpoint, the callback, and static assets. Paths here are matched
/// *relative to the admin router* (axum strips the `/admin` prefix before
/// the inner router sees them).
fn is_public_path(path: &str) -> bool {
    path == "/login"
        || path == "/logout"
        || path == "/auth/callback"
        || path.starts_with("/static/")
}

/// Gate every non-public `/admin/*` route behind a valid session cookie.
/// Missing/expired/tampered cookie ⇒ 302 to the login page, preserving the
/// originally-requested path in `?next=` so the user lands where they aimed.
pub async fn session_middleware(
    State(auth): State<DashboardAuth>,
    mut req: Request,
    next: Next,
) -> Response {
    if let DashboardAuth::Disabled = &auth {
        // Dev short-circuit. Loud at startup (see waygate-server main), quiet
        // per-request so we don't drown the log stream.
        let principal = dev_principal();
        let csrf_token = "dev-csrf".to_owned();
        req.extensions_mut().insert(principal.clone());
        req.extensions_mut().insert(CsrfToken(csrf_token.clone()));
        req.extensions_mut().insert(Session {
            principal,
            csrf_token,
            assurance: SessionAssurance::default(),
            exp: now_unix() + 86_400,
        });
        return next.run(req).await;
    }

    let path = req.uri().path().to_owned();
    if is_public_path(&path) {
        return next.run(req).await;
    }

    let cfg = auth.enforce().expect("enforce branch");

    let Some(raw) = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|hdr| cookie_value(hdr, SESSION_COOKIE).map(|s| s.to_owned()))
    else {
        return redirect_to_login(&path);
    };

    match session_decrypt::<Session>(&cfg.session_key, &raw) {
        Ok(session) => {
            // Re-enrich the cookie principal so SCIM deactivation (and any
            // future enrichment) takes effect within one TTL
            // window even on long-lived dashboard sessions. Cookie
            // intentionally doesn't persist SCIM state — the
            // enricher's TTL cache absorbs the per-request cost.
            let principal = if let Some(enricher) = auth.enricher() {
                enricher.enrich(session.principal.clone()).await
            } else {
                session.principal.clone()
            };
            // Active-check: same predicate as bearer_middleware so
            // a SCIM-deactivated user's dashboard session stops
            // working without waiting for the cookie to expire.
            if principal.scim_blocks_request() {
                tracing::warn!(
                    sub = %principal.sub,
                    "SCIM-deactivated principal rejected at dashboard session middleware",
                );
                return scim_inactive_dashboard_response();
            }
            req.extensions_mut().insert(principal);
            req.extensions_mut()
                .insert(CsrfToken(session.csrf_token.clone()));
            req.extensions_mut().insert(session);
            next.run(req).await
        }
        Err(e) => {
            tracing::debug!(error = %e, "session cookie rejected; redirecting to login");
            redirect_to_login(&path)
        }
    }
}

/// 403 for a SCIM-deactivated dashboard caller. Distinct from
/// `redirect_to_login` because re-login
/// won't help — the IdP would happily re-authenticate them,
/// and they'd land in the same denial. Render a static HTML
/// message so the operator-facing browser UI doesn't dump
/// JSON.
fn scim_inactive_dashboard_response() -> Response {
    let body = "<!doctype html><html><head><title>Account deactivated</title></head>\
                <body><h1>Account deactivated</h1>\
                <p>Your account is provisioned via SCIM but is marked \
                <code>active=false</code>. Contact your administrator to \
                reactivate.</p></body></html>";
    let mut resp = (StatusCode::FORBIDDEN, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

fn redirect_to_login(next_path: &str) -> Response {
    // `next_path` is the inner-router path — axum's
    // `.nest("/admin", …)` has already stripped the `/admin`
    // mount prefix before the middleware ran. The `sanitize_next`
    // sanitizer that consumes `next=` on the other side of the IdP
    // round-trip refuses anything that doesn't start with `/admin/`,
    // which means the un-prefixed inner path was being rejected and
    // the callback was bouncing every unauthenticated deep link
    // (including `/admin/t/<tenant>/<page>`) back to the default
    // tenant home. Re-prepend the mount prefix here so the round-trip
    // preserves the originally-requested URL.
    let absolute = if next_path.starts_with("/admin/") || next_path == "/admin" {
        // Defensive: if some upstream caller already prefixed the path
        // (no current callers do, but reuse-from-tests is possible),
        // don't double-prefix.
        next_path.to_owned()
    } else if next_path.starts_with('/') {
        format!("/admin{next_path}")
    } else {
        // Unrooted path slipped in somehow — bounce to safe default
        // rather than producing `/admin<garbage>`.
        "/admin/".to_owned()
    };
    let url = format!("/admin/login?next={}", urlencode_path(&absolute));
    Redirect::to(&url).into_response()
}

// ---- GET /admin/login -----------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub next: Option<String>,
    /// When set, the login handler appends this scope to the authorize URL
    /// and asks the IdP for `prompt=login` so the user re-authenticates before
    /// receiving the additional scope. Must be in the
    /// `allowed_step_up_scopes` whitelist; otherwise the flow runs as a
    /// normal login.
    #[serde(default)]
    pub step_up_scope: Option<String>,
}

pub async fn login_get(State(auth): State<DashboardAuth>, Query(q): Query<LoginQuery>) -> Response {
    let Some(cfg) = auth.enforce() else {
        // Dev mode: auth is disabled entirely. Bounce to the dashboard.
        return Redirect::to("/admin/").into_response();
    };

    let next = sanitize_next(q.next.as_deref());
    let pkce = new_pkce_pair();
    let state = new_random_token();

    // Step-up: when the client asked for an extra scope (only accepted if it
    // appears on the whitelist), append it to the authorize URL and force a
    // fresh IdP login. Authenticator policy belongs to the IdP; the gateway
    // does not request or validate an MFA-specific ACR. An unknown scope is
    // dropped silently rather than errored — the worst case is a normal
    // login, which is safe.
    let step_up = q
        .step_up_scope
        .as_deref()
        .filter(|s| cfg.allowed_step_up_scopes.iter().any(|a| a == s));
    let mut scopes = cfg.scopes.clone();
    if let Some(extra) = step_up {
        if !scopes.iter().any(|s| s == extra) {
            scopes.push(extra.to_owned());
        }
    }
    let prompt = step_up.map(|_| "login");

    let ls = LoginState {
        pkce_verifier: pkce.verifier.clone(),
        state: state.clone(),
        next: next.clone(),
        exp: now_unix() + cfg.login_state_ttl,
    };
    let login_cookie = match session_encrypt(&cfg.session_key, &ls) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "login-state encrypt failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let mut resp = Redirect::to(&authorize_url(&AuthorizeParams {
        authorization_endpoint: &cfg.endpoints.authorization_endpoint,
        client_id: &cfg.client_id,
        redirect_uri: &cfg.redirect_uri,
        scopes: &scopes,
        state: &state,
        pkce_challenge: &pkce.challenge,
        acr_values: None,
        prompt,
    }))
    .into_response();
    // Scope the login-state cookie to /admin; same-origin navigation only.
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&build_cookie(
            LOGIN_STATE_COOKIE,
            &login_cookie,
            cfg.login_state_ttl,
            cfg.secure_cookies,
        ))
        .expect("cookie header"),
    );
    resp
}

// ---- GET /admin/auth/callback --------------------------------------------

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

pub async fn callback_get(
    State(auth): State<DashboardAuth>,
    headers: axum::http::HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(cfg) = auth.enforce() else {
        return Redirect::to("/admin/").into_response();
    };

    if let Some(err) = q.error {
        tracing::warn!(
            error = %err,
            detail = q.error_description.unwrap_or_default(),
            "IdP returned an authorization error"
        );
        return callback_error("Sign-in was cancelled or rejected by the identity provider.");
    }
    let Some(code) = q.code else {
        return callback_error("The identity provider did not return an authorization code.");
    };
    let Some(state_in) = q.state else {
        return callback_error("The identity provider did not return the `state` parameter.");
    };

    // Pull + decrypt the login-state cookie. Its absence here means either
    // a direct hit on the callback URL or an expired cookie; both are handled
    // the same way — bounce the user back to the login start.
    let ls_cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|hdr| cookie_value(hdr, LOGIN_STATE_COOKIE).map(|s| s.to_owned()));
    let ls: LoginState = match ls_cookie
        .as_deref()
        .map(|raw| session_decrypt::<LoginState>(&cfg.session_key, raw))
    {
        Some(Ok(ls)) => ls,
        Some(Err(e)) => {
            tracing::debug!(error = %e, "login-state cookie failed decrypt");
            return callback_error("Login session expired. Please try again.");
        }
        None => {
            return callback_error("Login session missing. Please try again.");
        }
    };

    if !constant_time_eq(ls.state.as_bytes(), state_in.as_bytes()) {
        tracing::warn!("IdP state mismatch — possible CSRF or stale tab");
        return callback_error("Login state mismatch. Please try again.");
    }

    let token = match exchange_code(
        &cfg.token_http,
        ExchangeParams {
            token_endpoint: &cfg.endpoints.token_endpoint,
            client_id: &cfg.client_id,
            client_secret: &cfg.client_secret,
            redirect_uri: &cfg.redirect_uri,
            code: &code,
            pkce_verifier: &ls.pkce_verifier,
        },
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "token exchange failed");
            return callback_error("Could not exchange the authorization code. Please try again.");
        }
    };

    let Some(id_token) = token.id_token.as_deref() else {
        tracing::warn!("token response missing id_token");
        return callback_error("Identity provider did not return an ID token.");
    };

    let (mut principal, id_assurance) = match cfg
        .id_token_validator
        .validate_with_assurance(id_token)
        .await
    {
        Ok(validated) => validated,
        Err(e) => {
            tracing::warn!(error = %e, "id_token validation failed");
            return callback_error("Identity token was rejected. Please contact an administrator.");
        }
    };
    let assurance = session_assurance(&id_assurance);
    // OAuth2 RFC 6749 §5.1: the OIDC ID token's `scope` claim is optional
    // (Authentik does not emit it — `claims_supported` has no `scope`) and
    // the authoritative list of granted scopes is the top-level `scope` on
    // the token response. Without this overlay, dashboard sessions always
    // come back with an empty `scopes`, so every step-up flow
    // (`mcp:admin`, `mcp:invoke:high`, …) silently no-ops at the gate.
    apply_granted_scopes(&mut principal, token.scope.as_deref());

    let session = Session {
        principal,
        csrf_token: new_random_token(),
        assurance,
        exp: now_unix() + cfg.session_ttl,
    };
    let encrypted = match session_encrypt(&cfg.session_key, &session) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "session encrypt failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // Post-login, send the operator to their tenant-scoped home
    // (`/admin/t/<principal.tenant>/`) when no explicit `next` was set
    // at login time. Operators who hit `/admin/` directly today land on
    // the legacy un-prefixed page; with the URL prefix as the new
    // canonical shape we route them into the tenant scope instead so
    // the selector + banner activate on first paint. Explicit `next`
    // values are preserved (sanitize_next already accepts tenant-prefixed
    // paths because they start with `/admin/`).
    let redirect_to = if is_default_home(&ls.next) {
        crate::tenant_ctx::home_url(session.principal.tenant.as_str())
    } else {
        ls.next.clone()
    };
    let mut resp = Redirect::to(&redirect_to).into_response();
    let headers = resp.headers_mut();
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&build_cookie(
            SESSION_COOKIE,
            &encrypted,
            cfg.session_ttl,
            cfg.secure_cookies,
        ))
        .expect("cookie header"),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(LOGIN_STATE_COOKIE, cfg.secure_cookies))
            .expect("cookie header"),
    );
    resp
}

// ---- POST /admin/logout ---------------------------------------------------

pub async fn logout_post(State(auth): State<DashboardAuth>) -> Response {
    let secure = auth.enforce().map(|c| c.secure_cookies).unwrap_or(false);
    let mut resp = Redirect::to("/admin/login").into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(SESSION_COOKIE, secure)).expect("cookie header"),
    );
    resp
}

// ---- helpers --------------------------------------------------------------

/// Constrain the post-login redirect target so a crafted
/// `?next=https://evil.example/...` can't turn the gateway into an open
/// redirector. Anything that isn't a plain same-origin `/admin/...` path
/// falls back to the dashboard home.
///
/// `/admin/t/<tenant>/...` paths are accepted via the `/admin/` prefix
/// check — no separate case needed.
fn sanitize_next(raw: Option<&str>) -> String {
    match raw {
        Some(s) if s.starts_with("/admin/") || s == "/admin" => s.to_owned(),
        _ => "/admin/".to_owned(),
    }
}

/// True when `next` is the default sanitize result — i.e. the operator
/// hit `/admin/login` directly (no `?next=` set) and `sanitize_next`
/// returned the canonical fallback. The post-login redirect substitutes
/// the tenant-scoped home in this case so the selector + cross-tenant
/// banner activate on first paint.
fn is_default_home(next: &str) -> bool {
    next == "/admin/" || next == "/admin"
}

/// Percent-encode path characters that would break the `next=` query string.
/// Mirrors the hand-rolled encoder in pkce/dashboard — keep one here to
/// avoid a cycle with waygate-oidc for a non-OIDC concern.
fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Overlay the OAuth2 token-response `scope` onto a principal whose scopes
/// came from the OIDC ID token. Whitespace-separated per RFC 6749 §3.3.
/// Absent / empty → leave the principal's existing scopes alone (no
/// scope-stripping; the ID-token path can populate them on IdPs that do
/// emit a `scope` claim).
fn apply_granted_scopes(principal: &mut Principal, granted: Option<&str>) {
    if let Some(s) = granted {
        let parsed: Vec<String> = s.split_whitespace().map(str::to_owned).collect();
        if !parsed.is_empty() {
            principal.scopes = parsed;
        }
    }
}

/// Normalize signed ID-token assurance into the small factor vocabulary the
/// approval gate understands. The ACR is deliberately not used as a gateway
/// policy gate: the IdP owns authenticator selection and the callback only
/// validates the resulting signed token.
fn session_assurance(claims: &IdTokenAssurance) -> SessionAssurance {
    let has_amr = |needle: &str| claims.amr.iter().any(|v| v.eq_ignore_ascii_case(needle));
    // Authentik 2026.2 emits `amr=user` for its passwordless WebAuthn stage
    // and also emits `mfa` because the credential is stored as an MFA device.
    // That is a passkey login, not a separate MFA-token presentation.
    let authentik_passkey =
        claims.acr.as_deref() == Some("goauthentik.io/providers/oauth2/default") && has_amr("user");
    let has_passkey = authentik_passkey || has_amr("webauthn") || has_amr("passkey");
    let mut factors = Vec::new();
    if has_amr("mfa") && !authentik_passkey {
        factors.push("mfa".to_owned());
    }
    if has_passkey {
        factors.push("passkey".to_owned());
    }

    SessionAssurance {
        authenticated_at: claims.auth_time,
        factors,
    }
}

fn dev_principal() -> Principal {
    Principal {
        sub: "dev@local".into(),
        email: Some("dev@local".into()),
        groups: vec!["mcp-admins".into()],
        issuer: "local-dev".into(),
        scopes: vec!["mcp:invoke".into(), "mcp:read".into(), "mcp:admin".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

/// Terminal error page for the callback. Keeps markup inline so this path
/// stays independent of askama — important because a template failure here
/// would leave the user staring at a 500 with no recovery link.
fn callback_error(detail: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=utf-8>\
         <title>Sign-in failed · Waygate</title>\
         <body style=\"font-family: system-ui; max-width: 40rem; margin: 4rem auto; padding: 1rem\">\
         <h1>Sign-in failed</h1>\
         <p>{}</p>\
         <p><a href=\"/admin/login\">Try again</a></p>\
         </body>",
        waygate_core::html::escape(detail)
    );
    let mut resp = (StatusCode::BAD_REQUEST, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// Sanity bridge so callers using the `SessionError` type don't need to pull
/// it in directly. No code references this today — kept because error
/// surfaces tend to grow once the first production bug reports land.
#[allow(dead_code)]
pub(crate) fn is_expired(e: &SessionError) -> bool {
    matches!(e, SessionError::Expired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_next_accepts_admin_paths() {
        assert_eq!(sanitize_next(Some("/admin/")), "/admin/");
        assert_eq!(sanitize_next(Some("/admin/servers")), "/admin/servers");
        assert_eq!(sanitize_next(Some("/admin")), "/admin");
    }

    #[test]
    fn sanitize_next_rejects_open_redirects() {
        assert_eq!(sanitize_next(Some("https://evil.example/")), "/admin/");
        assert_eq!(sanitize_next(Some("//evil.example/")), "/admin/");
        assert_eq!(sanitize_next(Some("/other/area")), "/admin/");
        assert_eq!(sanitize_next(None), "/admin/");
    }

    #[test]
    fn sanitize_next_passes_tenant_prefixed_path() {
        // The tenant-scoped paths start with `/admin/` so the
        // existing prefix check accepts them. Pin this invariant so a
        // future refactor of `sanitize_next` doesn't accidentally
        // narrow it.
        assert_eq!(
            sanitize_next(Some("/admin/t/acme/servers")),
            "/admin/t/acme/servers",
        );
        assert_eq!(
            sanitize_next(Some("/admin/t/default/")),
            "/admin/t/default/",
        );
    }

    fn redirect_location(resp: &Response) -> String {
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_default()
    }

    /// `redirect_to_login` must re-prepend the `/admin` mount prefix
    /// that axum's `.nest("/admin", …)`
    /// strips before middleware sees the path. Without this, the `next=`
    /// query param round-trips through the IdP and gets rejected by
    /// `sanitize_next` (which requires `/admin/...` paths), and the
    /// callback's `is_default_home` then bounces every unauthenticated
    /// deep link to the default tenant home.
    #[test]
    fn redirect_to_login_re_prefixes_inner_paths() {
        // Tenant-prefixed deep link: middleware saw `/t/acme/servers`
        // because the outer nest stripped `/admin`. The next= param
        // must round-trip with the full `/admin/t/acme/servers`.
        let resp = redirect_to_login("/t/acme/servers");
        let loc = redirect_location(&resp);
        assert_eq!(loc, "/admin/login?next=/admin/t/acme/servers");

        // Legacy deep link: same story for the un-prefixed pages.
        let resp = redirect_to_login("/servers");
        let loc = redirect_location(&resp);
        assert_eq!(loc, "/admin/login?next=/admin/servers");

        // Already-prefixed path (defensive): don't double-prefix.
        let resp = redirect_to_login("/admin/t/default/policies");
        let loc = redirect_location(&resp);
        assert_eq!(loc, "/admin/login?next=/admin/t/default/policies");

        // Unrooted garbage path: bounce to the safe default rather
        // than constructing `/admin<garbage>`.
        let resp = redirect_to_login("garbage");
        let loc = redirect_location(&resp);
        assert_eq!(loc, "/admin/login?next=/admin/");
    }

    /// Full round-trip: middleware path → redirect_to_login → sanitize_next
    /// → callback `is_default_home` predicate. With the r3 fix, deep links
    /// MUST round-trip verbatim and MUST NOT be treated as the default
    /// home (which would substitute the tenant-scoped home page).
    #[test]
    fn deep_link_round_trips_through_sanitizer_and_default_home_check() {
        // Tenant-prefixed deep link.
        let next = redirect_location(&redirect_to_login("/t/acme/servers"));
        let after_idp = next.strip_prefix("/admin/login?next=").unwrap();
        // URL-encoded by `urlencode_path` — for these ASCII paths
        // the encoder is a no-op, so the raw form is what `Query`
        // would extract.
        assert_eq!(sanitize_next(Some(after_idp)), "/admin/t/acme/servers");
        assert!(
            !is_default_home(&sanitize_next(Some(after_idp))),
            "tenant-prefixed deep link must not be treated as default home",
        );

        // Legacy deep link.
        let next = redirect_location(&redirect_to_login("/servers"));
        let after_idp = next.strip_prefix("/admin/login?next=").unwrap();
        assert_eq!(sanitize_next(Some(after_idp)), "/admin/servers");
        assert!(!is_default_home(&sanitize_next(Some(after_idp))));
    }

    #[test]
    fn is_default_home_recognises_canonical_forms() {
        // Both shapes `sanitize_next` can return for the default
        // (no explicit `next=`) path. The callback substitutes the
        // tenant-scoped home only when one of these matches; explicit
        // `next` values (e.g. `/admin/t/acme/servers`) round-trip
        // verbatim.
        assert!(is_default_home("/admin/"));
        assert!(is_default_home("/admin"));
        assert!(!is_default_home("/admin/t/default/"));
        assert!(!is_default_home("/admin/servers"));
        assert!(!is_default_home("/"));
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn public_paths_recognized() {
        assert!(is_public_path("/login"));
        assert!(is_public_path("/auth/callback"));
        assert!(is_public_path("/static/css/base.css"));
        assert!(!is_public_path("/"));
        assert!(!is_public_path("/policies"));
    }

    fn principal_with_scopes(scopes: Vec<String>) -> Principal {
        Principal {
            sub: "u".into(),
            email: None,
            groups: vec![],
            issuer: "i".into(),
            scopes,
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn granted_scopes_overlay_replaces_id_token_scopes() {
        // Authentik path: ID token has no `scope`, OAuth response carries
        // the granted set. Principal must end up with the granted scopes
        // so `has_scope("mcp:admin")` and friends gate correctly.
        let mut p = principal_with_scopes(vec![]);
        apply_granted_scopes(&mut p, Some("openid profile email groups mcp:admin"));
        assert!(p.has_scope("mcp:admin"));
        assert!(p.has_scope("openid"));
    }

    #[test]
    fn granted_scopes_overlay_preserves_id_token_scopes_when_absent() {
        // IdPs that DO emit a `scope` claim in the ID token: the
        // ID-token-derived scopes must survive an absent token-response
        // `scope` field. No scope-stripping just because the optional
        // field was omitted.
        let mut p = principal_with_scopes(vec!["mcp:read".into()]);
        apply_granted_scopes(&mut p, None);
        assert!(p.has_scope("mcp:read"));
    }

    #[test]
    fn granted_scopes_overlay_treats_empty_string_as_absent() {
        // Defensive: a present-but-empty `scope` field would otherwise
        // wipe ID-token scopes. Treat it the same as None.
        let mut p = principal_with_scopes(vec!["mcp:read".into()]);
        apply_granted_scopes(&mut p, Some("   "));
        assert!(p.has_scope("mcp:read"));
    }

    #[test]
    fn acr_does_not_create_gateway_mfa_assurance() {
        let claims = IdTokenAssurance {
            auth_time: None,
            amr: vec!["pwd".into()],
            acr: Some("urn:example:mfa".into()),
        };
        let assurance = session_assurance(&claims);
        assert_eq!(assurance.authenticated_at, None);
        assert!(assurance.factors.is_empty());
    }

    #[test]
    fn authentik_default_acr_does_not_block_signed_login() {
        let claims = IdTokenAssurance {
            auth_time: Some(1_710_000_000),
            amr: vec!["pwd".into()],
            acr: Some("goauthentik.io/providers/oauth2/default".into()),
        };
        let assurance = session_assurance(&claims);
        assert_eq!(assurance.authenticated_at, claims.auth_time);
        assert!(assurance.factors.is_empty());
    }

    #[test]
    fn signed_webauthn_amr_records_passkey_without_promoting_to_mfa() {
        let claims = IdTokenAssurance {
            auth_time: Some(1_710_000_000),
            amr: vec!["webauthn".into()],
            acr: None,
        };
        let assurance = session_assurance(&claims);
        assert_eq!(assurance.authenticated_at, claims.auth_time);
        assert_eq!(assurance.factors, ["passkey"]);
    }

    #[test]
    fn authentik_passwordless_webauthn_is_passkey_not_mfa_token() {
        let claims = IdTokenAssurance {
            auth_time: Some(1_710_000_000),
            amr: vec!["user".into(), "mfa".into()],
            acr: Some("goauthentik.io/providers/oauth2/default".into()),
        };
        let assurance = session_assurance(&claims);
        assert_eq!(assurance.authenticated_at, claims.auth_time);
        assert_eq!(assurance.factors, ["passkey"]);
    }

    #[test]
    fn explicit_mfa_amr_records_only_mfa() {
        let claims = IdTokenAssurance {
            auth_time: Some(1_710_000_000),
            amr: vec!["mfa".into()],
            acr: None,
        };
        let assurance = session_assurance(&claims);
        assert_eq!(assurance.authenticated_at, claims.auth_time);
        assert_eq!(assurance.factors, ["mfa"]);
    }
}
