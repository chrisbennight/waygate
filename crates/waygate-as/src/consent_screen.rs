//! `/oauth/consent` interactive screen — the GET that
//! renders the approve/deny form and the POST that
//! consumes the user's decision.
//!
//! ## Flow recap
//!
//! 1. `/oauth/callback` receives the upstream code,
//!    validates the id-token, decides "this requires
//!    explicit consent." It writes a row to
//!    `oauth_consent_pending` (encrypted upstream
//!    tokens + the original `(client, scopes, state,
//!    code_challenge, redirect_uri)`) and 302s the
//!    user to `/oauth/consent?token=<pending_token>`.
//! 2. The GET handler loads that pending row, renders
//!    a small HTML page showing the client, the
//!    principal, and the requested scopes. The page
//!    has approve + deny buttons, each of which POSTs
//!    back with the same token (CSRF binding).
//! 3. The POST handler `take`s the pending row
//!    atomically. On approve, it replays the writes
//!    callback.rs normally does (consent upsert +
//!    Tier-A session upsert + `oauth_codes` insert),
//!    then 302s the user to the client's redirect
//!    URI with `code` + `state` + RFC 9207 `iss`. On
//!    deny, it 302s to the client with
//!    `error=access_denied` per RFC 6749 §4.1.2.1.
//!
//! ## Why HTML is hand-rendered (not askama)
//!
//! `waygate-as` doesn't currently depend on askama and
//! the screen is one form. Inlining `format!`-style
//! HTML here keeps the dep tree clean and avoids
//! pulling in a templating crate for ~30 lines of
//! markup. A later PR that grows the consent UX (e.g.
//! per-scope checkboxes, branding) is the right time
//! to graduate to askama.
//!
//! ## CSRF posture
//!
//! `token` is a 32-byte URL-safe random string the
//! callback minted in [`crate::consent_pending`]. It
//! serves as both the lookup key AND the CSRF token:
//! the POST handler requires the form-body `token` to
//! match a real pending row, and an attacker without
//! the value can't forge an approval. The `take`
//! semantics make the token single-use — a replayed
//! POST returns `pending_not_found`.

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};

use waygate_core::html::escape as html_escape;

use crate::callback::build_redirect;
use crate::router::AsState;
use crate::store::IssuedCode;

#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub token: String,
    /// `"approve"` or `"deny"`. Anything else → 400.
    pub decision: String,
}

/// Render the consent screen for `?token=<pending>`. On
/// an absent or expired token, returns 404 with a small
/// explanation — the user has no way to recover here
/// (the OAuth state is gone), so the right action is to
/// restart the flow at the client.
pub async fn handler_get(State(state): State<AsState>, Query(q): Query<ConsentQuery>) -> Response {
    let pending = match state.consent_pending.get(&q.token).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return render_expired();
        }
        Err(e) => {
            tracing::error!(error = %e, "consent screen: pending store get failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "consent store unavailable",
                "the gateway couldn't read the pending consent state. Try again from the client.",
            );
        }
    };
    let body = render_consent_page(
        &pending.token,
        &pending.client_id,
        &pending.principal_sub,
        pending.principal_email.as_deref(),
        &pending.scopes,
    );
    // Block clickjacking. The consent screen is an
    // unauthenticated approve button — framing it from
    // a hostile origin and tricking the user into
    // clicking would let an attacker piggyback an
    // approval onto an unrelated user action. CSP
    // frame-ancestors is the modern primary control;
    // X-Frame-Options is the old-browser fallback (most
    // browsers still honour it). The render is the only
    // GET in this module, so the headers go here, not
    // at a global layer.
    add_frame_protection(Html(body).into_response())
}

/// Handle the user's decision. Approve replays the
/// callback's "write the durable rows + 302 to client"
/// path; deny just redirects with `error=access_denied`.
/// Either way the pending row disappears (single-use
/// `take`).
pub async fn handler_post(State(state): State<AsState>, Form(form): Form<ConsentForm>) -> Response {
    let decision = form.decision.to_ascii_lowercase();
    if decision != "approve" && decision != "deny" {
        return error_response(
            StatusCode::BAD_REQUEST,
            "bad request",
            "decision must be \"approve\" or \"deny\".",
        );
    }
    // `take` returns None when the token is unknown OR
    // already-used (single-use) OR expired. All three
    // resolve to the same UX: "your consent session is
    // gone, restart at the client."
    let pending = match state.consent_pending.take(&form.token).await {
        Ok(Some(p)) => p,
        Ok(None) => return render_expired(),
        Err(e) => {
            tracing::error!(error = %e, "consent screen: pending store take failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "consent store unavailable",
                "the gateway couldn't claim the pending consent state. Try again from the client.",
            );
        }
    };

    if decision == "deny" {
        // Emit `error=access_denied` per RFC 6749
        // §4.1.2.1. State + RFC 9207 `iss` ride along
        // so the client can correlate the response with
        // their `/oauth/authorize` request.
        let redirect = build_deny_redirect(
            &pending.client_redirect_uri,
            pending.client_state.as_deref(),
            state.config.issuer(),
        );
        // AdminMutation-style audit: the user actively
        // refused. Chained best-effort here; the absence of an
        // audit row on a deny doesn't leave a grant
        // anywhere (there's no row to leak), so the
        // fail-closed `record_required` reasoning used
        // for durable security-relevant grants (e.g. the
        // consent grant itself, or a break-glass mint)
        // doesn't apply.
        state
            .evidence
            .record_chained_best_effort(
                waygate_evidence::AuditEvent::new(
                    "OAuthConsentDenied",
                    waygate_evidence::AuditOutcome::Denied,
                )
                .with_category(waygate_evidence::EvidenceCategory::OAuthEvent)
                .with_tenant(waygate_core::TenantId::parse(&pending.tenant_id).unwrap_or_default())
                .with_reason(format!(
                    "consent denied: tenant_id={} principal_sub={} client_id={} \
                     scopes={}",
                    pending.tenant_id,
                    pending.principal_sub,
                    pending.client_id,
                    pending.scopes.join(" "),
                )),
            )
            .await;
        return redirect_response(&redirect);
    }

    // Approve path: replay the durable writes the
    // callback would have done if it weren't gated. The
    // pending row is the source of truth — every field
    // comes from there so nothing is reconstructed from
    // the request.
    let scopes_owned: Vec<String> = pending.scopes.clone();
    if let Err(e) = state
        .consent
        .upsert(crate::consent::NewConsentGrant {
            tenant_id: pending.tenant_id.as_str(),
            principal_sub: pending.principal_sub.as_str(),
            client_id: pending.client_id.as_str(),
            scopes: &scopes_owned,
            expires_at: None,
        })
        .await
    {
        tracing::error!(error = %e, "consent screen: consent upsert failed on approve");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "consent store unavailable",
            "the gateway couldn't persist your approval. Restart from the client.",
        );
    }

    // Use the REAL upstream IdP access-token expiry the
    // callback recorded on the pending row
    // (`pending.access_expires_at`), NOT a synthetic
    // now()+1h — so a 5-min upstream token is recorded
    // as expiring in 5 minutes, and the refresh-on-demand
    // path kicks in at the right time.
    if let Err(e) = state
        .upstream_sessions
        .upsert(crate::sessions::NewSessionRow {
            sub: &pending.principal_sub,
            upstream_issuer: &state.config.upstream_issuer,
            tokens_ciphertext: &pending.upstream_tokens_ciphertext,
            key_id: &pending.key_id,
            access_expires_at: pending.access_expires_at,
        })
        .await
    {
        tracing::error!(error = %e, "consent screen: upstream-session upsert failed on approve");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session store unavailable",
            "the gateway couldn't persist the upstream session. Restart from the client.",
        );
    }

    let gw_code = waygate_oidc::pkce::new_random_token();
    let code_expires_at =
        OffsetDateTime::now_utc() + TimeDuration::seconds(state.config.code_ttl.as_secs() as i64);
    let issued = IssuedCode {
        code: gw_code.clone(),
        client_id: pending.client_id.clone(),
        redirect_uri: pending.client_redirect_uri.clone(),
        code_challenge: pending.code_challenge.clone(),
        scopes: pending.scopes.clone(),
        sub: pending.principal_sub.clone(),
        email: pending.principal_email.clone(),
        groups: pending.principal_groups.clone(),
        upstream_tokens_ciphertext: Some(pending.upstream_tokens_ciphertext.clone()),
        expires_at: code_expires_at,
        tenant_id: pending.tenant_id.clone(),
    };
    if let Err(e) = state.store.insert_code(&issued).await {
        tracing::error!(error = %e, "consent screen: insert_code failed on approve");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "oauth code store unavailable",
            "the gateway couldn't mint the authorization code. Restart from the client.",
        );
    }

    state
        .evidence
        .record_chained_best_effort(
            waygate_evidence::AuditEvent::new(
                "OAuthConsentApproved",
                waygate_evidence::AuditOutcome::Success,
            )
            .with_category(waygate_evidence::EvidenceCategory::OAuthEvent)
            .with_tenant(waygate_core::TenantId::parse(&pending.tenant_id).unwrap_or_default())
            .with_reason(format!(
                "consent approved: tenant_id={} principal_sub={} client_id={} \
                 scopes={}",
                pending.tenant_id,
                pending.principal_sub,
                pending.client_id,
                pending.scopes.join(" "),
            )),
        )
        .await;

    let redirect = build_redirect(
        &pending.client_redirect_uri,
        &gw_code,
        pending.client_state.as_deref(),
        state.config.issuer(),
    );
    redirect_response(&redirect)
}

fn render_expired() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "consent session expired",
        "this consent screen has expired or already been used. Please restart from your client.",
    )
}

/// Apply frame-protection headers to every HTML response
/// served by this module. `frame-ancestors 'none'` is
/// the CSP-3 control (no origin, including same-origin,
/// may frame the page); `X-Frame-Options: DENY` is the
/// pre-CSP-3 fallback. Modern browsers honour both;
/// older ones honour at least one.
fn add_frame_protection(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

/// Helper: build an error-page Response with the
/// frame-protection headers already attached. Every
/// HTML response from this module routes through here
/// or through `add_frame_protection` directly so the
/// clickjacking control can't be silently bypassed by
/// a future code path that builds its own Response
/// inline.
fn error_response(status: StatusCode, title: &str, body: &str) -> Response {
    add_frame_protection((status, Html(error_page(title, body))).into_response())
}

fn render_consent_page(
    token: &str,
    client_id: &str,
    principal_sub: &str,
    principal_email: Option<&str>,
    scopes: &[String],
) -> String {
    // HTML-escape every interpolation: the values come
    // from the upstream IdP / CIMD doc / request, none
    // of which we can fully trust to be `<script>`-free.
    let scopes_html = scopes
        .iter()
        .map(|s| format!("<li><code>{}</code></li>", html_escape(s)))
        .collect::<Vec<_>>()
        .join("");
    let email_line = principal_email
        .map(|e| format!("<p>Email: <code>{}</code></p>", html_escape(e)))
        .unwrap_or_default();
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Approve access?</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }}
    h1 {{ font-size: 1.4rem; margin-bottom: 0.5rem; }}
    code {{ background: #f4f4f5; padding: 1px 4px; border-radius: 3px; }}
    ul {{ padding-left: 1.5rem; }}
    .actions {{ display: flex; gap: 0.75rem; margin-top: 1.5rem; }}
    button {{ padding: 0.6rem 1.2rem; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; font-size: 1rem; }}
    .approve {{ background: #16a34a; color: white; border-color: #16a34a; }}
    .deny {{ background: white; }}
    .hint {{ color: #555; font-size: 0.85rem; margin-top: 1.5rem; }}
  </style>
</head>
<body>
  <h1>Approve access?</h1>
  <p>The client <code>{client}</code> is asking to act on your behalf.</p>
  <p>You're signed in as <code>{sub}</code>.</p>
  {email}
  <p>It will be able to:</p>
  <ul>{scopes}</ul>
  <form method="POST" action="/oauth/consent">
    <input type="hidden" name="token" value="{token}">
    <div class="actions">
      <button class="approve" type="submit" name="decision" value="approve">Approve</button>
      <button class="deny" type="submit" name="decision" value="deny">Deny</button>
    </div>
  </form>
  <p class="hint">You can revoke this access at any time from the gateway admin's OAuth consent panel.</p>
</body>
</html>
"##,
        client = html_escape(client_id),
        sub = html_escape(principal_sub),
        email = email_line,
        scopes = scopes_html,
        token = html_escape(token),
    )
}

fn error_page(title: &str, body: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }}
    h1 {{ font-size: 1.2rem; }}
    p {{ color: #555; }}
  </style>
</head>
<body><h1>{}</h1><p>{}</p></body>
</html>
"##,
        html_escape(title),
        html_escape(title),
        html_escape(body),
    )
}

/// Build the `error=access_denied` redirect URL per RFC
/// 6749 §4.1.2.1. Mirrors `callback::build_redirect` for
/// state + RFC 9207 `iss` handling.
fn build_deny_redirect(base: &str, state: Option<&str>, iss: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = format!("{base}{sep}error=access_denied");
    if let Some(s) = state {
        out.push_str("&state=");
        out.push_str(&urlencoding_minimal(s));
    }
    out.push_str("&iss=");
    out.push_str(&urlencoding_minimal(iss));
    out
}

fn redirect_response(url: &str) -> Response {
    let mut resp = (StatusCode::FOUND, "").into_response();
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(url).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    resp
}

// Local copy of callback.rs's tiny URL-encoder. Kept
// here to avoid making callback.rs re-export a private
// helper; the implementation is trivial and exactly the
// same characters need escaping.
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_handles_meta_chars() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"x\""), "&quot;x&quot;");
        assert_eq!(html_escape("'y'"), "&#x27;y&#x27;");
    }

    #[test]
    fn build_deny_redirect_appends_query() {
        let url = build_deny_redirect(
            "https://client.example/cb",
            Some("opaque-state-1"),
            "https://gateway.example",
        );
        assert!(url.contains("?error=access_denied"));
        assert!(url.contains("&state=opaque-state-1"));
        assert!(url.contains("&iss=https%3A%2F%2Fgateway.example"));
    }

    #[test]
    fn build_deny_redirect_keeps_existing_query() {
        let url = build_deny_redirect("https://client/cb?x=1", None, "https://gw");
        assert!(url.starts_with("https://client/cb?x=1&error=access_denied"));
    }

    #[test]
    fn build_deny_redirect_omits_state_when_absent() {
        let url = build_deny_redirect("https://client/cb", None, "https://gw");
        assert!(!url.contains("state="));
        assert!(url.contains("error=access_denied"));
        assert!(url.contains("iss="));
    }

    #[test]
    fn render_consent_page_renders_scopes_and_principal() {
        let html = render_consent_page(
            "tok123",
            "https://cli.example/codex.json",
            "alice",
            Some("alice@example.test"),
            &["mcp:invoke".into(), "mcp:read".into()],
        );
        // Token must be inside the hidden field (CSRF
        // binding); regression would let an attacker
        // approve without holding the token.
        assert!(html.contains("name=\"token\" value=\"tok123\""));
        assert!(html.contains("alice"));
        assert!(html.contains("alice@example.test"));
        assert!(html.contains("mcp:invoke"));
        assert!(html.contains("mcp:read"));
        // Both buttons present.
        assert!(html.contains("name=\"decision\" value=\"approve\""));
        assert!(html.contains("name=\"decision\" value=\"deny\""));
    }

    #[test]
    fn add_frame_protection_sets_both_headers() {
        // Regression guard: every HTML response from this
        // module MUST carry `frame-ancestors 'none'`
        // (CSP-3) and `X-Frame-Options: DENY` (legacy
        // fallback). A future code path that builds
        // its own Response inline and skips the
        // helper would re-introduce the clickjacking
        // gap.
        let resp = add_frame_protection(Html("hi").into_response());
        let headers = resp.headers();
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_SECURITY_POLICY)
                .and_then(|h| h.to_str().ok()),
            Some("frame-ancestors 'none'"),
        );
        assert_eq!(
            headers
                .get(axum::http::header::X_FRAME_OPTIONS)
                .and_then(|h| h.to_str().ok()),
            Some("DENY"),
        );
    }

    #[test]
    fn error_response_sets_frame_protection() {
        let resp = error_response(StatusCode::BAD_REQUEST, "t", "b");
        let headers = resp.headers();
        assert!(headers.contains_key(axum::http::header::CONTENT_SECURITY_POLICY));
        assert!(headers.contains_key(axum::http::header::X_FRAME_OPTIONS));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn render_consent_page_escapes_injected_html() {
        // An attacker-controlled CIMD `client_id` that
        // somehow contained markup must NOT execute —
        // the screen renders trusted operators, but the
        // values it interpolates aren't all under our
        // control.
        let html = render_consent_page(
            "tok",
            "<script>alert('x')</script>",
            "u",
            None,
            &["a".into()],
        );
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
