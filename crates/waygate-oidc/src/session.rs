//! Encrypted cookie payloads used by the admin dashboard.
//!
//! The dashboard does not run a server-side session store (punch-list
//! philosophy: "stateless first"). Instead, both the post-login session and
//! the short-lived PKCE login state ride in AES-256-GCM-encrypted cookies
//! keyed by a 32-byte secret supplied out-of-band (Infisical in prod, env
//! var in dev).
//!
//! Cookie wire format:
//! ```text
//! base64url( nonce (12 bytes) || ciphertext || gcm_tag (16 bytes) )
//! ```
//!
//! The nonce is fresh-random per encrypt. The tag is authenticated; any
//! tampering or key rotation invalidates the cookie (decode returns None, not
//! a bogus session).
//!
//! Claims are JSON — small enough (<500 bytes for a typical Authentik token)
//! that cookie-size pressure isn't a concern. No JWT wrapper because we
//! don't need third-party verification of these blobs; the only audience is
//! the gateway itself.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::aead;
use crate::Principal;

/// Name of the post-login session cookie. One per gateway deployment;
/// renaming this rolls every live session.
pub const SESSION_COOKIE: &str = "mcp-gw-session";

/// Name of the pre-callback PKCE login-state cookie. Short TTL — it lives
/// from the `/admin/login` redirect until the IdP round-trips back.
pub const LOGIN_STATE_COOKIE: &str = "mcp-gw-login";

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("payload too short (nonce missing)")]
    TooShort,
    #[error("gcm: {0}")]
    Gcm(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("expired")]
    Expired,
}

/// Authentication assurance captured from the validated ID token when the
/// dashboard session is minted. The encrypted cookie authenticates these
/// fields; approval code still applies a short freshness window at use time.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAssurance {
    /// Signed OIDC `auth_time` from the validated ID token.
    #[serde(default)]
    pub authenticated_at: Option<i64>,
    /// Server-normalized factors currently understood by the approval gate:
    /// `mfa` and `passkey`.
    #[serde(default)]
    pub factors: Vec<String>,
}

/// Claims stashed in the session cookie after a successful IdP round-trip.
/// Holds everything the dashboard needs to render without a second DB hit,
/// plus a CSRF token bound to this session for form posts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub principal: Principal,
    pub csrf_token: String,
    /// Defaults empty so cookies minted before assurance enforcement remain
    /// readable but cannot satisfy a protected approval factor.
    #[serde(default)]
    pub assurance: SessionAssurance,
    /// Unix seconds (UTC). Checked at decrypt time so an attacker can't
    /// replay a captured cookie past its expiry.
    pub exp: i64,
}

/// Claims stashed in the pre-callback cookie. Binds the in-flight PKCE
/// flow to this browser so an attacker can't hand a victim a crafted
/// `?code=&state=` URL and have it be accepted. The `verifier` is what
/// proves the callback came from the same browser that initiated login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginState {
    pub pkce_verifier: String,
    /// Random state echoed into the authorize URL; IdP must return it
    /// verbatim and we must match before trusting the code.
    pub state: String,
    /// Where to redirect once the flow completes. Bounded by the dashboard
    /// layer to same-origin `/admin/*` paths.
    pub next: String,
    pub exp: i64,
}

/// 32-byte AEAD key. Constructed from a base64url secret or straight bytes.
#[derive(Clone)]
pub struct SessionKey(pub(crate) [u8; 32]);

impl SessionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Accept either base64 (standard or URL-safe, with or without padding)
    /// or 64-char hex. Any other length is a hard error — we'd rather fail
    /// startup than silently truncate a misconfigured key.
    pub fn from_encoded(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut out = [0u8; 32];
            for (i, pair) in trimmed.as_bytes().chunks(2).enumerate() {
                out[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                    .map_err(|e| format!("hex: {e}"))?;
            }
            return Ok(Self(out));
        }
        // Try each base64 dialect in turn. `Engine` is not dyn-compatible so
        // we can't collect these into a slice — enumerate by hand.
        let candidates = [
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed),
            base64::engine::general_purpose::URL_SAFE.decode(trimmed),
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed),
            base64::engine::general_purpose::STANDARD.decode(trimmed),
        ];
        for cand in candidates.into_iter().flatten() {
            if cand.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&cand);
                return Ok(Self(out));
            }
        }
        Err("session key must be 32 bytes, base64url or 64-char hex".into())
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Encrypt arbitrary serde-serializable claims into a cookie-value string.
pub fn encrypt<T: Serialize>(key: &SessionKey, claims: &T) -> Result<String, SessionError> {
    let plaintext = serde_json::to_vec(claims)?;
    let blob = aead::seal(&aead::cipher(&key.0), &plaintext).map_err(gcm_err)?;
    Ok(URL_SAFE_NO_PAD.encode(blob))
}

/// Decrypt a cookie value. Returns `Err(Expired)` when the embedded `exp`
/// has passed — the caller can treat that identically to a missing cookie.
pub fn decrypt<T: for<'de> Deserialize<'de> + HasExp>(
    key: &SessionKey,
    cookie_value: &str,
) -> Result<T, SessionError> {
    let raw = URL_SAFE_NO_PAD.decode(cookie_value)?;
    let pt = aead::open(&aead::cipher(&key.0), &raw).map_err(gcm_err)?;
    let v: T = serde_json::from_slice(&pt)?;
    if v.exp() < now_unix() {
        return Err(SessionError::Expired);
    }
    Ok(v)
}

/// Map the shared envelope's errors onto this module's pre-consolidation
/// error surface: too-short blobs keep their dedicated variant, everything
/// else stays a `Gcm`.
fn gcm_err(e: aead::AeadError) -> SessionError {
    match e {
        aead::AeadError::Malformed => SessionError::TooShort,
        other => SessionError::Gcm(other.to_string()),
    }
}

/// Read a named cookie value out of a raw `Cookie:` header. Returns the
/// first matching value; later duplicates are ignored.
pub fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k == name {
                return Some(v);
            }
        }
    }
    None
}

/// Build a `Set-Cookie` header value with safe defaults for this app:
/// `HttpOnly`, `SameSite=Lax` (dashboard is same-site nav only),
/// `Secure` unless explicitly disabled for dev. `Path=/admin` scopes the
/// cookie to the admin area so it isn't sent on `/mcp` or `/api/v1`.
pub fn build_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    let mut s = format!("{name}={value}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age={max_age}",);
    if secure {
        s.push_str("; Secure");
    }
    s
}

/// Clear a cookie by setting Max-Age=0. Used by logout + callback error paths.
pub fn clear_cookie(name: &str, secure: bool) -> String {
    build_cookie(name, "", 0, secure)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Shared trait so `decrypt` can check expiry uniformly for both cookie types.
pub trait HasExp {
    fn exp(&self) -> i64;
}

impl HasExp for Session {
    fn exp(&self) -> i64 {
        self.exp
    }
}

impl HasExp for LoginState {
    fn exp(&self) -> i64 {
        self.exp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SessionKey {
        SessionKey::from_bytes([7u8; 32])
    }

    #[test]
    fn roundtrip_session() {
        let s = Session {
            principal: Principal {
                sub: "alice".into(),
                email: Some("alice@example.com".into()),
                groups: vec!["mcp-admins".into()],
                issuer: "iss".into(),
                scopes: vec!["mcp:admin".into()],
                tenant: waygate_core::TenantId::default(),
                auth_method: crate::AuthMethod::Oauth,
                raw_token: None,
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            csrf_token: "tok".into(),
            assurance: SessionAssurance {
                authenticated_at: Some(now_unix()),
                factors: vec!["mfa".into()],
            },
            exp: now_unix() + 3600,
        };
        let c = encrypt(&key(), &s).unwrap();
        let back: Session = decrypt(&key(), &c).unwrap();
        assert_eq!(back.principal.sub, "alice");
        assert_eq!(back.csrf_token, "tok");
        assert_eq!(back.assurance.factors, ["mfa"]);
    }

    #[test]
    fn expired_session_rejected() {
        let s = Session {
            principal: Principal {
                sub: "alice".into(),
                email: None,
                groups: vec![],
                issuer: "iss".into(),
                scopes: vec![],
                tenant: waygate_core::TenantId::default(),
                auth_method: crate::AuthMethod::Oauth,
                raw_token: None,
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            csrf_token: "tok".into(),
            assurance: SessionAssurance::default(),
            exp: now_unix() - 10,
        };
        let c = encrypt(&key(), &s).unwrap();
        let err = decrypt::<Session>(&key(), &c).unwrap_err();
        assert!(matches!(err, SessionError::Expired), "got {err:?}");
    }

    #[test]
    fn tamper_detected() {
        let s = Session {
            principal: Principal {
                sub: "alice".into(),
                email: None,
                groups: vec![],
                issuer: "iss".into(),
                scopes: vec![],
                tenant: waygate_core::TenantId::default(),
                auth_method: crate::AuthMethod::Oauth,
                raw_token: None,
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            csrf_token: "tok".into(),
            assurance: SessionAssurance::default(),
            exp: now_unix() + 3600,
        };
        let mut c = encrypt(&key(), &s).unwrap();
        // Flip a character in the middle of the ciphertext region.
        let mid = c.len() / 2;
        let ch = c.as_bytes()[mid];
        let flipped = if ch == b'A' { 'B' } else { 'A' };
        c.replace_range(mid..mid + 1, &flipped.to_string());
        let err = decrypt::<Session>(&key(), &c).unwrap_err();
        assert!(
            matches!(err, SessionError::Gcm(_) | SessionError::Json(_)),
            "tamper should fail auth, got {err:?}"
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let s = Session {
            principal: Principal {
                sub: "alice".into(),
                email: None,
                groups: vec![],
                issuer: "iss".into(),
                scopes: vec![],
                tenant: waygate_core::TenantId::default(),
                auth_method: crate::AuthMethod::Oauth,
                raw_token: None,
                roles: vec![],
                scim: None,
                enrichment_blocked: None,
                api_key_profile_restrictions: None,
            },
            csrf_token: "tok".into(),
            assurance: SessionAssurance::default(),
            exp: now_unix() + 3600,
        };
        let c = encrypt(&key(), &s).unwrap();
        let wrong = SessionKey::from_bytes([8u8; 32]);
        let err = decrypt::<Session>(&wrong, &c).unwrap_err();
        assert!(matches!(err, SessionError::Gcm(_)), "got {err:?}");
    }

    #[test]
    fn session_key_decodes_base64_and_hex() {
        let hex = "0101010101010101010101010101010101010101010101010101010101010101";
        assert_eq!(SessionKey::from_encoded(hex).unwrap().0, [1u8; 32]);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]);
        assert_eq!(SessionKey::from_encoded(&b64).unwrap().0, [2u8; 32]);
    }

    #[test]
    fn cookie_value_extracts_named() {
        let h = "foo=1; mcp-gw-session=abc; bar=2";
        assert_eq!(cookie_value(h, "mcp-gw-session"), Some("abc"));
        assert_eq!(cookie_value(h, "nope"), None);
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CompatBlob {
        v: String,
        exp: i64,
    }
    impl HasExp for CompatBlob {
        fn exp(&self) -> i64 {
            self.exp
        }
    }

    /// Cookie produced by the pre-consolidation `encrypt` under key
    /// `[9u8; 32]` (embedded exp is 2100-01-01 so the expiry check never
    /// trips). The shared envelope must keep decrypting it — live session
    /// cookies minted before the deploy must survive it.
    #[test]
    fn pre_consolidation_cookie_still_decrypts() {
        let k = SessionKey::from_bytes([9u8; 32]);
        let cookie = "QWEAz_e6WSYG7M51wnp2gEnn7HyUstcAAqUQzdV5btDNnO3KsaM_09UVtpQSjXWGxNK-pz_hXWH9r9lwC98ZwHZjMUg";
        let back: CompatBlob = decrypt(&k, cookie).unwrap();
        assert_eq!(back.v, "ws2-aead-compat");
    }
}
