//! Confidential-client authentication for the EMA ID-JAG redeem path.
//!
//! Per draft-ietf-oauth-identity-assertion-authz-grant §4.4 / §9.1 the client
//! redeeming an ID-JAG MUST authenticate with its registered credential
//! (confidential clients only). This module supports the two methods the
//! gateway accepts:
//!
//! * `client_secret` — HTTP Basic or POST body, verified against an argon2id
//!   hash in the [`crate::clients`] registry.
//! * `private_key_jwt` — an RFC 7523 §3 `client_assertion` JWT signed by a key
//!   in the client's registered JWKS.
//!
//! It returns the *authenticated* `client_id`, which the redeem handler then
//! requires to equal the ID-JAG's `client_id` claim (the draft §4.4.1 MUST).

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use thiserror::Error;

use crate::clients::ConfidentialClientStore;

/// RFC 7521 client-assertion type for private_key_jwt.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Asymmetric algorithms accepted for a private_key_jwt `client_assertion`.
/// HS* (symmetric) is deliberately excluded: accepting it would let a leaked
/// *public* JWK be used to forge an assertion (alg-confusion).
const ASSERTION_ALGS: [Algorithm; 6] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

#[derive(Debug, Error)]
pub enum ClientAuthError {
    /// No usable client credential was presented.
    #[error("client authentication required")]
    Missing,
    /// The presented client_id is not a registered confidential client.
    #[error("unknown confidential client")]
    UnknownClient,
    /// A client_secret did not verify.
    #[error("invalid client secret")]
    InvalidSecret,
    /// A private_key_jwt client_assertion failed verification.
    #[error("invalid client assertion")]
    InvalidAssertion,
    /// The client exists but doesn't have a credential of the presented kind.
    #[error("unsupported client authentication method")]
    UnsupportedMethod,
    /// Storage/infra error reaching the client registry.
    #[error("client auth store: {0}")]
    Store(String),
}

/// Credentials extracted from a token request, before verification.
#[derive(Debug)]
pub enum ClientCredentials {
    /// `client_secret` via HTTP Basic or POST body.
    Secret { client_id: String, secret: String },
    /// `private_key_jwt`: an RFC 7523 `client_assertion` JWT.
    PrivateKeyJwt { assertion: String },
}

impl ClientCredentials {
    /// Extract client credentials from a request's `Authorization` header and
    /// the token-endpoint form fields. Precedence: HTTP Basic, then
    /// private_key_jwt (`client_assertion`), then POST `client_secret`. Returns
    /// `None` when no credential is present.
    pub fn extract(
        authorization: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        client_assertion: Option<&str>,
        client_assertion_type: Option<&str>,
    ) -> Option<Self> {
        if let Some((id, secret)) = authorization.and_then(parse_basic) {
            return Some(ClientCredentials::Secret {
                client_id: id,
                secret,
            });
        }
        if client_assertion_type == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) {
            if let Some(assertion) = client_assertion {
                return Some(ClientCredentials::PrivateKeyJwt {
                    assertion: assertion.to_owned(),
                });
            }
        }
        if let (Some(id), Some(secret)) = (client_id, client_secret) {
            return Some(ClientCredentials::Secret {
                client_id: id.to_owned(),
                secret: secret.to_owned(),
            });
        }
        None
    }
}

/// Claims read from a private_key_jwt `client_assertion`. `aud`/`exp` are
/// validated by [`jsonwebtoken::Validation`]; `iss`/`sub` MUST both equal the
/// client_id (RFC 7523 §3).
#[derive(Debug, Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
}

/// Authenticate the redeeming client. Returns the authenticated `client_id` on
/// success. `expected_audiences` are the values a private_key_jwt assertion's
/// `aud` may carry (the gateway issuer and/or its token-endpoint URL).
pub async fn authenticate_client(
    store: &dyn ConfidentialClientStore,
    creds: &ClientCredentials,
    expected_audiences: &[&str],
) -> Result<String, ClientAuthError> {
    match creds {
        ClientCredentials::Secret { client_id, secret } => {
            let client = store
                .get(client_id)
                .await
                .map_err(|e| ClientAuthError::Store(e.to_string()))?
                .ok_or(ClientAuthError::UnknownClient)?;
            let hash = client
                .secret_hash
                .as_deref()
                .ok_or(ClientAuthError::UnsupportedMethod)?;
            verify_secret(secret, hash)?;
            Ok(client_id.clone())
        }
        ClientCredentials::PrivateKeyJwt { assertion } => {
            // Read `iss` from the UNVERIFIED payload only to discover which
            // client's JWKS to verify against. It becomes trustworthy only
            // after the signature check below.
            let claimed = claimed_issuer(assertion)?;
            let client = store
                .get(&claimed)
                .await
                .map_err(|e| ClientAuthError::Store(e.to_string()))?
                .ok_or(ClientAuthError::UnknownClient)?;
            let jwks = client
                .jwks
                .as_ref()
                .ok_or(ClientAuthError::UnsupportedMethod)?;
            verify_private_key_jwt(assertion, jwks, &claimed, expected_audiences)?;
            Ok(claimed)
        }
    }
}

fn verify_secret(secret: &str, hash: &str) -> Result<(), ClientAuthError> {
    let parsed = PasswordHash::new(hash).map_err(|_| ClientAuthError::InvalidSecret)?;
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .map_err(|_| ClientAuthError::InvalidSecret)
}

/// Decode (WITHOUT verifying) the assertion's `iss` claim to discover which
/// client's JWKS to verify against. Untrusted until the signature passes.
fn claimed_issuer(assertion: &str) -> Result<String, ClientAuthError> {
    let payload_b64 = assertion
        .split('.')
        .nth(1)
        .ok_or(ClientAuthError::InvalidAssertion)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| ClientAuthError::InvalidAssertion)?;
    let claims: AssertionClaims =
        serde_json::from_slice(&payload).map_err(|_| ClientAuthError::InvalidAssertion)?;
    Ok(claims.iss)
}

fn verify_private_key_jwt(
    assertion: &str,
    jwks_json: &serde_json::Value,
    client_id: &str,
    expected_audiences: &[&str],
) -> Result<(), ClientAuthError> {
    let header =
        jsonwebtoken::decode_header(assertion).map_err(|_| ClientAuthError::InvalidAssertion)?;
    // Reject symmetric algs before touching keys (alg-confusion guard).
    if !ASSERTION_ALGS.contains(&header.alg) {
        return Err(ClientAuthError::InvalidAssertion);
    }
    let jwks: JwkSet =
        serde_json::from_value(jwks_json.clone()).map_err(|_| ClientAuthError::InvalidAssertion)?;
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid),
        None => jwks.keys.first(),
    }
    .ok_or(ClientAuthError::InvalidAssertion)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| ClientAuthError::InvalidAssertion)?;

    let mut v = Validation::new(header.alg);
    v.set_audience(expected_audiences);
    v.set_issuer(&[client_id]); // RFC 7523 §3: iss == client_id
    v.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
    v.leeway = 30;
    let data = jsonwebtoken::decode::<AssertionClaims>(assertion, &key, &v)
        .map_err(|_| ClientAuthError::InvalidAssertion)?;
    // RFC 7523 §3: sub == client_id too (iss is already enforced by set_issuer).
    if data.claims.sub != client_id || data.claims.iss != client_id {
        return Err(ClientAuthError::InvalidAssertion);
    }
    Ok(())
}

/// Parse `Authorization: Basic …` per RFC 6749 §2.3.1 `client_secret_basic`.
///
/// The header is `base64( form-urlencode(client_id) ":" form-urlencode(secret) )`.
/// Form-encoding escapes any `:` in the client_id (URL-shaped client_ids like
/// `https://app/c.json` become `https%3A%2F%2Fapp%2Fc.json`), so the first
/// literal `:` is always the separator. We split there, then **form-decode**
/// each half — without the decode, a URL client_id would either split wrong
/// (raw `https:`) or stay percent-encoded and never match its registration.
fn parse_basic(header: &str) -> Option<(String, String)> {
    let b64 = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded = BASE64_STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((form_component_decode(id), form_component_decode(secret)))
}

/// `application/x-www-form-urlencoded` decode of a single component (`%XX`
/// escapes, `+`→space) — the encoding RFC 6749 §2.3.1 applies to each Basic
/// credential half.
fn form_component_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("a={s}").as_bytes())
        .find(|(k, _)| k == "a")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use time::OffsetDateTime;

    const CLIENT: &str = "https://app.example/client.json";
    const AUD: &str = "https://mcp.test";

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn parse_basic_decodes_id_and_secret() {
        let header = format!("Basic {}", BASE64_STANDARD.encode("client-x:s3cret"));
        assert_eq!(
            parse_basic(&header),
            Some(("client-x".to_owned(), "s3cret".to_owned())),
        );
        assert_eq!(parse_basic("Bearer xyz"), None);
    }

    #[test]
    fn parse_basic_form_decodes_url_client_id() {
        // RFC 6749 §2.3.1: each half is form-urlencoded before base64, so a
        // URL-shaped client_id's `:` and `/` arrive escaped. parse_basic must
        // split at the (single, separator) `:` and form-decode both halves.
        let raw = "https%3A%2F%2Fapp.example%2Fclient.json:s3cret-%2B-value";
        let header = format!("Basic {}", BASE64_STANDARD.encode(raw));
        assert_eq!(
            parse_basic(&header),
            Some((
                "https://app.example/client.json".to_owned(),
                "s3cret-+-value".to_owned(),
            )),
        );
    }

    #[test]
    fn extract_precedence_basic_then_assertion_then_post() {
        // Basic wins over everything.
        let basic = format!("Basic {}", BASE64_STANDARD.encode("id:sec"));
        let c = ClientCredentials::extract(
            Some(&basic),
            Some("other"),
            Some("p"),
            Some("a"),
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
        )
        .unwrap();
        assert!(matches!(c, ClientCredentials::Secret { client_id, .. } if client_id == "id"));

        // No Basic: assertion wins over POST secret.
        let c = ClientCredentials::extract(
            None,
            Some("id"),
            Some("p"),
            Some("the-assertion"),
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
        )
        .unwrap();
        assert!(
            matches!(c, ClientCredentials::PrivateKeyJwt { assertion } if assertion == "the-assertion")
        );

        // No Basic, no assertion: POST client_secret.
        let c = ClientCredentials::extract(None, Some("id"), Some("p"), None, None).unwrap();
        assert!(
            matches!(c, ClientCredentials::Secret { client_id, secret } if client_id == "id" && secret == "p")
        );

        // Nothing presented.
        assert!(ClientCredentials::extract(None, None, None, None, None).is_none());
    }

    // ---- private_key_jwt verification ----

    /// (jwks_json, encoding_key) for an Ed25519 client key published under `kid`.
    fn client_key(kid: &str) -> (serde_json::Value, EncodingKey) {
        let sk = SigningKey::from_bytes(&[19u8; 32]);
        let pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
        let enc = EncodingKey::from_ed_pem(pem.as_bytes()).unwrap();
        let jwk = waygate_oidc::pub_jwk_from_ed25519_pkcs8_pem(&pem, kid).unwrap();
        let jwks = json!({ "keys": [jwk] });
        (jwks, enc)
    }

    fn signed_assertion(enc: &EncodingKey, kid: &str, claims: serde_json::Value) -> String {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some(kid.to_owned());
        encode(&h, &claims, enc).unwrap()
    }

    #[test]
    fn private_key_jwt_accepts_valid_assertion() {
        let (jwks, enc) = client_key("ck1");
        let a = signed_assertion(
            &enc,
            "ck1",
            json!({"iss": CLIENT, "sub": CLIENT, "aud": AUD, "exp": now() + 300, "iat": now()}),
        );
        verify_private_key_jwt(&a, &jwks, CLIENT, &[AUD]).expect("valid assertion verifies");
    }

    #[test]
    fn private_key_jwt_rejects_symmetric_alg() {
        // HS256 assertion — must be refused at the alg guard before key lookup.
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some("ck1".into());
        let a = encode(
            &h,
            &json!({"iss": CLIENT, "sub": CLIENT, "aud": AUD, "exp": now() + 300}),
            &EncodingKey::from_secret(b"shared"),
        )
        .unwrap();
        let (jwks, _) = client_key("ck1");
        assert!(matches!(
            verify_private_key_jwt(&a, &jwks, CLIENT, &[AUD]),
            Err(ClientAuthError::InvalidAssertion)
        ));
    }

    #[test]
    fn private_key_jwt_rejects_wrong_audience() {
        let (jwks, enc) = client_key("ck1");
        let a = signed_assertion(
            &enc,
            "ck1",
            json!({"iss": CLIENT, "sub": CLIENT, "aud": "https://evil.example", "exp": now() + 300}),
        );
        assert!(matches!(
            verify_private_key_jwt(&a, &jwks, CLIENT, &[AUD]),
            Err(ClientAuthError::InvalidAssertion)
        ));
    }

    #[test]
    fn private_key_jwt_rejects_sub_client_mismatch() {
        // iss == client_id (so it routes to this client's key) but sub names a
        // different client — RFC 7523 §3 requires both to equal the client.
        let (jwks, enc) = client_key("ck1");
        let a = signed_assertion(
            &enc,
            "ck1",
            json!({"iss": CLIENT, "sub": "https://other.example/c.json", "aud": AUD, "exp": now() + 300}),
        );
        assert!(matches!(
            verify_private_key_jwt(&a, &jwks, CLIENT, &[AUD]),
            Err(ClientAuthError::InvalidAssertion)
        ));
    }

    #[test]
    fn private_key_jwt_rejects_foreign_key() {
        // Assertion signed by a DIFFERENT key than the one in the client's jwks.
        let (jwks, _good) = client_key("ck1");
        let other = SigningKey::from_bytes(&[20u8; 32]);
        let other_pem = other.to_pkcs8_pem(LineEnding::LF).unwrap();
        let other_enc = EncodingKey::from_ed_pem(other_pem.as_bytes()).unwrap();
        let a = signed_assertion(
            &other_enc,
            "ck1",
            json!({"iss": CLIENT, "sub": CLIENT, "aud": AUD, "exp": now() + 300}),
        );
        assert!(matches!(
            verify_private_key_jwt(&a, &jwks, CLIENT, &[AUD]),
            Err(ClientAuthError::InvalidAssertion)
        ));
    }
}
