//! End-to-end pin that an internal preloaded BearerValidator
//! fed `keyring.jwks()` validates access tokens signed under
//! ANY kid in the rotation set — not just the active one.
//!
//! The unit tests in `identity_jwt::tests` prove the
//! keyring publishes both kids in JWKS, but don't prove
//! the gateway's own BearerValidator (the one fed into the
//! AS-mode middleware in `build_bearer_layer`) verifies
//! tokens against the aggregated set. Without this pin, a
//! future refactor could quietly route the validator back
//! to the active issuer's `jwks()` (single-key) and break
//! rotation again with no test failure.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;

use jsonwebtoken::jwk::Jwk;
use waygate_oidc::{
    pub_jwk_from_ed25519_pkcs8_pem, BearerValidator, IdentityIssuer, IdentityKeyring, JwksProvider,
    SharedIdentityIssuer,
};

fn issuer(seed: u8, kid: &str, gateway_url: &str) -> SharedIdentityIssuer {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            kid,
            gateway_url,
            "gateway-main",
            Duration::from_secs(300),
        )
        .expect("issuer"),
    )
}

/// Derive the public JWK for a "verify-only" kid without
/// loading the private signing material. Mirrors the helper
/// production uses for non-active kids in the rotation
/// keyring.
fn verify_only_jwk(seed: u8, kid: &str) -> Jwk {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    pub_jwk_from_ed25519_pkcs8_pem(&pem, kid).expect("pub jwk")
}

#[tokio::test]
async fn preloaded_validator_accepts_tokens_from_every_kid_in_keyring() {
    let gateway_url = "https://mcp.example.test";
    let audience = gateway_url;

    // v1 needs to be a full IdentityIssuer in the test
    // because we mint a pre-rotation token with it. The
    // keyring receives v2 as the (full) active issuer and
    // v1 as a VERIFY-ONLY JWK — same secret-narrowing
    // shape production uses for non-active kids.
    let v1 = issuer(11, "v1", gateway_url);
    let v2 = issuer(22, "v2", gateway_url);
    let v1_jwk = verify_only_jwk(11, "v1");
    let keyring = IdentityKeyring::new(v2.clone(), vec![v1_jwk]).expect("keyring");

    // Mirror `build_bearer_layer`'s preloaded JwksProvider path:
    // serialize keyring.jwks() (NOT issuer.jwks()) and feed it
    // to BearerValidator. Feeding `issuer.jwks()` (single-key)
    // here is the regression this pins: the validator 401'd
    // unexpired pre-rotation tokens.
    let jwks_json = serde_json::to_string(&keyring.jwks()).unwrap();
    let jwks = Arc::new(JwksProvider::from_preloaded(gateway_url.to_owned(), &jwks_json).unwrap());
    let validator = BearerValidator::new(jwks, gateway_url.to_owned(), audience.to_owned());

    // Token signed under the active (v2) key must verify.
    let active_token = v2
        .mint_access_token(
            "alice",
            Some("alice@example.test"),
            &["mcp-users".into()],
            audience,
            &["mcp:invoke".into(), "mcp:read".into()],
            Some("test-client"),
            None,
            Duration::from_secs(60),
        )
        .unwrap();
    validator
        .validate(&active_token)
        .await
        .expect("active-key token must validate");

    // Token signed under the previous (v1) key — i.e. one
    // minted before the operator flipped ACTIVE — must ALSO
    // verify, because v1 is still in the keyring's JWKS until
    // the operator drops it in step 3 of the rotation playbook.
    let prerotation_token = v1
        .mint_access_token(
            "alice",
            Some("alice@example.test"),
            &["mcp-users".into()],
            audience,
            &["mcp:invoke".into(), "mcp:read".into()],
            Some("test-client"),
            None,
            Duration::from_secs(60),
        )
        .unwrap();
    validator.validate(&prerotation_token).await.expect(
        "pre-rotation (v1) token must still validate against the post-rotation \
         keyring — that's the whole point of keyring rotation",
    );
}

#[tokio::test]
async fn preloaded_validator_rejects_token_from_dropped_kid() {
    // Step 3 of the rotation playbook: after every old-key
    // token has expired — `max(identity_ttl,
    // access_token_ttl)` since the active flip, NOT just
    // identity_ttl (the same key signs both the short
    // per-upstream JWT and the hour-long AS access
    // token) — drop the old kid from
    // the KEYS env. A token still signed under that
    // dropped kid must now fail validation — pin that the
    // keyring excludes the dropped kid from JWKS, so the
    // validator doesn't trust it any more.
    let gateway_url = "https://mcp.example.test";
    let v1 = issuer(11, "v1", gateway_url);
    let v2 = issuer(22, "v2", gateway_url);

    // Pretend v1 was dropped: keyring carries only v2.
    let keyring = IdentityKeyring::new(v2.clone(), vec![]).expect("keyring");
    let jwks_json = serde_json::to_string(&keyring.jwks()).unwrap();
    let jwks = Arc::new(JwksProvider::from_preloaded(gateway_url.to_owned(), &jwks_json).unwrap());
    let validator = BearerValidator::new(jwks, gateway_url.to_owned(), gateway_url.to_owned());

    let v1_token = v1
        .mint_access_token(
            "alice",
            None,
            &[],
            gateway_url,
            &["mcp:invoke".into()],
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap();
    validator
        .validate(&v1_token)
        .await
        .expect_err("dropped-kid token must fail validation");
}
