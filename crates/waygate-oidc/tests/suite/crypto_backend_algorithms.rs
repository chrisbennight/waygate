//! Crypto-backend contract: the `jsonwebtoken` backend selected in the workspace
//! `Cargo.toml` (`rust_crypto`) must be able to SIGN and VERIFY a token for every
//! algorithm the production [`BearerValidator`] accepts.
//!
//! Regression guard for the 2026-06-10 production boot deadlock: a bump of
//! jsonwebtoken 9 -> 10 selected the native `aws_lc_rs` backend, whose first
//! JWT crypto operation wedged the gateway at startup (before it bound :8080)
//! under the hardened distroless runtime. These tests exercise the same
//! sign/verify paths the gateway runs at boot, so a backend that cannot perform
//! one of the gateway's algorithms — or that panics/hangs on first use in a way
//! reproducible on the host — fails here instead of in prod. A deploy-time
//! boot-smoke under the hardened distroless runtime (tracked separately) covers
//! the environment-specific dimension a host unit test cannot.
//!
//! `ALGS_UNDER_TEST` drives both the round-trips and a coverage assertion against
//! `BearerValidator::algorithms()`, so adding an algorithm to the production
//! validator without a real round-trip here fails `every_validator_algorithm_is_covered`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use waygate_oidc::{BearerValidator, IdentityIssuer, JwksProvider};

const ISSUER: &str = "https://crypto-backend.test";
const AUDIENCE: &str = "https://crypto-backend.test/mcp";

/// Every algorithm the production `BearerValidator` accepts. Kept in lock-step
/// with `BearerValidator::algorithms()` by `every_validator_algorithm_is_covered`.
const ALGS_UNDER_TEST: &[Algorithm] = &[
    Algorithm::EdDSA, // gateway's own Ed25519 signing key (the op that deadlocked)
    Algorithm::RS256, // OIDC IdPs (Authentik)
    Algorithm::RS512, // OIDC IdPs / peers
    Algorithm::ES256, // OIDC IdPs / peers
];

// RSA keypair fixture (shared with bearer.rs): the private half signs, jwks.json
// carries the public modulus/exponent. One RSA key covers both RS256 and RS512.
const RSA_PRIVATE_PEM: &[u8] = include_bytes!("../fixtures/private.pem");
const RSA_JWKS_JSON: &str = include_str!("../fixtures/jwks.json");

// P-256 keypair fixture (this test): PKCS#8 private + SPKI public, generated once
// via `openssl ecparam -name prime256v1`. Covers ES256.
const EC_PRIVATE_PEM: &[u8] = include_bytes!("../fixtures/ec_p256_private.pem");
const EC_PUBLIC_PEM: &[u8] = include_bytes!("../fixtures/ec_p256_public.pem");

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A signing+verifying keypair of the family appropriate for `alg`. Panics for an
/// algorithm with no key wired so that extending `ALGS_UNDER_TEST` without
/// providing a real key is a hard failure, not a silent skip.
fn keys_for(alg: Algorithm) -> (EncodingKey, DecodingKey) {
    match alg {
        Algorithm::EdDSA => eddsa_keys(),
        Algorithm::RS256 | Algorithm::RS512 => (
            EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).expect("rsa encoding key"),
            rsa_decoding_key(),
        ),
        Algorithm::ES256 => (
            EncodingKey::from_ec_pem(EC_PRIVATE_PEM).expect("ec encoding key"),
            DecodingKey::from_ec_pem(EC_PUBLIC_PEM).expect("ec decoding key"),
        ),
        other => panic!(
            "no test key wired for {other:?}; wire one in keys_for() when adding it to ALGS_UNDER_TEST"
        ),
    }
}

fn rsa_decoding_key() -> DecodingKey {
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_str(RSA_JWKS_JSON).expect("rsa jwks");
    DecodingKey::from_jwk(&set.keys[0]).expect("rsa decoding key")
}

/// Ed25519 keypair: sign via `EncodingKey::from_ed_pem`, verify via the public
/// JWK the gateway's own `IdentityIssuer` publishes (so the verify side matches
/// exactly what `/jwks` serves in production).
fn eddsa_keys() -> (EncodingKey, DecodingKey) {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("ed25519 pkcs8 pem");
    let enc = EncodingKey::from_ed_pem(pem.as_bytes()).expect("ed encoding key");
    let issuer = IdentityIssuer::from_ed25519_pkcs8_pem(
        &pem,
        "test-key",
        ISSUER,
        "gw",
        Duration::from_secs(60),
    )
    .expect("issuer");
    let jwks_json = serde_json::to_string(&issuer.jwks()).expect("jwks json");
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_str(&jwks_json).expect("ed jwks");
    let dec = DecodingKey::from_jwk(&set.keys[0]).expect("ed decoding key");
    (enc, dec)
}

/// Sign with `alg`/`enc`, then verify back with `dec` under a `Validation` shaped
/// like the production bearer path (issuer + audience set, 30s leeway, narrowed to
/// the single algorithm). Returns the decoded subject so the caller can assert the
/// round-trip actually carried data through real crypto.
fn round_trip(alg: Algorithm, enc: &EncodingKey, dec: &DecodingKey) -> String {
    let claims = Claims {
        sub: "alice".into(),
        iss: ISSUER.into(),
        aud: AUDIENCE.into(),
        exp: now() + 300,
    };
    let mut header = Header::new(alg);
    header.kid = Some("test-key".into());
    let token =
        encode(&header, &claims, enc).expect("sign must succeed under the configured backend");

    let mut v = Validation::new(alg);
    v.set_issuer(&[ISSUER]);
    v.set_audience(&[AUDIENCE]);
    v.leeway = 30;
    decode::<Claims>(&token, dec, &v)
        .expect("verify must succeed under the configured backend")
        .claims
        .sub
}

/// The crux: one algorithm at a time, the configured backend performs a full
/// sign -> verify round-trip. A backend that drops support for an algorithm the
/// gateway uses (or panics on first use) fails here.
#[test]
fn backend_signs_and_verifies_every_validator_algorithm() {
    for &alg in ALGS_UNDER_TEST {
        let (enc, dec) = keys_for(alg);
        assert_eq!(
            round_trip(alg, &enc, &dec),
            "alice",
            "sign->verify round-trip failed for {alg:?} under the configured jsonwebtoken backend",
        );
    }
}

/// `ALGS_UNDER_TEST` must equal the set the production validator accepts, so a
/// future change to `BearerValidator`'s algorithm list cannot add an unproven
/// algorithm without also adding a round-trip above (and vice versa).
#[test]
fn every_validator_algorithm_is_covered() {
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, RSA_JWKS_JSON).expect("preload"));
    let validator = BearerValidator::new(jwks, ISSUER, AUDIENCE);

    let produced: BTreeSet<String> = validator
        .algorithms()
        .iter()
        .map(|a| format!("{a:?}"))
        .collect();
    let tested: BTreeSet<String> = ALGS_UNDER_TEST.iter().map(|a| format!("{a:?}")).collect();

    assert_eq!(
        produced, tested,
        "every algorithm BearerValidator accepts must have a sign/verify round-trip in \
         ALGS_UNDER_TEST (and vice versa)",
    );
}

/// End-to-end through the real production path that deadlocked: the gateway mints
/// an EdDSA access token via its `IdentityIssuer` and the resource-server
/// `BearerValidator` verifies it. If the backend cannot sign or verify EdDSA,
/// every gateway-minted token is rejected at the `/mcp` boundary.
#[tokio::test]
async fn gateway_minted_eddsa_token_validates_through_bearer_validator() {
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    let issuer = IdentityIssuer::from_ed25519_pkcs8_pem(
        &pem,
        "gw-kid",
        ISSUER,
        "gateway-main",
        Duration::from_secs(60),
    )
    .expect("issuer");

    let token = issuer
        .mint_access_token(
            "user-1",
            Some("u@test"),
            &["mcp-users".into()],
            AUDIENCE,
            &["mcp:invoke".into()],
            None,
            None,
            Duration::from_secs(3600),
        )
        .expect("mint access token");

    let jwks_json = serde_json::to_string(&issuer.jwks()).expect("jwks json");
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, &jwks_json).expect("preload jwks"));
    let principal = BearerValidator::new(jwks, ISSUER, AUDIENCE)
        .validate(&token)
        .await
        .expect("gateway-minted EdDSA token must validate end-to-end");

    assert_eq!(principal.sub, "user-1");
    assert!(principal.has_scope("mcp:invoke"));
}
