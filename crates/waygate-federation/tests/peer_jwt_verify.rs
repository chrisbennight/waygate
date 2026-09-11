//! Integration tests for `PeerJwtValidator`. Signs JWTs
//! with a real Ed25519 keypair, populates the in-memory peer
//! JWKS cache with the matching
//! public key, and exercises the validator end-to-end —
//! happy path, audience mismatch, expired, issuer-unknown,
//! kid-unknown, signature-tampered, multi-tenant collision.
//!
//! No mocking: jsonwebtoken's encode + decode actually
//! verify the signature. The cache here is the real
//! `InMemoryPeerJwksCache` (not a test double), so the
//! `SharedPeerJwksCache` trait surface is exercised the same
//! way the production wiring uses it.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, OctetKeyPairParameters,
    OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::Rng;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_federation::jwks::{CachedJwks, InMemoryPeerJwksCache, SharedPeerJwksCache};
use waygate_federation::peer_jwt::PeerJwtValidator;
use waygate_federation::TrustTier;
use waygate_oidc::header_validator::HeaderValidator;
use waygate_oidc::validator::ValidationError;
use waygate_oidc::AuthMethod;

const AUDIENCE: &str = "https://gw.example/";
const ISSUER_A: &str = "https://peer-a.example/";
const ISSUER_B: &str = "https://peer-b.example/";
const KID_A: &str = "peer-a-key-1";
const KID_B: &str = "peer-b-key-1";

#[derive(Serialize)]
struct TestClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

struct PeerKeys {
    signing: SigningKey,
    jwk: Jwk,
}

fn make_peer_keys(kid: &str) -> PeerKeys {
    // `rand::rng()` returns the thread-local CSPRNG, OS-seeded.
    // Matches the pattern in `crates/waygate-apikeys/src/token.rs`.
    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    let signing = SigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
    // Ed25519 (Octet Key Pair, OKP) JWK form: `crv: Ed25519`,
    // `x: <base64url of 32-byte public key>`. JOSE's RFC 8037
    // section 2 spells this out.
    let x = URL_SAFE_NO_PAD.encode(verifying.to_bytes());
    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: Some(kid.to_owned()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: jsonwebtoken::jwk::EllipticCurve::Ed25519,
            x,
        }),
    };
    PeerKeys { signing, jwk }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_token(keys: &PeerKeys, kid: &str, claims: &TestClaims<'_>) -> String {
    let mut h = Header::new(Algorithm::EdDSA);
    h.kid = Some(kid.to_owned());
    // jsonwebtoken needs the Ed25519 private key in PKCS8
    // DER form (or PEM); the `ed25519_dalek::SigningKey`
    // implements `EncodePrivateKey` from `pkcs8` to give us
    // either. Encode once per token; ed25519 keypair gen is
    // cheap, so reusing the SigningKey across tokens is
    // fine.
    let pkcs8 = keys
        .signing
        .to_pkcs8_der()
        .expect("pkcs8 encode")
        .to_bytes();
    let key = EncodingKey::from_ed_der(&pkcs8);
    encode(&h, &claims, &key).expect("jwt encode")
}

fn cache_with(peer_id: Uuid, tenant: &str, issuer: &str, jwk: Jwk) -> CachedJwks {
    CachedJwks {
        peer_id,
        tenant_id: tenant.to_owned(),
        issuer: issuer.to_owned(),
        trust_tier: TrustTier::Full,
        keys: JwkSet { keys: vec![jwk] },
        fetched_at: OffsetDateTime::now_utc(),
    }
}

fn fresh_cache() -> (Arc<InMemoryPeerJwksCache>, SharedPeerJwksCache) {
    let arc = Arc::new(InMemoryPeerJwksCache::new());
    let shared: SharedPeerJwksCache = arc.clone();
    (arc, shared)
}

#[tokio::test]
async fn happy_path_accepts_peer_signed_token() {
    let (arc, shared) = fresh_cache();
    let keys = make_peer_keys(KID_A);
    let entry = cache_with(Uuid::new_v4(), "tenant-a", ISSUER_A, keys.jwk.clone());
    arc.upsert(entry);

    let now = now();
    let token = sign_token(
        &keys,
        KID_A,
        &TestClaims {
            iss: ISSUER_A,
            sub: "alice@peer-a",
            aud: AUDIENCE,
            exp: now + 60,
            iat: now,
            scope: Some("mcp:invoke mcp:read"),
        },
    );

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let principal = v
        .validate_header(&format!("Bearer {token}"))
        .await
        .expect("happy path must accept");
    assert_eq!(principal.sub, "alice@peer-a");
    assert_eq!(principal.issuer, ISSUER_A);
    assert_eq!(principal.tenant.as_str(), "tenant-a");
    assert_eq!(principal.auth_method, AuthMethod::PeerAssertion);
    assert_eq!(
        principal.scopes,
        vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()]
    );
    // raw_token MUST be None on PeerAssertion principals so
    // the upstream pool's RFC 8693 path doesn't accidentally
    // use the peer's JWT as the outbound subject token.
    assert!(
        principal.raw_token.is_none(),
        "PeerAssertion principals must not carry raw_token (subject-token leak vector)",
    );
}

#[tokio::test]
async fn audience_mismatch_rejected() {
    let (arc, shared) = fresh_cache();
    let keys = make_peer_keys(KID_A);
    let entry = cache_with(Uuid::new_v4(), "tenant-a", ISSUER_A, keys.jwk.clone());
    arc.upsert(entry);

    let now = now();
    let token = sign_token(
        &keys,
        KID_A,
        &TestClaims {
            iss: ISSUER_A,
            sub: "alice",
            aud: "https://other-gw.example/",
            exp: now + 60,
            iat: now,
            scope: None,
        },
    );

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let err = v
        .validate_header(&format!("Bearer {token}"))
        .await
        .expect_err("audience mismatch must reject");
    assert!(
        matches!(err, ValidationError::Jwt(_)),
        "expected Jwt class, got {err:?}",
    );
    assert!(err.is_client_error());
}

#[tokio::test]
async fn expired_token_rejected() {
    let (arc, shared) = fresh_cache();
    let keys = make_peer_keys(KID_A);
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-a",
        ISSUER_A,
        keys.jwk.clone(),
    ));

    let now = now();
    let token = sign_token(
        &keys,
        KID_A,
        &TestClaims {
            iss: ISSUER_A,
            sub: "alice",
            aud: AUDIENCE,
            // 5 minutes past validator's 30s leeway.
            exp: now - 300,
            iat: now - 600,
            scope: None,
        },
    );

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let err = v
        .validate_header(&format!("Bearer {token}"))
        .await
        .expect_err("expired must reject");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

#[tokio::test]
async fn unknown_issuer_falls_through_as_client_error() {
    let (arc, shared) = fresh_cache();
    // Cache has ONLY peer-a, but the token claims peer-b.
    let keys_a = make_peer_keys(KID_A);
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-a",
        ISSUER_A,
        keys_a.jwk.clone(),
    ));
    // Sign with peer-a's keys to make a syntactically valid
    // JWT; we want the issuer mismatch to be the rejection
    // signal, not a signature failure.
    let now = now();
    let token = sign_token(
        &keys_a,
        KID_A,
        &TestClaims {
            iss: ISSUER_B,
            sub: "bob",
            aud: AUDIENCE,
            exp: now + 60,
            iat: now,
            scope: None,
        },
    );

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let err = v
        .validate_header(&format!("Bearer {token}"))
        .await
        .expect_err("unknown issuer must reject");
    // Must be a client error so the bearer-middleware chain
    // falls through to the OAuth / API-key validator.
    assert!(
        err.is_client_error(),
        "unknown-issuer rejection must fall through to next validator (is_client_error true)",
    );
}

#[tokio::test]
async fn unknown_kid_falls_through_as_client_error() {
    let (arc, shared) = fresh_cache();
    let keys = make_peer_keys(KID_A);
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-a",
        ISSUER_A,
        keys.jwk.clone(),
    ));

    let now = now();
    // Sign with peer-a's key but the header's kid points at a
    // key the cache doesn't know — exercises the "iss matched
    // but no kid in the JWKS" branch.
    let token = sign_token(
        &keys,
        "rotated-kid-not-yet-published",
        &TestClaims {
            iss: ISSUER_A,
            sub: "alice",
            aud: AUDIENCE,
            exp: now + 60,
            iat: now,
            scope: None,
        },
    );

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let err = v
        .validate_header(&format!("Bearer {token}"))
        .await
        .expect_err("unknown kid must reject");
    assert!(err.is_client_error());
}

#[tokio::test]
async fn tampered_signature_rejected() {
    let (arc, shared) = fresh_cache();
    let keys = make_peer_keys(KID_A);
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-a",
        ISSUER_A,
        keys.jwk.clone(),
    ));

    let now = now();
    let token = sign_token(
        &keys,
        KID_A,
        &TestClaims {
            iss: ISSUER_A,
            sub: "alice",
            aud: AUDIENCE,
            exp: now + 60,
            iat: now,
            scope: None,
        },
    );

    // Flip the last character of the signature segment.
    let mut parts: Vec<&str> = token.split('.').collect();
    let tampered_sig = format!(
        "{}{}",
        &parts[2][..parts[2].len() - 1],
        if parts[2].ends_with('A') { "B" } else { "A" },
    );
    parts[2] = tampered_sig.as_str();
    let tampered = parts.join(".");

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let err = v
        .validate_header(&format!("Bearer {tampered}"))
        .await
        .expect_err("tampered sig must reject");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

#[tokio::test]
async fn same_issuer_two_tenants_same_key_refused_as_ambiguous() {
    // When the SAME key is registered for the SAME issuer in
    // two tenants (operator A and operator B both federate
    // with the same peer), a
    // JWT signed by that key verifies against BOTH cache
    // entries. Pre-fix the validator returned whichever
    // HashMap-order candidate it iterated first, leaking the
    // choice into `principal.tenant`. Fail-closed: refuse the
    // token rather than mint a non-deterministic principal —
    // operators have to pick a single tenant registration to
    // make federation calls work.
    let (arc, shared) = fresh_cache();
    let keys = make_peer_keys(KID_A);

    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-x",
        ISSUER_A,
        keys.jwk.clone(),
    ));
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-y",
        ISSUER_A,
        keys.jwk.clone(),
    ));

    let now = now();
    let token = sign_token(
        &keys,
        KID_A,
        &TestClaims {
            iss: ISSUER_A,
            sub: "alice",
            aud: AUDIENCE,
            exp: now + 60,
            iat: now,
            scope: None,
        },
    );

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let err = v
        .validate_header(&format!("Bearer {token}"))
        .await
        .expect_err("dual-tenant same-key must be refused as ambiguous");
    // The internal Ambiguous variant maps to a JWT InvalidToken
    // client error so the bearer middleware reports the OAuth-
    // shaped error.
    assert!(
        matches!(err, ValidationError::Jwt(_)),
        "expected Jwt class for ambiguous attribution, got {err:?}",
    );
    assert!(err.is_client_error());
}

#[tokio::test]
async fn two_peers_different_issuers_each_validate_against_their_own_keys() {
    // Confidence test: with two distinct (peer, key, issuer)
    // entries in the cache, only the matching peer's keys
    // can validate that peer's tokens. A token signed by
    // peer-a but claiming iss=peer-b must NOT validate even
    // though peer-b's entry is present.
    let (arc, shared) = fresh_cache();
    let keys_a = make_peer_keys(KID_A);
    let keys_b = make_peer_keys(KID_B);
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-a",
        ISSUER_A,
        keys_a.jwk.clone(),
    ));
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-b",
        ISSUER_B,
        keys_b.jwk.clone(),
    ));

    let now = now();
    // peer-a-signed token, but claims peer-b's iss + kid.
    // Cache will find peer-b's JWKS; signature check against
    // it must fail.
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KID_B.to_owned());
    let pkcs8 = keys_a
        .signing
        .to_pkcs8_der()
        .expect("pkcs8 encode")
        .to_bytes();
    let key = EncodingKey::from_ed_der(&pkcs8);
    let claims = TestClaims {
        iss: ISSUER_B,
        sub: "alice",
        aud: AUDIENCE,
        exp: now + 60,
        iat: now,
        scope: None,
    };
    let cross_signed = encode(&header, &claims, &key).expect("jwt encode");

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let err = v
        .validate_header(&format!("Bearer {cross_signed}"))
        .await
        .expect_err("cross-key-signed token must reject");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

/// A peer can claim ANY scope on their JWT, but the
/// validator MUST strip `mcp:admin*` and `scim:write*`
/// before they reach the local Principal. The admin scope
/// gate has a belt-and-suspenders deny in
/// `waygate_admin::scope::peer_assertion_permits`; this test
/// pins the *validator-layer* strip.
#[tokio::test]
async fn peer_assertion_strips_admin_and_scim_write_scopes() {
    let (arc, shared) = fresh_cache();
    let keys = make_peer_keys(KID_A);
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-a",
        ISSUER_A,
        keys.jwk.clone(),
    ));

    let now = now();
    let token = sign_token(
        &keys,
        KID_A,
        &TestClaims {
            iss: ISSUER_A,
            sub: "alice@peer-a",
            aud: AUDIENCE,
            exp: now + 60,
            iat: now,
            // A misbehaving / compromised peer claims admin
            // and scim:write. The validator must strip them
            // unconditionally — federated peers are NOT
            // operators of this gateway.
            scope: Some("mcp:invoke mcp:admin mcp:read scim:write scim:read"),
        },
    );

    let v = PeerJwtValidator::new(shared, AUDIENCE);
    let principal = v
        .validate_header(&format!("Bearer {token}"))
        .await
        .expect("happy path must accept");

    assert!(
        principal.scopes.contains(&"mcp:invoke".to_owned()),
        "user-level scopes pass through: {:?}",
        principal.scopes,
    );
    assert!(
        principal.scopes.contains(&"mcp:read".to_owned()),
        "user-level scopes pass through: {:?}",
        principal.scopes,
    );
    assert!(
        principal.scopes.contains(&"scim:read".to_owned()),
        "scim:read is allowed (directory lookup only): {:?}",
        principal.scopes,
    );
    assert!(
        !principal.scopes.contains(&"mcp:admin".to_owned()),
        "mcp:admin must be stripped: {:?}",
        principal.scopes,
    );
    assert!(
        !principal.scopes.contains(&"scim:write".to_owned()),
        "scim:write must be stripped: {:?}",
        principal.scopes,
    );
}

/// Same-issuer two-tenant where both records advertise THE
/// SAME kid but with DIFFERENT keys. The validator must not
/// short-circuit on
/// the first candidate's failed signature check — it must
/// keep iterating and accept when the second candidate's key
/// verifies. Pre-fix the loop returned after the first
/// candidate that owned the kid, making the validator's
/// behaviour depend on HashMap iteration order (which is
/// non-deterministic across runs).
#[tokio::test]
async fn same_issuer_two_tenants_different_keys_under_same_kid_still_accept() {
    let (arc, shared) = fresh_cache();
    let stale_keys = make_peer_keys(KID_A);
    let live_keys = make_peer_keys(KID_A);
    // The "stale" key collides on kid but isn't the signer.
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-stale",
        ISSUER_A,
        stale_keys.jwk.clone(),
    ));
    arc.upsert(cache_with(
        Uuid::new_v4(),
        "tenant-live",
        ISSUER_A,
        live_keys.jwk.clone(),
    ));

    let now = now();
    // Token signed by the LIVE key. Whichever candidate the
    // validator tries first, it must keep going until it
    // finds the matching key. Repeat the assertion a few
    // times to make a HashMap-order regression flaky-fail
    // rather than always-pass.
    for _ in 0..16 {
        let token = sign_token(
            &live_keys,
            KID_A,
            &TestClaims {
                iss: ISSUER_A,
                sub: "alice",
                aud: AUDIENCE,
                exp: now + 60,
                iat: now,
                scope: None,
            },
        );
        let v = PeerJwtValidator::new(shared.clone(), AUDIENCE);
        let principal = v
            .validate_header(&format!("Bearer {token}"))
            .await
            .expect("validator must iterate past the stale candidate's failed verify");
        assert_eq!(
            principal.tenant.as_str(),
            "tenant-live",
            "must attribute under the tenant whose key actually verified",
        );
    }
}
