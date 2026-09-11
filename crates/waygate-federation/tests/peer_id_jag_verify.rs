//! Tier-C integration tests for `verify_peer_id_jag`. Signs ID-JAGs
//! with a real Ed25519 keypair, publishes the matching public key in the
//! in-memory peer JWKS cache, and verifies end-to-end — no mocking
//! (`jsonwebtoken` encode + decode actually check the signature).
//!
//! The load-bearing security property: the redeemed tenant comes from the
//! PEER RECORD this gateway registered, NOT from the ID-JAG's `tenant` claim —
//! a peer must not be able to pick our tenant. Multi-tenant registration of the
//! same key fails closed.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::Rng;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_federation::jwks::{CachedJwks, InMemoryPeerJwksCache, SharedPeerJwksCache};
use waygate_federation::peer_jwt::{verify_peer_id_jag, PeerIdJagError};
use waygate_federation::TrustTier;
use waygate_oidc::ID_JAG_TYP;

const OUR_ISSUER: &str = "https://gw-b.example/"; // the redeeming Resource-AS (us)
const PEER_A: &str = "https://gw-a.example/"; // the minting peer
const KID_A: &str = "peer-a-key-1";
const RESOURCE: &str = "https://gw-b.example/servers/example-observability";
const CLIENT_ID: &str = "https://cli.example/c.json";

#[derive(Serialize)]
struct IdJagTestClaims<'a> {
    jti: &'a str,
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    resource: &'a str,
    client_id: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "str::is_empty")]
    scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<&'a str>,
}

struct PeerKeys {
    signing: SigningKey,
    jwk: Jwk,
}

fn make_peer_keys(kid: &str) -> PeerKeys {
    let mut secret = [0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    let signing = SigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
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
            curve: EllipticCurve::Ed25519,
            x,
        }),
    };
    PeerKeys { signing, jwk }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Sign an ID-JAG-shaped token. `typ` controls the JOSE `typ` header so the
/// token-confusion guard can be exercised (pass `None` for a plain JWT).
fn sign(keys: &PeerKeys, kid: &str, typ: Option<&str>, claims: &IdJagTestClaims<'_>) -> String {
    let mut h = Header::new(Algorithm::EdDSA);
    h.kid = Some(kid.to_owned());
    h.typ = typ.map(str::to_owned);
    let pkcs8 = keys.signing.to_pkcs8_der().expect("pkcs8").to_bytes();
    let key = EncodingKey::from_ed_der(&pkcs8);
    encode(&h, claims, &key).expect("jwt encode")
}

fn id_jag<'a>(tenant: Option<&'a str>) -> IdJagTestClaims<'a> {
    IdJagTestClaims {
        jti: "jti-1",
        iss: PEER_A,
        sub: "alice",
        aud: OUR_ISSUER,
        resource: RESOURCE,
        client_id: CLIENT_ID,
        iat: now(),
        exp: now() + 300,
        scope: "mcp:invoke",
        tenant,
    }
}

fn cache_entry(peer_id: Uuid, tenant: &str, issuer: &str, jwk: Jwk) -> CachedJwks {
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
async fn happy_path_returns_claims_and_peer_record_tenant() {
    let keys = make_peer_keys(KID_A);
    let (cache, shared) = fresh_cache();
    let peer_id = Uuid::new_v4();
    cache.upsert(cache_entry(peer_id, "bob-llc", PEER_A, keys.jwk.clone()));

    // The ID-JAG asserts a DIFFERENT tenant than the peer is registered under.
    // The verifier must IGNORE the claim and use the peer record's tenant.
    let token = sign(
        &keys,
        KID_A,
        Some(ID_JAG_TYP),
        &id_jag(Some("attacker-tenant")),
    );

    let verified = verify_peer_id_jag(&shared, &token, OUR_ISSUER, &[PEER_A.to_owned()])
        .await
        .expect("a registered peer's well-formed ID-JAG verifies");

    assert_eq!(verified.claims.sub, "alice");
    assert_eq!(verified.claims.resource, RESOURCE);
    assert_eq!(verified.claims.client_id, CLIENT_ID);
    assert_eq!(verified.peer_id, peer_id);
    assert_eq!(
        verified.tenant.as_str(),
        "bob-llc",
        "tenant MUST come from the peer record, never the assertion's `tenant` claim",
    );
}

#[tokio::test]
async fn unregistered_issuer_is_no_peer() {
    let keys = make_peer_keys(KID_A);
    let (_cache, shared) = fresh_cache(); // empty cache → no peer for PEER_A
    let token = sign(&keys, KID_A, Some(ID_JAG_TYP), &id_jag(None));

    let err = verify_peer_id_jag(&shared, &token, OUR_ISSUER, &[PEER_A.to_owned()])
        .await
        .expect_err("an unregistered issuer is not a peer");
    assert!(matches!(err, PeerIdJagError::NoPeer { .. }), "got: {err:?}");
}

#[tokio::test]
async fn untrusted_issuer_rejected_even_if_cached() {
    // The peer is in the JWKS cache, but its issuer is NOT in trusted_issuers.
    // verify_id_jag's issuer allow-list must still reject it (defense in depth:
    // a peer must be BOTH cached AND trusted for redeem).
    let keys = make_peer_keys(KID_A);
    let (cache, shared) = fresh_cache();
    cache.upsert(cache_entry(
        Uuid::new_v4(),
        "bob-llc",
        PEER_A,
        keys.jwk.clone(),
    ));
    let token = sign(&keys, KID_A, Some(ID_JAG_TYP), &id_jag(None));

    let err = verify_peer_id_jag(
        &shared,
        &token,
        OUR_ISSUER,
        &["https://someone-else/".to_owned()],
    )
    .await
    .expect_err("issuer not in trusted_issuers must be rejected");
    assert!(matches!(err, PeerIdJagError::Verify(_)), "got: {err:?}");
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let keys = make_peer_keys(KID_A);
    let (cache, shared) = fresh_cache();
    cache.upsert(cache_entry(
        Uuid::new_v4(),
        "bob-llc",
        PEER_A,
        keys.jwk.clone(),
    ));
    let mut claims = id_jag(None);
    claims.aud = "https://not-us.example/";
    let token = sign(&keys, KID_A, Some(ID_JAG_TYP), &claims);

    let err = verify_peer_id_jag(&shared, &token, OUR_ISSUER, &[PEER_A.to_owned()])
        .await
        .expect_err("an ID-JAG audienced at another Resource-AS must be rejected");
    assert!(matches!(err, PeerIdJagError::Verify(_)), "got: {err:?}");
}

#[tokio::test]
async fn non_id_jag_typ_rejected() {
    // Token-confusion guard: a plain JWT (no `oauth-id-jag+jwt` typ) signed by
    // the peer key must NOT be redeemable as an ID-JAG.
    let keys = make_peer_keys(KID_A);
    let (cache, shared) = fresh_cache();
    cache.upsert(cache_entry(
        Uuid::new_v4(),
        "bob-llc",
        PEER_A,
        keys.jwk.clone(),
    ));
    let token = sign(&keys, KID_A, None, &id_jag(None)); // typ omitted

    let err = verify_peer_id_jag(&shared, &token, OUR_ISSUER, &[PEER_A.to_owned()])
        .await
        .expect_err("a non-ID-JAG typ must be rejected");
    assert!(matches!(err, PeerIdJagError::Verify(_)), "got: {err:?}");
}

#[tokio::test]
async fn tampered_signature_rejected() {
    // The cache holds a DIFFERENT key than the one that signed the token, so the
    // signature can't verify — no key matches → NoKey (kid differs) or Verify.
    let signer = make_peer_keys(KID_A);
    let other = make_peer_keys(KID_A); // same kid, different key material
    let (cache, shared) = fresh_cache();
    cache.upsert(cache_entry(
        Uuid::new_v4(),
        "bob-llc",
        PEER_A,
        other.jwk.clone(),
    ));
    let token = sign(&signer, KID_A, Some(ID_JAG_TYP), &id_jag(None));

    let err = verify_peer_id_jag(&shared, &token, OUR_ISSUER, &[PEER_A.to_owned()])
        .await
        .expect_err("a signature that doesn't match the cached key must be rejected");
    assert!(
        matches!(
            err,
            PeerIdJagError::Verify(_) | PeerIdJagError::NoKey { .. }
        ),
        "got: {err:?}",
    );
}

#[tokio::test]
async fn rsa_peer_key_rejected_id_jag_is_eddsa_only() {
    // ID-JAG verification is EdDSA-only (matching the gateway's own ID-JAGs,
    // which the keyring signs with Ed25519 and verify_id_jag pins to EdDSA). A
    // peer that publishes an RSA key for the kid cannot redeem an ID-JAG —
    // `peer_decoding_key` rejects the RSA family before verification, so no
    // candidate key verifies: the key builder must not "appear to accept" a
    // family that verification will always reject.
    let keys = make_peer_keys(KID_A); // an EdDSA signer for the token
    let (cache, shared) = fresh_cache();
    // Register an RSA JWK (structurally valid, bogus components — never used,
    // the family is rejected first) under the SAME kid the token carries.
    let rsa_jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(KID_A.to_owned()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: "bogus-modulus".to_owned(),
            e: "AQAB".to_owned(),
        }),
    };
    cache.upsert(cache_entry(Uuid::new_v4(), "bob-llc", PEER_A, rsa_jwk));
    let token = sign(&keys, KID_A, Some(ID_JAG_TYP), &id_jag(None));

    let err = verify_peer_id_jag(&shared, &token, OUR_ISSUER, &[PEER_A.to_owned()])
        .await
        .expect_err("an RSA peer key must not verify an ID-JAG (EdDSA-only)");
    assert!(matches!(err, PeerIdJagError::NoKey { .. }), "got: {err:?}");
}

#[tokio::test]
async fn ambiguous_multi_tenant_refused() {
    // The SAME peer key is registered under two tenants (the migration's
    // UNIQUE(tenant_id, issuer) permits this). Both records verify the token, so
    // tenant attribution is ambiguous → fail closed rather than guess.
    let keys = make_peer_keys(KID_A);
    let (cache, shared) = fresh_cache();
    cache.upsert(cache_entry(
        Uuid::new_v4(),
        "bob-llc",
        PEER_A,
        keys.jwk.clone(),
    ));
    cache.upsert(cache_entry(
        Uuid::new_v4(),
        "carol-inc",
        PEER_A,
        keys.jwk.clone(),
    ));
    let token = sign(&keys, KID_A, Some(ID_JAG_TYP), &id_jag(None));

    let err = verify_peer_id_jag(&shared, &token, OUR_ISSUER, &[PEER_A.to_owned()])
        .await
        .expect_err("a multi-tenant-registered peer must fail closed");
    match err {
        PeerIdJagError::Ambiguous { tenants } => {
            assert_eq!(tenants.len(), 2, "both tenants reported: {tenants:?}");
        }
        other => panic!("expected Ambiguous, got {other:?}"),
    }
}
