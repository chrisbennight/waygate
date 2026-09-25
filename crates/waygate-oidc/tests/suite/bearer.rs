//! BearerValidator tests against a preloaded JWKS. The RSA keypair is a test
//! fixture under `tests/fixtures/` — generated once via `openssl` and never
//! regenerated. The private half is load-bearing for signing; the JWK only
//! carries the public modulus/exponent.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

use waygate_oidc::{BearerValidator, JwksProvider, ValidationError};

const ISSUER: &str = "https://test-issuer.local";
const AUDIENCE: &str = "https://mcp.example.com";
const KID: &str = "test-key-1";

const PRIVATE_PEM: &[u8] = include_bytes!("../fixtures/private.pem");
const JWKS_JSON: &str = include_str!("../fixtures/jwks.json");

#[derive(Debug, Serialize)]
struct TestClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    groups: &'a [&'a str],
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign(claims: &TestClaims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    let key = EncodingKey::from_rsa_pem(PRIVATE_PEM).expect("rsa private");
    encode(&header, claims, &key).expect("encode")
}

fn validator() -> BearerValidator {
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, JWKS_JSON).expect("preload"));
    BearerValidator::new(jwks, ISSUER, AUDIENCE)
}

#[tokio::test]
async fn valid_token_yields_principal() {
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 300,
        email: Some("alice@example.com"),
        scope: Some("mcp:invoke mcp:read"),
        groups: &["mcp-admins", "engineers"],
    };
    let token = sign(&claims);
    let principal = validator().validate(&token).await.expect("validate");
    assert_eq!(principal.sub, "alice");
    assert_eq!(principal.email.as_deref(), Some("alice@example.com"));
    assert_eq!(principal.issuer, ISSUER);
    assert!(principal.has_scope("mcp:invoke"));
    assert!(principal.has_scope("mcp:read"));
    assert!(!principal.has_scope("mcp:admin"));
    assert!(principal.in_group("mcp-admins"));
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        // past the 30s leeway
        exp: now() - 120,
        email: None,
        scope: None,
        groups: &[],
    };
    let token = sign(&claims);
    let err = validator().validate(&token).await.expect_err("expired");
    assert!(matches!(err, ValidationError::Jwt(_)), "got: {err:?}");
}

#[tokio::test]
async fn wrong_audience_is_rejected() {
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: "https://someone-else.example",
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let token = sign(&claims);
    let err = validator().validate(&token).await.expect_err("wrong aud");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

// --- EMA per-upstream resource audience binding ---

fn validator_with_resources() -> BearerValidator {
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, JWKS_JSON).expect("preload"));
    let map = std::collections::HashMap::from([(
        "https://mcp.example.com/servers/example-observability".to_owned(),
        "example-observability".to_owned(),
    )]);
    BearerValidator::new(jwks, ISSUER, AUDIENCE).with_resource_audiences(map)
}

#[tokio::test]
async fn resource_scoped_token_is_accepted_and_bound_to_its_server() {
    // A token whose aud is a registered per-upstream resource id validates
    // (additive to the estate audience) AND comes back confined to that server
    // via the call-restriction mechanism the invocation gate enforces.
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: "https://mcp.example.com/servers/example-observability",
        exp: now() + 300,
        email: None,
        scope: Some("mcp:invoke"),
        groups: &[],
    };
    let token = sign(&claims);
    let principal = validator_with_resources()
        .validate(&token)
        .await
        .expect("resource-scoped token validates");
    let r = principal
        .api_key_profile_restrictions
        .expect("resource-scoped token must carry a server binding");
    assert_eq!(
        r.allowed_servers.as_deref(),
        Some(&["example-observability".to_owned()][..]),
        "binding must confine the token to its one upstream",
    );
    assert_eq!(r.allowed_tools, None);
}

#[tokio::test]
async fn estate_audience_token_has_no_resource_binding() {
    // The estate-wide audience is unrestricted even when resource audiences are
    // configured — per-resource binding is purely additive.
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let token = sign(&claims);
    let principal = validator_with_resources()
        .validate(&token)
        .await
        .expect("estate token validates");
    assert!(
        principal.api_key_profile_restrictions.is_none(),
        "estate-audience token must be unrestricted",
    );
}

#[tokio::test]
async fn unregistered_resource_audience_is_rejected() {
    // A token whose aud is NOT the estate audience and NOT a registered resource
    // id is rejected outright (not silently treated as estate-wide).
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: "https://mcp.example.com/servers/not-registered",
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let token = sign(&claims);
    let err = validator_with_resources()
        .validate(&token)
        .await
        .expect_err("unregistered resource aud must be rejected");
    assert!(matches!(err, ValidationError::Jwt(_)), "got: {err:?}");
}

/// Claims with a multi-valued `aud` array — the shape `TestClaims` (single
/// `&str`) can't express. Multi-valued `aud` is the surface where the
/// audience-membership gate once diverged from resource binding.
#[derive(Debug, Serialize)]
struct ArrayAudClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a [&'a str],
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

fn validator_with_two_resources() -> BearerValidator {
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, JWKS_JSON).expect("preload"));
    let map = std::collections::HashMap::from([
        (
            "https://mcp.example.com/servers/example-observability".to_owned(),
            "example-observability".to_owned(),
        ),
        (
            "https://mcp.example.com/servers/prometheus".to_owned(),
            "prometheus".to_owned(),
        ),
    ]);
    BearerValidator::new(jwks, ISSUER, AUDIENCE).with_resource_audiences(map)
}

#[tokio::test]
async fn multi_valued_aud_with_single_resource_is_bound_fail_closed() {
    // The regression this pins: a multi-valued `aud` array that
    // contains a single registered resource id (here alongside an attacker-
    // controlled audience) used to pass the audience-membership gate but resolve
    // to NO binding — silently promoting the token to an unrestricted estate
    // principal. It must now be CONFINED to the one registered upstream.
    let claims = ArrayAudClaims {
        sub: "alice",
        iss: ISSUER,
        aud: &[
            "https://mcp.example.com/servers/example-observability",
            "https://attacker.example/evil",
        ],
        exp: now() + 300,
        scope: Some("mcp:invoke"),
    };
    let token = sign_value(&claims);
    let principal = validator_with_resources()
        .validate(&token)
        .await
        .expect("array aud with one registered resource validates");
    let r = principal
        .api_key_profile_restrictions
        .expect("must be confined, not promoted to unrestricted estate");
    assert_eq!(
        r.allowed_servers.as_deref(),
        Some(&["example-observability".to_owned()][..]),
        "a single registered resource id in a multi-valued aud must bind to it",
    );
}

#[tokio::test]
async fn multi_valued_aud_with_multiple_resources_is_rejected() {
    // Two distinct registered resource ids in one `aud` — no single upstream to
    // confine to. Reject (fail closed); never fall back to unrestricted estate.
    let claims = ArrayAudClaims {
        sub: "alice",
        iss: ISSUER,
        aud: &[
            "https://mcp.example.com/servers/example-observability",
            "https://mcp.example.com/servers/prometheus",
        ],
        exp: now() + 300,
        scope: Some("mcp:invoke"),
    };
    let token = sign_value(&claims);
    let err = validator_with_two_resources()
        .validate(&token)
        .await
        .expect_err("two registered resource ids must be rejected");
    assert!(
        matches!(err, ValidationError::AmbiguousResourceAudience(2)),
        "got: {err:?}",
    );
}

#[tokio::test]
async fn wrong_issuer_is_rejected() {
    let claims = TestClaims {
        sub: "alice",
        iss: "https://evil-idp.example",
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let token = sign(&claims);
    let err = validator().validate(&token).await.expect_err("wrong iss");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

#[tokio::test]
async fn additional_issuers_accepted_alongside_primary() {
    // Authentik's per-provider issuer mode mints distinct `iss` URLs per
    // provider; with `with_additional_issuers` the validator should accept
    // them while still rejecting unrelated issuers.
    let extra = "https://test-issuer.local/application/o/example-channel/";
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, JWKS_JSON).expect("preload"));
    let v = BearerValidator::new(jwks, ISSUER, AUDIENCE)
        .with_additional_issuers(vec![extra.to_owned()]);

    let claims = TestClaims {
        sub: "example-channel",
        iss: extra,
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: Some("mcp:invoke:high"),
        groups: &["message-operators"],
    };
    let token = sign(&claims);
    let principal = v.validate(&token).await.expect("per-provider issuer");
    assert_eq!(principal.issuer, extra);

    // Primary issuer still works.
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let token = sign(&claims);
    v.validate(&token).await.expect("primary issuer");

    // Unrelated issuer still rejected.
    let claims = TestClaims {
        sub: "alice",
        iss: "https://evil-idp.example",
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let token = sign(&claims);
    let err = v.validate(&token).await.expect_err("unknown iss");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

#[tokio::test]
async fn unknown_kid_is_rejected() {
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("bogus-kid".into());
    let key = EncodingKey::from_rsa_pem(PRIVATE_PEM).unwrap();
    let token = encode(&header, &claims, &key).unwrap();

    let err = validator().validate(&token).await.expect_err("unknown kid");
    // The JWKS is preloaded and won't refresh via the network, so decoding_key
    // returns UnknownKid wrapped in ValidationError::Jwks.
    assert!(matches!(err, ValidationError::Jwks(_)), "got: {err:?}");
}

#[tokio::test]
async fn missing_authorization_header_reports_missing() {
    let v = validator();
    let err = v.validate_header("").await.expect_err("empty");
    assert!(matches!(err, ValidationError::Malformed));
}

#[tokio::test]
async fn malformed_scheme_is_rejected() {
    let v = validator();
    let err = v
        .validate_header("Basic abc")
        .await
        .expect_err("wrong scheme");
    assert!(matches!(err, ValidationError::Malformed));
}

#[tokio::test]
async fn unknown_kid_is_a_client_error_not_infra() {
    // Regression test for the gateway-AS short-circuit bug. When the chain
    // hits a preloaded validator (e.g. the gateway's own AS-minted JWKS) with
    // a token signed by a different IdP, the resulting `UnknownKid` must
    // surface as a client error so `bearer_middleware` falls through to the
    // next validator. Marking it infra would 503 every cross-IdP request.
    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("not-in-the-preloaded-jwks".into());
    let key = EncodingKey::from_rsa_pem(PRIVATE_PEM).unwrap();
    let token = encode(&header, &claims, &key).unwrap();

    let err = validator().validate(&token).await.expect_err("unknown kid");
    assert!(matches!(err, ValidationError::Jwks(_)), "got: {err:?}");
    assert!(
        err.is_client_error(),
        "UnknownKid must be a client error so the validator chain falls through; got: {err:?}",
    );
}

#[tokio::test]
async fn from_preloaded_does_not_attempt_network_refresh_on_cache_miss() {
    // Belt-and-suspenders for the production failure mode: a preloaded
    // provider must never attempt OIDC discovery / JWKS fetch, even after
    // the refresh interval for a network-backed provider would have elapsed.
    // The previous behaviour set the interval to 30s; under load the chain
    // would tip past that and try to fetch `<issuer>/.well-known/openid-
    // configuration` — which on the gateway's own public URL returns 404 +
    // empty body, surfacing as a `Jwks(Http(decode))` infra error and a 503
    // for the entire request even though a later (Authentik-backed)
    // validator in the chain would have accepted the token.
    //
    // ISSUER here (`https://test-issuer.local`) does not resolve. If
    // `from_preloaded` lazy-refreshed, this test would either hang on
    // connect timeout or return `Jwks(Http(_))` (infra). Asserting
    // `UnknownKid` (client) confirms refresh was skipped entirely.
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, JWKS_JSON).expect("preload"));
    let v = BearerValidator::new(jwks, ISSUER, AUDIENCE);

    let claims = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 300,
        email: None,
        scope: None,
        groups: &[],
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("kid-not-in-preloaded".into());
    let key = EncodingKey::from_rsa_pem(PRIVATE_PEM).unwrap();
    let token = encode(&header, &claims, &key).unwrap();

    let err = v.validate(&token).await.expect_err("cache miss must error");
    let detail = format!("{err:?}");
    assert!(
        matches!(
            err,
            ValidationError::Jwks(waygate_oidc::JwksError::UnknownKid(_))
        ),
        "preloaded provider must return UnknownKid (no network) — got: {detail}",
    );
}

// ---------------------------------------------------------------------------
// CVE-2026-25537 / GHSA-h395-gr6q-cpjc regression pins.
//
// jsonwebtoken < 10.3.0 silently treated a malformed standard `exp`/`nbf`
// claim (a JSON *string* instead of a number) as "not present": the value
// failed to parse into the numeric validator slot, so time validation was
// skipped and the token was accepted with an unverifiable / attacker-chosen
// expiry. jsonwebtoken >= 10.3.0 rejects the malformed claim instead.
//
// `BearerValidator` (this gateway's externally-accepted bearer path) builds
// `Validation::new(header.alg)` and `decode::<Claims>`, where `Claims` omits
// `exp`/`nbf` entirely — so it relies *wholly* on jsonwebtoken's own
// standard-claim validation for type-correctness of `exp`. These tests are
// version-coupled to the jsonwebtoken 10 bump on this branch and pin the
// post-fix rejection so a future downgrade or a default-feature regression
// that re-disabled standard-claim validation is caught.
//
// The contract asserted is *behavioral* (a string `exp`/`nbf` is rejected;
// the otherwise-identical numeric control is accepted), not a snapshot of the
// crate's internal error enum.
// ---------------------------------------------------------------------------

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

/// Sign an arbitrary serializable claims body with the same RSA fixture key,
/// kid, and algorithm the accepted-token tests use. Used to mint tokens whose
/// `exp`/`nbf` standard claim is a JSON *string* — the only thing that differs
/// from a valid token is the wire type of that one claim.
fn sign_value<T: serde::Serialize>(claims: &T) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    let key = EncodingKey::from_rsa_pem(PRIVATE_PEM).expect("rsa private");
    encode(&header, claims, &key).expect("encode")
}

/// Claims identical in shape to a valid access token, but with `exp` typed as
/// a `String` so it serializes to a JSON string on the wire. Every other claim
/// (iss/aud/sub) is valid, so the malformed `exp` is the *only* reason the
/// token can be rejected.
#[derive(Debug, Serialize)]
struct StringExpClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    /// JSON string instead of a number — the CVE-2026-25537 trigger.
    exp: String,
}

/// A token whose `exp` standard claim is a JSON string must be REJECTED by the
/// production bearer path, while the byte-for-byte-equivalent token with a
/// numeric `exp` is ACCEPTED. The numeric control proves the rejection is
/// specifically caused by the malformed claim type, not anything incidental
/// (signature, issuer, audience, kid — all held identical).
#[tokio::test]
async fn string_exp_is_rejected_numeric_exp_is_accepted() {
    let far_future = now() + 3600;

    // Control: numeric exp, everything else valid → accepted.
    let control = TestClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: far_future,
        email: None,
        scope: None,
        groups: &[],
    };
    let control_token = sign(&control);
    validator()
        .validate(&control_token)
        .await
        .expect("numeric-exp control token must be accepted");

    // Malformed: same claims, but exp is a JSON string with the same numeric
    // content → must be rejected by jsonwebtoken's standard-claim validation.
    let malformed = StringExpClaims {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: far_future.to_string(),
    };
    let malformed_token = sign_value(&malformed);
    let err = validator()
        .validate(&malformed_token)
        .await
        .expect_err("string-typed exp must be rejected (CVE-2026-25537)");

    // Surfaces through the validator's JWT error variant; the inner
    // jsonwebtoken kind is a malformed/missing standard-claim rejection.
    // (Under the production default `required_spec_claims = {"exp"}`, a
    // non-numeric `exp` lands in `MissingRequiredClaim("exp")` because it
    // fails to parse into the numeric slot before the format check runs —
    // pre-fix jsonwebtoken behaved differently in the *non-required* path,
    // pinned separately below. Both are post-fix rejections; the point here
    // is that the production path does NOT silently accept it.)
    match err {
        ValidationError::Jwt(e) => {
            use jsonwebtoken::errors::ErrorKind;
            assert!(
                matches!(
                    e.kind(),
                    ErrorKind::InvalidClaimFormat(c) | ErrorKind::MissingRequiredClaim(c) if c == "exp"
                ),
                "expected a malformed/missing `exp` rejection, got: {:?}",
                e.kind(),
            );
        }
        other => panic!("expected ValidationError::Jwt, got: {other:?}"),
    }
}

/// The CVE-2026-25537 fix proper: when a standard time claim is malformed (a
/// JSON string) and time validation is enabled but the claim is NOT in
/// `required_spec_claims`, pre-fix jsonwebtoken *silently treated it as
/// absent* and accepted the token; the fixed crate rejects it with
/// `InvalidClaimFormat`. This drives `jsonwebtoken::decode` directly with a
/// `Validation` shaped like the production validator (same issuer / audience /
/// leeway / header alg, preloaded fixture key) to exercise the exact branch
/// the advisory describes — for both `exp` and `nbf`.
#[test]
fn malformed_time_claims_rejected_with_invalid_claim_format() {
    use jsonwebtoken::errors::ErrorKind;

    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_str(JWKS_JSON).expect("jwks");
    let key = DecodingKey::from_jwk(&jwks.keys[0]).expect("decoding key");

    // Build a Validation matching the production bearer path (validator.rs):
    // narrowed to the header alg, issuer + audience set, 30s leeway.
    let prod_like = |alg: Algorithm| {
        let mut v = Validation::new(alg);
        v.set_issuer(&[ISSUER]);
        v.set_audience(&[AUDIENCE]);
        v.leeway = 30;
        v
    };

    // --- exp as a string -------------------------------------------------
    #[derive(Serialize)]
    struct ExpStr<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: String,
    }
    let exp_token = sign_value(&ExpStr {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: (now() + 3600).to_string(),
    });
    let alg = decode_header(&exp_token).unwrap().alg;
    let mut v = prod_like(alg);
    // Drop the default `{"exp"}` required set so the format check — not the
    // required-claim check — is the rejection path. This is the precise
    // configuration where pre-fix jsonwebtoken silently accepted.
    v.required_spec_claims = std::collections::HashSet::new();
    v.validate_exp = true;
    let err = decode::<serde_json::Value>(&exp_token, &key, &v)
        .expect_err("string exp must reject under the fixed crate");
    assert_eq!(
        err.into_kind(),
        ErrorKind::InvalidClaimFormat("exp".to_string()),
        "string-typed exp must reject with InvalidClaimFormat (CVE-2026-25537)",
    );

    // --- nbf as a string -------------------------------------------------
    // `nbf` is the claim the silent-bypass actually exposed for the gateway:
    // it is never in the required set, so pre-fix a forged string `nbf` was
    // accepted whenever nbf validation was enabled.
    #[derive(Serialize)]
    struct NbfStr<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        nbf: String,
    }
    let nbf_token = sign_value(&NbfStr {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 3600,
        nbf: (now().saturating_sub(60)).to_string(),
    });
    let alg = decode_header(&nbf_token).unwrap().alg;
    let mut v = prod_like(alg);
    v.required_spec_claims = std::collections::HashSet::new();
    v.validate_nbf = true;
    let err = decode::<serde_json::Value>(&nbf_token, &key, &v)
        .expect_err("string nbf must reject under the fixed crate");
    assert_eq!(
        err.into_kind(),
        ErrorKind::InvalidClaimFormat("nbf".to_string()),
        "string-typed nbf must reject with InvalidClaimFormat (CVE-2026-25537)",
    );

    // Control: the same token shapes with NUMERIC exp/nbf are accepted, so the
    // rejections above are caused by the claim *type*, not the surrounding
    // claims or the prod-like Validation.
    #[derive(Serialize)]
    struct NumericTime<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        nbf: u64,
    }
    let ok_token = sign_value(&NumericTime {
        sub: "alice",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: now() + 3600,
        nbf: now().saturating_sub(60),
    });
    let alg = decode_header(&ok_token).unwrap().alg;
    let mut v = prod_like(alg);
    v.required_spec_claims = std::collections::HashSet::new();
    v.validate_exp = true;
    v.validate_nbf = true;
    decode::<serde_json::Value>(&ok_token, &key, &v)
        .expect("numeric exp/nbf control must be accepted");
}
