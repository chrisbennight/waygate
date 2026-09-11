//! End-to-end "token factory" loop: mint an access token via
//! [`IdentityIssuer::mint_access_token`] (exactly what `/oauth/token` does)
//! and validate it via [`BearerValidator`] configured like the resource
//! server (preloaded JWKS, gateway's own issuer+audience).
//!
//! If this roundtrip breaks, every gateway-minted token is rejected at the
//! `/mcp` boundary and the AS mode is unusable.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;

use waygate_oidc::{BearerValidator, IdentityIssuer, JwksProvider};

const ISSUER: &str = "https://mcp.test";
const AUDIENCE: &str = "https://mcp.test/mcp";

fn test_issuer() -> IdentityIssuer {
    // Deterministic key — tests are reproducible, and Ed25519 public keys
    // derive from the private so no separate public file is needed.
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    IdentityIssuer::from_ed25519_pkcs8_pem(
        &pem,
        "gw-test-kid",
        ISSUER,
        "gateway-main",
        Duration::from_secs(60),
    )
    .expect("build issuer")
}

async fn validator_for(issuer: &IdentityIssuer) -> BearerValidator {
    let jwks_json = serde_json::to_string(&issuer.jwks()).expect("jwks json");
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, &jwks_json).expect("preload jwks"));
    // No `.with_algorithms(...)` — match `waygate-server/main.rs` exactly
    // so this test exercises the same shape as production.
    BearerValidator::new(jwks, ISSUER, AUDIENCE)
}

#[tokio::test]
async fn mint_then_validate_yields_expected_principal() {
    let issuer = test_issuer();
    let token = issuer
        .mint_access_token(
            "user-42",
            Some("u@test"),
            &["mcp-users".into(), "mcp-admins".into()],
            AUDIENCE,
            &["mcp:invoke".into(), "mcp:read".into()],
            Some("https://cli.test/claude.json"),
            None,
            Duration::from_secs(3600),
        )
        .expect("mint access token");

    let v = validator_for(&issuer).await;
    let principal = v
        .validate(&token)
        .await
        .expect("validate gateway-minted token");

    assert_eq!(principal.sub, "user-42");
    assert_eq!(principal.email.as_deref(), Some("u@test"));
    assert_eq!(principal.issuer, ISSUER);
    assert_eq!(
        principal.groups,
        vec!["mcp-users".to_string(), "mcp-admins".into()]
    );
    assert!(principal.has_scope("mcp:invoke"));
    assert!(principal.has_scope("mcp:read"));
    assert!(!principal.has_scope("mcp:admin"));
    assert!(principal.in_group("mcp-admins"));
}

#[tokio::test]
async fn validator_rejects_wrong_audience() {
    let issuer = test_issuer();
    let token = issuer
        .mint_access_token(
            "user-42",
            None,
            &[],
            "https://other.test/mcp",
            &["mcp:invoke".into()],
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap();

    let v = validator_for(&issuer).await;
    let err = v.validate(&token).await.expect_err("wrong aud must fail");
    assert!(
        format!("{err:?}").to_lowercase().contains("audience"),
        "unexpected error: {err:?}"
    );
}

/// When the AS mints an access token under a non-default tenant, the
/// resulting JWT MUST carry the `tenant` claim so `BearerValidator`
/// populates `Principal.tenant` with that tenant. Without this, every
/// gateway-minted admin token silently lands on the `default` tenant
/// — see `crates/waygate-admin/src/oauth_consent.rs` (which scopes
/// admin reads/writes by `principal.tenant`).
#[tokio::test]
async fn mint_access_token_carries_tenant_claim_into_principal() {
    let issuer = test_issuer();
    let token = issuer
        .mint_access_token(
            "user-acme",
            None,
            &[],
            AUDIENCE,
            &["mcp:admin".into()],
            Some("https://cli.test/acme.json"),
            Some("acme"),
            Duration::from_secs(60),
        )
        .unwrap();
    let v = validator_for(&issuer).await;
    let principal = v.validate(&token).await.expect("validate acme token");
    assert_eq!(
        principal.tenant.as_str(),
        "acme",
        "BearerValidator must hydrate Principal.tenant from the JWT `tenant` claim, \
         otherwise per-tenant admin endpoints silently target the default tenant",
    );
}

/// Pin that omitting tenant on mint (legacy / dev callers
/// passing `None`) keeps the prior default-fallback
/// behaviour — the JWT then carries no `tenant` claim and
/// `BearerValidator` returns `TenantId::default()`.
#[tokio::test]
async fn mint_access_token_without_tenant_keeps_default_fallback() {
    let issuer = test_issuer();
    let token = issuer
        .mint_access_token(
            "u",
            None,
            &[],
            AUDIENCE,
            &["mcp:read".into()],
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap();
    let v = validator_for(&issuer).await;
    let principal = v.validate(&token).await.expect("validate");
    assert_eq!(
        principal.tenant.as_str(),
        "default",
        "legacy callers passing tenant=None must hit the validator's default-tenant fallback",
    );
}

/// `waygate-server/main.rs` builds the preloaded-JWKS validator with plain
/// `BearerValidator::new` — no `.with_algorithms(...)` widening. The default
/// must accept EdDSA or every gateway-minted access token is rejected at the
/// `/mcp` boundary. If this starts failing, add `.with_algorithms(vec![
/// Algorithm::EdDSA, ...])` wherever gateway-minted tokens are validated, or
/// re-expand the default list in `BearerValidator::new`.
#[tokio::test]
async fn default_validator_accepts_gateway_minted_eddsa_tokens() {
    let issuer = test_issuer();
    let token = issuer
        .mint_access_token(
            "u",
            None,
            &[],
            AUDIENCE,
            &["mcp:invoke".into()],
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap();
    let jwks_json = serde_json::to_string(&issuer.jwks()).unwrap();
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, &jwks_json).unwrap());
    // No `.with_algorithms(...)` — matches waygate-server/main.rs exactly.
    let v = BearerValidator::new(jwks, ISSUER, AUDIENCE);
    v.validate(&token)
        .await
        .expect("default validator must accept gateway-minted EdDSA");
}

#[tokio::test]
async fn validator_rejects_wrong_issuer() {
    // A token minted by a *different* issuer (different iss claim) must be
    // rejected even if the signing key happens to verify.
    let issuer_other = IdentityIssuer::from_ed25519_pkcs8_pem(
        &SigningKey::from_bytes(&[9u8; 32])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap(),
        "gw-test-kid",
        "https://imposter.test",
        "gateway-main",
        Duration::from_secs(60),
    )
    .unwrap();

    let token = issuer_other
        .mint_access_token(
            "user",
            None,
            &[],
            AUDIENCE,
            &["mcp:invoke".into()],
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap();

    // Validator keyed to the *real* issuer.
    let real = test_issuer();
    let v = validator_for(&real).await;
    let err = v.validate(&token).await.expect_err("wrong iss must fail");
    assert!(
        format!("{err:?}").to_lowercase().contains("issuer"),
        "unexpected error: {err:?}"
    );
}
