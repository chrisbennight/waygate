//! EMA ID-JAG redeem (RFC 7523 `jwt-bearer`) against a live Postgres.
//!
//! Drives the real [`waygate_as::build_router`] `/oauth/token` handler with the
//! `jwt-bearer` grant: register a confidential client, mint an ID-JAG with the
//! gateway's own issuer, then redeem it (authenticating the client with a
//! client_secret) for an audience-restricted access token. Exercises the
//! handler behaviours that need the DB — happy path (aud == resource, tenant
//! carried through), single-use replay, client-binding mismatch, the
//! token-confusion / wrong-audience guards, and confidential-client
//! authentication (required; bad secret rejected).
//!
//! Skips cleanly when `GATEWAY_AS_DATABASE_URL` is unset so `cargo test` passes
//! without a database; CI provisions Postgres and runs it for real. The pure
//! verification contract (typ / aud / iss / exp) is unit-tested in
//! `waygate-oidc::identity_jwt`, the scope-strip contract in `waygate-as::token`,
//! and confidential-client auth in `waygate-as::client_auth`.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tower::ServiceExt;

use jsonwebtoken::jwk::JwkSet;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_as::{
    build_router, AsConfig, ConfidentialClientStore, CrossAppDenied, CrossAppPolicy, EmaDeps,
    PgConfidentialClientStore, ResolvedSubject, SubjectResolveError, SubjectTokenResolver,
    UpstreamCrypto,
};
use waygate_evidence::audit::NullSink;
use waygate_federation::jwks::{CachedJwks, InMemoryPeerJwksCache, SharedPeerJwksCache};
use waygate_federation::TrustTier;
use waygate_oidc::{
    IdTokenValidator, IdentityIssuer, JwksProvider, Principal, SharedIdentityIssuer,
};
use waygate_storage::PgAuditSink;

// EMA (Tier-C): a *peer* gateway that mints ID-JAGs we redeem.
const PEER_ISSUER: &str = "https://peer-a.test";
const PEER_KID: &str = "peer-a-key";

const ISSUER: &str = "https://mcp.test";
const RESOURCE: &str = "https://mcp.test/servers/example-observability";
const CLIENT_ID: &str = "https://cli.test/claude.json";
const CLIENT_SECRET: &str = "cs-test-secret-value";

async fn connect() -> Option<PgPool> {
    let url = env::var("GATEWAY_AS_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to GATEWAY_AS_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");
    Some(pool)
}

fn test_issuer() -> SharedIdentityIssuer {
    let sk = SigningKey::from_bytes(&[31u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            "gw-redeem-test",
            ISSUER,
            "gateway-main",
            Duration::from_secs(60),
        )
        .expect("build issuer"),
    )
}

fn test_id_validator() -> Arc<IdTokenValidator> {
    let jwks = Arc::new(
        JwksProvider::from_preloaded(ISSUER, r#"{"keys":[]}"#).expect("preload empty jwks"),
    );
    Arc::new(IdTokenValidator::new(
        jwks,
        ISSUER,
        "https://cli.test/c.json",
    ))
}

fn test_config() -> AsConfig {
    AsConfig {
        public_url: ISSUER.into(),
        audience: "https://mcp.test/mcp".into(),
        upstream_issuer: "https://auth.test".into(),
        upstream_authorize_endpoint: "https://auth.test/authorize".into(),
        upstream_token_endpoint: "https://auth.test/token".into(),
        upstream_client_id: "gateway-client".into(),
        upstream_client_secret: "unused".into(),
        upstream_redirect_uri: "https://mcp.test/oauth/callback".into(),
        upstream_scopes: vec!["openid".into()],
        upstream_crypto: UpstreamCrypto::from_key_bytes([0x42; 32]),
        cimd_allowed_hosts: None,
        cimd_dev_doc_dir: None,
        access_token_ttl: Duration::from_secs(3600),
        refresh_token_ttl: Duration::from_secs(30 * 86_400),
        transaction_ttl: Duration::from_secs(900),
        code_ttl: Duration::from_secs(60),
        allowed_scopes: vec!["mcp:invoke".into(), "mcp:read".into()],
        require_explicit_consent: false,
        idjag_ttl: Duration::from_secs(300),
        idjag_require_scim: true,
        idjag_allowed_audiences: vec![ISSUER.into()],
        idjag_known_resources: vec![RESOURCE.into()],
        // Self-redemption: we trust ID-JAGs minted by our own issuer.
        idjag_trusted_issuers: vec![ISSUER.into()],
        idjag_advertise: false,
    }
}

// Redeem never invokes the mint-side seams; trivial impls satisfy EmaDeps.
struct UnusedResolver;
#[async_trait]
impl SubjectTokenResolver for UnusedResolver {
    async fn resolve(&self, _t: &str, _tok: &str) -> Result<ResolvedSubject, SubjectResolveError> {
        Err(SubjectResolveError)
    }
}
struct UnusedCrossApp;
#[async_trait]
impl CrossAppPolicy for UnusedCrossApp {
    async fn authorize(&self, _p: &Principal, _c: &str, _r: &str) -> Result<(), CrossAppDenied> {
        Err(CrossAppDenied)
    }
}

fn router(pool: PgPool, issuer: SharedIdentityIssuer) -> axum::Router<()> {
    router_with_config(pool, issuer, test_config(), None)
}

fn router_with_config(
    pool: PgPool,
    issuer: SharedIdentityIssuer,
    config: AsConfig,
    peer_cache: Option<waygate_federation::jwks::SharedPeerJwksCache>,
) -> axum::Router<()> {
    let jwks_json = serde_json::to_string(&issuer.jwks()).expect("serialize jwks");
    let verifier =
        Arc::new(JwksProvider::from_preloaded(ISSUER, &jwks_json).expect("preload gateway jwks"));
    let ema = EmaDeps {
        subject_resolver: Arc::new(UnusedResolver),
        cross_app_policy: Arc::new(UnusedCrossApp),
        enricher: None,
        verifier: Some(verifier),
        client_store: Some(Arc::new(PgConfidentialClientStore::new(pool.clone()))),
        peer_jwks: peer_cache,
    };
    build_router(
        config,
        pool,
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        issuer,
        test_id_validator(),
        Arc::new(NullSink),
        Some(ema),
    )
}

/// Register a confidential client authenticating by client_secret. Uses a fixed
/// salt (no RNG needed in tests); production minting uses a random salt.
async fn register_client(pool: &PgPool, client_id: &str, secret: &str) {
    let salt = SaltString::from_b64("ZHVtbXlzYWx0Zm9ydGVzdA").expect("salt");
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .expect("hash secret")
        .to_string();
    PgConfidentialClientStore::new(pool.clone())
        .upsert(client_id, Some(&hash), None)
        .await
        .expect("register confidential client");
}

fn mint(
    issuer: &IdentityIssuer,
    aud: &str,
    resource: &str,
    client_id: &str,
    tenant: Option<&str>,
) -> String {
    issuer
        .mint_id_jag(
            "alice",
            Some("alice@example.test"),
            aud,
            resource,
            client_id,
            &["mcp:invoke".into(), "mcp:read".into()],
            tenant,
            Duration::from_secs(300),
        )
        .expect("mint id-jag")
}

async fn redeem(
    router: axum::Router<()>,
    assertion: &str,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> (StatusCode, Value) {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    ser.append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
    ser.append_pair("assertion", assertion);
    if let Some(id) = client_id {
        ser.append_pair("client_id", id);
    }
    if let Some(secret) = client_secret {
        ser.append_pair("client_secret", secret);
    }
    let body = ser.finish();
    let resp = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("redeem oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let json: Value = serde_json::from_slice(&bytes).expect("json body");
    (status, json)
}

/// Decode a JWT's claims (signature not verified — we assert the shape the AS
/// minted; the signature round-trip is covered by waygate-oidc unit tests).
fn jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("jwt has payload segment");
    let raw = URL_SAFE_NO_PAD.decode(payload).expect("b64url payload");
    serde_json::from_slice(&raw).expect("json claims")
}

// --- EMA (Tier-C): peer-minted ID-JAG redeem ---

/// A second, independent issuer standing in for a *peer* gateway, with a
/// distinct key, issuer URL, and kid so its tokens are only verifiable against
/// its own JWKS (which we publish into the peer cache), never our self keyring.
fn peer_issuer() -> SharedIdentityIssuer {
    let sk = SigningKey::from_bytes(&[77u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("peer pem");
    Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            PEER_KID,
            PEER_ISSUER,
            "gateway-main",
            Duration::from_secs(60),
        )
        .expect("build peer issuer"),
    )
}

/// Publish the peer's JWKS into a fresh peer cache under `tenant` — the tenant
/// THIS gateway has the peer registered in (what a redeemed token should land
/// in, regardless of the assertion's `tenant` claim).
fn peer_cache(peer: &SharedIdentityIssuer, tenant: &str) -> SharedPeerJwksCache {
    let jwks_json = serde_json::to_string(&peer.jwks()).expect("serialize peer jwks");
    let keys: JwkSet = serde_json::from_str(&jwks_json).expect("parse peer jwks");
    let cache = Arc::new(InMemoryPeerJwksCache::new());
    cache.upsert(CachedJwks {
        peer_id: Uuid::new_v4(),
        tenant_id: tenant.to_owned(),
        issuer: PEER_ISSUER.to_owned(),
        trust_tier: TrustTier::Full,
        keys,
        fetched_at: OffsetDateTime::now_utc(),
    });
    cache
}

/// A config that trusts the peer issuer for redeem (in addition to self).
fn config_trusting_peer() -> AsConfig {
    let mut cfg = test_config();
    cfg.idjag_trusted_issuers.push(PEER_ISSUER.into());
    cfg
}

#[tokio::test]
async fn peer_minted_id_jag_redeems_with_tenant_from_peer_record() {
    // The headline Tier-C property: a peer gateway mints an ID-JAG; we verify it
    // against the peer's cached JWKS and mint an audience-restricted token whose
    // tenant comes from OUR peer registration — NOT the assertion's `tenant`
    // claim (which here asserts a different, attacker-chosen tenant).
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let peer = peer_issuer();
    let cache = peer_cache(&peer, "bob-llc");
    // ID-JAG: aud = OUR issuer, iss = peer, resource = a registered upstream,
    // tenant claim = a tenant we must IGNORE.
    let assertion = peer
        .mint_id_jag(
            "alice",
            Some("alice@peer-a.test"),
            ISSUER,
            RESOURCE,
            CLIENT_ID,
            &["mcp:invoke".into(), "mcp:read".into()],
            Some("attacker-tenant"),
            Duration::from_secs(300),
        )
        .expect("mint peer id-jag");

    let (status, body) = redeem(
        router_with_config(pool, test_issuer(), config_trusting_peer(), Some(cache)),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let access = body
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token present");
    let claims = jwt_claims(access);
    assert_eq!(
        claims.get("aud").and_then(Value::as_str),
        Some(RESOURCE),
        "peer-redeemed token MUST be audience-restricted to the ID-JAG resource",
    );
    assert_eq!(claims.get("sub").and_then(Value::as_str), Some("alice"));
    assert_eq!(
        claims.get("tenant").and_then(Value::as_str),
        Some("bob-llc"),
        "tenant MUST come from the peer record, NOT the assertion's `tenant` claim",
    );
}

#[tokio::test]
async fn peer_minted_id_jag_rejected_when_peer_redemption_not_configured() {
    // Same valid peer ID-JAG, but the redeem router has no peer JWKS cache
    // (peer_jwks: None). A peer-issued assertion must be rejected — only
    // self-issued ID-JAGs are redeemable without federation wired.
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let peer = peer_issuer();
    let assertion = peer
        .mint_id_jag(
            "alice",
            None,
            ISSUER,
            RESOURCE,
            CLIENT_ID,
            &["mcp:invoke".into()],
            Some("bob-llc"),
            Duration::from_secs(300),
        )
        .expect("mint peer id-jag");

    let (status, body) = redeem(
        // peer cache = None even though the issuer is trusted.
        router_with_config(pool, test_issuer(), config_trusting_peer(), None),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_grant"),
    );
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn redeem_mints_audience_restricted_token_with_no_refresh() {
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();
    let assertion = mint(&issuer, ISSUER, RESOURCE, CLIENT_ID, Some("acme-prod"));
    let (status, body) = redeem(
        router(pool, issuer),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body.get("token_type").and_then(Value::as_str),
        Some("Bearer")
    );
    assert!(
        body.get("refresh_token").is_none(),
        "a redeemed ID-JAG yields no refresh token",
    );
    assert_eq!(
        body.get("scope").and_then(Value::as_str),
        Some("mcp:invoke mcp:read"),
    );
    let access = body
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token present");
    let claims = jwt_claims(access);
    assert_eq!(
        claims.get("aud").and_then(Value::as_str),
        Some(RESOURCE),
        "issued access token aud MUST equal the ID-JAG resource",
    );
    assert_eq!(claims.get("sub").and_then(Value::as_str), Some("alice"));
    assert_eq!(
        claims.get("tenant").and_then(Value::as_str),
        Some("acme-prod"),
        "the subject's tenant MUST be carried onto the redeemed access token",
    );
}

#[tokio::test]
async fn redeem_rejects_replayed_assertion() {
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();
    let assertion = mint(&issuer, ISSUER, RESOURCE, CLIENT_ID, None);

    let (s1, _) = redeem(
        router(pool.clone(), issuer.clone()),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "first redemption succeeds");

    let (s2, body2) = redeem(
        router(pool, issuer),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;
    assert_eq!(s2, StatusCode::BAD_REQUEST);
    assert_eq!(
        body2.get("error").and_then(Value::as_str),
        Some("invalid_grant")
    );
}

#[tokio::test]
async fn redeem_rejects_client_id_mismatch() {
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();
    // ID-JAG bound to a DIFFERENT client than the one authenticating.
    let assertion = mint(
        &issuer,
        ISSUER,
        RESOURCE,
        "https://other.example/c.json",
        None,
    );
    let (status, body) = redeem(
        router(pool, issuer),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_grant")
    );
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn redeem_rejects_token_confusion() {
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();
    // A per-upstream identity JWT (typ absent) signed by the same key must NOT
    // be redeemable as an ID-JAG, even with valid client auth.
    let principal = Principal {
        sub: "alice".into(),
        email: None,
        groups: vec![],
        issuer: ISSUER.into(),
        scopes: vec![],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    };
    let not_an_idjag = issuer.mint(&principal, ISSUER).expect("mint identity jwt");
    let (status, body) = redeem(
        router(pool, issuer),
        &not_an_idjag,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_grant")
    );
}

#[tokio::test]
async fn redeem_rejects_wrong_audience() {
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();
    let assertion = mint(
        &issuer,
        "https://other-resource-as.example",
        RESOURCE,
        CLIENT_ID,
        None,
    );
    let (status, body) = redeem(
        router(pool, issuer),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_grant")
    );
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn redeem_requires_client_authentication() {
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();
    let assertion = mint(&issuer, ISSUER, RESOURCE, CLIENT_ID, None);
    // No client_secret presented — the spec requires confidential-client auth.
    let (status, body) = redeem(router(pool, issuer), &assertion, Some(CLIENT_ID), None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_client")
    );
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn redeem_rejects_unregistered_resource() {
    // A valid ID-JAG (good signature, issuer, audience,
    // client binding) whose `resource` is NOT a registered per-upstream resource
    // id must be refused at redeem time with `invalid_target` — BEFORE minting.
    // The minted access token would carry `aud = resource`, and the /mcp
    // BearerValidator only CONFINES a token whose `aud` is a registered resource
    // id; an estate-audience token is deliberately unrestricted. So redeeming an
    // assertion whose `resource` == the estate audience (the first case) would
    // otherwise mint an UNRESTRICTED estate bearer instead of a one-upstream
    // bearer — bypassing the resource binding.
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    // Neither is in `idjag_known_resources` (= [RESOURCE]).
    for resource in [
        "https://mcp.test/mcp",             // the estate audience — the attack
        "https://mcp.test/servers/unknown", // a non-manifest upstream id
    ] {
        let issuer = test_issuer();
        let assertion = mint(&issuer, ISSUER, resource, CLIENT_ID, None);
        let (status, body) = redeem(
            router(pool.clone(), issuer),
            &assertion,
            Some(CLIENT_ID),
            Some(CLIENT_SECRET),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resource {resource}: body {body}"
        );
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some("invalid_target"),
            "unregistered resource {resource} must be refused with invalid_target",
        );
        assert!(
            body.get("access_token").is_none(),
            "resource {resource}: no token must be minted",
        );
    }
}

#[tokio::test]
async fn redeem_rejects_estate_audience_even_if_listed_as_known_resource() {
    // `idjag_known_resources` is the manifest-derived set
    // UNIONED with operator-supplied `GATEWAY_AS_IDJAG_RESOURCES`. An operator
    // could mis-list the estate audience there. The estate audience is the ONE
    // resource value that yields an UNRESTRICTED token at /mcp, so redeem must
    // reject `resource == audience` explicitly — regardless of the allow-list.
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();

    let mut cfg = test_config();
    let estate = cfg.audience.clone(); // "https://mcp.test/mcp"
    cfg.idjag_known_resources.push(estate.clone()); // operator footgun
    let assertion = mint(&issuer, ISSUER, &estate, CLIENT_ID, None);

    let (status, body) = redeem(
        router_with_config(pool, issuer, cfg, None),
        &assertion,
        Some(CLIENT_ID),
        Some(CLIENT_SECRET),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_target"),
        "the estate audience must never be redeemable, even if mis-listed in known_resources",
    );
    assert!(
        body.get("access_token").is_none(),
        "no token may be minted for the estate audience",
    );
}

#[tokio::test]
async fn redeem_rejects_bad_client_secret() {
    let Some(pool) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    register_client(&pool, CLIENT_ID, CLIENT_SECRET).await;
    let issuer = test_issuer();
    let assertion = mint(&issuer, ISSUER, RESOURCE, CLIENT_ID, None);
    let (status, body) = redeem(
        router(pool, issuer),
        &assertion,
        Some(CLIENT_ID),
        Some("wrong-secret"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_client")
    );
    assert!(body.get("access_token").is_none());
}
