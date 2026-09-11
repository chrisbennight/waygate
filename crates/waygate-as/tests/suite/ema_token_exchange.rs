//! Behavioural coverage for the EMA token-exchange (ID-JAG mint) grant at
//! `POST /oauth/token` (`waygate_as::token::handle_token_exchange`).
//!
//! Like `cors_preflight.rs`, this drives the *real* [`waygate_as::build_router`]
//! through `tower::ServiceExt::oneshot` and needs no database: the
//! token-exchange path resolves the subject (injected fake), enriches
//! (`None` here), evaluates the cross-app policy (injected fake), intersects
//! scopes, and mints — none of which touch the OAuth store. The pool is built
//! `connect_lazy` purely to satisfy the signature, and the evidence sink is
//! `NullSink`.
//!
//! The two side dependencies the endpoint needs — the RFC 8693 subject-token
//! resolver and the cross-app policy — are exactly the injection seams
//! `waygate-server` fills in prod ([`waygate_as::EmaDeps`]). Faking them here
//! lets us assert the *handler's* contract (validate-before-mint ordering, the
//! SCIM gate, scope intersection, the ID-JAG wire shape and audience binding)
//! independently of the Cedar engine and the validator stack.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sqlx::postgres::PgPool;
use tower::ServiceExt;

use waygate_as::{
    build_router, AsConfig, CrossAppDenied, CrossAppPolicy, EmaDeps, ResolvedSubject,
    SubjectResolveError, SubjectTokenResolver, UpstreamCrypto,
};
use waygate_evidence::audit::NullSink;
use waygate_oidc::{
    IdTokenValidator, IdentityIssuer, JwksProvider, Principal, ScimGroupRef, ScimPrincipalAttrs,
};

const ISSUER: &str = "https://mcp.test";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TT_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
const TT_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const RESOURCE_AS: &str = "https://resource-as.test";
const RESOURCE: &str = "https://mcp.test/example-messages";
const CLIENT_ID: &str = "claude-code";

// ---------------------------------------------------------------------------
// Router scaffolding (DB-free; mirrors cors_preflight.rs).
// ---------------------------------------------------------------------------

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
        // AS allow-list includes a privileged scope (mcp:admin) the subject
        // principal does NOT hold, so the principal-derived limiting test can
        // prove an in-allow-list scope is still dropped when the subject lacks
        // it. mcp:read is intentionally ABSENT so the happy path observes the
        // allow-list intersection (read is requested and dropped).
        allowed_scopes: vec!["mcp:invoke".into(), "mcp:admin".into()],
        require_explicit_consent: false,
        idjag_ttl: Duration::from_secs(300),
        idjag_require_scim: true,
        idjag_allowed_audiences: vec![RESOURCE_AS.into()],
        idjag_known_resources: vec![RESOURCE.into()],
        idjag_trusted_issuers: vec![ISSUER.into()],
        idjag_advertise: false,
    }
}

fn test_issuer() -> Arc<IdentityIssuer> {
    let sk = SigningKey::from_bytes(&[23u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
    Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            "gw-test-kid",
            ISSUER,
            "gateway-main",
            Duration::from_secs(60),
        )
        .expect("build issuer"),
    )
}

/// Empty-JWKS id-token validator — never invoked here (the subject resolver is
/// faked); present only to satisfy the router signature.
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

fn router(ema: Option<EmaDeps>) -> axum::Router<()> {
    let pool = PgPool::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool construction never connects");
    build_router(
        test_config(),
        pool,
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        test_issuer(),
        test_id_validator(),
        Arc::new(NullSink),
        ema,
    )
}

// ---------------------------------------------------------------------------
// Fakes for the two EMA injection seams.
// ---------------------------------------------------------------------------

/// Resolves to the wrapped principal + authenticated `client_id`, or
/// `SubjectResolveError` when `principal` is `None`. The `client_id` models
/// the value the subject token itself carries (gateway access token's
/// `client_id` / id_token's `azp`) — the handler binds it, not the form field.
struct FakeResolver {
    principal: Option<Principal>,
    client_id: Option<String>,
}

#[async_trait]
impl SubjectTokenResolver for FakeResolver {
    async fn resolve(
        &self,
        _subject_token_type: &str,
        _subject_token: &str,
    ) -> Result<ResolvedSubject, SubjectResolveError> {
        match &self.principal {
            Some(p) => Ok(ResolvedSubject {
                principal: p.clone(),
                client_id: self.client_id.clone(),
            }),
            None => Err(SubjectResolveError),
        }
    }
}

/// Allows or denies the cross-app grant per `allow`.
struct FakeCrossApp {
    allow: bool,
}

#[async_trait]
impl CrossAppPolicy for FakeCrossApp {
    async fn authorize(
        &self,
        _principal: &Principal,
        _client_id: &str,
        _resource: &str,
    ) -> Result<(), CrossAppDenied> {
        if self.allow {
            Ok(())
        } else {
            Err(CrossAppDenied)
        }
    }
}

fn ema_deps(resolved: Option<Principal>, client_id: Option<&str>, allow: bool) -> EmaDeps {
    EmaDeps {
        subject_resolver: Arc::new(FakeResolver {
            principal: resolved,
            client_id: client_id.map(str::to_owned),
        }),
        cross_app_policy: Arc::new(FakeCrossApp { allow }),
        // No enricher: the resolver already returns a principal with the SCIM
        // facts the handler gates on, exactly as the chained enricher would.
        enricher: None,
        // These tests exercise the mint path only; the redeem verifier, client
        // registry, and peer JWKS cache are unused here.
        verifier: None,
        client_store: None,
        peer_jwks: None,
    }
}

// ---------------------------------------------------------------------------
// Principal builders.
// ---------------------------------------------------------------------------

fn principal(sub: &str, scim: Option<ScimPrincipalAttrs>) -> Principal {
    Principal {
        sub: sub.into(),
        email: Some(format!("{sub}@example.test")),
        groups: vec!["mcp-users".into()],
        issuer: "https://auth.test".into(),
        scopes: vec!["mcp:invoke".into(), "mcp:read".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn scim(active: bool) -> ScimPrincipalAttrs {
    ScimPrincipalAttrs {
        user_id: "u-1".into(),
        user_name: "alice".into(),
        external_id: None,
        active,
        attrs: Value::Null,
        groups: vec![ScimGroupRef {
            id: "g-1".into(),
            display_name: "mcp-users".into(),
        }],
    }
}

// ---------------------------------------------------------------------------
// Request helpers.
// ---------------------------------------------------------------------------

fn happy_params() -> Vec<(&'static str, &'static str)> {
    vec![
        ("grant_type", GRANT),
        ("requested_token_type", TT_ID_JAG),
        ("subject_token", "subject-token-value"),
        ("subject_token_type", TT_ACCESS),
        ("audience", RESOURCE_AS),
        ("resource", RESOURCE),
        ("client_id", CLIENT_ID),
        ("scope", "mcp:invoke mcp:read"),
    ]
}

async fn post_token(router: axum::Router<()>, params: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        ser.append_pair(k, v);
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
        .expect("token oneshot");

    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    let json: Value = serde_json::from_slice(&bytes).expect("json body");
    (status, json)
}

/// Decode a JWT's header + claims (signature not verified — these tests assert
/// the *shape* the AS mints, not that it round-trips its own key, which the
/// waygate-oidc unit tests cover).
fn jwt_header_and_claims(token: &str) -> (Value, Value) {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "ID-JAG must be a 3-segment JWS: {token}");
    let dec = |seg: &str| -> Value {
        let raw = URL_SAFE_NO_PAD.decode(seg).expect("base64url segment");
        serde_json::from_slice(&raw).expect("json segment")
    };
    (dec(parts[0]), dec(parts[1]))
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_mints_id_jag_with_audience_binding_and_intersected_scope() {
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some(CLIENT_ID),
        true,
    );
    let (status, body) = post_token(router(Some(ema)), &happy_params()).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");

    // RFC 8693 §2.2.1 response shape for an issued ID-JAG.
    assert_eq!(
        body.get("issued_token_type").and_then(Value::as_str),
        Some(TT_ID_JAG),
    );
    assert_eq!(
        body.get("token_type").and_then(Value::as_str),
        Some("N_A"),
        "an ID-JAG is not a bearer token",
    );
    assert_eq!(
        body.get("expires_in").and_then(Value::as_i64),
        Some(300),
        "expires_in tracks config.idjag_ttl",
    );
    // Scope = requested ∩ allow-list: asked for invoke+read, AS allows invoke.
    assert_eq!(
        body.get("scope").and_then(Value::as_str),
        Some("mcp:invoke"),
        "minted scope must be the intersection, never widened to the request",
    );

    let token = body
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token present");
    let (header, claims) = jwt_header_and_claims(token);

    // EMA media type — how a Resource AS tells an ID-JAG apart from a plain JWT.
    assert_eq!(
        header.get("typ").and_then(Value::as_str),
        Some("oauth-id-jag+jwt"),
    );
    // Audience binding: the ID-JAG names BOTH the Resource AS (`aud`) the client
    // will redeem it at and the concrete MCP server (`resource`) it's good for.
    assert_eq!(claims.get("aud").and_then(Value::as_str), Some(RESOURCE_AS));
    assert_eq!(
        claims.get("resource").and_then(Value::as_str),
        Some(RESOURCE),
    );
    assert_eq!(
        claims.get("client_id").and_then(Value::as_str),
        Some(CLIENT_ID),
        "the requesting client is bound into the grant",
    );
    assert_eq!(claims.get("sub").and_then(Value::as_str), Some("alice"));
}

#[tokio::test]
async fn cross_app_denial_returns_403_access_denied_and_no_token() {
    // Subject resolves fine and SCIM is active, but the Cedar policy denies.
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some(CLIENT_ID),
        false,
    );
    let (status, body) = post_token(router(Some(ema)), &happy_params()).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("access_denied")
    );
    assert!(
        body.get("access_token").is_none(),
        "a denied exchange must not mint a token",
    );
}

#[tokio::test]
async fn deactivated_scim_principal_is_denied() {
    // SCIM row present but inactive (the tombstone surfaces a
    // deprovisioned user this way). `scim_blocks_request` fails closed even
    // though the cross-app fake would allow.
    let ema = ema_deps(
        Some(principal("alice", Some(scim(false)))),
        Some(CLIENT_ID),
        true,
    );
    let (status, body) = post_token(router(Some(ema)), &happy_params()).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("access_denied")
    );
}

#[tokio::test]
async fn never_provisioned_principal_is_denied_when_require_scim() {
    // No SCIM row at all. EMA posture: an ID-JAG must prove directory
    // membership, so `idjag_require_scim` (default-on) denies even though the
    // cross-app fake would allow.
    let ema = ema_deps(Some(principal("alice", None)), Some(CLIENT_ID), true);
    let (status, body) = post_token(router(Some(ema)), &happy_params()).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("access_denied")
    );
}

#[tokio::test]
async fn invalid_subject_token_returns_400_invalid_grant() {
    // Resolver rejects the subject token.
    let ema = ema_deps(None, None, true);
    let (status, body) = post_token(router(Some(ema)), &happy_params()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_grant")
    );
}

#[tokio::test]
async fn wrong_requested_token_type_returns_400_invalid_request() {
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some(CLIENT_ID),
        true,
    );
    let mut params = happy_params();
    // Ask for a plain access token instead of an ID-JAG.
    for p in params.iter_mut() {
        if p.0 == "requested_token_type" {
            p.1 = TT_ACCESS;
        }
    }
    let (status, body) = post_token(router(Some(ema)), &params).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_request"),
    );
}

#[tokio::test]
async fn missing_audience_returns_400_invalid_request() {
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some(CLIENT_ID),
        true,
    );
    let params: Vec<(&str, &str)> = happy_params()
        .into_iter()
        .filter(|(k, _)| *k != "audience")
        .collect();
    let (status, body) = post_token(router(Some(ema)), &params).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_request"),
    );
}

#[tokio::test]
async fn grant_disabled_returns_unsupported_grant_type() {
    // `ema = None` ⇒ the token-exchange grant is not enabled on this AS.
    let (status, body) = post_token(router(None), &happy_params()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("unsupported_grant_type"),
    );
}

#[tokio::test]
async fn form_client_id_that_disagrees_with_subject_token_is_rejected() {
    // The subject token authenticates as "real-client"; the caller's form
    // asserts a DIFFERENT client (happy_params sends CLIENT_ID). The handler
    // must refuse to mint an ID-JAG bound to a client the caller didn't
    // authenticate as — and must not fall back to the form value.
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some("real-client"),
        true,
    );
    let (status, body) = post_token(router(Some(ema)), &happy_params()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_grant")
    );
    assert!(
        body.get("access_token").is_none(),
        "a spoofed client_id must not mint a token",
    );
}

#[tokio::test]
async fn subject_token_without_client_binding_is_rejected() {
    // Valid subject + active SCIM, but the subject token carries no client
    // binding (no client_id/azp). There is no authenticated client to bind
    // into the assertion, so the handler fails closed rather than trusting the
    // form client_id.
    let ema = ema_deps(Some(principal("alice", Some(scim(true)))), None, true);
    let (status, body) = post_token(router(Some(ema)), &happy_params()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_grant")
    );
}

#[tokio::test]
async fn untrusted_audience_returns_400_invalid_target() {
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some(CLIENT_ID),
        true,
    );
    let mut params = happy_params();
    for p in params.iter_mut() {
        if p.0 == "audience" {
            p.1 = "https://evil-resource-as.test";
        }
    }
    let (status, body) = post_token(router(Some(ema)), &params).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_target")
    );
    assert!(
        body.get("access_token").is_none(),
        "the AS must not sign an ID-JAG for an untrusted audience",
    );
}

#[tokio::test]
async fn unknown_resource_returns_400_invalid_target() {
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some(CLIENT_ID),
        true,
    );
    let mut params = happy_params();
    for p in params.iter_mut() {
        if p.0 == "resource" {
            p.1 = "https://mcp.test/unknown-server";
        }
    }
    let (status, body) = post_token(router(Some(ema)), &params).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("invalid_target")
    );
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn scope_is_limited_to_principal_authority() {
    // mcp:admin IS in the AS allow-list (test_config) but is NOT among the
    // subject principal's scopes (mcp:invoke, mcp:read). A request for it must
    // be dropped by the principal-derived limit, so a low-privilege subject
    // token cannot escalate to a privileged ID-JAG scope via the exchange.
    let ema = ema_deps(
        Some(principal("alice", Some(scim(true)))),
        Some(CLIENT_ID),
        true,
    );
    let mut params = happy_params();
    for p in params.iter_mut() {
        if p.0 == "scope" {
            p.1 = "mcp:invoke mcp:admin";
        }
    }
    let (status, body) = post_token(router(Some(ema)), &params).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body.get("scope").and_then(Value::as_str),
        Some("mcp:invoke"),
        "mcp:admin is allow-listed but not held by the subject — must be dropped",
    );
}
