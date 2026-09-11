//! End-to-end OAuth flow against a live Postgres.
//!
//! Drives the `/oauth/token` axum handler with a seeded `oauth_codes` row
//! (simulating what `/oauth/callback` would have persisted) and then
//! exercises refresh rotation + replay detection. Uses the real
//! [`waygate_as::build_router`], [`OauthStore`], and [`IdentityIssuer`] —
//! the only thing stubbed is the upstream Authentik hop (never touched by
//! `/oauth/token`).
//!
//! Skips cleanly when `GATEWAY_AS_DATABASE_URL` is unset so `cargo test`
//! passes on a machine without a database.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use time::{Duration as TimeDuration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

use waygate_as::store::{IssuedCode, OauthStore, RefreshToken};
use waygate_as::{build_router, AsConfig, UpstreamCrypto};
use waygate_oidc::{BearerValidator, IdTokenValidator, IdentityIssuer, JwksProvider};

const ISSUER: &str = "https://mcp.test";
const AUDIENCE: &str = "https://mcp.test/mcp";
const CLIENT_ID: &str = "https://cli.test/claude.json";
const CLIENT_REDIRECT: &str = "http://localhost:54321/callback";

/// Connect, migrate, and return both pool and a per-test suffix that's
/// stamped into every token/code the test inserts. The suffix keeps rows
/// from parallel test runs isolated and makes post-test cleanup trivial.
async fn connect() -> Option<(PgPool, String)> {
    let pool = waygate_test_support::pg::pool_or_skip("GATEWAY_AS_DATABASE_URL").await?;
    let suffix = Uuid::now_v7().simple().to_string();
    Some((pool, suffix))
}

async fn cleanup(pool: &PgPool, suffix: &str) {
    // Prefix-match on every token column we might have inserted into.
    let pat = format!("%{suffix}");
    let _ = sqlx::query("DELETE FROM oauth_codes WHERE code LIKE $1")
        .bind(&pat)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM oauth_refresh_tokens WHERE token LIKE $1")
        .bind(&pat)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM oauth_transactions WHERE txn_id LIKE $1")
        .bind(&pat)
        .execute(pool)
        .await;
}

/// Empty-JWKS id_token validator. The `/oauth/token` tests never drive
/// `/oauth/callback`, so the validator is only present to satisfy the
/// router signature — it never gets invoked.
fn test_id_validator() -> Arc<IdTokenValidator> {
    let jwks = Arc::new(
        JwksProvider::from_preloaded(ISSUER, r#"{"keys":[]}"#).expect("preload empty jwks"),
    );
    Arc::new(IdTokenValidator::new(jwks, ISSUER, CLIENT_ID))
}

fn test_issuer() -> IdentityIssuer {
    let sk = SigningKey::from_bytes(&[23u8; 32]);
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

fn test_config() -> AsConfig {
    AsConfig {
        public_url: ISSUER.into(),
        audience: AUDIENCE.into(),
        upstream_issuer: "https://auth.test".into(),
        upstream_authorize_endpoint: "https://auth.test/authorize".into(),
        upstream_token_endpoint: "https://auth.test/token".into(),
        upstream_client_id: "gateway-client".into(),
        upstream_client_secret: "unused-in-this-test".into(),
        upstream_redirect_uri: "https://mcp.test/oauth/callback".into(),
        upstream_scopes: vec!["openid".into(), "profile".into(), "email".into()],
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
        idjag_allowed_audiences: vec![],
        idjag_known_resources: vec![],
        idjag_trusted_issuers: vec![],
        idjag_advertise: false,
    }
}

fn pkce_pair(verifier: &str) -> (String, String) {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier.to_owned(), challenge)
}

fn seeded_code(suffix: &str, code_challenge: &str, expires_at: OffsetDateTime) -> IssuedCode {
    IssuedCode {
        code: format!("testcode-{suffix}"),
        client_id: CLIENT_ID.into(),
        redirect_uri: CLIENT_REDIRECT.into(),
        code_challenge: code_challenge.to_owned(),
        scopes: vec!["mcp:invoke".into(), "mcp:read".into()],
        sub: "user-42".into(),
        email: Some("u@test".into()),
        groups: vec!["mcp-users".into()],
        upstream_tokens_ciphertext: None,
        expires_at,
        tenant_id: "default".into(),
    }
}

async fn post_token(
    router: &axum::Router<()>,
    form: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let body = form
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencoding(v)))
        .collect::<Vec<_>>()
        .join("&");
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, value)
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn validator_for(issuer: &IdentityIssuer) -> BearerValidator {
    let jwks_json = serde_json::to_string(&issuer.jwks()).unwrap();
    let jwks = Arc::new(JwksProvider::from_preloaded(ISSUER, &jwks_json).unwrap());
    BearerValidator::new(jwks, ISSUER, AUDIENCE)
}

#[tokio::test]
async fn authorization_code_grant_mints_validatable_jwt() {
    let Some((pool, suffix)) = connect().await else {
        eprintln!("skipping: GATEWAY_AS_DATABASE_URL not set");
        return;
    };
    let store = OauthStore::new(pool.clone());
    let issuer = Arc::new(test_issuer());
    let router = build_router(
        test_config(),
        pool.clone(),
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        issuer.clone(),
        test_id_validator(),
        Arc::new(waygate_evidence::audit::NullSink),
        None,
    );

    let (verifier, challenge) = pkce_pair("verifier-abcdef1234567890-a-long-enough-string");
    let code = seeded_code(
        &suffix,
        &challenge,
        OffsetDateTime::now_utc() + TimeDuration::seconds(60),
    );
    store.insert_code(&code).await.expect("seed code");

    let (status, body) = post_token(
        &router,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code.code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", CLIENT_ID),
            ("code_verifier", &verifier),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body = {body:?}");
    let access = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let refresh = body["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "mcp:invoke mcp:read");

    // The minted JWT must round-trip through the resource-server validator —
    // this is the full "token factory" contract end-to-end.
    let v = validator_for(&issuer).await;
    let principal = v
        .validate(&access)
        .await
        .expect("gateway JWT must validate");
    assert_eq!(principal.sub, "user-42");
    assert!(principal.has_scope("mcp:invoke"));
    assert!(principal.has_scope("mcp:read"));

    // Refresh token written to store with no revocation stamp.
    let stored = store.find_refresh(&refresh).await.unwrap().unwrap();
    assert!(stored.revoked_at.is_none());
    assert_eq!(stored.sub, "user-42");
    assert_eq!(stored.client_id, CLIENT_ID);

    // Double-spend: the code was consumed, a second /oauth/token with the
    // same code must fail.
    let (status2, body2) = post_token(
        &router,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code.code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", CLIENT_ID),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(status2, StatusCode::BAD_REQUEST);
    assert_eq!(body2["error"], "invalid_grant");

    cleanup(&pool, &suffix).await;
}

#[tokio::test]
async fn authorization_code_rejects_pkce_mismatch() {
    let Some((pool, suffix)) = connect().await else {
        return;
    };
    let store = OauthStore::new(pool.clone());
    let router = build_router(
        test_config(),
        pool.clone(),
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        Arc::new(test_issuer()),
        test_id_validator(),
        Arc::new(waygate_evidence::audit::NullSink),
        None,
    );

    let (_v, challenge) = pkce_pair("the-right-verifier-at-least-43-chars-of-padding");
    let code = seeded_code(
        &suffix,
        &challenge,
        OffsetDateTime::now_utc() + TimeDuration::seconds(60),
    );
    store.insert_code(&code).await.unwrap();

    let (status, body) = post_token(
        &router,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code.code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", CLIENT_ID),
            (
                "code_verifier",
                "a-completely-different-verifier-that-wont-match",
            ),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    cleanup(&pool, &suffix).await;
}

#[tokio::test]
async fn authorization_code_rejects_redirect_uri_mismatch() {
    let Some((pool, suffix)) = connect().await else {
        return;
    };
    let store = OauthStore::new(pool.clone());
    let router = build_router(
        test_config(),
        pool.clone(),
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        Arc::new(test_issuer()),
        test_id_validator(),
        Arc::new(waygate_evidence::audit::NullSink),
        None,
    );

    let (verifier, challenge) = pkce_pair("verifier-xyz-more-than-43-chars-padding-here");
    let code = seeded_code(
        &suffix,
        &challenge,
        OffsetDateTime::now_utc() + TimeDuration::seconds(60),
    );
    store.insert_code(&code).await.unwrap();

    let (status, body) = post_token(
        &router,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code.code),
            ("redirect_uri", "http://localhost:9/evil"),
            ("client_id", CLIENT_ID),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    cleanup(&pool, &suffix).await;
}

#[tokio::test]
async fn authorization_code_rejects_expired_code() {
    let Some((pool, suffix)) = connect().await else {
        return;
    };
    let store = OauthStore::new(pool.clone());
    let router = build_router(
        test_config(),
        pool.clone(),
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        Arc::new(test_issuer()),
        test_id_validator(),
        Arc::new(waygate_evidence::audit::NullSink),
        None,
    );

    let (verifier, challenge) = pkce_pair("verifier-xyz-more-than-43-chars-padding-here");
    // Expiry already past — `take_code` filters on `expires_at > now()`.
    let code = seeded_code(
        &suffix,
        &challenge,
        OffsetDateTime::now_utc() - TimeDuration::seconds(5),
    );
    store.insert_code(&code).await.unwrap();

    let (status, body) = post_token(
        &router,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code.code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", CLIENT_ID),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    cleanup(&pool, &suffix).await;
}

#[tokio::test]
async fn refresh_grant_rotates_and_detects_replay() {
    let Some((pool, suffix)) = connect().await else {
        return;
    };
    let store = OauthStore::new(pool.clone());
    let issuer = Arc::new(test_issuer());
    let router = build_router(
        test_config(),
        pool.clone(),
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        issuer.clone(),
        test_id_validator(),
        Arc::new(waygate_evidence::audit::NullSink),
        None,
    );

    // Seed an initial refresh row directly (simulates what /oauth/token would
    // have persisted on the original authorization_code grant).
    let original_token = format!("orig-{suffix}");
    let rt = RefreshToken {
        token: original_token.clone(),
        sub: "user-42".into(),
        email: Some("u@test".into()),
        groups: vec!["mcp-users".into()],
        scopes: vec!["mcp:invoke".into()],
        client_id: CLIENT_ID.into(),
        rotated_from: None,
        expires_at: OffsetDateTime::now_utc() + TimeDuration::days(30),
        revoked_at: None,
        tenant_id: "default".into(),
    };
    store.insert_refresh(&rt).await.unwrap();

    // First refresh → new access + new refresh, old refresh revoked.
    let (status, body) = post_token(
        &router,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &original_token),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body = {body:?}");
    let rotated_token = body["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(rotated_token, original_token, "refresh must rotate");

    let v = validator_for(&issuer).await;
    v.validate(body["access_token"].as_str().unwrap())
        .await
        .expect("rotated access token must validate");

    let prev = store.find_refresh(&original_token).await.unwrap().unwrap();
    assert!(
        prev.revoked_at.is_some(),
        "previous refresh must be revoked"
    );
    let new = store.find_refresh(&rotated_token).await.unwrap().unwrap();
    assert!(new.revoked_at.is_none());
    assert_eq!(new.rotated_from.as_deref(), Some(original_token.as_str()));

    // Replay detection: present the *original* (already-rotated) token.
    // RFC 6749 §10.4 treats this as a theft signal — the whole chain must
    // be revoked.
    let (status_replay, body_replay) = post_token(
        &router,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &original_token),
        ],
    )
    .await;
    assert_eq!(status_replay, StatusCode::BAD_REQUEST);
    assert_eq!(body_replay["error"], "invalid_grant");

    // Rotated descendant must now also be revoked.
    let descendant = store.find_refresh(&rotated_token).await.unwrap().unwrap();
    assert!(
        descendant.revoked_at.is_some(),
        "replay must revoke the rotated descendant"
    );

    cleanup(&pool, &suffix).await;
}

#[tokio::test]
async fn concurrent_refresh_rotates_exactly_once() {
    // Two simultaneous `/oauth/token` refresh requests for the same
    // live token must NOT both mint successor tokens — that would
    // defeat single-use rotation (RFC 6749 §10.4). The atomic
    // `revoke_refresh` + rows-affected check is what serializes the
    // winner.
    let Some((pool, suffix)) = connect().await else {
        return;
    };
    let store = OauthStore::new(pool.clone());
    let issuer = Arc::new(test_issuer());
    let router = build_router(
        test_config(),
        pool.clone(),
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        issuer.clone(),
        test_id_validator(),
        Arc::new(waygate_evidence::audit::NullSink),
        None,
    );

    let original_token = format!("concurrent-{suffix}");
    let rt = RefreshToken {
        token: original_token.clone(),
        sub: "user-42".into(),
        email: Some("u@test".into()),
        groups: vec!["mcp-users".into()],
        scopes: vec!["mcp:invoke".into()],
        client_id: CLIENT_ID.into(),
        rotated_from: None,
        expires_at: OffsetDateTime::now_utc() + TimeDuration::days(30),
        revoked_at: None,
        tenant_id: "default".into(),
    };
    store.insert_refresh(&rt).await.unwrap();

    let r1 = router.clone();
    let r2 = router.clone();
    let tok1 = original_token.clone();
    let tok2 = original_token.clone();
    let (first, second) = tokio::join!(
        async move {
            post_token(
                &r1,
                &[("grant_type", "refresh_token"), ("refresh_token", &tok1)],
            )
            .await
        },
        async move {
            post_token(
                &r2,
                &[("grant_type", "refresh_token"), ("refresh_token", &tok2)],
            )
            .await
        },
    );

    let statuses = [first.0, second.0];
    let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let bad_count = statuses
        .iter()
        .filter(|s| **s == StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(
        ok_count, 1,
        "exactly one request must succeed, got statuses {statuses:?}"
    );
    assert_eq!(
        bad_count, 1,
        "exactly one request must fail, got statuses {statuses:?}"
    );

    // The losing body must be `invalid_grant` — not a 500, not a
    // partially-rotated state.
    let losing_body = if first.0 == StatusCode::BAD_REQUEST {
        &first.1
    } else {
        &second.1
    };
    assert_eq!(losing_body["error"], "invalid_grant");

    // Exactly one successor row exists with `rotated_from = original`.
    let successors: i64 =
        sqlx::query_scalar(r#"SELECT COUNT(*) FROM oauth_refresh_tokens WHERE rotated_from = $1"#)
            .bind(&original_token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        successors, 1,
        "concurrent refreshes must produce exactly one successor row"
    );

    // And the original is revoked.
    let original = store.find_refresh(&original_token).await.unwrap().unwrap();
    assert!(original.revoked_at.is_some(), "original must be revoked");

    // Cleanup includes the successor row (whatever token value it chose),
    // since they all share our test suffix via the issued `new_random_token`
    // path — use a tailored delete that cleans the chain instead of LIKE.
    let _ =
        sqlx::query(r#"DELETE FROM oauth_refresh_tokens WHERE token = $1 OR rotated_from = $1"#)
            .bind(&original_token)
            .execute(&pool)
            .await;
    cleanup(&pool, &suffix).await;
}

#[tokio::test]
async fn refresh_grant_rejects_unknown_token() {
    let Some((pool, suffix)) = connect().await else {
        return;
    };
    let router = build_router(
        test_config(),
        pool.clone(),
        waygate_core::http_client::client(waygate_core::http_client::Profile::Standard).unwrap(),
        Arc::new(test_issuer()),
        test_id_validator(),
        Arc::new(waygate_evidence::audit::NullSink),
        None,
    );

    let (status, body) = post_token(
        &router,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", "never-issued-this"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    cleanup(&pool, &suffix).await;
}

#[tokio::test]
async fn sweep_expired_clears_stale_rows() {
    let Some((pool, suffix)) = connect().await else {
        return;
    };
    let store = OauthStore::new(pool.clone());

    // Expired code + live code — sweeper must take only the expired one.
    let expired_code = seeded_code(
        &format!("expired-{suffix}"),
        "chal-does-not-matter",
        OffsetDateTime::now_utc() - TimeDuration::seconds(30),
    );
    let live_code = seeded_code(
        &format!("live-{suffix}"),
        "chal-does-not-matter",
        OffsetDateTime::now_utc() + TimeDuration::seconds(60),
    );
    store.insert_code(&expired_code).await.unwrap();
    store.insert_code(&live_code).await.unwrap();

    // Same contract for refresh tokens: the sweeper must also clear
    // expired refresh rows, not just codes + transactions, or a
    // revoked-and-expired refresh row would pile up forever.
    let expired_refresh = RefreshToken {
        token: format!("rt-expired-{suffix}"),
        sub: "user-42".into(),
        email: None,
        groups: vec![],
        scopes: vec!["mcp:invoke".into()],
        client_id: CLIENT_ID.into(),
        rotated_from: None,
        expires_at: OffsetDateTime::now_utc() - TimeDuration::seconds(30),
        revoked_at: None,
        tenant_id: "default".into(),
    };
    let live_refresh = RefreshToken {
        token: format!("rt-live-{suffix}"),
        expires_at: OffsetDateTime::now_utc() + TimeDuration::seconds(3600),
        ..expired_refresh.clone()
    };
    store.insert_refresh(&expired_refresh).await.unwrap();
    store.insert_refresh(&live_refresh).await.unwrap();

    // `sweep_expired()` is a GLOBAL delete (every expired row in the DB), so on
    // a shared test DB a concurrently-running test's own expired rows can be
    // caught by this sweep too — assert it took AT LEAST ours (>= 1), not
    // exactly one (which flaked under parallel *_pg execution against one DB).
    // The per-row checks below carry the precise contract: OUR expired rows are
    // gone and OUR live rows survive.
    let counts = store.sweep_expired().await.unwrap();
    assert!(
        counts.codes >= 1,
        "the sweep must take our expired code row"
    );
    assert!(
        counts.refresh_tokens >= 1,
        "the sweep must take our expired refresh row",
    );

    // Expired gone, live present — for both tables.
    assert!(store.take_code(&expired_code.code).await.unwrap().is_none());
    assert!(store.take_code(&live_code.code).await.unwrap().is_some());
    assert!(store
        .find_refresh(&expired_refresh.token)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .find_refresh(&live_refresh.token)
        .await
        .unwrap()
        .is_some());

    cleanup(&pool, &suffix).await;
}
