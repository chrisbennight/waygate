//! Live Postgres smoke for `PgScimResolver`.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so `cargo test`
//! on a laptop without a DB passes without special-casing.
//!
//! The unit tests in `enricher.rs` cover the cache + best-effort
//! semantics with a fake resolver; this file exercises the SQL itself
//! against a real Postgres so a regression in:
//!
//! - the migration 0019/0020 schema (column names, indexes), or
//! - the resolver's UNION query that detects ambiguity,
//!
//! trips the test rather than passing silently. Specifically pins
//! that the `external_id` / `user_name`
//! ambiguity detection refuses to enrich when one row's `external_id`
//! matches another row's `user_name`.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_oidc::PrincipalEnricher;
use waygate_scim::{PgScimEnricher, ScimResolveError, ScimResolver};

#[tokio::test]
async fn ambiguous_match_returns_err_ambiguous() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    // Use a unique tenant per test run so concurrent test runs don't
    // race on the same rows. Test cleans up at the end.
    let tenant = format!("test-amb-{}", Uuid::new_v4());
    let collide = format!("collide-{}", Uuid::new_v4());

    // Row X: external_id = "<collide>" (and a different user_name).
    let x_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scim_users (id, tenant_id, external_id, user_name, active, attrs)
        VALUES ($1, $2, $3, $4, true, '{}')
        "#,
    )
    .bind(x_id)
    .bind(&tenant)
    .bind(&collide)
    .bind(format!("user-x-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("insert row X");

    // Row Y: user_name = "<collide>" (and a different external_id).
    let y_id = Uuid::new_v4();
    let y_ext = format!("y-ext-{}", Uuid::new_v4());
    sqlx::query(
        r#"
        INSERT INTO scim_users (id, tenant_id, external_id, user_name, active, attrs)
        VALUES ($1, $2, $3, $4, true, '{}')
        "#,
    )
    .bind(y_id)
    .bind(&tenant)
    .bind(&y_ext)
    .bind(&collide)
    .execute(&pool)
    .await
    .expect("insert row Y");

    let resolver = waygate_scim::PgScimResolver::new(pool.clone());
    // The resolver surfaces ambiguity as
    // `Err(ScimResolveError::Ambiguous)`
    // — NOT `Ok(None)` — so the enricher can mark the
    // principal `enrichment_blocked` and the bearer middleware
    // 403s the request. A test that called `.expect(...)` on
    // the Result would panic before its assertions and the
    // "AUDIT_DATABASE_URL set" smoke path would mask the real
    // contract.
    match resolver.resolve(&tenant, &collide).await {
        Err(ScimResolveError::Ambiguous {
            tenant: t,
            sub: s,
            rows,
        }) => {
            assert_eq!(t, tenant);
            assert_eq!(s, collide);
            assert!(
                rows.len() >= 2,
                "ambiguous error must enumerate at least the two conflicting row ids; got {rows:?}",
            );
            assert!(
                rows.contains(&x_id) && rows.contains(&y_id),
                "ambiguous error must include both conflicting row ids X and Y; got {rows:?}",
            );
        }
        Err(other) => panic!(
            "ambiguous match must return ScimResolveError::Ambiguous, got store-error: {other:?}",
        ),
        Ok(other) => {
            panic!("ambiguous match must NOT return Ok (fail-CLOSED, not fail-open); got {other:?}",)
        }
    }

    // Sanity: unique-by-external-id resolves to that row.
    let only_ext = format!("only-ext-{}", Uuid::new_v4());
    let only_ext_user = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scim_users (id, tenant_id, external_id, user_name, active, attrs)
        VALUES ($1, $2, $3, $4, true, '{}')
        "#,
    )
    .bind(only_ext_user)
    .bind(&tenant)
    .bind(&only_ext)
    .bind(format!("unique-uname-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("insert single-row case");
    let single = resolver
        .resolve(&tenant, &only_ext)
        .await
        .expect("resolve single-row");
    let single = single.expect("single ext_id hit must resolve");
    assert_eq!(single.user_id, only_ext_user);

    // Sanity: same-row both-column match (external_id == user_name)
    // returns exactly that row, not ambiguity.
    let twin = format!("twin-{}", Uuid::new_v4());
    let twin_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scim_users (id, tenant_id, external_id, user_name, active, attrs)
        VALUES ($1, $2, $3, $3, true, '{}')
        "#,
    )
    .bind(twin_id)
    .bind(&tenant)
    .bind(&twin)
    .execute(&pool)
    .await
    .expect("insert twin row");
    let twin_resolved = resolver
        .resolve(&tenant, &twin)
        .await
        .expect("resolve twin");
    let twin_resolved = twin_resolved.expect("twin row must resolve, not be treated as ambiguous");
    assert_eq!(twin_resolved.user_id, twin_id);

    // Cleanup so the next test run isn't polluted with our rows.
    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup tenant rows");
}

/// `PgScimEnricher` builds on the resolver; smoke that the
/// ambiguity path also surfaces through the public enricher API
/// (best-effort: enricher returns the principal unchanged).
#[tokio::test]
async fn enricher_handles_ambiguity_as_no_enrichment() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let tenant = format!("test-enr-amb-{}", Uuid::new_v4());
    let collide = format!("collide-{}", Uuid::new_v4());
    let x_id = Uuid::new_v4();
    let y_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scim_users (id, tenant_id, external_id, user_name, active, attrs) VALUES
            ($1, $2, $3, $4, true, '{}'),
            ($5, $2, $6, $3, true, '{}')
        "#,
    )
    .bind(x_id)
    .bind(&tenant)
    .bind(&collide)
    .bind(format!("user-x-{}", Uuid::new_v4()))
    .bind(y_id)
    .bind(format!("ext-y-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("insert ambiguous pair");

    let enricher = PgScimEnricher::new(pool.clone());
    let p = waygate_oidc::Principal {
        sub: collide.clone(),
        email: None,
        groups: vec![],
        issuer: "https://idp.test/".into(),
        scopes: vec![],
        tenant: waygate_core::TenantId::parse(&tenant).expect("tenant parse"),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
        roles: vec![],
    };
    let enriched = enricher.enrich(p).await;
    // Ambiguity is fail-CLOSED, NOT fail-open.
    // A "leave scim=None" shape would be a fail-open bug because
    // the active-check only fires when scim is Some. Instead,
    // ambiguity surfaces through `enrichment_blocked` so the
    // bearer middleware 403s the request.
    assert!(
        enriched.scim.is_none(),
        "ambiguous SCIM match must still leave Principal.scim == None (no row attached)",
    );
    assert!(
        enriched.enrichment_blocked.is_some(),
        "ambiguous SCIM match must set Principal.enrichment_blocked so the bearer middleware 403s",
    );
    let reason = enriched.enrichment_blocked.as_deref().unwrap();
    assert!(
        reason.starts_with("scim_ambiguous_match"),
        "block reason must identify the ambiguity (got `{reason}`)",
    );
    assert!(
        enriched.scim_blocks_request(),
        "scim_blocks_request() must agree the request is blocked",
    );

    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}
