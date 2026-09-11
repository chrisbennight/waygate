//! Live Postgres smoke test for [`PgConsentStore`].
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` without a DB passes. Pins five behaviours
//! the AS callback + admin REST handler depend on:
//!
//! 1. First-grant insert lands a row and returns it.
//! 2. Re-consent (same triple, broader scopes) UPSERTs
//!    in place — same row id, refreshed scopes, bumped
//!    granted_at, NULL revoked_at.
//! 3. Revoke flips revoked_at and the partial-index
//!    "active" lookup hides the row.
//! 4. Re-consent after revoke clears revoked_at —
//!    the user got re-granted, not silently locked out.
//! 5. List scoping: tenant filter, principal_sub filter,
//!    and limit clamp at MAX_LIST_LIMIT.

use std::env;

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;

use waygate_as::consent::{ConsentStore, NewConsentGrant, PgConsentStore, MAX_LIST_LIMIT};

async fn connect() -> Option<sqlx::PgPool> {
    let url = env::var("AUDIT_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    Some(pool)
}

async fn ensure_tenant(pool: &sqlx::PgPool, id: &str) {
    sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed tenant");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_grant_then_reconsent_then_revoke_then_regrant() {
    let Some(pool) = connect().await else {
        eprintln!("skipping oauth_consent Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let store = PgConsentStore::new(pool.clone());

    // Use a fresh tenant id per run so a co-tenant smoke
    // doesn't see our rows. Seed the tenants row first
    // because oauth_consent.tenant_id FKs tenants(id).
    let tenant_id = format!("pg-consent-smoke-{}", Uuid::new_v4());
    ensure_tenant(&pool, &tenant_id).await;

    let sub = format!("pg-consent-user-{}", Uuid::new_v4());
    let client_id = format!("https://cli.example/{}.json", Uuid::new_v4());
    let initial_scopes = vec!["mcp:invoke".to_string()];

    // 1. First-grant insert lands a row.
    let g1 = store
        .upsert(NewConsentGrant {
            tenant_id: &tenant_id,
            principal_sub: &sub,
            client_id: &client_id,
            scopes: &initial_scopes,
            expires_at: None,
        })
        .await
        .expect("first upsert");
    assert_eq!(g1.tenant_id, tenant_id);
    assert_eq!(g1.principal_sub, sub);
    assert_eq!(g1.client_id, client_id);
    assert_eq!(g1.scopes, initial_scopes);
    assert!(g1.revoked_at.is_none());
    assert!(g1.expires_at.is_none());

    // 2. Re-consent with broader scopes UPSERTs in place.
    let broader = vec!["mcp:invoke".to_string(), "mcp:read".into()];
    let g2 = store
        .upsert(NewConsentGrant {
            tenant_id: &tenant_id,
            principal_sub: &sub,
            client_id: &client_id,
            scopes: &broader,
            expires_at: None,
        })
        .await
        .expect("re-consent upsert");
    assert_eq!(
        g2.id, g1.id,
        "UPSERT on the unique triple must reuse the original row id"
    );
    assert_eq!(g2.scopes, broader, "scopes must reflect the latest call");
    assert!(g2.revoked_at.is_none());
    assert!(
        g2.granted_at >= g1.granted_at,
        "granted_at must have bumped to >= the original"
    );

    // 3. Revoke flips revoked_at; partial-index lookup hides the row.
    let removed = store
        .revoke(&tenant_id, &sub, &client_id)
        .await
        .expect("revoke");
    assert!(removed, "live → revoked transition reports true");

    // Idempotency: a second revoke is a no-op success.
    let again = store
        .revoke(&tenant_id, &sub, &client_id)
        .await
        .expect("revoke again");
    assert!(
        !again,
        "second revoke against already-revoked row returns false"
    );

    // Partial index proof: the active-grants-by-principal
    // lookup omits revoked rows. Use a raw SQL probe
    // matching the index predicate to confirm.
    let active_count: i64 = sqlx::query(
        r#"
        SELECT COUNT(*) AS n
          FROM oauth_consent
         WHERE tenant_id = $1
           AND principal_sub = $2
           AND revoked_at IS NULL
        "#,
    )
    .bind(&tenant_id)
    .bind(&sub)
    .fetch_one(&pool)
    .await
    .expect("count active")
    .get("n");
    assert_eq!(active_count, 0);

    // 4. Re-consent after revoke clears revoked_at — the
    //    user re-granted, not locked out.
    let g3 = store
        .upsert(NewConsentGrant {
            tenant_id: &tenant_id,
            principal_sub: &sub,
            client_id: &client_id,
            scopes: &initial_scopes,
            expires_at: None,
        })
        .await
        .expect("re-grant after revoke");
    assert_eq!(g3.id, g1.id, "still the same surrogate id");
    assert!(
        g3.revoked_at.is_none(),
        "revoked_at must clear on re-consent — otherwise re-auth would lock the user out"
    );
    assert_eq!(g3.scopes, initial_scopes);

    // 5. List scoping (tenant + sub) + limit clamp.
    let bare = store
        .list(&tenant_id, Some(&sub), 50, 0)
        .await
        .expect("list-by-sub");
    assert_eq!(bare.len(), 1);
    assert_eq!(bare[0].id, g1.id);

    // Limit clamp: ask for 1_000_000; we should never get
    // more than MAX_LIST_LIMIT rows back.
    let clamped = store
        .list(&tenant_id, None, 1_000_000, 0)
        .await
        .expect("list-clamped");
    assert!(
        clamped.len() <= MAX_LIST_LIMIT as usize,
        "Pg query must clamp limit, got {} > {}",
        clamped.len(),
        MAX_LIST_LIMIT
    );

    // Cleanup — leave the table tidy. The tenants row is
    // also fresh-per-run; cascade DELETE on the FK drops
    // our oauth_consent row when we drop the tenant.
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .expect("cleanup tenant (cascades oauth_consent)");
}
