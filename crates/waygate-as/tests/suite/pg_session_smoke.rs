//! Live Postgres smoke test for the dashboard-side OAuth session queries:
//! `OauthStore::list_active_sessions` and `revoke_by_client_sub`.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so `cargo test`
//! without a DB passes. Tests cover the three behaviours the dashboard
//! depends on:
//!
//! 1. A live refresh-token row shows up as one aggregated session.
//! 2. Two distinct `(client_id, sub)` pairs come back as two sessions
//!    with independent chain counts.
//! 3. `revoke_by_client_sub` flips every live row for a pair to
//!    `revoked_at = now()` and the session disappears from the listing.

use std::env;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_as::store::{OauthStore, RefreshToken};

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

fn live_token(client_id: &str, sub: &str, suffix: u32) -> RefreshToken {
    RefreshToken {
        token: format!("pg-smoke-{}-{suffix}", Uuid::new_v4()),
        sub: sub.to_owned(),
        email: Some(format!("{sub}@example.test")),
        groups: vec!["mcp-users".into()],
        scopes: vec!["mcp:invoke".into(), "mcp:read".into()],
        client_id: client_id.to_owned(),
        rotated_from: None,
        expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
        revoked_at: None,
        tenant_id: "default".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_and_revoke_by_client_sub_roundtrip() {
    let Some(pool) = connect().await else {
        eprintln!("skipping oauth-sessions Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let store = OauthStore::new(pool.clone());

    // Two clients, two subjects. Three live RTs total. Client A has two
    // rotation rows for the same sub (simulates an in-flight rotation
    // — the chain_count should be 2).
    let a_user = format!("pg-smoke-user-a-{}", Uuid::new_v4());
    let b_user = format!("pg-smoke-user-b-{}", Uuid::new_v4());
    let client_a = format!("https://cli-a.example/{}.json", Uuid::new_v4());
    let client_b = format!("https://cli-b.example/{}.json", Uuid::new_v4());
    let toks = vec![
        live_token(&client_a, &a_user, 1),
        live_token(&client_a, &a_user, 2),
        live_token(&client_b, &b_user, 1),
    ];
    for t in &toks {
        store.insert_refresh(t).await.expect("insert");
    }

    // 1. Both sessions show up. Use a large limit; filter by sub locally
    //    so other rows in the DB (from co-tenant smoke runs) don't break
    //    the assertion.
    let sessions = store.list_active_sessions(1024).await.expect("list");
    let a = sessions
        .iter()
        .find(|s| s.sub == a_user)
        .expect("client_a session present");
    assert_eq!(a.client_id, client_a);
    assert_eq!(a.chain_count, 2, "two live RTs for client A's user");
    assert_eq!(a.scopes, vec!["mcp:invoke".to_string(), "mcp:read".into()]);
    assert!(sessions.iter().any(|s| s.sub == b_user));

    // 2. Revoking client A's session flips both A-rows; client B unaffected.
    let revoked = store
        .revoke_by_client_sub(&client_a, &a_user)
        .await
        .expect("revoke");
    assert_eq!(revoked, 2, "revoke flips both live A rows");

    let after = store
        .list_active_sessions(1024)
        .await
        .expect("list-after-revoke");
    assert!(
        !after.iter().any(|s| s.sub == a_user),
        "client A session must vanish post-revoke",
    );
    assert!(
        after.iter().any(|s| s.sub == b_user),
        "client B session must still be there",
    );

    // 3. Cleanup — leave the table tidy.
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE sub IN ($1, $2)")
        .bind(&a_user)
        .bind(&b_user)
        .execute(&pool)
        .await
        .expect("cleanup");
}

/// Regression: pin that rotate_refresh preserves a
/// non-default tenant_id onto the successor row.
/// `rotate_refresh`'s successor INSERT is separate from the
/// regular insert path and must bind tenant_id explicitly —
/// otherwise the row silently resets to 'default' via the
/// migration-0010 column default, and every subsequent
/// access token for that chain would then carry
/// `tenant=default` even though the original auth-code
/// chain was minted for, e.g., tenant=acme.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_refresh_preserves_non_default_tenant() {
    let Some(pool) = connect().await else {
        eprintln!("skipping rotate_refresh tenant smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let store = OauthStore::new(pool.clone());

    // Seed a tenant row so the FK on oauth_consent /
    // tenants stays valid for any co-tenant smoke; the
    // refresh table itself has no FK but a real tenant id
    // is what production would emit.
    let tenant_id = format!("pg-rot-tenant-{}", Uuid::new_v4());
    sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .expect("seed tenant");

    let sub = format!("pg-rot-user-{}", Uuid::new_v4());
    let client_id = format!("https://cli.example/{}.json", Uuid::new_v4());

    // Predecessor row carries the non-default tenant.
    let predecessor_token = format!("pred-{}", Uuid::new_v4());
    let mut predecessor = live_token(&client_id, &sub, 1);
    predecessor.token = predecessor_token.clone();
    predecessor.tenant_id = tenant_id.clone();
    store
        .insert_refresh(&predecessor)
        .await
        .expect("insert pred");

    // Build the successor as the AS would
    // (token.rs::handle_refresh) — same tenant copied
    // forward from the predecessor.
    let mut successor = live_token(&client_id, &sub, 2);
    successor.token = format!("succ-{}", Uuid::new_v4());
    successor.rotated_from = Some(predecessor_token.clone());
    successor.tenant_id = tenant_id.clone();

    let won = store
        .rotate_refresh(&predecessor_token, &successor)
        .await
        .expect("rotate");
    assert!(won, "rotate_refresh must succeed against live predecessor");

    // Read back: the inserted-by-rotation row must carry
    // the original tenant_id, NOT silently fall back to
    // 'default'.
    let after = store
        .find_refresh(&successor.token)
        .await
        .expect("find_refresh")
        .expect("row must exist after rotation");
    assert_eq!(
        after.tenant_id, tenant_id,
        "rotation must preserve tenant_id — otherwise the next access token \
         mint would re-hydrate Principal.tenant as 'default' and a non-default \
         tenant admin would silently shift to default-tenant authority",
    );

    // Cleanup.
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE sub = $1")
        .bind(&sub)
        .execute(&pool)
        .await
        .expect("cleanup rt");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .expect("cleanup tenant");
}
