//! End-to-end tenant-enforcement smoke against real
//! Postgres. Validates that `PgTenantEnricher` correctly
//! transitions a principal across the three lookup outcomes
//! (active / suspended / missing) when wired to a real
//! `PgTenantResolver` over the migrated schema.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` on a laptop without a DB passes. Same pattern
//! as `waygate-rbac::tests::pg_composite_fk_smoke` and
//! `waygate-tenants::tests::pg_backfill_smoke`.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use waygate_core::TenantId;
use waygate_oidc::{AuthMethod, Principal, PrincipalEnricher};
use waygate_tenants::PgTenantEnricher;

fn principal(tenant: &str) -> Principal {
    Principal {
        sub: format!("alice-{}", Uuid::new_v4()),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: vec![],
        tenant: TenantId::parse(tenant).unwrap_or_default(),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
        roles: vec![],
    }
}

#[tokio::test]
async fn enricher_transitions_principal_across_active_suspended_missing() {
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

    let active_id = format!("test-tenants-active-{}", Uuid::new_v4());
    let suspended_id = format!("test-tenants-suspended-{}", Uuid::new_v4());
    let missing_id = format!("test-tenants-missing-{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO tenants (id, display_name, status) VALUES ($1, $1, 'active'), ($2, $2, 'suspended')",
    )
    .bind(&active_id)
    .bind(&suspended_id)
    .execute(&pool)
    .await
    .expect("seed tenants");

    // Use a short cache TTL so the suspend-then-invalidate test
    // below is robust to wallclock skew without sleeping the
    // whole TTL window.
    let enricher = Arc::new(PgTenantEnricher::new(pool.clone()));

    let out_active = enricher.enrich(principal(&active_id)).await;
    assert!(
        out_active.enrichment_blocked.is_none(),
        "active tenant must pass through unchanged",
    );

    let out_suspended = enricher.enrich(principal(&suspended_id)).await;
    assert_eq!(
        out_suspended.enrichment_blocked.as_deref(),
        Some("tenant_suspended"),
    );

    let out_missing = enricher.enrich(principal(&missing_id)).await;
    assert_eq!(
        out_missing.enrichment_blocked.as_deref(),
        Some("tenant_not_found"),
    );

    // Suspend the active tenant via SQL (operator-edit path),
    // invalidate the cache, and confirm the next enrich sees
    // the new state.
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(&active_id)
        .execute(&pool)
        .await
        .expect("flip to suspended");
    enricher.invalidate(&active_id).await;
    let out_after_suspend = enricher.enrich(principal(&active_id)).await;
    assert_eq!(
        out_after_suspend.enrichment_blocked.as_deref(),
        Some("tenant_suspended"),
        "invalidate(id) followed by an enrich must re-fetch and see the new status",
    );

    // The seeded `default` tenant must always resolve as
    // active. This is the back-compat pin: single-tenant
    // deployments rely on it; if migration 0024's seed ever
    // drifts, this test fails loudly. Use a fresh enricher to
    // bypass any cached state from earlier in this test.
    let fresh = PgTenantEnricher::new_with_resolver(
        Arc::new(waygate_tenants::PgTenantResolver::new(pool.clone())),
        Duration::from_secs(60),
        100,
    );
    let out_default = fresh.enrich(principal("default")).await;
    assert!(
        out_default.enrichment_blocked.is_none(),
        "default tenant must be seeded as active",
    );

    // Regression: prove the
    // missing→active transition works once create_tenant
    // invalidates. Cache a `Missing` for a fresh id, INSERT
    // the tenant via SQL (simulating the admin handler's
    // store.create), invalidate, then re-enrich and confirm
    // the result is now Active. Without the invalidation,
    // the operator's POST /api/v1/admin/tenants would
    // leave this principal denied until the 60s TTL.
    let just_created = format!("test-tenants-justcreated-{}", Uuid::new_v4());
    let blocked = fresh.enrich(principal(&just_created)).await;
    assert_eq!(
        blocked.enrichment_blocked.as_deref(),
        Some("tenant_not_found"),
    );
    sqlx::query("INSERT INTO tenants (id, display_name, status) VALUES ($1, $1, 'active')")
        .bind(&just_created)
        .execute(&pool)
        .await
        .expect("insert just-created tenant");
    fresh.invalidate(&just_created).await;
    let after = fresh.enrich(principal(&just_created)).await;
    assert!(
        after.enrichment_blocked.is_none(),
        "invalidate after create must let the new tenant pass on the next request — \
         without it, POST /api/v1/admin/tenants leaves the principal denied for up to TTL",
    );

    sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
        .bind(&[active_id, suspended_id, just_created][..])
        .execute(&pool)
        .await
        .ok();
}
