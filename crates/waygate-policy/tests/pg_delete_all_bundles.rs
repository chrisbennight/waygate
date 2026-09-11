//! Tenant DELETE must drop every
//! policy_bundles row for the tenant so re-creating the same
//! tenant id can clone from default at v1, not at v2+.
//! Skips when `AUDIT_DATABASE_URL` is not set.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_policy::{PgPolicyStore, PolicyStore};

#[tokio::test]
async fn delete_all_bundles_drops_drafts_and_published() {
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

    let store = PgPolicyStore::new(pool.clone());
    let target = format!("test-delete-target-{}", Uuid::new_v4());
    let other = format!("test-delete-other-{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO tenants (id, display_name, status) \
         VALUES ($1, $1, 'active'), ($2, $2, 'active')",
    )
    .bind(&target)
    .bind(&other)
    .execute(&pool)
    .await
    .expect("seed tenants");

    // Seed: target tenant gets one published bundle + one
    // draft. Other tenant gets one published bundle that must
    // survive the cascade.
    let target_draft = store
        .create_draft(
            &target,
            "permit(principal, action, resource);",
            None,
            Some("test"),
        )
        .await
        .expect("target draft");
    let target_published = store
        .create_draft(
            &target,
            "forbid(principal, action, resource);",
            None,
            Some("test"),
        )
        .await
        .expect("target second draft");
    let _ = store
        .publish(&target, target_published.id, "test")
        .await
        .expect("publish target");
    // Leave target_draft as 'draft' to prove the cascade hits
    // both statuses.
    let _ = target_draft;

    let other_draft = store
        .create_draft(
            &other,
            "permit(principal, action, resource);",
            None,
            Some("test"),
        )
        .await
        .expect("other draft");
    let _ = store
        .publish(&other, other_draft.id, "test")
        .await
        .expect("publish other");

    // Act.
    let n = store
        .delete_all_bundles_for_tenant(&target)
        .await
        .expect("delete_all_bundles_for_tenant");
    assert_eq!(
        n, 2,
        "delete_all should sweep both the draft and the published row in the target tenant",
    );

    let target_left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM policy_bundles WHERE tenant_id = $1")
            .bind(&target)
            .fetch_one(&pool)
            .await
            .expect("count target");
    assert_eq!(target_left.0, 0);

    let other_left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM policy_bundles WHERE tenant_id = $1")
            .bind(&other)
            .fetch_one(&pool)
            .await
            .expect("count other");
    assert_eq!(
        other_left.0, 1,
        "delete_all must NOT touch other tenants' bundles",
    );

    // Cleanup.
    sqlx::query("DELETE FROM tenants WHERE id = $1 OR id = $2")
        .bind(&target)
        .bind(&other)
        .execute(&pool)
        .await
        .ok();
}
