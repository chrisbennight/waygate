//! Tenant DELETE must drop every
//! gateway_roles row for the tenant (and the composite-FK ON
//! DELETE CASCADE must take role_assignments + group_role_mappings
//! with them) so re-creating the same tenant id starts clean.
//! Skips when `AUDIT_DATABASE_URL` is not set.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_rbac::{PgRbacStore, RbacStore};

#[tokio::test]
async fn delete_all_roles_cascades_to_assignments_and_group_mappings() {
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

    let store = PgRbacStore::new(pool.clone());
    let target = format!("test-rbac-delete-target-{}", Uuid::new_v4());
    let other = format!("test-rbac-delete-other-{}", Uuid::new_v4());

    // Seed: two roles in target tenant, one role in another
    // tenant. Then a direct assignment + a SCIM group mapping
    // for each target role to prove the cascade.
    let role_a = store
        .create_role(&target, "role_a", None, &["mcp:read".into()])
        .await
        .expect("create role_a");
    let _role_b = store
        .create_role(&target, "role_b", None, &["mcp:invoke".into()])
        .await
        .expect("create role_b");
    let role_o = store
        .create_role(&other, "role_o", None, &["mcp:admin".into()])
        .await
        .expect("create role_o");

    // Add an assignment so the cascade has something to chew on.
    store
        .create_assignment(&target, role_a.id, "sub:test")
        .await
        .expect("create_assignment");
    // Add a scim_group + group mapping for role_a so the
    // composite FK cascade exercises the group_role_mappings
    // table too.
    let group_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO scim_groups (id, tenant_id, display_name, attrs) VALUES ($1, $2, $3, '{}')",
    )
    .bind(group_id)
    .bind(&target)
    .bind(format!("g-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("seed scim_group");
    store
        .create_group_mapping(&target, group_id, role_a.id)
        .await
        .expect("create_group_mapping");

    // Act.
    let n = store
        .delete_all_roles_for_tenant(&target)
        .await
        .expect("delete_all_roles_for_tenant");
    assert_eq!(
        n, 2,
        "delete_all should remove both target-tenant roles, leaving the other tenant intact",
    );

    // Roles are gone.
    let target_roles_left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM gateway_roles WHERE tenant_id = $1")
            .bind(&target)
            .fetch_one(&pool)
            .await
            .expect("count target roles");
    assert_eq!(target_roles_left.0, 0);

    // Children cascaded.
    let assignments_left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM role_assignments WHERE tenant_id = $1")
            .bind(&target)
            .fetch_one(&pool)
            .await
            .expect("count target assignments");
    assert_eq!(
        assignments_left.0, 0,
        "ON DELETE CASCADE should sweep role_assignments",
    );
    let group_mappings_left: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM group_role_mappings WHERE tenant_id = $1")
            .bind(&target)
            .fetch_one(&pool)
            .await
            .expect("count target group_mappings");
    assert_eq!(
        group_mappings_left.0, 0,
        "ON DELETE CASCADE should sweep group_role_mappings",
    );

    // Other tenant's role still present.
    let other_role: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM gateway_roles WHERE id = $1")
        .bind(role_o.id)
        .fetch_one(&pool)
        .await
        .expect("count other role");
    assert_eq!(
        other_role.0, 1,
        "delete_all must NOT touch other tenants' rows",
    );

    // Cleanup.
    sqlx::query("DELETE FROM gateway_roles WHERE tenant_id = $1")
        .bind(&other)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1")
        .bind(&target)
        .execute(&pool)
        .await
        .ok();
}
