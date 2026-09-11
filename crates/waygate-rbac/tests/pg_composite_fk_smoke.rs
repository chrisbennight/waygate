//! Issue #148: composite-FK parent-tenant immutability pin.
//!
//! Issue #148 explicitly required a
//! migration test proving that `UPDATE scim_groups.tenant_id` is
//! refused while a `group_role_mappings` row references it. The
//! composite FK added in migration 0023 is supposed to deliver
//! that — this smoke proves it does, against a real Postgres.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` on a laptop without a DB passes without
//! special-casing. Same pattern as the existing
//! `waygate_scim::tests::pg_resolver_smoke`.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn parent_tenant_update_is_refused_while_mapping_references_group() {
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

    // Per-test tenant + UUIDs so concurrent test runs don't race
    // and so cleanup is unambiguous.
    let tenant = format!("test-issue148-{}", Uuid::new_v4());
    let other_tenant = format!("test-issue148-other-{}", Uuid::new_v4());
    let group_id = Uuid::new_v4();
    let role_id = Uuid::new_v4();

    // Seed: one SCIM group + one role + one mapping linking them.
    sqlx::query(
        r#"
        INSERT INTO scim_groups (id, tenant_id, display_name, attrs)
        VALUES ($1, $2, $3, '{}')
        "#,
    )
    .bind(group_id)
    .bind(&tenant)
    .bind(format!("group-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("insert scim_groups row");

    sqlx::query(
        r#"
        INSERT INTO gateway_roles (id, tenant_id, name, scopes)
        VALUES ($1, $2, $3, ARRAY['mcp:read'])
        "#,
    )
    .bind(role_id)
    .bind(&tenant)
    .bind(format!("role-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("insert gateway_roles row");

    sqlx::query(
        r#"
        INSERT INTO group_role_mappings (tenant_id, group_id, role_id)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(&tenant)
    .bind(group_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .expect("insert group_role_mappings row");

    // Load-bearing assertion (issue #148 acceptance criterion):
    // attempting to change the parent's tenant_id while a mapping
    // references it MUST be refused. With `ON UPDATE NO ACTION`
    // on the composite FK, Postgres surfaces SQLSTATE 23503
    // (foreign_key_violation).
    let result = sqlx::query(r#"UPDATE scim_groups SET tenant_id = $1 WHERE id = $2"#)
        .bind(&other_tenant)
        .bind(group_id)
        .execute(&pool)
        .await;
    match result {
        Err(sqlx::Error::Database(db)) => {
            assert_eq!(
                db.code().as_deref(),
                Some("23503"),
                "expected FK violation (23503) refusing the parent-tenant UPDATE; got `{}` `{}`",
                db.code().as_deref().unwrap_or("?"),
                db.message(),
            );
        }
        Ok(_) => panic!(
            "parent-tenant UPDATE on referenced scim_groups row MUST be refused by the composite FK",
        ),
        Err(other) => panic!("expected database FK violation; got non-database error: {other:?}"),
    }

    // Positive case: an unreferenced scim_groups row's tenant_id
    // CAN still be updated — the FK constraint only fires when
    // something references the row. Without this assertion we'd
    // pass even if I'd accidentally locked every parent UPDATE.
    let unreferenced_group = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scim_groups (id, tenant_id, display_name, attrs)
        VALUES ($1, $2, $3, '{}')
        "#,
    )
    .bind(unreferenced_group)
    .bind(&tenant)
    .bind(format!("unreferenced-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("insert unreferenced scim_groups row");
    sqlx::query(r#"UPDATE scim_groups SET tenant_id = $1 WHERE id = $2"#)
        .bind(&other_tenant)
        .bind(unreferenced_group)
        .execute(&pool)
        .await
        .expect(
            "unreferenced scim_groups row's tenant_id MUST still be updatable — \
             the FK only constrains rows that ARE referenced",
        );

    // Cleanup so concurrent runs (and the next iteration) don't
    // see this test's rows. DELETE order matches the cascade: the
    // mapping goes first (held by the referencing FK), then the
    // parent rows.
    sqlx::query("DELETE FROM group_role_mappings WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup mappings");
    sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1 OR tenant_id = $2")
        .bind(&tenant)
        .bind(&other_tenant)
        .execute(&pool)
        .await
        .expect("cleanup scim_groups");
    sqlx::query("DELETE FROM gateway_roles WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup gateway_roles");
}
