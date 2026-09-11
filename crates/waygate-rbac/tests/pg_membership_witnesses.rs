//! Version-conditional RBAC membership mutations.
//!
//! A governed approval reviews a specific role version (and, for a group
//! revoke, a specific mapping generation). These tests pin the SQL contract:
//! stale witnesses cause no side effect, while current witnesses mutate the
//! intended row.

use time::Duration;
use uuid::Uuid;
use waygate_rbac::{PgRbacStore, RbacStore};

#[tokio::test]
async fn guarded_membership_mutations_refuse_stale_witnesses() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgRbacStore::new(pool.clone());
    let tenant = format!("test-rbac-witness-{}", Uuid::new_v4());
    let group_id = Uuid::new_v4();
    let local_group_id = Uuid::new_v4();

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
    .expect("seed group");
    sqlx::query(
        r#"
        INSERT INTO scim_groups (id, tenant_id, display_name, source, attrs)
        VALUES ($1, $2, $3, 'local', '{}')
        "#,
    )
    .bind(local_group_id)
    .bind(&tenant)
    .bind(format!("local-group-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("seed local group");

    let role = store
        .create_role(&tenant, "operators", None, &["mcp:read".into()])
        .await
        .expect("seed role");
    let changed = store
        .update_role(
            &tenant,
            role.id,
            "operators",
            None,
            &["mcp:read".into(), "mcp:invoke".into()],
        )
        .await
        .expect("update role")
        .expect("role exists");
    assert_ne!(
        role.updated_at, changed.updated_at,
        "a role edit must advance the version witness",
    );

    let stale_assignment = store
        .create_assignment_if_role_version(&tenant, role.id, "alice", role.updated_at)
        .await
        .expect("stale guarded assignment grant");
    assert!(stale_assignment.is_none());
    assert!(store
        .list_assignments(&tenant, Some(role.id), Some("alice"))
        .await
        .expect("list assignments")
        .is_empty());

    let assignment = store
        .create_assignment_if_role_version(&tenant, role.id, "alice", changed.updated_at)
        .await
        .expect("current guarded assignment grant")
        .expect("current role version grants");
    let changed_again = store
        .update_role(
            &tenant,
            role.id,
            "operators",
            Some("reviewed role changed"),
            &changed.scopes,
        )
        .await
        .expect("second role update")
        .expect("role exists");
    assert_ne!(changed.updated_at, changed_again.updated_at);

    assert!(
        store
            .create_group_mapping_if_role_version(
                &tenant,
                local_group_id,
                role.id,
                changed_again.updated_at,
            )
            .await
            .expect("guarded local group mapping grant")
            .is_none(),
        "API-key catalog groups must not be eligible for RBAC mappings",
    );

    let stale_revoke = store
        .delete_assignment_if_role_version(&tenant, assignment.id, role.id, changed.updated_at)
        .await
        .expect("stale guarded assignment revoke");
    assert!(stale_revoke.is_none());
    assert!(store
        .get_assignment(&tenant, assignment.id)
        .await
        .expect("read assignment")
        .is_some());
    assert!(store
        .delete_assignment_if_role_version(
            &tenant,
            assignment.id,
            role.id,
            changed_again.updated_at,
        )
        .await
        .expect("current guarded assignment revoke")
        .is_some());

    let stale_group_grant = store
        .create_group_mapping_if_role_version(&tenant, group_id, role.id, changed.updated_at)
        .await
        .expect("stale guarded group mapping grant");
    assert!(stale_group_grant.is_none());
    let mapping = store
        .create_group_mapping_if_role_version(&tenant, group_id, role.id, changed_again.updated_at)
        .await
        .expect("current guarded group mapping grant")
        .expect("current role version maps");

    let stale_mapping_revoke = store
        .delete_group_mapping_if_versions(
            &tenant,
            group_id,
            role.id,
            mapping.created_at - Duration::seconds(1),
            changed_again.updated_at,
        )
        .await
        .expect("stale mapping-generation revoke");
    assert!(stale_mapping_revoke.is_none());
    assert_eq!(
        store
            .list_group_mappings(&tenant, Some(role.id), Some(group_id))
            .await
            .expect("list mappings")
            .len(),
        1,
    );
    assert!(store
        .delete_group_mapping_if_versions(
            &tenant,
            group_id,
            role.id,
            mapping.created_at,
            changed_again.updated_at,
        )
        .await
        .expect("current guarded mapping revoke")
        .is_some());

    store
        .delete_role(&tenant, role.id)
        .await
        .expect("cleanup role");
    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup user");
    sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup group");
}

#[tokio::test]
async fn durable_scim_membership_controls_group_role_resolution() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgRbacStore::new(pool.clone());
    let tenant = format!("test-scim-rbac-{}", Uuid::new_v4());
    let group_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO scim_groups (id, tenant_id, display_name, source, attrs)
        VALUES ($1, $2, $3, 'scim', '{}')
        "#,
    )
    .bind(group_id)
    .bind(&tenant)
    .bind(format!("operators-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("seed SCIM group");
    sqlx::query("INSERT INTO scim_users (id, tenant_id, user_name) VALUES ($1, $2, 'alice')")
        .bind(user_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed SCIM user");
    sqlx::query("INSERT INTO scim_user_groups (user_id, group_id, tenant_id) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(group_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed durable membership");

    let role = store
        .create_role(&tenant, "operators", None, &["mcp:admin".into()])
        .await
        .expect("seed role");
    store
        .create_group_mapping_if_role_version(&tenant, group_id, role.id, role.updated_at)
        .await
        .expect("seed guarded group mapping")
        .expect("SCIM group is eligible for mapping");

    let resolved = store
        .resolve_for_subject(&tenant, "alice", &[group_id])
        .await
        .expect("resolve durable membership");
    assert_eq!(resolved.role_names, vec!["operators"]);
    assert_eq!(resolved.granted_scopes, vec!["mcp:admin"]);

    sqlx::query(
        "DELETE FROM scim_user_groups WHERE tenant_id = $1 AND user_id = $2 AND group_id = $3",
    )
    .bind(&tenant)
    .bind(user_id)
    .bind(group_id)
    .execute(&pool)
    .await
    .expect("revoke durable membership");
    let after_revoke = store
        .resolve_for_subject(&tenant, "alice", &[group_id])
        .await;
    assert!(
        after_revoke.expect("resolve after revoke").is_empty(),
        "a stale enricher group id must not preserve a revoked durable membership",
    );

    store
        .delete_role(&tenant, role.id)
        .await
        .expect("cleanup role");
    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup user");
    sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup group");
}
