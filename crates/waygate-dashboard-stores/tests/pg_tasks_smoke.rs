//! Live Postgres smoke test for [`PgTaskStore`].
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` without a DB passes. Pins five
//! behaviours the future Tasks-aware
//! `InvocationService` write-through + the admin REST
//! handler depend on:
//!
//! 1. Insert → get round-trip; every field returned.
//! 2. Tenant scoping on `get`: a task in tenant A is
//!    invisible to a `get` issued under tenant B
//!    (returns None — the not-found-vs-wrong-tenant
//!    collapse is deliberate; leaking existence across
//!    tenants would be info disclosure).
//! 3. `list` filter combinations (no filter, by
//!    principal_sub, by status, both).
//! 4. `update_status` mutates the row + returns the
//!    post-update view; the `updated_at` trigger fires.
//! 5. `MAX_LIST_LIMIT` clamp.

use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_dashboard_stores::tasks::{
    NewTask, PgTaskStore, TaskError, TaskListFilter, TaskStatus, TaskStatusUpdate, TaskStore,
    MAX_LIST_LIMIT,
};

async fn connect() -> Option<sqlx::PgPool> {
    waygate_test_support::pg::audit_pool_or_skip().await
}

/// Seed a tenant + mcp_server + mcp_tool so the
/// `task_states.tool_id` FK is satisfied. The server
/// is created with the supplied `visibility` so the
/// tenant-mismatch trigger's global-server carve-out
/// can be exercised. Returns the `(tenant_id,
/// tool_id)` the test rows hang off.
async fn seed_fixtures_with_visibility(
    pool: &sqlx::PgPool,
    suffix: &str,
    visibility: &str,
) -> (String, Uuid) {
    let tenant_id = format!("pg-tasks-{suffix}");
    sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(&tenant_id)
    .execute(pool)
    .await
    .expect("seed tenant");
    let server_id: Uuid = sqlx::query(
        r#"
        INSERT INTO mcp_servers (id, tenant_id, name, transport, runtime_target, status, visibility)
        VALUES ($1, $2, $3, 'http', '{}'::jsonb, 'live', $4)
        RETURNING id
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .bind(format!("svc-{suffix}"))
    .bind(visibility)
    .fetch_one(pool)
    .await
    .expect("seed mcp_servers")
    .get("id");
    let tool_id: Uuid = sqlx::query(
        r#"
        INSERT INTO mcp_tools (id, server_id, name)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(server_id)
    .bind(format!("tool-{suffix}"))
    .fetch_one(pool)
    .await
    .expect("seed mcp_tools")
    .get("id");
    (tenant_id, tool_id)
}

/// Tenant-only-visibility variant — the historical
/// shape every test except the global carve-out wants.
async fn seed_fixtures(pool: &sqlx::PgPool, suffix: &str) -> (String, Uuid) {
    seed_fixtures_with_visibility(pool, suffix, "tenant_only").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tasks_lifecycle_and_isolation() {
    let Some(pool) = connect().await else {
        eprintln!("skipping tasks Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let (tenant_a, tool_a) = seed_fixtures(&pool, &suffix).await;
    let (tenant_b, _tool_b) = seed_fixtures(&pool, &format!("b-{suffix}")).await;
    let store = PgTaskStore::new(pool.clone());

    let alice = format!("alice-{suffix}");
    let bob = format!("bob-{suffix}");

    // 1. Insert → get round-trip.
    let t1 = store
        .insert(NewTask {
            tenant_id: &tenant_a,
            principal_sub: &alice,
            tool_id: tool_a,
            arguments_hash: "deadbeef",
            status: TaskStatus::Pending,
        })
        .await
        .expect("insert t1");
    assert_eq!(t1.tenant_id, tenant_a);
    assert_eq!(t1.principal_sub, alice);
    assert_eq!(t1.tool_id, tool_a);
    assert_eq!(t1.status, TaskStatus::Pending);
    assert!(t1.completed_at.is_none());

    let fetched = store
        .get(&tenant_a, t1.id)
        .await
        .expect("get t1")
        .expect("t1 present");
    assert_eq!(fetched.id, t1.id);

    // 2. Tenant isolation: tenant_b looking up t1 returns
    //    None even though the id exists in the DB.
    let cross = store.get(&tenant_b, t1.id).await.expect("get cross");
    assert!(
        cross.is_none(),
        "tenant_b must NOT see tenant_a's task — info disclosure",
    );

    // 3. List filter combinations. Seed a second task
    //    for bob in tenant_a so the principal_sub filter
    //    is meaningful.
    let t2 = store
        .insert(NewTask {
            tenant_id: &tenant_a,
            principal_sub: &bob,
            tool_id: tool_a,
            arguments_hash: "f00d",
            status: TaskStatus::Running,
        })
        .await
        .expect("insert t2");

    // No filter — both rows.
    let all = store
        .list(&tenant_a, TaskListFilter::default(), 50, 0)
        .await
        .expect("list all");
    assert!(all.iter().any(|t| t.id == t1.id));
    assert!(all.iter().any(|t| t.id == t2.id));

    // Filter by sub.
    let by_alice = store
        .list(
            &tenant_a,
            TaskListFilter {
                principal_sub: Some(&alice),
                status: None,
            },
            50,
            0,
        )
        .await
        .expect("list by sub");
    assert!(by_alice.iter().any(|t| t.id == t1.id));
    assert!(!by_alice.iter().any(|t| t.id == t2.id));

    // Filter by status.
    let by_running = store
        .list(
            &tenant_a,
            TaskListFilter {
                principal_sub: None,
                status: Some(TaskStatus::Running),
            },
            50,
            0,
        )
        .await
        .expect("list by status");
    assert!(!by_running.iter().any(|t| t.id == t1.id));
    assert!(by_running.iter().any(|t| t.id == t2.id));

    // Both filters AND'd.
    let by_both = store
        .list(
            &tenant_a,
            TaskListFilter {
                principal_sub: Some(&alice),
                status: Some(TaskStatus::Running),
            },
            50,
            0,
        )
        .await
        .expect("list both");
    assert!(
        by_both.is_empty(),
        "alice + running = empty (alice's only task is pending)",
    );

    // 4. update_status mutates + the trigger bumps
    //    updated_at.
    let pre_update = t1.updated_at;
    // Sleep just enough for clock to advance past the
    // trigger's `now()` resolution (Postgres timestamps
    // are microsecond-precise, so a few ms is plenty).
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let completed_at = OffsetDateTime::now_utc();
    let updated = store
        .update_status(
            &tenant_a,
            t1.id,
            TaskStatusUpdate {
                status: TaskStatus::Succeeded,
                result_url: Some("https://gw.test/tasks/x/result"),
                resume_token: None,
                error_message: None,
                completed_at: Some(completed_at),
            },
        )
        .await
        .expect("update")
        .expect("row found in tenant");
    assert_eq!(updated.status, TaskStatus::Succeeded);
    assert_eq!(
        updated.result_url.as_deref(),
        Some("https://gw.test/tasks/x/result"),
    );
    assert!(updated.completed_at.is_some());
    assert!(
        updated.updated_at > pre_update,
        "trigger must bump updated_at: pre={pre_update}, post={}",
        updated.updated_at,
    );

    // Cross-tenant update returns None (same isolation
    // contract as get).
    let cross_update = store
        .update_status(
            &tenant_b,
            t1.id,
            TaskStatusUpdate {
                status: TaskStatus::Cancelled,
                result_url: None,
                resume_token: None,
                error_message: None,
                completed_at: None,
            },
        )
        .await
        .expect("cross update");
    assert!(cross_update.is_none());

    // 5. MAX_LIST_LIMIT clamp.
    let clamped = store
        .list(&tenant_a, TaskListFilter::default(), 1_000_000, 0)
        .await
        .expect("list clamped");
    assert!(
        clamped.len() <= MAX_LIST_LIMIT as usize,
        "list must clamp; got {} > {}",
        clamped.len(),
        MAX_LIST_LIMIT,
    );

    // Cleanup — cascade through tenants.
    sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind(&tenant_a)
        .bind(&tenant_b)
        .execute(&pool)
        .await
        .expect("cleanup tenants");
}

/// The SQL-layer `task_states_tenant_match_trg` must
/// refuse an insert
/// whose `tenant_id` does not match the
/// `mcp_servers.tenant_id` reachable through
/// `mcp_tools.server_id` UNLESS the owning server is
/// `visibility='global'`. The global carve-out
/// matches `CatalogStore::resolve_tool`, which
/// explicitly lets non-owner tenants invoke a
/// global-visible server.
///
/// This test pins the *tenant_only* (default) shape —
/// the cross-tenant rejection. The global allow path
/// is covered by
/// [`global_visibility_tool_allows_cross_tenant_task`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_tenant_tool_insert_is_rejected_by_trigger() {
    let Some(pool) = connect().await else {
        eprintln!("skipping cross-tenant-tool smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let (tenant_a, _tool_a) = seed_fixtures(&pool, &format!("xt-a-{suffix}")).await;
    let (tenant_b, tool_b) = seed_fixtures(&pool, &format!("xt-b-{suffix}")).await;
    let store = PgTaskStore::new(pool.clone());

    let alice = format!("alice-{suffix}");

    // Try to insert a task row in tenant_a that
    // references tenant_b's tool. The trigger must
    // raise; the application sees Err(Database(_)).
    let bad = store
        .insert(NewTask {
            tenant_id: &tenant_a,
            principal_sub: &alice,
            tool_id: tool_b,
            arguments_hash: "deadbeef",
            status: TaskStatus::Pending,
        })
        .await;
    let err = bad.expect_err("cross-tenant insert must be rejected");
    // TaskError::Database wraps the sqlx error; the
    // trigger's RAISE message bubbles through unchanged.
    let TaskError::Database(db_err) = &err;
    let msg = db_err.to_string();
    assert!(
        msg.contains("does not match owning server tenant_id"),
        "expected tenant-mismatch raise, got: {msg}",
    );

    // Sanity: the good path (same tenant) still works.
    let good = store
        .insert(NewTask {
            tenant_id: &tenant_b,
            principal_sub: &alice,
            tool_id: tool_b,
            arguments_hash: "f00d",
            status: TaskStatus::Pending,
        })
        .await
        .expect("same-tenant insert");
    assert_eq!(good.tenant_id, tenant_b);

    // Also assert UPDATE goes through the trigger:
    // flipping tenant_id to tenant_a on a row whose
    // tool belongs to tenant_b must raise.
    let bad_update = sqlx::query("UPDATE task_states SET tenant_id = $1 WHERE id = $2")
        .bind(&tenant_a)
        .bind(good.id)
        .execute(&pool)
        .await;
    let upd_err = bad_update.expect_err("cross-tenant UPDATE must be rejected");
    assert!(
        upd_err
            .to_string()
            .contains("does not match owning server tenant_id"),
        "expected tenant-mismatch raise on UPDATE, got: {upd_err}",
    );

    // Cleanup.
    sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind(&tenant_a)
        .bind(&tenant_b)
        .execute(&pool)
        .await
        .expect("cleanup tenants");
}

/// `CatalogStore::resolve_tool` accepts `(s.visibility
/// = 'global' OR s.tenant_id = $1)`, so a principal in
/// tenant A can invoke a tool that lives on a server
/// owned by tenant B IFF that server is global-
/// visible. The expected task-row shape in that case
/// records the task under the *calling* tenant (tenant
/// A) — that's the only way an admin in tenant A sees
/// their own user's invocations.
///
/// Round 1's trigger was too strict and would have
/// rejected this legitimate global-tool call.
/// Round 3 (this test) pins the carve-out: insert
/// `(tenant_id=A, tool_id=tool_in_global_server_owned_by_B)`
/// must succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_visibility_tool_allows_cross_tenant_task() {
    let Some(pool) = connect().await else {
        eprintln!("skipping global-tool smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let (tenant_a, _tool_a) = seed_fixtures(&pool, &format!("gv-caller-{suffix}")).await;
    // Tenant B owns a *global-visibility* server. Its
    // tools are callable from tenant A per the catalog
    // contract.
    let (tenant_b, tool_global) =
        seed_fixtures_with_visibility(&pool, &format!("gv-owner-{suffix}"), "global").await;
    let store = PgTaskStore::new(pool.clone());

    let alice = format!("alice-{suffix}");

    // Calling tenant (A) records the task; the tool
    // lives on tenant B's global server. Trigger must
    // allow.
    let row = store
        .insert(NewTask {
            tenant_id: &tenant_a,
            principal_sub: &alice,
            tool_id: tool_global,
            arguments_hash: "global-call",
            status: TaskStatus::Pending,
        })
        .await
        .expect("global-server insert must succeed regardless of tool owner tenant");
    assert_eq!(
        row.tenant_id, tenant_a,
        "global-tool task must record under the CALLING tenant — only then will tenant A's admin see it",
    );
    assert_eq!(row.tool_id, tool_global);

    // Sanity: tenant B (the owner) calling its own
    // global tool still works.
    let owner_call = store
        .insert(NewTask {
            tenant_id: &tenant_b,
            principal_sub: &alice,
            tool_id: tool_global,
            arguments_hash: "owner-self-call",
            status: TaskStatus::Pending,
        })
        .await
        .expect("owner-tenant insert against own global tool");
    assert_eq!(owner_call.tenant_id, tenant_b);

    // Cleanup.
    sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind(&tenant_a)
        .bind(&tenant_b)
        .execute(&pool)
        .await
        .expect("cleanup tenants");
}
