//! Live Postgres smoke test for [`PgAgentConfigStore`].
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so a bare `cargo test`
//! without a DB passes (CI provisions Postgres and exports the URL). Pins the
//! behaviours the dashboard + future runtime depend on:
//!
//! 1. Insert → get round-trip; every field returned (incl. the JSONB
//!    `allowed_tools` array and a NULL `token_budget`).
//! 2. Tenant isolation on `get`/`update`/`delete`.
//! 3. Guarded writes reject stale versions without changing the row.
//! 4. `(tenant, name)` UNIQUE collision → `DuplicateName`.
//! 5. Full-replace `update` mutates the row, clears a nullable field, and the
//!    `updated_at` trigger fires.
//! 6. `MAX_LIST_LIMIT` clamp.
//! 7. The largest validator-accepted, maximally escaped config persists.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_dashboard_stores::agent_config::{
    AgentConfigError, AgentConfigFields, AgentConfigStore, AgentKind, PgAgentConfigStore,
    MAX_LIST_LIMIT,
};

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

fn fields<'a>(name: &'a str, model: &'a str, tools: &'a [String]) -> AgentConfigFields<'a> {
    AgentConfigFields {
        name,
        kind: AgentKind::Chat,
        model_alias: model,
        instructions: Some("be careful"),
        allowed_tools: tools,
        max_steps: 8,
        max_tool_calls: 16,
        token_budget: Some(1000),
        enabled: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_config_lifecycle_and_isolation() {
    let Some(pool) = connect().await else {
        eprintln!("skipping agent_config Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant_a = format!("ac-a-{suffix}");
    let tenant_b = format!("ac-b-{suffix}");
    let store = PgAgentConfigStore::new(pool.clone());

    let escaped = "\u{0001}";
    let boundary_name = escaped.repeat(64);
    let boundary_model = escaped.repeat(128);
    let boundary_instructions = escaped.repeat(8_000);
    let boundary_tools = vec![escaped.repeat(256); 200];
    let boundary = store
        .insert(
            &tenant_a,
            AgentConfigFields {
                name: &boundary_name,
                kind: AgentKind::Classification,
                model_alias: &boundary_model,
                instructions: Some(&boundary_instructions),
                allowed_tools: &boundary_tools,
                max_steps: 100,
                max_tool_calls: 500,
                token_budget: Some(i32::MAX),
                enabled: true,
            },
        )
        .await
        .expect("persist largest escaped config");
    assert_eq!(
        boundary.instructions.as_deref(),
        Some(boundary_instructions.as_str())
    );
    assert_eq!(boundary.allowed_tools, boundary_tools);

    let tools = vec![
        "gateway-observe.query_audit".to_owned(),
        "gateway-admin.propose_change".to_owned(),
    ];

    // 1. Insert → get round-trip.
    let a = store
        .insert(&tenant_a, fields("ops-chat", "gpt-x", &tools))
        .await
        .expect("insert a");
    assert_eq!(a.tenant_id, tenant_a);
    assert_eq!(a.name, "ops-chat");
    assert_eq!(a.kind, AgentKind::Chat);
    assert_eq!(a.allowed_tools, tools);
    assert_eq!(a.token_budget, Some(1000));
    assert!(!a.enabled);

    let fetched = store
        .get(&tenant_a, a.id)
        .await
        .expect("get a")
        .expect("a present");
    assert_eq!(fetched.id, a.id);
    assert_eq!(fetched.allowed_tools, tools);

    // 2. Tenant isolation.
    assert!(store
        .get(&tenant_b, a.id)
        .await
        .expect("cross get")
        .is_none());

    // 3. A stale proposal witness cannot overwrite a newer row. A matching
    //    witness can, and the returned version becomes the next write guard.
    let stale_version = a.updated_at - time::Duration::seconds(1);
    assert!(store
        .update_if_updated_at_matches(
            &tenant_a,
            a.id,
            stale_version,
            fields("ops-chat", "stale-model", &[]),
        )
        .await
        .expect("stale guarded update")
        .is_none());
    assert_eq!(
        store
            .get(&tenant_a, a.id)
            .await
            .expect("get after stale update")
            .expect("row remains")
            .model_alias,
        "gpt-x",
    );
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let a = store
        .update_if_updated_at_matches(
            &tenant_a,
            a.id,
            a.updated_at,
            fields("ops-chat", "gpt-guarded", &tools),
        )
        .await
        .expect("current guarded update")
        .expect("matching row");
    assert_eq!(a.model_alias, "gpt-guarded");

    // 4. Duplicate (tenant, name) → DuplicateName; same name in another tenant
    //    is fine.
    assert!(matches!(
        store
            .insert(&tenant_a, fields("ops-chat", "gpt-y", &[]))
            .await,
        Err(AgentConfigError::DuplicateName)
    ));
    let tenant_b_agent = store
        .insert(&tenant_b, fields("ops-chat", "gpt-x", &[]))
        .await
        .expect("same name other tenant");

    // 5. Full-replace update: flip enabled, clear token_budget + instructions,
    //    empty the allowlist; trigger bumps updated_at.
    let pre = a.updated_at;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let updated = store
        .update(
            &tenant_a,
            a.id,
            AgentConfigFields {
                name: "ops-chat",
                kind: AgentKind::PolicyReview,
                model_alias: "gpt-z",
                instructions: None,
                allowed_tools: &[],
                max_steps: 5,
                max_tool_calls: 9,
                token_budget: None,
                enabled: true,
            },
        )
        .await
        .expect("update")
        .expect("row found");
    assert!(updated.enabled);
    assert_eq!(updated.kind, AgentKind::PolicyReview);
    assert_eq!(updated.model_alias, "gpt-z");
    assert!(updated.instructions.is_none(), "nullable field cleared");
    assert!(updated.token_budget.is_none(), "nullable field cleared");
    assert!(updated.allowed_tools.is_empty());
    assert!(
        updated.updated_at > pre,
        "trigger must bump updated_at: pre={pre}, post={}",
        updated.updated_at,
    );

    // Cross-tenant update → None.
    assert!(store
        .update(&tenant_b, a.id, fields("x", "y", &[]))
        .await
        .expect("cross update")
        .is_none());

    // 6. MAX_LIST_LIMIT clamp.
    let clamped = store
        .list(&tenant_a, 1_000_000, 0)
        .await
        .expect("list clamped");
    assert!(clamped.len() <= MAX_LIST_LIMIT as usize);

    // Cross-tenant and stale guarded deletes are no-ops; the current version
    // removes exactly the reviewed row. Direct delete still removes its own
    // tenant's row.
    assert!(!store.delete(&tenant_b, a.id).await.expect("cross delete"));
    assert!(store
        .delete(&tenant_b, tenant_b_agent.id)
        .await
        .expect("direct delete"));
    assert!(!store
        .delete_if_updated_at_matches(&tenant_a, a.id, a.updated_at)
        .await
        .expect("stale guarded delete"));
    assert!(store
        .delete_if_updated_at_matches(&tenant_a, a.id, updated.updated_at)
        .await
        .expect("current guarded delete"));

    // Cleanup any rows this test created (no tenants FK cascade here).
    sqlx::query("DELETE FROM agent_configs WHERE tenant_id IN ($1, $2)")
        .bind(&tenant_a)
        .bind(&tenant_b)
        .execute(&pool)
        .await
        .expect("cleanup");
}
