//! Live Postgres tests for the lagging LLM budget gate
//! (`migrations/0049_llm_budgets.sql` + `waygate_storage::check_llm_budget`).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset. Each test runs under a
//! unique tenant and cleans up its rows.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_evidence::usage::LlmUsageRow;
use waygate_storage::{
    check_llm_budget, insert_llm_usage, upsert_llm_budget, BudgetDimension, CostBreakdown,
    LlmBudgetRow, PgAuditSink,
};

fn budget(
    tenant: &str,
    principal_sub: Option<&str>,
    model_alias: Option<&str>,
    window_seconds: i64,
    max_total_tokens: Option<i64>,
) -> LlmBudgetRow {
    LlmBudgetRow {
        id: Uuid::now_v7(),
        tenant_id: tenant.to_string(),
        principal_sub: principal_sub.map(str::to_string),
        model_alias: model_alias.map(str::to_string),
        window_seconds,
        max_total_tokens,
        max_total_cost: None,
        enabled: true,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

fn usage(tenant: &str, principal_sub: &str, alias: &str, input: u64, output: u64) -> LlmUsageRow {
    LlmUsageRow {
        tenant_id: tenant.to_string(),
        principal_sub: Some(principal_sub.to_string()),
        model_alias: alias.to_string(),
        provider: "openrouter".into(),
        provider_account_id: None,
        model_served: Some("served-x".into()),
        inbound_surface: "chat_completions".into(),
        input_tokens: Some(input),
        output_tokens: Some(output),
        cached_read_tokens: None,
        cache_write_tokens: None,
        reasoning_tokens: None,
        finish_reason: Some("stop".into()),
        refusal: false,
        latency_ms: Some(1),
        gateway_cache_hit: false,
    }
}

#[tokio::test]
async fn budget_rejects_when_recorded_usage_meets_the_limit() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_budget test: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    PgAuditSink::migrate(&pool).await.expect("migrate");
    let tenant = format!("budget-test-{}", Uuid::now_v7());

    // alice: 5 total tokens / hour on gpt-x.
    upsert_llm_budget(
        &pool,
        &budget(&tenant, Some("alice"), Some("gpt-x"), 3600, Some(5)),
    )
    .await
    .expect("set budget");

    // No usage yet → within budget.
    assert!(
        check_llm_budget(&pool, &tenant, Some("alice"), "gpt-x")
            .await
            .expect("check")
            .is_none(),
        "no usage ⇒ within budget"
    );

    // Record 6 tokens (3 in + 3 out) ≥ 5 limit.
    insert_llm_usage(
        &pool,
        &usage(&tenant, "alice", "gpt-x", 3, 3),
        &CostBreakdown::default(),
    )
    .await
    .expect("record usage");

    let exc = check_llm_budget(&pool, &tenant, Some("alice"), "gpt-x")
        .await
        .expect("check");
    assert_eq!(
        exc.map(|e| e.dimension),
        Some(BudgetDimension::Tokens),
        "6 tokens ≥ 5 limit ⇒ rejected on tokens"
    );

    // A different principal under the SAME tenant is NOT affected by alice's
    // per-principal budget.
    assert!(
        check_llm_budget(&pool, &tenant, Some("bob"), "gpt-x")
            .await
            .expect("check")
            .is_none(),
        "bob has his own (unset) budget"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn tenant_wide_budget_counts_all_principals() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_budget tenant-wide test: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    PgAuditSink::migrate(&pool).await.expect("migrate");
    let tenant = format!("budget-tw-test-{}", Uuid::now_v7());

    // Tenant-wide, all models: 10 tokens / hour (principal_sub = NULL,
    // model_alias = NULL).
    upsert_llm_budget(&pool, &budget(&tenant, None, None, 3600, Some(10)))
        .await
        .expect("set budget");

    // alice and bob each spend 6 (3+3) ⇒ 12 ≥ 10 tenant-wide.
    insert_llm_usage(
        &pool,
        &usage(&tenant, "alice", "gpt-x", 3, 3),
        &CostBreakdown::default(),
    )
    .await
    .expect("record alice");
    insert_llm_usage(
        &pool,
        &usage(&tenant, "bob", "gpt-y", 3, 3),
        &CostBreakdown::default(),
    )
    .await
    .expect("record bob");

    // A tenant-wide budget rejects ANY principal once the tenant total is over,
    // regardless of which model the call names.
    let exc = check_llm_budget(&pool, &tenant, Some("carol"), "gpt-z")
        .await
        .expect("check");
    assert_eq!(
        exc.map(|e| e.dimension),
        Some(BudgetDimension::Tokens),
        "tenant total 12 ≥ 10 ⇒ even a fresh principal is refused"
    );

    cleanup(&pool, &tenant).await;
}

async fn cleanup(pool: &sqlx::PgPool, tenant: &str) {
    sqlx::query("DELETE FROM llm_usage WHERE tenant_id = $1")
        .bind(tenant)
        .execute(pool)
        .await
        .expect("cleanup usage");
    sqlx::query("DELETE FROM llm_budgets WHERE tenant_id = $1")
        .bind(tenant)
        .execute(pool)
        .await
        .expect("cleanup budgets");
}
