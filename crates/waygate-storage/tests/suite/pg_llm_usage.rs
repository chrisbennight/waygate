//! Live Postgres round-trip for the inference usage ledger
//! (`migrations/0048_llm_usage.sql` + `waygate_storage::insert_llm_usage`).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset. When set, applies
//! migrations, inserts one usage row (with a computed cost) under a unique
//! tenant, reads it back, asserts the token + cost columns persisted, then
//! deletes the row.

use std::env;
use std::str::FromStr;

use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;

use waygate_evidence::usage::{LlmUsageRecorder, LlmUsageRow};
use waygate_storage::{
    insert_llm_usage, upsert_llm_model, CostBreakdown, CostSource, LlmModelUpsert, PgAuditSink,
    PgLlmUsageSink,
};

#[tokio::test]
async fn insert_llm_usage_roundtrip() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_usage Pg roundtrip: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");

    let tenant = format!("usage-test-{}", Uuid::now_v7());
    let row = LlmUsageRow {
        tenant_id: tenant.clone(),
        principal_sub: Some("alice".into()),
        model_alias: "gpt-x".into(),
        provider: "openrouter".into(),
        provider_account_id: None,
        model_served: Some("served-x".into()),
        inbound_surface: "chat_completions".into(),
        input_tokens: Some(3),
        output_tokens: Some(1),
        cached_read_tokens: None,
        cache_write_tokens: None,
        reasoning_tokens: None,
        finish_reason: Some("stop".into()),
        refusal: false,
        latency_ms: Some(42),
        gateway_cache_hit: false,
    };

    // A computed cost round-trips through the NUMERIC columns + cost_source.
    let cost = CostBreakdown {
        input_cost: Some(Decimal::from_str("0.0009").unwrap()),
        output_cost: Some(Decimal::from_str("0.0006").unwrap()),
        total_cost: Some(Decimal::from_str("0.0015").unwrap()),
        source: CostSource::ComputedFromCatalog,
    };
    insert_llm_usage(&pool, &row, &cost).await.expect("insert");

    let got = sqlx::query(
        "SELECT model_alias, provider, model_served, input_tokens, output_tokens, \
                finish_reason, refusal, latency_ms, total_cost, cost_source \
           FROM llm_usage WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("select the inserted row");

    let model_alias: String = got.get("model_alias");
    let provider: String = got.get("provider");
    let model_served: Option<String> = got.get("model_served");
    let input_tokens: Option<i64> = got.get("input_tokens");
    let output_tokens: Option<i64> = got.get("output_tokens");
    let finish_reason: Option<String> = got.get("finish_reason");
    let refusal: bool = got.get("refusal");
    let latency_ms: Option<i64> = got.get("latency_ms");
    let total_cost: Option<Decimal> = got.get("total_cost");
    let cost_source: Option<String> = got.get("cost_source");

    assert_eq!(model_alias, "gpt-x");
    assert_eq!(provider, "openrouter");
    assert_eq!(model_served.as_deref(), Some("served-x"));
    assert_eq!(input_tokens, Some(3));
    assert_eq!(output_tokens, Some(1));
    assert_eq!(finish_reason.as_deref(), Some("stop"));
    assert!(!refusal);
    assert_eq!(latency_ms, Some(42));
    assert_eq!(total_cost, Some(Decimal::from_str("0.0015").unwrap()));
    assert_eq!(cost_source.as_deref(), Some("computed_from_catalog"));

    sqlx::query("DELETE FROM llm_usage WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn sink_prices_a_call_from_the_catalog() {
    // End-to-end: the sink looks up the model's catalog rates and computes the
    // call's cost. Seed a model, set its rates, record a usage row through the
    // sink, and assert the persisted cost.
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_usage sink cost test: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");

    let tenant = format!("usage-cost-test-{}", Uuid::now_v7());

    // Seed the model, then set its per-Mtok rates (the seeder upsert is
    // cost-free, so an operator UPDATE supplies pricing). Cost attributes to
    // model_served, so the catalog row's upstream_model must equal the served
    // model the sink prices.
    upsert_llm_model(
        &pool,
        &LlmModelUpsert {
            tenant_id: tenant.clone(),
            alias: "gpt-x".into(),
            provider: "openrouter".into(),
            credential_label: "MAIN".into(),
            upstream_model: "served-x".into(),
            base_url: "https://x".into(),
            path: "chat/completions".into(),
            upstream_api: "chat_completions".into(),
            openai_chatgpt: false,
            risk: "high".into(),
            requires_approval: false,
            description: None,
            enabled: true,
        },
    )
    .await
    .expect("seed model");
    sqlx::query(
        "UPDATE llm_models SET input_cost_per_mtok = 3, output_cost_per_mtok = 6 \
           WHERE tenant_id = $1 AND alias = 'gpt-x'",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("set rates");

    let sink = PgLlmUsageSink::new(pool.clone());
    sink.record_usage(LlmUsageRow {
        tenant_id: tenant.clone(),
        principal_sub: Some("alice".into()),
        model_alias: "gpt-x".into(),
        provider: "openrouter".into(),
        provider_account_id: None,
        model_served: Some("served-x".into()),
        inbound_surface: "chat_completions".into(),
        input_tokens: Some(1_000_000),
        output_tokens: Some(500_000),
        cached_read_tokens: None,
        cache_write_tokens: None,
        reasoning_tokens: None,
        finish_reason: Some("stop".into()),
        refusal: false,
        latency_ms: Some(10),
        gateway_cache_hit: false,
    })
    .await;

    let got = sqlx::query("SELECT total_cost, cost_source FROM llm_usage WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("select the recorded row");
    let total_cost: Option<Decimal> = got.get("total_cost");
    let cost_source: Option<String> = got.get("cost_source");

    // 1_000_000 * $3/Mtok + 500_000 * $6/Mtok = 3 + 3 = 6.
    assert_eq!(total_cost, Some(Decimal::from_str("6").unwrap()));
    assert_eq!(cost_source.as_deref(), Some("computed_from_catalog"));

    sqlx::query("DELETE FROM llm_usage WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup usage");
    sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup models");
}

#[tokio::test]
async fn sink_records_unknown_cost_for_an_uncataloged_served_model() {
    // Cost attributes to model_served: when the provider reports a served
    // model the catalog does not know (e.g. auto-routing to an uncataloged
    // model), the sink records Unknown cost rather than mispricing it with
    // some other model's rates. Tokens are still recorded.
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_usage uncataloged-served test: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");

    let tenant = format!("usage-uncat-test-{}", Uuid::now_v7());

    // A priced model exists for one upstream, but the call served a DIFFERENT,
    // uncataloged model — its rates must not be borrowed.
    upsert_llm_model(
        &pool,
        &LlmModelUpsert {
            tenant_id: tenant.clone(),
            alias: "gpt-x".into(),
            provider: "openrouter".into(),
            credential_label: "MAIN".into(),
            upstream_model: "openai/cataloged".into(),
            base_url: "https://x".into(),
            path: "chat/completions".into(),
            upstream_api: "chat_completions".into(),
            openai_chatgpt: false,
            risk: "high".into(),
            requires_approval: false,
            description: None,
            enabled: true,
        },
    )
    .await
    .expect("seed model");
    sqlx::query(
        "UPDATE llm_models SET input_cost_per_mtok = 3, output_cost_per_mtok = 6 \
           WHERE tenant_id = $1 AND alias = 'gpt-x'",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("set rates");

    let sink = PgLlmUsageSink::new(pool.clone());
    sink.record_usage(LlmUsageRow {
        tenant_id: tenant.clone(),
        principal_sub: Some("alice".into()),
        model_alias: "gpt-x".into(),
        provider: "openrouter".into(),
        provider_account_id: None,
        // The provider auto-routed to a model not in the catalog.
        model_served: Some("vendor/auto-routed-elsewhere".into()),
        inbound_surface: "chat_completions".into(),
        input_tokens: Some(1_000_000),
        output_tokens: Some(500_000),
        cached_read_tokens: None,
        cache_write_tokens: None,
        reasoning_tokens: None,
        finish_reason: Some("stop".into()),
        refusal: false,
        latency_ms: Some(10),
        gateway_cache_hit: false,
    })
    .await;

    let got = sqlx::query(
        "SELECT total_cost, cost_source, input_tokens FROM llm_usage WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("select the recorded row");
    let total_cost: Option<Decimal> = got.get("total_cost");
    let cost_source: Option<String> = got.get("cost_source");
    let input_tokens: Option<i64> = got.get("input_tokens");

    assert_eq!(total_cost, None, "uncataloged served model is not priced");
    assert_eq!(cost_source.as_deref(), Some("unknown"));
    assert_eq!(input_tokens, Some(1_000_000), "tokens are still recorded");

    sqlx::query("DELETE FROM llm_usage WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup usage");
    sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup models");
}

#[tokio::test]
async fn sink_prices_by_the_calls_provider_when_upstream_name_collides() {
    // Two providers expose the SAME upstream_model name with different rates.
    // The served lookup must match the call's resolved provider, not borrow the
    // other provider's pricing.
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_usage provider-disambiguation test: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");

    let tenant = format!("usage-provdis-test-{}", Uuid::now_v7());

    // Same upstream_model "shared-m" under two providers, different aliases
    // (the PK is (tenant, alias)), different rates.
    for (alias, provider) in [("a-or", "openrouter"), ("a-oai", "openai")] {
        upsert_llm_model(
            &pool,
            &LlmModelUpsert {
                tenant_id: tenant.clone(),
                alias: alias.into(),
                provider: provider.into(),
                credential_label: "MAIN".into(),
                upstream_model: "shared-m".into(),
                base_url: "https://x".into(),
                path: "chat/completions".into(),
                upstream_api: "chat_completions".into(),
                openai_chatgpt: false,
                risk: "high".into(),
                requires_approval: false,
                description: None,
                enabled: true,
            },
        )
        .await
        .expect("seed model");
    }
    // openrouter: $3/Mtok input; openai: $100/Mtok input.
    sqlx::query(
        "UPDATE llm_models SET input_cost_per_mtok = 3 WHERE tenant_id = $1 AND alias = 'a-or'",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("set openrouter rate");
    sqlx::query(
        "UPDATE llm_models SET input_cost_per_mtok = 100 WHERE tenant_id = $1 AND alias = 'a-oai'",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("set openai rate");

    let sink = PgLlmUsageSink::new(pool.clone());
    sink.record_usage(LlmUsageRow {
        tenant_id: tenant.clone(),
        principal_sub: Some("alice".into()),
        model_alias: "a-oai".into(),
        provider: "openai".into(),
        provider_account_id: None,
        model_served: Some("shared-m".into()),
        inbound_surface: "chat_completions".into(),
        input_tokens: Some(1_000_000),
        output_tokens: None,
        cached_read_tokens: None,
        cache_write_tokens: None,
        reasoning_tokens: None,
        finish_reason: Some("stop".into()),
        refusal: false,
        latency_ms: Some(10),
        gateway_cache_hit: false,
    })
    .await;

    let total_cost: Option<Decimal> =
        sqlx::query("SELECT total_cost FROM llm_usage WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("select")
            .get("total_cost");
    // Priced with openai's $100/Mtok, NOT openrouter's $3.
    assert_eq!(total_cost, Some(Decimal::from_str("100").unwrap()));

    sqlx::query("DELETE FROM llm_usage WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup usage");
    sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup models");
}
