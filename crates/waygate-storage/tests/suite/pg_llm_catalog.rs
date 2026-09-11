//! Live Postgres round-trip for the inference-plane model catalog
//! (`migrations/0047_llm_models.sql` + `waygate_storage::llm_catalog`).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset, so plain
//! `cargo test` (CI without the DB service, local dev) passes without
//! special-casing. When the URL is set we connect, apply migrations
//! (idempotent), exercise upsert/get/list under a unique tenant, and
//! delete our rows — leaving the database as we found it.

use std::env;

use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use waygate_storage::{
    get_llm_model, list_discovered_llm_models, list_llm_models, mark_discovered_absent,
    upsert_discovered_llm_model, upsert_llm_model, LlmDiscoveredModelUpsert, LlmModelUpsert,
    PgAuditSink,
};

fn sample(tenant: &str, alias: &str) -> LlmModelUpsert {
    LlmModelUpsert {
        tenant_id: tenant.to_string(),
        alias: alias.to_string(),
        provider: "openrouter".into(),
        credential_label: "PRIMARY".into(),
        upstream_model: "openai/gpt-4o".into(),
        base_url: "https://openrouter.ai/api/v1".into(),
        path: "chat/completions".into(),
        upstream_api: "chat_completions".into(),
        openai_chatgpt: false,
        risk: "high".into(),
        requires_approval: false,
        description: Some("frontier chat model".into()),
        enabled: true,
    }
}

#[tokio::test]
async fn images_catalog_kind_and_subscription_route_roundtrip() {
    let Some(pool) = waygate_test_support::pg::pool_or_skip("AUDIT_DATABASE_URL").await else {
        return;
    };
    PgAuditSink::migrate(&pool).await.expect("apply migrations");
    let tenant = format!("image-catalog-{}", Uuid::now_v7());
    let mut row = sample(&tenant, "gpt-image-2");
    row.provider = "openai".into();
    row.upstream_model = "gpt-image-2".into();
    row.base_url = "https://chatgpt.com/backend-api/codex".into();
    row.path = "images".into();
    row.upstream_api = "images".into();
    row.openai_chatgpt = true;
    upsert_llm_model(&pool, &row).await.unwrap();
    let model = get_llm_model(&pool, &tenant, &row.alias)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(model.upstream_api, "images");
    assert!(model.openai_chatgpt);
    let kind: String = sqlx::query_scalar(
        "SELECT kind FROM llm_models_catalog WHERE tenant_id=$1 AND tool_name=$2",
    )
    .bind(&tenant)
    .bind(&row.alias)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kind, "images");
    sqlx::query("DELETE FROM llm_models WHERE tenant_id=$1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn upsert_get_list_roundtrip() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_catalog Pg roundtrip: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");

    // Unique tenant isolates this run from any other data and makes
    // cleanup a single scoped DELETE.
    let tenant = format!("llm-cat-test-{}", Uuid::now_v7());

    // Insert.
    upsert_llm_model(&pool, &sample(&tenant, "gpt-x"))
        .await
        .expect("insert");

    let got = get_llm_model(&pool, &tenant, "gpt-x")
        .await
        .expect("get")
        .expect("row present after insert");
    assert_eq!(got.provider, "openrouter");
    assert_eq!(got.credential_label, "PRIMARY");
    assert_eq!(got.upstream_model, "openai/gpt-4o");
    assert_eq!(got.risk, "high");
    assert!(got.enabled);
    assert_eq!(got.description.as_deref(), Some("frontier chat model"));

    // Upsert again with a changed field — the ON CONFLICT path updates
    // in place rather than erroring or inserting a duplicate.
    let mut updated = sample(&tenant, "gpt-x");
    updated.risk = "medium".into();
    updated.path = "v1/chat/completions".into();
    upsert_llm_model(&pool, &updated).await.expect("update");

    let got2 = get_llm_model(&pool, &tenant, "gpt-x")
        .await
        .expect("get")
        .expect("row present after update");
    assert_eq!(got2.risk, "medium", "conflict updates the row in place");
    assert_eq!(got2.path, "v1/chat/completions");

    // A disabled model is retained (get sees it) but excluded from the
    // discovery listing.
    let mut disabled = sample(&tenant, "gpt-disabled");
    disabled.enabled = false;
    upsert_llm_model(&pool, &disabled)
        .await
        .expect("insert disabled");

    assert!(
        get_llm_model(&pool, &tenant, "gpt-disabled")
            .await
            .expect("get")
            .is_some(),
        "get returns a disabled row"
    );

    let listed = list_llm_models(&pool, &tenant).await.expect("list");
    let aliases: Vec<&str> = listed.iter().map(|m| m.alias.as_str()).collect();
    assert_eq!(
        aliases,
        vec!["gpt-x"],
        "list returns only enabled models, ordered by alias"
    );

    // Clean up — leave the database as we found it.
    sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}

// --- Dynamic model discovery (migrations/0054_llm_models_discovery.sql) -------

/// Connect + migrate, or print a visible skip and return `None` when
/// `AUDIT_DATABASE_URL` is unset (so a bare `cargo test` is "not run", not a
/// false green — CI provisions the DB).
async fn connect_or_skip(test: &str) -> Option<PgPool> {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping {test}: AUDIT_DATABASE_URL not set");
        return None;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");
    Some(pool)
}

/// A discovered-model upsert payload with no costing (callers set costing
/// fields they want to exercise).
fn discovered(tenant: &str, alias: &str, provider: &str) -> LlmDiscoveredModelUpsert {
    LlmDiscoveredModelUpsert {
        tenant_id: tenant.to_string(),
        alias: alias.to_string(),
        provider: provider.to_string(),
        credential_label: "MAIN".into(),
        upstream_model: alias.to_string(),
        base_url: "https://x".into(),
        path: "chat/completions".into(),
        upstream_api: "chat_completions".into(),
        openai_chatgpt: false,
        input_cost_per_mtok: None,
        output_cost_per_mtok: None,
        cached_read_cost_per_mtok: None,
        cache_write_cost_per_mtok: None,
        currency: None,
    }
}

/// `(source, present_upstream)` for one row — the columns the projected
/// `LlmModelRow` does not expose, read directly so the discovery contract is
/// asserted at the schema boundary.
async fn provenance(pool: &PgPool, tenant: &str, alias: &str) -> (String, bool) {
    sqlx::query_as::<_, (String, bool)>(
        "SELECT source, present_upstream FROM llm_models WHERE tenant_id = $1 AND alias = $2",
    )
    .bind(tenant)
    .bind(alias)
    .fetch_one(pool)
    .await
    .expect("provenance row")
}

/// Effective-live aliases for a tenant (what `list_llm_models` returns).
async fn live_aliases(pool: &PgPool, tenant: &str) -> Vec<String> {
    list_llm_models(pool, tenant)
        .await
        .expect("list")
        .into_iter()
        .map(|m| m.alias)
        .collect()
}

async fn cleanup(pool: &PgPool, tenant: &str) {
    sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1")
        .bind(tenant)
        .execute(pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn discovered_upsert_inserts_lists_and_sets_costing() {
    let Some(pool) = connect_or_skip("discovered_upsert_inserts_lists_and_sets_costing").await
    else {
        return;
    };
    let tenant = format!("llm-disc-{}", Uuid::now_v7());

    let mut d = discovered(&tenant, "openrouter:gpt-x", "openrouter");
    d.input_cost_per_mtok = Some(Decimal::new(3, 0));
    d.output_cost_per_mtok = Some(Decimal::new(15, 0));
    upsert_discovered_llm_model(&pool, &d)
        .await
        .expect("insert discovered");

    // A present discovered row is effective-live.
    assert_eq!(live_aliases(&pool, &tenant).await, vec!["openrouter:gpt-x"]);

    // Provenance + costing + schema-default (low) risk landed.
    let (source, present) = provenance(&pool, &tenant, "openrouter:gpt-x").await;
    assert_eq!(source, "discovered");
    assert!(present);
    let row = get_llm_model(&pool, &tenant, "openrouter:gpt-x")
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.input_cost_per_mtok, Some(Decimal::new(3, 0)));
    assert_eq!(row.output_cost_per_mtok, Some(Decimal::new(15, 0)));
    assert_eq!(
        row.risk, "low",
        "discovered rows take the schema default risk (low)"
    );
    assert!(row.enabled);
    assert!(
        !row.openai_chatgpt,
        "a non-Codex discovered row is plain-Bearer (openai_chatgpt = false)"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn discovered_upsert_persists_codex_routing() {
    let Some(pool) = connect_or_skip("discovered_upsert_persists_codex_routing").await else {
        return;
    };
    let tenant = format!("llm-disc-{}", Uuid::now_v7());

    // A Codex-surface discovered row: the Responses shape against the ChatGPT
    // backend, flagged so dispatch uses the Codex fingerprint auth. The storage
    // layer must round-trip the routing columns the refresher writes.
    let mut d = discovered(&tenant, "openai:gpt-5.5-codex", "openai");
    d.path = "responses".into();
    d.upstream_api = "responses".into();
    d.openai_chatgpt = true;
    upsert_discovered_llm_model(&pool, &d)
        .await
        .expect("insert codex discovered");

    let row = get_llm_model(&pool, &tenant, "openai:gpt-5.5-codex")
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.path, "responses");
    assert_eq!(row.upstream_api, "responses");
    assert!(
        row.openai_chatgpt,
        "the Codex ChatGPT-backend auth flag persists through upsert→select"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn discovered_upsert_fills_nulls_but_preserves_operator_costing() {
    let Some(pool) =
        connect_or_skip("discovered_upsert_fills_nulls_but_preserves_operator_costing").await
    else {
        return;
    };
    let tenant = format!("llm-disc-cost-{}", Uuid::now_v7());

    // First discovery: no costing.
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "m", "openrouter"))
        .await
        .expect("insert");

    // Operator sets the input rate by hand.
    sqlx::query(
        "UPDATE llm_models SET input_cost_per_mtok = 5 WHERE tenant_id = $1 AND alias = 'm'",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("operator set cost");

    // Next cycle reports a different input rate (would clobber) and a new output
    // rate (fills a NULL).
    let mut d = discovered(&tenant, "m", "openrouter");
    d.input_cost_per_mtok = Some(Decimal::new(9, 0));
    d.output_cost_per_mtok = Some(Decimal::new(7, 0));
    upsert_discovered_llm_model(&pool, &d)
        .await
        .expect("re-upsert");

    let row = get_llm_model(&pool, &tenant, "m").await.unwrap().unwrap();
    assert_eq!(
        row.input_cost_per_mtok,
        Some(Decimal::new(5, 0)),
        "operator-set cost is preserved (never clobbered)"
    );
    assert_eq!(
        row.output_cost_per_mtok,
        Some(Decimal::new(7, 0)),
        "a NULL cost is filled from discovery"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn discovered_upsert_adopts_currency_with_first_rates() {
    let Some(pool) = connect_or_skip("discovered_upsert_adopts_currency_with_first_rates").await
    else {
        return;
    };
    let tenant = format!("llm-disc-cur-{}", Uuid::now_v7());

    // Cycle 1: discovered, no rates → currency is the default 'USD'.
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "m", "openrouter"))
        .await
        .unwrap();
    assert_eq!(
        get_llm_model(&pool, &tenant, "m")
            .await
            .unwrap()
            .unwrap()
            .currency,
        "USD"
    );

    // Cycle 2: rates arrive in EUR. The row had NO pricing, so currency is
    // adopted alongside the filled rates rather than left at the stale default.
    let mut d = discovered(&tenant, "m", "openrouter");
    d.input_cost_per_mtok = Some(Decimal::new(3, 0));
    d.currency = Some("EUR".into());
    upsert_discovered_llm_model(&pool, &d).await.unwrap();
    let row = get_llm_model(&pool, &tenant, "m").await.unwrap().unwrap();
    assert_eq!(row.input_cost_per_mtok, Some(Decimal::new(3, 0)));
    assert_eq!(
        row.currency, "EUR",
        "currency adopts the provider unit alongside the first rates"
    );

    // Cycle 3: a later cycle reports GBP + a different rate. The row is now
    // priced, so the rate (COALESCE) AND the currency are preserved — pricing is
    // never relabeled.
    let mut d3 = discovered(&tenant, "m", "openrouter");
    d3.input_cost_per_mtok = Some(Decimal::new(9, 0));
    d3.currency = Some("GBP".into());
    upsert_discovered_llm_model(&pool, &d3).await.unwrap();
    let row = get_llm_model(&pool, &tenant, "m").await.unwrap().unwrap();
    assert_eq!(
        row.input_cost_per_mtok,
        Some(Decimal::new(3, 0)),
        "existing rate preserved"
    );
    assert_eq!(
        row.currency, "EUR",
        "currency stays locked to the first adopted pricing"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn discovered_upsert_skips_cross_currency_fill_on_priced_row() {
    let Some(pool) =
        connect_or_skip("discovered_upsert_skips_cross_currency_fill_on_priced_row").await
    else {
        return;
    };
    let tenant = format!("llm-xcur-{}", Uuid::now_v7());

    // Cycle 1: input priced in USD; output still NULL → the row is USD.
    let mut d1 = discovered(&tenant, "m", "openrouter");
    d1.input_cost_per_mtok = Some(Decimal::new(3, 0));
    d1.currency = Some("USD".into());
    upsert_discovered_llm_model(&pool, &d1).await.unwrap();
    let row = get_llm_model(&pool, &tenant, "m").await.unwrap().unwrap();
    assert_eq!(row.input_cost_per_mtok, Some(Decimal::new(3, 0)));
    assert_eq!(row.currency, "USD");
    assert!(row.output_cost_per_mtok.is_none());

    // Cycle 2: a EUR payload would fill the NULL output. Because the row is
    // already priced in USD, the cross-currency rates are NOT adopted — the
    // output stays NULL and the currency stays USD (no mislabeling).
    let mut d2 = discovered(&tenant, "m", "openrouter");
    d2.output_cost_per_mtok = Some(Decimal::new(5, 0));
    d2.currency = Some("EUR".into());
    upsert_discovered_llm_model(&pool, &d2).await.unwrap();
    let row = get_llm_model(&pool, &tenant, "m").await.unwrap().unwrap();
    assert_eq!(
        row.input_cost_per_mtok,
        Some(Decimal::new(3, 0)),
        "USD input unchanged"
    );
    assert!(
        row.output_cost_per_mtok.is_none(),
        "a cross-currency rate is not filled into a USD-priced row"
    );
    assert_eq!(
        row.currency, "USD",
        "currency unchanged by the cross-currency payload"
    );

    // Cycle 3: a matching USD payload DOES fill the still-NULL output.
    let mut d3 = discovered(&tenant, "m", "openrouter");
    d3.output_cost_per_mtok = Some(Decimal::new(9, 0));
    d3.currency = Some("USD".into());
    upsert_discovered_llm_model(&pool, &d3).await.unwrap();
    let row = get_llm_model(&pool, &tenant, "m").await.unwrap().unwrap();
    assert_eq!(
        row.output_cost_per_mtok,
        Some(Decimal::new(9, 0)),
        "a same-currency fill applies"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn discovered_upsert_does_not_clobber_config_pin() {
    let Some(pool) = connect_or_skip("discovered_upsert_does_not_clobber_config_pin").await else {
        return;
    };
    let tenant = format!("llm-disc-pin-{}", Uuid::now_v7());

    // Operator pins alias "shared" (openai) via the config path.
    let mut pin = sample(&tenant, "shared");
    pin.provider = "openai".into();
    pin.upstream_model = "gpt-4o".into();
    upsert_llm_model(&pool, &pin).await.expect("config pin");

    // Discovery sees the same alias under a different provider/route + costing.
    let mut d = discovered(&tenant, "shared", "openrouter");
    d.upstream_model = "openai/gpt-4o".into();
    d.input_cost_per_mtok = Some(Decimal::new(99, 0));
    upsert_discovered_llm_model(&pool, &d)
        .await
        .expect("gated discovered upsert");

    // The pin is untouched: still config, still the operator's route, and
    // discovery's costing did not land (provenance gate).
    assert_eq!(provenance(&pool, &tenant, "shared").await.0, "config");
    let row = get_llm_model(&pool, &tenant, "shared")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.provider, "openai", "pin provider preserved");
    assert_eq!(row.upstream_model, "gpt-4o", "pin route preserved");
    assert!(
        row.input_cost_per_mtok.is_none(),
        "discovery costing did not clobber the pin"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn reconciliation_soft_disables_then_reappear_re_enables() {
    let Some(pool) = connect_or_skip("reconciliation_soft_disables_then_reappear_re_enables").await
    else {
        return;
    };
    let tenant = format!("llm-disc-recon-{}", Uuid::now_v7());

    upsert_discovered_llm_model(&pool, &discovered(&tenant, "a", "openrouter"))
        .await
        .unwrap();
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "b", "openrouter"))
        .await
        .unwrap();
    assert_eq!(live_aliases(&pool, &tenant).await, vec!["a", "b"]);

    // A fresh discovery returns only "a" → "b" is soft-disabled.
    let affected = mark_discovered_absent(&pool, &tenant, "openrouter", &["a".to_string()])
        .await
        .unwrap();
    assert_eq!(
        affected, 1,
        "only the unseen discovered row b is marked absent"
    );
    assert_eq!(
        live_aliases(&pool, &tenant).await,
        vec!["a"],
        "absent b drops out of the listing"
    );
    // Soft-disable, not delete: the row is retained.
    assert!(get_llm_model(&pool, &tenant, "b").await.unwrap().is_some());
    assert!(!provenance(&pool, &tenant, "b").await.1);

    // The catalog view (searchTools / I7) honors the same effective-live filter.
    let view_aliases: Vec<String> = sqlx::query_scalar(
        "SELECT tool_name FROM llm_models_catalog WHERE tenant_id = $1 ORDER BY tool_name",
    )
    .bind(&tenant)
    .fetch_all(&pool)
    .await
    .expect("view");
    assert_eq!(
        view_aliases,
        vec!["a"],
        "view hides the soft-disabled model"
    );

    // "b" reappears in a later cycle → re-enabled and re-listed.
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "b", "openrouter"))
        .await
        .unwrap();
    assert_eq!(
        live_aliases(&pool, &tenant).await,
        vec!["a", "b"],
        "reappeared b is live again"
    );

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn mark_discovered_absent_scopes_to_provider_and_source() {
    let Some(pool) = connect_or_skip("mark_discovered_absent_scopes_to_provider_and_source").await
    else {
        return;
    };
    let tenant = format!("llm-disc-scope-{}", Uuid::now_v7());

    upsert_discovered_llm_model(&pool, &discovered(&tenant, "or-seen", "openrouter"))
        .await
        .unwrap();
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "or-gone", "openrouter"))
        .await
        .unwrap();
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "goog-x", "google"))
        .await
        .unwrap();
    // A config pin under the SAME provider being reconciled.
    upsert_llm_model(&pool, &sample(&tenant, "or-pinned"))
        .await
        .unwrap();

    // Reconcile an openrouter discovery that returned only "or-seen".
    let affected = mark_discovered_absent(&pool, &tenant, "openrouter", &["or-seen".to_string()])
        .await
        .unwrap();
    assert_eq!(affected, 1, "only the unseen openrouter discovered row");

    assert!(
        !provenance(&pool, &tenant, "or-gone").await.1,
        "or-gone soft-disabled"
    );
    assert!(
        provenance(&pool, &tenant, "or-seen").await.1,
        "seen row stays present"
    );
    assert!(
        provenance(&pool, &tenant, "goog-x").await.1,
        "other provider untouched"
    );
    let (pin_src, pin_present) = provenance(&pool, &tenant, "or-pinned").await;
    assert_eq!(pin_src, "config");
    assert!(
        pin_present,
        "a config pin is never soft-disabled by reconciliation"
    );

    // Idempotent: already-absent rows are not re-touched.
    let again = mark_discovered_absent(&pool, &tenant, "openrouter", &["or-seen".to_string()])
        .await
        .unwrap();
    assert_eq!(again, 0);

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn config_pin_reclaims_a_discovered_alias() {
    let Some(pool) = connect_or_skip("config_pin_reclaims_a_discovered_alias").await else {
        return;
    };
    let tenant = format!("llm-disc-reclaim-{}", Uuid::now_v7());

    // Discovery mints "x".
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "x", "openrouter"))
        .await
        .unwrap();
    assert_eq!(provenance(&pool, &tenant, "x").await.0, "discovered");

    // Operator later pins "x" → reclaimed as config.
    upsert_llm_model(&pool, &sample(&tenant, "x"))
        .await
        .unwrap();
    let (source, present) = provenance(&pool, &tenant, "x").await;
    assert_eq!(
        source, "config",
        "a pin reclaims provenance from a discovered row"
    );
    assert!(present);

    // Reconciliation for that provider can no longer disable it.
    mark_discovered_absent(&pool, &tenant, "openrouter", &[])
        .await
        .unwrap();
    assert!(
        provenance(&pool, &tenant, "x").await.1,
        "reclaimed pin survives reconciliation"
    );
    assert_eq!(live_aliases(&pool, &tenant).await, vec!["x"]);

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn config_reclaim_drops_discovery_pricing_only_on_reroute() {
    let Some(pool) =
        connect_or_skip("config_reclaim_drops_discovery_pricing_only_on_reroute").await
    else {
        return;
    };

    // (a) Reclaim a priced discovered alias to a DIFFERENT provider/upstream →
    //     the stale discovery-filled pricing (for the old route) is dropped, so
    //     llm_usage won't mis-cost the new route.
    let t_a = format!("llm-reroute-{}", Uuid::now_v7());
    let mut d = discovered(&t_a, "m", "openrouter");
    d.upstream_model = "openai/gpt-4o".into();
    d.input_cost_per_mtok = Some(Decimal::new(3, 0));
    d.currency = Some("EUR".into());
    upsert_discovered_llm_model(&pool, &d).await.unwrap();

    let mut pin = sample(&t_a, "m"); // sample() routes openrouter/openai-gpt-4o
    pin.provider = "openai".into();
    pin.upstream_model = "gpt-4o".into();
    upsert_llm_model(&pool, &pin).await.unwrap();

    let row = get_llm_model(&pool, &t_a, "m").await.unwrap().unwrap();
    assert_eq!(provenance(&pool, &t_a, "m").await.0, "config");
    assert_eq!(row.provider, "openai");
    assert!(
        row.input_cost_per_mtok.is_none(),
        "stale discovery pricing dropped when the pin re-routes the alias"
    );
    assert_eq!(
        row.currency, "USD",
        "currency reset to default with the dropped rates"
    );
    cleanup(&pool, &t_a).await;

    // (b) Reclaim a priced discovered alias to the SAME provider/upstream → the
    //     still-valid pricing is kept (discovery cannot re-fill a config row).
    let t_b = format!("llm-samepin-{}", Uuid::now_v7());
    let mut d2 = discovered(&t_b, "or", "openrouter");
    d2.upstream_model = "openai/gpt-4o".into();
    d2.input_cost_per_mtok = Some(Decimal::new(3, 0));
    upsert_discovered_llm_model(&pool, &d2).await.unwrap();

    let mut pin2 = sample(&t_b, "or");
    pin2.provider = "openrouter".into();
    pin2.upstream_model = "openai/gpt-4o".into();
    upsert_llm_model(&pool, &pin2).await.unwrap();

    let row2 = get_llm_model(&pool, &t_b, "or").await.unwrap().unwrap();
    assert_eq!(provenance(&pool, &t_b, "or").await.0, "config");
    assert_eq!(
        row2.input_cost_per_mtok,
        Some(Decimal::new(3, 0)),
        "a same-route reclaim keeps the still-valid pricing"
    );
    cleanup(&pool, &t_b).await;

    // (c) Operator-set costing on a config pin survives a redeploy that even
    //     re-points the provider — the drop fires only for source='discovered'.
    let t_c = format!("llm-redeploy-{}", Uuid::now_v7());
    upsert_llm_model(&pool, &sample(&t_c, "k")).await.unwrap();
    sqlx::query(
        "UPDATE llm_models SET input_cost_per_mtok = 4 WHERE tenant_id = $1 AND alias = 'k'",
    )
    .bind(&t_c)
    .execute(&pool)
    .await
    .unwrap();
    let mut pin3 = sample(&t_c, "k");
    pin3.provider = "openai".into();
    pin3.upstream_model = "gpt-4o".into();
    upsert_llm_model(&pool, &pin3).await.unwrap();
    let row3 = get_llm_model(&pool, &t_c, "k").await.unwrap().unwrap();
    assert_eq!(
        row3.input_cost_per_mtok,
        Some(Decimal::new(4, 0)),
        "operator-set cost on a config pin survives a redeploy / re-point"
    );
    cleanup(&pool, &t_c).await;
}

#[tokio::test]
async fn list_discovered_returns_only_live_discovered() {
    let Some(pool) = connect_or_skip("list_discovered_returns_only_live_discovered").await else {
        return;
    };
    let tenant = format!("llm-listdisc-{}", Uuid::now_v7());

    // A live discovered row, a config pin, and a discovered row that a later
    // cycle dropped (soft-disabled).
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "live", "openrouter"))
        .await
        .unwrap();
    upsert_llm_model(&pool, &sample(&tenant, "pinned"))
        .await
        .unwrap();
    upsert_discovered_llm_model(&pool, &discovered(&tenant, "gone", "openrouter"))
        .await
        .unwrap();
    mark_discovered_absent(&pool, &tenant, "openrouter", &["live".to_string()])
        .await
        .unwrap();

    // The resolver's discovered layer sees ONLY the live discovered row — not the
    // config pin (routes from env), not the soft-disabled discovered row.
    let aliases: Vec<String> = list_discovered_llm_models(&pool, &tenant)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.alias)
        .collect();
    assert_eq!(aliases, vec!["live"]);

    cleanup(&pool, &tenant).await;
}

#[tokio::test]
async fn negative_cost_rate_is_rejected() {
    // The cost columns weight token budgets and compute total_cost
    // (rate * tokens). A negative rate would *credit* a budget, so
    // the schema rejects it (CHECK llm_models_costs_nonnegative). The
    // upsert API does not expose costing yet, so this drives raw SQL —
    // pinning the constraint at the boundary regardless of writer.
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_catalog cost-constraint test: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");

    let tenant = format!("llm-cat-neg-{}", Uuid::now_v7());

    // Negative rate → rejected. A valid credential_label is supplied so
    // the ONLY violated constraint is the cost CHECK (not NOT NULL).
    let negative = sqlx::query(
        "INSERT INTO llm_models (tenant_id, alias, provider, credential_label, upstream_model, base_url, input_cost_per_mtok) \
         VALUES ($1, 'neg', 'openrouter', 'PRIMARY', 'm', 'https://x', -1)",
    )
    .bind(&tenant)
    .execute(&pool)
    .await;
    assert!(
        negative.is_err(),
        "a negative cost rate must be rejected by the CHECK constraint"
    );

    // Zero (and NULL via the column default) are accepted.
    sqlx::query(
        "INSERT INTO llm_models (tenant_id, alias, provider, credential_label, upstream_model, base_url, output_cost_per_mtok) \
         VALUES ($1, 'ok', 'openrouter', 'PRIMARY', 'm', 'https://x', 0)",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("a zero / non-negative cost rate is accepted");

    sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}
