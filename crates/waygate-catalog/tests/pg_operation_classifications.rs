//! `_pg` coverage for the per-operation classification read.
//!
//! `resolve_tool` folds `tool_operation_classifications` rows into the resolved
//! definition inside the single round-trip the dispatch path allows. That fold
//! is dynamic SQL — a correlated `jsonb_agg` with a review filter — so the
//! aggregate shape, the column names the decoder expects, and the review
//! predicate only hold if PostgreSQL has actually run them.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset so `cargo test` on a laptop
//! without a DB passes. A clean run with the variable unset is NOT a pass.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use waygate_catalog::{
    CatalogStore, ImportServer, ImportTool, ManifestImporter, PgCatalogStore, ResolvedTool,
};

fn server(tenant: &str) -> ImportServer {
    ImportServer {
        tenant_id: tenant.to_string(),
        name: "example-secrets".to_string(),
        transport: "http".to_string(),
        runtime_target: serde_json::json!({ "url": "http://x.test/mcp" }),
        classification_mode: "manifest".to_string(),
        tools: vec![ImportTool {
            name: "read".to_string(),
            approved_behavior_hash: None,
            risk: "high".to_string(),
            side_effects: true,
            pii: true,
            discriminator: None,
            operations: Vec::new(),
        }],
    }
}

#[tokio::test]
async fn resolve_tool_returns_reviewed_operation_classifications_only() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg operation classifications: AUDIT_DATABASE_URL not set");
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

    // Per-test tenant so concurrent runs don't race.
    let tenant = format!("test-operation-classifications-{}", Uuid::new_v4());
    ManifestImporter::new(pool.clone())
        .import_atomic(&tenant, &[server(&tenant)], true)
        .await
        .expect("seed import");

    let tool_id: Uuid = sqlx::query_scalar(
        "SELECT t.id FROM mcp_tools t \
           JOIN mcp_servers s ON s.id = t.server_id \
          WHERE s.tenant_id = $1 AND s.name = 'example-secrets' AND t.name = 'read'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("read the imported tool id");

    sqlx::query("UPDATE tool_classifications SET discriminator = 'operation' WHERE tool_id = $1")
        .bind(tool_id)
        .execute(&pool)
        .await
        .expect("name the discriminator");

    // Two reviewed refinements and one still awaiting review.
    sqlx::query(
        "INSERT INTO tool_operation_classifications \
             (tool_id, operation, risk, side_effects, pii, reviewed_at, reviewer) \
         VALUES \
             ($1, 'projects.list',  'low',    false, false, now(), 'operator'), \
             ($1, 'secrets.list',   'medium', false, true,  now(), 'operator'), \
             ($1, 'secrets.reveal', 'low',    false, false, NULL,  NULL)",
    )
    .bind(tool_id)
    .execute(&pool)
    .await
    .expect("insert operation classifications");

    let store = PgCatalogStore::new(pool.clone());
    let resolved = store
        .resolve_tool(&tenant, "example-secrets.read")
        .await
        .expect("resolve the tool");

    let ResolvedTool::Live(def) = resolved else {
        panic!("expected a live tool, got {resolved:?}");
    };

    assert_eq!(def.discriminator.as_deref(), Some("operation"));

    let names: Vec<&str> = def.operations.iter().map(|o| o.value.as_str()).collect();
    assert_eq!(
        names,
        vec!["projects.list", "secrets.list"],
        "an unreviewed row is not yet an operator's decision, so it must not be \
         returned as a refinement; the tool-level classification stands for it"
    );

    let listed = def
        .operations
        .iter()
        .find(|o| o.value == "secrets.list")
        .expect("the reviewed medium-risk entry is present");
    assert_eq!(listed.risk, "medium", "risk decodes from the aggregate");
    assert!(!listed.side_effects, "flags decode from the aggregate");
    assert!(listed.pii, "flags decode from the aggregate");
}

#[tokio::test]
async fn resolve_tool_returns_an_empty_list_for_a_tool_with_no_operations() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg operation classifications: AUDIT_DATABASE_URL not set");
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

    let tenant = format!("test-operation-none-{}", Uuid::new_v4());
    ManifestImporter::new(pool.clone())
        .import_atomic(&tenant, &[server(&tenant)], true)
        .await
        .expect("seed import");

    let resolved = PgCatalogStore::new(pool.clone())
        .resolve_tool(&tenant, "example-secrets.read")
        .await
        .expect("resolve the tool");

    let ResolvedTool::Live(def) = resolved else {
        panic!("expected a live tool, got {resolved:?}");
    };

    // Every tool imported today is in this shape: the `COALESCE` has to render
    // the absent aggregate as an empty list rather than a SQL NULL the decoder
    // would have to interpret.
    assert!(def.discriminator.is_none());
    assert!(def.operations.is_empty());
}
