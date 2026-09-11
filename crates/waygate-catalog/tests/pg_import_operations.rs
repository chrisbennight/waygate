//! `_pg` coverage for the importer's per-operation write path.
//!
//! The manifest is the authoritative reviewed set, so importing it must land
//! the operation rows already reviewed, must drop a refinement the manifest
//! stopped naming, and must refuse a refinement more dangerous than the tool
//! it arrived through. All three are SQL — an UPSERT, an anti-join delete, and
//! a check that has to roll its transaction back — so they only hold if
//! PostgreSQL has actually run them.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset so `cargo test` on a laptop
//! without a DB passes. A clean run with the variable unset is NOT a pass.

use std::env;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
use waygate_catalog::{
    CatalogError, CatalogStore, ImportOperation, ImportServer, ImportTool, ManifestImporter,
    PgCatalogStore,
};

fn operation(value: &str, risk: &str, side_effects: bool, pii: bool) -> ImportOperation {
    ImportOperation {
        value: value.to_string(),
        risk: risk.to_string(),
        side_effects,
        pii,
    }
}

fn server(tenant: &str, operations: Vec<ImportOperation>) -> ImportServer {
    ImportServer {
        tenant_id: tenant.to_string(),
        name: "gitea".to_string(),
        transport: "http".to_string(),
        runtime_target: serde_json::json!({ "url": "http://x.test/mcp" }),
        classification_mode: "manifest".to_string(),
        tools: vec![ImportTool {
            name: "api.mutate".to_string(),
            approved_behavior_hash: None,
            risk: "high".to_string(),
            side_effects: true,
            pii: true,
            discriminator: Some("operation_id".to_string()),
            operations,
        }],
    }
}

/// Connects and migrates, or `None` when no database is configured.
async fn pool() -> Option<PgPool> {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg importer operations: AUDIT_DATABASE_URL not set");
        return None;
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
    Some(pool)
}

async fn tool_id(pool: &PgPool, tenant: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT t.id FROM mcp_tools t \
           JOIN mcp_servers s ON s.id = t.server_id \
          WHERE s.tenant_id = $1 AND s.name = 'gitea' AND t.name = 'api.mutate'",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await
    .expect("read the imported tool id")
}

/// `(operation, risk, reviewed)` for one tool, in a stable order.
async fn rows(pool: &PgPool, tool: Uuid) -> Vec<(String, String, bool)> {
    sqlx::query_as(
        "SELECT operation, risk, reviewed_at IS NOT NULL \
           FROM tool_operation_classifications WHERE tool_id = $1 ORDER BY operation",
    )
    .bind(tool)
    .fetch_all(pool)
    .await
    .expect("read the operation classifications")
}

#[tokio::test]
async fn importing_a_manifest_lands_its_operations_already_reviewed() {
    let Some(pool) = pool().await else { return };
    let tenant = format!("test-import-operations-{}", Uuid::new_v4());

    ManifestImporter::new(pool.clone())
        .import_atomic(
            &tenant,
            &[server(
                &tenant,
                vec![
                    operation("repository.create_branch", "medium", true, false),
                    operation("issue.create_issue", "low", true, false),
                ],
            )],
            true,
        )
        .await
        .expect("import a refined tool");

    let tool = tool_id(&pool, &tenant).await;

    let discriminator: Option<String> =
        sqlx::query_scalar("SELECT discriminator FROM tool_classifications WHERE tool_id = $1")
            .bind(tool)
            .fetch_one(&pool)
            .await
            .expect("read the discriminator");
    assert_eq!(
        discriminator.as_deref(),
        Some("operation_id"),
        "the argument that selects the operation must reach the catalog, or the \
         read path cannot tell which argument to look at"
    );

    assert_eq!(
        rows(&pool, tool).await,
        vec![
            ("issue.create_issue".to_string(), "low".to_string(), true),
            (
                "repository.create_branch".to_string(),
                "medium".to_string(),
                true
            ),
        ],
        "the manifest is the operator's reviewed set; a row left unreviewed \
         would be ignored by the read path and silently fall back to the tool"
    );

    // The refinement must be visible through the interface dispatch reads,
    // not merely present in the table.
    let resolved = PgCatalogStore::new(pool.clone());
    let names: Vec<String> = match resolved
        .resolve_tool(&tenant, "gitea.api.mutate")
        .await
        .expect("resolve the imported tool")
    {
        waygate_catalog::ResolvedTool::Live(def) => {
            assert_eq!(def.discriminator.as_deref(), Some("operation_id"));
            def.operations.into_iter().map(|o| o.value).collect()
        }
        other => panic!("expected a live tool, got {other:?}"),
    };
    assert_eq!(
        names,
        vec!["issue.create_issue", "repository.create_branch"]
    );
}

#[tokio::test]
async fn reimporting_replaces_the_reviewed_set_rather_than_merging_into_it() {
    let Some(pool) = pool().await else { return };
    let tenant = format!("test-import-operations-replace-{}", Uuid::new_v4());
    let importer = ManifestImporter::new(pool.clone());

    importer
        .import_atomic(
            &tenant,
            &[server(
                &tenant,
                vec![
                    operation("repository.delete", "high", true, false),
                    operation("repository.get", "low", false, false),
                ],
            )],
            true,
        )
        .await
        .expect("seed import");

    // The manifest stops naming repository.get and downgrades repository.delete.
    importer
        .import_atomic(
            &tenant,
            &[server(
                &tenant,
                vec![operation("repository.delete", "medium", true, false)],
            )],
            true,
        )
        .await
        .expect("re-import the narrowed manifest");

    assert_eq!(
        rows(&pool, tool_id(&pool, &tenant).await).await,
        vec![("repository.delete".to_string(), "medium".to_string(), true)],
        "a value the manifest no longer names must lose its refinement and fall \
         back to the tool's own row, not linger as a grant absent from the source"
    );
}

#[tokio::test]
async fn an_operation_more_dangerous_than_its_tool_is_refused_and_writes_nothing() {
    let Some(pool) = pool().await else { return };
    let tenant = format!("test-import-operations-ceiling-{}", Uuid::new_v4());

    // The tool is `high`; a `critical` operation under it would mean a value
    // nobody listed is treated more leniently than one already assessed as
    // more dangerous than the tool itself.
    let error = ManifestImporter::new(pool.clone())
        .import_atomic(
            &tenant,
            &[server(
                &tenant,
                vec![
                    operation("repository.get", "low", false, false),
                    operation("admin.delete_user", "critical", true, true),
                ],
            )],
            true,
        )
        .await
        .expect_err("an operation above its tool's ceiling must be refused");
    assert!(
        matches!(error, CatalogError::InvalidInput(_)),
        "expected invalid input, got {error:?}"
    );

    let servers: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_servers WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count the servers for this tenant");
    assert_eq!(
        servers, 0,
        "the refusal must roll back the whole import; a partially applied \
         manifest would leave the sibling operation approved on its own"
    );
}
