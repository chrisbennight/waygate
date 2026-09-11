//! PostgreSQL contract test for quarantine-on-absence during a full manifest reconcile.
//!
//! `import_atomic(.., quarantine_absent = true)` must flip a `live` server that
//! is ABSENT from the reconciled set to `quarantined` (a status flip, NEVER a
//! delete — deleting would fall through to `resolve_invocation_tool`'s unknown-tool
//! least-sensitive default), while leaving a present server `live` and an
//! operator-`retired` absent server untouched (only `live` is flipped).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset so `cargo test` on a laptop
//! without a DB passes. Mirrors `waygate-tenants::tests::pg_backfill_smoke`.

use std::env;

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;
use waygate_catalog::{ImportServer, ImportTool, ManifestImporter};

fn srv(tenant: &str, name: &str) -> ImportServer {
    ImportServer {
        tenant_id: tenant.to_string(),
        name: name.to_string(),
        transport: "http".to_string(),
        runtime_target: serde_json::json!({ "url": "http://x.test/mcp" }),
        classification_mode: "manifest".to_string(),
        tools: vec![ImportTool {
            name: "send".to_string(),
            approved_behavior_hash: None,
            risk: "low".to_string(),
            side_effects: true,
            pii: false,
            discriminator: None,
            operations: Vec::new(),
        }],
    }
}

async fn status_of(pool: &sqlx::PgPool, tenant: &str, name: &str) -> Option<String> {
    sqlx::query("SELECT status FROM mcp_servers WHERE tenant_id = $1 AND name = $2")
        .bind(tenant)
        .bind(name)
        .fetch_optional(pool)
        .await
        .expect("query mcp_servers.status")
        .map(|r| r.get::<String, _>("status"))
}

#[tokio::test]
async fn quarantine_absent_flips_only_live_absent_servers() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg quarantine_absent: AUDIT_DATABASE_URL not set");
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
    let tenant = format!("test-2b-quarantine-{}", Uuid::new_v4());
    let importer = ManifestImporter::new(pool.clone());

    // Seed a..c all live (quarantine_absent is a no-op here — all present).
    importer
        .import_atomic(
            &tenant,
            &[srv(&tenant, "a"), srv(&tenant, "b"), srv(&tenant, "c")],
            true,
        )
        .await
        .expect("seed import");
    let legacy_mode: String = sqlx::query_scalar(
        "SELECT classification_mode FROM mcp_servers \
         WHERE tenant_id = $1 AND name = 'a'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("read legacy classification mode");
    assert_eq!(legacy_mode, "manifest");

    // Operator-retire `c` — an authoritative block the reconcile must NOT clobber.
    sqlx::query("UPDATE mcp_servers SET status = 'retired' WHERE tenant_id = $1 AND name = 'c'")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("operator-retire c");

    // Reconcile to {a} only: b (live) and c (retired) are absent from the full set.
    let stats = importer
        .import_atomic(&tenant, &[srv(&tenant, "a")], true)
        .await
        .expect("reconcile to {a}");

    assert_eq!(
        status_of(&pool, &tenant, "a").await.as_deref(),
        Some("live"),
        "present server stays live"
    );
    assert_eq!(
        status_of(&pool, &tenant, "b").await.as_deref(),
        Some("quarantined"),
        "absent LIVE server is quarantined (status flip, not deleted)"
    );
    assert!(
        status_of(&pool, &tenant, "b").await.is_some(),
        "absent server row must remain (quarantined, never deleted)"
    );
    assert_eq!(
        status_of(&pool, &tenant, "c").await.as_deref(),
        Some("retired"),
        "operator-retired absent server is preserved (only `live` is flipped)"
    );
    assert_eq!(
        stats.quarantined, 1,
        "exactly one server (b) was auto-quarantined; c was not live"
    );

    let mut annotation_native = srv(&tenant, "annotation-native");
    annotation_native.classification_mode = "mcp_annotations".to_string();
    annotation_native.tools[0].approved_behavior_hash = Some("a".repeat(64));
    let imported = importer.import(&[annotation_native]).await;
    assert!(imported.errors.is_empty());
    let annotation_mode: String = sqlx::query_scalar(
        "SELECT classification_mode FROM mcp_servers \
         WHERE tenant_id = $1 AND name = 'annotation-native'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("read annotation classification mode");
    assert_eq!(annotation_mode, "mcp_annotations");
    let metadata_slots: (String, Option<serde_json::Value>, Option<serde_json::Value>) =
        sqlx::query_as(
            "SELECT v.schema_hash, v.tool_annotations, v.action_metadata \
             FROM mcp_tool_versions v \
             JOIN mcp_tools t ON t.id = v.tool_id \
             JOIN mcp_servers s ON s.id = t.server_id \
             WHERE s.tenant_id = $1 AND s.name = 'annotation-native'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("read security metadata slots");
    assert_eq!(metadata_slots, ("a".repeat(64), None, None));

    // The auto-quarantine is audited in catalog_approvals (mirrors operator
    // status transitions), so an absence quarantine is as traceable.
    let approval_reason: String = sqlx::query_scalar(
        "SELECT a.reason FROM catalog_approvals a \
         JOIN mcp_servers s ON s.id = a.subject_id \
         WHERE s.tenant_id = $1 AND s.name = 'b' \
           AND a.action = 'quarantined' AND a.actor = 'manifest-reconcile'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("read catalog_approvals reason for b");
    assert_eq!(
        approval_reason, "auto-quarantined: server absent from the reconciled manifest set",
        "the auto-quarantine evidence names the accepted manifest source"
    );

    // Re-adding a server restores only an absence quarantine owned by the
    // reconciler. It must not make an operator-retired peer callable again.
    importer
        .import_atomic(
            &tenant,
            &[srv(&tenant, "a"), srv(&tenant, "b"), srv(&tenant, "c")],
            true,
        )
        .await
        .expect("re-add auto-quarantined b");
    assert_eq!(
        status_of(&pool, &tenant, "b").await.as_deref(),
        Some("live"),
        "a returning server is callable after its reconcile-owned quarantine"
    );
    assert_eq!(
        status_of(&pool, &tenant, "c").await.as_deref(),
        Some("retired"),
        "re-add must preserve an operator retirement"
    );
    let restore_reason: String = sqlx::query_scalar(
        "SELECT a.reason FROM catalog_approvals a \
         JOIN mcp_servers s ON s.id = a.subject_id \
         WHERE s.tenant_id = $1 AND s.name = 'b' \
           AND a.action = 'approved' AND a.actor = 'manifest-reconcile' \
         ORDER BY a.created_at DESC, a.id DESC LIMIT 1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("read auto-restore evidence for b");
    assert_eq!(
        restore_reason,
        "auto-restored: server returned to the reconciled manifest set"
    );

    // A later operator quarantine supersedes the reconciler's lifecycle
    // evidence and remains authoritative across another present-set import.
    sqlx::query(
        "WITH changed AS ( \
             UPDATE mcp_servers SET status = 'quarantined', updated_at = now() \
              WHERE tenant_id = $1 AND name = 'b' RETURNING id \
         ) \
         INSERT INTO catalog_approvals \
             (id, tenant_id, subject_type, subject_id, subject_version_hash, \
              action, actor, reason) \
         SELECT $2, $1, 'server', id, NULL, 'quarantined', 'operator-test', \
                'manual quarantine must survive reconcile' FROM changed",
    )
    .bind(&tenant)
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await
    .expect("operator-quarantine b");
    importer
        .import_atomic(
            &tenant,
            &[srv(&tenant, "a"), srv(&tenant, "b"), srv(&tenant, "c")],
            true,
        )
        .await
        .expect("reconcile operator-quarantined b");
    assert_eq!(
        status_of(&pool, &tenant, "b").await.as_deref(),
        Some("quarantined"),
        "operator quarantine must not be cleared by manifest presence"
    );

    // A clean empty set is authoritative for exactly its named tenant. It must
    // quarantine that tenant's live rows without crossing into another tenant.
    let empty_tenant = format!("test-empty-reconcile-{}", Uuid::new_v4());
    let neighbor_tenant = format!("test-empty-neighbor-{}", Uuid::new_v4());
    importer
        .import_atomic(&empty_tenant, &[srv(&empty_tenant, "only-server")], true)
        .await
        .expect("seed empty-reconcile tenant");
    importer
        .import_atomic(&neighbor_tenant, &[srv(&neighbor_tenant, "neighbor")], true)
        .await
        .expect("seed neighbor tenant");
    let empty_stats = importer
        .import_atomic(&empty_tenant, &[], true)
        .await
        .expect("reconcile authoritative empty set");
    assert_eq!(empty_stats.quarantined, 1);
    assert_eq!(
        status_of(&pool, &empty_tenant, "only-server")
            .await
            .as_deref(),
        Some("quarantined")
    );
    assert_eq!(
        status_of(&pool, &neighbor_tenant, "neighbor")
            .await
            .as_deref(),
        Some("live"),
        "an empty reconcile must remain tenant-scoped"
    );

    // Routine and concurrent convergence of the same accepted generation must
    // not manufacture fresh approval history. One server approval and one tool
    // version approval are durable for this generation.
    let evidence_tenant = format!("test-reconcile-evidence-{}", Uuid::new_v4());
    let evidence_servers = vec![srv(&evidence_tenant, "evidence-server")];
    importer
        .import_atomic(&evidence_tenant, &evidence_servers, true)
        .await
        .expect("initial evidence reconcile");
    let initial_state: (String, String, String) = sqlx::query_as(
        "SELECT s.updated_at::text, v.schema_hash, v.approved_at::text \
         FROM mcp_servers s \
         JOIN mcp_tools t ON t.server_id = s.id AND t.name = 'send' \
         JOIN mcp_tool_versions v ON v.tool_id = t.id \
         WHERE s.tenant_id = $1 AND s.name = 'evidence-server' \
         ORDER BY v.approved_at DESC LIMIT 1",
    )
    .bind(&evidence_tenant)
    .fetch_one(&pool)
    .await
    .expect("read initial reconcile state");
    sqlx::query("SELECT pg_sleep(0.01)")
        .execute(&pool)
        .await
        .expect("separate timestamp observations");
    let (first, second) = tokio::join!(
        importer.import_atomic(&evidence_tenant, &evidence_servers, true),
        importer.import_atomic(&evidence_tenant, &evidence_servers, true),
    );
    first.expect("first concurrent reconcile");
    second.expect("second concurrent reconcile");
    importer
        .import_atomic(&evidence_tenant, &evidence_servers, true)
        .await
        .expect("routine repeated reconcile");
    let repeated_state: (String, String) = sqlx::query_as(
        "SELECT s.updated_at::text, v.approved_at::text \
         FROM mcp_servers s \
         JOIN mcp_tools t ON t.server_id = s.id AND t.name = 'send' \
         JOIN mcp_tool_versions v ON v.tool_id = t.id \
         WHERE s.tenant_id = $1 AND s.name = 'evidence-server' \
         ORDER BY v.approved_at DESC LIMIT 1",
    )
    .bind(&evidence_tenant)
    .fetch_one(&pool)
    .await
    .expect("read repeated reconcile state");
    assert_eq!(
        repeated_state,
        (initial_state.0.clone(), initial_state.2.clone()),
        "unchanged convergence must preserve CAS and approval timestamps"
    );
    let evidence: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor, reason FROM catalog_approvals \
         WHERE tenant_id = $1 AND action = 'approved' ORDER BY subject_type",
    )
    .bind(&evidence_tenant)
    .fetch_all(&pool)
    .await
    .expect("read reconcile approval evidence");
    assert_eq!(evidence.len(), 2, "one server + one tool-version approval");
    assert!(evidence
        .iter()
        .all(|(actor, reason)| actor == "manifest-reconcile"
            && reason == "reconciled from an accepted manifest generation"));

    // A manifest rollback must reactivate the accepted version rather than
    // leaving the superseded version selected by its newer approval timestamp.
    let mut changed_servers = evidence_servers.clone();
    changed_servers[0].tools[0].pii = true;
    importer
        .import_atomic(&evidence_tenant, &changed_servers, true)
        .await
        .expect("activate changed version");
    let changed_server_updated_at: String = sqlx::query_scalar(
        "SELECT updated_at::text FROM mcp_servers \
         WHERE tenant_id = $1 AND name = 'evidence-server'",
    )
    .bind(&evidence_tenant)
    .fetch_one(&pool)
    .await
    .expect("read changed server witness");
    assert_ne!(
        changed_server_updated_at, initial_state.0,
        "authorization fact changes must invalidate the parent CAS witness"
    );
    let changed_hash: String = sqlx::query_scalar(
        "SELECT v.schema_hash FROM mcp_tool_versions v \
         JOIN mcp_tools t ON t.id = v.tool_id \
         JOIN mcp_servers s ON s.id = t.server_id \
         WHERE s.tenant_id = $1 AND s.name = 'evidence-server' \
         ORDER BY v.approved_at DESC LIMIT 1",
    )
    .bind(&evidence_tenant)
    .fetch_one(&pool)
    .await
    .expect("read changed selected version");
    assert_ne!(changed_hash, initial_state.1);
    sqlx::query("SELECT pg_sleep(0.01)")
        .execute(&pool)
        .await
        .expect("separate rollback timestamp");
    importer
        .import_atomic(&evidence_tenant, &evidence_servers, true)
        .await
        .expect("reactivate original version");
    let rollback_hash: String = sqlx::query_scalar(
        "SELECT v.schema_hash FROM mcp_tool_versions v \
         JOIN mcp_tools t ON t.id = v.tool_id \
         JOIN mcp_servers s ON s.id = t.server_id \
         WHERE s.tenant_id = $1 AND s.name = 'evidence-server' \
         ORDER BY v.approved_at DESC LIMIT 1",
    )
    .bind(&evidence_tenant)
    .fetch_one(&pool)
    .await
    .expect("read rollback selected version");
    assert_eq!(rollback_hash, initial_state.1);

    // Best-effort cleanup (per-test tenant; CI DB is ephemeral, so residue is
    // harmless if an FK without ON DELETE CASCADE blocks the delete).
    let _ = sqlx::query("DELETE FROM mcp_servers WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM mcp_servers WHERE tenant_id = ANY($1)")
        .bind(&[empty_tenant, neighbor_tenant, evidence_tenant])
        .execute(&pool)
        .await;
}
