use serde_json::json;
use uuid::Uuid;
use waygate_catalog::pending_invocations::{
    InvocationDecision, InvocationSummary, NewInvocationRequest, PendingInvocationStore,
    PgPendingInvocationStore, RequestError,
};
use waygate_catalog::{
    CatalogStore, GrantLookup, ImportServer, ImportTool, ManifestImporter, PgCatalogStore,
};

fn server(tenant: &str, risk: &str) -> ImportServer {
    ImportServer {
        tenant_id: tenant.into(),
        name: "fixture".into(),
        transport: "http".into(),
        runtime_target: json!({"url":"http://fixture.test/mcp"}),
        classification_mode: "manifest".into(),
        tools: vec![ImportTool {
            name: "write".into(),
            approved_behavior_hash: None,
            risk: risk.into(),
            side_effects: true,
            pii: false,
            discriminator: None,
            operations: vec![],
        }],
    }
}

async fn fixture(pool: &sqlx::PgPool) -> NewInvocationRequest {
    let tenant = format!("pending-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants(id,display_name,status) VALUES($1,$1,'active')")
        .bind(&tenant)
        .execute(pool)
        .await
        .unwrap();
    ManifestImporter::new(pool.clone())
        .import_atomic(&tenant, &[server(&tenant, "high")], false)
        .await
        .unwrap();
    let tool_id:Uuid=sqlx::query_scalar("SELECT t.id FROM mcp_tools t JOIN mcp_servers s ON s.id=t.server_id WHERE s.tenant_id=$1 AND s.name='fixture' AND t.name='write'").bind(&tenant).fetch_one(pool).await.unwrap();
    let tool = PgCatalogStore::new(pool.clone())
        .resolve_live_tool_id(&tenant, tool_id)
        .await
        .unwrap()
        .unwrap();
    NewInvocationRequest {
        tenant,
        principal_issuer: "https://requester.fixture".into(),
        principal_sub: "agent".into(),
        tool_id,
        server: "fixture".into(),
        tool: "write".into(),
        behavior_hash: tool.schema_hash,
        argument_hash: waygate_catalog::argument_hash(
            json!({"payload":"synthetic-input-value"}).as_object(),
        ),
        summary: InvocationSummary {
            description: Some("Replace fixture configuration.".into()),
            affected_fields: vec!["payload".into()],
        },
    }
}

#[tokio::test]
async fn retained_requests_deduplicate_and_approve_once_with_exact_single_use_authority() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let request = fixture(&pool).await;
    let store = PgPendingInvocationStore::new(pool.clone());
    let (first, repeated) = tokio::join!(store.retain(&request), store.retain(&request));
    let id = first.unwrap();
    assert_eq!(id, repeated.unwrap());
    let pending = store.get(&request.tenant, id).await.unwrap().unwrap();
    assert_eq!(pending.status, "pending");
    assert!(store.get("other-tenant", id).await.unwrap().is_none());
    assert_eq!(store.pending(&request.tenant).await.unwrap().len(), 1);
    assert!(!serde_json::to_string(&pending.summary)
        .unwrap()
        .contains("synthetic-input-value"));
    assert!(matches!(
        store
            .decide(InvocationDecision {
                tenant: &request.tenant,
                id,
                approver_issuer: &request.principal_issuer,
                approver_sub: &request.principal_sub,
                reason: "Self approval",
                approve: true
            })
            .await,
        Err(RequestError::SelfApproval)
    ));
    let approve = || InvocationDecision {
        tenant: &request.tenant,
        id,
        approver_issuer: "https://other.fixture",
        approver_sub: &request.principal_sub,
        reason: "Reviewed exact requested effects",
        approve: true,
    };
    let (first, second) = tokio::join!(store.decide(approve()), store.decide(approve()));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(matches!(
        if first.is_err() { first } else { second },
        Err(RequestError::Changed)
    ));
    let restarted = PgPendingInvocationStore::new(pool.clone());
    let decided = restarted.get(&request.tenant, id).await.unwrap().unwrap();
    assert_eq!(decided.status, "approved");
    assert!(decided.grant_id.is_some());
    assert!(restarted.pending(&request.tenant).await.unwrap().is_empty());
    let bounded:bool=sqlx::query_scalar("SELECT g.expires_at<=r.expires_at AND g.expires_at<=r.decided_at+INTERVAL '5 minutes' FROM pending_invocation_requests r JOIN approval_grants g ON g.id=r.grant_id WHERE r.tenant_id=$1 AND r.id=$2").bind(&request.tenant).bind(id).fetch_one(&pool).await.unwrap();
    assert!(bounded);
    let catalog = PgCatalogStore::new(pool.clone());
    let binding =
        waygate_catalog::approval_binding_hash(&request.behavior_hash, &request.argument_hash);
    let lookup = || GrantLookup {
        tenant_id: &request.tenant,
        principal_issuer: &request.principal_issuer,
        principal_sub: &request.principal_sub,
        client_id: None,
        tool_id: request.tool_id,
        argument_hash: &binding,
        execution_binding: None,
    };
    let mut wrong = lookup();
    wrong.principal_issuer = "https://other.fixture";
    assert!(catalog.claim_grant(wrong).await.unwrap().is_none());
    let mut changed = lookup();
    changed.argument_hash = "unreviewed-binding";
    assert!(catalog.claim_grant(changed).await.unwrap().is_none());
    assert_eq!(
        catalog.claim_grant(lookup()).await.unwrap().unwrap().id,
        decided.grant_id.unwrap()
    );
    assert!(catalog.claim_grant(lookup()).await.unwrap().is_none());
    assert_ne!(
        restarted.retain(&request).await.unwrap(),
        id,
        "a later refused call is a new request, not replay of a decided request"
    );
    sqlx::query("DELETE FROM tenants WHERE id=$1")
        .bind(&request.tenant)
        .execute(&pool)
        .await
        .unwrap();
    assert!(restarted.get(&request.tenant, id).await.unwrap().is_none());
}

#[tokio::test]
async fn expiry_context_limits_and_capacity_cannot_become_approval_authority() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let mut request = fixture(&pool).await;
    let store = PgPendingInvocationStore::new(pool.clone());
    let id = store.retain(&request).await.unwrap();
    sqlx::query("UPDATE pending_invocation_requests SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE tenant_id=$1 AND id=$2").bind(&request.tenant).bind(id).execute(&pool).await.unwrap();
    let approve = |id| InvocationDecision {
        tenant: &request.tenant,
        id,
        approver_issuer: "https://admin.fixture",
        approver_sub: "admin",
        reason: "Reviewed exact effects",
        approve: true,
    };
    assert_eq!(
        store
            .get(&request.tenant, id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "expired"
    );
    assert!(matches!(
        store.decide(approve(id)).await,
        Err(RequestError::Changed)
    ));
    let fresh = store.retain(&request).await.unwrap();
    assert_ne!(fresh, id);
    ManifestImporter::new(pool.clone())
        .import_atomic(&request.tenant, &[server(&request.tenant, "medium")], false)
        .await
        .unwrap();
    assert!(matches!(
        store.decide(approve(fresh)).await,
        Err(RequestError::Changed)
    ));
    let grant_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM approval_grants WHERE tenant_id=$1")
            .bind(&request.tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(grant_count, 0);
    request.argument_hash = "different-request".into();
    request.summary.description = Some("x".repeat(64 * 1024 + 1));
    let unavailable = store.retain(&request).await.unwrap();
    assert!(store
        .get(&request.tenant, unavailable)
        .await
        .unwrap()
        .unwrap()
        .summary
        .is_none());
    assert!(matches!(
        store.decide(approve(unavailable)).await,
        Err(RequestError::Invalid(_))
    ));
    store
        .decide(InvocationDecision {
            approve: false,
            ..approve(unavailable)
        })
        .await
        .unwrap();
    sqlx::query("DELETE FROM pending_invocation_requests WHERE tenant_id=$1")
        .bind(&request.tenant)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO pending_invocation_requests(tenant_id,id,principal_issuer,principal_sub,tool_id,server_name,tool_name,behavior_hash,argument_hash)
        SELECT $1,gen_random_uuid(),$2,$3,$4,$5,$6,$7,'quota-'||n::text FROM generate_series(1,100) n")
        .bind(&request.tenant).bind(&request.principal_issuer).bind(&request.principal_sub).bind(request.tool_id).bind(&request.server).bind(&request.tool).bind(&request.behavior_hash).execute(&pool).await.unwrap();
    assert!(matches!(
        store.retain(&request).await,
        Err(RequestError::Capacity)
    ));
    request.argument_hash = "quota-1".into();
    assert!(
        store.retain(&request).await.is_ok(),
        "deduplication does not consume another quota slot"
    );
    sqlx::query("DELETE FROM tenants WHERE id=$1")
        .bind(&request.tenant)
        .execute(&pool)
        .await
        .unwrap();
}
