use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use waygate_admin::{dashboard_router, DashboardAuth};
use waygate_catalog::pending_invocations::{InvocationSummary, NewInvocationRequest};
use waygate_catalog::{CatalogStore, ImportServer, ImportTool, ManifestImporter, PgCatalogStore};

async fn get(app: axum::Router, path: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}
fn decision(id: Uuid, action: &str, csrf: &str, reviewed: bool) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/default/invocation-requests/{id}/decide"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "csrf={csrf}&reason=Reviewed+exact+request&action={action}&reviewed={reviewed}"
        )))
        .unwrap()
}

#[tokio::test]
async fn direct_requests_are_reviewable_and_issue_only_one_grant_with_required_evidence() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let name = format!("invocation-{}", Uuid::new_v4());
    ManifestImporter::new(pool.clone())
        .import_atomic(
            "default",
            &[ImportServer {
                tenant_id: "default".into(),
                name: name.clone(),
                transport: "http".into(),
                runtime_target: serde_json::json!({"url":"http://fixture.test/mcp"}),
                classification_mode: "manifest".into(),
                tools: vec![ImportTool {
                    name: "write".into(),
                    approved_behavior_hash: None,
                    risk: "high".into(),
                    side_effects: true,
                    pii: false,
                    discriminator: None,
                    operations: vec![],
                }],
            }],
            false,
        )
        .await
        .unwrap();
    let tool_id:Uuid=sqlx::query_scalar("SELECT t.id FROM mcp_tools t JOIN mcp_servers s ON s.id=t.server_id WHERE s.tenant_id='default' AND s.name=$1").bind(&name).fetch_one(&pool).await.unwrap();
    let catalog = Arc::new(PgCatalogStore::new(pool.clone()));
    let tool = catalog
        .resolve_live_tool_id("default", tool_id)
        .await
        .unwrap()
        .unwrap();
    let mut draft = NewInvocationRequest {
        tenant: "default".into(),
        principal_issuer: "https://requester.fixture".into(),
        principal_sub: "agent".into(),
        tool_id,
        server: name.clone(),
        tool: "write".into(),
        behavior_hash: tool.schema_hash,
        argument_hash: "first-argument-digest".into(),
        summary: InvocationSummary {
            description: Some("Replace <script>untrusted()</script> configura\u{200B}tion".into()),
            affected_fields: vec!["payload".into()],
        },
    };
    let requests = catalog.pending_invocations().unwrap();
    let id = requests.retain(&draft).await.unwrap();
    let mut state = crate::admin_state::base_admin_state();
    state.servers.catalog.set(Some(catalog));
    state.evidence = Arc::new(waygate_storage::PgAuditSink::with_pool(pool.clone()));
    let app = dashboard_router(Arc::new(state), DashboardAuth::Disabled);
    let (status, list) = get(app.clone(), "/t/default/invocation-requests").await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.contains(&format!("request={id}")));
    assert!(!list.contains("<script>untrusted()</script>"));
    assert!(list.contains("U+200B"));
    assert!(!list.contains('\u{200B}'));
    let url = format!("/t/default/invocation-requests?request={id}");
    let (status, review) = get(app.clone(), &url).await;
    assert_eq!(status, StatusCode::OK);
    assert!(review.contains("Argument values are not stored"));
    assert!(review.contains("Approve this invocation request"));
    assert_eq!(
        get(
            app.clone(),
            &format!("/t/other-tenant/invocation-requests?request={id}")
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(decision(id, "approve", "wrong", true))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(decision(id, "approve", "dev-csrf", false))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let (first, retry) = tokio::join!(
        app.clone()
            .oneshot(decision(id, "approve", "dev-csrf", true)),
        app.clone()
            .oneshot(decision(id, "approve", "dev-csrf", true))
    );
    assert_eq!(first.unwrap().status(), StatusCode::SEE_OTHER);
    assert_eq!(retry.unwrap().status(), StatusCode::SEE_OTHER);
    let decided = requests.get("default", id).await.unwrap().unwrap();
    assert_eq!(decided.status, "approved");
    assert!(decided.grant_id.is_some());
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approval_grants WHERE tenant_id='default' AND tool_id=$1",
    )
    .bind(tool_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    let evidence:i64=sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE tenant_id='default' AND action='invocation.approve' AND reason=$1").bind(format!("request={id}")).fetch_one(&pool).await.unwrap();
    assert_eq!(evidence, 1);
    draft.argument_hash = "second-argument-digest".into();
    let denied = requests.retain(&draft).await.unwrap();
    assert_eq!(
        app.clone()
            .oneshot(decision(denied, "deny", "dev-csrf", true))
            .await
            .unwrap()
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        requests
            .get("default", denied)
            .await
            .unwrap()
            .unwrap()
            .status,
        "denied"
    );
    draft.principal_issuer = "local-dev".into();
    draft.principal_sub = "dev@local".into();
    let own = requests.retain(&draft).await.unwrap();
    let (_, review) = get(
        app.clone(),
        &format!("/t/default/invocation-requests?request={own}"),
    )
    .await;
    assert!(!review.contains(">Approve this invocation request</button>"));
    assert_eq!(
        app.clone()
            .oneshot(decision(own, "approve", "dev-csrf", true))
            .await
            .unwrap()
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        requests.get("default", own).await.unwrap().unwrap().status,
        "pending"
    );
}
