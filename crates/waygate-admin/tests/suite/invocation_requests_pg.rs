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
    let executions = Arc::new(waygate_codemode::PgExecutionStore::new(pool.clone()));
    let mut state = crate::admin_state::base_admin_state()
        .with_decision_batches(Some(Arc::new(
            waygate_dashboard_stores::decision_batches::PgDecisionBatchStore::new(pool.clone()),
        )))
        .with_codemode_execution_store(Some(executions.clone()));
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

    use waygate_codemode::{
        ExecutionEventKind, ExecutionStatus, ExecutionStore, ExecutionTransition, NewExecutionEvent,
    };
    for source in ["direct", "code_mode"] {
        for action in ["approve", "deny"] {
            let mut selected = Vec::new();
            let mut ids = Vec::new();
            for suffix in ["first", "second"] {
                let id = if source == "direct" {
                    draft.principal_issuer = "https://requester.fixture".into();
                    draft.principal_sub = "agent".into();
                    draft.argument_hash = format!("bulk-{action}-{suffix}");
                    requests.retain(&draft).await.unwrap()
                } else {
                    let id = Uuid::new_v4();
                    let source_text =
                        "return await connectors.fixture.write({payload:'reviewed'});";
                    let digest = waygate_codemode::source_digest(source_text);
                    executions.submit(waygate_codemode::NewExecution{id,tenant_id:"default".into(),principal_issuer:"https://requester.fixture".into(),principal_sub:"agent".into(),source:Some(source_text.into()),program_input:None,source_digest:digest.clone(),execution_profile:serde_json::json!({"name":"approval_bound_mutation"}),sdk_contract_version:1,runner_contract_version:3,retention_until:time::OffsetDateTime::now_utc()+time::Duration::days(1)}).await.unwrap();
                    let (_, claim) = executions
                        .claim(
                            "default",
                            id,
                            Uuid::new_v4(),
                            std::time::Duration::from_secs(30),
                            source_text.into(),
                            serde_json::json!({"contract_version":1,"bindings":[]}),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    let approval = serde_json::json!({"connector":name,"operation":"write","argument_hash":format!("{action}-{suffix}"),"arguments_preview":{"payload":"[redacted]"},"description":"Reviewed one call","risk":"high","source_digest":digest,"call_id":Uuid::new_v4(),"step":1,"contract":{"authority":{"authority":"catalog","tool_id":tool_id,"catalog_schema_hash":draft.behavior_hash}},"prior_effects":1});
                    let request_digest = waygate_catalog::argument_hash(approval.as_object());
                    executions
                        .transition(
                            &claim,
                            ExecutionTransition {
                                from: vec![ExecutionStatus::Running],
                                to: ExecutionStatus::WaitingForApproval,
                                event: NewExecutionEvent {
                                    kind: ExecutionEventKind::WaitingForApproval,
                                    step_number: None,
                                    call_id: None,
                                    attempt: None,
                                    detail: serde_json::json!({}),
                                },
                                terminal_reason_code: None,
                                result_metadata: None,
                                result_payload: None,
                                resume_context: Some(serde_json::json!({"approval":approval})),
                            },
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    selected.push(
                        serde_json::json!({"source":"code_mode","id":id,"digest":request_digest})
                            .to_string(),
                    );
                    id
                };
                if source == "direct" {
                    selected.push(serde_json::json!({"source":"direct","id":id}).to_string());
                }
                ids.push(id);
            }
            let (_, list) = get(app.clone(), "/t/default/invocation-requests").await;
            assert!(list.contains(if source == "direct" {
                "bulk-direct-invocations"
            } else {
                "bulk-codemode-invocations"
            }));
            let (_, inbox) = get(app.clone(), "/t/default/decisions").await;
            assert!(inbox.contains(&ids[0].to_string()));
            let form = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("csrf", "dev-csrf")
                .append_pair("reason", "Reviewed exact calls")
                .append_pair("action", action)
                .extend_pairs(selected.iter().map(|value| ("selected", value)))
                .finish();
            let response = app
                .clone()
                .oneshot(post("/t/default/decisions/bulk/invocations/review", form))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let location = response.headers()["location"]
                .to_str()
                .unwrap()
                .strip_prefix("/admin")
                .unwrap()
                .to_owned();
            let batch = Uuid::parse_str(location.rsplit('/').next().unwrap()).unwrap();
            let (status, review) = get(app.clone(), &location).await;
            assert_eq!(status, StatusCode::OK);
            assert!(review.contains("Reviewed exact calls"));
            assert!(review.contains("does not confirm execution"));
            if source == "direct" {
                app.clone()
                    .oneshot(decision(ids[1], "deny", "dev-csrf", true))
                    .await
                    .unwrap();
            } else {
                executions
                    .deny_waiting_approval(
                        "default",
                        ids[1],
                        "other-admin",
                        Some("Concurrent decision"),
                        None,
                    )
                    .await
                    .unwrap();
            }
            let confirm = || {
                post(
                    &format!("{location}/confirm"),
                    "csrf=dev-csrf&reviewed=true".into(),
                )
            };
            let (first, retry) = tokio::join!(
                app.clone().oneshot(confirm()),
                app.clone().oneshot(confirm())
            );
            assert_eq!(first.unwrap().status(), StatusCode::SEE_OTHER);
            assert_eq!(retry.unwrap().status(), StatusCode::SEE_OTHER);
            let outcomes:Vec<String>=sqlx::query_scalar("SELECT result->>'outcome' FROM admin_decision_batch_items WHERE batch_id=$1 ORDER BY item_index").bind(batch).fetch_all(&pool).await.unwrap();
            assert_eq!(
                outcomes,
                vec![
                    if action == "approve" {
                        "grant_issued"
                    } else {
                        "invocation_denied"
                    },
                    "changed"
                ]
            );
            if source == "direct" {
                assert_eq!(
                    requests
                        .get("default", ids[0])
                        .await
                        .unwrap()
                        .unwrap()
                        .status,
                    if action == "approve" {
                        "approved"
                    } else {
                        "denied"
                    }
                );
            } else {
                let execution = executions.get("default", ids[0]).await.unwrap().unwrap();
                assert_eq!(
                    execution.status,
                    if action == "approve" {
                        ExecutionStatus::WaitingForApproval
                    } else {
                        ExecutionStatus::Failed
                    }
                );
                let count:i64=sqlx::query_scalar("SELECT count(*) FROM approval_grants WHERE tenant_id='default' AND execution_id=$1").bind(ids[0]).fetch_one(&pool).await.unwrap();
                assert_eq!(count, if action == "approve" { 1 } else { 0 });
            }
            let (_, results) = get(app.clone(), &location).await;
            assert!(results.contains("Invocation decision results"));
        }
    }
}

fn post(path: &str, form: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap()
}
