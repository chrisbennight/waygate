use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;
use waygate_admin::{dashboard_router, DashboardAuth};
use waygate_changeset::{
    ApprovalRequirement, ChangeRequestStatus, ChangeRequestStore, NewChangeRequest,
    PgChangeRequestStore,
};
use waygate_quota::{PgRateLimitPolicyStore, QuotaAction, QuotaScope, RateLimitPolicyStore};

fn post(path: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}
async fn get(app: axum::Router, path: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}
fn tokens(html: &str) -> BTreeMap<uuid::Uuid, String> {
    html.split("<input ")
        .filter(|tag| tag.split('>').next().unwrap().contains("data-bulk-item"))
        .map(|tag| {
            let value = tag
                .split("value=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .replace("&#34;", "\"")
                .replace("&quot;", "\"")
                .replace("&amp;", "&");
            let id = serde_json::from_str::<serde_json::Value>(&value).unwrap()["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            (id, value)
        })
        .collect()
}
fn form(selected: &[String], csrf: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf", csrf)
        .append_pair("reason", "Reviewed independent quotas")
        .extend_pairs(selected.iter().map(|value| ("selected", value)))
        .finish()
}

#[tokio::test]
async fn selected_changes_preserve_conditions_exact_intent_and_independent_execution() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let changes = Arc::new(PgChangeRequestStore::new(pool.clone()));
    let policies = Arc::new(PgRateLimitPolicyStore::new(pool.clone()));
    let prefix = format!("bulk-quota-{}", uuid::Uuid::new_v4());
    let mut rows = BTreeMap::new();
    for scenario in [
        "success", "partial", "quorum", "role", "factor", "cooldown", "conflict", "expired",
        "changed",
    ] {
        let mut requirement = ApprovalRequirement::single("dashboard-admins");
        match scenario {
            "partial" | "quorum" => requirement.required_approvals = 2,
            "role" => requirement.eligible_role = "quota-reviewers".into(),
            "factor" => requirement.factors = vec!["mfa".into()],
            "cooldown" => requirement.cooldown_seconds = Some(3600),
            _ => {}
        }
        let value = format!("{prefix}-{scenario}");
        let row=changes.propose(NewChangeRequest{tenant_id:"default".into(),requested_by:"propose-only-agent".into(),client_id:None,action_type:"rate_limit.create".into(),params:serde_json::json!({"name":value,"scope":"principal","scope_value":value,"action":"call","bucket_capacity":10,"refill_per_second":1.0}),preview:None,target_etag:None,justification:"Independent per-principal quota".into(),requirement,expires_at:time::OffsetDateTime::now_utc()+time::Duration::hours(2)}).await.unwrap();
        if scenario == "quorum" {
            assert!(
                changes
                    .record_approval("default", row.id, "other-admin")
                    .await
                    .unwrap()
                    .counted
            );
        }
        rows.insert(scenario, row);
    }
    let mut state = crate::admin_state::base_admin_state()
        .with_change_request_store(Some(changes.clone()))
        .with_rate_limit_policy_store(Some(policies.clone()))
        .with_decision_batches(Some(Arc::new(
            waygate_dashboard_stores::decision_batches::PgDecisionBatchStore::new(pool.clone()),
        )));
    state.evidence = Arc::new(waygate_storage::PgAuditSink::with_pool(pool.clone()));
    let app = dashboard_router(Arc::new(state), DashboardAuth::Disabled);
    let (status, list) = get(app.clone(), "/t/default/changes").await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.contains("Selected rate-limit policy creations"));
    let mut selected = Vec::new();
    for row in rows.values() {
        let (_, focused) = get(
            app.clone(),
            &format!("/t/default/changes?pending_id={}", row.id),
        )
        .await;
        selected.push(
            tokens(&focused)
                .get(&row.id)
                .expect("focused pending request offers a supported choice")
                .clone(),
        );
    }
    for variant in ["duplicate-target", "different-action", "privileged"] {
        let mut params = rows["success"].params.clone();
        if variant == "different-action" {
            params["action"] = serde_json::json!("discovery");
        }
        let row = changes
            .propose(NewChangeRequest {
                tenant_id: "default".into(),
                requested_by: "propose-only-agent".into(),
                client_id: None,
                action_type: if variant == "privileged" {
                    "api_key.mint".into()
                } else {
                    "rate_limit.create".into()
                },
                params,
                preview: None,
                target_etag: None,
                justification: "Compatibility refusal fixture".into(),
                requirement: ApprovalRequirement::single("dashboard-admins"),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
        let (_, focused) = get(
            app.clone(),
            &format!("/t/default/changes?pending_id={}", row.id),
        )
        .await;
        let choices = tokens(&focused);
        if variant == "privileged" {
            assert!(
                !choices.contains_key(&row.id),
                "privileged changes remain on individual review"
            );
        } else {
            let original = selected[rows.keys().position(|key| *key == "success").unwrap()].clone();
            assert_eq!(
                app.clone()
                    .oneshot(post(
                        "/t/default/decisions/bulk/changes/review",
                        form(&[original, choices[&row.id].clone()], "dev-csrf")
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
    }
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/t/other-tenant/decisions/bulk/changes/review",
                form(&selected, "dev-csrf")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/t/default/decisions/bulk/changes/review",
                form(&selected, "wrong")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/t/default/decisions/bulk/changes/review",
                form(&[selected[0].clone(), selected[0].clone()], "dev-csrf")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = app
        .clone()
        .oneshot(post(
            "/t/default/decisions/bulk/changes/review",
            form(&selected, "dev-csrf"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"]
        .to_str()
        .unwrap()
        .strip_prefix("/admin")
        .unwrap()
        .to_owned();
    let batch = uuid::Uuid::parse_str(location.rsplit('/').next().unwrap()).unwrap();
    let (_, review) = get(app.clone(), &location).await;
    assert!(review.contains("quota-reviewers"));
    assert!(review.contains("mfa"));
    assert!(review.contains("reviewer quorum"));
    assert!(review.contains("propose-only-agent"));
    assert_eq!(
        app.clone()
            .oneshot(post(&format!("{location}/confirm"), "csrf=dev-csrf".into()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let conflict = format!("{prefix}-conflict");
    policies
        .create(
            "default",
            "Existing live policy",
            QuotaScope::Principal,
            Some(&conflict),
            20,
            2.0,
            QuotaAction::Call,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE change_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='default' AND id=$1").bind(rows["expired"].id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE change_requests SET params=jsonb_set(params,'{bucket_capacity}','99'::jsonb) WHERE tenant_id='default' AND id=$1").bind(rows["changed"].id).execute(&pool).await.unwrap();
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
    for ((scenario, row), outcome) in rows.iter().zip(outcomes) {
        let current = changes.get("default", row.id).await.unwrap().unwrap();
        let expected = match *scenario {
            "success" | "quorum" => {
                assert_eq!(current.status, ChangeRequestStatus::Executed);
                "change_executed"
            }
            "partial" => {
                assert_eq!(current.status, ChangeRequestStatus::Pending);
                let progress = changes
                    .record_approval("default", row.id, "dev@local")
                    .await
                    .unwrap();
                assert!(!progress.recorded);
                assert_eq!(progress.collected, 1);
                "approval_recorded"
            }
            "conflict" => {
                assert_eq!(current.status, ChangeRequestStatus::Failed);
                "change_failed"
            }
            "role" | "factor" | "cooldown" => {
                assert_eq!(current.status, ChangeRequestStatus::Pending);
                "requirements_not_met"
            }
            _ => {
                assert_eq!(current.status, ChangeRequestStatus::Pending);
                "changed"
            }
        };
        assert_eq!(outcome, expected, "{scenario}");
        let (status, detail) = get(
            app.clone(),
            &format!("/t/default/changes/{}/decision-state", row.id),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(detail.contains(&format!(
            "Current state: <strong>{}</strong>",
            current
                .effective_status(time::OffsetDateTime::now_utc())
                .as_db_str()
        )));
        assert!(detail.contains(&row.id.to_string()));
        if *scenario == "cooldown" {
            assert!(changes
                .list_approvers("default", row.id)
                .await
                .unwrap()
                .is_empty());
            assert!(detail.contains("Approval is available after"));
            assert!(detail.contains(&waygate_core::fmt::format_ts_abs(
                current.created_at + time::Duration::hours(1)
            )));
        }
    }
    let (_, results) = get(app.clone(), &location).await;
    assert!(results.contains("Approval recorded toward quorum"));
    assert!(results.contains("Approval completed; execution succeeded"));
    assert!(results.contains("Execution reported failure"));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rate_limit_policies WHERE tenant_id='default' AND scope_value LIKE $1").bind(format!("{prefix}%")).fetch_one(&pool).await.unwrap();
    assert_eq!(
        count, 3,
        "only independent successful changes and the pre-existing conflicting target exist"
    );
    let evidence:i64=sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE tenant_id='default' AND action='change.bulk_approve' AND reason LIKE $1").bind(format!("%batch={batch}")).fetch_one(&pool).await.unwrap();
    assert_eq!(
        evidence, 4,
        "every recorded approval is attributed once, including failed execution"
    );
    let (status, _) = get(
        app.clone(),
        &format!(
            "/t/other-tenant/changes/{}/decision-state",
            rows["success"].id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let value = format!("{prefix}-evidence");
    let mut requirement = ApprovalRequirement::single("dashboard-admins");
    requirement.required_approvals = 2;
    let row=changes.propose(NewChangeRequest{tenant_id:"default".into(),requested_by:"propose-only-agent".into(),client_id:None,action_type:"rate_limit.create".into(),params:serde_json::json!({"name":value,"scope":"principal","scope_value":value,"action":"call","bucket_capacity":10,"refill_per_second":1.0}),preview:None,target_etag:None,justification:"Post-commit evidence fixture".into(),requirement,expires_at:time::OffsetDateTime::now_utc()+time::Duration::hours(1)}).await.unwrap();
    changes
        .record_approval("default", row.id, "bulk-evidence-reviewer")
        .await
        .unwrap();
    let (_, focused) = get(
        app.clone(),
        &format!("/t/default/changes?pending_id={}", row.id),
    )
    .await;
    let response = app
        .clone()
        .oneshot(post(
            "/t/default/decisions/bulk/changes/review",
            form(&[tokens(&focused)[&row.id].clone()], "dev-csrf"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"]
        .to_str()
        .unwrap()
        .strip_prefix("/admin")
        .unwrap()
        .to_owned();
    let batch = uuid::Uuid::parse_str(location.rsplit('/').next().unwrap()).unwrap();
    sqlx::query("ALTER TABLE audit_log ADD CONSTRAINT bulk_change_test_audit_failure CHECK(action <> 'ChangeRequestExecute' OR position('bulk-evidence-reviewer' in coalesce(reason,''))=0) NOT VALID").execute(&pool).await.unwrap();
    let response = app
        .clone()
        .oneshot(post(
            &format!("{location}/confirm"),
            "csrf=dev-csrf&reviewed=true".into(),
        ))
        .await;
    sqlx::query("ALTER TABLE audit_log DROP CONSTRAINT bulk_change_test_audit_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(response.unwrap().status(), StatusCode::SEE_OTHER);
    let stored = changes.get("default", row.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ChangeRequestStatus::Executed);
    let outcome: String = sqlx::query_scalar(
        "SELECT result->>'outcome' FROM admin_decision_batch_items WHERE batch_id=$1",
    )
    .bind(batch)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outcome, "applied_evidence_attention");
    let evidence:i64=sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE tenant_id='default' AND action='change.bulk_approve' AND reason=$1").bind(format!("change={} batch={batch}",row.id)).fetch_one(&pool).await.unwrap();
    assert_eq!(evidence, 1);
    let (_, result) = get(app.clone(), &location).await;
    assert!(result.contains("Applied; evidence needs attention"));
    assert!(result.contains(&format!("/changes/{}/decision-state", row.id)));
    let (status, detail) = get(
        app.clone(),
        &format!("/t/default/changes/{}/decision-state", row.id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(detail.contains("Current state: <strong>executed</strong>"));
    assert!(detail.contains("does not confirm"));
    assert_eq!(
        app.clone()
            .oneshot(post(
                &format!("{location}/confirm"),
                "csrf=dev-csrf&reviewed=true".into()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::SEE_OTHER
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rate_limit_policies WHERE tenant_id='default' AND scope_value=$1",
    )
    .bind(&value)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}
