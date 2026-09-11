use time::OffsetDateTime;
use waygate_changeset::{
    ApprovalRequirement, ChangeRequestLifecycle, ChangeRequestStatus, ChangeRequestStore,
    NewChangeRequest, PgChangeRequestStore,
};
use waygate_test_support::pg::audit_pool_or_skip;

#[tokio::test]
async fn history_summaries_preserve_metadata_without_loading_unbounded_payloads() {
    let Some(pool) = audit_pool_or_skip().await else {
        return;
    };
    let store = PgChangeRequestStore::new(pool.clone());
    let run = uuid::Uuid::new_v4().simple().to_string();
    let tenant = format!("summary-{run}");
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert test tenant");
    let proposed = store
        .propose(NewChangeRequest {
            tenant_id: tenant.clone(),
            requested_by: "agent".into(),
            client_id: None,
            action_type: "agent_config.create".into(),
            params: serde_json::json!({"large": "x".repeat(384 * 1024)}),
            preview: None,
            target_etag: None,
            justification: "exercise bounded history".into(),
            requirement: ApprovalRequirement::single("dashboard-admins"),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
        })
        .await
        .expect("propose large request");
    store
        .try_deny(&tenant, proposed.id, "human", "not approved")
        .await
        .expect("deny request")
        .expect("request transitioned");

    let executed = store
        .propose(NewChangeRequest {
            tenant_id: tenant.clone(),
            requested_by: "agent".into(),
            client_id: None,
            action_type: "agent_config.create".into(),
            params: serde_json::json!({"small": true}),
            preview: None,
            target_etag: None,
            justification: "exercise bounded history outcome".into(),
            requirement: ApprovalRequirement::single("dashboard-admins"),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
        })
        .await
        .expect("propose executable request");
    // The proposer is also the eligible admin satisfying the one-review quorum.
    store
        .try_approve(&tenant, executed.id, "agent")
        .await
        .expect("approve request")
        .expect("request transitioned");
    store
        .try_begin_execution(&tenant, executed.id)
        .await
        .expect("claim request")
        .expect("request claimed");
    store
        .mark_executed(
            &tenant,
            executed.id,
            serde_json::json!({"large": "x".repeat(384 * 1024)}),
        )
        .await
        .expect("record result")
        .expect("request executed");
    assert_eq!(store.count_pending_up_to(&tenant, 50).await.unwrap(), 0);

    let pending = store
        .propose(NewChangeRequest {
            tenant_id: tenant.clone(),
            requested_by: "agent".into(),
            client_id: None,
            action_type: "agent_config.update".into(),
            params: serde_json::json!({"large": "x".repeat(384 * 1024)}),
            preview: None,
            target_etag: None,
            justification: "exercise payload-free maker listing".into(),
            requirement: ApprovalRequirement::single("dashboard-admins"),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
        })
        .await
        .expect("propose large pending request");

    let summaries = store
        .list_summaries(&tenant, Some(ChangeRequestLifecycle::Decided), 50, 0)
        .await
        .expect("list bounded history");
    assert_eq!(summaries.len(), 2);
    let summary = summaries
        .iter()
        .find(|summary| summary.id == proposed.id)
        .expect("denied summary");
    assert_eq!(summary.id, proposed.id);
    assert_eq!(summary.action_type, proposed.action_type);
    assert_eq!(summary.requested_by, proposed.requested_by);
    assert_eq!(summary.status, ChangeRequestStatus::Denied);
    assert_eq!(summary.denied_reason.as_deref(), Some("not approved"));
    let outcome = summaries
        .iter()
        .find(|summary| summary.id == executed.id)
        .and_then(|summary| summary.execution_result_preview.as_deref())
        .expect("bounded execution-result preview");
    assert_eq!(outcome.chars().count(), 201);
    assert!(outcome.ends_with('…'));
    assert!(
        summaries
            .iter()
            .find(|summary| summary.id == executed.id)
            .is_some_and(|summary| summary.execution_result.is_none()),
        "oversized structured receipts must remain outside history summaries"
    );

    let statuses = store
        .list_for_requester(&tenant, "agent", None, 500, 0)
        .await
        .expect("list payload-free maker statuses");
    assert_eq!(statuses.len(), 3);
    assert!(statuses.iter().any(|status| status.id == pending.id));
    assert!(
        statuses
            .iter()
            .find(|status| status.id == executed.id)
            .expect("executed status")
            .execution_result
            .is_none(),
        "oversized execution results are fetched only from the individual status endpoint"
    );
    assert_eq!(store.count_pending_up_to(&tenant, 50).await.unwrap(), 1);
    assert_eq!(store.count_pending_up_to(&tenant, 1).await.unwrap(), 1);

    let stored_size: i32 = sqlx::query_scalar(
        "SELECT octet_length(params::text) FROM change_requests WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&tenant)
    .bind(proposed.id)
    .fetch_one(&pool)
    .await
    .expect("stored payload size");
    assert!(stored_size > 300_000, "fixture must store a large payload");
}
