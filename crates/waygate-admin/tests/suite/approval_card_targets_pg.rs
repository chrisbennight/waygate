//! Approval cards name each change's target and show current → proposed
//! values from the live stores.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use waygate_admin::{dashboard_router, DashboardAuth};
use waygate_changeset::{
    ApprovalRequirement, ChangeRequestStore, NewChangeRequest, PgChangeRequestStore,
};
use waygate_dashboard_stores::agent_config::{
    AgentConfigFields, AgentConfigStore, AgentKind, InMemoryAgentConfigStore,
};
use waygate_quota::{PgRateLimitPolicyStore, QuotaAction, QuotaScope, RateLimitPolicyStore};
use waygate_rbac::{PgRbacStore, RbacStore};

fn request(action_type: &str, params: serde_json::Value) -> NewChangeRequest {
    NewChangeRequest {
        tenant_id: "default".into(),
        requested_by: "propose-only-agent".into(),
        client_id: None,
        action_type: action_type.into(),
        params,
        preview: None,
        target_etag: None,
        justification: "Maintenance".into(),
        requirement: ApprovalRequirement::single("dashboard-admins"),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    }
}

async fn card(app: &axum::Router, id: uuid::Uuid) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/default/changes?pending_id={id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(
        to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

/// The text before the exact parameters: the title, changes, and outcome.
fn summary(html: &str) -> &str {
    &html[..html.find("Exact parameters").expect("exact parameters")]
}

#[tokio::test]
async fn cards_name_targets_and_show_current_and_proposed_values() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let changes = Arc::new(PgChangeRequestStore::new(pool.clone()));
    let limits = Arc::new(PgRateLimitPolicyStore::new(pool.clone()));
    let rbac = Arc::new(PgRbacStore::new(pool.clone()));
    let agents = Arc::new(InMemoryAgentConfigStore::new());

    let limit_name = format!("search-burst-{suffix}");
    let limit = limits
        .create(
            "default",
            &limit_name,
            QuotaScope::Principal,
            Some("alice"),
            60,
            1.0,
            QuotaAction::Call,
        )
        .await
        .unwrap();
    let role_name = format!("operators-{suffix}");
    let role = rbac
        .create_role(
            "default",
            &role_name,
            None,
            &["mcp:read".to_owned(), "mcp:invoke".to_owned()],
        )
        .await
        .unwrap();
    let holder = format!("bob-{suffix}");
    rbac.create_assignment("default", role.id, &holder)
        .await
        .unwrap();
    let agent_name = format!("triage-{suffix}");
    let agent = agents
        .insert(
            "default",
            AgentConfigFields {
                name: &agent_name,
                kind: AgentKind::Chat,
                model_alias: "small",
                instructions: None,
                allowed_tools: &["docs.search".to_owned()],
                max_steps: 10,
                max_tool_calls: 20,
                token_budget: None,
                enabled: true,
            },
        )
        .await
        .unwrap();

    let delete_limit = changes
        .propose(request("rate_limit.delete", json!({"policy_id": limit.id})))
        .await
        .unwrap();
    let update_limit = changes
        .propose(request(
            "rate_limit.update",
            json!({"policy_id": limit.id, "bucket_capacity": 120}),
        ))
        .await
        .unwrap();
    let missing_limit = changes
        .propose(request(
            "rate_limit.delete",
            json!({"policy_id": uuid::Uuid::new_v4()}),
        ))
        .await
        .unwrap();
    let update_role = changes
        .propose(request(
            "rbac.role.update",
            json!({"id": role.id, "name": role_name, "scopes": ["mcp:read", "mcp:admin:read"]}),
        ))
        .await
        .unwrap();
    let delete_role = changes
        .propose(request("rbac.role.delete", json!({"id": role.id})))
        .await
        .unwrap();
    let update_agent = changes
        .propose(request(
            "agent_config.update",
            json!({"agent_id": agent.id, "config": {"name": agent_name, "kind": "chat",
                "model_alias": "large", "allowed_tools": ["docs.search", "docs.fetch"],
                "max_steps": 10, "max_tool_calls": 20, "enabled": true}}),
        ))
        .await
        .unwrap();

    let state = crate::admin_state::base_admin_state()
        .with_change_request_store(Some(changes.clone()))
        .with_rate_limit_policy_store(Some(limits.clone()))
        .with_rbac_store(Some(rbac.clone()))
        .with_agent_configs(Some(agents.clone()));
    let app = dashboard_router(Arc::new(state), DashboardAuth::Disabled);

    // A deletion names its target and the settings that go with it.
    let html = card(&app, delete_limit.id).await;
    let text = summary(&html);
    assert!(text.contains(&format!(
        "<strong>Delete rate limit “{limit_name}”</strong>"
    )));
    assert!(text.contains("Applies to: Every call by principal “alice”"));
    assert!(text.contains("Limit: capacity 60, refilling 1 per second"));
    assert!(
        !text.contains(&limit.id.to_string()),
        "IDs stay with the exact parameters"
    );
    assert!(html.contains(r#"<details class="params-review">"#));
    assert!(html.contains(">Approve<"));

    // An update shows only what changes.
    let html = card(&app, update_limit.id).await;
    let text = summary(&html);
    assert!(text.contains(&format!(
        "<strong>Change rate limit “{limit_name}”</strong>"
    )));
    assert!(text.contains("Capacity: 60 → 120"));
    assert!(!text.contains("Refill per second"));

    // A missing target blocks approval and keeps the parameters open.
    let html = card(&app, missing_limit.id).await;
    assert!(html.contains("Approval unavailable:</strong> The rate limit no longer exists."));
    assert!(!html.contains(">Approve<"));

    // A list replacement shows what is added and removed.
    let html = card(&app, update_role.id).await;
    let text = summary(&html);
    assert!(text.contains(&format!("<strong>Change role “{role_name}”</strong>")));
    assert!(text.contains("Scopes added: “mcp:admin:read”"));
    assert!(text.contains("Scopes removed: “mcp:invoke”"));
    assert!(!text.contains("Name:"));

    // Deleting a role names who loses it.
    let html = card(&app, delete_role.id).await;
    let text = summary(&html);
    assert!(text.contains(&format!("<strong>Delete role “{role_name}”</strong>")));
    assert!(text.contains(&format!("Assigned to: “{holder}”")));

    let html = card(&app, update_agent.id).await;
    let text = summary(&html);
    assert!(text.contains(&format!(
        "<strong>Change gateway agent “{agent_name}”</strong>"
    )));
    assert!(text.contains("Model: “small” → “large”"));
    assert!(text.contains("Tools added: “docs.fetch”"));
    assert!(!text.contains("Step limit"));
}
