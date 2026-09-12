//! Live-Postgres API contracts for audited mutations and retained inspection rules.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::util::ServiceExt;

use waygate_admin::{api_router, AdminState};
use waygate_dashboard_stores::inspection_rules::PgInspectionRulesStore;
use waygate_oidc::Principal;
use waygate_quota::PgRateLimitPolicyStore;
use waygate_storage::PgAuditSink;
use waygate_test_support::pg::audit_pool_or_skip;
use waygate_upstream::pool::UpstreamPool;

fn admin_principal() -> Principal {
    Principal {
        sub: "admin@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: vec!["mcp:admin".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn req(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let mut r = b.body(body).unwrap();
    r.extensions_mut().insert(admin_principal());
    r
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Exactly one admin_mutation audit row for `action` whose reason names the
/// mutated row's id — the end-to-end contract of the shared recorder.
async fn assert_one_audit_row(pool: &sqlx::PgPool, action: &str, id_marker: &str) {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log \
         WHERE category = 'admin_mutation' AND action = $1 AND reason LIKE '%' || $2 || '%'",
    )
    .bind(action)
    .bind(id_marker)
    .fetch_one(pool)
    .await
    .expect("audit_log query");
    assert_eq!(
        n, 1,
        "expected exactly one {action} audit row naming {id_marker}"
    );
}

#[tokio::test]
async fn supported_mutations_emit_audit_and_custom_rule_writes_are_refused() {
    let Some(pool) = audit_pool_or_skip().await else {
        return;
    };
    let url = std::env::var("AUDIT_DATABASE_URL").expect("guarded by audit_pool_or_skip");
    let sink = PgAuditSink::connect(&url).await.expect("pg audit sink");

    let upstreams = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let state = Arc::new(
        AdminState::new(
            upstreams,
            None,
            None,
            Arc::new(sink),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_rate_limit_policy_store(Some(Arc::new(PgRateLimitPolicyStore::new(pool.clone()))))
        .with_inspection_rules_store(Some(Arc::new(PgInspectionRulesStore::new(pool.clone())))),
    );
    let app = api_router(state);
    let run = uuid::Uuid::new_v4().simple().to_string();

    // ---- rate_limit_policies: create → update → delete ----
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/rate_limit_policies",
            Some(json!({
                "name": format!("audit-pin-{run}"),
                "scope": "principal",
                "scope_value": format!("sub-{run}"),
                "bucket_capacity": 10,
                "refill_per_second": 1.0,
                "action": "call",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let policy_id = body_json(resp).await["id"].as_str().unwrap().to_owned();

    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            &format!("/api/v1/admin/rate_limit_policies/{policy_id}"),
            Some(json!({ "bucket_capacity": 20 })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/admin/rate_limit_policies/{policy_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Seed retained data directly; public writes must not create inert controls.
    let rule_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO inspection_rules (id, tenant_id, inspector, name, config, applies_to, enabled) VALUES ($1::uuid, 'default', 'pii', $2, '{}'::jsonb, '{}'::jsonb, true)")
        .bind(&rule_id).bind(format!("audit-pin-{run}")).execute(&pool).await.unwrap();
    let detail = format!("/api/v1/admin/inspection_rules/{rule_id}");
    for (method, path) in [
        ("POST", "/api/v1/admin/inspection_rules"),
        ("PATCH", detail.as_str()),
    ] {
        let response = app
            .clone()
            .oneshot(req(method, path, Some(json!({}))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
    let response = app
        .clone()
        .oneshot(req("GET", &detail, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let row = body_json(response).await;
    assert_eq!(row["enforcement"], "not_enforced");
    assert_eq!(row["enabled"], true);
    let listed = body_json(
        app.clone()
            .oneshot(req("GET", "/api/v1/admin/inspection_rules", None))
            .await
            .unwrap(),
    )
    .await;
    assert!(listed["rules"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["enforcement"] == "not_enforced"));
    for method in ["GET", "DELETE"] {
        let mut other = req(method, &detail, None);
        let mut principal = admin_principal();
        principal.tenant = "other-tenant".parse().unwrap();
        other.extensions_mut().insert(principal);
        assert_eq!(
            app.clone().oneshot(other).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/admin/inspection_rules/{rule_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // ---- the audit rows, matched by action + the mutated row's id ----
    assert_one_audit_row(&pool, "rate_limit_policies.create", &policy_id).await;
    assert_one_audit_row(&pool, "rate_limit_policies.update", &policy_id).await;
    assert_one_audit_row(&pool, "rate_limit_policies.delete", &policy_id).await;
    assert_one_audit_row(&pool, "InspectionRuleDeleted", &rule_id).await;
}
