//! Route-level coverage for the `/api/v1/catalog/*` read endpoints.
//!
//! Uses an in-memory `CatalogStore` fake so the test doesn't need a
//! live Postgres pool — the Pg impl is exercised by the
//! `waygate-catalog` integration suite that needs the DB anyway.
//!
//! Pins:
//! 1. `None` store ⇒ both endpoints 503 (matches the audit / sessions
//!    pattern for a DB-less deployment).
//! 2. `mcp:read` is insufficient; `mcp:admin` succeeds.
//! 3. With a wired store, the list endpoint returns the store's rows
//!    and a malformed `since` is a 400.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::util::ServiceExt;

use waygate_admin::catalog::{
    unquarantine_server_if_unchanged_core, CatalogServerUnquarantineParams,
};
use waygate_admin::{api_router, AdminState};
use waygate_catalog::{
    ApprovalAction, CatalogError, CatalogServerStatus, CatalogServerStatusChange,
    CatalogServerSummary, CatalogServerTransitionTarget, CatalogVisibility, DriftEvent,
    DriftObservation, ResolvedTool, SharedCatalogStore,
};
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;

/// Catalog store fake returning a fixed server list + empty drift.
#[derive(Default)]
struct FakeCatalog {
    servers: Vec<CatalogServerSummary>,
    /// What `set_server_status` reports: `true` ⇒ a row was
    /// updated (endpoint → 204), `false` ⇒ no such server
    /// (endpoint → 404).
    server_present: bool,
    /// Lifecycle state returned by the versioned transition lookup. Present
    /// server fixtures default to `proposed`, matching initial approval.
    transition_status: Option<CatalogServerStatus>,
    /// Optional conditional-transition outcome. `None` follows
    /// `server_present`; `Some(false)` simulates a stale reviewed row.
    transition_result: Option<bool>,
    /// What `last_approve_actor` returns. `None`
    /// means "no prior approval recorded" — the first-time-approval
    /// path. `Some("alice")` simulates Alice having previously
    /// approved the same server.
    last_approver: Option<String>,
}

#[async_trait]
impl waygate_catalog::CatalogStore for FakeCatalog {
    async fn approved_servers(
        &self,
        _tenant: &str,
    ) -> Result<Vec<CatalogServerSummary>, CatalogError> {
        Ok(self.servers.clone())
    }
    async fn resolve_tool(&self, _t: &str, _fq: &str) -> Result<ResolvedTool, CatalogError> {
        Ok(ResolvedTool::NotFound)
    }
    async fn record_drift(&self, _o: DriftObservation<'_>) -> Result<(), CatalogError> {
        Ok(())
    }
    async fn record_approval(&self, _a: ApprovalAction<'_>) -> Result<(), CatalogError> {
        Ok(())
    }
    async fn list_drift_events(
        &self,
        _t: &str,
        _since: time::OffsetDateTime,
        _limit: u32,
    ) -> Result<Vec<DriftEvent>, CatalogError> {
        Ok(vec![])
    }
    async fn set_server_status(
        &self,
        _tenant: &str,
        _server_id: uuid::Uuid,
        _status: CatalogServerStatus,
        _actor: &str,
        _reason: Option<&str>,
    ) -> Result<bool, CatalogError> {
        // `server_present` lets a test distinguish the 204
        // (updated) path from the 404 (no such server) path.
        Ok(self.server_present)
    }
    async fn server_transition_target(
        &self,
        tenant: &str,
        server_id: uuid::Uuid,
    ) -> Result<Option<CatalogServerTransitionTarget>, CatalogError> {
        if !self.server_present {
            return Ok(None);
        }
        Ok(Some(CatalogServerTransitionTarget {
            id: server_id,
            tenant_id: tenant.to_owned(),
            name: "example-messages".into(),
            status: self
                .transition_status
                .unwrap_or(CatalogServerStatus::Proposed),
            updated_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        }))
    }
    async fn transition_server_status_if_unchanged(
        &self,
        _change: CatalogServerStatusChange<'_>,
    ) -> Result<bool, CatalogError> {
        Ok(self.transition_result.unwrap_or(self.server_present))
    }
    async fn last_approve_actor(
        &self,
        _tenant: &str,
        _server_id: uuid::Uuid,
    ) -> Result<Option<String>, CatalogError> {
        Ok(self.last_approver.clone())
    }
    async fn find_grant<'a>(
        &self,
        _lookup: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, CatalogError> {
        // This fake's tests don't exercise grants
        // (that's the enforcement slice's surface). None
        // keeps existing paths unchanged.
        Ok(None)
    }
    async fn claim_grant<'a>(
        &self,
        _lookup: waygate_catalog::GrantLookup<'a>,
    ) -> Result<Option<waygate_catalog::ApprovalGrant>, CatalogError> {
        // Same reasoning — admin-API tests don't run
        // through the per-call HITL enforcement path.
        Ok(None)
    }
    async fn create_grant<'a>(
        &self,
        _grant: waygate_catalog::NewApprovalGrant<'a>,
    ) -> Result<waygate_catalog::ApprovalGrant, CatalogError> {
        // Grant mint flow has its own dedicated test
        // file with its own in-memory store fake; this fake's tests
        // don't exercise it.
        Err(CatalogError::Unknown(
            "create_grant not supported in this fake",
        ))
    }
    async fn list_grants<'a>(
        &self,
        _tenant_id: &'a str,
        _filter: waygate_catalog::GrantFilter<'a>,
    ) -> Result<Vec<waygate_catalog::ApprovalGrant>, CatalogError> {
        Ok(vec![])
    }
    async fn revoke_grant(&self, _tenant_id: &str, _id: uuid::Uuid) -> Result<bool, CatalogError> {
        Ok(false)
    }
    async fn sweep_grants(&self, _older_than: time::OffsetDateTime) -> Result<u64, CatalogError> {
        Ok(0)
    }
}

fn principal_with(scopes: &[&str]) -> Principal {
    Principal {
        sub: "admin@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn state_with_catalog(catalog: Option<SharedCatalogStore>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        catalog,
        "http://127.0.0.1:0".into(),
    ))
}

#[tokio::test]
async fn servers_503s_without_catalog() {
    let app = api_router(state_with_catalog(None).await);
    let mut req = Request::builder()
        .uri("/api/v1/catalog/servers")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn drift_503s_without_catalog() {
    let app = api_router(state_with_catalog(None).await);
    let mut req = Request::builder()
        .uri("/api/v1/catalog/drift_events")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn servers_requires_admin_scope() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog::default());
    let app = api_router(state_with_catalog(Some(catalog)).await);

    // No principal → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/catalog/servers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // mcp:read insufficient.
    let mut req = Request::builder()
        .uri("/api/v1/catalog/servers")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn servers_returns_store_rows() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        servers: vec![CatalogServerSummary {
            id: uuid::Uuid::nil(),
            tenant_id: "default".into(),
            name: "example-messages".into(),
            transport: "http".into(),
            status: CatalogServerStatus::Live,
            visibility: CatalogVisibility::TenantOnly,
            owner: None,
        }],
        ..Default::default()
    });
    let app = api_router(state_with_catalog(Some(catalog)).await);
    let mut req = Request::builder()
        .uri("/api/v1/catalog/servers")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["servers"][0]["name"], "example-messages");
    assert_eq!(body["servers"][0]["status"], "live");
}

#[tokio::test]
async fn drift_rejects_malformed_since() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog::default());
    let app = api_router(state_with_catalog(Some(catalog)).await);
    let mut req = Request::builder()
        .uri("/api/v1/catalog/drift_events?since=not-a-timestamp")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST a status transition (approve / quarantine) with an optional
/// `{ "reason": ... }` JSON body and an `mcp:admin` principal.
fn status_request(path: &str, body: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    req
}

#[tokio::test]
async fn approve_503s_without_catalog() {
    let app = api_router(state_with_catalog(None).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app.oneshot(status_request(&path, "{}")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn approve_requires_admin_scope() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog::default());
    let app = api_router(state_with_catalog(Some(catalog)).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());

    // No principal → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&path)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // mcp:read insufficient.
    let mut req = Request::builder()
        .method("POST")
        .uri(&path)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn approve_204_when_server_present() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        ..Default::default()
    });
    let app = api_router(state_with_catalog(Some(catalog)).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app
        .oneshot(status_request(&path, r#"{"reason":"vetted"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn approve_rejects_quarantined_server_direct_bypass() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        transition_status: Some(CatalogServerStatus::Quarantined),
        ..Default::default()
    });
    let app = api_router(state_with_catalog(Some(catalog)).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app
        .oneshot(status_request(&path, r#"{"reason":"restore"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body.contains("catalog.server.unquarantine"),
        "response must direct the caller to the governed recovery action: {body}",
    );
}

#[tokio::test]
async fn approve_preserves_retired_transition_behavior() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        transition_status: Some(CatalogServerStatus::Retired),
        ..Default::default()
    });
    let app = api_router(state_with_catalog(Some(catalog)).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app
        .oneshot(status_request(&path, r#"{"reason":"restore"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn governed_unquarantine_fails_closed_when_reviewed_row_is_stale() {
    let server_id = uuid::Uuid::nil();
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        transition_status: Some(CatalogServerStatus::Quarantined),
        transition_result: Some(false),
        ..Default::default()
    });
    let state = state_with_catalog(Some(catalog)).await;
    let target = CatalogServerTransitionTarget {
        id: server_id,
        tenant_id: "default".into(),
        name: "example-messages".into(),
        status: CatalogServerStatus::Quarantined,
        updated_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
    };
    let params = CatalogServerUnquarantineParams {
        server_id,
        expected_name: "example-messages".into(),
        reason: "validated catalog".into(),
    };

    let error = unquarantine_server_if_unchanged_core(
        state.as_ref(),
        "default",
        &principal_with(&["mcp:admin"]),
        &params,
        &target,
    )
    .await
    .expect_err("stale reviewed row must fail");
    assert!(
        matches!(error, waygate_admin::error::ApiError::Conflict(_)),
        "stale target must be a conflict: {error:?}",
    );
}

#[tokio::test]
async fn governed_unquarantine_returns_the_narrow_transition_result() {
    let server_id = uuid::Uuid::nil();
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        transition_status: Some(CatalogServerStatus::Quarantined),
        ..Default::default()
    });
    let state = state_with_catalog(Some(catalog)).await;
    let target = CatalogServerTransitionTarget {
        id: server_id,
        tenant_id: "default".into(),
        name: "example-messages".into(),
        status: CatalogServerStatus::Quarantined,
        updated_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
    };
    let params = CatalogServerUnquarantineParams {
        server_id,
        expected_name: "example-messages".into(),
        reason: "validated catalog".into(),
    };

    let response = unquarantine_server_if_unchanged_core(
        state.as_ref(),
        "default",
        &principal_with(&["mcp:admin"]),
        &params,
        &target,
    )
    .await
    .expect("exact quarantined target transitions");
    assert_eq!(
        state.upstreams.tool_catalog_epoch().current(),
        1,
        "a durable visibility transition must invalidate cached discovery",
    );
    assert_eq!(response.server_id, server_id);
    assert_eq!(response.server, "example-messages");
    assert_eq!(response.previous_status, "quarantined");
    assert_eq!(response.status, "live");
}

#[tokio::test]
async fn governed_unquarantine_limits_reason_characters_without_restricting_catalog_name() {
    let server_id = uuid::Uuid::nil();
    let catalog_name = "文".repeat(300);
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        transition_status: Some(CatalogServerStatus::Quarantined),
        ..Default::default()
    });
    let state = state_with_catalog(Some(catalog)).await;
    let target = CatalogServerTransitionTarget {
        id: server_id,
        tenant_id: "default".into(),
        name: catalog_name.clone(),
        status: CatalogServerStatus::Quarantined,
        updated_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
    };
    let params = CatalogServerUnquarantineParams {
        server_id,
        expected_name: catalog_name,
        reason: "文".repeat(200),
    };

    unquarantine_server_if_unchanged_core(
        state.as_ref(),
        "default",
        &principal_with(&["mcp:admin"]),
        &params,
        &target,
    )
    .await
    .expect("200 characters must not be rejected because they occupy 600 UTF-8 bytes");
}

#[tokio::test]
async fn quarantine_404_when_server_absent() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog::default());
    let app = api_router(state_with_catalog(Some(catalog)).await);
    let path = format!("/api/v1/catalog/servers/{}/quarantine", uuid::Uuid::nil());
    let resp = app.oneshot(status_request(&path, "{}")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn quarantine_accepts_empty_body() {
    // No body at all — the handler treats the reason as absent.
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        ..Default::default()
    });
    let state = state_with_catalog(Some(catalog)).await;
    let epoch = state.upstreams.tool_catalog_epoch();
    let app = api_router(state);
    let path = format!("/api/v1/catalog/servers/{}/quarantine", uuid::Uuid::nil());
    let req = Request::builder()
        .method("POST")
        .uri(&path)
        .body(Body::empty())
        .unwrap();
    let mut req = req;
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        epoch.current(),
        1,
        "quarantine must invalidate clients that cached the live server",
    );
}

// ----- Two-approver tests -----

async fn state_with_two_approver(
    catalog: Option<SharedCatalogStore>,
    enabled: bool,
) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(
        AdminState::new(
            pool,
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            catalog,
            "http://127.0.0.1:0".into(),
        )
        .with_two_approver_mode(enabled),
    )
}

fn approve_req_as(path: &str, sub: &str) -> Request<Body> {
    let mut p = principal_with(&["mcp:admin"]);
    p.sub = sub.to_owned();
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    req.extensions_mut().insert(p);
    req
}

/// When two-approver mode is OFF (the default), the same actor MUST be
/// able to approve a server even when they were the prior approver.
/// Preserves single-actor approval for deployments that haven't opted
/// in.
#[tokio::test]
async fn two_approver_off_allows_same_actor_to_re_approve() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        last_approver: Some("alice@example.com".into()),
        ..Default::default()
    });
    let app = api_router(state_with_two_approver(Some(catalog), false).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app
        .oneshot(approve_req_as(&path, "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// When two-approver mode is ON, an admin whose `sub` matches the most
/// recent prior approver of the same server MUST be refused with 409.
/// This is the headline behavior — it prevents one actor from
/// unilaterally re-promoting state they previously promoted.
#[tokio::test]
async fn two_approver_on_blocks_same_actor() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        last_approver: Some("alice@example.com".into()),
        ..Default::default()
    });
    let app = api_router(state_with_two_approver(Some(catalog), true).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app
        .oneshot(approve_req_as(&path, "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// Two-approver mode ON, BUT the calling admin differs from the prior
/// approver → approval proceeds. The rule is about distinctness, not
/// about requiring two simultaneous signers.
#[tokio::test]
async fn two_approver_on_allows_different_actor() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        last_approver: Some("alice@example.com".into()),
        ..Default::default()
    });
    let app = api_router(state_with_two_approver(Some(catalog), true).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app
        .oneshot(approve_req_as(&path, "bob@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// First-time approval (no prior approver) under two-approver mode is
/// always allowed. The rule is "no actor can approve twice," not "every
/// promotion needs two approvers," so the initial promotion proceeds.
#[tokio::test]
async fn two_approver_on_allows_first_time_approval() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        last_approver: None,
        ..Default::default()
    });
    let app = api_router(state_with_two_approver(Some(catalog), true).await);
    let path = format!("/api/v1/catalog/servers/{}/approve", uuid::Uuid::nil());
    let resp = app
        .oneshot(approve_req_as(&path, "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// Two-approver mode applies ONLY to approve (promotion to live).
/// Quarantine bypasses the rule — operators must always be able to
/// pull a misbehaving server out fast, even if they were the prior
/// approver. Without this asymmetry, a single negligent admin who
/// approved a bad server couldn't pull it back themselves.
#[tokio::test]
async fn two_approver_on_does_not_block_quarantine() {
    let catalog: SharedCatalogStore = Arc::new(FakeCatalog {
        server_present: true,
        last_approver: Some("alice@example.com".into()),
        ..Default::default()
    });
    let app = api_router(state_with_two_approver(Some(catalog), true).await);
    let path = format!("/api/v1/catalog/servers/{}/quarantine", uuid::Uuid::nil());
    let resp = app
        .oneshot(approve_req_as(&path, "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "quarantine is exempt from two-approver rule"
    );
}
