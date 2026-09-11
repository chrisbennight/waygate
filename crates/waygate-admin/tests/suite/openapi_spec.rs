//! OpenAPI spec contract tests.
//!
//! We don't snapshot the whole JSON (field ordering + utoipa version drift
//! would turn this into maintenance noise). Instead we assert the load-bearing
//! invariants:
//!
//! - `/api/v1/openapi.json` is reachable without a bearer token
//! - Every annotated path is present
//! - Every DTO referenced by the admin UI + CI clients has a schema entry
//! - Every local component-schema `$ref` resolves
//! - The error envelope schema is stable (`error` + `detail` fields)
//!
//! If any of those drift, the test catches it before a client or docs build
//! does.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

use waygate_admin::{api_router, AdminState};
use waygate_upstream::pool::UpstreamPool;

async fn empty_state() -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    Arc::new(AdminState::new(
        pool,
        None,
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

async fn fetch_spec() -> serde_json::Value {
    let app = api_router(empty_state().await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 256 KiB is comfortably bigger than the current spec and leaves room for
    // a handful of future endpoints without the limit surprising us.
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("response must be valid JSON")
}

#[tokio::test]
async fn openapi_json_is_served_without_auth() {
    // The point of this assertion: the spec route sits outside the scope
    // middleware so client codegen / CI lint doesn't need a bearer. If a
    // refactor accidentally pulls it under `require_read`, this fires.
    let spec = fetch_spec().await;
    assert_eq!(spec["openapi"].as_str().unwrap_or(""), "3.1.0");
    assert_eq!(
        spec["info"]["title"].as_str().unwrap_or(""),
        "Waygate Admin API"
    );
}

#[tokio::test]
async fn all_admin_paths_are_documented() {
    let spec = fetch_spec().await;
    let paths = spec["paths"].as_object().expect("paths must be an object");

    for expected in [
        "/api/v1/servers",
        "/api/v1/servers/{name}",
        "/api/v1/servers/{name}/tools",
        "/api/v1/servers/{name}/catalog/refresh",
        "/api/v1/policies",
        "/api/v1/policies/simulate",
        "/api/v1/audit",
        "/api/v1/admin/upstream_sessions",
        "/api/v1/admin/upstream_sessions/{sub}/{upstream_issuer}",
        "/api/v1/catalog/servers",
        "/api/v1/catalog/drift_events",
        "/api/v1/catalog/servers/{id}/approve",
        "/api/v1/catalog/servers/{id}/quarantine",
        "/api/v1/policy_bundles",
        "/api/v1/policy_bundles/active",
        "/api/v1/policy_bundles/{id}/publish",
        "/api/v1/policy_bundles/{version}/rollback",
    ] {
        assert!(
            paths.contains_key(expected),
            "missing path `{expected}` in OpenAPI spec"
        );
    }
}

#[tokio::test]
async fn all_dto_schemas_are_documented() {
    let spec = fetch_spec().await;
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas must be an object");

    for expected in [
        "ApiErrorBody",
        "ServerSummary",
        "ServerDetail",
        "ToolListResponse",
        "ToolView",
        "RefreshCatalogResponse",
        "PoliciesResponse",
        "SimulateRequest",
        "SimulatePrincipal",
        "SimulateAction",
        "SimulateResource",
        "SimulateResponse",
        "AuditListResponse",
        "SessionRow",
        "SessionListResponse",
        "ServerListResponse",
        "DriftListResponse",
        "StatusChangeBody",
        "BundleListResponse",
        "CreateDraftBody",
        "PolicyBundle",
        "PolicyBundleSummary",
        "PolicyStatus",
        "CatalogServerSummary",
        "CatalogServerStatus",
        "CatalogVisibility",
        "DriftEvent",
        "DriftSeverity",
        "PolicySnapshot",
        "ToolClassification",
        "RiskTier",
        "AuditRow",
    ] {
        assert!(
            schemas.contains_key(expected),
            "missing schema `{expected}` in OpenAPI spec"
        );
    }
}

fn assert_local_schema_refs_resolve(
    value: &serde_json::Value,
    schemas: &serde_json::Map<String, serde_json::Value>,
) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(|value| value.as_str()) {
                if let Some(name) = reference.strip_prefix("#/components/schemas/") {
                    assert!(
                        schemas.contains_key(name),
                        "unresolved local schema reference `{reference}`"
                    );
                }
            }
            for child in object.values() {
                assert_local_schema_refs_resolve(child, schemas);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                assert_local_schema_refs_resolve(child, schemas);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn every_local_schema_reference_resolves() {
    let spec = fetch_spec().await;
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas must be an object");

    assert_local_schema_refs_resolve(&spec, schemas);
}

#[tokio::test]
async fn error_envelope_shape_is_stable() {
    // The `{error, detail}` envelope is part of the public contract — every
    // non-2xx response uses it. Freeze the two field names here so a rename
    // forces a deliberate spec-breaking change.
    let spec = fetch_spec().await;
    let props = &spec["components"]["schemas"]["ApiErrorBody"]["properties"];
    assert!(props.get("error").is_some(), "error field missing");
    assert!(props.get("detail").is_some(), "detail field missing");
}

#[tokio::test]
async fn list_servers_documents_401_and_403() {
    // Scope gating is a security-relevant contract; downstream clients key
    // retry logic off these statuses. Keep them documented on a representative
    // read endpoint.
    let spec = fetch_spec().await;
    let responses = &spec["paths"]["/api/v1/servers"]["get"]["responses"];
    assert!(responses.get("200").is_some());
    assert!(responses.get("401").is_some());
    assert!(responses.get("403").is_some());
}

#[tokio::test]
async fn server_summary_documents_runtime_health_fields() {
    let spec = fetch_spec().await;
    let properties = &spec["components"]["schemas"]["ServerSummary"]["properties"];
    for field in [
        "runtime_status",
        "last_success_at",
        "last_error_class",
        "next_retry_at",
        "connected",
        "breaker",
        "connected_lanes",
        "total_lanes",
        "published_tool_count",
        "quarantined_tool_count",
        "rejected_output_schema_count",
    ] {
        assert!(
            properties.get(field).is_some(),
            "ServerSummary.{field} missing from OpenAPI"
        );
    }
}
