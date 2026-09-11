//! Prove the `BearerLayer` actually invokes a wired
//! `PrincipalEnricher` after a validator accepts the token, and that
//! the enriched principal lands in the request extensions.
//!
//! Companion to the unit tests inside `waygate_scim::enricher` which
//! cover the enricher's own cache/miss/error semantics. This test is
//! about middleware *plumbing*: we don't want to discover at runtime
//! that wiring an enricher was a no-op.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use tower::ServiceExt;

use waygate_oidc::header_validator::HeaderValidator;
use waygate_oidc::middleware::bearer_middleware;
use waygate_oidc::validator::ValidationError;
use waygate_oidc::{
    AuthMethod, BearerLayer, Principal, PrincipalEnricher, ScimGroupRef, ScimPrincipalAttrs,
};

/// Bypass JWT validation entirely — this test is about the post-
/// validation enrichment hook. The validator just returns a fixed
/// principal so we can observe what the enricher does to it.
struct AcceptAllValidator;

#[async_trait]
impl HeaderValidator for AcceptAllValidator {
    async fn validate_header(&self, _header: &str) -> Result<Principal, ValidationError> {
        Ok(Principal {
            sub: "alice".into(),
            email: None,
            groups: vec![],
            issuer: "https://test/".into(),
            scopes: vec![],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        })
    }
}

/// Test enricher that stamps a known marker into the principal's
/// `scim` field. Assertions read it back out of the handler to
/// confirm the middleware actually called us.
struct MarkerEnricher;

#[async_trait]
impl PrincipalEnricher for MarkerEnricher {
    async fn enrich(&self, mut principal: Principal) -> Principal {
        principal.scim = Some(ScimPrincipalAttrs {
            user_id: "marker-user-id".into(),
            user_name: principal.sub.clone(),
            external_id: Some("marker-ext".into()),
            active: true,
            attrs: serde_json::json!({"marker": true}),
            groups: vec![ScimGroupRef {
                id: "marker-group-id".into(),
                display_name: "marker-group".into(),
            }],
        });
        principal
    }
}

async fn echo_scim(Extension(p): Extension<Principal>) -> impl IntoResponse {
    // Return enough of the principal that the test can prove the
    // enricher ran AND that its output reached the handler.
    let scim = p.scim.expect("enricher should have set scim");
    axum::Json(serde_json::json!({
        "sub": p.sub,
        "scim_user_id": scim.user_id,
        "scim_groups": scim.groups.iter().map(|g| g.display_name.clone()).collect::<Vec<_>>(),
    }))
}

fn router_with(layer: BearerLayer) -> Router {
    Router::new()
        .route("/", get(echo_scim))
        .layer(from_fn_with_state(layer, bearer_middleware))
}

#[tokio::test]
async fn enricher_runs_when_wired() {
    let validator: Arc<dyn HeaderValidator> = Arc::new(AcceptAllValidator);
    let layer = BearerLayer::enforce(validator, "https://gw.test/prm")
        .with_principal_enricher(Arc::new(MarkerEnricher));
    let app = router_with(layer);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_response().into_body(), 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["sub"], "alice");
    assert_eq!(v["scim_user_id"], "marker-user-id");
    assert_eq!(
        v["scim_groups"],
        serde_json::json!(["marker-group"]),
        "enricher's group must reach the handler unchanged",
    );
}

/// Without an enricher wired, the principal flows through untouched.
/// Guards against a wiring regression that would silently call some
/// default enricher (there isn't one, but assert it).
#[tokio::test]
async fn no_enricher_leaves_principal_scim_none() {
    let validator: Arc<dyn HeaderValidator> = Arc::new(AcceptAllValidator);
    let layer = BearerLayer::enforce(validator, "https://gw.test/prm");
    let app = Router::new()
        .route(
            "/",
            get(|Extension(p): Extension<Principal>| async move {
                axum::Json(serde_json::json!({"has_scim": p.scim.is_some()}))
            }),
        )
        .layer(from_fn_with_state(layer, bearer_middleware));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_response().into_body(), 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["has_scim"], false);
}

/// When the enricher returns a principal whose SCIM row is
/// `active=false`, the bearer middleware must return 403 BEFORE
/// forwarding to the handler.
/// Pins the load-bearing contract that SCIM deactivation takes
/// effect on every bearer-gated surface (not only Cedar-gated
/// tool calls).
#[tokio::test]
async fn enricher_deactivated_principal_rejected_403() {
    struct DeactivatingEnricher;
    #[async_trait]
    impl PrincipalEnricher for DeactivatingEnricher {
        async fn enrich(&self, mut principal: Principal) -> Principal {
            principal.scim = Some(ScimPrincipalAttrs {
                user_id: "u".into(),
                user_name: principal.sub.clone(),
                external_id: None,
                active: false, // ← key
                attrs: serde_json::Value::Null,
                groups: vec![],
            });
            principal
        }
    }
    let validator: Arc<dyn HeaderValidator> = Arc::new(AcceptAllValidator);
    let layer = BearerLayer::enforce(validator, "https://gw.test/prm")
        .with_principal_enricher(Arc::new(DeactivatingEnricher));
    let app: Router = Router::new()
        .route(
            "/",
            get(|| async {
                // Handler should never run for a deactivated principal.
                panic!(
                    "handler ran for SCIM-deactivated principal — bearer middleware failed to 403",
                );
                #[allow(unreachable_code)]
                StatusCode::OK
            }),
        )
        .layer(from_fn_with_state(layer, bearer_middleware));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "SCIM-deactivated principal must be rejected at the bearer layer, not reach the handler",
    );
    // WWW-Authenticate should carry the scim_inactive description
    // so a thoughtful client surfaces a useful message.
    let www = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        www.contains("scim_inactive"),
        "WWW-Authenticate must signal scim_inactive; got `{www}`",
    );
}

/// An enricher whose internal lookup fails (returns the original
/// principal) MUST NOT block the request. Matches the best-effort
/// contract on `PrincipalEnricher::enrich`.
#[tokio::test]
async fn enricher_returning_unchanged_principal_still_serves_request() {
    struct PassthroughEnricher;
    #[async_trait]
    impl PrincipalEnricher for PassthroughEnricher {
        async fn enrich(&self, principal: Principal) -> Principal {
            // Simulate the "store unreachable, return as-is" branch.
            principal
        }
    }
    let validator: Arc<dyn HeaderValidator> = Arc::new(AcceptAllValidator);
    let layer = BearerLayer::enforce(validator, "https://gw.test/prm")
        .with_principal_enricher(Arc::new(PassthroughEnricher));
    let app = Router::new()
        .route(
            "/",
            get(|Extension(p): Extension<Principal>| async move {
                axum::Json(serde_json::json!({"has_scim": p.scim.is_some()}))
            }),
        )
        .layer(from_fn_with_state(layer, bearer_middleware));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_response().into_body(), 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["has_scim"], false);
}
