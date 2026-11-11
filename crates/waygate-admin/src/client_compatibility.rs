//! Operator-only, tenant-confined client compatibility observations.

use crate::{
    chrome::PageChrome,
    error::{ApiError, ApiResult},
    state::AdminState,
    tenant_ctx::TenantContext,
};
use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap},
    response::{Html, IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use std::sync::Arc;
use waygate_mcp::client_observations::{
    ClientObservationQuery, ClientObservationReport, REPORT_PAGE_CAP,
};
use waygate_oidc::Principal;

fn authorize<'a>(
    principal: Option<&'a Principal>,
    tenant: Option<&TenantContext>,
) -> Result<&'a Principal, ApiError> {
    crate::scope::require_admin_extension(principal)?;
    let principal = principal.ok_or(ApiError::Unauthorized("no principal on request"))?;
    if tenant.is_some_and(|t| t.slug != principal.tenant.as_str()) {
        return Err(ApiError::Forbidden(
            "client reports are confined to the authenticated tenant",
        ));
    }
    Ok(principal)
}

fn validate(query: &ClientObservationQuery) -> Result<(), ApiError> {
    if query.subject.as_ref().is_some_and(|s| s.len() > 512)
        || query.issuer.as_ref().is_some_and(|s| s.len() > 512)
        || query
            .client
            .as_ref()
            .is_some_and(|s| s.chars().count() > 128)
        || !(1..=86_400).contains(&query.window_seconds)
        || !(1..=REPORT_PAGE_CAP).contains(&query.limit)
        || query.offset > 4096
    {
        return Err(ApiError::BadRequest(
            "client report filter exceeds its bounds".into(),
        ));
    }
    Ok(())
}

fn normalize(mut query: ClientObservationQuery) -> ClientObservationQuery {
    query.subject = query.subject.filter(|s| !s.is_empty());
    query.issuer = query.issuer.filter(|s| !s.is_empty());
    query.client = query.client.filter(|s| !s.is_empty());
    query
}

async fn api(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    Query(query): Query<ClientObservationQuery>,
) -> ApiResult<impl IntoResponse> {
    let principal = authorize(user.as_ref().map(|Extension(p)| p), None)?;
    let query = normalize(query);
    validate(&query)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(
            state
                .observability
                .clients
                .report(principal.tenant.clone(), &query),
        ),
    ))
}

#[derive(Template)]
#[template(path = "client_compatibility.html")]
struct Page {
    chrome: PageChrome,
    report: ClientObservationReport,
    subject: String,
    issuer: String,
    client: String,
    next_url: Option<String>,
}

impl Page {
    fn timestamp(&self, unix: &i64) -> String {
        time::OffsetDateTime::from_unix_timestamp(*unix)
            .map_or_else(|_| "Unknown".to_owned(), waygate_core::fmt::format_ts_abs)
    }
}

async fn page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(query): Query<ClientObservationQuery>,
) -> Response {
    let tenant = tenant.map(|Extension(t)| t);
    let query = normalize(query);
    let principal =
        match authorize(user.as_ref().map(|Extension(p)| p), tenant.as_ref()).and_then(|p| {
            validate(&query)?;
            Ok(p)
        }) {
            Ok(p) => p,
            Err(e) => return e.into_response(),
        };
    let report = state
        .observability
        .clients
        .report(principal.tenant.clone(), &query);
    let chrome = PageChrome::build(
        &state,
        "Client compatibility",
        "/client_compatibility",
        &headers,
        Some(crate::dashboard::user_display(principal)),
        tenant,
        String::new(),
    );
    let next_url = report.next_offset.map(|offset| {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer
            .append_pair("offset", &offset.to_string())
            .append_pair("limit", &query.limit.to_string())
            .append_pair("window_seconds", &query.window_seconds.to_string());
        for (key, value) in [
            ("subject", &query.subject),
            ("issuer", &query.issuer),
            ("client", &query.client),
        ] {
            if let Some(value) = value {
                serializer.append_pair(key, value);
            }
        }
        format!(
            "{}?{}",
            chrome.nav_url("/client_compatibility"),
            serializer.finish()
        )
    });
    let view = Page {
        chrome,
        report,
        subject: query.subject.unwrap_or_default(),
        issuer: query.issuer.unwrap_or_default(),
        client: query.client.unwrap_or_default(),
        next_url,
    };
    match view.render() {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Html(body)).into_response(),
        Err(e) => {
            tracing::error!(error=%e, "client compatibility template failed");
            ApiError::Internal("template render failed".into()).into_response()
        }
    }
}

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/api/v1/admin/client_compatibility", get(api))
        .with_state(state)
}

pub fn dashboard_router() -> Router<Arc<AdminState>> {
    Router::new().route("/client_compatibility", get(page))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn principal(tenant: &str) -> Principal {
        serde_json::from_value(serde_json::json!({"tenant":tenant,"issuer":"https://identity.example","sub":"operator","email":null,"groups":[],"scopes":["mcp:admin"]})).unwrap()
    }

    fn state() -> Arc<AdminState> {
        Arc::new(AdminState::new(
            Arc::new(waygate_upstream::UpstreamPool::from_manifests_disconnected(
                Default::default(),
            )),
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "https://gateway.example".into(),
        ))
    }

    #[tokio::test]
    async fn client_report_api_refuses_nonoperators_and_filters_to_authenticated_tenant() {
        let state = state();
        let p = principal("acme");
        let other = principal("other");
        state.observability.clients.observe(
            &p,
            Some("visible"),
            Some("1"),
            Some("2026-07-28"),
            "2026-07-28",
        );
        state.observability.clients.observe(
            &other,
            Some("private-other"),
            Some("2"),
            Some("2025-11-25"),
            "legacy",
        );
        let request = || {
            Request::builder()
                .uri("/api/v1/admin/client_compatibility")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            router(state.clone())
                .oneshot(request())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut reader = p.clone();
        reader.scopes = vec!["mcp:read".into()];
        let mut peer = p.clone();
        peer.auth_method = waygate_oidc::AuthMethod::PeerAssertion;
        for refused in [reader, peer] {
            assert_eq!(
                router(state.clone())
                    .layer(Extension(refused))
                    .oneshot(request())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        let response = router(state.clone())
            .layer(Extension(p.clone()))
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["rows"].as_array().unwrap().len(), 1);
        assert_eq!(report["rows"][0]["client_name"], "visible");
        let invalid = Request::builder()
            .uri("/api/v1/admin/client_compatibility?limit=101")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router(state)
                .layer(Extension(p))
                .oneshot(invalid)
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn client_report_dashboard_escapes_metadata_preserves_filters_and_refuses_other_tenant() {
        let state = state();
        let p = principal("acme");
        for name in ["<script>fixture</script>", "second"] {
            state
                .observability
                .clients
                .observe(&p, Some(name), Some("1"), None, "legacy");
        }
        let tenant = TenantContext {
            slug: "acme".into(),
            display_name: None,
            is_cross_tenant: false,
            principal_tenant: "acme".into(),
            available_tenants: vec![],
            more_tenants_available: false,
        };
        let app = dashboard_router()
            .with_state(state.clone())
            .layer(Extension(tenant.clone()))
            .layer(Extension(p.clone()));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/client_compatibility?limit=2&subject=operator&client=")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            to_bytes(response.into_body(), 512 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("fixture"));
        assert!(!body.contains("<script>fixture</script>"));
        let app = dashboard_router()
            .with_state(state.clone())
            .layer(Extension(tenant.clone()))
            .layer(Extension(p.clone()));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/client_compatibility?limit=1&subject=operator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = String::from_utf8(
            to_bytes(response.into_body(), 512 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("/admin/t/acme/client_compatibility?"));
        assert!(body.contains("subject=operator"));
        assert!(body.contains("Next page"));
        let cross = TenantContext {
            slug: "other".into(),
            is_cross_tenant: true,
            ..tenant
        };
        let app = dashboard_router()
            .with_state(state)
            .layer(Extension(cross))
            .layer(Extension(p));
        assert_eq!(
            app.oneshot(
                Request::builder()
                    .uri("/client_compatibility")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
            StatusCode::FORBIDDEN
        );
    }
}
