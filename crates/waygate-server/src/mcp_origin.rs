//! Reject invalid browser origins before authentication or MCP body processing.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use waygate_mcp::origin::OriginPolicy;

pub(crate) async fn guard(
    State(policy): State<OriginPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if (path == "/mcp" || path.starts_with("/mcp/")) && !policy.allows(request.headers()) {
        return (StatusCode::FORBIDDEN, "Origin is not allowed").into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn invalid_origin_is_refused_before_authentication_and_only_on_mcp_paths() {
        let app = Router::new()
            .nest("/mcp", Router::new().fallback(|| async { StatusCode::OK }))
            .route("/api/v1/other", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(|req: Request, next: Next| async move {
                if req.headers().get("authorization").is_none() {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                next.run(req).await
            }))
            .layer(middleware::from_fn_with_state(
                OriginPolicy::from_config("https://gateway.example", None).unwrap(),
                guard,
            ));
        for path in ["/mcp", "/mcp/nested", "/api/v1/other"] {
            for authenticated in [false, true] {
                for origin in [
                    None,
                    Some("https://gateway.example"),
                    Some("null"),
                    Some("https://evil.example"),
                ] {
                    let mut req = Request::builder().uri(path);
                    if let Some(origin) = origin {
                        req = req.header("origin", origin);
                    }
                    if authenticated {
                        req = req.header("authorization", "test-fixture");
                    }
                    let response = app
                        .clone()
                        .oneshot(req.body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    let expected = if path.starts_with("/mcp")
                        && matches!(origin, Some("null" | "https://evil.example"))
                    {
                        StatusCode::FORBIDDEN
                    } else if authenticated {
                        StatusCode::OK
                    } else {
                        StatusCode::UNAUTHORIZED
                    };
                    assert_eq!(
                        response.status(),
                        expected,
                        "{path}, {authenticated}, {origin:?}"
                    );
                }
            }
        }
    }
}
