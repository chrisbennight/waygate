//! Requests a rolling restart lets finish before the MCP transport closes.
//!
//! Shutdown waits on one work tracker for in-flight requests and detached
//! Code Mode runs, and closes the MCP transport only afterward. The tracker
//! wraps the authenticated surface outside authentication, so a request still
//! being authenticated when shutdown begins is counted. Standing notification
//! streams are not work: a `GET` stream and a 2026-07-28
//! `subscriptions/listen` stream never end on their own, so counting them
//! would hold every restart open for the whole drain window. The HTTP server's
//! own graceful shutdown still waits for any other read.

use axum::body::Body;
use axum::extract::Request;
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use futures::StreamExt;
use tokio_util::task::TaskTracker;

const HEADER_MCP_METHOD: &str = "Mcp-Method";

/// Hold a drain token until the request's response body has been sent or
/// dropped, so a streamed result keeps the transport open until it is written.
pub async fn track_request(work: TaskTracker, request: Request, next: Next) -> Response {
    let standing = request.method() != Method::POST
        || request
            .headers()
            .get(HEADER_MCP_METHOD)
            .is_some_and(|method| method == "subscriptions/listen");
    if standing {
        return next.run(request).await;
    }
    let token = work.token();
    next.run(request).await.map(|body| {
        Body::from_stream(body.into_data_stream().inspect(move |_| {
            let _ = &token;
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::any;
    use tower::ServiceExt;

    fn router(work: TaskTracker) -> axum::Router {
        axum::Router::new()
            .route("/mcp", any(|| async { "result" }))
            .layer(axum::middleware::from_fn(move |request, next| {
                let work = work.clone();
                async move { track_request(work, request, next).await }
            }))
    }

    #[tokio::test]
    async fn request_holds_drain_until_its_body_is_consumed() {
        let work = TaskTracker::new();
        let response = router(work.clone())
            .oneshot(
                Request::post("/mcp")
                    .header(HEADER_MCP_METHOD, "tools/call")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            work.len(),
            1,
            "an unsent result keeps the request in flight"
        );
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(work.is_empty(), "a sent result releases the drain");
    }

    #[tokio::test]
    async fn standing_streams_never_hold_the_drain() {
        let work = TaskTracker::new();
        for request in [
            Request::get("/mcp").body(Body::empty()).expect("request"),
            Request::post("/mcp")
                .header(HEADER_MCP_METHOD, "subscriptions/listen")
                .body(Body::empty())
                .expect("request"),
        ] {
            let _response = router(work.clone())
                .oneshot(request)
                .await
                .expect("response");
            assert!(work.is_empty());
        }
    }
}
