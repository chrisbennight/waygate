//! Promote structured rmcp JSON-RPC errors to the HTTP status +
//! headers that OAuth-aware clients expect.
//!
//! rmcp's `StreamableHttpService` returns every JSON-RPC error
//! inside an HTTP 200 OK body per JSON-RPC over HTTP semantics.
//! That's correct for the protocol but unhelpful for two
//! gateway-specific errors:
//!
//! - `insufficient_scope` (step-up): RFC 6750 §3 wants a 403
//!   with `WWW-Authenticate: Bearer error="insufficient_scope",
//!   scope="<required>"` so an OAuth-aware client can detect
//!   the step-up without parsing the JSON-RPC body.
//! - `rate_limited`: RFC 6585 §4 wants a 429 with a
//!   `Retry-After: <seconds>` header so generic HTTP clients
//!   can implement backoff without knowing about JSON-RPC.
//!
//! This middleware sits in front of the rmcp service. After
//! the inner service returns, it peeks at the response body. If
//! the JSON envelope's `result.error` field matches one of the
//! two structured errors, it rewrites:
//!
//! - status code → 403 or 429
//! - adds the matching header
//! - body kept verbatim so existing rmcp clients that DO read
//!   the body still see the same `data` envelope
//!
//! Streaming responses (SSE / chunked) are passed through
//! unchanged — tool-call responses are non-streaming in this
//! gateway today, and applying body inspection to a stream
//! would either buffer the whole thing (defeating streaming)
//! or risk corrupting the framing.
//!
//! ## Why not change the rmcp adapter?
//!
//! rmcp's `StreamableHttpService` doesn't expose a hook to
//! customise the HTTP-layer status code from an inner JSON-RPC
//! error. Forking the adapter would be a much larger change for
//! the same outcome. A response-rewriting middleware is the
//! smallest-blast-radius shape and is testable in isolation.

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use axum::middleware::Next;
use futures::StreamExt;
use tokio_util::bytes::Bytes;

/// Cap is large enough to cover every realistic JSON-RPC error
/// envelope (KB-scale) but small enough to keep the buffering
/// cost bounded for tool-call success bodies that happen to be
/// JSON. Responses larger than this are passed through
/// unchanged via the streaming-reconstruct path — every byte we
/// read into the head buffer is re-emitted, then the tail of
/// the original stream chains on. Nothing is dropped.
///
/// Deliberately do NOT pre-check `Content-Length`: gating on its
/// presence would miss legitimate JSON-RPC error envelopes sent
/// without it (chunked / hyper-default encoding). The streaming
/// buffer below correctly handles "we don't know how big this
/// is" by reading until either MAX_BUFFER_BYTES or end-of-stream,
/// whichever comes first.
const MAX_BUFFER_BYTES: usize = 64 * 1024;

/// Wrap a downstream rmcp response: when the JSON-RPC body
/// carries a structured `insufficient_scope` or `rate_limited`
/// error in its `result.error` field, promote the response to
/// the corresponding HTTP status + add the right header. The
/// body bytes are kept verbatim so JSON-RPC clients still see
/// the same envelope.
///
/// `resource_metadata_url` is threaded in from the server's
/// composition root so the 403 challenge can include the
/// resource-metadata URL per RFC 9728 §5.1, matching the bearer
/// middleware's 401 shape.
pub async fn promote_mcp_errors(
    req: Request<Body>,
    next: Next,
    resource_metadata_url: String,
) -> Response<Body> {
    let resp = next.run(req).await;

    // Non-JSON responses (SSE, plain text, binary) skip the
    // inspection entirely — the classifier targets JSON-RPC
    // error envelopes and nothing else has the structured
    // `error.data.error` shape we look for.
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/json"))
        .unwrap_or(false);
    if !is_json {
        return resp;
    }

    let original_status = resp.status();
    let (parts, body) = resp.into_parts();

    // Stream-buffer up to MAX_BUFFER_BYTES. On overflow we don't
    // lose data — we reconstruct the body by chaining the head
    // bytes we read with the rest of the original stream and
    // forward it unchanged. On end-of-stream within the cap we
    // have the complete body for classification.
    match buffer_or_passthrough(body).await {
        BufferOutcome::Complete(bytes) => {
            // When the classifier doesn't recognise the
            // envelope, preserve the ORIGINAL status rather than
            // defaulting to OK.
            let (status, extra_header) = classify(&bytes, &resource_metadata_url, original_status);
            let mut new_parts = parts;
            new_parts.status = status;
            if let Some((name, value)) = extra_header {
                new_parts.headers.insert(name, value);
            }
            Response::from_parts(new_parts, Body::from(bytes))
        }
        BufferOutcome::Overflow(reconstructed) => {
            // Body exceeded MAX_BUFFER_BYTES. We've already
            // consumed the head; rebuild the body with head +
            // remaining stream so the client gets every byte.
            // Original status is preserved.
            Response::from_parts(parts, reconstructed)
        }
        BufferOutcome::ReadError(e) => {
            tracing::warn!(
                error = ?e,
                "mcp_http_promote: response body read error during inspection",
            );
            let mut p = parts;
            p.status = StatusCode::BAD_GATEWAY;
            Response::from_parts(p, Body::empty())
        }
    }
}

enum BufferOutcome {
    /// Body fully buffered within `MAX_BUFFER_BYTES`. Safe to
    /// inspect + rewrite.
    Complete(Bytes),
    /// Body exceeded the cap; head + remaining stream are
    /// stitched back into a passthrough body so no bytes are
    /// dropped.
    Overflow(Body),
    /// Genuine read error from the underlying body. Surfaces
    /// as a 502.
    ReadError(axum::Error),
}

/// Stream-read up to `MAX_BUFFER_BYTES` of the body. If
/// end-of-stream comes first, return the complete buffer. If we
/// hit the cap with
/// frames remaining, reconstruct the body by chaining the
/// already-read head onto the remainder so a passthrough
/// emits every byte the inner service produced. On any read
/// error, surface it for the caller to map to a 502.
async fn buffer_or_passthrough(body: Body) -> BufferOutcome {
    let mut stream = body.into_data_stream();
    let mut head = Vec::with_capacity(4096);
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(chunk) => {
                if head.len() + chunk.len() > MAX_BUFFER_BYTES {
                    // Overflow path: stitch head + remaining
                    // stream back together. The current chunk
                    // wasn't pushed into head, so it gets
                    // re-emitted first as part of the
                    // remainder via futures::stream::once.
                    let head_bytes = Bytes::from(head);
                    let tail = stream;
                    let reconstructed = futures::stream::once(async move { Ok(head_bytes) })
                        .chain(futures::stream::once(async move { Ok(chunk) }))
                        .chain(tail);
                    return BufferOutcome::Overflow(Body::from_stream(reconstructed));
                }
                head.extend_from_slice(&chunk);
            }
            Err(e) => return BufferOutcome::ReadError(e),
        }
    }
    BufferOutcome::Complete(Bytes::from(head))
}

/// Inspect the JSON-RPC body bytes. Returns the (status,
/// optional response header) to apply.
///
/// `original_status` is the status the inner service already
/// set. The classifier ONLY overrides it for the two recognised
/// promotion targets; for anything else (unparseable body,
/// unknown shape, success envelope) it returns the original
/// status untouched — never hardcode a default status here, or a
/// non-200 unrelated response silently downgrades to OK.
fn classify(
    bytes: &[u8],
    resource_metadata_url: &str,
    original_status: StatusCode,
) -> (StatusCode, Option<(axum::http::HeaderName, HeaderValue)>) {
    let default = (original_status, None);
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return default;
    };

    // The rmcp adapter at waygate-mcp/src/server.rs places our
    // structured error payload into the JSON-RPC `error.data`
    // field via McpError::new(..., Some(data)). The wire shape
    // is therefore:
    //   { "jsonrpc": "2.0", "id": ..., "error": {
    //       "code": ..., "message": ..., "data": {
    //         "error": "insufficient_scope" | "rate_limited",
    //         ...
    //       }
    //   }}
    let data = v.get("error").and_then(|e| e.get("data"));
    let kind = data.and_then(|d| d.get("error")).and_then(|s| s.as_str());

    match kind {
        Some("insufficient_scope") => {
            let required_scope = data
                .and_then(|d| d.get("required_scope"))
                .and_then(|s| s.as_str())
                .unwrap_or("");
            // RFC 6750 §3: Bearer challenge. RFC 9728 §5.1:
            // include `resource_metadata` so clients can
            // discover the AS. Same shape as bearer
            // middleware's 401 challenge.
            let www = if required_scope.is_empty() {
                format!(
                    r#"Bearer error="insufficient_scope", resource_metadata="{resource_metadata_url}""#
                )
            } else {
                format!(
                    r#"Bearer error="insufficient_scope", scope="{required_scope}", resource_metadata="{resource_metadata_url}""#
                )
            };
            let value =
                HeaderValue::from_str(&www).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
            (
                StatusCode::FORBIDDEN,
                Some((header::WWW_AUTHENTICATE, value)),
            )
        }
        Some("rate_limited") => {
            // RFC 6585 §4: `Retry-After` is integer seconds or
            // HTTP-date. We emit integer seconds because the
            // quota service computes them already (clamped to
            // [1, 3600] in `waygate_quota::compute_retry_after_seconds`).
            let secs = data
                .and_then(|d| d.get("retry_after_seconds"))
                .and_then(|n| n.as_u64())
                .unwrap_or(1);
            let value = HeaderValue::from_str(&secs.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("1"));
            (
                StatusCode::TOO_MANY_REQUESTS,
                Some((header::RETRY_AFTER, value)),
            )
        }
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PRM: &str = "https://gw.example/.well-known/oauth-protected-resource";

    #[test]
    fn insufficient_scope_promotes_to_403_with_challenge() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "step-up required (scope `mcp:invoke:high`): tool is high-risk",
                "data": {
                    "error": "insufficient_scope",
                    "required_scope": "mcp:invoke:high",
                    "reason": "tool is high-risk"
                }
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, hdr) = classify(&bytes, PRM, StatusCode::OK);
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (name, value) = hdr.expect("WWW-Authenticate header");
        assert_eq!(name, header::WWW_AUTHENTICATE);
        let v = value.to_str().unwrap();
        assert!(
            v.contains(r#"error="insufficient_scope""#),
            "challenge must carry error=insufficient_scope: {v}",
        );
        assert!(
            v.contains(r#"scope="mcp:invoke:high""#),
            "challenge must carry scope=<required>: {v}",
        );
        assert!(
            v.contains(&format!(r#"resource_metadata="{PRM}""#)),
            "challenge must carry resource_metadata: {v}",
        );
    }

    #[test]
    fn insufficient_scope_with_no_required_scope_still_promotes() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "step-up required",
                "data": { "error": "insufficient_scope" }
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, hdr) = classify(&bytes, PRM, StatusCode::OK);
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, value) = hdr.expect("WWW-Authenticate header");
        let v = value.to_str().unwrap();
        // No scope= in the challenge when required_scope was
        // absent (we don't fabricate a value).
        assert!(!v.contains("scope=\""), "no scope= when missing: {v}");
        assert!(v.contains("resource_metadata="));
    }

    #[test]
    fn rate_limited_promotes_to_429_with_retry_after() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "rate-limited",
                "data": {
                    "error": "rate_limited",
                    "policy_id": "00000000-0000-0000-0000-000000000001",
                    "policy_name": "tenant-broad",
                    "retry_after_seconds": 42
                }
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, hdr) = classify(&bytes, PRM, StatusCode::OK);
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let (name, value) = hdr.expect("Retry-After header");
        assert_eq!(name, header::RETRY_AFTER);
        assert_eq!(value.to_str().unwrap(), "42");
    }

    #[test]
    fn rate_limited_missing_seconds_defaults_to_one() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "rate-limited",
                "data": { "error": "rate_limited" }
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, hdr) = classify(&bytes, PRM, StatusCode::OK);
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(hdr.unwrap().1.to_str().unwrap(), "1");
    }

    #[test]
    fn other_jsonrpc_errors_left_untouched() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "bad params",
                "data": { "error": "invalid_params" }
            }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, hdr) = classify(&bytes, PRM, StatusCode::OK);
        assert_eq!(status, StatusCode::OK);
        assert!(hdr.is_none());
    }

    #[test]
    fn success_responses_left_untouched() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [] }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, hdr) = classify(&bytes, PRM, StatusCode::OK);
        assert_eq!(status, StatusCode::OK);
        assert!(hdr.is_none());
    }

    #[test]
    fn non_json_body_left_untouched() {
        let bytes = b"not json at all";
        let (status, hdr) = classify(bytes, PRM, StatusCode::OK);
        assert_eq!(status, StatusCode::OK);
        assert!(hdr.is_none());
    }

    // Unrelated JSON-RPC responses with a non-200 original status
    // must keep that status. A classifier that defaulted to
    // StatusCode::OK for every non-promoted shape would silently
    // downgrade it (e.g. a 500 from the rmcp adapter on an
    // internal error would become a 200 with "internal_error" in
    // the body — a health-check or monitoring alarm would miss it).
    #[test]
    fn unrelated_json_with_non_200_original_preserves_status() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32603, "message": "internal_error" }
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        for orig in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let (status, hdr) = classify(&bytes, PRM, orig);
            assert_eq!(status, orig, "non-promoted shape must preserve {orig}");
            assert!(hdr.is_none());
        }
    }

    // Even non-JSON garbage paired with a non-200 original status
    // preserves the status.
    #[test]
    fn non_json_body_with_non_200_original_preserves_status() {
        let bytes = b"<html>oops</html>";
        let (status, hdr) = classify(bytes, PRM, StatusCode::BAD_GATEWAY);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(hdr.is_none());
    }

    // The middleware's body-buffering cap can't be exercised
    // directly from the classifier (the Content-Length pre-check
    // lives in `promote_mcp_errors`), so pin the constant here: a
    // future "I'll just bump it to 100MB" tweak should get caught
    // in review — the rationale (KB-scale error envelopes only)
    // lives on the const's doc comment.
    //
    // End-to-end test through the actual middleware. Builds a
    // tiny axum service that returns a 2 MiB JSON body (well past
    // MAX_BUFFER_BYTES) and crucially does NOT set Content-Length
    // (so the streaming-buffer path is exercised), then asserts
    // every byte survives end-to-end.
    //
    // An overflow must reconstruct and forward the complete body,
    // never truncate it to empty. And buffering must never gate
    // on Content-Length: a response missing the header still
    // needs to be read up to MAX_BUFFER_BYTES and classified, not
    // skipped outright.
    #[tokio::test]
    async fn large_json_body_without_content_length_is_passed_through_untouched() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let big_body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "x".repeat(2 * 1024 * 1024) }] }
        }))
        .unwrap();
        let big_body_len = big_body.len();
        assert!(
            big_body_len > MAX_BUFFER_BYTES,
            "test body must exceed MAX_BUFFER_BYTES",
        );

        let big_body_for_handler = big_body.clone();
        let app = Router::new()
            .route(
                "/x",
                get(move || {
                    let body = big_body_for_handler.clone();
                    async move {
                        let mut resp = Response::new(Body::from(body));
                        resp.headers_mut().insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        );
                        // Deliberately NO Content-Length —
                        // exercises the round-2 streaming
                        // buffer path.
                        resp
                    }
                }),
            )
            .layer(axum::middleware::from_fn(|req, next| async move {
                promote_mcp_errors(req, next, PRM.to_owned()).await
            }));

        let resp = app
            .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("collect body");
        assert_eq!(
            bytes.len(),
            big_body_len,
            "body must be preserved end-to-end despite exceeding MAX_BUFFER_BYTES with no Content-Length",
        );
        assert_eq!(bytes.as_ref(), big_body.as_slice());
    }

    // A small JSON-RPC insufficient_scope envelope WITHOUT
    // Content-Length must still classify + promote — buffering
    // must never skip inspection just because the header is
    // absent.
    #[tokio::test]
    async fn insufficient_scope_without_content_length_still_promotes() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let err_body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "step-up required",
                "data": {
                    "error": "insufficient_scope",
                    "required_scope": "mcp:invoke:high"
                }
            }
        }))
        .unwrap();
        let err_body_for_handler = err_body.clone();
        let app = Router::new()
            .route(
                "/x",
                get(move || {
                    let body = err_body_for_handler.clone();
                    async move {
                        let mut resp = Response::new(Body::from(body));
                        resp.headers_mut().insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        );
                        // No Content-Length — chunked encoding.
                        resp
                    }
                }),
            )
            .layer(axum::middleware::from_fn(|req, next| async move {
                promote_mcp_errors(req, next, PRM.to_owned()).await
            }));

        let resp = app
            .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "insufficient_scope must still promote without Content-Length",
        );
        let www = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate header set")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(www.contains(r#"error="insufficient_scope""#));
        assert!(www.contains(r#"scope="mcp:invoke:high""#));
        // Body preserved verbatim.
        let bytes = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("body");
        assert_eq!(bytes.as_ref(), err_body.as_slice());
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn max_buffer_bytes_constant_is_small_enough_for_error_envelopes_only() {
        assert!(
            MAX_BUFFER_BYTES <= 256 * 1024,
            "MAX_BUFFER_BYTES must stay small (KB-scale) — the middleware is for error \
             envelope inspection, not buffering tool-call success bodies. Larger responses \
             skip via the Content-Length pre-check.",
        );
        assert!(
            MAX_BUFFER_BYTES >= 8 * 1024,
            "MAX_BUFFER_BYTES must accommodate realistic error envelopes with reasons + \
             policy_ids + retry hints.",
        );
    }

    // Regression for the May-29 prod-down incident: the gateway
    // boot path wraps `mcp_service` with this middleware via
    // `Router::new().fallback_service(svc).layer(...)`. An
    // earlier revision used `nest_service("/", svc)` instead,
    // which compiles cleanly but panics at construction-time on
    // axum 0.8 with "Nesting at the root is no longer
    // supported." The prod gateway crash-looped silently behind
    // the migration-26 boot blocker. This test pins the exact
    // outer router shape main.rs uses so any future change that
    // reintroduces `nest_service("/", ...)` (or any other root-
    // nesting variant) panics inside `cargo test` rather than
    // 30s into a redeploy.
    #[tokio::test]
    async fn mcp_wrapper_router_shape_does_not_panic_at_root() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let inner_service: Router<()> = Router::new().route("/probe", get(|| async { "ok" }));
        // Mirror main.rs: Router::new().fallback_service(svc).layer(...)
        let wrapped =
            Router::new()
                .fallback_service(inner_service)
                .layer(axum::middleware::from_fn(|req, next| async move {
                    promote_mcp_errors(req, next, PRM.to_owned()).await
                }));
        let outer: Router<()> = Router::new().nest("/mcp", wrapped);

        let resp = outer
            .oneshot(
                Request::builder()
                    .uri("/mcp/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router construction + dispatch must not panic");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
