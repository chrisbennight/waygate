//! Provider-native Anthropic Messages ingress (`POST /v1/messages`).
//!
//! The body is forwarded to the model's Anthropic Messages route without
//! canonical translation, so prompt-cache breakpoints, extended thinking,
//! native content blocks, and provider server-side tools reach the provider
//! intact. The route is provider-pinned: a model served by any other protocol
//! is rejected rather than translated. Governance is identical to the
//! canonical routes because the call enters the same `InvocationService`
//! (invariant I1). Responses and errors use the Anthropic wire shapes.

use super::*;

/// Largest gateway-generated error body reshaped into the Anthropic envelope.
const MAX_ERROR_BODY: usize = 64 * 1024;

pub(super) async fn messages(State(state): State<LlmRouterState>, req: Request) -> Response {
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let (payload, model) = match read_llm_body(req).await {
        Ok(parts) => parts,
        Err(resp) => return anthropic_error_envelope(*resp).await,
    };
    let Value::Object(args) = payload else {
        return anthropic_error_envelope(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "request body must be a JSON object",
        ))
        .await;
    };
    let request = InvocationRequest::new(LLM_SERVER, model)
        .with_arguments(Some(args))
        .with_native_messages_surface(true);

    match state.invocation.invoke(principal.as_ref(), request).await {
        // The provider's Messages body, returned verbatim.
        Ok(InvocationResponse::UnaryValue(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(InvocationResponse::Unary(_))
        | Ok(InvocationResponse::InputRequired(_))
        | Ok(InvocationResponse::Task(_)) => {
            anthropic_error_envelope(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "unexpected tool result on the inference route",
            ))
            .await
        }
        Ok(InvocationResponse::Stream(stream)) => native_sse(stream),
        Err(e) => anthropic_error_envelope(invocation_error_response(e)).await,
    }
}

/// Relay provider Messages events as named SSE events. A failure after the
/// stream started is reported with the Anthropic `error` event shape.
fn native_sse(stream: InvocationStream) -> Response {
    let sse = stream.map(|item| {
        let event = match item {
            Ok(chunk) => {
                let data = chunk.event.to_string();
                match chunk.event_name {
                    Some(name) => Event::default().event(name).data(data),
                    None => Event::default().data(data),
                }
            }
            Err(e) => Event::default()
                .event("error")
                .data(anthropic_error_body("api_error", &e.to_string()).to_string()),
        };
        Ok::<Event, std::convert::Infallible>(event)
    });
    Sse::new(sse).into_response()
}

fn anthropic_error_body(err_type: &str, message: &str) -> Value {
    json!({ "type": "error", "error": { "type": err_type, "message": message } })
}

/// The Anthropic error type for a gateway error type. Gateway-only categories
/// map to the closest Anthropic category so SDK error classes stay meaningful.
fn anthropic_error_type(openai_type: &str) -> &'static str {
    match openai_type {
        "invalid_request_error" => "invalid_request_error",
        "authentication_error" => "authentication_error",
        "permission_error" => "permission_error",
        "not_found_error" => "not_found_error",
        "rate_limit_error" | "insufficient_quota" => "rate_limit_error",
        _ => "api_error",
    }
}

/// Reshape a gateway error response into the Anthropic envelope
/// (`{"type":"error","error":{"type","message"}}`), keeping its status and
/// headers such as a step-up `WWW-Authenticate` challenge. Reusing the shared
/// mapping keeps HTTP status semantics identical across inference routes.
async fn anthropic_error_envelope(resp: Response) -> Response {
    let (parts, body) = resp.into_parts();
    let parsed = axum::body::to_bytes(body, MAX_ERROR_BODY)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let error = parsed.as_ref().and_then(|v| v.get("error"));
    let message = error
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("request failed");
    let err_type = anthropic_error_type(
        error
            .and_then(|e| e.get("type"))
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let mut out = (parts.status, Json(anthropic_error_body(err_type, message))).into_response();
    for (name, value) in &parts.headers {
        if name != axum::http::header::CONTENT_TYPE && name != axum::http::header::CONTENT_LENGTH {
            out.headers_mut().append(name, value.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tower::ServiceExt;
    use waygate_invocation::InvocationChunk;

    /// Records each request and answers with a unary body, or with a stream
    /// when the request asked for one.
    #[derive(Default)]
    struct Capture(Mutex<Vec<InvocationRequest>>);

    #[async_trait::async_trait]
    impl waygate_invocation::InvocationService for Capture {
        async fn invoke(
            &self,
            _: Option<&waygate_oidc::Principal>,
            req: InvocationRequest,
        ) -> Result<InvocationResponse, InvocationError> {
            let stream = req
                .arguments
                .as_ref()
                .and_then(|a| a.get("stream"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            self.0.lock().unwrap().push(req);
            if !stream {
                return Ok(InvocationResponse::UnaryValue(
                    json!({"type": "message", "id": "msg_1"}),
                ));
            }
            let chunks = vec![
                Ok(InvocationChunk {
                    event: json!({"type": "message_start"}),
                    event_name: Some("message_start".into()),
                    terminal: false,
                }),
                Err(InvocationError::Upstream(rmcp::ErrorData::internal_error(
                    "provider stream failed",
                    None,
                ))),
            ];
            Ok(InvocationResponse::Stream(Box::pin(futures::stream::iter(
                chunks,
            ))))
        }
    }

    fn post(body: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_owned()))
            .unwrap()
    }

    async fn text_body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    #[tokio::test]
    async fn messages_route_marks_the_native_surface_and_returns_the_body_verbatim() {
        let capture = Arc::new(Capture::default());
        let app = router(capture.clone(), None, Arc::new(StaticModelResolver::new()));
        let resp = app
            .oneshot(post(
                r#"{"model":"claude-x","max_tokens":8,"messages":[],"system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            json_body(resp).await,
            json!({"type": "message", "id": "msg_1"})
        );
        let requests = capture.0.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert!(req.native_messages_surface);
        assert!(!req.responses_surface && !req.embeddings_surface);
        assert_eq!(req.server, LLM_SERVER);
        assert_eq!(req.tool, "claude-x");
        assert_eq!(
            req.arguments.as_ref().unwrap()["system"][0]["cache_control"],
            json!({"type": "ephemeral"})
        );
    }

    #[tokio::test]
    async fn messages_route_streams_named_events_and_anthropic_error_frames() {
        let capture = Arc::new(Capture::default());
        let app = router(capture, None, Arc::new(StaticModelResolver::new()));
        let resp = app
            .oneshot(post(
                r#"{"model":"claude-x","max_tokens":8,"messages":[],"stream":true}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let text = text_body(resp).await;
        assert!(
            text.contains("event: message_start\ndata: {\"type\":\"message_start\"}"),
            "{text}"
        );
        assert!(!text.contains("[DONE]"), "{text}");
        let error_data = text
            .split("event: error\ndata: ")
            .nth(1)
            .and_then(|rest| rest.lines().next())
            .expect("error frame");
        let error: Value = serde_json::from_str(error_data).expect("json");
        assert_eq!(error["type"], "error");
        assert_eq!(error["error"]["type"], "api_error");
    }

    #[tokio::test]
    async fn malformed_bodies_get_anthropic_errors_without_invoking() {
        let capture = Arc::new(Capture::default());
        let app = router(capture.clone(), None, Arc::new(StaticModelResolver::new()));
        for body in ["not json", r#"{"max_tokens":8}"#] {
            let resp = app.clone().oneshot(post(body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let error = json_body(resp).await;
            assert_eq!(error["type"], "error");
            assert_eq!(error["error"]["type"], "invalid_request_error");
        }
        assert!(capture.0.lock().unwrap().is_empty());
    }

    async fn json_body(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn gateway_errors_use_the_anthropic_envelope_and_keep_status_and_headers() {
        let resp =
            anthropic_error_envelope(invocation_error_response(InvocationError::StepUpRequired {
                required_scope: "mcp:invoke:high".into(),
                reason: "fresh authentication required".into(),
            }))
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .is_some());
        assert_eq!(
            json_body(resp).await,
            json!({"type": "error", "error": {
                "type": "permission_error",
                "message": "fresh authentication required"
            }})
        );
    }

    #[tokio::test]
    async fn gateway_only_error_types_map_to_anthropic_categories() {
        for (openai, anthropic) in [
            ("insufficient_quota", "rate_limit_error"),
            ("upstream_error", "api_error"),
            ("invalid_request_error", "invalid_request_error"),
        ] {
            let resp =
                anthropic_error_envelope(error_response(StatusCode::BAD_REQUEST, openai, "m"))
                    .await;
            assert_eq!(json_body(resp).await["error"]["type"], anthropic);
        }
    }
}
