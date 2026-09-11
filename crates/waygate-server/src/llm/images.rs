//! Standard Images API ingress and bounded multipart-to-Codex conversion.

use super::*;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart};
use base64::Engine;
use waygate_invocation::ImagesSurface;

/// Total encoded HTTP body limit, including all edit uploads and form fields.
const MAX_IMAGE_BODY: usize = 64 * 1024 * 1024;
/// Bound aggregate upload, base64 conversion, and response allocations across both routes.
pub(super) const MAX_CONCURRENT_IMAGES: usize = 2;
const IMAGE_UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const IMAGE_DELIVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const IMAGE_DELIVERY_CHUNK: usize = 64 * 1024;

pub(super) async fn generations(State(state): State<LlmRouterState>, req: Request) -> Response {
    handle(state, req, ImagesSurface::Generations).await
}

pub(super) async fn edits(State(state): State<LlmRouterState>, req: Request) -> Response {
    handle(state, req, ImagesSurface::Edits).await
}

async fn handle(state: LlmRouterState, req: Request, surface: ImagesSurface) -> Response {
    let Ok(permit) = state.image_capacity.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "image request capacity is full; try again later",
        );
    };
    let response = invoke_image(state, req, surface).await;
    deliver_response(response, permit)
}

fn deliver_response(response: Response, permit: tokio::sync::OwnedSemaphorePermit) -> Response {
    let (parts, body) = response.into_parts();
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    // The producer deadline runs even when HTTP backpressure stops polling the
    // response. Copy small chunks so queued bytes cannot retain the large body.
    let delivery = tokio::spawn(async move {
        let _permit = permit;
        let send = async {
            let mut body = body.into_data_stream();
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(std::io::Error::other)?;
                for chunk in chunk.chunks(IMAGE_DELIVERY_CHUNK) {
                    sender
                        .send(bytes::Bytes::copy_from_slice(chunk))
                        .await
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "image client disconnected",
                            )
                        })?;
                }
            }
            Ok::<_, std::io::Error>(())
        };
        tokio::select! {
            _ = sender.closed() => Ok(()),
            result = tokio::time::timeout(IMAGE_DELIVERY_TIMEOUT, send) => {
                result.unwrap_or_else(|_| Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut, "image response delivery exceeded 60 seconds",
                )))
            }
        }
    });
    let stream = futures::stream::unfold(
        (receiver, Some(delivery)),
        |(mut receiver, mut delivery)| async move {
            if let Some(chunk) = receiver.recv().await {
                return Some((Ok(chunk), (receiver, delivery)));
            }
            match delivery.take()?.await {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some((Err(error), (receiver, delivery))),
                Err(_) => Some((
                    Err(std::io::Error::other("image response delivery failed")),
                    (receiver, delivery),
                )),
            }
        },
    );
    Response::from_parts(parts, axum::body::Body::from_stream(stream))
}

async fn invoke_image(state: LlmRouterState, req: Request, surface: ImagesSurface) -> Response {
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let payload =
        match tokio::time::timeout(IMAGE_UPLOAD_TIMEOUT, read_image_body(req, surface)).await {
            Ok(Ok(body)) => body,
            Ok(Err(response)) => return *response,
            Err(_) => {
                return error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "invalid_request_error",
                    "image upload exceeded 60 seconds",
                )
            }
        };
    let Some(model) = payload
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.trim().is_empty())
    else {
        return bad_request("model must be a non-empty string");
    };
    let model = model.to_owned();
    let Value::Object(arguments) = payload else {
        unreachable!("model requires an object")
    };
    let mut request = InvocationRequest::new(LLM_SERVER, model).with_arguments(Some(arguments));
    request.images_surface = Some(surface);
    match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::UnaryValue(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "unexpected image response",
        ),
        Err(e) => invocation_error_response(e),
    }
}

fn bad_request(message: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_request_error", message)
}

async fn read_image_body(req: Request, surface: ImagesSurface) -> Result<Value, Box<Response>> {
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    if surface == ImagesSurface::Generations {
        if !content_type
            .split(';')
            .next()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_request_error",
                "generations require application/json",
            )
            .into());
        }
        let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY)
            .await
            .map_err(|_| {
                error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request_error",
                    "image request body exceeds 8 MiB",
                )
            })?;
        return serde_json::from_slice(&bytes)
            .map_err(|_| bad_request("invalid image JSON body").into());
    }
    if !content_type
        .to_ascii_lowercase()
        .starts_with("multipart/form-data;")
    {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request_error",
            "edits require multipart/form-data with image uploads",
        )
        .into());
    }
    // Bound the body before parsing, including multipart overhead. The rebuilt
    // request lets Axum's parser use this endpoint's larger upload limit.
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_IMAGE_BODY)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                "image edit body exceeds 64 MiB",
            )
        })?;
    let mut req = Request::from_parts(parts, axum::body::Body::from(bytes));
    DefaultBodyLimit::max(MAX_IMAGE_BODY).apply(&mut req);
    let mut form = Multipart::from_request(req, &())
        .await
        .map_err(|_| bad_request("invalid multipart image request"))?;
    let mut body = serde_json::Map::new();
    let mut images = Vec::new();
    while let Some(field) = form
        .next_field()
        .await
        .map_err(|_| bad_request("invalid multipart field"))?
    {
        let name = field
            .name()
            .ok_or_else(|| bad_request("multipart fields require names"))?
            .to_owned();
        if matches!(name.as_str(), "image" | "image[]" | "mask") {
            if (name == "mask" && body.contains_key("mask"))
                || (name != "mask" && images.len() >= 16)
            {
                return Err(bad_request("edits accept up to 16 images and one mask").into());
            }
            let bytes = field
                .bytes()
                .await
                .map_err(|_| bad_request("invalid image upload"))?;
            let mime = image_mime(&bytes)
                .ok_or_else(|| bad_request("uploads must be PNG, JPEG, or WebP images"))?;
            if name == "mask" && mime != "image/png" {
                return Err(bad_request("mask must be PNG").into());
            }
            let prefix = format!("data:{mime};base64,");
            let mut image_url = String::with_capacity(prefix.len() + bytes.len().div_ceil(3) * 4);
            image_url.push_str(&prefix);
            base64::engine::general_purpose::STANDARD.encode_string(&bytes, &mut image_url);
            let image = Value::Object(serde_json::Map::from_iter([(
                "image_url".into(),
                Value::String(image_url),
            )]));
            if name == "mask" {
                body.insert(name, image);
            } else {
                images.push(image);
            }
        } else {
            if body.contains_key(&name) {
                return Err(bad_request("duplicate image parameter").into());
            }
            let value = field
                .text()
                .await
                .map_err(|_| bad_request("image parameters must be UTF-8 text"))?;
            let value = match name.as_str() {
                "n" | "output_compression" | "partial_images" => {
                    Value::from(value.parse::<u64>().map_err(|_| {
                        bad_request("image numeric parameter must be an unsigned integer")
                    })?)
                }
                "stream" => Value::from(
                    value
                        .parse::<bool>()
                        .map_err(|_| bad_request("stream must be true or false"))?,
                ),
                "model" | "prompt" | "size" | "quality" | "background" | "output_format"
                | "moderation" | "input_fidelity" | "user" | "response_format" => {
                    Value::String(value)
                }
                _ => return Err(bad_request("unsupported image form field").into()),
            };
            body.insert(name, value);
        }
    }
    body.insert("images".into(), Value::Array(images));
    Ok(Value::Object(body))
}

fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some("image/webp")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[derive(Default)]
    struct Capture(Mutex<Vec<InvocationRequest>>, Option<u16>, bool);

    #[async_trait::async_trait]
    impl waygate_invocation::InvocationService for Capture {
        async fn invoke(
            &self,
            _: Option<&waygate_oidc::Principal>,
            req: InvocationRequest,
        ) -> Result<InvocationResponse, InvocationError> {
            self.0.lock().unwrap().push(req);
            if let Some(status) = self.1 {
                return Err(InvocationError::Upstream(rmcp::ErrorData::internal_error(
                    "image provider rejected the request",
                    Some(json!({"image_http_status": status})),
                )));
            }
            let mut response =
                json!({"created":42,"data":[{"b64_json":"aW1hZ2U="}],"output_format":"png"});
            if self.2 {
                response["data"][0]["b64_json"] =
                    Value::String("a".repeat(4 * IMAGE_DELIVERY_CHUNK));
            }
            Ok(InvocationResponse::UnaryValue(response))
        }
    }

    fn app(capture: Arc<Capture>) -> Router {
        router(capture, None, Arc::new(StaticModelResolver::new()))
    }

    fn generation_request() -> Request {
        Request::builder()
            .method("POST")
            .uri("/v1/images/generations")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"model":"gpt-image-2","prompt":"fixture"}"#,
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn image_capacity_precedes_upload_reads_and_covers_response_delivery() {
        let capture = Arc::new(Capture(Mutex::default(), None, true));
        let app = app(capture.clone());
        let mut responses = Vec::new();
        for _ in 0..MAX_CONCURRENT_IMAGES {
            let response = app.clone().oneshot(generation_request()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            responses.push(response);
        }
        for path in ["/v1/images/generations", "/v1/images/edits"] {
            let body = axum::body::Body::from_stream(futures::stream::poll_fn(
                |_| -> std::task::Poll<Option<Result<bytes::Bytes, std::io::Error>>> {
                    panic!("a refused request must not poll the upload body")
                },
            ));
            let mut request = generation_request();
            *request.uri_mut() = path.parse().unwrap();
            *request.body_mut() = body;
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        assert_eq!(capture.0.lock().unwrap().len(), MAX_CONCURRENT_IMAGES);
        drop(responses.pop());
        tokio::task::yield_now().await;
        let response = app.clone().oneshot(generation_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        axum::body::to_bytes(response.into_body(), 4 * IMAGE_DELIVERY_CHUNK + 1024)
            .await
            .unwrap();
        let response = app.oneshot(generation_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(start_paused = true)]
    async fn unpolled_image_response_expires_and_releases_capacity() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = capacity.clone().try_acquire_owned().unwrap();
        let response = deliver_response(
            Response::new(axum::body::Body::from(vec![b'a'; 4 * IMAGE_DELIVERY_CHUNK])),
            permit,
        );
        tokio::task::yield_now().await;
        assert!(capacity.clone().try_acquire_owned().is_err());
        // Never poll the response until after the independent producer deadline.
        tokio::time::advance(IMAGE_DELIVERY_TIMEOUT).await;
        let _recovered =
            tokio::time::timeout(std::time::Duration::from_secs(1), capacity.acquire())
                .await
                .unwrap()
                .unwrap();
        let error = axum::body::to_bytes(response.into_body(), 4 * IMAGE_DELIVERY_CHUNK)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("delivery exceeded"));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_uploads_time_out_and_cancelled_uploads_release_capacity() {
        let capture = Arc::new(Capture::default());
        let app = app(capture.clone());
        let started = Arc::new(tokio::sync::Semaphore::new(0));
        let mut tasks = Vec::new();
        for _ in 0..MAX_CONCURRENT_IMAGES {
            let started = started.clone();
            let body = axum::body::Body::from_stream(futures::stream::poll_fn(
                move |_| -> std::task::Poll<Option<Result<bytes::Bytes, std::io::Error>>> {
                    started.add_permits(1);
                    std::task::Poll::Pending
                },
            ));
            let mut request = generation_request();
            *request.body_mut() = body;
            tasks.push(tokio::spawn(app.clone().oneshot(request)));
        }
        started
            .acquire_many(MAX_CONCURRENT_IMAGES as u32)
            .await
            .unwrap()
            .forget();
        let response = app.clone().oneshot(generation_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(capture.0.lock().unwrap().is_empty());
        let cancelled = tasks.pop().unwrap();
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        let response = app.clone().oneshot(generation_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);
        tokio::time::advance(IMAGE_UPLOAD_TIMEOUT).await;
        let response = tasks.pop().unwrap().await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        drop(response);
        let response = app.oneshot(generation_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(capture.0.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn generation_route_preserves_the_standard_response() {
        let capture = Arc::new(Capture::default());
        let response = app(capture.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/images/generations")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"model":"gpt-image-2","prompt":"a square","quality":"low"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["data"][0]["b64_json"], "aW1hZ2U=");
        assert_eq!(body["output_format"], "png");
        let requests = capture.0.lock().unwrap();
        assert_eq!(requests[0].images_surface, Some(ImagesSurface::Generations));
        assert_eq!(requests[0].arguments.as_ref().unwrap()["quality"], "low");
    }

    fn multipart(fields: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(
                format!(
                    "--image-boundary\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(value);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--image-boundary--\r\n");
        body
    }

    fn edit_request(body: Vec<u8>) -> Request {
        Request::builder()
            .method("POST")
            .uri("/v1/images/edits")
            .header(
                "content-type",
                "multipart/form-data; boundary=image-boundary",
            )
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn multipart_edits_preserve_multiple_images_mask_and_numeric_options() {
        let capture = Arc::new(Capture::default());
        let png = b"\x89PNG\r\n\x1a\nfixture";
        let response = app(capture.clone())
            .oneshot(edit_request(multipart(&[
                ("model", b"gpt-image-2"),
                ("prompt", b"make it blue"),
                ("image[]", png),
                ("image[]", png),
                ("mask", png),
                ("n", b"2"),
            ])))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let requests = capture.0.lock().unwrap();
        assert_eq!(requests[0].images_surface, Some(ImagesSurface::Edits));
        let body = requests[0].arguments.as_ref().unwrap();
        assert_eq!(body["images"].as_array().unwrap().len(), 2);
        assert_eq!(body["mask"]["image_url"], body["images"][0]["image_url"]);
        assert_eq!(body["n"], 2);
        let encoded = body["images"][0]["image_url"]
            .as_str()
            .unwrap()
            .strip_prefix("data:image/png;base64,")
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
            png
        );
    }

    #[tokio::test]
    async fn malformed_uploads_never_reach_invocation() {
        for fields in [
            vec![("image", b"not an image".as_slice())],
            vec![("prompt", b"one".as_slice()), ("prompt", b"two".as_slice())],
            vec![("n", b"many".as_slice())],
            vec![("unexpected", b"value".as_slice())],
        ] {
            let capture = Arc::new(Capture::default());
            let response = app(capture.clone())
                .oneshot(edit_request(multipart(&fields)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(capture.0.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn oversized_image_bodies_are_rejected_before_invocation() {
        for (path, content_type, limit) in [
            ("/v1/images/generations", "application/json", MAX_BODY),
            (
                "/v1/images/edits",
                "multipart/form-data; boundary=image-boundary",
                MAX_IMAGE_BODY,
            ),
        ] {
            let capture = Arc::new(Capture::default());
            let response = app(capture.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", content_type)
                        .body(axum::body::Body::from(vec![b' '; limit + 1]))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert!(capture.0.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn image_provider_errors_use_standard_http_envelopes() {
        for (upstream, expected, kind) in [
            (400, StatusCode::BAD_REQUEST, "invalid_request_error"),
            (413, StatusCode::PAYLOAD_TOO_LARGE, "invalid_request_error"),
            (
                422,
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request_error",
            ),
            (429, StatusCode::TOO_MANY_REQUESTS, "rate_limit_error"),
            (401, StatusCode::BAD_GATEWAY, "upstream_error"),
            (403, StatusCode::BAD_GATEWAY, "upstream_error"),
            (502, StatusCode::BAD_GATEWAY, "upstream_error"),
        ] {
            let capture = Arc::new(Capture(Mutex::new(Vec::new()), Some(upstream), false));
            let response = app(capture.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/images/generations")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            r#"{"model":"image-alias","prompt":"fixture"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            let body: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["error"]["type"], kind);
            assert_eq!(capture.0.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    #[ignore = "requires OpenAI Python SDK; run with IMAGES_SDK_PYTHON as documented in docs/images-api.md"]
    async fn openai_python_sdk_images_smoke() {
        let python = std::env::var("IMAGES_SDK_PYTHON")
            .expect("set IMAGES_SDK_PYTHON to the SDK virtualenv Python");
        let capture = Arc::new(Capture::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fixture = app(capture.clone());
        let server = tokio::spawn(async move { axum::serve(listener, fixture).await.unwrap() });
        let result = tokio::process::Command::new(python)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/test-images-sdk.py"
            ))
            .arg(format!("http://{addr}/v1"))
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        server.abort();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let requests = capture.0.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].images_surface, Some(ImagesSurface::Generations));
        assert_eq!(requests[1].images_surface, Some(ImagesSurface::Edits));
        assert_eq!(
            requests[1].arguments.as_ref().unwrap()["images"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(requests[1].arguments.as_ref().unwrap().contains_key("mask"));
    }

    #[test]
    fn image_config_resolves_the_same_operation_as_the_catalog() {
        let defs: Vec<ModelDef> = serde_json::from_value(json!([{
            "alias":"gpt-image-2", "provider":"openai", "credential_label":"PRIMARY",
            "base_url":"https://chatgpt.com/backend-api/codex", "surface":"codex", "kind":"images"
        }]))
        .unwrap();
        let row = model_def_to_upsert(&defs[0]);
        assert_eq!(row.upstream_api, "images");
        assert_eq!(row.path, "images");
        assert!(row.openai_chatgpt);
        let (_, resolver) = build_from_defs(defs, None).unwrap().unwrap();
        let model = resolver.resolve(LLM_SERVER, "gpt-image-2").unwrap();
        assert_eq!(model.operation, LlmOperation::Images);
        assert_eq!(model.route.path, row.path);
        assert!(ModelKindFilter::Images.matches(&row.upstream_api));
        assert!(!ModelKindFilter::Chat.matches(&row.upstream_api));
        assert_eq!(model_modality(&row.upstream_api), "text+image->image");
    }
}
