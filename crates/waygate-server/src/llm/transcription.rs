//! Standard transcription ingress; uploads pass through the shared invocation boundary.

use super::*;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart};
use std::collections::BTreeMap;
use waygate_core::audio::{AudioUpload, TranscriptionInput, MAX_TRANSCRIPTION_FILE_BYTES};

/// Uploads and buffered transcripts are held in memory, so ingress bounds how
/// many requests can hold them at once, from before the body is read until the
/// response is delivered.
pub(super) const MAX_CONCURRENT_UPLOADS: usize = 4;
const MAX_TRANSCRIPTION_BODY: usize = MAX_TRANSCRIPTION_FILE_BYTES + 64 * 1024;
const MAX_FIELD_BYTES: usize = 16 * 1024;
const UPLOAD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
const DELIVERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

pub(super) fn validate_config(def: &ModelDef) -> anyhow::Result<()> {
    if !is_transcription(def) {
        anyhow::ensure!(
            def.transcription.is_none(),
            "transcription capabilities require kind transcription"
        );
        return Ok(());
    }
    anyhow::ensure!(
        def.provider.eq_ignore_ascii_case("openai")
            || def.provider.eq_ignore_ascii_case("openrouter"),
        "transcription requires an OpenAI-compatible bearer provider"
    );
    anyhow::ensure!(
        def.surface.is_none()
            && def.fallbacks.is_empty()
            && def.credential_labels.as_ref().is_none_or(Vec::is_empty)
            && def.cache_ttl_ms.is_none()
            && def.ttfb_ms.is_none(),
        "transcription requires one route without surface overrides, fallbacks, caching, or streaming deadlines"
    );
    def.transcription
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("transcription models require explicit transcription capabilities")
        })?
        .validate()?;
    let url = reqwest::Url::parse(&def.base_url)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "transcription provider URL must use HTTP(S) without user information, queries, or fragments"
    );
    anyhow::ensure!(
        def.path.as_ref().is_none_or(|p| !p.is_empty()
            && !p.contains(['?', '#'])
            && !p.split('/').any(|segment| segment == "..")),
        "invalid transcription provider path"
    );
    Ok(())
}

fn bad_request(message: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_request_error", message)
}

fn too_large() -> Response {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "invalid_request_error",
        "audio file exceeds the 25 MiB (26214400-byte) limit",
    )
}

pub(super) async fn create(State(state): State<LlmRouterState>, req: Request) -> Response {
    let Ok(permit) = state.transcription_capacity.clone().try_acquire_owned() else {
        let mut response = error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "transcription upload capacity is full; retry with backoff",
        );
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
        return response;
    };
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let input = match tokio::time::timeout(UPLOAD_DEADLINE, read_form(req)).await {
        Ok(Ok(input)) => input,
        Ok(Err(response)) => return *response,
        Err(_) => {
            return error_response(
                StatusCode::REQUEST_TIMEOUT,
                "invalid_request_error",
                "transcription upload exceeded its deadline",
            )
        }
    };
    let Some(model) = input.fields.get("model").cloned() else {
        return bad_request("transcription requires a model");
    };
    let mut request = InvocationRequest::new(LLM_SERVER, model);
    request.transcription = Some(input);
    let mut response = match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::UnaryValue(body)) => Json(body).into_response(),
        Ok(InvocationResponse::Media { media_type, body }) => (
            [(axum::http::header::CONTENT_TYPE, media_type)],
            axum::body::Body::from_stream(body),
        )
            .into_response(),
        Ok(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "unexpected response on the transcription route",
        ),
        Err(error) => invocation_error_response(error),
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    deliver_with_capacity(response, permit, DELIVERY_DEADLINE, "transcription")
}

async fn read_form(req: Request) -> Result<TranscriptionInput, Box<Response>> {
    let multipart = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .starts_with("multipart/form-data")
        });
    if !multipart {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request_error",
            "transcriptions require multipart/form-data",
        )
        .into());
    }
    // Bound the body before parsing, including multipart overhead. The rebuilt
    // request lets Axum's parser use this endpoint's larger upload limit.
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_TRANSCRIPTION_BODY)
        .await
        .map_err(|_| too_large())?;
    let mut req = Request::from_parts(parts, axum::body::Body::from(bytes));
    DefaultBodyLimit::max(MAX_TRANSCRIPTION_BODY).apply(&mut req);
    let mut form = Multipart::from_request(req, &())
        .await
        .map_err(|_| bad_request("invalid multipart transcription request"))?;
    let mut upload = None;
    let mut fields = BTreeMap::new();
    while let Some(field) = form
        .next_field()
        .await
        .map_err(|_| bad_request("invalid multipart transcription request"))?
    {
        let name = field
            .name()
            .ok_or_else(|| bad_request("multipart fields require names"))?
            .to_owned();
        if name == "file" {
            if upload.is_some() {
                return Err(bad_request("only one audio file is accepted").into());
            }
            let content_type = field
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_owned();
            let file_name = field
                .file_name()
                .unwrap_or_default()
                .rsplit(['/', '\\'])
                .next()
                .expect("a final path segment")
                .to_owned();
            let bytes = field
                .bytes()
                .await
                .map_err(|_| bad_request("invalid audio upload"))?;
            if bytes.len() > MAX_TRANSCRIPTION_FILE_BYTES {
                return Err(too_large().into());
            }
            upload = Some(AudioUpload {
                bytes: Arc::from(bytes.as_ref()),
                content_type,
                file_name,
            });
        } else {
            let value = field
                .text()
                .await
                .map_err(|_| bad_request("invalid transcription form field"))?;
            if value.len() > MAX_FIELD_BYTES {
                return Err(bad_request("transcription form field is too long").into());
            }
            if fields.insert(name, value).is_some() {
                return Err(bad_request("duplicate transcription form field").into());
            }
        }
    }
    let upload = upload.ok_or_else(|| bad_request("transcription requires an audio file"))?;
    Ok(TranscriptionInput { upload, fields })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn config(extra: Value) -> ModelDef {
        let mut value = json!({"alias":"asr","provider":"openai","credential_label":"STT",
            "kind":"transcription","base_url":"http://provider.invalid/v1",
            "upstream_model":"provider-asr",
            "transcription":{"file_types":["wav"],"response_formats":["json","text"]}});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn transcription_configuration_requires_explicit_capabilities_and_one_bearer_route() {
        assert!(validate_config(&config(json!({}))).is_ok());
        for extra in [
            json!({"transcription":null}),
            json!({"transcription":{"file_types":[],"response_formats":["json"]}}),
            json!({"provider":"anthropic"}),
            json!({"surface":"codex"}),
            json!({"cache_ttl_ms":1000}),
            json!({"credential_labels":["BACKUP"]}),
            json!({"base_url":"http://provider.invalid/v1?key=private"}),
            json!({"path":"../audio/transcriptions"}),
            json!({"kind":"chat"}),
        ] {
            assert!(validate_config(&config(extra.clone())).is_err(), "{extra}");
        }
        // A private provider still uses a server-side bearer credential.
        assert!(build_from_defs(
            vec![config(
                json!({"authentication":"none","credential_label":""})
            )],
            None
        )
        .is_err());
    }

    #[test]
    fn transcription_catalog_and_live_route_share_the_same_operation() {
        let def = config(json!({}));
        let row = model_def_to_upsert(&def);
        let (_, resolver) = build_from_defs(vec![def], None).unwrap().unwrap();
        let model = resolver.resolve(LLM_SERVER, &row.alias).unwrap();
        assert!(matches!(model.operation, LlmOperation::Transcription(_)));
        assert_eq!(model.route.upstream_model, "provider-asr");
        assert_eq!(row.upstream_api, "transcription");
        assert_eq!(row.path, "audio/transcriptions");
        assert_eq!(model.route.path, row.path);
        assert!(ModelKindFilter::from_query("type=transcriptions")
            .unwrap()
            .matches(&row.upstream_api));
        assert!(!ModelKindFilter::Chat.matches(&row.upstream_api));
        assert_eq!(model_modality(&row.upstream_api), "audio->text");
    }

    #[derive(Default)]
    struct Capture {
        requests: std::sync::Mutex<Vec<InvocationRequest>>,
        text: bool,
    }

    #[async_trait::async_trait]
    impl waygate_invocation::InvocationService for Capture {
        async fn invoke(
            &self,
            _: Option<&waygate_oidc::Principal>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse, InvocationError> {
            self.requests.lock().unwrap().push(request);
            if self.text {
                return Ok(InvocationResponse::Media {
                    media_type: "text/plain; charset=utf-8",
                    body: futures::stream::once(async { Ok(bytes::Bytes::from("fixture words")) })
                        .boxed(),
                });
            }
            Ok(InvocationResponse::UnaryValue(
                json!({"text":"fixture words"}),
            ))
        }
    }

    fn form(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, file_name, value) in parts {
            body.extend_from_slice(b"--fixture\r\nContent-Disposition: form-data; name=\"");
            body.extend_from_slice(name.as_bytes());
            body.push(b'"');
            if let Some(file_name) = file_name {
                body.extend_from_slice(b"; filename=\"");
                body.extend_from_slice(file_name.as_bytes());
                body.extend_from_slice(b"\"\r\nContent-Type: audio/wav");
            }
            body.extend_from_slice(b"\r\n\r\n");
            body.extend_from_slice(value);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--fixture--\r\n");
        body
    }

    fn post(content_type: &str, body: Vec<u8>) -> Request {
        Request::builder()
            .method("POST")
            .uri("/v1/audio/transcriptions")
            .header("content-type", content_type)
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    fn app(capture: Arc<Capture>) -> Router<()> {
        let (_, resolver) = build_from_defs(vec![config(json!({}))], None)
            .unwrap()
            .unwrap();
        router(capture, None, resolver)
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn standard_form_reaches_the_invocation_boundary_with_its_file_and_fields() {
        let capture = Arc::new(Capture::default());
        let response = app(capture.clone())
            .oneshot(post(
                "multipart/form-data; boundary=fixture",
                form(&[
                    ("model", None, b"asr"),
                    ("response_format", None, b"json"),
                    ("file", Some("dir/sample.wav"), b"RIFF fixture audio"),
                ]),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(body_text(response).await, r#"{"text":"fixture words"}"#);
        let requests = capture.requests.lock().unwrap();
        assert_eq!(requests[0].tool, "asr");
        let input = requests[0].transcription.as_ref().unwrap();
        assert_eq!(input.upload.bytes.as_ref(), b"RIFF fixture audio");
        assert_eq!(input.upload.file_name, "sample.wav");
        assert_eq!(input.upload.content_type, "audio/wav");
        assert_eq!(input.fields.len(), 2);
        assert_eq!(input.fields["response_format"], "json");
        assert!(!format!("{input:?}").contains("fixture audio"));
    }

    #[tokio::test]
    async fn text_formats_use_the_standard_plain_text_content_type() {
        let capture = Arc::new(Capture {
            text: true,
            ..Default::default()
        });
        let response = app(capture)
            .oneshot(post(
                "multipart/form-data; boundary=fixture",
                form(&[
                    ("model", None, b"asr"),
                    ("response_format", None, b"text"),
                    ("file", Some("sample.wav"), b"RIFF"),
                ]),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_text(response).await, "fixture words");
    }

    #[tokio::test]
    async fn malformed_and_oversized_uploads_fail_before_invocation() {
        let capture = Arc::new(Capture::default());
        let app = app(capture.clone());
        let oversized = vec![0u8; MAX_TRANSCRIPTION_FILE_BYTES + 1];
        for (content_type, body, status) in [
            (
                "application/json",
                br#"{"model":"asr"}"#.to_vec(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "multipart/form-data; boundary=fixture",
                form(&[("model", None, b"asr")]),
                StatusCode::BAD_REQUEST,
            ),
            (
                "multipart/form-data; boundary=fixture",
                form(&[("file", Some("a.wav"), b"RIFF")]),
                StatusCode::BAD_REQUEST,
            ),
            (
                "multipart/form-data; boundary=fixture",
                form(&[
                    ("model", None, b"asr"),
                    ("model", None, b"other"),
                    ("file", Some("a.wav"), b"RIFF"),
                ]),
                StatusCode::BAD_REQUEST,
            ),
            (
                "multipart/form-data; boundary=fixture",
                form(&[
                    ("model", None, b"asr"),
                    ("file", Some("a.wav"), b"RIFF"),
                    ("file", Some("b.wav"), b"RIFF"),
                ]),
                StatusCode::BAD_REQUEST,
            ),
            (
                "multipart/form-data; boundary=fixture",
                form(&[("model", None, b"asr"), ("file", Some("a.wav"), &oversized)]),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = app.clone().oneshot(post(content_type, body)).await.unwrap();
            assert_eq!(response.status(), status);
            let body: Value = serde_json::from_str(&body_text(response).await).unwrap();
            assert_eq!(body["error"]["type"], "invalid_request_error");
        }
        assert!(capture.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn full_upload_capacity_is_reported_as_retryable_before_reading_the_body() {
        let capture = Arc::new(Capture::default());
        let (_, resolver) = build_from_defs(vec![config(json!({}))], None)
            .unwrap()
            .unwrap();
        let state = LlmRouterState {
            invocation: capture.clone(),
            models: None,
            resolver,
            image_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            audio_resource_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            transcription_capacity: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        let response = create(
            State(state),
            post(
                "multipart/form-data; boundary=fixture",
                form(&[("model", None, b"asr"), ("file", Some("a.wav"), b"RIFF")]),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "1");
        assert!(capture.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unread_responses_keep_their_capacity_until_delivered() {
        let capture = Arc::new(Capture::default());
        let (_, resolver) = build_from_defs(vec![config(json!({}))], None)
            .unwrap()
            .unwrap();
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let state = LlmRouterState {
            invocation: capture.clone(),
            models: None,
            resolver,
            image_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            audio_resource_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            transcription_capacity: capacity.clone(),
        };
        let request = || {
            post(
                "multipart/form-data; boundary=fixture",
                form(&[("model", None, b"asr"), ("file", Some("a.wav"), b"RIFF")]),
            )
        };
        let unread = create(State(state.clone()), request()).await;
        assert_eq!(unread.status(), StatusCode::OK);
        let refused = create(State(state.clone()), request()).await;
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body_text(unread).await, r#"{"text":"fixture words"}"#);
        // Delivery finishes after the body is consumed; wait for the slot.
        let _slot = tokio::time::timeout(std::time::Duration::from_secs(5), capacity.acquire())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(capture.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn provider_failures_keep_their_client_status_without_exposing_authentication() {
        for (status, expected) in [
            (413, StatusCode::PAYLOAD_TOO_LARGE),
            (400, StatusCode::BAD_REQUEST),
            (429, StatusCode::TOO_MANY_REQUESTS),
            (401, StatusCode::BAD_GATEWAY),
            (504, StatusCode::GATEWAY_TIMEOUT),
        ] {
            let response = invocation_error_response(InvocationError::Upstream(
                rmcp::ErrorData::internal_error(
                    "transcription provider request failed",
                    Some(json!({"audio_http_status":status,"retry_after_seconds":null})),
                ),
            ));
            assert_eq!(response.status(), expected);
            assert!(response.headers().get("www-authenticate").is_none());
        }
    }
}
