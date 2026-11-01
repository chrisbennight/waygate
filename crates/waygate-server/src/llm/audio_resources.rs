//! Standard voice/consent routes select one configured provider without a client extension.

use super::*;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Path};
use std::collections::BTreeMap;
use waygate_core::audio::{
    AudioResourceOperation as Operation, AudioResourceRequest, AudioUpload,
    MAX_VOICE_RECORDING_BYTES,
};

const MAX_RESOURCE_UPLOAD: usize = MAX_VOICE_RECORDING_BYTES + 64 * 1024;
const UPLOAD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

pub(super) async fn create_voice(State(state): State<LlmRouterState>, req: Request) -> Response {
    handle(state, req, Operation::VoiceCreate, None).await
}

pub(super) async fn delete_voice(
    State(state): State<LlmRouterState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    handle(state, req, Operation::VoiceDelete, Some(id)).await
}

pub(super) async fn consents(State(state): State<LlmRouterState>, req: Request) -> Response {
    let operation = if req.method() == axum::http::Method::GET {
        Operation::ConsentList
    } else {
        Operation::ConsentCreate
    };
    handle(state, req, operation, None).await
}

pub(super) async fn consent(
    State(state): State<LlmRouterState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let operation = match *req.method() {
        axum::http::Method::GET => Operation::ConsentRetrieve,
        axum::http::Method::DELETE => Operation::ConsentDelete,
        _ => Operation::ConsentUpdate,
    };
    handle(state, req, operation, Some(id)).await
}

fn bad_request(message: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_request_error", message)
}

async fn handle(
    state: LlmRouterState,
    req: Request,
    operation: Operation,
    id: Option<String>,
) -> Response {
    let Some(model) = state.resolver.audio_resource_model(LLM_SERVER) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "invalid_request_error",
            "no unambiguous audio resource provider is configured",
        );
    };
    let Ok(_permit) = state.audio_resource_capacity.clone().try_acquire_owned() else {
        let mut response = error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "audio resource capacity is full; retry with backoff",
        );
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
        return response;
    };
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let resource =
        match tokio::time::timeout(UPLOAD_DEADLINE, read_request(req, operation, id)).await {
            Ok(Ok(resource)) => resource,
            Ok(Err(response)) => return *response,
            Err(_) => {
                return error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "invalid_request_error",
                    "audio resource upload exceeded its deadline",
                )
            }
        };
    let mut request = InvocationRequest::new(LLM_SERVER, model);
    request.audio_resource = Some(resource);
    let mut response = match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::UnaryValue(body)) => Json(body).into_response(),
        Ok(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "unexpected audio resource response",
        ),
        Err(error) => invocation_error_response(error),
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn read_request(
    req: Request,
    operation: Operation,
    id: Option<String>,
) -> Result<AudioResourceRequest, Box<Response>> {
    if operation != Operation::ConsentList && req.uri().query().is_some() {
        return Err(bad_request("resource operation does not accept query fields").into());
    }
    let mut resource = AudioResourceRequest {
        operation,
        id,
        fields: BTreeMap::new(),
        upload: None,
    };
    if operation == Operation::ConsentList {
        let query = req.uri().query().map(str::to_owned);
        axum::body::to_bytes(req.into_body(), 0)
            .await
            .map_err(|_| bad_request("resource reads do not accept a request body"))?;
        let mut url = reqwest::Url::parse("http://resource.invalid").expect("fixed URL");
        url.set_query(query.as_deref());
        for (key, value) in url.query_pairs() {
            if resource
                .fields
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(bad_request("duplicate resource query field").into());
            }
        }
    } else if operation == Operation::ConsentUpdate {
        let bytes = axum::body::to_bytes(req.into_body(), 16 * 1024)
            .await
            .map_err(|_| bad_request("resource metadata exceeds its byte limit"))?;
        let body: BTreeMap<String, String> = serde_json::from_slice(&bytes).map_err(|_| {
            bad_request("resource metadata must be a JSON object with string fields")
        })?;
        resource.fields = body;
    } else if let Some(upload_field) = operation.upload_field() {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, MAX_RESOURCE_UPLOAD)
            .await
            .map_err(|_| {
                error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request_error",
                    "voice resource upload exceeds its byte limit",
                )
            })?;
        let mut req = Request::from_parts(parts, axum::body::Body::from(bytes));
        DefaultBodyLimit::max(MAX_RESOURCE_UPLOAD).apply(&mut req);
        let mut form = Multipart::from_request(req, &())
            .await
            .map_err(|_| bad_request("recording-based creation requires multipart/form-data"))?;
        while let Some(field) = form
            .next_field()
            .await
            .map_err(|_| bad_request("invalid audio resource multipart request"))?
        {
            let name = field
                .name()
                .ok_or_else(|| bad_request("multipart fields require names"))?
                .to_owned();
            if name == upload_field {
                if resource.upload.is_some() {
                    return Err(bad_request("only one recording is accepted").into());
                }
                let content_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_owned();
                let file_name = field
                    .file_name()
                    .unwrap_or("recording")
                    .rsplit(['/', '\\'])
                    .next()
                    .expect("a final path segment")
                    .to_owned();
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| bad_request("invalid recording upload"))?;
                resource.upload = Some(AudioUpload {
                    bytes: Arc::from(bytes.as_ref()),
                    content_type,
                    file_name,
                });
            } else {
                let value = field
                    .text()
                    .await
                    .map_err(|_| bad_request("invalid audio resource form field"))?;
                if resource.fields.insert(name, value).is_some() {
                    return Err(bad_request("duplicate audio resource field").into());
                }
            }
        }
    } else {
        axum::body::to_bytes(req.into_body(), 0)
            .await
            .map_err(|_| bad_request("resource operation does not accept a request body"))?;
    }
    resource
        .validate()
        .map_err(|message| Box::new(bad_request(message)))?;
    Ok(resource)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[derive(Default)]
    struct Capture(std::sync::Mutex<Vec<InvocationRequest>>);

    #[async_trait::async_trait]
    impl waygate_invocation::InvocationService for Capture {
        async fn invoke(
            &self,
            _: Option<&waygate_oidc::Principal>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse, InvocationError> {
            let operation = request.audio_resource.as_ref().unwrap().operation;
            self.0.lock().unwrap().push(request);
            Ok(InvocationResponse::UnaryValue(match operation {
                Operation::ConsentList => json!({"object":"list","data":[],"has_more":false}),
                Operation::VoiceDelete => {
                    json!({"object":"audio.voice.deleted","id":"voice_fixture","deleted":true})
                }
                _ => {
                    json!({"object":"audio.voice_consent","id":"cons_fixture","created_at":1,"name":"fixture","language":"en-US"})
                }
            }))
        }
    }

    fn definition(alias: &str) -> ModelDef {
        serde_json::from_value(json!({"alias":alias,"provider":"openai","credential_label":"AUDIO","base_url":"http://provider.invalid/v1","kind":"speech","speech":{"formats":["pcm"],"voices":["narrator"],"resources":["voice_create","voice_delete","consent_create","consent_list","consent_retrieve","consent_update","consent_delete"]}})).unwrap()
    }

    #[test]
    fn resource_routes_require_one_explicit_provider_and_are_not_guessed_from_catalog() {
        assert!(build_from_defs(vec![definition("one"), definition("two")], None).is_err());
        let (_, resolver) = build_from_defs(vec![definition("one")], None)
            .unwrap()
            .unwrap();
        assert_eq!(
            resolver.audio_resource_model(LLM_SERVER).as_deref(),
            Some("one")
        );
        assert!(StaticModelResolver::new()
            .audio_resource_model(LLM_SERVER)
            .is_none());
    }

    #[tokio::test]
    async fn standard_consent_metadata_query_and_deletion_keep_the_same_provider() {
        let capture = Arc::new(Capture::default());
        let (_, resolver) = build_from_defs(vec![definition("resource-provider")], None)
            .unwrap()
            .unwrap();
        let app = router(capture.clone(), None, resolver);
        for (method, path, body) in [
            (
                "GET",
                "/v1/audio/voice_consents?limit=10&after=cons_previous",
                "",
            ),
            (
                "POST",
                "/v1/audio/voice_consents/cons_fixture",
                r#"{"name":"updated"}"#,
            ),
            ("DELETE", "/v1/audio/voices/voice_fixture", ""),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let requests = capture.0.lock().unwrap();
        assert!(requests
            .iter()
            .all(|request| request.tool == "resource-provider"));
        let list = requests[0].audio_resource.as_ref().unwrap();
        assert_eq!(list.operation, Operation::ConsentList);
        assert_eq!(list.fields["limit"], "10");
        assert_eq!(list.fields["after"], "cons_previous");
        assert_eq!(
            requests[1].audio_resource.as_ref().unwrap().fields["name"],
            "updated"
        );
        assert_eq!(
            requests[2].audio_resource.as_ref().unwrap().id.as_deref(),
            Some("voice_fixture")
        );
    }

    #[tokio::test]
    async fn recording_uploads_preserve_file_and_consent_without_extra_client_fields() {
        let body = "--fixture\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nreference\r\n--fixture\r\nContent-Disposition: form-data; name=\"consent\"\r\n\r\ncons_fixture\r\n--fixture\r\nContent-Disposition: form-data; name=\"audio_sample\"; filename=\"reference.wav\"\r\nContent-Type: audio/wav\r\n\r\nfixture recording\r\n--fixture--\r\n";
        let request = Request::builder()
            .method("POST")
            .header("content-type", "multipart/form-data; boundary=fixture")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resource = read_request(request, Operation::VoiceCreate, None)
            .await
            .unwrap();
        assert_eq!(resource.fields.len(), 2);
        assert_eq!(resource.fields["consent"], "cons_fixture");
        let upload = resource.upload.as_ref().unwrap();
        assert_eq!(upload.bytes.as_ref(), b"fixture recording");
        assert_eq!(upload.file_name, "reference.wav");
        assert!(!format!("{resource:?}").contains("fixture recording"));
        let request = Request::builder()
            .method("POST")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"type":"prompt","name":"voice","prompt":"private description"}"#,
            ))
            .unwrap();
        assert!(read_request(request, Operation::VoiceCreate, None)
            .await
            .is_err());
    }
}
