//! Standard Speech API ingress; audio passes through the shared invocation boundary.

use super::*;

pub(super) fn validate_config(def: &ModelDef) -> anyhow::Result<()> {
    if !is_speech(def) {
        anyhow::ensure!(
            def.speech.is_none(),
            "speech capabilities require kind speech"
        );
        return Ok(());
    }
    anyhow::ensure!(
        def.provider.eq_ignore_ascii_case("openai")
            || def.provider.eq_ignore_ascii_case("openrouter"),
        "speech requires an OpenAI-compatible bearer provider"
    );
    anyhow::ensure!(def.surface.is_none() && def.fallbacks.is_empty() && def.credential_labels.as_ref().is_none_or(Vec::is_empty) && def.cache_ttl_ms.is_none() && def.ttfb_ms.is_none(), "speech requires one route without surface overrides, fallbacks, caching, or chat streaming deadlines");
    def.speech
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("speech models require explicit speech capabilities"))?
        .validate()?;
    let url = reqwest::Url::parse(&def.base_url)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "speech provider URL must use HTTP(S) without user information, queries, or fragments"
    );
    anyhow::ensure!(
        def.path.as_ref().is_none_or(|p| !p.is_empty()
            && !p.contains(['?', '#'])
            && !p.split('/').any(|segment| segment == "..")),
        "invalid speech provider path"
    );
    Ok(())
}

pub(super) async fn create(State(state): State<LlmRouterState>, req: Request) -> Response {
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let (body, model) = match read_llm_body(req).await {
        Ok(parts) => parts,
        Err(response) => return *response,
    };
    let mut request =
        InvocationRequest::new(LLM_SERVER, model).with_arguments(body.as_object().cloned());
    request.speech_surface = true;
    match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::Media { media_type, body }) => (
            [
                (axum::http::header::CONTENT_TYPE, media_type),
                (axum::http::header::CACHE_CONTROL, "no-store"),
                (
                    axum::http::header::HeaderName::from_static("x-accel-buffering"),
                    "no",
                ),
            ],
            axum::body::Body::from_stream(body),
        )
            .into_response(),
        Ok(_) => super::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "unexpected response on the speech route",
        ),
        Err(error) => invocation_error_response(error),
    }
}

pub(super) fn error_response(error: &InvocationError) -> Option<Response> {
    let InvocationError::Upstream(error) = error else {
        return None;
    };
    let data = error.data.as_ref()?;
    let status = data.get("speech_http_status")?.as_u64()?;
    let (status, kind) = match status {
        429 => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_error"),
        400..=499 if !matches!(status, 401 | 403) => (
            StatusCode::from_u16(status as u16).ok()?,
            "invalid_request_error",
        ),
        504 => (StatusCode::GATEWAY_TIMEOUT, "api_error"),
        _ => (StatusCode::BAD_GATEWAY, "api_error"),
    };
    let mut response = super::error_response(status, kind, &error.message);
    if let Some(seconds) = data.get("retry_after_seconds").and_then(Value::as_u64) {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            seconds
                .min(300)
                .to_string()
                .parse()
                .expect("numeric retry delay"),
        );
    }
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: Value) -> ModelDef {
        let mut value = json!({"alias":"speech","provider":"openai","credential_label":"SPEECH","kind":"speech","base_url":"http://provider.invalid/v1","speech":{"formats":["mp3","pcm","wav"],"voices":["narrator"],"instructions":true,"sse_formats":["pcm"]}});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn speech_configuration_requires_explicit_capabilities_and_single_standard_route() {
        assert!(validate_config(&config(json!({}))).is_ok());
        for extra in [
            json!({"speech":null}),
            json!({"speech":{"formats":[],"voices":["narrator"]}}),
            json!({"surface":"codex"}),
            json!({"cache_ttl_ms":1000}),
            json!({"credential_labels":["BACKUP"]}),
            json!({"base_url":"http://provider.invalid/v1?key=private"}),
            json!({"path":"../audio/speech"}),
        ] {
            assert!(validate_config(&config(extra)).is_err());
        }
    }

    #[test]
    fn speech_catalog_and_live_route_share_the_same_operation() {
        let def = config(json!({}));
        let row = model_def_to_upsert(&def);
        let (_, resolver) = build_from_defs(vec![def], None).unwrap().unwrap();
        let model = resolver.resolve(LLM_SERVER, &row.alias).unwrap();
        assert!(matches!(model.operation, LlmOperation::Speech(_)));
        assert_eq!(row.upstream_api, "speech");
        assert_eq!(row.path, "audio/speech");
        assert_eq!(model.route.path, row.path);
        assert!(ModelKindFilter::Speech.matches(&row.upstream_api));
        assert!(!ModelKindFilter::Chat.matches(&row.upstream_api));
        assert_eq!(model_modality(&row.upstream_api), "text->audio");
    }

    #[test]
    fn provider_overload_preserves_retry_guidance_without_exposing_authentication() {
        let response = error_response(&InvocationError::Upstream(rmcp::ErrorData::internal_error(
            "speech provider request failed",
            Some(json!({"speech_http_status":429,"retry_after_seconds":10})),
        )))
        .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "10");
        let response = error_response(&InvocationError::Upstream(rmcp::ErrorData::internal_error(
            "speech provider request failed",
            Some(json!({"speech_http_status":401})),
        )))
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(response.headers().get("www-authenticate").is_none());
    }
}
