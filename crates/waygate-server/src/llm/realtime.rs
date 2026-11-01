//! Standard authenticated WebSocket and unified WebRTC call ingress.

use super::*;
use axum::extract::{
    ws::{Message, WebSocketUpgrade},
    DefaultBodyLimit, FromRequest, Multipart, Path,
};
use futures::SinkExt;
use waygate_core::realtime::{RealtimeRequest, MAX_REALTIME_EVENT_BYTES, MAX_REALTIME_SDP_BYTES};

pub(super) fn validate_config(def: &ModelDef) -> anyhow::Result<()> {
    if !is_realtime(def) {
        anyhow::ensure!(
            def.realtime.is_none(),
            "Realtime capabilities require kind realtime"
        );
        return Ok(());
    }
    anyhow::ensure!(
        def.provider.eq_ignore_ascii_case("openai")
            || def.provider.eq_ignore_ascii_case("openrouter"),
        "Realtime requires an OpenAI-compatible provider"
    );
    anyhow::ensure!(
        def.surface.is_none()
            && def.fallbacks.is_empty()
            && def.credential_labels.as_ref().is_none_or(Vec::is_empty)
            && def.cache_ttl_ms.is_none()
            && def.ttfb_ms.is_none()
            && def.path.as_ref().is_none_or(|path| path == "realtime"),
        "Realtime requires one standard route without fallbacks, caching, or path overrides"
    );
    def.realtime
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Realtime models require explicit capabilities"))?
        .validate()
        .map_err(anyhow::Error::msg)?;
    let url = reqwest::Url::parse(&def.base_url)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Realtime base URL requires HTTP(S) without user information, query, or fragment"
    );
    Ok(())
}

fn bad(message: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_request_error", message)
}

pub(super) async fn websocket(
    State(state): State<LlmRouterState>,
    ws: WebSocketUpgrade,
    req: Request,
) -> Response {
    let mut url = reqwest::Url::parse("http://realtime.invalid").expect("fixed URL");
    url.set_query(req.uri().query());
    let mut model = None;
    for (name, value) in url.query_pairs() {
        if name != "model" || value.is_empty() || model.replace(value.into_owned()).is_some() {
            return bad("Realtime WebSocket requires one model query parameter");
        }
    }
    let Some(model) = model else {
        return bad("Realtime WebSocket requires a model");
    };
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let mut request = InvocationRequest::new(LLM_SERVER, model);
    request.realtime = Some(RealtimeRequest::WebSocket);
    let response = state.invocation.invoke(principal.as_ref(), request).await;
    match response {
        Ok(InvocationResponse::Realtime {
            mut commands,
            mut events,
        }) => ws
            .max_message_size(MAX_REALTIME_EVENT_BYTES)
            .max_frame_size(MAX_REALTIME_EVENT_BYTES)
            .max_write_buffer_size(MAX_REALTIME_EVENT_BYTES * 2)
            .on_upgrade(move |socket| async move {
                let (mut output, mut input) = socket.split();
                let read = async {
                    let mut count = 0usize;
                    while let Some(message) = input.next().await {
                        match message {
                            Ok(Message::Text(text)) => {
                                count += 1;
                                if count > 100_000 {
                                    break;
                                }
                                let Ok(value) = serde_json::from_str(&text) else {
                                    break;
                                };
                                if commands.send(value).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Message::Ping(_) | Message::Pong(_)) => {}
                            _ => break,
                        }
                    }
                };
                let write = async {
                    while let Some(event) = events.next().await {
                        let Ok(value) = event else { break };
                        if output
                            .send(Message::Text(value.to_string().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                };
                tokio::select! { _ = read => {}, _ = write => {} }
            })
            .into_response(),
        Ok(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "unexpected Realtime response",
        ),
        Err(error) => invocation_error_response(error),
    }
}

pub(super) async fn create_call(State(state): State<LlmRouterState>, req: Request) -> Response {
    if req.uri().query().is_some() {
        return bad("unified WebRTC call creation takes multipart fields");
    }
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    let Ok(_permit) = state.audio_resource_capacity.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "Realtime call upload capacity is full",
        );
    };
    let (sdp, session, model) =
        match tokio::time::timeout(std::time::Duration::from_secs(30), read_offer(req)).await {
            Ok(Ok(offer)) => offer,
            Ok(Err(response)) => return *response,
            Err(_) => {
                return error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "invalid_request_error",
                    "Realtime offer upload exceeded its deadline",
                )
            }
        };
    // A fixed route makes model-less native call controls work on every replica.
    if state.resolver.realtime_call_model(LLM_SERVER).as_deref() != Some(&model) {
        return bad("WebRTC requires the configured call model");
    }
    let mut request = InvocationRequest::new(LLM_SERVER, model);
    request.realtime = Some(RealtimeRequest::WebRtc { sdp, session });
    match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::RealtimeCall {
            call_id,
            sdp,
            delivery_guard,
        }) => {
            let mut location = reqwest::Url::parse("http://gateway.invalid/v1/realtime/calls/")
                .expect("fixed URL");
            location
                .path_segments_mut()
                .expect("HTTP path")
                .pop_if_empty()
                .push(&call_id);
            let location = location.path().to_owned();
            let body = futures::stream::unfold(
                (Some(sdp), Some(delivery_guard)),
                |(sdp, guard)| async move {
                    match sdp {
                        Some(sdp) => Some((
                            Ok::<_, std::convert::Infallible>(bytes::Bytes::from(sdp)),
                            (None, guard),
                        )),
                        None => {
                            if let Some(guard) = guard {
                                guard.disarm();
                            }
                            None
                        }
                    }
                },
            );
            (
                StatusCode::CREATED,
                [
                    (axum::http::header::CONTENT_TYPE, "application/sdp"),
                    (axum::http::header::CACHE_CONTROL, "no-store"),
                    (axum::http::header::LOCATION, location.as_str()),
                ],
                axum::body::Body::from_stream(body),
            )
                .into_response()
        }
        Ok(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "unexpected WebRTC response",
        ),
        Err(error) => invocation_error_response(error),
    }
}

async fn read_offer(req: Request) -> Result<(String, Value, String), Box<Response>> {
    const MAX_OFFER: usize = MAX_REALTIME_SDP_BYTES + MAX_REALTIME_EVENT_BYTES + 16 * 1024;
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_OFFER)
        .await
        .map_err(|_| bad("Realtime offer exceeds its byte limit"))?;
    let mut req = Request::from_parts(parts, axum::body::Body::from(bytes));
    DefaultBodyLimit::max(MAX_OFFER).apply(&mut req);
    let mut form = Multipart::from_request(req, &())
        .await
        .map_err(|_| bad("unified WebRTC calls require multipart/form-data"))?;
    let mut sdp = None;
    let mut session = None;
    while let Some(field) = form
        .next_field()
        .await
        .map_err(|_| bad("invalid Realtime multipart offer"))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        let text = field
            .text()
            .await
            .map_err(|_| bad("Realtime offer fields require text"))?;
        match name.as_str() {
            "sdp"
                if sdp.is_none()
                    && text.len() <= MAX_REALTIME_SDP_BYTES
                    && text.starts_with("v=0") =>
            {
                sdp = Some(text)
            }
            "session" if session.is_none() && text.len() <= MAX_REALTIME_EVENT_BYTES => {
                session = Some(
                    serde_json::from_str::<Value>(&text)
                        .map_err(|_| bad("Realtime session must be a JSON object"))?,
                )
            }
            _ => {
                return Err(bad("unsupported, duplicate, or oversized Realtime offer field").into())
            }
        }
    }
    let session = session.ok_or_else(|| bad("Realtime calls require session configuration"))?;
    let model = session
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty())
        .ok_or_else(|| bad("Realtime session requires a model"))?
        .to_owned();
    Ok((
        sdp.ok_or_else(|| bad("Realtime calls require an SDP offer"))?,
        session,
        model,
    ))
}

pub(super) async fn hangup(
    State(state): State<LlmRouterState>,
    Path(call_id): Path<String>,
    req: Request,
) -> Response {
    if req.uri().query().is_some() {
        return bad("Realtime hangup does not accept query fields");
    }
    let principal = waygate_oidc::middleware::principal_from_req(&req).cloned();
    if axum::body::to_bytes(req.into_body(), 0).await.is_err() {
        return bad("Realtime hangup does not accept a request body");
    }
    let Some(model) = state.resolver.realtime_call_model(LLM_SERVER) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "invalid_request_error",
            "no Realtime call provider is configured",
        );
    };
    let mut request = InvocationRequest::new(LLM_SERVER, model);
    request.realtime = Some(RealtimeRequest::Hangup { call_id });
    match state.invocation.invoke(principal.as_ref(), request).await {
        Ok(InvocationResponse::UnaryValue(value)) if value.is_null() => {
            StatusCode::OK.into_response()
        }
        Ok(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "unexpected Realtime hangup response",
        ),
        Err(error) => invocation_error_response(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ModelDef {
        serde_json::from_value(json!({"alias":"live","provider":"openai","credential_label":"TEST","base_url":"http://provider.invalid/v1","kind":"realtime","realtime":{"websocket":true,"webrtc":true,"voices":["narrator"]}})).unwrap()
    }

    #[test]
    fn realtime_routes_and_catalog_require_explicit_unambiguous_configuration() {
        let def = config();
        let row = model_def_to_upsert(&def);
        let (_, resolver) = build_from_defs(vec![def.clone()], None).unwrap().unwrap();
        assert!(matches!(
            resolver.resolve(LLM_SERVER, "live").unwrap().operation,
            LlmOperation::Realtime(_)
        ));
        assert_eq!(
            resolver.realtime_call_model(LLM_SERVER).as_deref(),
            Some("live")
        );
        assert_eq!(row.upstream_api, "realtime");
        assert_eq!(row.path, "realtime");
        assert!(ModelKindFilter::Realtime.matches(&row.upstream_api));
        assert!(!ModelKindFilter::Chat.matches(&row.upstream_api));
        let mut second = def.clone();
        second.alias = "other".into();
        assert!(build_from_defs(vec![def.clone(), second.clone()], None).is_err());
        second.realtime.as_mut().unwrap().webrtc = false;
        assert!(build_from_defs(vec![def.clone(), second], None).is_ok());
        for extra in [
            json!({"realtime":null}),
            json!({"cache_ttl_ms":1}),
            json!({"surface":"codex"}),
            json!({"base_url":"https://user:secret@provider.invalid"}),
            json!({"path":"native"}),
        ] {
            let mut value=serde_json::from_str::<Value>(r#"{"alias":"live","provider":"openai","credential_label":"TEST","base_url":"http://provider.invalid/v1","kind":"realtime","realtime":{"websocket":true,"voices":["narrator"]}}"#).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(validate_config(&serde_json::from_value(value).unwrap()).is_err());
        }
    }
}
