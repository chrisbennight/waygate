//! Images dispatch using the shared provider transport and credential store.

use super::*;
use waygate_llm_translate::images::{extract_images, ImagesRequest};

/// Bounds base64 results independently of smaller chat response limits.
pub const MAX_IMAGE_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

impl DispatchError {
    /// HTTP status metadata without exposing provider bodies or credentials.
    pub fn provider_status(&self) -> Option<u16> {
        match self {
            Self::Provider(ProviderError::Status { status, .. }) => Some(*status),
            _ => None,
        }
    }
}

impl LlmDispatcher {
    /// Exactly one provider attempt. A timeout or disconnect can follow a
    /// successful generation; automatic replay could charge for another image.
    pub async fn dispatch_images(
        &self,
        req: ImagesRequest,
        route: &ResolvedRoute,
    ) -> Result<(InferenceRecord, Value), DispatchError> {
        if route.provider != LlmProvider::OpenAi || route.embeddings_no_auth {
            return Err(ProviderError::Protocol(
                "image route requires an authenticated OpenAI credential".into(),
            )
            .into());
        }
        if route.openai_chatgpt {
            return Err(ProviderError::Protocol("consumer subscription image routes are no longer supported; migrate this model to the OpenAI Images API".into()).into());
        }
        let bearer = self
            .credentials
            .api_key(route.provider, &route.credential_label)
            .await?;
        let auth = ProviderAuth::Bearer;
        let record = InferenceRecord::new(
            route.provider,
            &route.credential_label,
            &req.model_requested,
            if req.edit {
                Surface::ImagesEdits
            } else {
                Surface::ImagesGenerations
            },
            route.protocol,
        );
        let started = std::time::Instant::now();
        let response = self
            .providers
            .send_bounded(
                ProviderRequest {
                    base_url: route.base_url.clone(),
                    path: format!(
                        "{}/{}",
                        route.path.trim_end_matches('/'),
                        if req.edit { "edits" } else { "generations" }
                    ),
                    bearer,
                    auth,
                    body: req.render(&route.upstream_model),
                    stream: false,
                },
                MAX_IMAGE_RESPONSE_BYTES,
            )
            .await
            .and_then(|response| match response {
                ProviderResponse::Unary(body) => {
                    if body.get("created").and_then(Value::as_u64).is_none()
                        || !body
                            .get("data")
                            .and_then(Value::as_array)
                            .is_some_and(|items| {
                                !items.is_empty()
                                    && items.iter().all(|item| {
                                        item.get("b64_json")
                                            .and_then(Value::as_str)
                                            .is_some_and(|s| !s.is_empty())
                                    })
                            })
                    {
                        return Err(ProviderError::Protocol(
                            "invalid Images API response".into(),
                        ));
                    }
                    Ok(body)
                }
                ProviderResponse::Stream(_) => {
                    Err(ProviderError::Protocol("unexpected image stream".into()))
                }
            })
            .inspect_err(|_| {
                waygate_telemetry::metrics::record_llm_request_failure(
                    route.provider.as_str(),
                    &record.model_requested,
                    record.provider_account_id.as_deref(),
                    started.elapsed().as_secs_f64(),
                    waygate_telemetry::metrics::LlmFailurePhase::Dispatch,
                )
            })?;
        Ok((extract_images(record, &response), response))
    }
}
