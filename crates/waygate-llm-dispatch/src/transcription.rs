//! Transcription uses one provider attempt; an upload is never replayed.

use super::*;
use waygate_llm_translate::transcription::TranscriptionRequest;

impl LlmDispatcher {
    pub async fn dispatch_transcription(
        &self,
        request: TranscriptionRequest,
        route: &ResolvedRoute,
    ) -> Result<TranscriptionBody, DispatchError> {
        if route.openai_chatgpt || route.embeddings_no_auth {
            return Err(ProviderError::Protocol(
                "transcription requires a standard bearer route".into(),
            )
            .into());
        }
        let bearer = self
            .credentials
            .api_key(route.provider, &route.credential_label)
            .await?;
        let json = request.format.is_json();
        let (upload, fields) = request.render(&route.upstream_model);
        Ok(self
            .providers
            .send_transcription(&route.base_url, &route.path, &bearer, upload, fields, json)
            .await?)
    }
}
