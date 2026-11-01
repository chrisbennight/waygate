//! Speech uses one provider attempt; a failed response must not replay generation.

use super::*;
use waygate_llm_translate::speech::SpeechRequest;

impl LlmDispatcher {
    pub async fn dispatch_speech(
        &self,
        request: SpeechRequest,
        route: &ResolvedRoute,
    ) -> Result<SpeechResponse, DispatchError> {
        if route.openai_chatgpt || route.embeddings_no_auth {
            return Err(
                ProviderError::Protocol("speech requires a standard bearer route".into()).into(),
            );
        }
        let bearer = self
            .credentials
            .bearer(route.provider, &route.credential_label)
            .await?;
        let sse = request.sse;
        let media_type = request.format.media_type();
        Ok(self
            .providers
            .send_speech(
                ProviderRequest {
                    base_url: route.base_url.clone(),
                    path: route.path.clone(),
                    bearer,
                    auth: ProviderAuth::Bearer,
                    body: request.render(&route.upstream_model),
                    stream: sse,
                    account_id: None,
                    codex_ua_version: None,
                },
                media_type,
            )
            .await?)
    }
}
