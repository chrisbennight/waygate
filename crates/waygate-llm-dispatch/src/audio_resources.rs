//! Authorized standard resource operations use one configured provider attempt.

use super::*;
use waygate_core::audio::AudioResourceRequest;

impl LlmDispatcher {
    pub async fn dispatch_audio_resource(
        &self,
        request: AudioResourceRequest,
        route: &ResolvedRoute,
    ) -> Result<Value, DispatchError> {
        if route.openai_chatgpt || route.embeddings_no_auth {
            return Err(ProviderError::Protocol(
                "audio resources require a standard bearer provider".into(),
            )
            .into());
        }
        let bearer = self
            .credentials
            .api_key(route.provider, &route.credential_label)
            .await?;
        Ok(self
            .providers
            .send_audio_resource(&route.base_url, &bearer, request)
            .await?)
    }
}
