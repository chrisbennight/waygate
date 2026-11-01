//! Realtime provider calls retain one credential snapshot and never replay session creation.

use super::*;
use futures::{future::BoxFuture, FutureExt};

#[derive(Clone)]
pub struct RealtimeCallControl {
    providers: ProviderClient,
    base_url: String,
    bearer: Arc<String>,
    call_id: String,
}

impl RealtimeCallControl {
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub async fn hangup(&self) -> Result<(), DispatchError> {
        self.providers
            .hangup_realtime_call(&self.base_url, &self.bearer, &self.call_id)
            .await
            .map_err(Into::into)
    }

    pub async fn connect_sideband(&self) -> Result<RealtimeSocket, DispatchError> {
        self.providers
            .connect_realtime(&self.base_url, &self.bearer, None, Some(&self.call_id))
            .await
            .map_err(Into::into)
    }
}

pub struct RealtimeCallSetup {
    pub control: RealtimeCallControl,
    pub answer: BoxFuture<'static, Result<String, DispatchError>>,
}

fn validate_route(route: &ResolvedRoute) -> Result<(), DispatchError> {
    if route.openai_chatgpt || route.embeddings_no_auth {
        return Err(
            ProviderError::Protocol("Realtime requires a standard API-key route".into()).into(),
        );
    }
    Ok(())
}

impl LlmDispatcher {
    pub async fn connect_realtime(
        &self,
        route: &ResolvedRoute,
    ) -> Result<RealtimeSocket, DispatchError> {
        validate_route(route)?;
        let bearer = self
            .credentials
            .api_key(route.provider, &route.credential_label)
            .await?;
        self.providers
            .connect_realtime(&route.base_url, &bearer, Some(&route.upstream_model), None)
            .await
            .map_err(Into::into)
    }

    pub async fn create_realtime_call(
        &self,
        route: &ResolvedRoute,
        sdp: String,
        session: Value,
    ) -> Result<RealtimeCallSetup, DispatchError> {
        validate_route(route)?;
        let bearer = self
            .credentials
            .api_key(route.provider, &route.credential_label)
            .await?;
        let response = self
            .providers
            .create_realtime_call(&route.base_url, &bearer, sdp, session)
            .await?;
        Ok(RealtimeCallSetup {
            control: RealtimeCallControl {
                providers: self.providers.clone(),
                base_url: route.base_url.clone(),
                bearer: Arc::new(bearer),
                call_id: response.call_id,
            },
            answer: response
                .answer
                .map(|result| result.map_err(Into::into))
                .boxed(),
        })
    }

    pub async fn hangup_realtime_call(
        &self,
        route: &ResolvedRoute,
        call_id: &str,
    ) -> Result<(), DispatchError> {
        validate_route(route)?;
        let bearer = self
            .credentials
            .api_key(route.provider, &route.credential_label)
            .await?;
        self.providers
            .hangup_realtime_call(&route.base_url, &bearer, call_id)
            .await
            .map_err(Into::into)
    }
}
