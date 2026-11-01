//! Realtime transport retains the configured HTTP proxy/TLS policy and one-attempt semantics.

use super::*;
use futures::{future::BoxFuture, FutureExt};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    handshake::derive_accept_key,
    protocol::{Role, WebSocketConfig},
};
use waygate_core::realtime::{MAX_REALTIME_EVENT_BYTES, MAX_REALTIME_SDP_BYTES};

pub use tokio_tungstenite::tungstenite::Message as RealtimeMessage;
pub type RealtimeSocket = tokio_tungstenite::WebSocketStream<reqwest::Upgraded>;

pub struct RealtimeCallResponse {
    pub call_id: String,
    /// The caller installs call cleanup before reading the answer body.
    pub answer: BoxFuture<'static, Result<String, ProviderError>>,
}

fn endpoint(base: &str, segments: &[&str]) -> Result<reqwest::Url, ProviderError> {
    let invalid = || ProviderError::Protocol("invalid Realtime provider URL".into());
    let mut url = reqwest::Url::parse(base).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    url.path_segments_mut()
        .map_err(|_| invalid())?
        .pop_if_empty()
        .extend(segments.iter().copied());
    Ok(url)
}

fn failure(response: &reqwest::Response) -> ProviderError {
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| std::time::Duration::from_secs(seconds.min(300)));
    ProviderError::Status {
        status: response.status().as_u16(),
        body: "Realtime provider rejected the request".into(),
        retry_after,
    }
}

impl ProviderClient {
    pub async fn connect_realtime(
        &self,
        base_url: &str,
        bearer: &str,
        model: Option<&str>,
        call_id: Option<&str>,
    ) -> Result<RealtimeSocket, ProviderError> {
        if model.is_some() == call_id.is_some() {
            return Err(ProviderError::Protocol(
                "Realtime requires exactly one model or call identifier".into(),
            ));
        }
        let http = self.single_attempt_http.as_ref().ok_or_else(|| {
            ProviderError::Protocol("single-attempt Realtime transport is not configured".into())
        })?;
        let mut url = endpoint(base_url, &["realtime"])?;
        if let Some(model) = model {
            url.query_pairs_mut().append_pair("model", model);
        }
        if let Some(call_id) = call_id {
            url.query_pairs_mut().append_pair("call_id", call_id);
        }
        let mut ws_url = url.clone();
        ws_url
            .set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
            .expect("fixed WebSocket scheme");
        let handshake = ws_url
            .as_str()
            .into_client_request()
            .map_err(|_| ProviderError::Protocol("invalid Realtime handshake".into()))?;
        let key = handshake
            .headers()
            .get("sec-websocket-key")
            .expect("generated WebSocket key");
        let response = http
            .get(url)
            .version(reqwest::Version::HTTP_11)
            .headers(handshake.headers().clone())
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|_| ProviderError::Transport("Realtime connection failed".into()))?;
        if response.status() != reqwest::StatusCode::SWITCHING_PROTOCOLS {
            return Err(failure(&response));
        }
        let valid_upgrade = response
            .headers()
            .get("upgrade")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        let valid_connection = response
            .headers()
            .get("connection")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            });
        let valid_accept = response
            .headers()
            .get("sec-websocket-accept")
            .is_some_and(|value| value.as_bytes() == derive_accept_key(key.as_bytes()).as_bytes());
        if !valid_upgrade
            || !valid_connection
            || !valid_accept
            || response.headers().contains_key("sec-websocket-protocol")
            || response.headers().contains_key("sec-websocket-extensions")
        {
            return Err(ProviderError::Protocol(
                "Realtime provider returned an invalid WebSocket handshake".into(),
            ));
        }
        let upgraded = response
            .upgrade()
            .await
            .map_err(|_| ProviderError::Transport("Realtime upgrade failed".into()))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_REALTIME_EVENT_BYTES))
            .max_frame_size(Some(MAX_REALTIME_EVENT_BYTES));
        Ok(tokio_tungstenite::WebSocketStream::from_raw_socket(
            upgraded,
            Role::Client,
            Some(config),
        )
        .await)
    }

    pub async fn create_realtime_call(
        &self,
        base_url: &str,
        bearer: &str,
        sdp: String,
        session: Value,
    ) -> Result<RealtimeCallResponse, ProviderError> {
        if sdp.len() > MAX_REALTIME_SDP_BYTES || !sdp.starts_with("v=0") {
            return Err(ProviderError::Protocol(
                "invalid or oversized WebRTC offer".into(),
            ));
        }
        let http = self.single_attempt_http.as_ref().ok_or_else(|| {
            ProviderError::Protocol("single-attempt Realtime transport is not configured".into())
        })?;
        let url = endpoint(base_url, &["realtime", "calls"])?;
        let form = reqwest::multipart::Form::new()
            .text("sdp", sdp)
            .text("session", session.to_string());
        let response = http
            .post(url.clone())
            .bearer_auth(bearer)
            .multipart(form)
            .send()
            .await
            .map_err(|_| {
                ProviderError::Transport(
                    "WebRTC setup failed; call creation was not retried".into(),
                )
            })?;
        if !response.status().is_success() {
            return Err(failure(&response));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| url.join(value).ok())
            .ok_or_else(|| {
                ProviderError::Protocol("WebRTC provider omitted its call identifier".into())
            })?;
        let segments: Vec<_> = location.path_segments().into_iter().flatten().collect();
        if segments.len() < 3
            || segments[segments.len() - 3..segments.len() - 1] != ["realtime", "calls"]
            || location.query().is_some()
            || location.fragment().is_some()
        {
            return Err(ProviderError::Protocol(
                "WebRTC provider returned an invalid call location".into(),
            ));
        }
        let call_id = percent_encoding::percent_decode_str(segments[segments.len() - 1])
            .decode_utf8()
            .map_err(|_| {
                ProviderError::Protocol(
                    "WebRTC provider returned an invalid call identifier".into(),
                )
            })?
            .into_owned();
        if call_id.is_empty()
            || call_id.len() > 512
            || matches!(call_id.as_str(), "." | "..")
            || call_id.chars().any(char::is_control)
        {
            return Err(ProviderError::Protocol(
                "WebRTC provider returned an invalid call identifier".into(),
            ));
        }
        Ok(RealtimeCallResponse {
            call_id,
            answer: read_sdp(response).boxed(),
        })
    }

    pub async fn hangup_realtime_call(
        &self,
        base_url: &str,
        bearer: &str,
        call_id: &str,
    ) -> Result<(), ProviderError> {
        let http = self.single_attempt_http.as_ref().ok_or_else(|| {
            ProviderError::Protocol("single-attempt Realtime transport is not configured".into())
        })?;
        let response = http
            .post(endpoint(
                base_url,
                &["realtime", "calls", call_id, "hangup"],
            )?)
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|_| {
                ProviderError::Transport("Realtime hangup could not be confirmed".into())
            })?;
        if !response.status().is_success() {
            return Err(failure(&response));
        }
        Ok(())
    }
}

async fn read_sdp(response: reqwest::Response) -> Result<String, ProviderError> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_REALTIME_SDP_BYTES as u64)
    {
        return Err(ProviderError::Protocol(
            "WebRTC answer exceeds its byte limit".into(),
        ));
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| ProviderError::Transport("WebRTC answer was interrupted".into()))?;
        if chunk.len() > MAX_REALTIME_SDP_BYTES.saturating_sub(bytes.len()) {
            return Err(ProviderError::Protocol(
                "WebRTC answer exceeds its byte limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let sdp = String::from_utf8(bytes)
        .map_err(|_| ProviderError::Protocol("WebRTC provider returned invalid SDP".into()))?;
    if !sdp.starts_with("v=0") {
        return Err(ProviderError::Protocol(
            "WebRTC provider returned invalid SDP".into(),
        ));
    }
    Ok(sdp)
}
