//! Single-attempt speech transport. Provider error bodies and transport URLs stay private.

use super::*;

pub type AudioStream = BoxStream<'static, Result<bytes::Bytes, ProviderError>>;
pub const MAX_AUDIO_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

pub enum SpeechResponse {
    Audio(AudioStream),
    Events(SseStream),
}

impl ProviderClient {
    pub async fn send_speech(
        &self,
        req: ProviderRequest,
        media_type: &'static str,
    ) -> Result<SpeechResponse, ProviderError> {
        if !matches!(req.auth, ProviderAuth::Bearer) {
            return Err(ProviderError::Protocol(
                "speech requires bearer authentication".into(),
            ));
        }
        let http = self.single_attempt_http.as_ref().ok_or_else(|| {
            ProviderError::Protocol("single-attempt speech transport is not configured".into())
        })?;
        let url = format!(
            "{}/{}",
            req.base_url.trim_end_matches('/'),
            req.path.trim_start_matches('/')
        );
        let response = http
            .post(url)
            .bearer_auth(&req.bearer)
            .header(
                reqwest::header::ACCEPT,
                if req.stream {
                    "text/event-stream"
                } else {
                    media_type
                },
            )
            .json(&req.body)
            .send()
            .await
            .map_err(|_| ProviderError::Transport("speech provider connection failed".into()))?;
        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(|s| std::time::Duration::from_secs(s.min(300)));
            return Err(ProviderError::Status {
                status: status.as_u16(),
                body: "speech provider rejected the request".into(),
                retry_after,
            });
        }
        if !req.stream
            && response
                .content_length()
                .is_some_and(|length| length > MAX_AUDIO_RESPONSE_BYTES as u64)
        {
            return Err(ProviderError::Protocol(
                "speech audio response exceeds its byte limit".into(),
            ));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .unwrap_or("")
            .trim();
        let valid_type = if req.stream {
            content_type == "text/event-stream"
        } else {
            content_type == media_type
                || content_type == "application/octet-stream"
                || (media_type == "audio/wav" && content_type == "audio/x-wav")
        };
        if !valid_type {
            return Err(ProviderError::Protocol(
                "speech provider returned an unexpected content type".into(),
            ));
        }
        if req.stream {
            Ok(SpeechResponse::Events(sse::into_event_stream(response)))
        } else {
            Ok(SpeechResponse::Audio(
                response
                    .bytes_stream()
                    .map(|chunk| {
                        chunk.map_err(|_| {
                            ProviderError::Transport("speech audio stream interrupted".into())
                        })
                    })
                    .boxed(),
            ))
        }
    }
}
