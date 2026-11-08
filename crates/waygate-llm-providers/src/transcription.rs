//! Single-attempt transcription transport. Audio, transcripts and provider error
//! bodies stay private.

use std::collections::BTreeMap;

use super::*;
use waygate_core::audio::AudioUpload;

pub const MAX_TRANSCRIPTION_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// A provider transcript in the requested shape: a JSON object containing a
/// string `text`, or the plain-text body of a text, SRT or VTT response.
pub enum TranscriptionBody {
    Json(Value),
    Text(String),
}

impl ProviderClient {
    pub async fn send_transcription(
        &self,
        base_url: &str,
        path: &str,
        bearer: &str,
        upload: AudioUpload,
        fields: BTreeMap<String, String>,
        json: bool,
    ) -> Result<TranscriptionBody, ProviderError> {
        let http = self.single_attempt_http.as_ref().ok_or_else(|| {
            ProviderError::Protocol(
                "single-attempt transcription transport is not configured".into(),
            )
        })?;
        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let file = reqwest::multipart::Part::bytes(upload.bytes.to_vec())
            .file_name(upload.file_name)
            .mime_str(&upload.content_type)
            .map_err(|_| ProviderError::Protocol("invalid transcription content type".into()))?;
        let mut form = reqwest::multipart::Form::new();
        for (key, value) in fields {
            form = form.text(key, value);
        }
        let response = http
            .post(url)
            .bearer_auth(bearer)
            .header(
                reqwest::header::ACCEPT,
                if json {
                    "application/json"
                } else {
                    "text/plain"
                },
            )
            .multipart(form.part("file", file))
            .send()
            .await
            .map_err(|_| {
                ProviderError::Transport(
                    "transcription provider connection failed; request was not retried".into(),
                )
            })?;
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
                body: "transcription provider rejected the request".into(),
                retry_after,
            });
        }
        let too_large =
            || ProviderError::Protocol("transcription response exceeded its byte limit".into());
        if response
            .content_length()
            .is_some_and(|size| size > MAX_TRANSCRIPTION_RESPONSE_BYTES as u64)
        {
            return Err(too_large());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                ProviderError::Transport("transcription response interrupted".into())
            })?;
            if chunk.len() > MAX_TRANSCRIPTION_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                return Err(too_large());
            }
            bytes.extend_from_slice(&chunk);
        }
        if json {
            let body: Value = serde_json::from_slice(&bytes).map_err(|_| {
                ProviderError::Protocol("transcription provider returned invalid JSON".into())
            })?;
            if !body.get("text").is_some_and(Value::is_string) {
                return Err(ProviderError::Protocol(
                    "transcription provider response has no text".into(),
                ));
            }
            Ok(TranscriptionBody::Json(body))
        } else {
            String::from_utf8(bytes)
                .map(TranscriptionBody::Text)
                .map_err(|_| {
                    ProviderError::Protocol(
                        "transcription provider returned invalid UTF-8 text".into(),
                    )
                })
        }
    }
}
