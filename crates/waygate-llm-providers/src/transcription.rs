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

/// Whether a provider content type matches the requested `response_format`.
fn content_type_matches(format: &str, media_type: &str) -> bool {
    match format {
        "json" | "verbose_json" => {
            media_type == "application/json" || media_type.ends_with("+json")
        }
        "srt" => media_type.starts_with("text/") || media_type == "application/x-subrip",
        _ => media_type.starts_with("text/"),
    }
}

/// Whether a text body has the shape of the requested format. A WebVTT file
/// starts with its signature; an SRT file is empty or starts with a cue number.
fn text_matches(format: &str, text: &str) -> bool {
    let text = text.trim_start_matches('\u{feff}');
    match format {
        "vtt" => text.starts_with("WEBVTT"),
        "srt" => {
            let text = text.trim_start();
            text.is_empty() || text.starts_with(|c: char| c.is_ascii_digit())
        }
        _ => true,
    }
}

impl ProviderClient {
    /// `format` is the validated `response_format` already present in `fields`.
    pub async fn send_transcription(
        &self,
        base_url: &str,
        path: &str,
        bearer: &str,
        upload: AudioUpload,
        fields: BTreeMap<String, String>,
        format: &str,
    ) -> Result<TranscriptionBody, ProviderError> {
        let json = matches!(format, "json" | "verbose_json");
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
        let wrong_format = || {
            ProviderError::Protocol(
                "transcription provider response does not match the requested format".into(),
            )
        };
        let media_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !content_type_matches(format, &media_type) {
            return Err(wrong_format());
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
            let body: Value = serde_json::from_slice(&bytes).map_err(|_| wrong_format())?;
            if !body.get("text").is_some_and(Value::is_string) {
                return Err(wrong_format());
            }
            Ok(TranscriptionBody::Json(body))
        } else {
            let text = String::from_utf8(bytes).map_err(|_| wrong_format())?;
            if !text_matches(format, &text) {
                return Err(wrong_format());
            }
            Ok(TranscriptionBody::Text(text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_content_type_and_body_must_match_the_requested_format() {
        assert!(content_type_matches("json", "application/json"));
        assert!(content_type_matches(
            "verbose_json",
            "application/vnd.fixture+json"
        ));
        assert!(!content_type_matches("json", "text/plain"));
        assert!(!content_type_matches("text", "application/json"));
        assert!(!content_type_matches("text", ""));
        assert!(content_type_matches("vtt", "text/vtt"));
        assert!(content_type_matches("srt", "application/x-subrip"));
        assert!(text_matches(
            "vtt",
            "\u{feff}WEBVTT\n\n00:00.000 --> 00:01.000\nhello"
        ));
        assert!(!text_matches("vtt", "hello"));
        assert!(text_matches(
            "srt",
            "1\n00:00:00,000 --> 00:00:01,000\nhello"
        ));
        assert!(text_matches("srt", ""));
        assert!(!text_matches("srt", "hello"));
        assert!(text_matches("text", "hello"));
    }
}
