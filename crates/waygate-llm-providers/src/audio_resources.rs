//! Bounded, single-attempt standard voice and consent transport.

use super::*;
use waygate_core::audio::AudioResourceRequest;

const MAX_RESOURCE_RESPONSE: usize = 1024 * 1024;

impl ProviderClient {
    pub async fn send_audio_resource(
        &self,
        base_url: &str,
        bearer: &str,
        request: AudioResourceRequest,
    ) -> Result<Value, ProviderError> {
        let operation = request.operation;
        let expected_id = request.id.clone();
        request
            .validate()
            .map_err(|message| ProviderError::Protocol(message.into()))?;
        let http = self.single_attempt_http.as_ref().ok_or_else(|| {
            ProviderError::Protocol("single-attempt audio transport is not configured".into())
        })?;
        let invalid_url = || ProviderError::Protocol("invalid audio resource provider URL".into());
        let mut url = reqwest::Url::parse(base_url).map_err(|_| invalid_url())?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid_url());
        }
        {
            let mut segments = url.path_segments_mut().map_err(|_| invalid_url())?;
            segments
                .pop_if_empty()
                .push("audio")
                .push(request.operation.collection());
            if let Some(id) = &request.id {
                segments.push(id);
            }
        }
        if request.operation.method() == "GET" {
            url.query_pairs_mut().extend_pairs(&request.fields);
        }
        let method = reqwest::Method::from_bytes(request.operation.method().as_bytes())
            .expect("fixed resource method");
        let mut call = http
            .request(method, url)
            .bearer_auth(bearer)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(upload) = request.upload {
            let part = reqwest::multipart::Part::bytes(upload.bytes.to_vec())
                .file_name(upload.file_name)
                .mime_str(&upload.content_type)
                .map_err(|_| ProviderError::Protocol("invalid audio upload content type".into()))?;
            let mut form = reqwest::multipart::Form::new().part(
                request
                    .operation
                    .upload_field()
                    .expect("validated upload operation"),
                part,
            );
            for (key, value) in request.fields {
                form = form.text(key, value);
            }
            call = call.multipart(form);
        } else if request.operation.method() != "GET" && !request.fields.is_empty() {
            call = call.json(&request.fields);
        }
        let response = call.send().await.map_err(|_| {
            ProviderError::Transport(
                "audio resource connection failed; operation was not retried".into(),
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
                body: "audio resource provider rejected the request".into(),
                retry_after,
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESOURCE_RESPONSE as u64)
        {
            return Err(ProviderError::Protocol(
                "audio resource response exceeded its byte limit".into(),
            ));
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                ProviderError::Transport("audio resource response interrupted".into())
            })?;
            if chunk.len() > MAX_RESOURCE_RESPONSE.saturating_sub(bytes.len()) {
                return Err(ProviderError::Protocol(
                    "audio resource response exceeded its byte limit".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&bytes).map_err(|_| {
            ProviderError::Protocol("audio resource provider returned invalid JSON".into())
        })?;
        use waygate_core::audio::AudioResourceOperation::*;
        let object = match operation {
            VoiceCreate => "audio.voice",
            VoiceDelete => "audio.voice.deleted",
            ConsentList => "list",
            _ => "audio.voice_consent",
        };
        let valid_identity = if operation == ConsentList {
            body.get("data").is_some_and(Value::is_array)
                && body.get("has_more").is_some_and(Value::is_boolean)
        } else {
            body.get("id").and_then(Value::as_str).is_some_and(|id| {
                !id.is_empty() && expected_id.as_ref().is_none_or(|expected| expected == id)
            })
        };
        if body.get("object").and_then(Value::as_str) != Some(object)
            || !valid_identity
            || (matches!(operation, VoiceDelete | ConsentDelete)
                && body.get("deleted").and_then(Value::as_bool) != Some(true))
            || (operation == VoiceCreate
                && body.get("type").is_some_and(|kind| kind != "audio_sample"))
        {
            return Err(ProviderError::Protocol("audio resource provider did not confirm the standard operation result; request was not retried".into()));
        }
        Ok(body)
    }
}
