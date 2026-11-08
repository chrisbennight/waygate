//! OpenAI transcription request validation and explicitly configured provider capabilities.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use waygate_core::audio::{AudioUpload, TranscriptionInput, MAX_TRANSCRIPTION_FILE_BYTES};

use crate::TranslateError;

const MAX_PROMPT_CHARS: usize = 4096;
const MAX_LANGUAGE_CHARS: usize = 16;

/// What a configured transcription provider actually implements. Each option
/// is rejected before provider contact unless the provider supports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptionCapabilities {
    /// Accepted audio files, identified by file extension as in the OpenAI API.
    pub file_types: Vec<TranscriptionFileType>,
    /// Supported `response_format` values; `json`, the API default, is required.
    pub response_formats: Vec<TranscriptionFormat>,
    #[serde(default)]
    pub language: bool,
    #[serde(default)]
    pub prompt: bool,
    #[serde(default)]
    pub temperature: bool,
}

impl TranscriptionCapabilities {
    pub fn validate(&self) -> Result<(), TranslateError> {
        if self.file_types.is_empty() || !self.response_formats.contains(&TranscriptionFormat::Json)
        {
            return Err(TranslateError::Invalid(
                "transcription capabilities require file types and the json response format".into(),
            ));
        }
        Ok(())
    }
}

/// The audio file types the OpenAI transcription API accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TranscriptionFileType {
    Flac,
    M4a,
    Mp3,
    Mp4,
    Mpeg,
    Mpga,
    Oga,
    Ogg,
    Wav,
    Webm,
}

impl TranscriptionFileType {
    /// The type named by a file name's extension, compared case-insensitively.
    pub fn from_file_name(name: &str) -> Option<Self> {
        let (_, extension) = name.rsplit_once('.')?;
        serde_json::from_value(serde_json::Value::String(extension.to_ascii_lowercase())).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptionFormat {
    Json,
    VerboseJson,
    Text,
    Srt,
    Vtt,
}

impl TranscriptionFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::VerboseJson => "verbose_json",
            Self::Text => "text",
            Self::Srt => "srt",
            Self::Vtt => "vtt",
        }
    }

    /// JSON formats return an object with `text`; the others return plain text.
    pub fn is_json(self) -> bool {
        matches!(self, Self::Json | Self::VerboseJson)
    }

    /// The response content type the OpenAI API uses for this format.
    pub fn media_type(self) -> &'static str {
        if self.is_json() {
            "application/json"
        } else {
            "text/plain; charset=utf-8"
        }
    }
}

/// A validated transcription request. Audio and prompt text are never included
/// in parser errors and the type has no Debug output.
pub struct TranscriptionRequest {
    upload: AudioUpload,
    fields: BTreeMap<String, String>,
    pub format: TranscriptionFormat,
}

impl TranscriptionRequest {
    pub fn parse(
        input: TranscriptionInput,
        caps: &TranscriptionCapabilities,
    ) -> Result<Self, TranslateError> {
        let invalid = |message: &str| TranslateError::Invalid(message.into());
        let TranscriptionInput { upload, mut fields } = input;
        for key in fields.keys() {
            if !matches!(
                key.as_str(),
                "model" | "response_format" | "language" | "prompt" | "temperature" | "stream"
            ) {
                return Err(invalid("unsupported transcription request field"));
            }
        }
        if fields
            .get("model")
            .is_none_or(|model| model.trim().is_empty())
        {
            return Err(invalid("transcription requires a model"));
        }
        if upload.bytes.is_empty() || upload.bytes.len() > MAX_TRANSCRIPTION_FILE_BYTES {
            return Err(invalid("transcription file is empty or too large"));
        }
        if !TranscriptionFileType::from_file_name(&upload.file_name)
            .is_some_and(|kind| caps.file_types.contains(&kind))
        {
            return Err(invalid(
                "transcription file type is not supported by this model",
            ));
        }
        // Completed-file transcription only; an explicit non-streaming request
        // is the default behavior and is not forwarded.
        match fields.remove("stream").as_deref() {
            None => {}
            Some(value) if value.eq_ignore_ascii_case("false") => {}
            Some(_) => return Err(invalid("streaming transcription is not supported")),
        }
        let format = match fields.get("response_format") {
            None => TranscriptionFormat::Json,
            Some(value) => serde_json::from_value(serde_json::Value::String(value.clone()))
                .map_err(|_| invalid("invalid transcription response_format"))?,
        };
        if !caps.response_formats.contains(&format) {
            return Err(invalid(
                "transcription response_format is not supported by this model",
            ));
        }
        if let Some(language) = fields.get("language") {
            if !caps.language {
                return Err(invalid(
                    "transcription language is not supported by this model",
                ));
            }
            if language.is_empty()
                || language.len() > MAX_LANGUAGE_CHARS
                || !language
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Err(invalid("invalid transcription language"));
            }
        }
        if let Some(prompt) = fields.get("prompt") {
            if !caps.prompt {
                return Err(invalid(
                    "transcription prompt is not supported by this model",
                ));
            }
            if prompt.chars().count() > MAX_PROMPT_CHARS {
                return Err(invalid("transcription prompt is too long"));
            }
        }
        if let Some(temperature) = fields.get("temperature") {
            if !caps.temperature {
                return Err(invalid(
                    "transcription temperature is not supported by this model",
                ));
            }
            if !temperature
                .parse::<f64>()
                .is_ok_and(|value| (0.0..=1.0).contains(&value))
            {
                return Err(invalid("invalid transcription temperature"));
            }
        }
        fields.insert("response_format".into(), format.as_str().into());
        Ok(Self {
            upload,
            fields,
            format,
        })
    }

    /// The provider form: the configured upstream model replaces the alias.
    pub fn render(mut self, model: &str) -> (AudioUpload, BTreeMap<String, String>) {
        self.fields.insert("model".into(), model.into());
        (self.upload, self.fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    fn caps(extra: serde_json::Value) -> TranscriptionCapabilities {
        let mut value = json!({"file_types":["wav"],"response_formats":["json","text"]});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    fn input(file_name: &str, fields: &[(&str, &str)]) -> TranscriptionInput {
        TranscriptionInput {
            upload: AudioUpload {
                bytes: Arc::from(&b"RIFF fixture"[..]),
                content_type: "audio/wav".into(),
                file_name: file_name.into(),
            },
            fields: [("model", "alias")]
                .iter()
                .chain(fields)
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
        }
    }

    #[test]
    fn capabilities_require_file_types_and_the_default_json_format() {
        assert!(caps(json!({})).validate().is_ok());
        assert!(caps(json!({"file_types":[]})).validate().is_err());
        assert!(caps(json!({"response_formats":["text"]}))
            .validate()
            .is_err());
        assert!(serde_json::from_value::<TranscriptionCapabilities>(
            json!({"file_types":["wav"],"response_formats":["json"],"timestamps":true})
        )
        .is_err());
        assert!(serde_json::from_value::<TranscriptionCapabilities>(
            json!({"file_types":["aiff"],"response_formats":["json"]})
        )
        .is_err());
    }

    #[test]
    fn upstream_model_replaces_the_alias_and_the_default_format_is_explicit() {
        let request = TranscriptionRequest::parse(
            input("Sample.WAV", &[("stream", "false")]),
            &caps(json!({})),
        )
        .unwrap();
        assert_eq!(request.format, TranscriptionFormat::Json);
        let (upload, fields) = request.render("upstream-model");
        assert_eq!(upload.file_name, "Sample.WAV");
        assert_eq!(
            fields,
            BTreeMap::from([
                ("model".to_owned(), "upstream-model".to_owned()),
                ("response_format".to_owned(), "json".to_owned()),
            ])
        );
    }

    #[test]
    fn supported_options_are_forwarded_when_the_provider_declares_them() {
        let caps = caps(
            json!({"response_formats":["json","verbose_json","text","srt","vtt"],
            "language":true,"prompt":true,"temperature":true}),
        );
        for (format, json_body) in [
            ("verbose_json", true),
            ("text", false),
            ("srt", false),
            ("vtt", false),
        ] {
            let request = TranscriptionRequest::parse(
                input(
                    "a.wav",
                    &[
                        ("response_format", format),
                        ("language", "en"),
                        ("prompt", "private vocabulary"),
                        ("temperature", "0.2"),
                    ],
                ),
                &caps,
            )
            .unwrap();
            assert_eq!(request.format.is_json(), json_body);
            assert_eq!(request.format.as_str(), format);
            let (_, fields) = request.render("m");
            assert_eq!(fields["prompt"], "private vocabulary");
            assert_eq!(fields["language"], "en");
            assert_eq!(fields["temperature"], "0.2");
        }
        assert_eq!(
            TranscriptionFormat::Text.media_type(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            TranscriptionFormat::VerboseJson.media_type(),
            "application/json"
        );
    }

    #[test]
    fn unsupported_options_and_inputs_fail_without_echoing_content() {
        let limited = caps(json!({}));
        for (file_name, fields) in [
            ("a.mp3", vec![]),
            ("wav", vec![]),
            ("a.wav", vec![("response_format", "srt")]),
            ("a.wav", vec![("response_format", "private")]),
            ("a.wav", vec![("stream", "true")]),
            ("a.wav", vec![("language", "en")]),
            ("a.wav", vec![("prompt", "private prompt")]),
            ("a.wav", vec![("temperature", "0")]),
            ("a.wav", vec![("timestamp_granularities[]", "word")]),
            ("a.wav", vec![("model", " ")]),
        ] {
            let error = TranscriptionRequest::parse(input(file_name, &fields), &limited)
                .err()
                .expect("unsupported request passed");
            assert!(!error.to_string().contains("private"));
        }
        let open = caps(json!({"language":true,"prompt":true,"temperature":true}));
        let long_prompt = "x".repeat(MAX_PROMPT_CHARS + 1);
        for fields in [
            vec![("language", "en us")],
            vec![("prompt", long_prompt.as_str())],
            vec![("temperature", "1.5")],
            vec![("temperature", "NaN")],
        ] {
            assert!(TranscriptionRequest::parse(input("a.wav", &fields), &open).is_err());
        }
        let mut empty = input("a.wav", &[]);
        empty.upload.bytes = Arc::from(&b""[..]);
        assert!(TranscriptionRequest::parse(empty, &limited).is_err());
    }
}
