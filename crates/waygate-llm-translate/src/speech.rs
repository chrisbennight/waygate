//! OpenAI Speech request validation and explicitly configured provider capabilities.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::TranslateError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpeechCapabilities {
    pub formats: Vec<SpeechFormat>,
    #[serde(default)]
    pub voices: Vec<String>,
    #[serde(default)]
    pub custom_voices: bool,
    #[serde(default)]
    pub instructions: bool,
    #[serde(default)]
    pub sse_formats: Vec<SpeechFormat>,
    /// Absent means only normal speed is supported.
    pub speed_range: Option<(f64, f64)>,
}

impl SpeechCapabilities {
    pub fn validate(&self) -> Result<(), TranslateError> {
        if self.formats.is_empty()
            || (self.voices.is_empty() && !self.custom_voices)
            || self.voices.iter().any(|v| v.trim().is_empty())
            || self
                .sse_formats
                .iter()
                .any(|format| !self.formats.contains(format))
            || self.speed_range.is_some_and(|(min, max)| {
                !min.is_finite()
                    || !max.is_finite()
                    || min < 0.25
                    || max > 4.0
                    || min > 1.0
                    || max < 1.0
            })
        {
            return Err(TranslateError::Invalid(
                "invalid speech capabilities".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpeechFormat {
    Mp3,
    Opus,
    Aac,
    Flac,
    Wav,
    Pcm,
}

impl SpeechFormat {
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Mp3 => "audio/mpeg",
            Self::Opus => "audio/ogg",
            Self::Aac => "audio/aac",
            Self::Flac => "audio/flac",
            Self::Wav => "audio/wav",
            Self::Pcm => "audio/pcm",
        }
    }
}

/// Content-bearing fields are never included in parser errors or Debug output.
pub struct SpeechRequest {
    body: Map<String, Value>,
    pub format: SpeechFormat,
    pub sse: bool,
}

impl SpeechRequest {
    pub fn parse(
        body: Map<String, Value>,
        caps: &SpeechCapabilities,
    ) -> Result<Self, TranslateError> {
        let invalid = |message: &str| TranslateError::Invalid(message.into());
        for key in body.keys() {
            if !matches!(
                key.as_str(),
                "model"
                    | "input"
                    | "voice"
                    | "instructions"
                    | "response_format"
                    | "speed"
                    | "stream_format"
            ) {
                return Err(invalid("unsupported Speech API request field"));
            }
        }
        for (field, limit, required) in [
            ("model", usize::MAX, true),
            ("input", 4096, true),
            ("instructions", 4096, false),
        ] {
            match body.get(field) {
                Some(Value::String(s))
                    if s.chars().count() <= limit && (!required || !s.trim().is_empty()) => {}
                None if !required => {}
                _ => return Err(invalid("invalid or missing Speech API text field")),
            }
        }
        if body.contains_key("instructions") && !caps.instructions {
            return Err(invalid(
                "speech instructions are not supported by this model",
            ));
        }
        let supported_voice = match body.get("voice") {
            Some(Value::String(name)) => caps.voices.contains(name),
            Some(Value::Object(voice)) if caps.custom_voices && voice.len() == 1 => voice
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.trim().is_empty()),
            _ => false,
        };
        if !supported_voice {
            return Err(invalid("unsupported or invalid speech voice selection"));
        }
        let format = match body.get("response_format") {
            None => SpeechFormat::Mp3,
            Some(value) => serde_json::from_value(value.clone())
                .map_err(|_| invalid("invalid speech response_format"))?,
        };
        if !caps.formats.contains(&format) {
            return Err(invalid(
                "speech response_format is not supported by this model",
            ));
        }
        let sse = match body.get("stream_format").and_then(Value::as_str) {
            None if !body.contains_key("stream_format") => false,
            Some("audio") => false,
            Some("sse") if caps.sse_formats.contains(&format) => true,
            _ => return Err(invalid("unsupported or invalid speech stream_format")),
        };
        let speed = match body.get("speed") {
            None => 1.0,
            Some(value) => value
                .as_f64()
                .ok_or_else(|| invalid("invalid speech speed"))?,
        };
        let (min, max) = caps.speed_range.unwrap_or((1.0, 1.0));
        if !speed.is_finite() || speed < min || speed > max {
            return Err(invalid("speech speed is not supported by this model"));
        }
        Ok(Self { body, format, sse })
    }

    pub fn render(mut self, model: &str) -> Value {
        self.body
            .insert("model".into(), Value::String(model.into()));
        Value::Object(self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn caps() -> SpeechCapabilities {
        serde_json::from_value(
            json!({"formats":["mp3","pcm"],"voices":["narrator"],"custom_voices":true}),
        )
        .unwrap()
    }

    #[test]
    fn custom_voice_identity_and_unicode_input_survive_model_routing() {
        let body = json!({"model":"alias","input":"你".repeat(4096),"voice":{"id":"voice_fixture"},"response_format":"pcm"});
        let request = SpeechRequest::parse(body.as_object().unwrap().clone(), &caps()).unwrap();
        let rendered = request.render("upstream-model");
        assert_eq!(rendered["model"], "upstream-model");
        assert_eq!(rendered["input"], body["input"]);
        assert_eq!(rendered["voice"], body["voice"]);
        let mut too_long = body;
        too_long["input"] = json!("你".repeat(4097));
        assert!(SpeechRequest::parse(too_long.as_object().unwrap().clone(), &caps()).is_err());
    }

    #[test]
    fn unsupported_fields_and_capabilities_fail_without_echoing_content() {
        for extra in [
            json!({"instructions":"private instructions"}),
            json!({"voice":"private unknown name"}),
            json!({"speed":2}),
            json!({"stream_format":"sse"}),
            json!({"response_format":"wav"}),
            json!({"seed":123}),
            json!({"stream":false}),
        ] {
            let mut body = json!({"model":"alias","input":"private speech","voice":"narrator"})
                .as_object()
                .unwrap()
                .clone();
            body.extend(extra.as_object().unwrap().clone());
            let error = SpeechRequest::parse(body, &caps())
                .err()
                .expect("unsupported request passed");
            assert!(!error.to_string().contains("private"));
        }
    }
}
