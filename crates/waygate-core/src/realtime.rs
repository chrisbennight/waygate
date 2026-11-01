//! Realtime capability declarations and runtime-only session requests.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audio::AudioResourceOperation;

pub const MAX_REALTIME_EVENT_BYTES: usize = 1024 * 1024;
pub const MAX_REALTIME_SDP_BYTES: usize = 64 * 1024;

fn default_session_seconds() -> u64 {
    600
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeCapabilities {
    #[serde(default)]
    pub websocket: bool,
    #[serde(default)]
    pub webrtc: bool,
    #[serde(default = "default_session_seconds")]
    pub max_session_seconds: u64,
    #[serde(default)]
    pub voices: Vec<String>,
    #[serde(default)]
    pub custom_voices: bool,
    #[serde(default)]
    pub instructions: bool,
    #[serde(default)]
    pub audio_input: bool,
    #[serde(default)]
    pub tools: bool,
    #[serde(default)]
    pub resources: Vec<AudioResourceOperation>,
    /// Explicitly trusted measured usage; disabled for provider placeholders.
    #[serde(default)]
    pub measured_usage: bool,
}

impl RealtimeCapabilities {
    pub fn validate(&self) -> Result<(), &'static str> {
        if (!self.websocket && !self.webrtc)
            || !(1..=3600).contains(&self.max_session_seconds)
            || (self.voices.is_empty() && !self.custom_voices)
            || self.voices.iter().any(|voice| voice.trim().is_empty())
        {
            return Err("invalid Realtime capabilities");
        }
        Ok(())
    }

    pub fn validate_session(&self, session: &Value) -> Result<(), &'static str> {
        if !session.is_object() || session.get("type").and_then(Value::as_str) != Some("realtime") {
            return Err("only standard realtime sessions are supported");
        }
        self.validate_options(session)
    }

    fn validate_options(&self, session: &Value) -> Result<(), &'static str> {
        if !session.is_object() {
            return Err("Realtime options must be an object");
        }
        if session.get("instructions").is_some() && !self.instructions {
            return Err("Realtime instructions are not supported by this provider");
        }
        if !self.tools
            && (session
                .get("tools")
                .is_some_and(|value| !matches!(value,Value::Array(items) if items.is_empty()))
                || session
                    .get("tool_choice")
                    .is_some_and(|value| value != "none" && value != "auto"))
        {
            return Err("Realtime tools are not supported by this provider");
        }
        if !self.audio_input
            && session
                .pointer("/audio/input")
                .is_some_and(|value| !value.is_null())
        {
            return Err("Realtime audio input is not supported by this provider");
        }
        if let Some(voice) = session.pointer("/audio/output/voice") {
            let valid = match voice {
                Value::String(name) => self.voices.contains(name),
                Value::Object(value) if self.custom_voices && value.len() == 1 => value
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| !id.trim().is_empty()),
                _ => false,
            };
            if !valid {
                return Err("unsupported Realtime voice selection");
            }
        }
        Ok(())
    }

    pub fn validate_client_event(
        &self,
        event: &Value,
        model_alias: &str,
        upstream_model: &str,
    ) -> Result<(), &'static str> {
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or("Realtime events require a type")?;
        if !matches!(
            kind,
            "session.update"
                | "response.create"
                | "response.cancel"
                | "conversation.item.create"
                | "conversation.item.delete"
                | "conversation.item.retrieve"
                | "conversation.item.truncate"
                | "input_audio_buffer.append"
                | "input_audio_buffer.commit"
                | "input_audio_buffer.clear"
                | "output_audio_buffer.clear"
        ) {
            return Err("unsupported standard Realtime event type");
        }
        if kind.starts_with("input_audio_buffer.") && !self.audio_input {
            return Err("Realtime audio input is not supported by this provider");
        }
        if kind == "session.update" {
            let session = event
                .get("session")
                .ok_or("session.update requires session configuration")?;
            self.validate_session(session)?;
            if session
                .get("model")
                .is_some_and(|model| model != model_alias && model != upstream_model)
            {
                return Err("the model cannot change during a Realtime session");
            }
        }
        if kind == "response.create" {
            if let Some(response) = event.get("response") {
                self.validate_options(response)?;
                if let Some(items) = response.get("input").and_then(Value::as_array) {
                    for item in items {
                        self.validate_item(item)?;
                    }
                }
            }
        }
        if kind == "conversation.item.create" {
            self.validate_item(event.get("item").ok_or("conversation item required")?)?;
        }
        Ok(())
    }

    fn validate_item(&self, item: &Value) -> Result<(), &'static str> {
        if !self.tools
            && item
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "function_call"
                            | "function_call_output"
                            | "mcp_call"
                            | "mcp_approval_response"
                    )
                })
        {
            return Err("Realtime tools are not supported by this provider");
        }
        if !self.audio_input
            && item
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(|parts| {
                    parts.iter().any(|part| {
                        part.get("type")
                            .and_then(Value::as_str)
                            .is_some_and(|kind| matches!(kind, "input_audio" | "audio"))
                    })
                })
        {
            return Err("Realtime audio input is not supported by this provider");
        }
        Ok(())
    }
}

#[derive(Clone)]
pub enum RealtimeRequest {
    WebSocket,
    WebRtc { sdp: String, session: Value },
    Hangup { call_id: String },
}

impl std::fmt::Debug for RealtimeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WebSocket => "RealtimeRequest::WebSocket",
            Self::WebRtc { .. } => "RealtimeRequest::WebRtc(..)",
            Self::Hangup { .. } => "RealtimeRequest::Hangup(..)",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_only_capabilities_refuse_native_events_and_unsupported_options() {
        let caps: RealtimeCapabilities =
            serde_json::from_value(json!({"websocket":true,"voices":["narrator"]})).unwrap();
        for event in [
            json!({"type":"text.append","text":"text"}),
            json!({"type":"text.flush"}),
            json!({"type":"input_audio_buffer.append","audio":"AAAA"}),
            json!({"type":"response.create","response":{"instructions":"direction"}}),
            json!({"type":"response.create","response":{"tools":[{"type":"function","name":"tool"}]}}),
            json!({"type":"response.create","response":{"input":[{"type":"message","content":[{"type":"input_audio","audio":"AAAA"}]}]}}),
            json!({"type":"session.update","session":{"type":"realtime","model":"other"}}),
            json!({"type":"session.update","session":{"type":"realtime","audio":{"output":{"voice":"other"}}}}),
        ] {
            assert!(
                caps.validate_client_event(&event, "alias", "upstream")
                    .is_err(),
                "{event}"
            );
        }
        for event in [
            json!({"type":"response.create"}),
            json!({"type":"conversation.item.create","item":{"type":"message","role":"user","content":[{"type":"input_text","text":"complete text"}]}}),
            json!({"type":"response.cancel"}),
            json!({"type":"conversation.item.truncate","item_id":"item","content_index":0,"audio_end_ms":1}),
        ] {
            assert!(caps
                .validate_client_event(&event, "alias", "upstream")
                .is_ok());
        }
    }
}
