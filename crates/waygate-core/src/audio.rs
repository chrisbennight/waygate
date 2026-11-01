//! Shared standard voice-resource requests. Recording bytes stay inside the runtime.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub const MAX_VOICE_RECORDING_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioResourceOperation {
    VoiceCreate,
    VoiceDelete,
    ConsentCreate,
    ConsentList,
    ConsentRetrieve,
    ConsentUpdate,
    ConsentDelete,
}

impl AudioResourceOperation {
    pub fn collection(self) -> &'static str {
        match self {
            Self::VoiceCreate | Self::VoiceDelete => "voices",
            _ => "voice_consents",
        }
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::VoiceDelete | Self::ConsentDelete => "DELETE",
            Self::ConsentList | Self::ConsentRetrieve => "GET",
            _ => "POST",
        }
    }

    pub fn uses_id(self) -> bool {
        matches!(
            self,
            Self::VoiceDelete | Self::ConsentRetrieve | Self::ConsentUpdate | Self::ConsentDelete
        )
    }

    pub fn upload_field(self) -> Option<&'static str> {
        match self {
            Self::VoiceCreate => Some("audio_sample"),
            Self::ConsentCreate => Some("recording"),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::VoiceCreate => "voice_create",
            Self::VoiceDelete => "voice_delete",
            Self::ConsentCreate => "consent_create",
            Self::ConsentList => "consent_list",
            Self::ConsentRetrieve => "consent_retrieve",
            Self::ConsentUpdate => "consent_update",
            Self::ConsentDelete => "consent_delete",
        }
    }
}

#[derive(Clone)]
pub struct AudioUpload {
    pub bytes: Arc<[u8]>,
    pub content_type: String,
    pub file_name: String,
}

#[derive(Clone)]
pub struct AudioResourceRequest {
    pub operation: AudioResourceOperation,
    pub id: Option<String>,
    pub fields: BTreeMap<String, String>,
    pub upload: Option<AudioUpload>,
}

impl std::fmt::Debug for AudioResourceRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioResourceRequest")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

impl AudioResourceRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        use AudioResourceOperation::*;
        if self.operation.uses_id() != self.id.is_some()
            || self.id.as_ref().is_some_and(|id| {
                id.is_empty()
                    || id.len() > 512
                    || matches!(id.as_str(), "." | "..")
                    || id.chars().any(char::is_control)
            })
        {
            return Err("invalid voice resource identifier");
        }
        let allowed: &[&str] = match self.operation {
            VoiceCreate => &["name", "consent", "type"],
            ConsentCreate => &["name", "language"],
            ConsentList => &["limit", "after"],
            ConsentUpdate => &["name"],
            _ => &[],
        };
        if self
            .fields
            .keys()
            .any(|key| !allowed.contains(&key.as_str()))
            || self.fields.values().any(|value| value.len() > 4096)
        {
            return Err("unsupported voice resource field");
        }
        let required: &[&str] = match self.operation {
            VoiceCreate => &["name", "consent"],
            ConsentCreate => &["name", "language"],
            ConsentUpdate => &["name"],
            _ => &[],
        };
        if required.iter().any(|key| {
            self.fields
                .get(*key)
                .is_none_or(|value| value.trim().is_empty())
        }) || self
            .fields
            .get("name")
            .is_some_and(|name| name.chars().count() > 256)
            || self
                .fields
                .get("type")
                .is_some_and(|value| value != "audio_sample")
            || self.fields.get("limit").is_some_and(|value| {
                value
                    .parse::<u32>()
                    .map_or(true, |limit| !(1..=100).contains(&limit))
            })
        {
            return Err(
                "invalid voice resource request fields; only recording-based voices are supported",
            );
        }
        match (&self.upload, self.operation.upload_field()) {
            (Some(upload), Some(_))
                if !upload.bytes.is_empty()
                    && upload.bytes.len() <= MAX_VOICE_RECORDING_BYTES
                    && (upload.content_type.starts_with("audio/")
                        || upload.content_type == "application/octet-stream")
                    && !upload.content_type.contains(['\r', '\n'])
                    && upload.content_type.len() <= 256
                    && !upload.file_name.is_empty()
                    && upload.file_name.len() <= 256
                    && !matches!(upload.file_name.as_str(), "." | "..")
                    && !upload.file_name.chars().any(char::is_control)
                    && !upload.file_name.contains(['/', '\\']) => {}
            (None, None) => {}
            _ => return Err("invalid or missing audio resource recording"),
        }
        Ok(())
    }
}
