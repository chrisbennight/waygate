//! Bounded recovery facts for an owned gateway file delivery.
//!
//! Callers may record facts only at the gateway's file-input boundary, or
//! after inspection of a result from a call that actually prepared file inputs.
//! This is not a classifier for arbitrary upstream JSON-RPC error data.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

macro_rules! vocabulary {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant),+
        }
        impl $name {
            pub fn parse(value: &str) -> Option<Self> {
                match value { $($text => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

vocabulary!(FileRecoveryCategory {
    UnsupportedCapability => "unsupported_capability",
    AuthenticationRequired => "authentication_required",
    InvalidFileInput => "invalid_file_input",
    InvalidToolContract => "invalid_tool_contract",
    FileUnavailable => "file_unavailable",
    NotEnabled => "not_enabled",
    QuotaExhausted => "quota_exhausted",
    TemporarilyUnavailable => "temporarily_unavailable",
    PolicyViolation => "policy_violation",
    IntegrityMismatch => "integrity_mismatch",
    TransferFailed => "transfer_failed",
    CompletionUnknown => "completion_unknown",
});
vocabulary!(FileRecoveryReason {
    UploadCapacityExhausted => "upload_capacity_exhausted",
    ReceiptCapacity => "receipt_capacity",
    FileTooLarge => "file_too_large",
    UnsupportedType => "unsupported_type",
    StorageBudgetExceeded => "storage_budget_exceeded",
    IntegrityMismatch => "integrity_mismatch",
    UploadTimeout => "upload_timeout",
    UploadCancelled => "upload_cancelled",
    TransferFailed => "transfer_failed",
    UploadNotFound => "upload_not_found",
    InvalidFileInput => "invalid_file_input",
    CompletionUnknown => "completion_unknown",
    DeliveryRecoveryUnavailable => "delivery_recovery_unavailable",
});
vocabulary!(FileRecoveryStage {
    AuthorizeUpload => "authorize_upload",
    Receive => "receive",
    Ingest => "ingest",
    Cancel => "cancel",
    Status => "status",
});
vocabulary!(FileRecoveryCleanupState {
    Cancelled => "cancelled",
    Cancelling => "cancelling",
    Unconfirmed => "unconfirmed",
});

/// Only enums, booleans, bounded integers, and gateway-owned UUIDs cross this
/// boundary. Unknown facts are absent; absence never means no publication.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<FileRecoveryCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<FileRecoveryReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<FileRecoveryStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_attempted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_pending: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_state: Option<FileRecoveryCleanupState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_ids: Vec<Uuid>,
}

impl FileRecovery {
    /// IDs must come from the current invocation's owner-scoped processor,
    /// never from error data or an upstream-authored metadata field. Additional
    /// delivery handles remain discoverable through delivery_status(original URI).
    pub fn from_file_failure(data: Option<&Value>, owned_ids: &[String]) -> Self {
        const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
        const MAX_DELIVERY_IDS: usize = 20;
        let value = |key: &str| data.and_then(|data| data.get(key));
        let number = |key: &str| {
            value(key)
                .and_then(Value::as_u64)
                .filter(|number| *number <= MAX_SAFE_INTEGER)
        };
        Self {
            category: value("error")
                .or_else(|| value("code"))
                .and_then(Value::as_str)
                .and_then(FileRecoveryCategory::parse),
            reason: value("reason")
                .and_then(Value::as_str)
                .and_then(FileRecoveryReason::parse),
            stage: value("stage")
                .and_then(Value::as_str)
                .and_then(FileRecoveryStage::parse),
            publication_attempted: value("publication_attempted").and_then(Value::as_bool),
            retryable: value("retryable").and_then(Value::as_bool),
            retry_after_seconds: number("retry_after_seconds"),
            max_bytes: number("max_bytes"),
            capacity: number("capacity"),
            cleanup_pending: value("cleanup_pending").and_then(Value::as_bool),
            cleanup_state: value("cleanup_state")
                .and_then(Value::as_str)
                .and_then(FileRecoveryCleanupState::parse),
            delivery_ids: owned_ids
                .iter()
                .filter_map(|id| Uuid::parse_str(id).ok())
                .take(MAX_DELIVERY_IDS)
                .collect(),
        }
    }
}

/// One ephemeral observation per invocation. The handle is skipped during
/// request serialization, so upstreams and serialized requests cannot supply it.
#[derive(Clone, Default)]
pub struct FileRecoveryHandle(Arc<Mutex<Option<FileRecovery>>>);

impl std::fmt::Debug for FileRecoveryHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileRecoveryHandle(..)")
    }
}

impl FileRecoveryHandle {
    pub fn record(&self, mut recovery: FileRecovery) {
        // Keep the complete optional detail below 2 KiB, even if a trusted
        // caller constructs the public DTO without using its projection.
        recovery.delivery_ids.truncate(20);
        for hint in [
            &mut recovery.retry_after_seconds,
            &mut recovery.max_bytes,
            &mut recovery.capacity,
        ] {
            if hint.is_some_and(|value| value > 9_007_199_254_740_991) {
                *hint = None;
            }
        }
        if recovery != FileRecovery::default()
            && serde_json::to_vec(&recovery).is_ok_and(|bytes| bytes.len() <= 2048)
        {
            *self.0.lock().expect("file recovery observation poisoned") = Some(recovery);
        }
    }

    pub fn take(&self) -> Option<FileRecovery> {
        self.0
            .lock()
            .expect("file recovery observation poisoned")
            .take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recovery_rejects_unknown_values_and_bounds_numbers_ids_and_bytes() {
        let owned = Uuid::new_v4().to_string();
        let ids = vec![owned; 100];
        let recovery = FileRecovery::from_file_failure(
            Some(&json!({
                "error":"future_category", "reason":"private://token", "stage":"future_stage",
                "publication_attempted":"false", "retryable":1,
                "retry_after_seconds":-1, "max_bytes":u64::MAX, "capacity":9007199254740991_u64,
                "cleanup_state":"future_cleanup", "cleanup_pending":true,
                "delivery_ids":[Uuid::new_v4()], "token":"unreleased credential", "message":"private diagnostic"
            })),
            &ids,
        );
        let observation = FileRecoveryHandle::default();
        observation.record(recovery);
        let recovery = observation.take().unwrap();
        assert!(
            observation.take().is_none(),
            "observations are consumed once"
        );
        assert_eq!(recovery.delivery_ids.len(), 20);
        let value = serde_json::to_value(&recovery).unwrap();
        for absent in [
            "category",
            "reason",
            "stage",
            "publication_attempted",
            "retryable",
            "retry_after_seconds",
            "max_bytes",
            "cleanup_state",
            "token",
            "message",
        ] {
            assert!(
                value.get(absent).is_none(),
                "unknown or malformed fact released"
            );
        }
        assert_eq!(value["capacity"], 9007199254740991_u64);
        assert_eq!(value["cleanup_pending"], true);
        assert!(serde_json::to_vec(&recovery).unwrap().len() <= 2048);
        assert_eq!(
            FileRecovery::from_file_failure(None, &["invalid UUID".into()]),
            FileRecovery::default()
        );
    }

    #[test]
    fn serialized_requests_cannot_create_or_reuse_observation_handles() {
        let handle = FileRecoveryHandle::default();
        let mut request = crate::InvocationRequest::new("printable", "ingest");
        request.file_recovery = Some(handle);
        let mut value = serde_json::to_value(&request).unwrap();
        assert!(value.get("file_recovery").is_none());
        value["file_recovery"] =
            json!({"category":"invalid_file_input", "publication_attempted":false});
        let request: crate::InvocationRequest = serde_json::from_value(value).unwrap();
        assert!(request.file_recovery.is_none());
    }
}
