//! Validation and normalization for MCP tool behavior claims.
//!
//! Tool annotations are advisory server claims. This module makes those claims
//! deterministic and bounded so the gateway can hash and quarantine them; it
//! does not turn them into authorization or grant the upstream any authority
//! over catalog-owned risk.

use rmcp::model::{Tool, ToolAnnotations};
use serde_json::{Map, Value};
use thiserror::Error;

/// Experimental MCP extension identifier for tool action metadata.
pub(crate) const ACTION_METADATA_KEY: &str = "io.modelcontextprotocol/action-metadata";

const MAX_SECURITY_METADATA_BYTES: usize = 16 * 1024;
const MAX_CLASSIFIER_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SecurityMetadata {
    pub(crate) annotations: Value,
    pub(crate) action_metadata: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BehaviorClaims {
    pub side_effects: bool,
    pub input_sensitive: bool,
    pub output_sensitive: bool,
    pub requires_review: bool,
}

impl BehaviorClaims {
    /// Whether a tool call must pause for a one-time approval grant under the
    /// manifest's explicit approval authority. Both the pool resolver and the
    /// Code Mode approval-eligibility check derive the requirement here so
    /// they cannot disagree.
    pub fn requires_approval(&self, approval_mode: crate::ApprovalMode) -> bool {
        approval_mode.uses_per_call_requirements() && self.requires_review
    }

    /// Legacy `pii` fact projection: "protected input OR output", retained
    /// for the existing Cedar schema and audit columns.
    pub fn protected_data(&self) -> bool {
        self.input_sensitive || self.output_sensitive
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SecurityMetadataError {
    #[error("standard MCP annotations are missing")]
    MissingAnnotations,
    #[error("standard MCP annotation `{0}` must be an explicit boolean")]
    MissingHint(&'static str),
    #[error("action metadata is missing")]
    MissingActionMetadata,
    #[error("action metadata conflicts between annotations and tool metadata")]
    ConflictingActionMetadata,
    #[error("action metadata must be a bounded JSON object")]
    MalformedActionMetadata,
    #[error("action metadata field `{0}` must be a bounded non-empty string")]
    MalformedClassifier(&'static str),
    #[error("action metadata field `requiresReview` must be a boolean")]
    MalformedReview,
    #[error("security metadata exceeds the gateway size bound")]
    TooLarge,
}

/// Normalize one live rmcp tool.
///
/// The pinned rmcp release exposes extension-neutral `_meta` but its typed
/// `ToolAnnotations` cannot retain extension keys. During that compatibility
/// window, action metadata is accepted from `Tool._meta`. The value-level
/// normalizer also recognizes the extension's canonical annotation location so
/// adopting a future rmcp representation does not change the policy contract.
pub(crate) fn normalize_tool(tool: &Tool) -> Result<SecurityMetadata, SecurityMetadataError> {
    let annotations = tool.annotations.as_ref().map(standard_annotations_value);
    let meta = tool.meta.as_ref().map(|meta| Value::Object(meta.0.clone()));
    normalize_values(annotations.as_ref(), meta.as_ref())
}

/// Capture all security metadata that the current rmcp representation can
/// preserve, including malformed values. Drift hashing must change when a
/// claim changes even when annotation-native admission rejects that claim.
pub(crate) fn hash_components(tool: &Tool) -> (Option<Value>, Option<Value>) {
    let annotations = tool.annotations.as_ref().map(standard_annotations_value);
    let action_metadata = annotations
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get(ACTION_METADATA_KEY))
        .cloned()
        .or_else(|| {
            tool.meta
                .as_ref()
                .and_then(|meta| meta.0.get(ACTION_METADATA_KEY))
                .cloned()
        });
    (annotations, action_metadata)
}

pub(crate) fn behavior_hash(tool: &Tool) -> String {
    let (annotations, _action_metadata) = hash_components(tool);
    // Hash the COMPLETE namespaced `_meta` object, not just the
    // action-metadata namespace inside it: a claim under any sibling
    // namespace is still an upstream behavior/sensitivity assertion, and a
    // change to it must produce a new reviewed hash rather than drifting
    // silently past approval.
    let namespaced_metadata = tool.meta.as_ref().map(|meta| Value::Object(meta.0.clone()));
    waygate_catalog::behavior_hash(
        tool.name.as_ref(),
        tool.description.as_deref(),
        &tool.input_schema,
        tool.output_schema.as_deref(),
        annotations.as_ref(),
        namespaced_metadata.as_ref(),
    )
}

pub fn behavior_claims(
    annotations: &Value,
    action_metadata: &Value,
) -> Result<BehaviorClaims, SecurityMetadataError> {
    let normalized = normalize_values(
        Some(annotations),
        Some(&Value::Object(Map::from_iter([(
            ACTION_METADATA_KEY.to_owned(),
            action_metadata.clone(),
        )]))),
    )?;
    let annotations = normalized
        .annotations
        .as_object()
        .ok_or(SecurityMetadataError::MissingAnnotations)?;
    let action = normalized
        .action_metadata
        .as_object()
        .ok_or(SecurityMetadataError::MalformedActionMetadata)?;
    let input = object_field(action, "inputMetadata")?;
    let returned = object_field(action, "returnMetadata")?;
    Ok(BehaviorClaims {
        side_effects: !boolean_hint(annotations, "readOnlyHint")?,
        input_sensitive: classifier_requires_protection(input, "sensitivity")?,
        output_sensitive: classifier_requires_protection(returned, "sensitivity")?,
        requires_review: action
            .get("requiresReview")
            .and_then(Value::as_bool)
            .ok_or(SecurityMetadataError::MalformedReview)?,
    })
}

pub(crate) fn normalize_values(
    annotations: Option<&Value>,
    meta: Option<&Value>,
) -> Result<SecurityMetadata, SecurityMetadataError> {
    let annotations = annotations
        .and_then(Value::as_object)
        .ok_or(SecurityMetadataError::MissingAnnotations)?;
    for hint in [
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    ] {
        if !annotations.get(hint).is_some_and(Value::is_boolean) {
            return Err(SecurityMetadataError::MissingHint(hint));
        }
    }

    let annotation_action = annotations.get(ACTION_METADATA_KEY);
    let meta_action = meta
        .and_then(Value::as_object)
        .and_then(|meta| meta.get(ACTION_METADATA_KEY));
    if annotation_action.is_some() && meta_action.is_some() && annotation_action != meta_action {
        return Err(SecurityMetadataError::ConflictingActionMetadata);
    }
    let action_metadata = annotation_action
        .or(meta_action)
        .ok_or(SecurityMetadataError::MissingActionMetadata)?;
    validate_action_metadata(action_metadata)?;

    let normalized_annotations = Value::Object(
        [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ]
        .into_iter()
        .filter_map(|key| {
            annotations
                .get(key)
                .cloned()
                .map(|value| (key.to_owned(), value))
        })
        .collect(),
    );
    let normalized_action_metadata = action_metadata.clone();
    let total_bytes = serialized_len(&normalized_annotations)?
        .checked_add(serialized_len(&normalized_action_metadata)?)
        .ok_or(SecurityMetadataError::TooLarge)?;
    if total_bytes > MAX_SECURITY_METADATA_BYTES {
        return Err(SecurityMetadataError::TooLarge);
    }

    Ok(SecurityMetadata {
        annotations: normalized_annotations,
        action_metadata: normalized_action_metadata,
    })
}

fn standard_annotations_value(annotations: &ToolAnnotations) -> Value {
    let mut value = Map::new();
    for (name, hint) in [
        ("readOnlyHint", annotations.read_only_hint),
        ("destructiveHint", annotations.destructive_hint),
        ("idempotentHint", annotations.idempotent_hint),
        ("openWorldHint", annotations.open_world_hint),
    ] {
        if let Some(hint) = hint {
            value.insert(name.to_owned(), Value::Bool(hint));
        }
    }
    Value::Object(value)
}

fn validate_action_metadata(value: &Value) -> Result<(), SecurityMetadataError> {
    let action = value
        .as_object()
        .ok_or(SecurityMetadataError::MalformedActionMetadata)?;
    let input = object_field(action, "inputMetadata")?;
    classifier(input, "destination", "inputMetadata.destination")?;
    classifier(input, "sensitivity", "inputMetadata.sensitivity")?;
    let returned = object_field(action, "returnMetadata")?;
    classifier(returned, "source", "returnMetadata.source")?;
    classifier(returned, "sensitivity", "returnMetadata.sensitivity")?;
    classifier(action, "outcome", "outcome")?;
    if !action.get("requiresReview").is_some_and(Value::is_boolean) {
        return Err(SecurityMetadataError::MalformedReview);
    }
    Ok(())
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a Map<String, Value>, SecurityMetadataError> {
    object
        .get(key)
        .and_then(Value::as_object)
        .ok_or(SecurityMetadataError::MalformedClassifier(key))
}

fn classifier(
    object: &Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<(), SecurityMetadataError> {
    let valid = object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty() && value.len() <= MAX_CLASSIFIER_LENGTH);
    if valid {
        Ok(())
    } else {
        Err(SecurityMetadataError::MalformedClassifier(path))
    }
}

fn boolean_hint(
    annotations: &Map<String, Value>,
    key: &'static str,
) -> Result<bool, SecurityMetadataError> {
    annotations
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(SecurityMetadataError::MissingHint(key))
}

fn classifier_requires_protection(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<bool, SecurityMetadataError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(SecurityMetadataError::MalformedClassifier(key))?;
    Ok(!matches!(value, "none" | "public" | "operational"))
}

fn serialized_len(value: &Value) -> Result<usize, SecurityMetadataError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| SecurityMetadataError::TooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn annotations() -> Value {
        json!({
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        })
    }

    fn action() -> Value {
        json!({
            "inputMetadata": {
                "destination": "internal",
                "sensitivity": "sensitive"
            },
            "returnMetadata": {
                "source": "first-party",
                "sensitivity": "sensitive"
            },
            "outcome": "benign",
            "requiresReview": false
        })
    }

    #[test]
    fn accepts_transition_meta_and_future_annotation_location() {
        let from_meta = normalize_values(
            Some(&annotations()),
            Some(&json!({ACTION_METADATA_KEY: action()})),
        )
        .expect("transition _meta is supported");

        let mut canonical = annotations().as_object().unwrap().clone();
        canonical.insert(ACTION_METADATA_KEY.to_owned(), action());
        let from_annotations = normalize_values(Some(&Value::Object(canonical.clone())), None)
            .expect("canonical annotation location is supported");

        assert_eq!(from_meta.action_metadata, from_annotations.action_metadata);

        assert_eq!(
            normalize_values(
                Some(&Value::Object(canonical)),
                Some(&json!({ACTION_METADATA_KEY: {"outcome": "different"}})),
            )
            .unwrap_err(),
            SecurityMetadataError::ConflictingActionMetadata
        );
    }

    #[test]
    fn fails_closed_on_missing_or_malformed_claims() {
        assert_eq!(
            normalize_values(None, None).unwrap_err(),
            SecurityMetadataError::MissingAnnotations
        );
        assert!(matches!(
            normalize_values(Some(&annotations()), None),
            Err(SecurityMetadataError::MissingActionMetadata)
        ));
        assert!(matches!(
            normalize_values(
                Some(&annotations()),
                Some(&json!({ACTION_METADATA_KEY: {"outcome": "benign"}}))
            ),
            Err(SecurityMetadataError::MalformedClassifier(_))
        ));
    }

    #[test]
    fn claims_derive_behavior_and_protect_open_sensitivity_values() {
        let claims = behavior_claims(&annotations(), &action()).expect("claims");
        assert!(!claims.side_effects);
        assert!(claims.input_sensitive);
        assert!(claims.output_sensitive);
        assert!(!claims.requires_review);

        let mut future = action();
        future["inputMetadata"]["sensitivity"] = json!("future-classifier");
        assert!(
            behavior_claims(&annotations(), &future)
                .expect("open classifiers remain accepted")
                .input_sensitive
        );
    }

    #[test]
    fn approval_mode_is_explicit_and_defaults_to_per_call() {
        let base = BehaviorClaims {
            side_effects: true,
            input_sensitive: false,
            output_sensitive: false,
            requires_review: false,
        };
        // Policy-only mode suppresses annotation-driven approval regardless
        // of the tool's other behavior claims.
        for claims in [
            base,
            BehaviorClaims {
                output_sensitive: true,
                ..base
            },
            BehaviorClaims {
                input_sensitive: true,
                ..base
            },
            BehaviorClaims {
                requires_review: true,
                ..base
            },
        ] {
            assert!(!claims.requires_approval(crate::ApprovalMode::PolicyOnly));
        }
        // The default per-call mode requires approval exactly when the tool
        // claims review; sensitivity alone does not gate it.
        assert!(!BehaviorClaims {
            output_sensitive: true,
            ..base
        }
        .requires_approval(crate::ApprovalMode::PerCall));
        assert!(BehaviorClaims {
            side_effects: false,
            requires_review: true,
            ..base
        }
        .requires_approval(crate::ApprovalMode::PerCall));
    }
}
