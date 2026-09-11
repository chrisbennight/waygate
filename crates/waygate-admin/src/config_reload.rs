//! Shared policy/manifest reload-doorbell operation.
//!
//! The direct `gateway-control.reload_config` tool and the governed
//! `config.reload` change executor both call this core. The Postgres doorbells
//! fan out to every listening replica; the periodic reload poll remains the
//! backstop when a notification is missed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::state::AdminState;

/// Which configuration plane to ask the fleet to reconcile.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConfigReloadTarget {
    /// Reload Cedar policy files.
    Policy,
    /// Reload upstream manifest files.
    Manifest,
    /// Reload both policy and manifest files.
    #[default]
    Both,
}

impl ConfigReloadTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Manifest => "manifest",
            Self::Both => "both",
        }
    }

    fn includes_policy(self) -> bool {
        matches!(self, Self::Policy | Self::Both)
    }

    fn includes_manifest(self) -> bool {
        matches!(self, Self::Manifest | Self::Both)
    }
}

/// Captured params for a direct or governed config reload.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct ConfigReloadParams {
    /// Configuration plane to reload. Defaults to `both`.
    #[serde(default)]
    pub target: ConfigReloadTarget,
}

/// Which fleet-wide reload doorbells were actually rung.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigReloadResponse {
    /// Requested target: `policy`, `manifest`, or `both`.
    pub target: String,
    /// Doorbells fired. A configured target with no published pointer is a
    /// no-op and is absent from this list.
    pub triggered: Vec<String>,
    /// `true` when at least one Postgres doorbell fired. Each fired doorbell
    /// notifies every listening replica, with the periodic poll as backstop.
    pub fleet_wide: bool,
}

/// Validate the requested planes and ring their fleet-wide doorbells.
///
/// Pointer reads happen before either notification so an unreadable requested
/// plane cannot prevent validation of the other only after a side effect has
/// already begun. Notifications themselves are idempotent operational nudges.
pub async fn reload_config_core(
    state: &AdminState,
    tenant: &str,
    params: &ConfigReloadParams,
) -> ApiResult<ConfigReloadResponse> {
    let policy_pointer = if params.target.includes_policy() {
        match state.policy.policy_store.get() {
            Some(store) => store
                .read_pointer(tenant)
                .await
                .map_err(|e| ApiError::Internal(format!("policy read_pointer: {e}")))?
                .map(|pointer| (store, pointer.current_hash)),
            None => None,
        }
    } else {
        None
    };
    let manifest_pointer = if params.target.includes_manifest() {
        match state.servers.manifest_store.get() {
            Some(store) => store
                .read_pointer(tenant)
                .await
                .map_err(|e| ApiError::Internal(format!("manifest read_pointer: {e}")))?
                .map(|pointer| (store, pointer.current_hash)),
            None => None,
        }
    } else {
        None
    };

    let mut triggered = Vec::new();
    if let Some((store, hash)) = policy_pointer {
        store
            .notify_reload(&hash)
            .await
            .map_err(|e| ApiError::Internal(format!("policy notify_reload: {e}")))?;
        triggered.push("policy".to_owned());
    }
    if let Some((store, hash)) = manifest_pointer {
        store
            .notify_reload(&hash)
            .await
            .map_err(|e| ApiError::Internal(format!("manifest notify_reload: {e}")))?;
        triggered.push("manifest".to_owned());
    }

    let fleet_wide = !triggered.is_empty();
    Ok(ConfigReloadResponse {
        target: params.target.as_str().to_owned(),
        triggered,
        fleet_wide,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use waygate_upstream::UpstreamPool;

    use super::*;

    #[test]
    fn params_default_to_both_and_reject_unknown_targets() {
        let params: ConfigReloadParams = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(params.target.as_str(), "both");

        let manifest: ConfigReloadParams =
            serde_json::from_value(serde_json::json!({"target": "manifest"})).unwrap();
        assert_eq!(manifest.target.as_str(), "manifest");

        assert!(
            serde_json::from_value::<ConfigReloadParams>(serde_json::json!({
                "target": "unknown"
            }))
            .is_err()
        );
    }

    #[test]
    fn targets_select_exactly_the_requested_reload_planes() {
        assert!(ConfigReloadTarget::Policy.includes_policy());
        assert!(!ConfigReloadTarget::Policy.includes_manifest());
        assert!(!ConfigReloadTarget::Manifest.includes_policy());
        assert!(ConfigReloadTarget::Manifest.includes_manifest());
        assert!(ConfigReloadTarget::Both.includes_policy());
        assert!(ConfigReloadTarget::Both.includes_manifest());
    }

    #[tokio::test]
    async fn reload_without_published_pointers_is_an_explicit_no_op() {
        let state = AdminState::new(
            Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new())),
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".to_owned(),
        );

        let response = reload_config_core(&state, "default", &ConfigReloadParams::default())
            .await
            .expect("missing stores are a no-op");

        assert_eq!(response.target, "both");
        assert!(response.triggered.is_empty());
        assert!(!response.fleet_wide);
    }
}
