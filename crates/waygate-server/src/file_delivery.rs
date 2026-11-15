//! Owner-scoped recovery for gateway-to-upstream upload staging.

use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use waygate_mcp::{
    files::{file_transfer_failure, invalid_file_request, FileInputOutcome, FileTransferReason},
    SharedCatalog,
};
use waygate_oidc::Principal;
use waygate_transfer::{GatewayFileDelivery, GatewayFileStorage};

pub(crate) struct DeliveryManager {
    catalog: SharedCatalog,
    storage: Arc<GatewayFileStorage>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct DeliveryStatus {
    /// Opaque identifier for this caller-owned delivery, usable with cancel_delivery.
    pub delivery_id: String,
    /// Original gateway file URI. Cancelling a delivery never deletes this file.
    pub uri: String,
    /// Receiving upstream server.
    pub server: String,
    /// Receiving upstream tool.
    pub tool: String,
    /// Last gateway-observed delivery or invocation stage.
    pub stage: String,
    /// Current upstream staging state, or unknown when it cannot be confirmed.
    pub state: String,
    /// Whether the upstream advertised the optional upload lifecycle extension.
    pub cancel_supported: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct DeliveryStatuses {
    /// Maximum file size admitted into gateway storage, in bytes.
    pub upload_max_bytes: u64,
    /// Configured maximum active byte transfers across all callers.
    pub active_transfer_capacity: usize,
    /// Configured maximum active byte transfers for one caller.
    pub per_owner_transfer_capacity: usize,
    /// Most recent caller-owned deliveries for the original gateway file.
    pub deliveries: Vec<DeliveryStatus>,
    /// More historical deliveries exist than this bounded response includes.
    pub limited: bool,
    /// Continue the same file's history with this opaque delivery cursor.
    pub next_cursor: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct DeliveryCancellation {
    /// Opaque caller-owned delivery identifier.
    pub delivery_id: String,
    /// Upstream-confirmed staging state, including cancelling or committed.
    pub state: String,
    /// True only when the upstream confirms cancellation and resource release.
    pub cancelled: bool,
}

impl DeliveryManager {
    pub fn new(catalog: SharedCatalog, storage: Arc<GatewayFileStorage>) -> Self {
        Self { catalog, storage }
    }

    fn authorize_delivery(
        principal: &Principal,
        delivery: &GatewayFileDelivery,
    ) -> Result<(), McpError> {
        if crate::file_transfer::profile_blocks_file_origin(
            principal,
            &delivery.source_server,
            &delivery.source_tool,
        ) || crate::file_transfer::profile_blocks_file_origin(
            principal,
            &delivery.server,
            &delivery.tool,
        ) {
            return Err(unavailable());
        }
        Ok(())
    }

    async fn state(&self, principal: &Principal, delivery: &GatewayFileDelivery) -> String {
        if !delivery.lifecycle_supported {
            return "unknown".into();
        }
        match self
            .catalog
            .manage_file_upload(
                &delivery.server,
                &delivery.upstream_uri,
                false,
                Some(principal),
            )
            .await
        {
            Ok(value) => {
                safe_state(value.get("state").and_then(serde_json::Value::as_str)).to_owned()
            }
            Err(error) => {
                tracing::warn!(delivery_id=%delivery.id, code=?error.code, "upstream upload status unavailable");
                "unknown".into()
            }
        }
    }

    pub async fn status(
        &self,
        principal: &Principal,
        file_id: Uuid,
        cursor: Option<Uuid>,
    ) -> Result<DeliveryStatuses, McpError> {
        let owner = crate::file_transfer::owner_from_principal(principal);
        if let Some(cursor) = cursor {
            let anchor = self
                .storage
                .owned_delivery(&owner, cursor)
                .await
                .map_err(storage_error)?
                .ok_or_else(unavailable)?;
            if anchor.file_id != file_id {
                return Err(unavailable());
            }
        }
        let mut records = self
            .storage
            .deliveries_for_file(&owner, file_id, cursor)
            .await
            .map_err(storage_error)?;
        let limited = records.len() > 20;
        records.truncate(20);
        let next_cursor = if limited {
            records.last().map(|r| r.id.to_string())
        } else {
            None
        };
        let mut deliveries = Vec::with_capacity(records.len());
        for record in records {
            Self::authorize_delivery(principal, &record)?;
            let state = self.state(principal, &record).await;
            deliveries.push(DeliveryStatus {
                delivery_id: record.id.to_string(),
                uri: format!("mcp-file://gateway/{}", record.file_id),
                server: record.server,
                tool: record.tool,
                stage: record.stage,
                state,
                cancel_supported: record.lifecycle_supported,
            });
        }
        Ok(DeliveryStatuses {
            deliveries,
            limited,
            next_cursor,
            upload_max_bytes: 0,
            active_transfer_capacity: 0,
            per_owner_transfer_capacity: 0,
        })
    }

    pub async fn cancel(
        &self,
        principal: &Principal,
        id: Uuid,
    ) -> Result<DeliveryCancellation, McpError> {
        let owner = crate::file_transfer::owner_from_principal(principal);
        let record = self
            .storage
            .owned_delivery(&owner, id)
            .await
            .map_err(storage_error)?
            .ok_or_else(unavailable)?;
        Self::authorize_delivery(principal, &record)?;
        if !record.lifecycle_supported {
            return Err(invalid_file_request(FileTransferReason::NotEnabled,"upstream upload cancellation is not supported; retain the source file and inspect the destination before retrying"));
        }
        // The upstream serializes cancellation with reception and publication.
        // It must refuse cancellation once publication has begun.
        let value = self
            .catalog
            .manage_file_upload(&record.server, &record.upstream_uri, true, Some(principal))
            .await?;
        let state = safe_state(value.get("state").and_then(serde_json::Value::as_str)).to_owned();
        let cancelled = value.get("cancelled").and_then(serde_json::Value::as_bool) == Some(true)
            && state == "cancelled";
        if matches!(state.as_str(), "cancelled" | "cancelling") {
            self.storage
                .set_delivery_stage(&owner, id, &state)
                .await
                .map_err(storage_error)?;
        }
        Ok(DeliveryCancellation {
            delivery_id: id.to_string(),
            state,
            cancelled,
        })
    }

    pub async fn settle(
        &self,
        principal: &Principal,
        invocation: &str,
        outcome: FileInputOutcome,
    ) -> Vec<String> {
        let owner = crate::file_transfer::owner_from_principal(principal);
        let records = match self
            .storage
            .deliveries_for_invocation(&owner, invocation)
            .await
        {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(%error,"upload delivery recovery lookup failed");
                return Vec::new();
            }
        };
        let mut ids = Vec::with_capacity(records.len());
        for record in records {
            ids.push(record.id.to_string());
            let stage = match outcome {
                FileInputOutcome::NotDispatched | FileInputOutcome::Rejected => "rejected",
                FileInputOutcome::Completed => "completed",
                FileInputOutcome::Unknown => "completion_unknown",
            };
            if let Err(error) = self
                .storage
                .set_delivery_stage(&owner, record.id, stage)
                .await
            {
                tracing::warn!(delivery_id=%record.id,%error,"upload delivery outcome could not be recorded");
            }
            if matches!(
                outcome,
                FileInputOutcome::NotDispatched | FileInputOutcome::Rejected
            ) && record.lifecycle_supported
            {
                if let Err(error) = self.cancel(principal, record.id).await {
                    tracing::warn!(delivery_id=%record.id,code=?error.code,"rejected upload cleanup remains unconfirmed");
                }
            }
        }
        ids
    }

    pub async fn dispatch_started(
        &self,
        principal: &Principal,
        invocation: &str,
    ) -> Result<(), McpError> {
        let owner = crate::file_transfer::owner_from_principal(principal);
        for record in self
            .storage
            .deliveries_for_invocation(&owner, invocation)
            .await
            .map_err(storage_error)?
        {
            if !self
                .storage
                .set_delivery_stage(&owner, record.id, "dispatched")
                .await
                .map_err(storage_error)?
            {
                return Err(invalid_file_request(FileTransferReason::FileUnavailable,"upload delivery was cancelled or is no longer ready; the consuming tool was not dispatched"));
            }
        }
        Ok(())
    }
}

fn unavailable() -> McpError {
    invalid_file_request(
        FileTransferReason::FileUnavailable,
        "delivery is unavailable or expired",
    )
}
fn storage_error(error: waygate_transfer::FileStorageError) -> McpError {
    tracing::warn!(%error,"upload delivery recovery store unavailable");
    file_transfer_failure(
        FileTransferReason::TemporarilyUnavailable,
        "upload delivery recovery is unavailable",
    )
}
fn safe_state(state: Option<&str>) -> &str {
    match state {
        Some(
            v @ ("prepared" | "receiving" | "ready" | "failed" | "cancelling" | "cancelled"
            | "committed" | "commit_uncertain"),
        ) => v,
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use waygate_mcp::UpstreamCatalog;

    struct LifecycleCatalog {
        cancelled: AtomicBool,
        committed: AtomicBool,
        cancels: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl UpstreamCatalog for LifecycleCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["printable".into()]
        }
        async fn list_tools(&self, _: &str) -> Result<Vec<rmcp::model::Tool>, McpError> {
            Ok(Vec::new())
        }
        async fn call_tool(
            &self,
            _: &str,
            _: &str,
            _: Option<serde_json::Map<String, serde_json::Value>>,
            _: Option<&Principal>,
            _: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<rmcp::model::CallToolResult, McpError> {
            unreachable!("recovery never replays the consuming tool")
        }
        async fn manage_file_upload(
            &self,
            server: &str,
            uri: &str,
            cancel: bool,
            _: Option<&Principal>,
        ) -> Result<serde_json::Value, McpError> {
            assert_eq!(server, "printable");
            assert_eq!(uri, "mcp-file://printable/upload/private");
            if cancel {
                self.cancels.fetch_add(1, Ordering::SeqCst);
                if !self.committed.load(Ordering::SeqCst) {
                    self.cancelled.store(true, Ordering::SeqCst);
                }
            }
            let committed = self.committed.load(Ordering::SeqCst);
            let cancelled = self.cancelled.load(Ordering::SeqCst) && !committed;
            Ok(
                serde_json::json!({"state":if committed {"committed"}else if cancelled{"cancelled"}else{"ready"},"cancelled":cancelled}),
            )
        }
    }

    #[tokio::test]
    async fn cancellation_is_owned_and_definite_rejection_reclaims_without_replaying() {
        let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
            return;
        };
        let tenant = format!("delivery-manager-{}", Uuid::new_v4().simple());
        sqlx::query("INSERT INTO tenants(id,display_name) VALUES($1,$1)")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
        let principal = Principal {
            sub: "owner".into(),
            email: None,
            groups: Vec::new(),
            issuer: "issuer".into(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::parse(&tenant).unwrap(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
            roles: Vec::new(),
        };
        let root = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            GatewayFileStorage::new(pool.clone(), root.path())
                .await
                .unwrap(),
        );
        let owner = crate::file_transfer::owner_from_principal(&principal);
        let id = Uuid::new_v4();
        let file_id = Uuid::new_v4();
        storage
            .record_delivery(waygate_transfer::NewFileDelivery {
                id,
                owner: &owner,
                file_id,
                invocation_id: "call",
                server: "printable",
                tool: "artifact",
                source_server: "gateway",
                source_tool: "prepare_upload",
                upstream_uri: "mcp-file://printable/upload/private",
                lifecycle_supported: true,
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
        let catalog = Arc::new(LifecycleCatalog {
            cancelled: AtomicBool::new(false),
            committed: AtomicBool::new(false),
            cancels: AtomicUsize::new(0),
        });
        let manager = DeliveryManager::new(catalog.clone(), storage.clone());
        let mut other = principal.clone();
        other.sub = "other".into();
        assert!(manager.cancel(&other, id).await.is_err());
        assert_eq!(catalog.cancels.load(Ordering::SeqCst), 0);
        assert!(manager
            .status(&other, file_id, None)
            .await
            .unwrap()
            .deliveries
            .is_empty());
        manager
            .settle(&principal, "call", FileInputOutcome::Unknown)
            .await;
        assert_eq!(catalog.cancels.load(Ordering::SeqCst), 0);
        assert_eq!(
            storage
                .owned_delivery(&owner, id)
                .await
                .unwrap()
                .unwrap()
                .stage,
            "completion_unknown"
        );
        manager
            .settle(&principal, "call", FileInputOutcome::Rejected)
            .await;
        assert_eq!(catalog.cancels.load(Ordering::SeqCst), 1);
        assert_eq!(
            manager
                .status(&principal, file_id, None)
                .await
                .unwrap()
                .deliveries[0]
                .state,
            "cancelled"
        );
        assert!(!storage
            .set_delivery_stage(&owner, id, "completed")
            .await
            .unwrap());
        catalog.committed.store(true, Ordering::SeqCst);
        let cancellation = manager.cancel(&principal, id).await.unwrap();
        assert_eq!(cancellation.state, "committed");
        assert!(!cancellation.cancelled);
        sqlx::query("DELETE FROM tenants WHERE id=$1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }
}
