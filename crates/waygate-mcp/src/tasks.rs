//! Native upstream task routing. Short IDs resolve durable routing metadata,
//! never execution state; the upstream remains the lifecycle authority.

use rmcp::model::{ClientCapabilities, Task};
use std::sync::Arc;
use waygate_invocation::TaskAction;
use waygate_oidc::Principal;

pub mod store;
pub use store::PgTaskRouteStore;
pub use waygate_invocation::task_routes::{TaskRoute, TaskRouteStore};

pub const HANDLE_PREFIX: &str = "wgt_";
const LEGACY_HANDLE_PREFIX: &str = "waygate-task-v1.";

pub fn is_upstream_task(handle: &str) -> bool {
    handle.starts_with(HANDLE_PREFIX) || handle.starts_with(LEGACY_HANDLE_PREFIX)
}
pub const DEFAULT_RETENTION_SECONDS: u64 = 36 * 60 * 60;
const MAX_ROUTE_BYTES: usize = 24 * 1024;

#[derive(Clone)]
pub struct TaskRouter {
    store: Arc<dyn TaskRouteStore>,
    retention_seconds: u64,
}

/// A lifecycle RPC dispatched under the original tool's admitted contract.
#[derive(Debug, Clone)]
pub struct TaskRpc {
    pub task_id: String,
    pub action: TaskAction,
    pub binding: String,
    pub capabilities: ClientCapabilities,
    pub expires_at: i64,
    pub created_at: String,
}

impl TaskRouter {
    pub fn new(store: Arc<dyn TaskRouteStore>, retention_seconds: u64) -> Self {
        Self {
            store,
            retention_seconds,
        }
    }

    pub(crate) async fn register(
        &self,
        mut route: TaskRoute,
        task: &mut Task,
    ) -> Result<String, rmcp::ErrorData> {
        let created = time::OffsetDateTime::parse(
            &task.created_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| invalid("upstream task has an invalid creation time"))?;
        let ttl = task
            .ttl_ms
            .unwrap_or(u64::MAX)
            .min(self.retention_seconds.saturating_mul(1000));
        let expires_ms = created.unix_timestamp_nanos() / 1_000_000 + i128::from(ttl);
        route.exp = i64::try_from(expires_ms / 1000).map_err(|_| invalid("invalid task expiry"))?;
        if route.exp <= time::OffsetDateTime::now_utc().unix_timestamp() {
            return Err(invalid("upstream task has already expired"));
        }
        route.created_at = task.created_at.clone();
        route.ttl_ms = ttl;
        route.upstream_id = task.task_id.clone();
        if route.upstream_id.is_empty() || route.upstream_id.len() > 4096 {
            return Err(invalid("upstream task identifier is empty or too large"));
        }
        if serde_json::to_vec(&route)
            .map_err(|_| invalid("invalid task routing metadata"))?
            .len()
            > MAX_ROUTE_BYTES
        {
            return Err(invalid("task routing metadata exceeds the size limit"));
        }
        let id = uuid::Uuid::new_v4();
        self.store.insert(id, &route).await.map_err(storage_error)?;
        let handle = format!("{HANDLE_PREFIX}{}", id.simple());
        task.task_id = handle.clone();
        task.ttl_ms = Some(ttl);
        Ok(handle)
    }

    pub(crate) async fn open(
        &self,
        handle: &str,
        principal: &Principal,
    ) -> Result<TaskRoute, rmcp::ErrorData> {
        if handle.starts_with(LEGACY_HANDLE_PREFIX) {
            return Err(invalid("Legacy task handles are no longer supported; use the originating upstream to recover outstanding work"));
        }
        if handle.len() != HANDLE_PREFIX.len() + 32 {
            return Err(not_found());
        }
        let encoded = handle.strip_prefix(HANDLE_PREFIX).ok_or_else(not_found)?;
        let id = uuid::Uuid::parse_str(encoded).map_err(|_| not_found())?;
        let route = self
            .store
            .get(id, principal.tenant.as_str())
            .await
            .map_err(storage_error)?
            .ok_or_else(not_found)?;
        if route.exp <= time::OffsetDateTime::now_utc().unix_timestamp()
            || !route.belongs_to(principal)
        {
            return Err(not_found());
        }
        Ok(route)
    }
}

fn storage_error(error: waygate_core::store::StoreError) -> rmcp::ErrorData {
    // Database diagnostics can contain metadata; expose only the failure category.
    tracing::warn!(
        conflict = matches!(error, waygate_core::store::StoreError::Conflict),
        "upstream task routing storage operation failed"
    );
    rmcp::ErrorData::internal_error("Task routing storage unavailable; upstream work may still be running; do not automatically resubmit the original tool call", None)
}

pub(crate) fn not_found() -> rmcp::ErrorData {
    invalid("Task not found or no longer accessible")
}
pub(crate) fn invalid(message: &'static str) -> rmcp::ErrorData {
    rmcp::ErrorData::invalid_params(message, None)
}

/// Preserve upstream protocol errors and expose the same stable invocation categories.
pub(crate) fn invocation_error(error: waygate_invocation::InvocationError) -> rmcp::ErrorData {
    use waygate_invocation::InvocationError;
    let message = error.to_string();
    let data = match error {
        InvocationError::Upstream(error) => return error,
        InvocationError::InvalidArguments(detail) => {
            return rmcp::ErrorData::invalid_params(detail, None)
        }
        InvocationError::AuditUnavailable(_) => {
            return rmcp::ErrorData::internal_error(message, None)
        }
        InvocationError::StepUpRequired {
            required_scope,
            reason,
        } => serde_json::json!({
            "error": "insufficient_scope", "required_scope": required_scope, "reason": reason,
        }),
        InvocationError::Forbidden {
            reason,
            policy_ids,
            reasons,
        } => serde_json::json!({
            "error": "forbidden", "reason": reason, "policy_ids": policy_ids, "reasons": reasons,
        }),
        InvocationError::ApprovalRequired {
            tool,
            reason,
            satisfiable,
        } => serde_json::json!({
            "error": "approval_required", "tool": tool, "reason": reason, "satisfiable": satisfiable,
        }),
        InvocationError::RateLimited {
            policy_id,
            policy_name,
            retry_after_seconds,
        } => serde_json::json!({
            "error": "rate_limited", "policy_id": policy_id, "policy_name": policy_name,
            "retry_after_seconds": retry_after_seconds,
        }),
        error => serde_json::json!({"error": error.kind()}),
    };
    rmcp::ErrorData::new(rmcp::model::ErrorCode::INVALID_REQUEST, message, Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;
    use waygate_invocation::InvocationContractIdentity;
    use waygate_invocation::{InvocationContractAuthority, InvocationRisk};
    fn principal() -> Principal {
        Principal {
            sub: "alice".into(),
            issuer: "issuer".into(),
            tenant: waygate_core::TenantId::default(),
            email: None,
            groups: vec![],
            scopes: vec![],
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }
    fn route(p: &Principal) -> TaskRoute {
        TaskRoute::new(
            p,
            "server",
            "tool",
            "binding".into(),
            InvocationContractIdentity {
                authority: InvocationContractAuthority::SyntheticModel,
                input_schema_hash: None,
                output_schema_hash: None,
                tool_annotations_hash: None,
                action_metadata_hash: None,
                operations_hash: None,
                risk: InvocationRisk::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            Map::new(),
            waygate_core::RequestFacts::default(),
        )
    }
    #[tokio::test]
    async fn handles_are_short_and_bound_to_owner_profile_and_retention() {
        let store = Arc::new(waygate_test_support::task_routes::InMemoryTaskRouteStore::default());
        let router = TaskRouter::new(store.clone(), DEFAULT_RETENTION_SECONDS);
        let p = principal();
        let created = waygate_core::fmt::format_ts_rfc3339(time::OffsetDateTime::now_utc());
        let mut task = Task::new(
            "opaque",
            rmcp::model::TaskStatus::Working,
            &created,
            &created,
        )
        .with_ttl_ms(3_600_000);
        let handle = router.register(route(&p), &mut task).await.unwrap();
        assert_eq!(task.ttl_ms, Some(3_600_000));
        assert_eq!(handle.len(), 36);
        let second_replica = TaskRouter::new(store.clone(), DEFAULT_RETENTION_SECONDS);
        assert_eq!(
            second_replica.open(&handle, &p).await.unwrap().upstream_id,
            "opaque"
        );
        let mut other = p.clone();
        other.sub = "mallory".into();
        assert!(second_replica.open(&handle, &other).await.is_err());
        other = p.clone();
        other.issuer = "another-issuer".into();
        assert!(second_replica.open(&handle, &other).await.is_err());
        other = p.clone();
        other.tenant = waygate_core::TenantId::parse("other").unwrap();
        assert!(second_replica.open(&handle, &other).await.is_err());
        other = p.clone();
        other.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "limited".into(),
            profile_name: "limited".into(),
            allowed_servers: Some(vec!["server".into()]),
            allowed_tools: None,
        });
        assert!(second_replica.open(&handle, &other).await.is_err());
        other = p.clone();
        other.auth_method = waygate_oidc::AuthMethod::ApiKey;
        assert!(second_replica.open(&handle, &other).await.is_err());
        let mut expired = second_replica.open(&handle, &p).await.unwrap();
        expired.exp = 1;
        let id = uuid::Uuid::new_v4();
        store.insert(id, &expired).await.unwrap();
        assert!(router
            .open(&format!("{HANDLE_PREFIX}{}", id.simple()), &p)
            .await
            .is_err());
        assert!(router.open(&format!("{handle}!"), &p).await.is_err());
        assert!(router.open("waygate-task-v1.old", &p).await.is_err());
        // Policy metadata grows in storage, never in the client-visible identifier.
        let mut large = route(&p);
        large.request_facts.file_paths = vec!["long/path/".repeat(100)];
        task.task_id = "upstream-id".into();
        assert_eq!(
            router.register(large, &mut task).await.unwrap().len(),
            handle.len()
        );
        let expired_created = "2000-01-01T00:00:00Z";
        task.created_at = expired_created.into();
        assert!(router.register(route(&p), &mut task).await.is_err());
    }

    #[tokio::test]
    async fn unavailable_storage_returns_an_error_without_publishing_a_task_id() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        pool.close().await;
        let router = TaskRouter::new(
            Arc::new(PgTaskRouteStore::new(pool)),
            DEFAULT_RETENTION_SECONDS,
        );
        let p = principal();
        let handle = format!("{HANDLE_PREFIX}{}", uuid::Uuid::new_v4().simple());
        assert_eq!(
            router.open(&handle, &p).await.err().unwrap().code,
            rmcp::model::ErrorCode::INTERNAL_ERROR
        );
        let created = waygate_core::fmt::format_ts_rfc3339(time::OffsetDateTime::now_utc());
        let mut task = Task::new(
            "upstream-still-running",
            rmcp::model::TaskStatus::Working,
            &created,
            &created,
        );
        assert!(router.register(route(&p), &mut task).await.is_err());
        assert_eq!(task.task_id, "upstream-still-running");
    }
}
