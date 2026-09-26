//! Native upstream task routing. Handles contain encrypted routing metadata,
//! never execution state; the upstream remains the lifecycle authority.

use rmcp::model::{ClientCapabilities, Task};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use waygate_invocation::{InvocationContractIdentity, TaskAction};
use waygate_oidc::{
    session::{self, HasExp, SessionKey},
    Principal,
};

pub const HANDLE_PREFIX: &str = "waygate-task-v1.";
pub const DEFAULT_RETENTION_SECONDS: u64 = 36 * 60 * 60;
const MAX_HANDLE_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub struct TaskSealer {
    key: SessionKey,
    retention_seconds: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct TaskRoute {
    kind: String,
    sub: String,
    issuer: String,
    tenant: String,
    profile: Value,
    auth_method: String,
    pub server: String,
    pub tool: String,
    pub upstream_id: String,
    pub binding: String,
    pub contract: InvocationContractIdentity,
    /// Only reviewed operation selection is retained, never tool arguments.
    pub operation_arguments: Map<String, Value>,
    pub created_at: String,
    pub ttl_ms: u64,
    pub exp: i64,
}
impl HasExp for TaskRoute {
    fn exp(&self) -> i64 {
        self.exp
    }
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

impl TaskSealer {
    pub fn new(key: SessionKey, retention_seconds: u64) -> Self {
        Self {
            key,
            retention_seconds,
        }
    }

    pub(crate) fn seal(
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
        let encoded = session::encrypt(&self.key, &route)
            .map_err(|_| invalid("could not protect task routing"))?;
        let handle = format!("{HANDLE_PREFIX}{encoded}");
        if handle.len() > MAX_HANDLE_BYTES {
            return Err(invalid("task routing exceeds the handle size limit"));
        }
        task.task_id = handle.clone();
        task.ttl_ms = Some(ttl);
        Ok(handle)
    }

    pub(crate) fn open(
        &self,
        handle: &str,
        principal: &Principal,
    ) -> Result<TaskRoute, rmcp::ErrorData> {
        if handle.len() > MAX_HANDLE_BYTES {
            return Err(not_found());
        }
        let encoded = handle.strip_prefix(HANDLE_PREFIX).ok_or_else(not_found)?;
        let route: TaskRoute = session::decrypt(&self.key, encoded).map_err(|_| not_found())?;
        if route.kind != "upstream-task-v1"
            || route.sub != principal.sub
            || route.issuer != principal.issuer
            || route.tenant != principal.tenant.as_str()
            || route.profile != profile(principal)
            || route.auth_method != principal.auth_method.as_str()
        {
            return Err(not_found());
        }
        Ok(route)
    }
}

impl TaskRoute {
    pub(crate) fn new(
        principal: &Principal,
        server: &str,
        tool: &str,
        binding: String,
        contract: InvocationContractIdentity,
        operation_arguments: Map<String, Value>,
    ) -> Self {
        Self {
            kind: "upstream-task-v1".into(),
            sub: principal.sub.clone(),
            issuer: principal.issuer.clone(),
            tenant: principal.tenant.as_str().into(),
            profile: profile(principal),
            auth_method: principal.auth_method.as_str().into(),
            server: server.into(),
            tool: tool.into(),
            binding,
            contract,
            operation_arguments,
            upstream_id: String::new(),
            created_at: String::new(),
            ttl_ms: 0,
            exp: 0,
        }
    }
}

fn profile(principal: &Principal) -> Value {
    principal
        .api_key_profile_restrictions
        .as_ref()
        .map_or(Value::Null, |p| {
            let mut servers = p.allowed_servers.clone().unwrap_or_default();
            servers.sort();
            servers.dedup();
            let mut tools = p.allowed_tools.clone().unwrap_or_default();
            tools.sort();
            tools.dedup();
            serde_json::json!({"profile_id": p.profile_id, "servers": servers, "tools": tools})
        })
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
        )
    }
    #[test]
    fn handles_are_portable_but_bound_to_owner_profile_and_retention() {
        let key = SessionKey::from_bytes([41; 32]);
        let sealer = TaskSealer::new(key.clone(), DEFAULT_RETENTION_SECONDS);
        let p = principal();
        let created = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let mut task = Task::new(
            "opaque",
            rmcp::model::TaskStatus::Working,
            &created,
            &created,
        )
        .with_ttl_ms(60000);
        let handle = sealer.seal(route(&p), &mut task).unwrap();
        assert_eq!(task.ttl_ms, Some(60000));
        assert!(!handle.contains("opaque"));
        let second_replica = TaskSealer::new(key.clone(), DEFAULT_RETENTION_SECONDS);
        assert_eq!(
            second_replica.open(&handle, &p).unwrap().upstream_id,
            "opaque"
        );
        let mut other = p.clone();
        other.sub = "mallory".into();
        assert!(second_replica.open(&handle, &other).is_err());
        other = p.clone();
        other.issuer = "another-issuer".into();
        assert!(second_replica.open(&handle, &other).is_err());
        other = p.clone();
        other.tenant = waygate_core::TenantId::parse("other").unwrap();
        assert!(second_replica.open(&handle, &other).is_err());
        other = p.clone();
        other.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "limited".into(),
            profile_name: "limited".into(),
            allowed_servers: Some(vec!["server".into()]),
            allowed_tools: None,
        });
        assert!(second_replica.open(&handle, &other).is_err());
        assert!(
            TaskSealer::new(SessionKey::from_bytes([42; 32]), DEFAULT_RETENTION_SECONDS)
                .open(&handle, &p)
                .is_err()
        );
        let mut expired = second_replica.open(&handle, &p).unwrap();
        expired.exp = 1;
        let expired_handle = format!(
            "{HANDLE_PREFIX}{}",
            session::encrypt(&key, &expired).unwrap()
        );
        assert!(sealer.open(&expired_handle, &p).is_err());
        let mut tampered = handle;
        tampered.push('!');
        assert!(sealer.open(&tampered, &p).is_err());
    }
}
