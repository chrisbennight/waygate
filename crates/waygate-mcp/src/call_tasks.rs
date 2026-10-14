//! Gateway-run tasks for long-running upstream tool calls.
//!
//! When a client declares the tasks extension on a call to an upstream tool
//! the operator listed as long-running, and that upstream does not run the
//! call as a task itself, the gateway can run the call in the background and
//! answer with a task handle. This module is the seam between the MCP surface
//! and the durable executor that owns those calls; the executor applies the
//! same invocation pipeline a direct call uses.

use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{GetTaskResult, JsonObject, Task};
use rmcp::ErrorData as McpError;
use waygate_invocation::InvocationError;
use waygate_oidc::Principal;

/// Prefix of every gateway call-task identifier.
pub const PREFIX: &str = "wgc_";

/// Whether `task_id` names a gateway call task rather than an upstream-owned
/// or built-in task.
pub fn is_call_task(task_id: &str) -> bool {
    task_id.starts_with(PREFIX)
}

/// The client-visible identifier of the call task backed by `execution_id`.
pub fn task_id(execution_id: uuid::Uuid) -> String {
    format!("{PREFIX}{}", execution_id.simple())
}

/// The execution behind a call-task identifier, or `None` for anything that
/// is not exactly a prefix followed by a hyphen-free UUID.
pub fn execution_id(task_id: &str) -> Option<uuid::Uuid> {
    let encoded = task_id.strip_prefix(PREFIX)?;
    if encoded.len() != 32 {
        return None;
    }
    uuid::Uuid::parse_str(encoded).ok()
}

/// One fully qualified upstream tool call to run in the background.
#[derive(Debug, Clone)]
pub struct QualifiedCall {
    pub server: String,
    pub tool: String,
    pub arguments: Option<JsonObject>,
}

/// Durable executor for gateway call tasks.
#[async_trait]
pub trait GatewayCallTasks: Send + Sync + 'static {
    /// Run `call` in the background under `principal`'s ordinary governance.
    ///
    /// `Ok(Some(task))` means the call passed every governance gate, was
    /// durably claimed, and will be dispatched. `Ok(None)` declines before any
    /// governance ran (for example, no background capacity), so the caller
    /// runs the call synchronously instead. `Err` is the refusal a direct call
    /// would have returned; nothing was dispatched.
    async fn start(
        &self,
        principal: &Principal,
        call: QualifiedCall,
    ) -> Result<Option<Task>, InvocationError>;

    /// Project one call task owned by `principal`. `None` when the identifier
    /// is unknown, expired, or owned by someone else.
    async fn get(
        &self,
        principal: &Principal,
        task_id: &str,
    ) -> Result<Option<GetTaskResult>, McpError>;

    /// Request cancellation of one call task owned by `principal`. `false`
    /// when the identifier is unknown, expired, or owned by someone else.
    async fn cancel(&self, principal: &Principal, task_id: &str) -> Result<bool, McpError>;
}

pub type SharedGatewayCallTasks = Arc<dyn GatewayCallTasks>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip_and_reject_other_shapes() {
        let id = uuid::Uuid::new_v4();
        let task = task_id(id);
        assert!(is_call_task(&task));
        assert_eq!(task.len(), PREFIX.len() + 32);
        assert_eq!(execution_id(&task), Some(id));
        assert_eq!(execution_id(&format!("{PREFIX}{id}")), None);
        assert_eq!(execution_id(&id.to_string()), None);
        assert_eq!(execution_id(&format!("{task}0")), None);
        assert!(!is_call_task(&format!("wgt_{}", id.simple())));
    }
}
