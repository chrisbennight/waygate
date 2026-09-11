//! Failure mapping for governed catalog resolution.
//!
//! Lifecycle blocks and infrastructure outages are different contracts: the
//! former is an authorization-shaped refusal, while the latter must remain
//! retryable and must be recorded as an execution failure before dispatch.

use rmcp::ErrorData;
use waygate_invocation::InvocationError;

use crate::audit::AuditOutcome;

use super::{DefaultInvocationService, InvocationContext};

impl DefaultInvocationService {
    pub(super) async fn catalog_unavailable_error(
        &self,
        ctx: &InvocationContext<'_>,
        server: &str,
        tool: &str,
    ) -> InvocationError {
        tracing::warn!(%server, %tool, "refusing call: authoritative catalog unavailable");
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::ExecutionError)
                    .with_principal(ctx.principal)
                    .with_tool(server, tool)
                    .with_reason("authoritative catalog unavailable"),
            )
            .await;
        InvocationError::Upstream(ErrorData::internal_error(
            "the governed tool catalog is unavailable; retry the request",
            Some(serde_json::json!({
                "error": "catalog_unavailable",
                "retryable": true,
            })),
        ))
    }
}
