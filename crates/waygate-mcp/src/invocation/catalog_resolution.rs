//! Failure mapping for governed catalog resolution.
//!
//! A refusal and a temporary condition are different contracts. Every
//! per-tool refusal returns the same `tool_unavailable` error as a name that
//! does not exist, so a caller cannot tell a withheld tool from an absent
//! one. A quarantined or retired server is reported as forbidden, but only to
//! a caller who may discover that server. A temporary condition remains
//! retryable for that same caller, and anyone else receives the absent-tool
//! error. It is recorded as an execution failure before dispatch.
//!
//! The precise reason appears only in the log line and in the audit reason,
//! `refused:<code>` or `unavailable:<code>`, so administrators can search for
//! it. The caller's error carries the trace id that locates both.

use rmcp::ErrorData;
use waygate_invocation::InvocationError;
use waygate_oidc::Principal;

use crate::audit::AuditOutcome;
use crate::authz::profile_blocks_server;
use crate::catalog::{TemporaryUnavailability, ToolRefusal};

use super::{DefaultInvocationService, InvocationContext};

impl DefaultInvocationService {
    pub(super) async fn refusal_error(
        &self,
        ctx: &InvocationContext<'_>,
        server: &str,
        tool: &str,
        reason: ToolRefusal,
    ) -> InvocationError {
        let trace_id = refusal_trace_id();
        tracing::info!(
            %server,
            %tool,
            reason = reason.code(),
            %trace_id,
            "refusing call: catalog refused the tool",
        );
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::Denied)
                    .with_principal(ctx.principal)
                    .with_tool(server, tool)
                    .with_reason(format!("refused:{}", reason.code())),
            )
            .await;
        let server_block = match reason {
            ToolRefusal::ServerQuarantined => Some("server quarantined"),
            ToolRefusal::ServerRetired => Some("server retired"),
            ToolRefusal::NotInCatalog
            | ToolRefusal::Unclassified
            | ToolRefusal::NotAdmitted
            | ToolRefusal::LanesDisagree
            | ToolRefusal::DriftQuarantined
            | ToolRefusal::ReviewRequired
            | ToolRefusal::KeptBlocked
            | ToolRefusal::ApprovalPending => None,
        };
        match server_block {
            Some(block) if self.may_disclose_server(ctx.principal, server).await => {
                InvocationError::Forbidden {
                    reason: block.to_owned(),
                    policy_ids: Vec::new(),
                    reasons: Vec::new(),
                    trace_id: Some(trace_id),
                }
            }
            _ => InvocationError::ToolUnavailable {
                tool: format!("{server}.{tool}"),
                trace_id,
            },
        }
    }

    pub(super) async fn catalog_unavailable_error(
        &self,
        ctx: &InvocationContext<'_>,
        server: &str,
        tool: &str,
        reason: TemporaryUnavailability,
    ) -> InvocationError {
        let trace_id = refusal_trace_id();
        tracing::warn!(
            %server,
            %tool,
            reason = reason.code(),
            %trace_id,
            "refusing call: tool is temporarily unavailable",
        );
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::ExecutionError)
                    .with_principal(ctx.principal)
                    .with_tool(server, tool)
                    .with_reason(format!("unavailable:{}", reason.code())),
            )
            .await;
        // A retryable answer would confirm that the server exists, so a
        // caller who may not discover it receives the absent-tool error.
        if !self.may_disclose_server(ctx.principal, server).await {
            return InvocationError::ToolUnavailable {
                tool: format!("{server}.{tool}"),
                trace_id,
            };
        }
        InvocationError::Upstream(ErrorData::internal_error(
            "the governed tool catalog is unavailable; retry the request",
            Some(serde_json::json!({
                "error": "catalog_unavailable",
                "retryable": true,
                "trace_id": trace_id,
            })),
        ))
    }

    /// Whether an error may name a server-wide block or a temporary
    /// condition. It applies the checks
    /// `tools/list` and discovery use to show a server: the caller's
    /// credential profile admits it and Cedar lets the caller discover it.
    /// With authentication disabled there is no principal and every server
    /// is visible.
    async fn may_disclose_server(&self, principal: Option<&Principal>, server: &str) -> bool {
        match principal {
            None => true,
            Some(principal) => {
                !profile_blocks_server(principal, server)
                    && self.authz.may_discover_server(principal, server).await
            }
        }
    }
}

/// The trace id a refusal returns to the caller and writes to its log line.
/// With an OpenTelemetry context it is that trace's id, which the audit
/// recorder also stamps on the row; otherwise a random id still ties the
/// caller's error to the log line.
fn refusal_trace_id() -> String {
    waygate_telemetry::correlation::current_trace_id()
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string())
}
