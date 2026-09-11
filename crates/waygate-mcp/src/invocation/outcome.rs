//! Post-dispatch audit and telemetry helpers.

use super::*;

impl DefaultInvocationService {
    /// Emit audit rows and metrics deferred by [`Self::inspect_response`].
    ///
    /// This runs only after output validation confirms the redacted response
    /// is forwardable, so rejected substitutions cannot produce telemetry
    /// claiming that a redaction reached the caller.
    pub(super) async fn flush_pending_redactions(&self, ctx: &mut InvocationContext<'_>) {
        if ctx.pending_redactions.is_empty() {
            return;
        }
        // Snapshot fields before draining the mutable pending list.
        let (risk, pii) = {
            let facts = ctx.facts();
            (facts.risk, facts.pii)
        };
        let principal = ctx.principal;
        let server = ctx.server;
        let tool = ctx.tool;
        // Every success row carries the same fired Cedar permits as the final
        // outcome row.
        let policy_ids = ctx.authz_policy_ids.clone();
        for (inspector_name, findings_count) in std::mem::take(&mut ctx.pending_redactions) {
            self.audit
                .record_chained_best_effort(
                    ctx.audit_event("CallTool", AuditOutcome::Success)
                        .with_principal(principal)
                        .with_tool(server, tool)
                        .with_risk(risk)
                        .with_pii(pii)
                        .with_policies(policy_ids.clone())
                        // This is post-authorization telemetry, not another
                        // replayable authorization decision.
                        .with_reason(format!(
                            "response inspector `{inspector_name}` redacted {findings_count} finding(s)"
                        )),
                )
                .await;
            waygate_telemetry::metrics::record_response_inspector_redaction(
                server,
                tool,
                inspector_name,
                findings_count,
            );
        }
    }
}
