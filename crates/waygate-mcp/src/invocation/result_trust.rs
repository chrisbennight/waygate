//! Result-level MCP trust claims used by annotation-native tools.

use rmcp::model::CallToolResult;
use serde_json::Value;
use thiserror::Error;

use super::{AuditOutcome, InvocationContext, InvocationError, SharedEvidence};

const TRUST_ANNOTATIONS_KEY: &str = "io.modelcontextprotocol/trust-annotations";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ResultTrust {
    pub(super) sensitive: bool,
    pub(super) untrusted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum ResultTrustError {
    #[error("result trust annotations are missing")]
    Missing,
    #[error("result trust annotations must contain explicit sensitive and untrusted booleans")]
    Malformed,
}

/// The complete annotation-native result-trust gate: the result must carry
/// explicit trust labels, and a `sensitive` result is released only when the
/// admitted contract's reviewed RETURN classification anticipated protected
/// output (`anticipated_sensitive_output`) — distinct from the combined
/// `pii` fact, which also covers protected input. A violation audits and
/// meters the refusal (via [`block_response`]) and returns the pipeline
/// error; success logs the validated labels. Owning the whole gate here
/// keeps the pipeline stage a single call.
pub(super) async fn enforce(
    audit: &SharedEvidence,
    ctx: &InvocationContext<'_>,
    result: &CallToolResult,
    anticipated_sensitive_output: bool,
) -> Result<(), InvocationError> {
    let reason = match parse(result) {
        Ok(trust) if trust.sensitive && !anticipated_sensitive_output => {
            "result sensitivity exceeds the admitted tool contract".to_owned()
        }
        Ok(trust) => {
            tracing::debug!(
                server = %ctx.server,
                tool = %ctx.tool,
                sensitive = trust.sensitive,
                untrusted = trust.untrusted,
                "validated annotation-native result trust claims",
            );
            return Ok(());
        }
        Err(error) => error.to_string(),
    };
    Err(block_response(audit, ctx, "trust-annotations", reason).await)
}

pub(super) fn parse(result: &CallToolResult) -> Result<ResultTrust, ResultTrustError> {
    let trust = result
        .meta
        .as_ref()
        .and_then(|meta| meta.0.get(TRUST_ANNOTATIONS_KEY))
        .and_then(Value::as_object)
        .ok_or(ResultTrustError::Missing)?;
    Ok(ResultTrust {
        sensitive: trust
            .get("sensitive")
            .and_then(Value::as_bool)
            .ok_or(ResultTrustError::Malformed)?,
        untrusted: trust
            .get("untrusted")
            .and_then(Value::as_bool)
            .ok_or(ResultTrustError::Malformed)?,
    })
}

/// Audit + meter a refused upstream response and build the pipeline error,
/// shared by result-trust enforcement and the response inspectors. Free
/// function (over `&SharedEvidence`) so the response-blocking concern lives
/// beside the trust logic instead of growing the pipeline module.
pub(super) async fn block_response(
    audit: &SharedEvidence,
    ctx: &InvocationContext<'_>,
    inspector_name: &'static str,
    reason: String,
) -> InvocationError {
    let facts = ctx.facts();
    let tenant = ctx
        .principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);
    let principal_sub = ctx.principal.map(|p| p.sub.as_str());
    tracing::info!(
        server = %ctx.server,
        tool = %ctx.tool,
        tenant = %tenant,
        user = ?principal_sub,
        inspector = %inspector_name,
        reason = %reason,
        "response_inspection_blocked: refusing to forward upstream response",
    );
    audit
        .record_chained_best_effort(
            ctx.audit_event(ctx.response_audit_action(), AuditOutcome::Denied)
                .with_principal(ctx.principal)
                .with_tool(ctx.server, ctx.tool)
                .with_risk(facts.risk)
                .with_pii(facts.pii)
                .with_reason(format!("response inspector `{inspector_name}` blocked")),
        )
        .await;
    waygate_telemetry::metrics::record_response_inspector_block(
        ctx.server,
        ctx.tool,
        inspector_name,
    );
    InvocationError::ResponseInspectionBlocked {
        tool: format!("{}.{}", ctx.server, ctx.tool),
        inspector_name,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use rmcp::model::{CallToolResult, MetaObject as Meta};
    use serde_json::json;

    use super::{parse, ResultTrust, ResultTrustError, TRUST_ANNOTATIONS_KEY};

    #[test]
    fn requires_explicit_labels_and_allows_future_members() {
        let mut meta = Meta::new();
        meta.0.insert(
            TRUST_ANNOTATIONS_KEY.into(),
            json!({
                "sensitive": true,
                "untrusted": false,
                "future": "retained by the result"
            }),
        );
        let result = CallToolResult::structured(json!({"value": "secret"})).with_meta(Some(meta));
        assert_eq!(
            parse(&result).expect("trust labels"),
            ResultTrust {
                sensitive: true,
                untrusted: false
            }
        );
        assert_eq!(
            parse(&CallToolResult::structured(json!({"ok": true}))).unwrap_err(),
            ResultTrustError::Missing
        );
    }
}
