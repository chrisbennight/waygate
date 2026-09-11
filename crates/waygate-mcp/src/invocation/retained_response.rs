//! Recovery of connector HTTP bodies retained outside their compact tool result.
//!
//! Some connector adapters protect direct model context by replacing a large
//! `data` member with a `payload` envelope that names an MCP resource. Code
//! Mode reduces the body inside its runtime; direct clients receive a governed
//! file. Recovery and delivery never change the invoking caller's authority.

use rmcp::model::{CallToolResult, ErrorData, ReadResourceResult, ResourceContents};

use crate::catalog::{
    CallScopedResourceReader, CallToolResultProcessing, CallToolResultProcessingError,
    CallToolResultProcessor, ToolCallMrtr,
};

use super::{AuditOutcome, DefaultInvocationService, InvocationContext, InvocationError};

const RECOVERY_FAILED_ERROR: &str = "retained_response_recovery_failed";
// MCP resources/read returns a buffered JSON value. Disk-file admission must
// not authorize unbounded JSON decoding and inspection allocations in memory.
const MAX_RETAINED_BODY_BYTES: usize = 16 * 1024 * 1024;

impl InvocationContext<'_> {
    pub(super) fn response_output_validator(
        &self,
        result: &CallToolResult,
    ) -> Option<&jsonschema::Validator> {
        if self
            .retained_operation_succeeded
            .load(std::sync::atomic::Ordering::Relaxed)
            && result
                .meta
                .as_ref()
                .is_some_and(|meta| meta.contains_key(crate::files::RETAINED_DELIVERY_META_KEY))
        {
            Some(crate::retained_delivery::validator())
        } else {
            self.tool_snapshot().output_validator()
        }
    }

    pub(super) fn response_audit_action(&self) -> &'static str {
        if self.facts().side_effects
            && self
                .retained_operation_succeeded
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            "ResponseDelivery"
        } else {
            "CallTool"
        }
    }
}

impl DefaultInvocationService {
    pub(super) async fn record_delivery_outcome(
        &self,
        base: crate::audit::AuditEvent,
        output: &CallToolResult,
    ) {
        let delivery = output
            .meta
            .as_ref()
            .and_then(|meta| meta.get(crate::files::RETAINED_DELIVERY_META_KEY));
        let suffix = match delivery.and_then(|value| value["delivery_status"].as_str()) {
            Some("file") => Some("response attachment published"),
            Some("unavailable") => {
                Some("operation succeeded; response attachment unavailable; do not redispatch")
            }
            _ => None,
        };
        let base = if let Some(suffix) = suffix {
            let reason = base
                .reason
                .as_ref()
                .map_or_else(|| suffix.to_owned(), |reason| format!("{reason}; {suffix}"));
            base.with_reason(reason)
        } else {
            base
        };
        self.audit.record_chained_best_effort(base).await;
    }
}

pub(super) struct RecoveredResponse {
    pub target: RetainedResponse,
    pub original: CallToolResult,
    pub bytes: Vec<u8>,
    pub value: serde_json::Value,
    pub binary: bool,
    pub file_delivery: bool,
}

impl RecoveredResponse {
    /// Preserve exact bytes when inspection did not change the value; otherwise
    /// publish only the inspected replacement, never the original body.
    pub fn inspected_bytes(&self, result: &CallToolResult) -> Result<Vec<u8>, InvocationError> {
        let value = result
            .structured_content
            .as_ref()
            .and_then(|root| root.get("data"))
            .ok_or_else(|| recovery_failure(&self.target))?;
        if value == &self.value {
            return Ok(self.bytes.clone());
        }
        if self.binary {
            use base64::Engine;
            return value
                .as_str()
                .and_then(|blob| base64::engine::general_purpose::STANDARD.decode(blob).ok())
                .ok_or_else(|| recovery_failure(&self.target));
        }
        if is_json_media_type(&self.target.media_type) {
            serde_json::to_vec(value).map_err(|_| recovery_failure(&self.target))
        } else {
            value
                .as_str()
                .map(|text| text.as_bytes().to_vec())
                .ok_or_else(|| recovery_failure(&self.target))
        }
    }

    pub fn compact(&self, mut result: CallToolResult) -> CallToolResult {
        if let Some(root) = result
            .structured_content
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
        {
            root.remove("data");
            let ceiling = self
                .original
                .structured_content
                .as_ref()
                .and_then(|root| root.pointer("/payload/context_ceiling_bytes"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            root.insert(
                "payload".to_owned(),
                serde_json::json!({
                    "bytes":self.target.declared_bytes, "media_type":self.target.media_type,
                    "resource_uri":self.target.uri, "retained":true, "inlined":false,
                    "context_ceiling_bytes":ceiling, "reason":"gateway-managed response delivery"
                }),
            );
            // Text mirrors the compact structure; no hydrated body or stale
            // upstream preview may survive in the model-visible content.
            result.content = vec![rmcp::model::ContentBlock::text(
                serde_json::Value::Object(root.clone()).to_string(),
            )];
        }
        result
    }
}

fn resource_bytes(resource: &ReadResourceResult) -> Result<Vec<u8>, RetainedResponseError> {
    match resource.contents.as_slice() {
        [ResourceContents::TextResourceContents { text, .. }] => Ok(text.as_bytes().to_vec()),
        [ResourceContents::BlobResourceContents { blob, .. }] => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(blob)
                .map_err(|_| RetainedResponseError::UnexpectedContents)
        }
        _ => Err(RetainedResponseError::UnexpectedContents),
    }
}

pub(super) fn delivery_failure(mut result: CallToolResult, reason: &str) -> CallToolResult {
    crate::retained_delivery::attach(
        &mut result,
        crate::retained_delivery::Delivery::Unavailable {
            operation_status: crate::retained_delivery::OperationStatus::Succeeded,
            error: reason.to_owned(),
            retry_operation: false,
        },
    );
    result.content.push(rmcp::model::ContentBlock::text(format!(
        "The operation succeeded, but its response attachment is unavailable ({reason}). Do not repeat the operation to retrieve its attachment."
    )));
    result
}

pub(super) fn is_recovery_failure(error: &ErrorData) -> bool {
    error.data.as_ref().is_some_and(|data| {
        matches!(
            data.get("error").and_then(serde_json::Value::as_str),
            Some(
                RECOVERY_FAILED_ERROR
                    | "retained_response_resource_unavailable"
                    | "bounded_resource_read_unsupported"
            )
        )
    })
}

pub(super) struct RetainedResponseProcessor<'a> {
    service: &'a DefaultInvocationService,
    ctx: &'a InvocationContext<'a>,
}

impl<'a> RetainedResponseProcessor<'a> {
    pub(super) fn new(
        service: &'a DefaultInvocationService,
        ctx: &'a InvocationContext<'a>,
    ) -> Self {
        Self { service, ctx }
    }
}

/// Process retained responses before releasing the originating session, for
/// both reads and mutations and independently of the caller's delivery choice.
pub(super) async fn dispatch(
    service: &DefaultInvocationService,
    ctx: &InvocationContext<'_>,
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
    admitted: &waygate_invocation::InvocationContractIdentity,
    mrtr: ToolCallMrtr,
) -> Result<rmcp::model::CallToolResponse, InvocationError> {
    let processor = RetainedResponseProcessor::new(service, ctx);
    service
        .catalog
        .call_tool_response_processed(
            ctx.server,
            ctx.tool,
            arguments,
            ctx.principal,
            Some(admitted),
            CallToolResultProcessing {
                mrtr,
                processor: &processor,
            },
        )
        .await
}

#[async_trait::async_trait]
impl CallToolResultProcessor for RetainedResponseProcessor<'_> {
    async fn process(
        &self,
        result: CallToolResult,
        reader: &dyn CallScopedResourceReader,
    ) -> Result<CallToolResult, CallToolResultProcessingError> {
        let original = result.clone();
        match self
            .service
            .recover_retained_response(self.ctx, result, reader)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if self.ctx.facts().side_effects && original.is_error != Some(true) => {
                // Inspection may subsequently discard this compact response.
                // Keep the confirmed operation outcome independently of it.
                self.ctx
                    .retained_operation_succeeded
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                let error = error.into_error();
                let reason = match &error {
                    InvocationError::Upstream(error) => match error
                        .data
                        .as_ref()
                        .and_then(|data| data.get("error"))
                        .and_then(serde_json::Value::as_str)
                    {
                        Some("retained_response_storage_unavailable") => {
                            "retained_response_storage_unavailable"
                        }
                        Some("retained_response_resource_unavailable") => {
                            "retained_response_resource_unavailable"
                        }
                        Some("retained_response_invalid_envelope") => {
                            "retained_response_invalid_envelope"
                        }
                        Some("bounded_resource_read_unsupported") => {
                            "bounded_resource_read_unsupported"
                        }
                        _ => RECOVERY_FAILED_ERROR,
                    },
                    _ => error.kind(),
                };
                Ok(delivery_failure(original, reason))
            }
            Err(error) => Err(error),
        }
    }
}

impl DefaultInvocationService {
    /// Recover a Code Mode connector body retained behind an MCP resource.
    /// The known originating server is used directly because dynamic resource
    /// links need not be advertised by `resources/list`. Recovery precedes
    /// inspection and schema validation, so JavaScript receives only content
    /// that crossed the ordinary egress controls.
    pub(super) async fn recover_retained_response(
        &self,
        ctx: &InvocationContext<'_>,
        mut result: CallToolResult,
        reader: &dyn CallScopedResourceReader,
    ) -> Result<CallToolResult, CallToolResultProcessingError> {
        // Delivery status belongs to the gateway, never to upstream-supplied
        // metadata. It describes processing performed after this dispatch.
        if let Some(meta) = result.meta.as_mut() {
            meta.remove(crate::files::RETAINED_DELIVERY_META_KEY);
        }
        let target = recognize(&result).map_err(|error| {
            CallToolResultProcessingError::new(
                InvocationError::Upstream(ErrorData::internal_error(
                    error.to_string(),
                    Some(serde_json::json!({"error":"retained_response_invalid_envelope"})),
                )),
                false,
            )
        })?;
        let Some(target) = target else {
            return Ok(result);
        };
        ctx.retained_operation_succeeded
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // A session-affine retained envelope is still upstream resource I/O;
        // it must not reinterpret the gateway-owned file-transfer namespace
        // as a legacy Low-risk native resource. Keep this narrow refusal in
        // the retained-response path without turning the internal recovery
        // into a caller-issued ReadResource operation.
        if crate::files::is_reserved_file_uri(&target.uri) {
            return Err(CallToolResultProcessingError::new(
                self.deny_retained_resource(
                    ctx,
                    "retained connector response uses the reserved gateway file URI namespace"
                        .to_owned(),
                )
                .await,
                false,
            ));
        }
        let file_limit = self
            .file_output_processor
            .as_ref()
            .and_then(|processor| processor.retained_response_max_bytes());
        let materialize = ctx.response_delivery
            == waygate_invocation::ResponseDelivery::Materialize
            && ctx
                .response_materialization_limit_bytes
                .is_some_and(|limit| target.declared_bytes <= limit as u64);
        let Some(limit_bytes) = (if materialize {
            ctx.response_materialization_limit_bytes
        } else {
            file_limit.or_else(|| {
                (ctx.response_delivery == waygate_invocation::ResponseDelivery::Materialize)
                    .then_some(ctx.response_materialization_limit_bytes)
                    .flatten()
            })
        }) else {
            return Err(CallToolResultProcessingError::new(
                InvocationError::Upstream(ErrorData::internal_error(
                    "retained response requires configured gateway file storage",
                    Some(serde_json::json!({"error": "retained_response_storage_unavailable"})),
                )),
                false,
            ));
        };
        let limit_bytes = limit_bytes.min(MAX_RETAINED_BODY_BYTES);
        if target.declared_bytes > u64::try_from(limit_bytes).unwrap_or(u64::MAX) {
            return Err(CallToolResultProcessingError::new(
                InvocationError::ResponseMaterializationLimit {
                    tool: format!("{}.{}", ctx.server, ctx.tool),
                    minimum_response_bytes: target.declared_bytes,
                    limit_bytes,
                },
                false,
            ));
        }
        // Ownership is a manifest routing boundary, not an authentication
        // feature. Enforce it in auth-disabled mode too; only the subsequent
        // visibility/profile/Cedar decisions depend on a principal.
        //
        // The upstream adapter holds its fleet routing read admission across
        // the tool call and this retained-response processing. Read the fleet
        // claims synchronously inside that guard: re-acquiring Tokio's fair
        // RwLock here could deadlock behind a queued writer that is itself
        // waiting for the outer admission.
        let mut fleet_claims = self.catalog.admitted_resource_routing_claims();
        if fleet_claims.is_empty() {
            fleet_claims.extend(
                self.catalog
                    .resource_claims(ctx.server)
                    .into_iter()
                    .map(|claim| (ctx.server.to_owned(), claim)),
            );
        }
        let matching_claims: Vec<_> = fleet_claims
            .iter()
            .filter(|(_, claim)| target.uri.starts_with(&claim.uri_prefix))
            .collect();
        let current_server_declares_any =
            fleet_claims.iter().any(|(server, _)| server == ctx.server);
        // An undeclared server retains the compatibility Low-risk path. A
        // fleet declaration reserves its prefix even when the server returning
        // the retained envelope declared nothing itself. The session-affine
        // read cannot be rerouted to that owner, so any matching claim from
        // another server is a refusal rather than a Low-risk read against the
        // envelope's origin.
        if matching_claims
            .iter()
            .any(|(server, _)| server != ctx.server)
        {
            return Err(CallToolResultProcessingError::new(
                self.deny_retained_resource(
                    ctx,
                    "retained connector response is owned by another upstream's declared resource prefix"
                        .to_owned(),
                )
                .await,
                false,
            ));
        }
        let resource_risk = match matching_claims
            .iter()
            .map(|(_, claim)| claim.risk)
            .max_by_key(|risk| risk.severity())
        {
            Some(risk) => risk,
            None if !current_server_declares_any => crate::protocol::RiskTier::Low,
            None => {
                return Err(CallToolResultProcessingError::new(
                    self.deny_retained_resource(
                        ctx,
                        "retained connector response is outside the server's declared resource prefixes"
                            .to_owned(),
                    )
                    .await,
                    false,
                ));
            }
        };
        if let Some(principal) = ctx.principal {
            if !self.authz.may_discover_server(principal, ctx.server).await {
                return Err(CallToolResultProcessingError::new(
                    self.deny_retained_resource(
                        ctx,
                        "retained connector response server is not discoverable".to_owned(),
                    )
                    .await,
                    false,
                ));
            }
            if crate::authz::profile_blocks_resources(principal, ctx.server) {
                return Err(CallToolResultProcessingError::new(
                    self.deny_retained_resource(
                        ctx,
                        format!(
                            "API key profile does not allow native resources on `{}`",
                            ctx.server
                        ),
                    )
                    .await,
                    false,
                ));
            }
            // Recovery needs an unconditional allow: this read happens inside a
            // tool call that has no way to relay a step-up prompt or claim an
            // approval grant, so any verdict short of Allow is a refusal here.
            //
            // This decision governs attachment delivery after dispatch. It
            // must not describe an already-applied operation as refused.
            let verdict = self
                .authz
                .authorize_resource_read(principal, ctx.server, &target.uri, resource_risk)
                .await;
            let allowed = verdict.is_allow();
            let policy_ids = verdict.policy_ids().to_vec();
            let (reason, reasons) = match &verdict {
                crate::authz::AuthzVerdict::Allow { .. } => {
                    ("retained resource read authorized".to_owned(), Vec::new())
                }
                crate::authz::AuthzVerdict::Deny {
                    reason, reasons, ..
                } => (reason.clone(), reasons.clone()),
                crate::authz::AuthzVerdict::StepUpRequired { reason, .. }
                | crate::authz::AuthzVerdict::ApprovalRequired { reason, .. } => {
                    (reason.clone(), Vec::new())
                }
            };
            let mut event = ctx
                .audit_event(
                    "ReadResource",
                    if allowed {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Denied
                    },
                )
                .with_principal(Some(principal))
                .with_tenant(principal.tenant.clone())
                .with_tool(ctx.server, "resources/read")
                .with_target(target.uri.clone())
                .with_risk(resource_risk)
                .with_policies(policy_ids.clone())
                .with_reason(reason.clone())
                .with_decision_inputs(
                    principal.scopes.clone(),
                    Some(principal.auth_method.as_str().to_owned()),
                    principal.roles.clone(),
                    None,
                );
            // This decision authorizes the resource read, not the outer tool's
            // operation. The invocation hierarchy still links both decisions.
            event.operation = None;
            self.audit.record_chained_best_effort(event).await;
            if !allowed {
                return Err(CallToolResultProcessingError::new(
                    InvocationError::Forbidden {
                        reason,
                        policy_ids,
                        reasons,
                    },
                    false,
                ));
            }
        }
        let mut meta = rmcp::model::MetaObject::new();
        meta.insert(
            crate::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
            // JSON string escaping can expand a byte into six ASCII bytes;
            // the resource envelope also consumes space. The decoded body is
            // checked independently against the admitted delivery budget.
            serde_json::json!(limit_bytes.saturating_mul(6).saturating_add(4096)),
        );
        let resource = reader
            .read_resource(
                rmcp::model::ReadResourceRequestParams::new(target.uri.clone())
                    .with_meta(rmcp::model::RequestMetaObject(meta)),
            )
            .await
            .map_err(|error| {
                let upstream_failure = error.is_transport();
                if error.mcp_error().is_some_and(|error| {
                    error.data.as_ref().is_some_and(|data| {
                        data.get("error").and_then(serde_json::Value::as_str)
                            == Some(crate::catalog::RESPONSE_MATERIALIZATION_LIMIT_ERROR)
                    })
                }) {
                    CallToolResultProcessingError::new(
                        InvocationError::ResponseMaterializationLimit {
                            tool: format!("{}.{}", ctx.server, ctx.tool),
                            minimum_response_bytes: u64::try_from(limit_bytes)
                                .unwrap_or(u64::MAX)
                                .saturating_add(1),
                            limit_bytes,
                        },
                        upstream_failure,
                    )
                } else {
                    tracing::warn!(
                        server = %ctx.server,
                        tool = %ctx.tool,
                        upstream_failure,
                        "retained connector response resource read failed",
                    );
                    let error = if error.mcp_error().is_some_and(|error| {
                        error
                            .data
                            .as_ref()
                            .and_then(|data| data.get("error"))
                            .and_then(serde_json::Value::as_str)
                            == Some("bounded_resource_read_unsupported")
                    }) {
                        recovery_error(&target, "bounded_resource_read_unsupported")
                    } else if error.mcp_error().is_some_and(|error| {
                        error.code == rmcp::model::ErrorCode::RESOURCE_NOT_FOUND
                    }) {
                        recovery_error(&target, "retained_response_resource_unavailable")
                    } else {
                        recovery_failure(&target)
                    };
                    CallToolResultProcessingError::new(error, upstream_failure)
                }
            })?;
        let original = result.clone();
        let bytes = resource_bytes(&resource)
            .map_err(|_| CallToolResultProcessingError::new(recovery_failure(&target), false))?;
        let binary = matches!(
            resource.contents.first(),
            Some(ResourceContents::BlobResourceContents { .. })
        );
        hydrate(&mut result, &target, resource, limit_bytes).map_err(|error| {
            CallToolResultProcessingError::new(
                match error {
                    RetainedResponseError::MaterializationLimit { response_bytes } => {
                        InvocationError::ResponseMaterializationLimit {
                            tool: format!("{}.{}", ctx.server, ctx.tool),
                            minimum_response_bytes: response_bytes,
                            limit_bytes,
                        }
                    }
                    _ => recovery_failure(&target),
                },
                false,
            )
        })?;
        let value = result
            .structured_content
            .as_ref()
            .and_then(|root| root.get("data"))
            .cloned()
            .expect("hydration supplies data");
        // The runtime consumes serialized JSON, whose escaped representation
        // can exceed the original body size. Route that case through storage.
        let encoded_fits = ctx
            .response_materialization_limit_bytes
            .is_some_and(|limit| {
                result.structured_content.as_ref().is_some_and(|value| {
                    serde_json::to_vec(value).is_ok_and(|encoded| encoded.len() <= limit)
                })
            });
        *ctx.retained_response
            .lock()
            .expect("retained response lock") = Some(RecoveredResponse {
            target,
            original,
            bytes,
            value,
            binary,
            file_delivery: !materialize || binary || !encoded_fits,
        });
        Ok(result)
    }

    /// Record the later resource gate locally. The final outcome matcher skips
    /// `Forbidden` because ordinary tool authorization already owns that
    /// error's evidence row; retained-resource recovery is a distinct
    /// post-dispatch authorization decision.
    ///
    async fn deny_retained_resource(
        &self,
        ctx: &InvocationContext<'_>,
        reason: String,
    ) -> InvocationError {
        let facts = ctx.facts();
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("ResponseDelivery", AuditOutcome::Denied)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_risk(facts.risk)
                    .with_pii(facts.pii)
                    .with_reason(reason.clone()),
            )
            .await;
        InvocationError::Forbidden {
            reason,
            policy_ids: Vec::new(),
            reasons: Vec::new(),
        }
    }
}

fn recovery_failure(target: &RetainedResponse) -> InvocationError {
    recovery_error(target, RECOVERY_FAILED_ERROR)
}

fn recovery_error(target: &RetainedResponse, reason: &'static str) -> InvocationError {
    InvocationError::Upstream(ErrorData::internal_error(
        format!(
            "retained connector response for operation `{}` at `{}` could not be recovered",
            target.operation_id, target.uri,
        ),
        Some(serde_json::json!({
            "error": reason,
            "operation_id": target.operation_id,
            "resource_uri": target.uri,
        })),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RetainedResponse {
    pub uri: String,
    pub declared_bytes: u64,
    pub operation_id: String,
    pub media_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetainedResponseError {
    InvalidEnvelope,
    UnexpectedContents,
    ResourceIdentityChanged,
    SizeChanged,
    MaterializationLimit { response_bytes: u64 },
    InvalidJsonBody,
}

impl std::fmt::Display for RetainedResponseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEnvelope => "retained connector response envelope is invalid",
            Self::UnexpectedContents => {
                "retained connector response did not resolve to exactly one resource"
            }
            Self::ResourceIdentityChanged => {
                "retained connector response resolved to a different resource identity"
            }
            Self::SizeChanged => "retained connector response size changed before it was recovered",
            Self::MaterializationLimit { .. } => {
                "retained connector response exceeds the caller materialization budget"
            }
            Self::InvalidJsonBody => "retained JSON connector response does not contain valid JSON",
        })
    }
}

/// Recognize the connector platform's successful out-of-line HTTP envelope.
///
/// The complete shape check prevents an arbitrary upstream object containing
/// a `resource_uri` member from causing a second request. Once the outer HTTP
/// envelope identifies this contract, a retained payload missing its URI,
/// media type or size is an error rather than an instruction to guess.
pub(super) fn recognize(
    result: &CallToolResult,
) -> Result<Option<RetainedResponse>, RetainedResponseError> {
    if result.is_error == Some(true) {
        return Ok(None);
    }
    let Some(root) = result
        .structured_content
        .as_ref()
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    if root.get("success").and_then(serde_json::Value::as_bool) != Some(true)
        || !root
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|status| (200..300).contains(&status))
        || root
            .get("content_type")
            .and_then(serde_json::Value::as_str)
            .is_none()
        || root
            .get("headers")
            .and_then(serde_json::Value::as_object)
            .is_none()
        || root
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .is_none()
        || root.contains_key("data")
    {
        return Ok(None);
    }
    let Some(payload) = root.get("payload").and_then(serde_json::Value::as_object) else {
        return Ok(None);
    };
    if payload.get("inlined").and_then(serde_json::Value::as_bool) != Some(false)
        || payload.get("retained").and_then(serde_json::Value::as_bool) != Some(true)
    {
        return Ok(None);
    }
    let operation_id = root
        .get("operation_id")
        .and_then(serde_json::Value::as_str)
        .expect("operation_id shape checked above");
    let uri = payload
        .get("resource_uri")
        .and_then(serde_json::Value::as_str)
        .filter(|uri| !uri.is_empty())
        .ok_or(RetainedResponseError::InvalidEnvelope)?;
    let declared_bytes = payload
        .get("bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or(RetainedResponseError::InvalidEnvelope)?;
    let media_type = payload
        .get("media_type")
        .and_then(serde_json::Value::as_str)
        .filter(|media_type| !media_type.is_empty())
        .ok_or(RetainedResponseError::InvalidEnvelope)?;
    Ok(Some(RetainedResponse {
        uri: uri.to_owned(),
        declared_bytes,
        operation_id: operation_id.to_owned(),
        media_type: media_type.to_owned(),
    }))
}

/// Replace the retained envelope with the same `data` member a small response
/// carries. The URI and byte count are rechecked so the adapter cannot swap or
/// mutate the body between the tool result and resource read.
pub(super) fn hydrate(
    result: &mut CallToolResult,
    target: &RetainedResponse,
    resource: ReadResourceResult,
    limit_bytes: usize,
) -> Result<(), RetainedResponseError> {
    let mut contents = resource.contents.into_iter();
    let Some(content) = contents.next() else {
        return Err(RetainedResponseError::UnexpectedContents);
    };
    if contents.next().is_some() {
        return Err(RetainedResponseError::UnexpectedContents);
    }
    let (uri, text, binary) = match content {
        ResourceContents::TextResourceContents { uri, text, .. } => (uri, text, false),
        ResourceContents::BlobResourceContents { uri, blob, .. } => (uri, blob, true),
        _ => return Err(RetainedResponseError::UnexpectedContents),
    };
    if uri != target.uri {
        return Err(RetainedResponseError::ResourceIdentityChanged);
    }
    let response_bytes = if binary {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&text)
            .map_err(|_| RetainedResponseError::UnexpectedContents)?
            .len() as u64
    } else {
        text.len() as u64
    };
    if response_bytes > u64::try_from(limit_bytes).unwrap_or(u64::MAX) {
        return Err(RetainedResponseError::MaterializationLimit { response_bytes });
    }
    if response_bytes != target.declared_bytes {
        return Err(RetainedResponseError::SizeChanged);
    }
    let root = result
        .structured_content
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(RetainedResponseError::InvalidEnvelope)?;
    root.remove("payload");
    let data = if !binary && is_json_media_type(&target.media_type) {
        serde_json::from_str(&text).map_err(|_| RetainedResponseError::InvalidJsonBody)?
    } else {
        serde_json::Value::String(text)
    };
    root.insert("data".to_owned(), data);
    Ok(())
}

fn is_json_media_type(media_type: &str) -> bool {
    let essence = media_type
        .split_once(';')
        .map_or(media_type, |(essence, _)| essence)
        .trim()
        .to_ascii_lowercase();
    essence == "application/json"
        || (essence.starts_with("application/") && essence.ends_with("+json"))
}

#[cfg(test)]
mod tests {
    use rmcp::model::CallToolResult;
    use serde_json::json;

    use super::*;

    fn retained(bytes: u64) -> CallToolResult {
        CallToolResult::structured(json!({
            "content_type": "text/plain; charset=utf-8",
            "headers": {},
            "operation_id": "downloadLog",
            "payload": {
                "bytes": bytes,
                "context_ceiling_bytes": 65_536,
                "inlined": false,
                "media_type": "text/plain",
                "preview": "first lines only",
                "reason": "above the context-scale ceiling",
                "resource_uri": "connector-response:/downloadLog/0",
                "retained": true
            },
            "status": 200,
            "success": true
        }))
    }

    #[test]
    fn retained_text_becomes_the_normal_inline_response_shape() {
        let mut result = retained(12);
        let target = recognize(&result)
            .expect("valid envelope")
            .expect("retained response");

        hydrate(
            &mut result,
            &target,
            ReadResourceResult::new(vec![ResourceContents::text(
                "failure here",
                "connector-response:/downloadLog/0",
            )]),
            1024,
        )
        .expect("hydrate text response");

        assert_eq!(
            result.structured_content.as_ref().unwrap()["data"],
            "failure here"
        );
        assert!(result
            .structured_content
            .as_ref()
            .unwrap()
            .get("payload")
            .is_none());
    }

    #[test]
    fn retained_json_becomes_the_same_structured_value_as_an_inline_response() {
        const JSON_BODY: &str = r#"[{"name":"large result"}]"#;
        let mut result = retained(JSON_BODY.len() as u64);
        result.structured_content.as_mut().unwrap()["payload"]["media_type"] =
            json!("application/json; charset=utf-8");
        let target = recognize(&result)
            .expect("valid envelope")
            .expect("retained response");

        hydrate(
            &mut result,
            &target,
            ReadResourceResult::new(vec![ResourceContents::text(
                JSON_BODY,
                "connector-response:/downloadLog/0",
            )]),
            1024,
        )
        .expect("hydrate JSON response");

        assert_eq!(
            result.structured_content.as_ref().unwrap()["data"],
            json!([{"name": "large result"}]),
        );
    }

    #[test]
    fn unrelated_resource_fields_do_not_trigger_recovery() {
        let result = CallToolResult::structured(json!({
            "success": true,
            "operation_id": "ordinary",
            "data": {"resource_uri": "connector-response:/ordinary/0"}
        }));

        assert_eq!(recognize(&result).expect("shape is valid"), None);
    }

    #[test]
    fn retained_recovery_requires_identity_not_presentation_metadata() {
        let mut result = retained(12);
        let payload = result.structured_content.as_mut().unwrap()["payload"]
            .as_object_mut()
            .unwrap();
        for field in ["preview", "reason", "context_ceiling_bytes"] {
            payload.remove(field);
        }
        assert!(recognize(&result).unwrap().is_some());
        for field in ["resource_uri", "bytes", "media_type"] {
            let mut malformed = result.clone();
            malformed.structured_content.as_mut().unwrap()["payload"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(
                recognize(&malformed),
                Err(RetainedResponseError::InvalidEnvelope)
            );
        }
    }

    #[test]
    fn changed_size_is_refused_without_replacing_the_preview() {
        let mut result = retained(99);
        let target = recognize(&result).unwrap().unwrap();

        assert_eq!(
            hydrate(
                &mut result,
                &target,
                ReadResourceResult::new(vec![ResourceContents::text(
                    "short",
                    "connector-response:/downloadLog/0",
                )]),
                1024,
            ),
            Err(RetainedResponseError::SizeChanged)
        );
        assert!(result
            .structured_content
            .as_ref()
            .unwrap()
            .get("data")
            .is_none());
        assert!(result
            .structured_content
            .as_ref()
            .unwrap()
            .get("payload")
            .is_some());
    }

    #[test]
    fn actual_body_over_budget_is_refused_before_hydration() {
        let mut result = retained(1);
        let target = recognize(&result).unwrap().unwrap();

        assert_eq!(
            hydrate(
                &mut result,
                &target,
                ReadResourceResult::new(vec![ResourceContents::text(
                    "xx",
                    "connector-response:/downloadLog/0",
                )]),
                1,
            ),
            Err(RetainedResponseError::MaterializationLimit { response_bytes: 2 })
        );
        assert!(result
            .structured_content
            .as_ref()
            .unwrap()
            .get("payload")
            .is_some());
    }
}
